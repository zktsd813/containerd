package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

const (
	directDedupPublicationVersion = int(trenvpub.Version)
	directRestoreMapPageSize      = uint64(4096)
	directRestoreMapMaxExtents    = 1_000_000
	directRestoreMapMaxBytes      = 128 << 20
)

const (
	dedupRestoreCodePublication = "dedup_publication_invalid"
	dedupRestoreCodeBaseMap     = "dedup_base_restore_map_invalid"
	dedupRestoreCodeStats       = "dedup_stats_mismatch"
	dedupRestoreCodeDevice      = "dedup_reader_device_unbound"
	dedupRestoreCodeRemapFile   = "dedup_remap_file_failed"
)

// dedupRestoreError is the reader-side direct-dedup error contract. Callers
// should use dedupRestoreErrorCode instead of parsing the rendered error.
type dedupRestoreError struct {
	Code string
	Err  error
}

func (e *dedupRestoreError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err == nil {
		return fmt.Sprintf("dedup restore failed (%s)", e.Code)
	}
	return fmt.Sprintf("dedup restore failed (%s): %v", e.Code, e.Err)
}

func (e *dedupRestoreError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func dedupRestoreErrorCode(err error) string {
	var target *dedupRestoreError
	if errors.As(err, &target) {
		return target.Code
	}
	return ""
}

func newDedupRestoreError(code string, err error) error {
	return &dedupRestoreError{Code: code, Err: err}
}

type directPseudoMMImportPlan struct {
	checkpointPath        string
	workPath              string
	publication           metadataPublicationRecord
	daxDevice             string
	daxStartPage          int64
	restoreMap            []byte
	restoreMapSHA256      string
	restoreMapExtentCount uint64
	restoreMapPageCount   uint64
}

func prepareDirectReaderPseudoMM(ctx context.Context, plan directPseudoMMImportPlan, state trenvContainerState, config daemonConfig) error {
	if state.PID <= 0 {
		return fmt.Errorf("reader pseudo_mm import target pid is invalid: %d", state.PID)
	}
	if err := validateReaderPageExtent(plan.publication, config); err != nil {
		if len(plan.restoreMap) > 0 {
			return newDedupRestoreError(dedupRestoreCodeDevice, err)
		}
		return err
	}
	return materializeDirectReaderPseudoMM(ctx, state, config, plan)
}

func directV5DedupPublication(publication metadataPublicationRecord) (bool, error) {
	phase := strings.TrimSpace(publication.CheckpointPhase)
	hasDedupMetadata := len(publication.BaseRestoreMap) > 0 ||
		publication.Stats.RestoreMapExtentCount > 0 ||
		publication.Stats.DedupAppliedPages > 0 ||
		publication.Stats.SkippedWritablePages > 0
	if phase == trenvpub.DedupRestoreCOWPhase {
		if publication.Version != directDedupPublicationVersion {
			return false, newDedupRestoreError(
				dedupRestoreCodePublication,
				fmt.Errorf("dedup phase requires publication version %d, got %d", directDedupPublicationVersion, publication.Version))
		}
		if publication.ManifestSchema != trenvpub.ManifestSchema {
			return false, newDedupRestoreError(
				dedupRestoreCodePublication,
				fmt.Errorf("dedup publication manifest schema is %q, expected %q", publication.ManifestSchema, trenvpub.ManifestSchema))
		}
		if publication.DedupApplySchema != trenvpub.DedupApplySchema {
			return false, newDedupRestoreError(
				dedupRestoreCodePublication,
				fmt.Errorf("dedup publication apply schema is %q, expected %q", publication.DedupApplySchema, trenvpub.DedupApplySchema))
		}
		return true, nil
	}
	if publication.Version >= directDedupPublicationVersion && hasDedupMetadata {
		return false, newDedupRestoreError(
			dedupRestoreCodePublication,
			fmt.Errorf("V5 dedup metadata requires checkpoint phase %q", trenvpub.DedupRestoreCOWPhase))
	}
	return false, nil
}

func validateDirectRestoreMapDevice(device string) error {
	if strings.TrimSpace(device) == "" {
		return errors.New("reader-local DAX device is empty")
	}
	if !filepath.IsAbs(device) {
		return fmt.Errorf("reader-local DAX device %q is not absolute", device)
	}
	if strings.ContainsAny(device, " \t\r\n") {
		return fmt.Errorf("reader-local DAX device %q contains whitespace", device)
	}
	return nil
}

func buildDirectV5RestoreMap(publication metadataPublicationRecord, device string) ([]byte, string, uint64, error) {
	if err := validateDirectRestoreMapDevice(device); err != nil {
		return nil, "", 0, newDedupRestoreError(dedupRestoreCodeDevice, err)
	}
	extents := publication.BaseRestoreMap
	if len(extents) == 0 {
		return nil, "", 0, newDedupRestoreError(
			dedupRestoreCodeBaseMap,
			errors.New("V5 derived publication has no BaseRestoreMap extents"))
	}
	if len(extents) > directRestoreMapMaxExtents {
		return nil, "", 0, newDedupRestoreError(
			dedupRestoreCodeBaseMap,
			fmt.Errorf("BaseRestoreMap has %d extents; maximum is %d", len(extents), directRestoreMapMaxExtents))
	}
	pageExtent := publication.PageExtent
	if pageExtent.PageSize != int64(directRestoreMapPageSize) {
		return nil, "", 0, newDedupRestoreError(
			dedupRestoreCodeBaseMap,
			fmt.Errorf("page extent page size is %d, expected %d", pageExtent.PageSize, directRestoreMapPageSize))
	}
	if pageExtent.OffsetBytes < 0 ||
		pageExtent.PayloadBytes <= 0 ||
		pageExtent.OffsetBytes%int64(directRestoreMapPageSize) != 0 ||
		pageExtent.PayloadBytes%int64(directRestoreMapPageSize) != 0 {
		return nil, "", 0, newDedupRestoreError(
			dedupRestoreCodeBaseMap,
			errors.New("page extent payload is not a positive 4K-aligned range"))
	}
	payloadStart := uint64(pageExtent.OffsetBytes) / directRestoreMapPageSize
	payloadPages := uint64(pageExtent.PayloadBytes) / directRestoreMapPageSize
	if payloadStart > math.MaxUint64-payloadPages {
		return nil, "", 0, newDedupRestoreError(dedupRestoreCodeBaseMap, errors.New("page extent payload range overflows"))
	}
	payloadEnd := payloadStart + payloadPages
	if publication.Stats.RestoreMapExtentCount != uint64(len(extents)) {
		return nil, "", 0, newDedupRestoreError(
			dedupRestoreCodeStats,
			fmt.Errorf("RestoreMapExtentCount=%d does not match BaseRestoreMap extent count=%d", publication.Stats.RestoreMapExtentCount, len(extents)))
	}

	var remap bytes.Buffer
	var previousEnd uint64
	var totalPages uint64
	for index, extent := range extents {
		if extent.ShardIndex != 0 {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d uses unsupported shard index %d", index, extent.ShardIndex))
		}
		if extent.Type != trenvpub.RestoreExtentTypeSharedReadonly || extent.Flags != trenvpub.RestoreExtentFlagCOW {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d has unsupported type=%d flags=%d", index, extent.Type, extent.Flags))
		}
		if extent.NrPages == 0 {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d has zero pages", index))
		}
		if extent.Vaddr%directRestoreMapPageSize != 0 {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d vaddr %#x is not 4K aligned", index, extent.Vaddr))
		}
		if extent.NrPages > (math.MaxUint64-extent.Vaddr)/directRestoreMapPageSize {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d virtual range overflows", index))
		}
		virtualEnd := extent.Vaddr + extent.NrPages*directRestoreMapPageSize
		if index > 0 && extent.Vaddr < previousEnd {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d overlaps or is not sorted", index))
		}
		previousEnd = virtualEnd
		if extent.Pgoff < payloadStart || extent.Pgoff >= payloadEnd || extent.NrPages > payloadEnd-extent.Pgoff {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("BaseRestoreMap extent %d pgoff range [%d,%d) is outside page payload [%d,%d)",
					index, extent.Pgoff, extent.Pgoff+extent.NrPages, payloadStart, payloadEnd))
		}
		if totalPages > math.MaxUint64-extent.NrPages {
			return nil, "", 0, newDedupRestoreError(dedupRestoreCodeStats, errors.New("BaseRestoreMap page sum overflows"))
		}
		totalPages += extent.NrPages
		line := fmt.Sprintf("0x%x %d %d %s\n", extent.Vaddr, extent.NrPages, extent.Pgoff, device)
		if remap.Len() > directRestoreMapMaxBytes-len(line) {
			return nil, "", 0, newDedupRestoreError(
				dedupRestoreCodeBaseMap,
				fmt.Errorf("generated DAX remap exceeds %d bytes", directRestoreMapMaxBytes))
		}
		_, _ = remap.WriteString(line)
	}
	if publication.Stats.DedupAppliedPages != totalPages {
		return nil, "", 0, newDedupRestoreError(
			dedupRestoreCodeStats,
			fmt.Errorf("DedupAppliedPages=%d does not match BaseRestoreMap page sum=%d", publication.Stats.DedupAppliedPages, totalPages))
	}
	data := remap.Bytes()
	digest := sha256.Sum256(data)
	return append([]byte(nil), data...), fmt.Sprintf("%x", digest[:]), totalPages, nil
}

func resolveDirectPseudoMMImportPlan(req switchRequest, config daemonConfig) (directPseudoMMImportPlan, bool, error) {
	checkpointPath := filepath.Clean(strings.TrimSpace(req.CheckpointPath))
	if checkpointPath == "." || filepath.Base(checkpointPath) != "image" {
		return directPseudoMMImportPlan{}, false, nil
	}
	restoreRoot := filepath.Dir(filepath.Dir(checkpointPath))
	publicationPath := filepath.Join(restoreRoot, "publication.reader"+trenvpub.Extension)
	if !isRegularFile(publicationPath) {
		legacyPath := filepath.Join(restoreRoot, "publication.reader.json")
		if isRegularFile(legacyPath) {
			return directPseudoMMImportPlan{}, false, fmt.Errorf(
				"legacy reader publication %q is unsupported; only strict V5 %s is accepted",
				legacyPath,
				trenvpub.Extension)
		}
		return directPseudoMMImportPlan{}, false, nil
	}
	publication, err := readPublicationRecord(publicationPath)
	if err != nil {
		return directPseudoMMImportPlan{}, false, err
	}

	pageExtent := publication.PageExtent
	if publication.State != "COMMITTED" || publication.Generation == 0 || publication.WriterEpoch == 0 {
		return directPseudoMMImportPlan{}, false, errors.New("reader publication is not a fenced COMMITTED generation")
	}
	if err := validateDirectStorageExtent(pageExtent, directPageExtentRole); err != nil {
		return directPseudoMMImportPlan{}, false, fmt.Errorf("reader page extent: %w", err)
	}
	if pageExtent.OffsetBytes < 0 || pageExtent.LengthBytes <= 0 || pageExtent.PageSize <= 0 || pageExtent.OffsetBytes%pageExtent.PageSize != 0 {
		return directPseudoMMImportPlan{}, false, errors.New("reader page DAX placement is invalid")
	}
	isDedup, err := directV5DedupPublication(publication)
	if err != nil {
		return directPseudoMMImportPlan{}, false, err
	}
	daxDevice, err := resolveReaderDaxDevice(pageExtent, config)
	if err != nil {
		if isDedup {
			return directPseudoMMImportPlan{}, false, newDedupRestoreError(dedupRestoreCodeDevice, err)
		}
		return directPseudoMMImportPlan{}, false, err
	}
	var restoreMap []byte
	var restoreMapSHA256 string
	var restoreMapPageCount uint64
	if isDedup {
		restoreMap, restoreMapSHA256, restoreMapPageCount, err = buildDirectV5RestoreMap(publication, daxDevice)
		if err != nil {
			return directPseudoMMImportPlan{}, false, err
		}
	}
	workRoot := strings.TrimSpace(req.PseudoMMMaterializationRoot)
	if workRoot == "" {
		workRoot = strings.TrimSpace(config.PseudoMMMaterializationRoot)
	}
	if workRoot == "" {
		workRoot = filepath.Join(config.WorkingDirectory, "pseudo-mm-materialized")
	}
	artifactID := publication.ArtifactID
	if artifactID == "" {
		artifactID = publication.CheckpointID
	}
	workPath := filepath.Join(workRoot, sanitizePathPart(artifactID), sanitizePathPart(req.ContainerID))
	return directPseudoMMImportPlan{
		checkpointPath:        checkpointPath,
		workPath:              workPath,
		publication:           publication,
		daxDevice:             daxDevice,
		daxStartPage:          pageExtent.OffsetBytes / pageExtent.PageSize,
		restoreMap:            restoreMap,
		restoreMapSHA256:      restoreMapSHA256,
		restoreMapExtentCount: uint64(len(publication.BaseRestoreMap)),
		restoreMapPageCount:   restoreMapPageCount,
	}, true, nil
}
