package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

const (
	directRootfsStateDirectoryName     = "rootfs-state"
	directDaxPlacementPolicyFirstFit   = "first-fit"
	directDaxPlacementPolicyRoundRobin = "round-robin"
	directDaxPlacementLayoutContiguous = "contiguous-criu-page-stream"
)

var errDirectDaxShardFull = errors.New("dax shard full")

type directDaxPlacement struct {
	CheckpointID     string    `json:"checkpoint_id"`
	WriterID         string    `json:"writer_id"`
	ShardID          string    `json:"shard_id"`
	DaxDevice        string    `json:"dax_device"`
	DaxStartPage     int64     `json:"dax_start_page"`
	DaxLengthPages   int64     `json:"dax_length_pages"`
	PageCount        int64     `json:"page_count"`
	ConvertPageCount int64     `json:"convert_page_count"`
	PageSize         int64     `json:"page_size"`
	Layout           string    `json:"layout"`
	State            string    `json:"state"`
	UpdatedAt        time.Time `json:"updated_at"`
	NewReservation   bool      `json:"-"`
	WriterStateRoot  string    `json:"-"`
}

type directWriterShardAllocatorState struct {
	WriterID     string    `json:"writer_id"`
	ShardID      string    `json:"shard_id"`
	DevicePages  int64     `json:"device_pages"`
	AlignPages   int64     `json:"align_pages"`
	NextFreePage int64     `json:"next_free_page"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type directWriterShardExtentRecord struct {
	CheckpointID string    `json:"checkpoint_id"`
	ExtentType   string    `json:"extent_type"`
	ImagePath    string    `json:"image_path"`
	StartPage    int64     `json:"start_page"`
	LengthPages  int64     `json:"length_pages"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type directWriterShardSelectorState struct {
	WriterID  string    `json:"writer_id"`
	Policy    string    `json:"policy"`
	ShardIDs  []string  `json:"shard_ids"`
	NextIndex int       `json:"next_index"`
	UpdatedAt time.Time `json:"updated_at"`
}

type directDaxPlacementCandidate struct {
	shard       daxShardConfig
	devicePages int64
	alignPages  int64
	lengthPages int64
	pageSize    int64
}

type directMetadataBundleFile struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

type directMetadataBundleManifest struct {
	CheckpointID string                     `json:"checkpoint_id"`
	ImagePath    string                     `json:"image_path"`
	Placement    string                     `json:"placement"`
	Files        []directMetadataBundleFile `json:"files"`
	CreatedAt    time.Time                  `json:"created_at"`
}

func prepareDirectCheckpointPublication(ctx context.Context, req checkpointRequest, state trenvContainerState, config daemonConfig) (directDaxPlacement, error) {
	placement, err := directCheckpointPlacement(req, config)
	if err != nil {
		return directDaxPlacement{}, err
	}
	if err := runDirectCriuConvert(ctx, req, state, placement); err != nil {
		rollbackDirectDaxPlacementReservation(placement)
		return directDaxPlacement{}, err
	}
	if pageCount, err := readDirectConvertPageCount(req.ImagePath); err == nil {
		placement.PageCount = pageCount
		placement.ConvertPageCount = pageCount
	}
	return placement, nil
}

func finalizeDirectCheckpoint(ctx context.Context, req checkpointRequest, state trenvContainerState, config daemonConfig, placement directDaxPlacement) error {
	if req.Publication == nil && strings.TrimSpace(req.MetadataBundlePath) == "" && len(req.ActionExportRoots) == 0 {
		return nil
	}
	if strings.TrimSpace(req.MetadataBundlePath) != "" {
		if err := writeDirectMetadataBundle(req.ImagePath, req.MetadataBundlePath, placement); err != nil {
			rollbackDirectDaxPlacementReservation(placement)
			return fmt.Errorf("write metadata bundle: %w", err)
		}
		if err := exportDirectRuntimeRootfsState(state.Rootfs, req.WorkPath, req.MetadataBundlePath); err != nil {
			rollbackDirectDaxPlacementReservation(placement)
			return fmt.Errorf("export runtime rootfs state: %w", err)
		}
	}
	if len(req.ActionExportRoots) > 0 {
		exportRoot := directCheckpointActionExportRoot(req)
		if exportRoot == "" {
			rollbackDirectDaxPlacementReservation(placement)
			return errors.New("checkpoint action export root is empty")
		}
		if err := exportDirectActionRoots(state.Rootfs, exportRoot, req.ActionExportRoots); err != nil {
			rollbackDirectDaxPlacementReservation(placement)
			return fmt.Errorf("export packaged action roots: %w", err)
		}
	}
	if req.Publication != nil {
		pageExtent, err := directPageStorageExtent(placement)
		if err != nil {
			rollbackDirectDaxPlacementReservation(placement)
			return fmt.Errorf("seal page DAX extent: %w", err)
		}
		artifactExtent, artifactFiles, artifactPlacement, err := writeDirectDaxArtifact(req, placement, config)
		if err != nil {
			rollbackDirectDaxPlacementReservation(placement)
			return fmt.Errorf("write artifact DAX extent: %w", err)
		}
		if err := writeDirectPublication(ctx, req, placement, config, pageExtent, artifactExtent, artifactFiles); err != nil {
			rollbackDirectDaxPlacementReservation(artifactPlacement)
			rollbackDirectDaxPlacementReservation(placement)
			return fmt.Errorf("write publication metadata: %w", err)
		}
	}
	return nil
}

func directCheckpointActionExportRoot(req checkpointRequest) string {
	if req.Publication != nil && strings.TrimSpace(req.Publication.CheckpointActionExportRoot) != "" {
		return strings.TrimSpace(req.Publication.CheckpointActionExportRoot)
	}
	if strings.TrimSpace(req.WorkPath) != "" {
		return filepath.Join(req.WorkPath, "action-root")
	}
	return ""
}

func directCheckpointPlacement(req checkpointRequest, config daemonConfig) (directDaxPlacement, error) {
	if req.Publication != nil && config.CheckpointWriterDisabled {
		return directDaxPlacement{}, errors.New("checkpoint writer is disabled")
	}
	if req.Publication != nil {
		if config.WriterEpoch == 0 {
			return directDaxPlacement{}, errors.New("checkpoint writer epoch must be non-zero")
		}
		publicationPath := trenvpub.NormalizePath(strings.TrimSpace(req.Publication.PublicationPath))
		if publicationPath != "" && pathExists(publicationPath) {
			return directDaxPlacement{}, fmt.Errorf("immutable publication already exists at %q", publicationPath)
		}
	}
	writerID := strings.TrimSpace(config.WriterID)
	if writerID == "" {
		writerID = defaultWriterID()
	}
	shards, err := directCheckpointDaxShards(config)
	if err != nil {
		return directDaxPlacement{}, err
	}
	pageSize := int64(os.Getpagesize())
	pageBytes, pageCount := directCheckpointPagePayload(req.ImagePath, pageSize)
	writerStateRoot := strings.TrimSpace(config.WriterStateRoot)
	if writerStateRoot == "" {
		writerStateRoot = directDefaultWriterStateRoot(req.ImagePath)
	}
	placement, err := resolveDirectDaxPlacement(
		writerStateRoot,
		writerID,
		checkpointID(req.ImagePath),
		req.ImagePath,
		shards,
		pageBytes,
		config.DaxPlacementPolicy)
	if err != nil {
		return directDaxPlacement{}, err
	}
	placement.PageCount = pageCount
	placement.ConvertPageCount = pageCount
	placement.WriterStateRoot = writerStateRoot
	return placement, nil
}

func directCheckpointDaxShards(config daemonConfig) ([]daxShardConfig, error) {
	if len(config.DaxShards) > 0 {
		shards := make([]daxShardConfig, 0, len(config.DaxShards))
		for _, shard := range config.DaxShards {
			normalized, err := normalizeDaxShardConfig(shard)
			if err != nil {
				return nil, err
			}
			shards = append(shards, normalized)
		}
		return shards, nil
	}
	daxDevice := strings.TrimSpace(config.DaxDevice)
	if daxDevice == "" {
		var err error
		daxDevice, err = detectDaxDevice()
		if err != nil {
			return nil, err
		}
	}
	shardID := strings.TrimSpace(config.ShardID)
	if shardID == "" {
		shardID = filepath.Base(daxDevice)
	}
	shard, err := normalizeDaxShardConfig(daxShardConfig{ShardID: shardID, DaxDevice: daxDevice})
	if err != nil {
		return nil, err
	}
	return []daxShardConfig{shard}, nil
}

func directArtifactDaxShards(config daemonConfig) ([]daxShardConfig, error) {
	if len(config.ArtifactDaxShards) == 0 {
		return directCheckpointDaxShards(config)
	}
	shards := make([]daxShardConfig, 0, len(config.ArtifactDaxShards))
	for _, shard := range config.ArtifactDaxShards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return nil, err
		}
		shards = append(shards, normalized)
	}
	return shards, nil
}

func resolveDirectDaxPlacement(root, writerID, checkpointIDValue, imagePath string, shards []daxShardConfig, requestedBytes int64, policy string) (directDaxPlacement, error) {
	if len(shards) == 0 {
		return directDaxPlacement{}, errors.New("no DAX shards configured")
	}
	if strings.TrimSpace(checkpointIDValue) == "" {
		return directDaxPlacement{}, errors.New("checkpoint id is empty")
	}
	normalizedPolicy, err := normalizeDirectDaxPlacementPolicy(policy)
	if err != nil {
		return directDaxPlacement{}, err
	}
	candidates, err := buildDirectDaxPlacementCandidates(shards, requestedBytes)
	if err != nil {
		return directDaxPlacement{}, err
	}
	if existing, ok, err := existingDirectDaxPlacement(root, writerID, checkpointIDValue, candidates); err != nil {
		return directDaxPlacement{}, err
	} else if ok {
		return existing, nil
	}
	if normalizedPolicy == directDaxPlacementPolicyRoundRobin {
		return resolveDirectRoundRobinDaxPlacement(root, writerID, checkpointIDValue, imagePath, candidates)
	}
	return allocateDirectDaxPlacementInOrder(root, writerID, checkpointIDValue, imagePath, candidates)
}

func normalizeDirectDaxPlacementPolicy(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", directDaxPlacementPolicyFirstFit:
		return directDaxPlacementPolicyFirstFit, nil
	case directDaxPlacementPolicyRoundRobin:
		return directDaxPlacementPolicyRoundRobin, nil
	default:
		return "", fmt.Errorf("unsupported DAX placement policy %q", policy)
	}
}

func buildDirectDaxPlacementCandidates(shards []daxShardConfig, requestedBytes int64) ([]directDaxPlacementCandidate, error) {
	pageSize := int64(os.Getpagesize())
	if requestedBytes <= 0 {
		requestedBytes = pageSize
	}
	candidates := make([]directDaxPlacementCandidate, 0, len(shards))
	for _, shard := range shards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return nil, err
		}
		devicePages, alignPages, err := directDaxDeviceGeometry(normalized.DaxDevice, pageSize)
		if err != nil {
			return nil, err
		}
		lengthPages := roundUpInt64(requestedBytes, alignPages*pageSize) / pageSize
		if lengthPages <= 0 {
			return nil, fmt.Errorf("invalid slot length %d pages for shard %q", lengthPages, normalized.ShardID)
		}
		candidates = append(candidates, directDaxPlacementCandidate{
			shard:       normalized,
			devicePages: devicePages,
			alignPages:  alignPages,
			lengthPages: lengthPages,
			pageSize:    pageSize,
		})
	}
	return candidates, nil
}

func allocateDirectDaxPlacementInOrder(root, writerID, checkpointIDValue, imagePath string, candidates []directDaxPlacementCandidate) (directDaxPlacement, error) {
	var exhausted []string
	for _, candidate := range candidates {
		placement, err := allocateDirectCandidateDaxPlacement(root, writerID, checkpointIDValue, imagePath, candidate)
		if err == nil {
			return placement, nil
		}
		if errors.Is(err, errDirectDaxShardFull) {
			exhausted = append(exhausted, fmt.Sprintf("%s: %v", candidate.shard.ShardID, err))
			continue
		}
		return directDaxPlacement{}, err
	}
	if len(exhausted) > 0 {
		return directDaxPlacement{}, fmt.Errorf("all DAX shards exhausted: %s", strings.Join(exhausted, "; "))
	}
	return directDaxPlacement{}, errors.New("no DAX placement candidates")
}

func allocateDirectCandidateDaxPlacement(root, writerID, checkpointIDValue, imagePath string, candidate directDaxPlacementCandidate) (directDaxPlacement, error) {
	startPage, existed, err := allocateDirectWriterShardDaxPagesWithResult(
		root,
		writerID,
		candidate.shard.ShardID,
		checkpointIDValue,
		imagePath,
		candidate.devicePages,
		candidate.alignPages,
		candidate.lengthPages)
	if err != nil {
		return directDaxPlacement{}, err
	}
	return directDaxPlacement{
		CheckpointID:    checkpointIDValue,
		WriterID:        writerID,
		ShardID:         candidate.shard.ShardID,
		DaxDevice:       candidate.shard.DaxDevice,
		DaxStartPage:    startPage,
		DaxLengthPages:  candidate.lengthPages,
		PageSize:        candidate.pageSize,
		Layout:          directDaxPlacementLayoutContiguous,
		State:           "COMMITTED",
		UpdatedAt:       time.Now().UTC(),
		NewReservation:  !existed,
		WriterStateRoot: root,
	}, nil
}

func existingDirectDaxPlacement(root, writerID, checkpointIDValue string, candidates []directDaxPlacementCandidate) (directDaxPlacement, bool, error) {
	for _, candidate := range candidates {
		stateDir := directWriterShardAllocatorDir(root, writerID, candidate.shard.ShardID)
		record, err := loadDirectWriterShardExtent(directWriterShardExtentPath(stateDir, checkpointIDValue))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return directDaxPlacement{}, false, err
		}
		if record.LengthPages < candidate.lengthPages {
			return directDaxPlacement{}, false, fmt.Errorf(
				"existing dax extent for checkpoint %q on shard %q is too small: have %d pages, need %d",
				checkpointIDValue,
				candidate.shard.ShardID,
				record.LengthPages,
				candidate.lengthPages)
		}
		return directDaxPlacement{
			CheckpointID:    checkpointIDValue,
			WriterID:        writerID,
			ShardID:         candidate.shard.ShardID,
			DaxDevice:       candidate.shard.DaxDevice,
			DaxStartPage:    record.StartPage,
			DaxLengthPages:  record.LengthPages,
			PageSize:        candidate.pageSize,
			Layout:          directDaxPlacementLayoutContiguous,
			State:           "COMMITTED",
			UpdatedAt:       time.Now().UTC(),
			NewReservation:  false,
			WriterStateRoot: root,
		}, true, nil
	}
	return directDaxPlacement{}, false, nil
}

func resolveDirectRoundRobinDaxPlacement(root, writerID, checkpointIDValue, imagePath string, candidates []directDaxPlacementCandidate) (directDaxPlacement, error) {
	if strings.TrimSpace(root) == "" {
		return directDaxPlacement{}, errors.New("writer selector state root is empty")
	}
	selectorDir := directWriterShardSelectorDir(root, writerID)
	if err := os.MkdirAll(selectorDir, 0o755); err != nil {
		return directDaxPlacement{}, err
	}
	lockFile, err := os.OpenFile(filepath.Join(selectorDir, "selector.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return directDaxPlacement{}, err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return directDaxPlacement{}, err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	shardIDs := directCandidateShardIDs(candidates)
	state, err := loadDirectWriterShardSelectorState(directWriterShardSelectorPath(root, writerID), writerID, shardIDs)
	if err != nil {
		return directDaxPlacement{}, err
	}
	ordered := rotateDirectDaxPlacementCandidates(candidates, state.NextIndex)
	placement, err := allocateDirectDaxPlacementInOrder(root, writerID, checkpointIDValue, imagePath, ordered)
	if err != nil {
		return directDaxPlacement{}, err
	}
	selectedIndex := directCandidateIndexByShardID(candidates, placement.ShardID)
	if selectedIndex >= 0 {
		state.WriterID = writerID
		state.Policy = directDaxPlacementPolicyRoundRobin
		state.ShardIDs = shardIDs
		state.NextIndex = (selectedIndex + 1) % len(candidates)
		state.UpdatedAt = time.Now().UTC()
		if err := writeDirectJSONFileAtomic(directWriterShardSelectorPath(root, writerID), state); err != nil {
			rollbackDirectDaxPlacementReservation(placement)
			return directDaxPlacement{}, err
		}
	}
	return placement, nil
}

func directDefaultWriterStateRoot(imagePath string) string {
	checkpointRoot := filepath.Dir(filepath.Clean(imagePath))
	checkpointsDir := filepath.Dir(checkpointRoot)
	if filepath.Base(checkpointsDir) == "checkpoints" {
		return filepath.Join(filepath.Dir(checkpointsDir), "writers")
	}
	return filepath.Join(checkpointRoot, "writers")
}

func directDaxDeviceGeometry(daxDevice string, pageSize int64) (int64, int64, error) {
	if pageSize <= 0 {
		pageSize = int64(os.Getpagesize())
	}
	deviceName := filepath.Base(strings.TrimSpace(daxDevice))
	if deviceName == "" || deviceName == "." || deviceName == string(os.PathSeparator) {
		return 0, 0, fmt.Errorf("invalid DAX device %q", daxDevice)
	}
	if info, err := os.Stat(daxDevice); err == nil && info.Mode().IsRegular() {
		if info.Size() < pageSize || info.Size()%pageSize != 0 {
			return 0, 0, fmt.Errorf("DAX backing file %q size %d is not page aligned", daxDevice, info.Size())
		}
		return info.Size() / pageSize, 1, nil
	}
	deviceDir, err := directDaxDeviceSysfsDir(deviceName)
	if err != nil {
		return 0, 0, err
	}
	sizeBytes, err := directReadSysfsUint(filepath.Join(deviceDir, "size"))
	if err != nil {
		return 0, 0, fmt.Errorf("read dax size for %q: %w", daxDevice, err)
	}
	alignBytes, err := directReadSysfsUint(filepath.Join(deviceDir, "align"))
	if err != nil {
		return 0, 0, fmt.Errorf("read dax align for %q: %w", daxDevice, err)
	}
	if alignBytes < uint64(pageSize) {
		alignBytes = uint64(pageSize)
	}
	if sizeBytes < uint64(pageSize) {
		return 0, 0, fmt.Errorf("dax device %q is smaller than page size: size=%d pageSize=%d", daxDevice, sizeBytes, pageSize)
	}
	if sizeBytes%uint64(pageSize) != 0 {
		return 0, 0, fmt.Errorf("dax device %q size %d is not page aligned", daxDevice, sizeBytes)
	}
	if alignBytes%uint64(pageSize) != 0 {
		return 0, 0, fmt.Errorf("dax device %q align %d is not page aligned", daxDevice, alignBytes)
	}
	return int64(sizeBytes) / pageSize, int64(alignBytes) / pageSize, nil
}

func directDaxDeviceSysfsDir(deviceName string) (string, error) {
	candidates := []string{
		filepath.Join("/sys/bus/dax/devices", deviceName),
		filepath.Join("/sys/class/dax", deviceName),
	}
	for _, candidate := range candidates {
		if pathExists(filepath.Join(candidate, "size")) && pathExists(filepath.Join(candidate, "align")) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no sysfs dax geometry found for %q", deviceName)
}

func directReadSysfsUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(string(data)), 0, 64)
}

func allocateDirectWriterShardDaxPages(root, writerID, shardID, checkpointIDValue, imagePath string, devicePages, alignPages, lengthPages int64) (int64, error) {
	startPage, _, err := allocateDirectWriterShardDaxPagesWithResult(root, writerID, shardID, checkpointIDValue, imagePath, devicePages, alignPages, lengthPages)
	return startPage, err
}

func allocateDirectWriterShardDaxPagesWithResult(root, writerID, shardID, checkpointIDValue, imagePath string, devicePages, alignPages, lengthPages int64) (int64, bool, error) {
	if strings.TrimSpace(root) == "" {
		return 0, false, errors.New("writer allocator state root is empty")
	}
	if strings.TrimSpace(writerID) == "" {
		return 0, false, errors.New("writer id is empty")
	}
	if strings.TrimSpace(shardID) == "" {
		return 0, false, errors.New("shard id is empty")
	}
	if strings.TrimSpace(checkpointIDValue) == "" {
		return 0, false, errors.New("checkpoint id is empty")
	}
	if devicePages <= 0 {
		return 0, false, fmt.Errorf("invalid dax device size %d pages", devicePages)
	}
	if alignPages <= 0 {
		return 0, false, fmt.Errorf("invalid dax alignment %d pages", alignPages)
	}
	if lengthPages <= 0 {
		return 0, false, fmt.Errorf("invalid dax reservation length %d pages", lengthPages)
	}
	if lengthPages > devicePages {
		return 0, false, fmt.Errorf("requested dax reservation %d pages exceeds device capacity %d pages", lengthPages, devicePages)
	}

	stateDir := directWriterShardAllocatorDir(root, writerID, shardID)
	extentsDir := filepath.Join(stateDir, "extents")
	if err := os.MkdirAll(extentsDir, 0o755); err != nil {
		return 0, false, err
	}

	lockFile, err := os.OpenFile(filepath.Join(stateDir, "allocator.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return 0, false, err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return 0, false, err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	extentPath := directWriterShardExtentPath(stateDir, checkpointIDValue)
	if record, err := loadDirectWriterShardExtent(extentPath); err == nil {
		if record.LengthPages < lengthPages {
			return 0, false, fmt.Errorf("existing dax extent for checkpoint %q is too small: have %d pages, need %d", checkpointIDValue, record.LengthPages, lengthPages)
		}
		return record.StartPage, true, nil
	} else if !os.IsNotExist(err) {
		return 0, false, err
	}

	statePath := filepath.Join(stateDir, "allocator.json")
	state, err := loadDirectWriterShardAllocatorState(statePath, writerID, shardID, devicePages, alignPages)
	if err != nil {
		return 0, false, err
	}
	startPage := roundUpInt64(state.NextFreePage, alignPages)
	if startPage+lengthPages > devicePages {
		return 0, false, fmt.Errorf(
			"%w: no free append-only dax reservation for checkpoint %q (next=%d devicePages=%d alignPages=%d lengthPages=%d)",
			errDirectDaxShardFull,
			checkpointIDValue,
			state.NextFreePage,
			devicePages,
			alignPages,
			lengthPages)
	}

	now := time.Now().UTC()
	state.WriterID = writerID
	state.ShardID = shardID
	state.DevicePages = devicePages
	state.AlignPages = alignPages
	state.NextFreePage = startPage + lengthPages
	state.UpdatedAt = now
	record := directWriterShardExtentRecord{
		CheckpointID: checkpointIDValue,
		ExtentType:   directDaxExtentType(checkpointIDValue),
		ImagePath:    imagePath,
		StartPage:    startPage,
		LengthPages:  lengthPages,
		UpdatedAt:    now,
	}
	if err := writeDirectJSONFileAtomic(statePath, state); err != nil {
		return 0, false, err
	}
	if err := writeDirectJSONFileAtomic(extentPath, record); err != nil {
		return 0, false, err
	}
	return startPage, false, nil
}

func directDaxExtentType(allocationID string) string {
	if strings.HasSuffix(allocationID, directArtifactAllocationID) {
		return "artifact"
	}
	return "page"
}

func rollbackDirectDaxPlacementReservation(placement directDaxPlacement) {
	if err := rollbackDirectDaxPlacementReservationErr(placement); err != nil {
		fmt.Fprintf(os.Stderr, "%s: rollback dax reservation skipped: %v\n", daemonName, err)
	}
}

func rollbackDirectDaxPlacementReservationErr(placement directDaxPlacement) error {
	if !placement.NewReservation {
		return nil
	}
	root := strings.TrimSpace(placement.WriterStateRoot)
	if root == "" {
		return errors.New("writer state root is empty")
	}
	if strings.TrimSpace(placement.WriterID) == "" || strings.TrimSpace(placement.ShardID) == "" || strings.TrimSpace(placement.CheckpointID) == "" {
		return errors.New("placement identity is incomplete")
	}
	if placement.DaxLengthPages <= 0 || placement.DaxStartPage < 0 {
		return errors.New("placement range is invalid")
	}

	stateDir := directWriterShardAllocatorDir(root, placement.WriterID, placement.ShardID)
	lockFile, err := os.OpenFile(filepath.Join(stateDir, "allocator.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	extentPath := directWriterShardExtentPath(stateDir, placement.CheckpointID)
	record, err := loadDirectWriterShardExtent(extentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if record.StartPage != placement.DaxStartPage || record.LengthPages != placement.DaxLengthPages {
		return fmt.Errorf("extent no longer matches placement for checkpoint %q", placement.CheckpointID)
	}

	statePath := filepath.Join(stateDir, "allocator.json")
	state, err := loadDirectWriterShardAllocatorStateForRollback(statePath, placement.WriterID, placement.ShardID)
	if err != nil {
		return err
	}
	expectedNext := placement.DaxStartPage + placement.DaxLengthPages
	if state.NextFreePage != expectedNext {
		return fmt.Errorf("reservation is not allocator tail: next=%d expected=%d", state.NextFreePage, expectedNext)
	}

	if err := os.Remove(extentPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	state.NextFreePage = placement.DaxStartPage
	state.UpdatedAt = time.Now().UTC()
	return writeDirectJSONFileAtomic(statePath, state)
}

func directWriterShardAllocatorDir(root, writerID, shardID string) string {
	return filepath.Join(root, directSafePathSegment(writerID), "shards", directSafePathSegment(shardID))
}

func directWriterShardSelectorDir(root, writerID string) string {
	return filepath.Join(root, directSafePathSegment(writerID))
}

func directWriterShardSelectorPath(root, writerID string) string {
	return filepath.Join(directWriterShardSelectorDir(root, writerID), "selector.json")
}

func directWriterShardExtentPath(stateDir, checkpointIDValue string) string {
	return filepath.Join(stateDir, "extents", directSafePathSegment(checkpointIDValue)+".json")
}

func loadDirectWriterShardExtent(path string) (directWriterShardExtentRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return directWriterShardExtentRecord{}, err
	}
	var record directWriterShardExtentRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return directWriterShardExtentRecord{}, err
	}
	if record.StartPage < 0 || record.LengthPages <= 0 {
		return directWriterShardExtentRecord{}, fmt.Errorf("invalid dax extent record at %q", path)
	}
	return record, nil
}

func loadDirectWriterShardAllocatorState(path, writerID, shardID string, devicePages, alignPages int64) (directWriterShardAllocatorState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return directWriterShardAllocatorState{
				WriterID:     writerID,
				ShardID:      shardID,
				DevicePages:  devicePages,
				AlignPages:   alignPages,
				NextFreePage: 0,
			}, nil
		}
		return directWriterShardAllocatorState{}, err
	}
	var state directWriterShardAllocatorState
	if err := json.Unmarshal(data, &state); err != nil {
		return directWriterShardAllocatorState{}, err
	}
	if state.WriterID != writerID {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator writer id mismatch: state=%q requested=%q", state.WriterID, writerID)
	}
	if state.ShardID != shardID {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator shard id mismatch: state=%q requested=%q", state.ShardID, shardID)
	}
	if state.DevicePages != devicePages {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator device size changed: state=%d requested=%d pages", state.DevicePages, devicePages)
	}
	if state.AlignPages != alignPages {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator alignment changed: state=%d requested=%d pages", state.AlignPages, alignPages)
	}
	if state.NextFreePage < 0 {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator next free page is invalid: %d", state.NextFreePage)
	}
	return state, nil
}

func loadDirectWriterShardAllocatorStateForRollback(path, writerID, shardID string) (directWriterShardAllocatorState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return directWriterShardAllocatorState{}, err
	}
	var state directWriterShardAllocatorState
	if err := json.Unmarshal(data, &state); err != nil {
		return directWriterShardAllocatorState{}, err
	}
	if state.WriterID != writerID {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator writer id mismatch: state=%q requested=%q", state.WriterID, writerID)
	}
	if state.ShardID != shardID {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator shard id mismatch: state=%q requested=%q", state.ShardID, shardID)
	}
	if state.NextFreePage < 0 {
		return directWriterShardAllocatorState{}, fmt.Errorf("allocator next free page is invalid: %d", state.NextFreePage)
	}
	return state, nil
}

func loadDirectWriterShardSelectorState(path, writerID string, shardIDs []string) (directWriterShardSelectorState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return directWriterShardSelectorState{
				WriterID:  writerID,
				Policy:    directDaxPlacementPolicyRoundRobin,
				ShardIDs:  shardIDs,
				NextIndex: 0,
			}, nil
		}
		return directWriterShardSelectorState{}, err
	}
	var state directWriterShardSelectorState
	if err := json.Unmarshal(data, &state); err != nil {
		return directWriterShardSelectorState{}, err
	}
	if state.WriterID != writerID || state.Policy != directDaxPlacementPolicyRoundRobin || !sameDirectStringSlice(state.ShardIDs, shardIDs) {
		return directWriterShardSelectorState{
			WriterID:  writerID,
			Policy:    directDaxPlacementPolicyRoundRobin,
			ShardIDs:  shardIDs,
			NextIndex: 0,
		}, nil
	}
	if state.NextIndex < 0 || state.NextIndex >= len(shardIDs) {
		state.NextIndex = 0
	}
	return state, nil
}

func directCandidateShardIDs(candidates []directDaxPlacementCandidate) []string {
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.shard.ShardID)
	}
	return ids
}

func rotateDirectDaxPlacementCandidates(candidates []directDaxPlacementCandidate, start int) []directDaxPlacementCandidate {
	if len(candidates) == 0 {
		return nil
	}
	if start < 0 || start >= len(candidates) {
		start = 0
	}
	ordered := make([]directDaxPlacementCandidate, 0, len(candidates))
	ordered = append(ordered, candidates[start:]...)
	ordered = append(ordered, candidates[:start]...)
	return ordered
}

func directCandidateIndexByShardID(candidates []directDaxPlacementCandidate, shardID string) int {
	for i, candidate := range candidates {
		if candidate.shard.ShardID == shardID {
			return i
		}
	}
	return -1
}

func sameDirectStringSlice(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func directSafePathSegment(value string) string {
	trimmed := strings.TrimSpace(value)
	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '.', r == '_', r == '-':
			builder.WriteRune(r)
		default:
			builder.WriteByte('_')
		}
	}
	safe := builder.String()
	if safe == "" || safe == "." || safe == ".." {
		safe = "id"
	}
	pathHash := fnv.New64a()
	_, _ = pathHash.Write([]byte(trimmed))
	return fmt.Sprintf("%s-%012x", safe, pathHash.Sum64()&0xffffffffffff)
}

func writeDirectJSONFileAtomic(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func runDirectCriuConvert(ctx context.Context, req checkpointRequest, state trenvContainerState, placement directDaxPlacement) error {
	mntNsFile, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", state.PID))
	if err != nil {
		return fmt.Errorf("open mount namespace for checkpoint convert: %w", err)
	}
	defer mntNsFile.Close()
	pseudoMMDrv, err := os.OpenFile(directPseudoMMPath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open %s for checkpoint convert: %w", directPseudoMMPath, err)
	}
	defer pseudoMMDrv.Close()

	args := []string{
		"convert",
		"-D",
		req.ImagePath,
		"-W",
		req.WorkPath,
		"-v4",
		"-o",
		filepath.Join(req.WorkPath, "convert.log"),
		"--inherit-fd",
		"fd[3]:switch-ns-mnt",
		"--inherit-fd",
		fmt.Sprintf("fd[4]:%s", directPseudoMMInheritID),
		"--mem-pool",
		"dax",
		"--dax-device",
		placement.DaxDevice,
		"--dax-pgoff",
		strconv.FormatInt(placement.DaxStartPage, 10),
		"--tcp-close",
	}
	cmd := exec.CommandContext(ctx, nonEmptyOrDefault(state.CriuBinary, "criu"), args...)
	cmd.ExtraFiles = []*os.File{mntNsFile, pseudoMMDrv}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("criu convert failed: %s", commandErrorString(err, stderr.String()+"\n"+stdout.String()))
	}
	return nil
}

func readDirectConvertPageCount(imagePath string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(imagePath, "convert-pgnum.img"))
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, err
	}
	if value < 0 {
		return 0, fmt.Errorf("invalid convert page count %d", value)
	}
	return value, nil
}

func directCheckpointPagePayload(imagePath string, pageSize int64) (int64, int64) {
	matches, err := filepath.Glob(filepath.Join(imagePath, "pages-*.img"))
	if err != nil {
		return 0, 0
	}
	if pathExists(filepath.Join(imagePath, "pages.img")) {
		matches = append(matches, filepath.Join(imagePath, "pages.img"))
	}
	var total int64
	for _, match := range matches {
		info, err := os.Stat(match)
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	if pageSize <= 0 {
		pageSize = int64(os.Getpagesize())
	}
	return total, roundUpInt64(total, pageSize) / pageSize
}

func roundUpInt64(value, align int64) int64 {
	if align <= 0 || value <= 0 {
		return value
	}
	remainder := value % align
	if remainder == 0 {
		return value
	}
	return value + align - remainder
}

func writeDirectMetadataBundle(imagePath, bundlePath string, placement directDaxPlacement) error {
	if err := os.RemoveAll(bundlePath); err != nil {
		return err
	}
	imageBundlePath := filepath.Join(bundlePath, "image")
	if err := os.MkdirAll(imageBundlePath, 0o755); err != nil {
		return err
	}
	var files []directMetadataBundleFile
	err := filepath.Walk(imagePath, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(imagePath, sourcePath)
		if err != nil {
			return err
		}
		if !isDirectReaderMetadataFile(relative) {
			return nil
		}
		targetPath := filepath.Join(imageBundlePath, relative)
		if err := copyFile(sourcePath, targetPath, info.Mode().Perm()); err != nil {
			return err
		}
		files = append(files, directMetadataBundleFile{
			Path: filepath.ToSlash(filepath.Join("image", relative)),
			Size: info.Size(),
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	portablePlacement := placement
	portablePlacement.DaxDevice = ""
	if err := writeJSONFile(filepath.Join(bundlePath, "placement.json"), portablePlacement); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(bundlePath, "bundle.json"), directMetadataBundleManifest{
		CheckpointID: placement.CheckpointID,
		ImagePath:    "image",
		Placement:    "placement.json",
		Files:        files,
		CreatedAt:    time.Now().UTC(),
	})
}

func isDirectReaderMetadataFile(relativePath string) bool {
	base := filepath.Base(relativePath)
	if matched, _ := filepath.Match("pages-*.img", base); matched {
		return false
	}
	if matched, _ := filepath.Match("pseudo_mm_id-*", base); matched {
		return false
	}
	return base != "pages.img" && base != "cgroup.img"
}

func exportDirectActionRoots(rootfs, exportRoot string, roots []string) error {
	if len(roots) == 0 {
		return nil
	}
	for _, root := range roots {
		relative, err := directContainerSubpath(root)
		if err != nil {
			return err
		}
		sourcePath := filepath.Join(rootfs, relative)
		if _, err := os.Stat(sourcePath); err != nil {
			return fmt.Errorf("stat action export root %q: %w", sourcePath, err)
		}
		targetPath := filepath.Join(exportRoot, relative)
		if err := os.RemoveAll(targetPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := copyTree(sourcePath, targetPath); err != nil {
			return fmt.Errorf("export %q -> %q: %w", sourcePath, targetPath, err)
		}
	}
	return nil
}

func exportDirectRuntimeRootfsState(rootfs, workPath, metadataBundlePath string) error {
	if strings.TrimSpace(workPath) == "" || strings.TrimSpace(metadataBundlePath) == "" {
		return nil
	}
	paths, err := directRuntimeRootfsStatePaths(filepath.Join(workPath, "dump.log"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	exportRoot := filepath.Join(metadataBundlePath, directRootfsStateDirectoryName)
	if err := os.RemoveAll(exportRoot); err != nil {
		return err
	}
	for _, guestPath := range paths {
		relative, err := directContainerSubpath(guestPath)
		if err != nil {
			return err
		}
		sourcePath := filepath.Join(rootfs, relative)
		info, err := os.Stat(sourcePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat runtime rootfs state %q: %w", sourcePath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		targetPath := filepath.Join(exportRoot, relative)
		if err := copyFile(sourcePath, targetPath, info.Mode().Perm()); err != nil {
			return fmt.Errorf("export runtime rootfs state %q -> %q: %w", sourcePath, targetPath, err)
		}
	}
	return nil
}

func directRuntimeRootfsStatePaths(dumpLogPath string) ([]string, error) {
	data, err := os.ReadFile(dumpLogPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		fd, guestPath, ok := parseDirectDumpedRegularPath(line)
		if !ok || fd < 0 || !shouldExportDirectRuntimeRootfsPath(guestPath) {
			continue
		}
		if _, exists := seen[guestPath]; exists {
			continue
		}
		seen[guestPath] = struct{}{}
		paths = append(paths, guestPath)
	}
	sort.Strings(paths)
	return paths, nil
}

func parseDirectDumpedRegularPath(line string) (int, string, bool) {
	const marker = "Dumping path for "
	idx := strings.Index(line, marker)
	if idx < 0 {
		return 0, "", false
	}
	rest := line[idx+len(marker):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0, "", false
	}
	fd, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", false
	}
	start := strings.LastIndex(line, "[/")
	end := strings.LastIndex(line, "]")
	if start < 0 || end <= start {
		return 0, "", false
	}
	return fd, line[start+1 : end], true
}

func shouldExportDirectRuntimeRootfsPath(path string) bool {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(os.PathSeparator) {
		return false
	}
	staticPrefixes := []string{"/bin", "/boot", "/dev", "/etc", "/home/app", "/lib", "/lib64", "/opt", "/proc", "/run", "/sbin", "/sys", "/usr"}
	for _, prefix := range staticPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return false
		}
	}
	return true
}

func writeDirectPublication(ctx context.Context, req checkpointRequest, placement directDaxPlacement, config daemonConfig, pageExtent, artifactExtent trenvpub.StorageExtent, artifactFiles []trenvpub.ArtifactFile) error {
	publication := req.Publication
	if publication == nil {
		return nil
	}
	publicationPath := trenvpub.NormalizePath(strings.TrimSpace(publication.PublicationPath))
	if publicationPath == "" {
		return errors.New("publication path is empty")
	}
	if config.WriterEpoch == 0 {
		return errors.New("writer epoch must be non-zero for a v5 publication")
	}
	bundleSize, err := directoryRegularFileSize(req.MetadataBundlePath)
	if err != nil {
		return err
	}
	createdAt := time.Now().UTC()
	record := metadataPublicationRecord{
		Version:                    int(trenvpub.Version),
		ArtifactID:                 placement.CheckpointID,
		CheckpointID:               placement.CheckpointID,
		ManifestSchema:             trenvpub.ManifestSchema,
		Generation:                 uint64(createdAt.UnixNano()),
		WriterEpoch:                config.WriterEpoch,
		State:                      "COMMITTED",
		CheckpointPhase:            strings.TrimSpace(publication.CheckpointPhase),
		Fingerprint:                strings.TrimSpace(publication.Fingerprint),
		SnapshotStartMode:          strings.TrimSpace(publication.SnapshotStartMode),
		RuntimeKind:                strings.TrimSpace(publication.RuntimeKind),
		RuntimeFamily:              strings.TrimSpace(publication.RuntimeFamily),
		CheckpointPath:             req.ImagePath,
		MetadataBundlePath:         req.MetadataBundlePath,
		PlacementPath:              filepath.Join(req.MetadataBundlePath, "placement.json"),
		CheckpointActionExportRoot: strings.TrimSpace(publication.CheckpointActionExportRoot),
		MetadataBundleSize:         bundleSize,
		PageExtent:                 pageExtent,
		ArtifactExtent:             artifactExtent,
		Files:                      append([]trenvpub.ArtifactFile(nil), artifactFiles...),
		WriterID:                   placement.WriterID,
		ShardID:                    placement.ShardID,
		DaxDevice:                  placement.DaxDevice,
		DaxStartPage:               placement.DaxStartPage,
		DaxLengthPages:             placement.DaxLengthPages,
		PageCount:                  placement.PageCount,
		PageSize:                   placement.PageSize,
		Layout:                     placement.Layout,
		Shards: []trenvpub.Shard{{
			WriterID:       placement.WriterID,
			ShardID:        placement.ShardID,
			DaxDevice:      placement.DaxDevice,
			DaxStartPage:   placement.DaxStartPage,
			DaxLengthPages: placement.DaxLengthPages,
			PageCount:      placement.PageCount,
			PageSize:       placement.PageSize,
			Layout:         placement.Layout,
		}},
		CreatedAt: createdAt,
	}
	if publication.ActionNamespace != "" || publication.ActionName != "" || publication.ActionRevision != "" {
		record.ActionIdentity = &metadataPublicationActionIdentity{
			Namespace:          strings.TrimSpace(publication.ActionNamespace),
			FullyQualifiedName: strings.TrimSpace(publication.ActionName),
			Revision:           strings.TrimSpace(publication.ActionRevision),
		}
	}
	if filepath.Ext(publicationPath) == trenvpub.Extension {
		if config.DedupCheckpointMode == "sync-required" {
			if len(record.Shards) != 1 {
				return fmt.Errorf(
					"sync-required dedup supports exactly one page shard, got %d",
					len(record.Shards))
			}
			baseDirectory := filepath.Join(
				dedupWorkDirectory(config),
				"base-staging",
				sanitizePathPart(record.ArtifactID))
			if err := os.MkdirAll(baseDirectory, 0o755); err != nil {
				return err
			}
			basePath := filepath.Join(
				baseDirectory,
				fmt.Sprintf("base-%d%s", record.Generation, trenvpub.Extension))
			if err := trenvpub.WriteFileNoReplace(basePath, publicationRecordToBinary(record)); err != nil {
				return err
			}
			baseRecord := record
			baseRecord.PublicationPath = basePath
			dedupContext := ctx
			cancel := func() {}
			if config.DedupTimeout > 0 {
				dedupContext, cancel = context.WithTimeout(ctx, config.DedupTimeout)
			}
			defer cancel()
			if err := runDedupPublication(
				dedupContext,
				config,
				baseRecord,
				"checkpoint-sync-required",
				publicationPath); err != nil {
				return fmt.Errorf("required checkpoint dedup rejected: %w", err)
			}
			return nil
		}
		return trenvpub.WriteFileNoReplace(publicationPath, publicationRecordToBinary(record))
	}
	if config.DedupCheckpointMode == "sync-required" {
		return errors.New("sync-required dedup needs a binary .trpub publication path")
	}
	return writeDirectJSONFileNoReplace(publicationPath, record)
}

func writeDirectJSONFileNoReplace(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if pathExists(path) {
		return fmt.Errorf("publication metadata already exists at %q", path)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("publication metadata already exists at %q", path)
		}
		return err
	}
	return nil
}

func directContainerSubpath(root string) (string, error) {
	clean := filepath.Clean(root)
	relative := strings.TrimPrefix(clean, string(os.PathSeparator))
	if relative == "" || relative == "." {
		return "", fmt.Errorf("invalid container path %q", root)
	}
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == ".." {
			return "", fmt.Errorf("invalid container path %q", root)
		}
	}
	return relative, nil
}
