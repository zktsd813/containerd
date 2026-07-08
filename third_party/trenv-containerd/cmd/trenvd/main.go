package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

type daemonRequest struct {
	CommandLabel    string                    `json:"commandLabel"`
	TimeoutMillis   int64                     `json:"timeoutMillis"`
	Operation       string                    `json:"operation"`
	CreateContainer *createContainerRequest   `json:"createContainer,omitempty"`
	Checkpoint      *checkpointRequest        `json:"checkpointContainer,omitempty"`
	Restore         *switchRequest            `json:"restoreIntoContainer,omitempty"`
	Switch          *switchRequest            `json:"switchIntoCandidate,omitempty"`
	Container       *containerRequest         `json:"container,omitempty"`
	Cleanup         *cleanupContainersRequest `json:"cleanupContainers,omitempty"`
	MetadataResolve *metadataResolveRequest   `json:"metadataResolve,omitempty"`
}

// A structured checkpoint request is preferred over allowing the invoker to
// execute helper binaries. trenvd owns DAX placement, publication commit, and
// action-root export so those host-side decisions stay outside the invoker
// container.
type checkpointRequest struct {
	ImagePath          string                        `json:"imagePath"`
	WorkPath           string                        `json:"workPath"`
	MetadataBundlePath string                        `json:"metadataBundlePath"`
	ActionExportRoots  []string                      `json:"actionExportRoots"`
	ReservationBytes   int64                         `json:"reservationBytes"`
	Publication        *checkpointPublicationRequest `json:"publication,omitempty"`
	ContainerID        string                        `json:"containerId"`
}

type checkpointPublicationRequest struct {
	PublicationPath            string `json:"publicationPath"`
	RuntimeKind                string `json:"runtimeKind,omitempty"`
	RuntimeFamily              string `json:"runtimeFamily,omitempty"`
	ActionNamespace            string `json:"actionNamespace,omitempty"`
	ActionName                 string `json:"actionName,omitempty"`
	ActionRevision             string `json:"actionRevision,omitempty"`
	CheckpointPhase            string `json:"checkpointPhase,omitempty"`
	Fingerprint                string `json:"fingerprint,omitempty"`
	SnapshotStartMode          string `json:"snapshotStartMode,omitempty"`
	CheckpointActionExportRoot string `json:"checkpointActionExportRoot,omitempty"`
}

type switchRequest struct {
	CheckpointPath              string           `json:"checkpointPath"`
	DaxDevice                   string           `json:"daxDevice,omitempty"`
	DaxDeviceFallback           string           `json:"-"`
	ReaderDaxShards             []daxShardConfig `json:"-"`
	SourceContainer             string           `json:"sourceContainer,omitempty"`
	ActionSourceRootfs          string           `json:"actionSourceRootfs,omitempty"`
	ShellID                     string           `json:"shellId,omitempty"`
	CompatibilityClass          string           `json:"compatibilityClass,omitempty"`
	ActiveRuntimeKind           string           `json:"activeRuntimeKind,omitempty"`
	ActiveRuntimeFamily         string           `json:"activeRuntimeFamily,omitempty"`
	StableActionRoot            string           `json:"stableActionRoot,omitempty"`
	PseudoMMMaterializationRoot string           `json:"-"`
	ActionRebinds               []actionRebind   `json:"actionRebinds"`
	NullIO                      bool             `json:"nullIO"`
	PidFile                     string           `json:"pidFile,omitempty"`
	ContainerID                 string           `json:"containerId"`
}

type actionRebind struct {
	SourceRoot string `json:"sourceRoot"`
	TargetRoot string `json:"targetRoot"`
}

type execResponse struct {
	Ok             bool             `json:"ok"`
	Stdout         string           `json:"stdout"`
	Stderr         string           `json:"stderr"`
	ExitCode       int              `json:"exitCode"`
	Error          string           `json:"error"`
	Operation      string           `json:"operation,omitempty"`
	DurationMicros int64            `json:"durationMicros,omitempty"`
	TimingsMicros  map[string]int64 `json:"timingsMicros,omitempty"`
}

type metadataResolveRequest struct {
	Fingerprint     string `json:"fingerprint"`
	RuntimeKind     string `json:"runtimeKind,omitempty"`
	RuntimeFamily   string `json:"runtimeFamily,omitempty"`
	ActionNamespace string `json:"actionNamespace,omitempty"`
	ActionName      string `json:"actionName,omitempty"`
	ActionRevision  string `json:"actionRevision,omitempty"`
	ReaderContainer string `json:"readerContainer"`
}

type metadataResolveResponse struct {
	Found                      bool   `json:"found"`
	CheckpointID               string `json:"checkpoint_id,omitempty"`
	SnapshotStartMode          string `json:"snapshot_start_mode,omitempty"`
	CheckpointPath             string `json:"checkpoint_path,omitempty"`
	MetadataBundlePath         string `json:"metadata_bundle_path,omitempty"`
	PlacementPath              string `json:"placement_path,omitempty"`
	CheckpointActionExportRoot string `json:"checkpoint_action_export_root,omitempty"`
	PublicationPath            string `json:"publication_path,omitempty"`
	Fingerprint                string `json:"fingerprint,omitempty"`
	Source                     string `json:"source,omitempty"`
	CreatedAt                  string `json:"created_at,omitempty"`
}

type metadataPublicationActionIdentity struct {
	Namespace          string `json:"namespace"`
	FullyQualifiedName string `json:"fully_qualified_name"`
	Revision           string `json:"revision"`
}

type metadataPublicationRecord struct {
	Version                    int                                `json:"version"`
	ArtifactID                 string                             `json:"artifact_id"`
	CheckpointID               string                             `json:"checkpoint_id"`
	State                      string                             `json:"state"`
	CheckpointPhase            string                             `json:"checkpoint_phase,omitempty"`
	Fingerprint                string                             `json:"fingerprint,omitempty"`
	SnapshotStartMode          string                             `json:"snapshot_start_mode,omitempty"`
	RuntimeKind                string                             `json:"runtime_kind,omitempty"`
	RuntimeFamily              string                             `json:"runtime_family,omitempty"`
	ActionIdentity             *metadataPublicationActionIdentity `json:"action_identity,omitempty"`
	CheckpointPath             string                             `json:"checkpoint_path"`
	MetadataBundlePath         string                             `json:"metadata_bundle_path"`
	PlacementPath              string                             `json:"placement_path"`
	CheckpointActionExportRoot string                             `json:"checkpoint_action_export_root,omitempty"`
	MetadataBundleSize         int64                              `json:"metadata_bundle_size"`
	MetadataBundleSHA256       string                             `json:"metadata_bundle_sha256"`
	WriterID                   string                             `json:"writer_id"`
	ShardID                    string                             `json:"shard_id"`
	DaxDevice                  string                             `json:"dax_device"`
	DaxStartPage               int64                              `json:"dax_start_page"`
	DaxLengthPages             int64                              `json:"dax_length_pages"`
	PageCount                  int64                              `json:"page_count"`
	PageSize                   int64                              `json:"page_size"`
	Layout                     string                             `json:"layout"`
	Shards                     []trenvpub.Shard                   `json:"shards,omitempty"`
	BaseRestoreMap             []trenvpub.RestoreExtent           `json:"base_restore_map,omitempty"`
	DedupDelta                 []trenvpub.RestoreExtent           `json:"dedup_delta,omitempty"`
	Stats                      trenvpub.Stats                     `json:"stats,omitempty"`
	CreatedAt                  time.Time                          `json:"created_at"`
	PublicationPath            string                             `json:"-"`
	PeerURL                    string                             `json:"-"`
}

type daemonConfig struct {
	WriterID                    string
	WriterStateRoot             string
	DaxDevice                   string
	ShardID                     string
	DaxShards                   []daxShardConfig
	ReaderDaxShards             []daxShardConfig
	DaxPlacementPolicy          string
	CheckpointWriterDisabled    bool
	WorkingDirectory            string
	MetadataListen              string
	MetadataPeers               []string
	PseudoMMMaterializationRoot string
	DedupInterval               time.Duration
	DedupOnCheckpoint           bool
	DedupTimeout                time.Duration
	DedupDedupdBinary           string
	DedupPublicationBinary      string
	DedupExecution              string
	DedupOutputDirectory        string
	DedupMinPages               uint64
}

type daxShardConfig struct {
	ShardID   string
	DaxDevice string
}

func (d daxShardConfig) String() string {
	if d.ShardID == "" {
		return d.DaxDevice
	}
	return d.ShardID + "=" + d.DaxDevice
}

var activeConfig daemonConfig
var dedupRunGate = make(chan struct{}, 1)

func writeFrame(conn net.Conn, payload []byte) error {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func runCommand(req daemonRequest) (resp execResponse) {
	startedAt := time.Now()
	operation := strings.TrimSpace(req.Operation)
	if operation == "" && req.CreateContainer != nil {
		operation = "createContainer"
	}
	if operation == "" && req.Checkpoint != nil {
		operation = "checkpointContainer"
	}
	if operation == "" && req.Restore != nil {
		operation = "restoreIntoContainer"
	}
	if operation == "" && req.Switch != nil {
		operation = "switchIntoCandidate"
	}
	if operation == "" && req.Container != nil {
		operation = "container"
	}
	if operation == "" && req.Cleanup != nil {
		operation = "cleanupContainers"
	}
	defer func() {
		resp.Operation = operation
		resp.DurationMicros = elapsedMicros(startedAt)
	}()

	switch operation {
	case "createContainer":
		if req.CreateContainer == nil {
			return execResponse{Ok: false, Error: "createContainer operation requires createContainer request"}
		}
		return runCreateContainerRequest(*req.CreateContainer, req.TimeoutMillis, activeConfig)
	case "checkpointContainer":
		if req.Checkpoint != nil {
			return runDirectCheckpointRequest(*req.Checkpoint, req.TimeoutMillis, activeConfig)
		}
		return execResponse{Ok: false, Error: "checkpointContainer operation requires checkpointContainer request"}
	case "restoreIntoContainer":
		if req.Restore == nil {
			return execResponse{Ok: false, Error: "restoreIntoContainer operation requires restoreIntoContainer request"}
		}
		return runDirectRestoreRequest(*req.Restore, req.TimeoutMillis, activeConfig)
	case "switchIntoCandidate":
		if req.Switch == nil {
			return execResponse{Ok: false, Error: "switchIntoCandidate operation requires switchIntoCandidate request"}
		}
		return runDirectSwitchRequest(*req.Switch, req.TimeoutMillis, activeConfig)
	case "pauseContainer", "resumeContainer", "removeContainer":
		if req.Container == nil {
			return execResponse{Ok: false, Error: fmt.Sprintf("%s operation requires container request", operation)}
		}
		return runContainerLifecycleRequest(operation, *req.Container, req.TimeoutMillis, activeConfig)
	case "cleanupContainers":
		if req.Cleanup == nil {
			return execResponse{Ok: false, Error: "cleanupContainers operation requires cleanupContainers request"}
		}
		return runCleanupContainersRequest(*req.Cleanup, req.TimeoutMillis, activeConfig)
	case "metadataResolve":
		if req.MetadataResolve == nil {
			return execResponse{Ok: false, Error: "metadataResolve operation requires metadataResolve request"}
		}
		return runMetadataResolveRequest(*req.MetadataResolve, req.TimeoutMillis, activeConfig)
	case "":
		return execResponse{Ok: false, Error: "operation is empty"}
	default:
		return execResponse{Ok: false, Error: fmt.Sprintf("unsupported operation %q", operation)}
	}
}

func runMetadataResolveRequest(req metadataResolveRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := time.Duration(timeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := resolveMetadata(ctx, req, config)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	return execResponse{Ok: true, Stdout: string(payload) + "\n"}
}

func resolveMetadata(ctx context.Context, req metadataResolveRequest, config daemonConfig) (metadataResolveResponse, error) {
	fingerprint := strings.TrimSpace(req.Fingerprint)
	if fingerprint == "" {
		return metadataResolveResponse{}, errors.New("metadata resolve fingerprint is empty")
	}
	readerContainer := strings.TrimSpace(req.ReaderContainer)
	if readerContainer == "" {
		return metadataResolveResponse{}, errors.New("metadata resolve reader container is empty")
	}

	publications, err := fetchPeerPublications(ctx, config.MetadataPeers, fingerprint)
	if err != nil {
		return metadataResolveResponse{}, err
	}
	if len(publications) == 0 {
		return metadataResolveResponse{Found: false}, nil
	}
	sort.Slice(publications, func(i, j int) bool {
		return publicationLess(publications[i], publications[j])
	})
	selected := publications[len(publications)-1]
	// The daemon returns reader-local paths. Remote writer paths are only used
	// to fetch the artifact; CRIU/runc must never restore from peer-local paths.
	cacheRoot, err := materializePeerArtifact(ctx, selected, readerContainer, config)
	if err != nil {
		return metadataResolveResponse{}, err
	}

	metadataBundlePath := filepath.Join(cacheRoot, "metadata-bundle")
	checkpointPath := filepath.Join(metadataBundlePath, "image")
	placementPath := filepath.Join(metadataBundlePath, "placement.json")
	actionRoot := filepath.Join(cacheRoot, "action-root")
	if !isDirectory(actionRoot) {
		actionRoot = ""
	}
	publicationPath := filepath.Join(cacheRoot, "publication.reader"+trenvpub.Extension)

	return metadataResolveResponse{
		Found:                      true,
		CheckpointID:               selected.CheckpointID,
		SnapshotStartMode:          nonEmptyOrDefault(selected.SnapshotStartMode, "restore"),
		CheckpointPath:             checkpointPath,
		MetadataBundlePath:         metadataBundlePath,
		PlacementPath:              placementPath,
		CheckpointActionExportRoot: actionRoot,
		PublicationPath:            publicationPath,
		Fingerprint:                selected.Fingerprint,
		Source:                     "publication-reader-network",
		CreatedAt:                  selected.CreatedAt.Format(time.RFC3339Nano),
	}, nil
}

func fetchPeerPublications(ctx context.Context, peers []string, fingerprint string) ([]metadataPublicationRecord, error) {
	normalizedPeers := normalizePeerURLs(peers)
	if len(normalizedPeers) == 0 {
		return nil, nil
	}
	var results []metadataPublicationRecord
	var failures []string
	client := &http.Client{}
	for _, peer := range normalizedPeers {
		endpoint := peer + "/v1/publications?fingerprint=" + url.QueryEscape(fingerprint)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", peer, err))
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				failures = append(failures, fmt.Sprintf("%s: status %s", peer, resp.Status))
				return
			}
			var publications []metadataPublicationRecord
			if err := json.NewDecoder(resp.Body).Decode(&publications); err != nil {
				failures = append(failures, fmt.Sprintf("%s: decode publications: %v", peer, err))
				return
			}
			for _, publication := range publications {
				if publication.State == "COMMITTED" && publication.Fingerprint == fingerprint {
					publication.PeerURL = peer
					results = append(results, publication)
				}
			}
		}()
	}
	if len(results) == 0 && len(failures) > 0 {
		return nil, fmt.Errorf("metadata publication fetch failed: %s", strings.Join(failures, "; "))
	}
	return results, nil
}

func materializePeerArtifact(ctx context.Context, publication metadataPublicationRecord, readerContainer string, config daemonConfig) (string, error) {
	if strings.TrimSpace(publication.PeerURL) == "" {
		return "", errors.New("selected publication is missing peer URL")
	}
	checkpointID := strings.TrimSpace(publication.CheckpointID)
	if checkpointID == "" {
		return "", errors.New("selected publication is missing checkpoint id")
	}
	cacheRoot := filepath.Join(config.WorkingDirectory, "reader-cache", publicationCacheKey(publication))
	cacheCommitted := filepath.Join(cacheRoot, "COMMITTED")
	if isRegularFile(cacheCommitted) {
		if err := materializeRestoreState(cacheRoot, checkpointID, readerContainer, publication, config); err != nil {
			return "", err
		}
		return filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(checkpointID)), nil
	}

	if err := os.MkdirAll(filepath.Join(config.WorkingDirectory, "reader-cache"), 0o755); err != nil {
		return "", err
	}
	stageRoot, err := os.MkdirTemp(filepath.Join(config.WorkingDirectory, "reader-cache"), publicationCacheKey(publication)+".tmp.")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stageRoot)

	if err := fetchArtifactTar(ctx, publication, stageRoot); err != nil {
		return "", err
	}
	if err := validateMaterializedArtifact(stageRoot, publication); err != nil {
		return "", err
	}
	// Commit by rename after validation so readers never observe a partially
	// extracted metadata bundle or action-root.
	if err := os.RemoveAll(cacheRoot); err != nil {
		return "", err
	}
	if err := os.Rename(stageRoot, cacheRoot); err != nil {
		return "", err
	}
	if err := writeReaderPublication(cacheRoot, publication); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(cacheRoot, "COMMITTED"), []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		return "", err
	}
	if err := materializeRestoreState(cacheRoot, checkpointID, readerContainer, publication, config); err != nil {
		return "", err
	}
	return filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(checkpointID)), nil
}

func publicationCacheKey(publication metadataPublicationRecord) string {
	key := strings.TrimSpace(publication.ArtifactID)
	if key == "" {
		key = strings.TrimSpace(publication.CheckpointID)
	}
	return sanitizePathPart(key)
}

func fetchArtifactTar(ctx context.Context, publication metadataPublicationRecord, target string) error {
	artifactID := strings.TrimSpace(publication.CheckpointID)
	if artifactID == "" {
		return errors.New("publication checkpoint id is empty")
	}
	endpoint := publication.PeerURL + "/v1/artifacts/" + url.PathEscape(artifactID) + ".tar"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch artifact %q failed: status %s", artifactID, resp.Status)
	}
	return extractTar(resp.Body, target)
}

func validateMaterializedArtifact(root string, publication metadataPublicationRecord) error {
	bundlePath := filepath.Join(root, "metadata-bundle")
	if !isDirectory(filepath.Join(bundlePath, "image")) {
		return errors.New("metadata bundle image directory is missing")
	}
	if !isRegularFile(filepath.Join(bundlePath, "bundle.json")) {
		return errors.New("metadata bundle manifest is missing")
	}
	if !isRegularFile(filepath.Join(bundlePath, "placement.json")) {
		return errors.New("metadata bundle placement is missing")
	}
	if publication.MetadataBundleSHA256 != "" {
		_, digest, err := digestDirectory(bundlePath)
		if err != nil {
			return err
		}
		if digest != publication.MetadataBundleSHA256 {
			return fmt.Errorf("metadata bundle digest mismatch: want %s got %s", publication.MetadataBundleSHA256, digest)
		}
	}
	return nil
}

func materializeRestoreState(cacheRoot, checkpointID, readerContainer string, publication metadataPublicationRecord, config daemonConfig) error {
	restoreRoot := filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(checkpointID))
	if err := os.RemoveAll(restoreRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(restoreRoot, 0o755); err != nil {
		return err
	}
	if err := copyTree(filepath.Join(cacheRoot, "metadata-bundle"), filepath.Join(restoreRoot, "metadata-bundle")); err != nil {
		return err
	}
	actionRoot := filepath.Join(cacheRoot, "action-root")
	if isDirectory(actionRoot) {
		// The restore workdir is target-private. Metadata and action-root are
		// copied out of the immutable cache so CRIU logs and action writes do
		// not mutate the cached publication artifact.
		if err := copyTree(actionRoot, filepath.Join(restoreRoot, "action-root")); err != nil {
			return err
		}
	}
	return writeReaderPublication(restoreRoot, publication)
}

func writeReaderPublication(root string, publication metadataPublicationRecord) error {
	record := publication
	record.CheckpointPath = filepath.Join(root, "metadata-bundle", "image")
	record.MetadataBundlePath = filepath.Join(root, "metadata-bundle")
	record.PlacementPath = filepath.Join(root, "metadata-bundle", "placement.json")
	actionRoot := filepath.Join(root, "action-root")
	if isDirectory(actionRoot) {
		record.CheckpointActionExportRoot = actionRoot
	} else {
		record.CheckpointActionExportRoot = ""
	}
	return trenvpub.WriteFileNoReplace(filepath.Join(root, "publication.reader"+trenvpub.Extension), publicationRecordToBinary(record))
}

func elapsedMicros(startedAt time.Time) int64 {
	elapsed := time.Since(startedAt).Microseconds()
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func defaultWriterID() string {
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		return hostname
	}
	return "unknown-writer"
}

func checkpointID(imagePath string) string {
	return filepath.Base(filepath.Dir(filepath.Clean(imagePath)))
}

func detectDaxDevice() (string, error) {
	matches, err := filepath.Glob("/dev/dax*.0")
	if err != nil {
		return "", err
	}
	sort.Strings(matches)
	for _, match := range matches {
		if stat, err := os.Stat(match); err == nil && stat.Mode()&os.ModeDevice != 0 {
			return match, nil
		}
	}
	return "", errors.New("no usable /dev/dax*.0 device found")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func nonEmptyOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func sanitizePathPart(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

func normalizePeerURLs(peers []string) []string {
	var normalized []string
	seen := map[string]bool{}
	for _, peer := range peers {
		trimmed := strings.TrimRight(strings.TrimSpace(peer), "/")
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
			trimmed = "http://" + trimmed
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}

func splitCommaList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseDaxShardConfig(value string) (daxShardConfig, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return daxShardConfig{}, errors.New("empty DAX shard")
	}
	shardID, daxDevice, ok := strings.Cut(trimmed, "=")
	if !ok {
		daxDevice = trimmed
		shardID = filepath.Base(daxDevice)
	}
	return normalizeDaxShardConfig(daxShardConfig{
		ShardID:   shardID,
		DaxDevice: daxDevice,
	})
}

func parseDaxShardConfigList(value string) ([]daxShardConfig, error) {
	var shards []daxShardConfig
	for _, item := range splitCommaList(value) {
		shard, err := parseDaxShardConfig(item)
		if err != nil {
			return nil, err
		}
		shards = append(shards, shard)
	}
	if err := rejectDuplicateDaxShardConfig(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func normalizeDaxShardConfig(shard daxShardConfig) (daxShardConfig, error) {
	shardID := strings.TrimSpace(shard.ShardID)
	daxDevice := strings.TrimSpace(shard.DaxDevice)
	if daxDevice == "" {
		return daxShardConfig{}, errors.New("DAX shard device is empty")
	}
	if shardID == "" {
		shardID = filepath.Base(daxDevice)
	}
	if shardID == "." || shardID == string(os.PathSeparator) {
		return daxShardConfig{}, fmt.Errorf("invalid DAX shard id %q", shardID)
	}
	return daxShardConfig{ShardID: shardID, DaxDevice: daxDevice}, nil
}

func rejectDuplicateDaxShardConfig(shards []daxShardConfig) error {
	seenShardIDs := map[string]bool{}
	seenDevices := map[string]bool{}
	for _, shard := range shards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return err
		}
		if seenShardIDs[normalized.ShardID] {
			return fmt.Errorf("duplicate DAX shard id %q", normalized.ShardID)
		}
		if seenDevices[normalized.DaxDevice] {
			return fmt.Errorf("duplicate DAX device %q", normalized.DaxDevice)
		}
		seenShardIDs[normalized.ShardID] = true
		seenDevices[normalized.DaxDevice] = true
	}
	return nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envDefaultBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid boolean %s=%q, using %v\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func envDefaultDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid duration %s=%q, using %s\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func envDefaultUint64(name string, fallback uint64) uint64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid uint64 %s=%q, using %d\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func safeJoin(root, name string) (string, error) {
	separator := string(os.PathSeparator)
	cleanName := filepath.Clean(strings.TrimPrefix(name, separator))
	if cleanName == "." || strings.HasPrefix(cleanName, ".."+separator) || cleanName == ".." || filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	target := filepath.Join(root, cleanName)
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	cleanTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if cleanTarget != cleanRoot && !strings.HasPrefix(cleanTarget, cleanRoot+separator) {
		return "", fmt.Errorf("archive path escapes target root: %q", name)
	}
	return target, nil
}

func copyFile(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyTree(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(source)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.Symlink(linkTarget, target)
	}
	if !info.IsDir() {
		return copyFile(source, target, info.Mode().Perm())
	}
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		targetPath := target
		if relative != "." {
			targetPath = filepath.Join(target, relative)
		}
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			// Preserve action-root symlinks, especially Python virtualenv links.
			// Dereferencing them would copy host/runtime targets into the
			// publication and change action filesystem semantics.
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			if _, err := os.Lstat(targetPath); err == nil {
				return fmt.Errorf("copy target already exists: %s", targetPath)
			} else if !os.IsNotExist(err) {
				return err
			}
			return os.Symlink(linkTarget, targetPath)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, targetPath, info.Mode().Perm())
	})
}

type metadataDigestEntry struct {
	Path   string
	Size   int64
	SHA256 string
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestDirectory(root string) (int64, string, error) {
	var entries []metadataDigestEntry
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		sum, err := fileSHA256(path)
		if err != nil {
			return err
		}
		entries = append(entries, metadataDigestEntry{
			Path:   filepath.ToSlash(relative),
			Size:   info.Size(),
			SHA256: sum,
		})
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	hash := sha256.New()
	var total int64
	for _, entry := range entries {
		total += entry.Size
		fmt.Fprintf(hash, "%s\x00%d\x00%s\x00", entry.Path, entry.Size, entry.SHA256)
	}
	return total, hex.EncodeToString(hash.Sum(nil)), nil
}

func writeJSONFile(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

type dedupRunStatus struct {
	CheckpointID       string    `json:"checkpoint_id"`
	ArtifactID         string    `json:"artifact_id"`
	BasePublication    string    `json:"base_publication"`
	DerivedPublication string    `json:"derived_publication,omitempty"`
	CheckpointPath     string    `json:"checkpoint_path"`
	State              string    `json:"state"`
	Reason             string    `json:"reason,omitempty"`
	Error              string    `json:"error,omitempty"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
}

func dedupEnabled(config daemonConfig) bool {
	return config.DedupInterval > 0 || config.DedupOnCheckpoint
}

func normalizeDedupConfig(config daemonConfig) daemonConfig {
	if strings.TrimSpace(config.DedupDedupdBinary) == "" {
		config.DedupDedupdBinary = "dedupd"
	}
	if strings.TrimSpace(config.DedupPublicationBinary) == "" {
		config.DedupPublicationBinary = "trenv-dedup-pub"
	}
	if strings.TrimSpace(config.DedupExecution) == "" {
		config.DedupExecution = "cpu"
	}
	if strings.TrimSpace(config.DedupOutputDirectory) == "" {
		config.DedupOutputDirectory = filepath.Join(config.WorkingDirectory, "dedup")
	}
	if config.DedupTimeout <= 0 {
		config.DedupTimeout = 15 * time.Minute
	}
	if config.DedupMinPages == 0 {
		config.DedupMinPages = 1
	}
	return config
}

func startDedupScheduler(ctx context.Context, config daemonConfig) {
	config = normalizeDedupConfig(config)
	if config.DedupInterval <= 0 {
		return
	}
	go func() {
		triggerDedupCycleWithContext(ctx, config, "startup")
		ticker := time.NewTicker(config.DedupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				triggerDedupCycleWithContext(ctx, config, "interval")
			}
		}
	}()
}

func triggerDedupCycle(config daemonConfig, reason string) {
	config = normalizeDedupConfig(config)
	if !dedupEnabled(config) {
		return
	}
	go triggerDedupCycleWithContext(context.Background(), config, reason)
}

func triggerDedupCycleWithContext(parent context.Context, config daemonConfig, reason string) {
	config = normalizeDedupConfig(config)
	ctx, cancel := context.WithTimeout(parent, config.DedupTimeout)
	defer cancel()
	if err := runDedupCycle(ctx, config, reason); err != nil {
		fmt.Fprintf(os.Stderr, "trenvd dedup cycle failed: %v\n", err)
	}
}

func runDedupCycle(ctx context.Context, config daemonConfig, reason string) error {
	config = normalizeDedupConfig(config)
	select {
	case dedupRunGate <- struct{}{}:
		defer func() { <-dedupRunGate }()
	default:
		return nil
	}
	candidates, err := listDedupCandidates(config)
	if err != nil {
		return err
	}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runDedupPublication(ctx, config, candidate, reason); err != nil {
			fmt.Fprintf(os.Stderr, "trenvd dedup skipped checkpoint=%s artifact=%s: %v\n", candidate.CheckpointID, candidate.ArtifactID, err)
		}
	}
	return nil
}

func listDedupCandidates(config daemonConfig) ([]metadataPublicationRecord, error) {
	publications, err := listCommittedPublications(config, "")
	if err != nil {
		return nil, err
	}
	dedupByCheckpoint := map[string]bool{}
	for _, publication := range publications {
		if publicationHasDedup(publication) {
			dedupByCheckpoint[publication.CheckpointID] = true
		}
	}
	var candidates []metadataPublicationRecord
	for _, publication := range publications {
		if publicationHasDedup(publication) {
			continue
		}
		if dedupByCheckpoint[publication.CheckpointID] {
			continue
		}
		if filepath.Ext(publication.PublicationPath) != trenvpub.Extension {
			continue
		}
		if dedupNoExtentsMarked(config, publication) {
			continue
		}
		if !isDirectory(publication.CheckpointPath) || !checkpointHasPages(publication.CheckpointPath) {
			continue
		}
		candidates = append(candidates, publication)
	}
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].CreatedAt.Before(candidates[j].CreatedAt)
	})
	return candidates, nil
}

func checkpointHasPages(checkpointPath string) bool {
	matches, err := filepath.Glob(filepath.Join(checkpointPath, "pages-*.img"))
	return err == nil && len(matches) > 0
}

func runDedupPublication(ctx context.Context, config daemonConfig, publication metadataPublicationRecord, reason string) error {
	startedAt := time.Now().UTC()
	workRoot := filepath.Join(dedupWorkDirectory(config), sanitizePathPart(publication.ArtifactID))
	if err := os.RemoveAll(workRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		return err
	}

	ledgerPath := filepath.Join(workRoot, "checkpoint-ledger.bin")
	summaryPath := filepath.Join(workRoot, "checkpoint-ledger-summary.json")
	planPath := filepath.Join(workRoot, "checkpoint-apply-plan.json")

	ledgerArgs := []string{
		"checkpoint-ledger",
		"--source", publication.CheckpointPath,
		"--page-size", "4096",
		"--execution", config.DedupExecution,
		"--output", ledgerPath,
	}
	if strings.TrimSpace(publication.DaxDevice) != "" {
		ledgerArgs = append(ledgerArgs, "--dax-device", publication.DaxDevice)
	}
	if _, stderr, err := runDedupCommand(ctx, config.DedupDedupdBinary, ledgerArgs, summaryPath); err != nil {
		_ = writeDedupStatus(config, publication, dedupRunStatus{
			State:          "failed",
			Reason:         reason,
			Error:          commandErrorString(err, stderr),
			CheckpointPath: publication.CheckpointPath,
			StartedAt:      startedAt,
			FinishedAt:     time.Now().UTC(),
		})
		return fmt.Errorf("checkpoint-ledger: %s", commandErrorString(err, stderr))
	}

	if _, stderr, err := runDedupCommand(ctx, config.DedupDedupdBinary, []string{
		"checkpoint-apply-plan",
		"--source", publication.CheckpointPath,
		"--page-size", "4096",
		"--ledger", ledgerPath,
	}, planPath); err != nil {
		_ = writeDedupStatus(config, publication, dedupRunStatus{
			State:          "failed",
			Reason:         reason,
			Error:          commandErrorString(err, stderr),
			CheckpointPath: publication.CheckpointPath,
			StartedAt:      startedAt,
			FinishedAt:     time.Now().UTC(),
		})
		return fmt.Errorf("checkpoint-apply-plan: %s", commandErrorString(err, stderr))
	}

	createdAt := time.Now().UTC()
	derivedPath := filepath.Join(
		publicationDirectory(config),
		fmt.Sprintf("%s.dedup-%s%s", sanitizePathPart(publication.CheckpointID), createdAt.Format("20060102T150405.000000000Z"), trenvpub.Extension))
	_, stderr, err := runDedupCommand(ctx, config.DedupPublicationBinary, []string{
		"--base", publication.PublicationPath,
		"--plan", planPath,
		"--output", derivedPath,
		"--created-at", createdAt.Format(time.RFC3339Nano),
		"--min-pages", strconv.FormatUint(config.DedupMinPages, 10),
	}, "")
	if err != nil {
		state := "failed"
		if strings.Contains(stderr, "no publishable dedup extents") {
			state = "no-extents"
		}
		_ = writeDedupStatus(config, publication, dedupRunStatus{
			State:              state,
			Reason:             reason,
			Error:              commandErrorString(err, stderr),
			CheckpointPath:     publication.CheckpointPath,
			DerivedPublication: derivedPath,
			StartedAt:          startedAt,
			FinishedAt:         time.Now().UTC(),
		})
		if state == "no-extents" {
			return nil
		}
		return fmt.Errorf("trenv-dedup-pub: %s", commandErrorString(err, stderr))
	}

	if err := writeDedupStatus(config, publication, dedupRunStatus{
		State:              "published",
		Reason:             reason,
		CheckpointPath:     publication.CheckpointPath,
		DerivedPublication: derivedPath,
		StartedAt:          startedAt,
		FinishedAt:         time.Now().UTC(),
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "trenvd dedup published checkpoint=%s base=%s derived=%s\n", publication.CheckpointID, publication.PublicationPath, derivedPath)
	return nil
}

func runDedupCommand(ctx context.Context, binary string, args []string, stdoutPath string) (string, string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdoutBuilder strings.Builder
	var stderrBuilder strings.Builder
	var stdoutFile *os.File
	var stdoutTemp string
	if strings.TrimSpace(stdoutPath) != "" {
		if err := os.MkdirAll(filepath.Dir(stdoutPath), 0o755); err != nil {
			return "", "", err
		}
		file, err := os.CreateTemp(filepath.Dir(stdoutPath), filepath.Base(stdoutPath)+".tmp.")
		if err != nil {
			return "", "", err
		}
		stdoutFile = file
		stdoutTemp = file.Name()
		cmd.Stdout = stdoutFile
	} else {
		cmd.Stdout = &stdoutBuilder
	}
	cmd.Stderr = &stderrBuilder

	err := cmd.Run()
	if stdoutFile != nil {
		if closeErr := stdoutFile.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(stdoutTemp, stdoutPath)
		}
		if err != nil {
			_ = os.Remove(stdoutTemp)
		}
	}
	return stdoutBuilder.String(), stderrBuilder.String(), err
}

func commandErrorString(err error, stderr string) string {
	message := strings.TrimSpace(stderr)
	if message == "" && err != nil {
		message = err.Error()
	}
	if message == "" {
		message = "unknown error"
	}
	return message
}

func dedupWorkDirectory(config daemonConfig) string {
	if strings.TrimSpace(config.DedupOutputDirectory) != "" {
		return config.DedupOutputDirectory
	}
	return filepath.Join(config.WorkingDirectory, "dedup")
}

func dedupStatusPath(config daemonConfig, publication metadataPublicationRecord) string {
	key := strings.TrimSpace(publication.ArtifactID)
	if key == "" {
		key = publication.CheckpointID
	}
	return filepath.Join(dedupWorkDirectory(config), "status", sanitizePathPart(key)+".json")
}

func dedupNoExtentsMarked(config daemonConfig, publication metadataPublicationRecord) bool {
	data, err := os.ReadFile(dedupStatusPath(config, publication))
	if err != nil {
		return false
	}
	var status dedupRunStatus
	if err := json.Unmarshal(data, &status); err != nil {
		return false
	}
	return status.State == "no-extents"
}

func writeDedupStatus(config daemonConfig, publication metadataPublicationRecord, status dedupRunStatus) error {
	status.CheckpointID = publication.CheckpointID
	status.ArtifactID = publication.ArtifactID
	status.BasePublication = publication.PublicationPath
	if status.CheckpointPath == "" {
		status.CheckpointPath = publication.CheckpointPath
	}
	if status.StartedAt.IsZero() {
		status.StartedAt = time.Now().UTC()
	}
	if status.FinishedAt.IsZero() {
		status.FinishedAt = time.Now().UTC()
	}
	return writeJSONFile(dedupStatusPath(config, publication), status)
}

func publicationDirectory(config daemonConfig) string {
	return filepath.Join(config.WorkingDirectory, "checkpoints", "publication")
}

func publicationHasDedup(record metadataPublicationRecord) bool {
	return record.Stats.DedupDeltaCount > 0 ||
		record.Stats.DedupAppliedCount > 0 ||
		len(record.DedupDelta) > 0 ||
		record.CheckpointPhase == trenvpub.DedupRestoreCOWPhase
}

func publicationPriority(record metadataPublicationRecord) int {
	if publicationHasDedup(record) {
		return 1
	}
	return 0
}

func publicationLess(a, b metadataPublicationRecord) bool {
	if publicationPriority(a) != publicationPriority(b) {
		return publicationPriority(a) < publicationPriority(b)
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	if a.CheckpointID != b.CheckpointID {
		return a.CheckpointID < b.CheckpointID
	}
	return a.ArtifactID < b.ArtifactID
}

func listCommittedPublications(config daemonConfig, fingerprint string) ([]metadataPublicationRecord, error) {
	dir := publicationDirectory(config)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var publications []metadataPublicationRecord
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), trenvpub.Extension) && !strings.HasSuffix(entry.Name(), ".json")) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		record, err := readPublicationRecord(path)
		if err != nil {
			continue
		}
		if record.State != "COMMITTED" {
			continue
		}
		if strings.TrimSpace(fingerprint) != "" && record.Fingerprint != fingerprint {
			continue
		}
		record.PublicationPath = path
		publications = append(publications, record)
	}
	sort.Slice(publications, func(i, j int) bool {
		return publicationLess(publications[i], publications[j])
	})
	return publications, nil
}

func readPublicationRecord(path string) (metadataPublicationRecord, error) {
	if filepath.Ext(path) == trenvpub.Extension {
		pub, err := trenvpub.ReadFile(path)
		if err != nil {
			return metadataPublicationRecord{}, err
		}
		record := publicationRecordFromBinary(pub)
		record.PublicationPath = path
		return record, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return metadataPublicationRecord{}, err
	}
	var record metadataPublicationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return metadataPublicationRecord{}, err
	}
	if record.CheckpointID == "" {
		record.CheckpointID = record.ArtifactID
	}
	record.PublicationPath = path
	return record, nil
}

func publicationRecordFromBinary(pub trenvpub.Publication) metadataPublicationRecord {
	record := metadataPublicationRecord{
		Version:                    int(trenvpub.Version),
		ArtifactID:                 pub.ArtifactID,
		CheckpointID:               pub.CheckpointID,
		State:                      pub.State,
		CheckpointPhase:            pub.CheckpointPhase,
		Fingerprint:                pub.Fingerprint,
		SnapshotStartMode:          pub.SnapshotStartMode,
		RuntimeKind:                pub.RuntimeKind,
		RuntimeFamily:              pub.RuntimeFamily,
		CheckpointPath:             pub.CheckpointPath,
		MetadataBundlePath:         pub.MetadataBundlePath,
		PlacementPath:              pub.PlacementPath,
		CheckpointActionExportRoot: pub.CheckpointActionExportRoot,
		MetadataBundleSize:         pub.MetadataBundleSize,
		MetadataBundleSHA256:       pub.MetadataBundleSHA256,
		CreatedAt:                  pub.CreatedAt,
	}
	if record.CheckpointID == "" {
		record.CheckpointID = record.ArtifactID
	}
	if pub.ActionIdentity != nil {
		record.ActionIdentity = &metadataPublicationActionIdentity{
			Namespace:          pub.ActionIdentity.Namespace,
			FullyQualifiedName: pub.ActionIdentity.FullyQualifiedName,
			Revision:           pub.ActionIdentity.Revision,
		}
	}
	if len(pub.Shards) > 0 {
		shard := pub.Shards[0]
		record.WriterID = shard.WriterID
		record.ShardID = shard.ShardID
		record.DaxDevice = shard.DaxDevice
		record.DaxStartPage = shard.DaxStartPage
		record.DaxLengthPages = shard.DaxLengthPages
		record.PageCount = shard.PageCount
		record.PageSize = shard.PageSize
		record.Layout = shard.Layout
	}
	record.Shards = append([]trenvpub.Shard(nil), pub.Shards...)
	record.BaseRestoreMap = append([]trenvpub.RestoreExtent(nil), pub.BaseRestoreMap...)
	record.DedupDelta = append([]trenvpub.RestoreExtent(nil), pub.DedupDelta...)
	record.Stats = pub.Stats
	return record
}

func publicationRecordToBinary(record metadataPublicationRecord) trenvpub.Publication {
	var identity *trenvpub.ActionIdentity
	if record.ActionIdentity != nil {
		identity = &trenvpub.ActionIdentity{
			Namespace:          record.ActionIdentity.Namespace,
			FullyQualifiedName: record.ActionIdentity.FullyQualifiedName,
			Revision:           record.ActionIdentity.Revision,
		}
	}
	shards := append([]trenvpub.Shard(nil), record.Shards...)
	if len(shards) == 0 {
		shards = []trenvpub.Shard{{
			WriterID:       record.WriterID,
			ShardID:        record.ShardID,
			DaxDevice:      record.DaxDevice,
			DaxStartPage:   record.DaxStartPage,
			DaxLengthPages: record.DaxLengthPages,
			PageCount:      record.PageCount,
			PageSize:       record.PageSize,
			Layout:         record.Layout,
		}}
	}
	return trenvpub.Publication{
		ArtifactID:                 record.ArtifactID,
		CheckpointID:               record.CheckpointID,
		State:                      record.State,
		CheckpointPhase:            record.CheckpointPhase,
		Fingerprint:                record.Fingerprint,
		SnapshotStartMode:          record.SnapshotStartMode,
		RuntimeKind:                record.RuntimeKind,
		RuntimeFamily:              record.RuntimeFamily,
		ActionIdentity:             identity,
		CheckpointPath:             record.CheckpointPath,
		MetadataBundlePath:         record.MetadataBundlePath,
		PlacementPath:              record.PlacementPath,
		CheckpointActionExportRoot: record.CheckpointActionExportRoot,
		MetadataBundleSize:         record.MetadataBundleSize,
		MetadataBundleSHA256:       record.MetadataBundleSHA256,
		Shards:                     shards,
		BaseRestoreMap:             append([]trenvpub.RestoreExtent(nil), record.BaseRestoreMap...),
		DedupDelta:                 append([]trenvpub.RestoreExtent(nil), record.DedupDelta...),
		Stats:                      record.Stats,
		CreatedAt:                  record.CreatedAt,
	}
}

func findPublicationByCheckpointID(config daemonConfig, checkpointID string) (metadataPublicationRecord, error) {
	if strings.TrimSpace(checkpointID) == "" {
		return metadataPublicationRecord{}, errors.New("checkpoint id is empty")
	}
	publications, err := listCommittedPublications(config, "")
	if err != nil {
		return metadataPublicationRecord{}, err
	}
	for i := len(publications) - 1; i >= 0; i-- {
		record := publications[i]
		if record.CheckpointID == checkpointID || record.ArtifactID == checkpointID {
			return record, nil
		}
	}
	return metadataPublicationRecord{}, fmt.Errorf("publication %q was not found", checkpointID)
}

func handlePublications(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		publications, err := listCommittedPublications(config, r.URL.Query().Get("fingerprint"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(publications); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func handleArtifact(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/artifacts/")
		name = strings.TrimSuffix(name, ".tar")
		checkpointID, err := url.PathUnescape(name)
		if err != nil || checkpointID == "" || strings.Contains(checkpointID, "/") || strings.Contains(checkpointID, "..") {
			http.Error(w, "invalid checkpoint id", http.StatusBadRequest)
			return
		}
		publication, err := findPublicationByCheckpointID(config, checkpointID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		if err := writeArtifactTar(w, publication); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func handleBinaryPublication(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v2/publications/")
		name = strings.TrimSuffix(name, trenvpub.Extension)
		checkpointID, err := url.PathUnescape(name)
		if err != nil || checkpointID == "" || strings.Contains(checkpointID, "/") || strings.Contains(checkpointID, "..") {
			http.Error(w, "invalid checkpoint id", http.StatusBadRequest)
			return
		}
		publication, err := findPublicationByCheckpointID(config, checkpointID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", trenvpub.ContentType)
		http.ServeFile(w, r, publication.PublicationPath)
	}
}

func writeArtifactTar(writer io.Writer, publication metadataPublicationRecord) error {
	tw := tar.NewWriter(writer)
	defer tw.Close()
	// Artifact tar deliberately contains metadata/action-root only. DAX page
	// payload remains in the shared DAX publication and is referenced by
	// placement.json.
	if err := addDirectoryToTar(tw, publication.MetadataBundlePath, "metadata-bundle"); err != nil {
		return err
	}
	if strings.TrimSpace(publication.CheckpointActionExportRoot) != "" && isDirectory(publication.CheckpointActionExportRoot) {
		if err := addDirectoryToTar(tw, publication.CheckpointActionExportRoot, "action-root"); err != nil {
			return err
		}
	}
	archiveName := "publication.original" + filepath.Ext(publication.PublicationPath)
	if archiveName == "publication.original" {
		archiveName = "publication.original"
	}
	return addFileToTar(tw, publication.PublicationPath, archiveName)
}

func addDirectoryToTar(tw *tar.Writer, sourceRoot, archiveRoot string) error {
	sourceRoot = filepath.Clean(sourceRoot)
	return filepath.Walk(sourceRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil {
			return nil
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		name := archiveRoot
		if relative != "." {
			name = filepath.ToSlash(filepath.Join(archiveRoot, relative))
		}
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		header.Name = name
		if info.IsDir() {
			header.Name = strings.TrimSuffix(header.Name, "/") + "/"
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tw, file)
		return err
	})
}

func addFileToTar(tw *tar.Writer, sourcePath, archivePath string) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact source is not a regular file: %s", sourcePath)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = archivePath
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(tw, file)
	return err
}

func extractTar(reader io.Reader, target string) error {
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		targetPath, err := safeJoin(target, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := ensureArchivePathHasNoSymlink(target, targetPath); err != nil {
				return err
			}
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode).Perm()); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			parent := filepath.Dir(targetPath)
			// Reject writes through symlink parents before creating files. This
			// keeps a malicious or malformed artifact from escaping target root.
			if err := ensureArchivePathHasNoSymlink(target, parent); err != nil {
				return err
			}
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return err
			}
			if err := ensureArchivePathHasNoSymlink(target, targetPath); err != nil {
				return err
			}
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode).Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if header.Linkname == "" {
				return fmt.Errorf("archive symlink %q has empty target", header.Name)
			}
			parent := filepath.Dir(targetPath)
			// Symlinks are allowed as entries, but not as traversal components
			// leading to later entries.
			if err := ensureArchivePathHasNoSymlink(target, parent); err != nil {
				return err
			}
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return err
			}
			if err := ensureArchivePathHasNoSymlink(target, parent); err != nil {
				return err
			}
			if _, err := os.Lstat(targetPath); err == nil {
				return fmt.Errorf("archive symlink target already exists: %q", header.Name)
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry type for %q", header.Name)
		}
	}
}

func ensureArchivePathHasNoSymlink(root, path string) error {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	if strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || relative == ".." || filepath.IsAbs(relative) {
		return fmt.Errorf("archive path escapes target root: %q", path)
	}
	current := cleanRoot
	for _, part := range strings.Split(relative, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive path traverses symlink: %q", path)
		}
	}
	return nil
}

func startMetadataServer(config daemonConfig) (*http.Server, net.Listener, error) {
	if strings.TrimSpace(config.MetadataListen) == "" {
		return nil, nil, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/publications", handlePublications(config))
	mux.HandleFunc("/v1/artifacts/", handleArtifact(config))
	mux.HandleFunc("/v2/publications/", handleBinaryPublication(config))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", config.MetadataListen)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "trenvd metadata server failed: %v\n", err)
		}
	}()
	return server, listener, nil
}

func serveConn(conn net.Conn) {
	defer conn.Close()

	body, err := readFrame(conn)
	if err != nil {
		return
	}

	var req daemonRequest
	if err := json.Unmarshal(body, &req); err != nil {
		resp, _ := json.Marshal(execResponse{Ok: false, Error: fmt.Sprintf("invalid request: %v", err)})
		_ = writeFrame(conn, resp)
		return
	}

	respBody, _ := json.Marshal(runCommand(req))
	_ = writeFrame(conn, respBody)
}

func main() {
	socketPath := flag.String("socket-path", envDefault("TRENVD_SOCKET_PATH", "/run/trenvd/trenvd.sock"), "Unix socket path")
	writerID := flag.String("writer-id", envDefault("TRENVD_WRITER_ID", ""), "checkpoint writer identity; defaults to host name")
	writerStateRoot := flag.String("writer-state-root", envDefault("TRENVD_WRITER_STATE_ROOT", ""), "writer-owned allocator state root; defaults beside the OpenWhisk checkpoint root")
	daxDevice := flag.String("dax-device", envDefault("TRENVD_DAX_DEVICE", ""), "DAX device path for checkpoint conversion; autodetects first /dev/dax*.0 when empty")
	shardID := flag.String("shard-id", envDefault("TRENVD_SHARD_ID", ""), "writer-owned DAX shard identity; defaults to DAX device basename")
	daxShards := flag.String("dax-shards", envDefault("TRENVD_DAX_SHARDS", ""), "comma-separated DAX shard mappings as shard-id=/dev/daxN.0")
	readerDaxShards := flag.String("reader-dax-shards", envDefault("TRENVD_READER_DAX_SHARDS", ""), "comma-separated reader-local DAX shard mappings as shard-id=/dev/daxN.0")
	daxPlacementPolicy := flag.String("dax-placement-policy", envDefault("TRENVD_DAX_PLACEMENT_POLICY", "first-fit"), "DAX placement policy for checkpoint writers: first-fit or round-robin")
	checkpointWriterEnabled := flag.Bool("checkpoint-writer-enabled", envDefaultBool("TRENVD_CHECKPOINT_WRITER_ENABLED", true), "allow this trenvd to create checkpoint publications")
	workingDirectory := flag.String("working-directory", envDefault("TRENVD_WORKING_DIRECTORY", "/tmp/openwhisk-trenv"), "OpenWhisk TrEnv working directory")
	metadataListen := flag.String("metadata-listen", envDefault("TRENVD_METADATA_LISTEN", ""), "optional TCP listen address for metadata HTTP, for example 127.0.0.1:18080")
	metadataPeers := flag.String("metadata-peers", envDefault("TRENVD_METADATA_PEERS", ""), "comma-separated metadata peer HTTP URLs")
	pseudoMMMaterializationRoot := flag.String("pseudo-mm-materialization-root", envDefault("TRENVD_PSEUDO_MM_MATERIALIZATION_ROOT", ""), "host-local root for reusable reader pseudo_mm materializations")
	dedupInterval := flag.Duration("dedup-interval", envDefaultDuration("TRENVD_DEDUP_INTERVAL", 0), "periodic checkpoint dedup interval; 0 disables the scheduler")
	dedupOnCheckpoint := flag.Bool("dedup-on-checkpoint", envDefaultBool("TRENVD_DEDUP_ON_CHECKPOINT", false), "run checkpoint dedup asynchronously after a successful checkpoint")
	dedupTimeout := flag.Duration("dedup-timeout", envDefaultDuration("TRENVD_DEDUP_TIMEOUT", 15*time.Minute), "timeout for one dedup cycle")
	dedupDedupdBinary := flag.String("dedup-dedupd-binary", envDefault("TRENVD_DEDUP_DEDUPD_BINARY", "dedupd"), "dedupd binary used by automatic checkpoint dedup")
	dedupPublicationBinary := flag.String("dedup-publication-binary", envDefault("TRENVD_DEDUP_PUBLICATION_BINARY", "trenv-dedup-pub"), "trenv-dedup-pub binary used to write derived dedup publications")
	dedupExecution := flag.String("dedup-execution", envDefault("TRENVD_DEDUP_EXECUTION", "cpu"), "dedupd fingerprint execution backend: cpu, sw, or hw")
	dedupOutputDirectory := flag.String("dedup-output-directory", envDefault("TRENVD_DEDUP_OUTPUT_DIRECTORY", ""), "directory for automatic dedup ledgers, plans, and status files")
	dedupMinPages := flag.Uint64("dedup-min-pages", envDefaultUint64("TRENVD_DEDUP_MIN_PAGES", 1), "minimum dedup extent size to publish")
	flag.Parse()

	parsedDaxShards, err := parseDaxShardConfigList(*daxShards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --dax-shards: %v\n", err)
		os.Exit(1)
	}
	parsedReaderDaxShards, err := parseDaxShardConfigList(*readerDaxShards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --reader-dax-shards: %v\n", err)
		os.Exit(1)
	}

	activeConfig = daemonConfig{
		WriterID:                    *writerID,
		WriterStateRoot:             *writerStateRoot,
		DaxDevice:                   *daxDevice,
		ShardID:                     *shardID,
		DaxShards:                   parsedDaxShards,
		ReaderDaxShards:             parsedReaderDaxShards,
		DaxPlacementPolicy:          *daxPlacementPolicy,
		CheckpointWriterDisabled:    !*checkpointWriterEnabled,
		WorkingDirectory:            *workingDirectory,
		MetadataListen:              *metadataListen,
		MetadataPeers:               splitCommaList(*metadataPeers),
		PseudoMMMaterializationRoot: *pseudoMMMaterializationRoot,
		DedupInterval:               *dedupInterval,
		DedupOnCheckpoint:           *dedupOnCheckpoint,
		DedupTimeout:                *dedupTimeout,
		DedupDedupdBinary:           *dedupDedupdBinary,
		DedupPublicationBinary:      *dedupPublicationBinary,
		DedupExecution:              *dedupExecution,
		DedupOutputDirectory:        *dedupOutputDirectory,
		DedupMinPages:               *dedupMinPages,
	}

	if activeConfig.WorkingDirectory == "" {
		activeConfig.WorkingDirectory = "/tmp/openwhisk-trenv"
	}
	if strings.TrimSpace(activeConfig.PseudoMMMaterializationRoot) == "" {
		activeConfig.PseudoMMMaterializationRoot = filepath.Join(activeConfig.WorkingDirectory, "pseudo-mm-materialized")
	}
	activeConfig = normalizeDedupConfig(activeConfig)
	switch activeConfig.DedupExecution {
	case "cpu", "sw", "hw":
	default:
		fmt.Fprintf(os.Stderr, "invalid --dedup-execution %q; expected cpu, sw, or hw\n", activeConfig.DedupExecution)
		os.Exit(1)
	}
	if err := os.MkdirAll(activeConfig.WorkingDirectory, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create working directory: %v\n", err)
		os.Exit(1)
	}

	metadataServer, metadataListener, err := startMetadataServer(activeConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start metadata server: %v\n", err)
		os.Exit(1)
	}
	if metadataListener != nil {
		defer metadataListener.Close()
	}

	if err := os.MkdirAll(filepath.Dir(*socketPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create socket directory: %v\n", err)
		os.Exit(1)
	}

	if err := os.RemoveAll(*socketPath); err != nil {
		fmt.Fprintf(os.Stderr, "failed to remove stale socket: %v\n", err)
		os.Exit(1)
	}

	listener, err := net.Listen("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to listen on %s: %v\n", *socketPath, err)
		os.Exit(1)
	}
	defer listener.Close()

	if err := os.Chmod(*socketPath, 0o660); err != nil {
		fmt.Fprintf(os.Stderr, "failed to chmod socket: %v\n", err)
		os.Exit(1)
	}

	daemonCtx, daemonCancel := context.WithCancel(context.Background())
	defer daemonCancel()
	startDedupScheduler(daemonCtx, activeConfig)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		daemonCancel()
		if metadataServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = metadataServer.Shutdown(ctx)
			cancel()
		}
		_ = listener.Close()
		_ = os.Remove(*socketPath)
		os.Exit(0)
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go serveConn(conn)
	}
}
