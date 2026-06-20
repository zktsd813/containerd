package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

const (
	pseudoMMInheritID                  = "pseudo-mm-drv"
	defaultDaxSlotBytes          int64 = 256 << 20
	activeRuntimeFamilyEnv             = "OW_TR_ACTIVE_RUNTIME_FAMILY"
	daxPlacementPolicyFirstFit         = "first-fit"
	daxPlacementPolicyRoundRobin       = "round-robin"
)

var runtimeTaskStateDir = filepath.Join("/run/containerd", "io.containerd.runtime.v2.task")

var errDaxShardFull = errors.New("dax shard full")

type stringListFlag []string

func (s *stringListFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringListFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	*s = append(*s, trimmed)
	return nil
}

type daxShardOption struct {
	ShardID   string
	DaxDevice string
}

type daxShardFlag []daxShardOption

func (d *daxShardFlag) String() string {
	items := make([]string, 0, len(*d))
	for _, shard := range *d {
		items = append(items, shard.String())
	}
	return strings.Join(items, ",")
}

func (d *daxShardFlag) Set(value string) error {
	shard, err := parseDaxShardOption(value)
	if err != nil {
		return err
	}
	*d = append(*d, shard)
	return nil
}

func (d daxShardOption) String() string {
	if d.ShardID == "" {
		return d.DaxDevice
	}
	return d.ShardID + "=" + d.DaxDevice
}

type daxPlacementCandidate struct {
	shard       daxShardOption
	devicePages int64
	alignPages  int64
	lengthPages int64
	pageSize    int64
}

type daxAllocationRecord struct {
	ImagePath   string    `json:"imagePath"`
	StartPage   int64     `json:"startPage"`
	LengthPages int64     `json:"lengthPages"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

type writerShardAllocatorState struct {
	WriterID     string    `json:"writer_id"`
	ShardID      string    `json:"shard_id"`
	DevicePages  int64     `json:"device_pages"`
	AlignPages   int64     `json:"align_pages"`
	NextFreePage int64     `json:"next_free_page"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type writerShardExtentRecord struct {
	CheckpointID string    `json:"checkpoint_id"`
	ImagePath    string    `json:"image_path"`
	StartPage    int64     `json:"start_page"`
	LengthPages  int64     `json:"length_pages"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type writerShardSelectorState struct {
	WriterID  string    `json:"writer_id"`
	Policy    string    `json:"policy"`
	ShardIDs  []string  `json:"shard_ids"`
	NextIndex int       `json:"next_index"`
	UpdatedAt time.Time `json:"updated_at"`
}

type daxPlacement struct {
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
}

type metadataBundleFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type metadataBundleManifest struct {
	CheckpointID string               `json:"checkpoint_id"`
	ImagePath    string               `json:"image_path"`
	Placement    string               `json:"placement"`
	Files        []metadataBundleFile `json:"files"`
	CreatedAt    time.Time            `json:"created_at"`
}

type checkpointPublicationContext struct {
	RuntimeKind                string
	RuntimeFamily              string
	ActionNamespace            string
	ActionName                 string
	ActionRevision             string
	CheckpointPhase            string
	Fingerprint                string
	SnapshotStartMode          string
	CheckpointActionExportRoot string
}

type checkpointPublicationActionIdentity struct {
	Namespace          string `json:"namespace"`
	FullyQualifiedName string `json:"fully_qualified_name"`
	Revision           string `json:"revision"`
}

type checkpointPublicationMetadata struct {
	Version                    int                                  `json:"version"`
	ArtifactID                 string                               `json:"artifact_id"`
	CheckpointID               string                               `json:"checkpoint_id"`
	State                      string                               `json:"state"`
	CheckpointPhase            string                               `json:"checkpoint_phase,omitempty"`
	Fingerprint                string                               `json:"fingerprint,omitempty"`
	SnapshotStartMode          string                               `json:"snapshot_start_mode,omitempty"`
	RuntimeKind                string                               `json:"runtime_kind,omitempty"`
	RuntimeFamily              string                               `json:"runtime_family,omitempty"`
	ActionIdentity             *checkpointPublicationActionIdentity `json:"action_identity,omitempty"`
	CheckpointPath             string                               `json:"checkpoint_path"`
	MetadataBundlePath         string                               `json:"metadata_bundle_path"`
	PlacementPath              string                               `json:"placement_path"`
	CheckpointActionExportRoot string                               `json:"checkpoint_action_export_root,omitempty"`
	MetadataBundleSize         int64                                `json:"metadata_bundle_size"`
	MetadataBundleSHA256       string                               `json:"metadata_bundle_sha256"`
	WriterID                   string                               `json:"writer_id"`
	ShardID                    string                               `json:"shard_id"`
	DaxDevice                  string                               `json:"dax_device"`
	DaxStartPage               int64                                `json:"dax_start_page"`
	DaxLengthPages             int64                                `json:"dax_length_pages"`
	PageCount                  int64                                `json:"page_count"`
	PageSize                   int64                                `json:"page_size"`
	Layout                     string                               `json:"layout"`
	CreatedAt                  time.Time                            `json:"created_at"`
}

type metadataDigestEntry struct {
	Path   string
	Size   int64
	SHA256 string
}

func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trenv-checkpoint-task", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		address                    = fs.String("address", "/run/containerd/containerd.sock", "containerd socket address")
		namespaceValue             = fs.String("namespace", "default", "containerd namespace")
		imagePath                  = fs.String("image-path", "", "CRIU image output directory")
		workPath                   = fs.String("work-path", "", "CRIU work/log output directory")
		openTCP                    = fs.Bool("tcp-established", true, "allow checkpointing established TCP connections")
		tcpClose                   = fs.Bool("tcp-close", true, "restore connected TCP sockets in closed state during criu convert")
		daxDevice                  = fs.String("dax-device", "", "optional DAX device path; autodetects first /dev/dax*.0 when empty")
		daxPgoff                   = fs.Int("dax-pgoff", 0, "page offset on the DAX device used by criu convert")
		daxPlacementPolicy         = fs.String("dax-placement-policy", daxPlacementPolicyFirstFit, "DAX shard placement policy: first-fit or round-robin")
		pseudoMMPath               = fs.String("pseudo-mm-path", "/dev/pseudo_mm", "pseudo_mm device path")
		metadataBundlePath         = fs.String("metadata-bundle-path", "", "optional output directory for reader-sync CRIU metadata bundle")
		publicationPath            = fs.String("publication-path", "", "optional output path for writer publication metadata")
		runtimeKind                = fs.String("runtime-kind", "", "OpenWhisk action runtime kind for publication metadata")
		runtimeFamily              = fs.String("runtime-family", "", "OpenWhisk action runtime family for publication metadata")
		actionNamespace            = fs.String("action-namespace", "", "OpenWhisk action namespace for publication metadata")
		actionName                 = fs.String("action-name", "", "OpenWhisk fully qualified action name for publication metadata")
		actionRevision             = fs.String("action-revision", "", "OpenWhisk action revision for publication metadata")
		checkpointPhase            = fs.String("checkpoint-phase", "", "logical checkpoint phase for publication metadata")
		fingerprint                = fs.String("fingerprint", "", "OpenWhisk TrEnv snapshot fingerprint for publication discovery")
		snapshotStartMode          = fs.String("snapshot-start-mode", "", "snapshot start mode exposed to publication readers")
		checkpointActionExportRoot = fs.String("checkpoint-action-export-root", "", "exported packaged action root path for publication readers")
		writerID                   = fs.String("writer-id", "", "checkpoint writer identity for metadata bundle placement")
		shardID                    = fs.String("shard-id", "", "writer-owned DAX shard identity for metadata bundle placement")
		writerStateRoot            = fs.String("writer-state-root", "", "optional writer-owned allocator state root")
		timeout                    = fs.Duration("timeout", 60*time.Second, "overall timeout")
	)
	var actionExportRoots stringListFlag
	var daxShards daxShardFlag
	fs.Var(&actionExportRoots, "action-export-root", "optional packaged action root to export alongside the checkpoint (repeatable)")
	fs.Var(&daxShards, "dax-shard", "DAX shard mapping as shard-id=/dev/daxN.0 or bare /dev/daxN.0 (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *imagePath == "" {
		return usageFailure(stderr, "image path must be provided via --image-path")
	}
	if *workPath == "" {
		return usageFailure(stderr, "work path must be provided via --work-path")
	}
	if fs.NArg() != 1 {
		return usageFailure(stderr, "usage: trenv-checkpoint-task [flags] CONTAINER")
	}
	containerID := fs.Arg(0)

	if err := os.MkdirAll(*imagePath, 0o755); err != nil {
		return stepFailure(stderr, "create image path", err)
	}
	if err := os.MkdirAll(*workPath, 0o755); err != nil {
		return stepFailure(stderr, "create work path", err)
	}

	resolvedDaxShards := []daxShardOption(daxShards)
	if len(resolvedDaxShards) == 0 {
		resolvedDaxDevice := strings.TrimSpace(*daxDevice)
		if resolvedDaxDevice == "" {
			var err error
			resolvedDaxDevice, err = detectDaxDevice()
			if err != nil {
				return stepFailure(stderr, "detect dax device", err)
			}
		}
		resolvedShardID := strings.TrimSpace(*shardID)
		if resolvedShardID == "" {
			resolvedShardID = filepath.Base(resolvedDaxDevice)
		}
		resolvedDaxShards = []daxShardOption{{
			ShardID:   resolvedShardID,
			DaxDevice: resolvedDaxDevice,
		}}
	}
	resolvedPlacementPolicy, err := normalizeDaxPlacementPolicy(*daxPlacementPolicy)
	if err != nil {
		return usageFailure(stderr, err.Error())
	}
	if *daxPgoff > 0 && len(resolvedDaxShards) != 1 {
		return usageFailure(stderr, "--dax-pgoff requires exactly one DAX shard")
	}

	for i, shard := range resolvedDaxShards {
		normalized, err := normalizeDaxShardOption(shard)
		if err != nil {
			return usageFailure(stderr, err.Error())
		}
		resolvedDaxShards[i] = normalized
	}
	if err := rejectDuplicateDaxShards(resolvedDaxShards); err != nil {
		return usageFailure(stderr, err.Error())
	}

	resolvedWriterID := strings.TrimSpace(*writerID)
	if resolvedWriterID == "" {
		resolvedWriterID = defaultWriterID()
	}
	resolvedMetadataBundlePath := strings.TrimSpace(*metadataBundlePath)
	if resolvedMetadataBundlePath == "" {
		resolvedMetadataBundlePath = filepath.Join(*workPath, "metadata-bundle")
	}
	resolvedPublicationPath := strings.TrimSpace(*publicationPath)
	if resolvedPublicationPath == "" {
		resolvedPublicationPath = defaultPublicationPath(*imagePath)
	} else {
		resolvedPublicationPath = trenvpub.NormalizePath(resolvedPublicationPath)
	}
	resolvedWriterStateRoot := strings.TrimSpace(*writerStateRoot)
	if resolvedWriterStateRoot == "" {
		resolvedWriterStateRoot = filepath.Join(checkpointRootFromImagePath(*imagePath), "writers")
	}
	resolvedCheckpointActionExportRoot := strings.TrimSpace(*checkpointActionExportRoot)
	if resolvedCheckpointActionExportRoot == "" && len(actionExportRoots) > 0 {
		resolvedCheckpointActionExportRoot = filepath.Join(*workPath, "action-root")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	ctx = namespaces.WithNamespace(ctx, *namespaceValue)

	client, err := containerd.New(*address, containerd.WithTimeout(*timeout))
	if err != nil {
		return stepFailure(stderr, "create containerd client", err)
	}
	defer client.Close()

	container, err := client.LoadContainer(ctx, containerID)
	if err != nil {
		return stepFailure(stderr, fmt.Sprintf("load container %q", containerID), err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return stepFailure(stderr, fmt.Sprintf("load task for container %q", containerID), err)
	}
	info, err := container.Info(ctx)
	if err != nil {
		return stepFailure(stderr, fmt.Sprintf("inspect container %q", containerID), err)
	}
	spec, err := container.Spec(ctx)
	if err != nil {
		return stepFailure(stderr, fmt.Sprintf("load spec for container %q", containerID), err)
	}
	shellJob := checkpointNeedsShellJob(spec)

	mntNsFile, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", task.Pid()))
	if err != nil {
		return stepFailure(stderr, "open mount namespace", err)
	}
	defer mntNsFile.Close()

	pseudoMMDrv, err := os.OpenFile(*pseudoMMPath, os.O_RDWR, 0)
	if err != nil {
		return stepFailure(stderr, "open pseudo_mm device", err)
	}
	defer pseudoMMDrv.Close()

	if _, err := task.Checkpoint(ctx, checkpointOptions(info.Runtime.Name, *imagePath, *workPath, *openTCP, shellJob)); err != nil {
		return stepFailure(stderr, "checkpoint task", err)
	}

	placement, err := resolveDaxPlacement(
		ctx,
		container,
		spec,
		*imagePath,
		resolvedDaxShards,
		*daxPgoff,
		resolvedWriterID,
		resolvedWriterStateRoot,
		resolvedPlacementPolicy)
	if err != nil {
		return stepFailure(stderr, "allocate dax pgoff", err)
	}

	if err := runConvert(ctx, *imagePath, *workPath, placement.DaxDevice, int(placement.DaxStartPage), *tcpClose, mntNsFile, pseudoMMDrv); err != nil {
		return stepFailure(stderr, "criu convert", err)
	}
	if pageCount, err := readConvertPageCount(*imagePath); err == nil {
		placement.ConvertPageCount = pageCount
		placement.PageCount = pageCount
	}
	if err := writeMetadataBundle(*imagePath, resolvedMetadataBundlePath, placement); err != nil {
		return stepFailure(stderr, "write metadata bundle", err)
	}
	if err := exportActionRoots(runtimeTaskStateDir, *namespaceValue, containerID, *workPath, actionExportRoots); err != nil {
		return stepFailure(stderr, "export packaged action roots", err)
	}
	publicationContext := checkpointPublicationContext{
		RuntimeKind:                strings.TrimSpace(*runtimeKind),
		RuntimeFamily:              strings.TrimSpace(*runtimeFamily),
		ActionNamespace:            strings.TrimSpace(*actionNamespace),
		ActionName:                 strings.TrimSpace(*actionName),
		ActionRevision:             strings.TrimSpace(*actionRevision),
		CheckpointPhase:            strings.TrimSpace(*checkpointPhase),
		Fingerprint:                strings.TrimSpace(*fingerprint),
		SnapshotStartMode:          strings.TrimSpace(*snapshotStartMode),
		CheckpointActionExportRoot: resolvedCheckpointActionExportRoot,
	}
	if err := writePublicationMetadata(*imagePath, resolvedMetadataBundlePath, resolvedPublicationPath, placement, publicationContext); err != nil {
		return stepFailure(stderr, "write publication metadata", err)
	}

	fmt.Fprintln(stdout, *imagePath)
	return 0
}

func taskRootfsPath(stateRoot, namespaceValue, containerID string) string {
	return filepath.Join(stateRoot, namespaceValue, containerID, "rootfs")
}

func resolveActionSubpath(root string) (string, error) {
	clean := filepath.Clean(root)
	relative := strings.TrimPrefix(clean, string(os.PathSeparator))
	if relative == "" || relative == "." {
		return "", fmt.Errorf("invalid action root %q", root)
	}
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == ".." {
			return "", fmt.Errorf("invalid action root %q", root)
		}
	}
	return relative, nil
}

func copyFile(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	return dst.Close()
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

	if info.IsDir() {
		if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(source)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if err := copyTree(filepath.Join(source, entry.Name()), filepath.Join(target, entry.Name())); err != nil {
				return err
			}
		}
		return os.Chmod(target, info.Mode().Perm())
	}

	if info.Mode().IsRegular() {
		return copyFile(source, target, info.Mode().Perm())
	}

	return fmt.Errorf("unsupported staged file type at %q with mode %v", source, info.Mode())
}

func exportActionRoots(stateRoot, namespaceValue, containerID, workPath string, roots []string) error {
	if len(roots) == 0 {
		return nil
	}

	rootfs := taskRootfsPath(stateRoot, namespaceValue, containerID)
	exportRoot := filepath.Join(workPath, "action-root")
	for _, root := range roots {
		relative, err := resolveActionSubpath(root)
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

func resolveDaxPlacement(ctx context.Context,
	container containerd.Container,
	spec *specs.Spec,
	imagePath string,
	shards []daxShardOption,
	requested int,
	writerID,
	writerStateRoot,
	policy string) (daxPlacement, error) {
	if len(shards) == 0 {
		return daxPlacement{}, errors.New("no DAX shards configured")
	}
	checkpointIDValue := checkpointID(imagePath)
	if strings.TrimSpace(checkpointIDValue) == "" {
		return daxPlacement{}, errors.New("checkpoint id is empty")
	}
	normalizedPolicy, err := normalizeDaxPlacementPolicy(policy)
	if err != nil {
		return daxPlacement{}, err
	}
	slotBytes, err := checkpointReservationBytes(ctx, container, spec)
	if err != nil {
		return daxPlacement{}, err
	}
	if slotBytes < defaultDaxSlotBytes {
		slotBytes = defaultDaxSlotBytes
	}

	candidates, err := buildDaxPlacementCandidates(shards, slotBytes)
	if err != nil {
		return daxPlacement{}, err
	}
	if requested > 0 && len(candidates) != 1 {
		return daxPlacement{}, errors.New("--dax-pgoff requires exactly one DAX shard")
	}

	if existing, ok, err := existingDaxPlacement(writerStateRoot, writerID, checkpointIDValue, candidates); err != nil {
		return daxPlacement{}, err
	} else if ok {
		return existing, nil
	}

	if normalizedPolicy == daxPlacementPolicyRoundRobin {
		return resolveRoundRobinDaxPlacement(writerStateRoot, writerID, checkpointIDValue, imagePath, candidates, requested)
	}

	return allocateDaxPlacementInOrder(writerStateRoot, writerID, checkpointIDValue, imagePath, candidates, requested)
}

func buildDaxPlacementCandidates(shards []daxShardOption, requestedSlotBytes int64) ([]daxPlacementCandidate, error) {
	candidates := make([]daxPlacementCandidate, 0, len(shards))
	for _, shard := range shards {
		normalized, err := normalizeDaxShardOption(shard)
		if err != nil {
			return nil, err
		}
		sizeBytes, alignBytes, err := daxDeviceGeometry(normalized.DaxDevice)
		if err != nil {
			return nil, err
		}
		slotBytes := roundUp(requestedSlotBytes, alignBytes)
		pageSize := int64(os.Getpagesize())
		if slotBytes%pageSize != 0 {
			return nil, fmt.Errorf("slot size %d is not page aligned (page size %d)", slotBytes, pageSize)
		}
		devicePages := sizeBytes / pageSize
		alignPages := alignBytes / pageSize
		lengthPages := slotBytes / pageSize
		if lengthPages <= 0 {
			return nil, fmt.Errorf("invalid slot length %d pages for shard %q", lengthPages, normalized.ShardID)
		}
		if alignPages <= 0 {
			return nil, fmt.Errorf("invalid alignment %d pages for shard %q", alignPages, normalized.ShardID)
		}
		candidates = append(candidates, daxPlacementCandidate{
			shard:       normalized,
			devicePages: devicePages,
			alignPages:  alignPages,
			lengthPages: lengthPages,
			pageSize:    pageSize,
		})
	}
	return candidates, nil
}

func allocateDaxPlacementInOrder(root, writerID, checkpointIDValue, imagePath string, candidates []daxPlacementCandidate, requested int) (daxPlacement, error) {
	var exhausted []string
	for _, candidate := range candidates {
		placement, err := allocateCandidateDaxPlacement(root, writerID, checkpointIDValue, imagePath, candidate, requested)
		if err == nil {
			return placement, nil
		}
		if errors.Is(err, errDaxShardFull) {
			exhausted = append(exhausted, fmt.Sprintf("%s: %v", candidate.shard.ShardID, err))
			continue
		}
		return daxPlacement{}, err
	}
	if len(exhausted) > 0 {
		return daxPlacement{}, fmt.Errorf("all DAX shards exhausted: %s", strings.Join(exhausted, "; "))
	}
	return daxPlacement{}, errors.New("no DAX placement candidates")
}

func allocateCandidateDaxPlacement(root, writerID, checkpointIDValue, imagePath string, candidate daxPlacementCandidate, requested int) (daxPlacement, error) {
	startPage := int64(requested)
	if requested <= 0 {
		var err error
		startPage, _, err = allocateWriterShardDaxPagesWithResult(
			root,
			writerID,
			candidate.shard.ShardID,
			checkpointIDValue,
			imagePath,
			candidate.devicePages,
			candidate.alignPages,
			candidate.lengthPages)
		if err != nil {
			return daxPlacement{}, err
		}
	} else if startPage%candidate.alignPages != 0 {
		return daxPlacement{}, fmt.Errorf("requested dax pgoff %d is not aligned to %d pages", startPage, candidate.alignPages)
	} else if startPage+candidate.lengthPages > candidate.devicePages {
		return daxPlacement{}, fmt.Errorf(
			"requested dax reservation exceeds device capacity: start=%d length=%d devicePages=%d",
			startPage,
			candidate.lengthPages,
			candidate.devicePages)
	}

	return daxPlacement{
		CheckpointID:   checkpointIDValue,
		WriterID:       writerID,
		ShardID:        candidate.shard.ShardID,
		DaxDevice:      candidate.shard.DaxDevice,
		DaxStartPage:   startPage,
		DaxLengthPages: candidate.lengthPages,
		PageSize:       candidate.pageSize,
		Layout:         "contiguous-criu-page-stream",
		State:          "COMMITTED",
		UpdatedAt:      time.Now().UTC(),
	}, nil
}

func checkpointOptions(runtime, imagePath, workPath string, openTCP bool, shellJob bool) containerd.CheckpointTaskOpts {
	return func(info *containerd.CheckpointTaskInfo) error {
		switch runtime {
		case plugin.RuntimeRuncV1, plugin.RuntimeRuncV2:
			if info.Options == nil {
				info.Options = &options.CheckpointOptions{}
			}
			opts, ok := info.Options.(*options.CheckpointOptions)
			if !ok {
				return errors.New("invalid v2 shim checkpoint options format")
			}
			opts.ImagePath = imagePath
			opts.WorkPath = workPath
			opts.OpenTcp = openTCP
			opts.Terminal = shellJob
			opts.FileLocks = true
		default:
			if info.Options == nil {
				info.Options = &runctypes.CheckpointOptions{}
			}
			opts, ok := info.Options.(*runctypes.CheckpointOptions)
			if !ok {
				return errors.New("invalid v1 shim checkpoint options format")
			}
			opts.ImagePath = imagePath
			opts.WorkPath = workPath
			opts.OpenTcp = openTCP
			opts.Terminal = shellJob
			opts.FileLocks = true
		}
		return nil
	}
}

func runConvert(ctx context.Context,
	imagePath,
	workPath,
	daxDevice string,
	daxPgoff int,
	tcpClose bool,
	mntNsFile,
	pseudoMMDrv *os.File) error {
	args := []string{
		"convert",
		"-D",
		imagePath,
		"-W",
		workPath,
		"-v4",
		"-o",
		filepath.Join(workPath, "convert.log"),
		"--inherit-fd",
		"fd[3]:switch-ns-mnt",
		"--inherit-fd",
		fmt.Sprintf("fd[4]:%s", pseudoMMInheritID),
		"--mem-pool",
		"dax",
		"--dax-device",
		daxDevice,
		"--dax-pgoff",
		strconv.Itoa(daxPgoff),
	}
	if tcpClose {
		args = append(args, "--tcp-close")
	}

	cmd := exec.CommandContext(ctx, "criu", args...)
	cmd.ExtraFiles = []*os.File{mntNsFile, pseudoMMDrv}
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func checkpointReservationBytes(ctx context.Context, container containerd.Container, spec *specs.Spec) (int64, error) {
	if spec == nil {
		var err error
		spec, err = container.Spec(ctx)
		if err != nil {
			return defaultDaxSlotBytes, nil
		}
	}

	limit := memoryLimitBytes(spec)
	if limit <= 0 {
		return defaultDaxSlotBytes, nil
	}

	return limit, nil
}

func checkpointNeedsShellJob(spec *specs.Spec) bool {
	if spec == nil || spec.Process == nil {
		return false
	}

	for _, entry := range spec.Process.Env {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if key == activeRuntimeFamilyEnv && strings.EqualFold(value, "java") {
			return true
		}
	}

	return false
}

func memoryLimitBytes(spec *specs.Spec) int64 {
	if spec == nil || spec.Linux == nil || spec.Linux.Resources == nil || spec.Linux.Resources.Memory == nil ||
		spec.Linux.Resources.Memory.Limit == nil {
		return 0
	}

	limit := *spec.Linux.Resources.Memory.Limit
	if limit <= 0 {
		return 0
	}

	return limit
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

func defaultPublicationPath(imagePath string) string {
	checkpointRoot := filepath.Dir(filepath.Clean(imagePath))
	checkpointsDir := filepath.Dir(checkpointRoot)
	if filepath.Base(checkpointsDir) == "checkpoints" {
		return filepath.Join(checkpointsDir, "publication", checkpointID(imagePath)+trenvpub.Extension)
	}
	return filepath.Join(checkpointRoot, "publication"+trenvpub.Extension)
}

func readConvertPageCount(imagePath string) (int64, error) {
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

func writeMetadataBundle(imagePath, bundlePath string, placement daxPlacement) error {
	if err := os.RemoveAll(bundlePath); err != nil {
		return err
	}
	imageBundlePath := filepath.Join(bundlePath, "image")
	if err := os.MkdirAll(imageBundlePath, 0o755); err != nil {
		return err
	}

	var files []metadataBundleFile
	err := filepath.Walk(imagePath, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(imagePath, sourcePath)
		if err != nil {
			return err
		}
		if !isReaderMetadataFile(relative) {
			return nil
		}

		targetPath := filepath.Join(imageBundlePath, relative)
		if err := copyFile(sourcePath, targetPath, info.Mode().Perm()); err != nil {
			return err
		}
		sum, err := fileSHA256(targetPath)
		if err != nil {
			return err
		}
		files = append(files, metadataBundleFile{
			Path:   filepath.ToSlash(filepath.Join("image", relative)),
			Size:   info.Size(),
			SHA256: sum,
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	placementPath := filepath.Join(bundlePath, "placement.json")
	if err := writeJSONFile(placementPath, placement); err != nil {
		return err
	}
	manifest := metadataBundleManifest{
		CheckpointID: placement.CheckpointID,
		ImagePath:    "image",
		Placement:    "placement.json",
		Files:        files,
		CreatedAt:    time.Now().UTC(),
	}
	return writeJSONFile(filepath.Join(bundlePath, "bundle.json"), manifest)
}

func writePublicationMetadata(imagePath, bundlePath, publicationPath string, placement daxPlacement, context checkpointPublicationContext) error {
	if strings.TrimSpace(publicationPath) == "" {
		return errors.New("publication path is empty")
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "bundle.json")); err != nil {
		return fmt.Errorf("metadata bundle manifest is not ready: %w", err)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "placement.json")); err != nil {
		return fmt.Errorf("metadata bundle placement is not ready: %w", err)
	}

	bundleSize, bundleSHA256, err := digestDirectory(bundlePath)
	if err != nil {
		return err
	}

	record := buildPublicationMetadata(imagePath, bundlePath, placement, context, bundleSize, bundleSHA256, time.Now().UTC())
	if filepath.Ext(publicationPath) == ".json" {
		return writeJSONFileNoReplaceAtomic(publicationPath, record)
	}
	return trenvpub.WriteFileNoReplace(publicationPath, publicationRecordToBinary(record))
}

func publicationActionIdentity(context checkpointPublicationContext) *checkpointPublicationActionIdentity {
	if context.ActionNamespace == "" && context.ActionName == "" && context.ActionRevision == "" {
		return nil
	}
	return &checkpointPublicationActionIdentity{
		Namespace:          context.ActionNamespace,
		FullyQualifiedName: context.ActionName,
		Revision:           context.ActionRevision,
	}
}

func buildPublicationMetadata(imagePath, bundlePath string, placement daxPlacement, context checkpointPublicationContext,
	bundleSize int64, bundleSHA256 string, createdAt time.Time) checkpointPublicationMetadata {
	return checkpointPublicationMetadata{
		Version:                    int(trenvpub.Version),
		ArtifactID:                 placement.CheckpointID,
		CheckpointID:               placement.CheckpointID,
		State:                      "COMMITTED",
		CheckpointPhase:            context.CheckpointPhase,
		Fingerprint:                context.Fingerprint,
		SnapshotStartMode:          context.SnapshotStartMode,
		RuntimeKind:                context.RuntimeKind,
		RuntimeFamily:              context.RuntimeFamily,
		ActionIdentity:             publicationActionIdentity(context),
		CheckpointPath:             imagePath,
		MetadataBundlePath:         bundlePath,
		PlacementPath:              filepath.Join(bundlePath, "placement.json"),
		CheckpointActionExportRoot: context.CheckpointActionExportRoot,
		MetadataBundleSize:         bundleSize,
		MetadataBundleSHA256:       bundleSHA256,
		WriterID:                   placement.WriterID,
		ShardID:                    placement.ShardID,
		DaxDevice:                  placement.DaxDevice,
		DaxStartPage:               placement.DaxStartPage,
		DaxLengthPages:             placement.DaxLengthPages,
		PageCount:                  placement.PageCount,
		PageSize:                   placement.PageSize,
		Layout:                     placement.Layout,
		CreatedAt:                  createdAt,
	}
}

func publicationRecordToBinary(record checkpointPublicationMetadata) trenvpub.Publication {
	var identity *trenvpub.ActionIdentity
	if record.ActionIdentity != nil {
		identity = &trenvpub.ActionIdentity{
			Namespace:          record.ActionIdentity.Namespace,
			FullyQualifiedName: record.ActionIdentity.FullyQualifiedName,
			Revision:           record.ActionIdentity.Revision,
		}
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
		Shards: []trenvpub.Shard{{
			WriterID:       record.WriterID,
			ShardID:        record.ShardID,
			DaxDevice:      record.DaxDevice,
			DaxStartPage:   record.DaxStartPage,
			DaxLengthPages: record.DaxLengthPages,
			PageCount:      record.PageCount,
			PageSize:       record.PageSize,
			Layout:         record.Layout,
		}},
		Stats:     trenvpub.Stats{},
		CreatedAt: record.CreatedAt,
	}
}

func digestDirectory(root string) (int64, string, error) {
	var entries []metadataDigestEntry
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
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

func isReaderMetadataFile(relativePath string) bool {
	base := filepath.Base(relativePath)
	if matched, _ := filepath.Match("pages-*.img", base); matched {
		return false
	}
	if base == "cgroup.img" {
		return false
	}
	return true
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

func writeJSONFile(path string, value interface{}) error {
	return writeJSONFileAtomic(path, value)
}

func writeJSONFileNoReplaceAtomic(path string, value interface{}) error {
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
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
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

func writeJSONFileAtomic(path string, value interface{}) error {
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
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
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

func daxDeviceGeometry(daxDevice string) (int64, int64, error) {
	deviceName := filepath.Base(daxDevice)
	deviceDir, err := daxDeviceSysfsDir(deviceName)
	if err != nil {
		return 0, 0, err
	}

	sizeBytes, err := readSysfsUint(filepath.Join(deviceDir, "size"))
	if err != nil {
		return 0, 0, fmt.Errorf("read dax size for %q: %w", daxDevice, err)
	}

	alignBytes, err := readSysfsUint(filepath.Join(deviceDir, "align"))
	if err != nil {
		return 0, 0, fmt.Errorf("read dax align for %q: %w", daxDevice, err)
	}
	if alignBytes < uint64(os.Getpagesize()) {
		alignBytes = uint64(os.Getpagesize())
	}

	return int64(sizeBytes), int64(alignBytes), nil
}

func daxDeviceSysfsDir(deviceName string) (string, error) {
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

func readSysfsUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 0, 64)
	if err != nil {
		return 0, err
	}
	return value, nil
}

func roundUp(value, align int64) int64 {
	if align <= 0 {
		return value
	}
	remainder := value % align
	if remainder == 0 {
		return value
	}
	return value + align - remainder
}

func parseDaxShardOption(value string) (daxShardOption, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return daxShardOption{}, errors.New("empty DAX shard")
	}
	shardID, daxDevice, ok := strings.Cut(trimmed, "=")
	if !ok {
		daxDevice = trimmed
		shardID = filepath.Base(daxDevice)
	}
	return normalizeDaxShardOption(daxShardOption{
		ShardID:   shardID,
		DaxDevice: daxDevice,
	})
}

func normalizeDaxShardOption(shard daxShardOption) (daxShardOption, error) {
	shardID := strings.TrimSpace(shard.ShardID)
	daxDevice := strings.TrimSpace(shard.DaxDevice)
	if daxDevice == "" {
		return daxShardOption{}, errors.New("DAX shard device is empty")
	}
	if shardID == "" {
		shardID = filepath.Base(daxDevice)
	}
	if shardID == "." || shardID == string(os.PathSeparator) {
		return daxShardOption{}, fmt.Errorf("invalid DAX shard id %q", shardID)
	}
	return daxShardOption{ShardID: shardID, DaxDevice: daxDevice}, nil
}

func rejectDuplicateDaxShards(shards []daxShardOption) error {
	seenShardIDs := map[string]bool{}
	seenDevices := map[string]bool{}
	for _, shard := range shards {
		normalized, err := normalizeDaxShardOption(shard)
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

func normalizeDaxPlacementPolicy(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", daxPlacementPolicyFirstFit:
		return daxPlacementPolicyFirstFit, nil
	case daxPlacementPolicyRoundRobin:
		return daxPlacementPolicyRoundRobin, nil
	default:
		return "", fmt.Errorf("unsupported DAX placement policy %q", policy)
	}
}

func checkpointRootFromImagePath(imagePath string) string {
	return filepath.Dir(filepath.Dir(filepath.Clean(imagePath)))
}

func writerShardAllocatorDir(root, writerID, shardID string) string {
	return filepath.Join(root, safePathSegment(writerID), "shards", safePathSegment(shardID))
}

func writerShardSelectorDir(root, writerID string) string {
	return filepath.Join(root, safePathSegment(writerID))
}

func writerShardSelectorPath(root, writerID string) string {
	return filepath.Join(writerShardSelectorDir(root, writerID), "selector.json")
}

func existingDaxPlacement(root, writerID, checkpointIDValue string, candidates []daxPlacementCandidate) (daxPlacement, bool, error) {
	for _, candidate := range candidates {
		stateDir := writerShardAllocatorDir(root, writerID, candidate.shard.ShardID)
		record, err := loadWriterShardExtent(writerShardExtentPath(stateDir, checkpointIDValue))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return daxPlacement{}, false, err
		}
		if record.LengthPages < candidate.lengthPages {
			return daxPlacement{}, false, fmt.Errorf(
				"existing dax extent for checkpoint %q on shard %q is too small: have %d pages, need %d",
				checkpointIDValue,
				candidate.shard.ShardID,
				record.LengthPages,
				candidate.lengthPages)
		}
		return daxPlacement{
			CheckpointID:   checkpointIDValue,
			WriterID:       writerID,
			ShardID:        candidate.shard.ShardID,
			DaxDevice:      candidate.shard.DaxDevice,
			DaxStartPage:   record.StartPage,
			DaxLengthPages: record.LengthPages,
			PageSize:       candidate.pageSize,
			Layout:         "contiguous-criu-page-stream",
			State:          "COMMITTED",
			UpdatedAt:      time.Now().UTC(),
		}, true, nil
	}
	return daxPlacement{}, false, nil
}

func resolveRoundRobinDaxPlacement(root, writerID, checkpointIDValue, imagePath string, candidates []daxPlacementCandidate, requested int) (daxPlacement, error) {
	if requested > 0 {
		return allocateDaxPlacementInOrder(root, writerID, checkpointIDValue, imagePath, candidates, requested)
	}
	if root == "" {
		return daxPlacement{}, errors.New("writer selector state root is empty")
	}
	selectorDir := writerShardSelectorDir(root, writerID)
	if err := os.MkdirAll(selectorDir, 0o755); err != nil {
		return daxPlacement{}, err
	}
	lockFile, err := os.OpenFile(filepath.Join(selectorDir, "selector.lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return daxPlacement{}, err
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return daxPlacement{}, err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	shardIDs := candidateShardIDs(candidates)
	state, err := loadWriterShardSelectorState(writerShardSelectorPath(root, writerID), writerID, shardIDs)
	if err != nil {
		return daxPlacement{}, err
	}
	ordered := rotateDaxPlacementCandidates(candidates, state.NextIndex)
	placement, err := allocateDaxPlacementInOrder(root, writerID, checkpointIDValue, imagePath, ordered, requested)
	if err != nil {
		return daxPlacement{}, err
	}
	selectedIndex := candidateIndexByShardID(candidates, placement.ShardID)
	if selectedIndex >= 0 {
		state.WriterID = writerID
		state.Policy = daxPlacementPolicyRoundRobin
		state.ShardIDs = shardIDs
		state.NextIndex = (selectedIndex + 1) % len(candidates)
		state.UpdatedAt = time.Now().UTC()
		if err := writeJSONFileAtomic(writerShardSelectorPath(root, writerID), state); err != nil {
			return daxPlacement{}, err
		}
	}
	return placement, nil
}

func loadWriterShardSelectorState(path, writerID string, shardIDs []string) (writerShardSelectorState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return writerShardSelectorState{
				WriterID:  writerID,
				Policy:    daxPlacementPolicyRoundRobin,
				ShardIDs:  shardIDs,
				NextIndex: 0,
			}, nil
		}
		return writerShardSelectorState{}, err
	}
	var state writerShardSelectorState
	if err := json.Unmarshal(data, &state); err != nil {
		return writerShardSelectorState{}, err
	}
	if state.WriterID != writerID || state.Policy != daxPlacementPolicyRoundRobin || !sameStringSlice(state.ShardIDs, shardIDs) {
		return writerShardSelectorState{
			WriterID:  writerID,
			Policy:    daxPlacementPolicyRoundRobin,
			ShardIDs:  shardIDs,
			NextIndex: 0,
		}, nil
	}
	if state.NextIndex < 0 || state.NextIndex >= len(shardIDs) {
		state.NextIndex = 0
	}
	return state, nil
}

func candidateShardIDs(candidates []daxPlacementCandidate) []string {
	ids := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		ids = append(ids, candidate.shard.ShardID)
	}
	return ids
}

func rotateDaxPlacementCandidates(candidates []daxPlacementCandidate, start int) []daxPlacementCandidate {
	if len(candidates) == 0 {
		return nil
	}
	if start < 0 || start >= len(candidates) {
		start = 0
	}
	ordered := make([]daxPlacementCandidate, 0, len(candidates))
	ordered = append(ordered, candidates[start:]...)
	ordered = append(ordered, candidates[:start]...)
	return ordered
}

func candidateIndexByShardID(candidates []daxPlacementCandidate, shardID string) int {
	for i, candidate := range candidates {
		if candidate.shard.ShardID == shardID {
			return i
		}
	}
	return -1
}

func sameStringSlice(left, right []string) bool {
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

func allocateWriterShardDaxPages(root,
	writerID,
	shardID,
	checkpointIDValue,
	imagePath string,
	devicePages,
	alignPages,
	lengthPages int64) (int64, error) {
	startPage, _, err := allocateWriterShardDaxPagesWithResult(root, writerID, shardID, checkpointIDValue, imagePath, devicePages, alignPages, lengthPages)
	return startPage, err
}

func allocateWriterShardDaxPagesWithResult(root,
	writerID,
	shardID,
	checkpointIDValue,
	imagePath string,
	devicePages,
	alignPages,
	lengthPages int64) (int64, bool, error) {
	if root == "" {
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

	stateDir := writerShardAllocatorDir(root, writerID, shardID)
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

	extentPath := writerShardExtentPath(stateDir, checkpointIDValue)
	if record, err := loadWriterShardExtent(extentPath); err == nil {
		if record.LengthPages < lengthPages {
			return 0, false, fmt.Errorf(
				"existing dax extent for checkpoint %q is too small: have %d pages, need %d",
				checkpointIDValue,
				record.LengthPages,
				lengthPages)
		}
		return record.StartPage, true, nil
	} else if !os.IsNotExist(err) {
		return 0, false, err
	}

	statePath := filepath.Join(stateDir, "allocator.json")
	state, err := loadWriterShardAllocatorState(statePath, writerID, shardID, devicePages, alignPages)
	if err != nil {
		return 0, false, err
	}

	startPage := roundUp(state.NextFreePage, alignPages)
	if startPage+lengthPages > devicePages {
		return 0, false, fmt.Errorf(
			"%w: "+
				"no free append-only dax reservation for checkpoint %q (next=%d devicePages=%d alignPages=%d lengthPages=%d)",
			errDaxShardFull,
			checkpointIDValue,
			state.NextFreePage,
			devicePages,
			alignPages,
			lengthPages)
	}

	now := time.Now().UTC()
	record := writerShardExtentRecord{
		CheckpointID: checkpointIDValue,
		ImagePath:    imagePath,
		StartPage:    startPage,
		LengthPages:  lengthPages,
		UpdatedAt:    now,
	}

	state.WriterID = writerID
	state.ShardID = shardID
	state.DevicePages = devicePages
	state.AlignPages = alignPages
	state.NextFreePage = startPage + lengthPages
	state.UpdatedAt = now
	if err := writeJSONFileAtomic(statePath, state); err != nil {
		return 0, false, err
	}
	if err := writeJSONFileAtomic(extentPath, record); err != nil {
		return 0, false, err
	}

	return startPage, false, nil
}

func writerShardExtentPath(stateDir, checkpointIDValue string) string {
	return filepath.Join(stateDir, "extents", safePathSegment(checkpointIDValue)+".json")
}

func loadWriterShardExtent(path string) (writerShardExtentRecord, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return writerShardExtentRecord{}, err
	}

	var record writerShardExtentRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return writerShardExtentRecord{}, err
	}
	if record.StartPage < 0 || record.LengthPages <= 0 {
		return writerShardExtentRecord{}, fmt.Errorf("invalid dax extent record at %q", path)
	}
	return record, nil
}

func loadWriterShardAllocatorState(path, writerID, shardID string, devicePages, alignPages int64) (writerShardAllocatorState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return writerShardAllocatorState{
				WriterID:     writerID,
				ShardID:      shardID,
				DevicePages:  devicePages,
				AlignPages:   alignPages,
				NextFreePage: 0,
			}, nil
		}
		return writerShardAllocatorState{}, err
	}

	var state writerShardAllocatorState
	if err := json.Unmarshal(data, &state); err != nil {
		return writerShardAllocatorState{}, err
	}
	if state.WriterID != writerID {
		return writerShardAllocatorState{}, fmt.Errorf("allocator writer id mismatch: state=%q requested=%q", state.WriterID, writerID)
	}
	if state.ShardID != shardID {
		return writerShardAllocatorState{}, fmt.Errorf("allocator shard id mismatch: state=%q requested=%q", state.ShardID, shardID)
	}
	if state.DevicePages != devicePages {
		return writerShardAllocatorState{}, fmt.Errorf("allocator device size changed: state=%d requested=%d pages", state.DevicePages, devicePages)
	}
	if state.AlignPages != alignPages {
		return writerShardAllocatorState{}, fmt.Errorf("allocator alignment changed: state=%d requested=%d pages", state.AlignPages, alignPages)
	}
	if state.NextFreePage < 0 {
		return writerShardAllocatorState{}, fmt.Errorf("allocator next free page is invalid: %d", state.NextFreePage)
	}
	return state, nil
}

func safePathSegment(value string) string {
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
	sum := sha256.Sum256([]byte(trimmed))
	return fmt.Sprintf("%s-%s", safe, hex.EncodeToString(sum[:])[:12])
}

func daxAllocationDir(imagePath string) string {
	checkpointRoot := checkpointRootFromImagePath(imagePath)
	return filepath.Join(checkpointRoot, ".dax-pgoff-allocations")
}

func allocateDaxPages(imagePath string, devicePages, alignPages, lengthPages int64) (int64, error) {
	if devicePages <= 0 {
		return 0, fmt.Errorf("invalid dax device size %d pages", devicePages)
	}
	if alignPages <= 0 {
		return 0, fmt.Errorf("invalid dax alignment %d pages", alignPages)
	}
	if lengthPages <= 0 {
		return 0, fmt.Errorf("invalid dax reservation length %d pages", lengthPages)
	}
	if lengthPages > devicePages {
		return 0, fmt.Errorf("requested dax reservation %d pages exceeds device capacity %d pages", lengthPages, devicePages)
	}

	stateDir := daxAllocationDir(imagePath)
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return 0, err
	}

	lockFile, err := os.OpenFile(filepath.Join(stateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return 0, err
	}
	defer lockFile.Close()

	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck

	records, err := loadDaxAllocations(stateDir)
	if err != nil {
		return 0, err
	}

	active := make([]daxAllocationRecord, 0, len(records))
	for _, record := range records {
		if record.ImagePath == imagePath {
			return record.StartPage, nil
		}
		if record.ImagePath == "" || !pathExists(record.ImagePath) {
			_ = os.Remove(allocationRecordPath(stateDir, record.ImagePath))
			continue
		}
		active = append(active, record)
	}

	preferredStart := preferredDaxStartPage(imagePath, devicePages, alignPages, lengthPages)
	startPage, ok := findAvailableStartPage(active, devicePages, alignPages, lengthPages, preferredStart)
	if !ok {
		return 0, fmt.Errorf("no free dax reservation for %q (devicePages=%d alignPages=%d lengthPages=%d)", imagePath, devicePages, alignPages, lengthPages)
	}

	record := daxAllocationRecord{
		ImagePath:   imagePath,
		StartPage:   startPage,
		LengthPages: lengthPages,
		UpdatedAt:   time.Now().UTC(),
	}
	if err := writeDaxAllocation(stateDir, record); err != nil {
		return 0, err
	}

	return startPage, nil
}

func loadDaxAllocations(stateDir string) ([]daxAllocationRecord, error) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return nil, err
	}

	var records []daxAllocationRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(stateDir, entry.Name()))
		if err != nil {
			return nil, err
		}

		var record daxAllocationRecord
		if err := json.Unmarshal(data, &record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}

	return records, nil
}

func allocationRecordPath(stateDir, imagePath string) string {
	sum := sha256.Sum256([]byte(imagePath))
	return filepath.Join(stateDir, hex.EncodeToString(sum[:])+".json")
}

func writeDaxAllocation(stateDir string, record daxAllocationRecord) error {
	path := allocationRecordPath(stateDir, record.ImagePath)
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func preferredDaxStartPage(imagePath string, devicePages, alignPages, lengthPages int64) int64 {
	maxStart := devicePages - lengthPages
	if maxStart <= 0 {
		return 0
	}
	slotCount := maxStart/alignPages + 1

	h := fnv.New64a()
	_, _ = h.Write([]byte(imagePath))
	return int64(h.Sum64()%uint64(slotCount)) * alignPages
}

func findAvailableStartPage(records []daxAllocationRecord,
	devicePages,
	alignPages,
	lengthPages,
	preferredStart int64) (int64, bool) {
	maxStart := devicePages - lengthPages
	if maxStart < 0 {
		return 0, false
	}

	tryRange := func(startFrom, startTo int64) (int64, bool) {
		for start := startFrom; start <= startTo; start += alignPages {
			if !overlapsExisting(records, start, lengthPages) {
				return start, true
			}
		}
		return 0, false
	}

	if preferredStart > maxStart {
		preferredStart = maxStart - (maxStart % alignPages)
	}
	if preferredStart < 0 {
		preferredStart = 0
	}

	if start, ok := tryRange(preferredStart, maxStart); ok {
		return start, true
	}
	if preferredStart > 0 {
		return tryRange(0, preferredStart-alignPages)
	}

	return 0, false
}

func overlapsExisting(records []daxAllocationRecord, startPage, lengthPages int64) bool {
	endPage := startPage + lengthPages
	for _, record := range records {
		recordEnd := record.StartPage + record.LengthPages
		if startPage < recordEnd && record.StartPage < endPage {
			return true
		}
	}
	return false
}

func usageFailure(stderr io.Writer, message string) int {
	fmt.Fprintln(stderr, message)
	return 2
}

func stepFailure(stderr io.Writer, step string, err error) int {
	fmt.Fprintf(stderr, "%s: %v\n", step, err)
	return 1
}
