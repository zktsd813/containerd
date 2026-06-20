package switchtask

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/defaults"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	"golang.org/x/sys/unix"
)

var runtimeTaskStateDir = filepath.Join(defaults.DefaultStateDir, "io.containerd.runtime.v2.task")

const defaultActionOverlayRoot = "/var/lib/openwhisk-trenv/action-overlays"

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
	shardID   string
	daxDevice string
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
	if d.shardID == "" {
		return d.daxDevice
	}
	return d.shardID + "=" + d.daxDevice
}

type actionRebind struct {
	sourceRoot string
	targetRoot string
}

type actionRebindFlag []actionRebind

func (a *actionRebindFlag) String() string {
	items := make([]string, 0, len(*a))
	for _, rebind := range *a {
		items = append(items, fmt.Sprintf("%s:%s", rebind.sourceRoot, rebind.targetRoot))
	}
	return strings.Join(items, ",")
}

func (a *actionRebindFlag) Set(value string) error {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	sourceRoot, targetRoot, ok := strings.Cut(trimmed, ":")
	if !ok {
		return fmt.Errorf("invalid action rebind %q", value)
	}
	sourceRoot = strings.TrimSpace(sourceRoot)
	targetRoot = strings.TrimSpace(targetRoot)
	if sourceRoot == "" || targetRoot == "" {
		return fmt.Errorf("invalid action rebind %q", value)
	}
	*a = append(*a, actionRebind{sourceRoot: sourceRoot, targetRoot: targetRoot})
	return nil
}

type stagedPath struct {
	source string
	target string
}

type overlayRebindMount struct {
	source string
	target string
	upper  string
	work   string
	merged string
}

type readerPublication struct {
	CheckpointID    string `json:"checkpoint_id"`
	WriterID        string `json:"writer_id"`
	ShardID         string `json:"shard_id"`
	DaxDevice       string `json:"dax_device"`
	DaxStartPage    int64  `json:"dax_start_page"`
	DaxLengthPages  int64  `json:"dax_length_pages"`
	PageCount       int64  `json:"page_count"`
	CheckpointPath  string `json:"checkpoint_path"`
	PlacementPath   string `json:"placement_path"`
	MetadataPath    string `json:"metadata_bundle_path"`
	PublicationPath string `json:"-"`
}

func actionOverlayRoot() string {
	if root := strings.TrimSpace(os.Getenv("TRENV_ACTION_OVERLAY_ROOT")); root != "" {
		return root
	}
	return defaultActionOverlayRoot
}

type pseudoMMImportPlan struct {
	publicationPath string
	workPath        string
	checkpointID    string
	daxDevice       string
	daxStartPage    int64
	daxLengthPages  int64
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

func ensureTargetPath(target string, sourceInfo os.FileInfo) error {
	if sourceInfo.IsDir() {
		return os.MkdirAll(target, 0o755)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(target, os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	return file.Close()
}

func buildRebindPlanFromRootfs(sourceRootfs, targetRootfs string, actionRebinds []actionRebind) ([]stagedPath, error) {
	if len(actionRebinds) == 0 {
		return nil, nil
	}
	var plan []stagedPath

	for _, actionRebind := range actionRebinds {
		sourceRelative, err := resolveActionSubpath(actionRebind.sourceRoot)
		if err != nil {
			return nil, err
		}
		targetRelative, err := resolveActionSubpath(actionRebind.targetRoot)
		if err != nil {
			return nil, err
		}

		sourcePath := filepath.Join(sourceRootfs, sourceRelative)
		sourceInfo, err := os.Stat(sourcePath)
		if err != nil {
			return nil, fmt.Errorf("stat source action root %q: %w", sourcePath, err)
		}

		targetPath := filepath.Join(targetRootfs, targetRelative)
		if err := ensureTargetPath(targetPath, sourceInfo); err != nil {
			return nil, fmt.Errorf("prepare target action root %q: %w", targetPath, err)
		}
		plan = append(plan, stagedPath{source: sourcePath, target: targetPath})
	}

	return plan, nil
}

func buildRebindPlan(stateRoot, namespaceValue, sourceContainerID, targetContainerID string, actionRebinds []actionRebind) ([]stagedPath, error) {
	if sourceContainerID == "" || sourceContainerID == targetContainerID {
		return nil, nil
	}

	sourceRootfs := taskRootfsPath(stateRoot, namespaceValue, sourceContainerID)
	targetRootfs := taskRootfsPath(stateRoot, namespaceValue, targetContainerID)
	return buildRebindPlanFromRootfs(sourceRootfs, targetRootfs, actionRebinds)
}

func detachTargetMount(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && err != unix.EINVAL && err != unix.ENOENT {
		return err
	}
	return nil
}

func replaceTargetPath(target string, sourceInfo os.FileInfo) error {
	targetInfo, err := os.Lstat(target)
	switch {
	case err == nil:
		if sourceInfo.IsDir() && targetInfo.IsDir() {
			return nil
		}
		if !sourceInfo.IsDir() && !targetInfo.IsDir() {
			return nil
		}
		if err := os.RemoveAll(target); err != nil {
			return err
		}
	case os.IsNotExist(err):
	default:
		return err
	}
	return ensureTargetPath(target, sourceInfo)
}

func bindMount(source, target string) error {
	return unix.Mount(source, target, "", uintptr(unix.MS_BIND), "")
}

func overlayMount(lower, upper, work, merged string) error {
	if err := os.MkdirAll(upper, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(work, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(merged, 0o755); err != nil {
		return err
	}
	opts := fmt.Sprintf("index=off,lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	return unix.Mount("overlay", merged, "overlay", unix.MS_MGC_VAL, opts)
}

func stableOverlayRebind(stateRoot, namespaceValue, targetContainerID, sourceRootfsOverride, stableActionRoot string,
	actionRebinds []actionRebind) (*overlayRebindMount, bool, error) {
	if strings.TrimSpace(sourceRootfsOverride) == "" || strings.TrimSpace(stableActionRoot) == "" {
		return nil, false, nil
	}
	if len(actionRebinds) != 1 {
		return nil, false, nil
	}
	rebind := actionRebinds[0]
	if strings.TrimSpace(rebind.sourceRoot) != strings.TrimSpace(stableActionRoot) ||
		strings.TrimSpace(rebind.targetRoot) != strings.TrimSpace(stableActionRoot) {
		return nil, false, nil
	}

	relative, err := resolveActionSubpath(stableActionRoot)
	if err != nil {
		return nil, false, err
	}
	sourcePath := filepath.Join(strings.TrimSpace(sourceRootfsOverride), relative)
	sourceInfo, err := os.Stat(sourcePath)
	if err != nil {
		return nil, false, fmt.Errorf("stat stable overlay source %q: %w", sourcePath, err)
	}
	if !sourceInfo.IsDir() {
		return nil, false, fmt.Errorf("stable overlay source %q is not a directory", sourcePath)
	}

	targetRootfs := taskRootfsPath(stateRoot, namespaceValue, targetContainerID)
	targetPath := filepath.Join(targetRootfs, relative)
	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		return nil, false, fmt.Errorf("prepare stable overlay target %q: %w", targetPath, err)
	}

	overlayBase := filepath.Join(actionOverlayRoot(), namespaceValue, targetContainerID)
	return &overlayRebindMount{
		source: sourcePath,
		target: targetPath,
		upper:  filepath.Join(overlayBase, "upper"),
		work:   filepath.Join(overlayBase, "work"),
		merged: targetPath,
	}, true, nil
}

func applyStableOverlayRebind(mountPlan overlayRebindMount) error {
	if err := detachTargetMount(mountPlan.target); err != nil {
		return fmt.Errorf("detach previous action root mount %q: %w", mountPlan.target, err)
	}
	if mountPlan.merged != mountPlan.target {
		if err := detachTargetMount(mountPlan.merged); err != nil {
			return fmt.Errorf("detach previous overlay mount %q: %w", mountPlan.merged, err)
		}
	}
	legacyMerged := filepath.Join(filepath.Dir(mountPlan.upper), "merged")
	if err := detachTargetMount(legacyMerged); err != nil {
		return fmt.Errorf("detach previous overlay mount %q: %w", legacyMerged, err)
	}
	overlayBase := filepath.Dir(mountPlan.upper)
	if err := os.RemoveAll(overlayBase); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove previous overlay state %q: %w", overlayBase, err)
	}
	if err := overlayMount(mountPlan.source, mountPlan.upper, mountPlan.work, mountPlan.merged); err != nil {
		return fmt.Errorf("mount overlay %q -> %q: %w", mountPlan.source, mountPlan.merged, err)
	}
	if mountPlan.merged == mountPlan.target {
		return nil
	}
	if err := bindMount(mountPlan.merged, mountPlan.target); err != nil {
		_ = detachTargetMount(mountPlan.merged)
		return fmt.Errorf("bind mount overlay view %q -> %q: %w", mountPlan.merged, mountPlan.target, err)
	}
	return nil
}

func applyRebindPlan(plan []stagedPath) error {
	for _, staged := range plan {
		sourceInfo, err := os.Stat(staged.source)
		if err != nil {
			return fmt.Errorf("stat source action root %q: %w", staged.source, err)
		}
		if err := detachTargetMount(staged.target); err != nil {
			return fmt.Errorf("detach previous action root mount %q: %w", staged.target, err)
		}
		if err := replaceTargetPath(staged.target, sourceInfo); err != nil {
			return fmt.Errorf("prepare bind target %q: %w", staged.target, err)
		}
		if err := bindMount(staged.source, staged.target); err != nil {
			return fmt.Errorf("bind mount %q -> %q: %w", staged.source, staged.target, err)
		}
	}
	return nil
}

func rebindPackagedActionRoots(stateRoot, namespaceValue, sourceContainerID, sourceRootfsOverride, targetContainerID, stableActionRoot string, actionRebinds []actionRebind) (string, error) {
	if overlayPlan, ok, err := stableOverlayRebind(
		stateRoot,
		namespaceValue,
		targetContainerID,
		sourceRootfsOverride,
		stableActionRoot,
		actionRebinds); err != nil {
		return "", err
	} else if ok {
		return "overlay", applyStableOverlayRebind(*overlayPlan)
	}

	var (
		plan []stagedPath
		err  error
	)

	if strings.TrimSpace(sourceRootfsOverride) != "" {
		targetRootfs := taskRootfsPath(stateRoot, namespaceValue, targetContainerID)
		plan, err = buildRebindPlanFromRootfs(strings.TrimSpace(sourceRootfsOverride), targetRootfs, actionRebinds)
	} else {
		plan, err = buildRebindPlan(stateRoot, namespaceValue, sourceContainerID, targetContainerID, actionRebinds)
	}
	if err != nil {
		return "", err
	}
	if len(plan) == 0 {
		return "none", nil
	}
	return "bind", applyRebindPlan(plan)
}

func parseDaxShardOption(value string) (daxShardOption, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return daxShardOption{}, fmt.Errorf("empty DAX shard")
	}
	shardID, daxDevice, ok := strings.Cut(trimmed, "=")
	if !ok {
		daxDevice = trimmed
		shardID = filepath.Base(daxDevice)
	}
	shardID = strings.TrimSpace(shardID)
	daxDevice = strings.TrimSpace(daxDevice)
	if daxDevice == "" {
		return daxShardOption{}, fmt.Errorf("DAX shard device is empty")
	}
	if shardID == "" {
		shardID = filepath.Base(daxDevice)
	}
	if shardID == "." || shardID == string(os.PathSeparator) {
		return daxShardOption{}, fmt.Errorf("invalid DAX shard id %q", shardID)
	}
	return daxShardOption{shardID: shardID, daxDevice: daxDevice}, nil
}

func readerDaxShardMap(shards []daxShardOption) map[string]string {
	if len(shards) == 0 {
		return nil
	}
	mapping := make(map[string]string, len(shards))
	for _, shard := range shards {
		mapping[shard.shardID] = shard.daxDevice
	}
	return mapping
}

func resolveReaderDaxDevice(publication readerPublication, daxDeviceOverride string, readerShards []daxShardOption, fallbackDaxDevice string) string {
	if override := strings.TrimSpace(daxDeviceOverride); override != "" {
		return override
	}
	if mapped := readerDaxShardMap(readerShards)[strings.TrimSpace(publication.ShardID)]; strings.TrimSpace(mapped) != "" {
		return strings.TrimSpace(mapped)
	}
	if publicationDevice := strings.TrimSpace(publication.DaxDevice); publicationDevice != "" {
		return publicationDevice
	}
	return strings.TrimSpace(fallbackDaxDevice)
}

func resolvePseudoMMImportPlan(checkpointPath, daxDeviceOverride string, readerShards []daxShardOption, fallbackDaxDevice string) (*pseudoMMImportPlan, bool, error) {
	cleanCheckpointPath := filepath.Clean(strings.TrimSpace(checkpointPath))
	if cleanCheckpointPath == "." || filepath.Base(cleanCheckpointPath) != "image" {
		return nil, false, nil
	}

	metadataBundlePath := filepath.Dir(cleanCheckpointPath)
	restoreRoot := filepath.Dir(metadataBundlePath)
	publicationPath := filepath.Join(restoreRoot, "publication.reader"+trenvpub.Extension)
	if info, err := os.Stat(publicationPath); err != nil {
		if os.IsNotExist(err) {
			publicationPath = filepath.Join(restoreRoot, "publication.reader.json")
			if info, err = os.Stat(publicationPath); err != nil {
				if os.IsNotExist(err) {
					return nil, false, nil
				}
				return nil, false, fmt.Errorf("stat reader publication %q: %w", publicationPath, err)
			} else if info.IsDir() {
				return nil, false, fmt.Errorf("reader publication %q is a directory", publicationPath)
			}
		} else {
			return nil, false, fmt.Errorf("stat reader publication %q: %w", publicationPath, err)
		}
	} else if info.IsDir() {
		return nil, false, fmt.Errorf("reader publication %q is a directory", publicationPath)
	}

	publication, err := readReaderPublication(publicationPath)
	if err != nil {
		return nil, false, err
	}

	daxDevice := resolveReaderDaxDevice(publication, daxDeviceOverride, readerShards, fallbackDaxDevice)
	if daxDevice == "" {
		return nil, false, fmt.Errorf("reader publication %q has no DAX device", publicationPath)
	}
	if publication.DaxStartPage < 0 {
		return nil, false, fmt.Errorf("reader publication %q has invalid dax_start_page %d", publicationPath, publication.DaxStartPage)
	}
	if publication.DaxLengthPages <= 0 {
		return nil, false, fmt.Errorf("reader publication %q has invalid dax_length_pages %d", publicationPath, publication.DaxLengthPages)
	}

	return &pseudoMMImportPlan{
		publicationPath: publicationPath,
		workPath:        filepath.Join(restoreRoot, "pseudo-mm-import-work"),
		checkpointID:    strings.TrimSpace(publication.CheckpointID),
		daxDevice:       daxDevice,
		daxStartPage:    publication.DaxStartPage,
		daxLengthPages:  publication.DaxLengthPages,
	}, true, nil
}

func readReaderPublication(path string) (readerPublication, error) {
	if filepath.Ext(path) == trenvpub.Extension {
		pub, err := trenvpub.ReadFile(path)
		if err != nil {
			return readerPublication{}, err
		}
		publication := readerPublication{
			CheckpointID:    pub.CheckpointID,
			CheckpointPath:  pub.CheckpointPath,
			PlacementPath:   pub.PlacementPath,
			MetadataPath:    pub.MetadataBundlePath,
			PublicationPath: path,
		}
		if len(pub.Shards) > 0 {
			shard := pub.Shards[0]
			publication.WriterID = shard.WriterID
			publication.ShardID = shard.ShardID
			publication.DaxDevice = shard.DaxDevice
			publication.DaxStartPage = shard.DaxStartPage
			publication.DaxLengthPages = shard.DaxLengthPages
			publication.PageCount = shard.PageCount
		}
		return publication, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return readerPublication{}, fmt.Errorf("read reader publication %q: %w", path, err)
	}
	var publication readerPublication
	if err := json.Unmarshal(data, &publication); err != nil {
		return readerPublication{}, fmt.Errorf("parse reader publication %q: %w", path, err)
	}
	publication.PublicationPath = path
	return publication, nil
}

func importReaderPseudoMM(ctx context.Context, checkpointPath, pseudoMMPath string, targetPid uint32, plan pseudoMMImportPlan, stderr io.Writer) error {
	if targetPid == 0 {
		return fmt.Errorf("target task pid is empty")
	}
	if err := os.MkdirAll(plan.workPath, 0o755); err != nil {
		return fmt.Errorf("create pseudo_mm import work dir %q: %w", plan.workPath, err)
	}

	mntNsFile, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", targetPid))
	if err != nil {
		return fmt.Errorf("open target mount namespace for pid %d: %w", targetPid, err)
	}
	defer mntNsFile.Close()

	pseudoMMDrv, err := os.OpenFile(strings.TrimSpace(pseudoMMPath), os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open pseudo_mm device %q: %w", pseudoMMPath, err)
	}
	defer pseudoMMDrv.Close()

	args := []string{
		"convert",
		"-D", checkpointPath,
		"-W", plan.workPath,
		"-v4",
		"-o", filepath.Join(plan.workPath, "pseudo-mm-import.log"),
		"--inherit-fd", "fd[3]:switch-ns-mnt",
		"--inherit-fd", "fd[4]:pseudo-mm-drv",
		"--mem-pool", "dax",
		"--dax-device", plan.daxDevice,
		"--dax-pgoff", strconv.FormatInt(plan.daxStartPage, 10),
		"--import-existing-dax",
		"--tcp-close",
	}
	cmd := exec.CommandContext(ctx, "criu", args...)
	cmd.ExtraFiles = []*os.File{mntNsFile, pseudoMMDrv}
	cmd.Stderr = stderr
	return cmd.Run()
}

func Run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("trenv-switch-task", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		address             = fs.String("address", "/run/containerd/containerd.sock", "containerd socket address")
		namespaceValue      = fs.String("namespace", "default", "containerd namespace")
		checkpointPath      = fs.String("checkpoint-path", "", "converted CRIU image directory")
		sourceContainer     = fs.String("source-container", "", "optional checkpoint source container for packaged action rebinding")
		actionSourceRootfs  = fs.String("action-source-rootfs", "", "optional exported source rootfs used for packaged action rebinding")
		shellID             = fs.String("shell-id", "", "optional immutable shell identifier for the target session")
		compatibilityClass  = fs.String("compatibility-class", "", "optional shell compatibility class for the target session")
		activeRuntimeKind   = fs.String("active-runtime-kind", "", "optional active runtime kind for the switched session")
		activeRuntimeFamily = fs.String("active-runtime-family", "", "optional active runtime family for the switched session")
		stableActionRoot    = fs.String("stable-action-root", "", "optional stable action root for the target shell")
		timeout             = fs.Duration("timeout", 60*time.Second, "overall timeout")
		nullIO              = fs.Bool("null-io", true, "switch with /dev/null-backed stdio")
		pidFile             = fs.String("pid-file", "", "optional pid file to write after switch")
		daxDevice           = fs.String("dax-device", "", "optional reader-local DAX device for pseudo_mm import")
		fallbackDaxDevice   = fs.String("fallback-dax-device", "", "legacy fallback DAX device when reader publication has no device")
		pseudoMMPath        = fs.String("pseudo-mm-path", "/dev/pseudo_mm", "pseudo_mm device path")
		prepareOnly         = fs.Bool("prepare-only", false, "prepare the target runtime envelope without restoring the checkpointed process")
		skipActionRebind    = fs.Bool("skip-action-rebind", false, "skip action root rebind because the target envelope was already prepared")
	)
	var actionRebinds actionRebindFlag
	var readerDaxShards daxShardFlag
	fs.Var(&actionRebinds, "action-rebind", "optional packaged action source:target root to rebind before switch (repeatable)")
	fs.Var(&readerDaxShards, "reader-dax-shard", "reader-local DAX shard mapping as shard-id=/dev/daxN.0 (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *checkpointPath == "" && !*prepareOnly {
		return usageFailure(stderr, "checkpoint path must be provided via --checkpoint-path")
	}
	if fs.NArg() != 1 {
		return usageFailure(stderr, "usage: trenv-switch-task [flags] CONTAINER")
	}
	containerID := fs.Arg(0)

	if len(actionRebinds) > 0 && strings.TrimSpace(*sourceContainer) == "" && strings.TrimSpace(*actionSourceRootfs) == "" && !*skipActionRebind {
		return usageFailure(stderr, "source container or action source rootfs must be provided when action-rebind is used")
	}
	_ = strings.TrimSpace(*shellID)
	_ = strings.TrimSpace(*compatibilityClass)
	_ = strings.TrimSpace(*activeRuntimeKind)
	_ = strings.TrimSpace(*activeRuntimeFamily)
	_ = strings.TrimSpace(*stableActionRoot)

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

	rebindMode := "skipped"
	if !*skipActionRebind {
		rebindMode, err = rebindPackagedActionRoots(
			runtimeTaskStateDir,
			*namespaceValue,
			strings.TrimSpace(*sourceContainer),
			strings.TrimSpace(*actionSourceRootfs),
			containerID,
			strings.TrimSpace(*stableActionRoot),
			actionRebinds)
		if err != nil {
			return stepFailure(stderr, fmt.Sprintf("prepare packaged action roots for switch into %q", containerID), err)
		}
	}

	if *prepareOnly {
		fmt.Fprintf(stdout, "prepared target=%s rebind=%s\n", containerID, rebindMode)
		return 0
	}

	if importPlan, ok, err := resolvePseudoMMImportPlan(*checkpointPath, *daxDevice, []daxShardOption(readerDaxShards), *fallbackDaxDevice); err != nil {
		return stepFailure(stderr, "resolve reader pseudo_mm import", err)
	} else if ok {
		targetTask, err := container.Task(ctx, nil)
		if err != nil {
			return stepFailure(stderr, fmt.Sprintf("load prepared target task %q", containerID), err)
		}
		if err := importReaderPseudoMM(ctx, *checkpointPath, *pseudoMMPath, targetTask.Pid(), *importPlan, stderr); err != nil {
			return stepFailure(stderr, fmt.Sprintf("import reader pseudo_mm for %q", containerID), err)
		}
		fmt.Fprintf(stdout, "pseudo_mm_import checkpoint=%s dax=%s start_page=%d length_pages=%d publication=%s\n",
			importPlan.checkpointID,
			importPlan.daxDevice,
			importPlan.daxStartPage,
			importPlan.daxLengthPages,
			importPlan.publicationPath)
	}

	var ioCreator cio.Creator
	if *nullIO {
		ioCreator = cio.NullIO
	} else {
		ioCreator = cio.NewCreator(cio.WithStdio)
	}

	task, err := container.SwitchTask(ctx, ioCreator, func(ctx context.Context, client *containerd.Client, info *containerd.TaskInfo) error {
		info.CheckpointPath = *checkpointPath
		return nil
	})
	if err != nil {
		return stepFailure(stderr, fmt.Sprintf("switch task %q", containerID), err)
	}

	if *pidFile != "" {
		if err := os.WriteFile(*pidFile, []byte(fmt.Sprintf("%d\n", task.Pid())), 0o644); err != nil {
			return stepFailure(stderr, fmt.Sprintf("write pid file %q", *pidFile), err)
		}
	}

	fmt.Fprintf(stdout, "%d\n", task.Pid())
	return 0
}

func usageFailure(stderr io.Writer, message string) int {
	fmt.Fprintln(stderr, message)
	return 2
}

func stepFailure(stderr io.Writer, step string, err error) int {
	fmt.Fprintf(stderr, "%s: %v\n", step, err)
	return 1
}
