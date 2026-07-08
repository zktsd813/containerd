package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	criurpc "github.com/containerd/containerd/third_party/trenv-containerd/pkg/criurpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

const (
	directDescriptorsFilename = "descriptors.json"
	directPseudoMMPath        = "/dev/pseudo_mm"
	directPseudoMMInheritID   = "pseudo-mm-drv"
)

type directCriuOptions struct {
	imagesDirectory string
	workDirectory   string
	logFile         string
	logLevel        int32
	cgroupFile      *os.File
}

type directCriuResult struct {
	pid           int
	stdout        string
	timingsMicros map[string]int64
}

type directCriuSession struct {
	restoredPID int
	criuBinary  string
}

func runDirectCRIURequest(operation string, req switchRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := requestTimeout(timeoutMillis, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	startedAt := time.Now()
	result, err := directRestoreIntoCandidate(ctx, operation, req, config)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error(), TimingsMicros: result.timingsMicros}
	}
	resp := containerResponse{
		ContainerID: req.ContainerID,
		Host:        resultContainerHost(config, req.ContainerID),
		Port:        resultContainerPort(config, req.ContainerID),
		PID:         result.pid,
	}
	payload, err := json.Marshal(resp)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error(), TimingsMicros: result.timingsMicros}
	}
	if result.timingsMicros == nil {
		result.timingsMicros = map[string]int64{}
	}
	result.timingsMicros["direct_restore_total"] = elapsedMicros(startedAt)
	stdout := result.stdout
	if stdout != "" && !strings.HasSuffix(stdout, "\n") {
		stdout += "\n"
	}
	stdout += string(payload) + "\n"
	return execResponse{Ok: true, Stdout: stdout, TimingsMicros: result.timingsMicros}
}

func resultContainerHost(config daemonConfig, containerID string) string {
	state, err := loadContainerState(config, containerID)
	if err == nil && strings.TrimSpace(state.Host) != "" {
		return state.Host
	}
	return "127.0.0.1"
}

func resultContainerPort(config daemonConfig, containerID string) int {
	state, err := loadContainerState(config, containerID)
	if err == nil && state.Port > 0 {
		return state.Port
	}
	return 8080
}

func directRestoreIntoCandidate(ctx context.Context, operation string, req switchRequest, config daemonConfig) (directCriuResult, error) {
	timings := map[string]int64{}
	record := func(name string, started time.Time) {
		timings[name] = elapsedMicros(started)
	}
	started := time.Now()
	state, err := loadContainerState(config, req.ContainerID)
	record("load_state", started)
	if err != nil {
		return directCriuResult{timingsMicros: timings}, err
	}
	if strings.TrimSpace(req.CheckpointPath) == "" {
		return directCriuResult{timingsMicros: timings}, errors.New("checkpoint path is empty")
	}
	if !isDirectory(req.CheckpointPath) {
		return directCriuResult{timingsMicros: timings}, fmt.Errorf("checkpoint path %q is not a directory", req.CheckpointPath)
	}
	if state.PID <= 0 {
		return directCriuResult{timingsMicros: timings}, fmt.Errorf("container %q has invalid candidate pid %d", state.ContainerID, state.PID)
	}

	started = time.Now()
	rebindMode, err := prepareDirectSwitchTarget(req, state, config)
	record("prepare_target", started)
	if err != nil {
		return directCriuResult{timingsMicros: timings}, err
	}

	workDir := filepath.Join(config.WorkingDirectory, "restore-work", sanitizePathPart(req.ContainerID), sanitizePathPart(checkpointID(req.CheckpointPath)))
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		return directCriuResult{timingsMicros: timings}, err
	}
	opts := directCriuOptions{
		imagesDirectory: req.CheckpointPath,
		workDirectory:   workDir,
		logFile:         operation + ".log",
		logLevel:        4,
	}
	started = time.Now()
	restoredPID, err := runDirectCriuSwitch(ctx, state, opts, timings)
	record("criu_switch", started)
	if err != nil {
		return directCriuResult{timingsMicros: timings}, err
	}
	if restoredPID <= 0 {
		return directCriuResult{timingsMicros: timings}, errors.New("CRIU restore did not report a restored pid")
	}

	state.PID = restoredPID
	state.State = "running"
	state.UpdatedAt = time.Now().UTC()
	if err := saveContainerState(config, state); err != nil {
		return directCriuResult{timingsMicros: timings}, err
	}
	if strings.TrimSpace(req.PidFile) != "" {
		if err := os.MkdirAll(filepath.Dir(req.PidFile), 0o755); err != nil {
			return directCriuResult{timingsMicros: timings}, err
		}
		if err := os.WriteFile(req.PidFile, []byte(fmt.Sprintf("%d\n", restoredPID)), 0o644); err != nil {
			return directCriuResult{timingsMicros: timings}, err
		}
	}
	stdout := fmt.Sprintf("direct_restore operation=%s container=%s pid=%d checkpoint=%s rebind=%s\n",
		operation, state.ContainerID, restoredPID, req.CheckpointPath, rebindMode)
	return directCriuResult{pid: restoredPID, stdout: stdout, timingsMicros: timings}, nil
}

func runDirectCriuSwitch(ctx context.Context, state trenvContainerState, opts directCriuOptions, timings map[string]int64) (int, error) {
	imageDir, err := os.Open(opts.imagesDirectory)
	if err != nil {
		return 0, err
	}
	defer imageDir.Close()
	workDir, err := os.Open(opts.workDirectory)
	if err != nil {
		return 0, err
	}
	defer workDir.Close()

	requestType := criurpc.CriuReqType_RESTORE
	rpcOpts := &criurpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
		WorkDirFd:       proto.Int32(int32(workDir.Fd())),
		EvasiveDevices:  proto.Bool(true),
		LogLevel:        proto.Int32(opts.logLevel),
		LogFile:         proto.String(opts.logFile),
		RstSibling:      proto.Bool(true),
		ManageCgroups:   proto.Bool(true),
		NotifyScripts:   proto.Bool(true),
		OrphanPtsMaster: proto.Bool(true),
		Switch:          proto.Bool(true),
	}
	var extraFiles []*os.File
	defer closeFiles(extraFiles)

	started := time.Now()
	if err := inheritDirectSwitchNamespaces(rpcOpts, state.PID, &extraFiles); err != nil {
		return 0, fmt.Errorf("handle switch namespaces: %w", err)
	}
	timings["handle_namespaces"] = elapsedMicros(started)

	started = time.Now()
	if err := inheritDirectPseudoMM(rpcOpts, &extraFiles); err != nil {
		return 0, err
	}
	timings["handle_pseudomm"] = elapsedMicros(started)

	started = time.Now()
	if err := applyDirectCgroup(state.PID, rpcOpts, &opts); err != nil {
		return 0, fmt.Errorf("apply cgroup: %w", err)
	}
	timings["apply_cgroup"] = elapsedMicros(started)
	if opts.cgroupFile != nil {
		defer opts.cgroupFile.Close()
	}

	started = time.Now()
	if err := syscall.Kill(state.PID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return 0, fmt.Errorf("kill candidate pid %d: %w", state.PID, err)
	}
	timings["kill_candidate"] = elapsedMicros(started)

	started = time.Now()
	if err := inheritDirectDescriptors(rpcOpts, opts.imagesDirectory); err != nil {
		return 0, err
	}
	timings["inherit_descriptors"] = elapsedMicros(started)

	session := directCriuSession{criuBinary: nonEmptyOrDefault(state.CriuBinary, "criu")}
	req := &criurpc.CriuReq{Type: &requestType, Opts: rpcOpts}
	started = time.Now()
	if err := session.criuSwrk(req, opts, extraFiles); err != nil {
		return 0, err
	}
	timings["criu_swrk"] = elapsedMicros(started)
	return session.restoredPID, nil
}

func inheritDirectSwitchNamespaces(rpcOpts *criurpc.CriuOpts, pid int, extraFiles *[]*os.File) error {
	for _, ns := range []string{"mnt", "net", "ipc", "uts"} {
		nsPath := fmt.Sprintf("/proc/%d/ns/%s", pid, ns)
		nsFd, err := os.Open(nsPath)
		if err != nil {
			return fmt.Errorf("namespace %s does not exist at %s: %w", ns, nsPath, err)
		}
		inheritFd := &criurpc.InheritFd{
			Key: proto.String(fmt.Sprintf("switch-ns-%s", ns)),
			Fd:  proto.Int32(int32(4 + len(*extraFiles))),
		}
		rpcOpts.InheritFd = append(rpcOpts.InheritFd, inheritFd)
		*extraFiles = append(*extraFiles, nsFd)
	}
	return nil
}

func inheritDirectPseudoMM(rpcOpts *criurpc.CriuOpts, extraFiles *[]*os.File) error {
	drvFile, err := os.Open(directPseudoMMPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open %s: %w", directPseudoMMPath, err)
	}
	inheritFd := &criurpc.InheritFd{
		Key: proto.String(directPseudoMMInheritID),
		Fd:  proto.Int32(int32(4 + len(*extraFiles))),
	}
	rpcOpts.InheritFd = append(rpcOpts.InheritFd, inheritFd)
	*extraFiles = append(*extraFiles, drvFile)
	return nil
}

func inheritDirectDescriptors(rpcOpts *criurpc.CriuOpts, imageDir string) error {
	data, err := os.ReadFile(filepath.Join(imageDir, directDescriptorsFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var fds []string
	if err := json.Unmarshal(data, &fds); err != nil {
		return err
	}
	for i, fd := range fds {
		if strings.Contains(fd, "pipe:") {
			rpcOpts.InheritFd = append(rpcOpts.InheritFd, &criurpc.InheritFd{
				Key: proto.String(fd),
				Fd:  proto.Int32(int32(i)),
			})
		}
	}
	return nil
}

func applyDirectCgroup(pid int, rpcOpts *criurpc.CriuOpts, opts *directCriuOptions) error {
	cgroups, err := parseDirectCgroupFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return err
	}
	if len(cgroups) != 1 {
		return fmt.Errorf("expected cgroup v2 unified hierarchy, got %d entries", len(cgroups))
	}
	var cgroupFile *os.File
	for ctrl, path := range cgroups {
		rpcOpts.CgRoot = append(rpcOpts.CgRoot, &criurpc.CgroupRoot{
			Ctrl: proto.String(ctrl),
			Path: proto.String(path),
		})
		cgroupFile, err = os.Open(filepath.Join("/sys/fs/cgroup", path))
		if err != nil {
			return err
		}
	}
	if cgroupFile == nil {
		return fmt.Errorf("empty cgroup for pid %d", pid)
	}
	opts.cgroupFile = cgroupFile
	rpcOpts.CgroupYard = proto.String("/sys/fs/cgroup")
	mode := criurpc.CriuCgMode_PROPS
	rpcOpts.ManageCgroupsMode = &mode
	return nil
}

func parseDirectCgroupFile(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	cgroups := make(map[string]string)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), ":", 3)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid cgroup entry: %s", scanner.Text())
		}
		for _, subs := range strings.Split(parts[1], ",") {
			cgroups[subs] = parts[2]
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return cgroups, nil
}

func (session *directCriuSession) criuSwrk(req *criurpc.CriuReq, opts directCriuOptions, extraFiles []*os.File) error {
	fds, err := unix.Socketpair(unix.AF_LOCAL, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	criuClient := os.NewFile(uintptr(fds[0]), "criu-transport-client")
	clientConn, err := net.FileConn(criuClient)
	_ = criuClient.Close()
	if err != nil {
		return err
	}
	criuClientConn := clientConn.(*net.UnixConn)
	defer criuClientConn.Close()

	criuServer := os.NewFile(uintptr(fds[1]), "criu-transport-server")
	defer criuServer.Close()

	cmd := exec.Command(nonEmptyOrDefault(session.criuBinary, "criu"), "swrk", "3")
	cmd.Stdin = nil
	cmd.ExtraFiles = append([]*os.File{criuServer}, extraFiles...)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("criu swrk start: %w", err)
	}
	_ = criuServer.Close()
	criuProcess := cmd.Process
	var criuProcessState *os.ProcessState
	defer func() {
		if criuProcessState == nil {
			_ = criuClientConn.Close()
			_, _ = criuProcess.Wait()
		}
	}()

	data, err := proto.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := criuClientConn.Write(data); err != nil {
		return err
	}
	buf := make([]byte, 10*4096)
	oob := make([]byte, 4096)
	for {
		n, oobn, _, _, err := criuClientConn.ReadMsgUnix(buf, oob)
		if err != nil {
			return fmt.Errorf("criu swrk read: %w", err)
		}
		if n == 0 {
			return errors.New("unexpected EOF from criu swrk")
		}
		if n == len(buf) {
			return errors.New("CRIU response buffer is too small")
		}
		resp := new(criurpc.CriuResp)
		if err := proto.Unmarshal(buf[:n], resp); err != nil {
			return err
		}
		if !resp.GetSuccess() {
			return fmt.Errorf("criu failed: type %s errno %d log file: %s",
				req.GetType().String(), resp.GetCrErrno(), filepath.Join(opts.workDirectory, req.GetOpts().GetLogFile()))
		}
		switch resp.GetType() {
		case criurpc.CriuReqType_NOTIFY:
			if err := session.criuNotification(resp, oob[:oobn]); err != nil {
				return err
			}
			notifyType := criurpc.CriuReqType_NOTIFY
			notifyReq := &criurpc.CriuReq{Type: &notifyType, NotifySuccess: proto.Bool(true)}
			data, err = proto.Marshal(notifyReq)
			if err != nil {
				return err
			}
			if _, err := criuClientConn.Write(data); err != nil {
				return err
			}
			continue
		case criurpc.CriuReqType_RESTORE:
			if restore := resp.GetRestore(); restore != nil && restore.GetPid() > 0 {
				session.restoredPID = int(restore.GetPid())
			}
		case criurpc.CriuReqType_DUMP, criurpc.CriuReqType_PRE_DUMP, criurpc.CriuReqType_FEATURE_CHECK:
		default:
			return fmt.Errorf("unexpected CRIU response type %s", resp.GetType().String())
		}
		break
	}
	_ = criuClientConn.CloseWrite()
	criuProcessState, err = criuProcess.Wait()
	if err != nil {
		return fmt.Errorf("criu swrk wait: %w", err)
	}
	if !criuProcessState.Success() && req.GetType() != criurpc.CriuReqType_PRE_DUMP {
		return fmt.Errorf("criu failed: %s log file: %s", criuProcessState.String(), filepath.Join(opts.workDirectory, req.GetOpts().GetLogFile()))
	}
	return nil
}

func (session *directCriuSession) criuNotification(resp *criurpc.CriuResp, _ []byte) error {
	notify := resp.GetNotify()
	if notify == nil {
		return fmt.Errorf("invalid CRIU notification: %s", resp.String())
	}
	switch notify.GetScript() {
	case "post-restore":
		if notify.GetPid() > 0 {
			session.restoredPID = int(notify.GetPid())
		}
		return nil
	default:
		return fmt.Errorf("unsupported CRIU notification type %q", notify.GetScript())
	}
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func prepareDirectSwitchTarget(req switchRequest, target trenvContainerState, config daemonConfig) (string, error) {
	if err := applyDirectRootfsState(target.Rootfs, req.CheckpointPath); err != nil {
		return "", err
	}
	return rebindDirectPackagedActionRoots(req, target, config)
}

func applyDirectRootfsState(targetRootfs, checkpointPath string) error {
	cleanCheckpointPath := filepath.Clean(strings.TrimSpace(checkpointPath))
	if cleanCheckpointPath == "." || filepath.Base(cleanCheckpointPath) != "image" {
		return nil
	}
	sourceRoot := filepath.Join(filepath.Dir(cleanCheckpointPath), directRootfsStateDirectoryName)
	if info, err := os.Stat(sourceRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat rootfs state %q: %w", sourceRoot, err)
	} else if !info.IsDir() {
		return fmt.Errorf("rootfs state %q is not a directory", sourceRoot)
	}
	return filepath.WalkDir(sourceRoot, func(sourcePath string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(sourceRoot, sourcePath)
		if err != nil {
			return err
		}
		if relative == "." {
			return nil
		}
		targetPath := filepath.Join(targetRootfs, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}
		if info.Mode().IsRegular() {
			if err := directReplaceTargetPath(targetPath, info); err != nil {
				return fmt.Errorf("prepare rootfs state target %q: %w", targetPath, err)
			}
			return copyFile(sourcePath, targetPath, info.Mode().Perm())
		}
		return fmt.Errorf("unsupported rootfs state file type at %q with mode %v", sourcePath, info.Mode())
	})
}

func rebindDirectPackagedActionRoots(req switchRequest, target trenvContainerState, config daemonConfig) (string, error) {
	if len(req.ActionRebinds) == 0 {
		return "none", nil
	}
	if mode, ok, err := stableDirectOverlayRebind(req, target, config); err != nil || ok {
		return mode, err
	}
	sourceRootfs := strings.TrimSpace(req.ActionSourceRootfs)
	if sourceRootfs == "" && strings.TrimSpace(req.SourceContainer) != "" && strings.TrimSpace(req.SourceContainer) != target.ContainerID {
		source, err := loadContainerState(config, req.SourceContainer)
		if err != nil {
			return "", fmt.Errorf("load source container %q for action rebind: %w", req.SourceContainer, err)
		}
		sourceRootfs = source.Rootfs
	}
	if sourceRootfs == "" {
		return "none", nil
	}
	for _, rebind := range req.ActionRebinds {
		sourceRelative, err := directContainerSubpath(rebind.SourceRoot)
		if err != nil {
			return "", err
		}
		targetRelative, err := directContainerSubpath(rebind.TargetRoot)
		if err != nil {
			return "", err
		}
		sourcePath := filepath.Join(sourceRootfs, sourceRelative)
		sourceInfo, err := os.Stat(sourcePath)
		if err != nil {
			return "", fmt.Errorf("stat source action root %q: %w", sourcePath, err)
		}
		targetPath := filepath.Join(target.Rootfs, targetRelative)
		if err := directDetachTargetMount(targetPath); err != nil {
			return "", fmt.Errorf("detach previous action root mount %q: %w", targetPath, err)
		}
		if err := directReplaceTargetPath(targetPath, sourceInfo); err != nil {
			return "", fmt.Errorf("prepare action root target %q: %w", targetPath, err)
		}
		if err := unix.Mount(sourcePath, targetPath, "", uintptr(unix.MS_BIND), ""); err != nil {
			return "", fmt.Errorf("bind mount %q -> %q: %w", sourcePath, targetPath, err)
		}
	}
	return "bind", nil
}

func stableDirectOverlayRebind(req switchRequest, target trenvContainerState, config daemonConfig) (string, bool, error) {
	sourceRootfs := strings.TrimSpace(req.ActionSourceRootfs)
	stableActionRoot := strings.TrimSpace(req.StableActionRoot)
	if sourceRootfs == "" || stableActionRoot == "" || len(req.ActionRebinds) != 1 {
		return "", false, nil
	}
	rebind := req.ActionRebinds[0]
	if strings.TrimSpace(rebind.SourceRoot) != stableActionRoot || strings.TrimSpace(rebind.TargetRoot) != stableActionRoot {
		return "", false, nil
	}
	relative, err := directContainerSubpath(stableActionRoot)
	if err != nil {
		return "", false, err
	}
	sourcePath := filepath.Join(sourceRootfs, relative)
	if info, err := os.Stat(sourcePath); err != nil {
		return "", false, fmt.Errorf("stat stable overlay source %q: %w", sourcePath, err)
	} else if !info.IsDir() {
		return "", false, fmt.Errorf("stable overlay source %q is not a directory", sourcePath)
	}
	targetPath := filepath.Join(target.Rootfs, relative)
	if err := os.MkdirAll(targetPath, 0o755); err != nil {
		return "", false, err
	}
	overlayBase := directActionOverlayRoot(config, target.ContainerID)
	upper := filepath.Join(overlayBase, "upper")
	work := filepath.Join(overlayBase, "work")
	if err := directDetachTargetMount(targetPath); err != nil {
		return "", false, err
	}
	_ = unix.Unmount(filepath.Join(overlayBase, "merged"), unix.MNT_DETACH)
	if err := os.RemoveAll(overlayBase); err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	for _, dir := range []string{upper, work, targetPath} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", false, err
		}
	}
	opts := fmt.Sprintf("index=off,lowerdir=%s,upperdir=%s,workdir=%s", sourcePath, upper, work)
	if err := unix.Mount("overlay", targetPath, "overlay", unix.MS_MGC_VAL, opts); err != nil {
		return "", false, fmt.Errorf("mount overlay %q -> %q: %w", sourcePath, targetPath, err)
	}
	return "overlay", true, nil
}

func directActionOverlayRoot(config daemonConfig, containerID string) string {
	if root := strings.TrimSpace(os.Getenv("TRENV_ACTION_OVERLAY_ROOT")); root != "" {
		return filepath.Join(root, sanitizePathPart(containerID))
	}
	return filepath.Join(config.WorkingDirectory, "action-overlays", sanitizePathPart(containerID))
}

func cleanupDirectActionOverlays(config daemonConfig, containerID string) {
	root := directActionOverlayRoot(config, containerID)
	_ = unix.Unmount(filepath.Join(root, "merged"), unix.MNT_DETACH)
	_ = os.RemoveAll(root)
}

func directDetachTargetMount(path string) error {
	if err := unix.Unmount(path, unix.MNT_DETACH); err != nil && err != unix.EINVAL && err != unix.ENOENT {
		return err
	}
	return nil
}

func directReplaceTargetPath(target string, sourceInfo os.FileInfo) error {
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
