package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/containernetworking/cni/libcni"
	cnicurrent "github.com/containernetworking/cni/pkg/types/100"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type createContainerRequest struct {
	ContainerID           string              `json:"containerId"`
	LogicalName           string              `json:"logicalName"`
	Spec                  createContainerSpec `json:"spec"`
	StartMode             string              `json:"startMode"`
	RootfsCacheDirectory  string              `json:"rootfsCacheDirectory"`
	RuncBinary            string              `json:"runcBinary"`
	CriuBinary            string              `json:"criuBinary"`
	UseCNI                bool                `json:"useCni"`
	UseHostNetwork        bool                `json:"useHostNetwork"`
	AddressStrategy       string              `json:"addressStrategy"`
	HostAddress           string              `json:"hostAddress"`
	HostPort              int                 `json:"hostPort"`
	CNI                   createContainerCNI  `json:"cni"`
	CleanupOnStartFailure bool                `json:"cleanupOnStartFailure"`
}

type createContainerSpec struct {
	Image         string            `json:"image"`
	MemoryMiB     int64             `json:"memoryMiB"`
	CPUShares     int               `json:"cpuShares"`
	CPULimit      *float64          `json:"cpuLimit,omitempty"`
	Environment   map[string]string `json:"environment"`
	Network       string            `json:"network"`
	DNSServers    []string          `json:"dnsServers"`
	DNSSearch     []string          `json:"dnsSearch"`
	DNSOptions    []string          `json:"dnsOptions"`
	RuntimeKind   string            `json:"runtimeKind,omitempty"`
	RuntimeFamily string            `json:"runtimeFamily,omitempty"`
}

type createContainerCNI struct {
	DataDir         string `json:"dataDir"`
	NetworkName     string `json:"networkName"`
	InterfacePrefix string `json:"interfacePrefix"`
}

type containerRequest struct {
	ContainerID string `json:"containerId"`
}

type cleanupContainersRequest struct {
	ContainerPrefix string `json:"containerPrefix"`
}

type containerResponse struct {
	ContainerID string `json:"containerId"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	PID         int    `json:"pid,omitempty"`
}

type trenvContainerState struct {
	ContainerID    string    `json:"containerId"`
	LogicalName    string    `json:"logicalName"`
	Image          string    `json:"image"`
	Rootfs         string    `json:"rootfs"`
	Bundle         string    `json:"bundle"`
	PID            int       `json:"pid"`
	Host           string    `json:"host"`
	Port           int       `json:"port"`
	CgroupPath     string    `json:"cgroupPath"`
	RuncRoot       string    `json:"runcRoot"`
	RuncBinary     string    `json:"runcBinary"`
	CriuBinary     string    `json:"criuBinary"`
	CheckpointPath string    `json:"checkpointPath,omitempty"`
	State          string    `json:"state"`
	CNIDataDir     string    `json:"cniDataDir,omitempty"`
	CNIConfDir     string    `json:"cniConfDir,omitempty"`
	CNIBinDir      string    `json:"cniBinDir,omitempty"`
	CNINetworkName string    `json:"cniNetworkName,omitempty"`
	CNIInterface   string    `json:"cniInterface,omitempty"`
	UseCNI         bool      `json:"useCni"`
	UseHostNetwork bool      `json:"useHostNetwork"`
	CreatedAt      time.Time `json:"createdAt"`
	UpdatedAt      time.Time `json:"updatedAt"`
}

type rootfsCacheEntry struct {
	Bundle string
	Rootfs string
	Config string
}

func runCreateContainerRequest(req createContainerRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := requestTimeout(timeoutMillis, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	state, err := createDirectContainer(ctx, req, config)
	if err != nil {
		if req.CleanupOnStartFailure && strings.TrimSpace(req.ContainerID) != "" {
			_ = removeDirectContainer(context.Background(), strings.TrimSpace(req.ContainerID), config)
		}
		return execResponse{Ok: false, Error: err.Error()}
	}
	payload, err := json.Marshal(containerResponse{
		ContainerID: state.ContainerID,
		Host:        state.Host,
		Port:        state.Port,
		PID:         state.PID,
	})
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	return execResponse{Ok: true, Stdout: string(payload) + "\n"}
}

func runDirectCheckpointRequest(req checkpointRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := requestTimeout(timeoutMillis, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	state, err := loadContainerState(config, req.ContainerID)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	if strings.TrimSpace(req.ImagePath) == "" {
		return execResponse{Ok: false, Error: "checkpoint image path is empty"}
	}
	if strings.TrimSpace(req.WorkPath) == "" {
		return execResponse{Ok: false, Error: "checkpoint work path is empty"}
	}
	if err := os.MkdirAll(req.ImagePath, 0o755); err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	if err := os.MkdirAll(req.WorkPath, 0o755); err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	args := []string{
		"--root", state.RuncRoot,
		"checkpoint",
		"--image-path", req.ImagePath,
		"--work-path", req.WorkPath,
		"--leave-running",
		"--tcp-established",
		"--file-locks",
		state.ContainerID,
	}
	stdout, stderr, err := runCommandCapture(ctx, state.RuncBinary, args...)
	if err != nil {
		return commandExecResponse("runc checkpoint", stdout, stderr, err, ctx)
	}
	placement, err := prepareDirectCheckpointPublication(ctx, req, state, config)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	if err := finalizeDirectCheckpoint(ctx, req, state, config, placement); err != nil {
		response := execResponse{Ok: false, Error: err.Error()}
		if config.DedupCheckpointMode == "sync-required" {
			response.ErrorCode = "dedup_checkpoint_rejected"
		}
		return response
	}
	state.CheckpointPath = req.ImagePath
	state.UpdatedAt = time.Now().UTC()
	_ = saveContainerState(config, state)
	return execResponse{Ok: true, Stdout: req.ImagePath + "\n"}
}

func runDirectRestoreRequest(req switchRequest, timeoutMillis int64, config daemonConfig) execResponse {
	if err := validateSwitchPublicationIdentity(req); err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	return runDirectCRIURequest("restoreIntoContainer", req, timeoutMillis, config)
}

func runDirectSwitchRequest(req switchRequest, timeoutMillis int64, config daemonConfig) execResponse {
	if err := validateSwitchPublicationIdentity(req); err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	return runDirectCRIURequest("switchIntoCandidate", req, timeoutMillis, config)
}

func runContainerLifecycleRequest(operation string, req containerRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := requestTimeout(timeoutMillis, 10*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	containerID := strings.TrimSpace(req.ContainerID)
	if containerID == "" {
		return execResponse{Ok: false, Error: "container id is empty"}
	}
	var err error
	switch operation {
	case "pauseContainer":
		err = freezeDirectContainer(config, containerID, true)
	case "resumeContainer":
		err = freezeDirectContainer(config, containerID, false)
	case "removeContainer":
		err = removeDirectContainer(ctx, containerID, config)
	default:
		err = fmt.Errorf("unsupported container lifecycle operation %q", operation)
	}
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	return execResponse{Ok: true, Stdout: fmt.Sprintf("%s %s\n", operation, containerID)}
}

func runCleanupContainersRequest(req cleanupContainersRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := requestTimeout(timeoutMillis, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	prefix := strings.TrimSpace(req.ContainerPrefix)
	if prefix == "" {
		return execResponse{Ok: false, Error: "container prefix is empty"}
	}
	ids, err := listContainerStateIDs(config)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	var warnings []string
	for _, id := range ids {
		if !strings.HasPrefix(id, prefix) {
			continue
		}
		if err := removeDirectContainer(ctx, id, config); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s: %v", id, err))
		}
	}
	if err := removeDirectProjectedContainersByPrefix(prefix, config); err != nil {
		warnings = append(warnings, fmt.Sprintf("restore projections: %v", err))
	}
	stdout := fmt.Sprintf("cleanupContainers prefix=%s\n", prefix)
	if len(warnings) > 0 {
		stdout += "warnings=" + strings.Join(warnings, " | ") + "\n"
	}
	return execResponse{Ok: len(warnings) == 0, Stdout: stdout, Error: strings.Join(warnings, " | ")}
}

func createDirectContainer(ctx context.Context, req createContainerRequest, config daemonConfig) (trenvContainerState, error) {
	containerID := strings.TrimSpace(req.ContainerID)
	if containerID == "" {
		return trenvContainerState{}, errors.New("container id is empty")
	}
	cache, err := resolveRootfsCache(req.RootfsCacheDirectory, req.Spec.Image)
	if err != nil {
		return trenvContainerState{}, err
	}
	now := time.Now().UTC()
	containerRoot := filepath.Join(runtimeContainersRoot(config), sanitizePathPart(containerID))
	bundle := filepath.Join(containerRoot, "bundle")
	mergedRootfs := filepath.Join(containerRoot, "rootfs")
	upper := filepath.Join(containerRoot, "overlay-upper")
	work := filepath.Join(containerRoot, "overlay-work")
	pidPath := filepath.Join(containerRoot, "init.pid")
	runcRoot := filepath.Join(config.WorkingDirectory, "runc")
	runcBinary := nonEmptyOrDefault(req.RuncBinary, "runc")
	criuBinary := nonEmptyOrDefault(req.CriuBinary, "criu")
	if err := os.RemoveAll(containerRoot); err != nil {
		return trenvContainerState{}, err
	}
	for _, dir := range []string{bundle, mergedRootfs, upper, work, runcRoot} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return trenvContainerState{}, err
		}
	}
	if err := mountOverlay(cache.Rootfs, upper, work, mergedRootfs); err != nil {
		return trenvContainerState{}, err
	}
	mounted := true
	created := false
	started := false
	cniAdded := false
	pid := 0
	defer func() {
		if started {
			return
		}
		if cniAdded && pid > 0 {
			_ = delCNI(context.Background(), trenvContainerState{
				ContainerID:    containerID,
				PID:            pid,
				CNIDataDir:     req.CNI.DataDir,
				CNIConfDir:     "/etc/cni/net.d",
				CNIBinDir:      "/opt/cni/bin",
				CNINetworkName: req.CNI.NetworkName,
				CNIInterface:   cniInterfaceName(req.CNI.InterfacePrefix),
				UseCNI:         req.UseCNI,
				UseHostNetwork: req.UseHostNetwork,
			})
		}
		if created {
			_, _, _ = runCommandCapture(context.Background(), runcBinary, "--root", runcRoot, "kill", containerID, "KILL")
			_, _, _ = runCommandCapture(context.Background(), runcBinary, "--root", runcRoot, "delete", "--force", containerID)
		}
		if mounted {
			_ = syscall.Unmount(mergedRootfs, syscall.MNT_DETACH)
		}
		if req.CleanupOnStartFailure {
			_ = os.RemoveAll(containerRoot)
			_ = os.Remove(statePath(config, containerID))
		}
	}()
	cgroupPath := filepath.Join("openwhisk-trenv", sanitizePathPart(containerID))
	if err := writeBundleConfig(cache.Config, filepath.Join(bundle, "config.json"), mergedRootfs, cgroupPath, req); err != nil {
		return trenvContainerState{}, err
	}
	args := []string{"--root", runcRoot, "create", "--bundle", bundle, "--pid-file", pidPath, containerID}
	stdout, stderr, err := runCommandDiscardStdio(ctx, runcBinary, args...)
	if err != nil {
		return trenvContainerState{}, fmt.Errorf("runc create failed: %s", commandErrorString(err, stderr+"\n"+stdout))
	}
	created = true
	pid, err = readPidFile(pidPath)
	if err != nil {
		return trenvContainerState{}, err
	}
	host := nonEmptyOrDefault(req.HostAddress, "127.0.0.1")
	if req.UseCNI && !req.UseHostNetwork {
		cniHost, err := addCNI(ctx, containerID, pid, req.CNI)
		if err != nil {
			return trenvContainerState{}, err
		}
		cniAdded = true
		if cniHost != "" {
			host = cniHost
		}
	}
	stdout, stderr, err = runCommandDiscardStdio(ctx, runcBinary, "--root", runcRoot, "start", containerID)
	if err != nil {
		return trenvContainerState{}, fmt.Errorf("runc start failed: %s", commandErrorString(err, stderr+"\n"+stdout))
	}
	started = true
	mounted = false
	state := trenvContainerState{
		ContainerID:    containerID,
		LogicalName:    nonEmptyOrDefault(req.LogicalName, containerID),
		Image:          req.Spec.Image,
		Rootfs:         mergedRootfs,
		Bundle:         bundle,
		PID:            pid,
		Host:           host,
		Port:           req.HostPort,
		CgroupPath:     cgroupPath,
		RuncRoot:       runcRoot,
		RuncBinary:     runcBinary,
		CriuBinary:     criuBinary,
		State:          "running",
		CNIDataDir:     req.CNI.DataDir,
		CNIConfDir:     "/etc/cni/net.d",
		CNIBinDir:      "/opt/cni/bin",
		CNINetworkName: req.CNI.NetworkName,
		CNIInterface:   cniInterfaceName(req.CNI.InterfacePrefix),
		UseCNI:         req.UseCNI,
		UseHostNetwork: req.UseHostNetwork,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if state.Port == 0 {
		state.Port = 8080
	}
	if err := saveContainerState(config, state); err != nil {
		return trenvContainerState{}, err
	}
	return state, nil
}

func writeBundleConfig(sourceConfig, targetConfig, rootfs, cgroupPath string, req createContainerRequest) error {
	spec, err := readOCISpec(sourceConfig)
	if err != nil {
		return err
	}
	if spec.Root == nil {
		spec.Root = &specs.Root{}
	}
	spec.Root.Path = rootfs
	spec.Root.Readonly = false
	if spec.Process == nil {
		spec.Process = &specs.Process{}
	}
	spec.Process.Terminal = false
	if len(spec.Process.Args) == 0 {
		spec.Process.Args = []string{"/bin/sh"}
	}
	if spec.Process.Cwd == "" {
		spec.Process.Cwd = "/"
	}
	spec.Process.Env = mergeEnv(spec.Process.Env, req.Spec.Environment)
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	spec.Linux.CgroupsPath = cgroupPath
	spec.Linux.Namespaces = ensureNamespaces(spec.Linux.Namespaces, req.UseHostNetwork)
	applyResources(spec, req.Spec)
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(targetConfig, data, 0o644)
}

func readOCISpec(path string) (specs.Spec, error) {
	var spec specs.Spec
	data, err := os.ReadFile(path)
	if err != nil {
		return defaultOCISpec(), err
	}
	if err := json.Unmarshal(data, &spec); err != nil {
		return specs.Spec{}, fmt.Errorf("parse OCI config %s: %w", path, err)
	}
	if spec.Version == "" {
		spec.Version = "1.0.2"
	}
	return spec, nil
}

func defaultOCISpec() specs.Spec {
	return specs.Spec{
		Version: "1.0.2",
		Process: &specs.Process{
			Args: []string{"/bin/sh"},
			Env:  []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
			Cwd:  "/",
		},
		Root: &specs.Root{Path: "rootfs"},
		Mounts: []specs.Mount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
			{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
		},
		Linux: &specs.Linux{},
	}
}

func ensureNamespaces(namespaces []specs.LinuxNamespace, useHostNetwork bool) []specs.LinuxNamespace {
	required := []specs.LinuxNamespaceType{
		specs.PIDNamespace,
		specs.MountNamespace,
		specs.IPCNamespace,
		specs.UTSNamespace,
		specs.CgroupNamespace,
	}
	if !useHostNetwork {
		required = append(required, specs.NetworkNamespace)
	}
	seen := map[specs.LinuxNamespaceType]bool{}
	result := make([]specs.LinuxNamespace, 0, len(namespaces)+len(required))
	for _, ns := range namespaces {
		if useHostNetwork && ns.Type == specs.NetworkNamespace {
			continue
		}
		seen[ns.Type] = true
		result = append(result, ns)
	}
	for _, ns := range required {
		if !seen[ns] {
			result = append(result, specs.LinuxNamespace{Type: ns})
		}
	}
	return result
}

func applyResources(spec specs.Spec, createSpec createContainerSpec) {
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	if spec.Linux.Resources == nil {
		spec.Linux.Resources = &specs.LinuxResources{}
	}
	if createSpec.MemoryMiB > 0 {
		limit := createSpec.MemoryMiB * 1024 * 1024
		spec.Linux.Resources.Memory = &specs.LinuxMemory{Limit: &limit}
	}
	if createSpec.CPUShares > 0 || createSpec.CPULimit != nil {
		cpu := &specs.LinuxCPU{}
		if createSpec.CPUShares > 0 {
			shares := uint64(createSpec.CPUShares)
			cpu.Shares = &shares
		}
		if createSpec.CPULimit != nil && *createSpec.CPULimit > 0 {
			period := uint64(100000)
			quota := int64(math.Round(*createSpec.CPULimit * float64(period)))
			cpu.Period = &period
			cpu.Quota = &quota
		}
		spec.Linux.Resources.CPU = cpu
	}
}

func mergeEnv(existing []string, overrides map[string]string) []string {
	values := map[string]string{}
	for _, entry := range existing {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			values[key] = value
		}
	}
	for key, value := range overrides {
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sortStrings(keys)
	merged := make([]string, 0, len(keys))
	for _, key := range keys {
		merged = append(merged, key+"="+values[key])
	}
	return merged
}

func resolveRootfsCache(root, image string) (rootfsCacheEntry, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return rootfsCacheEntry{}, errors.New("rootfs cache directory is empty")
	}
	imageKey := sanitizePathPart(image)
	candidates := []string{
		filepath.Join(root, imageKey),
		root,
	}
	for _, candidate := range candidates {
		rootfs := filepath.Join(candidate, "rootfs")
		config := filepath.Join(candidate, "config.json")
		if isDirectory(rootfs) && isRegularFile(config) {
			return rootfsCacheEntry{Bundle: candidate, Rootfs: rootfs, Config: config}, nil
		}
	}
	return rootfsCacheEntry{}, fmt.Errorf("rootfs cache miss for image %q under %s; expected %s/rootfs and config.json", image, root, imageKey)
}

func mountOverlay(lower, upper, work, merged string) error {
	if err := prepareOverlayDirectories(upper, work, merged); err != nil {
		return err
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)
	return syscall.Mount("overlay", merged, "overlay", 0, opts)
}

func prepareOverlayDirectories(upper, work, merged string) error {
	for _, directory := range []string{upper, work, merged} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			return fmt.Errorf("create overlay directory %s: %w", directory, err)
		}
	}
	return nil
}

func addCNI(ctx context.Context, containerID string, pid int, cfg createContainerCNI) (string, error) {
	confPath, err := findCNIConfig(cfg.NetworkName)
	if err != nil {
		return "", err
	}
	network, err := libcni.ConfListFromFile(confPath)
	if err != nil {
		return "", err
	}
	cni := libcni.NewCNIConfigWithCacheDir([]string{"/opt/cni/bin"}, nonEmptyOrDefault(cfg.DataDir, "/var/run/cni"), nil)
	result, err := cni.AddNetworkList(ctx, network, &libcni.RuntimeConf{
		ContainerID: containerID,
		NetNS:       fmt.Sprintf("/proc/%d/ns/net", pid),
		IfName:      cniInterfaceName(cfg.InterfacePrefix),
	})
	if err != nil {
		return "", err
	}
	current, err := cnicurrent.NewResultFromResult(result)
	if err != nil {
		return "", err
	}
	for _, ip := range current.IPs {
		if ip != nil && ip.Address.IP != nil {
			return ip.Address.IP.String(), nil
		}
	}
	return "", nil
}

func delCNI(ctx context.Context, state trenvContainerState) error {
	if !state.UseCNI || state.UseHostNetwork {
		return nil
	}
	confPath, err := findCNIConfig(state.CNINetworkName)
	if err != nil {
		return err
	}
	network, err := libcni.ConfListFromFile(confPath)
	if err != nil {
		return err
	}
	netns := fmt.Sprintf("/proc/%d/ns/net", state.PID)
	cni := libcni.NewCNIConfigWithCacheDir([]string{nonEmptyOrDefault(state.CNIBinDir, "/opt/cni/bin")}, nonEmptyOrDefault(state.CNIDataDir, "/var/run/cni"), nil)
	return cni.DelNetworkList(ctx, network, &libcni.RuntimeConf{
		ContainerID: state.ContainerID,
		NetNS:       netns,
		IfName:      nonEmptyOrDefault(state.CNIInterface, "eth0"),
	})
}

func findCNIConfig(networkName string) (string, error) {
	name := nonEmptyOrDefault(networkName, "openwhisk-trenv-bridge")
	dir := "/etc/cni/net.d"
	candidates := []string{
		filepath.Join(dir, name+".conflist"),
		filepath.Join(dir, name+".conf"),
	}
	for _, candidate := range candidates {
		if isRegularFile(candidate) {
			return candidate, nil
		}
	}
	matches, err := filepath.Glob(filepath.Join(dir, "*.conflist"))
	if err == nil {
		for _, match := range matches {
			if cniConfigNameMatches(match, name) {
				return match, nil
			}
		}
	}
	matches, err = filepath.Glob(filepath.Join(dir, "*.conf"))
	if err == nil {
		for _, match := range matches {
			if cniConfigNameMatches(match, name) {
				return match, nil
			}
		}
	}
	return "", fmt.Errorf("CNI config for network %q not found under %s", name, dir)
}

func cniConfigNameMatches(path, name string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var header struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &header); err != nil {
		return false
	}
	return header.Name == name
}

func cniInterfaceName(prefix string) string {
	value := strings.TrimSpace(prefix)
	if value == "" {
		return "eth0"
	}
	last := value[len(value)-1]
	if last >= '0' && last <= '9' {
		return value
	}
	return value + "0"
}

func freezeDirectContainer(config daemonConfig, containerID string, freeze bool) error {
	state, err := loadContainerState(config, containerID)
	if err != nil {
		return err
	}
	cgroupPath, err := directContainerCgroupPath(state)
	if err != nil {
		return err
	}
	value := "0"
	if freeze {
		value = "1"
	}
	path := filepath.Join("/sys/fs/cgroup", cgroupPath, "cgroup.freeze")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o644); err != nil {
		return err
	}
	state.CgroupPath = cgroupPath
	if freeze {
		state.State = "paused"
	} else {
		state.State = "running"
	}
	state.UpdatedAt = time.Now().UTC()
	return saveContainerState(config, state)
}

func removeDirectContainer(ctx context.Context, containerID string, config daemonConfig) error {
	state, err := loadContainerState(config, containerID)
	if err != nil {
		if os.IsNotExist(err) {
			return removeDirectProjectedTreesForContainer(containerID, config)
		}
		return err
	}
	cgroupPath, err := directContainerCgroupPath(state)
	if err != nil {
		cgroupPath = expectedDirectContainerCgroupPath(state.ContainerID)
	}
	_ = delCNI(ctx, state)
	_, _, _ = runCommandCapture(ctx, state.RuncBinary, "--root", state.RuncRoot, "kill", state.ContainerID, "KILL")
	killCgroupProcs(cgroupPath)
	_, _, _ = runCommandCapture(ctx, state.RuncBinary, "--root", state.RuncRoot, "delete", "--force", state.ContainerID)
	cleanupDirectActionOverlays(config, state.ContainerID)
	_ = syscall.Unmount(state.Rootfs, syscall.MNT_DETACH)
	projectionErr := removeDirectProjectedTreesForContainer(containerID, config)
	if err := os.RemoveAll(filepath.Dir(state.Bundle)); err != nil {
		return err
	}
	stateErr := os.Remove(statePath(config, containerID))
	if projectionErr != nil {
		return projectionErr
	}
	return stateErr
}

func directContainerCgroupPath(state trenvContainerState) (string, error) {
	return directStoredCgroupPath(state)
}

func directStoredCgroupPath(state trenvContainerState) (string, error) {
	path := strings.TrimSpace(state.CgroupPath)
	if path == "" {
		return "", fmt.Errorf("empty cgroup path for %s", state.ContainerID)
	}
	normalized, err := normalizeDirectCgroupPath(path)
	if err != nil {
		return "", err
	}
	expected := expectedDirectContainerCgroupPath(state.ContainerID)
	if normalized != expected {
		return "", fmt.Errorf("unsafe cgroup path %q for %s; expected %q", normalized, state.ContainerID, expected)
	}
	return normalized, nil
}

func expectedDirectContainerCgroupPath(containerID string) string {
	return filepath.Join("openwhisk-trenv", sanitizePathPart(containerID))
}

func normalizeDirectCgroupPath(path string) (string, error) {
	normalized := strings.TrimPrefix(strings.TrimSpace(path), "/")
	if normalized == "" {
		return "", fmt.Errorf("empty cgroup path")
	}
	return normalized, nil
}

func killCgroupProcs(cgroupPath string) {
	data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(cgroupPath, "/"), "cgroup.procs"))
	if err != nil {
		return
	}
	for _, field := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(field)
		if err == nil {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	}
}

func saveContainerState(config daemonConfig, state trenvContainerState) error {
	if err := os.MkdirAll(stateRoot(config), 0o755); err != nil {
		return err
	}
	return writeJSONFile(statePath(config, state.ContainerID), state)
}

func loadContainerState(config daemonConfig, containerID string) (trenvContainerState, error) {
	path := statePath(config, containerID)
	data, err := os.ReadFile(path)
	if err != nil {
		return trenvContainerState{}, err
	}
	var state trenvContainerState
	if err := json.Unmarshal(data, &state); err != nil {
		return trenvContainerState{}, err
	}
	return state, nil
}

func listContainerStateIDs(config daemonConfig) ([]string, error) {
	entries, err := os.ReadDir(stateRoot(config))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		ids = append(ids, strings.TrimSuffix(entry.Name(), ".json"))
	}
	sortStrings(ids)
	return ids, nil
}

func stateRoot(config daemonConfig) string {
	return filepath.Join(config.WorkingDirectory, daemonStateDirectory, "containers")
}

func runtimeContainersRoot(config daemonConfig) string {
	return filepath.Join(config.WorkingDirectory, "runtime")
}

func statePath(config daemonConfig, containerID string) string {
	return filepath.Join(stateRoot(config), sanitizePathPart(containerID)+".json")
}

func readPidFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse pid file %s: %w", path, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d in %s", pid, path)
	}
	return pid, nil
}

func requestTimeout(timeoutMillis int64, fallback time.Duration) time.Duration {
	timeout := time.Duration(timeoutMillis) * time.Millisecond
	if timeout <= 0 {
		return fallback
	}
	return timeout
}

func runCommandCapture(ctx context.Context, binary string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	stdoutFile, err := os.CreateTemp("", daemonName+"-command-stdout-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(stdoutFile.Name())
	stderrFile, err := os.CreateTemp("", daemonName+"-command-stderr-*")
	if err != nil {
		_ = stdoutFile.Close()
		return "", "", err
	}
	defer os.Remove(stderrFile.Name())

	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	err = cmd.Run()
	_ = stdoutFile.Close()
	_ = stderrFile.Close()
	stdout, stdoutErr := os.ReadFile(stdoutFile.Name())
	stderr, stderrErr := os.ReadFile(stderrFile.Name())
	if err == nil {
		if stdoutErr != nil {
			err = stdoutErr
		} else if stderrErr != nil {
			err = stderrErr
		}
	}
	return string(stdout), string(stderr), err
}

func runCommandDiscardStdio(ctx context.Context, binary string, args ...string) (string, string, error) {
	stdinFile, err := os.Open(os.DevNull)
	if err != nil {
		return "", "", err
	}
	defer stdinFile.Close()
	stdoutFile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return "", "", err
	}
	defer stdoutFile.Close()
	stderrFile, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return "", "", err
	}
	defer stderrFile.Close()

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = stdinFile
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	return "", "", cmd.Run()
}

func commandExecResponse(label, stdout, stderr string, err error, ctx context.Context) execResponse {
	exitCode := 1
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		exitCode = exitErr.ExitCode()
	}
	message := err.Error()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		message = label + " timed out"
	}
	return execResponse{Ok: false, Stdout: stdout, Stderr: stderr, ExitCode: exitCode, Error: message}
}

func sortStrings(values []string) {
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
}
