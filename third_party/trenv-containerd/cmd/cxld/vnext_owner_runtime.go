package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

// vnextOwnerRuntimeConfig is all-or-nothing. An empty configuration leaves
// the VNext Owner RPC unavailable; a partial or invalid configuration aborts
// daemon startup. It never creates or formats a device or Owner journal.
type vnextOwnerRuntimeConfig struct {
	ControlFilePath    string
	ControlSlotBytes   uint64
	DAXDeviceList      string
	SchedulerAuthority vnextOwnerSchedulerAuthorityConfig
}

type vnextOwnerSchedulerAuthorityInput struct {
	Endpoints         string
	LeaderKey         string
	ExpectedCluster   string
	CAFile            string
	ClientCertFile    string
	ClientKeyFile     string
	DialTimeoutMillis int64
	ReadTimeoutMillis int64
}

func parseVNextOwnerSchedulerAuthorityInput(
	input vnextOwnerSchedulerAuthorityInput,
) (vnextOwnerSchedulerAuthorityConfig, error) {
	var config vnextOwnerSchedulerAuthorityConfig
	if input.Endpoints != "" {
		if strings.TrimSpace(input.Endpoints) != input.Endpoints {
			return config, errors.New(
				"Scheduler authority etcd endpoints have surrounding whitespace")
		}
		config.Endpoints = strings.Split(input.Endpoints, ",")
		for index, endpoint := range config.Endpoints {
			if endpoint == "" {
				return vnextOwnerSchedulerAuthorityConfig{}, fmt.Errorf(
					"Scheduler authority etcd endpoint %d is empty", index)
			}
		}
	}
	config.LeaderKey = input.LeaderKey
	if input.ExpectedCluster != "" {
		cluster, err := decodeVNextOwnerSchedulerHexU64(
			"Scheduler authority expected cluster ID",
			input.ExpectedCluster,
			false)
		if err != nil {
			return vnextOwnerSchedulerAuthorityConfig{}, err
		}
		config.ExpectedCluster = cluster
	}
	config.CAFile = input.CAFile
	config.ClientCertFile = input.ClientCertFile
	config.ClientKeyFile = input.ClientKeyFile
	var err error
	config.DialTimeout, err = vnextOwnerSchedulerTimeoutFromMillis(
		"Scheduler authority etcd dial timeout", input.DialTimeoutMillis)
	if err != nil {
		return vnextOwnerSchedulerAuthorityConfig{}, err
	}
	config.ReadTimeout, err = vnextOwnerSchedulerTimeoutFromMillis(
		"Scheduler authority etcd read timeout", input.ReadTimeoutMillis)
	if err != nil {
		return vnextOwnerSchedulerAuthorityConfig{}, err
	}
	return config, nil
}

func vnextOwnerSchedulerTimeoutFromMillis(
	name string,
	value int64,
) (time.Duration, error) {
	if value < 0 || value > int64(math.MaxInt64)/int64(time.Millisecond) {
		return 0, fmt.Errorf("%s milliseconds are outside the duration ABI", name)
	}
	return time.Duration(value) * time.Millisecond, nil
}

type vnextOwnerOpenedDevice struct {
	device *vnextPersistentDevice
	close  func() error
}

type vnextOwnerRuntimeDependencies struct {
	openControlFile        func(string) (*os.File, error)
	openDevice             func(string) (vnextOwnerOpenedDevice, error)
	openSchedulerAuthority func(
		vnextOwnerSchedulerAuthorityConfig,
	) (vnextOwnerSchedulerAuthorityVerifier, func() error, error)
}

type vnextOwnerRuntime struct {
	mu                      sync.Mutex
	service                 *vnextOwnerService
	schedulerAuthorityClose func() error
	controlFile             *os.File
	controlClose            func() error
	devices                 []vnextOwnerOpenedDevice
	closed                  bool
}

type vnextOwnerRuntimeCloseErrors struct {
	failures []error
}

func (closeErrors *vnextOwnerRuntimeCloseErrors) Error() string {
	messages := make([]string, 0, len(closeErrors.failures))
	for _, failure := range closeErrors.failures {
		messages = append(messages, failure.Error())
	}
	return strings.Join(messages, "; ")
}

// Is keeps every exactly-once terminal diagnosis discoverable on Go versions
// that predate multi-error Unwrap support.
func (closeErrors *vnextOwnerRuntimeCloseErrors) Is(target error) bool {
	for _, failure := range closeErrors.failures {
		if errors.Is(failure, target) {
			return true
		}
	}
	return false
}

func appendVNextOwnerRuntimeCloseError(existing error, next error) error {
	if next == nil {
		return existing
	}
	if existing == nil {
		return next
	}
	if aggregate, ok := existing.(*vnextOwnerRuntimeCloseErrors); ok {
		aggregate.failures = append(aggregate.failures, next)
		return aggregate
	}
	return &vnextOwnerRuntimeCloseErrors{failures: []error{existing, next}}
}

func openVNextOwnerRuntime(config vnextOwnerRuntimeConfig) (*vnextOwnerRuntime, error) {
	return openVNextOwnerRuntimeWithDependencies(config, vnextOwnerRuntimeDependencies{
		openControlFile: func(path string) (*os.File, error) {
			return os.OpenFile(path, os.O_RDWR, 0)
		},
		openDevice: func(path string) (vnextOwnerOpenedDevice, error) {
			device, err := openVNextDevDAXDevice(path)
			if err != nil {
				return vnextOwnerOpenedDevice{}, err
			}
			return vnextOwnerOpenedDevice{
				device: device,
				close:  device.closeStorage,
			}, nil
		},
		openSchedulerAuthority: func(
			config vnextOwnerSchedulerAuthorityConfig,
		) (vnextOwnerSchedulerAuthorityVerifier, func() error, error) {
			verifier, closeAuthority, err := openVNextOwnerSchedulerAuthority(config)
			if err != nil {
				return nil, nil, err
			}
			return verifier, closeAuthority, nil
		},
	})
}

func openVNextOwnerRuntimeWithDependencies(
	config vnextOwnerRuntimeConfig,
	dependencies vnextOwnerRuntimeDependencies,
) (_ *vnextOwnerRuntime, returnErr error) {
	controlPath := strings.TrimSpace(config.ControlFilePath)
	deviceList := strings.TrimSpace(config.DAXDeviceList)
	runtimeConfiguredFields := 0
	if controlPath != "" {
		runtimeConfiguredFields++
	}
	if config.ControlSlotBytes != 0 {
		runtimeConfiguredFields++
	}
	if deviceList != "" {
		runtimeConfiguredFields++
	}
	authorityConfiguredFields := vnextOwnerSchedulerAuthorityConfiguredFields(
		config.SchedulerAuthority)
	if runtimeConfiguredFields == 0 && authorityConfiguredFields == 0 {
		return nil, nil
	}
	if runtimeConfiguredFields != 3 {
		return nil, errors.New(
			"VNext Owner requires control file, control slot bytes, and DAX devices together")
	}
	if authorityConfiguredFields != 8 {
		return nil, errors.New(
			"local VNext Owner requires all eight Scheduler-authority etcd settings together")
	}
	if dependencies.openControlFile == nil || dependencies.openDevice == nil ||
		dependencies.openSchedulerAuthority == nil {
		return nil, errors.New("VNext Owner runtime open dependencies are incomplete")
	}
	if err := validateVNextOwnerRuntimePath(controlPath, "control file"); err != nil {
		return nil, err
	}
	devicePaths, err := parseVNextOwnerDevicePaths(deviceList)
	if err != nil {
		return nil, err
	}
	if err := validateVNextOwnerSchedulerAuthorityConfig(
		config.SchedulerAuthority, true); err != nil {
		return nil, fmt.Errorf("validate VNext Owner Scheduler authority: %w", err)
	}

	runtime := &vnextOwnerRuntime{}
	defer func() {
		if returnErr != nil {
			if closeErr := runtime.Close(); closeErr != nil {
				returnErr = fmt.Errorf(
					"%w; VNext Owner startup cleanup also failed: %v",
					returnErr, closeErr)
			}
		}
	}()

	schedulerAuthority, closeSchedulerAuthority, err :=
		dependencies.openSchedulerAuthority(config.SchedulerAuthority)
	if err != nil {
		return nil, fmt.Errorf("open VNext Owner Scheduler authority: %w", err)
	}
	if closeSchedulerAuthority != nil {
		runtime.schedulerAuthorityClose = closeSchedulerAuthority
	}
	if schedulerAuthority == nil || closeSchedulerAuthority == nil {
		return nil, errors.New(
			"VNext Owner Scheduler authority opener returned incomplete state")
	}

	controlFile, err := dependencies.openControlFile(controlPath)
	if err != nil {
		return nil, fmt.Errorf("open existing VNext Owner control file: %w", err)
	}
	runtime.controlFile = controlFile
	runtime.controlClose = controlFile.Close
	controlStat, err := controlFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat VNext Owner control file: %w", err)
	}
	if !controlStat.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"VNext Owner control path must be an existing regular file, got mode %s",
			controlStat.Mode())
	}

	devices := make([]*vnextPersistentDevice, 0, len(devicePaths))
	bindings := make([]vnextLocalDAXBinding, 0, len(devicePaths))
	for _, path := range devicePaths {
		opened, err := dependencies.openDevice(path)
		if err != nil {
			return nil, fmt.Errorf("open existing TRCXL006 device %q: %w", path, err)
		}
		if opened.device == nil || opened.close == nil {
			if opened.close != nil {
				_ = opened.close()
			}
			return nil, fmt.Errorf("VNext device opener returned incomplete state for %q", path)
		}
		runtime.devices = append(runtime.devices, opened)
		binding, err := vnextLocalDAXBindingFromDevice(opened.device, path)
		if err != nil {
			return nil, fmt.Errorf("bind existing TRCXL006 device %q: %w", path, err)
		}
		devices = append(devices, opened.device)
		bindings = append(bindings, binding)
	}
	directory, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		return nil, fmt.Errorf("build VNext Owner local DAX directory: %w", err)
	}
	group, err := openVNextOwnerGroup(controlFile, config.ControlSlotBytes, devices)
	if err != nil {
		return nil, fmt.Errorf("open existing TROWN010 Owner group: %w", err)
	}
	service, err := newVNextOwnerServiceWithSchedulerAuthority(
		group, directory, schedulerAuthority)
	if err != nil {
		return nil, fmt.Errorf("initialize VNext Owner service: %w", err)
	}
	runtime.service = service
	return runtime, nil
}

func parseVNextOwnerDevicePaths(value string) ([]string, error) {
	items := strings.Split(value, ",")
	paths := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		path := strings.TrimSpace(item)
		if path == "" {
			return nil, fmt.Errorf("VNext Owner DAX device %d is empty", index)
		}
		if err := validateVNextOwnerRuntimePath(path, "DAX device"); err != nil {
			return nil, err
		}
		if _, duplicate := seen[path]; duplicate {
			return nil, fmt.Errorf("VNext Owner DAX device path %q is duplicated", path)
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	if len(paths) == 0 {
		return nil, errors.New("VNext Owner DAX device list is empty")
	}
	return paths, nil
}

func vnextOwnerSchedulerAuthorityConfiguredFields(
	config vnextOwnerSchedulerAuthorityConfig,
) int {
	configured := 0
	if len(config.Endpoints) != 0 {
		configured++
	}
	if config.LeaderKey != "" {
		configured++
	}
	if config.ExpectedCluster != 0 {
		configured++
	}
	if config.CAFile != "" {
		configured++
	}
	if config.ClientCertFile != "" {
		configured++
	}
	if config.ClientKeyFile != "" {
		configured++
	}
	if config.DialTimeout != 0 {
		configured++
	}
	if config.ReadTimeout != 0 {
		configured++
	}
	return configured
}

func validateVNextOwnerRuntimePath(path string, role string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.IndexFunc(path, unicode.IsSpace) >= 0 {
		return fmt.Errorf("VNext Owner %s path %q is not an absolute clean whitespace-free path", role, path)
	}
	return nil
}

func (runtime *vnextOwnerRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return nil
	}
	// No operation may start through this runtime after shutdown begins. A
	// failed resource close remains recorded below and is retried by the next
	// Close call.
	runtime.service = nil
	var closeErr error
	if runtime.schedulerAuthorityClose != nil {
		// clientv3.Client.Close is terminal even when it reports an error.
		// Never call it twice and obscure the first shutdown diagnosis.
		closeSchedulerAuthority := runtime.schedulerAuthorityClose
		runtime.schedulerAuthorityClose = nil
		if err := closeSchedulerAuthority(); err != nil {
			closeErr = appendVNextOwnerRuntimeCloseError(
				closeErr,
				fmt.Errorf("close VNext Owner Scheduler authority: %w", err))
		}
	}
	for index := len(runtime.devices) - 1; index >= 0; index-- {
		if runtime.devices[index].close == nil {
			continue
		}
		if err := runtime.devices[index].close(); err != nil {
			closeErr = appendVNextOwnerRuntimeCloseError(closeErr, err)
			if !isVNextTerminalFileCloseError(err) {
				continue
			}
		}
		runtime.devices[index].close = nil
		runtime.devices[index].device = nil
	}
	if runtime.controlClose != nil {
		// An os.File close is an exactly-once terminal action even when it
		// reports an error. Clear the callback before returning so a retry
		// cannot overwrite the original diagnosis with os.ErrClosed.
		controlClose := runtime.controlClose
		runtime.controlClose = nil
		runtime.controlFile = nil
		if err := controlClose(); err != nil {
			closeErr = appendVNextOwnerRuntimeCloseError(
				closeErr,
				fmt.Errorf("close VNext Owner control file: %w", err))
		}
	}
	runtime.closed = true
	for index := range runtime.devices {
		if runtime.devices[index].close != nil {
			runtime.closed = false
			break
		}
	}
	return closeErr
}

func closeVNextOwnerRuntimeWithRetry(
	runtime *vnextOwnerRuntime,
	attempts int,
) error {
	if runtime == nil {
		return nil
	}
	if attempts < 1 {
		attempts = 1
	}
	var closeErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := runtime.Close(); err != nil {
			closeErr = appendVNextOwnerRuntimeCloseError(closeErr, err)
		}
		runtime.mu.Lock()
		closed := runtime.closed
		runtime.mu.Unlock()
		if closed {
			return closeErr
		}
	}
	return closeErr
}
