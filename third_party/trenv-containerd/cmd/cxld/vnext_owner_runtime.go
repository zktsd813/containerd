package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

// vnextOwnerRuntimeConfig is all-or-nothing. An empty configuration leaves
// the VNext Owner RPC unavailable; a partial or invalid configuration aborts
// daemon startup. It never creates or formats a device or Owner journal.
type vnextOwnerRuntimeConfig struct {
	ControlFilePath  string
	ControlSlotBytes uint64
	DAXDeviceList    string
}

type vnextOwnerOpenedDevice struct {
	device *vnextPersistentDevice
	close  func() error
}

type vnextOwnerRuntimeDependencies struct {
	openControlFile func(string) (*os.File, error)
	openDevice      func(string) (vnextOwnerOpenedDevice, error)
}

type vnextOwnerRuntime struct {
	mu           sync.Mutex
	service      *vnextOwnerService
	controlFile  *os.File
	controlClose func() error
	devices      []vnextOwnerOpenedDevice
	closed       bool
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
	})
}

func openVNextOwnerRuntimeWithDependencies(
	config vnextOwnerRuntimeConfig,
	dependencies vnextOwnerRuntimeDependencies,
) (_ *vnextOwnerRuntime, returnErr error) {
	controlPath := strings.TrimSpace(config.ControlFilePath)
	deviceList := strings.TrimSpace(config.DAXDeviceList)
	configuredFields := 0
	if controlPath != "" {
		configuredFields++
	}
	if config.ControlSlotBytes != 0 {
		configuredFields++
	}
	if deviceList != "" {
		configuredFields++
	}
	if configuredFields == 0 {
		return nil, nil
	}
	if configuredFields != 3 {
		return nil, errors.New(
			"VNext Owner requires control file, control slot bytes, and DAX devices together")
	}
	if dependencies.openControlFile == nil || dependencies.openDevice == nil {
		return nil, errors.New("VNext Owner runtime open dependencies are incomplete")
	}
	if err := validateVNextOwnerRuntimePath(controlPath, "control file"); err != nil {
		return nil, err
	}
	devicePaths, err := parseVNextOwnerDevicePaths(deviceList)
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("open existing TROWN008 Owner group: %w", err)
	}
	service, err := newVNextOwnerService(group, directory)
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
