package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextCRIURemapMagic    = "TRREMAP006"
	vnextCRIURemapFilename = "vnext-dax-remap.txt"
	vnextMaxCRIURemapBytes = cxlcheckpoint.MaxPayloadBytes
)

// vnextLocalDAXBinding is node-local attach state. DevicePath must never be
// copied into a publication, Scheduler root, DeviceTable digest, or PageID.
// ContentRegionBase is taken from the validated local V6 superblock and turns
// a portable DataPageIndex into the page offset expected by CRIU.
type vnextLocalDAXBinding struct {
	DeviceUUID        string
	OwnerID           string
	OwnerEpoch        uint64
	DataPageCount     uint64
	ContentRegionBase uint64
	DevicePath        string
}

type vnextLocalDAXDirectory struct {
	byUUID map[string]vnextLocalDAXBinding
}

func newVNextLocalDAXDirectory(
	bindings []vnextLocalDAXBinding,
) (*vnextLocalDAXDirectory, error) {
	if len(bindings) == 0 {
		return nil, errors.New("VNext local DAX directory is empty")
	}
	directory := &vnextLocalDAXDirectory{
		byUUID: make(map[string]vnextLocalDAXBinding, len(bindings)),
	}
	paths := make(map[string]string, len(bindings))
	for _, binding := range bindings {
		if binding.DeviceUUID == "" || binding.OwnerID == "" ||
			binding.OwnerEpoch == 0 || binding.DataPageCount == 0 ||
			binding.ContentRegionBase == 0 ||
			binding.ContentRegionBase%cxlcheckpoint.PageSize != 0 {
			return nil, fmt.Errorf("local DAX binding %q has invalid V6 identity or geometry",
				binding.DeviceUUID)
		}
		if err := validateVNextLocalDAXPath(binding.DevicePath); err != nil {
			return nil, fmt.Errorf("local DAX binding %q: %w", binding.DeviceUUID, err)
		}
		if _, exists := directory.byUUID[binding.DeviceUUID]; exists {
			return nil, fmt.Errorf("duplicate local DAX binding for UUID %q", binding.DeviceUUID)
		}
		if previousUUID, exists := paths[binding.DevicePath]; exists {
			return nil, fmt.Errorf(
				"local DAX path %q aliases UUIDs %q and %q",
				binding.DevicePath, previousUUID, binding.DeviceUUID)
		}
		directory.byUUID[binding.DeviceUUID] = binding
		paths[binding.DevicePath] = binding.DeviceUUID
	}
	return directory, nil
}

func vnextLocalDAXBindingFromDevice(
	device *vnextPersistentDevice,
	devicePath string,
) (vnextLocalDAXBinding, error) {
	if device == nil {
		return vnextLocalDAXBinding{}, errors.New("VNext local DAX device is nil")
	}
	if err := validateVNextLocalDAXPath(devicePath); err != nil {
		return vnextLocalDAXBinding{}, err
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	if err := device.checkUsableLocked(); err != nil {
		return vnextLocalDAXBinding{}, err
	}
	return vnextLocalDAXBinding{
		DeviceUUID:        device.superblock.DeviceUUID,
		OwnerID:           device.superblock.OwnerID,
		OwnerEpoch:        device.superblock.OwnerEpoch,
		DataPageCount:     device.superblock.Geometry.DataPageCount,
		ContentRegionBase: device.superblock.Geometry.ContentRegionBase,
		DevicePath:        devicePath,
	}, nil
}

// buildVNextCRIUCompleteRemap creates the strict, ephemeral five-field input
// consumed by CRIU VNext:
//
//   pages_image_id vaddr page_count device_page_offset local_device_path
//
// The portable publication is validated before any local path is resolved.
// Every DeviceTable entry must match a locally attached V6 superblock, and
// every sparse present-page run is emitted exactly once in canonical order.
func (directory *vnextLocalDAXDirectory) buildVNextCRIUCompleteRemap(
	publication cxlcheckpoint.Publication,
) ([]byte, error) {
	if directory == nil || len(directory.byUUID) == 0 {
		return nil, errors.New("VNext local DAX directory is unavailable")
	}
	if err := publication.Validate(); err != nil {
		return nil, fmt.Errorf("validate V6 publication before CRIU remap: %w", err)
	}
	portableDevices := make(map[string]cxlcheckpoint.Device, len(publication.Devices))
	for _, portable := range publication.Devices {
		binding, exists := directory.byUUID[portable.DeviceUUID]
		if !exists {
			return nil, fmt.Errorf(
				"no local DAX binding for publication device UUID %q",
				portable.DeviceUUID)
		}
		if binding.OwnerID != portable.OwnerID ||
			binding.OwnerEpoch != portable.OwnerEpoch ||
			binding.DataPageCount != portable.DataPageCount {
			return nil, fmt.Errorf(
				"local DAX binding %q does not match publication Owner/epoch/capacity",
				portable.DeviceUUID)
		}
		portableDevices[portable.DeviceUUID] = portable
	}

	var output bytes.Buffer
	output.WriteString(vnextCRIURemapMagic)
	output.WriteByte('\n')
	for runIndex, run := range publication.PageMap.Runs {
		if _, exists := portableDevices[run.FirstPage.DeviceUUID]; !exists {
			return nil, fmt.Errorf(
				"PageMap run %d references unresolved device %q",
				runIndex, run.FirstPage.DeviceUUID)
		}
		binding := directory.byUUID[run.FirstPage.DeviceUUID]
		contentBasePage := binding.ContentRegionBase / cxlcheckpoint.PageSize
		devicePageOffset, ok := vnextAdd(contentBasePage, run.FirstPage.DataPageIndex)
		if !ok || devicePageOffset > uint64(^uint64(0)>>1) {
			return nil, fmt.Errorf("PageMap run %d local device offset overflows signed ABI", runIndex)
		}
		devicePageEnd, ok := vnextAdd(devicePageOffset, run.PageCount)
		contentRegionEnd, capacityOK := vnextAdd(contentBasePage, binding.DataPageCount)
		if !ok || !capacityOK || devicePageEnd > contentRegionEnd ||
			devicePageEnd > uint64(^uint64(0)>>1) {
			return nil, fmt.Errorf("PageMap run %d local device range exceeds V6 geometry", runIndex)
		}
		line := fmt.Sprintf(
			"%d %d %d %d %s\n",
			run.PagesImageID,
			run.StartVAddr,
			run.PageCount,
			devicePageOffset,
			binding.DevicePath)
		if len(line) > vnextMaxCRIURemapBytes-output.Len() {
			return nil, fmt.Errorf(
				"strict CRIU remap exceeds %d bytes", vnextMaxCRIURemapBytes)
		}
		output.WriteString(line)
	}
	return append([]byte(nil), output.Bytes()...), nil
}

// materializeVNextCRIUCompleteRemap writes a private adapter file for one CRIU
// invocation. It is atomic within workDirectory and returns a cleanup
// function; callers must not retain it as checkpoint metadata.
func (directory *vnextLocalDAXDirectory) materializeVNextCRIUCompleteRemap(
	workDirectory string,
	publication cxlcheckpoint.Publication,
) (string, func(), error) {
	data, err := directory.buildVNextCRIUCompleteRemap(publication)
	if err != nil {
		return "", nil, err
	}
	if workDirectory == "" || !filepath.IsAbs(workDirectory) {
		return "", nil, errors.New("VNext CRIU work directory must be absolute")
	}
	if err := os.MkdirAll(workDirectory, 0o700); err != nil {
		return "", nil, fmt.Errorf("create VNext CRIU work directory: %w", err)
	}
	temporary, err := os.CreateTemp(workDirectory, "."+vnextCRIURemapFilename+".tmp.")
	if err != nil {
		return "", nil, fmt.Errorf("create temporary VNext CRIU remap: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanupTemporary := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	if err := temporary.Chmod(0o600); err != nil {
		cleanupTemporary()
		return "", nil, fmt.Errorf("chmod temporary VNext CRIU remap: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		cleanupTemporary()
		return "", nil, fmt.Errorf("write temporary VNext CRIU remap: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		cleanupTemporary()
		return "", nil, fmt.Errorf("sync temporary VNext CRIU remap: %w", err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return "", nil, fmt.Errorf("close temporary VNext CRIU remap: %w", err)
	}
	finalPath := filepath.Join(workDirectory, vnextCRIURemapFilename)
	if err := os.Rename(temporaryPath, finalPath); err != nil {
		_ = os.Remove(temporaryPath)
		return "", nil, fmt.Errorf("publish temporary VNext CRIU remap: %w", err)
	}
	if err := syncVNextDirectory(workDirectory); err != nil {
		_ = os.Remove(finalPath)
		return "", nil, err
	}
	cleanup := func() {
		_ = os.Remove(finalPath)
	}
	return finalPath, cleanup, nil
}

func validateVNextLocalDAXPath(path string) error {
	if path == "" || len(path) > cxlcheckpoint.MaxIdentityBytes ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("local DAX path %q is empty, relative, too long, or not clean", path)
	}
	if strings.IndexFunc(path, unicode.IsSpace) >= 0 {
		return fmt.Errorf("local DAX path %q contains whitespace unsupported by TRREMAP006", path)
	}
	return nil
}

func syncVNextDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open VNext CRIU work directory for sync: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync VNext CRIU work directory: %w", err)
	}
	return nil
}
