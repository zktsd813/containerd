package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const vnextReaderDevDAXOpenFlags = unix.O_RDONLY | unix.O_CLOEXEC

type vnextReaderDAXCacheInvalidator func([]byte) error

type vnextReaderDAXCacheInstruction uint8

const (
	vnextReaderDAXCacheUnavailable vnextReaderDAXCacheInstruction = iota
	vnextReaderDAXCacheCLFlush
	vnextReaderDAXCacheCLFlushOpt
)

type vnextReaderDAXCPUFeatures struct {
	clflush    bool
	clflushopt bool
}

// parseVNextReaderDAXCPUFeatures intersects the feature rows for every CPU
// observed in /proc/cpuinfo. The invalidation routine can migrate between
// CPUs, so a raw opcode is usable only when every observed CPU supports it.
// An input without a feature row returns the unavailable zero value.
func parseVNextReaderDAXCPUFeatures(cpuInfo string) vnextReaderDAXCPUFeatures {
	features := vnextReaderDAXCPUFeatures{}
	observedCPU := false
	for _, line := range strings.Split(cpuInfo, "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		if key != "flags" && key != "Features" {
			continue
		}
		cpuFeatures := vnextReaderDAXCPUFeatures{}
		for _, flag := range strings.Fields(value) {
			switch flag {
			case "clflush":
				cpuFeatures.clflush = true
			case "clflushopt":
				cpuFeatures.clflushopt = true
			}
		}
		if !observedCPU {
			features = cpuFeatures
			observedCPU = true
			continue
		}
		features.clflush = features.clflush && cpuFeatures.clflush
		features.clflushopt = features.clflushopt && cpuFeatures.clflushopt
	}
	return features
}

func selectVNextReaderDAXCacheInstruction(
	features vnextReaderDAXCPUFeatures,
) vnextReaderDAXCacheInstruction {
	switch {
	case features.clflushopt:
		return vnextReaderDAXCacheCLFlushOpt
	case features.clflush:
		return vnextReaderDAXCacheCLFlush
	default:
		return vnextReaderDAXCacheUnavailable
	}
}

// vnextReaderDevDAXDependencies is an unexported syscall seam. Production
// always uses defaultVNextReaderDevDAXDependencies. Tests use it only to map
// an O_RDONLY regular file as a deterministic mmap simulation; accepting a
// regular file is never part of the production constructor contract.
type vnextReaderDevDAXDependencies struct {
	openFile       func(string, int, os.FileMode) (*os.File, error)
	statFile       func(*os.File) (os.FileInfo, error)
	geometry       func(string) (vnextDAXGeometry, error)
	mmap           func(int, int64, int, int, int) ([]byte, error)
	munmap         func([]byte) error
	close          func(*os.File) error
	newInvalidator func() (
		vnextReaderDAXCacheInvalidator, error)
}

func defaultVNextReaderDevDAXDependencies() vnextReaderDevDAXDependencies {
	return vnextReaderDevDAXDependencies{
		openFile: os.OpenFile,
		statFile: func(file *os.File) (os.FileInfo, error) {
			return file.Stat()
		},
		geometry: func(path string) (vnextDAXGeometry, error) {
			return resolveVNextDAXGeometry(path, vnextDAXSysfsRoots)
		},
		mmap:   unix.Mmap,
		munmap: unix.Munmap,
		close: func(file *os.File) error {
			return file.Close()
		},
		newInvalidator: newVNextReaderDAXCacheInvalidator,
	}
}

func validateVNextReaderDevDAXDependencies(
	dependencies vnextReaderDevDAXDependencies,
) error {
	if dependencies.openFile == nil || dependencies.statFile == nil ||
		dependencies.geometry == nil || dependencies.mmap == nil ||
		dependencies.munmap == nil || dependencies.close == nil ||
		dependencies.newInvalidator == nil {
		return errors.New("VNext Reader devdax dependencies are incomplete")
	}
	return nil
}

type vnextReaderDevDAXErrors struct {
	failures []error
}

func (failures *vnextReaderDevDAXErrors) Error() string {
	messages := make([]string, 0, len(failures.failures))
	for _, failure := range failures.failures {
		messages = append(messages, failure.Error())
	}
	return strings.Join(messages, "; ")
}

func (failures *vnextReaderDevDAXErrors) Is(target error) bool {
	for _, failure := range failures.failures {
		if errors.Is(failure, target) {
			return true
		}
	}
	return false
}

func appendVNextReaderDevDAXError(existing error, next error) error {
	if next == nil {
		return existing
	}
	if existing == nil {
		return next
	}
	if aggregate, ok := existing.(*vnextReaderDevDAXErrors); ok {
		aggregate.failures = append(aggregate.failures, next)
		return aggregate
	}
	return &vnextReaderDevDAXErrors{failures: []error{existing, next}}
}

// vnextReadOnlyDevDAXSource owns only read-only mappings. It deliberately
// does not implement vnextDeviceStorage, io.WriterAt, Sync, allocator recovery,
// formatting, or any Owner operation.
type vnextReadOnlyDevDAXSource struct {
	mu sync.RWMutex

	devices         map[string]*vnextReadOnlyDevDAXDevice
	orderedUUIDs    []string
	admissionClosed bool

	closeMu       sync.Mutex
	closeComplete bool
	closeErr      error
}

type vnextReadOnlyDevDAXDevice struct {
	mu sync.Mutex

	binding          vnextLocalDAXBinding
	file             *os.File
	mapped           []byte
	size             uint64
	mappingAlignment uint64
	invalidate       vnextReaderDAXCacheInvalidator
	munmap           func([]byte) error
	closeFile        func(*os.File) error

	superblockLoaded bool
	superblock       vnextDeviceSuperblock
	unmapped         bool
	fileClosed       bool
	closed           bool
	terminalCloseErr error
}

// openVNextReadOnlyDevDAXSource maps every configured local device
// all-or-nothing. It may inspect trusted path, stat, sysfs, and CPU metadata,
// but it never loads, copies, invalidates, or parses a byte from shared memory.
func openVNextReadOnlyDevDAXSource(
	directory *vnextLocalDAXDirectory,
) (*vnextReadOnlyDevDAXSource, error) {
	return openVNextReadOnlyDevDAXSourceWithDependencies(
		directory, defaultVNextReaderDevDAXDependencies())
}

func openVNextReadOnlyDevDAXSourceWithDependencies(
	directory *vnextLocalDAXDirectory,
	dependencies vnextReaderDevDAXDependencies,
) (*vnextReadOnlyDevDAXSource, error) {
	if err := validateVNextReaderDevDAXDependencies(dependencies); err != nil {
		return nil, err
	}
	bindings, err := cloneVNextReaderDevDAXBindings(directory)
	if err != nil {
		return nil, err
	}
	invalidate, err := dependencies.newInvalidator()
	if err != nil {
		return nil, fmt.Errorf(
			"construct VNext Reader devdax cache invalidator: %w", err)
	}
	if invalidate == nil {
		return nil, errors.New(
			"VNext Reader devdax cache invalidator constructor returned nil")
	}
	source := &vnextReadOnlyDevDAXSource{
		devices:      make(map[string]*vnextReadOnlyDevDAXDevice, len(bindings)),
		orderedUUIDs: make([]string, 0, len(bindings)),
	}
	for _, binding := range bindings {
		device, openErr := openVNextReadOnlyDevDAXDevice(
			binding, invalidate, dependencies)
		if openErr != nil {
			primary := fmt.Errorf(
				"open VNext Reader devdax device %q: %w",
				binding.DeviceUUID, openErr)
			for index := len(source.orderedUUIDs) - 1; index >= 0; index-- {
				uuid := source.orderedUUIDs[index]
				closeErr := source.devices[uuid].discard()
				if closeErr != nil {
					primary = appendVNextReaderDevDAXError(
						primary,
						fmt.Errorf("close partial VNext Reader devdax %q: %w",
							uuid, closeErr))
				}
			}
			return nil, primary
		}
		source.devices[binding.DeviceUUID] = device
		source.orderedUUIDs = append(source.orderedUUIDs, binding.DeviceUUID)
	}
	return source, nil
}

func cloneVNextReaderDevDAXBindings(
	directory *vnextLocalDAXDirectory,
) ([]vnextLocalDAXBinding, error) {
	if directory == nil || len(directory.byUUID) == 0 {
		return nil, errors.New("VNext Reader devdax directory is unavailable")
	}
	bindings := make([]vnextLocalDAXBinding, 0, len(directory.byUUID))
	for _, binding := range directory.byUUID {
		bindings = append(bindings, binding)
	}
	canonical, err := newVNextLocalDAXDirectory(bindings)
	if err != nil {
		return nil, fmt.Errorf("validate VNext Reader devdax directory: %w", err)
	}
	bindings = bindings[:0]
	for _, binding := range canonical.byUUID {
		bindings = append(bindings, binding)
	}
	sort.Slice(bindings, func(i, j int) bool {
		return bindings[i].DeviceUUID < bindings[j].DeviceUUID
	})
	return bindings, nil
}

func openVNextReadOnlyDevDAXDevice(
	binding vnextLocalDAXBinding,
	invalidate vnextReaderDAXCacheInvalidator,
	dependencies vnextReaderDevDAXDependencies,
) (*vnextReadOnlyDevDAXDevice, error) {
	file, err := dependencies.openFile(
		binding.DevicePath, vnextReaderDevDAXOpenFlags, 0)
	if err != nil {
		return nil, fmt.Errorf("open O_RDONLY devdax %q: %w", binding.DevicePath, err)
	}
	fileClosed := false
	closeFile := func(primary error) error {
		if fileClosed {
			return primary
		}
		fileClosed = true
		if closeErr := dependencies.close(file); closeErr != nil {
			primary = appendVNextReaderDevDAXError(
				primary, fmt.Errorf("close VNext Reader devdax file: %w", closeErr))
		}
		return primary
	}
	stat, err := dependencies.statFile(file)
	if err != nil {
		return nil, closeFile(fmt.Errorf("stat VNext Reader devdax: %w", err))
	}
	if stat == nil || stat.Mode()&os.ModeCharDevice == 0 {
		mode := os.FileMode(0)
		if stat != nil {
			mode = stat.Mode()
		}
		return nil, closeFile(fmt.Errorf(
			"VNext Reader devdax requires a character device, got mode %s: %w",
			mode, errVNextWrongFormat))
	}
	geometry, err := dependencies.geometry(binding.DevicePath)
	if err != nil {
		return nil, closeFile(fmt.Errorf(
			"resolve VNext Reader devdax geometry: %w", err))
	}
	if err := vnextValidateDAXGeometry(
		geometry.sizeBytes, geometry.alignBytes); err != nil {
		return nil, closeFile(err)
	}
	if geometry.sizeBytes > uint64(maxInt()) {
		return nil, closeFile(fmt.Errorf(
			"VNext Reader devdax capacity %d exceeds mmap length ABI: %w",
			geometry.sizeBytes, errVNextWrongFormat))
	}
	mapped, err := dependencies.mmap(
		int(file.Fd()), 0, int(geometry.sizeBytes),
		unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		return nil, closeFile(fmt.Errorf(
			"map VNext Reader devdax PROT_READ: %w", err))
	}
	cleanupMapping := func(primary error) error {
		if unmapErr := dependencies.munmap(mapped); unmapErr != nil {
			primary = appendVNextReaderDevDAXError(
				primary, fmt.Errorf("unmap partial VNext Reader devdax: %w", unmapErr))
		}
		return closeFile(primary)
	}
	if len(mapped) != int(geometry.sizeBytes) || len(mapped) == 0 {
		return nil, cleanupMapping(fmt.Errorf(
			"VNext Reader devdax mmap length %d differs from capacity %d: %w",
			len(mapped), geometry.sizeBytes, errVNextWrongFormat))
	}
	address := uintptr(unsafe.Pointer(&mapped[0]))
	if address%uintptr(geometry.alignBytes) != 0 {
		return nil, cleanupMapping(fmt.Errorf(
			"VNext Reader devdax mapping address %#x is not aligned to %d: %w",
			address, geometry.alignBytes, errVNextWrongFormat))
	}
	return &vnextReadOnlyDevDAXDevice{
		binding:          binding,
		file:             file,
		mapped:           mapped,
		size:             geometry.sizeBytes,
		mappingAlignment: geometry.alignBytes,
		invalidate:       invalidate,
		munmap:           dependencies.munmap,
		closeFile:        dependencies.close,
	}, nil
}

func (source *vnextReadOnlyDevDAXSource) ReadVNextDescriptor(
	ctx context.Context,
	binding vnextLocalDAXBinding,
	dataPageIndex uint64,
) (vnextPageDescriptor, error) {
	device, err := source.device(binding)
	if err != nil {
		return vnextPageDescriptor{}, err
	}
	return device.readDescriptor(ctx, dataPageIndex)
}

func (source *vnextReadOnlyDevDAXSource) ReadVNextContentPage(
	ctx context.Context,
	binding vnextLocalDAXBinding,
	dataPageIndex uint64,
) ([]byte, error) {
	device, err := source.device(binding)
	if err != nil {
		return nil, err
	}
	return device.readContentPage(ctx, dataPageIndex)
}

func (source *vnextReadOnlyDevDAXSource) device(
	binding vnextLocalDAXBinding,
) (*vnextReadOnlyDevDAXDevice, error) {
	if source == nil {
		return nil, os.ErrClosed
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.admissionClosed {
		return nil, fmt.Errorf("VNext Reader devdax source is closed: %w", os.ErrClosed)
	}
	device := source.devices[binding.DeviceUUID]
	if device == nil || device.binding != binding {
		return nil, errors.New(
			"VNext Reader devdax binding does not exactly match configured local state")
	}
	return device, nil
}

func (device *vnextReadOnlyDevDAXDevice) readDescriptor(
	ctx context.Context,
	dataPageIndex uint64,
) (vnextPageDescriptor, error) {
	device.mu.Lock()
	defer device.mu.Unlock()
	if err := device.checkReadableLocked(ctx); err != nil {
		return vnextPageDescriptor{}, err
	}
	superblock, err := device.loadSuperblockLocked()
	if err != nil {
		return vnextPageDescriptor{}, err
	}
	offset, err := superblock.Geometry.descriptorOffset(dataPageIndex)
	if err != nil {
		return vnextPageDescriptor{}, err
	}
	raw := make([]byte, vnextPageDescriptorSize)
	if err := device.copyInvalidatedLocked(raw, offset); err != nil {
		return vnextPageDescriptor{}, fmt.Errorf(
			"copy invalidated VNext descriptor: %w", err)
	}
	return parseVNextPageDescriptor(raw)
}

func (device *vnextReadOnlyDevDAXDevice) readContentPage(
	ctx context.Context,
	dataPageIndex uint64,
) ([]byte, error) {
	device.mu.Lock()
	defer device.mu.Unlock()
	if err := device.checkReadableLocked(ctx); err != nil {
		return nil, err
	}
	superblock, err := device.loadSuperblockLocked()
	if err != nil {
		return nil, err
	}
	offset, err := superblock.Geometry.contentOffset(dataPageIndex)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, vnextContentPageSize)
	if err := device.copyInvalidatedLocked(raw, offset); err != nil {
		return nil, fmt.Errorf(
			"copy invalidated VNext content page: %w", err)
	}
	return raw, nil
}

func (device *vnextReadOnlyDevDAXDevice) checkReadableLocked(
	ctx context.Context,
) error {
	if device.closed || device.unmapped || device.fileClosed ||
		device.file == nil || len(device.mapped) == 0 {
		return fmt.Errorf("VNext Reader devdax device is closed: %w", os.ErrClosed)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (device *vnextReadOnlyDevDAXDevice) loadSuperblockLocked() (vnextDeviceSuperblock, error) {
	if device.superblockLoaded {
		return device.superblock, nil
	}
	readSlot := func(offset uint64) (vnextDeviceSuperblock, error) {
		raw := make([]byte, vnextSuperblockSlotBytes)
		if err := device.copyInvalidatedLocked(raw, offset); err != nil {
			return vnextDeviceSuperblock{}, err
		}
		return vnextReadSuperblockSlot(bytes.NewReader(raw), 0)
	}
	first, firstErr := readSlot(0)
	if firstErr != nil && errors.Is(firstErr, errVNextReaderCacheInvalidation) {
		return vnextDeviceSuperblock{}, firstErr
	}
	second, secondErr := readSlot(vnextSuperblockSlotBytes)
	if secondErr != nil && errors.Is(secondErr, errVNextReaderCacheInvalidation) {
		return vnextDeviceSuperblock{}, secondErr
	}
	selected, err := vnextSelectSuperblock(first, firstErr, second, secondErr)
	if err != nil {
		return vnextDeviceSuperblock{}, err
	}
	if selected.DeviceUUID != device.binding.DeviceUUID ||
		selected.OwnerID != device.binding.OwnerID ||
		selected.OwnerEpoch != device.binding.OwnerEpoch ||
		selected.Geometry.DeviceBytes != device.size ||
		selected.Geometry.DataPageCount != device.binding.DataPageCount ||
		selected.Geometry.ContentRegionBase != device.binding.ContentRegionBase {
		return vnextDeviceSuperblock{}, errors.New(
			"VNext Reader devdax superblock does not match configured local binding")
	}
	device.superblock = selected
	device.superblockLoaded = true
	return selected, nil
}

var errVNextReaderCacheInvalidation = errors.New(
	"VNext Reader non-coherent cache invalidation failed")

func (device *vnextReadOnlyDevDAXDevice) copyInvalidatedLocked(
	destination []byte,
	offset uint64,
) error {
	if len(destination) == 0 || uint64(len(destination))%vnextDAXCacheLineBytes != 0 ||
		offset%vnextDAXCacheLineBytes != 0 ||
		offset > math.MaxUint64-uint64(len(destination)) {
		return errors.New("VNext Reader invalidation range is empty, unaligned, or overflowing")
	}
	end := offset + uint64(len(destination))
	if end > device.size || end > uint64(len(device.mapped)) ||
		offset > uint64(maxInt()) || end > uint64(maxInt()) {
		return errors.New("VNext Reader invalidation range exceeds mapped capacity")
	}
	mapped := device.mapped[int(offset):int(end)]
	if err := device.invalidate(mapped); err != nil {
		return appendVNextReaderDevDAXError(
			errVNextReaderCacheInvalidation, err)
	}
	if copied := copy(destination, mapped); copied != len(destination) {
		return errors.New("VNext Reader invalidated copy was short")
	}
	return nil
}

// Close first prevents new source calls, then closes each mapping in stable
// UUID order. A failed munmap is retryable; os.File.Close is terminal and is
// therefore invoked at most once even when it returns an error.
func (source *vnextReadOnlyDevDAXSource) Close() error {
	if source == nil {
		return nil
	}
	source.closeMu.Lock()
	defer source.closeMu.Unlock()
	source.mu.Lock()
	source.admissionClosed = true
	source.mu.Unlock()
	if source.closeComplete {
		return source.closeErr
	}
	var closeErr error
	complete := true
	for _, uuid := range source.orderedUUIDs {
		deviceComplete, err := source.devices[uuid].close()
		if err != nil {
			closeErr = appendVNextReaderDevDAXError(
				closeErr, fmt.Errorf("close VNext Reader devdax %q: %w", uuid, err))
		}
		if !deviceComplete {
			complete = false
		}
	}
	if complete {
		source.closeComplete = true
		source.closeErr = closeErr
	}
	return closeErr
}

func (device *vnextReadOnlyDevDAXDevice) close() (bool, error) {
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.closed {
		return true, device.terminalCloseErr
	}
	if !device.unmapped {
		if err := device.munmap(device.mapped); err != nil {
			return false, fmt.Errorf("unmap VNext Reader devdax: %w", err)
		}
		device.unmapped = true
		device.mapped = nil
	}
	if !device.fileClosed {
		device.fileClosed = true
		if err := device.closeFile(device.file); err != nil {
			device.terminalCloseErr = fmt.Errorf(
				"close VNext Reader devdax file: %w", err)
		}
	}
	device.file = nil
	device.closed = true
	return true, device.terminalCloseErr
}

// discard is constructor-failure cleanup. Unlike normal Close, there is no
// returned source through which an unmap can be retried, so it attempts the
// terminal file close even when munmap fails and preserves both causes.
func (device *vnextReadOnlyDevDAXDevice) discard() error {
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.closed {
		return device.terminalCloseErr
	}
	var cleanupErr error
	if !device.unmapped {
		if err := device.munmap(device.mapped); err != nil {
			cleanupErr = appendVNextReaderDevDAXError(
				cleanupErr, fmt.Errorf("unmap partial VNext Reader devdax: %w", err))
		} else {
			device.unmapped = true
			device.mapped = nil
		}
	}
	if !device.fileClosed {
		device.fileClosed = true
		if err := device.closeFile(device.file); err != nil {
			device.terminalCloseErr = fmt.Errorf(
				"close partial VNext Reader devdax file: %w", err)
			cleanupErr = appendVNextReaderDevDAXError(
				cleanupErr, device.terminalCloseErr)
		}
	}
	device.file = nil
	device.closed = true
	return cleanupErr
}

func validateVNextReaderDAXCacheRange(address uintptr, length uintptr) error {
	cacheLine := uintptr(vnextDAXCacheLineBytes)
	if address == 0 || length == 0 || address%cacheLine != 0 ||
		length%cacheLine != 0 || length > ^uintptr(0)-address {
		return errors.New(
			"VNext Reader devdax invalidation address/length is empty, unaligned, or overflowing")
	}
	return nil
}

var _ vnextReaderDAXSource = (*vnextReadOnlyDevDAXSource)(nil)
