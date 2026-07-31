package main

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const vnextDAXCacheLineBytes uint64 = 64

var vnextDAXSysfsRoots = []string{
	"/sys/bus/dax/devices",
	"/sys/class/dax",
}

const vnextCPUCacheLineSizePath = "/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

// vnextDeviceStorage is the persistent random-access contract used by the
// VNext metadata and content code. In particular, callers must not assume
// that FD implements read(2) or write(2): Linux devdax character devices are
// accessed by the mmap-backed implementation below.
type vnextDeviceStorage interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Size() uint64
	FD() uintptr
	MappingAlignment() uint64
	Close() error
}

type vnextSynchronizedWriterAt interface {
	io.WriterAt
	Sync() error
}

type vnextByteRange struct {
	start uint64
	end   uint64
}

func (r vnextByteRange) valid() bool {
	return r.start < r.end
}

type vnextRegularFileStorage struct {
	file *os.File
	size uint64
}

func newVNextRegularFileStorage(file *os.File) (*vnextRegularFileStorage, error) {
	if file == nil {
		return nil, errors.New("VNext device file is nil")
	}
	stat, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat VNext device file: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf(
			"VNext file backend requires a regular file, got mode %s; use the explicit devdax backend: %w",
			stat.Mode(), errVNextWrongFormat)
	}
	if stat.Size() <= 0 {
		return nil, errors.New("VNext device file has no capacity")
	}
	if uint64(stat.Size()) > uint64(math.MaxInt64) {
		return nil, fmt.Errorf("VNext device file exceeds signed offset range: %w", errVNextWrongFormat)
	}
	return &vnextRegularFileStorage{file: file, size: uint64(stat.Size())}, nil
}

func (s *vnextRegularFileStorage) ReadAt(data []byte, offset int64) (int, error) {
	if err := vnextValidateSignedStorageRange(s.size, offset, len(data), "read"); err != nil {
		return 0, err
	}
	return s.file.ReadAt(data, offset)
}

func (s *vnextRegularFileStorage) WriteAt(data []byte, offset int64) (int, error) {
	if err := vnextValidateSignedStorageRange(s.size, offset, len(data), "write"); err != nil {
		return 0, err
	}
	return s.file.WriteAt(data, offset)
}

func (s *vnextRegularFileStorage) Sync() error {
	return s.file.Sync()
}

func (s *vnextRegularFileStorage) Size() uint64 {
	return s.size
}

func (s *vnextRegularFileStorage) FD() uintptr {
	return s.file.Fd()
}

func (s *vnextRegularFileStorage) MappingAlignment() uint64 {
	return uint64(os.Getpagesize())
}

// The caller owns files passed to formatVNextFileDevice/openVNextFileDevice.
func (s *vnextRegularFileStorage) Close() error {
	return nil
}

type vnextMappedDAXStorage struct {
	mu sync.Mutex

	file             *os.File
	mapped           []byte
	size             uint64
	mappingAlignment uint64
	dirty            []vnextByteRange
	writeback        func([]byte) error
	closeFile        func() error
	regularFile      bool
	unmapped         bool
	closed           bool
}

// os.File.Close is terminal even when it reports an error: the Go runtime
// invalidates its poll descriptor before returning. Mark that stage
// separately so callers retry writeback/sync/munmap failures, but never call
// the same file Close callback twice and replace the original diagnosis with
// os.ErrClosed.
type vnextTerminalFileCloseError struct {
	cause error
}

func (err *vnextTerminalFileCloseError) Error() string {
	return err.cause.Error()
}

func (err *vnextTerminalFileCloseError) Unwrap() error {
	return err.cause
}

func isVNextTerminalFileCloseError(err error) bool {
	var terminal *vnextTerminalFileCloseError
	return errors.As(err, &terminal)
}

func newVNextMappedDAXStorage(
	file *os.File,
	size uint64,
	mappingAlignment uint64,
	ownedFile bool,
	writeback func([]byte) error,
) (*vnextMappedDAXStorage, error) {
	if file == nil {
		return nil, errors.New("VNext mapped storage file is nil")
	}
	if writeback == nil {
		return nil, errors.New("VNext mapped storage writeback function is nil")
	}
	if err := vnextValidateDAXGeometry(size, mappingAlignment); err != nil {
		return nil, err
	}
	if size > uint64(maxInt()) {
		return nil, fmt.Errorf(
			"DAX capacity %d exceeds this process mmap length ABI: %w",
			size, errVNextWrongFormat)
	}
	mapped, err := unix.Mmap(
		int(file.Fd()),
		0,
		int(size),
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("map complete VNext devdax capacity: %w", err)
	}
	address := uintptr(unsafe.Pointer(&mapped[0]))
	if address%uintptr(mappingAlignment) != 0 {
		_ = unix.Munmap(mapped)
		return nil, fmt.Errorf(
			"DAX mapping address %#x is not aligned to sysfs align %d: %w",
			address, mappingAlignment, errVNextWrongFormat)
	}
	stat, err := file.Stat()
	if err != nil {
		_ = unix.Munmap(mapped)
		return nil, fmt.Errorf("stat mapped VNext storage: %w", err)
	}
	storage := &vnextMappedDAXStorage{
		file:             file,
		mapped:           mapped,
		size:             size,
		mappingAlignment: mappingAlignment,
		writeback:        writeback,
		regularFile:      stat.Mode().IsRegular(),
	}
	if ownedFile {
		storage.closeFile = file.Close
	}
	return storage, nil
}

func (s *vnextMappedDAXStorage) ReadAt(data []byte, offset int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.unmapped {
		return 0, os.ErrClosed
	}
	if err := vnextValidateSignedStorageRange(s.size, offset, len(data), "read"); err != nil {
		return 0, err
	}
	return copy(data, s.mapped[int(offset):int(offset)+len(data)]), nil
}

func (s *vnextMappedDAXStorage) WriteAt(data []byte, offset int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.unmapped {
		return 0, os.ErrClosed
	}
	if err := vnextValidateSignedStorageRange(s.size, offset, len(data), "write"); err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return 0, nil
	}
	start := uint64(offset)
	end := start + uint64(len(data))
	copy(s.mapped[int(start):int(end)], data)
	s.addDirtyLocked(vnextByteRange{
		start: vnextAlignDown(start, vnextDAXCacheLineBytes),
		end:   vnextAlignUpBounded(end, vnextDAXCacheLineBytes, s.size),
	})
	return len(data), nil
}

func (s *vnextMappedDAXStorage) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.unmapped {
		return os.ErrClosed
	}
	return s.syncLocked()
}

func (s *vnextMappedDAXStorage) syncLocked() error {
	if len(s.dirty) == 0 {
		return nil
	}
	// Each callback receives only cache-line-rounded bytes dirtied through
	// WriteAt. Failure keeps the complete dirty set for a safe retry.
	for _, dirty := range s.dirty {
		if err := s.writeback(s.mapped[int(dirty.start):int(dirty.end)]); err != nil {
			return fmt.Errorf(
				"write back DAX cache lines [%d,%d): %w",
				dirty.start, dirty.end, err)
		}
	}
	// A regular-file mapping is used only as a deterministic simulation. Give
	// it normal msync/fsync persistence, limited to pages containing dirty
	// cache lines. Real devdax persistence is the cache-line writeback plus
	// fence performed above; it must not degrade into a whole-device msync.
	if s.regularFile {
		for _, dirtyPage := range vnextPageRanges(s.dirty, uint64(os.Getpagesize()), s.size) {
			if err := unix.Msync(
				s.mapped[int(dirtyPage.start):int(dirtyPage.end)],
				unix.MS_SYNC); err != nil {
				return fmt.Errorf(
					"sync mmap simulation pages [%d,%d): %w",
					dirtyPage.start, dirtyPage.end, err)
			}
		}
		if err := s.file.Sync(); err != nil {
			return fmt.Errorf("sync mmap simulation file: %w", err)
		}
	}
	s.dirty = nil
	return nil
}

func (s *vnextMappedDAXStorage) Size() uint64 {
	return s.size
}

func (s *vnextMappedDAXStorage) FD() uintptr {
	return s.file.Fd()
}

func (s *vnextMappedDAXStorage) MappingAlignment() uint64 {
	return s.mappingAlignment
}

func (s *vnextMappedDAXStorage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.unmapped {
		if err := s.syncLocked(); err != nil {
			return err
		}
		if err := unix.Munmap(s.mapped); err != nil {
			return fmt.Errorf("unmap VNext DAX storage: %w", err)
		}
		s.unmapped = true
		s.mapped = nil
		s.dirty = nil
	}
	if s.closeFile != nil {
		closeFile := s.closeFile
		s.closeFile = nil
		err := closeFile()
		s.closed = true
		if err != nil {
			return &vnextTerminalFileCloseError{cause: fmt.Errorf(
				"close VNext DAX device: %w", err)}
		}
	}
	s.closed = true
	return nil
}

// discardAndClose is only for a constructor or open operation that already
// failed. It releases the mapping even when persistence could not be proven;
// the caller still returns the original failure and must not expose a device.
func (s *vnextMappedDAXStorage) discardAndClose() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if !s.unmapped {
		if err := unix.Munmap(s.mapped); err != nil {
			return fmt.Errorf("unmap failed VNext DAX storage: %w", err)
		}
		s.unmapped = true
		s.mapped = nil
		s.dirty = nil
	}
	if s.closeFile != nil {
		closeFile := s.closeFile
		s.closeFile = nil
		err := closeFile()
		s.closed = true
		if err != nil {
			return fmt.Errorf("close failed VNext DAX device: %w", err)
		}
	}
	s.closed = true
	return nil
}

func (s *vnextMappedDAXStorage) addDirtyLocked(candidate vnextByteRange) {
	if !candidate.valid() {
		return
	}
	ranges := append(append([]vnextByteRange(nil), s.dirty...), candidate)
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].start == ranges[j].start {
			return ranges[i].end < ranges[j].end
		}
		return ranges[i].start < ranges[j].start
	})
	merged := ranges[:0]
	for _, current := range ranges {
		if len(merged) == 0 || current.start > merged[len(merged)-1].end {
			merged = append(merged, current)
			continue
		}
		if current.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = current.end
		}
	}
	s.dirty = merged
}

type vnextDAXGeometry struct {
	sizeBytes  uint64
	alignBytes uint64
}

func resolveVNextDAXGeometry(devicePath string, sysfsRoots []string) (vnextDAXGeometry, error) {
	deviceName := filepath.Base(strings.TrimSpace(devicePath))
	if deviceName == "" || deviceName == "." || deviceName == string(os.PathSeparator) {
		return vnextDAXGeometry{}, fmt.Errorf("invalid devdax path %q", devicePath)
	}
	var failures []string
	for _, root := range sysfsRoots {
		directory := filepath.Join(root, deviceName)
		size, sizeErr := readVNextSysfsUint(filepath.Join(directory, "size"))
		align, alignErr := readVNextSysfsUint(filepath.Join(directory, "align"))
		if sizeErr != nil || alignErr != nil {
			failures = append(failures, fmt.Sprintf(
				"%s (size: %v; align: %v)", directory, sizeErr, alignErr))
			continue
		}
		if err := vnextValidateDAXGeometry(size, align); err != nil {
			return vnextDAXGeometry{}, fmt.Errorf("invalid devdax geometry in %s: %w", directory, err)
		}
		return vnextDAXGeometry{sizeBytes: size, alignBytes: align}, nil
	}
	return vnextDAXGeometry{}, fmt.Errorf(
		"cannot resolve devdax geometry for %q from sysfs: %s",
		deviceName, strings.Join(failures, "; "))
}

func readVNextSysfsUint(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(data)), 0, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func vnextValidateDAXGeometry(size, align uint64) error {
	if os.Getpagesize() != int(vnextContentPageSize) {
		return fmt.Errorf(
			"VNext requires an exact 4096-byte host page, got %d: %w",
			os.Getpagesize(), errVNextWrongFormat)
	}
	if size == 0 || size > uint64(math.MaxInt64) || size%vnextContentPageSize != 0 {
		return fmt.Errorf(
			"devdax size %d is not a positive signed-offset multiple of 4096: %w",
			size, errVNextWrongFormat)
	}
	if align < vnextContentPageSize ||
		align%vnextContentPageSize != 0 ||
		align&(align-1) != 0 {
		return fmt.Errorf(
			"devdax align %d is not a power-of-two multiple of 4096: %w",
			align, errVNextWrongFormat)
	}
	if size%align != 0 {
		return fmt.Errorf(
			"devdax size %d is not a multiple of mapping align %d: %w",
			size, align, errVNextWrongFormat)
	}
	return nil
}

func openVNextMappedDevDAXStorage(devicePath string) (*os.File, *vnextMappedDAXStorage, error) {
	if err := preflightVNextDAXCacheProtocol(); err != nil {
		return nil, nil, err
	}
	geometry, err := resolveVNextDAXGeometry(devicePath, vnextDAXSysfsRoots)
	if err != nil {
		return nil, nil, err
	}
	file, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open devdax %q: %w", devicePath, err)
	}
	stat, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, fmt.Errorf("stat devdax %q: %w", devicePath, err)
	}
	if stat.Mode()&os.ModeCharDevice == 0 {
		_ = file.Close()
		return nil, nil, fmt.Errorf(
			"VNext devdax backend requires a character device, got mode %s: %w",
			stat.Mode(), errVNextWrongFormat)
	}
	storage, err := newVNextMappedDAXStorage(
		file,
		geometry.sizeBytes,
		geometry.alignBytes,
		true,
		directWritebackDaxCache)
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, storage, nil
}

func preflightVNextDAXCacheProtocol() error {
	features, err := currentDirectDaxCPUFeatures()
	if err != nil {
		return fmt.Errorf("inspect CPU DAX cache instructions: %w", err)
	}
	cacheLineBytes, err := readVNextSysfsUint(vnextCPUCacheLineSizePath)
	if err != nil {
		return fmt.Errorf("read CPU cache-line size: %w", err)
	}
	return validateVNextDAXCacheProtocol(features, cacheLineBytes)
}

func validateVNextDAXCacheProtocol(
	features directDaxCPUFeatureSet,
	cacheLineBytes uint64,
) error {
	if cacheLineBytes != vnextDAXCacheLineBytes {
		return fmt.Errorf(
			"CPU cache-line size is %d, VNext descriptor/writeback ABI requires %d: %w",
			cacheLineBytes, vnextDAXCacheLineBytes, errVNextWrongFormat)
	}
	if selectDirectDaxWritebackInstruction(features) == directDaxCacheUnavailable {
		return fmt.Errorf(
			"CPU has no CLWB, CLFLUSHOPT, or CLFLUSH writeback instruction: %w",
			errVNextWrongFormat)
	}
	if selectDirectDaxInvalidateInstruction(features) == directDaxCacheUnavailable {
		return fmt.Errorf(
			"CPU has no CLFLUSHOPT or CLFLUSH invalidation instruction: %w",
			errVNextWrongFormat)
	}
	return nil
}

// openVNextDevDAXDevice is the startup path for a real devdax character
// device. It only accepts an already formatted TRCXL006 device; it never
// initializes, upgrades, or repairs an unrecognized device in place.
func openVNextDevDAXDevice(devicePath string) (*vnextPersistentDevice, error) {
	file, storage, err := openVNextMappedDevDAXStorage(devicePath)
	if err != nil {
		return nil, err
	}
	device, err := openVNextStorageDevice(file, storage)
	if err != nil {
		if closeErr := storage.discardAndClose(); closeErr != nil {
			return nil, fmt.Errorf("open existing VNext devdax: %v; close storage: %w", err, closeErr)
		}
		return nil, err
	}
	return device, nil
}

// formatVNextDevDAXDevice is an explicit destructive, offline operation. It
// is intentionally not called by daemon startup and has no CLI wiring in this
// change. Operators must choose this entry point separately from open.
func formatVNextDevDAXDevice(
	devicePath string,
	deviceUUID string,
	ownerID string,
	ownerEpoch uint64,
	allocatorSlotBytes uint64,
) (*vnextPersistentDevice, error) {
	file, storage, err := openVNextMappedDevDAXStorage(devicePath)
	if err != nil {
		return nil, err
	}
	device, err := formatVNextStorageDevice(
		file, storage, deviceUUID, ownerID, ownerEpoch, allocatorSlotBytes)
	if err != nil {
		if closeErr := storage.discardAndClose(); closeErr != nil {
			return nil, fmt.Errorf("format VNext devdax: %v; close storage: %w", err, closeErr)
		}
		return nil, err
	}
	return device, nil
}

func (d *vnextPersistentDevice) closeStorage() error {
	if d == nil || d.storage == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.storage.Close()
}

func vnextValidateSignedStorageRange(size uint64, offset int64, length int, operation string) error {
	if offset < 0 {
		return fmt.Errorf("VNext storage %s offset %d is negative", operation, offset)
	}
	if length < 0 {
		return fmt.Errorf("VNext storage %s length %d is negative", operation, length)
	}
	start := uint64(offset)
	if start > uint64(math.MaxInt64) || uint64(length) > uint64(math.MaxInt64)-start {
		return fmt.Errorf("VNext storage %s range exceeds signed offset ABI", operation)
	}
	end := start + uint64(length)
	if end > size {
		return fmt.Errorf(
			"VNext storage %s range [%d,%d) exceeds capacity %d",
			operation, start, end, size)
	}
	return nil
}

func vnextValidateUnsignedStorageRange(size, offset uint64, length int, operation string) error {
	if offset > uint64(math.MaxInt64) {
		return fmt.Errorf("VNext storage %s offset exceeds signed offset ABI", operation)
	}
	return vnextValidateSignedStorageRange(size, int64(offset), length, operation)
}

func vnextPageRanges(ranges []vnextByteRange, pageBytes, capacity uint64) []vnextByteRange {
	var result []vnextByteRange
	for _, current := range ranges {
		pageRange := vnextByteRange{
			start: vnextAlignDown(current.start, pageBytes),
			end:   vnextAlignUpBounded(current.end, pageBytes, capacity),
		}
		if len(result) == 0 || pageRange.start > result[len(result)-1].end {
			result = append(result, pageRange)
			continue
		}
		if pageRange.end > result[len(result)-1].end {
			result[len(result)-1].end = pageRange.end
		}
	}
	return result
}

func vnextAlignDown(value, alignment uint64) uint64 {
	return value &^ (alignment - 1)
}

func vnextAlignUpBounded(value, alignment, limit uint64) uint64 {
	if value == 0 {
		return 0
	}
	last := value - 1
	aligned := vnextAlignDown(last, alignment) + alignment
	if aligned > limit {
		return limit
	}
	return aligned
}

func maxInt() int {
	return int(^uint(0) >> 1)
}
