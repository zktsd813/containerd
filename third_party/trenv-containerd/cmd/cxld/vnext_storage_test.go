package main

import (
	"bytes"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type testVNextAlignedStorage struct {
	vnextDeviceStorage
	alignment uint64
}

func (s testVNextAlignedStorage) MappingAlignment() uint64 {
	return s.alignment
}

func newTestVNextMappedStorage(
	t *testing.T,
	capacity uint64,
	writeback func([]byte) error,
) (*os.File, *vnextMappedDAXStorage) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mapped-dax.img")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create mmap simulation: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if err := file.Truncate(int64(capacity)); err != nil {
		t.Fatalf("size mmap simulation: %v", err)
	}
	storage, err := newVNextMappedDAXStorage(
		file, capacity, vnextContentPageSize, false, writeback)
	if err != nil {
		t.Fatalf("map simulation: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return file, storage
}

func remapTestVNextStorage(
	t *testing.T,
	file *os.File,
	capacity uint64,
) *vnextMappedDAXStorage {
	t.Helper()
	storage, err := newVNextMappedDAXStorage(
		file,
		capacity,
		vnextContentPageSize,
		false,
		func([]byte) error { return nil })
	if err != nil {
		t.Fatalf("remap simulation: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })
	return storage
}

func TestVNextMappedDAXStorageBoundsAndDirtyCacheLines(t *testing.T) {
	var writebackLengths []int
	file, storage := newTestVNextMappedStorage(
		t,
		4*vnextContentPageSize,
		func(data []byte) error {
			writebackLengths = append(writebackLengths, len(data))
			return nil
		})

	if _, err := storage.WriteAt([]byte{0x11, 0x22}, 65); err != nil {
		t.Fatalf("write first unaligned range: %v", err)
	}
	if _, err := storage.WriteAt([]byte{0x33, 0x44}, 4095); err != nil {
		t.Fatalf("write cross-page range: %v", err)
	}
	wantDirty := []vnextByteRange{{start: 64, end: 128}, {start: 4032, end: 4160}}
	if !reflect.DeepEqual(storage.dirty, wantDirty) {
		t.Fatalf("dirty cache lines %#v, want %#v", storage.dirty, wantDirty)
	}

	read := make([]byte, 2)
	if _, err := storage.ReadAt(read, 65); err != nil {
		t.Fatalf("read mapped write: %v", err)
	}
	if !bytes.Equal(read, []byte{0x11, 0x22}) {
		t.Fatalf("mapped read is %x", read)
	}
	if _, err := storage.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative read offset was accepted")
	}
	if _, err := storage.ReadAt(make([]byte, 2), int64(storage.Size()-1)); err == nil {
		t.Fatal("read beyond capacity was accepted")
	}
	if _, err := storage.WriteAt(make([]byte, 2), int64(storage.Size()-1)); err == nil {
		t.Fatal("write beyond capacity was accepted")
	}
	if err := vnextValidateUnsignedStorageRange(
		uint64(math.MaxInt64), uint64(math.MaxInt64), 1, "test"); err == nil {
		t.Fatal("signed-offset overflow was accepted")
	}

	if err := storage.Sync(); err != nil {
		t.Fatalf("sync mapped writes: %v", err)
	}
	if !reflect.DeepEqual(writebackLengths, []int{64, 128}) {
		t.Fatalf("writeback lengths %v, want exact dirty cache lines [64 128]", writebackLengths)
	}
	if len(storage.dirty) != 0 {
		t.Fatalf("successful sync retained dirty ranges: %#v", storage.dirty)
	}
	onDisk := make([]byte, 2)
	if _, err := file.ReadAt(onDisk, 4095); err != nil {
		t.Fatalf("read synchronized simulation file: %v", err)
	}
	if !bytes.Equal(onDisk, []byte{0x33, 0x44}) {
		t.Fatalf("synchronized simulation bytes are %x", onDisk)
	}
	if err := storage.Sync(); err != nil {
		t.Fatalf("clean sync: %v", err)
	}
	if !reflect.DeepEqual(writebackLengths, []int{64, 128}) {
		t.Fatal("clean sync wrote back data")
	}
}

func TestVNextMappedDAXStorageWritebackFailureIsFailClosed(t *testing.T) {
	unsupported := errors.New("CPU cache writeback unsupported")
	_, storage := newTestVNextMappedStorage(
		t,
		2*vnextContentPageSize,
		func([]byte) error { return unsupported })
	if _, err := storage.WriteAt([]byte{0xaa}, 17); err != nil {
		t.Fatalf("write mapped byte: %v", err)
	}
	if err := storage.Sync(); !errors.Is(err, unsupported) {
		t.Fatalf("unsupported writeback returned %v", err)
	}
	wantDirty := []vnextByteRange{{start: 0, end: 64}}
	if !reflect.DeepEqual(storage.dirty, wantDirty) {
		t.Fatalf("failed sync lost dirty authority: %#v", storage.dirty)
	}
	storage.writeback = func([]byte) error { return nil }
	if err := storage.Sync(); err != nil {
		t.Fatalf("retry mapped sync: %v", err)
	}
	if len(storage.dirty) != 0 {
		t.Fatalf("successful retry retained %#v", storage.dirty)
	}
}

func TestVNextMappedDAXPersistentDeviceRestartAndABRecovery(t *testing.T) {
	const capacity = 4 << 20
	file, storage := newTestVNextMappedStorage(
		t, capacity, func([]byte) error { return nil })
	device, err := formatVNextStorageDevice(
		file, storage, "mapped-device", "owner-mapped", 9, 64<<10)
	if err != nil {
		t.Fatalf("format mapped VNext device: %v", err)
	}
	request := vnextCheckpointAllocationRequest{
		RequestID:    "mapped-request",
		CheckpointID: "mapped-checkpoint",
		ProducerID:   "mapped-producer",
		OwnerID:      "owner-mapped",
		OwnerEpoch:   9,
		MaxExtents:   2,
		Contents: []vnextContentRequest{{
			Kind:       vnextContentMemory,
			ObjectID:   77,
			ByteLength: vnextContentPageSize,
			PageCount:  1,
		}},
	}
	grant, err := device.reserve(request)
	if err != nil {
		t.Fatalf("reserve mapped page: %v", err)
	}
	payload := bytes.Repeat([]byte{0x5a}, int(vnextContentPageSize))
	if err := device.writePage(grant, 0, payload); err != nil {
		t.Fatalf("write mapped page: %v", err)
	}
	if err := device.commit(grant); err != nil {
		t.Fatalf("commit mapped page: %v", err)
	}
	if err := storage.Close(); err != nil {
		t.Fatalf("close first mapping: %v", err)
	}

	reopenedStorage := remapTestVNextStorage(t, file, capacity)
	reopened, err := openVNextStorageDevice(file, reopenedStorage)
	if err != nil {
		t.Fatalf("open mapped VNext device: %v", err)
	}
	record, ok := reopened.allocator.lookup(request.CheckpointID)
	if !ok || record.State != vnextAllocationCommitted {
		t.Fatalf("mapped allocation did not survive restart: %#v", record)
	}
	dataPage, err := vnextRecordPhysicalPage(&record, 0)
	if err != nil {
		t.Fatalf("resolve mapped data page: %v", err)
	}
	content, err := reopened.readContentPageLocked(dataPage)
	if err != nil {
		t.Fatalf("read restarted mapped page: %v", err)
	}
	if !bytes.Equal(content, payload) {
		t.Fatal("mapped content changed across close/remap")
	}

	// Sequence 2 is superblock B. Tearing only its commit header must leave
	// sequence 1 in A usable after a fresh mapping.
	if err := vnextWriteAtFull(
		reopenedStorage, make([]byte, vnextFormatHeaderSize), vnextSuperblockSlotBytes); err != nil {
		t.Fatalf("tear mapped superblock B: %v", err)
	}
	if err := reopenedStorage.Sync(); err != nil {
		t.Fatalf("sync mapped tear: %v", err)
	}
	if err := reopenedStorage.Close(); err != nil {
		t.Fatalf("close torn mapping: %v", err)
	}

	recoveredStorage := remapTestVNextStorage(t, file, capacity)
	recovered, err := openVNextStorageDevice(file, recoveredStorage)
	if err != nil {
		t.Fatalf("recover mapped A/B envelope: %v", err)
	}
	if recovered.superblock.Sequence != 1 {
		t.Fatalf("selected superblock sequence %d, want 1", recovered.superblock.Sequence)
	}
}

func TestVNextMappedDAXOpenDoesNotAutoFormat(t *testing.T) {
	const capacity = 4 << 20
	file, storage := newTestVNextMappedStorage(
		t, capacity, func([]byte) error { return nil })
	if _, err := openVNextStorageDevice(file, storage); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("blank mapped device open returned %v", err)
	}
	firstPage := make([]byte, vnextContentPageSize)
	if _, err := storage.ReadAt(firstPage, 0); err != nil {
		t.Fatalf("read blank device after rejected open: %v", err)
	}
	if !bytes.Equal(firstPage, make([]byte, len(firstPage))) {
		t.Fatal("startup open modified or formatted a blank device")
	}
}

func TestVNextExternalContentUsesSysfsAlignedMappingWindow(t *testing.T) {
	file, device := newTestVNextPersistentDevice(t, 4<<20, 64<<10)
	const devdaxAlignment = uint64(2 << 20)
	device.storage = testVNextAlignedStorage{
		vnextDeviceStorage: device.storage,
		alignment:          devdaxAlignment,
	}
	contentOffset, err := device.superblock.Geometry.contentOffset(0)
	if err != nil {
		t.Fatalf("resolve first content offset: %v", err)
	}
	if contentOffset%devdaxAlignment == 0 {
		t.Fatalf("test needs an offset inside an aligned mapping window, got %d", contentOffset)
	}
	payload := bytes.Repeat([]byte{0x6c}, int(vnextContentPageSize))
	if err := vnextWriteAtFull(file, payload, contentOffset); err != nil {
		t.Fatalf("simulate external producer: %v", err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("sync simulated external producer: %v", err)
	}
	visible, err := device.readVisibleExternalContentLocked(
		contentOffset, vnextCRCCopyEngineCPU, false)
	if err != nil {
		t.Fatalf("read through 2 MiB-aligned mmap window: %v", err)
	}
	if !bytes.Equal(visible, payload) {
		t.Fatal("aligned external mapping returned different content")
	}
}

func TestVNextRegularFileStorageRejectsCharacterDevice(t *testing.T) {
	file, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	defer file.Close() //nolint:errcheck
	if _, err := newVNextRegularFileStorage(file); !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("regular-file backend accepted character device: %v", err)
	}
}

func TestResolveVNextDAXGeometryFallsBackToClassSysfs(t *testing.T) {
	root := t.TempDir()
	busRoot := filepath.Join(root, "sys", "bus", "dax", "devices")
	classRoot := filepath.Join(root, "sys", "class", "dax")
	deviceName := "dax9.3"
	if err := os.MkdirAll(filepath.Join(busRoot, deviceName), 0o755); err != nil {
		t.Fatalf("create incomplete bus sysfs: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(busRoot, deviceName, "size"), []byte("0x200000\n"), 0o600); err != nil {
		t.Fatalf("write incomplete bus size: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(classRoot, deviceName), 0o755); err != nil {
		t.Fatalf("create class sysfs: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(classRoot, deviceName, "size"), []byte("0x200000\n"), 0o600); err != nil {
		t.Fatalf("write class size: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(classRoot, deviceName, "align"), []byte("0x200000\n"), 0o600); err != nil {
		t.Fatalf("write class align: %v", err)
	}

	geometry, err := resolveVNextDAXGeometry(
		filepath.Join("/dev", deviceName), []string{busRoot, classRoot})
	if err != nil {
		t.Fatalf("resolve class sysfs fallback: %v", err)
	}
	if geometry.sizeBytes != 2<<20 || geometry.alignBytes != 2<<20 {
		t.Fatalf("resolved geometry %#v", geometry)
	}
	if _, err := resolveVNextDAXGeometry(
		filepath.Join("/dev", deviceName), []string{busRoot}); err == nil {
		t.Fatal("incomplete sysfs geometry was accepted")
	}
}

func TestVNextDAXGeometryRequiresExactPageMultiples(t *testing.T) {
	if err := vnextValidateDAXGeometry(2<<20, 2<<20); err != nil {
		t.Fatalf("valid 4 KiB-page geometry: %v", err)
	}
	for _, test := range []struct {
		name  string
		size  uint64
		align uint64
	}{
		{name: "unaligned size", size: (2 << 20) - 1, align: 4096},
		{name: "sub-page align", size: 2 << 20, align: 2048},
		{name: "non-power-of-two align", size: 3 << 20, align: 3 << 12},
		{name: "size not align multiple", size: 3 << 20, align: 2 << 20},
		{name: "signed offset overflow", size: uint64(math.MaxInt64) + 1, align: 4096},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := vnextValidateDAXGeometry(test.size, test.align); err == nil {
				t.Fatalf("accepted size=%d align=%d", test.size, test.align)
			}
		})
	}
}

func TestVNextDAXCacheProtocolRequiresExact64ByteWritebackAndInvalidate(t *testing.T) {
	fullySupported := directDaxCPUFeatureSet{
		clflush:    true,
		clflushopt: true,
		clwb:       true,
	}
	if err := validateVNextDAXCacheProtocol(
		fullySupported, vnextDAXCacheLineBytes); err != nil {
		t.Fatalf("valid cache protocol rejected: %v", err)
	}
	if err := validateVNextDAXCacheProtocol(fullySupported, 128); err == nil {
		t.Fatal("128-byte cache line was accepted by the 64-byte descriptor ABI")
	}
	if err := validateVNextDAXCacheProtocol(
		directDaxCPUFeatureSet{}, vnextDAXCacheLineBytes); err == nil {
		t.Fatal("CPU without writeback/invalidation instructions was accepted")
	}
	if err := validateVNextDAXCacheProtocol(
		directDaxCPUFeatureSet{clwb: true}, vnextDAXCacheLineBytes); err == nil {
		t.Fatal("CLWB-only CPU without an invalidating instruction was accepted")
	}
	if err := validateVNextDAXCacheProtocol(
		directDaxCPUFeatureSet{clflush: true}, vnextDAXCacheLineBytes); err != nil {
		t.Fatalf("CLFLUSH fallback rejected: %v", err)
	}
}
