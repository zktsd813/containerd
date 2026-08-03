package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

type vnextReaderDevDAXTestCharInfo struct {
	os.FileInfo
}

func (info vnextReaderDevDAXTestCharInfo) Mode() os.FileMode {
	return info.FileInfo.Mode() | os.ModeCharDevice
}

type vnextReaderDevDAXTestRecord struct {
	deviceUUID string
	offset     uint64
	length     int
}

type vnextReaderDevDAXTestMappedRange struct {
	deviceUUID string
	start      uintptr
	end        uintptr
}

type vnextReaderDevDAXTestInvalidator struct {
	mu sync.Mutex

	ranges  []vnextReaderDevDAXTestMappedRange
	records []vnextReaderDevDAXTestRecord
	before  func()
	failAt  int
	failure error

	blockDevice string
	blockLength int
	blockOnce   sync.Once
	blockEnter  chan struct{}
	blockLeave  chan struct{}
}

func (invalidator *vnextReaderDevDAXTestInvalidator) bind(
	source *vnextReadOnlyDevDAXSource,
) {
	invalidator.mu.Lock()
	defer invalidator.mu.Unlock()
	invalidator.ranges = nil
	for uuid, device := range source.devices {
		start := uintptr(unsafe.Pointer(&device.mapped[0]))
		invalidator.ranges = append(
			invalidator.ranges,
			vnextReaderDevDAXTestMappedRange{
				deviceUUID: uuid,
				start:      start,
				end:        start + uintptr(len(device.mapped)),
			})
	}
}

func (invalidator *vnextReaderDevDAXTestInvalidator) invalidate(
	mapped []byte,
) error {
	address := uintptr(unsafe.Pointer(&mapped[0]))
	invalidator.mu.Lock()
	uuid := ""
	var offset uint64
	for _, candidate := range invalidator.ranges {
		if address >= candidate.start &&
			address+uintptr(len(mapped)) <= candidate.end {
			uuid = candidate.deviceUUID
			offset = uint64(address - candidate.start)
			break
		}
	}
	if uuid == "" {
		invalidator.mu.Unlock()
		return errors.New("test invalidation range is outside every mapping")
	}
	invalidator.records = append(
		invalidator.records,
		vnextReaderDevDAXTestRecord{
			deviceUUID: uuid, offset: offset, length: len(mapped),
		})
	call := len(invalidator.records)
	before := invalidator.before
	fail := invalidator.failAt == call
	failure := invalidator.failure
	block := uuid == invalidator.blockDevice &&
		len(mapped) == invalidator.blockLength
	invalidator.mu.Unlock()
	if before != nil {
		before()
	}
	if block {
		invalidator.blockOnce.Do(func() {
			close(invalidator.blockEnter)
			<-invalidator.blockLeave
		})
	}
	if fail {
		return failure
	}
	return nil
}

func (invalidator *vnextReaderDevDAXTestInvalidator) snapshot() []vnextReaderDevDAXTestRecord {
	invalidator.mu.Lock()
	defer invalidator.mu.Unlock()
	return append([]vnextReaderDevDAXTestRecord(nil), invalidator.records...)
}

type vnextReaderDevDAXTestOperations struct {
	mu sync.Mutex

	openFlags      []int
	mmapProt       []int
	mmapFlags      []int
	activeMappings map[uintptr][]byte
	activeFiles    map[*os.File]struct{}
	openCalls      int
	mmapCalls      int
	munmaps        int
	closes         int

	pretendCharacter bool
	openFailAt       int
	openErr          error
	munmapFailures   int
	munmapErr        error
	closeErr         error
}

func vnextReaderDevDAXRegularFileSimulationDependenciesForTest(
	t *testing.T,
	invalidator *vnextReaderDevDAXTestInvalidator,
	operations *vnextReaderDevDAXTestOperations,
) vnextReaderDevDAXDependencies {
	t.Helper()
	dependencies := defaultVNextReaderDevDAXDependencies()
	dependencies.openFile = func(
		path string,
		flags int,
		mode os.FileMode,
	) (*os.File, error) {
		operations.mu.Lock()
		operations.openCalls++
		call := operations.openCalls
		operations.openFlags = append(operations.openFlags, flags)
		fail := operations.openFailAt == call
		failure := operations.openErr
		operations.mu.Unlock()
		if fail {
			return nil, failure
		}
		file, err := os.OpenFile(path, flags, mode)
		if err == nil {
			operations.mu.Lock()
			if operations.activeFiles == nil {
				operations.activeFiles = make(map[*os.File]struct{})
			}
			operations.activeFiles[file] = struct{}{}
			operations.mu.Unlock()
		}
		return file, err
	}
	dependencies.statFile = func(file *os.File) (os.FileInfo, error) {
		info, err := file.Stat()
		if err != nil || !operations.pretendCharacter {
			return info, err
		}
		return vnextReaderDevDAXTestCharInfo{FileInfo: info}, nil
	}
	dependencies.geometry = func(path string) (vnextDAXGeometry, error) {
		info, err := os.Stat(path)
		if err != nil {
			return vnextDAXGeometry{}, err
		}
		return vnextDAXGeometry{
			sizeBytes: uint64(info.Size()), alignBytes: uint64(os.Getpagesize()),
		}, nil
	}
	dependencies.mmap = func(
		fd int,
		offset int64,
		length int,
		prot int,
		flags int,
	) ([]byte, error) {
		operations.mu.Lock()
		operations.mmapCalls++
		operations.mmapProt = append(operations.mmapProt, prot)
		operations.mmapFlags = append(operations.mmapFlags, flags)
		operations.mu.Unlock()
		mapped, err := unix.Mmap(fd, offset, length, prot, flags)
		if err == nil {
			operations.mu.Lock()
			if operations.activeMappings == nil {
				operations.activeMappings = make(map[uintptr][]byte)
			}
			address := uintptr(unsafe.Pointer(&mapped[0]))
			operations.activeMappings[address] = mapped
			operations.mu.Unlock()
		}
		return mapped, err
	}
	dependencies.munmap = func(mapped []byte) error {
		operations.mu.Lock()
		operations.munmaps++
		if operations.munmapFailures > 0 {
			operations.munmapFailures--
			failure := operations.munmapErr
			operations.mu.Unlock()
			return failure
		}
		operations.mu.Unlock()
		err := unix.Munmap(mapped)
		if err == nil {
			operations.mu.Lock()
			delete(operations.activeMappings,
				uintptr(unsafe.Pointer(&mapped[0])))
			operations.mu.Unlock()
		}
		return err
	}
	dependencies.close = func(file *os.File) error {
		operations.mu.Lock()
		operations.closes++
		failure := operations.closeErr
		operations.mu.Unlock()
		actual := file.Close()
		operations.mu.Lock()
		delete(operations.activeFiles, file)
		operations.mu.Unlock()
		if failure != nil {
			return failure
		}
		return actual
	}
	dependencies.newInvalidator = func() (
		vnextReaderDAXCacheInvalidator,
		error,
	) {
		return invalidator.invalidate, nil
	}
	t.Cleanup(func() {
		operations.mu.Lock()
		mappings := make([][]byte, 0, len(operations.activeMappings))
		for _, mapped := range operations.activeMappings {
			mappings = append(mappings, mapped)
		}
		files := make([]*os.File, 0, len(operations.activeFiles))
		for file := range operations.activeFiles {
			files = append(files, file)
		}
		operations.mu.Unlock()
		for _, mapped := range mappings {
			_ = unix.Munmap(mapped)
		}
		for _, file := range files {
			_ = file.Close()
		}
	})
	return dependencies
}

func openVNextReaderDevDAXSimulationForTest(
	t *testing.T,
	fixture *vnextReaderTestFixture,
	invalidator *vnextReaderDevDAXTestInvalidator,
	operations *vnextReaderDevDAXTestOperations,
) *vnextReadOnlyDevDAXSource {
	t.Helper()
	operations.pretendCharacter = true
	dependencies := vnextReaderDevDAXRegularFileSimulationDependenciesForTest(
		t, invalidator, operations)
	source, err := openVNextReadOnlyDevDAXSourceWithDependencies(
		fixture.directory, dependencies)
	if err != nil {
		t.Fatalf("open test-only regular-file devdax simulation: %v", err)
	}
	invalidator.bind(source)
	t.Cleanup(func() { _ = source.Close() })
	return source
}

func (operations *vnextReaderDevDAXTestOperations) counts() (
	int,
	int,
	int,
	int,
) {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	return operations.openCalls, operations.mmapCalls,
		operations.munmaps, operations.closes
}

func TestVNextReaderDevDAXConstructorIsReadOnlyAndReadsNoMappedBytes(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{}
	source := openVNextReaderDevDAXSimulationForTest(
		t, fixture, invalidator, operations)
	if got := invalidator.snapshot(); len(got) != 0 {
		t.Fatalf("constructor invalidated or read mapped bytes: %#v", got)
	}
	operations.mu.Lock()
	openFlags := append([]int(nil), operations.openFlags...)
	mmapProt := append([]int(nil), operations.mmapProt...)
	mmapFlags := append([]int(nil), operations.mmapFlags...)
	operations.mu.Unlock()
	if len(openFlags) != 2 || len(mmapProt) != 2 || len(mmapFlags) != 2 {
		t.Fatalf("two-device open/map calls=%d/%d/%d",
			len(openFlags), len(mmapProt), len(mmapFlags))
	}
	for index := range openFlags {
		if openFlags[index] != vnextReaderDevDAXOpenFlags ||
			openFlags[index]&unix.O_ACCMODE != unix.O_RDONLY ||
			mmapProt[index] != unix.PROT_READ ||
			mmapProt[index]&unix.PROT_WRITE != 0 ||
			mmapFlags[index] != unix.MAP_SHARED {
			t.Fatalf("device %d flags/prot/map=%#x/%#x/%#x",
				index, openFlags[index], mmapProt[index], mmapFlags[index])
		}
	}
	if len(source.devices) != 2 || !reflect.DeepEqual(
		source.orderedUUIDs, []string{"reader-device-a", "reader-device-b"}) {
		t.Fatalf("multi-device source=%v order=%v",
			len(source.devices), source.orderedUUIDs)
	}
}

func TestVNextReaderDevDAXProductionContractRejectsRegularFile(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{pretendCharacter: false}
	dependencies := vnextReaderDevDAXRegularFileSimulationDependenciesForTest(
		t, invalidator, operations)
	source, err := openVNextReadOnlyDevDAXSourceWithDependencies(
		fixture.directory, dependencies)
	if source != nil || err == nil || !errors.Is(err, errVNextWrongFormat) {
		t.Fatalf("regular file returned source=%#v err=%v", source, err)
	}
	openCalls, mmapCalls, _, closes := operations.counts()
	if openCalls != 1 || mmapCalls != 0 || closes != 1 ||
		len(invalidator.snapshot()) != 0 {
		t.Fatalf("regular-file rejection open/map/close/invalidate=%d/%d/%d/%d",
			openCalls, mmapCalls, closes, len(invalidator.snapshot()))
	}
}

func TestVNextReaderDevDAXFirstAuthorizedReadInvalidatesExactMultiDeviceRanges(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	store, request := vnextReaderArmTestRestore(t, fixture)
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{}
	source := openVNextReaderDevDAXSimulationForTest(
		t, fixture, invalidator, operations)
	var unclaimed int64
	invalidator.before = func() {
		store.mu.RLock()
		entry := store.byRequestID[request.Activation.Request.ActivationRequestID]
		claimed := entry.firstReadClaimed
		store.mu.RUnlock()
		if !claimed {
			atomic.StoreInt64(&unclaimed, 1)
		}
	}
	runner := &vnextReaderTestRunner{}
	reader, err := newVNextAuthorizedReader(
		fixture.directory, store, source, runner)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Restore(context.Background(), request); err != nil {
		t.Fatalf("restore through read-only multi-devdax source: %v", err)
	}
	if atomic.LoadInt64(&unclaimed) != 0 {
		t.Fatal("mapped byte was invalidated before the one-shot permit was consumed")
	}
	want := make([]vnextReaderDevDAXTestRecord, 0, 10)
	for _, run := range fixture.storage.PageRuns {
		uuid := run.FirstPage.DeviceUUID
		device := fixture.devices[uuid]
		descriptorOffset, err := device.superblock.Geometry.descriptorOffset(
			run.FirstPage.DataPageIndex)
		if err != nil {
			t.Fatal(err)
		}
		contentOffset, err := device.superblock.Geometry.contentOffset(
			run.FirstPage.DataPageIndex)
		if err != nil {
			t.Fatal(err)
		}
		want = append(want,
			vnextReaderDevDAXTestRecord{deviceUUID: uuid, offset: 0, length: 4096},
			vnextReaderDevDAXTestRecord{deviceUUID: uuid, offset: 4096, length: 4096},
			vnextReaderDevDAXTestRecord{deviceUUID: uuid, offset: descriptorOffset, length: 64},
			vnextReaderDevDAXTestRecord{deviceUUID: uuid, offset: contentOffset, length: 4096},
			vnextReaderDevDAXTestRecord{deviceUUID: uuid, offset: descriptorOffset, length: 64},
		)
	}
	if got := invalidator.snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("multi-devdax invalidation order:\n got=%#v\nwant=%#v", got, want)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls=%d, want 1", runner.calls)
	}
}

func TestVNextReaderDevDAXSuperblockIsLoadedOnlyInsideFirstSourceCall(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{}
	source := openVNextReaderDevDAXSimulationForTest(
		t, fixture, invalidator, operations)
	device := fixture.devices["reader-device-a"]
	device.mu.Lock()
	for _, offset := range []uint64{0, vnextSuperblockSlotBytes} {
		if err := vnextWriteAtFull(
			device.storage, make([]byte, vnextFormatHeaderSize), offset); err != nil {
			device.mu.Unlock()
			t.Fatal(err)
		}
	}
	if err := device.storage.Sync(); err != nil {
		device.mu.Unlock()
		t.Fatal(err)
	}
	device.mu.Unlock()
	binding := fixture.directory.byUUID["reader-device-a"]
	if _, err := source.ReadVNextDescriptor(
		context.Background(), binding, 10); err == nil {
		t.Fatal("source used a superblock snapshot taken during construction")
	}
	got := invalidator.snapshot()
	if len(got) != 2 || got[0].offset != 0 ||
		got[1].offset != vnextSuperblockSlotBytes {
		t.Fatalf("lazy A/B reads=%#v", got)
	}
}

func TestVNextReaderDevDAXInvalidationFailureIsFailClosedAndOneShot(
	t *testing.T,
) {
	for _, failAt := range []int{1, 2, 3, 4} {
		t.Run(string(rune('0'+failAt)), func(t *testing.T) {
			fixture := newVNextReaderTestFixture(t)
			store, request := vnextReaderArmTestRestore(t, fixture)
			failure := errors.New("test non-coherent invalidation failure")
			invalidator := &vnextReaderDevDAXTestInvalidator{
				failAt: failAt, failure: failure,
			}
			operations := &vnextReaderDevDAXTestOperations{}
			source := openVNextReaderDevDAXSimulationForTest(
				t, fixture, invalidator, operations)
			runner := &vnextReaderTestRunner{}
			reader, err := newVNextAuthorizedReader(
				fixture.directory, store, source, runner)
			if err != nil {
				t.Fatal(err)
			}
			_, err = reader.Restore(context.Background(), request)
			if !errors.Is(err, errVNextReaderCacheInvalidation) ||
				!errors.Is(err, failure) {
				t.Fatalf("invalidation %d error=%v", failAt, err)
			}
			beforeReplay := len(invalidator.snapshot())
			if _, err := reader.Restore(
				context.Background(), request); !errors.Is(
				err, errVNextReaderFirstReadAlreadyClaimed) {
				t.Fatalf("invalidation replay error=%v", err)
			}
			if len(invalidator.snapshot()) != beforeReplay || runner.calls != 0 {
				t.Fatalf("failed/replayed invalidation calls=%d runner=%d",
					len(invalidator.snapshot()), runner.calls)
			}
		})
	}
}

func TestVNextReaderDevDAXRejectsBindingSubstitutionBeforeMappedAccess(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{}
	source := openVNextReaderDevDAXSimulationForTest(
		t, fixture, invalidator, operations)
	binding := fixture.directory.byUUID["reader-device-a"]
	binding.DevicePath += "-substituted"
	if _, err := source.ReadVNextDescriptor(
		context.Background(), binding, 10); err == nil {
		t.Fatal("source accepted a substituted local binding")
	}
	if got := invalidator.snapshot(); len(got) != 0 {
		t.Fatalf("binding substitution reached mapped bytes: %#v", got)
	}
}

func TestVNextReaderDevDAXPerDeviceReadsAndCloseAreConcurrentSafe(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	invalidator := &vnextReaderDevDAXTestInvalidator{
		blockDevice: "reader-device-a",
		blockLength: int(vnextPageDescriptorSize),
		blockEnter:  make(chan struct{}),
		blockLeave:  make(chan struct{}),
	}
	operations := &vnextReaderDevDAXTestOperations{}
	source := openVNextReaderDevDAXSimulationForTest(
		t, fixture, invalidator, operations)
	bindingA := fixture.directory.byUUID["reader-device-a"]
	bindingB := fixture.directory.byUUID["reader-device-b"]
	readADone := make(chan error, 1)
	go func() {
		_, err := source.ReadVNextDescriptor(
			context.Background(), bindingA, 10)
		readADone <- err
	}()
	select {
	case <-invalidator.blockEnter:
	case <-time.After(2 * time.Second):
		t.Fatal("device A read did not reach descriptor invalidation")
	}
	readBDone := make(chan error, 1)
	go func() {
		_, err := source.ReadVNextDescriptor(
			context.Background(), bindingB, 20)
		readBDone <- err
	}()
	select {
	case err := <-readBDone:
		if err != nil {
			t.Fatalf("device B read blocked behind A: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("different-device read was serialized behind device A")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- source.Close() }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		source.mu.RLock()
		closed := source.admissionClosed
		source.mu.RUnlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not close source admission")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := source.ReadVNextDescriptor(
		context.Background(), bindingB, 20); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("post-Close read error=%v", err)
	}
	_, _, munmaps, closes := operations.counts()
	if munmaps != 0 || closes != 0 {
		t.Fatalf("Close unmapped beneath active read: unmap/close=%d/%d",
			munmaps, closes)
	}
	close(invalidator.blockLeave)
	if err := <-readADone; err != nil {
		t.Fatalf("admitted device A read: %v", err)
	}
	if err := <-closeDone; err != nil {
		t.Fatalf("Close after read drain: %v", err)
	}
	_, _, munmaps, closes = operations.counts()
	if munmaps != 2 || closes != 2 {
		t.Fatalf("two-device cleanup unmap/close=%d/%d", munmaps, closes)
	}
	var wait sync.WaitGroup
	wait.Add(16)
	for index := 0; index < 16; index++ {
		go func() {
			defer wait.Done()
			if err := source.Close(); err != nil {
				t.Errorf("repeated Close: %v", err)
			}
		}()
	}
	wait.Wait()
	_, _, afterMunmaps, afterCloses := operations.counts()
	if afterMunmaps != munmaps || afterCloses != closes {
		t.Fatalf("repeated Close changed unmap/close=%d/%d",
			afterMunmaps, afterCloses)
	}
}

func TestVNextReaderDevDAXPartialOpenPreservesCleanupErrorsAndClosesTerminalOnce(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	openErr := errors.New("test second devdax open failure")
	unmapErr := errors.New("test partial devdax munmap failure")
	closeErr := errors.New("test terminal devdax close failure")
	invalidator := &vnextReaderDevDAXTestInvalidator{}
	operations := &vnextReaderDevDAXTestOperations{
		pretendCharacter: true,
		openFailAt:       2,
		openErr:          openErr,
		munmapFailures:   1,
		munmapErr:        unmapErr,
		closeErr:         closeErr,
	}
	dependencies := vnextReaderDevDAXRegularFileSimulationDependenciesForTest(
		t, invalidator, operations)
	source, err := openVNextReadOnlyDevDAXSourceWithDependencies(
		fixture.directory, dependencies)
	if source != nil || !errors.Is(err, openErr) || !errors.Is(err, unmapErr) ||
		!errors.Is(err, closeErr) {
		t.Fatalf("partial open source=%#v err=%v", source, err)
	}
	openCalls, mmapCalls, munmaps, closes := operations.counts()
	if openCalls != 2 || mmapCalls != 1 || munmaps != 1 || closes != 1 {
		t.Fatalf("partial cleanup open/map/unmap/close=%d/%d/%d/%d",
			openCalls, mmapCalls, munmaps, closes)
	}
}

func TestVNextReaderDevDAXCloseRetriesMunmapButNeverRepeatsFileClose(
	t *testing.T,
) {
	t.Run("retry-munmap", func(t *testing.T) {
		fixture := newVNextReaderTestFixture(t)
		unmapErr := errors.New("test retryable munmap failure")
		invalidator := &vnextReaderDevDAXTestInvalidator{}
		operations := &vnextReaderDevDAXTestOperations{
			munmapFailures: 1, munmapErr: unmapErr,
		}
		source := openVNextReaderDevDAXSimulationForTest(
			t, fixture, invalidator, operations)
		if err := source.Close(); !errors.Is(err, unmapErr) {
			t.Fatalf("first Close error=%v", err)
		}
		_, _, munmaps, closes := operations.counts()
		if munmaps != 2 || closes != 1 {
			t.Fatalf("first Close unmap/close=%d/%d", munmaps, closes)
		}
		if err := source.Close(); err != nil {
			t.Fatalf("retry Close: %v", err)
		}
		_, _, munmaps, closes = operations.counts()
		if munmaps != 3 || closes != 2 {
			t.Fatalf("retry Close unmap/close=%d/%d", munmaps, closes)
		}
		if err := source.Close(); err != nil {
			t.Fatalf("idempotent Close: %v", err)
		}
		_, _, afterMunmaps, afterCloses := operations.counts()
		if afterMunmaps != munmaps || afterCloses != closes {
			t.Fatal("completed Close repeated munmap or file close")
		}
	})

	t.Run("terminal-close-error", func(t *testing.T) {
		fixture := newVNextReaderTestFixture(t)
		closeErr := errors.New("test terminal file close error")
		invalidator := &vnextReaderDevDAXTestInvalidator{}
		operations := &vnextReaderDevDAXTestOperations{closeErr: closeErr}
		source := openVNextReaderDevDAXSimulationForTest(
			t, fixture, invalidator, operations)
		if err := source.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("terminal Close error=%v", err)
		}
		if err := source.Close(); !errors.Is(err, closeErr) {
			t.Fatalf("replayed terminal Close error=%v", err)
		}
		_, _, munmaps, closes := operations.counts()
		if munmaps != 2 || closes != 2 {
			t.Fatalf("terminal Close unmap/close=%d/%d", munmaps, closes)
		}
	})
}

func TestVNextReaderDevDAXInvalidationRangeRejectsUnalignedAndOverflow(
	t *testing.T,
) {
	cacheLine := uintptr(vnextDAXCacheLineBytes)
	if err := validateVNextReaderDAXCacheRange(2*cacheLine, cacheLine); err != nil {
		t.Fatalf("valid cache range: %v", err)
	}
	for _, test := range []struct {
		name    string
		address uintptr
		length  uintptr
	}{
		{name: "zero-address", address: 0, length: cacheLine},
		{name: "zero-length", address: cacheLine, length: 0},
		{name: "unaligned-address", address: cacheLine + 1, length: cacheLine},
		{name: "unaligned-length", address: cacheLine, length: cacheLine + 1},
		{name: "overflow", address: ^uintptr(0) - cacheLine + 1, length: cacheLine},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateVNextReaderDAXCacheRange(
				test.address, test.length); err == nil {
				t.Fatal("invalid cache range was accepted")
			}
		})
	}
}

func TestVNextReaderDevDAXCPUFeatureSelectionRequiresEveryObservedCPU(
	t *testing.T,
) {
	for _, test := range []struct {
		name        string
		cpuInfo     string
		features    vnextReaderDAXCPUFeatures
		instruction vnextReaderDAXCacheInstruction
	}{
		{
			name: "identical",
			cpuInfo: "processor: 0\nflags: fpu clflush clflushopt\n" +
				"processor: 1\nflags: fpu clflush clflushopt\n",
			features: vnextReaderDAXCPUFeatures{
				clflush: true, clflushopt: true,
			},
			instruction: vnextReaderDAXCacheCLFlushOpt,
		},
		{
			name: "heterogeneous",
			cpuInfo: "processor: 0\nflags: fpu clflush clflushopt\n" +
				"processor: 1\nflags: fpu clflush\n",
			features: vnextReaderDAXCPUFeatures{
				clflush: true, clflushopt: false,
			},
			instruction: vnextReaderDAXCacheCLFlush,
		},
		{
			name:        "no-flags",
			cpuInfo:     "processor: 0\nmodel name: test CPU\n",
			features:    vnextReaderDAXCPUFeatures{},
			instruction: vnextReaderDAXCacheUnavailable,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			features := parseVNextReaderDAXCPUFeatures(test.cpuInfo)
			if features != test.features {
				t.Fatalf("features=%+v, want %+v", features, test.features)
			}
			if instruction := selectVNextReaderDAXCacheInstruction(features); instruction != test.instruction {
				t.Fatalf("instruction=%d, want %d", instruction, test.instruction)
			}
		})
	}
}
