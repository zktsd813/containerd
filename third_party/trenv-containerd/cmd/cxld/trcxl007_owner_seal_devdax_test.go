package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007"
	"golang.org/x/sys/unix"
)

type trcxl007OwnerSealDevDAXTestInvalidation struct {
	binding trcxl007.ProducerScatterDeviceBinding
	offset  uint64
	length  int
	address uintptr
}

type trcxl007OwnerSealDevDAXTestLease struct {
	mu sync.Mutex

	invalidations []trcxl007OwnerSealDevDAXTestInvalidation
	invalidateErr error
	closeErr      error
	closeCalls    int
}

func (lease *trcxl007OwnerSealDevDAXTestLease) InvalidateExactRange(
	ctx context.Context,
	binding trcxl007.ProducerScatterDeviceBinding,
	offset uint64,
	direct []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	address := uintptr(0)
	if len(direct) > 0 {
		address = uintptr(unsafe.Pointer(&direct[0]))
	}
	lease.mu.Lock()
	lease.invalidations = append(
		lease.invalidations,
		trcxl007OwnerSealDevDAXTestInvalidation{
			binding: binding,
			offset:  offset,
			length:  len(direct),
			address: address,
		})
	err := lease.invalidateErr
	lease.mu.Unlock()
	return err
}

func (lease *trcxl007OwnerSealDevDAXTestLease) Close() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.closeCalls++
	return lease.closeErr
}

func (lease *trcxl007OwnerSealDevDAXTestLease) snapshot() (
	[]trcxl007OwnerSealDevDAXTestInvalidation,
	int,
) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return append(
		[]trcxl007OwnerSealDevDAXTestInvalidation(nil),
		lease.invalidations...), lease.closeCalls
}

type trcxl007OwnerSealDevDAXTestVisibility struct {
	mu sync.Mutex

	acquisitions [][]trcxl007.ProducerScatterDeviceBinding
	acquireErr   error
	leaseOnError bool
	returnNil    bool
	mutateInput  bool
	onAcquire    func()
	newLease     func(int) *trcxl007OwnerSealDevDAXTestLease
	leases       []*trcxl007OwnerSealDevDAXTestLease
}

func (visibility *trcxl007OwnerSealDevDAXTestVisibility) Acquire(
	ctx context.Context,
	devices []trcxl007.ProducerScatterDeviceBinding,
) (trcxl007OwnerSealDevDAXVisibilityLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	visibility.mu.Lock()
	call := len(visibility.acquisitions)
	visibility.acquisitions = append(
		visibility.acquisitions,
		append([]trcxl007.ProducerScatterDeviceBinding(nil), devices...))
	acquireErr := visibility.acquireErr
	leaseOnError := visibility.leaseOnError
	returnNil := visibility.returnNil
	mutateInput := visibility.mutateInput
	onAcquire := visibility.onAcquire
	newLease := visibility.newLease
	visibility.mu.Unlock()
	if mutateInput && len(devices) > 0 {
		devices[0].DeviceOwnerEpoch++
	}
	if onAcquire != nil {
		onAcquire()
	}
	if acquireErr != nil && !leaseOnError {
		return nil, acquireErr
	}
	if returnNil {
		return nil, nil
	}
	lease := &trcxl007OwnerSealDevDAXTestLease{}
	if newLease != nil {
		lease = newLease(call)
	}
	visibility.mu.Lock()
	visibility.leases = append(visibility.leases, lease)
	visibility.mu.Unlock()
	return lease, acquireErr
}

type trcxl007OwnerSealDevDAXTestNilContext struct{}

func (*trcxl007OwnerSealDevDAXTestNilContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func (*trcxl007OwnerSealDevDAXTestNilContext) Done() <-chan struct{} { return nil }
func (*trcxl007OwnerSealDevDAXTestNilContext) Err() error            { return nil }
func (*trcxl007OwnerSealDevDAXTestNilContext) Value(interface{}) interface{} {
	return nil
}

func (visibility *trcxl007OwnerSealDevDAXTestVisibility) snapshot() (
	[][]trcxl007.ProducerScatterDeviceBinding,
	[]*trcxl007OwnerSealDevDAXTestLease,
) {
	visibility.mu.Lock()
	defer visibility.mu.Unlock()
	acquisitions := make([][]trcxl007.ProducerScatterDeviceBinding, 0,
		len(visibility.acquisitions))
	for _, devices := range visibility.acquisitions {
		acquisitions = append(
			acquisitions,
			append([]trcxl007.ProducerScatterDeviceBinding(nil), devices...))
	}
	return acquisitions, append(
		[]*trcxl007OwnerSealDevDAXTestLease(nil), visibility.leases...)
}

type trcxl007OwnerSealDevDAXTestMapping struct {
	uuid   string
	mapped []byte
}

type trcxl007OwnerSealDevDAXTestOperations struct {
	mu sync.Mutex

	pathUUID map[string]string
	pathRdev map[string]uint64
	fdUUID   map[int]string
	files    map[*os.File]string
	mappings map[uintptr]trcxl007OwnerSealDevDAXTestMapping

	openFlags []int
	mmapProt  []int
	mmapFlags []int
	cleanup   []string

	pretendCharacter bool
	statRdevOverride map[string]uint64
	geometryOverride map[string]trcxl007OwnerSealDevDAXKernelGeometry
	munmapFailures   map[string]int
	munmapErrors     map[string]error
	closeErrors      map[string]error
}

func (operations *trcxl007OwnerSealDevDAXTestOperations) dependencies(
	t *testing.T,
) trcxl007OwnerSealDevDAXDependencies {
	t.Helper()
	dependencies := defaultTRCXL007OwnerSealDevDAXDependencies()
	dependencies.openFile = func(
		path string,
		flags int,
		mode os.FileMode,
	) (*os.File, error) {
		file, err := os.OpenFile(path, flags, mode)
		operations.mu.Lock()
		operations.openFlags = append(operations.openFlags, flags)
		if err == nil {
			uuid := operations.pathUUID[path]
			operations.fdUUID[int(file.Fd())] = uuid
			operations.files[file] = uuid
		}
		operations.mu.Unlock()
		return file, err
	}
	dependencies.statFile = func(
		file *os.File,
	) (trcxl007OwnerSealDevDAXFileIdentity, error) {
		operations.mu.Lock()
		uuid := operations.files[file]
		path := file.Name()
		rdev := operations.pathRdev[path]
		if override, exists := operations.statRdevOverride[uuid]; exists {
			rdev = override
		}
		character := operations.pretendCharacter
		operations.mu.Unlock()
		return trcxl007OwnerSealDevDAXFileIdentity{
			characterDevice: character,
			rdev:            rdev,
		}, nil
	}
	dependencies.geometry = func(
		path string,
	) (trcxl007OwnerSealDevDAXKernelGeometry, error) {
		operations.mu.Lock()
		uuid := operations.pathUUID[path]
		rdev := operations.pathRdev[path]
		if override, exists := operations.geometryOverride[uuid]; exists {
			operations.mu.Unlock()
			return override, nil
		}
		operations.mu.Unlock()
		stat, err := os.Stat(path)
		if err != nil {
			return trcxl007OwnerSealDevDAXKernelGeometry{}, err
		}
		return trcxl007OwnerSealDevDAXKernelGeometry{
			sizeBytes:  uint64(stat.Size()),
			alignBytes: uint64(os.Getpagesize()),
			rdev:       rdev,
		}, nil
	}
	dependencies.mmap = func(
		fd int,
		offset int64,
		length int,
		prot int,
		flags int,
	) ([]byte, error) {
		mapped, err := unix.Mmap(fd, offset, length, prot, flags)
		operations.mu.Lock()
		operations.mmapProt = append(operations.mmapProt, prot)
		operations.mmapFlags = append(operations.mmapFlags, flags)
		if err == nil {
			address := uintptr(unsafe.Pointer(&mapped[0]))
			operations.mappings[address] = trcxl007OwnerSealDevDAXTestMapping{
				uuid:   operations.fdUUID[fd],
				mapped: mapped,
			}
		}
		operations.mu.Unlock()
		return mapped, err
	}
	dependencies.munmap = func(mapped []byte) error {
		address := uintptr(unsafe.Pointer(&mapped[0]))
		operations.mu.Lock()
		mapping := operations.mappings[address]
		uuid := mapping.uuid
		operations.cleanup = append(operations.cleanup, "unmap:"+uuid)
		if operations.munmapFailures[uuid] > 0 {
			operations.munmapFailures[uuid]--
			err := operations.munmapErrors[uuid]
			operations.mu.Unlock()
			return err
		}
		operations.mu.Unlock()
		err := unix.Munmap(mapped)
		if err == nil {
			operations.mu.Lock()
			delete(operations.mappings, address)
			operations.mu.Unlock()
		}
		return err
	}
	dependencies.close = func(file *os.File) error {
		operations.mu.Lock()
		uuid := operations.files[file]
		operations.cleanup = append(operations.cleanup, "close:"+uuid)
		injected := operations.closeErrors[uuid]
		operations.mu.Unlock()
		actual := file.Close()
		operations.mu.Lock()
		delete(operations.fdUUID, int(file.Fd()))
		delete(operations.files, file)
		operations.mu.Unlock()
		if injected != nil {
			return injected
		}
		return actual
	}
	t.Cleanup(func() {
		operations.mu.Lock()
		mappings := make([][]byte, 0, len(operations.mappings))
		for _, mapping := range operations.mappings {
			mappings = append(mappings, mapping.mapped)
		}
		files := make([]*os.File, 0, len(operations.files))
		for file := range operations.files {
			files = append(files, file)
		}
		operations.mappings = make(
			map[uintptr]trcxl007OwnerSealDevDAXTestMapping)
		operations.files = make(map[*os.File]string)
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

func (operations *trcxl007OwnerSealDevDAXTestOperations) snapshot() (
	[]int,
	[]int,
	[]int,
	[]string,
	int,
	int,
) {
	operations.mu.Lock()
	defer operations.mu.Unlock()
	return append([]int(nil), operations.openFlags...),
		append([]int(nil), operations.mmapProt...),
		append([]int(nil), operations.mmapFlags...),
		append([]string(nil), operations.cleanup...),
		len(operations.mappings),
		len(operations.files)
}

type trcxl007OwnerSealDevDAXTestFixture struct {
	geometry   trcxl007.DeviceGeometry
	bindings   []trcxl007OwnerSealDevDAXBinding
	operations *trcxl007OwnerSealDevDAXTestOperations
	visibility *trcxl007OwnerSealDevDAXTestVisibility
	deps       trcxl007OwnerSealDevDAXDependencies
}

func newTRCXL007OwnerSealDevDAXTestFixture(
	t *testing.T,
) *trcxl007OwnerSealDevDAXTestFixture {
	t.Helper()
	geometry, err := trcxl007.CalculateDeviceGeometry(
		2<<20,
		trcxl007.MinAllocatorSnapshotSlotBytes,
		trcxl007.MinOwnerStateSnapshotSlotBytes)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	operations := &trcxl007OwnerSealDevDAXTestOperations{
		pathUUID:         make(map[string]string),
		pathRdev:         make(map[string]uint64),
		fdUUID:           make(map[int]string),
		files:            make(map[*os.File]string),
		mappings:         make(map[uintptr]trcxl007OwnerSealDevDAXTestMapping),
		pretendCharacter: true,
		statRdevOverride: make(map[string]uint64),
		geometryOverride: make(
			map[string]trcxl007OwnerSealDevDAXKernelGeometry),
		munmapFailures: make(map[string]int),
		munmapErrors:   make(map[string]error),
		closeErrors:    make(map[string]error),
	}
	canonical := make([]trcxl007OwnerSealDevDAXBinding, 0, 2)
	for index, uuid := range []string{"seal-device-a", "seal-device-b"} {
		path := fmt.Sprintf("%s/%s.dax", directory, uuid)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(int64(geometry.DeviceBytes)); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		pattern := make([]byte, 4*trcxl007.ContentPageBytes)
		for byteIndex := range pattern {
			pattern[byteIndex] = byte(0x20 + index + byteIndex%31)
		}
		if _, err := file.WriteAt(
			pattern,
			int64(geometry.ContentRegionBase+3*uint64(trcxl007.ContentPageBytes))); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		rdev := uint64(101 + index)
		operations.pathUUID[path] = uuid
		operations.pathRdev[path] = rdev
		canonical = append(canonical, trcxl007OwnerSealDevDAXBinding{
			Binding: trcxl007.ProducerScatterDeviceBinding{
				DeviceUUID:          uuid,
				DeviceOwnerEpoch:    11,
				DataPageCount:       geometry.DataPageCount,
				DeviceBindingSHA256: sha256.Sum256([]byte("binding-" + uuid)),
			},
			Geometry:     geometry,
			DevicePath:   path,
			ExpectedRdev: rdev,
		})
	}
	// Constructor input is deliberately non-canonical. The source must retain
	// its own canonical, immutable table.
	bindings := []trcxl007OwnerSealDevDAXBinding{canonical[1], canonical[0]}
	fixture := &trcxl007OwnerSealDevDAXTestFixture{
		geometry:   geometry,
		bindings:   bindings,
		operations: operations,
		visibility: &trcxl007OwnerSealDevDAXTestVisibility{},
	}
	fixture.deps = operations.dependencies(t)
	return fixture
}

func (fixture *trcxl007OwnerSealDevDAXTestFixture) open(
	t *testing.T,
) *trcxl007OwnerSealDevDAXSource {
	t.Helper()
	source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
		fixture.bindings, fixture.visibility, fixture.deps)
	if err != nil {
		t.Fatalf("open test-only regular-file mapping through dependencies: %v", err)
	}
	t.Cleanup(func() { _ = source.Close() })
	return source
}

func TestTRCXL007OwnerSealDevDAXFailsClosedWithoutVisibilityProtocol(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
		fixture.bindings, nil, fixture.deps)
	if source != nil || !errors.Is(
		err, errTRCXL007OwnerSealVisibilityProtocolUnavailable) {
		t.Fatalf("nil visibility protocol returned source=%#v err=%v", source, err)
	}
	openFlags, mmapProt, _, _, _, files := fixture.operations.snapshot()
	if len(openFlags) != 0 || len(mmapProt) != 0 || files != 0 {
		t.Fatalf("fail-closed constructor opened/mapped files: %d/%d/%d",
			len(openFlags), len(mmapProt), files)
	}
}

func TestTRCXL007OwnerSealDevDAXProductionRejectsRegularFiles(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	fixture.operations.pretendCharacter = false
	source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
		fixture.bindings, fixture.visibility, fixture.deps)
	if source != nil || err == nil || !strings.Contains(err.Error(), "character devdax") {
		t.Fatalf("production regular-file open returned source=%#v err=%v", source, err)
	}
	_, mmapProt, _, _, mappings, files := fixture.operations.snapshot()
	if len(mmapProt) != 0 || mappings != 0 || files != 0 {
		t.Fatalf("regular-file rejection mapped/leaked=%d/%d/%d",
			len(mmapProt), mappings, files)
	}
}

func TestTRCXL007OwnerSealDevDAXResolvesSysfsSizeAndAlignment(t *testing.T) {
	root := t.TempDir()
	deviceName := "dax-test.0"
	directory := root + "/" + deviceName
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory+"/size", []byte("0x200000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory+"/align", []byte("4096\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory+"/dev", []byte("1:5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	geometry, err := resolveTRCXL007OwnerSealDevDAXKernelGeometry(
		"/dev/"+deviceName, []string{root + "/missing", root})
	if err != nil {
		t.Fatal(err)
	}
	if geometry.sizeBytes != 2<<20 || geometry.alignBytes != 4096 ||
		geometry.rdev != unix.Mkdev(1, 5) {
		t.Fatalf("sysfs geometry=%#v", geometry)
	}
	if err := os.WriteFile(directory+"/align", []byte("6144\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveTRCXL007OwnerSealDevDAXKernelGeometry(
		"/dev/"+deviceName, []string{root}); err == nil {
		t.Fatal("invalid sysfs alignment was accepted")
	}
}

func TestTRCXL007OwnerSealDevDAXReturnsCanonicalDirectReadOnlyViews(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	fixture.visibility.mutateInput = true
	source := fixture.open(t)
	if got, want := source.orderedUUIDs,
		[]string{"seal-device-a", "seal-device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("source UUID order=%v want=%v", got, want)
	}
	openFlags, mmapProt, mmapFlags, _, _, _ := fixture.operations.snapshot()
	if len(openFlags) != 2 || len(mmapProt) != 2 || len(mmapFlags) != 2 {
		t.Fatalf("open/map calls=%d/%d/%d",
			len(openFlags), len(mmapProt), len(mmapFlags))
	}
	for index := range openFlags {
		if openFlags[index] != trcxl007OwnerSealDevDAXOpenFlags ||
			openFlags[index]&unix.O_ACCMODE != unix.O_RDONLY ||
			openFlags[index]&unix.O_NOFOLLOW == 0 ||
			mmapProt[index] != unix.PROT_READ ||
			mmapProt[index]&unix.PROT_WRITE != 0 ||
			mmapFlags[index] != unix.MAP_SHARED {
			t.Fatalf("mapping %d flags/prot/map=%#x/%#x/%#x",
				index, openFlags[index], mmapProt[index], mmapFlags[index])
		}
	}
	pass, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if err != nil {
		t.Fatal(err)
	}
	binding := source.bindingTable[1]
	view, err := pass.ReadableExtent(binding, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	offset := fixture.geometry.ContentRegionBase +
		3*uint64(trcxl007.ContentPageBytes)
	length := 2 * trcxl007.ContentPageBytes
	device := source.devices[binding.DeviceUUID]
	wantAddress := uintptr(unsafe.Pointer(&device.mapped[int(offset)]))
	gotAddress := uintptr(unsafe.Pointer(&view.Bytes[0]))
	if gotAddress != wantAddress || len(view.Bytes) != length || cap(view.Bytes) != length {
		t.Fatalf("view address/len/cap=%#x/%d/%d want=%#x/%d/%d",
			gotAddress, len(view.Bytes), cap(view.Bytes), wantAddress, length, length)
	}
	if view.Binding != binding || view.StartDataPageIndex != 3 || view.PageCount != 2 ||
		view.Backing.BackingID != binding.DeviceBindingSHA256 ||
		view.Backing.ByteOffset != offset ||
		view.Backing.ByteLength != uint64(length) {
		t.Fatalf("direct view identity/backing=%#v", view)
	}
	acquisitions, leases := fixture.visibility.snapshot()
	if len(acquisitions) != 1 || !reflect.DeepEqual(acquisitions[0], source.bindingTable) ||
		len(leases) != 1 {
		t.Fatalf("group-wide acquisition=%#v leases=%d", acquisitions, len(leases))
	}
	invalidations, closeCalls := leases[0].snapshot()
	if len(invalidations) != 1 || invalidations[0].binding != binding ||
		invalidations[0].offset != offset || invalidations[0].length != length ||
		invalidations[0].address != wantAddress || closeCalls != 0 {
		t.Fatalf("exact invalidation=%#v closeCalls=%d", invalidations, closeCalls)
	}
	if err := pass.Close(); err != nil {
		t.Fatal(err)
	}
	_, closeCalls = leases[0].snapshot()
	if closeCalls != 1 {
		t.Fatalf("group-wide lease close calls=%d want=1", closeCalls)
	}
}

func TestTRCXL007OwnerSealDevDAXRequiresExactBindingTableAndOneActivePass(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	source := fixture.open(t)
	reversed := append([]trcxl007.ProducerScatterDeviceBinding(nil), source.bindingTable...)
	reversed[0], reversed[1] = reversed[1], reversed[0]
	if pass, err := source.OpenReadPass(context.Background(), reversed); pass != nil || err == nil {
		t.Fatalf("non-canonical binding table returned pass=%#v err=%v", pass, err)
	}
	mutated := append([]trcxl007.ProducerScatterDeviceBinding(nil), source.bindingTable...)
	mutated[0].DeviceOwnerEpoch++
	if pass, err := source.OpenReadPass(context.Background(), mutated); pass != nil || err == nil {
		t.Fatalf("mutated binding table returned pass=%#v err=%v", pass, err)
	}
	first, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := source.OpenReadPass(
		context.Background(), source.bindingTable); second != nil ||
		!errors.Is(err, errTRCXL007OwnerSealDevDAXActivePass) {
		t.Fatalf("second active pass=%#v err=%v", second, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	acquisitions, _ := fixture.visibility.snapshot()
	if len(acquisitions) != 2 {
		t.Fatalf("visibility acquisition count=%d want=2", len(acquisitions))
	}
}

func TestTRCXL007OwnerSealDevDAXRejectsInvalidExtentsBeforeInvalidation(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	source := fixture.open(t)
	pass, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if err != nil {
		t.Fatal(err)
	}
	binding := source.bindingTable[0]
	tests := []struct {
		name    string
		binding trcxl007.ProducerScatterDeviceBinding
		start   uint64
		pages   uint64
	}{
		{name: "zero-pages", binding: binding, start: 0, pages: 0},
		{name: "start-at-end", binding: binding,
			start: binding.DataPageCount, pages: 1},
		{name: "range-past-end", binding: binding,
			start: binding.DataPageCount - 1, pages: 2},
		{name: "overflow", binding: binding, start: ^uint64(0), pages: 2},
		{name: "stale-binding", binding: func() trcxl007.ProducerScatterDeviceBinding {
			stale := binding
			stale.DeviceBindingSHA256[0] ^= 0xff
			return stale
		}(), start: 0, pages: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			view, err := pass.ReadableExtent(test.binding, test.start, test.pages)
			if err == nil || view.Bytes != nil {
				t.Fatalf("invalid extent returned view=%#v err=%v", view, err)
			}
		})
	}
	_, leases := fixture.visibility.snapshot()
	invalidations, _ := leases[0].snapshot()
	if len(invalidations) != 0 {
		t.Fatalf("invalid extents reached visibility invalidation: %#v", invalidations)
	}
	if err := pass.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestTRCXL007OwnerSealDevDAXRejectsDuplicateAndMismatchedBindingsBeforeOpen(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	canonical, err := cloneTRCXL007OwnerSealDevDAXBindings(fixture.bindings)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]trcxl007OwnerSealDevDAXBinding)
	}{
		{name: "duplicate-uuid", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[1].Binding.DeviceUUID = values[0].Binding.DeviceUUID
		}},
		{name: "duplicate-path", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[1].DevicePath = values[0].DevicePath
		}},
		{name: "duplicate-rdev", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[1].ExpectedRdev = values[0].ExpectedRdev
		}},
		{name: "duplicate-backing", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[1].Binding.DeviceBindingSHA256 = values[0].Binding.DeviceBindingSHA256
		}},
		{name: "page-count-mismatch", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[0].Binding.DataPageCount--
		}},
		{name: "zero-epoch", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[0].Binding.DeviceOwnerEpoch = 0
		}},
		{name: "unclean-path", mutate: func(values []trcxl007OwnerSealDevDAXBinding) {
			values[0].DevicePath += "/../alias"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			values := append([]trcxl007OwnerSealDevDAXBinding(nil), canonical...)
			test.mutate(values)
			source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
				values, fixture.visibility, fixture.deps)
			if source != nil || err == nil {
				t.Fatalf("invalid binding returned source=%#v err=%v", source, err)
			}
		})
	}
	oversized := make(
		[]trcxl007OwnerSealDevDAXBinding, trcxl007.MaxOwnerStateDevices+1)
	if source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
		oversized, fixture.visibility, fixture.deps); source != nil || err == nil {
		t.Fatalf("oversized binding table returned source=%#v err=%v", source, err)
	}
	openFlags, _, _, _, _, _ := fixture.operations.snapshot()
	if len(openFlags) != 0 {
		t.Fatalf("invalid binding preflight opened %d devices", len(openFlags))
	}
}

func TestTRCXL007OwnerSealDevDAXChecksRdevAndSysfsGeometry(
	t *testing.T,
) {
	t.Run("rdev", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		fixture.operations.statRdevOverride["seal-device-a"] = 999
		source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
			fixture.bindings, fixture.visibility, fixture.deps)
		if source != nil || err == nil || !strings.Contains(err.Error(), "rdev") {
			t.Fatalf("rdev mismatch returned source=%#v err=%v", source, err)
		}
		_, mmapProt, _, _, _, files := fixture.operations.snapshot()
		if len(mmapProt) != 0 || files != 0 {
			t.Fatalf("rdev mismatch mapped/leaked=%d/%d", len(mmapProt), files)
		}
	})
	t.Run("geometry", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		fixture.operations.geometryOverride["seal-device-a"] =
			trcxl007OwnerSealDevDAXKernelGeometry{
				sizeBytes:  fixture.geometry.DeviceBytes + uint64(os.Getpagesize()),
				alignBytes: uint64(os.Getpagesize()),
				rdev:       101,
			}
		source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
			fixture.bindings, fixture.visibility, fixture.deps)
		if source != nil || err == nil || !strings.Contains(err.Error(), "sysfs size") {
			t.Fatalf("geometry mismatch returned source=%#v err=%v", source, err)
		}
		_, mmapProt, _, _, _, files := fixture.operations.snapshot()
		if len(mmapProt) != 0 || files != 0 {
			t.Fatalf("geometry mismatch mapped/leaked=%d/%d", len(mmapProt), files)
		}
	})
	t.Run("sysfs-dev", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		fixture.operations.geometryOverride["seal-device-a"] =
			trcxl007OwnerSealDevDAXKernelGeometry{
				sizeBytes:  fixture.geometry.DeviceBytes,
				alignBytes: uint64(os.Getpagesize()),
				rdev:       999,
			}
		source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
			fixture.bindings, fixture.visibility, fixture.deps)
		if source != nil || err == nil || !strings.Contains(err.Error(), "sysfs dev rdev") {
			t.Fatalf("sysfs dev mismatch returned source=%#v err=%v", source, err)
		}
		_, mmapProt, _, _, _, files := fixture.operations.snapshot()
		if len(mmapProt) != 0 || files != 0 {
			t.Fatalf("sysfs dev mismatch mapped/leaked=%d/%d", len(mmapProt), files)
		}
	})
	t.Run("nil-file", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		dependencies := fixture.deps
		dependencies.openFile = func(string, int, os.FileMode) (*os.File, error) {
			return nil, nil
		}
		source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
			fixture.bindings, fixture.visibility, dependencies)
		if source != nil || err == nil || !strings.Contains(err.Error(), "nil devdax file") {
			t.Fatalf("nil open result returned source=%#v err=%v", source, err)
		}
	})
	t.Run("file-with-open-error", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		dependencies := fixture.deps
		openFailure := errors.New("injected open error with file")
		var returnedFile *os.File
		dependencies.openFile = func(
			path string,
			flags int,
			mode os.FileMode,
		) (*os.File, error) {
			file, err := os.OpenFile(path, flags, mode)
			if err != nil {
				return nil, err
			}
			returnedFile = file
			return file, openFailure
		}
		dependencies.close = func(file *os.File) error { return file.Close() }
		source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
			fixture.bindings, fixture.visibility, dependencies)
		if source != nil || !errors.Is(err, openFailure) || returnedFile == nil {
			t.Fatalf("file+open-error returned source=%#v file=%#v err=%v",
				source, returnedFile, err)
		}
		if _, statErr := returnedFile.Stat(); statErr == nil {
			t.Fatal("file returned alongside open error was not closed")
		}
	})
	t.Run("mapping-with-error", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		dependencies := fixture.deps
		mmapFailure := errors.New("injected mmap error with view")
		baseMmap := dependencies.mmap
		dependencies.mmap = func(
			fd int,
			offset int64,
			length int,
			prot int,
			flags int,
		) ([]byte, error) {
			mapped, err := baseMmap(fd, offset, length, prot, flags)
			if err != nil {
				return nil, err
			}
			return mapped, mmapFailure
		}
		source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
			fixture.bindings, fixture.visibility, dependencies)
		if source != nil || !errors.Is(err, mmapFailure) {
			t.Fatalf("view+mmap-error returned source=%#v err=%v", source, err)
		}
		_, _, _, cleanup, mappings, files := fixture.operations.snapshot()
		want := []string{"unmap:seal-device-a", "close:seal-device-a"}
		if !reflect.DeepEqual(cleanup, want) || mappings != 0 || files != 0 {
			t.Fatalf("failed mmap cleanup=%v mappings/files=%d/%d",
				cleanup, mappings, files)
		}
	})
}

func TestTRCXL007OwnerSealDevDAXCloseRejectsActivePassAndUsesReverseTwoPhaseCleanup(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	source := fixture.open(t)
	pass, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); !errors.Is(err, errTRCXL007OwnerSealDevDAXActivePass) {
		t.Fatalf("close with active pass err=%v", err)
	}
	_, _, _, cleanup, mappings, files := fixture.operations.snapshot()
	if len(cleanup) != 0 || mappings != 2 || files != 2 {
		t.Fatalf("active close cleaned resources=%v mappings/files=%d/%d",
			cleanup, mappings, files)
	}
	if err := pass.Close(); err != nil {
		t.Fatal(err)
	}
	if next, err := source.OpenReadPass(
		context.Background(), source.bindingTable); next != nil ||
		!errors.Is(err, errTRCXL007OwnerSealDevDAXClosed) {
		t.Fatalf("closed admission returned pass=%#v err=%v", next, err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _, cleanup, mappings, files = fixture.operations.snapshot()
	want := []string{
		"unmap:seal-device-b", "unmap:seal-device-a",
		"close:seal-device-b", "close:seal-device-a",
	}
	if !reflect.DeepEqual(cleanup, want) || mappings != 0 || files != 0 {
		t.Fatalf("cleanup=%v mappings/files=%d/%d want=%v/0/0",
			cleanup, mappings, files, want)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _, cleanupAgain, _, _ := fixture.operations.snapshot()
	if !reflect.DeepEqual(cleanupAgain, want) {
		t.Fatalf("idempotent close repeated cleanup: %v", cleanupAgain)
	}
}

func TestTRCXL007OwnerSealDevDAXCloseCombinesAllFailuresAndRetriesMunmap(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	unmapFailure := errors.New("injected device-b munmap failure")
	closeFailureA := errors.New("injected device-a close failure")
	closeFailureB := errors.New("injected device-b close failure")
	fixture.operations.munmapFailures["seal-device-b"] = 1
	fixture.operations.munmapErrors["seal-device-b"] = unmapFailure
	fixture.operations.closeErrors["seal-device-a"] = closeFailureA
	fixture.operations.closeErrors["seal-device-b"] = closeFailureB
	source := fixture.open(t)
	first := source.Close()
	if !errors.Is(first, unmapFailure) || !errors.Is(first, closeFailureA) ||
		!errors.Is(first, closeFailureB) {
		t.Fatalf("first combined close error=%v", first)
	}
	_, _, _, cleanup, mappings, files := fixture.operations.snapshot()
	wantFirst := []string{
		"unmap:seal-device-b", "unmap:seal-device-a",
		"close:seal-device-b", "close:seal-device-a",
	}
	if !reflect.DeepEqual(cleanup, wantFirst) || mappings != 1 || files != 0 {
		t.Fatalf("first cleanup=%v mappings/files=%d/%d", cleanup, mappings, files)
	}
	second := source.Close()
	if errors.Is(second, unmapFailure) || !errors.Is(second, closeFailureA) ||
		!errors.Is(second, closeFailureB) {
		t.Fatalf("retry close error=%v", second)
	}
	_, _, _, cleanup, mappings, files = fixture.operations.snapshot()
	wantSecond := append(append([]string(nil), wantFirst...), "unmap:seal-device-b")
	if !reflect.DeepEqual(cleanup, wantSecond) || mappings != 0 || files != 0 {
		t.Fatalf("retry cleanup=%v mappings/files=%d/%d", cleanup, mappings, files)
	}
	third := source.Close()
	if !errors.Is(third, closeFailureA) || !errors.Is(third, closeFailureB) {
		t.Fatalf("stable terminal close error=%v", third)
	}
	_, _, _, cleanup, _, _ = fixture.operations.snapshot()
	if !reflect.DeepEqual(cleanup, wantSecond) {
		t.Fatalf("terminal close repeated cleanup=%v", cleanup)
	}
}

func TestTRCXL007OwnerSealDevDAXVisibilityFailuresDoNotExposeViews(
	t *testing.T,
) {
	t.Run("acquire", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		acquireFailure := errors.New("injected group acquire failure")
		fixture.visibility.acquireErr = acquireFailure
		source := fixture.open(t)
		pass, err := source.OpenReadPass(context.Background(), source.bindingTable)
		if pass != nil || !errors.Is(err, acquireFailure) {
			t.Fatalf("acquire failure returned pass=%#v err=%v", pass, err)
		}
		acquisitions, leases := fixture.visibility.snapshot()
		if len(acquisitions) != 1 || len(leases) != 0 {
			t.Fatalf("failed acquisition calls/leases=%d/%d",
				len(acquisitions), len(leases))
		}
	})
	t.Run("acquire-error-with-lease", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		acquireFailure := errors.New("injected acquisition with lease failure")
		closeFailure := errors.New("injected failed-acquisition lease close failure")
		fixture.visibility.acquireErr = acquireFailure
		fixture.visibility.leaseOnError = true
		fixture.visibility.newLease = func(int) *trcxl007OwnerSealDevDAXTestLease {
			return &trcxl007OwnerSealDevDAXTestLease{closeErr: closeFailure}
		}
		source := fixture.open(t)
		pass, err := source.OpenReadPass(context.Background(), source.bindingTable)
		if pass != nil || !errors.Is(err, acquireFailure) ||
			!errors.Is(err, closeFailure) {
			t.Fatalf("acquire error with lease returned pass=%#v err=%v", pass, err)
		}
		_, leases := fixture.visibility.snapshot()
		if len(leases) != 1 {
			t.Fatalf("failed acquisition leases=%d", len(leases))
		}
		_, closeCalls := leases[0].snapshot()
		if closeCalls != 1 {
			t.Fatalf("failed acquisition lease close calls=%d", closeCalls)
		}
		if next, nextErr := source.OpenReadPass(
			context.Background(), source.bindingTable); next != nil ||
			!errors.Is(nextErr, errTRCXL007OwnerSealDevDAXClosed) {
			t.Fatalf("failed lease cleanup left admission open: pass=%#v err=%v",
				next, nextErr)
		}
	})
	t.Run("invalidate", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		invalidateFailure := errors.New("injected exact invalidation failure")
		fixture.visibility.newLease = func(int) *trcxl007OwnerSealDevDAXTestLease {
			return &trcxl007OwnerSealDevDAXTestLease{
				invalidateErr: invalidateFailure,
			}
		}
		source := fixture.open(t)
		pass, err := source.OpenReadPass(context.Background(), source.bindingTable)
		if err != nil {
			t.Fatal(err)
		}
		view, err := pass.ReadableExtent(source.bindingTable[0], 0, 1)
		if view.Bytes != nil || !errors.Is(err, invalidateFailure) {
			t.Fatalf("invalidation failure returned view=%#v err=%v", view, err)
		}
		if err := pass.Close(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("context-after-acquire", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.visibility.onAcquire = cancel
		source := fixture.open(t)
		pass, err := source.OpenReadPass(ctx, source.bindingTable)
		if pass != nil || !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled acquisition returned pass=%#v err=%v", pass, err)
		}
		_, leases := fixture.visibility.snapshot()
		if len(leases) != 1 {
			t.Fatalf("canceled acquisition leases=%d", len(leases))
		}
		_, closeCalls := leases[0].snapshot()
		if closeCalls != 1 {
			t.Fatalf("canceled acquisition lease close calls=%d", closeCalls)
		}
	})
	t.Run("context-after-acquire-close-failure", func(t *testing.T) {
		fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
		closeFailure := errors.New("injected canceled-acquisition close failure")
		ctx, cancel := context.WithCancel(context.Background())
		fixture.visibility.onAcquire = cancel
		fixture.visibility.newLease = func(int) *trcxl007OwnerSealDevDAXTestLease {
			return &trcxl007OwnerSealDevDAXTestLease{closeErr: closeFailure}
		}
		source := fixture.open(t)
		pass, err := source.OpenReadPass(ctx, source.bindingTable)
		if pass != nil || !errors.Is(err, context.Canceled) ||
			!errors.Is(err, closeFailure) {
			t.Fatalf("canceled close failure returned pass=%#v err=%v", pass, err)
		}
		if next, nextErr := source.OpenReadPass(
			context.Background(), source.bindingTable); next != nil ||
			!errors.Is(nextErr, errTRCXL007OwnerSealDevDAXClosed) {
			t.Fatalf("canceled close failure left admission open: pass=%#v err=%v",
				next, nextErr)
		}
	})
}

func TestTRCXL007OwnerSealDevDAXPassCloseErrorClosesAdmission(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	leaseCloseFailure := errors.New("injected group lease close failure")
	fixture.visibility.newLease = func(call int) *trcxl007OwnerSealDevDAXTestLease {
		lease := &trcxl007OwnerSealDevDAXTestLease{}
		if call == 0 {
			lease.closeErr = leaseCloseFailure
		}
		return lease
	}
	source := fixture.open(t)
	first, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); !errors.Is(err, leaseCloseFailure) {
		t.Fatalf("first lease close err=%v", err)
	}
	if err := first.Close(); !errors.Is(err, leaseCloseFailure) {
		t.Fatalf("idempotent first lease close err=%v", err)
	}
	second, err := source.OpenReadPass(context.Background(), source.bindingTable)
	if second != nil || !errors.Is(err, errTRCXL007OwnerSealDevDAXClosed) {
		t.Fatalf("lease close failure left admission open: pass=%#v err=%v",
			second, err)
	}
}

func TestTRCXL007OwnerSealDevDAXTypedNilVisibilityValuesFailClosed(
	t *testing.T,
) {
	fixture := newTRCXL007OwnerSealDevDAXTestFixture(t)
	var typedNilProtocol *trcxl007OwnerSealDevDAXTestVisibility
	source, err := openTRCXL007OwnerSealDevDAXSourceWithDependencies(
		fixture.bindings, typedNilProtocol, fixture.deps)
	if source != nil || !errors.Is(
		err, errTRCXL007OwnerSealVisibilityProtocolUnavailable) {
		t.Fatalf("typed nil protocol returned source=%#v err=%v", source, err)
	}
	var typedNilContext *trcxl007OwnerSealDevDAXTestNilContext
	validSource := fixture.open(t)
	pass, err := validSource.OpenReadPass(typedNilContext, validSource.bindingTable)
	if pass != nil || err == nil || !strings.Contains(err.Error(), "context is nil") {
		t.Fatalf("typed nil context returned pass=%#v err=%v", pass, err)
	}
	fixture.visibility.returnNil = true
	source = fixture.open(t)
	pass, err = source.OpenReadPass(context.Background(), source.bindingTable)
	if pass != nil || err == nil || !strings.Contains(err.Error(), "nil lease") {
		t.Fatalf("nil group lease returned pass=%#v err=%v", pass, err)
	}
	if next, nextErr := source.OpenReadPass(
		context.Background(), source.bindingTable); next != nil ||
		!errors.Is(nextErr, errTRCXL007OwnerSealDevDAXClosed) {
		t.Fatalf("nil group lease left admission open: pass=%#v err=%v",
			next, nextErr)
	}
}
