package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

const (
	testVNextOwnerDeviceSlotBytes  = uint64(16 << 10)
	testVNextOwnerControlSlotBytes = uint64(128 << 10)
)

type vnextOwnerTestDeviceSpec struct {
	UUID string
	Size int64
}

type vnextOwnerTestFixture struct {
	deviceFiles []*os.File
	devices     []*vnextPersistentDevice
	controlFile *os.File
	group       *vnextOwnerGroup
}

func newVNextOwnerTestFixture(
	t *testing.T,
	specs []vnextOwnerTestDeviceSpec,
) *vnextOwnerTestFixture {
	t.Helper()
	fixture := &vnextOwnerTestFixture{}
	for index, spec := range specs {
		path := fmt.Sprintf("%s/device-%d.img", t.TempDir(), index)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("create device %q: %v", spec.UUID, err)
		}
		t.Cleanup(func() { _ = file.Close() })
		if err := file.Truncate(spec.Size); err != nil {
			t.Fatalf("truncate device %q: %v", spec.UUID, err)
		}
		device, err := formatVNextFileDevice(
			file, spec.UUID, "owner-0", 7, testVNextOwnerDeviceSlotBytes)
		if err != nil {
			t.Fatalf("format device %q: %v", spec.UUID, err)
		}
		fixture.deviceFiles = append(fixture.deviceFiles, file)
		fixture.devices = append(fixture.devices, device)
	}
	controlPath := t.TempDir() + "/owner-control.img"
	controlFile, err := os.OpenFile(controlPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("create Owner control file: %v", err)
	}
	t.Cleanup(func() { _ = controlFile.Close() })
	if err := controlFile.Truncate(int64(testVNextOwnerControlSlotBytes * 2)); err != nil {
		t.Fatalf("truncate Owner control file: %v", err)
	}
	group, err := formatVNextOwnerGroup(
		controlFile, testVNextOwnerControlSlotBytes, fixture.devices)
	if err != nil {
		t.Fatalf("format Owner group: %v", err)
	}
	fixture.controlFile = controlFile
	fixture.group = group
	return fixture
}

func (fixture *vnextOwnerTestFixture) reopen(t *testing.T) *vnextOwnerGroup {
	t.Helper()
	devices := make([]*vnextPersistentDevice, 0, len(fixture.deviceFiles))
	for _, file := range fixture.deviceFiles {
		device, err := openVNextFileDevice(file)
		if err != nil {
			t.Fatalf("reopen Owner device: %v", err)
		}
		devices = append(devices, device)
	}
	group, err := openVNextOwnerGroup(
		fixture.controlFile, testVNextOwnerControlSlotBytes, devices)
	if err != nil {
		t.Fatalf("reopen Owner group: %v", err)
	}
	fixture.devices = devices
	fixture.group = group
	return group
}

func vnextOwnerMemoryRequest(id string, pages uint64, maxExtents uint32) vnextCheckpointAllocationRequest {
	return vnextCheckpointAllocationRequest{
		RequestID:    "owner-request-" + id,
		CheckpointID: "owner-checkpoint-" + id,
		ProducerID:   "owner-producer-" + id,
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextContentRequest{{
			Kind:       vnextContentMemory,
			ObjectID:   uint64(id[0]) + uint64(len(id))*1000,
			ByteLength: pages * vnextContentPageSize,
			PageCount:  pages,
		}},
		MaxExtents: maxExtents,
	}
}

func writeAllVNextOwnerPages(
	t *testing.T,
	group *vnextOwnerGroup,
	grant vnextOwnerWriteGrant,
	totalPages uint64,
) {
	t.Helper()
	for logicalPage := uint64(0); logicalPage < totalPages; logicalPage++ {
		content := bytes.Repeat([]byte{byte(logicalPage%251 + 1)}, int(vnextContentPageSize))
		if err := group.writePage(grant, logicalPage, content); err != nil {
			t.Fatalf("write Owner logical page %d: %v", logicalPage, err)
		}
	}
}

func vnextOwnerInventoryFreePages(snapshot vnextOwnerInventorySnapshot) uint64 {
	var pages uint64
	for _, device := range snapshot.Devices {
		pages += device.FreeDataPages
	}
	return pages
}

func TestVNextOwnerInventoryIsStableAndTracksReserveAbort(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "inventory-device-b", Size: 256 << 10},
		{UUID: "inventory-device-a", Size: 384 << 10},
	})
	initial, err := fixture.group.inventory("owner-0", 7)
	if err != nil {
		t.Fatalf("read initial Owner inventory: %v", err)
	}
	if initial.OwnerID != "owner-0" || initial.OwnerEpoch != 7 ||
		initial.SnapshotSequence == 0 || len(initial.Devices) != 2 ||
		initial.Devices[0].DeviceUUID != "inventory-device-a" ||
		initial.Devices[1].DeviceUUID != "inventory-device-b" {
		t.Fatalf("initial inventory is not complete and UUID-stable: %#v", initial)
	}
	for _, device := range initial.Devices {
		if device.TotalDataPages == 0 || device.FreeDataPages != device.TotalDataPages {
			t.Fatalf("fresh inventory has unexpected capacity: %#v", device)
		}
	}
	initialRetry, err := fixture.group.inventory("owner-0", 7)
	if err != nil {
		t.Fatalf("retry initial Owner inventory: %v", err)
	}
	if !reflect.DeepEqual(initialRetry, initial) {
		t.Fatalf("read-only inventory changed the journal or counts: %#v != %#v",
			initialRetry, initial)
	}

	request := vnextOwnerMemoryRequest("inventory-capacity", 3, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve inventory capacity: %v", err)
	}
	reserved, err := fixture.group.inventory("owner-0", 7)
	if err != nil {
		t.Fatalf("read reserved Owner inventory: %v", err)
	}
	if reserved.SnapshotSequence <= initial.SnapshotSequence ||
		vnextOwnerInventoryFreePages(initial)-vnextOwnerInventoryFreePages(reserved) != 3 {
		t.Fatalf("reserve was not reflected atomically in inventory: before=%#v after=%#v",
			initial, reserved)
	}
	reservedRetry, err := fixture.group.inventory("owner-0", 7)
	if err != nil || !reflect.DeepEqual(reservedRetry, reserved) {
		t.Fatalf("reserved inventory read was not idempotent: %v / %#v", err, reservedRetry)
	}

	if err := fixture.group.abort(grant); err != nil {
		t.Fatalf("abort inventory allocation: %v", err)
	}
	aborted, err := fixture.group.inventory("owner-0", 7)
	if err != nil {
		t.Fatalf("read aborted Owner inventory: %v", err)
	}
	if aborted.SnapshotSequence <= reserved.SnapshotSequence ||
		vnextOwnerInventoryFreePages(aborted) != vnextOwnerInventoryFreePages(initial) {
		t.Fatalf("abort did not restore inventory capacity: reserved=%#v aborted=%#v",
			reserved, aborted)
	}
}

func TestVNextOwnerInventoryCannotObservePartialMultiDeviceReserve(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "inventory-atomic-a", Size: 256 << 10},
		{UUID: "inventory-atomic-b", Size: 256 << 10},
	})
	initial, err := fixture.group.inventory("owner-0", 7)
	if err != nil {
		t.Fatal(err)
	}
	pages := fixture.devices[0].superblock.Geometry.DataPageCount + 1
	request := vnextOwnerMemoryRequest("inventory-atomic", pages, 2)
	firstFragmentPrepared := make(chan struct{})
	releaseReserve := make(chan struct{})
	blocked := false
	fixture.group.faultHook = func(stage, _ string) error {
		if stage == vnextOwnerFailAfterPrepare && !blocked {
			blocked = true
			close(firstFragmentPrepared)
			<-releaseReserve
		}
		return nil
	}
	type reserveResult struct {
		grant vnextOwnerWriteGrant
		err   error
	}
	reserveDone := make(chan reserveResult, 1)
	go func() {
		grant, reserveErr := fixture.group.reserve(request)
		reserveDone <- reserveResult{grant: grant, err: reserveErr}
	}()
	<-firstFragmentPrepared

	inventoryStarted := make(chan struct{})
	inventoryDone := make(chan vnextOwnerInventorySnapshot, 1)
	inventoryErr := make(chan error, 1)
	go func() {
		close(inventoryStarted)
		snapshot, inventoryReadErr := fixture.group.inventory("owner-0", 7)
		if inventoryReadErr != nil {
			inventoryErr <- inventoryReadErr
			return
		}
		inventoryDone <- snapshot
	}()
	<-inventoryStarted
	select {
	case snapshot := <-inventoryDone:
		t.Fatalf("inventory crossed the Owner lock during partial prepare: %#v", snapshot)
	case err := <-inventoryErr:
		t.Fatalf("inventory unexpectedly failed during partial prepare: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseReserve)
	result := <-reserveDone
	if result.err != nil {
		t.Fatalf("complete multi-device reserve: %v", result.err)
	}
	var snapshot vnextOwnerInventorySnapshot
	select {
	case snapshot = <-inventoryDone:
	case err := <-inventoryErr:
		t.Fatalf("inventory after reserve: %v", err)
	case <-time.After(time.Second):
		t.Fatal("inventory remained blocked after reserve completed")
	}
	if consumed := vnextOwnerInventoryFreePages(initial) -
		vnextOwnerInventoryFreePages(snapshot); consumed != pages {
		t.Fatalf("atomic inventory saw %d consumed pages, want %d: %#v",
			consumed, pages, snapshot)
	}
	if err := fixture.group.abort(result.grant); err != nil {
		t.Fatalf("abort atomic inventory allocation: %v", err)
	}
}

func TestVNextOwnerInventoryRejectsUnsignedJournalSequence(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "inventory-sequence", Size: 256 << 10,
	}})
	fixture.group.mu.Lock()
	fixture.group.journal.SnapshotSequence = uint64(math.MaxInt64) + 1
	fixture.group.mu.Unlock()
	if _, err := fixture.group.inventory("owner-0", 7); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("unsigned journal sequence returned %v, want corruption", err)
	}
}

func TestVNextOwnerGroupSupportsOneDeviceWithoutCompatibilityPath(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{UUID: "device-only", Size: 256 << 10}})
	request := vnextOwnerMemoryRequest("one-device", 3, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve one-device Owner group: %v", err)
	}
	if len(grant.Extents) != 1 || grant.Extents[0].DeviceUUID != "device-only" {
		t.Fatalf("unexpected one-device grant: %#v", grant.Extents)
	}
	writeAllVNextOwnerPages(t, fixture.group, grant, 3)
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("commit one-device Owner group: %v", err)
	}
	fixture.reopen(t)
	record := fixture.group.journal.Transactions[grant.AllocationRecordID]
	if record == nil || record.State != vnextOwnerCommitted {
		t.Fatalf("one-device commit did not survive restart: %#v", record)
	}
}

func TestVNextOwnerFragmentRetryRejectsDifferentIdentityOrPlan(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{UUID: "device-retry", Size: 256 << 10}})
	request := vnextOwnerMemoryRequest("fragment-retry", 1, 1)
	plan := []vnextPageExtent{{StartDataPageIndex: 0, PageCount: 1, LogicalPageStart: 0}}
	if _, err := fixture.devices[0].allocator.reserveAtIDWithExtents(request, 9, plan); err != nil {
		t.Fatalf("reserve fixed-ID fragment: %v", err)
	}

	if _, err := fixture.devices[0].allocator.reserveAtIDWithExtents(request, 10, plan); !errors.Is(err, errVNextAlreadyExists) {
		t.Fatalf("retry with a different Owner ID returned %v", err)
	}
	differentPlan := []vnextPageExtent{{StartDataPageIndex: 1, PageCount: 1, LogicalPageStart: 0}}
	if _, err := fixture.devices[0].allocator.reserveAtIDWithExtents(request, 9, differentPlan); !errors.Is(err, errVNextAlreadyExists) {
		t.Fatalf("retry with a different physical plan returned %v", err)
	}
}

func TestVNextOwnerTransactionValidationRejectsRequestDigestMismatch(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{UUID: "device-digest", Size: 256 << 10}})
	request := vnextOwnerMemoryRequest("digest", 1, 1)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve Owner transaction: %v", err)
	}
	transaction := fixture.group.journal.Transactions[grant.AllocationRecordID]
	if transaction == nil {
		t.Fatal("reserved Owner transaction is missing")
	}
	tampered := *transaction
	tampered.RequestDigest[0] ^= 0xff
	if err := vnextValidateOwnerTransaction(
		&tampered, fixture.group.devices, fixture.group.ownerID, fixture.group.ownerEpoch,
	); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("tampered request digest returned %v", err)
	}
}

func TestVNextOwnerPlacementPrefersOneBestFitDeviceDeterministically(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "a-large", Size: 384 << 10},
		{UUID: "z-small", Size: 256 << 10},
	})
	request := vnextOwnerMemoryRequest("single-preferred", 8, 4)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve single-device candidate: %v", err)
	}
	if len(grant.Extents) != 1 || grant.Extents[0].DeviceUUID != "z-small" {
		t.Fatalf("best-fit policy selected %#v, want z-small", grant.Extents)
	}

	equal := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-b", Size: 256 << 10},
		{UUID: "device-a", Size: 256 << 10},
	})
	equalGrant, err := equal.group.reserve(vnextOwnerMemoryRequest("uuid-tie", 8, 4))
	if err != nil {
		t.Fatalf("reserve deterministic tie: %v", err)
	}
	if equalGrant.Extents[0].DeviceUUID != "device-a" {
		t.Fatalf("UUID tie-break selected %q, want device-a", equalGrant.Extents[0].DeviceUUID)
	}
}

func TestVNextOwnerMultiDeviceSpillUsesSameGlobalIDAndRestarts(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	pages := capacity + 3
	request := vnextOwnerMemoryRequest("spill", pages, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve multi-device spill: %v", err)
	}
	if len(grant.Extents) != 2 {
		t.Fatalf("spill returned %d extents: %#v", len(grant.Extents), grant.Extents)
	}
	deviceSet := make(map[string]struct{})
	var logical uint64
	for _, extent := range grant.Extents {
		if extent.GlobalLogicalStart != logical {
			t.Fatalf("grant logical coverage jumps at %#v", extent)
		}
		logical += extent.PageCount
		deviceSet[extent.DeviceUUID] = struct{}{}
		device := fixture.group.devices[extent.DeviceUUID]
		record, ok := device.allocator.lookup(request.CheckpointID)
		if !ok || record.AllocationRecordID != grant.AllocationRecordID {
			t.Fatalf("device %q fragment has record %#v", extent.DeviceUUID, record)
		}
	}
	if len(deviceSet) != 2 || logical != pages {
		t.Fatalf("spill covered %d pages on %d devices", logical, len(deviceSet))
	}
	writeAllVNextOwnerPages(t, fixture.group, grant, pages)
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("commit spill: %v", err)
	}
	tampered := grant
	tampered.ProducerID = "wrong-producer"
	if err := fixture.group.commit(tampered); !errors.Is(err, errVNextAuthority) {
		t.Fatalf("tampered idempotent commit returned %v", err)
	}
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("idempotent committed Owner request: %v", err)
	}
	reopened := fixture.reopen(t)
	transaction := reopened.journal.Transactions[grant.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted || len(transaction.Fragments) != 2 {
		t.Fatalf("spill transaction after restart: %#v", transaction)
	}
	if err := reopened.reclaimCheckpoint(request.CheckpointID, grant.AllocationRecordID); err != nil {
		t.Fatalf("reclaim spill: %v", err)
	}
	for _, device := range reopened.devices {
		record, ok := device.allocator.lookup(request.CheckpointID)
		if ok && record.State != vnextAllocationReclaimed {
			t.Fatalf("fragment reclaim state is %d", record.State)
		}
	}
}

func TestVNextOwnerHoleReuseAndAllocationIDNonReuse(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{UUID: "device-hole", Size: 384 << 10}})
	grants := make([]vnextOwnerWriteGrant, 3)
	for index := range grants {
		request := vnextOwnerMemoryRequest(fmt.Sprintf("hole-%d", index), 4, 2)
		grant, err := fixture.group.reserve(request)
		if err != nil {
			t.Fatalf("reserve hole seed %d: %v", index, err)
		}
		writeAllVNextOwnerPages(t, fixture.group, grant, 4)
		if err := fixture.group.commit(grant); err != nil {
			t.Fatalf("commit hole seed %d: %v", index, err)
		}
		grants[index] = grant
	}
	holeStart := grants[1].Extents[0].StartDataPageIndex
	if err := fixture.group.reclaimCheckpoint(
		grants[1].CheckpointID, grants[1].AllocationRecordID); err != nil {
		t.Fatalf("reclaim middle checkpoint: %v", err)
	}
	reuse, err := fixture.group.reserve(vnextOwnerMemoryRequest("hole-reuse", 3, 2))
	if err != nil {
		t.Fatalf("reserve hole reuse: %v", err)
	}
	if reuse.Extents[0].StartDataPageIndex != holeStart {
		t.Fatalf("best-fit hole reuse starts at %d, want %d", reuse.Extents[0].StartDataPageIndex, holeStart)
	}
	if reuse.AllocationRecordID <= grants[2].AllocationRecordID {
		t.Fatal("Owner allocation ID was reused after reclaim")
	}
	if err := fixture.group.abort(reuse); err != nil {
		t.Fatalf("abort reused-hole checkpoint: %v", err)
	}
	next, err := fixture.group.reserve(vnextOwnerMemoryRequest("after-abort", 1, 1))
	if err != nil {
		t.Fatalf("reserve after abort: %v", err)
	}
	if next.AllocationRecordID <= reuse.AllocationRecordID {
		t.Fatal("Owner allocation ID was reused after abort")
	}
}

func TestVNextOwnerStartsAboveRecoveredDeviceHighWater(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	// Reformat the Owner control record after advancing different device-local
	// high-waters with terminal allocations.
	for index, device := range fixture.devices {
		for allocation := 0; allocation <= index; allocation++ {
			request := vnextOwnerMemoryRequest(fmt.Sprintf("pre-owner-%d-%d", index, allocation), 1, 1)
			grant, err := device.reserve(request)
			if err != nil {
				t.Fatalf("advance device high-water: %v", err)
			}
			if err := device.abort(grant); err != nil {
				t.Fatalf("abort high-water seed: %v", err)
			}
		}
	}
	maxHighWater := uint64(0)
	for _, device := range fixture.devices {
		if highWater := device.allocator.allocationIDHighWater(); highWater > maxHighWater {
			maxHighWater = highWater
		}
	}
	if err := vnextZeroRange(fixture.controlFile, 0, testVNextOwnerControlSlotBytes*2); err != nil {
		t.Fatalf("clear old Owner journal: %v", err)
	}
	group, err := formatVNextOwnerGroup(
		fixture.controlFile, testVNextOwnerControlSlotBytes, fixture.devices)
	if err != nil {
		t.Fatalf("reformat Owner group at device high-water: %v", err)
	}
	grant, err := group.reserve(vnextOwnerMemoryRequest("after-high-water", 1, 1))
	if err != nil {
		t.Fatalf("reserve after recovered high-water: %v", err)
	}
	if grant.AllocationRecordID != maxHighWater {
		t.Fatalf("Owner issued ID %d, want recovered high-water %d", grant.AllocationRecordID, maxHighWater)
	}
}

func TestVNextOwnerRecoversPartialPrepareByAbortingAllFragments(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("prepare-crash", capacity+2, 2)
	calls := 0
	fixture.group.faultHook = func(stage, deviceUUID string) error {
		if stage == vnextOwnerFailAfterPrepare {
			calls++
			if calls == 1 {
				return errVNextOwnerCrashInjected
			}
		}
		return nil
	}
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextOwnerCrashInjected) {
		t.Fatalf("partial prepare returned %v", err)
	}
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	if fixture.group.journal.Transactions[allocationID].State != vnextOwnerPreparing {
		t.Fatal("crash did not leave durable PREPARING state")
	}
	reopened := fixture.reopen(t)
	transaction := reopened.journal.Transactions[allocationID]
	if transaction.State != vnextOwnerAborted {
		t.Fatalf("partial prepare recovered as state %d", transaction.State)
	}
	for _, device := range reopened.devices {
		record, ok := device.allocator.lookup(request.CheckpointID)
		if ok && record.State != vnextAllocationAborted {
			t.Fatalf("partial fragment recovered as state %d", record.State)
		}
	}
	next, err := reopened.reserve(vnextOwnerMemoryRequest("after-prepare-crash", 1, 1))
	if err != nil {
		t.Fatalf("reserve after prepare recovery: %v", err)
	}
	if next.AllocationRecordID <= allocationID {
		t.Fatal("partial prepare allocation ID was reused")
	}
}

func TestVNextOwnerRecoversMidDeviceCommit(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	pages := capacity + 2
	request := vnextOwnerMemoryRequest("commit-crash", pages, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve commit crash: %v", err)
	}
	writeAllVNextOwnerPages(t, fixture.group, grant, pages)
	commitCalls := 0
	fixture.group.faultHook = func(stage, deviceUUID string) error {
		if stage == vnextOwnerFailDuringCommit {
			commitCalls++
			if commitCalls == 2 {
				return errVNextOwnerCrashInjected
			}
		}
		return nil
	}
	if err := fixture.group.commit(grant); !errors.Is(err, errVNextOwnerCrashInjected) {
		t.Fatalf("mid-commit fault returned %v", err)
	}
	if fixture.group.journal.Transactions[grant.AllocationRecordID].State != vnextOwnerCommitting {
		t.Fatal("mid-commit fault did not leave COMMITTING")
	}
	reopened := fixture.reopen(t)
	transaction := reopened.journal.Transactions[grant.AllocationRecordID]
	if transaction.State != vnextOwnerCommitted {
		t.Fatalf("mid-commit recovery ended in state %d", transaction.State)
	}
	for _, fragment := range transaction.Fragments {
		record, ok := reopened.devices[fragment.DeviceUUID].allocator.lookup(request.CheckpointID)
		if !ok || record.State != vnextAllocationCommitted {
			t.Fatalf("fragment %q after commit recovery: %#v", fragment.DeviceUUID, record)
		}
	}
}

func TestVNextOwnerRecoversMidDeviceAbort(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("abort-crash", capacity+2, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve abort crash: %v", err)
	}
	abortCalls := 0
	fixture.group.faultHook = func(stage, _ string) error {
		if stage == vnextOwnerFailDuringAbort {
			abortCalls++
			if abortCalls == 2 {
				return errVNextOwnerCrashInjected
			}
		}
		return nil
	}
	if err := fixture.group.abort(grant); !errors.Is(err, errVNextOwnerCrashInjected) {
		t.Fatalf("mid-abort fault returned %v", err)
	}
	if fixture.group.journal.Transactions[grant.AllocationRecordID].State != vnextOwnerAborting {
		t.Fatal("mid-abort fault did not leave ABORTING")
	}
	if _, err := fixture.group.reserve(vnextOwnerMemoryRequest("poison-check", 1, 1)); !errors.Is(err, errVNextOwnerPoisoned) {
		t.Fatalf("Owner group remained usable after partial abort: %v", err)
	}

	reopened := fixture.reopen(t)
	transaction := reopened.journal.Transactions[grant.AllocationRecordID]
	if transaction.State != vnextOwnerAborted {
		t.Fatalf("mid-abort recovery ended in state %d", transaction.State)
	}
	for _, fragment := range transaction.Fragments {
		record, ok := reopened.devices[fragment.DeviceUUID].allocator.lookup(request.CheckpointID)
		if !ok || record.State != vnextAllocationAborted {
			t.Fatalf("fragment %q after abort recovery: %#v", fragment.DeviceUUID, record)
		}
	}
}

func TestVNextOwnerJournalABFallbackAndMissingCommittedFragment(t *testing.T) {
	t.Run("torn newest journal falls back", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{UUID: "device-only", Size: 256 << 10}})
		if err := vnextWriteAtFull(
			fixture.controlFile,
			make([]byte, vnextFormatHeaderSize),
			testVNextOwnerControlSlotBytes); err != nil {
			t.Fatalf("tear Owner journal B: %v", err)
		}
		if err := fixture.controlFile.Sync(); err != nil {
			t.Fatalf("sync torn journal: %v", err)
		}
		group, err := openVNextOwnerGroup(
			fixture.controlFile, testVNextOwnerControlSlotBytes, fixture.devices)
		if err != nil {
			t.Fatalf("fallback to Owner journal A: %v", err)
		}
		if group.journal.SnapshotSequence != 1 {
			t.Fatalf("selected Owner journal sequence %d, want 1", group.journal.SnapshotSequence)
		}
	})

	t.Run("committed journal rejects missing device fragment", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
			{UUID: "device-a", Size: 256 << 10},
			{UUID: "device-b", Size: 256 << 10},
		})
		capacity := fixture.devices[0].superblock.Geometry.DataPageCount
		pages := capacity + 1
		request := vnextOwnerMemoryRequest("missing-fragment", pages, 2)
		grant, err := fixture.group.reserve(request)
		if err != nil {
			t.Fatalf("reserve: %v", err)
		}
		writeAllVNextOwnerPages(t, fixture.group, grant, pages)
		if err := fixture.group.commit(grant); err != nil {
			t.Fatalf("commit: %v", err)
		}
		targetUUID := grant.Extents[0].DeviceUUID
		target := fixture.group.devices[targetUUID]
		record, _ := target.allocator.lookup(request.CheckpointID)
		target.mu.Lock()
		if err := target.clearRecordDescriptorsLocked(record, false, false); err != nil {
			target.mu.Unlock()
			t.Fatalf("clear fragment descriptors for corruption: %v", err)
		}
		target.mu.Unlock()
		empty, err := newVNextCheckpointAllocator(target.superblock)
		if err != nil {
			t.Fatalf("create empty replacement allocator: %v", err)
		}
		empty.mu.Lock()
		empty.nextAllocationRecordID = target.allocator.allocationIDHighWater()
		target.allocator.mu.Lock()
		empty.snapshotSequence = target.allocator.snapshotSequence
		target.allocator.mu.Unlock()
		empty.mu.Unlock()
		data, sequence, err := empty.marshalNextSnapshot()
		if err != nil {
			t.Fatalf("marshal missing-fragment snapshot: %v", err)
		}
		offset := target.superblock.Geometry.AllocatorSlotAOffset
		if sequence%2 == 0 {
			offset = target.superblock.Geometry.AllocatorSlotBOffset
		}
		if err := vnextWriteCommittedEnvelopeSlot(
			target.file, offset, target.superblock.Geometry.AllocatorSlotBytes, data); err != nil {
			t.Fatalf("persist missing-fragment corruption: %v", err)
		}
		reopenedDevices := make([]*vnextPersistentDevice, 0, len(fixture.deviceFiles))
		for _, file := range fixture.deviceFiles {
			device, err := openVNextFileDevice(file)
			if err != nil {
				t.Fatalf("reopen corrupted device fixture: %v", err)
			}
			reopenedDevices = append(reopenedDevices, device)
		}
		if _, err := openVNextOwnerGroup(
			fixture.controlFile, testVNextOwnerControlSlotBytes, reopenedDevices); !errors.Is(err, errVNextCorrupt) {
			t.Fatalf("missing committed fragment returned %v", err)
		}
	})

	t.Run("journal rejects valid device snapshot with different producer identity", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(
			t, []vnextOwnerTestDeviceSpec{{UUID: "device-only", Size: 256 << 10}})
		request := vnextOwnerMemoryRequest("device-journal-mismatch", 2, 1)
		grant, err := fixture.group.reserve(request)
		if err != nil {
			t.Fatalf("reserve mismatch fixture: %v", err)
		}
		target := fixture.group.devices[grant.Extents[0].DeviceUUID]
		target.mu.Lock()
		target.allocator.mu.Lock()
		record := target.allocator.records[grant.AllocationRecordID]
		record.ProducerID = "different-but-valid-producer"
		target.allocator.mu.Unlock()
		if err := target.persistAllocatorLocked(); err != nil {
			target.mu.Unlock()
			t.Fatalf("persist independently valid mismatched device snapshot: %v", err)
		}
		target.mu.Unlock()

		reopenedDevice, err := openVNextFileDevice(fixture.deviceFiles[0])
		if err != nil {
			t.Fatalf("reopen independently valid device snapshot: %v", err)
		}
		if _, err := openVNextOwnerGroup(
			fixture.controlFile,
			testVNextOwnerControlSlotBytes,
			[]*vnextPersistentDevice{reopenedDevice}); !errors.Is(err, errVNextCorrupt) {
			t.Fatalf("journal/device producer mismatch returned %v", err)
		}
	})
}

func TestVNextOwnerGrantOrderingIsStable(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-c", Size: 256 << 10},
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("stable-order", capacity*2+1, 3)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve three-device spill: %v", err)
	}
	deviceOrder := make([]string, 0, len(grant.Extents))
	var logical uint64
	for _, extent := range grant.Extents {
		deviceOrder = append(deviceOrder, extent.DeviceUUID)
		if extent.GlobalLogicalStart != logical {
			t.Fatalf("non-contiguous grant ordering: %#v", grant.Extents)
		}
		logical += extent.PageCount
	}
	if !sort.StringsAreSorted(deviceOrder) {
		t.Fatalf("grant devices are not stable UUID order: %v", deviceOrder)
	}
}

func TestVNextOwnerNoSpaceIsDurableBeforeErrorAndLeavesAllocatorUnchanged(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("extent-budget", capacity+1, 1)
	segments, totalPages, digest, err := fixture.group.validateOwnerRequestLocked(request)
	if err != nil {
		t.Fatalf("validate no-space request: %v", err)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeFree := make(map[string]uint64)
	beforeDeviceHighWater := make(map[string]uint64)
	beforeDeviceImages := make([][]byte, len(fixture.deviceFiles))
	for deviceUUID, device := range fixture.group.devices {
		beforeFree[deviceUUID] = device.allocator.freePages()
		beforeDeviceHighWater[deviceUUID] = device.allocator.allocationIDHighWater()
	}
	for index, file := range fixture.deviceFiles {
		beforeDeviceImages[index], err = os.ReadFile(file.Name())
		if err != nil {
			t.Fatalf("read device image %d before no-space Reserve: %v", index, err)
		}
	}
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("extent-budget failure returned %v", err)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence+1 ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater+1 {
		t.Fatal("no-space result was not durably assigned exactly one Owner record")
	}
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	transaction := fixture.group.journal.Transactions[allocationID]
	if allocationID != beforeHighWater || transaction == nil ||
		transaction.AllocationRecordID != allocationID ||
		transaction.RequestID != request.RequestID ||
		transaction.CheckpointID != request.CheckpointID ||
		transaction.ProducerID != request.ProducerID ||
		transaction.RequestDigest != digest ||
		transaction.State != vnextOwnerRejectedNoSpace ||
		transaction.TotalPages != totalPages ||
		transaction.MaxExtents != request.MaxExtents ||
		!reflect.DeepEqual(transaction.Contents, segments) ||
		len(transaction.Fragments) != 0 {
		t.Fatalf("no-space tombstone is incomplete: %#v", transaction)
	}
	for deviceUUID, device := range fixture.group.devices {
		if device.allocator.freePages() != beforeFree[deviceUUID] ||
			device.allocator.allocationIDHighWater() != beforeDeviceHighWater[deviceUUID] {
			t.Fatalf("no-space tombstone mutated allocator counters on %q", deviceUUID)
		}
	}
	for index, file := range fixture.deviceFiles {
		after, err := os.ReadFile(file.Name())
		if err != nil {
			t.Fatalf("read device image %d after no-space Reserve: %v", index, err)
		}
		if !bytes.Equal(after, beforeDeviceImages[index]) {
			t.Fatalf("no-space tombstone changed allocator, descriptor, or payload bytes on device %d", index)
		}
	}
	reopened := fixture.reopen(t)
	recovered := reopened.journal.Transactions[allocationID]
	if recovered == nil || recovered.State != vnextOwnerRejectedNoSpace ||
		recovered.RequestDigest != digest || len(recovered.Fragments) != 0 {
		t.Fatalf("immediate restart did not recover durable no-space tombstone: %#v", recovered)
	}
}

func TestVNextOwnerRejectedNoSpaceReplaySurvivesCapacityAndRestart(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "device-only", Size: 256 << 10,
	}})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	fillerRequest := vnextOwnerMemoryRequest("no-space-filler", capacity, 1)
	fillerGrant, err := fixture.group.reserve(fillerRequest)
	if err != nil {
		t.Fatalf("reserve capacity filler: %v", err)
	}
	request := vnextOwnerMemoryRequest("durable-no-space", 1, 1)
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("initial no-space Reserve returned %v", err)
	}
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	if allocationID == 0 {
		t.Fatal("no-space Reserve did not consume a positive allocation ID")
	}
	if err := fixture.group.abort(fillerGrant); err != nil {
		t.Fatalf("free capacity after no-space Reserve: %v", err)
	}
	if got := fixture.group.devices["device-only"].allocator.freePages(); got != capacity {
		t.Fatalf("free capacity after filler abort = %d, want %d", got, capacity)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("exact retry after capacity appeared returned %v", err)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		fixture.group.journal.RequestIndex[request.RequestID] != allocationID {
		t.Fatal("exact no-space replay mutated or replaced its durable tombstone")
	}

	changedDigest := request
	changedDigest.Contents = append([]vnextContentRequest(nil), request.Contents...)
	changedDigest.Contents[0].ObjectID++
	if _, err := fixture.group.reserve(changedDigest); !errors.Is(err, errVNextAlreadyExists) {
		t.Fatalf("changed request digest returned %v", err)
	}
	changedIdentity := request
	changedIdentity.RequestID += "-different"
	if _, err := fixture.group.reserve(changedIdentity); !errors.Is(err, errVNextAlreadyExists) {
		t.Fatalf("changed request identity for tombstoned checkpoint returned %v", err)
	}

	reopened := fixture.reopen(t)
	beforeSequence = reopened.journal.SnapshotSequence
	beforeHighWater = reopened.journal.NextAllocationRecordID
	if _, err := reopened.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("exact no-space retry after restart returned %v", err)
	}
	transaction := reopened.journal.Transactions[allocationID]
	if transaction == nil || transaction.State != vnextOwnerRejectedNoSpace ||
		len(transaction.Fragments) != 0 ||
		reopened.journal.SnapshotSequence != beforeSequence ||
		reopened.journal.NextAllocationRecordID != beforeHighWater {
		t.Fatalf("restart changed no-space tombstone: %#v", transaction)
	}
}

func TestVNextOwnerRejectsZeroFragmentNonTombstone(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "device-only", Size: 256 << 10,
	}})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("zero-fragment-format", capacity+1, 1)
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("create valid no-space tombstone: %v", err)
	}
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	transaction := fixture.group.journal.Transactions[allocationID]
	malformedTransaction := *transaction
	malformedTransaction.State = vnextOwnerGranted
	if err := vnextValidateOwnerTransaction(
		&malformedTransaction, fixture.group.devices, fixture.group.ownerID, fixture.group.ownerEpoch); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("validator accepted zero-fragment GRANTED transaction: %v", err)
	}

	encoded, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatalf("marshal valid no-space journal: %v", err)
	}
	payload, err := vnextParseEnvelope(encoded, vnextOwnerJournalMagic, vnextMaxEnvelopePayload)
	if err != nil {
		t.Fatalf("extract valid no-space journal payload: %v", err)
	}
	payload = append([]byte(nil), payload...)
	stateOffset := 8 + 4 + len(fixture.group.ownerID) + 8 +
		vnextOwnerSchedulerHighWaterEncodedBytes + 8 + 8 + 4 + 4 + 8 + 4 + 8
	payload[stateOffset] = byte(vnextOwnerGranted)
	malformed, err := vnextMarshalEnvelope(vnextOwnerJournalMagic, payload)
	if err != nil {
		t.Fatalf("marshal malformed zero-fragment journal: %v", err)
	}
	if _, err := parseVNextOwnerJournal(malformed, fixture.group.devices); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("parser accepted zero-fragment GRANTED transaction: %v", err)
	}
}

func TestVNextOwnerNoSpacePersistenceFailureIsUnavailableAndPoisoned(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "device-only", Size: 256 << 10,
	}})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("no-space-persist-failure", capacity+1, 1)
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeFree := fixture.devices[0].allocator.freePages()
	fixture.group.controlSlotBytes = 1
	_, err := fixture.group.reserve(request)
	if err == nil || errors.Is(err, errVNextNoSpace) || !errors.Is(err, errVNextMetadataFull) {
		t.Fatalf("no-space tombstone persist failure returned %v", err)
	}
	if fixture.group.poisoned == nil {
		t.Fatal("ambiguous no-space tombstone persistence did not poison Owner")
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		len(fixture.group.journal.Transactions) != 0 ||
		fixture.devices[0].allocator.freePages() != beforeFree {
		t.Fatal("failed no-space tombstone persistence changed visible journal or allocator state")
	}
}

func TestVNextOwnerNoSpaceJournalWriteFailureIsNeverDefinitive(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "device-only", Size: 256 << 10,
	}})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("no-space-write-failure", capacity+1, 1)
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeFree := fixture.devices[0].allocator.freePages()
	if err := fixture.controlFile.Close(); err != nil {
		t.Fatalf("close Owner journal before injected write failure: %v", err)
	}
	_, err := fixture.group.reserve(request)
	if err == nil || errors.Is(err, errVNextNoSpace) {
		t.Fatalf("no-space tombstone write failure returned %v", err)
	}
	if fixture.group.poisoned == nil {
		t.Fatal("ambiguous no-space tombstone write did not poison Owner")
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		len(fixture.group.journal.Transactions) != 0 ||
		fixture.devices[0].allocator.freePages() != beforeFree {
		t.Fatal("failed no-space tombstone write changed visible journal or allocator state")
	}
}

func TestVNextOwnerMixedMemoryArtifactSplitPreservesTailSemantics(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextCheckpointAllocationRequest{
		RequestID:    "owner-request-mixed-split",
		CheckpointID: "owner-checkpoint-mixed-split",
		ProducerID:   "owner-producer-mixed-split",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		MaxExtents:   2,
		Contents: []vnextContentRequest{
			{
				Kind:       vnextContentMemory,
				ObjectID:   101,
				ByteLength: (capacity - 1) * vnextContentPageSize,
				PageCount:  capacity - 1,
			},
			{Kind: vnextContentArtifact, ObjectID: 102, ByteLength: 4096 + 904, PageCount: 2},
		},
	}
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve mixed split: %v", err)
	}
	if len(grant.Extents) != 2 || grant.Extents[0].DeviceUUID != "device-a" ||
		grant.Extents[0].PageCount != capacity || grant.Extents[1].DeviceUUID != "device-b" ||
		grant.Extents[1].PageCount != 1 {
		t.Fatalf("mixed request did not split at expected device boundary: %#v", grant.Extents)
	}
	deviceARecord, _ := fixture.group.devices["device-a"].allocator.lookup(request.CheckpointID)
	deviceBRecord, _ := fixture.group.devices["device-b"].allocator.lookup(request.CheckpointID)
	if len(deviceARecord.Contents) != 2 ||
		deviceARecord.Contents[1].Kind != vnextContentArtifact ||
		deviceARecord.Contents[1].ByteLength != 4096 {
		t.Fatalf("first artifact fragment metadata: %#v", deviceARecord.Contents)
	}
	if len(deviceBRecord.Contents) != 1 ||
		deviceBRecord.Contents[0].Kind != vnextContentArtifact ||
		deviceBRecord.Contents[0].ObjectID != 102 ||
		deviceBRecord.Contents[0].ByteLength != 904 {
		t.Fatalf("artifact tail fragment metadata: %#v", deviceBRecord.Contents)
	}
	tailGrant := grant.fragmentGrants["device-b"]
	tailAuthorization, err := fixture.group.devices["device-b"].allocator.authorizePageWrite(tailGrant, 0)
	if err != nil {
		t.Fatalf("authorize artifact tail: %v", err)
	}
	if tailAuthorization.ExpectedPayloadLength != 904 ||
		tailAuthorization.ContentKind != vnextContentArtifact ||
		tailAuthorization.ContentObjectID != 102 {
		t.Fatalf("artifact tail authorization: %#v", tailAuthorization)
	}
	for logicalPage := uint64(0); logicalPage < capacity+1; logicalPage++ {
		length := int(vnextContentPageSize)
		if logicalPage == capacity {
			length = 904
		}
		if err := fixture.group.writePage(
			grant, logicalPage, bytes.Repeat([]byte{0x5a}, length)); err != nil {
			t.Fatalf("write mixed logical page %d: %v", logicalPage, err)
		}
	}
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("commit mixed split: %v", err)
	}
}

func TestVNextOwnerOrdinaryPartialPrepareFailureAbortsWholeCheckpoint(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("ordinary-prepare-failure", capacity+2, 2)
	initialFree := make(map[string]uint64)
	for deviceUUID, device := range fixture.group.devices {
		initialFree[deviceUUID] = device.allocator.freePages()
	}
	prepareCalls := 0
	expectedFailure := errors.New("injected ordinary prepare failure")
	fixture.group.faultHook = func(stage, deviceUUID string) error {
		if stage == vnextOwnerFailBeforePrepare {
			prepareCalls++
			if prepareCalls == 2 {
				return expectedFailure
			}
		}
		return nil
	}
	if grant, err := fixture.group.reserve(request); !errors.Is(err, expectedFailure) || grant.AllocationRecordID != 0 {
		t.Fatalf("ordinary partial failure returned grant=%#v err=%v", grant, err)
	}
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	transaction := fixture.group.journal.Transactions[allocationID]
	if transaction == nil || transaction.State != vnextOwnerAborted {
		t.Fatalf("ordinary partial failure ended as %#v", transaction)
	}
	for deviceUUID, device := range fixture.group.devices {
		if device.allocator.freePages() != initialFree[deviceUUID] {
			t.Fatalf("partial failure leaked pages on %q", deviceUUID)
		}
		record, ok := device.allocator.lookup(request.CheckpointID)
		if ok && record.State != vnextAllocationAborted {
			t.Fatalf("partial failure fragment on %q is state %d", deviceUUID, record.State)
		}
	}
}

func TestVNextOwnerRecoversMidReclaim(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	pages := capacity + 2
	request := vnextOwnerMemoryRequest("reclaim-crash", pages, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve reclaim crash: %v", err)
	}
	writeAllVNextOwnerPages(t, fixture.group, grant, pages)
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("commit reclaim crash: %v", err)
	}
	reclaimCalls := 0
	fixture.group.faultHook = func(stage, deviceUUID string) error {
		if stage == vnextOwnerFailDuringReclaim {
			reclaimCalls++
			if reclaimCalls == 2 {
				return errVNextOwnerCrashInjected
			}
		}
		return nil
	}
	if err := fixture.group.reclaimCheckpoint(
		request.CheckpointID, grant.AllocationRecordID); !errors.Is(err, errVNextOwnerCrashInjected) {
		t.Fatalf("mid-reclaim fault returned %v", err)
	}
	if fixture.group.journal.Transactions[grant.AllocationRecordID].State != vnextOwnerReclaiming {
		t.Fatal("mid-reclaim fault did not leave RECLAIMING")
	}
	reopened := fixture.reopen(t)
	recovered := reopened.journal.Transactions[grant.AllocationRecordID]
	if recovered.State != vnextOwnerReclaimed || recovered.Reclaim == nil ||
		recovered.Reclaim.TerminalJournalSequence == 0 ||
		vnextAllZero(recovered.Reclaim.OwnerReceipt[:]) ||
		recovered.Reclaim.OwnerReceipt != vnextOwnerReclaimReceipt(
			recovered.Reclaim.Allocation,
			recovered.Reclaim.RequestDigest,
			recovered.Reclaim.SchedulerProof,
			recovered.Reclaim.TerminalJournalSequence) {
		t.Fatalf("mid-reclaim recovery lacks terminal evidence: %#v", recovered)
	}
	for _, device := range reopened.devices {
		record, ok := device.allocator.lookup(request.CheckpointID)
		if !ok || record.State != vnextAllocationReclaimed {
			t.Fatalf("reclaim recovery fragment: %#v", record)
		}
	}
}

func TestVNextOwnerGrantedRetryAfterRestartIsIdempotent(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "device-a", Size: 256 << 10},
		{UUID: "device-b", Size: 256 << 10},
	})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("granted-retry", capacity+1, 2)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve before restart: %v", err)
	}
	reopened := fixture.reopen(t)
	beforeSequence := reopened.journal.SnapshotSequence
	beforeHighWater := reopened.journal.NextAllocationRecordID
	retried, err := reopened.reserve(request)
	if err != nil {
		t.Fatalf("retry GRANTED allocation after restart: %v", err)
	}
	if retried.AllocationRecordID != grant.AllocationRecordID ||
		!reflect.DeepEqual(retried.Extents, grant.Extents) ||
		len(retried.fragmentGrants) != 0 {
		t.Fatalf("GRANTED retry changed grant:\nold=%#v\nnew=%#v", grant, retried)
	}
	if reopened.journal.SnapshotSequence != beforeSequence ||
		reopened.journal.NextAllocationRecordID != beforeHighWater {
		t.Fatal("idempotent GRANTED retry mutated Owner journal")
	}
	if err := reopened.abort(retried); err != nil {
		t.Fatalf("abort retried grant: %v", err)
	}
}
