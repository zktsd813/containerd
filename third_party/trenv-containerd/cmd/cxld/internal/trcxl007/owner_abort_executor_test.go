package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// ownerAbortReadArmedSizeDriftStorage models an operational backing-size
// change at an exact phase boundary. Reads in [triggerStart, triggerEnd) arm
// the drift; the next Size checks then fail without mutating media.
type ownerAbortReadArmedSizeDriftStorage struct {
	*ownerReserveExecutorTestStorage
	triggerStart uint64
	triggerEnd   uint64
	enabled      bool
	armed        bool
}

type ownerAbortLateDescriptorConflictStorage struct {
	*ownerReserveExecutorTestStorage
	injectAfterRead int
	descriptorReads int
	offset          uint64
	wire            []byte
}

type ownerAbortPartialWriteStorage struct {
	*ownerReserveExecutorTestStorage
	partialWriteCall int
	partialBytes     int
	writeCalls       int
	enabled          bool
}

func (storage *ownerAbortPartialWriteStorage) WriteAt(
	source []byte,
	offset int64,
) (int, error) {
	storage.writeCalls++
	if storage.enabled && storage.writeCalls == storage.partialWriteCall &&
		storage.partialBytes >= 0 && storage.partialBytes < len(source) {
		written, err := storage.ownerReserveExecutorTestStorage.WriteAt(
			source[:storage.partialBytes],
			offset)
		return written, err
	}
	return storage.ownerReserveExecutorTestStorage.WriteAt(source, offset)
}

func (storage *ownerAbortLateDescriptorConflictStorage) ReadAt(
	destination []byte,
	offset int64,
) (int, error) {
	read, err := storage.ownerReserveExecutorTestStorage.ReadAt(
		destination,
		offset)
	if offset >= 0 {
		position := uint64(offset)
		if position >= storage.geometry.DescriptorRegionBase &&
			position < storage.geometry.ContentRegionBase {
			storage.descriptorReads++
			if storage.injectAfterRead != 0 &&
				storage.descriptorReads == storage.injectAfterRead {
				storage.rawWrite(storage.offset, storage.wire)
			}
		}
	}
	return read, err
}

func ownerAbortTestInstallLateDescriptorConflict(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	deviceUUID string,
	injectAfterRead int,
	offset uint64,
	wire []byte,
) *ownerAbortLateDescriptorConflictStorage {
	t.Helper()
	base, exists := fixture.storages[deviceUUID]
	if !exists {
		t.Fatalf("missing storage %q", deviceUUID)
	}
	wrapper := &ownerAbortLateDescriptorConflictStorage{
		ownerReserveExecutorTestStorage: base,
		injectAfterRead:                 injectAfterRead,
		offset:                          offset,
		wire:                            append([]byte(nil), wire...),
	}
	for index := range fixture.group.devices {
		if fixture.group.devices[index].deviceUUID == deviceUUID {
			fixture.group.devices[index].metadata.storage = wrapper
		}
	}
	if fixture.group.anchor.superblock.DeviceUUID == deviceUUID {
		fixture.group.anchor.storage = wrapper
	}
	for index := range fixture.input.Devices {
		if fixture.input.Devices[index].ExpectedDeviceUUID == deviceUUID {
			fixture.input.Devices[index].Storage = wrapper
		}
	}
	return wrapper
}

func ownerAbortTestInstallPartialWrite(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	deviceUUID string,
	partialWriteCall int,
	partialBytes int,
) *ownerAbortPartialWriteStorage {
	t.Helper()
	base, exists := fixture.storages[deviceUUID]
	if !exists {
		t.Fatalf("missing storage %q", deviceUUID)
	}
	wrapper := &ownerAbortPartialWriteStorage{
		ownerReserveExecutorTestStorage: base,
		partialWriteCall:                partialWriteCall,
		partialBytes:                    partialBytes,
		enabled:                         true,
	}
	for index := range fixture.group.devices {
		if fixture.group.devices[index].deviceUUID == deviceUUID {
			fixture.group.devices[index].metadata.storage = wrapper
		}
	}
	if fixture.group.anchor.superblock.DeviceUUID == deviceUUID {
		fixture.group.anchor.storage = wrapper
	}
	for index := range fixture.input.Devices {
		if fixture.input.Devices[index].ExpectedDeviceUUID == deviceUUID {
			fixture.input.Devices[index].Storage = wrapper
		}
	}
	return wrapper
}

func (storage *ownerAbortReadArmedSizeDriftStorage) ReadAt(
	destination []byte,
	offset int64,
) (int, error) {
	read, err := storage.ownerReserveExecutorTestStorage.ReadAt(
		destination,
		offset)
	if storage.enabled && offset >= 0 {
		position := uint64(offset)
		if position >= storage.triggerStart && position < storage.triggerEnd {
			storage.armed = true
		}
	}
	return read, err
}

func (storage *ownerAbortReadArmedSizeDriftStorage) Size() uint64 {
	size := storage.ownerReserveExecutorTestStorage.Size()
	if storage.enabled && storage.armed && size != 0 {
		return size - 1
	}
	return size
}

func ownerAbortTestInstallSizeDrift(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	deviceUUID string,
	triggerStart uint64,
	triggerEnd uint64,
) *ownerAbortReadArmedSizeDriftStorage {
	t.Helper()
	base, exists := fixture.storages[deviceUUID]
	if !exists {
		t.Fatalf("missing storage %q", deviceUUID)
	}
	wrapper := &ownerAbortReadArmedSizeDriftStorage{
		ownerReserveExecutorTestStorage: base,
		triggerStart:                    triggerStart,
		triggerEnd:                      triggerEnd,
		enabled:                         true,
	}
	for index := range fixture.group.devices {
		if fixture.group.devices[index].deviceUUID == deviceUUID {
			fixture.group.devices[index].metadata.storage = wrapper
		}
	}
	if fixture.group.anchor.superblock.DeviceUUID == deviceUUID {
		fixture.group.anchor.storage = wrapper
	}
	for index := range fixture.input.Devices {
		if fixture.input.Devices[index].ExpectedDeviceUUID == deviceUUID {
			fixture.input.Devices[index].Storage = wrapper
		}
	}
	return wrapper
}

func ownerAbortTestRequests(
	fixture *ownerReserveExecutorTestFixture,
	id string,
	pages uint64,
) (OwnerReserveRequest, OwnerPreparingAbortRequest) {
	reserve := fixture.request(id, pages)
	reclaim := sha256.Sum256([]byte("reclaim-" + id))
	reserve.AuthorityEvidence.ReclaimAuthoritySHA256 = reclaim
	bootstrap := fixture.input.OwnerStateBootstrap
	abort := OwnerPreparingAbortRequest{
		ClusterID:                  bootstrap.ClusterID,
		OwnerGroupID:               bootstrap.OwnerGroupID,
		CurrentOwnerID:             bootstrap.CurrentOwnerID,
		AnchorDeviceUUID:           bootstrap.AnchorDeviceUUID,
		StorageCompatibilityID:     bootstrap.StorageCompatibilityID,
		OwnerEpoch:                 bootstrap.OwnerEpoch,
		GroupConfigurationSequence: bootstrap.GroupConfigurationSequence,
		MembershipSHA256:           bootstrap.MembershipSHA256,
		AllocationRecordID:         1,
		RequestID:                  reserve.RequestID,
		CheckpointID:               reserve.CheckpointID,
		ReclaimAuthoritySHA256:     reclaim,
	}
	return reserve, abort
}

func ownerAbortTestPreparing(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	reserve OwnerReserveRequest,
) OwnerCheckpointReservePlan {
	t.Helper()
	plan := fixture.plan(t, reserve)
	if plan.Outcome != OwnerReservePlanned {
		t.Fatalf("reserve plan outcome = %d", plan.Outcome)
	}
	fixture.commitPreparing(t, plan)
	fixture.resetTracking()
	return plan
}

func ownerAbortTestDescriptorWire(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	run OwnerReservedDescriptorRun,
	pageOffset uint64,
) ([]byte, uint64) {
	t.Helper()
	if pageOffset >= run.PageCount {
		t.Fatalf("page offset %d outside run count %d", pageOffset, run.PageCount)
	}
	offset, err := fixture.geometry.DescriptorOffset(
		run.StartDataPageIndex + pageOffset)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	wire := fixture.storages[run.DeviceUUID].rawBytes(offset, PageDescriptorBytes)
	return wire, offset
}

func ownerAbortTestAssertAllocatorPages(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
	wantUnavailable bool,
	wantApplied uint64,
) {
	t.Helper()
	_, allocators, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	byUUID := make(map[string]AllocatorSnapshot, len(allocators))
	for _, allocator := range allocators {
		byUUID[allocator.DeviceUUID] = allocator.Snapshot
	}
	for _, fragment := range record.Fragments {
		allocator, exists := byUUID[fragment.DeviceUUID]
		if !exists {
			t.Fatalf("missing allocator %q", fragment.DeviceUUID)
		}
		if allocator.AppliedOwnerTransactionSequence != wantApplied {
			t.Fatalf("device %q applied transaction = %d, want %d",
				fragment.DeviceUUID,
				allocator.AppliedOwnerTransactionSequence,
				wantApplied)
		}
		for _, extent := range fragment.Extents {
			for page := extent.StartDataPageIndex; page < extent.StartDataPageIndex+extent.PageCount; page++ {
				unavailable, pageErr := allocator.PageUnavailable(page)
				if pageErr != nil || unavailable != wantUnavailable {
					t.Fatalf("device %q page %d unavailable = %v, %v; want %v",
						fragment.DeviceUUID,
						page,
						unavailable,
						pageErr,
						wantUnavailable)
				}
			}
		}
	}
}

func ownerAbortTestRunsForDevice(
	runs []OwnerReservedDescriptorRun,
	deviceUUID string,
) []OwnerReservedDescriptorRun {
	result := make([]OwnerReservedDescriptorRun, 0, len(runs))
	for _, run := range runs {
		if run.DeviceUUID == deviceUUID {
			result = append(result, run)
		}
	}
	return result
}

func ownerAbortTestDurableAborting(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
) ownerAbortRecoveryPlan {
	t.Helper()
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil || !present {
		t.Fatalf("active PREPARING = %#v, %v", preparing, err)
	}
	plan, err := fixture.group.preflightFreshPreparingAbortLocked(
		ownerState,
		preparing)
	if err != nil {
		t.Fatalf("preflightFreshPreparingAbortLocked: %v", err)
	}
	if err := fixture.group.anchor.commitOwnerState(plan.abortingState); err != nil {
		t.Fatalf("commit ABORTING: %v", err)
	}
	fixture.resetTracking()
	return plan
}

func ownerAbortTestExpectedFreshPlan(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
) ownerAbortRecoveryPlan {
	t.Helper()
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("expected-plan PlannerInputs: %v", err)
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil || !present {
		t.Fatalf("expected-plan PREPARING = %#v, %v", preparing, err)
	}
	plan, err := fixture.group.preflightFreshPreparingAbortLocked(
		ownerState,
		preparing)
	if err != nil {
		t.Fatalf("expected PREPARING abort plan: %v", err)
	}
	fixture.resetTracking()
	return plan
}

func ownerAbortTestDurableQuarantineEvidence(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	id string,
	pages uint64,
) (
	OwnerPreparingAbortRequest,
	ownerAbortRecoveryPlan,
	OwnerReservedDescriptorRun,
	uint64,
	[]byte,
) {
	t.Helper()
	reserve, abort := ownerAbortTestRequests(fixture, id, pages)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	plan := ownerAbortTestDurableAborting(t, fixture)
	if len(reservePlan.ReservedDescriptors) == 0 {
		t.Fatal("quarantine fixture has no descriptor runs")
	}
	run := reservePlan.ReservedDescriptors[0]
	_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	conflict := bytes.Repeat([]byte{0xd3}, PageDescriptorBytes)
	fixture.storages[run.DeviceUUID].rawWrite(offset, conflict)
	fixture.resetTracking()
	return abort, plan, run, offset, conflict
}

func ownerAbortTestAssertPoisonThenReopenRecovery(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	abort OwnerPreparingAbortRequest,
	expected ownerAbortRecoveryPlan,
	wantDisposition OwnerAbortDisposition,
) OwnerAbortExecutionResult {
	t.Helper()
	fixture.resetTracking()
	if _, err := fixture.group.AbortPreparingCheckpoint(abort); !errors.Is(
		err,
		ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("poisoned AbortPreparingCheckpoint = %v", err)
	}
	if _, _, err := fixture.group.PlannerInputs(); !errors.Is(
		err,
		ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("poisoned PlannerInputs = %v", err)
	}
	fixture.assertZeroIO(t)
	group := fixture.reopen(t)
	before, _, err := group.PlannerInputs()
	if err != nil {
		t.Fatalf("post-reopen PlannerInputs: %v", err)
	}
	beforeRecord, found := reservedDescriptorOwnerRecord(
		before,
		abort.AllocationRecordID)
	if !found {
		t.Fatalf("post-reopen state lost allocation %d", abort.AllocationRecordID)
	}
	wantForwardRecovered := beforeRecord.State == OwnerAllocationAborting
	wantReplayed := beforeRecord.State == OwnerAllocationAborted ||
		beforeRecord.State == OwnerAllocationQuarantined
	fixture.resetTracking()
	result, err := group.AbortPreparingCheckpoint(abort)
	if err != nil {
		t.Fatalf("post-reopen abort recovery = %#v, %v", result, err)
	}
	ownerAbortTestAssertExactTerminal(
		t,
		fixture,
		abort,
		result,
		expected,
		wantDisposition,
		wantForwardRecovered,
		wantReplayed)
	fixture.assertPayloads(t)
	return result
}

func ownerAbortTestAssertExactTerminal(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	abort OwnerPreparingAbortRequest,
	result OwnerAbortExecutionResult,
	expected ownerAbortRecoveryPlan,
	wantDisposition OwnerAbortDisposition,
	wantForwardRecovered bool,
	wantReplayed bool,
) {
	t.Helper()
	wantState := OwnerAllocationAborted
	wantUnavailable := false
	wantRecord := expected.cleanTerminalRecord
	wantOwnerState := expected.cleanTerminalState
	if wantDisposition == OwnerAbortQuarantine {
		wantState = OwnerAllocationQuarantined
		wantUnavailable = true
		wantRecord = expected.qTerminalRecord
		wantOwnerState = expected.qTerminalState
	}
	if result.Record.State != wantState ||
		result.Disposition != wantDisposition ||
		result.ForwardRecovered != wantForwardRecovered ||
		result.Replayed != wantReplayed ||
		result.Record.AllocationRecordID != abort.AllocationRecordID ||
		result.Record.RequestID != abort.RequestID ||
		result.Record.CheckpointID != abort.CheckpointID ||
		result.Record.AuthorityEvidence.ReclaimAuthoritySHA256 !=
			abort.ReclaimAuthoritySHA256 ||
		!reservedDescriptorRecordsEqual(result.Record, wantRecord) {
		t.Fatalf("exact terminal result = %#v", result)
	}
	abortingTransaction := expected.abortingRecord.OwnerTransactionSequence
	if result.Record.ReservationTransactionSequence !=
		expected.abortingRecord.ReservationTransactionSequence {
		t.Fatalf("terminal reservation transaction = %d, want immutable N = %d",
			result.Record.ReservationTransactionSequence,
			expected.abortingRecord.ReservationTransactionSequence)
	}
	if result.Record.OwnerTransactionSequence != abortingTransaction+1 {
		t.Fatalf("terminal transaction = %d, want M+1 = %d",
			result.Record.OwnerTransactionSequence,
			abortingTransaction+1)
	}
	ownerState, allocators, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("terminal PlannerInputs: %v", err)
	}
	durableRecord, found := reservedDescriptorOwnerRecord(
		ownerState,
		abort.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(durableRecord, result.Record) {
		t.Fatalf("durable terminal record = %#v, found=%v", durableRecord, found)
	}
	if !ownerStateSnapshotsCanonicalEqual(
		ownerState,
		wantOwnerState,
		fixture.group.anchor.geometry) {
		t.Fatalf("durable terminal Owner state differs from expected %d disposition",
			wantDisposition)
	}
	if ownerState.NextAllocationRecordID != result.Record.AllocationRecordID+1 ||
		ownerState.NextOwnerTransactionSequence !=
			result.Record.OwnerTransactionSequence+1 {
		t.Fatalf("terminal high-water = %d/%d",
			ownerState.NextAllocationRecordID,
			ownerState.NextOwnerTransactionSequence)
	}
	allocatorByUUID := make(map[string]AllocatorSnapshot, len(allocators))
	for _, allocator := range allocators {
		allocatorByUUID[allocator.DeviceUUID] = allocator.Snapshot
	}
	for _, fragment := range expected.abortingRecord.Fragments {
		allocator, exists := allocatorByUUID[fragment.DeviceUUID]
		if !exists ||
			allocator.SnapshotSequence !=
				fragment.TargetAllocatorSnapshotSequence ||
			allocator.AppliedOwnerTransactionSequence != abortingTransaction {
			t.Fatalf("terminal allocator for %q = %#v, exists=%v",
				fragment.DeviceUUID,
				allocator,
				exists)
		}
		for _, extent := range fragment.Extents {
			for page := extent.StartDataPageIndex; page < extent.StartDataPageIndex+extent.PageCount; page++ {
				unavailable, pageErr := allocator.PageUnavailable(page)
				if pageErr != nil || unavailable != wantUnavailable {
					t.Fatalf("terminal allocator %q page %d = %v, %v; want %v",
						fragment.DeviceUUID,
						page,
						unavailable,
						pageErr,
						wantUnavailable)
				}
			}
		}
	}
	preparingRecord := cloneOwnerStateRecord(expected.abortingRecord)
	preparingRecord.State = OwnerAllocationPreparing
	preparingRecord.OwnerTransactionSequence = abortingTransaction - 1
	runs, err := ownerReserveDescriptorsFromRecord(preparingRecord)
	if err != nil {
		t.Fatalf("terminal descriptor runs: %v", err)
	}
	for _, run := range runs {
		reservedWire, marshalErr := run.Descriptor.MarshalBinary()
		if marshalErr != nil {
			t.Fatalf("terminal RESERVED wire: %v", marshalErr)
		}
		quarantined := run.Descriptor
		quarantined.State = DescriptorQuarantined
		quarantined.OwnerTransactionSeq = abortingTransaction
		quarantinedWire, marshalErr := quarantined.MarshalBinary()
		if marshalErr != nil {
			t.Fatalf("terminal Q wire: %v", marshalErr)
		}
		for page := uint64(0); page < run.PageCount; page++ {
			wire, _ := ownerAbortTestDescriptorWire(t, fixture, run, page)
			class := classifyOwnerAbortDescriptor(
				wire,
				reservedWire,
				quarantinedWire)
			if wantDisposition == OwnerAbortClean &&
				class != ownerAbortDescriptorFree {
				t.Fatalf("terminal clean descriptor %q/%d class = %d, wire=%x",
					run.DeviceUUID,
					run.StartDataPageIndex+page,
					class,
					wire)
			}
			if wantDisposition == OwnerAbortQuarantine &&
				class != ownerAbortDescriptorQuarantined &&
				class != ownerAbortDescriptorConflict {
				t.Fatalf("terminal quarantine descriptor %q/%d class = %d, wire=%x",
					run.DeviceUUID,
					run.StartDataPageIndex+page,
					class,
					wire)
			}
		}
	}
}

func TestOwnerAbortExecutorCleanFromFreePreparingAndReplay(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "clean-free", 3)
	plan := ownerAbortTestPreparing(t, fixture, reserve)

	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil {
		t.Fatalf("AbortPreparingCheckpoint: %v", err)
	}
	if result.Record.State != OwnerAllocationAborted ||
		result.Record.OwnerTransactionSequence != 3 ||
		result.Disposition != OwnerAbortClean ||
		result.ForwardRecovered || result.Replayed {
		t.Fatalf("clean abort result = %#v", result)
	}
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil || ownerState.NextOwnerTransactionSequence != 4 {
		t.Fatalf("terminal Owner state next = %d, %v",
			ownerState.NextOwnerTransactionSequence,
			err)
	}
	for _, run := range plan.ReservedDescriptors {
		for page := uint64(0); page < run.PageCount; page++ {
			wire, _ := ownerAbortTestDescriptorWire(t, fixture, run, page)
			if !allZero(wire) {
				t.Fatalf("clean descriptor is not FREE: %x", wire)
			}
		}
	}
	ownerAbortTestAssertAllocatorPages(t, fixture, result.Record, false, 2)
	fixture.assertPayloads(t)

	fixture.resetTracking()
	replay, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil || !replay.Replayed || replay.ForwardRecovered ||
		replay.Record.State != OwnerAllocationAborted {
		t.Fatalf("abort replay = %#v, %v", replay, err)
	}
	fixture.assertZeroIO(t)
	if _, err := fixture.group.RecoverAbortingCheckpoint(); !errors.Is(
		err,
		ErrOwnerAbortNoAborting) {
		t.Fatalf("terminal RecoverAbortingCheckpoint = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerAbortExecutorRejectsSealedQuarantineProvenanceWithoutIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "sealed-quarantine", 1)
	ownerAbortTestPreparing(t, fixture, reserve)
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	records := ownerState.Records()
	transaction := ownerState.NextOwnerTransactionSequence
	records[0].State = OwnerAllocationQuarantined
	records[0].OwnerTransactionSequence = transaction
	records[0].OwnerVerifiedSealSHA256 = ownerStateTestSealSHA256()
	sealedBase := ownerState.Clone()
	sealedBase.SnapshotSequence++
	sealedBase.NextOwnerTransactionSequence = transaction + 1
	sealed := ownerReserveExecutorSnapshotWithRecords(t, sealedBase, records)
	if err := fixture.group.anchor.commitOwnerState(sealed); err != nil {
		t.Fatalf("commit sealed QUARANTINED state: %v", err)
	}
	fixture.resetTracking()

	if _, err := fixture.group.AbortPreparingCheckpoint(abort); !errors.Is(
		err,
		ErrOwnerAbortConflict) {
		t.Fatalf("sealed QUARANTINED abort error = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerAbortExecutorCleanAfterReservationAllocatorApplied(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "clean-applied", 4)
	plan := ownerAbortTestPreparing(t, fixture, reserve)
	if err := fixture.group.devices[0].metadata.persistPreparingReservedDescriptors(
		plan.PreparingOwnerState.Records()[0],
		plan.ReservedDescriptors); err != nil {
		t.Fatalf("persist RESERVED descriptors: %v", err)
	}
	if err := fixture.group.devices[0].metadata.commitAllocatorSnapshot(
		plan.AllocatorUpdates[0].DesiredSnapshot); err != nil {
		t.Fatalf("commit PREPARING allocator: %v", err)
	}
	fixture.resetTracking()

	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil || result.Record.State != OwnerAllocationAborted ||
		result.Disposition != OwnerAbortClean {
		t.Fatalf("clean applied abort = %#v, %v", result, err)
	}
	for _, run := range plan.ReservedDescriptors {
		for page := uint64(0); page < run.PageCount; page++ {
			wire, _ := ownerAbortTestDescriptorWire(t, fixture, run, page)
			if !allZero(wire) {
				t.Fatalf("released RESERVED descriptor = %x", wire)
			}
		}
	}
	ownerAbortTestAssertAllocatorPages(t, fixture, result.Record, false, 2)
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorFreshAbortFromMultiDevicePartialReserve(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a", "device-b", "device-c"},
		"device-c",
		2<<20)
	reserve, abort := ownerAbortTestRequests(
		fixture,
		"fresh-partial-reserve",
		fixture.geometry.DataPageCount+1)
	plan := ownerAbortTestPreparing(t, fixture, reserve)
	if len(plan.AllocatorUpdates) != 2 {
		t.Fatalf("allocator updates = %d, want 2", len(plan.AllocatorUpdates))
	}
	appliedUpdate := plan.AllocatorUpdates[0]
	var appliedDevice *DeviceMetadata
	for index := range fixture.group.devices {
		if fixture.group.devices[index].deviceUUID == appliedUpdate.DeviceUUID {
			appliedDevice = fixture.group.devices[index].metadata
			break
		}
	}
	if appliedDevice == nil {
		t.Fatalf("missing applied device %q", appliedUpdate.DeviceUUID)
	}
	if err := appliedDevice.commitAllocatorSnapshot(
		appliedUpdate.DesiredSnapshot); err != nil {
		t.Fatalf("commit one PREPARING allocator: %v", err)
	}
	currentSequence := make(map[string]uint64, 2)
	for _, update := range plan.AllocatorUpdates {
		for index := range fixture.group.devices {
			if fixture.group.devices[index].deviceUUID == update.DeviceUUID {
				currentSequence[update.DeviceUUID] =
					fixture.group.devices[index].metadata.allocator.SnapshotSequence
			}
		}
	}
	expected := ownerAbortTestExpectedFreshPlan(t, fixture)

	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil {
		t.Fatalf("AbortPreparingCheckpoint: %v", err)
	}
	ownerAbortTestAssertExactTerminal(
		t,
		fixture,
		abort,
		result,
		expected,
		OwnerAbortClean,
		false,
		false)
	if len(result.Record.Fragments) != 2 {
		t.Fatalf("terminal fragments = %d, want 2", len(result.Record.Fragments))
	}
	targets := make(map[uint64]bool, 2)
	for _, fragment := range result.Record.Fragments {
		want := currentSequence[fragment.DeviceUUID] + 1
		if fragment.TargetAllocatorSnapshotSequence != want {
			t.Fatalf("device %q abort target = %d, want current+1 = %d",
				fragment.DeviceUUID,
				fragment.TargetAllocatorSnapshotSequence,
				want)
		}
		targets[fragment.TargetAllocatorSnapshotSequence] = true
	}
	if len(targets) != 2 {
		t.Fatalf("partial-reserve abort targets did not diverge: %#v", targets)
	}
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorForeignDescriptorQuarantinesWholeCheckpoint(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "foreign", 3)
	plan := ownerAbortTestPreparing(t, fixture, reserve)
	run := plan.ReservedDescriptors[0]
	foreignDescriptor, err := BuildImmutableContentPageDescriptor(
		77,
		88,
		9,
		66,
		cxlcheckpoint.ContentArtifactPayloadV7,
		[]byte("foreign-content"))
	if err != nil {
		t.Fatalf("BuildImmutableContentPageDescriptor: %v", err)
	}
	foreignWire, err := foreignDescriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("foreign MarshalBinary: %v", err)
	}
	_, foreignOffset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	fixture.storages[run.DeviceUUID].rawWrite(foreignOffset, foreignWire)

	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil {
		t.Fatalf("AbortPreparingCheckpoint: %v", err)
	}
	if result.Record.State != OwnerAllocationQuarantined ||
		result.Disposition != OwnerAbortQuarantine {
		t.Fatalf("quarantine result = %#v", result)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		foreignOffset,
		PageDescriptorBytes); !bytes.Equal(got, foreignWire) {
		t.Fatalf("foreign descriptor changed: %x", got)
	}
	for page := uint64(1); page < run.PageCount; page++ {
		wire, _ := ownerAbortTestDescriptorWire(t, fixture, run, page)
		descriptor, parseErr := ParseDescriptor(wire)
		if parseErr != nil || descriptor.State != DescriptorQuarantined ||
			descriptor.OwnerTransactionSeq != 2 ||
			descriptor.PaddedPageCRC32C != 0 ||
			descriptor.ContentReferenceCount != 0 {
			t.Fatalf("safe page Q(M) = %#v, %v", descriptor, parseErr)
		}
	}
	ownerAbortTestAssertAllocatorPages(t, fixture, result.Record, true, 2)
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorQuarantineAdvancesAlreadyAllocatedPreparingBitmap(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "q-preparing-applied", 3)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	if err := fixture.group.devices[0].metadata.commitAllocatorSnapshot(
		reservePlan.AllocatorUpdates[0].DesiredSnapshot); err != nil {
		t.Fatalf("commit PREPARING allocator: %v", err)
	}
	run := reservePlan.ReservedDescriptors[0]
	_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	conflict := bytes.Repeat([]byte{0x9c}, PageDescriptorBytes)
	fixture.storages[run.DeviceUUID].rawWrite(offset, conflict)
	expected := ownerAbortTestExpectedFreshPlan(t, fixture)
	beforeBitmap := fixture.group.devices[0].metadata.allocator.BitmapBytes()

	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil {
		t.Fatalf("AbortPreparingCheckpoint: %v", err)
	}
	ownerAbortTestAssertExactTerminal(
		t,
		fixture,
		abort,
		result,
		expected,
		OwnerAbortQuarantine,
		false,
		false)
	_, allocators, err := fixture.group.PlannerInputs()
	if err != nil || len(allocators) != 1 ||
		!bytes.Equal(beforeBitmap, allocators[0].Snapshot.BitmapBytes()) {
		t.Fatalf("transaction-only Q bitmap changed: allocators=%#v, err=%v",
			allocators,
			err)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		offset,
		PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("transaction-only Q changed conflict: %x", got)
	}
}

func TestOwnerAbortExecutorEveryNonExactDescriptorForcesWholeQuarantine(t *testing.T) {
	tests := []struct {
		name string
		wire func(t *testing.T, expected Descriptor) []byte
	}{
		{
			name: "wrong-transaction",
			wire: func(t *testing.T, expected Descriptor) []byte {
				expected.OwnerTransactionSeq++
				wire, err := expected.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return wire
			},
		},
		{
			name: "wrong-object",
			wire: func(t *testing.T, expected Descriptor) []byte {
				expected.OriginObjectID++
				wire, err := expected.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return wire
			},
		},
		{
			name: "wrong-kind",
			wire: func(t *testing.T, expected Descriptor) []byte {
				expected.ContentKind = cxlcheckpoint.ContentArtifactPayloadV7
				wire, err := expected.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return wire
			},
		},
		{
			name: "immutable-sealed",
			wire: func(t *testing.T, _ Descriptor) []byte {
				descriptor, err := BuildImmutableContentPageDescriptor(
					91,
					92,
					7,
					93,
					cxlcheckpoint.ContentArtifactPayloadV7,
					[]byte("sealed"))
				if err != nil {
					t.Fatalf("BuildImmutableContentPageDescriptor: %v", err)
				}
				wire, err := descriptor.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return wire
			},
		},
		{
			name: "published-slot",
			wire: func(t *testing.T, _ Descriptor) []byte {
				descriptor, err := BuildPublishedSlotPageDescriptor(
					101,
					102,
					3,
					103,
					cxlcheckpoint.ContentPlacementSlotAV7,
					[]byte("published"))
				if err != nil {
					t.Fatalf("BuildPublishedSlotPageDescriptor: %v", err)
				}
				wire, err := descriptor.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return wire
			},
		},
		{
			name: "retiring",
			wire: func(t *testing.T, expected Descriptor) []byte {
				expected.State = DescriptorRetiring
				wire, err := expected.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				return wire
			},
		},
		{
			name: "corrupt-crc",
			wire: func(t *testing.T, expected Descriptor) []byte {
				wire, err := expected.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				wire[descriptorCRC32COffset] ^= 0xff
				return wire
			},
		},
		{
			name: "torn-prefix",
			wire: func(t *testing.T, expected Descriptor) []byte {
				canonical, err := expected.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary: %v", err)
				}
				wire := make([]byte, PageDescriptorBytes)
				copy(wire, canonical[:PageDescriptorBytes/2])
				return wire
			},
		},
		{
			name: "unknown-state-bytes",
			wire: func(_ *testing.T, _ Descriptor) []byte {
				return bytes.Repeat([]byte{0xa5}, PageDescriptorBytes)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			reserve, abort := ownerAbortTestRequests(
				fixture,
				"descriptor-"+test.name,
				2)
			plan := ownerAbortTestPreparing(t, fixture, reserve)
			run := plan.ReservedDescriptors[0]
			conflict := test.wire(t, run.Descriptor)
			_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
			fixture.storages[run.DeviceUUID].rawWrite(offset, conflict)

			result, err := fixture.group.AbortPreparingCheckpoint(abort)
			if err != nil || result.Record.State != OwnerAllocationQuarantined ||
				result.Disposition != OwnerAbortQuarantine {
				t.Fatalf("quarantine result = %#v, %v", result, err)
			}
			if got := fixture.storages[run.DeviceUUID].rawBytes(
				offset,
				PageDescriptorBytes); !bytes.Equal(got, conflict) {
				t.Fatalf("conflict bytes changed: %x", got)
			}
			safeWire, _ := ownerAbortTestDescriptorWire(t, fixture, run, 1)
			safe, err := ParseDescriptor(safeWire)
			if err != nil || safe.State != DescriptorQuarantined ||
				safe.OwnerTransactionSeq != 2 {
				t.Fatalf("safe page = %#v, %v", safe, err)
			}
			ownerAbortTestAssertAllocatorPages(
				t,
				fixture,
				result.Record,
				true,
				2)
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerAbortExecutorRequestAndAuthorityFailuresAreZeroIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, valid := ownerAbortTestRequests(fixture, "authority", 1)
	ownerAbortTestPreparing(t, fixture, reserve)
	tests := []struct {
		name string
		edit func(*OwnerPreparingAbortRequest)
		want error
	}{
		{
			name: "zero-authority",
			edit: func(request *OwnerPreparingAbortRequest) {
				request.ReclaimAuthoritySHA256 = [sha256.Size]byte{}
			},
			want: ErrInvalidOwnerPreparingAbortRequest,
		},
		{
			name: "wrong-authority",
			edit: func(request *OwnerPreparingAbortRequest) {
				request.ReclaimAuthoritySHA256 = sha256.Sum256([]byte("wrong"))
			},
			want: ErrOwnerAbortAuthorityConflict,
		},
		{
			name: "wrong-current-owner",
			edit: func(request *OwnerPreparingAbortRequest) {
				request.CurrentOwnerID = "another-owner"
			},
			want: ErrOwnerAbortAuthorityConflict,
		},
		{
			name: "wrong-membership",
			edit: func(request *OwnerPreparingAbortRequest) {
				request.MembershipSHA256[0] ^= 1
			},
			want: ErrOwnerAbortAuthorityConflict,
		},
		{
			name: "wrong-record",
			edit: func(request *OwnerPreparingAbortRequest) {
				request.AllocationRecordID++
			},
			want: ErrOwnerAbortConflict,
		},
		{
			name: "wrong-checkpoint",
			edit: func(request *OwnerPreparingAbortRequest) {
				request.CheckpointID = "checkpoint-other"
			},
			want: ErrOwnerAbortConflict,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.edit(&request)
			fixture.resetTracking()
			if _, err := fixture.group.AbortPreparingCheckpoint(request); !errors.Is(
				err,
				test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			fixture.assertZeroIO(t)
		})
	}
	fixture.resetTracking()
	if _, err := fixture.group.RecoverAbortingCheckpoint(); !errors.Is(
		err,
		ErrOwnerAbortNoAborting) {
		t.Fatalf("PREPARING recovery inferred authority: %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerAbortExecutorRejectsGrantedAndMissingDurableAuthorityWithoutIO(t *testing.T) {
	t.Run("GRANTED-is-not-abortable", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t,
			[]string{"device-a"},
			"device-a",
			2<<20)
		reserve, abort := ownerAbortTestRequests(fixture, "granted-conflict", 1)
		result, err := fixture.group.ExecuteCheckpointReserve(reserve)
		if err != nil || result.Record.State != OwnerAllocationGranted {
			t.Fatalf("create GRANTED fixture = %#v, %v", result, err)
		}
		fixture.resetTracking()
		if _, err := fixture.group.AbortPreparingCheckpoint(abort); !errors.Is(
			err,
			ErrOwnerAbortConflict) {
			t.Fatalf("GRANTED abort = %v", err)
		}
		fixture.assertZeroIO(t)
	})

	t.Run("synthetic-zero-durable-reclaim-commitment", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t,
			[]string{"device-a"},
			"device-a",
			2<<20)
		reserve, abort := ownerAbortTestRequests(
			fixture,
			"missing-durable-authority",
			1)
		plan := fixture.plan(t, reserve)
		records := plan.PreparingOwnerState.Records()
		records[0].AuthorityEvidence.ReclaimAuthoritySHA256 = [sha256.Size]byte{}
		synthetic := ownerReserveExecutorSnapshotWithRecords(
			t,
			plan.PreparingOwnerState,
			records)
		if err := fixture.group.anchor.commitOwnerState(synthetic); err != nil {
			t.Fatalf("commit synthetic zero-authority PREPARING: %v", err)
		}
		fixture.resetTracking()
		if _, err := fixture.group.AbortPreparingCheckpoint(abort); !errors.Is(
			err,
			ErrOwnerAbortAuthorityConflict) {
			t.Fatalf("missing durable reclaim commitment = %v", err)
		}
		fixture.assertZeroIO(t)
	})
}

func TestOwnerAbortExecutorExactQuarantineMarkerPinsRecovery(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, _ := ownerAbortTestRequests(fixture, "q-marker", 3)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	abortPlan := ownerAbortTestDurableAborting(t, fixture)
	run := reservePlan.ReservedDescriptors[0]
	quarantined := run.Descriptor
	quarantined.State = DescriptorQuarantined
	quarantined.OwnerTransactionSeq =
		abortPlan.abortingRecord.OwnerTransactionSequence
	wire, err := quarantined.MarshalBinary()
	if err != nil {
		t.Fatalf("Q(M) MarshalBinary: %v", err)
	}
	_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	fixture.storages[run.DeviceUUID].rawWrite(offset, wire)

	result, err := fixture.reopen(t).RecoverAbortingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationQuarantined ||
		result.Disposition != OwnerAbortQuarantine || !result.ForwardRecovered {
		t.Fatalf("Q marker recovery = %#v, %v", result, err)
	}
	for page := uint64(0); page < run.PageCount; page++ {
		got, _ := ownerAbortTestDescriptorWire(t, fixture, run, page)
		descriptor, parseErr := ParseDescriptor(got)
		if parseErr != nil || descriptor.State != DescriptorQuarantined ||
			descriptor.OwnerTransactionSeq != 2 {
			t.Fatalf("recovered Q page = %#v, %v", descriptor, parseErr)
		}
	}
	ownerAbortTestAssertAllocatorPages(t, fixture, result.Record, true, 2)
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorPartialAllocatorApplicationRecoversFixedDisposition(t *testing.T) {
	tests := []struct {
		name        string
		disposition OwnerAbortDisposition
		wantState   OwnerAllocationState
		unavailable bool
	}{
		{
			name:        "clean",
			disposition: OwnerAbortClean,
			wantState:   OwnerAllocationAborted,
			unavailable: false,
		},
		{
			name:        "quarantine",
			disposition: OwnerAbortQuarantine,
			wantState:   OwnerAllocationQuarantined,
			unavailable: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b", "device-c"},
				"device-c",
				2<<20)
			reserve, _ := ownerAbortTestRequests(
				fixture,
				"partial-"+test.name,
				fixture.geometry.DataPageCount+1)
			ownerAbortTestPreparing(t, fixture, reserve)
			plan := ownerAbortTestDurableAborting(t, fixture)
			if len(plan.devices) != 2 {
				t.Fatalf("affected devices = %d", len(plan.devices))
			}
			for _, entry := range plan.devices {
				if err := fixture.group.devices[entry.deviceIndex].metadata.
					persistAbortingDescriptorDisposition(
						plan.abortingRecord,
						test.disposition); err != nil {
					t.Fatalf("persist disposition on %q: %v", entry.deviceUUID, err)
				}
			}
			first := plan.devices[0]
			desired := first.desiredClean
			if test.disposition == OwnerAbortQuarantine {
				desired = first.desiredQuarantine
			}
			if err := fixture.group.devices[first.deviceIndex].metadata.
				commitAllocatorSnapshot(desired); err != nil {
				t.Fatalf("commit first abort allocator: %v", err)
			}

			result, err := fixture.reopen(t).RecoverAbortingCheckpoint()
			if err != nil || result.Record.State != test.wantState ||
				result.Disposition != test.disposition || !result.ForwardRecovered {
				t.Fatalf("partial recovery = %#v, %v", result, err)
			}
			ownerAbortTestAssertAllocatorPages(
				t,
				fixture,
				result.Record,
				test.unavailable,
				2)
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerAbortExecutorAppliedAllocatorsDisagreeGoesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a", "device-b", "device-c"},
		"device-c",
		2<<20)
	reserve, abort := ownerAbortTestRequests(
		fixture,
		"allocator-disagreement",
		fixture.geometry.DataPageCount+1)
	ownerAbortTestPreparing(t, fixture, reserve)
	plan := ownerAbortTestDurableAborting(t, fixture)
	if len(plan.devices) != 2 {
		t.Fatalf("affected devices = %d", len(plan.devices))
	}
	for _, entry := range plan.devices {
		if err := fixture.group.devices[entry.deviceIndex].metadata.
			persistAbortingDescriptorDisposition(
				plan.abortingRecord,
				OwnerAbortQuarantine); err != nil {
			t.Fatalf("persist Q on %q: %v", entry.deviceUUID, err)
		}
	}
	if err := fixture.group.devices[plan.devices[0].deviceIndex].metadata.
		commitAllocatorSnapshot(plan.devices[0].desiredClean); err != nil {
		t.Fatalf("commit clean allocator: %v", err)
	}
	if err := fixture.group.devices[plan.devices[1].deviceIndex].metadata.
		commitAllocatorSnapshot(plan.devices[1].desiredQuarantine); err != nil {
		t.Fatalf("commit quarantine allocator: %v", err)
	}
	group := fixture.reopen(t)
	fixture.resetTracking()
	_, err := group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("disagreement error = %v", err)
	}
	fixture.resetTracking()
	if _, _, err := group.PlannerInputs(); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("offline PlannerInputs = %v", err)
	}
	if _, err := group.AbortPreparingCheckpoint(abort); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("offline AbortPreparingCheckpoint = %v", err)
	}
	fixture.assertZeroIO(t)
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorAppliedDispositionDescriptorContradictionGoesOffline(t *testing.T) {
	tests := []struct {
		name        string
		disposition OwnerAbortDisposition
		corrupt     func(storage *ownerReserveExecutorTestStorage, offset uint64)
	}{
		{
			name:        "clean-then-foreign",
			disposition: OwnerAbortClean,
			corrupt: func(storage *ownerReserveExecutorTestStorage, offset uint64) {
				storage.rawWrite(offset, bytes.Repeat([]byte{0x6c}, PageDescriptorBytes))
			},
		},
		{
			name:        "quarantine-then-free",
			disposition: OwnerAbortQuarantine,
			corrupt: func(storage *ownerReserveExecutorTestStorage, offset uint64) {
				storage.rawWrite(offset, make([]byte, PageDescriptorBytes))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			reserve, _ := ownerAbortTestRequests(fixture, test.name, 2)
			reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
			plan := ownerAbortTestDurableAborting(t, fixture)
			entry := plan.devices[0]
			device := fixture.group.devices[entry.deviceIndex].metadata
			if err := device.persistAbortingDescriptorDisposition(
				plan.abortingRecord,
				test.disposition); err != nil {
				t.Fatalf("persist disposition: %v", err)
			}
			desired := entry.desiredClean
			if test.disposition == OwnerAbortQuarantine {
				desired = entry.desiredQuarantine
			}
			if err := device.commitAllocatorSnapshot(desired); err != nil {
				t.Fatalf("commit abort allocator: %v", err)
			}
			run := reservePlan.ReservedDescriptors[0]
			_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
			test.corrupt(fixture.storages[run.DeviceUUID], offset)

			_, err := fixture.reopen(t).RecoverAbortingCheckpoint()
			if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
				!errors.Is(err, ErrOwnerAbortDurableContradiction) {
				t.Fatalf("descriptor contradiction = %v", err)
			}
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerAbortExecutorLateDescriptorConflictWithoutAppliedMLockRetriesAsQuarantine(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "late-conflict-retry", 2)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	expected := ownerAbortTestExpectedFreshPlan(t, fixture)
	run := reservePlan.ReservedDescriptors[0]
	_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	conflict := bytes.Repeat([]byte{0xa7}, PageDescriptorBytes)
	wrapper := ownerAbortTestInstallLateDescriptorConflict(
		t,
		fixture,
		run.DeviceUUID,
		2,
		offset,
		conflict)
	fixture.resetTracking()
	_, err := fixture.group.AbortPreparingCheckpoint(abort)
	if !errors.Is(err, ErrOwnerAbortDescriptorDispositionChanged) ||
		!errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("late unlocked descriptor conflict = %v", err)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		offset,
		PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("late conflict changed: %x", got)
	}
	wrapper.injectAfterRead = 0
	fixture.resetTracking()
	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil {
		t.Fatalf("late conflict retry: %v", err)
	}
	ownerAbortTestAssertExactTerminal(
		t,
		fixture,
		abort,
		result,
		expected,
		OwnerAbortQuarantine,
		true,
		false)
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		offset,
		PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("quarantine retry overwrote conflict: %x", got)
	}
}

func TestOwnerAbortExecutorLateDescriptorConflictWithAppliedMLockGoesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "late-conflict-locked", 2)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	plan := ownerAbortTestDurableAborting(t, fixture)
	entry := plan.devices[0]
	device := fixture.group.devices[entry.deviceIndex].metadata
	if err := device.persistAbortingDescriptorDisposition(
		plan.abortingRecord,
		OwnerAbortClean); err != nil {
		t.Fatalf("persist clean descriptor phase: %v", err)
	}
	if err := device.commitAllocatorSnapshot(entry.desiredClean); err != nil {
		t.Fatalf("commit applied-M clean lock: %v", err)
	}
	run := reservePlan.ReservedDescriptors[0]
	_, offset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	conflict := bytes.Repeat([]byte{0xb6}, PageDescriptorBytes)
	ownerAbortTestInstallLateDescriptorConflict(
		t,
		fixture,
		run.DeviceUUID,
		1,
		offset,
		conflict)
	fixture.resetTracking()
	_, err := fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrOwnerAbortDescriptorDispositionChanged) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("late applied-M descriptor conflict = %v", err)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		offset,
		PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("locked conflict changed: %x", got)
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, abort)
}

func TestOwnerAbortExecutorAppliedQuarantineLockDoesNotRepairLateFree(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	abort, plan, run, conflictOffset, conflict :=
		ownerAbortTestDurableQuarantineEvidence(
			t,
			fixture,
			"applied-q-late-free",
			3)
	entry := plan.devices[0]
	device := fixture.group.devices[entry.deviceIndex].metadata
	if err := device.persistAbortingDescriptorDisposition(
		plan.abortingRecord,
		OwnerAbortQuarantine); err != nil {
		t.Fatalf("persist initial Q descriptors: %v", err)
	}
	if err := device.commitAllocatorSnapshot(entry.desiredQuarantine); err != nil {
		t.Fatalf("commit applied-M Q lock: %v", err)
	}
	_, lateOffset := ownerAbortTestDescriptorWire(t, fixture, run, 1)
	ownerAbortTestInstallLateDescriptorConflict(
		t,
		fixture,
		run.DeviceUUID,
		1,
		lateOffset,
		make([]byte, PageDescriptorBytes))
	fixture.resetTracking()
	_, err := fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrOwnerAbortDescriptorDispositionChanged) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("applied Q late FREE = %v", err)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		lateOffset,
		PageDescriptorBytes); !allZero(got) {
		t.Fatalf("applied Q repaired late FREE: %x", got)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		conflictOffset,
		PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("applied Q changed raw conflict: %x", got)
	}
	if fixture.storages[run.DeviceUUID].writeCalls != 0 ||
		fixture.storages[run.DeviceUUID].mutationCount != 0 {
		t.Fatalf("applied Q late mismatch was written: %#v", *fixture.trace)
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, abort)
}

func TestOwnerAbortExecutorAppliedCleanLockDoesNotRepairLateReserved(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "applied-clean-late-r", 2)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	plan := ownerAbortTestDurableAborting(t, fixture)
	entry := plan.devices[0]
	device := fixture.group.devices[entry.deviceIndex].metadata
	if err := device.persistAbortingDescriptorDisposition(
		plan.abortingRecord,
		OwnerAbortClean); err != nil {
		t.Fatalf("persist initial clean descriptors: %v", err)
	}
	if err := device.commitAllocatorSnapshot(entry.desiredClean); err != nil {
		t.Fatalf("commit applied-M clean lock: %v", err)
	}
	run := reservePlan.ReservedDescriptors[0]
	reservedWire, err := run.Descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal exact RESERVED: %v", err)
	}
	_, lateOffset := ownerAbortTestDescriptorWire(t, fixture, run, 0)
	ownerAbortTestInstallLateDescriptorConflict(
		t,
		fixture,
		run.DeviceUUID,
		1,
		lateOffset,
		reservedWire)
	fixture.resetTracking()
	_, err = fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrOwnerAbortDescriptorDispositionChanged) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("applied clean late RESERVED = %v", err)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		lateOffset,
		PageDescriptorBytes); !bytes.Equal(got, reservedWire) {
		t.Fatalf("applied clean repaired late RESERVED: %x", got)
	}
	if fixture.storages[run.DeviceUUID].writeCalls != 0 ||
		fixture.storages[run.DeviceUUID].mutationCount != 0 {
		t.Fatalf("applied clean late mismatch was written: %#v", *fixture.trace)
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, abort)
}

func TestOwnerAbortExecutorMultiDeviceDurabilityOrder(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a", "device-b", "device-c"},
		"device-c",
		2<<20)
	reserve, abort := ownerAbortTestRequests(
		fixture,
		"multi-order",
		fixture.geometry.DataPageCount+1)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	preparing := reservePlan.PreparingOwnerState.Records()[0]
	for _, deviceUUID := range []string{"device-a", "device-b"} {
		index := -1
		for candidate := range fixture.group.devices {
			if fixture.group.devices[candidate].deviceUUID == deviceUUID {
				index = candidate
				break
			}
		}
		if index < 0 {
			t.Fatalf("missing device %q", deviceUUID)
		}
		if err := fixture.group.devices[index].metadata.
			persistPreparingReservedDescriptors(
				preparing,
				ownerAbortTestRunsForDevice(
					reservePlan.ReservedDescriptors,
					deviceUUID)); err != nil {
			t.Fatalf("persist RESERVED on %q: %v", deviceUUID, err)
		}
	}
	fixture.resetTracking()

	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil || result.Record.State != OwnerAllocationAborted {
		t.Fatalf("multi-device abort = %#v, %v", result, err)
	}
	firstAllocator := -1
	lastAllocator := -1
	firstDescriptor := -1
	descriptorSync := make(map[string]bool)
	allocatorOrder := make([]string, 0, 2)
	seenAllocator := make(map[string]bool)
	ownerEvents := make([]int, 0, 12)
	for index, event := range *fixture.trace {
		if event.region == "content" {
			t.Fatalf("abort wrote content: %#v", event)
		}
		if event.region == "owner" {
			ownerEvents = append(ownerEvents, index)
		}
		if event.region == "descriptor" && firstDescriptor < 0 {
			firstDescriptor = index
		}
		if event.region == "descriptor" && event.kind == "sync" {
			descriptorSync[event.deviceUUID] = true
		}
		if event.region != "allocator" && event.region != "superblock" {
			continue
		}
		if event.deviceUUID != "device-a" && event.deviceUUID != "device-b" {
			continue
		}
		if firstAllocator < 0 {
			firstAllocator = index
			if !descriptorSync["device-a"] || !descriptorSync["device-b"] {
				t.Fatalf("allocator began before all descriptor Syncs: %#v",
					*fixture.trace)
			}
		}
		lastAllocator = index
		if event.region == "allocator" && !seenAllocator[event.deviceUUID] {
			seenAllocator[event.deviceUUID] = true
			allocatorOrder = append(allocatorOrder, event.deviceUUID)
		}
	}
	if firstAllocator < 0 || lastAllocator < firstAllocator ||
		len(allocatorOrder) != 2 || allocatorOrder[0] != "device-a" ||
		allocatorOrder[1] != "device-b" {
		t.Fatalf("allocator ordering = %v, %d..%d, trace=%#v",
			allocatorOrder,
			firstAllocator,
			lastAllocator,
			*fixture.trace)
	}
	if len(ownerEvents) != 12 || firstDescriptor <= ownerEvents[5] ||
		ownerEvents[6] <= lastAllocator {
		t.Fatalf("Owner/descriptor/allocator ordering invalid: owner=%v descriptor=%d allocator=%d",
			ownerEvents,
			firstDescriptor,
			lastAllocator)
	}
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorOwnerCommitEveryFailurePrefixRecovers(t *testing.T) {
	for failMutation := 1; failMutation <= 12; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b"},
				"device-b",
				2<<20)
			reserve, abort := ownerAbortTestRequests(
				fixture,
				fmt.Sprintf("owner-failure-%d", failMutation),
				2)
			ownerAbortTestPreparing(t, fixture, reserve)
			expected := ownerAbortTestExpectedFreshPlan(t, fixture)
			fixture.storages["device-b"].failMutation = failMutation
			_, err := fixture.group.AbortPreparingCheckpoint(abort)
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("Owner mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortClean)
		})
	}
}

func TestOwnerAbortExecutorDescriptorAndAllocatorEveryFailurePrefixRecovers(t *testing.T) {
	// With a FREE selected descriptor, mutation 1 is the mandatory descriptor
	// Sync and mutations 2..13 cover every allocator/superblock header-last
	// write and Sync boundary.
	for failMutation := 1; failMutation <= 13; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b"},
				"device-b",
				2<<20)
			reserve, abort := ownerAbortTestRequests(
				fixture,
				fmt.Sprintf("member-failure-%d", failMutation),
				2)
			ownerAbortTestPreparing(t, fixture, reserve)
			expected := ownerAbortTestExpectedFreshPlan(t, fixture)
			fixture.storages["device-a"].failMutation = failMutation
			_, err := fixture.group.AbortPreparingCheckpoint(abort)
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("member mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortClean)
		})
	}
}

func TestOwnerAbortExecutorDescriptorWriteAndSyncFailurePrefixesRecover(t *testing.T) {
	for failMutation := 1; failMutation <= 2; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b"},
				"device-b",
				2<<20)
			reserve, abort := ownerAbortTestRequests(
				fixture,
				fmt.Sprintf("descriptor-write-%d", failMutation),
				3)
			plan := ownerAbortTestPreparing(t, fixture, reserve)
			preparing := plan.PreparingOwnerState.Records()[0]
			if err := fixture.group.devices[0].metadata.
				persistPreparingReservedDescriptors(
					preparing,
					plan.ReservedDescriptors); err != nil {
				t.Fatalf("persist RESERVED: %v", err)
			}
			fixture.resetTracking()
			expected := ownerAbortTestExpectedFreshPlan(t, fixture)
			fixture.storages["device-a"].failMutation = failMutation
			_, err := fixture.group.AbortPreparingCheckpoint(abort)
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("descriptor mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortClean)
		})
	}
}

func TestOwnerAbortExecutorSecondDeviceEveryFailurePrefixRecovers(t *testing.T) {
	for failMutation := 1; failMutation <= 13; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b", "device-c"},
				"device-c",
				2<<20)
			reserve, abort := ownerAbortTestRequests(
				fixture,
				fmt.Sprintf("second-device-%d", failMutation),
				fixture.geometry.DataPageCount+1)
			ownerAbortTestPreparing(t, fixture, reserve)
			expected := ownerAbortTestExpectedFreshPlan(t, fixture)
			fixture.storages["device-b"].failMutation = failMutation
			_, err := fixture.group.AbortPreparingCheckpoint(abort)
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("second-device mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortClean)
		})
	}
}

func TestOwnerAbortExecutorQuarantineDeviceEveryFailurePrefixRecovers(t *testing.T) {
	// Q disposition has one descriptor write plus Sync followed by the twelve
	// allocator/superblock mutation boundaries.
	for failMutation := 1; failMutation <= 14; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			abort, expected, run, conflictOffset, conflict :=
				ownerAbortTestDurableQuarantineEvidence(
					t,
					fixture,
					fmt.Sprintf("q-device-failure-%d", failMutation),
					3)
			fixture.storages[run.DeviceUUID].failMutation = failMutation
			_, err := fixture.group.RecoverAbortingCheckpoint()
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("Q device mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortQuarantine)
			if got := fixture.storages[run.DeviceUUID].rawBytes(
				conflictOffset,
				PageDescriptorBytes); !bytes.Equal(got, conflict) {
				t.Fatalf("Q failure %d changed conflict: %x", failMutation, got)
			}
		})
	}
}

func TestOwnerAbortExecutorQuarantineTerminalOwnerEveryFailurePrefixRecovers(t *testing.T) {
	for failMutation := 1; failMutation <= 6; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b"},
				"device-b",
				2<<20)
			abort, expected, run, conflictOffset, conflict :=
				ownerAbortTestDurableQuarantineEvidence(
					t,
					fixture,
					fmt.Sprintf("q-owner-failure-%d", failMutation),
					3)
			if len(expected.devices) != 1 ||
				expected.devices[0].deviceUUID != "device-a" {
				t.Fatalf("Q terminal affected devices = %#v", expected.devices)
			}
			entry := expected.devices[0]
			device := fixture.group.devices[entry.deviceIndex].metadata
			if err := device.persistAbortingDescriptorDisposition(
				expected.abortingRecord,
				OwnerAbortQuarantine); err != nil {
				t.Fatalf("persist Q before terminal failure: %v", err)
			}
			if err := device.commitAllocatorSnapshot(
				entry.desiredQuarantine); err != nil {
				t.Fatalf("commit Q allocator before terminal failure: %v", err)
			}
			fixture.resetTracking()
			fixture.storages["device-b"].failMutation = failMutation
			_, err := fixture.group.RecoverAbortingCheckpoint()
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("Q terminal Owner mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortQuarantine)
			if got := fixture.storages[run.DeviceUUID].rawBytes(
				conflictOffset,
				PageDescriptorBytes); !bytes.Equal(got, conflict) {
				t.Fatalf("Q terminal failure %d changed conflict: %x",
					failMutation,
					got)
			}
		})
	}
}

func TestOwnerAbortExecutorQuarantineSecondDeviceEveryFailurePrefixRecovers(t *testing.T) {
	for failMutation := 1; failMutation <= 14; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b", "device-c"},
				"device-c",
				2<<20)
			abort, expected, run, conflictOffset, conflict :=
				ownerAbortTestDurableQuarantineEvidence(
					t,
					fixture,
					fmt.Sprintf("q-second-failure-%d", failMutation),
					fixture.geometry.DataPageCount+1)
			if len(expected.devices) != 2 ||
				expected.devices[1].deviceUUID != "device-b" {
				t.Fatalf("Q multi-device plan = %#v", expected.devices)
			}
			fixture.storages["device-b"].failMutation = failMutation
			_, err := fixture.group.RecoverAbortingCheckpoint()
			if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("Q second-device mutation %d error = %v", failMutation, err)
			}
			ownerAbortTestAssertPoisonThenReopenRecovery(
				t,
				fixture,
				abort,
				expected,
				OwnerAbortQuarantine)
			if got := fixture.storages[run.DeviceUUID].rawBytes(
				conflictOffset,
				PageDescriptorBytes); !bytes.Equal(got, conflict) {
				t.Fatalf("Q second-device failure %d changed conflict: %x",
					failMutation,
					got)
			}
		})
	}
}

func ownerAbortTestAssertStickyOfflineZeroIO(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	abort OwnerPreparingAbortRequest,
) {
	t.Helper()
	fixture.resetTracking()
	if _, _, err := fixture.group.PlannerInputs(); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("offline PlannerInputs = %v", err)
	}
	if _, err := fixture.group.AbortPreparingCheckpoint(abort); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("offline AbortPreparingCheckpoint = %v", err)
	}
	if _, err := fixture.group.RecoverAbortingCheckpoint(); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("offline RecoverAbortingCheckpoint = %v", err)
	}
	if _, err := fixture.group.ExecuteCheckpointReserve(
		fixture.request("offline-reserve", 1)); !errors.Is(
		err,
		ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("offline ExecuteCheckpointReserve = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerAbortExecutorPreparingBesideTransitionLatchesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	first := fixture.request("prior-terminal", 1)
	if _, err := fixture.group.ExecuteCheckpointReserve(first); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	secondReserve, secondAbort := ownerAbortTestRequests(
		fixture,
		"preparing-beside-transition",
		1)
	secondAbort.AllocationRecordID = 2
	plan := fixture.plan(t, secondReserve)
	records := plan.PreparingOwnerState.Records()
	records[0].State = OwnerAllocationCanceling
	malformed := ownerReserveExecutorSnapshotWithRecords(
		t,
		plan.PreparingOwnerState,
		records)
	if err := fixture.group.anchor.commitOwnerState(malformed); err != nil {
		t.Fatalf("commit malformed PREPARING state: %v", err)
	}
	fixture.resetTracking()

	_, err := fixture.group.AbortPreparingCheckpoint(secondAbort)
	if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("PREPARING transitional contradiction = %v", err)
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, secondAbort)
}

func TestOwnerAbortExecutorAbortingBesideTransitionLatchesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	first := fixture.request("prior-aborting-terminal", 1)
	if _, err := fixture.group.ExecuteCheckpointReserve(first); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	secondReserve, secondAbort := ownerAbortTestRequests(
		fixture,
		"aborting-beside-transition",
		1)
	secondAbort.AllocationRecordID = 2
	reservePlan := fixture.plan(t, secondReserve)
	fixture.commitPreparing(t, reservePlan)
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil || !present {
		t.Fatalf("active PREPARING = %#v, %v", preparing, err)
	}
	abortPlan, err := fixture.group.preflightFreshPreparingAbortLocked(
		ownerState,
		preparing)
	if err != nil {
		t.Fatalf("preflight abort: %v", err)
	}
	records := abortPlan.abortingState.Records()
	records[0].State = OwnerAllocationCommitting
	records[0].OwnerVerifiedSealSHA256 = ownerStateTestSealSHA256()
	malformed := ownerReserveExecutorSnapshotWithRecords(
		t,
		abortPlan.abortingState,
		records)
	if err := fixture.group.anchor.commitOwnerState(malformed); err != nil {
		t.Fatalf("commit malformed ABORTING state: %v", err)
	}
	fixture.resetTracking()

	_, err = fixture.group.AbortPreparingCheckpoint(secondAbort)
	if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("ABORTING transitional contradiction = %v", err)
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, secondAbort)
}

func TestOwnerAbortExecutorDescriptorReadPreflightIsZeroWrite(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "descriptor-read-preflight", 2)
	plan := ownerAbortTestPreparing(t, fixture, reserve)
	_, offset := ownerAbortTestDescriptorWire(
		t,
		fixture,
		plan.ReservedDescriptors[0],
		0)
	fixture.storages["device-a"].failReadOffset = &offset
	_, err := fixture.group.AbortPreparingCheckpoint(abort)
	if !errors.Is(err, ErrDeviceMetadataStorage) ||
		errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("descriptor preflight error = %v", err)
	}
	if fixture.storages["device-a"].writeCalls != 0 ||
		fixture.storages["device-a"].mutationCount != 0 ||
		len(*fixture.trace) != 0 {
		t.Fatalf("descriptor preflight mutated storage: %#v", *fixture.trace)
	}
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs after read failure: %v", err)
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil || !present || preparing.State != OwnerAllocationPreparing {
		t.Fatalf("Owner state after read failure = %#v, %v", preparing, err)
	}

	fixture.resetTracking()
	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil || result.Record.State != OwnerAllocationAborted {
		t.Fatalf("retry after read failure = %#v, %v", result, err)
	}
}

func TestOwnerAbortExecutorShortReadFailureClassification(t *testing.T) {
	t.Run("pre-ABORTING-is-retryable-without-recovery", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t,
			[]string{"device-a"},
			"device-a",
			2<<20)
		reserve, abort := ownerAbortTestRequests(fixture, "short-read-preparing", 2)
		ownerAbortTestPreparing(t, fixture, reserve)
		fixture.storages["device-a"].shortReadCall = 1
		_, err := fixture.group.AbortPreparingCheckpoint(abort)
		if !errors.Is(err, ErrDeviceMetadataStorage) ||
			errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
			errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
			errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
			t.Fatalf("PREPARING short read = %v", err)
		}
		if fixture.storages["device-a"].writeCalls != 0 ||
			fixture.storages["device-a"].mutationCount != 0 {
			t.Fatalf("PREPARING short read mutated storage: %#v", *fixture.trace)
		}
		fixture.resetTracking()
		if _, err := fixture.group.AbortPreparingCheckpoint(abort); err != nil {
			t.Fatalf("retry PREPARING short read: %v", err)
		}
	})

	t.Run("durable-ABORTING-needs-recovery-without-reopen", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t,
			[]string{"device-a"},
			"device-a",
			2<<20)
		reserve, _ := ownerAbortTestRequests(fixture, "short-read-aborting", 2)
		ownerAbortTestPreparing(t, fixture, reserve)
		ownerAbortTestDurableAborting(t, fixture)
		fixture.storages["device-a"].shortReadCall = 1
		_, err := fixture.group.RecoverAbortingCheckpoint()
		if !errors.Is(err, ErrDeviceMetadataStorage) ||
			!errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
			errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
			errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
			t.Fatalf("ABORTING short read = %v", err)
		}
		if fixture.storages["device-a"].writeCalls != 0 ||
			fixture.storages["device-a"].mutationCount != 0 {
			t.Fatalf("ABORTING short read mutated storage: %#v", *fixture.trace)
		}
		fixture.resetTracking()
		result, err := fixture.group.RecoverAbortingCheckpoint()
		if err != nil || result.Record.State != OwnerAllocationAborted ||
			!result.ForwardRecovered {
			t.Fatalf("retry ABORTING short read = %#v, %v", result, err)
		}
	})
}

func TestOwnerAbortExecutorRefreshReadFailurePoisonsReopen(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "refresh-read", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	expected := ownerAbortTestExpectedFreshPlan(t, fixture)
	offset := fixture.geometry.SuperblockAOffset
	fixture.storages["device-a"].failReadOffset = &offset
	_, err := fixture.group.AbortPreparingCheckpoint(abort)
	if !errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("refresh read failure = %v", err)
	}
	ownerAbortTestAssertPoisonThenReopenRecovery(
		t,
		fixture,
		abort,
		expected,
		OwnerAbortClean)
}

func TestOwnerAbortExecutorDescriptorMultiBatchShortWriteRecovers(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		16<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "multi-batch-short-write", 2050)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	preparing := reservePlan.PreparingOwnerState.Records()[0]
	if err := fixture.group.devices[0].metadata.
		persistPreparingReservedDescriptors(
			preparing,
			reservePlan.ReservedDescriptors); err != nil {
		t.Fatalf("persist multi-batch RESERVED: %v", err)
	}
	fixture.resetTracking()
	expected := ownerAbortTestDurableAborting(t, fixture)
	fixture.storages["device-a"].shortWriteCall = 2
	_, err := fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrDeviceMetadataStorage) ||
		!errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("multi-batch short write = %v", err)
	}
	if fixture.storages["device-a"].maxWrite > reservedDescriptorIOBatchBytes {
		t.Fatalf("descriptor write batch = %d, max %d",
			fixture.storages["device-a"].maxWrite,
			reservedDescriptorIOBatchBytes)
	}
	ownerAbortTestAssertPoisonThenReopenRecovery(
		t,
		fixture,
		abort,
		expected,
		OwnerAbortClean)
}

func TestOwnerAbortExecutorGenuineTornQuarantineWritePreservesRawAndRecovers(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	abort, expected, run, conflictOffset, conflict :=
		ownerAbortTestDurableQuarantineEvidence(
			t,
			fixture,
			"genuine-torn-q-write",
			3)
	if run.PageCount < 3 {
		t.Fatalf("Q torn fixture page count = %d", run.PageCount)
	}
	_, tornOffset := ownerAbortTestDescriptorWire(t, fixture, run, 1)
	wrapper := ownerAbortTestInstallPartialWrite(
		t,
		fixture,
		run.DeviceUUID,
		1,
		24)
	fixture.resetTracking()
	_, err := fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrDeviceMetadataStorage) ||
		!errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("genuine torn Q write = %v", err)
	}
	torn := fixture.storages[run.DeviceUUID].rawBytes(
		tornOffset,
		PageDescriptorBytes)
	preparing := cloneOwnerStateRecord(expected.abortingRecord)
	preparing.State = OwnerAllocationPreparing
	preparing.OwnerTransactionSequence--
	runs, err := ownerReserveDescriptorsFromRecord(preparing)
	if err != nil || len(runs) == 0 {
		t.Fatalf("derive torn expected descriptor: %v", err)
	}
	reservedWire, err := runs[0].Descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal expected RESERVED: %v", err)
	}
	quarantined := runs[0].Descriptor
	quarantined.State = DescriptorQuarantined
	quarantined.OwnerTransactionSeq = expected.abortingRecord.OwnerTransactionSequence
	quarantinedWire, err := quarantined.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal expected Q: %v", err)
	}
	if class := classifyOwnerAbortDescriptor(
		torn,
		reservedWire,
		quarantinedWire); class != ownerAbortDescriptorConflict {
		t.Fatalf("partial Q write class = %d, wire=%x", class, torn)
	}
	wrapper.enabled = false
	ownerAbortTestAssertPoisonThenReopenRecovery(
		t,
		fixture,
		abort,
		expected,
		OwnerAbortQuarantine)
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		tornOffset,
		PageDescriptorBytes); !bytes.Equal(got, torn) {
		t.Fatalf("recovery changed torn descriptor: got=%x want=%x", got, torn)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		conflictOffset,
		PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("recovery changed original conflict: got=%x want=%x", got, conflict)
	}
}

func TestOwnerAbortExecutorMetadataIOIsBounded(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		16<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "metadata-io-bound", 2050)
	reservePlan := ownerAbortTestPreparing(t, fixture, reserve)
	preparing := reservePlan.PreparingOwnerState.Records()[0]
	if err := fixture.group.devices[0].metadata.
		persistPreparingReservedDescriptors(
			preparing,
			reservePlan.ReservedDescriptors); err != nil {
		t.Fatalf("persist bounded-I/O RESERVED: %v", err)
	}
	fixture.resetTracking()
	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil || result.Record.State != OwnerAllocationAborted {
		t.Fatalf("bounded metadata abort = %#v, %v", result, err)
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.maxRead > reservedDescriptorIOBatchBytes ||
			storage.maxWrite > reservedDescriptorIOBatchBytes {
			t.Fatalf("device %q metadata I/O read/write = %d/%d, max %d",
				deviceUUID,
				storage.maxRead,
				storage.maxWrite,
				reservedDescriptorIOBatchBytes)
		}
	}
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorDeterministicPreflightsBeforeMutation(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*ownerReserveExecutorTestFixture) func()
		wantErr error
	}{
		{
			name: "owner-read-limit",
			mutate: func(fixture *ownerReserveExecutorTestFixture) func() {
				original := fixture.group.anchor.ownerStateReadLimitBytes
				fixture.group.anchor.ownerStateReadLimitBytes =
					OwnerStateEnvelopeHeaderBytes
				return func() {
					fixture.group.anchor.ownerStateReadLimitBytes = original
				}
			},
			wantErr: ErrDeviceMetadataOwnerStateReadLimit,
		},
		{
			name: "allocator-superblock-overflow",
			mutate: func(fixture *ownerReserveExecutorTestFixture) func() {
				original := fixture.group.devices[0].metadata.superblock.
					SuperblockSequence
				fixture.group.devices[0].metadata.superblock.SuperblockSequence =
					cxlcheckpoint.MaxSignedLong
				return func() {
					fixture.group.devices[0].metadata.superblock.SuperblockSequence =
						original
				}
			},
			wantErr: ErrDeviceMetadataSequence,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b"},
				"device-b",
				2<<20)
			reserve, abort := ownerAbortTestRequests(
				fixture,
				"preflight-"+test.name,
				1)
			ownerAbortTestPreparing(t, fixture, reserve)
			restore := test.mutate(fixture)
			_, err := fixture.group.AbortPreparingCheckpoint(abort)
			if !errors.Is(err, test.wantErr) ||
				errors.Is(err, ErrOwnerAbortRecoveryRequired) {
				t.Fatalf("preflight error = %v, want %v", err, test.wantErr)
			}
			for deviceUUID, storage := range fixture.storages {
				if storage.writeCalls != 0 || storage.mutationCount != 0 {
					t.Fatalf("device %q mutated in preflight: %#v",
						deviceUUID,
						storage.events)
				}
			}
			restore()
			fixture.resetTracking()
			result, err := fixture.group.AbortPreparingCheckpoint(abort)
			if err != nil || result.Record.State != OwnerAllocationAborted {
				t.Fatalf("retry after preflight = %#v, %v", result, err)
			}
		})
	}
}

func TestOwnerAbortExecutorInitialAbortingCommitPreMutationFailureStaysPreparing(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "initial-commit-preflight", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	drift := ownerAbortTestInstallSizeDrift(
		t,
		fixture,
		"device-a",
		fixture.geometry.DescriptorRegionBase,
		fixture.geometry.ContentRegionBase)
	fixture.resetTracking()
	_, err := fixture.group.AbortPreparingCheckpoint(abort)
	if !errors.Is(err, ErrDeviceMetadataSizeMismatch) ||
		errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("initial ABORTING commit pre-mutation error = %v", err)
	}
	if fixture.storages["device-a"].writeCalls != 0 ||
		fixture.storages["device-a"].mutationCount != 0 {
		t.Fatalf("initial commit preflight mutated storage: %#v", *fixture.trace)
	}
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs after initial commit preflight: %v", err)
	}
	preparing, present, err := ownerReserveActivePreparing(ownerState)
	if err != nil || !present || preparing.State != OwnerAllocationPreparing {
		t.Fatalf("state after initial commit preflight = %#v, %v", preparing, err)
	}

	drift.enabled = false
	drift.armed = false
	fixture.resetTracking()
	result, err := fixture.group.AbortPreparingCheckpoint(abort)
	if err != nil || result.Record.State != OwnerAllocationAborted {
		t.Fatalf("retry initial commit preflight = %#v, %v", result, err)
	}
}

func TestOwnerAbortExecutorPostRefreshOperationalPreflightNeedsRecoveryNotOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "post-refresh-preflight", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	drift := ownerAbortTestInstallSizeDrift(
		t,
		fixture,
		"device-a",
		fixture.geometry.OwnerStateSnapshotAOffset,
		fixture.geometry.DescriptorRegionBase)
	fixture.resetTracking()
	_, err := fixture.group.AbortPreparingCheckpoint(abort)
	if !errors.Is(err, ErrDeviceMetadataSizeMismatch) ||
		!errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("post-refresh operational preflight = %v", err)
	}
	ownerState, _, plannerErr := fixture.group.PlannerInputs()
	if plannerErr != nil {
		t.Fatalf("PlannerInputs after operational preflight: %v", plannerErr)
	}
	if _, present, activeErr := ownerAbortActiveAborting(ownerState); activeErr != nil || !present {
		t.Fatalf("state after operational preflight = %#v, %v", ownerState, activeErr)
	}

	drift.enabled = false
	drift.armed = false
	fixture.resetTracking()
	result, err := fixture.group.RecoverAbortingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationAborted ||
		!result.ForwardRecovered {
		t.Fatalf("post-refresh preflight recovery = %#v, %v", result, err)
	}
}

func TestOwnerAbortExecutorDurableAbortingTerminalPreflightBeforeDisposition(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, _ := ownerAbortTestRequests(fixture, "terminal-preflight", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	ownerAbortTestDurableAborting(t, fixture)
	original := fixture.group.anchor.ownerStateReadLimitBytes
	fixture.group.anchor.ownerStateReadLimitBytes = OwnerStateEnvelopeHeaderBytes
	_, err := fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) ||
		!errors.Is(err, ErrOwnerAbortRecoveryRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("durable ABORTING terminal preflight = %v", err)
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.writeCalls != 0 || storage.mutationCount != 0 {
			t.Fatalf("device %q mutated before terminal preflight: %#v",
				deviceUUID,
				storage.events)
		}
	}
	fixture.group.anchor.ownerStateReadLimitBytes = original
	fixture.resetTracking()
	result, err := fixture.group.RecoverAbortingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationAborted ||
		!result.ForwardRecovered {
		t.Fatalf("retry terminal preflight = %#v, %v", result, err)
	}
}

func TestOwnerAbortExecutorDurableAbortingTransactionExhaustionGoesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "aborting-transaction-exhaustion", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	plan := ownerAbortTestExpectedFreshPlan(t, fixture)
	record := cloneOwnerStateRecord(plan.abortingRecord)
	record.ReservationTransactionSequence = cxlcheckpoint.MaxSignedLong - 2
	record.OwnerTransactionSequence = cxlcheckpoint.MaxSignedLong - 1
	exhausted, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    plan.abortingState.ClusterID,
		OwnerGroupID:                 plan.abortingState.OwnerGroupID,
		CurrentOwnerID:               plan.abortingState.CurrentOwnerID,
		AnchorDeviceUUID:             plan.abortingState.AnchorDeviceUUID,
		StorageCompatibilityID:       plan.abortingState.StorageCompatibilityID,
		OwnerEpoch:                   plan.abortingState.OwnerEpoch,
		GroupConfigurationSequence:   plan.abortingState.GroupConfigurationSequence,
		MembershipSHA256:             plan.abortingState.MembershipSHA256,
		SnapshotSequence:             plan.abortingState.SnapshotSequence,
		NextAllocationRecordID:       plan.abortingState.NextAllocationRecordID,
		NextOwnerTransactionSequence: cxlcheckpoint.MaxSignedLong,
		Devices:                      plan.abortingState.Devices(),
		Records:                      []OwnerStateAllocationRecord{record},
	})
	if err != nil {
		t.Fatalf("build valid exhausted ABORTING state: %v", err)
	}
	if err := fixture.group.anchor.commitOwnerState(exhausted); err != nil {
		t.Fatalf("commit exhausted ABORTING state: %v", err)
	}
	fixture.reopen(t)
	fixture.resetTracking()
	_, err = fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrOwnerReserveSequenceOverflow) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		errors.Is(err, ErrOwnerAbortRecoveryRequired) {
		t.Fatalf("durable ABORTING transaction exhaustion = %v", err)
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.writeCalls != 0 || storage.mutationCount != 0 {
			t.Fatalf("device %q mutated before exhaustion OFFLINE: %#v",
				deviceUUID,
				storage.events)
		}
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, abort)
}

func TestOwnerAbortExecutorDurableAbortingSuperblockExhaustionGoesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "aborting-superblock-exhaustion", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	ownerAbortTestDurableAborting(t, fixture)
	device := fixture.group.devices[0].metadata
	exhausted := device.superblock
	exhausted.SuperblockSequence = cxlcheckpoint.MaxSignedLong
	wire, err := CanonicalSuperblockBytes(exhausted)
	if err != nil {
		t.Fatalf("marshal exhausted superblock: %v", err)
	}
	targetSlot := otherSuperblockSlot(device.superblockSlot)
	offset, err := superblockSlotOffset(fixture.geometry, targetSlot)
	if err != nil {
		t.Fatalf("exhausted superblock offset: %v", err)
	}
	fixture.storages["device-a"].rawWrite(offset, wire)
	fixture.reopen(t)
	fixture.resetTracking()
	_, err = fixture.group.RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrDeviceMetadataSequence) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) ||
		!errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		errors.Is(err, ErrOwnerAbortRecoveryRequired) {
		t.Fatalf("durable ABORTING superblock exhaustion = %v", err)
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.writeCalls != 0 || storage.mutationCount != 0 {
			t.Fatalf("device %q mutated before superblock OFFLINE: %#v",
				deviceUUID,
				storage.events)
		}
	}
	ownerAbortTestAssertStickyOfflineZeroIO(t, fixture, abort)
}

func TestOwnerAbortExecutorMixedAppliedAbortBitmapGoesOffline(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, _ := ownerAbortTestRequests(fixture, "mixed-bitmap", 2)
	ownerAbortTestPreparing(t, fixture, reserve)
	plan := ownerAbortTestDurableAborting(t, fixture)
	entry := plan.devices[0]
	device := fixture.group.devices[entry.deviceIndex].metadata
	bitmap := device.allocator.BitmapBytes()
	firstExtent := entry.fragment.Extents[0]
	ownerAllocatorSetBitmap(bitmap, firstExtent.StartDataPageIndex)
	mixed, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             device.allocator.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        device.allocator.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      device.allocator.OwnerEpoch,
		SnapshotSequence:                entry.fragment.TargetAllocatorSnapshotSequence,
		AppliedOwnerTransactionSequence: plan.abortingRecord.OwnerTransactionSequence,
		DataPageCount:                   device.allocator.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("NewAllocatorSnapshot: %v", err)
	}
	if err := device.commitAllocatorSnapshot(mixed); err != nil {
		t.Fatalf("commit mixed allocator: %v", err)
	}
	_, err = fixture.reopen(t).RecoverAbortingCheckpoint()
	if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerAbortDurableContradiction) {
		t.Fatalf("mixed bitmap error = %v", err)
	}
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorRejectsShallowCopyWithoutIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	_, abort := ownerAbortTestRequests(fixture, "copy", 1)
	copyValue := *fixture.group
	copyGroup := &copyValue
	if _, err := copyGroup.AbortPreparingCheckpoint(abort); !errors.Is(
		err,
		ErrOwnerDeviceGroupInput) {
		t.Fatalf("copied AbortPreparingCheckpoint = %v", err)
	}
	if _, err := copyGroup.RecoverAbortingCheckpoint(); !errors.Is(
		err,
		ErrOwnerDeviceGroupInput) {
		t.Fatalf("copied RecoverAbortingCheckpoint = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerAbortExecutorConcurrentExactRequestSerializes(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "concurrent", 4)
	ownerAbortTestPreparing(t, fixture, reserve)
	start := make(chan struct{})
	results := make([]OwnerAbortExecutionResult, 2)
	errorsByIndex := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errorsByIndex[index] =
				fixture.group.AbortPreparingCheckpoint(abort)
		}(index)
	}
	close(start)
	wait.Wait()
	fresh := 0
	replay := 0
	for index := range results {
		if errorsByIndex[index] != nil {
			t.Fatalf("abort %d: %v", index, errorsByIndex[index])
		}
		if results[index].Record.State != OwnerAllocationAborted {
			t.Fatalf("abort %d result = %#v", index, results[index])
		}
		if results[index].Replayed {
			replay++
		} else {
			fresh++
		}
	}
	if fresh != 1 || replay != 1 {
		t.Fatalf("fresh/replay = %d/%d, results=%#v", fresh, replay, results)
	}
	fixture.assertPayloads(t)
}

func TestOwnerAbortExecutorConcurrentPlannerInputsNeverObservesIntermediateState(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a", "device-b"},
		"device-b",
		2<<20)
	reserve, abort := ownerAbortTestRequests(fixture, "concurrent-planner", 4)
	ownerAbortTestPreparing(t, fixture, reserve)
	start := make(chan struct{})
	type plannerResult struct {
		state OwnerAllocationState
		err   error
	}
	plannerResults := make([]plannerResult, 32)
	var abortResult OwnerAbortExecutionResult
	var abortErr error
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		abortResult, abortErr = fixture.group.AbortPreparingCheckpoint(abort)
	}()
	for index := range plannerResults {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			ownerState, _, err := fixture.group.PlannerInputs()
			plannerResults[index].err = err
			if err != nil {
				return
			}
			record, found := reservedDescriptorOwnerRecord(
				ownerState,
				abort.AllocationRecordID)
			if !found {
				plannerResults[index].err = errors.New("allocation record missing")
				return
			}
			plannerResults[index].state = record.State
		}(index)
	}
	close(start)
	wait.Wait()
	if abortErr != nil || abortResult.Record.State != OwnerAllocationAborted {
		t.Fatalf("concurrent abort = %#v, %v", abortResult, abortErr)
	}
	for index, result := range plannerResults {
		if result.err != nil ||
			(result.state != OwnerAllocationPreparing &&
				result.state != OwnerAllocationAborted) {
			t.Fatalf("PlannerInputs %d observed state/error %d/%v",
				index,
				result.state,
				result.err)
		}
	}
	fixture.assertPayloads(t)
}
