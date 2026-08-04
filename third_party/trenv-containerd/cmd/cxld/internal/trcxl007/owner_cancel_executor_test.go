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

type ownerCancelReadTraceStorage struct {
	*ownerReserveExecutorTestStorage
}

func (storage *ownerCancelReadTraceStorage) ReadAt(
	destination []byte,
	offset int64,
) (int, error) {
	read, err := storage.metadataTestStorage.ReadAt(destination, offset)
	*storage.trace = append(*storage.trace, ownerReserveExecutorTestEvent{
		deviceUUID: storage.deviceUUID,
		kind:       "read",
		region:     storage.region(offset),
		offset:     uint64(offset),
		length:     read,
		err:        err != nil || read != len(destination),
	})
	return read, err
}

type ownerCancelCorruptAfterContentSyncStorage struct {
	*ownerReserveExecutorTestStorage
	contentOffset uint64
	armed         bool
}

func (storage *ownerCancelCorruptAfterContentSyncStorage) Sync() error {
	err := storage.ownerReserveExecutorTestStorage.Sync()
	if err == nil && storage.armed && storage.lastRegion == "content" {
		storage.rawWrite(storage.contentOffset, []byte{0x7f})
		storage.armed = false
	}
	return err
}

func ownerCancelTestGrant(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	id string,
	pages uint64,
) (OwnerReserveRequest, OwnerStateAllocationRecord) {
	t.Helper()
	reserve := fixture.request(id, pages)
	result, err := fixture.group.ExecuteCheckpointReserve(reserve)
	if err != nil {
		t.Fatalf("ExecuteCheckpointReserve(%q): %v", id, err)
	}
	if result.Record.State != OwnerAllocationGranted {
		t.Fatalf("grant %q state = %d", id, result.Record.State)
	}
	ownerCancelTestSeedSelectedContent(t, fixture, result.Record)
	fixture.resetTracking()
	return reserve, result.Record
}

func ownerCancelTestRequest(
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
) OwnerGrantedCancelRequest {
	bootstrap := fixture.input.OwnerStateBootstrap
	return OwnerGrantedCancelRequest{
		ClusterID:                  bootstrap.ClusterID,
		OwnerGroupID:               bootstrap.OwnerGroupID,
		CurrentOwnerID:             bootstrap.CurrentOwnerID,
		AnchorDeviceUUID:           bootstrap.AnchorDeviceUUID,
		StorageCompatibilityID:     bootstrap.StorageCompatibilityID,
		OwnerEpoch:                 bootstrap.OwnerEpoch,
		GroupConfigurationSequence: bootstrap.GroupConfigurationSequence,
		MembershipSHA256:           bootstrap.MembershipSHA256,
		AllocationRecordID:         record.AllocationRecordID,
		RequestID:                  record.RequestID,
		CheckpointID:               record.CheckpointID,
		ProducerID:                 record.ProducerID,
		ProducerCapabilitySHA256:   record.AuthorityEvidence.ProducerCapabilitySHA256,
		ProducerWriteFenceSHA256: sha256.Sum256([]byte(
			OwnerGrantedCancelFenceDigestDomain + ":" + record.CheckpointID)),
		ReclaimAuthoritySHA256: record.AuthorityEvidence.ReclaimAuthoritySHA256,
	}
}

func ownerCancelTestSeedSelectedContent(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
) {
	t.Helper()
	for _, fragment := range record.Fragments {
		storage := fixture.storages[fragment.DeviceUUID]
		for _, extent := range fragment.Extents {
			for page := uint64(0); page < extent.PageCount; page++ {
				offset, err := fixture.geometry.ContentOffset(
					extent.StartDataPageIndex + page)
				if err != nil {
					t.Fatalf("ContentOffset: %v", err)
				}
				storage.rawWrite(offset, []byte{0xa5})
				storage.rawWrite(offset+uint64(ContentPageBytes)-1, []byte{0x5a})
			}
		}
	}
}

func ownerCancelTestAssertSelectedContentZero(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
) {
	t.Helper()
	for _, fragment := range record.Fragments {
		storage := fixture.storages[fragment.DeviceUUID]
		for _, extent := range fragment.Extents {
			for page := uint64(0); page < extent.PageCount; page++ {
				offset, err := fixture.geometry.ContentOffset(
					extent.StartDataPageIndex + page)
				if err != nil {
					t.Fatalf("ContentOffset: %v", err)
				}
				if got := storage.rawBytes(offset, ContentPageBytes); !allZero(got) {
					t.Fatalf("device %q data page %d is not zero",
						fragment.DeviceUUID,
						extent.StartDataPageIndex+page)
				}
			}
		}
	}
}

func ownerCancelTestSelectedContent(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
) map[string][][]byte {
	t.Helper()
	result := make(map[string][][]byte)
	for _, fragment := range record.Fragments {
		storage := fixture.storages[fragment.DeviceUUID]
		for _, extent := range fragment.Extents {
			for page := uint64(0); page < extent.PageCount; page++ {
				offset, err := fixture.geometry.ContentOffset(
					extent.StartDataPageIndex + page)
				if err != nil {
					t.Fatalf("ContentOffset: %v", err)
				}
				result[fragment.DeviceUUID] = append(
					result[fragment.DeviceUUID],
					storage.rawBytes(offset, ContentPageBytes))
			}
		}
	}
	return result
}

func ownerCancelTestAssertSelectedContentEqual(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	record OwnerStateAllocationRecord,
	want map[string][][]byte,
) {
	t.Helper()
	got := ownerCancelTestSelectedContent(t, fixture, record)
	for deviceUUID := range want {
		if len(got[deviceUUID]) != len(want[deviceUUID]) {
			t.Fatalf("device %q content page count = %d, want %d",
				deviceUUID, len(got[deviceUUID]), len(want[deviceUUID]))
		}
		for page := range want[deviceUUID] {
			if !bytes.Equal(got[deviceUUID][page], want[deviceUUID][page]) {
				t.Fatalf("device %q selected page %d changed", deviceUUID, page)
			}
		}
	}
}

func ownerCancelTestDurableCanceling(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	granted OwnerStateAllocationRecord,
) ownerCancelRecoveryPlan {
	t.Helper()
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	plan, err := fixture.group.preflightFreshGrantedCancelLocked(ownerState, granted)
	if err != nil {
		t.Fatalf("preflightFreshGrantedCancelLocked: %v", err)
	}
	if err := fixture.group.anchor.commitOwnerState(plan.cancelingState); err != nil {
		t.Fatalf("commit CANCELING: %v", err)
	}
	fixture.resetTracking()
	return plan
}

func ownerCancelTestAssertPoisonThenReopenRecovery(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	request OwnerGrantedCancelRequest,
	wantDisposition OwnerCancelDisposition,
) OwnerCancelExecutionResult {
	t.Helper()
	fixture.resetTracking()
	if _, err := fixture.group.CancelGrantedCheckpoint(request); !errors.Is(
		err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("poisoned CancelGrantedCheckpoint = %v", err)
	}
	fixture.assertZeroIO(t)
	group := fixture.reopen(t)
	before, _, err := group.PlannerInputs()
	if err != nil {
		t.Fatalf("post-reopen PlannerInputs: %v", err)
	}
	beforeRecord, found := reservedDescriptorOwnerRecord(
		before, request.AllocationRecordID)
	if !found {
		t.Fatalf("post-reopen state lost allocation %d", request.AllocationRecordID)
	}
	wantForwardRecovered := beforeRecord.State == OwnerAllocationCanceling
	wantReplayed := beforeRecord.State == OwnerAllocationCanceled ||
		beforeRecord.State == OwnerAllocationQuarantined
	switch beforeRecord.State {
	case OwnerAllocationGranted,
		OwnerAllocationCanceling,
		OwnerAllocationCanceled,
		OwnerAllocationQuarantined:
	default:
		t.Fatalf("post-reopen allocation state = %d", beforeRecord.State)
	}
	fixture.resetTracking()
	result, err := group.CancelGrantedCheckpoint(request)
	if err != nil {
		t.Fatalf("post-reopen cancellation recovery = %#v, %v", result, err)
	}
	wantState := OwnerAllocationCanceled
	wantUnavailable := false
	if wantDisposition == OwnerCancelQuarantine {
		wantState = OwnerAllocationQuarantined
		wantUnavailable = true
	}
	if result.Record.State != wantState ||
		result.Disposition != wantDisposition ||
		result.ForwardRecovered != wantForwardRecovered ||
		result.Replayed != wantReplayed ||
		result.Record.AllocationRecordID != request.AllocationRecordID ||
		result.Record.RequestID != request.RequestID ||
		result.Record.CheckpointID != request.CheckpointID ||
		result.Record.ProducerID != request.ProducerID ||
		result.Record.AuthorityEvidence.ProducerCapabilitySHA256 !=
			request.ProducerCapabilitySHA256 ||
		result.Record.AuthorityEvidence.ReclaimAuthoritySHA256 !=
			request.ReclaimAuthoritySHA256 {
		t.Fatalf("exact recovered cancellation result = %#v", result)
	}
	ownerAbortTestAssertAllocatorPages(
		t,
		fixture,
		result.Record,
		wantUnavailable,
		result.Record.OwnerTransactionSequence-1)
	if wantDisposition == OwnerCancelClean {
		ownerCancelTestAssertSelectedContentZero(t, fixture, result.Record)
	}
	return result
}

func ownerCancelTestDevice(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	deviceUUID string,
) *DeviceMetadata {
	t.Helper()
	for index := range fixture.group.devices {
		if fixture.group.devices[index].deviceUUID == deviceUUID {
			return fixture.group.devices[index].metadata
		}
	}
	t.Fatalf("missing opened device %q", deviceUUID)
	return nil
}

func ownerCancelTestInstallReadTrace(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	deviceUUID string,
) {
	t.Helper()
	base := fixture.storages[deviceUUID]
	wrapper := &ownerCancelReadTraceStorage{ownerReserveExecutorTestStorage: base}
	ownerCancelTestInstallStorage(t, fixture, deviceUUID, wrapper)
}

func ownerCancelTestInstallStorage(
	t *testing.T,
	fixture *ownerReserveExecutorTestFixture,
	deviceUUID string,
	storage DeviceMetadataStorage,
) {
	t.Helper()
	found := false
	for index := range fixture.group.devices {
		if fixture.group.devices[index].deviceUUID == deviceUUID {
			fixture.group.devices[index].metadata.storage = storage
			found = true
		}
	}
	if fixture.group.anchor.superblock.DeviceUUID == deviceUUID {
		fixture.group.anchor.storage = storage
	}
	for index := range fixture.input.Devices {
		if fixture.input.Devices[index].ExpectedDeviceUUID == deviceUUID {
			fixture.input.Devices[index].Storage = storage
		}
	}
	if !found {
		t.Fatalf("missing device %q", deviceUUID)
	}
}

func TestOwnerGrantedCancelSingleDeviceCleanAndReplay(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 4<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "clean", 35)
	ownerBefore, allocatorsBefore, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs before cancellation: %v", err)
	}
	request := ownerCancelTestRequest(fixture, granted)
	result, err := fixture.group.CancelGrantedCheckpoint(request)
	if err != nil {
		t.Fatalf("CancelGrantedCheckpoint: %v", err)
	}
	if result.Record.State != OwnerAllocationCanceled ||
		result.Disposition != OwnerCancelClean || result.Replayed ||
		result.ForwardRecovered {
		t.Fatalf("clean cancellation result = %#v", result)
	}
	c := ownerBefore.NextOwnerTransactionSequence
	if result.Record.ReservationTransactionSequence !=
		granted.ReservationTransactionSequence ||
		result.Record.OwnerTransactionSequence != c+1 ||
		result.Record.Fragments[0].TargetAllocatorSnapshotSequence !=
			allocatorsBefore[0].Snapshot.SnapshotSequence+1 {
		t.Fatalf("clean cancellation sequences = %#v; C=%d allocator=%d",
			result.Record, c, allocatorsBefore[0].Snapshot.SnapshotSequence)
	}
	ownerCancelTestAssertSelectedContentZero(t, fixture, granted)
	ownerAbortTestAssertAllocatorPages(t, fixture, result.Record, false, c)
	for _, event := range *fixture.trace {
		if event.region == "content" && event.length > ownerCancelIOBatchBytes {
			t.Fatalf("oversized content I/O event: %#v", event)
		}
	}

	fixture.resetTracking()
	replay, err := fixture.group.CancelGrantedCheckpoint(request)
	if err != nil || !replay.Replayed || replay.Record.State != OwnerAllocationCanceled {
		t.Fatalf("terminal clean replay = %#v, %v", replay, err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerGrantedCancelOlderRecordAllowsLaterPriorTransactions(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b", "device-c"}, "device-c", 2<<20)
	_, first := ownerCancelTestGrant(
		t, fixture, "old", fixture.geometry.DataPageCount)
	_, second := ownerCancelTestGrant(t, fixture, "new", 1)
	if first.Fragments[0].DeviceUUID == second.Fragments[0].DeviceUUID {
		t.Fatalf("fixture did not place records on distinct devices: %q/%q",
			first.Fragments[0].DeviceUUID, second.Fragments[0].DeviceUUID)
	}
	ownerBefore, allocatorsBefore, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	c := ownerBefore.NextOwnerTransactionSequence
	result, err := fixture.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(fixture, first))
	if err != nil {
		t.Fatalf("cancel old GRANTED: %v", err)
	}
	if result.Record.AllocationRecordID != first.AllocationRecordID ||
		result.Record.ReservationTransactionSequence != first.ReservationTransactionSequence ||
		result.Record.OwnerTransactionSequence != c+1 {
		t.Fatalf("old cancellation result = %#v, C=%d", result, c)
	}
	ownerAfter, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs after: %v", err)
	}
	secondAfter, found := reservedDescriptorOwnerRecord(
		ownerAfter, second.AllocationRecordID)
	if !found || !reservedDescriptorRecordsEqual(secondAfter, second) {
		t.Fatalf("later GRANTED record changed: %#v", secondAfter)
	}
	byUUID := make(map[string]OwnerAllocatorDeviceSnapshot)
	for _, allocator := range allocatorsBefore {
		byUUID[allocator.DeviceUUID] = allocator
	}
	oldUUID := first.Fragments[0].DeviceUUID
	if result.Record.Fragments[0].TargetAllocatorSnapshotSequence !=
		byUUID[oldUUID].Snapshot.SnapshotSequence+1 {
		t.Fatalf("old target allocator sequence = %d, want current %d + 1",
			result.Record.Fragments[0].TargetAllocatorSnapshotSequence,
			byUUID[oldUUID].Snapshot.SnapshotSequence)
	}
}

func TestOwnerGrantedCancelAuthorityAndFenceFailuresAreZeroIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "authority", 2)
	base := ownerCancelTestRequest(fixture, granted)
	tests := []struct {
		name string
		edit func(*OwnerGrantedCancelRequest)
		want error
	}{
		{"zero-fence", func(r *OwnerGrantedCancelRequest) {
			r.ProducerWriteFenceSHA256 = [sha256.Size]byte{}
		}, ErrOwnerCancelFenceRequired},
		{"producer-capability", func(r *OwnerGrantedCancelRequest) {
			r.ProducerCapabilitySHA256 = sha256.Sum256([]byte("wrong"))
		}, ErrOwnerCancelAuthorityConflict},
		{"reclaim-authority", func(r *OwnerGrantedCancelRequest) {
			r.ReclaimAuthoritySHA256 = sha256.Sum256([]byte("wrong"))
		}, ErrOwnerCancelAuthorityConflict},
		{"producer-identity", func(r *OwnerGrantedCancelRequest) {
			r.ProducerID = "different-producer"
		}, ErrOwnerCancelConflict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.edit(&request)
			fixture.resetTracking()
			if _, err := fixture.group.CancelGrantedCheckpoint(request); !errors.Is(
				err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			fixture.assertZeroIO(t)
		})
	}
}

func TestOwnerGrantedCancelConflictQuarantinesWithoutPayloadIOAndReplays(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "conflict", 3)
	runs, err := ownerReserveDescriptorsFromRecord(granted)
	if err != nil {
		t.Fatalf("ownerReserveDescriptorsFromRecord: %v", err)
	}
	offset, err := fixture.geometry.DescriptorOffset(runs[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	conflict := make([]byte, PageDescriptorBytes)
	copy(conflict, []byte("foreign-torn-descriptor"))
	fixture.storages[runs[0].DeviceUUID].rawWrite(offset, conflict)
	wantContent := ownerCancelTestSelectedContent(t, fixture, granted)
	fixture.resetTracking()

	request := ownerCancelTestRequest(fixture, granted)
	result, err := fixture.group.CancelGrantedCheckpoint(request)
	if err != nil {
		t.Fatalf("conflict cancellation: %v", err)
	}
	if result.Record.State != OwnerAllocationQuarantined ||
		result.Disposition != OwnerCancelQuarantine {
		t.Fatalf("conflict result = %#v", result)
	}
	ownerCancelTestAssertSelectedContentEqual(t, fixture, granted, wantContent)
	if got := fixture.storages[runs[0].DeviceUUID].rawBytes(
		offset, PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("conflict bytes changed: %x", got)
	}
	for _, event := range *fixture.trace {
		if event.region == "content" {
			t.Fatalf("Quarantine touched payload: %#v", event)
		}
	}

	fixture.resetTracking()
	replay, err := fixture.group.CancelGrantedCheckpoint(request)
	if err != nil || !replay.Replayed ||
		replay.Record.State != OwnerAllocationQuarantined {
		t.Fatalf("terminal Quarantine conservative replay = %#v, %v", replay, err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerGrantedCancelAllDAXSanitizeBarrierAndBound(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b", "device-c"}, "device-c", 2<<20)
	_, granted := ownerCancelTestGrant(
		t, fixture, "barrier", fixture.geometry.DataPageCount+33)
	affected := ownerReserveExecutorAffectedDevices(granted)
	if len(affected) != 2 {
		t.Fatalf("affected devices = %v", affected)
	}
	for _, deviceUUID := range affected {
		ownerCancelTestInstallReadTrace(t, fixture, deviceUUID)
	}
	fixture.resetTracking()
	result, err := fixture.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(fixture, granted))
	if err != nil || result.Record.State != OwnerAllocationCanceled {
		t.Fatalf("multi-DAX cancellation = %#v, %v", result, err)
	}

	lastContentSync := make(map[string]int)
	lastDescriptorSync := make(map[string]int)
	firstContentRead := len(*fixture.trace)
	firstAllocatorWrite := len(*fixture.trace)
	contentWriteBytes := make(map[string]uint64)
	for index, event := range *fixture.trace {
		if event.region == "descriptor" {
			if event.kind == "write" &&
				(event.length <= 0 || event.length > ownerCancelIOBatchBytes) {
				t.Fatalf("invalid descriptor write: %#v", event)
			}
			if event.kind == "sync" {
				lastDescriptorSync[event.deviceUUID] = index
			}
		}
		if event.region == "allocator" && event.kind == "write" &&
			index < firstAllocatorWrite {
			firstAllocatorWrite = index
		}
		if event.region != "content" {
			continue
		}
		switch event.kind {
		case "write":
			if event.length <= 0 || event.length > ownerCancelIOBatchBytes {
				t.Fatalf("invalid content write: %#v", event)
			}
			contentWriteBytes[event.deviceUUID] += uint64(event.length)
		case "sync":
			lastContentSync[event.deviceUUID] = index
		case "read":
			if index < firstContentRead {
				firstContentRead = index
			}
		}
	}
	for _, deviceUUID := range affected {
		if syncIndex, found := lastContentSync[deviceUUID]; !found ||
			syncIndex >= firstContentRead {
			t.Fatalf("device %q content Sync index %d/%v is not before first read %d",
				deviceUUID, syncIndex, found, firstContentRead)
		}
		if syncIndex, found := lastDescriptorSync[deviceUUID]; !found ||
			syncIndex >= firstAllocatorWrite {
			t.Fatalf("device %q descriptor Sync index %d/%v is not before first allocator write %d",
				deviceUUID, syncIndex, found, firstAllocatorWrite)
		}
		var pages uint64
		for _, fragment := range granted.Fragments {
			if fragment.DeviceUUID == deviceUUID {
				for _, extent := range fragment.Extents {
					pages += extent.PageCount
				}
			}
		}
		if contentWriteBytes[deviceUUID] != pages*uint64(ContentPageBytes) {
			t.Fatalf("device %q zeroed %d bytes, want %d",
				deviceUUID,
				contentWriteBytes[deviceUUID],
				pages*uint64(ContentPageBytes))
		}
	}
}

func TestOwnerGrantedCancelSanitizationFailureNeverFreesAndRecovers(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "sanitize-failure", 4)
	plan := ownerCancelTestDurableCanceling(t, fixture, granted)
	fixture.storages["device-a"].failMutation = 1
	_, err := fixture.group.RecoverCancelingCheckpoint()
	if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("sanitization failure = %v", err)
	}
	allocator := ownerCancelTestDevice(t, fixture, "device-a").allocator
	if allocator.AppliedOwnerTransactionSequence !=
		granted.ReservationTransactionSequence {
		t.Fatalf("failed sanitization allocator applied transaction = %d, want %d",
			allocator.AppliedOwnerTransactionSequence,
			granted.ReservationTransactionSequence)
	}
	for _, extent := range granted.Fragments[0].Extents {
		for page := extent.StartDataPageIndex; page <
			extent.StartDataPageIndex+extent.PageCount; page++ {
			unavailable, pageErr := allocator.PageUnavailable(page)
			if pageErr != nil || !unavailable {
				t.Fatalf("failed sanitization page %d unavailable = %v, %v",
					page, unavailable, pageErr)
			}
		}
	}
	fixture.resetTracking()
	if _, err := fixture.group.RecoverCancelingCheckpoint(); !errors.Is(
		err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("poisoned same-handle retry = %v", err)
	}
	fixture.assertZeroIO(t)

	result, err := fixture.reopen(t).RecoverCancelingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationCanceled ||
		!result.ForwardRecovered {
		t.Fatalf("sanitization recovery = %#v, %v; plan=%#v", result, err, plan)
	}
}

func TestOwnerGrantedCancelReadFailureRequiresRecoveryAndReopen(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "read-failure", 2)
	ownerCancelTestDurableCanceling(t, fixture, granted)
	offset, err := fixture.geometry.ContentOffset(
		granted.Fragments[0].Extents[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("ContentOffset: %v", err)
	}
	fixture.storages["device-a"].failReadOffset = &offset
	_, err = fixture.group.RecoverCancelingCheckpoint()
	if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("content read failure = %v", err)
	}
	fixture.storages["device-a"].failReadOffset = nil
	result, err := fixture.reopen(t).RecoverCancelingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationCanceled {
		t.Fatalf("read-failure recovery = %#v, %v", result, err)
	}
}

func TestOwnerGrantedCancelDescriptorReadFailureLatchesOnlyAfterCanceling(t *testing.T) {
	t.Run("GRANTED-preflight-is-zero-mutation-and-retryable", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t, []string{"device-a"}, "device-a", 2<<20)
		_, granted := ownerCancelTestGrant(t, fixture, "descriptor-preflight-read", 2)
		run := ownerCancelPersistenceTestRun(t, fixture, granted)
		offset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 0)
		storage := fixture.storages["device-a"]
		storage.failReadOffset = &offset
		request := ownerCancelTestRequest(fixture, granted)
		_, err := fixture.group.CancelGrantedCheckpoint(request)
		if !errors.Is(err, ErrDeviceMetadataStorage) ||
			errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
			t.Fatalf("GRANTED descriptor read failure = %v", err)
		}
		if storage.writeCalls != 0 || storage.mutationCount != 0 ||
			ownerCancelTestDevice(t, fixture, "device-a").reopenRequired {
			t.Fatalf("GRANTED preflight failure mutated/latched: writes=%d mutations=%d reopen=%v",
				storage.writeCalls,
				storage.mutationCount,
				ownerCancelTestDevice(t, fixture, "device-a").reopenRequired)
		}
		storage.failReadOffset = nil
		fixture.resetTracking()
		result, err := fixture.group.CancelGrantedCheckpoint(request)
		if err != nil || result.Record.State != OwnerAllocationCanceled {
			t.Fatalf("same-handle preflight retry = %#v, %v", result, err)
		}
	})

	t.Run("durable-CANCELING-requires-recovery-and-reopen", func(t *testing.T) {
		fixture := newOwnerReserveExecutorTestFixture(
			t, []string{"device-a"}, "device-a", 2<<20)
		_, granted := ownerCancelTestGrant(t, fixture, "descriptor-durable-read", 2)
		ownerCancelTestDurableCanceling(t, fixture, granted)
		run := ownerCancelPersistenceTestRun(t, fixture, granted)
		offset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 0)
		storage := fixture.storages["device-a"]
		storage.failReadOffset = &offset
		_, err := fixture.group.RecoverCancelingCheckpoint()
		if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
			!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
			t.Fatalf("durable descriptor read failure = %v", err)
		}
		storage.failReadOffset = nil
		fixture.resetTracking()
		if _, err := fixture.group.RecoverCancelingCheckpoint(); !errors.Is(
			err, ErrOwnerDeviceGroupReopenRequired) {
			t.Fatalf("poisoned descriptor read retry = %v", err)
		}
		fixture.assertZeroIO(t)
		result, err := fixture.reopen(t).RecoverCancelingCheckpoint()
		if err != nil || result.Record.State != OwnerAllocationCanceled {
			t.Fatalf("descriptor read recovery = %#v, %v", result, err)
		}
	})
}

func TestOwnerGrantedCancelPreAppliedNonzeroSwitchesWholeCheckpointToQuarantine(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "nonzero-fallback", 2)
	offset, err := fixture.geometry.ContentOffset(
		granted.Fragments[0].Extents[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("ContentOffset: %v", err)
	}
	wrapper := &ownerCancelCorruptAfterContentSyncStorage{
		ownerReserveExecutorTestStorage: fixture.storages["device-a"],
		contentOffset:                   offset,
		armed:                           true,
	}
	ownerCancelTestInstallStorage(t, fixture, "device-a", wrapper)
	fixture.resetTracking()
	result, err := fixture.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(fixture, granted))
	if err != nil || result.Record.State != OwnerAllocationQuarantined ||
		result.Disposition != OwnerCancelQuarantine {
		t.Fatalf("nonzero fallback = %#v, %v", result, err)
	}
	ownerAbortTestAssertAllocatorPages(
		t, fixture, result.Record, true, result.Record.OwnerTransactionSequence-1)
}

func TestOwnerGrantedCancelLaterDAXReadErrorWinsOverEarlierNonzero(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b", "device-c"}, "device-c", 2<<20)
	_, granted := ownerCancelTestGrant(
		t, fixture, "nonzero-then-read-error", fixture.geometry.DataPageCount+1)
	affected := ownerReserveExecutorAffectedDevices(granted)
	if len(affected) != 2 {
		t.Fatalf("affected devices = %v", affected)
	}
	firstFragment := granted.Fragments[0]
	secondFragment := granted.Fragments[0]
	for _, fragment := range granted.Fragments {
		switch fragment.DeviceUUID {
		case affected[0]:
			firstFragment = fragment
		case affected[1]:
			secondFragment = fragment
		}
	}
	firstOffset, err := fixture.geometry.ContentOffset(
		firstFragment.Extents[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("first ContentOffset: %v", err)
	}
	secondOffset, err := fixture.geometry.ContentOffset(
		secondFragment.Extents[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("second ContentOffset: %v", err)
	}
	wrapper := &ownerCancelCorruptAfterContentSyncStorage{
		ownerReserveExecutorTestStorage: fixture.storages[affected[0]],
		contentOffset:                   firstOffset,
		armed:                           true,
	}
	ownerCancelTestInstallStorage(t, fixture, affected[0], wrapper)
	fixture.storages[affected[1]].failReadOffset = &secondOffset
	fixture.resetTracking()
	// resetTracking clears the read failure, so arm it at the exact verification
	// offset only after resetting all prior reserve I/O counters.
	fixture.storages[affected[1]].failReadOffset = &secondOffset

	_, err = fixture.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(fixture, granted))
	if !errors.Is(err, ErrDeviceMetadataStorage) ||
		!errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerCancelContentNotZero) {
		t.Fatalf("nonzero followed by later-DAX read failure = %v", err)
	}
	for _, event := range *fixture.trace {
		if event.region == "descriptor" || event.region == "allocator" {
			t.Fatalf("read failure reached reusable metadata phase: %#v", event)
		}
	}
	for _, fragment := range granted.Fragments {
		allocator := ownerCancelTestDevice(t, fixture, fragment.DeviceUUID).allocator
		if allocator.AppliedOwnerTransactionSequence !=
			granted.ReservationTransactionSequence {
			t.Fatalf("device %q allocator applied %d, want unchanged R=%d",
				fragment.DeviceUUID,
				allocator.AppliedOwnerTransactionSequence,
				granted.ReservationTransactionSequence)
		}
	}

	fixture.storages[affected[1]].failReadOffset = nil
	result, err := fixture.reopen(t).RecoverCancelingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationCanceled {
		t.Fatalf("later-DAX read recovery = %#v, %v", result, err)
	}
}

func TestOwnerGrantedCancelPartialAllocatorRecoveryAndAppliedCleanCorruption(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b", "device-c"}, "device-c", 2<<20)
	_, granted := ownerCancelTestGrant(
		t, fixture, "partial", fixture.geometry.DataPageCount+1)
	plan := ownerCancelTestDurableCanceling(t, fixture, granted)
	for _, entry := range plan.devices {
		device := ownerCancelTestDevice(t, fixture, entry.deviceUUID)
		if err := device.persistCancelingContentZeroes(plan.cancelingRecord); err != nil {
			t.Fatalf("zero %q: %v", entry.deviceUUID, err)
		}
	}
	for _, entry := range plan.devices {
		device := ownerCancelTestDevice(t, fixture, entry.deviceUUID)
		if err := device.verifyCancelingContentZeroes(plan.cancelingRecord); err != nil {
			t.Fatalf("verify %q: %v", entry.deviceUUID, err)
		}
		if err := device.persistCancelingDescriptorDisposition(
			plan.cancelingRecord, OwnerCancelClean, false); err != nil {
			t.Fatalf("descriptors %q: %v", entry.deviceUUID, err)
		}
	}
	if err := ownerCancelTestDevice(t, fixture, plan.devices[0].deviceUUID).
		commitAllocatorSnapshot(plan.devices[0].desiredClean); err != nil {
		t.Fatalf("first allocator: %v", err)
	}
	result, err := fixture.reopen(t).RecoverCancelingCheckpoint()
	if err != nil || result.Record.State != OwnerAllocationCanceled ||
		!result.ForwardRecovered {
		t.Fatalf("partial allocator recovery = %#v, %v", result, err)
	}

	// Repeat on a fresh fixture and stop after the allocator has durably locked
	// Clean. A later nonzero byte is an irreconcilable use-after-free signal.
	fixture = newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted = ownerCancelTestGrant(t, fixture, "applied-corrupt", 2)
	plan = ownerCancelTestDurableCanceling(t, fixture, granted)
	entry := plan.devices[0]
	device := ownerCancelTestDevice(t, fixture, entry.deviceUUID)
	if err := device.persistCancelingContentZeroes(plan.cancelingRecord); err != nil {
		t.Fatalf("zero applied fixture: %v", err)
	}
	if err := device.verifyCancelingContentZeroes(plan.cancelingRecord); err != nil {
		t.Fatalf("verify applied fixture: %v", err)
	}
	if err := device.persistCancelingDescriptorDisposition(
		plan.cancelingRecord, OwnerCancelClean, false); err != nil {
		t.Fatalf("descriptor applied fixture: %v", err)
	}
	if err := device.commitAllocatorSnapshot(entry.desiredClean); err != nil {
		t.Fatalf("allocator applied fixture: %v", err)
	}
	offset, err := fixture.geometry.ContentOffset(
		granted.Fragments[0].Extents[0].StartDataPageIndex)
	if err != nil {
		t.Fatalf("ContentOffset: %v", err)
	}
	fixture.storages[entry.deviceUUID].rawWrite(offset, []byte{1})
	_, err = fixture.reopen(t).RecoverCancelingCheckpoint()
	if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) ||
		!errors.Is(err, ErrOwnerCancelContentNotZero) {
		t.Fatalf("applied-C nonzero = %v", err)
	}
	fixture.resetTracking()
	if _, err := fixture.group.RecoverCancelingCheckpoint(); !errors.Is(
		err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("sticky OFFLINE retry = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerGrantedCancelOwnerCommitEveryFailurePrefixRecovers(t *testing.T) {
	probe := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b"}, "device-b", 2<<20)
	_, probeGranted := ownerCancelTestGrant(t, probe, "owner-prefix-probe", 2)
	if _, err := probe.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(probe, probeGranted)); err != nil {
		t.Fatalf("Owner prefix probe: %v", err)
	}
	mutationCount := probe.storages["device-b"].mutationCount
	if mutationCount == 0 {
		t.Fatal("Owner prefix probe observed no anchor mutation")
	}

	for failMutation := 1; failMutation <= mutationCount; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t, []string{"device-a", "device-b"}, "device-b", 2<<20)
			_, granted := ownerCancelTestGrant(
				t, fixture, fmt.Sprintf("owner-prefix-%d", failMutation), 2)
			request := ownerCancelTestRequest(fixture, granted)
			fixture.storages["device-b"].failMutation = failMutation
			_, err := fixture.group.CancelGrantedCheckpoint(request)
			if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("Owner mutation %d error = %v", failMutation, err)
			}
			ownerCancelTestAssertPoisonThenReopenRecovery(
				t, fixture, request, OwnerCancelClean)
		})
	}
}

func TestOwnerGrantedCancelCleanDeviceEveryFailurePrefixRecovers(t *testing.T) {
	probe := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b"}, "device-b", 2<<20)
	_, probeGranted := ownerCancelTestGrant(t, probe, "device-prefix-probe", 3)
	ownerCancelTestDurableCanceling(t, probe, probeGranted)
	if _, err := probe.group.RecoverCancelingCheckpoint(); err != nil {
		t.Fatalf("device prefix probe: %v", err)
	}
	mutationCount := probe.storages["device-a"].mutationCount
	if mutationCount == 0 {
		t.Fatal("device prefix probe observed no affected-device mutation")
	}

	for failMutation := 1; failMutation <= mutationCount; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t, []string{"device-a", "device-b"}, "device-b", 2<<20)
			_, granted := ownerCancelTestGrant(
				t, fixture, fmt.Sprintf("device-prefix-%d", failMutation), 3)
			request := ownerCancelTestRequest(fixture, granted)
			ownerCancelTestDurableCanceling(t, fixture, granted)
			fixture.storages["device-a"].failMutation = failMutation
			_, err := fixture.group.RecoverCancelingCheckpoint()
			if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
				errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
				t.Fatalf("affected-device mutation %d error = %v", failMutation, err)
			}
			ownerCancelTestAssertPoisonThenReopenRecovery(
				t, fixture, request, OwnerCancelClean)
		})
	}
}

func TestOwnerGrantedCancelPartialQuarantineFaultRecoversAndPreservesConflict(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b"}, "device-b", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "partial-q", 3)
	request := ownerCancelTestRequest(fixture, granted)
	ownerCancelTestDurableCanceling(t, fixture, granted)
	run := ownerCancelPersistenceTestRun(t, fixture, granted)
	conflictOffset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 0)
	conflict := bytes.Repeat([]byte{0xc7}, PageDescriptorBytes)
	fixture.storages[run.DeviceUUID].rawWrite(conflictOffset, conflict)
	wantContent := ownerCancelTestSelectedContent(t, fixture, granted)
	fixture.resetTracking()
	// Q writes the two safe descriptors and Syncs them at mutations 1 and 2;
	// mutation 3 fails the first allocator persistence boundary.
	fixture.storages[run.DeviceUUID].failMutation = 3
	_, err := fixture.group.RecoverCancelingCheckpoint()
	if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("partial Quarantine fault = %v", err)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		conflictOffset, PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("partial Q changed conflict: %x", got)
	}
	result := ownerCancelTestAssertPoisonThenReopenRecovery(
		t, fixture, request, OwnerCancelQuarantine)
	if result.Record.State != OwnerAllocationQuarantined {
		t.Fatalf("partial Q terminal = %#v", result)
	}
	if got := fixture.storages[run.DeviceUUID].rawBytes(
		conflictOffset, PageDescriptorBytes); !bytes.Equal(got, conflict) {
		t.Fatalf("recovered Q changed conflict: %x", got)
	}
	ownerCancelTestAssertSelectedContentEqual(t, fixture, granted, wantContent)
}

func TestOwnerGrantedCancelTornCleanDescriptorRecoversAsQuarantine(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b"}, "device-b", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "torn-clean-descriptor", 3)
	request := ownerCancelTestRequest(fixture, granted)
	plan := ownerCancelTestDurableCanceling(t, fixture, granted)
	entry := plan.devices[0]
	device := ownerCancelTestDevice(t, fixture, entry.deviceUUID)
	if err := device.persistCancelingContentZeroes(plan.cancelingRecord); err != nil {
		t.Fatalf("pre-torn content zero: %v", err)
	}
	if err := device.verifyCancelingContentZeroes(plan.cancelingRecord); err != nil {
		t.Fatalf("pre-torn content verify: %v", err)
	}
	run := ownerCancelPersistenceTestRun(t, fixture, granted)
	conflictOffset := ownerCancelPersistenceTestDescriptorOffset(t, fixture, run, 0)
	ownerAbortTestInstallPartialWrite(
		t, fixture, entry.deviceUUID, 1, 24)
	fixture.resetTracking()
	err := device.persistCancelingDescriptorDisposition(
		plan.cancelingRecord, OwnerCancelClean, false)
	if !errors.Is(err, ErrDeviceMetadataStorage) || !device.reopenRequired {
		t.Fatalf("torn Clean descriptor write = %v, reopen=%v",
			err, device.reopenRequired)
	}
	torn := fixture.storages[entry.deviceUUID].rawBytes(
		conflictOffset, PageDescriptorBytes)
	if allZero(torn) {
		t.Fatalf("partial descriptor write unexpectedly produced canonical FREE: %x", torn)
	}
	reservedWire := ownerCancelPersistenceTestWire(t, run.Descriptor)
	q := run.Descriptor
	q.State = DescriptorQuarantined
	q.OwnerTransactionSeq = plan.cancelingRecord.OwnerTransactionSequence
	qWire := ownerCancelPersistenceTestWire(t, q)
	if bytes.Equal(torn, reservedWire) || bytes.Equal(torn, qWire) {
		t.Fatalf("partial descriptor is not a raw conflict: %x", torn)
	}

	result := ownerCancelTestAssertPoisonThenReopenRecovery(
		t, fixture, request, OwnerCancelQuarantine)
	if result.Record.State != OwnerAllocationQuarantined {
		t.Fatalf("torn descriptor terminal = %#v", result)
	}
	if got := fixture.storages[entry.deviceUUID].rawBytes(
		conflictOffset, PageDescriptorBytes); !bytes.Equal(got, torn) {
		t.Fatalf("recovered cancellation changed torn raw bytes: %x", got)
	}
}

func TestOwnerGrantedCancelPostApplyRefreshReadFailureRecovers(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b"}, "device-b", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "refresh-read", 3)
	request := ownerCancelTestRequest(fixture, granted)
	plan := ownerCancelTestDurableCanceling(t, fixture, granted)
	entry := plan.devices[0]
	superblockOffset := uint64(0)
	fixture.storages[entry.deviceUUID].failReadOffset = &superblockOffset
	_, err := fixture.group.RecoverCancelingCheckpoint()
	if !errors.Is(err, ErrOwnerCancelRecoveryRequired) ||
		!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) ||
		errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("post-apply refresh read failure = %v", err)
	}
	allocator := ownerCancelTestDevice(t, fixture, entry.deviceUUID).allocator
	if allocator.AppliedOwnerTransactionSequence !=
		plan.cancelingRecord.OwnerTransactionSequence {
		t.Fatalf("refresh failed before allocator applied C: got %d, want %d",
			allocator.AppliedOwnerTransactionSequence,
			plan.cancelingRecord.OwnerTransactionSequence)
	}
	fixture.storages[entry.deviceUUID].failReadOffset = nil
	result := ownerCancelTestAssertPoisonThenReopenRecovery(
		t, fixture, request, OwnerCancelClean)
	if result.Record.State != OwnerAllocationCanceled {
		t.Fatalf("refresh-read terminal = %#v", result)
	}
}

func TestOwnerGrantedCancelConcurrentExactRequestsSerialize(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "concurrent", 2)
	request := ownerCancelTestRequest(fixture, granted)
	type outcome struct {
		result OwnerCancelExecutionResult
		err    error
	}
	outcomes := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for index := 0; index < 2; index++ {
		go func() {
			start.Wait()
			result, err := fixture.group.CancelGrantedCheckpoint(request)
			outcomes <- outcome{result: result, err: err}
		}()
	}
	start.Done()
	fresh, replay := 0, 0
	for index := 0; index < 2; index++ {
		outcome := <-outcomes
		if outcome.err != nil {
			t.Fatalf("concurrent cancellation: %v", outcome.err)
		}
		if outcome.result.Replayed {
			replay++
		} else {
			fresh++
		}
	}
	if fresh != 1 || replay != 1 {
		t.Fatalf("concurrent fresh/replay = %d/%d", fresh, replay)
	}
}

func TestOwnerGrantedCancelImmutableShapeAndSequenceOverflow(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a"}, "device-a", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "immutable", 2)
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	plan, err := fixture.group.preflightFreshGrantedCancelLocked(ownerState, granted)
	if err != nil {
		t.Fatalf("fresh cancellation plan: %v", err)
	}
	mutations := []struct {
		name string
		edit func(*OwnerStateAllocationRecord)
	}{
		{"reservation", func(r *OwnerStateAllocationRecord) {
			r.ReservationTransactionSequence++
		}},
		{"request", func(r *OwnerStateAllocationRecord) { r.RequestID += "-changed" }},
		{"demand", func(r *OwnerStateAllocationRecord) { r.ContentDemands[0].ByteLength-- }},
		{"extent", func(r *OwnerStateAllocationRecord) {
			r.Fragments[0].Extents[0].StartDataPageIndex++
		}},
		{"authority", func(r *OwnerStateAllocationRecord) {
			r.AuthorityEvidence.ReclaimAuthoritySHA256 = sha256.Sum256([]byte("changed"))
		}},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			record := cloneOwnerStateRecord(plan.cancelingRecord)
			mutation.edit(&record)
			_, err := ownerCancelReplaceRecordSnapshot(
				ownerState,
				record,
				plan.cancelingState.SnapshotSequence,
				plan.cancelingState.NextAllocationRecordID,
				plan.cancelingState.NextOwnerTransactionSequence,
				fixture.geometry)
			if !errors.Is(err, ErrOwnerCancelDurableContradiction) {
				t.Fatalf("immutable mutation error = %v", err)
			}
		})
	}

	overflow, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    ownerState.ClusterID,
		OwnerGroupID:                 ownerState.OwnerGroupID,
		CurrentOwnerID:               ownerState.CurrentOwnerID,
		AnchorDeviceUUID:             ownerState.AnchorDeviceUUID,
		StorageCompatibilityID:       ownerState.StorageCompatibilityID,
		OwnerEpoch:                   ownerState.OwnerEpoch,
		GroupConfigurationSequence:   ownerState.GroupConfigurationSequence,
		MembershipSHA256:             ownerState.MembershipSHA256,
		SnapshotSequence:             ownerState.SnapshotSequence + 1,
		NextAllocationRecordID:       ownerState.NextAllocationRecordID,
		NextOwnerTransactionSequence: cxlcheckpoint.MaxSignedLong,
		Devices:                      ownerState.Devices(),
		Records:                      ownerState.Records(),
	})
	if err != nil {
		t.Fatalf("overflow Owner state fixture: %v", err)
	}
	if err := fixture.group.anchor.commitOwnerState(overflow); err != nil {
		t.Fatalf("commit overflow fixture: %v", err)
	}
	fixture.resetTracking()
	if _, err := fixture.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(fixture, granted)); !errors.Is(
		err, ErrOwnerReserveSequenceOverflow) {
		t.Fatalf("sequence overflow cancellation = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerGrantedCancelUnaffectedTransactionCollisionOfflines(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t, []string{"device-a", "device-b"}, "device-b", 2<<20)
	_, granted := ownerCancelTestGrant(t, fixture, "collision", 1)
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	c := ownerState.NextOwnerTransactionSequence
	affected := granted.Fragments[0].DeviceUUID
	for index := range fixture.group.devices {
		opened := fixture.group.devices[index]
		if opened.deviceUUID == affected {
			continue
		}
		current := opened.metadata.allocator
		collision, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
			DeviceBindingSHA256:             current.DeviceBindingSHA256,
			OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
			OwnerEpoch:                      current.OwnerEpoch,
			SnapshotSequence:                current.SnapshotSequence,
			AppliedOwnerTransactionSequence: c,
			DataPageCount:                   current.DataPageCount,
		}, current.BitmapBytes())
		if err != nil {
			t.Fatalf("collision allocator: %v", err)
		}
		opened.metadata.allocator = collision
	}
	fixture.resetTracking()
	_, err = fixture.group.CancelGrantedCheckpoint(
		ownerCancelTestRequest(fixture, granted))
	if !errors.Is(err, ErrOwnerDeviceGroupOfflineRequired) {
		t.Fatalf("unaffected C collision = %v", err)
	}
	fixture.assertZeroIO(t)
}

func ExampleOwnerGrantedCancelRequest() {
	fence := sha256.Sum256([]byte(
		OwnerGrantedCancelFenceDigestDomain + ":checkpoint-42"))
	fmt.Printf("authenticated fence is nonzero: %v\n", fence != [sha256.Size]byte{})
	// Output: authenticated fence is nonzero: true
}
