package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type ownerReserveExecutorTestEvent struct {
	deviceUUID string
	kind       string
	region     string
	offset     uint64
	length     int
	err        bool
}

type ownerReserveExecutorTestStorage struct {
	*metadataTestStorage
	deviceUUID string
	geometry   DeviceGeometry
	trace      *[]ownerReserveExecutorTestEvent
	lastRegion string
}

func (storage *ownerReserveExecutorTestStorage) WriteAt(
	source []byte,
	offset int64,
) (int, error) {
	region := storage.region(offset)
	written, err := storage.metadataTestStorage.WriteAt(source, offset)
	storage.lastRegion = region
	*storage.trace = append(*storage.trace, ownerReserveExecutorTestEvent{
		deviceUUID: storage.deviceUUID,
		kind:       "write",
		region:     region,
		offset:     uint64(offset),
		length:     written,
		err:        err != nil || written != len(source),
	})
	return written, err
}

func (storage *ownerReserveExecutorTestStorage) Sync() error {
	err := storage.metadataTestStorage.Sync()
	*storage.trace = append(*storage.trace, ownerReserveExecutorTestEvent{
		deviceUUID: storage.deviceUUID,
		kind:       "sync",
		region:     storage.lastRegion,
		err:        err != nil,
	})
	return err
}

func (storage *ownerReserveExecutorTestStorage) region(offset int64) string {
	if offset < 0 {
		return "invalid"
	}
	position := uint64(offset)
	switch {
	case position >= storage.geometry.ContentRegionBase:
		return "content"
	case position >= storage.geometry.DescriptorRegionBase:
		return "descriptor"
	case position >= storage.geometry.OwnerStateSnapshotAOffset:
		return "owner"
	case position >= storage.geometry.AllocatorSnapshotAOffset:
		return "allocator"
	default:
		return "superblock"
	}
}

func (storage *ownerReserveExecutorTestStorage) resetExecutorTracking() {
	storage.metadataTestStorage.resetTracking()
	storage.lastRegion = ""
}

type ownerReserveExecutorTestFixture struct {
	input    OwnerDeviceGroupInput
	group    *OwnerDeviceGroup
	geometry DeviceGeometry
	storages map[string]*ownerReserveExecutorTestStorage
	trace    *[]ownerReserveExecutorTestEvent
	payloads map[string][]byte
}

func newOwnerReserveExecutorTestFixture(
	t *testing.T,
	deviceUUIDs []string,
	anchorUUID string,
	deviceBytes uint64,
) *ownerReserveExecutorTestFixture {
	t.Helper()
	geometry := metadataTestGeometry(t, deviceBytes, 16<<10)
	trace := make([]ownerReserveExecutorTestEvent, 0)
	devices := make([]OwnerStateDevice, len(deviceUUIDs))
	storages := make(map[string]*ownerReserveExecutorTestStorage, len(deviceUUIDs))
	payloads := make(map[string][]byte, len(deviceUUIDs))
	for index, deviceUUID := range deviceUUIDs {
		binding := (DeviceSuperblock{
			ClusterID:              "cluster-owner-executor",
			DeviceUUID:             deviceUUID,
			StorageCompatibilityID: cxlcheckpoint.V7StorageCompatibilityID,
			Geometry:               geometry,
		}).DeviceBindingSHA256()
		devices[index] = OwnerStateDevice{
			DeviceUUID:          deviceUUID,
			DeviceOwnerEpoch:    11,
			DataPageCount:       geometry.DataPageCount,
			DeviceBindingSHA256: binding,
		}
		storage := &ownerReserveExecutorTestStorage{
			metadataTestStorage: newMetadataTestStorage(geometry.DeviceBytes),
			deviceUUID:          deviceUUID,
			geometry:            geometry,
			trace:               &trace,
		}
		payload := []byte("owner-executor-payload-" + deviceUUID)
		storage.rawWrite(geometry.ContentRegionBase, payload)
		storages[deviceUUID] = storage
		payloads[deviceUUID] = payload
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	bootstrap := OwnerStateBootstrap{
		ClusterID:                  "cluster-owner-executor",
		OwnerGroupID:               "group-owner-executor",
		CurrentOwnerID:             "owner-node-executor",
		AnchorDeviceUUID:           anchorUUID,
		StorageCompatibilityID:     cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch:                 11,
		GroupConfigurationSequence: 4,
		MembershipSHA256:           membership,
		Devices:                    devices,
	}
	entries := make([]OwnerDeviceGroupDeviceInput, len(deviceUUIDs))
	for index, deviceUUID := range deviceUUIDs {
		entries[index] = OwnerDeviceGroupDeviceInput{
			ExpectedDeviceUUID:       deviceUUID,
			Storage:                  storages[deviceUUID],
			Geometry:                 geometry,
			OwnerStateReadLimitBytes: 16 << 10,
		}
	}
	input := OwnerDeviceGroupInput{
		Devices:             entries,
		OwnerStateBootstrap: bootstrap,
	}
	if err := FormatOwnerDeviceGroupOffline(input); err != nil {
		t.Fatalf("FormatOwnerDeviceGroupOffline: %v", err)
	}
	group, err := OpenOwnerDeviceGroup(input)
	if err != nil {
		t.Fatalf("OpenOwnerDeviceGroup: %v", err)
	}
	fixture := &ownerReserveExecutorTestFixture{
		input:    input,
		group:    group,
		geometry: geometry,
		storages: storages,
		trace:    &trace,
		payloads: payloads,
	}
	fixture.resetTracking()
	return fixture
}

func (fixture *ownerReserveExecutorTestFixture) resetTracking() {
	*fixture.trace = nil
	for _, storage := range fixture.storages {
		storage.resetExecutorTracking()
	}
}

func (fixture *ownerReserveExecutorTestFixture) reopen(t *testing.T) *OwnerDeviceGroup {
	t.Helper()
	group, err := OpenOwnerDeviceGroup(fixture.input)
	if err != nil {
		t.Fatalf("reopen Owner group: %v", err)
	}
	fixture.group = group
	fixture.resetTracking()
	return group
}

func (fixture *ownerReserveExecutorTestFixture) request(
	id string,
	pages uint64,
) OwnerReserveRequest {
	bootstrap := fixture.input.OwnerStateBootstrap
	return OwnerReserveRequest{
		ClusterID:                  bootstrap.ClusterID,
		OwnerGroupID:               bootstrap.OwnerGroupID,
		CurrentOwnerID:             bootstrap.CurrentOwnerID,
		AnchorDeviceUUID:           bootstrap.AnchorDeviceUUID,
		StorageCompatibilityID:     bootstrap.StorageCompatibilityID,
		OwnerEpoch:                 bootstrap.OwnerEpoch,
		GroupConfigurationSequence: bootstrap.GroupConfigurationSequence,
		MembershipSHA256:           bootstrap.MembershipSHA256,
		RequestID:                  "request-" + id,
		CheckpointID:               "checkpoint-" + id,
		ProducerID:                 "producer-" + id,
		DedupDomainID:              "dedup-" + id,
		SharingPolicyID:            "sharing-" + id,
		MaxExtents:                 MaxOwnerStateExtents,
		ContentDemands: []OwnerStateContentDemand{{
			Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
			ObjectID:         1,
			ByteLength:       pages * uint64(ContentPageBytes),
			CapacityPages:    pages,
			LogicalPageStart: 0,
		}},
		AuthorityEvidence: OwnerStateAuthorityEvidence{
			SchedulerReserveSHA256:   sha256.Sum256([]byte("scheduler-" + id)),
			ProducerCapabilitySHA256: sha256.Sum256([]byte("producer-" + id)),
			ReclaimAuthoritySHA256:   sha256.Sum256([]byte("reclaim-" + id)),
		},
	}
}

func (fixture *ownerReserveExecutorTestFixture) assertPayloads(t *testing.T) {
	t.Helper()
	for deviceUUID, payload := range fixture.payloads {
		got := fixture.storages[deviceUUID].rawBytes(
			fixture.geometry.ContentRegionBase,
			len(payload))
		if !bytes.Equal(got, payload) {
			t.Fatalf("device %q payload changed: %x", deviceUUID, got)
		}
	}
}

func (fixture *ownerReserveExecutorTestFixture) assertZeroIO(t *testing.T) {
	t.Helper()
	for deviceUUID, storage := range fixture.storages {
		if storage.readCalls != 0 || storage.writeCalls != 0 ||
			storage.mutationCount != 0 || len(storage.events) != 0 {
			t.Fatalf("device %q performed I/O: reads=%d writes=%d events=%#v",
				deviceUUID,
				storage.readCalls,
				storage.writeCalls,
				storage.events)
		}
	}
}

func (fixture *ownerReserveExecutorTestFixture) plan(
	t *testing.T,
	request OwnerReserveRequest,
) OwnerCheckpointReservePlan {
	t.Helper()
	ownerState, allocators, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	plan, err := PlanOwnerCheckpointReserve(ownerState, allocators, request)
	if err != nil {
		t.Fatalf("PlanOwnerCheckpointReserve: %v", err)
	}
	return plan
}

func (fixture *ownerReserveExecutorTestFixture) commitPreparing(
	t *testing.T,
	plan OwnerCheckpointReservePlan,
) {
	t.Helper()
	if err := fixture.group.anchor.commitOwnerState(plan.PreparingOwnerState); err != nil {
		t.Fatalf("commit PREPARING Owner state: %v", err)
	}
}

func ownerReserveExecutorAffectedDevices(
	record OwnerStateAllocationRecord,
) []string {
	result := make([]string, 0, len(record.Fragments))
	for _, fragment := range record.Fragments {
		result = append(result, fragment.DeviceUUID)
	}
	sort.Strings(result)
	return result
}

func ownerReserveExecutorFirstDescriptorOffset(
	t *testing.T,
	geometry DeviceGeometry,
	plan OwnerCheckpointReservePlan,
) (string, uint64) {
	t.Helper()
	if len(plan.ReservedDescriptors) == 0 {
		t.Fatal("plan has no RESERVED descriptor run")
	}
	run := plan.ReservedDescriptors[0]
	offset, err := geometry.DescriptorOffset(run.StartDataPageIndex)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	return run.DeviceUUID, offset
}

func ownerReserveExecutorSnapshotWithRecords(
	t *testing.T,
	base OwnerStateSnapshot,
	records []OwnerStateAllocationRecord,
) OwnerStateSnapshot {
	t.Helper()
	snapshot, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    base.ClusterID,
		OwnerGroupID:                 base.OwnerGroupID,
		CurrentOwnerID:               base.CurrentOwnerID,
		AnchorDeviceUUID:             base.AnchorDeviceUUID,
		StorageCompatibilityID:       base.StorageCompatibilityID,
		OwnerEpoch:                   base.OwnerEpoch,
		GroupConfigurationSequence:   base.GroupConfigurationSequence,
		MembershipSHA256:             base.MembershipSHA256,
		SnapshotSequence:             base.SnapshotSequence,
		NextAllocationRecordID:       base.NextAllocationRecordID,
		NextOwnerTransactionSequence: base.NextOwnerTransactionSequence,
		Devices:                      base.Devices(),
		Records:                      records,
	})
	if err != nil {
		t.Fatalf("NewOwnerStateSnapshot: %v", err)
	}
	return snapshot
}

func TestOwnerReserveExecutorSingleDeviceSuccessAndReplay(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		4<<20)
	request := fixture.request("single", 3)
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil {
		t.Fatalf("ExecuteCheckpointReserve: %v", err)
	}
	if result.Outcome != OwnerReservePlanned || result.ForwardRecovered ||
		result.Record.State != OwnerAllocationGranted ||
		result.Record.OwnerTransactionSequence != 2 {
		t.Fatalf("fresh result = %#v", result)
	}
	ownerState, allocators, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	if ownerState.NextOwnerTransactionSequence != 3 ||
		len(allocators) != 1 ||
		allocators[0].Snapshot.AppliedOwnerTransactionSequence != 1 {
		t.Fatalf("post-grant state = Owner next %d, allocators %#v",
			ownerState.NextOwnerTransactionSequence,
			allocators)
	}
	firstExtent := result.Record.Fragments[0].Extents[0]
	descriptorOffset, err := fixture.geometry.DescriptorOffset(
		firstExtent.StartDataPageIndex)
	if err != nil {
		t.Fatalf("DescriptorOffset: %v", err)
	}
	descriptor, err := ParseDescriptor(
		fixture.storages["device-a"].rawBytes(descriptorOffset, PageDescriptorBytes))
	if err != nil || descriptor.State != DescriptorReserved ||
		descriptor.OwnerTransactionSeq != 1 {
		t.Fatalf("persisted PREPARING descriptor = %#v, %v", descriptor, err)
	}
	fixture.assertPayloads(t)

	fixture.resetTracking()
	replay, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if replay.Outcome != OwnerReserveReplay || replay.Record.State != OwnerAllocationGranted {
		t.Fatalf("replay result = %#v", replay)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerReserveExecutorRejectsZeroReclaimAuthorityWithoutIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("zero-reclaim-authority", 1)
	request.AuthorityEvidence.ReclaimAuthoritySHA256 = [sha256.Size]byte{}
	fixture.resetTracking()
	if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
		err,
		ErrInvalidOwnerReserveRequest) {
		t.Fatalf("zero reclaim authority reserve = %v", err)
	}
	fixture.assertZeroIO(t)
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil || len(ownerState.Records()) != 0 ||
		ownerState.NextAllocationRecordID != 1 ||
		ownerState.NextOwnerTransactionSequence != 1 {
		t.Fatalf("invalid reserve changed cached Owner state = %#v, %v",
			ownerState,
			err)
	}
}

func TestOwnerReserveExecutorNoSpaceAndReplay(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("no-space", fixture.geometry.DataPageCount+1)
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil {
		t.Fatalf("ExecuteCheckpointReserve: %v", err)
	}
	if result.Outcome != OwnerReserveRejectedNoSpace ||
		result.Record.State != OwnerAllocationRejectedNoSpace {
		t.Fatalf("no-space result = %#v", result)
	}
	for _, event := range *fixture.trace {
		if event.region == "descriptor" || event.region == "allocator" ||
			event.region == "content" {
			t.Fatalf("no-space mutated %s: %#v", event.region, event)
		}
	}
	fixture.assertPayloads(t)
	fixture.resetTracking()
	replay, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil || replay.Outcome != OwnerReserveReplay ||
		replay.Record.State != OwnerAllocationRejectedNoSpace {
		t.Fatalf("no-space replay = %#v, %v", replay, err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerReserveExecutorNoSpaceCommitAmbiguityReopensAndReplays(t *testing.T) {
	for failMutation := 1; failMutation <= 6; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			request := fixture.request(
				"no-space-ambiguous",
				fixture.geometry.DataPageCount+1)
			fixture.storages["device-a"].failMutation = failMutation
			if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("REJECTED_NO_SPACE failure %d = %v", failMutation, err)
			}
			fixture.resetTracking()
			if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("poisoned no-space execution = %v", err)
			}
			fixture.assertZeroIO(t)

			result, err := fixture.reopen(t).ExecuteCheckpointReserve(request)
			if err != nil || result.Record.State != OwnerAllocationRejectedNoSpace {
				t.Fatalf("post-reopen no-space result = %#v, %v", result, err)
			}
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerDeviceGroupRejectsShallowCopyWithoutIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("copied-handle", 1)
	copiedValue := *fixture.group
	copied := &copiedValue

	if _, _, err := copied.PlannerInputs(); !errors.Is(err, ErrOwnerDeviceGroupInput) {
		t.Fatalf("copied PlannerInputs error = %v", err)
	}
	if _, err := copied.ExecuteCheckpointReserve(request); !errors.Is(
		err,
		ErrOwnerDeviceGroupInput) {
		t.Fatalf("copied ExecuteCheckpointReserve error = %v", err)
	}
	if _, err := copied.RecoverPreparingCheckpointReserve(); !errors.Is(
		err,
		ErrOwnerDeviceGroupInput) {
		t.Fatalf("copied RecoverPreparingCheckpointReserve error = %v", err)
	}
	if got := copied.Bootstrap(); got.ClusterID != "" || len(got.Devices) != 0 {
		t.Fatalf("copied Bootstrap exposed state: %#v", got)
	}
	fixture.assertZeroIO(t)

	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil || result.Record.State != OwnerAllocationGranted {
		t.Fatalf("original handle result = %#v, %v", result, err)
	}
}

func TestOwnerReserveExecutorActivePreparingConflictAndForwardRecovery(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("recover-exact", 4)
	plan := fixture.plan(t, request)
	if plan.Outcome != OwnerReservePlanned {
		t.Fatalf("plan outcome = %d", plan.Outcome)
	}
	fixture.commitPreparing(t, plan)
	fixture.resetTracking()

	different := fixture.request("recover-different", 4)
	if _, err := fixture.group.ExecuteCheckpointReserve(different); !errors.Is(
		err,
		ErrOwnerReserveConflict) {
		t.Fatalf("different request error = %v", err)
	}
	fixture.assertZeroIO(t)

	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil {
		t.Fatalf("forward recovery: %v", err)
	}
	if result.Outcome != OwnerReserveReplay || !result.ForwardRecovered ||
		result.Record.State != OwnerAllocationGranted {
		t.Fatalf("forward-recovery result = %#v", result)
	}
	fixture.assertPayloads(t)
}

func TestOwnerReserveExecutorTerminalReplayWhileNewerPreparingIsZeroIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	terminalRequest := fixture.request("terminal-before-preparing", 1)
	if _, err := fixture.group.ExecuteCheckpointReserve(terminalRequest); err != nil {
		t.Fatalf("terminal reserve: %v", err)
	}
	preparingRequest := fixture.request("active-after-terminal", 1)
	plan := fixture.plan(t, preparingRequest)
	fixture.commitPreparing(t, plan)
	fixture.resetTracking()

	replay, err := fixture.group.ExecuteCheckpointReserve(terminalRequest)
	if err != nil || replay.Outcome != OwnerReserveReplay ||
		replay.Record.State != OwnerAllocationGranted {
		t.Fatalf("terminal replay = %#v, %v", replay, err)
	}
	fixture.assertZeroIO(t)

	result, err := fixture.group.ExecuteCheckpointReserve(preparingRequest)
	if err != nil || !result.ForwardRecovered ||
		result.Record.State != OwnerAllocationGranted {
		t.Fatalf("newer PREPARING recovery = %#v, %v", result, err)
	}
}

func TestOwnerReserveExecutorDeterministicPreflightFailureDoesNotWriteOrPoison(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("preflight-size", 1)
	storage := fixture.storages["device-a"]
	storage.size--
	if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
		err,
		ErrDeviceMetadataSizeMismatch) {
		t.Fatalf("preflight size error = %v", err)
	}
	if storage.writeCalls != 0 || storage.mutationCount != 0 || len(*fixture.trace) != 0 {
		t.Fatalf("deterministic preflight wrote storage: %#v", *fixture.trace)
	}
	storage.size++
	fixture.resetTracking()
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil || result.Record.State != OwnerAllocationGranted {
		t.Fatalf("same handle after preflight failure = %#v, %v", result, err)
	}
}

func TestOwnerReserveExecutorDescriptorReadFailureForwardRecovers(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("descriptor-read", 3)
	plan := fixture.plan(t, request)
	deviceUUID, offset := ownerReserveExecutorFirstDescriptorOffset(
		t,
		fixture.geometry,
		plan)
	fixture.storages[deviceUUID].failReadOffset = &offset

	if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
		err,
		ErrOwnerReserveRecoveryRequired) || errors.Is(
		err,
		ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("descriptor read failure = %v", err)
	}
	fixture.resetTracking()
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil {
		t.Fatalf("same-handle descriptor recovery: %v", err)
	}
	if !result.ForwardRecovered || result.Record.State != OwnerAllocationGranted {
		t.Fatalf("descriptor recovery result = %#v", result)
	}
	fixture.assertPayloads(t)
}

func TestOwnerReserveExecutorForeignDescriptorNeedsAbortWithoutBlindRepair(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("descriptor-conflict", 2)
	plan := fixture.plan(t, request)
	deviceUUID, offset := ownerReserveExecutorFirstDescriptorOffset(
		t,
		fixture.geometry,
		plan)
	foreign := bytes.Repeat([]byte{0x5a}, PageDescriptorBytes)
	fixture.storages[deviceUUID].rawWrite(offset, foreign)

	_, err := fixture.group.ExecuteCheckpointReserve(request)
	if !errors.Is(err, ErrOwnerReserveRecoveryRequired) ||
		!errors.Is(err, ErrOwnerReserveAbortRequired) ||
		!errors.Is(err, ErrDeviceMetadataDescriptorConflict) ||
		errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
		t.Fatalf("descriptor conflict error = %v", err)
	}
	if got := fixture.storages[deviceUUID].rawBytes(offset, len(foreign)); !bytes.Equal(got, foreign) {
		t.Fatalf("foreign descriptor was modified: %x", got)
	}
	for _, event := range *fixture.trace {
		if event.region == "descriptor" || event.region == "allocator" {
			t.Fatalf("conflict performed forbidden mutation: %#v", event)
		}
	}

	fixture.resetTracking()
	if _, err := fixture.group.ExecuteCheckpointReserve(
		fixture.request("blocked-by-conflict", 1)); !errors.Is(
		err,
		ErrOwnerReserveConflict) {
		t.Fatalf("different request after conflict = %v", err)
	}
	fixture.assertZeroIO(t)
	if _, err := fixture.group.RecoverPreparingCheckpointReserve(); !errors.Is(
		err,
		ErrOwnerReserveAbortRequired) {
		t.Fatalf("blind recovery conflict = %v", err)
	}
	if got := fixture.storages[deviceUUID].rawBytes(offset, len(foreign)); !bytes.Equal(got, foreign) {
		t.Fatalf("recovery modified foreign descriptor: %x", got)
	}
	fixture.assertPayloads(t)
}

func TestOwnerReserveExecutorTornDescriptorNeedsAbortWithoutBlindRepair(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("descriptor-torn", 2)
	plan := fixture.plan(t, request)
	deviceUUID, offset := ownerReserveExecutorFirstDescriptorOffset(
		t,
		fixture.geometry,
		plan)
	wire, err := plan.ReservedDescriptors[0].Descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	// A power-loss prefix has a valid-looking beginning but lacks the canonical
	// tail/checksum. It is neither all-zero FREE nor byte-exact RESERVED.
	fixture.storages[deviceUUID].rawWrite(offset, wire[:PageDescriptorBytes/2])
	torn := fixture.storages[deviceUUID].rawBytes(offset, PageDescriptorBytes)
	if bytes.Equal(torn, wire) || allZero(torn) {
		t.Fatalf("test did not construct a torn descriptor: %x", torn)
	}

	_, err = fixture.group.ExecuteCheckpointReserve(request)
	if !errors.Is(err, ErrDeviceMetadataDescriptorConflict) ||
		!errors.Is(err, ErrOwnerReserveRecoveryRequired) ||
		!errors.Is(err, ErrOwnerReserveAbortRequired) {
		t.Fatalf("torn descriptor error = %v", err)
	}
	if got := fixture.storages[deviceUUID].rawBytes(offset, PageDescriptorBytes); !bytes.Equal(got, torn) {
		t.Fatalf("torn descriptor was repaired blindly: %x", got)
	}
	for _, event := range *fixture.trace {
		if event.region == "descriptor" || event.region == "allocator" {
			t.Fatalf("torn descriptor caused forbidden mutation: %#v", event)
		}
	}
	fixture.assertPayloads(t)
}

func TestOwnerReserveExecutorOwnerReadLimitPreflightIsZeroWrite(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("owner-read-limit", 1)
	originalLimit := fixture.group.anchor.ownerStateReadLimitBytes
	fixture.group.anchor.ownerStateReadLimitBytes = OwnerStateEnvelopeHeaderBytes
	if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
		err,
		ErrDeviceMetadataOwnerStateReadLimit) {
		t.Fatalf("Owner read-limit preflight = %v", err)
	}
	if len(*fixture.trace) != 0 {
		t.Fatalf("Owner read-limit preflight mutated storage: %#v", *fixture.trace)
	}
	fixture.group.anchor.ownerStateReadLimitBytes = originalLimit
	fixture.resetTracking()
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil || result.Record.State != OwnerAllocationGranted {
		t.Fatalf("execution after restoring read limit = %#v, %v", result, err)
	}
}

func TestOwnerReserveExecutorSuperblockOverflowPreflightIsZeroWrite(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("superblock-overflow", 1)
	originalSequence := fixture.group.devices[0].metadata.superblock.SuperblockSequence
	fixture.group.devices[0].metadata.superblock.SuperblockSequence =
		cxlcheckpoint.MaxSignedLong
	if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
		err,
		ErrDeviceMetadataSequence) {
		t.Fatalf("superblock overflow preflight = %v", err)
	}
	if len(*fixture.trace) != 0 {
		t.Fatalf("superblock overflow preflight mutated storage: %#v", *fixture.trace)
	}
	fixture.group.devices[0].metadata.superblock.SuperblockSequence = originalSequence
	fixture.resetTracking()
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil || result.Record.State != OwnerAllocationGranted {
		t.Fatalf("execution after restoring sequence = %#v, %v", result, err)
	}
}

func TestOwnerReserveExecutorRecoverWithoutPreparingIsZeroIO(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	if _, err := fixture.group.RecoverPreparingCheckpointReserve(); !errors.Is(
		err,
		ErrOwnerReserveNoPreparing) {
		t.Fatalf("RecoverPreparingCheckpointReserve = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerReserveExecutorMultiDeviceDurabilityOrder(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a", "device-b", "device-c"},
		"device-c",
		2<<20)
	request := fixture.request(
		"multi-order",
		fixture.geometry.DataPageCount+1)
	result, err := fixture.group.ExecuteCheckpointReserve(request)
	if err != nil {
		t.Fatalf("ExecuteCheckpointReserve: %v", err)
	}
	affected := ownerReserveExecutorAffectedDevices(result.Record)
	if len(affected) != 2 || affected[0] != "device-a" || affected[1] != "device-b" {
		t.Fatalf("affected devices = %v", affected)
	}

	firstAllocator := -1
	lastAllocator := -1
	descriptorSyncBeforeAllocator := make(map[string]bool)
	allocatorOrder := make([]string, 0, len(affected))
	seenAllocator := make(map[string]bool)
	ownerEvents := make([]int, 0, 12)
	for index, event := range *fixture.trace {
		if event.region == "content" {
			t.Fatalf("executor wrote content: %#v", event)
		}
		if event.region == "owner" {
			ownerEvents = append(ownerEvents, index)
		}
		if event.region == "descriptor" && event.kind == "sync" {
			descriptorSyncBeforeAllocator[event.deviceUUID] = true
		}
		if event.region != "allocator" && event.region != "superblock" {
			continue
		}
		if event.region == "superblock" && event.deviceUUID == "device-c" {
			continue
		}
		if firstAllocator < 0 {
			firstAllocator = index
			for _, deviceUUID := range affected {
				if !descriptorSyncBeforeAllocator[deviceUUID] {
					t.Fatalf("allocator began before descriptor Sync for %q: %#v",
						deviceUUID,
						*fixture.trace)
				}
			}
		}
		lastAllocator = index
		if event.region == "allocator" && !seenAllocator[event.deviceUUID] {
			seenAllocator[event.deviceUUID] = true
			allocatorOrder = append(allocatorOrder, event.deviceUUID)
		}
	}
	if firstAllocator < 0 || lastAllocator < firstAllocator {
		t.Fatalf("no allocator durability events: %#v", *fixture.trace)
	}
	if len(allocatorOrder) != 2 || allocatorOrder[0] != "device-a" ||
		allocatorOrder[1] != "device-b" {
		t.Fatalf("allocator order = %v", allocatorOrder)
	}
	// Each Owner envelope has three write/Sync pairs. The first six events are
	// PREPARING; the seventh Owner event must therefore begin GRANTED only after
	// both allocator superblock headers are durable.
	if len(ownerEvents) != 12 || ownerEvents[6] <= lastAllocator {
		t.Fatalf("Owner/allocator order is invalid: Owner=%v last allocator=%d trace=%#v",
			ownerEvents,
			lastAllocator,
			*fixture.trace)
	}
	fixture.assertPayloads(t)
}

func TestOwnerReserveExecutorPreparingCommitAmbiguityPoisonsUntilReopen(t *testing.T) {
	for failMutation := 1; failMutation <= 6; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			request := fixture.request("preparing-ambiguous", 2)
			fixture.storages["device-a"].failMutation = failMutation
			_, err := fixture.group.ExecuteCheckpointReserve(request)
			if !errors.Is(err, ErrOwnerReserveRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("PREPARING failure %d = %v", failMutation, err)
			}

			fixture.resetTracking()
			if _, _, err := fixture.group.PlannerInputs(); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("poisoned PlannerInputs = %v", err)
			}
			if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("poisoned ExecuteCheckpointReserve = %v", err)
			}
			fixture.assertZeroIO(t)

			group := fixture.reopen(t)
			result, err := group.ExecuteCheckpointReserve(request)
			if err != nil || result.Record.State != OwnerAllocationGranted {
				t.Fatalf("post-reopen recovery = %#v, %v", result, err)
			}
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerReserveExecutorDescriptorMutationAmbiguityRecoversAfterReopen(t *testing.T) {
	for _, failMutation := range []int{7, 8} {
		t.Run(string(rune('0'+failMutation)), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			request := fixture.request("descriptor-ambiguous", 2)
			fixture.storages["device-a"].failMutation = failMutation
			_, err := fixture.group.ExecuteCheckpointReserve(request)
			if !errors.Is(err, ErrOwnerReserveRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("descriptor failure %d = %v", failMutation, err)
			}
			fixture.resetTracking()
			if _, err := fixture.group.RecoverPreparingCheckpointReserve(); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("poisoned recovery = %v", err)
			}
			fixture.assertZeroIO(t)

			result, err := fixture.reopen(t).ExecuteCheckpointReserve(request)
			if err != nil || result.Record.State != OwnerAllocationGranted {
				t.Fatalf("post-reopen descriptor recovery = %#v, %v", result, err)
			}
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerReserveExecutorPartialAllocatorApplicationForwardRecovers(t *testing.T) {
	tests := make([]struct {
		name         string
		deviceUUID   string
		failMutation int
	}, 0, 24)
	for _, deviceUUID := range []string{"device-a", "device-b"} {
		for failMutation := 3; failMutation <= 14; failMutation++ {
			tests = append(tests, struct {
				name         string
				deviceUUID   string
				failMutation int
			}{
				name:       fmt.Sprintf("%s-mutation-%d", deviceUUID, failMutation),
				deviceUUID: deviceUUID, failMutation: failMutation,
			})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b", "device-c"},
				"device-c",
				2<<20)
			request := fixture.request(
				"allocator-partial",
				fixture.geometry.DataPageCount+1)
			plan := fixture.plan(t, request)
			if got := ownerReserveExecutorAffectedDevices(plan.Record); len(got) != 2 || got[0] != "device-a" || got[1] != "device-b" {
				t.Fatalf("affected devices = %v", got)
			}
			fixture.storages[test.deviceUUID].failMutation = test.failMutation
			_, err := fixture.group.ExecuteCheckpointReserve(request)
			if !errors.Is(err, ErrOwnerReserveRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("allocator failure = %v", err)
			}
			fixture.resetTracking()
			if _, err := fixture.group.ExecuteCheckpointReserve(request); !errors.Is(
				err,
				ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("poisoned execution = %v", err)
			}
			fixture.assertZeroIO(t)

			result, err := fixture.reopen(t).ExecuteCheckpointReserve(request)
			if err != nil || result.Record.State != OwnerAllocationGranted {
				t.Fatalf("partial-allocator recovery = %#v, %v", result, err)
			}
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerReserveExecutorGrantCommitAmbiguityRecoversAfterReopen(t *testing.T) {
	for failMutation := 7; failMutation <= 12; failMutation++ {
		t.Run(fmt.Sprintf("mutation-%d", failMutation), func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a", "device-b"},
				"device-b",
				2<<20)
			request := fixture.request("grant-ambiguous", 2)
			plan := fixture.plan(t, request)
			if got := ownerReserveExecutorAffectedDevices(plan.Record); len(got) != 1 || got[0] != "device-a" {
				t.Fatalf("affected devices = %v", got)
			}
			fixture.storages["device-b"].failMutation = failMutation
			_, err := fixture.group.ExecuteCheckpointReserve(request)
			if !errors.Is(err, ErrOwnerReserveRecoveryRequired) ||
				!errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
				t.Fatalf("GRANTED failure %d = %v", failMutation, err)
			}
			fixture.resetTracking()
			fixture.assertZeroIO(t)

			result, err := fixture.reopen(t).ExecuteCheckpointReserve(request)
			if err != nil || result.Record.State != OwnerAllocationGranted {
				t.Fatalf("post-reopen GRANTED recovery = %#v, %v", result, err)
			}
			fixture.assertPayloads(t)
		})
	}
}

func TestOwnerReserveExecutorOlderTransitionBlocksPreparingRecovery(t *testing.T) {
	states := []struct {
		name  string
		state OwnerAllocationState
	}{
		{name: "COMMITTING", state: OwnerAllocationCommitting},
		{name: "ABORTING", state: OwnerAllocationAborting},
		{name: "RECLAIMING", state: OwnerAllocationReclaiming},
	}
	for _, test := range states {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerReserveExecutorTestFixture(
				t,
				[]string{"device-a"},
				"device-a",
				2<<20)
			first := fixture.request("older-transition", 1)
			if _, err := fixture.group.ExecuteCheckpointReserve(first); err != nil {
				t.Fatalf("first reserve: %v", err)
			}
			second := fixture.request("newer-preparing", 1)
			plan := fixture.plan(t, second)
			records := plan.PreparingOwnerState.Records()
			records[0].State = test.state
			blocked := ownerReserveExecutorSnapshotWithRecords(
				t,
				plan.PreparingOwnerState,
				records)
			if err := fixture.group.anchor.commitOwnerState(blocked); err != nil {
				t.Fatalf("commit blocked state: %v", err)
			}
			fixture.resetTracking()

			if _, err := fixture.group.ExecuteCheckpointReserve(second); !errors.Is(
				err,
				ErrOwnerReserveTransitionBlocked) {
				t.Fatalf("ExecuteCheckpointReserve = %v", err)
			}
			if _, err := fixture.group.RecoverPreparingCheckpointReserve(); !errors.Is(
				err,
				ErrOwnerReserveTransitionBlocked) {
				t.Fatalf("RecoverPreparingCheckpointReserve = %v", err)
			}
			fixture.assertZeroIO(t)
		})
	}
}

func TestOwnerReserveExecutorTerminalReplaySurvivesUnrelatedTransition(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	first := fixture.request("transitioning-record", 1)
	second := fixture.request("terminal-record", 1)
	if _, err := fixture.group.ExecuteCheckpointReserve(first); err != nil {
		t.Fatalf("first reserve: %v", err)
	}
	if _, err := fixture.group.ExecuteCheckpointReserve(second); err != nil {
		t.Fatalf("second reserve: %v", err)
	}
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil {
		t.Fatalf("PlannerInputs: %v", err)
	}
	records := ownerState.Records()
	records[0].State = OwnerAllocationCommitting
	transitionBase := ownerState.Clone()
	transitionBase.SnapshotSequence++
	transitionBase.NextOwnerTransactionSequence++
	transitionState := ownerReserveExecutorSnapshotWithRecords(
		t,
		transitionBase,
		records)
	if err := fixture.group.anchor.commitOwnerState(transitionState); err != nil {
		t.Fatalf("commit transitional state: %v", err)
	}
	fixture.resetTracking()

	replay, err := fixture.group.ExecuteCheckpointReserve(second)
	if err != nil || replay.Outcome != OwnerReserveReplay ||
		replay.Record.State != OwnerAllocationGranted {
		t.Fatalf("terminal replay = %#v, %v", replay, err)
	}
	fixture.assertZeroIO(t)
	if _, err := fixture.group.ExecuteCheckpointReserve(first); !errors.Is(
		err,
		ErrOwnerReserveTransitionBlocked) {
		t.Fatalf("exact transitional request = %v", err)
	}
	if _, err := fixture.group.ExecuteCheckpointReserve(
		fixture.request("fresh-blocked", 1)); !errors.Is(
		err,
		ErrOwnerReserveTransitionBlocked) {
		t.Fatalf("fresh request = %v", err)
	}
	fixture.assertZeroIO(t)
}

func TestOwnerReserveExecutorConcurrentExactRequestSerializes(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		2<<20)
	request := fixture.request("concurrent", 8)
	start := make(chan struct{})
	results := make([]OwnerReserveExecutionResult, 2)
	errorsByIndex := make([]error, 2)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			results[index], errorsByIndex[index] =
				fixture.group.ExecuteCheckpointReserve(request)
		}(index)
	}
	close(start)
	wait.Wait()
	planned := 0
	replayed := 0
	for index := range results {
		if errorsByIndex[index] != nil {
			t.Fatalf("execution %d: %v", index, errorsByIndex[index])
		}
		switch results[index].Outcome {
		case OwnerReservePlanned:
			planned++
		case OwnerReserveReplay:
			replayed++
		default:
			t.Fatalf("execution %d outcome = %d", index, results[index].Outcome)
		}
		if results[index].Record.State != OwnerAllocationGranted {
			t.Fatalf("execution %d record = %#v", index, results[index].Record)
		}
	}
	if planned != 1 || replayed != 1 {
		t.Fatalf("planned/replayed = %d/%d, results %#v", planned, replayed, results)
	}
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil || len(ownerState.Records()) != 1 {
		t.Fatalf("serialized Owner state = %#v, %v", ownerState, err)
	}
	fixture.assertPayloads(t)
}

func TestOwnerReserveExecutorSerializesPlannerInputsWithMutations(t *testing.T) {
	fixture := newOwnerReserveExecutorTestFixture(
		t,
		[]string{"device-a"},
		"device-a",
		4<<20)
	requests := []OwnerReserveRequest{
		fixture.request("concurrent-planner-a", 4),
		fixture.request("concurrent-planner-b", 4),
	}
	const readerCount = 12
	start := make(chan struct{})
	readerErrors := make([]error, readerCount)
	writerErrors := make([]error, len(requests))
	var wait sync.WaitGroup
	for index := range readerErrors {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			ownerState, inputs, err := fixture.group.PlannerInputs()
			if err == nil {
				err = ownerState.Validate()
			}
			if err == nil && len(inputs) != 1 {
				err = fmt.Errorf("planner input count %d, want 1", len(inputs))
			}
			readerErrors[index] = err
		}(index)
	}
	for index := range requests {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			_, writerErrors[index] = fixture.group.ExecuteCheckpointReserve(
				requests[index])
		}(index)
	}
	close(start)
	wait.Wait()
	for index, err := range readerErrors {
		if err != nil {
			t.Fatalf("PlannerInputs %d: %v", index, err)
		}
	}
	for index, err := range writerErrors {
		if err != nil {
			t.Fatalf("reserve %d: %v", index, err)
		}
	}
	ownerState, _, err := fixture.group.PlannerInputs()
	if err != nil || len(ownerState.Records()) != len(requests) {
		t.Fatalf("final Owner state = %#v, %v", ownerState, err)
	}
	fixture.assertPayloads(t)
}
