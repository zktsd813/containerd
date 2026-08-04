package trcxl007

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type ownerAllocatorTestRun struct {
	start uint64
	count uint64
}

type ownerAllocatorTestFixture struct {
	state      OwnerStateSnapshot
	inputs     []OwnerAllocatorDeviceSnapshot
	geometries map[string]DeviceGeometry
}

func TestOwnerAllocatorSingleBestFitAndCheckpointTransitions(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 4, count: 6}},
		"device-b": {{start: 20, count: 5}, {start: 50, count: 5}},
	})
	request := ownerAllocatorTestRequest(fixture.state, []OwnerStateContentDemand{
		{
			Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
			ObjectID:         1,
			ByteLength:       3 * uint64(ContentPageBytes),
			CapacityPages:    3,
			LogicalPageStart: 0,
		},
		{
			Kind:             cxlcheckpoint.ContentArtifactPayloadV7,
			ObjectID:         2,
			ByteLength:       5000,
			CapacityPages:    2,
			LogicalPageStart: 3,
		},
	}, 4)

	before := ownerAllocatorInputBitmaps(fixture.inputs)
	plan, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, request)
	if err != nil {
		t.Fatalf("PlanOwnerCheckpointReserve: %v", err)
	}
	if plan.Outcome != OwnerReservePlanned {
		t.Fatalf("outcome = %d, want PLANNED", plan.Outcome)
	}
	if plan.RequestSHA256 == ([sha256.Size]byte{}) || plan.Record.RequestSHA256 != plan.RequestSHA256 {
		t.Fatalf("request digest was not derived and copied into the record")
	}
	if plan.PreparingOwnerState.SnapshotSequence != fixture.state.SnapshotSequence+1 ||
		plan.PreparingOwnerState.NextAllocationRecordID != fixture.state.NextAllocationRecordID+1 ||
		plan.PreparingOwnerState.NextOwnerTransactionSequence !=
			fixture.state.NextOwnerTransactionSequence+1 {
		t.Fatalf("PREPARING high-water transition is wrong")
	}
	preparingRecord := ownerAllocatorLastRecord(t, plan.PreparingOwnerState)
	if preparingRecord.State != OwnerAllocationPreparing ||
		preparingRecord.AllocationRecordID != fixture.state.NextAllocationRecordID ||
		preparingRecord.ReservationTransactionSequence != fixture.state.NextOwnerTransactionSequence ||
		preparingRecord.OwnerTransactionSequence != fixture.state.NextOwnerTransactionSequence {
		t.Fatalf("PREPARING record identity/state = %#v", preparingRecord)
	}
	if plan.GrantedOwnerState.SnapshotSequence != fixture.state.SnapshotSequence+2 ||
		plan.GrantedOwnerState.NextAllocationRecordID != fixture.state.NextAllocationRecordID+1 ||
		plan.GrantedOwnerState.NextOwnerTransactionSequence !=
			fixture.state.NextOwnerTransactionSequence+2 {
		t.Fatalf("GRANTED high-water transition is wrong")
	}
	grantedRecord := ownerAllocatorLastRecord(t, plan.GrantedOwnerState)
	if grantedRecord.State != OwnerAllocationGranted ||
		grantedRecord.ReservationTransactionSequence != preparingRecord.ReservationTransactionSequence ||
		grantedRecord.OwnerTransactionSequence != fixture.state.NextOwnerTransactionSequence+1 ||
		!reflect.DeepEqual(grantedRecord, plan.Record) {
		t.Fatalf("GRANTED record mismatch")
	}
	derivedAfterGrant, err := ownerReserveDescriptorsFromRecord(grantedRecord)
	if err != nil {
		t.Fatalf("derive RESERVED descriptors from GRANTED record: %v", err)
	}
	for _, run := range derivedAfterGrant {
		if run.Descriptor.OwnerTransactionSeq !=
			grantedRecord.ReservationTransactionSequence ||
			run.Descriptor.OwnerTransactionSeq == grantedRecord.OwnerTransactionSequence {
			t.Fatalf("GRANTED descriptor derivation used current transaction: %#v", run)
		}
	}

	if len(grantedRecord.Fragments) != 1 ||
		grantedRecord.Fragments[0].DeviceUUID != "device-b" ||
		len(grantedRecord.Fragments[0].Extents) != 1 {
		t.Fatalf("best-fit placement = %#v", grantedRecord.Fragments)
	}
	extent := grantedRecord.Fragments[0].Extents[0]
	if extent.StartDataPageIndex != 20 || extent.LogicalPageStart != 0 || extent.PageCount != 5 {
		t.Fatalf("best-fit extent = %#v", extent)
	}
	if len(plan.AllocatorUpdates) != 1 || plan.AllocatorUpdates[0].DeviceUUID != "device-b" {
		t.Fatalf("allocator updates = %#v", plan.AllocatorUpdates)
	}
	update := plan.AllocatorUpdates[0]
	if update.DesiredSnapshot.SnapshotSequence != update.PreviousSnapshotSequence+1 ||
		update.DesiredSnapshot.AppliedOwnerTransactionSequence !=
			fixture.state.NextOwnerTransactionSequence ||
		grantedRecord.Fragments[0].TargetAllocatorSnapshotSequence !=
			update.DesiredSnapshot.SnapshotSequence {
		t.Fatalf("allocator/fragment target sequence mismatch")
	}
	for page := uint64(20); page < 25; page++ {
		unavailable, err := update.DesiredSnapshot.PageUnavailable(page)
		if err != nil || !unavailable {
			t.Fatalf("desired page %d unavailable = %v, %v", page, unavailable, err)
		}
	}

	// Memory and artifact pages use the same physical run and bitmap. Only the
	// compact RESERVED descriptor plan splits at the object boundary.
	if len(plan.ReservedDescriptors) != 2 {
		t.Fatalf("descriptor runs = %d, want 2", len(plan.ReservedDescriptors))
	}
	first, second := plan.ReservedDescriptors[0], plan.ReservedDescriptors[1]
	if first.DeviceUUID != "device-b" || first.StartDataPageIndex != 20 ||
		first.LogicalPageStart != 0 || first.ObjectPageStart != 0 || first.PageCount != 3 ||
		first.Descriptor.State != DescriptorReserved ||
		first.Descriptor.ContentKind != cxlcheckpoint.ContentMemoryPayloadV7 ||
		first.Descriptor.OriginObjectID != 1 ||
		second.DeviceUUID != "device-b" || second.StartDataPageIndex != 23 ||
		second.LogicalPageStart != 3 || second.ObjectPageStart != 0 || second.PageCount != 2 ||
		second.Descriptor.ContentKind != cxlcheckpoint.ContentArtifactPayloadV7 ||
		second.Descriptor.OriginObjectID != 2 {
		t.Fatalf("descriptor boundary split = %#v / %#v", first, second)
	}
	for _, descriptorRun := range plan.ReservedDescriptors {
		if descriptorRun.Descriptor.AllocationRecordID != preparingRecord.AllocationRecordID ||
			descriptorRun.Descriptor.OwnerTransactionSeq !=
				preparingRecord.ReservationTransactionSequence {
			t.Fatalf("RESERVED descriptor transaction identity mismatch")
		}
		if err := descriptorRun.Descriptor.Validate(); err != nil {
			t.Fatalf("RESERVED descriptor: %v", err)
		}
	}

	ownerAllocatorRequireInputBitmaps(t, fixture.inputs, before)
	ownerAllocatorRequirePlanCanonical(t, fixture, plan)
}

func TestOwnerAllocatorRejectsReservationMutationDuringRecordReplacement(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 4, count: 6}},
	})
	request := ownerAllocatorTestMemoryRequest(
		fixture.state,
		"reservation-mutation",
		2,
		1)
	plan, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}

	base := plan.GrantedOwnerState
	replacement := ownerAllocatorLastRecord(t, base)
	originalReservation := replacement.ReservationTransactionSequence
	replacement.State = OwnerAllocationCommitted
	replacement.ReservationTransactionSequence = replacement.OwnerTransactionSequence
	replacement.OwnerTransactionSequence = base.NextOwnerTransactionSequence
	nextTransaction := base.NextOwnerTransactionSequence + 1
	anchorGeometry := fixture.geometries[base.AnchorDeviceUUID]

	// The replacement is independently well-formed: only the transition from
	// the retained record makes changing the immutable reservation invalid.
	records := base.Records()
	records[len(records)-1] = replacement
	if _, err := ownerReserveNewSnapshot(
		base,
		records,
		base.SnapshotSequence+1,
		base.NextAllocationRecordID,
		nextTransaction,
		anchorGeometry); err != nil {
		t.Fatalf("well-formed replacement control: %v", err)
	}

	_, err = ownerReserveReplaceLastRecordSnapshot(
		base,
		replacement,
		base.SnapshotSequence+1,
		base.NextAllocationRecordID,
		nextTransaction,
		anchorGeometry)
	if !errors.Is(err, ErrOwnerAllocatorInputMismatch) ||
		!strings.Contains(err.Error(), "reservation transaction sequence changed") {
		t.Fatalf(
			"reservation mutation %d -> %d error = %v",
			originalReservation,
			replacement.ReservationTransactionSequence,
			err)
	}
}

func TestOwnerAllocatorMinimumExtentsOnOneDevice(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 4}, {start: 20, count: 4}},
		"device-b": {{start: 0, count: 3}, {start: 20, count: 3}, {start: 40, count: 3}},
		"device-c": {{start: 2, count: 4}, {start: 30, count: 4}},
	})
	request := ownerAllocatorTestMemoryRequest(fixture.state, "minimum-one-device", 8, 5)
	plan, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	record := ownerAllocatorLastRecord(t, plan.GrantedOwnerState)
	if len(record.Fragments) != 1 || record.Fragments[0].DeviceUUID != "device-a" ||
		len(record.Fragments[0].Extents) != 2 {
		t.Fatalf("one-device minimum-extent placement = %#v", record.Fragments)
	}
	if record.Fragments[0].Extents[0].StartDataPageIndex != 0 ||
		record.Fragments[0].Extents[1].StartDataPageIndex != 20 {
		t.Fatalf("stable page tie-break = %#v", record.Fragments[0].Extents)
	}
}

func TestOwnerAllocatorSparseMultiDeviceDeterminismAndNoOverlap(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 4}, {start: 20, count: 2}},
		"device-b": {{start: 2, count: 3}, {start: 30, count: 2}},
		"device-c": {{start: 4, count: 3}, {start: 40, count: 1}},
	})
	request := ownerAllocatorTestMemoryRequest(fixture.state, "sparse-multi", 10, 4)
	before := ownerAllocatorInputBitmaps(fixture.inputs)
	left, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, request)
	if err != nil {
		t.Fatalf("ordered plan: %v", err)
	}
	reversed := append([]OwnerAllocatorDeviceSnapshot(nil), fixture.inputs...)
	for leftIndex, rightIndex := 0, len(reversed)-1; leftIndex < rightIndex; leftIndex, rightIndex = leftIndex+1, rightIndex-1 {
		reversed[leftIndex], reversed[rightIndex] = reversed[rightIndex], reversed[leftIndex]
	}
	right, err := PlanOwnerCheckpointReserve(fixture.state, reversed, request)
	if err != nil {
		t.Fatalf("reversed plan: %v", err)
	}
	ownerAllocatorRequirePlansEqual(t, fixture, left, right)
	ownerAllocatorRequireInputBitmaps(t, fixture.inputs, before)

	record := ownerAllocatorLastRecord(t, left.GrantedOwnerState)
	if len(record.Fragments) != 2 ||
		record.Fragments[0].DeviceUUID != "device-a" ||
		record.Fragments[1].DeviceUUID != "device-b" {
		t.Fatalf("multi-device fragments = %#v", record.Fragments)
	}
	extentCount := 0
	seen := make(map[string]map[uint64]bool)
	for _, fragment := range record.Fragments {
		if seen[fragment.DeviceUUID] == nil {
			seen[fragment.DeviceUUID] = make(map[uint64]bool)
		}
		for _, extent := range fragment.Extents {
			extentCount++
			for page := extent.StartDataPageIndex; page < extent.StartDataPageIndex+extent.PageCount; page++ {
				if seen[fragment.DeviceUUID][page] {
					t.Fatalf("overlapping output page %s/%d", fragment.DeviceUUID, page)
				}
				seen[fragment.DeviceUUID][page] = true
				if ownerAllocatorBitmapSet(before[fragment.DeviceUUID], page) {
					t.Fatalf("output reused unavailable page %s/%d", fragment.DeviceUUID, page)
				}
			}
		}
	}
	if extentCount != 4 || len(left.AllocatorUpdates) != 2 {
		t.Fatalf("bounded multi-device extent/update count = %d/%d", extentCount, len(left.AllocatorUpdates))
	}
}

func TestOwnerAllocatorExpandsPastFragmentedHighCapacityPrefix(t *testing.T) {
	// device-a and device-b have the largest total free capacities, but only as
	// one-page holes. Restricting planning to that capacity-ranked prefix would
	// falsely report no space at MaxExtents=2. The bounded prefix expansion must
	// reach device-c/device-d and use their two large runs.
	fragmentedA := make([]ownerAllocatorTestRun, 0, 10)
	for page := uint64(0); page < 20; page += 2 {
		fragmentedA = append(fragmentedA, ownerAllocatorTestRun{start: page, count: 1})
	}
	fragmentedB := make([]ownerAllocatorTestRun, 0, 9)
	for page := uint64(30); page < 48; page += 2 {
		fragmentedB = append(fragmentedB, ownerAllocatorTestRun{start: page, count: 1})
	}
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": fragmentedA,
		"device-b": fragmentedB,
		"device-c": {{start: 80, count: 8}},
		"device-d": {{start: 100, count: 7}},
	})
	request := ownerAllocatorTestMemoryRequest(fixture.state, "prefix-expansion", 10, 2)
	plan, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.Outcome != OwnerReservePlanned {
		t.Fatalf("outcome = %d, want PLANNED", plan.Outcome)
	}
	record := ownerAllocatorLastRecord(t, plan.GrantedOwnerState)
	if len(record.Fragments) != 2 ||
		record.Fragments[0].DeviceUUID != "device-c" ||
		record.Fragments[1].DeviceUUID != "device-d" {
		t.Fatalf("expanded-prefix placement = %#v", record.Fragments)
	}
	extentCount := 0
	for _, fragment := range record.Fragments {
		extentCount += len(fragment.Extents)
	}
	if extentCount != 2 {
		t.Fatalf("extent count = %d, want 2", extentCount)
	}
}

func TestOwnerAllocatorNoSpaceConsumesRecordButNeverMutatesDevice(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 4}, {start: 20, count: 2}},
		"device-b": {{start: 2, count: 3}, {start: 30, count: 2}},
	})
	before := ownerAllocatorInputBitmaps(fixture.inputs)
	tests := []struct {
		name    string
		request OwnerReserveRequest
	}{
		{
			name:    "capacity",
			request: ownerAllocatorTestMemoryRequest(fixture.state, "capacity-no-space", 12, 4),
		},
		{
			name:    "extent-cap",
			request: ownerAllocatorTestMemoryRequest(fixture.state, "extent-no-space", 10, 3),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, test.request)
			if err != nil {
				t.Fatalf("plan: %v", err)
			}
			if plan.Outcome != OwnerReserveRejectedNoSpace ||
				len(plan.AllocatorUpdates) != 0 || len(plan.ReservedDescriptors) != 0 ||
				plan.PreparingOwnerState.SnapshotSequence != 0 ||
				plan.GrantedOwnerState.SnapshotSequence != 0 {
				t.Fatalf("no-space mutation shape = %#v", plan)
			}
			record := ownerAllocatorLastRecord(t, plan.RejectedOwnerState)
			if record.State != OwnerAllocationRejectedNoSpace ||
				record.AllocationRecordID != fixture.state.NextAllocationRecordID ||
				record.ReservationTransactionSequence != 0 ||
				record.OwnerTransactionSequence != fixture.state.NextOwnerTransactionSequence ||
				len(record.Fragments) != 0 ||
				record.TotalDemandPages != ownerAllocatorDemandPages(test.request.ContentDemands) ||
				!reflect.DeepEqual(record.ContentDemands, test.request.ContentDemands) {
				t.Fatalf("no-space record = %#v", record)
			}
			if plan.RejectedOwnerState.SnapshotSequence != fixture.state.SnapshotSequence+1 ||
				plan.RejectedOwnerState.NextAllocationRecordID != fixture.state.NextAllocationRecordID+1 ||
				plan.RejectedOwnerState.NextOwnerTransactionSequence !=
					fixture.state.NextOwnerTransactionSequence+1 {
				t.Fatalf("no-space high-water transition is wrong")
			}
			ownerAllocatorRequireInputBitmaps(t, fixture.inputs, before)
			ownerAllocatorRequirePlanCanonical(t, fixture, plan)
		})
	}
}

func TestOwnerAllocatorExactReplayAndConflicts(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 10, count: 8}},
		"device-b": {{start: 20, count: 2}},
	})
	request := ownerAllocatorTestMemoryRequest(fixture.state, "replay", 4, 2)
	first, err := PlanOwnerCheckpointReserve(fixture.state, fixture.inputs, request)
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	committedInputs := ownerAllocatorApplyUpdates(fixture.inputs, first.AllocatorUpdates)
	replay, err := PlanOwnerCheckpointReserve(first.GrantedOwnerState, committedInputs, request)
	if err != nil {
		t.Fatalf("exact replay: %v", err)
	}
	if replay.Outcome != OwnerReserveReplay ||
		replay.RequestSHA256 != first.RequestSHA256 ||
		!reflect.DeepEqual(replay.Record, first.Record) ||
		len(replay.AllocatorUpdates) != 0 || len(replay.ReservedDescriptors) != 0 ||
		replay.PreparingOwnerState.SnapshotSequence != 0 ||
		replay.GrantedOwnerState.SnapshotSequence != 0 ||
		replay.RejectedOwnerState.SnapshotSequence != 0 {
		t.Fatalf("replay result = %#v", replay)
	}

	changedAuthority := request
	changedAuthority.AuthorityEvidence.ProducerCapabilitySHA256[0] ^= 1
	if _, err := PlanOwnerCheckpointReserve(
		first.GrantedOwnerState, committedInputs, changedAuthority); !errors.Is(err, ErrOwnerReserveConflict) {
		t.Fatalf("authority mismatch error = %v", err)
	}
	changedRequestID := request
	changedRequestID.RequestID = "different-request-same-checkpoint"
	if _, err := PlanOwnerCheckpointReserve(
		first.GrantedOwnerState, committedInputs, changedRequestID); !errors.Is(err, ErrOwnerReserveConflict) {
		t.Fatalf("checkpoint collision error = %v", err)
	}
	changedCheckpointID := request
	changedCheckpointID.CheckpointID = "different-checkpoint-same-request"
	if _, err := PlanOwnerCheckpointReserve(
		first.GrantedOwnerState, committedInputs, changedCheckpointID); !errors.Is(err, ErrOwnerReserveConflict) {
		t.Fatalf("request collision error = %v", err)
	}
}

func TestOwnerAllocatorPlacementSlotABASequence(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 10}},
	})
	state := fixture.state
	inputs := fixture.inputs
	kinds := []cxlcheckpoint.ContentKindV7{
		cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPlacementSlotBV7,
		cxlcheckpoint.ContentPlacementSlotAV7,
	}
	for index, kind := range kinds {
		request := ownerAllocatorTestRequest(state, []OwnerStateContentDemand{{
			Kind:             kind,
			ObjectID:         uint64(index + 1),
			ByteLength:       0,
			CapacityPages:    1,
			LogicalPageStart: 0,
		}}, 1)
		request.RequestID = "slot-request-" + string(rune('a'+index))
		request.CheckpointID = "slot-checkpoint-" + string(rune('a'+index))
		plan, err := PlanOwnerCheckpointReserve(state, inputs, request)
		if err != nil {
			t.Fatalf("slot %d plan: %v", index, err)
		}
		if plan.Outcome != OwnerReservePlanned || len(plan.ReservedDescriptors) != 1 ||
			plan.ReservedDescriptors[0].Descriptor.ContentKind != kind ||
			plan.ReservedDescriptors[0].StartDataPageIndex != uint64(index) {
			t.Fatalf("slot %d placement = %#v", index, plan)
		}
		state = plan.GrantedOwnerState
		inputs = ownerAllocatorApplyUpdates(inputs, plan.AllocatorUpdates)
	}
	if state.SnapshotSequence != fixture.state.SnapshotSequence+6 ||
		state.NextAllocationRecordID != fixture.state.NextAllocationRecordID+3 ||
		state.NextOwnerTransactionSequence != fixture.state.NextOwnerTransactionSequence+6 {
		t.Fatalf("A/B/A final high-water state is wrong")
	}
}

func TestOwnerAllocatorInputCrossChecks(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 4}},
		"device-b": {{start: 10, count: 4}},
	})
	request := ownerAllocatorTestMemoryRequest(fixture.state, "input-check", 2, 2)
	tests := []struct {
		name   string
		mutate func([]OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot
	}{
		{
			name: "missing-device",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				return inputs[:1]
			},
		},
		{
			name: "duplicate-device",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				inputs[1].DeviceUUID = inputs[0].DeviceUUID
				return inputs
			},
		},
		{
			name: "device-binding",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				inputs[0].Snapshot.DeviceBindingSHA256[0] ^= 1
				return inputs
			},
		},
		{
			name: "Owner-group-binding",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				inputs[0].Snapshot.OwnerGroupIdentitySHA256[0] ^= 1
				return inputs
			},
		},
		{
			name: "device-epoch",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				inputs[0].Snapshot.OwnerEpoch++
				return inputs
			},
		},
		{
			name: "data-page-count",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				inputs[0].Snapshot.DataPageCount--
				return inputs
			},
		},
		{
			name: "future-applied-transaction",
			mutate: func(inputs []OwnerAllocatorDeviceSnapshot) []OwnerAllocatorDeviceSnapshot {
				inputs[0].Snapshot.AppliedOwnerTransactionSequence =
					fixture.state.NextOwnerTransactionSequence
				return inputs
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			inputs := ownerAllocatorCloneInputs(fixture.inputs)
			inputs = test.mutate(inputs)
			if _, err := PlanOwnerCheckpointReserve(
				fixture.state, inputs, request); !errors.Is(err, ErrOwnerAllocatorInputMismatch) {
				t.Fatalf("input mismatch error = %v", err)
			}
		})
	}

	wrongOwner := request
	wrongOwner.OwnerEpoch++
	if _, err := PlanOwnerCheckpointReserve(
		fixture.state, fixture.inputs, wrongOwner); !errors.Is(err, ErrOwnerAllocatorInputMismatch) {
		t.Fatalf("request Owner identity mismatch error = %v", err)
	}

	// OwnerState.Validate permits independently versioned device entries, but
	// the formatter/open bootstrap contract for one active Owner group requires
	// every member epoch to equal the committed group epoch. The planner accepts
	// only that actually formattable committed state.
	wrongEpochDevices := fixture.state.Devices()
	wrongEpochDevices[0].DeviceOwnerEpoch--
	wrongEpochMembership, err := OwnerGroupMembershipSHA256(wrongEpochDevices)
	if err != nil {
		t.Fatalf("wrong-epoch membership: %v", err)
	}
	wrongEpochState, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    fixture.state.ClusterID,
		OwnerGroupID:                 fixture.state.OwnerGroupID,
		CurrentOwnerID:               fixture.state.CurrentOwnerID,
		AnchorDeviceUUID:             fixture.state.AnchorDeviceUUID,
		StorageCompatibilityID:       fixture.state.StorageCompatibilityID,
		OwnerEpoch:                   fixture.state.OwnerEpoch,
		GroupConfigurationSequence:   fixture.state.GroupConfigurationSequence,
		MembershipSHA256:             wrongEpochMembership,
		SnapshotSequence:             fixture.state.SnapshotSequence,
		NextAllocationRecordID:       fixture.state.NextAllocationRecordID,
		NextOwnerTransactionSequence: fixture.state.NextOwnerTransactionSequence,
		Devices:                      wrongEpochDevices,
		Records:                      fixture.state.Records(),
	})
	if err != nil {
		t.Fatalf("wrong-epoch Owner state fixture: %v", err)
	}
	wrongEpochRequest := ownerAllocatorRequestForState(wrongEpochState, request)
	if _, err := PlanOwnerCheckpointReserve(
		wrongEpochState,
		fixture.inputs,
		wrongEpochRequest); !errors.Is(err, ErrOwnerAllocatorInputMismatch) {
		t.Fatalf("membership/global Owner epoch mismatch error = %v", err)
	}
}

func TestOwnerReserveRequestDigestIsDerivedAndDomainSeparated(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 8}},
	})
	request := ownerAllocatorTestMemoryRequest(fixture.state, "digest", 2, 2)
	digest, err := OwnerReserveRequestSHA256(request)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	const wantHex = "8f7afb7c7a8d547f19c8174ba8975f3aef7cd6d951b3e575cba7898791860c94"
	if got := hex.EncodeToString(digest[:]); got != wantHex {
		t.Fatalf("request digest = %s", got)
	}
	if digest == sha256.Sum256([]byte(request.RequestID+request.CheckpointID)) ||
		digest == sha256.Sum256([]byte(OwnerReserveRequestDigestDomain)) {
		t.Fatalf("request digest is not a domain-separated complete encoding")
	}

	mutations := []func(*OwnerReserveRequest){
		func(value *OwnerReserveRequest) { value.OwnerEpoch++ },
		func(value *OwnerReserveRequest) { value.RequestID += "-changed" },
		func(value *OwnerReserveRequest) { value.MaxExtents++ },
		func(value *OwnerReserveRequest) { value.ContentDemands[0].ObjectID++ },
		func(value *OwnerReserveRequest) { value.AuthorityEvidence.SchedulerReserveSHA256[0] ^= 1 },
		func(value *OwnerReserveRequest) { value.AuthorityEvidence.ProducerCapabilitySHA256[0] ^= 1 },
		func(value *OwnerReserveRequest) { value.AuthorityEvidence.PublicationAuthoritySHA256[0] ^= 1 },
		func(value *OwnerReserveRequest) { value.AuthorityEvidence.ReclaimAuthoritySHA256[0] ^= 1 },
	}
	for index, mutate := range mutations {
		candidate := request
		candidate.ContentDemands = append([]OwnerStateContentDemand(nil), request.ContentDemands...)
		mutate(&candidate)
		changed, err := OwnerReserveRequestSHA256(candidate)
		if err != nil {
			t.Fatalf("mutation %d digest: %v", index, err)
		}
		if changed == digest {
			t.Fatalf("mutation %d did not change request digest", index)
		}
	}
}

func TestOwnerAllocatorSignedBoundsAndRequestValidation(t *testing.T) {
	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 8}},
	})
	baseRequest := ownerAllocatorTestMemoryRequest(fixture.state, "bounds", 2, 2)
	invalidRequests := []OwnerReserveRequest{
		func() OwnerReserveRequest { value := baseRequest; value.MaxExtents = 0; return value }(),
		func() OwnerReserveRequest {
			value := baseRequest
			value.MaxExtents = MaxOwnerStateExtents + 1
			return value
		}(),
		func() OwnerReserveRequest {
			value := baseRequest
			value.AuthorityEvidence.SchedulerReserveSHA256 = [sha256.Size]byte{}
			return value
		}(),
		func() OwnerReserveRequest {
			value := baseRequest
			value.AuthorityEvidence.ProducerCapabilitySHA256 = [sha256.Size]byte{}
			return value
		}(),
		func() OwnerReserveRequest {
			value := baseRequest
			value.AuthorityEvidence.ReclaimAuthoritySHA256 = [sha256.Size]byte{}
			return value
		}(),
	}
	for index, request := range invalidRequests {
		if _, err := PlanOwnerCheckpointReserve(
			fixture.state, fixture.inputs, request); !errors.Is(err, ErrInvalidOwnerReserveRequest) {
			t.Fatalf("invalid request %d error = %v", index, err)
		}
	}

	maximumAllocator := ownerAllocatorCloneInputs(fixture.inputs)
	maximumAllocator[0].Snapshot.SnapshotSequence = cxlcheckpoint.MaxSignedLong
	if _, err := PlanOwnerCheckpointReserve(
		fixture.state, maximumAllocator, baseRequest); !errors.Is(err, ErrOwnerReserveSequenceOverflow) {
		t.Fatalf("allocator sequence overflow error = %v", err)
	}

	nearMaximumState := ownerAllocatorStateWithHighWaters(
		t,
		fixture.state,
		cxlcheckpoint.MaxSignedLong-1,
		fixture.state.NextAllocationRecordID,
		fixture.state.NextOwnerTransactionSequence)
	nearMaximumRequest := ownerAllocatorRequestForState(nearMaximumState, baseRequest)
	if _, err := PlanOwnerCheckpointReserve(
		nearMaximumState, fixture.inputs, nearMaximumRequest); !errors.Is(err, ErrOwnerReserveSequenceOverflow) {
		t.Fatalf("Owner-state sequence overflow error = %v", err)
	}

	nearMaximumTransaction := ownerAllocatorStateWithHighWaters(
		t,
		fixture.state,
		fixture.state.SnapshotSequence,
		fixture.state.NextAllocationRecordID,
		cxlcheckpoint.MaxSignedLong-1)
	nearMaximumTransactionRequest := ownerAllocatorRequestForState(nearMaximumTransaction, baseRequest)
	if _, err := PlanOwnerCheckpointReserve(
		nearMaximumTransaction,
		fixture.inputs,
		nearMaximumTransactionRequest); !errors.Is(err, ErrOwnerReserveSequenceOverflow) {
		t.Fatalf("Owner transaction overflow error = %v", err)
	}

	maximumAllocationID := ownerAllocatorStateWithHighWaters(
		t,
		fixture.state,
		fixture.state.SnapshotSequence,
		cxlcheckpoint.MaxSignedLong,
		fixture.state.NextOwnerTransactionSequence)
	maximumAllocationRequest := ownerAllocatorRequestForState(maximumAllocationID, baseRequest)
	if _, err := PlanOwnerCheckpointReserve(
		maximumAllocationID,
		fixture.inputs,
		maximumAllocationRequest); !errors.Is(err, ErrOwnerReserveSequenceOverflow) {
		t.Fatalf("allocation-record ID overflow error = %v", err)
	}
}

func TestOwnerAllocatorRetainedHoleMetadataIsStrictlyBounded(t *testing.T) {
	const limit = 7
	runs := make(ownerAllocatorFreeRunHeap, 0, limit)
	for index := 0; index < 100000; index++ {
		ownerAllocatorRetainFreeRun(&runs, ownerAllocatorFreeRun{
			DeviceUUID:         "device-a",
			StartDataPageIndex: uint64(index * 2),
			PageCount:          uint64(index%97 + 1),
		}, limit)
		if len(runs) > limit {
			t.Fatalf("retained run count %d exceeds limit %d", len(runs), limit)
		}
	}
	if len(runs) != limit {
		t.Fatalf("retained run count = %d, want %d", len(runs), limit)
	}
	for _, run := range runs {
		if run.PageCount != 97 {
			t.Fatalf("bounded heap retained non-top run %#v", run)
		}
	}

	fixture := newOwnerAllocatorTestFixture(t, map[string][]ownerAllocatorTestRun{
		"device-a": {{start: 0, count: 1}},
	})
	input := fixture.inputs[0]
	bitmap := input.Snapshot.BitmapBytes()
	for page := uint64(0); page < input.Snapshot.DataPageCount; page++ {
		ownerAllocatorSetBitmap(bitmap, page)
	}
	for page := uint64(0); page < input.Snapshot.DataPageCount; page += 2 {
		bitmap[page/8] &^= byte(1) << uint(page%8)
	}
	sparse, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             input.Snapshot.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        input.Snapshot.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      input.Snapshot.OwnerEpoch,
		SnapshotSequence:                input.Snapshot.SnapshotSequence,
		AppliedOwnerTransactionSequence: input.Snapshot.AppliedOwnerTransactionSequence,
		DataPageCount:                   input.Snapshot.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("sparse snapshot: %v", err)
	}
	input.Snapshot = sparse
	validated, _, err := validateOwnerAllocatorInputs(fixture.state, []OwnerAllocatorDeviceSnapshot{input})
	if err != nil {
		t.Fatalf("validate sparse input: %v", err)
	}
	if err := validated[0].scanFreeRuns(8, 3); err != nil {
		t.Fatalf("scan sparse holes: %v", err)
	}
	if validated[0].freeRunCount <= 3 || len(validated[0].retainedRuns) != 3 {
		t.Fatalf("sparse run count/retained = %d/%d", validated[0].freeRunCount, len(validated[0].retainedRuns))
	}
}

func TestOwnerAllocatorModelHasNoCallerDigestPageRPCOrRuntimeState(t *testing.T) {
	requestType := reflect.TypeOf(OwnerReserveRequest{})
	for _, forbidden := range []string{"RequestSHA256", "ReservationTransactionSequence"} {
		if _, exists := requestType.FieldByName(forbidden); exists {
			t.Fatalf("request must not trust a caller-provided %s", forbidden)
		}
	}
	for _, value := range []interface{}{
		OwnerReserveRequest{},
		OwnerAllocatorDeviceSnapshot{},
		OwnerAllocatorSnapshotUpdate{},
		OwnerReservedDescriptorRun{},
		OwnerCheckpointReservePlan{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			lower := strings.ToLower(field.Name)
			for _, forbidden := range []string{
				"path", "mount", "mmap", "file", "socket", "rpc", "requestbody",
				"responsebody", "payloadbytes", "pagebytes", "generation", "runtime",
			} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("%s contains forbidden field %s", typeOf.Name(), field.Name)
				}
			}
			if field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8 {
				t.Fatalf("%s exposes page/RPC byte slice field %s", typeOf.Name(), field.Name)
			}
		}
	}
	if OwnerReservePlanned != 1 || OwnerReserveReplay != 2 || OwnerReserveRejectedNoSpace != 3 {
		t.Fatalf("reserve outcome ABI = %d/%d/%d", OwnerReservePlanned, OwnerReserveReplay, OwnerReserveRejectedNoSpace)
	}
}

func newOwnerAllocatorTestFixture(
	t *testing.T,
	freeByDevice map[string][]ownerAllocatorTestRun,
) ownerAllocatorTestFixture {
	t.Helper()
	uuids := make([]string, 0, len(freeByDevice))
	for uuid := range freeByDevice {
		uuids = append(uuids, uuid)
	}
	sort.Strings(uuids)
	geometries := make(map[string]DeviceGeometry, len(uuids))
	devices := make([]OwnerStateDevice, len(uuids))
	for index, uuid := range uuids {
		geometry, err := CalculateDeviceGeometry(1<<20, 4096, 16<<10)
		if err != nil {
			t.Fatalf("geometry %s: %v", uuid, err)
		}
		geometries[uuid] = geometry
		binding := (DeviceSuperblock{
			ClusterID:              "cluster-allocator",
			DeviceUUID:             uuid,
			StorageCompatibilityID: cxlcheckpoint.V7StorageCompatibilityID,
			Geometry:               geometry,
		}).DeviceBindingSHA256()
		devices[index] = OwnerStateDevice{
			DeviceUUID:          uuid,
			DeviceOwnerEpoch:    17,
			DataPageCount:       geometry.DataPageCount,
			DeviceBindingSHA256: binding,
		}
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("membership: %v", err)
	}
	state, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    "cluster-allocator",
		OwnerGroupID:                 "owner-group-allocator",
		CurrentOwnerID:               "owner-node-allocator",
		AnchorDeviceUUID:             uuids[0],
		StorageCompatibilityID:       cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch:                   17,
		GroupConfigurationSequence:   3,
		MembershipSHA256:             membership,
		SnapshotSequence:             10,
		NextAllocationRecordID:       1,
		NextOwnerTransactionSequence: 1,
		Devices:                      devices,
	})
	if err != nil {
		t.Fatalf("Owner state: %v", err)
	}
	inputs := make([]OwnerAllocatorDeviceSnapshot, len(devices))
	for index, device := range devices {
		geometry := geometries[device.DeviceUUID]
		bitmapBytes, err := geometry.AllocationBitmapBytes()
		if err != nil {
			t.Fatalf("bitmap bytes: %v", err)
		}
		bitmap := make([]byte, int(bitmapBytes))
		for page := uint64(0); page < geometry.DataPageCount; page++ {
			ownerAllocatorSetBitmap(bitmap, page)
		}
		for _, run := range freeByDevice[device.DeviceUUID] {
			if run.count == 0 || run.start+run.count > geometry.DataPageCount {
				t.Fatalf("invalid free run %s/%d+%d", device.DeviceUUID, run.start, run.count)
			}
			for page := run.start; page < run.start+run.count; page++ {
				bitmap[page/8] &^= byte(1) << uint(page%8)
			}
		}
		groupBinding := (DeviceSuperblock{
			ClusterID:                       state.ClusterID,
			OwnerGroupID:                    state.OwnerGroupID,
			CurrentOwnerID:                  state.CurrentOwnerID,
			OwnerGroupAnchorDeviceUUID:      state.AnchorDeviceUUID,
			OwnerEpoch:                      device.DeviceOwnerEpoch,
			OwnerGroupConfigurationSequence: state.GroupConfigurationSequence,
			OwnerGroupMembershipSHA256:      state.MembershipSHA256,
		}).OwnerGroupIdentitySHA256()
		snapshot, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
			DeviceBindingSHA256:             device.DeviceBindingSHA256,
			OwnerGroupIdentitySHA256:        groupBinding,
			OwnerEpoch:                      device.DeviceOwnerEpoch,
			SnapshotSequence:                uint64(100 + index),
			AppliedOwnerTransactionSequence: 0,
			DataPageCount:                   device.DataPageCount,
		}, bitmap)
		if err != nil {
			t.Fatalf("allocator %s: %v", device.DeviceUUID, err)
		}
		inputs[index] = OwnerAllocatorDeviceSnapshot{
			DeviceUUID: device.DeviceUUID,
			Geometry:   geometry,
			Snapshot:   snapshot,
		}
	}
	return ownerAllocatorTestFixture{
		state:      state,
		inputs:     inputs,
		geometries: geometries,
	}
}

func ownerAllocatorTestRequest(
	state OwnerStateSnapshot,
	demands []OwnerStateContentDemand,
	maxExtents uint32,
) OwnerReserveRequest {
	return OwnerReserveRequest{
		ClusterID:                  state.ClusterID,
		OwnerGroupID:               state.OwnerGroupID,
		CurrentOwnerID:             state.CurrentOwnerID,
		AnchorDeviceUUID:           state.AnchorDeviceUUID,
		StorageCompatibilityID:     state.StorageCompatibilityID,
		OwnerEpoch:                 state.OwnerEpoch,
		GroupConfigurationSequence: state.GroupConfigurationSequence,
		MembershipSHA256:           state.MembershipSHA256,
		RequestID:                  "reserve-request",
		CheckpointID:               "checkpoint-reserve",
		ProducerID:                 "producer-reserve",
		DedupDomainID:              "dedup-domain-reserve",
		SharingPolicyID:            "sharing-policy-reserve",
		MaxExtents:                 maxExtents,
		ContentDemands:             append([]OwnerStateContentDemand(nil), demands...),
		AuthorityEvidence: OwnerStateAuthorityEvidence{
			SchedulerReserveSHA256:     sha256.Sum256([]byte("scheduler-reserve-authority")),
			ProducerCapabilitySHA256:   sha256.Sum256([]byte("producer-capability-authority")),
			PublicationAuthoritySHA256: sha256.Sum256([]byte("publication-authority")),
			ReclaimAuthoritySHA256:     sha256.Sum256([]byte("reclaim-authority")),
		},
	}
}

func ownerAllocatorTestMemoryRequest(
	state OwnerStateSnapshot,
	identity string,
	pages uint64,
	maxExtents uint32,
) OwnerReserveRequest {
	request := ownerAllocatorTestRequest(state, []OwnerStateContentDemand{{
		Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
		ObjectID:         1,
		ByteLength:       pages * uint64(ContentPageBytes),
		CapacityPages:    pages,
		LogicalPageStart: 0,
	}}, maxExtents)
	request.RequestID = "request-" + identity
	request.CheckpointID = "checkpoint-" + identity
	return request
}

func ownerAllocatorLastRecord(t *testing.T, snapshot OwnerStateSnapshot) OwnerStateAllocationRecord {
	t.Helper()
	records := snapshot.Records()
	if len(records) == 0 {
		t.Fatalf("Owner state has no allocation record")
	}
	return records[len(records)-1]
}

func ownerAllocatorInputBitmaps(inputs []OwnerAllocatorDeviceSnapshot) map[string][]byte {
	result := make(map[string][]byte, len(inputs))
	for _, input := range inputs {
		result[input.DeviceUUID] = input.Snapshot.BitmapBytes()
	}
	return result
}

func ownerAllocatorRequireInputBitmaps(
	t *testing.T,
	inputs []OwnerAllocatorDeviceSnapshot,
	want map[string][]byte,
) {
	t.Helper()
	for _, input := range inputs {
		if !reflect.DeepEqual(input.Snapshot.BitmapBytes(), want[input.DeviceUUID]) {
			t.Fatalf("input bitmap %s was mutated", input.DeviceUUID)
		}
	}
}

func ownerAllocatorRequirePlanCanonical(
	t *testing.T,
	fixture ownerAllocatorTestFixture,
	plan OwnerCheckpointReservePlan,
) {
	t.Helper()
	anchorGeometry := fixture.geometries[fixture.state.AnchorDeviceUUID]
	for name, snapshot := range map[string]OwnerStateSnapshot{
		"PREPARING": plan.PreparingOwnerState,
		"GRANTED":   plan.GrantedOwnerState,
		"REJECTED":  plan.RejectedOwnerState,
	} {
		if snapshot.SnapshotSequence == 0 {
			continue
		}
		if _, err := CanonicalOwnerStateBytes(snapshot, anchorGeometry); err != nil {
			t.Fatalf("%s Owner state: %v", name, err)
		}
	}
	for _, update := range plan.AllocatorUpdates {
		if _, err := CanonicalAllocatorSnapshotBytes(
			update.DesiredSnapshot, fixture.geometries[update.DeviceUUID]); err != nil {
			t.Fatalf("allocator update %s: %v", update.DeviceUUID, err)
		}
	}
}

func ownerAllocatorRequirePlansEqual(
	t *testing.T,
	fixture ownerAllocatorTestFixture,
	left, right OwnerCheckpointReservePlan,
) {
	t.Helper()
	if left.Outcome != right.Outcome || left.RequestSHA256 != right.RequestSHA256 ||
		!reflect.DeepEqual(left.Record, right.Record) ||
		!reflect.DeepEqual(left.ReservedDescriptors, right.ReservedDescriptors) {
		t.Fatalf("deterministic plan metadata differs")
	}
	anchor := fixture.geometries[fixture.state.AnchorDeviceUUID]
	for _, pair := range [][2]OwnerStateSnapshot{
		{left.PreparingOwnerState, right.PreparingOwnerState},
		{left.GrantedOwnerState, right.GrantedOwnerState},
		{left.RejectedOwnerState, right.RejectedOwnerState},
	} {
		if pair[0].SnapshotSequence == 0 && pair[1].SnapshotSequence == 0 {
			continue
		}
		leftWire, err := CanonicalOwnerStateBytes(pair[0], anchor)
		if err != nil {
			t.Fatalf("left canonical Owner state: %v", err)
		}
		rightWire, err := CanonicalOwnerStateBytes(pair[1], anchor)
		if err != nil {
			t.Fatalf("right canonical Owner state: %v", err)
		}
		if !reflect.DeepEqual(leftWire, rightWire) {
			t.Fatalf("deterministic Owner-state bytes differ")
		}
	}
	if len(left.AllocatorUpdates) != len(right.AllocatorUpdates) {
		t.Fatalf("allocator update counts differ")
	}
	for index := range left.AllocatorUpdates {
		if left.AllocatorUpdates[index].DeviceUUID != right.AllocatorUpdates[index].DeviceUUID ||
			left.AllocatorUpdates[index].PreviousSnapshotSequence !=
				right.AllocatorUpdates[index].PreviousSnapshotSequence {
			t.Fatalf("allocator update identity differs at %d", index)
		}
		uuid := left.AllocatorUpdates[index].DeviceUUID
		leftWire, err := CanonicalAllocatorSnapshotBytes(
			left.AllocatorUpdates[index].DesiredSnapshot, fixture.geometries[uuid])
		if err != nil {
			t.Fatalf("left allocator: %v", err)
		}
		rightWire, err := CanonicalAllocatorSnapshotBytes(
			right.AllocatorUpdates[index].DesiredSnapshot, fixture.geometries[uuid])
		if err != nil {
			t.Fatalf("right allocator: %v", err)
		}
		if !reflect.DeepEqual(leftWire, rightWire) {
			t.Fatalf("deterministic allocator bytes differ at %d", index)
		}
	}
}

func ownerAllocatorApplyUpdates(
	inputs []OwnerAllocatorDeviceSnapshot,
	updates []OwnerAllocatorSnapshotUpdate,
) []OwnerAllocatorDeviceSnapshot {
	result := ownerAllocatorCloneInputs(inputs)
	byUUID := make(map[string]AllocatorSnapshot, len(updates))
	for _, update := range updates {
		byUUID[update.DeviceUUID] = update.DesiredSnapshot.Clone()
	}
	for index := range result {
		if snapshot, exists := byUUID[result[index].DeviceUUID]; exists {
			result[index].Snapshot = snapshot
		}
	}
	return result
}

func ownerAllocatorCloneInputs(
	inputs []OwnerAllocatorDeviceSnapshot,
) []OwnerAllocatorDeviceSnapshot {
	result := append([]OwnerAllocatorDeviceSnapshot(nil), inputs...)
	for index := range result {
		result[index].Snapshot = result[index].Snapshot.Clone()
	}
	return result
}

func ownerAllocatorDemandPages(demands []OwnerStateContentDemand) uint64 {
	var result uint64
	for _, demand := range demands {
		result += demand.CapacityPages
	}
	return result
}

func ownerAllocatorStateWithHighWaters(
	t *testing.T,
	base OwnerStateSnapshot,
	snapshotSequence,
	nextAllocationRecordID,
	nextOwnerTransactionSequence uint64,
) OwnerStateSnapshot {
	t.Helper()
	result, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    base.ClusterID,
		OwnerGroupID:                 base.OwnerGroupID,
		CurrentOwnerID:               base.CurrentOwnerID,
		AnchorDeviceUUID:             base.AnchorDeviceUUID,
		StorageCompatibilityID:       base.StorageCompatibilityID,
		OwnerEpoch:                   base.OwnerEpoch,
		GroupConfigurationSequence:   base.GroupConfigurationSequence,
		MembershipSHA256:             base.MembershipSHA256,
		SnapshotSequence:             snapshotSequence,
		NextAllocationRecordID:       nextAllocationRecordID,
		NextOwnerTransactionSequence: nextOwnerTransactionSequence,
		Devices:                      base.Devices(),
		Records:                      base.Records(),
	})
	if err != nil {
		t.Fatalf("high-water state: %v", err)
	}
	return result
}

func ownerAllocatorRequestForState(
	state OwnerStateSnapshot,
	base OwnerReserveRequest,
) OwnerReserveRequest {
	base.ClusterID = state.ClusterID
	base.OwnerGroupID = state.OwnerGroupID
	base.CurrentOwnerID = state.CurrentOwnerID
	base.AnchorDeviceUUID = state.AnchorDeviceUUID
	base.StorageCompatibilityID = state.StorageCompatibilityID
	base.OwnerEpoch = state.OwnerEpoch
	base.GroupConfigurationSequence = state.GroupConfigurationSequence
	base.MembershipSHA256 = state.MembershipSHA256
	return base
}
