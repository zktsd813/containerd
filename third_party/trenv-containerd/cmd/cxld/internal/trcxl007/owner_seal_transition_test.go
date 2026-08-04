package trcxl007

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type ownerSealTransitionTestFixture struct {
	granted     OwnerStateSnapshot
	plan        OwnerSealPlan
	seal        OwnerVerifiedSeal
	targetIndex int
}

func TestOwnerSealStateTransitionsKnownSequenceTargetByIDRecoveryAndReplay(t *testing.T) {
	fixture := newOwnerSealTransitionTestFixture(t)
	before := fixture.granted.Records()
	transitions, err := PlanFreshOwnerSealStateTransitions(
		fixture.granted, fixture.plan, fixture.seal)
	if err != nil {
		t.Fatalf("PlanFreshOwnerSealStateTransitions: %v", err)
	}
	committing := transitions.Committing()
	committed := transitions.Committed()
	sealSHA256 := fixture.seal.SHA256()

	if committing.SnapshotSequence != 9 ||
		committing.NextOwnerTransactionSequence != 104 ||
		committed.SnapshotSequence != 10 ||
		committed.NextOwnerTransactionSequence != 105 {
		t.Fatalf(
			"snapshot/next transaction sequence = COMMITTING %d/%d COMMITTED %d/%d",
			committing.SnapshotSequence,
			committing.NextOwnerTransactionSequence,
			committed.SnapshotSequence,
			committed.NextOwnerTransactionSequence)
	}
	committingRecords := committing.Records()
	committedRecords := committed.Records()
	if len(committingRecords) != 3 || len(committedRecords) != 3 || fixture.targetIndex != 1 {
		t.Fatalf("record count/target index = %d/%d/%d, want 3/3/1",
			len(committingRecords), len(committedRecords), fixture.targetIndex)
	}
	if committingRecords[fixture.targetIndex].State != OwnerAllocationCommitting ||
		committingRecords[fixture.targetIndex].OwnerTransactionSequence != 103 ||
		committingRecords[fixture.targetIndex].OwnerVerifiedSealSHA256 != sealSHA256 {
		t.Fatalf("COMMITTING target = %#v", committingRecords[fixture.targetIndex])
	}
	if committedRecords[fixture.targetIndex].State != OwnerAllocationCommitted ||
		committedRecords[fixture.targetIndex].OwnerTransactionSequence != 104 ||
		committedRecords[fixture.targetIndex].OwnerVerifiedSealSHA256 != sealSHA256 {
		t.Fatalf("COMMITTED target = %#v", committedRecords[fixture.targetIndex])
	}
	for _, index := range []int{0, 2} {
		if !reservedDescriptorRecordsEqual(before[index], committingRecords[index]) ||
			!reservedDescriptorRecordsEqual(before[index], committedRecords[index]) {
			t.Fatalf("non-target record %d changed across seal transitions", index)
		}
	}
	ownerSealTransitionTestAssertSnapshotScaffoldPreserved(
		t, fixture.granted, committing)
	ownerSealTransitionTestAssertSnapshotScaffoldPreserved(
		t, fixture.granted, committed)

	recovered, err := PlanCommittingOwnerSealCompletion(
		committing, fixture.plan, fixture.seal)
	if err != nil {
		t.Fatalf("PlanCommittingOwnerSealCompletion: %v", err)
	}
	if !ownerSealTransitionTestSnapshotsEqual(recovered, committed) {
		t.Fatal("COMMITTING recovery did not derive the exact planned COMMITTED snapshot")
	}

	replayInput := committed.Clone()
	replayed, err := PlanCommittingOwnerSealCompletion(
		replayInput, fixture.plan, fixture.seal)
	if err != nil {
		t.Fatalf("exact COMMITTED replay: %v", err)
	}
	if !ownerSealTransitionTestSnapshotsEqual(replayed, replayInput) ||
		!ownerSealTransitionTestSnapshotsEqual(replayInput, committed) {
		t.Fatal("exact COMMITTED replay mutated or substituted the terminal snapshot")
	}
}

func TestOwnerSealStateTransitionsRejectFreshMismatches(t *testing.T) {
	t.Run("stale plan snapshot", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.plan.ownerSnapshotSequence--
		ownerSealTransitionTestRefreshPlanAndSeal(&fixture.plan, &fixture.seal)
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("mutated plan identity", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.plan.requestID = "substituted-request"
		ownerSealTransitionTestRefreshPlanAndSeal(&fixture.plan, &fixture.seal)
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("mutated plan integrity", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.plan.runs[0].StartDataPageIndex++
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("zero seal", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		ownerSealTransitionTestRequireError(
			t, fixture.granted, fixture.plan, OwnerVerifiedSeal{})
	})
	t.Run("seal plan binding", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.seal.planIntegritySHA256[0] ^= 0xff
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("canonical grant record", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.granted.records[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex++
		if err := fixture.granted.Validate(); err != nil {
			t.Fatalf("mutated but structurally valid GRANTED state: %v", err)
		}
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("Owner group", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.granted.OwnerGroupID = "substituted-owner-group"
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("snapshot sequence", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.granted.SnapshotSequence--
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("next transaction", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.granted.NextOwnerTransactionSequence++
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("missing target", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		records := fixture.granted.Records()
		records = append(records[:fixture.targetIndex], records[fixture.targetIndex+1:]...)
		fixture.granted = ownerSealTransitionTestRebuild(
			t,
			fixture.granted,
			fixture.granted.SnapshotSequence,
			fixture.granted.NextOwnerTransactionSequence,
			records)
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("wrong state", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.granted.records[fixture.targetIndex].State = OwnerAllocationCanceling
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
	t.Run("sequence overflow", func(t *testing.T) {
		fixture := newOwnerSealTransitionTestFixture(t)
		fixture.plan.ownerSnapshotSequence = cxlcheckpoint.MaxSignedLong
		fixture.plan.sealTransaction = cxlcheckpoint.MaxSignedLong
		ownerSealTransitionTestRefreshPlanAndSeal(&fixture.plan, &fixture.seal)
		ownerSealTransitionTestRequireError(t, fixture.granted, fixture.plan, fixture.seal)
	})
}

func TestOwnerSealStateTransitionsRejectCompletionAndReplayMismatches(t *testing.T) {
	fixture := newOwnerSealTransitionTestFixture(t)
	transitions, err := PlanFreshOwnerSealStateTransitions(
		fixture.granted, fixture.plan, fixture.seal)
	if err != nil {
		t.Fatalf("PlanFreshOwnerSealStateTransitions: %v", err)
	}
	committing := transitions.Committing()
	committed := transitions.Committed()

	for _, test := range []struct {
		name  string
		state func() OwnerStateSnapshot
		plan  func() OwnerSealPlan
		seal  func() OwnerVerifiedSeal
	}{
		{
			name:  "different supplied H",
			state: func() OwnerStateSnapshot { return committing.Clone() },
			plan:  func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal {
				value := fixture.seal
				value.sha256 = sha256.Sum256([]byte("different-owner-verified-seal"))
				return value
			},
		},
		{
			name:  "zero supplied H",
			state: func() OwnerStateSnapshot { return committing.Clone() },
			plan:  func() OwnerSealPlan { return fixture.plan },
			seal:  func() OwnerVerifiedSeal { return OwnerVerifiedSeal{} },
		},
		{
			name: "different durable H",
			state: func() OwnerStateSnapshot {
				value := committing.Clone()
				value.records[fixture.targetIndex].OwnerVerifiedSealSHA256 =
					sha256.Sum256([]byte("different-durable-seal"))
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "wrong COMMITTING state",
			state: func() OwnerStateSnapshot {
				value := committing.Clone()
				value.records[fixture.targetIndex].State = OwnerAllocationCommitted
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "stale COMMITTING snapshot",
			state: func() OwnerStateSnapshot {
				value := committing.Clone()
				value.SnapshotSequence--
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "COMMITTING next transaction",
			state: func() OwnerStateSnapshot {
				value := committing.Clone()
				value.NextOwnerTransactionSequence++
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "COMMITTING record mutation",
			state: func() OwnerStateSnapshot {
				value := committing.Clone()
				value.records[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex++
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "COMMITTING Owner group",
			state: func() OwnerStateSnapshot {
				value := committing.Clone()
				value.OwnerGroupID = "substituted-owner-group"
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "missing COMMITTING target",
			state: func() OwnerStateSnapshot {
				records := committing.Records()
				records = append(records[:fixture.targetIndex], records[fixture.targetIndex+1:]...)
				return ownerSealTransitionTestRebuild(
					t,
					committing,
					committing.SnapshotSequence,
					committing.NextOwnerTransactionSequence,
					records)
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name:  "mutated recovery plan",
			state: func() OwnerStateSnapshot { return committing.Clone() },
			plan: func() OwnerSealPlan {
				value := cloneOwnerSealPlan(fixture.plan)
				value.checkpointID = "substituted-checkpoint"
				value.integritySHA256 = ownerSealPlanSHA256(value)
				return value
			},
			seal: func() OwnerVerifiedSeal {
				value := fixture.seal
				plan := cloneOwnerSealPlan(fixture.plan)
				plan.checkpointID = "substituted-checkpoint"
				plan.integritySHA256 = ownerSealPlanSHA256(plan)
				value.planIntegritySHA256 = plan.IntegritySHA256()
				return value
			},
		},
		{
			name: "terminal replay different H",
			state: func() OwnerStateSnapshot {
				value := committed.Clone()
				value.records[fixture.targetIndex].OwnerVerifiedSealSHA256 =
					sha256.Sum256([]byte("different-terminal-seal"))
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "terminal replay transaction",
			state: func() OwnerStateSnapshot {
				value := committed.Clone()
				value.records[fixture.targetIndex].OwnerTransactionSequence =
					fixture.plan.SealTransactionSequence()
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
		{
			name: "terminal replay after unrelated snapshot",
			state: func() OwnerStateSnapshot {
				value := committed.Clone()
				value.SnapshotSequence++
				return value
			},
			plan: func() OwnerSealPlan { return fixture.plan },
			seal: func() OwnerVerifiedSeal { return fixture.seal },
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, completionErr := PlanCommittingOwnerSealCompletion(
				test.state(), test.plan(), test.seal())
			if !errors.Is(completionErr, ErrInvalidOwnerSealStateTransition) {
				t.Fatalf("error = %v, want ErrInvalidOwnerSealStateTransition", completionErr)
			}
		})
	}
}

func TestOwnerSealStateTransitionsDefensiveCopiesAndPureShape(t *testing.T) {
	fixture := newOwnerSealTransitionTestFixture(t)
	transitions, err := PlanFreshOwnerSealStateTransitions(
		fixture.granted, fixture.plan, fixture.seal)
	if err != nil {
		t.Fatalf("PlanFreshOwnerSealStateTransitions: %v", err)
	}

	fixture.granted.devices[0].DeviceUUID = "mutated-input-device"
	fixture.granted.records[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex = 99
	first := transitions.Committing()
	if first.Devices()[0].DeviceUUID != "device-a" ||
		first.Records()[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex != 10 {
		t.Fatal("post-plan input mutation reached detached COMMITTING snapshot")
	}

	first.devices[0].DeviceUUID = "mutated-accessor-device"
	first.records[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex = 98
	second := transitions.Committing()
	terminal := transitions.Committed()
	if second.Devices()[0].DeviceUUID != "device-a" ||
		second.Records()[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex != 10 ||
		terminal.Devices()[0].DeviceUUID != "device-a" ||
		terminal.Records()[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex != 10 {
		t.Fatal("snapshot accessor mutation reached stored transition or sibling snapshot")
	}

	completionInput := second.Clone()
	completion, err := PlanCommittingOwnerSealCompletion(
		completionInput, fixture.plan, fixture.seal)
	if err != nil {
		t.Fatalf("PlanCommittingOwnerSealCompletion: %v", err)
	}
	completion.devices[0].DeviceUUID = "mutated-completion-device"
	completion.records[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex = 97
	if completionInput.Devices()[0].DeviceUUID != "device-a" ||
		completionInput.Records()[fixture.targetIndex].Fragments[0].Extents[0].StartDataPageIndex != 10 {
		t.Fatal("completion result aliases COMMITTING input")
	}

	typeOfTransitions := reflect.TypeOf(OwnerSealStateTransitions{})
	if typeOfTransitions.NumField() != 2 {
		t.Fatalf("OwnerSealStateTransitions field count = %d, want 2", typeOfTransitions.NumField())
	}
	for index := 0; index < typeOfTransitions.NumField(); index++ {
		field := typeOfTransitions.Field(index)
		if field.Type != reflect.TypeOf(OwnerStateSnapshot{}) {
			t.Fatalf("transition field %q has type %s, want OwnerStateSnapshot",
				field.Name, field.Type)
		}
	}
}

func newOwnerSealTransitionTestFixture(t *testing.T) ownerSealTransitionTestFixture {
	t.Helper()
	producer := newProducerScatterTestFixture(t)
	target := cloneOwnerStateRecord(producer.owner.records[0])
	records := []OwnerStateAllocationRecord{
		ownerStateTestNoSpaceRecord(5),
		target,
		ownerStateTestNoSpaceRecord(40),
	}
	granted, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    producer.owner.ClusterID,
		OwnerGroupID:                 producer.owner.OwnerGroupID,
		CurrentOwnerID:               producer.owner.CurrentOwnerID,
		AnchorDeviceUUID:             producer.owner.AnchorDeviceUUID,
		StorageCompatibilityID:       producer.owner.StorageCompatibilityID,
		OwnerEpoch:                   producer.owner.OwnerEpoch,
		GroupConfigurationSequence:   producer.owner.GroupConfigurationSequence,
		MembershipSHA256:             producer.owner.MembershipSHA256,
		SnapshotSequence:             producer.owner.SnapshotSequence,
		NextAllocationRecordID:       41,
		NextOwnerTransactionSequence: producer.owner.NextOwnerTransactionSequence,
		Devices:                      producer.owner.Devices(),
		Records:                      records,
	})
	if err != nil {
		t.Fatalf("multi-record GRANTED fixture: %v", err)
	}
	producerPlan, err := BuildProducerScatterPlan(granted, target.AllocationRecordID, producer.initial)
	if err != nil {
		t.Fatalf("BuildProducerScatterPlan multi-record fixture: %v", err)
	}
	plan, err := BuildFreshOwnerSealPlan(
		granted, target.AllocationRecordID, producerPlan, producer.initial)
	if err != nil {
		t.Fatalf("BuildFreshOwnerSealPlan multi-record fixture: %v", err)
	}
	seal := ownerSealTransitionTestSeal(plan, "owner-seal-transition-fixture")
	return ownerSealTransitionTestFixture{
		granted:     granted,
		plan:        plan,
		seal:        seal,
		targetIndex: 1,
	}
}

func ownerSealTransitionTestSeal(plan OwnerSealPlan, label string) OwnerVerifiedSeal {
	return OwnerVerifiedSeal{
		sha256:              sha256.Sum256([]byte(label)),
		planIntegritySHA256: plan.IntegritySHA256(),
	}
}

func ownerSealTransitionTestRefreshPlanAndSeal(
	plan *OwnerSealPlan,
	seal *OwnerVerifiedSeal,
) {
	plan.integritySHA256 = ownerSealPlanSHA256(*plan)
	seal.planIntegritySHA256 = plan.IntegritySHA256()
}

func ownerSealTransitionTestRequireError(
	t *testing.T,
	state OwnerStateSnapshot,
	plan OwnerSealPlan,
	seal OwnerVerifiedSeal,
) {
	t.Helper()
	_, err := PlanFreshOwnerSealStateTransitions(state, plan, seal)
	if !errors.Is(err, ErrInvalidOwnerSealStateTransition) {
		t.Fatalf("error = %v, want ErrInvalidOwnerSealStateTransition", err)
	}
}

func ownerSealTransitionTestRebuild(
	t *testing.T,
	base OwnerStateSnapshot,
	snapshotSequence uint64,
	nextTransactionSequence uint64,
	records []OwnerStateAllocationRecord,
) OwnerStateSnapshot {
	t.Helper()
	result, err := ownerSealBuildStateSnapshot(
		base, snapshotSequence, nextTransactionSequence, records)
	if err != nil {
		t.Fatalf("rebuild Owner state fixture: %v", err)
	}
	return result
}

func ownerSealTransitionTestAssertSnapshotScaffoldPreserved(
	t *testing.T,
	want OwnerStateSnapshot,
	got OwnerStateSnapshot,
) {
	t.Helper()
	if got.ClusterID != want.ClusterID ||
		got.OwnerGroupID != want.OwnerGroupID ||
		got.CurrentOwnerID != want.CurrentOwnerID ||
		got.AnchorDeviceUUID != want.AnchorDeviceUUID ||
		got.StorageCompatibilityID != want.StorageCompatibilityID ||
		got.OwnerEpoch != want.OwnerEpoch ||
		got.GroupConfigurationSequence != want.GroupConfigurationSequence ||
		got.MembershipSHA256 != want.MembershipSHA256 ||
		got.NextAllocationRecordID != want.NextAllocationRecordID ||
		!reflect.DeepEqual(got.Devices(), want.Devices()) {
		t.Fatal("Owner snapshot scaffold changed across seal transition")
	}
}

func ownerSealTransitionTestSnapshotsEqual(
	left OwnerStateSnapshot,
	right OwnerStateSnapshot,
) bool {
	return left.ClusterID == right.ClusterID &&
		left.OwnerGroupID == right.OwnerGroupID &&
		left.CurrentOwnerID == right.CurrentOwnerID &&
		left.AnchorDeviceUUID == right.AnchorDeviceUUID &&
		left.StorageCompatibilityID == right.StorageCompatibilityID &&
		left.OwnerEpoch == right.OwnerEpoch &&
		left.GroupConfigurationSequence == right.GroupConfigurationSequence &&
		left.MembershipSHA256 == right.MembershipSHA256 &&
		left.SnapshotSequence == right.SnapshotSequence &&
		left.NextAllocationRecordID == right.NextAllocationRecordID &&
		left.NextOwnerTransactionSequence == right.NextOwnerTransactionSequence &&
		reflect.DeepEqual(left.Devices(), right.Devices()) &&
		reflect.DeepEqual(left.Records(), right.Records())
}
