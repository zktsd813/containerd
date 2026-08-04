package trcxl007

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func TestCommittedOwnerSealReplayMatchesFreshPlanWithoutMutation(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	original := fixture.committed.Clone()

	replay, err := BuildCommittedOwnerSealReplayPlan(
		fixture.committed,
		fixture.freshPlan.AllocationRecordID(),
		fixture.publicationBytes,
		fixture.initialMapBytes,
	)
	if err != nil {
		t.Fatalf("BuildCommittedOwnerSealReplayPlan: %v", err)
	}
	if !reflect.DeepEqual(fixture.committed, original) {
		t.Fatal("committed replay builder mutated its Owner-state input")
	}
	if !reflect.DeepEqual(replay.Plan(), fixture.freshPlan) {
		t.Fatal("committed replay plan differs from the fresh seal plan")
	}
	if replay.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatalf("committed replay H = %x, want %x",
			replay.ExpectedOwnerVerifiedSealSHA256(), fixture.freshSeal.SHA256())
	}
	if err := replay.VerifyRecomputedSeal(fixture.freshSeal); err != nil {
		t.Fatalf("VerifyRecomputedSeal: %v", err)
	}

	// Exact terminal state planning remains mutation-free and idempotent when
	// an actual complete-transcript seal is explicitly supplied.
	terminal, err := PlanCommittingOwnerSealCompletion(
		fixture.committed, replay.Plan(), fixture.freshSeal)
	if err != nil {
		t.Fatalf("terminal replay transition: %v", err)
	}
	if !reflect.DeepEqual(terminal, fixture.committed) {
		t.Fatal("terminal replay changed the committed Owner snapshot")
	}
}

func TestCommittedOwnerSealReplayDetachesInputsAndAccessors(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	ownerInput := fixture.committed.Clone()
	publicationInput := append([]byte(nil), fixture.publicationBytes...)
	mappingInput := append([]byte(nil), fixture.initialMapBytes...)

	replay, err := BuildCommittedOwnerSealReplayPlan(
		ownerInput, 29, publicationInput, mappingInput)
	if err != nil {
		t.Fatalf("BuildCommittedOwnerSealReplayPlan: %v", err)
	}
	publicationInput[0] ^= 0xff
	mappingInput[0] ^= 0xff
	ownerInput.records[0].CheckpointID = "mutated-checkpoint"
	ownerInput.records[0].Fragments[0].Extents[0].StartDataPageIndex++

	first := replay.Plan()
	devices := first.Devices()
	objects := first.Objects()
	runs := first.ExtentRuns()
	devices[0].DeviceUUID = "mutated-device"
	objects[0].ObjectID++
	runs[0].StartDataPageIndex++
	second := replay.Plan()
	if !reflect.DeepEqual(second, fixture.freshPlan) {
		t.Fatal("input or accessor mutation reached the committed replay plan")
	}
	if replay.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("input mutation reached the committed replay seal scalar")
	}
	if err := replay.VerifyRecomputedSeal(fixture.freshSeal); err != nil {
		t.Fatalf("detached replay seal verification: %v", err)
	}
}

func TestCommittedOwnerSealReplaySelectsMiddleRecordAndPreservesNeighbors(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	target := fixture.committing.Records()[0]
	left := ownerSealRecoveryTestRejectedRecord(target, 28, 80, "left-terminal")
	right := ownerSealRecoveryTestRejectedRecord(target, 30, 90, "right-terminal")
	multiCommitting := ownerSealRecoveryTestRebuildOwner(
		t,
		fixture.committing,
		nil,
		[]OwnerStateAllocationRecord{left, target, right},
		fixture.committing.SnapshotSequence,
		31,
		fixture.committing.NextOwnerTransactionSequence,
	)
	multiCommitted, err := PlanCommittingOwnerSealCompletion(
		multiCommitting, fixture.freshPlan, fixture.freshSeal)
	if err != nil {
		t.Fatalf("construct middle-record COMMITTED state: %v", err)
	}
	original := multiCommitted.Clone()
	replay, err := BuildCommittedOwnerSealReplayPlan(
		multiCommitted, 29, fixture.publicationBytes, fixture.initialMapBytes)
	if err != nil {
		t.Fatalf("middle-record committed replay: %v", err)
	}
	if !reflect.DeepEqual(multiCommitted, original) ||
		!reflect.DeepEqual(replay.Plan(), fixture.freshPlan) ||
		replay.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("middle-record replay changed a neighbor, input, plan, or durable H")
	}
	if err := replay.VerifyRecomputedSeal(fixture.freshSeal); err != nil {
		t.Fatalf("middle-record full seal verification: %v", err)
	}
	records := multiCommitted.Records()
	if len(records) != 3 || !reflect.DeepEqual(records[0], left) ||
		!reflect.DeepEqual(records[2], right) ||
		records[1].State != OwnerAllocationCommitted ||
		records[1].AllocationRecordID != 29 {
		t.Fatalf("middle-record COMMITTED state changed a neighbor: %#v", records)
	}
}

func TestCommittedOwnerSealReplayCannotExposeOrMintOpaqueSeal(t *testing.T) {
	resultType := reflect.TypeOf(CommittedOwnerSealReplayPlan{})
	sealType := reflect.TypeOf(OwnerVerifiedSeal{})
	for index := 0; index < resultType.NumField(); index++ {
		if resultType.Field(index).Type == sealType {
			t.Fatalf("replay result field %q exposes an OwnerVerifiedSeal",
				resultType.Field(index).Name)
		}
	}
	for index := 0; index < resultType.NumMethod(); index++ {
		method := resultType.Method(index)
		for output := 0; output < method.Type.NumOut(); output++ {
			if method.Type.Out(output) == sealType {
				t.Fatalf("replay result method %q returns an OwnerVerifiedSeal", method.Name)
			}
		}
	}

	functionType := reflect.TypeOf(BuildCommittedOwnerSealReplayPlan)
	wantInputs := []reflect.Type{
		reflect.TypeOf(OwnerStateSnapshot{}),
		reflect.TypeOf(uint64(0)),
		reflect.TypeOf([]byte(nil)),
		reflect.TypeOf([]byte(nil)),
	}
	if functionType.NumIn() != len(wantInputs) || functionType.NumOut() != 2 {
		t.Fatalf("committed replay signature has %d inputs/%d outputs, want 4/2",
			functionType.NumIn(), functionType.NumOut())
	}
	for index := range wantInputs {
		if functionType.In(index) != wantInputs[index] {
			t.Fatalf("committed replay input %d = %s, want %s",
				index, functionType.In(index), wantInputs[index])
		}
	}
}

func TestCommittedOwnerSealReplayRejectsLifecycleAndMediaMismatches(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	base := fixture.committed
	records := base.Records()

	nextMismatch := ownerSealRecoveryTestRebuildOwner(
		t, base, nil, records, base.SnapshotSequence,
		base.NextAllocationRecordID, base.NextOwnerTransactionSequence+1)
	lowSnapshot := ownerSealRecoveryTestRebuildOwner(
		t, base, nil, records, 2,
		base.NextAllocationRecordID, base.NextOwnerTransactionSequence)

	transactionAtOne := base.Clone()
	transactionAtOne.records[0].OwnerTransactionSequence = 1

	zeroSeal := base.Clone()
	zeroSeal.records[0].OwnerVerifiedSealSHA256 = [sha256.Size]byte{}

	corruptPublication := append([]byte(nil), fixture.publicationBytes...)
	corruptPublication[len(corruptPublication)-1] ^= 0x80
	corruptMap := append([]byte(nil), fixture.initialMapBytes...)
	corruptMap[len(corruptMap)-1] ^= 0x80

	tests := []struct {
		name        string
		owner       OwnerStateSnapshot
		allocation  uint64
		publication []byte
		mapping     []byte
	}{
		{name: "GRANTED state", owner: fixture.producer.owner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "COMMITTING state", owner: fixture.committing, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "absent allocation", owner: base, allocation: 30, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "zero allocation", owner: base, allocation: 0, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "overflow allocation", owner: base, allocation: cxlcheckpoint.MaxSignedLong + 1, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "next transaction mismatch", owner: nextMismatch, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "snapshot cannot derive Q", owner: lowSnapshot, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "terminal transaction cannot derive S", owner: transactionAtOne, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "zero durable H", owner: zeroSeal, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "corrupt publication", owner: base, allocation: 29, publication: corruptPublication, mapping: fixture.initialMapBytes},
		{name: "corrupt map", owner: base, allocation: 29, publication: fixture.publicationBytes, mapping: corruptMap},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildCommittedOwnerSealReplayPlan(
				test.owner,
				test.allocation,
				test.publication,
				test.mapping,
			); !errors.Is(err, ErrInvalidOwnerSealRecoveryPlan) {
				t.Fatalf("error = %v, want committed replay rejection", err)
			}
		})
	}
}

func TestCommittedOwnerSealReplayRetainedMutationRequiresFullSealVerification(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	records := fixture.committed.Records()
	target := cloneOwnerStateRecord(records[0])

	// A terminal record that advances an immutable retained allocation field
	// can still be made structurally valid, but must not reconstruct the same
	// hypothetical GRANTED record committed by the seal plan.
	target.MaxExtents++
	mutated := ownerSealRecoveryTestRebuildOwner(
		t,
		fixture.committed,
		nil,
		[]OwnerStateAllocationRecord{target},
		fixture.committed.SnapshotSequence,
		fixture.committed.NextAllocationRecordID,
		fixture.committed.NextOwnerTransactionSequence,
	)
	replay, err := BuildCommittedOwnerSealReplayPlan(
		mutated, 29, fixture.publicationBytes, fixture.initialMapBytes,
	)
	if err != nil {
		t.Fatalf("structurally valid retained-record mutation: %v", err)
	}
	if reflect.DeepEqual(replay.Plan(), fixture.freshPlan) {
		t.Fatal("retained-record mutation did not change the reconstructed plan")
	}
	if replay.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("retained-record mutation changed the durable comparison H")
	}
	if err := replay.VerifyRecomputedSeal(fixture.freshSeal); !errors.Is(
		err, ErrInvalidOwnerSealRecoveryPlan,
	) {
		t.Fatalf("fresh-plan seal verification error = %v, want plan-binding rejection", err)
	}
	mutatedPages := ownerSealTranscriptTestPages(t, fixture.producer, replay.Plan())
	mutatedSeal := ownerSealTranscriptTestComplete(t, replay.Plan(), mutatedPages, nil)
	if mutatedSeal.SHA256() == replay.ExpectedOwnerVerifiedSealSHA256() {
		t.Fatal("retained-record mutation unexpectedly reproduced durable COMMITTED H")
	}
	if err := replay.VerifyRecomputedSeal(mutatedSeal); !errors.Is(
		err, ErrInvalidOwnerSealRecoveryPlan,
	) {
		t.Fatalf("mutated full-transcript verification error = %v, want H rejection", err)
	}
}
