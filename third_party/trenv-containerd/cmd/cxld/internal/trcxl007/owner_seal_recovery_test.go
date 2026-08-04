package trcxl007

import (
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type ownerSealRecoveryTestFixture struct {
	producer          producerScatterTestFixture
	freshPlan         OwnerSealPlan
	freshSeal         OwnerVerifiedSeal
	committing        OwnerStateSnapshot
	committed         OwnerStateSnapshot
	publicationBytes  []byte
	initialMapBytes   []byte
	initialMapping    cxlcheckpoint.ContentPlacementMap
	publication       cxlcheckpoint.PublicationV7
	publicationObject []cxlcheckpoint.ContentObject
}

func TestCommittingOwnerSealRecoveryMatchesFreshPlanSealAndCompletion(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		fixture.committing,
		fixture.freshPlan.AllocationRecordID(),
		fixture.publicationBytes,
		fixture.initialMapBytes,
	)
	if err != nil {
		t.Fatalf("BuildCommittingOwnerSealRecoveryPlan: %v", err)
	}
	recovered := recovery.Plan()
	if !reflect.DeepEqual(recovered, fixture.freshPlan) {
		t.Fatalf("recovered plan differs from fresh plan\nrecovered: %#v\nfresh: %#v",
			recovered, fixture.freshPlan)
	}
	if recovery.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatalf("expected recovered seal digest = %x, want fresh %x",
			recovery.ExpectedOwnerVerifiedSealSHA256(), fixture.freshSeal.SHA256())
	}
	pages := ownerSealTranscriptTestPages(t, fixture.producer, recovered)
	actualSeal := ownerSealTranscriptTestComplete(t, recovered, pages, nil)
	if err := recovery.VerifyRecomputedSeal(actualSeal); err != nil {
		t.Fatalf("VerifyRecomputedSeal: %v", err)
	}

	completed, err := PlanCommittingOwnerSealCompletion(
		fixture.committing, recovered, actualSeal)
	if err != nil {
		t.Fatalf("PlanCommittingOwnerSealCompletion: %v", err)
	}
	if !reflect.DeepEqual(completed, fixture.committed) {
		t.Fatalf("recovery completion differs from fresh terminal snapshot")
	}
	replayed, err := PlanCommittingOwnerSealCompletion(completed, recovered, actualSeal)
	if err != nil {
		t.Fatalf("terminal completion replay: %v", err)
	}
	if !reflect.DeepEqual(replayed, completed) {
		t.Fatal("terminal completion replay changed the Owner snapshot")
	}

	functionType := reflect.TypeOf(BuildCommittingOwnerSealRecoveryPlan)
	wantInputs := []reflect.Type{
		reflect.TypeOf(OwnerStateSnapshot{}),
		reflect.TypeOf(uint64(0)),
		reflect.TypeOf([]byte(nil)),
		reflect.TypeOf([]byte(nil)),
	}
	if functionType.NumIn() != len(wantInputs) || functionType.NumOut() != 2 {
		t.Fatalf("recovery builder signature has %d inputs/%d outputs, want 4/2",
			functionType.NumIn(), functionType.NumOut())
	}
	for index := range wantInputs {
		if functionType.In(index) != wantInputs[index] {
			t.Fatalf("recovery builder input %d = %s, want %s",
				index, functionType.In(index), wantInputs[index])
		}
	}
	resultType := reflect.TypeOf(CommittingOwnerSealRecoveryPlan{})
	sealType := reflect.TypeOf(OwnerVerifiedSeal{})
	for index := 0; index < resultType.NumField(); index++ {
		if resultType.Field(index).Type == sealType {
			t.Fatalf("recovery result field %q exposes an OwnerVerifiedSeal",
				resultType.Field(index).Name)
		}
	}
	for index := 0; index < resultType.NumMethod(); index++ {
		method := resultType.Method(index)
		for output := 0; output < method.Type.NumOut(); output++ {
			if method.Type.Out(output) == sealType {
				t.Fatalf("recovery result method %q returns an OwnerVerifiedSeal", method.Name)
			}
		}
	}
}

func TestCommittingOwnerSealRecoveryDetachesEveryInputAndAccessor(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	ownerInput := fixture.committing.Clone()
	publicationInput := append([]byte(nil), fixture.publicationBytes...)
	mappingInput := append([]byte(nil), fixture.initialMapBytes...)

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		ownerInput, 29, publicationInput, mappingInput)
	if err != nil {
		t.Fatalf("BuildCommittingOwnerSealRecoveryPlan: %v", err)
	}
	recovered := recovery.Plan()
	publicationInput[0] ^= 0xff
	mappingInput[0] ^= 0xff
	ownerInput.devices[0].DeviceUUID = "mutated-device"
	ownerInput.records[0].CheckpointID = "mutated-checkpoint"
	ownerInput.records[0].ContentDemands[0].ObjectID = 999
	ownerInput.records[0].Fragments[0].Extents[0].StartDataPageIndex = 99

	devices := recovered.Devices()
	objects := recovered.Objects()
	runs := recovered.ExtentRuns()
	devices[0].DeviceUUID = "mutated-accessor-device"
	objects[0].ObjectID = 999
	runs[0].StartDataPageIndex = 999
	if !reflect.DeepEqual(recovered, fixture.freshPlan) {
		t.Fatal("input or accessor mutation reached recovered compact plan")
	}
	if recovery.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("input mutation reached recovered expected seal digest")
	}
	if err := recovered.Validate(); err != nil {
		t.Fatalf("recovered plan after caller mutation: %v", err)
	}
	if err := recovery.VerifyRecomputedSeal(fixture.freshSeal); err != nil {
		t.Fatalf("actual seal verification after caller mutation: %v", err)
	}
}

func TestCommittingOwnerSealRecoveryRejectsNonExactEnvelopesAndVersions(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	padToPage := func(source []byte) []byte {
		result := append([]byte(nil), source...)
		padding := int(cxlcheckpoint.PageSize) - len(result)%int(cxlcheckpoint.PageSize)
		return append(result, make([]byte, padding)...)
	}
	corruptPublication := append([]byte(nil), fixture.publicationBytes...)
	corruptPublication[len(corruptPublication)-1] ^= 0x80
	corruptMapping := append([]byte(nil), fixture.initialMapBytes...)
	corruptMapping[len(corruptMapping)-1] ^= 0x80

	tests := []struct {
		name        string
		publication []byte
		mapping     []byte
	}{
		{name: "empty publication", publication: nil, mapping: fixture.initialMapBytes},
		{name: "truncated publication", publication: fixture.publicationBytes[:len(fixture.publicationBytes)-1], mapping: fixture.initialMapBytes},
		{name: "trailing publication", publication: append(append([]byte(nil), fixture.publicationBytes...), 0), mapping: fixture.initialMapBytes},
		{name: "capacity-padded publication", publication: padToPage(fixture.publicationBytes), mapping: fixture.initialMapBytes},
		{name: "corrupt publication", publication: corruptPublication, mapping: fixture.initialMapBytes},
		{name: "wrong publication envelope", publication: fixture.initialMapBytes, mapping: fixture.initialMapBytes},
		{name: "empty map", publication: fixture.publicationBytes, mapping: nil},
		{name: "truncated map", publication: fixture.publicationBytes, mapping: fixture.initialMapBytes[:len(fixture.initialMapBytes)-1]},
		{name: "trailing map", publication: fixture.publicationBytes, mapping: append(append([]byte(nil), fixture.initialMapBytes...), 0)},
		{name: "capacity-padded map", publication: fixture.publicationBytes, mapping: padToPage(fixture.initialMapBytes)},
		{name: "corrupt map", publication: fixture.publicationBytes, mapping: corruptMapping},
		{name: "wrong map envelope", publication: fixture.publicationBytes, mapping: fixture.publicationBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildCommittingOwnerSealRecoveryPlan(
				fixture.committing, 29, test.publication, test.mapping,
			); !errors.Is(err, ErrInvalidOwnerSealRecoveryPlan) {
				t.Fatalf("error = %v, want recovery-plan rejection", err)
			}
		})
	}

	publicationV2 := ownerSealRecoveryTestClonePublication(fixture.publication)
	publicationV2.MMTemplate.Version = 2
	publicationV2Bytes := ownerSealRecoveryTestPublicationBytes(t, publicationV2)
	if _, err := BuildCommittingOwnerSealRecoveryPlan(
		fixture.committing, 29, publicationV2Bytes, fixture.initialMapBytes,
	); !errors.Is(err, ErrInvalidOwnerSealRecoveryPlan) {
		t.Fatalf("typed metadata semantic version error = %v", err)
	}

	mappingV2 := ownerSealRecoveryTestCloneMapping(fixture.initialMapping)
	mappingV2.Version = 2
	mappingV2Bytes := ownerSealRecoveryTestMappingBytes(
		t, mappingV2, fixture.publicationObject)
	if _, err := BuildCommittingOwnerSealRecoveryPlan(
		fixture.committing, 29, fixture.publicationBytes, mappingV2Bytes,
	); !errors.Is(err, ErrInvalidOwnerSealRecoveryPlan) {
		t.Fatalf("initial map semantic version error = %v", err)
	}
}

func TestCommittingOwnerSealRecoveryRejectsExactJoinAndLifecycleMismatches(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	baseRecords := fixture.committing.Records()

	checkpointRecord := cloneOwnerStateRecord(baseRecords[0])
	checkpointRecord.CheckpointID = "different-checkpoint"
	checkpointOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, nil, []OwnerStateAllocationRecord{checkpointRecord},
		fixture.committing.SnapshotSequence,
		fixture.committing.NextAllocationRecordID,
		fixture.committing.NextOwnerTransactionSequence)

	demandRecord := cloneOwnerStateRecord(baseRecords[0])
	demandRecord.ContentDemands[3].ByteLength++
	demandOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, nil, []OwnerStateAllocationRecord{demandRecord},
		fixture.committing.SnapshotSequence,
		fixture.committing.NextAllocationRecordID,
		fixture.committing.NextOwnerTransactionSequence)

	extentRecord := cloneOwnerStateRecord(baseRecords[0])
	extentRecord.Fragments[0].Extents[0].StartDataPageIndex++
	extentOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, nil, []OwnerStateAllocationRecord{extentRecord},
		fixture.committing.SnapshotSequence,
		fixture.committing.NextAllocationRecordID,
		fixture.committing.NextOwnerTransactionSequence)

	nextMismatchOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, nil, baseRecords,
		fixture.committing.SnapshotSequence,
		fixture.committing.NextAllocationRecordID,
		fixture.committing.NextOwnerTransactionSequence+1)
	snapshotUnderflowOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, nil, baseRecords, 1,
		fixture.committing.NextAllocationRecordID,
		fixture.committing.NextOwnerTransactionSequence)

	sealAtGrantRecord := cloneOwnerStateRecord(baseRecords[0])
	sealAtGrantRecord.OwnerTransactionSequence = sealAtGrantRecord.ReservationTransactionSequence + 1
	sealAtGrantOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, nil, []OwnerStateAllocationRecord{sealAtGrantRecord},
		fixture.committing.SnapshotSequence,
		fixture.committing.NextAllocationRecordID,
		sealAtGrantRecord.OwnerTransactionSequence+1)

	deviceMismatch := fixture.committing.Devices()
	deviceMismatch[0].DataPageCount++
	deviceMismatchOwner := ownerSealRecoveryTestRebuildOwner(
		t, fixture.committing, deviceMismatch, baseRecords,
		fixture.committing.SnapshotSequence,
		fixture.committing.NextAllocationRecordID,
		fixture.committing.NextOwnerTransactionSequence)

	zeroSealOwner := fixture.committing.Clone()
	zeroSealOwner.records[0].OwnerVerifiedSealSHA256 = [sha256.Size]byte{}
	overflowOwner := fixture.committing.Clone()
	overflowOwner.records[0].OwnerTransactionSequence = cxlcheckpoint.MaxSignedLong
	overflowOwner.NextOwnerTransactionSequence = cxlcheckpoint.MaxSignedLong

	checkpointPublication := ownerSealRecoveryTestClonePublication(fixture.publication)
	checkpointPublication.CheckpointID = "different-checkpoint"
	checkpointPublicationBytes := ownerSealRecoveryTestPublicationBytes(t, checkpointPublication)
	ownerPublication := ownerSealRecoveryTestClonePublication(fixture.publication)
	ownerPublication.InitialAllocation.OwnerID = "different-owner"
	ownerPublicationBytes := ownerSealRecoveryTestPublicationBytes(t, ownerPublication)

	nonInitialMap := ownerSealRecoveryTestCloneMapping(fixture.initialMapping)
	nonInitialMap.Runs[0].DataPageIndex++
	nonInitialMapBytes := ownerSealRecoveryTestMappingBytes(
		t, nonInitialMap, fixture.publicationObject)

	tests := []struct {
		name        string
		owner       OwnerStateSnapshot
		allocation  uint64
		publication []byte
		mapping     []byte
	}{
		{name: "absent allocation", owner: fixture.committing, allocation: 30, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "zero allocation", owner: fixture.committing, allocation: 0, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "allocation overflow", owner: fixture.committing, allocation: cxlcheckpoint.MaxSignedLong + 1, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "GRANTED state", owner: fixture.producer.owner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "COMMITTED state", owner: fixture.committed, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "zero durable seal", owner: zeroSealOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "checkpoint record mismatch", owner: checkpointOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "content demand mismatch", owner: demandOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "extent mismatch", owner: extentOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "device capacity mismatch", owner: deviceMismatchOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "next transaction mismatch", owner: nextMismatchOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "snapshot sequence underflow", owner: snapshotUnderflowOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "seal does not follow grant", owner: sealAtGrantOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "transaction overflow", owner: overflowOwner, allocation: 29, publication: fixture.publicationBytes, mapping: fixture.initialMapBytes},
		{name: "publication checkpoint mismatch", owner: fixture.committing, allocation: 29, publication: checkpointPublicationBytes, mapping: fixture.initialMapBytes},
		{name: "publication owner mismatch", owner: fixture.committing, allocation: 29, publication: ownerPublicationBytes, mapping: fixture.initialMapBytes},
		{name: "non-initial physical map", owner: fixture.committing, allocation: 29, publication: fixture.publicationBytes, mapping: nonInitialMapBytes},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildCommittingOwnerSealRecoveryPlan(
				test.owner, test.allocation, test.publication, test.mapping,
			); !errors.Is(err, ErrInvalidOwnerSealRecoveryPlan) {
				t.Fatalf("error = %v, want recovery-plan rejection", err)
			}
		})
	}
}

func TestCommittingOwnerSealRecoveryMapIDBoundaryRequiresTranscriptMatch(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	alternateMap := ownerSealRecoveryTestCloneMapping(fixture.initialMapping)
	alternateMap.ContentPlacementMapID = "alternate-initial-placement-v7"
	alternateBytes := ownerSealRecoveryTestMappingBytes(
		t, alternateMap, fixture.publicationObject)

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		fixture.committing, 29, fixture.publicationBytes, alternateBytes)
	if err != nil {
		t.Fatalf("valid alternate map ID recovery: %v", err)
	}
	recovered := recovery.Plan()
	if reflect.DeepEqual(recovered, fixture.freshPlan) {
		t.Fatal("alternate map ID did not change slot-A plan commitment")
	}
	if recovery.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("builder did not preserve the durable COMMITTING seal H")
	}

	pages := ownerSealTranscriptTestPages(t, fixture.producer, fixture.freshPlan)
	var slotA OwnerSealObject
	for _, object := range recovered.Objects() {
		if object.Kind == cxlcheckpoint.ContentPlacementSlotAV7 {
			slotA = object
			break
		}
	}
	ownerSealRecoveryTestReplaceObjectPages(t, pages, slotA, alternateBytes)
	recomputed := ownerSealTranscriptTestComplete(t, recovered, pages, nil)
	if recomputed.SHA256() == recovery.ExpectedOwnerVerifiedSealSHA256() {
		t.Fatal("alternate map ID unexpectedly reproduced durable COMMITTING seal H")
	}
	if err := recovery.VerifyRecomputedSeal(recomputed); !errors.Is(
		err, ErrInvalidOwnerSealRecoveryPlan,
	) {
		t.Fatalf("alternate map ID recomputed-seal verification error = %v", err)
	}
	if _, err := PlanCommittingOwnerSealCompletion(
		fixture.committing, recovered, recomputed,
	); !errors.Is(err, ErrInvalidOwnerSealStateTransition) {
		t.Fatalf("mismatched full transcript completion error = %v", err)
	}
}

func TestCommittingOwnerSealRecoverySelectsMiddleRecordOnly(t *testing.T) {
	fixture := newOwnerSealRecoveryTestFixture(t)
	target := fixture.committing.Records()[0]
	left := ownerSealRecoveryTestRejectedRecord(target, 28, 80, "left")
	right := ownerSealRecoveryTestRejectedRecord(target, 30, 90, "right")
	multi := ownerSealRecoveryTestRebuildOwner(
		t,
		fixture.committing,
		nil,
		[]OwnerStateAllocationRecord{left, target, right},
		fixture.committing.SnapshotSequence,
		31,
		fixture.committing.NextOwnerTransactionSequence,
	)

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		multi, 29, fixture.publicationBytes, fixture.initialMapBytes)
	if err != nil {
		t.Fatalf("middle-record recovery: %v", err)
	}
	recovered := recovery.Plan()
	if !reflect.DeepEqual(recovered, fixture.freshPlan) ||
		recovery.ExpectedOwnerVerifiedSealSHA256() != fixture.freshSeal.SHA256() {
		t.Fatal("neighboring records changed recovered target plan or expected seal digest")
	}
	if err := recovery.VerifyRecomputedSeal(fixture.freshSeal); err != nil {
		t.Fatalf("middle-record actual seal verification: %v", err)
	}
	completed, err := PlanCommittingOwnerSealCompletion(multi, recovered, fixture.freshSeal)
	if err != nil {
		t.Fatalf("middle-record completion: %v", err)
	}
	records := completed.Records()
	if len(records) != 3 || !reflect.DeepEqual(records[0], left) ||
		!reflect.DeepEqual(records[2], right) ||
		records[1].State != OwnerAllocationCommitted ||
		records[1].AllocationRecordID != 29 {
		t.Fatalf("middle-record completion changed a neighbor or selected wrong target: %#v", records)
	}
}

func TestCommittingOwnerSealRecoveryFragmentedTwoDAXDoesNotRequireAnchorAllocation(t *testing.T) {
	producer := newProducerScatterTestFixture(t)
	devices := producer.owner.Devices()
	devices = append(devices, OwnerStateDevice{
		DeviceUUID:          "device-c",
		DeviceOwnerEpoch:    producer.owner.OwnerEpoch,
		DataPageCount:       128,
		DeviceBindingSHA256: sha256.Sum256([]byte("binding-device-c")),
	})
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("three-device membership: %v", err)
	}
	owner, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    producer.owner.ClusterID,
		OwnerGroupID:                 producer.owner.OwnerGroupID,
		CurrentOwnerID:               producer.owner.CurrentOwnerID,
		AnchorDeviceUUID:             "device-c",
		StorageCompatibilityID:       producer.owner.StorageCompatibilityID,
		OwnerEpoch:                   producer.owner.OwnerEpoch,
		GroupConfigurationSequence:   producer.owner.GroupConfigurationSequence,
		MembershipSHA256:             membership,
		SnapshotSequence:             producer.owner.SnapshotSequence,
		NextAllocationRecordID:       producer.owner.NextAllocationRecordID,
		NextOwnerTransactionSequence: producer.owner.NextOwnerTransactionSequence,
		Devices:                      devices,
		Records:                      producer.owner.Records(),
	})
	if err != nil {
		t.Fatalf("Owner with unallocated anchor: %v", err)
	}
	producer.owner = owner
	producer.plan, err = BuildProducerScatterPlan(owner, 29, producer.initial)
	if err != nil {
		t.Fatalf("two-DAX Producer plan with third anchor: %v", err)
	}
	fresh, err := BuildFreshOwnerSealPlan(owner, 29, producer.plan, producer.initial)
	if err != nil {
		t.Fatalf("fresh plan with unallocated anchor: %v", err)
	}
	pages := ownerSealTranscriptTestPages(t, producer, fresh)
	seal := ownerSealTranscriptTestComplete(t, fresh, pages, nil)
	transitions, err := PlanFreshOwnerSealStateTransitions(owner, fresh, seal)
	if err != nil {
		t.Fatalf("fresh transitions with unallocated anchor: %v", err)
	}
	publicationBytes := ownerSealRecoveryTestPublicationBytes(
		t, producer.initial.Publication)
	mappingObjects, err := producer.initial.Publication.MappingContentObjects()
	if err != nil {
		t.Fatalf("mapping objects: %v", err)
	}
	mappingBytes := ownerSealRecoveryTestMappingBytes(
		t, producer.initial.InitialContentPlacementMap, mappingObjects)

	recovery, err := BuildCommittingOwnerSealRecoveryPlan(
		transitions.Committing(), 29, publicationBytes, mappingBytes)
	if err != nil {
		t.Fatalf("fragmented two-DAX recovery without anchor allocation: %v", err)
	}
	recovered := recovery.Plan()
	if !reflect.DeepEqual(recovered, fresh) ||
		recovery.ExpectedOwnerVerifiedSealSHA256() != seal.SHA256() {
		t.Fatal("fragmented two-DAX recovery differs from fresh plan/seal digest")
	}
	if err := recovery.VerifyRecomputedSeal(seal); err != nil {
		t.Fatalf("fragmented two-DAX actual seal verification: %v", err)
	}
	if recovered.AnchorDeviceUUID() != "device-c" || len(recovered.Devices()) != 2 ||
		len(recovered.ExtentRuns()) != 6 {
		t.Fatalf("recovered anchor/devices/runs = %q/%d/%d, want device-c/2/6",
			recovered.AnchorDeviceUUID(), len(recovered.Devices()), len(recovered.ExtentRuns()))
	}
	for _, device := range recovered.Devices() {
		if device.DeviceUUID == recovered.AnchorDeviceUUID() {
			t.Fatal("compact allocation unexpectedly includes the Owner-group anchor")
		}
	}
}

func newOwnerSealRecoveryTestFixture(t *testing.T) ownerSealRecoveryTestFixture {
	t.Helper()
	producer := newProducerScatterTestFixture(t)
	freshPlan := ownerSealPlanTestBuild(t, producer)
	pages := ownerSealTranscriptTestPages(t, producer, freshPlan)
	freshSeal := ownerSealTranscriptTestComplete(t, freshPlan, pages, nil)
	transitions, err := PlanFreshOwnerSealStateTransitions(
		producer.owner, freshPlan, freshSeal)
	if err != nil {
		t.Fatalf("PlanFreshOwnerSealStateTransitions: %v", err)
	}
	publication := ownerSealRecoveryTestClonePublication(producer.initial.Publication)
	publicationBytes := ownerSealRecoveryTestPublicationBytes(t, publication)
	mappingObjects, err := publication.MappingContentObjects()
	if err != nil {
		t.Fatalf("Publication.MappingContentObjects: %v", err)
	}
	initialMapping := ownerSealRecoveryTestCloneMapping(
		producer.initial.InitialContentPlacementMap)
	initialMapBytes := ownerSealRecoveryTestMappingBytes(
		t, initialMapping, mappingObjects)
	return ownerSealRecoveryTestFixture{
		producer:          producer,
		freshPlan:         freshPlan,
		freshSeal:         freshSeal,
		committing:        transitions.Committing(),
		committed:         transitions.Committed(),
		publicationBytes:  publicationBytes,
		initialMapBytes:   initialMapBytes,
		initialMapping:    initialMapping,
		publication:       publication,
		publicationObject: mappingObjects,
	}
}

func ownerSealRecoveryTestPublicationBytes(
	t *testing.T,
	publication cxlcheckpoint.PublicationV7,
) []byte {
	t.Helper()
	encoded, err := cxlcheckpoint.CanonicalPublicationV7Bytes(publication)
	if err != nil {
		t.Fatalf("CanonicalPublicationV7Bytes: %v", err)
	}
	return encoded
}

func ownerSealRecoveryTestMappingBytes(
	t *testing.T,
	mapping cxlcheckpoint.ContentPlacementMap,
	objects []cxlcheckpoint.ContentObject,
) []byte {
	t.Helper()
	encoded, err := cxlcheckpoint.CanonicalContentPlacementMapBytes(mapping, objects)
	if err != nil {
		t.Fatalf("CanonicalContentPlacementMapBytes: %v", err)
	}
	return encoded
}

func ownerSealRecoveryTestClonePublication(
	publication cxlcheckpoint.PublicationV7,
) cxlcheckpoint.PublicationV7 {
	publication.InitialAllocation.Devices = append(
		[]cxlcheckpoint.AllocationDeviceV7(nil),
		publication.InitialAllocation.Devices...)
	publication.InitialAllocation.Extents = append(
		[]cxlcheckpoint.AllocationExtentV7(nil),
		publication.InitialAllocation.Extents...)
	publication.Objects = append([]cxlcheckpoint.ContentObjectV7(nil), publication.Objects...)
	return publication
}

func ownerSealRecoveryTestCloneMapping(
	mapping cxlcheckpoint.ContentPlacementMap,
) cxlcheckpoint.ContentPlacementMap {
	mapping.Devices = append([]cxlcheckpoint.Device(nil), mapping.Devices...)
	mapping.Runs = append([]cxlcheckpoint.ContentPlacementRun(nil), mapping.Runs...)
	return mapping
}

func ownerSealRecoveryTestRebuildOwner(
	t *testing.T,
	base OwnerStateSnapshot,
	devices []OwnerStateDevice,
	records []OwnerStateAllocationRecord,
	snapshotSequence uint64,
	nextAllocationRecordID uint64,
	nextOwnerTransactionSequence uint64,
) OwnerStateSnapshot {
	t.Helper()
	if devices == nil {
		devices = base.Devices()
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	owner, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    base.ClusterID,
		OwnerGroupID:                 base.OwnerGroupID,
		CurrentOwnerID:               base.CurrentOwnerID,
		AnchorDeviceUUID:             base.AnchorDeviceUUID,
		StorageCompatibilityID:       base.StorageCompatibilityID,
		OwnerEpoch:                   base.OwnerEpoch,
		GroupConfigurationSequence:   base.GroupConfigurationSequence,
		MembershipSHA256:             membership,
		SnapshotSequence:             snapshotSequence,
		NextAllocationRecordID:       nextAllocationRecordID,
		NextOwnerTransactionSequence: nextOwnerTransactionSequence,
		Devices:                      devices,
		Records:                      records,
	})
	if err != nil {
		t.Fatalf("NewOwnerStateSnapshot: %v", err)
	}
	return owner
}

func ownerSealRecoveryTestRejectedRecord(
	base OwnerStateAllocationRecord,
	allocationID uint64,
	transaction uint64,
	suffix string,
) OwnerStateAllocationRecord {
	record := cloneOwnerStateRecord(base)
	record.AllocationRecordID = allocationID
	record.ReservationTransactionSequence = 0
	record.OwnerTransactionSequence = transaction
	record.State = OwnerAllocationRejectedNoSpace
	record.RequestID = "request-" + suffix
	record.CheckpointID = "checkpoint-" + suffix
	record.ProducerID = "producer-" + suffix
	record.RequestSHA256 = sha256.Sum256([]byte(record.RequestID))
	record.Fragments = nil
	record.OwnerVerifiedSealSHA256 = [sha256.Size]byte{}
	return record
}

func ownerSealRecoveryTestReplaceObjectPages(
	t *testing.T,
	pages [][]byte,
	object OwnerSealObject,
	exact []byte,
) {
	t.Helper()
	if object.ObjectID == 0 || uint64(len(exact)) != object.ExactByteLength {
		t.Fatalf("replacement object/length = %d/%d, want nonzero/%d",
			object.ObjectID, len(exact), object.ExactByteLength)
	}
	for objectPage := uint64(0); objectPage < object.CapacityPages; objectPage++ {
		logical := object.LogicalPageStart + objectPage
		page := make([]byte, ContentPageBytes)
		start := objectPage * uint64(ContentPageBytes)
		if start < uint64(len(exact)) {
			end := start + uint64(ContentPageBytes)
			if end > uint64(len(exact)) {
				end = uint64(len(exact))
			}
			copy(page, exact[int(start):int(end)])
		}
		pages[int(logical)] = page
	}
}
