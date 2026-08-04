package trcxl007

import (
	"crypto/sha256"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func TestFreshOwnerSealPlanFragmentedTwoDAXIteratorAndExactDescriptors(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	record := fixture.owner.records[0]

	if plan.ClusterID() != fixture.owner.ClusterID ||
		plan.OwnerGroupID() != fixture.owner.OwnerGroupID ||
		plan.AnchorDeviceUUID() != fixture.owner.AnchorDeviceUUID ||
		plan.StorageCompatibilityID() != cxlcheckpoint.V7StorageCompatibilityID ||
		plan.CheckpointID() != record.CheckpointID ||
		plan.OwnerID() != fixture.owner.CurrentOwnerID ||
		plan.RequestID() != record.RequestID ||
		plan.ProducerID() != record.ProducerID ||
		plan.DedupDomainID() != record.DedupDomainID ||
		plan.SharingPolicyID() != record.SharingPolicyID ||
		plan.OwnerEpoch() != fixture.owner.OwnerEpoch ||
		plan.GroupConfigurationSequence() != fixture.owner.GroupConfigurationSequence ||
		plan.OwnerSnapshotSequence() != fixture.owner.SnapshotSequence ||
		plan.AllocationRecordID() != record.AllocationRecordID ||
		plan.ReservationTransactionSequence() != record.ReservationTransactionSequence ||
		plan.GrantTransactionSequence() != record.OwnerTransactionSequence ||
		plan.SealTransactionSequence() != fixture.owner.NextOwnerTransactionSequence ||
		plan.TotalPages() != record.TotalDemandPages {
		t.Fatalf("plan scalar metadata does not exactly match Owner record: %#v", plan)
	}
	if plan.CommittingOwnerSnapshotSequence() != 9 ||
		plan.TerminalOwnerSnapshotSequence() != 10 ||
		plan.TerminalTransactionSequence() != 104 ||
		plan.NextTransactionSequenceAfterTerminal() != 105 {
		t.Fatalf("future sequences = snapshot %d/%d transaction %d/%d",
			plan.CommittingOwnerSnapshotSequence(), plan.TerminalOwnerSnapshotSequence(),
			plan.TerminalTransactionSequence(), plan.NextTransactionSequenceAfterTerminal())
	}
	if plan.MembershipSHA256() != fixture.owner.MembershipSHA256 ||
		plan.RequestSHA256() != record.RequestSHA256 ||
		plan.AuthorityEvidence() != record.AuthorityEvidence ||
		plan.SchedulerReserveSHA256() != record.AuthorityEvidence.SchedulerReserveSHA256 ||
		plan.ProducerCapabilitySHA256() != record.AuthorityEvidence.ProducerCapabilitySHA256 ||
		plan.PublicationAuthoritySHA256() != record.AuthorityEvidence.PublicationAuthoritySHA256 ||
		plan.ReclaimAuthoritySHA256() != record.AuthorityEvidence.ReclaimAuthoritySHA256 ||
		plan.GrantRecordSHA256() != producerScatterGrantRecordSHA256(record) ||
		plan.IntegritySHA256() == ([sha256.Size]byte{}) {
		t.Fatal("plan digest/authority metadata differs from canonical Owner record")
	}
	if len(plan.Devices()) != 2 || len(plan.Objects()) != 9 ||
		len(plan.ExtentRuns()) != 6 {
		t.Fatalf("compact table sizes = devices %d objects %d runs %d",
			len(plan.Devices()), len(plan.Objects()), len(plan.ExtentRuns()))
	}
	ownerSealPlanTestCheckObjectHashes(t, plan, fixture.initial)

	wantDevices := []string{
		"device-a", "device-a", "device-b", "device-b", "device-b",
		"device-a", "device-a", "device-a", "device-a", "device-b",
		"device-a", "device-a", "device-a", "device-b", "device-b",
		"device-b", "device-b",
	}
	wantDataPages := []uint64{
		10, 11, 20, 21, 22, 30, 31, 32, 33, 40, 40, 41, 42, 50, 51, 52, 53,
	}
	wantObjectIDs := []uint64{1, 1, 1, 2, 2, 3, 4, 5, 6, 7, 7, 8, 8, 9, 9, 9, 9}
	wantObjectPages := []uint64{0, 1, 2, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 2, 3}

	iterator, err := plan.PageIterator()
	if err != nil {
		t.Fatalf("PageIterator: %v", err)
	}
	for logical := uint64(0); logical < plan.TotalPages(); logical++ {
		target, nextErr := iterator.Next()
		if nextErr != nil {
			t.Fatalf("Next(%d): %v", logical, nextErr)
		}
		object := target.Object()
		device := target.Device()
		if target.LogicalPage() != logical || target.ObjectPage() != wantObjectPages[logical] ||
			device.DeviceUUID != wantDevices[logical] ||
			target.DataPageIndex() != wantDataPages[logical] ||
			object.ObjectID != wantObjectIDs[logical] ||
			uint64(target.DeviceIndex()) >= uint64(len(plan.Devices())) {
			t.Fatalf("logical page %d target = device %q/%d object %d/%d index %d",
				logical, device.DeviceUUID, target.DataPageIndex(), object.ObjectID,
				target.ObjectPage(), target.DeviceIndex())
		}
		meaningful, wantState, wantReferences := ownerSealPlanTestClassification(t, object, target.ObjectPage())
		if target.MeaningfulByteLength() != meaningful ||
			target.TargetState() != wantState ||
			target.InitialReferenceCount() != wantReferences {
			t.Fatalf("logical page %d classification = length %d state %d refs %d, want %d/%d/%d",
				logical, target.MeaningfulByteLength(), target.TargetState(),
				target.InitialReferenceCount(), meaningful, wantState, wantReferences)
		}

		reserved, reservedErr := target.ExpectedReservedDescriptor()
		wantReserved := Descriptor{
			AllocationRecordID:  record.AllocationRecordID,
			OriginObjectID:      object.ObjectID,
			OwnerTransactionSeq: record.ReservationTransactionSequence,
			State:               DescriptorReserved,
			ContentKind:         object.Kind,
		}
		if reservedErr != nil || reserved != wantReserved {
			t.Fatalf("logical page %d RESERVED = %#v / %v, want %#v",
				logical, reserved, reservedErr, wantReserved)
		}

		ownerCRC := uint32(0x10203040 + logical)
		if wantState == DescriptorEmptySlot || wantState == DescriptorZeroPadding {
			if _, badErr := target.TargetDescriptor(ownerCRC); !errors.Is(badErr, ErrInvalidOwnerSealPlan) {
				t.Fatalf("logical page %d accepted nonzero-target DML CRC: %v", logical, badErr)
			}
			ownerCRC = zeroContentPageCRC32C
		} else if logical == 0 {
			// Meaningful all-zero content is still immutable content. Its state
			// is selected by length/kind, never by the CRC value.
			ownerCRC = zeroContentPageCRC32C
		} else if logical == 1 {
			// Numeric CRC32C zero is a valid DML result, not an unwritten or
			// missing sentinel.
			ownerCRC = 0
		}
		targetDescriptor, targetErr := target.TargetDescriptor(ownerCRC)
		wantTarget := Descriptor{
			PaddedPageCRC32C:      ownerCRC,
			AllocationRecordID:    record.AllocationRecordID,
			OriginObjectID:        object.ObjectID,
			ContentReferenceCount: wantReferences,
			OwnerTransactionSeq:   plan.SealTransactionSequence(),
			PayloadLength:         meaningful,
			State:                 wantState,
			ContentKind:           object.Kind,
		}
		if targetErr != nil || targetDescriptor != wantTarget {
			t.Fatalf("logical page %d target descriptor = %#v / %v, want %#v",
				logical, targetDescriptor, targetErr, wantTarget)
		}
	}
	if _, err := iterator.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("first terminal Next error = %v, want io.EOF", err)
	}
	if _, err := iterator.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("repeated terminal Next error = %v, want io.EOF", err)
	}
}

func TestFreshOwnerSealPlanDetachedInputsAccessorsAndIterator(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	wantIntegrity := plan.IntegritySHA256()

	devices := plan.Devices()
	objects := plan.Objects()
	runs := plan.ExtentRuns()
	devices[0].DeviceUUID = "substituted-device"
	objects[0].ObjectID = 999
	objects[3].ExactSHA256[0] ^= 0xff
	runs[0].StartDataPageIndex = 999
	if plan.Devices()[0].DeviceUUID != "device-a" || plan.Objects()[0].ObjectID != 1 ||
		plan.ExtentRuns()[0].StartDataPageIndex != 10 || plan.IntegritySHA256() != wantIntegrity {
		t.Fatal("accessor mutation reached compact plan")
	}

	iterator, err := plan.PageIterator()
	if err != nil {
		t.Fatalf("PageIterator: %v", err)
	}
	// Same-package mutation demonstrates that PageIterator owns a detached copy
	// even though production callers cannot access these private slices.
	plan.devices[0].DeviceUUID = "mutated-after-iterator"
	plan.objects[0].ObjectID = 777
	plan.runs[0].StartDataPageIndex = 77
	target, err := iterator.Next()
	if err != nil || target.Device().DeviceUUID != "device-a" ||
		target.Object().ObjectID != 1 || target.DataPageIndex() != 10 {
		t.Fatalf("detached iterator first target = %#v / %v", target, err)
	}

	// Build detached every input graph, including private Producer/Owner slices.
	stable := ownerSealPlanTestBuild(t, fixture)
	fixture.initial.Publication.Objects[0].ObjectID = 888
	fixture.initial.ObjectWrites[0].CanonicalBytes = []byte("bad")
	fixture.plan.devices[0].DeviceUUID = "bad"
	fixture.plan.objects[0].canonicalBytes = []byte("bad")
	fixture.plan.runs[0].StartDataPageIndex = 88
	fixture.owner.devices[0].DeviceUUID = "bad"
	fixture.owner.records[0].Fragments[0].Extents[0].StartDataPageIndex = 88
	if err := stable.Validate(); err != nil {
		t.Fatalf("input mutation reached built plan: %v", err)
	}
}

func TestFreshOwnerSealPlanRejectsStateSequenceAndExactJoinSubstitution(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)

	for _, id := range []uint64{0, 30, cxlcheckpoint.MaxSignedLong + 1} {
		if _, err := BuildFreshOwnerSealPlan(fixture.owner, id, fixture.plan, fixture.initial); !errors.Is(err, ErrInvalidOwnerSealPlan) {
			t.Fatalf("allocation ID %d error = %v", id, err)
		}
	}

	notGranted := fixture.owner.Clone()
	notGranted.records[0].State = OwnerAllocationCanceling
	if err := notGranted.Validate(); err != nil {
		t.Fatalf("valid non-GRANTED fixture: %v", err)
	}
	if _, err := BuildFreshOwnerSealPlan(notGranted, 29, fixture.plan, fixture.initial); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("non-GRANTED error = %v", err)
	}

	transactionExhausted := fixture.owner.Clone()
	transactionExhausted.NextOwnerTransactionSequence = cxlcheckpoint.MaxSignedLong - 1
	if err := transactionExhausted.Validate(); err != nil {
		t.Fatalf("transaction-exhausted Owner fixture: %v", err)
	}
	if _, err := BuildFreshOwnerSealPlan(transactionExhausted, 29, fixture.plan, fixture.initial); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("transaction exhaustion error = %v", err)
	}

	snapshotExhausted := fixture.owner.Clone()
	snapshotExhausted.SnapshotSequence = cxlcheckpoint.MaxSignedLong - 1
	if err := snapshotExhausted.Validate(); err != nil {
		t.Fatalf("snapshot-exhausted Owner fixture: %v", err)
	}
	if _, err := BuildFreshOwnerSealPlan(snapshotExhausted, 29, fixture.plan, fixture.initial); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("snapshot exhaustion error = %v", err)
	}

	validButSubstitutedProducer := fixture.plan
	validButSubstitutedProducer.ownerGroupID = "substituted-owner-group"
	validButSubstitutedProducer.integritySHA256 = producerScatterPlanSHA256(validButSubstitutedProducer)
	if err := validButSubstitutedProducer.Validate(); err != nil {
		t.Fatalf("valid substituted Producer plan fixture: %v", err)
	}
	if _, err := BuildFreshOwnerSealPlan(
		fixture.owner, 29, validButSubstitutedProducer, fixture.initial,
	); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("Producer substitution error = %v", err)
	}

	validButSubstitutedPublication := ownerSealPlanTestRebuildInitial(
		t, fixture.initial, fixture.initial.Publication,
		"substituted-initial-placement", fixture.initial.ActiveContentPlacementRoot.RootID)
	if _, err := BuildFreshOwnerSealPlan(
		fixture.owner, 29, fixture.plan, validButSubstitutedPublication,
	); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("publication substitution error = %v", err)
	}

	plan := ownerSealPlanTestBuild(t, fixture)
	for _, mutate := range []func(*OwnerSealPlan){
		func(value *OwnerSealPlan) { value.requestID = "substituted-request" },
		func(value *OwnerSealPlan) { value.authorityEvidence.ReclaimAuthoritySHA256 = [sha256.Size]byte{} },
		func(value *OwnerSealPlan) { value.objects[3].ExactSHA256[0] ^= 1 },
		func(value *OwnerSealPlan) { value.runs[0].StartDataPageIndex++ },
	} {
		candidate := cloneOwnerSealPlan(plan)
		mutate(&candidate)
		if err := candidate.Validate(); !errors.Is(err, ErrInvalidOwnerSealPlan) {
			t.Fatalf("mutated compact plan error = %v", err)
		}
	}
	if _, err := (OwnerSealPageTarget{}).ExpectedReservedDescriptor(); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("zero page target RESERVED error = %v", err)
	}
	if _, err := (*OwnerSealPageIterator)(nil).Next(); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("nil iterator error = %v", err)
	}
	if _, err := (&OwnerSealPageIterator{}).Next(); !errors.Is(err, ErrInvalidOwnerSealPlan) {
		t.Fatalf("zero iterator error = %v", err)
	}
}

func TestFreshOwnerSealPlanCrossChecksDetachedProducerCRCVector(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	plan := ownerSealPlanTestBuild(t, fixture)
	raw := make([]byte, int(plan.TotalPages())*ProducerScatterCRCBytesPerPage)
	for index := range raw {
		raw[index] = byte(index + 1)
	}
	input, err := ParseProducerScatterCRCVector(raw, plan.TotalPages())
	if err != nil {
		t.Fatalf("ParseProducerScatterCRCVector: %v", err)
	}
	result := ProducerScatterResult{
		checkpointID:       plan.CheckpointID(),
		allocationRecordID: plan.AllocationRecordID(),
		crcVector:          input,
	}
	vector, err := plan.CrossCheckProducerScatterResult(result)
	if err != nil || !reflect.DeepEqual(vector.Bytes(), raw) {
		t.Fatalf("CrossCheckProducerScatterResult = %x / %v", vector.Bytes(), err)
	}
	result.crcVector.raw[0] ^= 0xff
	returned := vector.Bytes()
	returned[1] ^= 0xff
	if reflect.DeepEqual(vector.Bytes(), result.crcVector.Bytes()) || vector.Bytes()[1] != raw[1] {
		t.Fatal("cross-checked Producer CRC vector aliases input or accessor output")
	}

	for _, invalid := range []ProducerScatterResult{
		{checkpointID: "wrong", allocationRecordID: plan.AllocationRecordID(), crcVector: input},
		{checkpointID: plan.CheckpointID(), allocationRecordID: plan.AllocationRecordID() + 1, crcVector: input},
		{checkpointID: plan.CheckpointID(), allocationRecordID: plan.AllocationRecordID(),
			crcVector: ProducerScatterCRCVector{totalPages: plan.TotalPages() - 1, raw: raw[:len(raw)-4]}},
		{checkpointID: plan.CheckpointID(), allocationRecordID: plan.AllocationRecordID(),
			crcVector: ProducerScatterCRCVector{totalPages: plan.TotalPages(), raw: raw[:len(raw)-1]}},
	} {
		if _, err := plan.CrossCheckProducerScatterResult(invalid); !errors.Is(err, ErrInvalidOwnerSealPlan) {
			t.Fatalf("invalid Producer result error = %v", err)
		}
	}
}

func TestFreshOwnerSealPlanAllowsAllocationThatExcludesAnchorDAX(t *testing.T) {
	fixture := newProducerScatterTestFixture(t)
	publication := fixture.initial.Publication
	publication.InitialAllocation.Devices = []cxlcheckpoint.AllocationDeviceV7{{
		DeviceUUID: "device-b", DataPageCount: 128,
	}}
	publication.InitialAllocation.Extents = []cxlcheckpoint.AllocationExtentV7{{
		DeviceIndex: 0, StartDataPageIndex: 60, LogicalPageStart: 0,
		PageCount: publication.InitialAllocation.TotalPages,
	}}
	initial := ownerSealPlanTestRebuildInitial(
		t, fixture.initial, publication,
		fixture.initial.InitialContentPlacementMap.ContentPlacementMapID,
		fixture.initial.ActiveContentPlacementRoot.RootID)
	record := fixture.owner.records[0]
	record.Fragments = []OwnerStateDeviceFragment{{
		DeviceUUID: "device-b", DeviceOwnerEpoch: fixture.owner.OwnerEpoch,
		TargetAllocatorSnapshotSequence: 9,
		Extents: []OwnerStateExtent{{
			StartDataPageIndex: 60, LogicalPageStart: 0, PageCount: record.TotalDemandPages,
		}},
	}}
	owner := ownerSealPlanTestRebuildOwner(t, fixture.owner, record)
	producer, err := BuildProducerScatterPlan(owner, record.AllocationRecordID, initial)
	if err != nil {
		t.Fatalf("BuildProducerScatterPlan without anchor allocation: %v", err)
	}
	plan, err := BuildFreshOwnerSealPlan(owner, record.AllocationRecordID, producer, initial)
	if err != nil {
		t.Fatalf("BuildFreshOwnerSealPlan without anchor allocation: %v", err)
	}
	if plan.AnchorDeviceUUID() != "device-a" || len(plan.Devices()) != 1 ||
		plan.Devices()[0].DeviceUUID != "device-b" || len(plan.ExtentRuns()) != 1 {
		t.Fatalf("anchor/subset plan = anchor %q devices %#v runs %#v",
			plan.AnchorDeviceUUID(), plan.Devices(), plan.ExtentRuns())
	}
	iterator, err := plan.PageIterator()
	if err != nil {
		t.Fatalf("PageIterator: %v", err)
	}
	for logical := uint64(0); logical < plan.TotalPages(); logical++ {
		target, nextErr := iterator.Next()
		if nextErr != nil || target.Device().DeviceUUID != "device-b" ||
			target.DataPageIndex() != 60+logical {
			t.Fatalf("logical page %d subset target = %#v / %v", logical, target, nextErr)
		}
	}
}

func TestOwnerSealPlanHasOnlyCompactMetadataTables(t *testing.T) {
	typeOfPlan := reflect.TypeOf(OwnerSealPlan{})
	wantSlices := map[string]bool{"devices": true, "objects": true, "runs": true}
	for index := 0; index < typeOfPlan.NumField(); index++ {
		field := typeOfPlan.Field(index)
		if field.Type.Kind() == reflect.Slice {
			if !wantSlices[field.Name] {
				t.Fatalf("unexpected slice field %q (%s) may be a per-page table", field.Name, field.Type)
			}
			delete(wantSlices, field.Name)
		}
		lower := strings.ToLower(field.Name)
		if strings.Contains(lower, "pagetarget") || strings.Contains(lower, "crcvector") ||
			strings.Contains(lower, "descriptorarray") {
			t.Fatalf("compact plan contains per-page-looking field %q", field.Name)
		}
	}
	if len(wantSlices) != 0 {
		t.Fatalf("compact plan slice fields changed: missing %#v", wantSlices)
	}
	objectType := reflect.TypeOf(OwnerSealObject{})
	for index := 0; index < objectType.NumField(); index++ {
		if objectType.Field(index).Type.Kind() == reflect.Slice {
			t.Fatalf("OwnerSealObject contains slice field %q", objectType.Field(index).Name)
		}
	}
}

func ownerSealPlanTestBuild(t *testing.T, fixture producerScatterTestFixture) OwnerSealPlan {
	t.Helper()
	plan, err := BuildFreshOwnerSealPlan(fixture.owner, 29, fixture.plan, fixture.initial)
	if err != nil {
		t.Fatalf("BuildFreshOwnerSealPlan: %v", err)
	}
	return plan
}

func ownerSealPlanTestCheckObjectHashes(
	t *testing.T,
	plan OwnerSealPlan,
	initial cxlcheckpoint.InitialPublicationV7Plan,
) {
	t.Helper()
	for _, object := range plan.Objects() {
		var required bool
		var want [sha256.Size]byte
		switch object.Kind {
		case cxlcheckpoint.ContentMMTemplateMetadataV7:
			required, want = true, initial.Publication.MMTemplate.SHA256
		case cxlcheckpoint.ContentVirtualPageMapMetadataV7:
			required, want = true, initial.Publication.VirtualPageMap.SHA256
		case cxlcheckpoint.ContentArtifactManifestMetadataV7:
			required, want = true, initial.Publication.ArtifactManifest.SHA256
		case cxlcheckpoint.ContentPlacementSlotAV7:
			required, want = true, initial.ActiveContentPlacementRoot.ContentPlacementMapSHA256
		case cxlcheckpoint.ContentPublicationV7:
			required, want = true, initial.ActiveContentPlacementRoot.ImmutablePublicationSHA256
		}
		if object.ExactSHA256Required != required || object.ExactSHA256 != want {
			t.Fatalf("object %d kind %d exact SHA required/digest = %t/%x, want %t/%x",
				object.ObjectID, object.Kind, object.ExactSHA256Required,
				object.ExactSHA256, required, want)
		}
	}
}

func ownerSealPlanTestClassification(
	t *testing.T,
	object OwnerSealObject,
	objectPage uint64,
) (uint32, DescriptorState, uint64) {
	t.Helper()
	start := objectPage * uint64(ContentPageBytes)
	meaningful := uint32(0)
	if start < object.ExactByteLength {
		remaining := object.ExactByteLength - start
		if remaining > uint64(ContentPageBytes) {
			remaining = uint64(ContentPageBytes)
		}
		meaningful = uint32(remaining)
	}
	switch object.Kind {
	case cxlcheckpoint.ContentPlacementSlotAV7:
		if meaningful != 0 {
			return meaningful, DescriptorPublishedSlot, 1
		}
		return 0, DescriptorEmptySlot, 0
	case cxlcheckpoint.ContentPlacementSlotBV7:
		return 0, DescriptorEmptySlot, 0
	case cxlcheckpoint.ContentPublicationV7:
		if meaningful != 0 {
			return meaningful, DescriptorImmutableSealed, 1
		}
		return 0, DescriptorZeroPadding, 0
	default:
		if meaningful == 0 {
			t.Fatalf("object %d has unexpected empty immutable page %d", object.ObjectID, objectPage)
		}
		return meaningful, DescriptorImmutableSealed, 1
	}
}

func ownerSealPlanTestRebuildInitial(
	t *testing.T,
	base cxlcheckpoint.InitialPublicationV7Plan,
	publication cxlcheckpoint.PublicationV7,
	mapID string,
	rootID string,
) cxlcheckpoint.InitialPublicationV7Plan {
	t.Helper()
	plan, err := cxlcheckpoint.BuildInitialPublicationV7Plan(
		cxlcheckpoint.InitialPublicationV7Input{
			Publication:                  publication,
			MMTemplate:                   base.MMTemplate,
			VirtualPageMap:               base.VirtualPageMap,
			ArtifactManifest:             base.ArtifactManifest,
			InitialContentPlacementMapID: mapID,
			InitialActivePlacementRootID: rootID,
		})
	if err != nil {
		t.Fatalf("rebuild initial publication: %v", err)
	}
	return plan
}

func ownerSealPlanTestRebuildOwner(
	t *testing.T,
	base OwnerStateSnapshot,
	record OwnerStateAllocationRecord,
) OwnerStateSnapshot {
	t.Helper()
	owner, err := NewOwnerStateSnapshot(OwnerStateConfig{
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
		Records:                      []OwnerStateAllocationRecord{record},
	})
	if err != nil {
		t.Fatalf("rebuild Owner state: %v", err)
	}
	return owner
}
