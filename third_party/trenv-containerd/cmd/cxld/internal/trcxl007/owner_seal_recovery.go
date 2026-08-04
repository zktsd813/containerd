package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	// ErrInvalidOwnerSealRecoveryPlan identifies a non-canonical media
	// envelope, a publication/Owner join mismatch, or an impossible exact
	// COMMITTING lifecycle. Building a recovery plan is pure and performs no
	// device, descriptor, allocator, Owner-state, network, or runtime I/O.
	ErrInvalidOwnerSealRecoveryPlan = errors.New(
		"invalid TRCXL007 Owner seal recovery plan")
)

// CommittingOwnerSealRecoveryPlan is a detached reconstruction plus the
// durable seal digest that a complete recovery reread must reproduce. It does
// not contain and cannot mint an OwnerVerifiedSeal. That opaque proof remains
// obtainable only from OwnerSealTranscript.Finish after every page has been
// reread and verified.
type CommittingOwnerSealRecoveryPlan struct {
	plan                            OwnerSealPlan
	expectedOwnerVerifiedSealSHA256 [sha256.Size]byte
}

// Plan returns a detached compact plan suitable for a new recovery transcript.
func (recovery CommittingOwnerSealRecoveryPlan) Plan() OwnerSealPlan {
	return cloneOwnerSealPlan(recovery.plan)
}

// ExpectedOwnerVerifiedSealSHA256 returns the durable COMMITTING record's H.
// It is a comparison value, not an OwnerVerifiedSeal and not proof of reread.
func (recovery CommittingOwnerSealRecoveryPlan) ExpectedOwnerVerifiedSealSHA256() [sha256.Size]byte {
	return recovery.expectedOwnerVerifiedSealSHA256
}

// VerifyRecomputedSeal accepts only an opaque seal actually returned by a
// complete transcript for this exact recovered plan and whose SHA-256 equals
// durable H. Success still performs no Owner-state or descriptor mutation.
func (recovery CommittingOwnerSealRecoveryPlan) VerifyRecomputedSeal(
	seal OwnerVerifiedSeal,
) error {
	plan := cloneOwnerSealPlan(recovery.plan)
	if err := plan.Validate(); err != nil {
		return ownerSealRecoveryErrorf("recovered compact plan: %v", err)
	}
	if recovery.expectedOwnerVerifiedSealSHA256 == ([sha256.Size]byte{}) {
		return ownerSealRecoveryErrorf("expected Owner-verified seal SHA-256 is zero")
	}
	if err := seal.Validate(plan); err != nil {
		return ownerSealRecoveryErrorf("recomputed Owner-verified seal: %v", err)
	}
	if seal.SHA256() != recovery.expectedOwnerVerifiedSealSHA256 {
		return ownerSealRecoveryErrorf(
			"recomputed Owner-verified seal SHA-256 differs from durable COMMITTING H")
	}
	return nil
}

// BuildCommittingOwnerSealRecoveryPlan reconstructs the same compact seal plan
// that fresh sealing produced, using only one exact validated TROWN007
// COMMITTING snapshot and the exact unpadded TRPUB007 and initial slot-A
// TRCPM007 envelopes recovered from that allocation's media.
//
// The result exposes durable H only as a SHA-256 comparison value. It never
// returns an OwnerVerifiedSeal. Recovery must recompute a complete
// OwnerSealTranscript, pass its Finish result to VerifyRecomputedSeal, and use
// only that actual recomputed seal for descriptor/COMMITTED recovery work.
//
// TRPUB007 deliberately does not store the initial ContentPlacementMap ID. A
// different valid ID paired with the exact same canonical version-1 physical
// mapping therefore cannot be rejected by this pure builder. Such a change
// changes the slot-A object digest and hence the recomputed transcript seal;
// the mandatory full-media transcript comparison remains the fail-closed
// boundary. Semantic version 1 and the complete physical mapping are exact.
//
// The function retains no input bytes, Producer plan, CRC vector, DSA handle,
// raw capability, per-page table, or I/O seam. All returned slices are detached.
func BuildCommittingOwnerSealRecoveryPlan(
	committingState OwnerStateSnapshot,
	allocationRecordID uint64,
	publicationEnvelope []byte,
	initialPlacementEnvelope []byte,
) (CommittingOwnerSealRecoveryPlan, error) {
	owner := committingState.Clone()
	if err := owner.Validate(); err != nil {
		return ownerSealRecoveryFailure("Owner state: %v", err)
	}
	if allocationRecordID == 0 || allocationRecordID > cxlcheckpoint.MaxSignedLong {
		return ownerSealRecoveryFailure(
			"allocation record ID %d is outside 1..%d",
			allocationRecordID, cxlcheckpoint.MaxSignedLong)
	}
	record, found := producerScatterRecordByID(owner.Records(), allocationRecordID)
	if !found {
		return ownerSealRecoveryFailure(
			"allocation record %d is absent", allocationRecordID)
	}
	if record.State != OwnerAllocationCommitting {
		return ownerSealRecoveryFailure(
			"allocation record %d state is %d, want COMMITTING",
			allocationRecordID, record.State)
	}
	if record.OwnerVerifiedSealSHA256 == ([sha256.Size]byte{}) {
		return ownerSealRecoveryFailure(
			"COMMITTING allocation %d has a zero Owner-verified seal",
			allocationRecordID)
	}

	// A fresh transition wrote COMMITTING at Q+1 with current transaction S
	// and next transaction S+1. The GRANTED transaction is reconstructible as
	// R+1 from the immutable reservation transaction R.
	if owner.SnapshotSequence <= 1 {
		return ownerSealRecoveryFailure(
			"COMMITTING snapshot sequence %d cannot derive a positive prior sequence",
			owner.SnapshotSequence)
	}
	priorSnapshotSequence := owner.SnapshotSequence - 1
	grantTransaction, ok := checkedAdd(record.ReservationTransactionSequence, 1)
	if !ok || grantTransaction > cxlcheckpoint.MaxSignedLong {
		return ownerSealRecoveryFailure(
			"grant transaction overflows reservation transaction %d",
			record.ReservationTransactionSequence)
	}
	sealTransaction := record.OwnerTransactionSequence
	wantNextTransaction, ok := checkedAdd(sealTransaction, 1)
	if !ok || wantNextTransaction > cxlcheckpoint.MaxSignedLong ||
		owner.NextOwnerTransactionSequence != wantNextTransaction {
		return ownerSealRecoveryFailure(
			"COMMITTING next transaction is %d, want seal transaction %d plus one",
			owner.NextOwnerTransactionSequence, sealTransaction)
	}
	if err := ownerSealValidateFutureSequences(
		priorSnapshotSequence,
		record.ReservationTransactionSequence,
		grantTransaction,
		sealTransaction,
	); err != nil {
		return ownerSealRecoveryFailure("lifecycle sequence: %v", err)
	}

	publicationBytes := append([]byte(nil), publicationEnvelope...)
	publication, err := cxlcheckpoint.DecodePublicationV7(publicationBytes)
	if err != nil {
		return ownerSealRecoveryFailure("TRPUB007 envelope: %v", err)
	}
	canonicalPublicationBytes, err := cxlcheckpoint.CanonicalPublicationV7Bytes(publication)
	if err != nil {
		return ownerSealRecoveryFailure("canonical TRPUB007 envelope: %v", err)
	}
	if !bytes.Equal(publicationBytes, canonicalPublicationBytes) {
		return ownerSealRecoveryFailure(
			"TRPUB007 envelope is not the exact canonical unpadded encoding")
	}
	if publication.MMTemplate.Version != cxlcheckpoint.InitialPublicationV7SemanticVersion ||
		publication.VirtualPageMap.Version != cxlcheckpoint.InitialPublicationV7SemanticVersion ||
		publication.ArtifactManifest.Version != cxlcheckpoint.InitialPublicationV7SemanticVersion {
		return ownerSealRecoveryFailure(
			"TRPUB007 typed metadata versions are %d/%d/%d, want initial semantic version %d",
			publication.MMTemplate.Version,
			publication.VirtualPageMap.Version,
			publication.ArtifactManifest.Version,
			cxlcheckpoint.InitialPublicationV7SemanticVersion)
	}

	mappingObjects, err := publication.MappingContentObjects()
	if err != nil {
		return ownerSealRecoveryFailure("TRPUB007 mapping objects: %v", err)
	}
	initialPlacementBytes := append([]byte(nil), initialPlacementEnvelope...)
	initialPlacement, err := cxlcheckpoint.DecodeContentPlacementMap(
		initialPlacementBytes, mappingObjects)
	if err != nil {
		return ownerSealRecoveryFailure("initial slot-A TRCPM007 envelope: %v", err)
	}
	canonicalPlacementBytes, err := cxlcheckpoint.CanonicalContentPlacementMapBytes(
		initialPlacement, mappingObjects)
	if err != nil {
		return ownerSealRecoveryFailure("canonical initial slot-A TRCPM007 envelope: %v", err)
	}
	if !bytes.Equal(initialPlacementBytes, canonicalPlacementBytes) {
		return ownerSealRecoveryFailure(
			"initial slot-A TRCPM007 envelope is not the exact canonical unpadded encoding")
	}
	if initialPlacement.Version != cxlcheckpoint.InitialPublicationV7SemanticVersion {
		return ownerSealRecoveryFailure(
			"initial slot-A TRCPM007 semantic version is %d, want %d",
			initialPlacement.Version, cxlcheckpoint.InitialPublicationV7SemanticVersion)
	}
	if err := publication.CrossCheckInitialContentPlacementMap(initialPlacement); err != nil {
		return ownerSealRecoveryFailure(
			"initial slot-A TRCPM007 physical mapping: %v", err)
	}

	if err := ownerSealRecoveryCrossCheckPublication(owner, record, publication); err != nil {
		return CommittingOwnerSealRecoveryPlan{}, err
	}
	devices, runs, err := producerScatterCrossCheckPlacement(
		owner, record, publication.InitialAllocation)
	if err != nil {
		return ownerSealRecoveryFailure("Owner/publication placement: %v", err)
	}
	objects, err := ownerSealRecoveryObjects(
		publication, publicationBytes, initialPlacementBytes)
	if err != nil {
		return CommittingOwnerSealRecoveryPlan{}, err
	}

	// COMMITTING changed exactly State, OwnerTransactionSequence, and
	// OwnerVerifiedSealSHA256. Reversing only those fields reconstructs and
	// commits the complete durable GRANTED record, including MaxExtents,
	// demands, fragments, allocator targets, authority evidence, and hashes.
	hypotheticalGrant := cloneOwnerStateRecord(record)
	hypotheticalGrant.State = OwnerAllocationGranted
	hypotheticalGrant.OwnerTransactionSequence = grantTransaction
	hypotheticalGrant.OwnerVerifiedSealSHA256 = [sha256.Size]byte{}
	grantRecordSHA256 := producerScatterGrantRecordSHA256(hypotheticalGrant)
	if grantRecordSHA256 == ([sha256.Size]byte{}) {
		return ownerSealRecoveryFailure("hypothetical GRANTED-record SHA-256 is zero")
	}

	plan := OwnerSealPlan{
		clusterID:              owner.ClusterID,
		ownerGroupID:           owner.OwnerGroupID,
		anchorDeviceUUID:       owner.AnchorDeviceUUID,
		storageCompatibilityID: owner.StorageCompatibilityID,
		checkpointID:           record.CheckpointID,
		ownerID:                owner.CurrentOwnerID,
		requestID:              record.RequestID,
		producerID:             record.ProducerID,
		dedupDomainID:          record.DedupDomainID,
		sharingPolicyID:        record.SharingPolicyID,
		ownerEpoch:             owner.OwnerEpoch,
		groupConfiguration:     owner.GroupConfigurationSequence,
		ownerSnapshotSequence:  priorSnapshotSequence,
		allocationRecordID:     record.AllocationRecordID,
		reservationTransaction: record.ReservationTransactionSequence,
		grantTransaction:       grantTransaction,
		sealTransaction:        sealTransaction,
		totalPages:             record.TotalDemandPages,
		membershipSHA256:       owner.MembershipSHA256,
		requestSHA256:          record.RequestSHA256,
		authorityEvidence:      record.AuthorityEvidence,
		grantRecordSHA256:      grantRecordSHA256,
		devices:                append([]ProducerScatterDeviceBinding(nil), devices...),
		objects:                append([]OwnerSealObject(nil), objects...),
		runs:                   append([]ProducerScatterExtentRun(nil), runs...),
	}
	plan.integritySHA256 = ownerSealPlanSHA256(plan)
	if err := plan.Validate(); err != nil {
		return ownerSealRecoveryFailure("reconstructed compact plan: %v", err)
	}
	// Reuse the scalar-only phase join without creating an OwnerVerifiedSeal.
	// This proves that the reconstructed Q/R/(R+1)/S plan, group identity,
	// record identity, durable H, and full hypothetical GRANTED digest describe
	// this exact COMMITTING snapshot. Only a later complete transcript may
	// produce the opaque seal accepted by a completion transition.
	if _, _, err := ownerSealCrossCheckStatePhaseDigest(
		owner,
		plan,
		OwnerAllocationCommitting,
		plan.CommittingOwnerSnapshotSequence(),
		plan.TerminalTransactionSequence(),
		plan.SealTransactionSequence(),
		record.OwnerVerifiedSealSHA256,
	); err != nil {
		return ownerSealRecoveryFailure("exact COMMITTING phase: %v", err)
	}

	return CommittingOwnerSealRecoveryPlan{
		plan:                            cloneOwnerSealPlan(plan),
		expectedOwnerVerifiedSealSHA256: record.OwnerVerifiedSealSHA256,
	}, nil
}

func ownerSealRecoveryCrossCheckPublication(
	owner OwnerStateSnapshot,
	record OwnerStateAllocationRecord,
	publication cxlcheckpoint.PublicationV7,
) error {
	allocation := publication.InitialAllocation
	if publication.CheckpointID != record.CheckpointID ||
		publication.DedupDomainID != record.DedupDomainID ||
		publication.SharingPolicyID != record.SharingPolicyID {
		return ownerSealRecoveryErrorf(
			"TRPUB007 checkpoint, deduplication domain, or sharing policy differs from Owner record")
	}
	if allocation.OwnerID != owner.CurrentOwnerID ||
		allocation.OwnerEpoch != owner.OwnerEpoch ||
		allocation.AllocationRecordID != record.AllocationRecordID ||
		allocation.TotalPages != record.TotalDemandPages {
		return ownerSealRecoveryErrorf(
			"TRPUB007 allocation Owner, epoch, record ID, or total demand differs from Owner state")
	}
	if len(record.ContentDemands) != len(publication.Objects) {
		return ownerSealRecoveryErrorf(
			"Owner demand count %d differs from TRPUB007 object count %d",
			len(record.ContentDemands), len(publication.Objects))
	}
	for index := range publication.Objects {
		demand := record.ContentDemands[index]
		object := publication.Objects[index]
		if demand.Kind != object.Kind || demand.ObjectID != object.ObjectID ||
			demand.ByteLength != object.ImmutableByteLength ||
			demand.CapacityPages != object.CapacityPages ||
			demand.LogicalPageStart != object.LogicalPageStart {
			return ownerSealRecoveryErrorf(
				"Owner demand and TRPUB007 object %d differ", index)
		}
	}
	return nil
}

func ownerSealRecoveryObjects(
	publication cxlcheckpoint.PublicationV7,
	publicationBytes []byte,
	initialPlacementBytes []byte,
) ([]OwnerSealObject, error) {
	objects := make([]OwnerSealObject, len(publication.Objects))
	publicationSHA256 := sha256.Sum256(publicationBytes)
	initialPlacementSHA256 := sha256.Sum256(initialPlacementBytes)
	for index, source := range publication.Objects {
		object := OwnerSealObject{
			ObjectID:         source.ObjectID,
			Kind:             source.Kind,
			LogicalPageStart: source.LogicalPageStart,
			ExactByteLength:  source.ImmutableByteLength,
			CapacityPages:    source.CapacityPages,
		}
		switch source.Kind {
		case cxlcheckpoint.ContentMMTemplateMetadataV7:
			object.ExactSHA256Required = true
			object.ExactSHA256 = publication.MMTemplate.SHA256
		case cxlcheckpoint.ContentVirtualPageMapMetadataV7:
			object.ExactSHA256Required = true
			object.ExactSHA256 = publication.VirtualPageMap.SHA256
		case cxlcheckpoint.ContentArtifactManifestMetadataV7:
			object.ExactSHA256Required = true
			object.ExactSHA256 = publication.ArtifactManifest.SHA256
		case cxlcheckpoint.ContentPlacementSlotAV7:
			object.ExactByteLength = uint64(len(initialPlacementBytes))
			object.ExactSHA256Required = true
			object.ExactSHA256 = initialPlacementSHA256
		case cxlcheckpoint.ContentPlacementSlotBV7:
			object.ExactByteLength = 0
		case cxlcheckpoint.ContentPublicationV7:
			object.ExactByteLength = uint64(len(publicationBytes))
			object.ExactSHA256Required = true
			object.ExactSHA256 = publicationSHA256
		}
		if err := ownerSealValidateObject(object); err != nil {
			return nil, ownerSealRecoveryErrorf(
				"reconstructed object %d: %v", index, err)
		}
		objects[index] = object
	}
	return objects, nil
}

func ownerSealRecoveryFailure(
	format string,
	arguments ...interface{},
) (CommittingOwnerSealRecoveryPlan, error) {
	return CommittingOwnerSealRecoveryPlan{}, ownerSealRecoveryErrorf(format, arguments...)
}

func ownerSealRecoveryErrorf(format string, arguments ...interface{}) error {
	return fmt.Errorf(
		"%w: %s",
		ErrInvalidOwnerSealRecoveryPlan,
		fmt.Sprintf(format, arguments...))
}
