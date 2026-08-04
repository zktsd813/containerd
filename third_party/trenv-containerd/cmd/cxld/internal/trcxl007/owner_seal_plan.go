package trcxl007

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// OwnerSealPlanDigestDomain identifies the process-local, compact plan
	// commitment. It is not an on-media format and does not claim that any
	// payload, descriptor, or Owner-state write has occurred.
	OwnerSealPlanDigestDomain = "TRCXL007-owner-seal-plan-v1"
)

var (
	// ErrInvalidOwnerSealPlan identifies a non-canonical fresh GRANTED join,
	// compact-plan mutation, iterator divergence, or invalid descriptor target.
	// Building and iterating a plan are pure and perform no storage I/O.
	ErrInvalidOwnerSealPlan = errors.New("invalid TRCXL007 Owner seal plan")
)

// OwnerSealObject is the compact object-level input to page classification.
// ExactByteLength is the meaningful length derived by the canonical initial
// publication plan. It is therefore nonzero for the initially published slot
// A and Publication object even though their immutable graph lengths are zero.
type OwnerSealObject struct {
	ObjectID         uint64
	Kind             cxlcheckpoint.ContentKindV7
	LogicalPageStart uint64
	ExactByteLength  uint64
	CapacityPages    uint64

	// ExactSHA256 is a typed control-object commitment, not a page checksum.
	// It is required for the canonical meaningful bytes of MMTemplate,
	// VirtualPageMap, ArtifactManifest, initial placement slot A, and the
	// Publication envelope. External payload objects and never-published slot B
	// use the canonical false/all-zero pair.
	ExactSHA256Required bool
	ExactSHA256         [sha256.Size]byte
}

// OwnerSealPlan is a detached, I/O-free fresh-seal plan. It stores one entry
// per device, object, and compact physical extent. It deliberately stores no
// page target, page descriptor, CRC vector, page byte, DAX handle, or raw
// authority material.
type OwnerSealPlan struct {
	clusterID              string
	ownerGroupID           string
	anchorDeviceUUID       string
	storageCompatibilityID string
	checkpointID           string
	ownerID                string
	requestID              string
	producerID             string
	dedupDomainID          string
	sharingPolicyID        string

	ownerEpoch             uint64
	groupConfiguration     uint64
	ownerSnapshotSequence  uint64
	allocationRecordID     uint64
	reservationTransaction uint64
	grantTransaction       uint64
	sealTransaction        uint64
	totalPages             uint64
	membershipSHA256       [sha256.Size]byte
	requestSHA256          [sha256.Size]byte
	authorityEvidence      OwnerStateAuthorityEvidence
	grantRecordSHA256      [sha256.Size]byte
	devices                []ProducerScatterDeviceBinding
	objects                []OwnerSealObject
	runs                   []ProducerScatterExtentRun
	integritySHA256        [sha256.Size]byte
}

// OwnerSealPageIterator walks the compact object and extent tables together in
// checkpoint-logical order. Its memory use is O(objects+extents+devices), not
// O(pages). It owns detached plan slices so later mutation of another plan
// value cannot redirect an already-created iterator.
type OwnerSealPageIterator struct {
	plan        OwnerSealPlan
	logicalPage uint64
	objectIndex int
	objectPage  uint64
	runIndex    int
	runPage     uint64
}

// OwnerSealPageTarget is one derived page operation. Every field is private so
// callers cannot substitute the descriptor identity after iteration. Accessors
// return scalar values or detached value objects.
type OwnerSealPageTarget struct {
	allocationRecordID     uint64
	reservationTransaction uint64
	sealTransaction        uint64
	logicalPage            uint64
	objectPage             uint64
	deviceIndex            uint32
	dataPageIndex          uint64
	device                 ProducerScatterDeviceBinding
	object                 OwnerSealObject
	meaningfulByteLength   uint32
	targetState            DescriptorState
	targetReferenceCount   uint64
}

// BuildFreshOwnerSealPlan performs a pure exact join of one canonical
// TROWN007 GRANTED allocation, the exact Producer scatter plan derived from
// that grant, and one canonical initial-publication plan. The selected seal
// transaction is the Owner snapshot's current next-transaction sequence.
//
// The builder reserves enough signed-Long sequence space for both durable
// GRANTED -> COMMITTING and COMMITTING -> COMMITTED transitions. It neither
// trusts Producer CRC values nor performs payload, descriptor, device, Owner,
// network, or runtime I/O.
func BuildFreshOwnerSealPlan(
	ownerState OwnerStateSnapshot,
	allocationRecordID uint64,
	producerPlan ProducerScatterPlan,
	publicationPlan cxlcheckpoint.InitialPublicationV7Plan,
) (OwnerSealPlan, error) {
	owner := ownerState.Clone()
	if err := owner.Validate(); err != nil {
		return OwnerSealPlan{}, ownerSealInvalidf("Owner state: %v", err)
	}
	if allocationRecordID == 0 || allocationRecordID > cxlcheckpoint.MaxSignedLong {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"allocation record ID %d is outside 1..%d",
			allocationRecordID, cxlcheckpoint.MaxSignedLong)
	}
	if err := publicationPlan.Validate(); err != nil {
		return OwnerSealPlan{}, ownerSealInvalidf("initial publication plan: %v", err)
	}
	canonicalPublication, err := cxlcheckpoint.BuildInitialPublicationV7Plan(
		cxlcheckpoint.InitialPublicationV7Input{
			Publication:                  publicationPlan.Publication,
			MMTemplate:                   publicationPlan.MMTemplate,
			VirtualPageMap:               publicationPlan.VirtualPageMap,
			ArtifactManifest:             publicationPlan.ArtifactManifest,
			InitialContentPlacementMapID: publicationPlan.InitialContentPlacementMap.ContentPlacementMapID,
			InitialActivePlacementRootID: publicationPlan.ActiveContentPlacementRoot.RootID,
		})
	if err != nil {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"rebuild initial publication plan: %v", err)
	}
	if err := producerPlan.Validate(); err != nil {
		return OwnerSealPlan{}, ownerSealInvalidf("Producer scatter plan: %v", err)
	}
	expectedProducerPlan, err := BuildProducerScatterPlan(
		owner, allocationRecordID, canonicalPublication)
	if err != nil {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"derive exact Producer scatter plan: %v", err)
	}
	if !reflect.DeepEqual(producerPlan, expectedProducerPlan) {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"supplied Producer scatter plan is not the exact canonical GRANTED/publication join")
	}

	record, found := producerScatterRecordByID(owner.Records(), allocationRecordID)
	if !found {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"allocation record %d is absent", allocationRecordID)
	}
	if record.State != OwnerAllocationGranted {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"allocation record %d state is %d, want GRANTED",
			allocationRecordID, record.State)
	}
	if record.OwnerVerifiedSealSHA256 != ([sha256.Size]byte{}) {
		return OwnerSealPlan{}, ownerSealInvalidf(
			"fresh GRANTED allocation already has an Owner-verified seal")
	}
	sealTransaction := owner.NextOwnerTransactionSequence
	if err := ownerSealValidateFutureSequences(
		owner.SnapshotSequence,
		record.ReservationTransactionSequence,
		record.OwnerTransactionSequence,
		sealTransaction,
	); err != nil {
		return OwnerSealPlan{}, err
	}

	objects := make([]OwnerSealObject, len(canonicalPublication.ObjectWrites))
	for index, write := range canonicalPublication.ObjectWrites {
		object := OwnerSealObject{
			ObjectID:         write.ObjectID,
			Kind:             write.Kind,
			LogicalPageStart: write.LogicalPageStart,
			ExactByteLength:  write.ExactByteLength,
			CapacityPages:    write.CapacityPages,
		}
		if write.WriteSource == cxlcheckpoint.InitialPublicationV7CanonicalControlBytes {
			object.ExactSHA256Required = true
			object.ExactSHA256 = sha256.Sum256(write.CanonicalBytes)
		}
		objects[index] = object
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
		ownerSnapshotSequence:  owner.SnapshotSequence,
		allocationRecordID:     record.AllocationRecordID,
		reservationTransaction: record.ReservationTransactionSequence,
		grantTransaction:       record.OwnerTransactionSequence,
		sealTransaction:        sealTransaction,
		totalPages:             record.TotalDemandPages,
		membershipSHA256:       owner.MembershipSHA256,
		requestSHA256:          record.RequestSHA256,
		authorityEvidence:      record.AuthorityEvidence,
		grantRecordSHA256:      expectedProducerPlan.grantRecordSHA256,
		devices:                append([]ProducerScatterDeviceBinding(nil), expectedProducerPlan.devices...),
		objects:                append([]OwnerSealObject(nil), objects...),
		runs:                   append([]ProducerScatterExtentRun(nil), expectedProducerPlan.runs...),
	}
	plan.integritySHA256 = ownerSealPlanSHA256(plan)
	if err := plan.Validate(); err != nil {
		return OwnerSealPlan{}, err
	}
	return plan, nil
}

// Validate checks the complete detached compact shape and integrity digest.
// It performs no I/O and does not materialize page targets.
func (plan OwnerSealPlan) Validate() error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{name: "cluster ID", value: plan.clusterID},
		{name: "Owner-group ID", value: plan.ownerGroupID},
		{name: "anchor device UUID", value: plan.anchorDeviceUUID},
		{name: "checkpoint ID", value: plan.checkpointID},
		{name: "Owner ID", value: plan.ownerID},
		{name: "request ID", value: plan.requestID},
		{name: "Producer ID", value: plan.producerID},
		{name: "deduplication-domain ID", value: plan.dedupDomainID},
		{name: "sharing-policy ID", value: plan.sharingPolicyID},
	} {
		if err := validateOwnerStateIdentity(identity.name, identity.value); err != nil {
			return ownerSealInvalidf("%v", err)
		}
	}
	if err := validateOwnerStateDeviceUUID("anchor device UUID", plan.anchorDeviceUUID); err != nil {
		return ownerSealInvalidf("%v", err)
	}
	if plan.storageCompatibilityID != cxlcheckpoint.V7StorageCompatibilityID {
		return ownerSealInvalidf("storage compatibility ID is not the compiled V7 target")
	}
	for _, value := range []struct {
		name  string
		value uint64
	}{
		{name: "Owner epoch", value: plan.ownerEpoch},
		{name: "group-configuration sequence", value: plan.groupConfiguration},
		{name: "Owner snapshot sequence", value: plan.ownerSnapshotSequence},
		{name: "allocation-record ID", value: plan.allocationRecordID},
		{name: "total pages", value: plan.totalPages},
	} {
		if value.value == 0 || value.value > cxlcheckpoint.MaxSignedLong {
			return ownerSealInvalidf(
				"%s %d is outside 1..%d", value.name, value.value, cxlcheckpoint.MaxSignedLong)
		}
	}
	if err := ownerSealValidateFutureSequences(
		plan.ownerSnapshotSequence,
		plan.reservationTransaction,
		plan.grantTransaction,
		plan.sealTransaction,
	); err != nil {
		return err
	}
	if plan.membershipSHA256 == ([sha256.Size]byte{}) ||
		plan.requestSHA256 == ([sha256.Size]byte{}) ||
		plan.authorityEvidence.SchedulerReserveSHA256 == ([sha256.Size]byte{}) ||
		plan.authorityEvidence.ProducerCapabilitySHA256 == ([sha256.Size]byte{}) ||
		plan.authorityEvidence.PublicationAuthoritySHA256 == ([sha256.Size]byte{}) ||
		plan.authorityEvidence.ReclaimAuthoritySHA256 == ([sha256.Size]byte{}) ||
		plan.grantRecordSHA256 == ([sha256.Size]byte{}) {
		return ownerSealInvalidf(
			"plan has a zero membership, request, authority, or grant-record commitment")
	}

	if len(plan.devices) == 0 || len(plan.devices) > MaxOwnerStateDevices {
		return ownerSealInvalidf("device count %d is outside bounds", len(plan.devices))
	}
	previousUUID := ""
	for index, device := range plan.devices {
		if err := validateOwnerStateDeviceUUID("device UUID", device.DeviceUUID); err != nil {
			return ownerSealInvalidf("device %d: %v", index, err)
		}
		if index > 0 && previousUUID >= device.DeviceUUID {
			return ownerSealInvalidf("devices are duplicate or not strictly ordered by UUID")
		}
		if device.DeviceOwnerEpoch != plan.ownerEpoch || device.DataPageCount == 0 ||
			device.DataPageCount > cxlcheckpoint.MaxSignedLong ||
			device.DeviceBindingSHA256 == ([sha256.Size]byte{}) {
			return ownerSealInvalidf("device %d has an invalid binding", index)
		}
		previousUUID = device.DeviceUUID
	}

	if len(plan.objects) == 0 || len(plan.objects) > MaxOwnerStateContentDemands {
		return ownerSealInvalidf("object count %d is outside bounds", len(plan.objects))
	}
	expectedLogical := uint64(0)
	previousObjectID := uint64(0)
	for index, object := range plan.objects {
		if err := ownerSealValidateObject(object); err != nil {
			return ownerSealInvalidf("object %d: %v", index, err)
		}
		if index > 0 && previousObjectID >= object.ObjectID {
			return ownerSealInvalidf("objects are duplicate or not strictly ordered by ID")
		}
		if object.LogicalPageStart != expectedLogical {
			return ownerSealInvalidf(
				"object %d starts at logical page %d, want %d",
				object.ObjectID, object.LogicalPageStart, expectedLogical)
		}
		next, ok := checkedAdd(expectedLogical, object.CapacityPages)
		if !ok || next > cxlcheckpoint.MaxSignedLong {
			return ownerSealInvalidf("object coverage overflows the signed-Long ABI")
		}
		expectedLogical = next
		previousObjectID = object.ObjectID
	}
	if expectedLogical != plan.totalPages {
		return ownerSealInvalidf(
			"objects cover %d pages, want %d", expectedLogical, plan.totalPages)
	}

	if len(plan.runs) == 0 || len(plan.runs) > MaxOwnerStateExtents {
		return ownerSealInvalidf("extent-run count %d is outside bounds", len(plan.runs))
	}
	expectedLogical = 0
	for index, run := range plan.runs {
		if uint64(run.DeviceIndex) >= uint64(len(plan.devices)) || run.PageCount == 0 ||
			run.PageCount > cxlcheckpoint.MaxSignedLong || run.LogicalPageStart != expectedLogical {
			return ownerSealInvalidf("extent run %d has invalid device or logical coverage", index)
		}
		physicalEnd, physicalOK := checkedAdd(run.StartDataPageIndex, run.PageCount)
		if !physicalOK || physicalEnd > plan.devices[run.DeviceIndex].DataPageCount ||
			physicalEnd > cxlcheckpoint.MaxSignedLong {
			return ownerSealInvalidf("extent run %d exceeds device or signed-Long bounds", index)
		}
		if index > 0 {
			previous := plan.runs[index-1]
			previousPhysicalEnd, physicalEndOK := checkedAdd(
				previous.StartDataPageIndex, previous.PageCount)
			previousLogicalEnd, logicalEndOK := checkedAdd(
				previous.LogicalPageStart, previous.PageCount)
			if physicalEndOK && logicalEndOK && previous.DeviceIndex == run.DeviceIndex &&
				previousPhysicalEnd == run.StartDataPageIndex &&
				previousLogicalEnd == run.LogicalPageStart {
				return ownerSealInvalidf("extent runs %d and %d are coalescible", index-1, index)
			}
		}
		next, addOK := checkedAdd(expectedLogical, run.PageCount)
		if !addOK || next > cxlcheckpoint.MaxSignedLong {
			return ownerSealInvalidf("extent coverage overflows the signed-Long ABI")
		}
		expectedLogical = next
	}
	if expectedLogical != plan.totalPages {
		return ownerSealInvalidf(
			"extents cover %d pages, want %d", expectedLogical, plan.totalPages)
	}
	if plan.integritySHA256 == ([sha256.Size]byte{}) ||
		plan.integritySHA256 != ownerSealPlanSHA256(plan) {
		return ownerSealInvalidf("plan integrity SHA-256 differs")
	}
	return nil
}

func (plan OwnerSealPlan) ClusterID() string              { return plan.clusterID }
func (plan OwnerSealPlan) OwnerGroupID() string           { return plan.ownerGroupID }
func (plan OwnerSealPlan) AnchorDeviceUUID() string       { return plan.anchorDeviceUUID }
func (plan OwnerSealPlan) StorageCompatibilityID() string { return plan.storageCompatibilityID }
func (plan OwnerSealPlan) CheckpointID() string           { return plan.checkpointID }
func (plan OwnerSealPlan) OwnerID() string                { return plan.ownerID }
func (plan OwnerSealPlan) RequestID() string              { return plan.requestID }
func (plan OwnerSealPlan) ProducerID() string             { return plan.producerID }
func (plan OwnerSealPlan) DedupDomainID() string          { return plan.dedupDomainID }
func (plan OwnerSealPlan) SharingPolicyID() string        { return plan.sharingPolicyID }
func (plan OwnerSealPlan) OwnerEpoch() uint64             { return plan.ownerEpoch }
func (plan OwnerSealPlan) GroupConfigurationSequence() uint64 {
	return plan.groupConfiguration
}
func (plan OwnerSealPlan) OwnerSnapshotSequence() uint64 { return plan.ownerSnapshotSequence }
func (plan OwnerSealPlan) AllocationRecordID() uint64    { return plan.allocationRecordID }
func (plan OwnerSealPlan) ReservationTransactionSequence() uint64 {
	return plan.reservationTransaction
}
func (plan OwnerSealPlan) GrantTransactionSequence() uint64 { return plan.grantTransaction }
func (plan OwnerSealPlan) SealTransactionSequence() uint64  { return plan.sealTransaction }
func (plan OwnerSealPlan) TotalPages() uint64               { return plan.totalPages }

// CommittingOwnerSnapshotSequence is the exact next TROWN007 full-snapshot
// sequence. Build/Validate prove that the addition cannot overflow.
func (plan OwnerSealPlan) CommittingOwnerSnapshotSequence() uint64 {
	return plan.ownerSnapshotSequence + 1
}

// TerminalOwnerSnapshotSequence is the exact COMMITTED/QUARANTINED snapshot
// sequence after a successful durable COMMITTING snapshot.
func (plan OwnerSealPlan) TerminalOwnerSnapshotSequence() uint64 {
	return plan.ownerSnapshotSequence + 2
}

// TerminalTransactionSequence is the current Owner transaction for the
// COMMITTED/QUARANTINED record derived from this fresh seal transaction.
func (plan OwnerSealPlan) TerminalTransactionSequence() uint64 {
	return plan.sealTransaction + 1
}

// NextTransactionSequenceAfterTerminal is the high-water value required by a
// valid terminal Owner snapshot.
func (plan OwnerSealPlan) NextTransactionSequenceAfterTerminal() uint64 {
	return plan.sealTransaction + 2
}

func (plan OwnerSealPlan) MembershipSHA256() [sha256.Size]byte {
	return plan.membershipSHA256
}

func (plan OwnerSealPlan) RequestSHA256() [sha256.Size]byte {
	return plan.requestSHA256
}

func (plan OwnerSealPlan) AuthorityEvidence() OwnerStateAuthorityEvidence {
	return plan.authorityEvidence
}

func (plan OwnerSealPlan) SchedulerReserveSHA256() [sha256.Size]byte {
	return plan.authorityEvidence.SchedulerReserveSHA256
}

func (plan OwnerSealPlan) ProducerCapabilitySHA256() [sha256.Size]byte {
	return plan.authorityEvidence.ProducerCapabilitySHA256
}

func (plan OwnerSealPlan) PublicationAuthoritySHA256() [sha256.Size]byte {
	return plan.authorityEvidence.PublicationAuthoritySHA256
}

func (plan OwnerSealPlan) ReclaimAuthoritySHA256() [sha256.Size]byte {
	return plan.authorityEvidence.ReclaimAuthoritySHA256
}

func (plan OwnerSealPlan) GrantRecordSHA256() [sha256.Size]byte {
	return plan.grantRecordSHA256
}

func (plan OwnerSealPlan) IntegritySHA256() [sha256.Size]byte {
	return plan.integritySHA256
}

func (plan OwnerSealPlan) Devices() []ProducerScatterDeviceBinding {
	return append([]ProducerScatterDeviceBinding(nil), plan.devices...)
}

func (plan OwnerSealPlan) Objects() []OwnerSealObject {
	return append([]OwnerSealObject(nil), plan.objects...)
}

func (plan OwnerSealPlan) ExtentRuns() []ProducerScatterExtentRun {
	return append([]ProducerScatterExtentRun(nil), plan.runs...)
}

// CrossCheckProducerScatterResult accepts only the exact execution result for
// this checkpoint/allocation and returns a detached, structurally validated
// CRC candidate vector. The vector remains non-authoritative: it is neither
// stored in the plan nor incorporated into the Owner seal commitment.
func (plan OwnerSealPlan) CrossCheckProducerScatterResult(
	result ProducerScatterResult,
) (ProducerScatterCRCVector, error) {
	if err := plan.Validate(); err != nil {
		return ProducerScatterCRCVector{}, err
	}
	if result.checkpointID != plan.checkpointID ||
		result.allocationRecordID != plan.allocationRecordID {
		return ProducerScatterCRCVector{}, ownerSealInvalidf(
			"Producer scatter result checkpoint/allocation identity differs")
	}
	if result.crcVector.totalPages != plan.totalPages {
		return ProducerScatterCRCVector{}, ownerSealInvalidf(
			"Producer CRC vector covers %d pages, want %d",
			result.crcVector.totalPages, plan.totalPages)
	}
	vector, err := ParseProducerScatterCRCVector(
		result.crcVector.Bytes(), plan.totalPages)
	if err != nil {
		return ProducerScatterCRCVector{}, ownerSealInvalidf(
			"Producer CRC vector: %v", err)
	}
	return vector, nil
}

// PageIterator validates and detaches the compact plan, then returns a cursor
// positioned at checkpoint logical page zero.
func (plan OwnerSealPlan) PageIterator() (OwnerSealPageIterator, error) {
	if err := plan.Validate(); err != nil {
		return OwnerSealPageIterator{}, err
	}
	return OwnerSealPageIterator{plan: cloneOwnerSealPlan(plan)}, nil
}

// Next returns the next canonical page target or io.EOF after exact completion.
// It performs constant work and allocates no per-page slice or page buffer.
func (iterator *OwnerSealPageIterator) Next() (OwnerSealPageTarget, error) {
	if iterator == nil {
		return OwnerSealPageTarget{}, ownerSealInvalidf("page iterator is nil")
	}
	if iterator.plan.totalPages == 0 {
		return OwnerSealPageTarget{}, ownerSealInvalidf("page iterator is uninitialized")
	}
	if iterator.logicalPage == iterator.plan.totalPages {
		if iterator.objectIndex != len(iterator.plan.objects) || iterator.objectPage != 0 ||
			iterator.runIndex != len(iterator.plan.runs) || iterator.runPage != 0 {
			return OwnerSealPageTarget{}, ownerSealInvalidf(
				"page iterator cursors did not finish together")
		}
		return OwnerSealPageTarget{}, io.EOF
	}
	if iterator.logicalPage > iterator.plan.totalPages ||
		iterator.objectIndex < 0 || iterator.objectIndex >= len(iterator.plan.objects) ||
		iterator.runIndex < 0 || iterator.runIndex >= len(iterator.plan.runs) {
		return OwnerSealPageTarget{}, ownerSealInvalidf("page iterator cursor is outside the compact plan")
	}
	object := iterator.plan.objects[iterator.objectIndex]
	run := iterator.plan.runs[iterator.runIndex]
	objectLogical, objectOK := checkedAdd(object.LogicalPageStart, iterator.objectPage)
	runLogical, runOK := checkedAdd(run.LogicalPageStart, iterator.runPage)
	dataPageIndex, dataOK := checkedAdd(run.StartDataPageIndex, iterator.runPage)
	if !objectOK || !runOK || !dataOK || objectLogical != iterator.logicalPage ||
		runLogical != iterator.logicalPage || iterator.objectPage >= object.CapacityPages ||
		iterator.runPage >= run.PageCount ||
		uint64(run.DeviceIndex) >= uint64(len(iterator.plan.devices)) {
		return OwnerSealPageTarget{}, ownerSealInvalidf("object and extent cursors diverged")
	}
	meaningful, state, references, err := ownerSealClassifyPage(object, iterator.objectPage)
	if err != nil {
		return OwnerSealPageTarget{}, err
	}
	target := OwnerSealPageTarget{
		allocationRecordID:     iterator.plan.allocationRecordID,
		reservationTransaction: iterator.plan.reservationTransaction,
		sealTransaction:        iterator.plan.sealTransaction,
		logicalPage:            iterator.logicalPage,
		objectPage:             iterator.objectPage,
		deviceIndex:            run.DeviceIndex,
		dataPageIndex:          dataPageIndex,
		device:                 iterator.plan.devices[run.DeviceIndex],
		object:                 object,
		meaningfulByteLength:   meaningful,
		targetState:            state,
		targetReferenceCount:   references,
	}
	if err := target.validate(); err != nil {
		return OwnerSealPageTarget{}, err
	}

	iterator.logicalPage++
	iterator.objectPage++
	if iterator.objectPage == object.CapacityPages {
		iterator.objectIndex++
		iterator.objectPage = 0
	}
	iterator.runPage++
	if iterator.runPage == run.PageCount {
		iterator.runIndex++
		iterator.runPage = 0
	}
	return target, nil
}

func (target OwnerSealPageTarget) LogicalPage() uint64 { return target.logicalPage }
func (target OwnerSealPageTarget) ObjectPage() uint64  { return target.objectPage }
func (target OwnerSealPageTarget) DeviceIndex() uint32 { return target.deviceIndex }
func (target OwnerSealPageTarget) DataPageIndex() uint64 {
	return target.dataPageIndex
}
func (target OwnerSealPageTarget) Device() ProducerScatterDeviceBinding { return target.device }
func (target OwnerSealPageTarget) Object() OwnerSealObject              { return target.object }
func (target OwnerSealPageTarget) MeaningfulByteLength() uint32 {
	return target.meaningfulByteLength
}
func (target OwnerSealPageTarget) TargetState() DescriptorState { return target.targetState }
func (target OwnerSealPageTarget) InitialReferenceCount() uint64 {
	return target.targetReferenceCount
}

// ExpectedReservedDescriptor returns the one exact descriptor written during
// PREPARING and retained through GRANTED. Its Owner transaction is immutable
// reservation transaction R, not the later grant or seal transaction.
func (target OwnerSealPageTarget) ExpectedReservedDescriptor() (Descriptor, error) {
	if err := target.validate(); err != nil {
		return Descriptor{}, err
	}
	descriptor := Descriptor{
		AllocationRecordID:  target.allocationRecordID,
		OriginObjectID:      target.object.ObjectID,
		OwnerTransactionSeq: target.reservationTransaction,
		State:               DescriptorReserved,
		ContentKind:         target.object.Kind,
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, ownerSealInvalidf("expected RESERVED descriptor: %v", err)
	}
	return descriptor, nil
}

// TargetDescriptor injects the CRC32C returned by the Owner's hardware DML
// reread into the exact target descriptor. It never accepts content bytes and
// never computes a CPU CRC. EMPTY_SLOT and ZERO_PADDING additionally require
// that the supplied DML result equal the canonical full-zero-page CRC32C.
func (target OwnerSealPageTarget) TargetDescriptor(
	ownerDMLCRC32C uint32,
) (Descriptor, error) {
	if err := target.validate(); err != nil {
		return Descriptor{}, err
	}
	if (target.targetState == DescriptorEmptySlot ||
		target.targetState == DescriptorZeroPadding) &&
		ownerDMLCRC32C != zeroContentPageCRC32C {
		return Descriptor{}, ownerSealInvalidf(
			"logical page %d zero target DML CRC32C %#08x does not equal canonical zero-page CRC32C %#08x",
			target.logicalPage, ownerDMLCRC32C, zeroContentPageCRC32C)
	}
	descriptor := Descriptor{
		PaddedPageCRC32C:      ownerDMLCRC32C,
		AllocationRecordID:    target.allocationRecordID,
		OriginObjectID:        target.object.ObjectID,
		ContentReferenceCount: target.targetReferenceCount,
		OwnerTransactionSeq:   target.sealTransaction,
		PayloadLength:         target.meaningfulByteLength,
		State:                 target.targetState,
		ContentKind:           target.object.Kind,
	}
	if err := descriptor.Validate(); err != nil {
		return Descriptor{}, ownerSealInvalidf("target descriptor: %v", err)
	}
	return descriptor, nil
}

func (target OwnerSealPageTarget) validate() error {
	if target.allocationRecordID == 0 ||
		target.allocationRecordID > cxlcheckpoint.MaxSignedLong ||
		target.reservationTransaction == 0 ||
		target.reservationTransaction > cxlcheckpoint.MaxSignedLong ||
		target.sealTransaction == 0 ||
		target.sealTransaction > cxlcheckpoint.MaxSignedLong ||
		target.sealTransaction <= target.reservationTransaction {
		return ownerSealInvalidf("page target has an invalid allocation or transaction identity")
	}
	if err := ownerSealValidateObject(target.object); err != nil {
		return ownerSealInvalidf("page target object: %v", err)
	}
	if target.objectPage >= target.object.CapacityPages {
		return ownerSealInvalidf("page target object page is outside capacity")
	}
	wantLogical, ok := checkedAdd(target.object.LogicalPageStart, target.objectPage)
	if !ok || wantLogical != target.logicalPage {
		return ownerSealInvalidf("page target logical/object position differs")
	}
	if target.device.DeviceUUID == "" || target.device.DeviceOwnerEpoch == 0 ||
		target.device.DataPageCount == 0 ||
		target.device.DeviceBindingSHA256 == ([sha256.Size]byte{}) ||
		target.dataPageIndex >= target.device.DataPageCount {
		return ownerSealInvalidf("page target has an invalid device binding or physical page")
	}
	meaningful, state, references, err := ownerSealClassifyPage(target.object, target.objectPage)
	if err != nil {
		return err
	}
	if target.meaningfulByteLength != meaningful || target.targetState != state ||
		target.targetReferenceCount != references {
		return ownerSealInvalidf("page target descriptor classification differs from its object")
	}
	return nil
}

func ownerSealValidateFutureSequences(
	ownerSnapshot uint64,
	reservation uint64,
	grant uint64,
	seal uint64,
) error {
	for _, value := range []struct {
		name  string
		value uint64
	}{
		{name: "Owner snapshot sequence", value: ownerSnapshot},
		{name: "reservation transaction", value: reservation},
		{name: "grant transaction", value: grant},
		{name: "seal transaction", value: seal},
	} {
		if value.value == 0 || value.value > cxlcheckpoint.MaxSignedLong {
			return ownerSealInvalidf(
				"%s %d is outside 1..%d", value.name, value.value, cxlcheckpoint.MaxSignedLong)
		}
	}
	wantGrant, ok := checkedAdd(reservation, 1)
	if !ok || wantGrant > cxlcheckpoint.MaxSignedLong || grant != wantGrant {
		return ownerSealInvalidf("grant transaction does not immediately follow reservation")
	}
	if seal <= grant {
		return ownerSealInvalidf("seal transaction %d does not exceed grant transaction %d", seal, grant)
	}
	terminalTransaction, terminalOK := checkedAdd(seal, 1)
	nextTransaction, nextOK := checkedAdd(seal, 2)
	committingSnapshot, committingOK := checkedAdd(ownerSnapshot, 1)
	terminalSnapshot, snapshotOK := checkedAdd(ownerSnapshot, 2)
	if !terminalOK || !nextOK || !committingOK || !snapshotOK ||
		terminalTransaction > cxlcheckpoint.MaxSignedLong ||
		nextTransaction > cxlcheckpoint.MaxSignedLong ||
		committingSnapshot > cxlcheckpoint.MaxSignedLong ||
		terminalSnapshot > cxlcheckpoint.MaxSignedLong {
		return ownerSealInvalidf(
			"fresh seal lacks signed-Long sequence space for COMMITTING and terminal state")
	}
	return nil
}

func ownerSealValidateObject(object OwnerSealObject) error {
	if object.ObjectID == 0 || object.ObjectID > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("object ID is outside the signed-Long ABI")
	}
	if !validOwnerStateContentKind(object.Kind) {
		return fmt.Errorf("content kind %d is outside the V7 contract", object.Kind)
	}
	if object.LogicalPageStart > cxlcheckpoint.MaxSignedLong ||
		object.CapacityPages == 0 || object.CapacityPages > cxlcheckpoint.MaxSignedLong ||
		object.ExactByteLength > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("logical start, capacity, or exact length is outside the signed-Long ABI")
	}
	capacityBytes, ok := checkedMul(object.CapacityPages, uint64(ContentPageBytes))
	if !ok || capacityBytes > cxlcheckpoint.MaxSignedLong ||
		object.ExactByteLength > capacityBytes {
		return fmt.Errorf("exact length exceeds capacity or signed-Long bounds")
	}
	switch object.Kind {
	case cxlcheckpoint.ContentPlacementSlotBV7:
		if object.ExactByteLength != 0 {
			return fmt.Errorf("placement slot B has meaningful bytes")
		}
	case cxlcheckpoint.ContentPlacementSlotAV7,
		cxlcheckpoint.ContentPublicationV7:
		if object.ExactByteLength == 0 {
			return fmt.Errorf("initial slot A or Publication exact length is zero")
		}
	default:
		if object.ExactByteLength == 0 {
			return fmt.Errorf("immutable object exact length is zero")
		}
		minimumPages, pagesOK := ownerSealPagesForBytes(object.ExactByteLength)
		if !pagesOK || minimumPages != object.CapacityPages {
			return fmt.Errorf("immutable object capacity is not the exact ceil(length/page size)")
		}
	}
	if object.Kind == cxlcheckpoint.ContentMemoryPayloadV7 &&
		object.ExactByteLength != capacityBytes {
		return fmt.Errorf("memory object does not fill every capacity page")
	}
	wantExactSHA := object.Kind == cxlcheckpoint.ContentMMTemplateMetadataV7 ||
		object.Kind == cxlcheckpoint.ContentVirtualPageMapMetadataV7 ||
		object.Kind == cxlcheckpoint.ContentArtifactManifestMetadataV7 ||
		object.Kind == cxlcheckpoint.ContentPlacementSlotAV7 ||
		object.Kind == cxlcheckpoint.ContentPublicationV7
	if object.ExactSHA256Required != wantExactSHA {
		return fmt.Errorf("typed control-object SHA-256 requirement is non-canonical")
	}
	if object.ExactSHA256Required {
		if object.ExactSHA256 == ([sha256.Size]byte{}) {
			return fmt.Errorf("required typed control-object SHA-256 is zero")
		}
	} else if object.ExactSHA256 != ([sha256.Size]byte{}) {
		return fmt.Errorf("object without a typed SHA-256 requirement has a nonzero digest")
	}
	return nil
}

func ownerSealClassifyPage(
	object OwnerSealObject,
	objectPage uint64,
) (uint32, DescriptorState, uint64, error) {
	if err := ownerSealValidateObject(object); err != nil {
		return 0, 0, 0, ownerSealInvalidf("classify object: %v", err)
	}
	if objectPage >= object.CapacityPages {
		return 0, 0, 0, ownerSealInvalidf("object page %d is outside capacity", objectPage)
	}
	pageByteStart, ok := checkedMul(objectPage, uint64(ContentPageBytes))
	if !ok || pageByteStart > cxlcheckpoint.MaxSignedLong {
		return 0, 0, 0, ownerSealInvalidf("object page byte offset overflows")
	}
	meaningful := uint32(0)
	if pageByteStart < object.ExactByteLength {
		remaining := object.ExactByteLength - pageByteStart
		if remaining > uint64(ContentPageBytes) {
			remaining = uint64(ContentPageBytes)
		}
		meaningful = uint32(remaining)
	}
	switch object.Kind {
	case cxlcheckpoint.ContentPlacementSlotAV7:
		if meaningful > 0 {
			return meaningful, DescriptorPublishedSlot, 1, nil
		}
		return 0, DescriptorEmptySlot, 0, nil
	case cxlcheckpoint.ContentPlacementSlotBV7:
		return 0, DescriptorEmptySlot, 0, nil
	case cxlcheckpoint.ContentPublicationV7:
		if meaningful > 0 {
			return meaningful, DescriptorImmutableSealed, 1, nil
		}
		return 0, DescriptorZeroPadding, 0, nil
	default:
		if meaningful == 0 {
			return 0, 0, 0, ownerSealInvalidf(
				"non-reservation immutable object has a full empty capacity page")
		}
		return meaningful, DescriptorImmutableSealed, 1, nil
	}
}

func ownerSealPagesForBytes(byteLength uint64) (uint64, bool) {
	if byteLength == 0 || byteLength > cxlcheckpoint.MaxSignedLong {
		return 0, false
	}
	pages := byteLength / uint64(ContentPageBytes)
	if byteLength%uint64(ContentPageBytes) != 0 {
		if pages == cxlcheckpoint.MaxSignedLong {
			return 0, false
		}
		pages++
	}
	return pages, pages > 0 && pages <= cxlcheckpoint.MaxSignedLong
}

func cloneOwnerSealPlan(plan OwnerSealPlan) OwnerSealPlan {
	plan.devices = append([]ProducerScatterDeviceBinding(nil), plan.devices...)
	plan.objects = append([]OwnerSealObject(nil), plan.objects...)
	plan.runs = append([]ProducerScatterExtentRun(nil), plan.runs...)
	return plan
}

func ownerSealPlanSHA256(plan OwnerSealPlan) [sha256.Size]byte {
	digest := sha256.New()
	producerScatterDigestString(digest, OwnerSealPlanDigestDomain)
	producerScatterDigestString(digest, plan.clusterID)
	producerScatterDigestString(digest, plan.ownerGroupID)
	producerScatterDigestString(digest, plan.anchorDeviceUUID)
	producerScatterDigestString(digest, plan.storageCompatibilityID)
	producerScatterDigestString(digest, plan.checkpointID)
	producerScatterDigestString(digest, plan.ownerID)
	producerScatterDigestString(digest, plan.requestID)
	producerScatterDigestString(digest, plan.producerID)
	producerScatterDigestString(digest, plan.dedupDomainID)
	producerScatterDigestString(digest, plan.sharingPolicyID)
	producerScatterDigestUint64(digest, plan.ownerEpoch)
	producerScatterDigestUint64(digest, plan.groupConfiguration)
	producerScatterDigestUint64(digest, plan.ownerSnapshotSequence)
	producerScatterDigestUint64(digest, plan.allocationRecordID)
	producerScatterDigestUint64(digest, plan.reservationTransaction)
	producerScatterDigestUint64(digest, plan.grantTransaction)
	producerScatterDigestUint64(digest, plan.sealTransaction)
	producerScatterDigestUint64(digest, plan.totalPages)
	_, _ = digest.Write(plan.membershipSHA256[:])
	_, _ = digest.Write(plan.requestSHA256[:])
	_, _ = digest.Write(plan.authorityEvidence.SchedulerReserveSHA256[:])
	_, _ = digest.Write(plan.authorityEvidence.ProducerCapabilitySHA256[:])
	_, _ = digest.Write(plan.authorityEvidence.PublicationAuthoritySHA256[:])
	_, _ = digest.Write(plan.authorityEvidence.ReclaimAuthoritySHA256[:])
	_, _ = digest.Write(plan.grantRecordSHA256[:])
	producerScatterDigestUint64(digest, uint64(len(plan.devices)))
	for _, device := range plan.devices {
		producerScatterDigestString(digest, device.DeviceUUID)
		producerScatterDigestUint64(digest, device.DeviceOwnerEpoch)
		producerScatterDigestUint64(digest, device.DataPageCount)
		_, _ = digest.Write(device.DeviceBindingSHA256[:])
	}
	producerScatterDigestUint64(digest, uint64(len(plan.objects)))
	for _, object := range plan.objects {
		producerScatterDigestUint64(digest, object.ObjectID)
		_, _ = digest.Write([]byte{byte(object.Kind)})
		producerScatterDigestUint64(digest, object.LogicalPageStart)
		producerScatterDigestUint64(digest, object.ExactByteLength)
		producerScatterDigestUint64(digest, object.CapacityPages)
		if object.ExactSHA256Required {
			_, _ = digest.Write([]byte{1})
		} else {
			_, _ = digest.Write([]byte{0})
		}
		_, _ = digest.Write(object.ExactSHA256[:])
	}
	producerScatterDigestUint64(digest, uint64(len(plan.runs)))
	for _, run := range plan.runs {
		producerScatterDigestUint64(digest, uint64(run.DeviceIndex))
		producerScatterDigestUint64(digest, run.StartDataPageIndex)
		producerScatterDigestUint64(digest, run.LogicalPageStart)
		producerScatterDigestUint64(digest, run.PageCount)
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func ownerSealInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidOwnerSealPlan, fmt.Sprintf(format, arguments...))
}
