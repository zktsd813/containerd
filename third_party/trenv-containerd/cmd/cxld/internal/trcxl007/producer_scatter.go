package trcxl007

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"runtime"
	"unsafe"

	"github.com/containerd/containerd/third_party/trenv-containerd/cmd/cxld/internal/trcxl007dml"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// The plan domain remains v1 because the plan already commits the separately
	// versioned complete GRANTED-record digest. The record domain is the hard cut
	// that adds OwnerVerifiedSealSHA256, including its canonical zero GRANTED value.
	producerScatterPlanDigestDomain        = "TRCXL007-producer-scatter-plan-v1"
	producerScatterGrantRecordDigestDomain = "TRCXL007-producer-scatter-grant-record-v2"
)

var (
	// ErrInvalidProducerScatterPlan identifies a zero, mutated, mismatched, or
	// otherwise non-canonical Owner-grant/publication join. Building a plan is
	// pure: this error is never proof that payload I/O occurred.
	ErrInvalidProducerScatterPlan = errors.New("invalid TRCXL007 Producer scatter plan")

	// ErrProducerScatterCancellationRequired identifies every execution failure
	// after a valid durable GRANTED allocation has been accepted. The caller must
	// fence the Producer through the authenticated Owner service and invoke the
	// separate GRANTED-cancellation path; PREPARING abort is never valid here.
	ErrProducerScatterCancellationRequired = errors.New(
		"TRCXL007 Producer scatter failed and GRANTED cancellation is required")
)

// ProducerScatterDeviceBinding is the complete portable identity supplied to
// the already capability-bound destination seam. It deliberately contains no
// host-local path, descriptor handle, mmap, file descriptor, socket, or raw
// authority material.
type ProducerScatterDeviceBinding struct {
	DeviceUUID          string
	DeviceOwnerEpoch    uint64
	DataPageCount       uint64
	DeviceBindingSHA256 [sha256.Size]byte
}

// ProducerScatterObject describes one object-level write. It is compact: one
// value is retained per object, never per page.
type ProducerScatterObject struct {
	ObjectID         uint64
	Kind             cxlcheckpoint.ContentKindV7
	LogicalPageStart uint64
	ExactByteLength  uint64
	CapacityPages    uint64
}

// ProducerScatterExtentRun maps one checkpoint-logical run to one entry in
// Devices(). Adjacent logical and physical runs on the same device are merged
// by the builder.
type ProducerScatterExtentRun struct {
	DeviceIndex        uint32
	StartDataPageIndex uint64
	LogicalPageStart   uint64
	PageCount          uint64
}

type producerScatterWriteSource uint8

const (
	producerScatterExternal producerScatterWriteSource = iota + 1
	producerScatterCanonical
	producerScatterZero
)

type producerScatterObjectPlan struct {
	ProducerScatterObject
	writeSource    producerScatterWriteSource
	canonicalBytes []byte
}

// ProducerScatterPlan is a detached, compact execution plan. Its slices are
// private and every accessor returns a copy. It carries no per-page target
// table and no raw capability or publication authority.
type ProducerScatterPlan struct {
	checkpointID           string
	allocationRecordID     uint64
	clusterID              string
	ownerGroupID           string
	anchorDeviceUUID       string
	ownerID                string
	ownerEpoch             uint64
	groupConfiguration     uint64
	membershipSHA256       [sha256.Size]byte
	reservationTransaction uint64
	grantTransaction       uint64
	grantRecordSHA256      [sha256.Size]byte
	totalPages             uint64
	devices                []ProducerScatterDeviceBinding
	objects                []producerScatterObjectPlan
	runs                   []ProducerScatterExtentRun
	integritySHA256        [sha256.Size]byte
}

// ProducerScatterSource supplies the exact meaningful bytes of one external
// memory, artifact, or restore-blob object. ReaderAt keeps every read bounded
// to an explicit object-relative offset. ExactByteLength must equal the
// canonical object write length.
type ProducerScatterSource struct {
	ObjectID        uint64
	ExactByteLength uint64
	Reader          ProducerScatterSourceReaderAt
}

// ProducerScatterBackingRange identifies one exact byte range within a stable
// physical backing object. IDs are authority-bound opaque commitments, not
// paths or bearer tokens. Every production source and destination adapter MUST
// use one shared global derivation namespace: every mapping of the same
// physical bytes must report the same BackingID, even at a different virtual
// address, while different backing objects must not share an ID. An adapter
// that cannot prove this rule is ineligible for production wiring. Byte ranges
// let preflight reject source/destination and destination/destination aliasing
// before the first COPY_CRC.
type ProducerScatterBackingRange struct {
	BackingID  [sha256.Size]byte
	ByteOffset uint64
	ByteLength uint64
}

// ProducerScatterSourceReaderAt supplies bounded object-relative reads plus an
// enforceable stable-backing identity. The authenticated Producer adapter must
// return the actual immutable source range; a generic unbounded io.Reader or a
// ReaderAt with no backing identity is intentionally not accepted.
type ProducerScatterSourceReaderAt interface {
	io.ReaderAt
	ProducerScatterBackingRange() ProducerScatterBackingRange
}

// ProducerScatterWritableExtent is one compact, physically contiguous run.
// Bytes must be exactly PageCount*4096 and remain stable until SyncDevice
// returns. One view is retained per extent, never per page.
type ProducerScatterWritableExtent struct {
	Bytes   []byte
	Backing ProducerScatterBackingRange
}

// ProducerScatterPageCopier is the exact Intel-DML adapter interface, not a
// locally redefined look-alike. Production construction must inject the
// hardware-only OpenHardware result. This package never calls Close and has no
// CPU/software checksum or copy fallback; the caller owns copier lifecycle.
type ProducerScatterPageCopier = trcxl007dml.Copier

// ProducerScatterDestination is an already authenticated and capability-bound
// content seam. PrepareDevice validates the complete portable binding.
// WritableExtent must return the exact stable contiguous view for the supplied
// compact run. The caller owns destination lifecycle.
type ProducerScatterDestination interface {
	PrepareDevice(binding ProducerScatterDeviceBinding) error
	WritableExtent(
		binding ProducerScatterDeviceBinding,
		startDataPageIndex uint64,
		pageCount uint64,
	) (ProducerScatterWritableExtent, error)
	SyncDevice(binding ProducerScatterDeviceBinding) error
}

// ProducerScatterExecutionRequest combines one already validated grant plan
// with external payload sources and narrow execution seams.
type ProducerScatterExecutionRequest struct {
	Plan        ProducerScatterPlan
	Sources     []ProducerScatterSource
	Destination ProducerScatterDestination
	Copier      ProducerScatterPageCopier
}

// ProducerScatterResult proves only that every planned capacity page was
// passed to CopyPage and every affected abstract destination was then synced.
// It does not prove descriptor sealing, Owner COMMITTED, static-root creation,
// publication, physical non-coherent CXL visibility, or Reader availability.
type ProducerScatterResult struct {
	checkpointID       string
	allocationRecordID uint64
	crcVector          ProducerScatterCRCVector
}

// ProducerScatterCancellationError retains the failed operation and cause
// while remaining discoverable with errors.Is. No partial result or progress
// vector is exposed through this error.
type ProducerScatterCancellationError struct {
	operation string
	cause     error
}

func (err *ProducerScatterCancellationError) Error() string {
	if err == nil {
		return ErrProducerScatterCancellationRequired.Error()
	}
	return fmt.Sprintf("%s during %s: %v",
		ErrProducerScatterCancellationRequired, err.operation, err.cause)
}

func (err *ProducerScatterCancellationError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func (err *ProducerScatterCancellationError) Is(target error) bool {
	return target == ErrProducerScatterCancellationRequired
}

// Operation returns a stable, non-secret description of the failed step.
func (err *ProducerScatterCancellationError) Operation() string {
	if err == nil {
		return ""
	}
	return err.operation
}

// BuildProducerScatterPlan performs a pure exact join between one canonical
// TROWN007 snapshot, one GRANTED allocation record, and one canonical V7
// initial-publication plan. It performs no device, descriptor, Owner, network,
// or runtime I/O.
func BuildProducerScatterPlan(
	ownerState OwnerStateSnapshot,
	allocationRecordID uint64,
	publicationPlan cxlcheckpoint.InitialPublicationV7Plan,
) (ProducerScatterPlan, error) {
	owner := ownerState.Clone()
	if err := owner.Validate(); err != nil {
		return ProducerScatterPlan{}, producerScatterInvalidf("Owner state: %v", err)
	}
	if allocationRecordID == 0 || allocationRecordID > cxlcheckpoint.MaxSignedLong {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"allocation record ID %d is outside 1..%d",
			allocationRecordID, cxlcheckpoint.MaxSignedLong)
	}
	if err := publicationPlan.Validate(); err != nil {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"initial publication plan: %v", err)
	}

	// Rebuild instead of retaining any caller-owned exported nested slice. A
	// concurrent caller mutation is a Go data race and unsupported; mutation
	// after this rebuild cannot affect the detached result.
	canonical, err := cxlcheckpoint.BuildInitialPublicationV7Plan(
		cxlcheckpoint.InitialPublicationV7Input{
			Publication:                  publicationPlan.Publication,
			MMTemplate:                   publicationPlan.MMTemplate,
			VirtualPageMap:               publicationPlan.VirtualPageMap,
			ArtifactManifest:             publicationPlan.ArtifactManifest,
			InitialContentPlacementMapID: publicationPlan.InitialContentPlacementMap.ContentPlacementMapID,
			InitialActivePlacementRootID: publicationPlan.ActiveContentPlacementRoot.RootID,
		})
	if err != nil {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"rebuild initial publication plan: %v", err)
	}

	record, found := producerScatterRecordByID(owner.Records(), allocationRecordID)
	if !found {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"allocation record %d is absent", allocationRecordID)
	}
	if record.State != OwnerAllocationGranted {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"allocation record %d state is %d, want GRANTED",
			allocationRecordID, record.State)
	}
	grantTransaction, ok := checkedAdd(record.ReservationTransactionSequence, 1)
	if record.ReservationTransactionSequence == 0 || !ok ||
		grantTransaction != record.OwnerTransactionSequence {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"GRANTED transaction %d does not immediately follow reservation %d",
			record.OwnerTransactionSequence, record.ReservationTransactionSequence)
	}
	if record.AuthorityEvidence.ProducerCapabilitySHA256 == ([sha256.Size]byte{}) ||
		record.AuthorityEvidence.PublicationAuthoritySHA256 == ([sha256.Size]byte{}) {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"GRANTED record lacks Producer-capability or publication-authority commitment")
	}
	if owner.StorageCompatibilityID != cxlcheckpoint.V7StorageCompatibilityID {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"Owner storage compatibility %q is not the V7 target",
			owner.StorageCompatibilityID)
	}

	publication := canonical.Publication
	allocation := publication.InitialAllocation
	if record.CheckpointID != publication.CheckpointID ||
		record.DedupDomainID != publication.DedupDomainID ||
		record.SharingPolicyID != publication.SharingPolicyID ||
		owner.CurrentOwnerID != allocation.OwnerID ||
		owner.OwnerEpoch != allocation.OwnerEpoch ||
		record.AllocationRecordID != allocation.AllocationRecordID ||
		record.TotalDemandPages != allocation.TotalPages {
		return ProducerScatterPlan{}, producerScatterInvalidf(
			"Owner record and publication allocation identities differ")
	}
	if err := producerScatterCrossCheckObjects(record, canonical); err != nil {
		return ProducerScatterPlan{}, err
	}
	devices, runs, err := producerScatterCrossCheckPlacement(owner, record, allocation)
	if err != nil {
		return ProducerScatterPlan{}, err
	}
	objects, err := producerScatterDetachObjects(canonical)
	if err != nil {
		return ProducerScatterPlan{}, err
	}

	plan := ProducerScatterPlan{
		checkpointID:           record.CheckpointID,
		allocationRecordID:     record.AllocationRecordID,
		clusterID:              owner.ClusterID,
		ownerGroupID:           owner.OwnerGroupID,
		anchorDeviceUUID:       owner.AnchorDeviceUUID,
		ownerID:                owner.CurrentOwnerID,
		ownerEpoch:             owner.OwnerEpoch,
		groupConfiguration:     owner.GroupConfigurationSequence,
		membershipSHA256:       owner.MembershipSHA256,
		reservationTransaction: record.ReservationTransactionSequence,
		grantTransaction:       record.OwnerTransactionSequence,
		grantRecordSHA256:      producerScatterGrantRecordSHA256(record),
		totalPages:             record.TotalDemandPages,
		devices:                append([]ProducerScatterDeviceBinding(nil), devices...),
		objects:                cloneProducerScatterObjectPlans(objects),
		runs:                   append([]ProducerScatterExtentRun(nil), runs...),
	}
	plan.integritySHA256 = producerScatterPlanSHA256(plan)
	if err := plan.Validate(); err != nil {
		return ProducerScatterPlan{}, err
	}
	return plan, nil
}

// Validate checks the detached plan's complete compact shape and integrity
// digest without performing I/O.
func (plan ProducerScatterPlan) Validate() error {
	if plan.checkpointID == "" || plan.clusterID == "" ||
		plan.ownerGroupID == "" || plan.anchorDeviceUUID == "" || plan.ownerID == "" ||
		plan.allocationRecordID == 0 || plan.ownerEpoch == 0 ||
		plan.groupConfiguration == 0 ||
		plan.reservationTransaction == 0 || plan.grantTransaction == 0 ||
		plan.totalPages == 0 {
		return producerScatterInvalidf("plan has a zero required identity or sequence")
	}
	if plan.grantRecordSHA256 == ([sha256.Size]byte{}) {
		return producerScatterInvalidf("plan has a zero canonical GRANTED-record commitment")
	}
	if plan.membershipSHA256 == ([sha256.Size]byte{}) {
		return producerScatterInvalidf("plan has a zero Owner-group membership commitment")
	}
	wantGrant, ok := checkedAdd(plan.reservationTransaction, 1)
	if !ok || plan.grantTransaction != wantGrant {
		return producerScatterInvalidf("grant transaction does not follow reservation")
	}
	if _, err := producerScatterCRCVectorLength(plan.totalPages); err != nil {
		return producerScatterInvalidf("CRC vector: %v", err)
	}
	if len(plan.devices) == 0 || len(plan.devices) > MaxOwnerStateDevices {
		return producerScatterInvalidf("device count %d is outside bounds", len(plan.devices))
	}
	previousUUID := ""
	for index, device := range plan.devices {
		if device.DeviceUUID == "" || device.DeviceOwnerEpoch != plan.ownerEpoch ||
			device.DataPageCount == 0 ||
			device.DeviceBindingSHA256 == ([sha256.Size]byte{}) {
			return producerScatterInvalidf("device %d has an invalid binding", index)
		}
		if index > 0 && previousUUID >= device.DeviceUUID {
			return producerScatterInvalidf("devices are not strictly ordered by UUID")
		}
		previousUUID = device.DeviceUUID
	}
	if len(plan.objects) == 0 || len(plan.objects) > MaxOwnerStateContentDemands {
		return producerScatterInvalidf("object count %d is outside bounds", len(plan.objects))
	}
	expectedLogical := uint64(0)
	previousObjectID := uint64(0)
	for index, object := range plan.objects {
		if object.ObjectID == 0 || (index > 0 && previousObjectID >= object.ObjectID) ||
			object.LogicalPageStart != expectedLogical || object.CapacityPages == 0 {
			return producerScatterInvalidf("object %d has non-canonical identity or coverage", index)
		}
		capacityBytes, multiplyOK := checkedMul(object.CapacityPages, uint64(ContentPageBytes))
		if !multiplyOK || object.ExactByteLength > capacityBytes {
			return producerScatterInvalidf("object %d length exceeds capacity", object.ObjectID)
		}
		switch object.writeSource {
		case producerScatterExternal:
			if len(object.canonicalBytes) != 0 || object.ExactByteLength == 0 {
				return producerScatterInvalidf("external object %d has invalid bytes/length", object.ObjectID)
			}
			if object.Kind != cxlcheckpoint.ContentMemoryPayloadV7 &&
				object.Kind != cxlcheckpoint.ContentArtifactPayloadV7 &&
				object.Kind != cxlcheckpoint.ContentRestoreBlobPayloadV7 {
				return producerScatterInvalidf("external object %d has non-payload kind %d",
					object.ObjectID, object.Kind)
			}
			if object.Kind == cxlcheckpoint.ContentMemoryPayloadV7 &&
				object.ExactByteLength != capacityBytes {
				return producerScatterInvalidf("memory object %d does not fill its capacity", object.ObjectID)
			}
		case producerScatterCanonical:
			if uint64(len(object.canonicalBytes)) != object.ExactByteLength || object.ExactByteLength == 0 {
				return producerScatterInvalidf("canonical object %d has invalid bytes/length", object.ObjectID)
			}
			if object.Kind == cxlcheckpoint.ContentMemoryPayloadV7 ||
				object.Kind == cxlcheckpoint.ContentArtifactPayloadV7 ||
				object.Kind == cxlcheckpoint.ContentRestoreBlobPayloadV7 ||
				object.Kind == cxlcheckpoint.ContentPlacementSlotBV7 {
				return producerScatterInvalidf("canonical object %d has invalid kind %d",
					object.ObjectID, object.Kind)
			}
		case producerScatterZero:
			if len(object.canonicalBytes) != 0 || object.ExactByteLength != 0 {
				return producerScatterInvalidf("zero object %d has meaningful bytes", object.ObjectID)
			}
			if object.Kind != cxlcheckpoint.ContentPlacementSlotBV7 {
				return producerScatterInvalidf("zero object %d is not placement slot B", object.ObjectID)
			}
		default:
			return producerScatterInvalidf("object %d has invalid write source", object.ObjectID)
		}
		next, addOK := checkedAdd(expectedLogical, object.CapacityPages)
		if !addOK {
			return producerScatterInvalidf("object coverage overflows")
		}
		expectedLogical = next
		previousObjectID = object.ObjectID
	}
	if expectedLogical != plan.totalPages {
		return producerScatterInvalidf("objects cover %d pages, want %d", expectedLogical, plan.totalPages)
	}
	if len(plan.runs) == 0 || len(plan.runs) > MaxOwnerStateExtents {
		return producerScatterInvalidf("extent-run count %d is outside bounds", len(plan.runs))
	}
	expectedLogical = 0
	for index, run := range plan.runs {
		if uint64(run.DeviceIndex) >= uint64(len(plan.devices)) || run.PageCount == 0 ||
			run.LogicalPageStart != expectedLogical {
			return producerScatterInvalidf("extent run %d has invalid device or logical coverage", index)
		}
		physicalEnd, physicalOK := checkedAdd(run.StartDataPageIndex, run.PageCount)
		if !physicalOK || physicalEnd > plan.devices[run.DeviceIndex].DataPageCount {
			return producerScatterInvalidf("extent run %d exceeds device capacity", index)
		}
		if index > 0 {
			previous := plan.runs[index-1]
			previousPhysicalEnd, physicalEndOK := checkedAdd(previous.StartDataPageIndex, previous.PageCount)
			previousLogicalEnd, logicalEndOK := checkedAdd(previous.LogicalPageStart, previous.PageCount)
			if physicalEndOK && logicalEndOK && previous.DeviceIndex == run.DeviceIndex &&
				previousPhysicalEnd == run.StartDataPageIndex &&
				previousLogicalEnd == run.LogicalPageStart {
				return producerScatterInvalidf("extent runs %d and %d are coalescible", index-1, index)
			}
		}
		next, addOK := checkedAdd(expectedLogical, run.PageCount)
		if !addOK {
			return producerScatterInvalidf("extent coverage overflows")
		}
		expectedLogical = next
	}
	if expectedLogical != plan.totalPages {
		return producerScatterInvalidf("extents cover %d pages, want %d", expectedLogical, plan.totalPages)
	}
	if plan.integritySHA256 == ([sha256.Size]byte{}) ||
		plan.integritySHA256 != producerScatterPlanSHA256(plan) {
		return producerScatterInvalidf("plan integrity SHA-256 differs")
	}
	return nil
}

func (plan ProducerScatterPlan) CheckpointID() string       { return plan.checkpointID }
func (plan ProducerScatterPlan) AllocationRecordID() uint64 { return plan.allocationRecordID }
func (plan ProducerScatterPlan) ClusterID() string          { return plan.clusterID }
func (plan ProducerScatterPlan) OwnerGroupID() string       { return plan.ownerGroupID }
func (plan ProducerScatterPlan) AnchorDeviceUUID() string   { return plan.anchorDeviceUUID }
func (plan ProducerScatterPlan) OwnerID() string            { return plan.ownerID }
func (plan ProducerScatterPlan) OwnerEpoch() uint64         { return plan.ownerEpoch }
func (plan ProducerScatterPlan) TotalPages() uint64         { return plan.totalPages }

// GrantRecordSHA256 binds the complete canonical durable GRANTED record,
// including request, Producer, authority commitments, demands, fragments, and
// allocator targets, without carrying any raw secret.
func (plan ProducerScatterPlan) GrantRecordSHA256() [sha256.Size]byte {
	return plan.grantRecordSHA256
}

func (plan ProducerScatterPlan) Devices() []ProducerScatterDeviceBinding {
	return append([]ProducerScatterDeviceBinding(nil), plan.devices...)
}

func (plan ProducerScatterPlan) Objects() []ProducerScatterObject {
	result := make([]ProducerScatterObject, len(plan.objects))
	for index := range plan.objects {
		result[index] = plan.objects[index].ProducerScatterObject
	}
	return result
}

func (plan ProducerScatterPlan) ExtentRuns() []ProducerScatterExtentRun {
	return append([]ProducerScatterExtentRun(nil), plan.runs...)
}

func (result ProducerScatterResult) CheckpointID() string       { return result.checkpointID }
func (result ProducerScatterResult) AllocationRecordID() uint64 { return result.allocationRecordID }

func (result ProducerScatterResult) CRCVector() ProducerScatterCRCVector {
	return result.crcVector.Clone()
}

// ExecuteProducerScatter writes every capacity page in canonical object/page
// order, using only the injected Intel-DML Copier, then syncs every affected
// DAX in canonical UUID order. Before the first copy it prepares every device
// and compact extent view and rejects all declared or actual backing overlap.
//
// The authenticated caller must externally serialize exactly one execution for
// this allocation and hold the Producer write capability/fence for the complete
// prepare->copy->sync interval. This function deliberately remains unwired from
// cxld main/runtime/service code until that distributed enforcement exists.
func ExecuteProducerScatter(
	ctx context.Context,
	request ProducerScatterExecutionRequest,
) (ProducerScatterResult, error) {
	if err := request.Plan.Validate(); err != nil {
		return ProducerScatterResult{}, err
	}
	fail := func(operation string, cause error) (ProducerScatterResult, error) {
		if cause == nil {
			cause = errors.New("unspecified Producer scatter failure")
		}
		return ProducerScatterResult{}, &ProducerScatterCancellationError{
			operation: operation,
			cause:     cause,
		}
	}
	if interfaceIsNil(ctx) {
		return fail("validate context", errors.New("nil context"))
	}
	if err := ctx.Err(); err != nil {
		return fail("check context before execution", err)
	}
	if interfaceIsNil(request.Destination) {
		return fail("validate destination", errors.New("nil Producer scatter destination"))
	}
	if interfaceIsNil(request.Copier) {
		return fail("validate page copier", errors.New("nil Producer scatter page copier"))
	}
	sources, sourceRanges, err := prepareProducerScatterSources(request.Plan, request.Sources)
	if err != nil {
		return fail("validate external sources", err)
	}

	for _, binding := range request.Plan.devices {
		if err := ctx.Err(); err != nil {
			return fail("check context before device prepare", err)
		}
		if err := request.Destination.PrepareDevice(binding); err != nil {
			return fail(fmt.Sprintf("prepare device %q", binding.DeviceUUID), err)
		}
	}
	preparedExtents, err := prepareProducerScatterExtents(
		ctx, request.Plan, request.Destination, sourceRanges)
	if err != nil {
		return fail("prepare all writable extents", err)
	}

	vectorLength, err := producerScatterCRCVectorLength(request.Plan.totalPages)
	if err != nil {
		return fail("size CRC vector", err)
	}
	crcBytes := make([]byte, vectorLength)
	var sourcePage [ContentPageBytes]byte
	runIndex := 0
	runOffset := uint64(0)
	logicalPage := uint64(0)

	for _, object := range request.Plan.objects {
		for objectPage := uint64(0); objectPage < object.CapacityPages; objectPage++ {
			if err := ctx.Err(); err != nil {
				return fail("check context before page copy", err)
			}
			for index := range sourcePage {
				sourcePage[index] = 0
			}
			if err := fillProducerScatterSourcePage(
				object, objectPage, sources[object.ObjectID], sourcePage[:]); err != nil {
				return fail(fmt.Sprintf("read object %d page %d", object.ObjectID, objectPage), err)
			}
			if runIndex >= len(request.Plan.runs) {
				return fail("map logical page", errors.New("compact extent cursor exhausted"))
			}
			run := request.Plan.runs[runIndex]
			prepared := preparedExtents[runIndex]
			mappedLogical, addOK := checkedAdd(run.LogicalPageStart, runOffset)
			if !addOK || mappedLogical != logicalPage {
				return fail("map logical page", errors.New("compact extent cursor diverged"))
			}
			byteOffset, multiplyOK := checkedMul(runOffset, uint64(ContentPageBytes))
			byteEnd, addOK := checkedAdd(byteOffset, uint64(ContentPageBytes))
			if !multiplyOK || !addOK || byteEnd > uint64(len(prepared.Bytes)) {
				return fail("map physical extent page", errors.New("prepared extent byte offset overflows"))
			}
			destinationPage := prepared.Bytes[int(byteOffset):int(byteEnd)]

			// From immediately before this call onward, an error may still mean
			// that the destination was partially or fully changed. Every return
			// therefore remains cancellation-required and exposes no CRC vector.
			checksum, err := request.Copier.CopyPage(destinationPage, sourcePage[:])
			if err != nil {
				return fail(fmt.Sprintf("copy logical page %d", logicalPage), err)
			}
			crcOffset, offsetOK := checkedMul(logicalPage, uint64(ProducerScatterCRCBytesPerPage))
			if !offsetOK || crcOffset > uint64(len(crcBytes)-ProducerScatterCRCBytesPerPage) {
				return fail("store CRC32C", errors.New("CRC vector offset overflow"))
			}
			binary.LittleEndian.PutUint32(crcBytes[int(crcOffset):int(crcOffset)+ProducerScatterCRCBytesPerPage], checksum)

			logicalPage++
			runOffset++
			if runOffset == run.PageCount {
				runIndex++
				runOffset = 0
			}
		}
	}
	if logicalPage != request.Plan.totalPages || runIndex != len(request.Plan.runs) || runOffset != 0 {
		return fail("complete page coverage", errors.New("object and extent cursors did not finish together"))
	}

	for _, binding := range request.Plan.devices {
		if err := ctx.Err(); err != nil {
			return fail("check context before device sync", err)
		}
		if err := request.Destination.SyncDevice(binding); err != nil {
			return fail(fmt.Sprintf("sync device %q", binding.DeviceUUID), err)
		}
	}
	if err := ctx.Err(); err != nil {
		return fail("check context after device sync", err)
	}
	vector, err := parseProducerScatterCRCVectorOwned(crcBytes, request.Plan.totalPages)
	if err != nil {
		return fail("finalize CRC vector", err)
	}
	return ProducerScatterResult{
		checkpointID:       request.Plan.checkpointID,
		allocationRecordID: request.Plan.allocationRecordID,
		crcVector:          vector,
	}, nil
}

type preparedProducerScatterSource struct {
	reader  ProducerScatterSourceReaderAt
	backing ProducerScatterBackingRange
}

type preparedProducerScatterExtent struct {
	ProducerScatterWritableExtent
	addressStart uintptr
	addressEnd   uintptr
}

func prepareProducerScatterExtents(
	ctx context.Context,
	plan ProducerScatterPlan,
	destination ProducerScatterDestination,
	sourceRanges []ProducerScatterBackingRange,
) ([]preparedProducerScatterExtent, error) {
	prepared := make([]preparedProducerScatterExtent, 0, len(plan.runs))
	for runIndex, run := range plan.runs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if uint64(run.DeviceIndex) >= uint64(len(plan.devices)) {
			return nil, fmt.Errorf("run %d device index is outside the compact table", runIndex)
		}
		binding := plan.devices[run.DeviceIndex]
		view, err := destination.WritableExtent(
			binding, run.StartDataPageIndex, run.PageCount)
		if err != nil {
			return nil, fmt.Errorf("device %q run %d: %w", binding.DeviceUUID, runIndex, err)
		}
		extentBytes, multiplyOK := checkedMul(run.PageCount, uint64(ContentPageBytes))
		if !multiplyOK || extentBytes > uint64(^uint(0)>>1) {
			return nil, fmt.Errorf("device %q run %d byte length overflows host int",
				binding.DeviceUUID, runIndex)
		}
		if uint64(len(view.Bytes)) != extentBytes {
			return nil, fmt.Errorf("device %q run %d view length %d, want %d",
				binding.DeviceUUID, runIndex, len(view.Bytes), extentBytes)
		}
		if err := validateProducerScatterBackingRange(
			fmt.Sprintf("device %q run %d", binding.DeviceUUID, runIndex),
			view.Backing, extentBytes); err != nil {
			return nil, err
		}
		addressStart, addressEnd, err := producerScatterSliceAddressRange(view.Bytes)
		if err != nil {
			return nil, fmt.Errorf("device %q run %d: %w", binding.DeviceUUID, runIndex, err)
		}
		candidate := preparedProducerScatterExtent{
			ProducerScatterWritableExtent: view,
			addressStart:                  addressStart,
			addressEnd:                    addressEnd,
		}
		for previousIndex, previous := range prepared {
			overlap, rangeErr := producerScatterBackingRangesOverlap(previous.Backing, candidate.Backing)
			if rangeErr != nil {
				return nil, rangeErr
			}
			if overlap || (previous.addressStart < candidate.addressEnd &&
				candidate.addressStart < previous.addressEnd) {
				return nil, fmt.Errorf("writable runs %d and %d alias", previousIndex, runIndex)
			}
		}
		for sourceIndex, sourceRange := range sourceRanges {
			overlap, rangeErr := producerScatterBackingRangesOverlap(sourceRange, candidate.Backing)
			if rangeErr != nil {
				return nil, rangeErr
			}
			if overlap {
				return nil, fmt.Errorf("external source %d aliases writable run %d", sourceIndex, runIndex)
			}
		}
		prepared = append(prepared, candidate)
	}
	return prepared, nil
}

func validateProducerScatterBackingRange(
	name string,
	value ProducerScatterBackingRange,
	exactByteLength uint64,
) error {
	if value.BackingID == ([sha256.Size]byte{}) {
		return fmt.Errorf("%s has a zero backing ID", name)
	}
	if exactByteLength == 0 || value.ByteLength != exactByteLength {
		return fmt.Errorf("%s backing length %d, want exact %d",
			name, value.ByteLength, exactByteLength)
	}
	if _, ok := checkedAdd(value.ByteOffset, value.ByteLength); !ok {
		return fmt.Errorf("%s backing range overflows", name)
	}
	return nil
}

func producerScatterBackingRangesOverlap(
	left ProducerScatterBackingRange,
	right ProducerScatterBackingRange,
) (bool, error) {
	leftEnd, leftOK := checkedAdd(left.ByteOffset, left.ByteLength)
	rightEnd, rightOK := checkedAdd(right.ByteOffset, right.ByteLength)
	if !leftOK || !rightOK {
		return false, errors.New("Producer scatter backing range overflows")
	}
	if left.BackingID != right.BackingID {
		return false, nil
	}
	return left.ByteOffset < rightEnd && right.ByteOffset < leftEnd, nil
}

func producerScatterSliceAddressRange(value []byte) (uintptr, uintptr, error) {
	if len(value) == 0 {
		return 0, 0, errors.New("writable extent view is empty")
	}
	start := uintptr(unsafe.Pointer(&value[0]))
	end := start + uintptr(len(value))
	if end < start {
		return 0, 0, errors.New("writable extent address range overflows")
	}
	runtime.KeepAlive(value)
	return start, end, nil
}

func producerScatterCrossCheckObjects(
	record OwnerStateAllocationRecord,
	plan cxlcheckpoint.InitialPublicationV7Plan,
) error {
	objects := plan.Publication.Objects
	if len(record.ContentDemands) != len(objects) || len(plan.ObjectWrites) != len(objects) {
		return producerScatterInvalidf("Owner demands and publication objects differ in count")
	}
	for index := range objects {
		demand := record.ContentDemands[index]
		object := objects[index]
		write := plan.ObjectWrites[index]
		if demand.Kind != object.Kind || demand.ObjectID != object.ObjectID ||
			demand.ByteLength != object.ImmutableByteLength ||
			demand.CapacityPages != object.CapacityPages ||
			demand.LogicalPageStart != object.LogicalPageStart {
			return producerScatterInvalidf("Owner demand and publication object %d differ", index)
		}
		if write.ObjectID != object.ObjectID || write.Kind != object.Kind ||
			write.LogicalPageStart != object.LogicalPageStart ||
			write.CapacityPages != object.CapacityPages {
			return producerScatterInvalidf("derived object write %d differs from publication object", index)
		}
	}
	return nil
}

type producerScatterRecordExtent struct {
	deviceUUID       string
	deviceOwnerEpoch uint64
	startDataPage    uint64
	logicalPageStart uint64
	pageCount        uint64
}

func producerScatterCrossCheckPlacement(
	owner OwnerStateSnapshot,
	record OwnerStateAllocationRecord,
	allocation cxlcheckpoint.InitialAllocationV7,
) ([]ProducerScatterDeviceBinding, []ProducerScatterExtentRun, error) {
	if len(record.Fragments) != len(allocation.Devices) {
		return nil, nil, producerScatterInvalidf("Owner fragments and publication devices differ in count")
	}
	membership := owner.Devices()
	devices := make([]ProducerScatterDeviceBinding, len(allocation.Devices))
	for index, allocated := range allocation.Devices {
		fragment := record.Fragments[index]
		if fragment.DeviceUUID != allocated.DeviceUUID {
			return nil, nil, producerScatterInvalidf("device %d UUID differs between Owner and publication", index)
		}
		member, found := producerScatterDeviceByUUID(membership, allocated.DeviceUUID)
		if !found || member.DeviceOwnerEpoch != fragment.DeviceOwnerEpoch ||
			member.DeviceOwnerEpoch != allocation.OwnerEpoch ||
			member.DataPageCount != allocated.DataPageCount ||
			member.DeviceBindingSHA256 == ([sha256.Size]byte{}) {
			return nil, nil, producerScatterInvalidf("device %q binding differs", allocated.DeviceUUID)
		}
		devices[index] = ProducerScatterDeviceBinding{
			DeviceUUID:          member.DeviceUUID,
			DeviceOwnerEpoch:    member.DeviceOwnerEpoch,
			DataPageCount:       member.DataPageCount,
			DeviceBindingSHA256: member.DeviceBindingSHA256,
		}
	}

	recordExtents := make([]producerScatterRecordExtent, 0, len(allocation.Extents))
	for _, fragment := range record.Fragments {
		for _, extent := range fragment.Extents {
			recordExtents = append(recordExtents, producerScatterRecordExtent{
				deviceUUID:       fragment.DeviceUUID,
				deviceOwnerEpoch: fragment.DeviceOwnerEpoch,
				startDataPage:    extent.StartDataPageIndex,
				logicalPageStart: extent.LogicalPageStart,
				pageCount:        extent.PageCount,
			})
		}
	}
	producerScatterSortRecordExtents(recordExtents)
	if len(recordExtents) != len(allocation.Extents) {
		return nil, nil, producerScatterInvalidf("Owner and publication extent counts differ")
	}
	runs := make([]ProducerScatterExtentRun, 0, len(allocation.Extents))
	for index, extent := range allocation.Extents {
		if uint64(extent.DeviceIndex) >= uint64(len(devices)) {
			return nil, nil, producerScatterInvalidf("publication extent %d device index is out of range", index)
		}
		recordExtent := recordExtents[index]
		device := devices[extent.DeviceIndex]
		if recordExtent.deviceUUID != device.DeviceUUID ||
			recordExtent.deviceOwnerEpoch != device.DeviceOwnerEpoch ||
			recordExtent.startDataPage != extent.StartDataPageIndex ||
			recordExtent.logicalPageStart != extent.LogicalPageStart ||
			recordExtent.pageCount != extent.PageCount {
			return nil, nil, producerScatterInvalidf("Owner and publication extent %d differ", index)
		}
		candidate := ProducerScatterExtentRun{
			DeviceIndex:        extent.DeviceIndex,
			StartDataPageIndex: extent.StartDataPageIndex,
			LogicalPageStart:   extent.LogicalPageStart,
			PageCount:          extent.PageCount,
		}
		if len(runs) > 0 {
			previous := &runs[len(runs)-1]
			previousPhysicalEnd, physicalOK := checkedAdd(previous.StartDataPageIndex, previous.PageCount)
			previousLogicalEnd, logicalOK := checkedAdd(previous.LogicalPageStart, previous.PageCount)
			if physicalOK && logicalOK && previous.DeviceIndex == candidate.DeviceIndex &&
				previousPhysicalEnd == candidate.StartDataPageIndex &&
				previousLogicalEnd == candidate.LogicalPageStart {
				merged, mergeOK := checkedAdd(previous.PageCount, candidate.PageCount)
				if !mergeOK {
					return nil, nil, producerScatterInvalidf("coalesced extent page count overflows")
				}
				previous.PageCount = merged
				continue
			}
		}
		runs = append(runs, candidate)
	}
	return devices, runs, nil
}

func producerScatterDetachObjects(
	plan cxlcheckpoint.InitialPublicationV7Plan,
) ([]producerScatterObjectPlan, error) {
	objects := make([]producerScatterObjectPlan, len(plan.ObjectWrites))
	for index, write := range plan.ObjectWrites {
		object := producerScatterObjectPlan{
			ProducerScatterObject: ProducerScatterObject{
				ObjectID:         write.ObjectID,
				Kind:             write.Kind,
				LogicalPageStart: write.LogicalPageStart,
				ExactByteLength:  write.ExactByteLength,
				CapacityPages:    write.CapacityPages,
			},
			canonicalBytes: append([]byte(nil), write.CanonicalBytes...),
		}
		switch write.WriteSource {
		case cxlcheckpoint.InitialPublicationV7ExternalPayload:
			object.writeSource = producerScatterExternal
		case cxlcheckpoint.InitialPublicationV7CanonicalControlBytes:
			object.writeSource = producerScatterCanonical
		case cxlcheckpoint.InitialPublicationV7NeverPublishedZeroSlot:
			object.writeSource = producerScatterZero
		default:
			return nil, producerScatterInvalidf("object %d has unknown write source %d", write.ObjectID, write.WriteSource)
		}
		objects[index] = object
	}
	return objects, nil
}

func prepareProducerScatterSources(
	plan ProducerScatterPlan,
	sources []ProducerScatterSource,
) (map[uint64]preparedProducerScatterSource, []ProducerScatterBackingRange, error) {
	externalCount := 0
	objectByID := make(map[uint64]producerScatterObjectPlan, len(plan.objects))
	for _, object := range plan.objects {
		objectByID[object.ObjectID] = object
		if object.writeSource == producerScatterExternal {
			externalCount++
		}
	}
	if len(sources) != externalCount {
		return nil, nil, fmt.Errorf("external source count %d, want %d", len(sources), externalCount)
	}
	result := make(map[uint64]preparedProducerScatterSource, len(sources))
	ranges := make([]ProducerScatterBackingRange, 0, len(sources))
	previousObjectID := uint64(0)
	for index, source := range append([]ProducerScatterSource(nil), sources...) {
		if source.ObjectID == 0 || (index > 0 && previousObjectID >= source.ObjectID) {
			return nil, nil, fmt.Errorf("external sources are duplicate or not strictly ordered at index %d", index)
		}
		object, found := objectByID[source.ObjectID]
		if !found || object.writeSource != producerScatterExternal {
			return nil, nil, fmt.Errorf("object %d does not accept an external source", source.ObjectID)
		}
		if source.ExactByteLength != object.ExactByteLength {
			return nil, nil, fmt.Errorf("object %d source length %d, want %d",
				source.ObjectID, source.ExactByteLength, object.ExactByteLength)
		}
		if interfaceIsNil(source.Reader) {
			return nil, nil, fmt.Errorf("object %d has a nil ReaderAt", source.ObjectID)
		}
		backing := source.Reader.ProducerScatterBackingRange()
		if err := validateProducerScatterBackingRange(
			fmt.Sprintf("external source object %d", source.ObjectID),
			backing, source.ExactByteLength); err != nil {
			return nil, nil, err
		}
		result[source.ObjectID] = preparedProducerScatterSource{
			reader: source.Reader, backing: backing,
		}
		ranges = append(ranges, backing)
		previousObjectID = source.ObjectID
	}
	return result, ranges, nil
}

func fillProducerScatterSourcePage(
	object producerScatterObjectPlan,
	objectPage uint64,
	source preparedProducerScatterSource,
	destination []byte,
) error {
	if len(destination) != ContentPageBytes {
		return fmt.Errorf("source staging page length %d, want %d", len(destination), ContentPageBytes)
	}
	pageByteOffset, ok := checkedMul(objectPage, uint64(ContentPageBytes))
	if !ok {
		return errors.New("object byte offset overflows")
	}
	if pageByteOffset >= object.ExactByteLength {
		return nil
	}
	remaining := object.ExactByteLength - pageByteOffset
	meaningful := uint64(ContentPageBytes)
	if remaining < meaningful {
		meaningful = remaining
	}
	switch object.writeSource {
	case producerScatterExternal:
		if interfaceIsNil(source.reader) {
			return errors.New("external ReaderAt is unavailable")
		}
		if pageByteOffset > cxlcheckpoint.MaxSignedLong {
			return errors.New("ReaderAt offset exceeds signed 64-bit range")
		}
		want := int(meaningful)
		n, err := source.reader.ReadAt(destination[:want], int64(pageByteOffset))
		if n < 0 || n > want {
			return fmt.Errorf("ReaderAt returned invalid count %d for %d bytes", n, want)
		}
		if n != want {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return fmt.Errorf("ReaderAt returned %d of %d bytes: %w", n, want, err)
		}
		if err != nil {
			return fmt.Errorf("ReaderAt returned all %d bytes with error: %w", want, err)
		}
		return nil
	case producerScatterCanonical:
		end, addOK := checkedAdd(pageByteOffset, meaningful)
		if !addOK || end > uint64(len(object.canonicalBytes)) {
			return errors.New("canonical byte range exceeds detached object")
		}
		copy(destination[:int(meaningful)], object.canonicalBytes[int(pageByteOffset):int(end)])
		return nil
	case producerScatterZero:
		return errors.New("zero object unexpectedly has meaningful bytes")
	default:
		return errors.New("unknown object write source")
	}
}

func cloneProducerScatterObjectPlans(source []producerScatterObjectPlan) []producerScatterObjectPlan {
	result := make([]producerScatterObjectPlan, len(source))
	for index := range source {
		result[index] = source[index]
		result[index].canonicalBytes = append([]byte(nil), source[index].canonicalBytes...)
	}
	return result
}

func producerScatterRecordByID(
	records []OwnerStateAllocationRecord,
	allocationRecordID uint64,
) (OwnerStateAllocationRecord, bool) {
	for _, record := range records {
		if record.AllocationRecordID == allocationRecordID {
			return cloneOwnerStateRecord(record), true
		}
	}
	return OwnerStateAllocationRecord{}, false
}

func producerScatterDeviceByUUID(
	devices []OwnerStateDevice,
	deviceUUID string,
) (OwnerStateDevice, bool) {
	for _, device := range devices {
		if device.DeviceUUID == deviceUUID {
			return device, true
		}
	}
	return OwnerStateDevice{}, false
}

func producerScatterSortRecordExtents(extents []producerScatterRecordExtent) {
	for index := 1; index < len(extents); index++ {
		value := extents[index]
		position := index
		for position > 0 && extents[position-1].logicalPageStart > value.logicalPageStart {
			extents[position] = extents[position-1]
			position--
		}
		extents[position] = value
	}
}

func producerScatterGrantRecordSHA256(
	record OwnerStateAllocationRecord,
) [sha256.Size]byte {
	digest := sha256.New()
	producerScatterDigestString(digest, producerScatterGrantRecordDigestDomain)
	producerScatterDigestUint64(digest, record.AllocationRecordID)
	producerScatterDigestUint64(digest, record.ReservationTransactionSequence)
	producerScatterDigestUint64(digest, record.OwnerTransactionSequence)
	_, _ = digest.Write([]byte{byte(record.State)})
	producerScatterDigestString(digest, record.RequestID)
	producerScatterDigestString(digest, record.CheckpointID)
	producerScatterDigestString(digest, record.ProducerID)
	producerScatterDigestString(digest, record.DedupDomainID)
	producerScatterDigestString(digest, record.SharingPolicyID)
	_, _ = digest.Write(record.RequestSHA256[:])
	producerScatterDigestUint64(digest, record.TotalDemandPages)
	producerScatterDigestUint64(digest, uint64(record.MaxExtents))
	_, _ = digest.Write(record.AuthorityEvidence.SchedulerReserveSHA256[:])
	_, _ = digest.Write(record.AuthorityEvidence.ProducerCapabilitySHA256[:])
	_, _ = digest.Write(record.AuthorityEvidence.PublicationAuthoritySHA256[:])
	_, _ = digest.Write(record.AuthorityEvidence.ReclaimAuthoritySHA256[:])
	_, _ = digest.Write(record.OwnerVerifiedSealSHA256[:])
	producerScatterDigestUint64(digest, uint64(len(record.ContentDemands)))
	for _, demand := range record.ContentDemands {
		_, _ = digest.Write([]byte{byte(demand.Kind)})
		producerScatterDigestUint64(digest, demand.ObjectID)
		producerScatterDigestUint64(digest, demand.ByteLength)
		producerScatterDigestUint64(digest, demand.CapacityPages)
		producerScatterDigestUint64(digest, demand.LogicalPageStart)
	}
	producerScatterDigestUint64(digest, uint64(len(record.Fragments)))
	for _, fragment := range record.Fragments {
		producerScatterDigestString(digest, fragment.DeviceUUID)
		producerScatterDigestUint64(digest, fragment.DeviceOwnerEpoch)
		producerScatterDigestUint64(digest, fragment.TargetAllocatorSnapshotSequence)
		producerScatterDigestUint64(digest, uint64(len(fragment.Extents)))
		for _, extent := range fragment.Extents {
			producerScatterDigestUint64(digest, extent.StartDataPageIndex)
			producerScatterDigestUint64(digest, extent.LogicalPageStart)
			producerScatterDigestUint64(digest, extent.PageCount)
		}
	}
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func producerScatterPlanSHA256(plan ProducerScatterPlan) [sha256.Size]byte {
	digest := sha256.New()
	producerScatterDigestString(digest, producerScatterPlanDigestDomain)
	producerScatterDigestString(digest, plan.checkpointID)
	producerScatterDigestUint64(digest, plan.allocationRecordID)
	producerScatterDigestString(digest, plan.clusterID)
	producerScatterDigestString(digest, plan.ownerGroupID)
	producerScatterDigestString(digest, plan.anchorDeviceUUID)
	producerScatterDigestString(digest, plan.ownerID)
	producerScatterDigestUint64(digest, plan.ownerEpoch)
	producerScatterDigestUint64(digest, plan.groupConfiguration)
	_, _ = digest.Write(plan.membershipSHA256[:])
	producerScatterDigestUint64(digest, plan.reservationTransaction)
	producerScatterDigestUint64(digest, plan.grantTransaction)
	_, _ = digest.Write(plan.grantRecordSHA256[:])
	producerScatterDigestUint64(digest, plan.totalPages)
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
		_, _ = digest.Write([]byte{byte(object.Kind), byte(object.writeSource)})
		producerScatterDigestUint64(digest, object.LogicalPageStart)
		producerScatterDigestUint64(digest, object.ExactByteLength)
		producerScatterDigestUint64(digest, object.CapacityPages)
		producerScatterDigestUint64(digest, uint64(len(object.canonicalBytes)))
		_, _ = digest.Write(object.canonicalBytes)
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

func producerScatterDigestString(writer io.Writer, value string) {
	producerScatterDigestUint64(writer, uint64(len(value)))
	_, _ = io.WriteString(writer, value)
}

func producerScatterDigestUint64(writer io.Writer, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func interfaceIsNil(value interface{}) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map,
		reflect.Ptr, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func producerScatterInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidProducerScatterPlan, fmt.Sprintf(format, arguments...))
}
