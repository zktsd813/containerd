package main

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// vnextOwnerService is the strict in-process boundary that a later cxld RPC
// adapter can call. It deliberately owns no compatibility decoder and returns
// no device-local path, file descriptor, allocator pointer, or writer token.
//
// The service mutex serializes one Owner's externally initiated lifecycle
// operations. The durable authority remains the Owner journal and the device
// allocator snapshots; this mutex is not a recovery mechanism.
type vnextOwnerService struct {
	mu sync.Mutex

	group     *vnextOwnerGroup
	directory *vnextLocalDAXDirectory
}

type vnextOwnerServiceErrorCode string

const (
	vnextOwnerServiceInvalidRequest            vnextOwnerServiceErrorCode = "invalid_request"
	vnextOwnerServiceIdentityMismatch          vnextOwnerServiceErrorCode = "identity_mismatch"
	vnextOwnerServiceTransactionNotFound       vnextOwnerServiceErrorCode = "transaction_not_found"
	vnextOwnerServiceTransactionState          vnextOwnerServiceErrorCode = "transaction_state_mismatch"
	vnextOwnerServiceConflict                  vnextOwnerServiceErrorCode = "identity_conflict"
	vnextOwnerServiceNoSpace                   vnextOwnerServiceErrorCode = "content_space_exhausted"
	vnextOwnerServiceAdmissionClosed           vnextOwnerServiceErrorCode = "allocation_admission_closed"
	vnextOwnerServiceAdmissionRequestConflict  vnextOwnerServiceErrorCode = "admission_request_conflict"
	vnextOwnerServiceAdmissionSequenceConflict vnextOwnerServiceErrorCode = "admission_sequence_conflict"
	vnextOwnerServicePublicationIncompatible   vnextOwnerServiceErrorCode = "publication_incompatible"
	vnextOwnerServicePublicationInvalid        vnextOwnerServiceErrorCode = "publication_invalid"
	vnextOwnerServiceSidecarMissing            vnextOwnerServiceErrorCode = "crc_sidecar_missing"
	vnextOwnerServiceSidecarInvalid            vnextOwnerServiceErrorCode = "crc_sidecar_invalid"
	vnextOwnerServicePayloadMismatch           vnextOwnerServiceErrorCode = "payload_crc_mismatch"
	vnextOwnerServiceUnavailable               vnextOwnerServiceErrorCode = "owner_unavailable"
)

// vnextOwnerServiceError is safe for a transport adapter to convert into a
// stable RPC error. Detail contains no write token or local DAX path added by
// this service. Cause remains process-local and is available through errors.Is
// and errors.As for logging and tests.
type vnextOwnerServiceError struct {
	Code      vnextOwnerServiceErrorCode
	Operation string
	Detail    string
	cause     error
}

func (e *vnextOwnerServiceError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail == "" {
		return fmt.Sprintf("VNext Owner %s failed (%s)", e.Operation, e.Code)
	}
	return fmt.Sprintf("VNext Owner %s failed (%s): %s", e.Operation, e.Code, e.Detail)
}

func (e *vnextOwnerServiceError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func vnextOwnerServiceFailure(
	operation string,
	code vnextOwnerServiceErrorCode,
	detail string,
	cause error,
) error {
	return &vnextOwnerServiceError{
		Code:      code,
		Operation: operation,
		Detail:    detail,
		cause:     cause,
	}
}

// vnextOwnerOperationIdentity is the complete durable lookup key accepted by
// seal, commit, and abort. It is an opaque lifecycle handle to callers: none
// of its fields grants device write authority by itself, and no write token is
// echoed from reserve.
type vnextOwnerOperationIdentity struct {
	RequestID          string
	CheckpointID       string
	ProducerID         string
	OwnerID            string
	OwnerEpoch         uint64
	AllocationRecordID uint64
}

// The portable content-kind values intentionally match the strict V6 content
// ABI, while remaining separate from cxld's allocator implementation type.
type vnextOwnerServiceContentKind uint8

const (
	vnextOwnerServiceContentMemory vnextOwnerServiceContentKind = iota + 1
	vnextOwnerServiceContentArtifact
	vnextOwnerServiceContentMMTemplate
	vnextOwnerServiceContentPageMap
	vnextOwnerServiceContentRestoreBlob
	vnextOwnerServiceContentPublication
)

func (kind vnextOwnerServiceContentKind) internal() (vnextContentKind, bool) {
	switch kind {
	case vnextOwnerServiceContentMemory:
		return vnextContentMemory, true
	case vnextOwnerServiceContentArtifact:
		return vnextContentArtifact, true
	case vnextOwnerServiceContentMMTemplate:
		return vnextContentMMTemplate, true
	case vnextOwnerServiceContentPageMap:
		return vnextContentPageMap, true
	case vnextOwnerServiceContentRestoreBlob:
		return vnextContentRestoreBlob, true
	case vnextOwnerServiceContentPublication:
		return vnextContentPublication, true
	default:
		return 0, false
	}
}

func vnextOwnerServiceKindFromInternal(kind vnextContentKind) (vnextOwnerServiceContentKind, bool) {
	switch kind {
	case vnextContentMemory:
		return vnextOwnerServiceContentMemory, true
	case vnextContentArtifact:
		return vnextOwnerServiceContentArtifact, true
	case vnextContentMMTemplate:
		return vnextOwnerServiceContentMMTemplate, true
	case vnextContentPageMap:
		return vnextOwnerServiceContentPageMap, true
	case vnextContentRestoreBlob:
		return vnextOwnerServiceContentRestoreBlob, true
	case vnextContentPublication:
		return vnextOwnerServiceContentPublication, true
	default:
		return 0, false
	}
}

type vnextOwnerReserveContent struct {
	Kind          vnextOwnerServiceContentKind
	ObjectID      uint64
	ByteLength    uint64
	CapacityPages uint64
}

type vnextOwnerReserveRequest struct {
	RequestID    string
	CheckpointID string
	ProducerID   string
	OwnerID      string
	OwnerEpoch   uint64
	Contents     []vnextOwnerReserveContent
	MaxExtents   uint32
}

type vnextOwnerPortableContentSegment struct {
	Kind             vnextOwnerServiceContentKind
	ObjectID         uint64
	ByteLength       uint64
	LogicalPageStart uint64
	PageCount        uint64
}

type vnextOwnerPortableExtent struct {
	DeviceUUID         string
	StartDataPageIndex uint64
	PageCount          uint64
	LogicalPageStart   uint64
}

type vnextOwnerPortableDevice struct {
	DeviceUUID        string
	DataPageCount     uint64
	ContentRegionBase uint64
}

// vnextOwnerReserveResponse is the complete producer-visible placement. The
// device table includes only devices used by this allocation and is sorted by
// stable UUID. Extents are ordered by LogicalPageStart and exactly cover
// TotalPages. ContentRegionBase is portable device geometry, not a host path.
type vnextOwnerReserveResponse struct {
	Operation  vnextOwnerOperationIdentity
	TotalPages uint64
	Contents   []vnextOwnerPortableContentSegment
	Extents    []vnextOwnerPortableExtent
	Devices    []vnextOwnerPortableDevice
}

// vnextOwnerInventoryRequest names the exact Owner incarnation whose live
// capacity the caller expects. RequestID is correlation only; it is echoed
// exactly and is never added to the durable Owner journal.
type vnextOwnerInventoryRequest struct {
	RequestID  string
	OwnerID    string
	OwnerEpoch uint64
}

type vnextOwnerInventoryResponse struct {
	RequestID        string
	OwnerID          string
	OwnerEpoch       uint64
	SnapshotSequence uint64
	Devices          []vnextOwnerInventoryDevice
}

// Admission status is an atomic read of one exact Owner incarnation. RequestID
// is correlation only and is not persisted in the Owner journal.
type vnextOwnerAdmissionStatusRequest struct {
	RequestID  string
	OwnerID    string
	OwnerEpoch uint64
}

type vnextOwnerAdmissionStatusResponse struct {
	RequestID         string
	OwnerID           string
	OwnerEpoch        uint64
	State             vnextOwnerAdmissionState
	AdmissionSequence uint64
	SnapshotSequence  uint64
	HasLastTransition bool
	LastTransition    vnextOwnerAdmissionTransitionRecord
}

// SetAdmission is an idempotent, persist-before-ack transition for one exact
// Owner epoch. The Owner computes RequestDigest from this complete request and
// persists it with the transition proof.
type vnextOwnerSetAdmissionRequest struct {
	RequestID        string
	OwnerID          string
	OwnerEpoch       uint64
	From             vnextOwnerAdmissionState
	Target           vnextOwnerAdmissionState
	ExpectedSequence uint64
}

type vnextOwnerSetAdmissionResponse struct {
	RequestID        string
	RequestDigest    [32]byte
	OwnerID          string
	OwnerEpoch       uint64
	From             vnextOwnerAdmissionState
	Target           vnextOwnerAdmissionState
	ExpectedSequence uint64
	ResultSequence   uint64
	Replayed         bool
}

type vnextOwnerReservationState string

const (
	vnextOwnerReservationNotFound        vnextOwnerReservationState = "NOT_FOUND"
	vnextOwnerReservationPreparing       vnextOwnerReservationState = "PREPARING"
	vnextOwnerReservationGranted         vnextOwnerReservationState = "GRANTED"
	vnextOwnerReservationSealed          vnextOwnerReservationState = "SEALED"
	vnextOwnerReservationCommitted       vnextOwnerReservationState = "COMMITTED"
	vnextOwnerReservationAborted         vnextOwnerReservationState = "ABORTED"
	vnextOwnerReservationRejectedNoSpace vnextOwnerReservationState = "REJECTED_NO_SPACE"
)

func (state vnextOwnerReservationState) valid() bool {
	switch state {
	case vnextOwnerReservationNotFound,
		vnextOwnerReservationPreparing,
		vnextOwnerReservationGranted,
		vnextOwnerReservationSealed,
		vnextOwnerReservationCommitted,
		vnextOwnerReservationAborted,
		vnextOwnerReservationRejectedNoSpace:
		return true
	default:
		return false
	}
}

// vnextOwnerReservationStatusResponse is a read-only recovery observation.
// Identity always echoes the complete original Reserve identity. Its
// AllocationRecordID is zero only for NOT_FOUND. Grant is present only when
// the complete immutable placement is safe to replay.
type vnextOwnerReservationStatusResponse struct {
	State             vnextOwnerReservationState
	AdmissionState    vnextOwnerAdmissionState
	AdmissionSequence uint64
	Identity          vnextOwnerOperationIdentity
	Grant             *vnextOwnerReserveResponse
}

// vnextOwnerExternalSealRequest is the complete producer seal request. The
// TRCRC006 map remains the memory-page evidence. ExternalContentPageCRCs must
// cover every other producer-written page in the durable grant exactly once;
// it cannot name the Owner-written publication slot.
type vnextOwnerExternalSealRequest struct {
	Operation               vnextOwnerOperationIdentity
	PublicationEnvelope     []byte
	CRCPageSidecars         map[uint32][]byte
	ExternalContentPageCRCs []vnextExternalContentPageCRC
}

type vnextOwnerPublicationPageRun struct {
	FirstPage cxlcheckpoint.PageID
	PageCount uint64
}

// vnextOwnerCheckpointRootLocator addresses only the exact canonical
// TRPUB006 bytes. PageRuns cover ceil(PublicationByteLength/4096), never the
// complete pre-reserved publication-slot capacity.
type vnextOwnerCheckpointRootLocator struct {
	PublicationByteLength uint64
	PublicationSHA256     [32]byte
	PageRuns              []vnextOwnerPublicationPageRun
}

// vnextOwnerCheckpointRoot is the complete candidate root returned by seal.
// Seal does not make this root Scheduler-visible: commit must succeed first,
// after which the Scheduler may transition the checkpoint to AVAILABLE.
type vnextOwnerCheckpointRoot struct {
	RootID            string
	RootVersion       uint64
	MMTemplateID      string
	PageMapID         string
	PageMapVersion    uint64
	DeviceTableDigest [32]byte
	ContractID        string
	Locator           vnextOwnerCheckpointRootLocator
}

type vnextOwnerSealResponse struct {
	Root vnextOwnerCheckpointRoot
}

func newVNextOwnerService(
	group *vnextOwnerGroup,
	directory *vnextLocalDAXDirectory,
) (*vnextOwnerService, error) {
	const operation = "initialize"
	if group == nil || directory == nil || len(directory.byUUID) == 0 {
		return nil, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceInvalidRequest,
			"Owner group and local DAX directory are required",
			nil)
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return nil, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not usable", err)
	}
	for _, deviceUUID := range group.deviceOrder {
		device := group.devices[deviceUUID]
		binding, exists := directory.byUUID[deviceUUID]
		if device == nil || !exists {
			return nil, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceInvalidRequest,
				fmt.Sprintf("local DAX binding for Owner device %q is missing", deviceUUID),
				nil)
		}
		if binding.OwnerID != group.ownerID ||
			binding.OwnerEpoch != group.ownerEpoch ||
			binding.DataPageCount != device.superblock.Geometry.DataPageCount ||
			binding.ContentRegionBase != device.superblock.Geometry.ContentRegionBase {
			return nil, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceIdentityMismatch,
				fmt.Sprintf("local DAX binding %q does not match Owner geometry", deviceUUID),
				errVNextAuthority)
		}
	}
	return &vnextOwnerService{group: group, directory: directory}, nil
}

// inventory is read-only. It intentionally does not take service.mu: the
// Owner group lock is the authority boundary and produces one atomic snapshot
// without making a long-running seal operation hold an unrelated service-wide
// queue. The read never persists or advances SnapshotSequence.
func (service *vnextOwnerService) inventory(
	request vnextOwnerInventoryRequest,
) (vnextOwnerInventoryResponse, error) {
	const operation = "inventory"
	if service == nil || service.group == nil {
		return vnextOwnerInventoryResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceUnavailable,
			"Owner group is not configured",
			nil)
	}
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes ||
		request.OwnerID == "" || len(request.OwnerID) > vnextMaxIdentityBytes ||
		request.OwnerEpoch == 0 || request.OwnerEpoch > uint64(math.MaxInt64) {
		return vnextOwnerInventoryResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceInvalidRequest,
			"inventory request identity is incomplete or outside the signed ABI",
			nil)
	}

	snapshot, err := service.group.inventory(request.OwnerID, request.OwnerEpoch)
	if err != nil {
		if errors.Is(err, errVNextAuthority) {
			return vnextOwnerInventoryResponse{}, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceIdentityMismatch,
				"requested Owner identity is not the live Owner incarnation",
				err)
		}
		return vnextOwnerInventoryResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceUnavailable,
			"Owner inventory is not available",
			err)
	}
	return vnextOwnerInventoryResponse{
		RequestID:        request.RequestID,
		OwnerID:          snapshot.OwnerID,
		OwnerEpoch:       snapshot.OwnerEpoch,
		SnapshotSequence: snapshot.SnapshotSequence,
		Devices:          append([]vnextOwnerInventoryDevice(nil), snapshot.Devices...),
	}, nil
}

func (service *vnextOwnerService) admissionStatus(
	request vnextOwnerAdmissionStatusRequest,
) (vnextOwnerAdmissionStatusResponse, error) {
	const operation = "admission-status"
	if service == nil || service.group == nil {
		return vnextOwnerAdmissionStatusResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not configured", nil)
	}
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes ||
		request.OwnerID == "" || len(request.OwnerID) > vnextMaxIdentityBytes ||
		request.OwnerEpoch == 0 || request.OwnerEpoch > uint64(math.MaxInt64) {
		return vnextOwnerAdmissionStatusResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceInvalidRequest,
			"admission status identity is incomplete or outside the signed ABI",
			nil)
	}
	snapshot, err := service.group.admissionStatus(request.OwnerID, request.OwnerEpoch)
	if err != nil {
		if errors.Is(err, errVNextAuthority) {
			return vnextOwnerAdmissionStatusResponse{}, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceIdentityMismatch,
				"requested Owner identity is not the live Owner incarnation",
				err)
		}
		return vnextOwnerAdmissionStatusResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner admission status is unavailable", err)
	}
	return vnextOwnerAdmissionStatusResponse{
		RequestID:         request.RequestID,
		OwnerID:           snapshot.OwnerID,
		OwnerEpoch:        snapshot.OwnerEpoch,
		State:             snapshot.State,
		AdmissionSequence: snapshot.AdmissionSequence,
		SnapshotSequence:  snapshot.SnapshotSequence,
		HasLastTransition: snapshot.HasLastTransition,
		LastTransition:    snapshot.LastTransition,
	}, nil
}

func (service *vnextOwnerService) setAdmission(
	request vnextOwnerSetAdmissionRequest,
) (vnextOwnerSetAdmissionResponse, error) {
	const operation = "set-admission"
	if service == nil || service.group == nil {
		return vnextOwnerSetAdmissionResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not configured", nil)
	}
	internal := vnextOwnerAdmissionTransitionRequest{
		RequestID:        request.RequestID,
		OwnerID:          request.OwnerID,
		OwnerEpoch:       request.OwnerEpoch,
		From:             request.From,
		Target:           request.Target,
		ExpectedSequence: request.ExpectedSequence,
	}
	if err := validateVNextOwnerAdmissionTransitionRequest(internal); err != nil {
		return vnextOwnerSetAdmissionResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceInvalidRequest, err.Error(), err)
	}
	result, err := service.group.setAdmission(internal)
	if err != nil {
		return vnextOwnerSetAdmissionResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	record := result.Record
	return vnextOwnerSetAdmissionResponse{
		RequestID:        record.RequestID,
		RequestDigest:    record.RequestDigest,
		OwnerID:          request.OwnerID,
		OwnerEpoch:       request.OwnerEpoch,
		From:             record.From,
		Target:           record.Target,
		ExpectedSequence: record.ExpectedSequence,
		ResultSequence:   record.ResultSequence,
		Replayed:         result.Replayed,
	}, nil
}

// reservationStatus does not take service.mu because group.mu is the atomic
// Owner authority boundary. It never persists a journal or allocator
// snapshot, advances a sequence, repairs a descriptor, or allocates a page.
func (service *vnextOwnerService) reservationStatus(
	request vnextOwnerReserveRequest,
) (vnextOwnerReservationStatusResponse, error) {
	const operation = "reservation-status"
	if service == nil || service.group == nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not configured", nil)
	}
	internal, err := request.internal()
	if err != nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceInvalidRequest, err.Error(), err)
	}

	group := service.group
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not usable", err)
	}
	_, _, digest, err := group.validateOwnerRequestLocked(internal)
	if err != nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	identity := vnextOwnerOperationIdentity{
		RequestID:    request.RequestID,
		CheckpointID: request.CheckpointID,
		ProducerID:   request.ProducerID,
		OwnerID:      request.OwnerID,
		OwnerEpoch:   request.OwnerEpoch,
	}
	admission := group.admissionSnapshotLocked()
	if err := validateVNextOwnerAdmissionHeadPair(
		admission.State, admission.AdmissionSequence); err != nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceUnavailable,
			"Owner admission evidence is not canonical",
			err)
	}
	response := vnextOwnerReservationStatusResponse{
		AdmissionState:    admission.State,
		AdmissionSequence: admission.AdmissionSequence,
		Identity:          identity,
	}
	allocationRecordID, found := group.journal.RequestIndex[request.RequestID]
	if !found {
		if conflictingID, conflict := group.journal.CheckpointIndex[request.CheckpointID]; conflict {
			return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceConflict,
				fmt.Sprintf("checkpoint identity belongs to allocation %d", conflictingID),
				errVNextAlreadyExists)
		}
		response.State = vnextOwnerReservationNotFound
		return response, nil
	}
	transaction := group.journal.Transactions[allocationRecordID]
	if transaction == nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceUnavailable,
			"Owner request index references a missing transaction",
			errVNextCorrupt)
	}
	if transaction.RequestDigest != digest ||
		transaction.RequestID != request.RequestID ||
		transaction.CheckpointID != request.CheckpointID ||
		transaction.ProducerID != request.ProducerID {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceConflict,
			"Reserve identity or ordered allocation request does not match the durable transaction",
			errVNextAlreadyExists)
	}
	identity.AllocationRecordID = transaction.AllocationRecordID
	response.Identity = identity
	switch transaction.State {
	case vnextOwnerPreparing:
		response.State = vnextOwnerReservationPreparing
		return response, nil
	case vnextOwnerAborted:
		// ABORTED is persisted only after every prepared fragment has cleared
		// descriptors, freed its bitmap pages, and persisted the allocator.
		// Startup recovery replays ABORTING before this state is observable.
		response.State = vnextOwnerReservationAborted
		return response, nil
	case vnextOwnerRejectedNoSpace:
		response.State = vnextOwnerReservationRejectedNoSpace
		return response, nil
	case vnextOwnerGranted:
		sealed := true
		for _, fragment := range transaction.Fragments {
			fragmentSealed, err := group.devices[fragment.DeviceUUID].ownerFragmentSealStatus(
				transaction.CheckpointID, transaction.AllocationRecordID)
			if err != nil {
				return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
					operation,
					vnextOwnerServiceUnavailable,
					"durable fragment seal status is unavailable",
					err)
			}
			sealed = sealed && fragmentSealed
		}
		response.State = vnextOwnerReservationGranted
		if sealed {
			response.State = vnextOwnerReservationSealed
		}
	case vnextOwnerCommitted:
		response.State = vnextOwnerReservationCommitted
	default:
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceTransactionState,
			fmt.Sprintf("durable transaction state %d is not a status-safe Reserve outcome", transaction.State),
			errVNextInvalidState)
	}

	grant := group.buildGrantGeometryLocked(transaction)
	portable, err := service.reserveResponse(internal, grant)
	if err != nil {
		return vnextOwnerReservationStatusResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceUnavailable,
			"durable placement cannot be represented",
			err)
	}
	response.Grant = &portable
	return response, nil
}

func (service *vnextOwnerService) reserve(
	request vnextOwnerReserveRequest,
) (vnextOwnerReserveResponse, error) {
	const operation = "reserve"
	service.mu.Lock()
	defer service.mu.Unlock()

	internal, err := request.internal()
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceInvalidRequest, err.Error(), err)
	}
	grant, err := service.group.reserve(internal)
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	response, err := service.reserveResponse(internal, grant)
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "reserved placement cannot be represented", err)
	}
	return response, nil
}

func (request vnextOwnerReserveRequest) internal() (vnextCheckpointAllocationRequest, error) {
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes ||
		request.CheckpointID == "" || len(request.CheckpointID) > vnextMaxIdentityBytes ||
		request.ProducerID == "" || len(request.ProducerID) > vnextMaxIdentityBytes ||
		request.OwnerID == "" || len(request.OwnerID) > vnextMaxIdentityBytes {
		return vnextCheckpointAllocationRequest{}, errors.New("reserve identity is empty or too long")
	}
	if request.OwnerEpoch == 0 || request.OwnerEpoch > uint64(math.MaxInt64) {
		return vnextCheckpointAllocationRequest{}, errors.New("Owner epoch is outside the signed ABI")
	}
	if request.MaxExtents == 0 || request.MaxExtents > vnextMaxExtentsPerRecord {
		return vnextCheckpointAllocationRequest{}, fmt.Errorf(
			"extent limit %d is outside 1..%d", request.MaxExtents, vnextMaxExtentsPerRecord)
	}
	if len(request.Contents) == 0 || len(request.Contents) > vnextMaxContentsPerRecord {
		return vnextCheckpointAllocationRequest{}, fmt.Errorf(
			"content count %d is outside 1..%d", len(request.Contents), vnextMaxContentsPerRecord)
	}
	contents := make([]vnextContentRequest, len(request.Contents))
	objects := make(map[uint64]struct{}, len(request.Contents))
	var totalPages uint64
	publicationSlots := 0
	for index, portable := range request.Contents {
		kind, ok := portable.Kind.internal()
		if !ok {
			return vnextCheckpointAllocationRequest{}, fmt.Errorf(
				"content %d has unknown kind %d", index, portable.Kind)
		}
		if portable.ObjectID == 0 || portable.CapacityPages == 0 {
			return vnextCheckpointAllocationRequest{}, fmt.Errorf(
				"content %d has a zero object ID or capacity", index)
		}
		if _, duplicate := objects[portable.ObjectID]; duplicate {
			return vnextCheckpointAllocationRequest{}, fmt.Errorf(
				"content object ID %d is duplicated", portable.ObjectID)
		}
		objects[portable.ObjectID] = struct{}{}
		capacity, ok := vnextMul(portable.CapacityPages, vnextContentPageSize)
		if !ok || portable.ByteLength > capacity {
			return vnextCheckpointAllocationRequest{}, fmt.Errorf(
				"content %d byte length exceeds reserved capacity", portable.ObjectID)
		}
		if kind == vnextContentMemory && portable.ByteLength != capacity {
			return vnextCheckpointAllocationRequest{}, fmt.Errorf(
				"memory content %d does not fill its reserved pages", portable.ObjectID)
		}
		if kind == vnextContentPublication && portable.ByteLength != capacity {
			return vnextCheckpointAllocationRequest{}, fmt.Errorf(
				"publication content %d is not a page-aligned slot", portable.ObjectID)
		}
		if kind == vnextContentPublication {
			publicationSlots++
			if portable.CapacityPages > cxlcheckpoint.MaxPublicationSlotPages {
				return vnextCheckpointAllocationRequest{}, fmt.Errorf(
					"publication content %d reserves %d pages, maximum is %d",
					portable.ObjectID,
					portable.CapacityPages,
					cxlcheckpoint.MaxPublicationSlotPages)
			}
		}
		totalPages, ok = vnextAdd(totalPages, portable.CapacityPages)
		if !ok || totalPages > uint64(math.MaxInt64) {
			return vnextCheckpointAllocationRequest{}, errors.New(
				"checkpoint page count exceeds the signed ABI")
		}
		contents[index] = vnextContentRequest{
			Kind:       kind,
			ObjectID:   portable.ObjectID,
			ByteLength: portable.ByteLength,
			PageCount:  portable.CapacityPages,
		}
	}
	if publicationSlots != 1 {
		return vnextCheckpointAllocationRequest{}, fmt.Errorf(
			"reserve request must contain exactly one publication slot, found %d",
			publicationSlots)
	}
	return vnextCheckpointAllocationRequest{
		RequestID:    request.RequestID,
		CheckpointID: request.CheckpointID,
		ProducerID:   request.ProducerID,
		OwnerID:      request.OwnerID,
		OwnerEpoch:   request.OwnerEpoch,
		Contents:     contents,
		MaxExtents:   request.MaxExtents,
	}, nil
}

func (service *vnextOwnerService) reserveResponse(
	request vnextCheckpointAllocationRequest,
	grant vnextOwnerWriteGrant,
) (vnextOwnerReserveResponse, error) {
	response := vnextOwnerReserveResponse{
		Operation: vnextOwnerOperationIdentity{
			RequestID:          grant.RequestID,
			CheckpointID:       grant.CheckpointID,
			ProducerID:         grant.ProducerID,
			OwnerID:            grant.OwnerID,
			OwnerEpoch:         grant.OwnerEpoch,
			AllocationRecordID: grant.AllocationRecordID,
		},
		Contents: make([]vnextOwnerPortableContentSegment, len(request.Contents)),
		Extents:  make([]vnextOwnerPortableExtent, len(grant.Extents)),
	}
	var logicalPage uint64
	for index, content := range request.Contents {
		kind, ok := vnextOwnerServiceKindFromInternal(content.Kind)
		if !ok {
			return vnextOwnerReserveResponse{}, fmt.Errorf("unknown internal content kind %d", content.Kind)
		}
		response.Contents[index] = vnextOwnerPortableContentSegment{
			Kind:             kind,
			ObjectID:         content.ObjectID,
			ByteLength:       content.ByteLength,
			LogicalPageStart: logicalPage,
			PageCount:        content.PageCount,
		}
		logicalPage, ok = vnextAdd(logicalPage, content.PageCount)
		if !ok {
			return vnextOwnerReserveResponse{}, errors.New("logical content coverage overflows")
		}
	}
	response.TotalPages = logicalPage

	usedDevices := make(map[string]struct{})
	var extentLogical uint64
	for index, extent := range grant.Extents {
		if extent.GlobalLogicalStart != extentLogical || extent.PageCount == 0 {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"grant extent %d is not in logical order", index)
		}
		response.Extents[index] = vnextOwnerPortableExtent{
			DeviceUUID:         extent.DeviceUUID,
			StartDataPageIndex: extent.StartDataPageIndex,
			PageCount:          extent.PageCount,
			LogicalPageStart:   extent.GlobalLogicalStart,
		}
		var ok bool
		extentLogical, ok = vnextAdd(extentLogical, extent.PageCount)
		if !ok {
			return vnextOwnerReserveResponse{}, errors.New("extent logical coverage overflows")
		}
		usedDevices[extent.DeviceUUID] = struct{}{}
	}
	if extentLogical != response.TotalPages {
		return vnextOwnerReserveResponse{}, fmt.Errorf(
			"grant covers %d pages, content segmentation covers %d",
			extentLogical, response.TotalPages)
	}

	deviceUUIDs := make([]string, 0, len(usedDevices))
	for deviceUUID := range usedDevices {
		deviceUUIDs = append(deviceUUIDs, deviceUUID)
	}
	sort.Strings(deviceUUIDs)
	response.Devices = make([]vnextOwnerPortableDevice, 0, len(deviceUUIDs))
	for _, deviceUUID := range deviceUUIDs {
		device := service.group.devices[deviceUUID]
		if device == nil {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"grant references detached device %q", deviceUUID)
		}
		response.Devices = append(response.Devices, vnextOwnerPortableDevice{
			DeviceUUID:        deviceUUID,
			DataPageCount:     device.superblock.Geometry.DataPageCount,
			ContentRegionBase: device.superblock.Geometry.ContentRegionBase,
		})
	}
	return response, nil
}

// sealExternal is the fail-closed VNext boundary for a complete externally
// produced checkpoint. Exact non-memory coverage is mandatory even when the
// record slice is empty; there is no service-level memory-only fallback.
func (service *vnextOwnerService) sealExternal(
	request vnextOwnerExternalSealRequest,
) (vnextOwnerSealResponse, error) {
	const operation = "seal"
	service.mu.Lock()
	defer service.mu.Unlock()

	grant, _, err := service.resolveOperation(
		operation, request.Operation, vnextOwnerGranted, true)
	if err != nil {
		return vnextOwnerSealResponse{}, err
	}
	if len(request.PublicationEnvelope) >= len(cxlcheckpoint.MagicString) &&
		string(request.PublicationEnvelope[:len(cxlcheckpoint.MagicString)]) != cxlcheckpoint.MagicString {
		return vnextOwnerSealResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServicePublicationIncompatible,
			"publication is not a strict TRPUB006 envelope",
			cxlcheckpoint.ErrWrongFormat)
	}
	publication, err := cxlcheckpoint.Decode(request.PublicationEnvelope)
	if err != nil {
		if errors.Is(err, cxlcheckpoint.ErrWrongFormat) {
			return vnextOwnerSealResponse{}, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServicePublicationIncompatible,
				"publication is not a strict TRPUB006 envelope",
				err)
		}
		return vnextOwnerSealResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServicePublicationInvalid,
			"TRPUB006 envelope failed integrity or semantic validation",
			err)
	}
	storage, err := cxlcheckpoint.EncodeForStorage(publication)
	if err != nil {
		return vnextOwnerSealResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	if !bytes.Equal(storage.ExactBytes, request.PublicationEnvelope) {
		return vnextOwnerSealResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServicePublicationInvalid,
			"TRPUB006 envelope is not the canonical deterministic encoding",
			cxlcheckpoint.ErrInvalid)
	}
	if publication.CheckpointID != request.Operation.CheckpointID ||
		publication.Root.CheckpointID != request.Operation.CheckpointID ||
		publication.Allocation.OwnerID != request.Operation.OwnerID ||
		publication.Allocation.OwnerEpoch != request.Operation.OwnerEpoch ||
		publication.Allocation.AllocationRecordID != request.Operation.AllocationRecordID {
		return vnextOwnerSealResponse{}, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceIdentityMismatch,
			"publication does not name the reserved checkpoint allocation",
			errVNextAuthority)
	}
	if err := vnextOwnerServiceRequireSidecars(publication, request.CRCPageSidecars); err != nil {
		return vnextOwnerSealResponse{}, err
	}
	if err := service.group.sealExternalCheckpointContent(
		grant,
		publication,
		service.directory,
		request.CRCPageSidecars,
		request.ExternalContentPageCRCs); err != nil {
		return vnextOwnerSealResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	for page := uint64(0); page < storage.CapacityPages; page++ {
		byteStart := page * cxlcheckpoint.PageSize
		byteEnd := byteStart + cxlcheckpoint.PageSize
		if err := service.group.writePage(
			grant,
			storage.LogicalPageStart+page,
			storage.PaddedBytes[int(byteStart):int(byteEnd)]); err != nil {
			return vnextOwnerSealResponse{}, vnextOwnerServiceWrap(operation, err)
		}
	}
	response := vnextOwnerSealResponse{
		Root: vnextOwnerCheckpointRoot{
			RootID:            publication.Root.RootID,
			RootVersion:       publication.Root.PublicationSequence,
			MMTemplateID:      publication.Root.MMTemplateID,
			PageMapID:         publication.Root.PageMapID,
			PageMapVersion:    publication.Root.PageMapVersion,
			DeviceTableDigest: publication.Root.DeviceTableDigest,
			ContractID:        cxlcheckpoint.V6CompatibilityID,
			Locator: vnextOwnerCheckpointRootLocator{
				PublicationByteLength: uint64(len(storage.ExactBytes)),
				PublicationSHA256:     storage.SHA256,
				PageRuns:              make([]vnextOwnerPublicationPageRun, len(storage.PageRuns)),
			},
		},
	}
	for index, run := range storage.PageRuns {
		response.Root.Locator.PageRuns[index] = vnextOwnerPublicationPageRun{
			FirstPage: run.FirstPage,
			PageCount: run.PageCount,
		}
	}
	return response, nil
}

func vnextOwnerServiceRequireSidecars(
	publication cxlcheckpoint.Publication,
	sidecars map[uint32][]byte,
) error {
	const operation = "seal"
	expected := make(map[uint32]struct{})
	for _, run := range publication.PageMap.Runs {
		expected[run.PagesImageID] = struct{}{}
	}
	for pagesImageID := range expected {
		data, exists := sidecars[pagesImageID]
		if !exists || len(data) == 0 {
			return vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceSidecarMissing,
				fmt.Sprintf("TRCRC006 sidecar for pages image %d is missing", pagesImageID),
				errVNextCRCSidecar)
		}
	}
	if len(sidecars) != len(expected) {
		return vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceSidecarInvalid,
			"TRCRC006 sidecar set contains an unexpected pages image",
			errVNextCRCSidecar)
	}
	return nil
}

func (service *vnextOwnerService) commit(identity vnextOwnerOperationIdentity) error {
	const operation = "commit"
	service.mu.Lock()
	defer service.mu.Unlock()

	grant, _, err := service.resolveOperation(
		operation, identity, vnextOwnerGranted, true, vnextOwnerCommitted)
	if err != nil {
		return err
	}
	if err := service.group.commit(grant); err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}
	return nil
}

func (service *vnextOwnerService) abort(identity vnextOwnerOperationIdentity) error {
	const operation = "abort"
	service.mu.Lock()
	defer service.mu.Unlock()

	grant, _, err := service.resolveOperation(
		operation, identity, vnextOwnerGranted, true, vnextOwnerAborted)
	if err != nil {
		return err
	}
	if err := service.group.abort(grant); err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}
	return nil
}

func (service *vnextOwnerService) resolveOperation(
	operation string,
	identity vnextOwnerOperationIdentity,
	requiredState vnextOwnerTransactionState,
	reconstructFragmentAuthority bool,
	alsoAllowed ...vnextOwnerTransactionState,
) (vnextOwnerWriteGrant, vnextOwnerTransactionState, error) {
	if identity.RequestID == "" || len(identity.RequestID) > vnextMaxIdentityBytes ||
		identity.CheckpointID == "" || len(identity.CheckpointID) > vnextMaxIdentityBytes ||
		identity.ProducerID == "" || len(identity.ProducerID) > vnextMaxIdentityBytes ||
		identity.OwnerID == "" || len(identity.OwnerID) > vnextMaxIdentityBytes ||
		identity.OwnerEpoch == 0 || identity.OwnerEpoch > uint64(math.MaxInt64) ||
		identity.AllocationRecordID == 0 || identity.AllocationRecordID > uint64(math.MaxInt64) {
		return vnextOwnerWriteGrant{}, 0, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceInvalidRequest,
			"operation identity is incomplete",
			nil)
	}

	group := service.group
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerWriteGrant{}, 0, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not usable", err)
	}
	transaction := group.journal.Transactions[identity.AllocationRecordID]
	if transaction == nil {
		return vnextOwnerWriteGrant{}, 0, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceTransactionNotFound,
			"allocation record does not exist",
			nil)
	}
	if identity.RequestID != transaction.RequestID ||
		identity.CheckpointID != transaction.CheckpointID ||
		identity.ProducerID != transaction.ProducerID ||
		identity.OwnerID != group.ownerID ||
		identity.OwnerEpoch != group.ownerEpoch {
		return vnextOwnerWriteGrant{}, 0, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceIdentityMismatch,
			"operation identity does not match the durable Owner transaction",
			errVNextAuthority)
	}
	allowed := transaction.State == requiredState
	for _, state := range alsoAllowed {
		allowed = allowed || transaction.State == state
	}
	if !allowed {
		return vnextOwnerWriteGrant{}, transaction.State, vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceTransactionState,
			fmt.Sprintf("durable transaction is in state %d", transaction.State),
			errVNextInvalidState)
	}
	if transaction.State == requiredState &&
		(operation == "seal" || operation == "commit") {
		if err := group.requireProducerMutationAllowedLocked(operation); err != nil {
			return vnextOwnerWriteGrant{}, transaction.State, vnextOwnerServiceWrap(operation, err)
		}
	}
	if operation == "abort" && transaction.State == requiredState {
		if err := group.requireReclaimSafetyLocked(operation); err != nil {
			return vnextOwnerWriteGrant{}, transaction.State, vnextOwnerServiceWrap(operation, err)
		}
	}
	grant := vnextOwnerWriteGrant{
		AllocationRecordID: transaction.AllocationRecordID,
		RequestID:          transaction.RequestID,
		CheckpointID:       transaction.CheckpointID,
		ProducerID:         transaction.ProducerID,
		OwnerID:            group.ownerID,
		OwnerEpoch:         group.ownerEpoch,
	}
	// A live GRANTED transaction always reconstructs its private per-device
	// writer grants from durable allocator records, even for commit and abort.
	// Terminal idempotent retries cannot and need not reconstruct cleared write
	// tokens; group.commit/group.abort authenticate their full identity before
	// returning success for COMMITTED/ABORTED.
	if reconstructFragmentAuthority && transaction.State == requiredState {
		var err error
		grant, err = group.buildGrantLocked(transaction)
		if err != nil {
			return vnextOwnerWriteGrant{}, transaction.State, vnextOwnerServiceFailure(
				operation,
				vnextOwnerServiceUnavailable,
				"durable device authority cannot be reconstructed",
				err)
		}
	}
	return grant, transaction.State, nil
}

func vnextOwnerServiceWrap(operation string, err error) error {
	if err == nil {
		return nil
	}
	var typed *vnextOwnerServiceError
	if errors.As(err, &typed) {
		return err
	}
	var admissionClosed *vnextOwnerAdmissionClosedError
	if errors.As(err, &admissionClosed) {
		return vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceAdmissionClosed,
			fmt.Sprintf("admission state=%s sequence=%d", admissionClosed.State, admissionClosed.Sequence),
			err)
	}
	var requestConflict *vnextOwnerAdmissionRequestConflictError
	if errors.As(err, &requestConflict) {
		return vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceAdmissionRequestConflict,
			fmt.Sprintf("admission requestId=%q conflicts with its durable digest",
				requestConflict.RequestID),
			err)
	}
	var sequenceConflict *vnextOwnerAdmissionSequenceConflictError
	if errors.As(err, &sequenceConflict) {
		return vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceAdmissionSequenceConflict,
			fmt.Sprintf(
				"admission state=%s sequence=%d, expected state=%s sequence=%d",
				sequenceConflict.CurrentState,
				sequenceConflict.CurrentSequence,
				sequenceConflict.RequestedFrom,
				sequenceConflict.ExpectedSequence),
			err)
	}
	switch {
	case errors.Is(err, errVNextAuthority):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceIdentityMismatch, "Owner authority does not match", err)
	case errors.Is(err, errVNextInvalidState):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceTransactionState, "transaction is not ready for this operation", err)
	case errors.Is(err, errVNextAlreadyExists):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceConflict, "request or checkpoint identity already exists", err)
	case errors.Is(err, errVNextNoSpace):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceNoSpace, "Owner cannot satisfy the checkpoint allocation", err)
	case errors.Is(err, errVNextMetadataFull):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner metadata is unavailable", err)
	case errors.Is(err, errVNextCRCSidecar):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceSidecarInvalid, "TRCRC006 validation failed", err)
	case errors.Is(err, cxlcheckpoint.ErrWrongFormat):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServicePublicationIncompatible, "publication is not TRPUB006", err)
	case errors.Is(err, cxlcheckpoint.ErrCorrupt), errors.Is(err, cxlcheckpoint.ErrInvalid):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServicePublicationInvalid, "TRPUB006 validation failed", err)
	case errors.Is(err, errVNextCorrupt):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServicePayloadMismatch, "payload does not match its CRC-32C record", err)
	default:
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner operation failed closed", err)
	}
}
