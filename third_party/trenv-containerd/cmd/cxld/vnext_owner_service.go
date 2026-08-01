package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

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

	group              *vnextOwnerGroup
	directory          *vnextLocalDAXDirectory
	now                func() time.Time
	schedulerAuthority vnextOwnerSchedulerAuthorityVerifier
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
	vnextOwnerServicePermissionDenied          vnextOwnerServiceErrorCode = "permission_denied"
	vnextOwnerServiceCapabilityConflict        vnextOwnerServiceErrorCode = "producer_capability_conflict"
	vnextOwnerServiceCapabilityDenied          vnextOwnerServiceErrorCode = "producer_capability_denied"
	vnextOwnerServiceCapabilityExpired         vnextOwnerServiceErrorCode = "producer_capability_expired"
	vnextOwnerServiceCapabilityRevoked         vnextOwnerServiceErrorCode = "producer_capability_revoked"
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

type vnextOwnerSchedulerLifecycleRequest struct {
	Operation          vnextOwnerOperationIdentity
	SchedulerAuthority vnextOwnerSchedulerAuthority
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
	RequestID          string
	CheckpointID       string
	ProducerID         string
	OwnerID            string
	OwnerEpoch         uint64
	Contents           []vnextOwnerReserveContent
	MaxExtents         uint32
	SchedulerAuthority vnextOwnerSchedulerAuthority
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
	State          vnextOwnerReservationState
	Replayed       bool
	SchedulerProof vnextOwnerSchedulerProof
	Operation      vnextOwnerOperationIdentity
	TotalPages     uint64
	Contents       []vnextOwnerPortableContentSegment
	Extents        []vnextOwnerPortableExtent
	Devices        []vnextOwnerPortableDevice
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
// is correlation only and is not persisted in the Owner journal. LastTransition
// proves only the current head; it is not complete-history evidence. Its absence
// or a different RequestID must not be interpreted as a generic NOT_APPLIED
// proof for an older SetAdmission request.
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
	RequestID          string
	OwnerID            string
	OwnerEpoch         uint64
	From               vnextOwnerAdmissionState
	Target             vnextOwnerAdmissionState
	ExpectedSequence   uint64
	SchedulerAuthority vnextOwnerSchedulerAuthority
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
	SchedulerProof   vnextOwnerSchedulerProof
}

type vnextOwnerSchedulerLifecycleResponse struct {
	Operation      vnextOwnerOperationIdentity
	Replayed       bool
	SchedulerProof vnextOwnerSchedulerProof
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
	Capability              vnextProducerCapabilityProof
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
	return newVNextOwnerServiceWithSchedulerAuthority(group, directory, nil)
}

func newVNextOwnerServiceWithSchedulerAuthority(
	group *vnextOwnerGroup,
	directory *vnextLocalDAXDirectory,
	schedulerAuthority vnextOwnerSchedulerAuthorityVerifier,
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
	return &vnextOwnerService{
		group:              group,
		directory:          directory,
		now:                time.Now,
		schedulerAuthority: schedulerAuthority,
	}, nil
}

func (service *vnextOwnerService) prepareSchedulerMutation(
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerVerifiedAuthority, error) {
	if service == nil || service.group == nil || service.schedulerAuthority == nil {
		return vnextOwnerSchedulerVerifiedAuthority{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable,
			"Scheduler authority verifier is not configured", nil)
	}
	verified, err := service.schedulerAuthority.Prepare(operation, mutation, authority)
	if err != nil {
		return vnextOwnerSchedulerVerifiedAuthority{}, vnextOwnerServiceWrap(operation, err)
	}
	return verified, nil
}

func (service *vnextOwnerService) verifyCurrentSchedulerMutation(
	operation string,
	verified vnextOwnerSchedulerVerifiedAuthority,
) error {
	if err := service.schedulerAuthority.VerifyCurrent(context.Background(), verified); err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}
	return nil
}

func (service *vnextOwnerService) authorizePreparedSchedulerMutation(
	operation string,
	rpcOperation string,
	mutation interface{},
	verified vnextOwnerSchedulerVerifiedAuthority,
) (vnextOwnerSchedulerProof, bool, error) {
	proof, status := service.group.schedulerProofStatus(
		rpcOperation, mutation, verified.Receipt)
	switch status {
	case vnextOwnerSchedulerReceiptExact:
		return proof, true, nil
	case vnextOwnerSchedulerReceiptConflict:
		return vnextOwnerSchedulerProof{}, false, vnextOwnerServiceWrap(
			operation, errVNextOwnerSchedulerReceiptConflict)
	case vnextOwnerSchedulerReceiptMissing:
		if err := service.verifyCurrentSchedulerMutation(operation, verified); err != nil {
			return vnextOwnerSchedulerProof{}, false, err
		}
		return vnextOwnerSchedulerProof{}, false, nil
	default:
		return vnextOwnerSchedulerProof{}, false, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable,
			"Scheduler receipt status is invalid", errVNextCorrupt)
	}
}

func (service *vnextOwnerService) durableSchedulerProof(
	operation string,
	rpcOperation string,
	mutation interface{},
	verified vnextOwnerSchedulerVerifiedAuthority,
) (vnextOwnerSchedulerProof, error) {
	proof, status := service.group.schedulerProofStatus(
		rpcOperation, mutation, verified.Receipt)
	if status != vnextOwnerSchedulerReceiptExact || !proof.valid() ||
		proof != verified.proof() {
		return vnextOwnerSchedulerProof{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable,
			"durable Scheduler proof does not match the verified mutation", errVNextCorrupt)
	}
	return proof, nil
}

func (service *vnextOwnerService) capabilityNowUnixNano(
	operation string,
) (uint64, error) {
	if service == nil || service.now == nil {
		return 0, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner capability clock is unavailable", nil)
	}
	now, err := unixNanoForVNextProducerCapability(service.now())
	if err != nil {
		return 0, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner capability clock is invalid", err)
	}
	return now, nil
}

func (service *vnextOwnerService) issueProducerCapabilityScheduler(
	request vnextOwnerIssueProducerCapabilityRequest,
	caller vnextOwnerCallerContext,
) (vnextOwnerIssueProducerCapabilityResponse, error) {
	const operation = "issue-producer-capability"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerScheduler {
		return vnextOwnerIssueProducerCapabilityResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"only an authenticated Scheduler may issue Producer capabilities", err)
	}
	verified, err := service.prepareSchedulerMutation(
		vnextOwnerRPCOperationIssueProducerCapability, request, request.SchedulerAuthority)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, err
	}
	request.SchedulerReceipt = verified.Receipt
	_, _, err = service.authorizePreparedSchedulerMutation(
		operation, vnextOwnerRPCOperationIssueProducerCapability, request, verified)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, err
	}
	now, err := service.capabilityNowUnixNano(operation)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, err
	}
	issuer := vnextOwnerSchedulerPrincipal(verified)
	record, replayed, err := service.group.issueProducerCapabilityWithScheduler(
		request, issuer, now, &verified)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	durableProof, err := service.durableSchedulerProof(
		operation, vnextOwnerRPCOperationIssueProducerCapability, request, verified)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, err
	}
	return vnextOwnerIssueProducerCapabilityResponse{
		RequestID: request.RequestID,
		Capability: vnextProducerCapabilityProof{
			CapabilityID: record.CapabilityID,
			Token:        request.Nonce,
		},
		Operation:         request.Operation,
		ProducerPrincipal: record.ProducerPrincipal,
		AllowedOperations: record.AllowedOperations,
		IssuedAtUnixNano:  record.IssuedAtUnixNano,
		ExpiresAtUnixNano: record.ExpiresAtUnixNano,
		Replayed:          replayed,
		SchedulerProof:    durableProof,
	}, nil
}

func (service *vnextOwnerService) producerCapabilityIssueStatusAndFenceScheduler(
	request vnextOwnerProducerCapabilityIssueStatusAndFenceRequest,
	caller vnextOwnerCallerContext,
) (vnextOwnerProducerCapabilityIssueStatusAndFenceResponse, error) {
	const operation = "producer-capability-issue-status-and-fence"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerScheduler {
		return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{},
			vnextOwnerServiceFailure(
				operation, vnextOwnerServicePermissionDenied,
				"only an authenticated Scheduler may resolve Producer capability Issue status", err)
	}
	if err := validateVNextOwnerProducerCapabilityIssueStatusAndFenceRequest(request); err != nil {
		return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{},
			vnextOwnerServiceFailure(
				operation, vnextOwnerServiceInvalidRequest, err.Error(), err)
	}
	verified, err := service.prepareSchedulerMutation(
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
		request,
		request.SchedulerAuthority)
	if err != nil {
		return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{}, err
	}
	replacementEligible, err := validateVNextOwnerProducerCapabilityIssueFenceTerm(
		request, verified)
	if err != nil {
		return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{},
			vnextOwnerServiceWrap(operation, err)
	}
	// Absence must never use the normal exact-receipt shortcut. Every query
	// establishes a fresh linearizable current-term point before it can advance
	// the Owner's durable high-water and report NOT_FOUND.
	if err := service.verifyCurrentSchedulerMutation(operation, verified); err != nil {
		return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{}, err
	}
	response, err := service.group.producerCapabilityIssueStatusAndFenceWithScheduler(
		request, replacementEligible, &verified)
	if err != nil {
		if errors.Is(err, errVNextProducerCapabilityTransactionNotFound) {
			return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{},
				vnextOwnerServiceFailure(
					operation, vnextOwnerServiceTransactionNotFound,
					"allocation record does not exist", err)
		}
		if errors.Is(err, errVNextOwnerPoisoned) || errors.Is(err, errVNextCorrupt) {
			return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{},
				vnextOwnerServiceFailure(
					operation, vnextOwnerServiceUnavailable,
					"Owner control journal is unavailable", err)
		}
		return vnextOwnerProducerCapabilityIssueStatusAndFenceResponse{},
			vnextOwnerServiceWrap(operation, err)
	}
	return response, nil
}

func (service *vnextOwnerService) revokeProducerCapabilityScheduler(
	request vnextOwnerRevokeProducerCapabilityRequest,
	caller vnextOwnerCallerContext,
) (vnextOwnerRevokeProducerCapabilityResponse, error) {
	const operation = "revoke-producer-capability"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerScheduler {
		return vnextOwnerRevokeProducerCapabilityResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"only an authenticated Scheduler may revoke Producer capabilities", err)
	}
	verified, err := service.prepareSchedulerMutation(
		vnextOwnerRPCOperationRevokeProducerCapability, request, request.SchedulerAuthority)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, err
	}
	request.SchedulerReceipt = verified.Receipt
	_, _, err = service.authorizePreparedSchedulerMutation(
		operation, vnextOwnerRPCOperationRevokeProducerCapability, request, verified)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, err
	}
	now, err := service.capabilityNowUnixNano(operation)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, err
	}
	revoker := vnextOwnerSchedulerPrincipal(verified)
	record, replayed, err := service.group.revokeProducerCapabilityWithScheduler(
		request, revoker, now, &verified)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	durableProof, err := service.durableSchedulerProof(
		operation, vnextOwnerRPCOperationRevokeProducerCapability, request, verified)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, err
	}
	return vnextOwnerRevokeProducerCapabilityResponse{
		RequestID:         request.RequestID,
		CapabilityID:      record.CapabilityID,
		Operation:         request.Operation,
		RevokedAtUnixNano: record.RevokedAtUnixNano,
		Replayed:          replayed,
		SchedulerProof:    durableProof,
	}, nil
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

func (service *vnextOwnerService) setAdmissionScheduler(
	request vnextOwnerSetAdmissionRequest,
) (vnextOwnerSetAdmissionResponse, error) {
	const operation = "set-admission"
	service.mu.Lock()
	defer service.mu.Unlock()
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
	verified, err := service.prepareSchedulerMutation(
		vnextOwnerRPCOperationSetAdmission, request, request.SchedulerAuthority)
	if err != nil {
		return vnextOwnerSetAdmissionResponse{}, err
	}
	_, _, err = service.authorizePreparedSchedulerMutation(
		operation, vnextOwnerRPCOperationSetAdmission, request, verified)
	if err != nil {
		return vnextOwnerSetAdmissionResponse{}, err
	}
	result, err := service.group.setAdmissionWithScheduler(internal, &verified)
	if err != nil {
		return vnextOwnerSetAdmissionResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	durableProof, err := service.durableSchedulerProof(
		operation, vnextOwnerRPCOperationSetAdmission, request, verified)
	if err != nil {
		return vnextOwnerSetAdmissionResponse{}, err
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
		SchedulerProof:   durableProof,
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
	portable.SchedulerProof = transaction.SchedulerReserveProof
	response.Grant = &portable
	return response, nil
}

func (service *vnextOwnerService) reserveScheduler(
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
	verified, err := service.prepareSchedulerMutation(
		vnextOwnerRPCOperationReserve, request, request.SchedulerAuthority)
	if err != nil {
		return vnextOwnerReserveResponse{}, err
	}
	_, exactReplay, err := service.authorizePreparedSchedulerMutation(
		operation, vnextOwnerRPCOperationReserve, request, verified)
	if err != nil {
		return vnextOwnerReserveResponse{}, err
	}
	grant, err := service.group.reserveWithScheduler(internal, &verified)
	if err != nil {
		if errors.Is(err, errVNextNoSpace) {
			durableProof, proofErr := service.durableSchedulerProof(
				operation, vnextOwnerRPCOperationReserve, request, verified)
			if proofErr != nil {
				return vnextOwnerReserveResponse{}, proofErr
			}
			service.group.mu.Lock()
			allocationID := service.group.journal.RequestIndex[request.RequestID]
			transaction := service.group.journal.Transactions[allocationID]
			if transaction == nil || transaction.State != vnextOwnerRejectedNoSpace {
				service.group.mu.Unlock()
				return vnextOwnerReserveResponse{}, vnextOwnerServiceFailure(
					operation, vnextOwnerServiceUnavailable,
					"durable no-space record is unavailable", errVNextCorrupt)
			}
			identity := vnextOwnerOperationIdentity{
				RequestID:          transaction.RequestID,
				CheckpointID:       transaction.CheckpointID,
				ProducerID:         transaction.ProducerID,
				OwnerID:            service.group.ownerID,
				OwnerEpoch:         service.group.ownerEpoch,
				AllocationRecordID: transaction.AllocationRecordID,
			}
			service.group.mu.Unlock()
			return vnextOwnerReserveResponse{
				State:          vnextOwnerReservationRejectedNoSpace,
				Replayed:       exactReplay,
				SchedulerProof: durableProof,
				Operation:      identity,
				Contents:       []vnextOwnerPortableContentSegment{},
				Extents:        []vnextOwnerPortableExtent{},
				Devices:        []vnextOwnerPortableDevice{},
			}, nil
		}
		return vnextOwnerReserveResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	durableProof, err := service.durableSchedulerProof(
		operation, vnextOwnerRPCOperationReserve, request, verified)
	if err != nil {
		return vnextOwnerReserveResponse{}, err
	}
	response, err := service.reserveResponse(internal, grant)
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable,
			"reserved placement cannot be represented", err)
	}
	response.Replayed = exactReplay
	response.SchedulerProof = durableProof
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
		State: vnextOwnerReservationGranted,
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
	caller vnextOwnerCallerContext,
) (vnextOwnerSealResponse, error) {
	const operation = "seal"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerProducer {
		return vnextOwnerSealResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"only the authenticated Producer may seal a checkpoint", err)
	}
	now, err := service.capabilityNowUnixNano(operation)
	if err != nil {
		return vnextOwnerSealResponse{}, err
	}
	if err := service.group.validateProducerCapability(
		request.Operation,
		request.Capability,
		caller.Principal,
		vnextProducerCapabilitySeal,
		now); err != nil {
		return vnextOwnerSealResponse{}, vnextOwnerServiceWrap(operation, err)
	}

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

func (service *vnextOwnerService) commitScheduler(
	request vnextOwnerSchedulerLifecycleRequest,
) (vnextOwnerSchedulerLifecycleResponse, error) {
	return service.schedulerLifecycle(
		"commit", vnextOwnerRPCOperationCommit, request,
		vnextOwnerCommitted, service.group.commitWithScheduler)
}

func (service *vnextOwnerService) abortScheduler(
	request vnextOwnerSchedulerLifecycleRequest,
) (vnextOwnerSchedulerLifecycleResponse, error) {
	return service.schedulerLifecycle(
		"abort", vnextOwnerRPCOperationAbort, request,
		vnextOwnerAborted, service.group.abortWithScheduler)
}

func (service *vnextOwnerService) schedulerLifecycle(
	operation string,
	rpcOperation string,
	request vnextOwnerSchedulerLifecycleRequest,
	terminalState vnextOwnerTransactionState,
	currentApply func(vnextOwnerWriteGrant, *vnextOwnerSchedulerVerifiedAuthority) error,
) (vnextOwnerSchedulerLifecycleResponse, error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	verified, err := service.prepareSchedulerMutation(
		rpcOperation, request.Operation, request.SchedulerAuthority)
	if err != nil {
		return vnextOwnerSchedulerLifecycleResponse{}, err
	}
	_, exactReplay, err := service.authorizePreparedSchedulerMutation(
		operation, rpcOperation, request.Operation, verified)
	if err != nil {
		return vnextOwnerSchedulerLifecycleResponse{}, err
	}
	grant, _, err := service.resolveOperation(
		operation, request.Operation, vnextOwnerGranted, true, terminalState)
	if err != nil {
		return vnextOwnerSchedulerLifecycleResponse{}, err
	}
	err = currentApply(grant, &verified)
	if err != nil {
		return vnextOwnerSchedulerLifecycleResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	durableProof, err := service.durableSchedulerProof(
		operation, rpcOperation, request.Operation, verified)
	if err != nil {
		return vnextOwnerSchedulerLifecycleResponse{}, err
	}
	return vnextOwnerSchedulerLifecycleResponse{
		Operation:      request.Operation,
		Replayed:       exactReplay,
		SchedulerProof: durableProof,
	}, nil
}

func (service *vnextOwnerService) producerAbort(
	identity vnextOwnerOperationIdentity,
	capability vnextProducerCapabilityProof,
	caller vnextOwnerCallerContext,
) error {
	const operation = "producer-abort"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerProducer {
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"only the authenticated Producer may use Producer abort", err)
	}

	group := service.group
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable, "Owner group is not usable", err)
	}
	transaction, record, err := group.validateProducerCapabilityProofLocked(
		identity, capability, caller.Principal, vnextProducerCapabilityAbort)
	if err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}

	// Proof validation above is intentionally state-independent. Only an exact
	// bearer may observe this terminal replay. ABORTED means every fragment was
	// already cleared and freed durably, so replay is a read-only success even
	// if the capability subsequently expired or was revoked.
	if transaction.State == vnextOwnerAborted {
		return nil
	}
	if transaction.State != vnextOwnerGranted {
		return vnextOwnerServiceFailure(
			operation,
			vnextOwnerServiceTransactionState,
			fmt.Sprintf("durable transaction is in state %d", transaction.State),
			errVNextInvalidState)
	}

	now, err := service.capabilityNowUnixNano(operation)
	if err != nil {
		return err
	}
	if err := validateVNextProducerCapabilityLiveAuthority(record, now); err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}
	if err := group.requireReclaimSafetyLocked(operation); err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}
	if err := group.abortTransactionLocked(
		transaction, vnextOwnerAbortByProducer); err != nil {
		return vnextOwnerServiceWrap(operation, group.poisonLocked(err))
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
	case errors.Is(err, errVNextOwnerSchedulerAuthority),
		errors.Is(err, errVNextOwnerSchedulerFenced):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"Scheduler authority is invalid, stale, or unavailable", err)
	case errors.Is(err, errVNextOwnerSchedulerReceiptConflict):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceConflict,
			"Scheduler mutation conflicts with its durable authority proof", err)
	case errors.Is(err, errVNextProducerCapabilityConflict):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceCapabilityConflict,
			"Producer capability request conflicts with durable state", err)
	case errors.Is(err, errVNextProducerCapabilityRevoked):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceCapabilityRevoked,
			"Producer capability is revoked", err)
	case errors.Is(err, errVNextProducerCapabilityExpired):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceCapabilityExpired,
			"Producer capability is expired", err)
	case errors.Is(err, errVNextProducerCapabilityDenied):
		return vnextOwnerServiceFailure(
			operation, vnextOwnerServiceCapabilityDenied,
			"Producer capability does not authorize this request", err)
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
