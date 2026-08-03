package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// STATUS_AND_FENCE is deliberately a separate Reader operation. It does
	// not share PREPARE or Owner protocol, operation, ALPN, or signing domains.
	// No transport is wired in this slice; a future authenticated listener must
	// negotiate this exact ALPN before passing its exact URI principal to Handle.
	vnextReaderPreparedStatusProtocol  = "cxld.vnext-reader-prepared-status-and-fence.v1"
	vnextReaderPreparedStatusOperation = "vnextReaderPreparedStatusAndFence"
	vnextReaderPreparedStatusALPN      = "cxld-vnext-reader-prepared-status/1"

	vnextReaderPreparedStatusAuthorityDomain          = "cxld-vnext-reader-prepared-status-and-fence-authority-v1"
	vnextReaderPreparedStatusAuthoritySignatureDomain = "cxld-vnext-reader-prepared-status-and-fence-authority-signature-v1"
	vnextReaderPreparedStatusAuthorityReceiptDomain   = "cxld-vnext-reader-prepared-status-and-fence-authority-receipt-v1"
	vnextReaderPreparedStatusRequestDigestDomain      = "cxld-vnext-reader-prepared-status-and-fence-request-digest-v1"
	vnextReaderPreparedStatusResponseReceiptDomain    = "cxld-vnext-reader-prepared-status-and-fence-response-receipt-v1"

	vnextReaderPreparedStatusMaxFrameBytes   = 16 << 20
	vnextReaderPreparedStatusMaxObjectFields = 16
)

type vnextReaderPreparedStatusAuthorityEnvelope struct {
	Domain                 string
	ClusterID              string
	SchedulerID            string
	SchedulerFenceRevision uint64
	LeaderLeaseID          uint64
	LeaderTermID           [sha256.Size]byte
	KeyID                  [sha256.Size]byte
	RequestDigest          [sha256.Size]byte
	Signature              [ed25519.SignatureSize]byte
}

// vnextReaderPreparedStatusAuthorityProof is status-specific current-leader
// evidence. It is not a PREPARE proof and grants no Owner, DAX, ACTIVE,
// mapping, release, reclaim, or CRIU authority.
type vnextReaderPreparedStatusAuthorityProof struct {
	AuthenticatedSchedulerPrincipal string
	SchedulerID                     string
	SchedulerFenceRevision          uint64
	LeaderLeaseID                   uint64
	LeaderTermID                    [sha256.Size]byte
	RequestDigest                   [sha256.Size]byte
	AuthorityReceipt                [sha256.Size]byte
}

type vnextReaderPreparedStatusAuthorityVerifier interface {
	VerifyVNextReaderPreparedStatusAuthority(
		context.Context,
		string,
		[sha256.Size]byte,
		vnextReaderPreparedStatusAuthorityEnvelope,
	) (vnextReaderPreparedStatusAuthorityProof, error)
}

type vnextReaderPreparedStatusStore interface {
	StatusAndFencePreparedExact(
		vnextReaderAcquiredAuthorization,
	) (vnextReaderPreparedStatusAndFenceResult, error)
}

type vnextReaderPreparedStatusRequest struct {
	Acquired  vnextReaderAcquiredAuthorization
	Authority vnextReaderPreparedStatusAuthorityEnvelope
}

// vnextReaderPreparedStatusResponse binds the configured local cxld target ID,
// not a unique process-start incarnation. A restart that reuses the same ID is
// indistinguishable in this slice, while its in-memory tombstones are gone.
// Consequently this response is only a process/store-lifetime observation and
// must never authorize release, reclaim, ACTIVE, or mapping after restart (or
// before it). Durable fencing or an explicit restart incarnation is future
// work.
type vnextReaderPreparedStatusResponse struct {
	RequestDigest       [sha256.Size]byte
	AuthorityProof      vnextReaderPreparedStatusAuthorityProof
	LocalExecutorNodeID string
	LocalCxldInstanceID string
	Acquired            vnextReaderAcquiredAuthorization
	Result              vnextReaderPreparedStatusAndFenceResult
	Receipt             [sha256.Size]byte
}

type vnextReaderPreparedStatusErrorCode string

const (
	vnextReaderPreparedStatusInvalidRequest vnextReaderPreparedStatusErrorCode = "INVALID_REQUEST"
	vnextReaderPreparedStatusAuthorityError vnextReaderPreparedStatusErrorCode = "AUTHORITY_REJECTED"
	vnextReaderPreparedStatusIdentityError  vnextReaderPreparedStatusErrorCode = "IDENTITY_REJECTED"
	vnextReaderPreparedStatusConflictError  vnextReaderPreparedStatusErrorCode = "CONFLICT"
	vnextReaderPreparedStatusCapacityError  vnextReaderPreparedStatusErrorCode = "CAPACITY_EXHAUSTED"
	vnextReaderPreparedStatusUnavailable    vnextReaderPreparedStatusErrorCode = "UNAVAILABLE"
)

type vnextReaderPreparedStatusAcceptance string

const (
	vnextReaderPreparedStatusDefinitelyNotAccepted vnextReaderPreparedStatusAcceptance = "DEFINITELY_NOT_ACCEPTED"
	vnextReaderPreparedStatusAcceptanceUnknown     vnextReaderPreparedStatusAcceptance = "UNKNOWN"
)

type vnextReaderPreparedStatusRPCError struct {
	Code       vnextReaderPreparedStatusErrorCode
	Acceptance vnextReaderPreparedStatusAcceptance
	Cause      error
}

func (failure *vnextReaderPreparedStatusRPCError) Error() string {
	if failure == nil {
		return "VNext Reader STATUS_AND_FENCE failure is unavailable"
	}
	return fmt.Sprintf("VNext Reader STATUS_AND_FENCE %s (%s): %v",
		failure.Code, failure.Acceptance, failure.Cause)
}

func (failure *vnextReaderPreparedStatusRPCError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

func vnextReaderPreparedStatusFailure(
	code vnextReaderPreparedStatusErrorCode,
	acceptance vnextReaderPreparedStatusAcceptance,
	cause error,
) *vnextReaderPreparedStatusRPCError {
	if cause == nil {
		cause = errors.New("unspecified VNext Reader STATUS_AND_FENCE failure")
	}
	return &vnextReaderPreparedStatusRPCError{
		Code: code, Acceptance: acceptance, Cause: cause,
	}
}

type vnextReaderPreparedStatusService struct {
	localExecutorNodeID string
	localCxldInstanceID string
	store               vnextReaderPreparedStatusStore
	authorityVerifier   vnextReaderPreparedStatusAuthorityVerifier
}

func newVNextReaderPreparedStatusService(
	localExecutorNodeID string,
	localCxldInstanceID string,
	store vnextReaderPreparedStatusStore,
	authorityVerifier vnextReaderPreparedStatusAuthorityVerifier,
) (*vnextReaderPreparedStatusService, error) {
	if err := validateVNextReaderIdentity(
		"local Reader executor node ID", localExecutorNodeID); err != nil {
		return nil, err
	}
	if err := validateVNextReaderIdentity(
		"local Reader cxld instance ID", localCxldInstanceID); err != nil {
		return nil, err
	}
	if vnextReaderPreparedStatusNilInterface(store) {
		return nil, errors.New(
			"VNext Reader STATUS_AND_FENCE authorization store is unavailable")
	}
	if vnextReaderPreparedStatusNilInterface(authorityVerifier) {
		return nil, errors.New(
			"VNext Reader STATUS_AND_FENCE authority verifier is unavailable")
	}
	return &vnextReaderPreparedStatusService{
		localExecutorNodeID: cloneVNextReaderRetainedString(localExecutorNodeID),
		localCxldInstanceID: cloneVNextReaderRetainedString(localCxldInstanceID),
		store:               store,
		authorityVerifier:   authorityVerifier,
	}, nil
}

func vnextReaderPreparedStatusNilInterface(value interface{}) bool {
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

// StatusAndFence authenticates one status query and then performs exactly one
// process-local store operation. There is deliberately no receiver clock: a
// structurally valid historical ACQUIRED identity remains queryable after its
// wall-clock expiry, but the result remains only a process/store-lifetime
// observation and provides no restart-incarnation proof.
func (service *vnextReaderPreparedStatusService) StatusAndFence(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	request vnextReaderPreparedStatusRequest,
) (vnextReaderPreparedStatusResponse, *vnextReaderPreparedStatusRPCError) {
	if service == nil || vnextReaderPreparedStatusNilInterface(service.store) ||
		vnextReaderPreparedStatusNilInterface(service.authorityVerifier) {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			errors.New("VNext Reader STATUS_AND_FENCE service is unavailable"))
	}
	if ctx == nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusInvalidRequest,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			errors.New("VNext Reader STATUS_AND_FENCE context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}
	if err := validateVNextReaderPreparedStatusPrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusAuthorityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}

	// Clone the variable-size identity before any validation, digesting,
	// verification, or storage so caller mutation cannot substitute PageRuns.
	request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
	authenticatedSchedulerPrincipal = cloneVNextReaderRetainedString(
		authenticatedSchedulerPrincipal)
	if err := validateVNextReaderPrepareAcquiredStructure(request.Acquired); err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusInvalidRequest,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}
	if request.Acquired.Authorization.ExecutorID != service.localExecutorNodeID ||
		request.Acquired.Authorization.CxldInstanceID != service.localCxldInstanceID {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusIdentityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf(
				"authorization targets executor/cxld %q/%q, local identity is %q/%q",
				request.Acquired.Authorization.ExecutorID,
				request.Acquired.Authorization.CxldInstanceID,
				service.localExecutorNodeID,
				service.localCxldInstanceID))
	}
	if err := validateVNextReaderPreparedStatusAuthorityEnvelope(
		request.Authority); err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusAuthorityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}
	requestDigest := vnextReaderPreparedStatusCanonicalRequestDigest(
		request.Acquired)
	if request.Authority.RequestDigest != requestDigest {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusAuthorityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			errors.New(
				"STATUS_AND_FENCE authority has a different request digest"))
	}

	proof, err := service.authorityVerifier.
		VerifyVNextReaderPreparedStatusAuthority(
			ctx, authenticatedSchedulerPrincipal, requestDigest, request.Authority)
	if err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusAuthorityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf("verify current STATUS_AND_FENCE Scheduler authority: %w", err))
	}
	if err := validateVNextReaderPreparedStatusAuthorityProof(
		proof,
		authenticatedSchedulerPrincipal,
		requestDigest,
		request.Authority); err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusAuthorityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}

	result, err := service.store.StatusAndFencePreparedExact(request.Acquired)
	if err != nil {
		return vnextReaderPreparedStatusResponse{},
			mapVNextReaderPreparedStatusStoreError(err)
	}
	if err := validateVNextReaderPreparedStatusStoreResult(
		result, request.Acquired); err != nil {
		// The only store call has already returned success. A malformed future
		// implementation cannot safely be described as a definitive rejection.
		return vnextReaderPreparedStatusResponse{}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusAcceptanceUnknown,
			fmt.Errorf("validate STATUS_AND_FENCE store result: %w", err))
	}
	response := vnextReaderPreparedStatusResponse{
		RequestDigest:       requestDigest,
		AuthorityProof:      cloneVNextReaderPreparedStatusAuthorityProof(proof),
		LocalExecutorNodeID: service.localExecutorNodeID,
		LocalCxldInstanceID: service.localCxldInstanceID,
		Acquired:            cloneVNextReaderAcquiredAuthorization(request.Acquired),
		Result:              cloneVNextReaderPreparedStatusResult(result),
	}
	response.Receipt = vnextReaderPreparedStatusCanonicalResponseReceipt(response)
	return response, nil
}

func mapVNextReaderPreparedStatusStoreError(
	err error,
) *vnextReaderPreparedStatusRPCError {
	code := vnextReaderPreparedStatusUnavailable
	acceptance := vnextReaderPreparedStatusAcceptanceUnknown
	switch {
	case errors.Is(err, errVNextReaderAuthorizationConflict):
		code = vnextReaderPreparedStatusConflictError
		acceptance = vnextReaderPreparedStatusDefinitelyNotAccepted
	case errors.Is(err, errVNextReaderAuthorizationStoreFull),
		errors.Is(err, errVNextReaderAuthorizationStoreRetainedBytesFull):
		code = vnextReaderPreparedStatusCapacityError
		acceptance = vnextReaderPreparedStatusDefinitelyNotAccepted
	case errors.Is(err, errVNextReaderAuthorizationIdentityMismatch),
		errors.Is(err, errVNextReaderAuthorizationNotFound):
		code = vnextReaderPreparedStatusIdentityError
		acceptance = vnextReaderPreparedStatusDefinitelyNotAccepted
	}
	return vnextReaderPreparedStatusFailure(code, acceptance, err)
}

func validateVNextReaderPreparedStatusStoreResult(
	result vnextReaderPreparedStatusAndFenceResult,
	want vnextReaderAcquiredAuthorization,
) error {
	switch result.State {
	case vnextReaderPreparedStatusExactPrepared:
		if result.Prepared.PreparationState != vnextReaderPreparationPrepared ||
			!equalVNextReaderAcquiredAuthorization(result.Prepared.Acquired, want) {
			return errors.New("PREPARED result does not contain the exact ACQUIRED receipt")
		}
	case vnextReaderPreparedStatusNotPreparedFenced:
		if !reflect.DeepEqual(
			result.Prepared, vnextReaderPreparedAuthorization{}) {
			return errors.New("NOT_PREPARED_FENCED result carries a prepared receipt")
		}
	default:
		return fmt.Errorf("STATUS_AND_FENCE store state %q is invalid", result.State)
	}
	return nil
}

func cloneVNextReaderPreparedStatusResult(
	result vnextReaderPreparedStatusAndFenceResult,
) vnextReaderPreparedStatusAndFenceResult {
	cloned := result
	if result.State == vnextReaderPreparedStatusExactPrepared {
		cloned.Prepared.Acquired = cloneVNextReaderAcquiredAuthorization(
			result.Prepared.Acquired)
	}
	return cloned
}

type vnextReaderPreparedStatusResponseEncoder func(
	vnextReaderPreparedStatusResponse,
) ([]byte, error)

type vnextReaderPreparedStatusRPC struct {
	service        *vnextReaderPreparedStatusService
	encodeResponse vnextReaderPreparedStatusResponseEncoder
}

func newVNextReaderPreparedStatusRPC(
	service *vnextReaderPreparedStatusService,
) *vnextReaderPreparedStatusRPC {
	if service == nil {
		return nil
	}
	return &vnextReaderPreparedStatusRPC{
		service:        service,
		encodeResponse: marshalVNextReaderPreparedStatusResponse,
	}
}

// Handle is transport-neutral. authenticatedSchedulerPrincipal must be exact
// channel evidence and is never decoded from the request body.
func (rpc *vnextReaderPreparedStatusRPC) Handle(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	frame []byte,
) ([]byte, *vnextReaderPreparedStatusRPCError) {
	if rpc == nil || rpc.service == nil || rpc.encodeResponse == nil {
		return nil, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			errors.New("VNext Reader STATUS_AND_FENCE RPC is unavailable"))
	}
	request, err := decodeVNextReaderPreparedStatusRequest(frame)
	if err != nil {
		return nil, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusInvalidRequest,
			vnextReaderPreparedStatusDefinitelyNotAccepted, err)
	}
	response, failure := rpc.service.StatusAndFence(
		ctx, authenticatedSchedulerPrincipal, request)
	if failure != nil {
		return nil, failure
	}
	body, err := rpc.encodeResponse(response)
	if err != nil {
		// The store decision may already have linearized. A failed response
		// encoding is necessarily ambiguous to the remote Scheduler.
		return nil, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusAcceptanceUnknown,
			fmt.Errorf("encode accepted STATUS_AND_FENCE response: %w", err))
	}
	return body, nil
}

func validateVNextReaderPreparedStatusAuthorityEnvelope(
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) error {
	if err := validateVNextReaderPreparedStatusUnsignedAuthorityEnvelope(
		authority); err != nil {
		return err
	}
	if allVNextReaderZero(authority.Signature[:]) {
		return errors.New("STATUS_AND_FENCE authority signature is zero")
	}
	return nil
}

func validateVNextReaderPreparedStatusUnsignedAuthorityEnvelope(
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) error {
	if authority.Domain != vnextReaderPreparedStatusAuthorityDomain {
		return fmt.Errorf("STATUS_AND_FENCE authority domain is %q, expected %q",
			authority.Domain, vnextReaderPreparedStatusAuthorityDomain)
	}
	if err := validateVNextReaderPreparedStatusClusterID(
		authority.ClusterID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"STATUS_AND_FENCE authority Scheduler ID", authority.SchedulerID); err != nil {
		return err
	}
	if authority.SchedulerFenceRevision == 0 ||
		authority.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		authority.LeaderLeaseID == 0 ||
		authority.LeaderLeaseID > cxlcheckpoint.MaxSignedLong {
		return errors.New(
			"STATUS_AND_FENCE authority fence or leader lease is outside the positive ABI")
	}
	if allVNextReaderZero(authority.LeaderTermID[:]) ||
		allVNextReaderZero(authority.KeyID[:]) ||
		allVNextReaderZero(authority.RequestDigest[:]) {
		return errors.New(
			"STATUS_AND_FENCE authority term, key, or request digest is zero")
	}
	return nil
}

func validateVNextReaderPreparedStatusClusterID(value string) error {
	if len(value) != 16 || value != strings.ToLower(value) {
		return errors.New(
			"STATUS_AND_FENCE cluster ID is not canonical 16-character lowercase hex")
	}
	decoded, err := strconv.ParseUint(value, 16, 64)
	if err != nil || decoded == 0 {
		return errors.New("STATUS_AND_FENCE cluster ID is outside the positive ABI")
	}
	return nil
}

func validateVNextReaderPreparedStatusAuthorityProof(
	proof vnextReaderPreparedStatusAuthorityProof,
	authenticatedSchedulerPrincipal string,
	requestDigest [sha256.Size]byte,
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) error {
	if err := validateVNextReaderPreparedStatusPrincipalURI(
		proof.AuthenticatedSchedulerPrincipal); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"verified STATUS_AND_FENCE Scheduler ID", proof.SchedulerID); err != nil {
		return err
	}
	if proof.SchedulerFenceRevision == 0 ||
		proof.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		proof.LeaderLeaseID == 0 ||
		proof.LeaderLeaseID > cxlcheckpoint.MaxSignedLong ||
		allVNextReaderZero(proof.LeaderTermID[:]) ||
		allVNextReaderZero(proof.RequestDigest[:]) ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) {
		return errors.New("verified STATUS_AND_FENCE Scheduler proof is incomplete")
	}
	if proof.AuthenticatedSchedulerPrincipal != authenticatedSchedulerPrincipal ||
		proof.SchedulerID != authority.SchedulerID ||
		proof.SchedulerFenceRevision != authority.SchedulerFenceRevision ||
		proof.LeaderLeaseID != authority.LeaderLeaseID ||
		proof.LeaderTermID != authority.LeaderTermID ||
		proof.RequestDigest != requestDigest ||
		proof.RequestDigest != authority.RequestDigest {
		return errors.New(
			"verified STATUS_AND_FENCE principal, leader, fence, or digest differs")
	}
	wantReceipt, err := vnextReaderPreparedStatusCanonicalAuthorityReceipt(
		authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return fmt.Errorf("derive verified STATUS_AND_FENCE authority receipt: %w", err)
	}
	if proof.AuthorityReceipt != wantReceipt {
		return errors.New(
			"verified STATUS_AND_FENCE authority receipt does not bind the exact envelope")
	}
	return nil
}

func cloneVNextReaderPreparedStatusAuthorityProof(
	proof vnextReaderPreparedStatusAuthorityProof,
) vnextReaderPreparedStatusAuthorityProof {
	cloned := proof
	cloned.AuthenticatedSchedulerPrincipal = cloneVNextReaderRetainedString(
		proof.AuthenticatedSchedulerPrincipal)
	cloned.SchedulerID = cloneVNextReaderRetainedString(proof.SchedulerID)
	return cloned
}

func vnextReaderPreparedStatusCanonicalRequestDigest(
	acquired vnextReaderAcquiredAuthorization,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderPreparedStatusRequestDigestDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPreparedStatusProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPreparedStatusOperation)
	vnextReaderWriteCanonicalAcquired(&buffer, acquired)
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderPreparedStatusAuthoritySignaturePreimage(
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) ([]byte, error) {
	if err := validateVNextReaderPreparedStatusUnsignedAuthorityEnvelope(
		authority); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderPreparedStatusAuthoritySignatureDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPreparedStatusProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPreparedStatusOperation)
	vnextReaderPrepareWriteString(&buffer, authority.Domain)
	vnextReaderPrepareWriteString(&buffer, authority.ClusterID)
	vnextReaderPrepareWriteString(&buffer, authority.SchedulerID)
	vnextReaderPrepareWriteU64(&buffer, authority.SchedulerFenceRevision)
	vnextReaderPrepareWriteU64(&buffer, authority.LeaderLeaseID)
	buffer.Write(authority.LeaderTermID[:])
	buffer.Write(authority.KeyID[:])
	buffer.Write(authority.RequestDigest[:])
	return append([]byte(nil), buffer.Bytes()...), nil
}

func vnextReaderPreparedStatusCanonicalAuthorityReceipt(
	authenticatedSchedulerPrincipal string,
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validateVNextReaderPreparedStatusPrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, err
	}
	if err := validateVNextReaderPreparedStatusAuthorityEnvelope(authority); err != nil {
		return zero, err
	}
	preimage, err := vnextReaderPreparedStatusAuthoritySignaturePreimage(authority)
	if err != nil {
		return zero, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderPreparedStatusAuthorityReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, authenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteU64(&buffer, uint64(len(preimage)))
	buffer.Write(preimage)
	buffer.Write(authority.Signature[:])
	return sha256.Sum256(buffer.Bytes()), nil
}

func vnextReaderPreparedStatusCanonicalResponseReceipt(
	response vnextReaderPreparedStatusResponse,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderPreparedStatusResponseReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPreparedStatusProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPreparedStatusOperation)
	buffer.Write(response.RequestDigest[:])
	proof := response.AuthorityProof
	vnextReaderPrepareWriteString(
		&buffer, proof.AuthenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteString(&buffer, proof.SchedulerID)
	vnextReaderPrepareWriteU64(&buffer, proof.SchedulerFenceRevision)
	vnextReaderPrepareWriteU64(&buffer, proof.LeaderLeaseID)
	buffer.Write(proof.LeaderTermID[:])
	buffer.Write(proof.RequestDigest[:])
	buffer.Write(proof.AuthorityReceipt[:])
	vnextReaderPrepareWriteString(&buffer, response.LocalExecutorNodeID)
	vnextReaderPrepareWriteString(&buffer, response.LocalCxldInstanceID)
	// Echo and bind queried identity A separately from current querying
	// authority B. A may come from an earlier Scheduler term.
	vnextReaderWriteCanonicalAcquired(&buffer, response.Acquired)
	vnextReaderPrepareWriteString(&buffer, string(response.Result.State))
	if response.Result.State == vnextReaderPreparedStatusExactPrepared {
		vnextReaderPrepareWriteU64(&buffer, 1)
		vnextReaderPrepareWriteString(
			&buffer, string(response.Result.Prepared.PreparationState))
	} else {
		vnextReaderPrepareWriteU64(&buffer, 0)
	}
	return sha256.Sum256(buffer.Bytes())
}

type vnextReaderPreparedStatusAuthorityWire struct {
	Domain                 string `json:"domain"`
	ClusterID              string `json:"clusterId"`
	SchedulerID            string `json:"schedulerId"`
	SchedulerFenceRevision uint64 `json:"schedulerFenceRevision"`
	LeaderLeaseID          uint64 `json:"leaderLeaseId"`
	LeaderTermID           string `json:"leaderTermId"`
	KeyID                  string `json:"keyId"`
	RequestDigest          string `json:"requestDigest"`
	Signature              string `json:"signature"`
}

type vnextReaderPreparedStatusRequestWire struct {
	Protocol  string                                 `json:"protocol"`
	Operation string                                 `json:"operation"`
	Acquired  vnextReaderPrepareAcquiredWire         `json:"acquired"`
	Authority vnextReaderPreparedStatusAuthorityWire `json:"authority"`
}

type vnextReaderPreparedStatusAuthorityProofWire struct {
	AuthenticatedSchedulerPrincipal string `json:"authenticatedSchedulerPrincipal"`
	SchedulerID                     string `json:"schedulerId"`
	SchedulerFenceRevision          uint64 `json:"schedulerFenceRevision"`
	LeaderLeaseID                   uint64 `json:"leaderLeaseId"`
	LeaderTermID                    string `json:"leaderTermId"`
	RequestDigest                   string `json:"requestDigest"`
	AuthorityReceipt                string `json:"authorityReceipt"`
}

type vnextReaderPreparedStatusPreparedWire struct {
	PreparationState string `json:"preparationState"`
}

type vnextReaderPreparedStatusResponseWire struct {
	Protocol            string                                      `json:"protocol"`
	Operation           string                                      `json:"operation"`
	RequestDigest       string                                      `json:"requestDigest"`
	AuthorityProof      vnextReaderPreparedStatusAuthorityProofWire `json:"authorityProof"`
	LocalExecutorNodeID string                                      `json:"localExecutorNodeId"`
	LocalCxldInstanceID string                                      `json:"localCxldInstanceId"`
	Acquired            vnextReaderPrepareAcquiredWire              `json:"acquired"`
	State               string                                      `json:"state"`
	Prepared            *vnextReaderPreparedStatusPreparedWire      `json:"prepared"`
	Receipt             string                                      `json:"receipt"`
}

func decodeVNextReaderPreparedStatusRequest(
	raw []byte,
) (vnextReaderPreparedStatusRequest, error) {
	var wire vnextReaderPreparedStatusRequestWire
	if err := decodeStrictVNextReaderPreparedStatusJSON(raw, &wire); err != nil {
		return vnextReaderPreparedStatusRequest{}, err
	}
	if wire.Protocol != vnextReaderPreparedStatusProtocol ||
		wire.Operation != vnextReaderPreparedStatusOperation {
		return vnextReaderPreparedStatusRequest{}, fmt.Errorf(
			"Reader STATUS_AND_FENCE protocol/operation is %q/%q, expected %q/%q",
			wire.Protocol, wire.Operation,
			vnextReaderPreparedStatusProtocol,
			vnextReaderPreparedStatusOperation)
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderPreparedStatusRequest{}, err
	}
	if err := validateVNextReaderPrepareAcquiredStructure(acquired); err != nil {
		return vnextReaderPreparedStatusRequest{}, err
	}
	authority, err := wire.Authority.internal()
	if err != nil {
		return vnextReaderPreparedStatusRequest{}, err
	}
	if err := validateVNextReaderPreparedStatusAuthorityEnvelope(authority); err != nil {
		return vnextReaderPreparedStatusRequest{}, err
	}
	if authority.RequestDigest !=
		vnextReaderPreparedStatusCanonicalRequestDigest(acquired) {
		return vnextReaderPreparedStatusRequest{}, errors.New(
			"STATUS_AND_FENCE authority digest does not match the canonical payload")
	}
	return vnextReaderPreparedStatusRequest{
		Acquired: acquired, Authority: authority,
	}, nil
}

func marshalVNextReaderPreparedStatusRequest(
	request vnextReaderPreparedStatusRequest,
) ([]byte, error) {
	if err := validateVNextReaderPrepareAcquiredStructure(request.Acquired); err != nil {
		return nil, err
	}
	if err := validateVNextReaderPreparedStatusAuthorityEnvelope(
		request.Authority); err != nil {
		return nil, err
	}
	if request.Authority.RequestDigest !=
		vnextReaderPreparedStatusCanonicalRequestDigest(request.Acquired) {
		return nil, errors.New(
			"STATUS_AND_FENCE authority does not bind the request payload")
	}
	wire := vnextReaderPreparedStatusRequestWire{
		Protocol:  vnextReaderPreparedStatusProtocol,
		Operation: vnextReaderPreparedStatusOperation,
		Acquired:  vnextReaderPrepareAcquiredWireFromInternal(request.Acquired),
		Authority: vnextReaderPreparedStatusAuthorityWireFromInternal(
			request.Authority),
	}
	return marshalBoundedVNextReaderPreparedStatusJSON(wire)
}

func marshalVNextReaderPreparedStatusResponse(
	response vnextReaderPreparedStatusResponse,
) ([]byte, error) {
	if err := validateVNextReaderPreparedStatusResponse(response); err != nil {
		return nil, err
	}
	var prepared *vnextReaderPreparedStatusPreparedWire
	if response.Result.State == vnextReaderPreparedStatusExactPrepared {
		prepared = &vnextReaderPreparedStatusPreparedWire{
			PreparationState: string(response.Result.Prepared.PreparationState),
		}
	}
	wire := vnextReaderPreparedStatusResponseWire{
		Protocol:      vnextReaderPreparedStatusProtocol,
		Operation:     vnextReaderPreparedStatusOperation,
		RequestDigest: hex.EncodeToString(response.RequestDigest[:]),
		AuthorityProof: vnextReaderPreparedStatusAuthorityProofWireFromInternal(
			response.AuthorityProof),
		LocalExecutorNodeID: response.LocalExecutorNodeID,
		LocalCxldInstanceID: response.LocalCxldInstanceID,
		Acquired: vnextReaderPrepareAcquiredWireFromInternal(
			response.Acquired),
		State:    string(response.Result.State),
		Prepared: prepared,
		Receipt:  hex.EncodeToString(response.Receipt[:]),
	}
	return marshalBoundedVNextReaderPreparedStatusJSON(wire)
}

func decodeVNextReaderPreparedStatusResponse(
	raw []byte,
) (vnextReaderPreparedStatusResponse, error) {
	var wire vnextReaderPreparedStatusResponseWire
	if err := decodeStrictVNextReaderPreparedStatusJSON(raw, &wire); err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	if wire.Protocol != vnextReaderPreparedStatusProtocol ||
		wire.Operation != vnextReaderPreparedStatusOperation {
		return vnextReaderPreparedStatusResponse{}, errors.New(
			"Reader STATUS_AND_FENCE response protocol or operation is invalid")
	}
	requestDigest, err := decodeVNextReaderPreparedStatusHexDigest(
		"response request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	proof, err := wire.AuthorityProof.internal()
	if err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	receipt, err := decodeVNextReaderPreparedStatusHexDigest(
		"response receipt", wire.Receipt)
	if err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	if err := validateVNextReaderPrepareAcquiredStructure(acquired); err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	result := vnextReaderPreparedStatusAndFenceResult{
		State: vnextReaderPreparedStatusAndFenceState(wire.State),
	}
	switch result.State {
	case vnextReaderPreparedStatusExactPrepared:
		if wire.Prepared == nil ||
			wire.Prepared.PreparationState != string(vnextReaderPreparationPrepared) {
			return vnextReaderPreparedStatusResponse{}, errors.New(
				"PREPARED status response has no full prepared receipt")
		}
		result.Prepared = vnextReaderPreparedAuthorization{
			Acquired: acquired, PreparationState: vnextReaderPreparationPrepared,
		}
	case vnextReaderPreparedStatusNotPreparedFenced:
		if wire.Prepared != nil {
			return vnextReaderPreparedStatusResponse{}, errors.New(
				"NOT_PREPARED_FENCED response carries a prepared receipt")
		}
	default:
		return vnextReaderPreparedStatusResponse{}, fmt.Errorf(
			"Reader STATUS_AND_FENCE response state %q is invalid", wire.State)
	}
	response := vnextReaderPreparedStatusResponse{
		RequestDigest:       requestDigest,
		AuthorityProof:      proof,
		LocalExecutorNodeID: wire.LocalExecutorNodeID,
		LocalCxldInstanceID: wire.LocalCxldInstanceID,
		Acquired:            acquired,
		Result:              result,
		Receipt:             receipt,
	}
	if err := validateVNextReaderPreparedStatusResponse(response); err != nil {
		return vnextReaderPreparedStatusResponse{}, err
	}
	return response, nil
}

func validateVNextReaderPreparedStatusResponse(
	response vnextReaderPreparedStatusResponse,
) error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"response local executor node ID", response.LocalExecutorNodeID},
		{"response local cxld instance ID", response.LocalCxldInstanceID},
		{"response authenticated Scheduler principal",
			response.AuthorityProof.AuthenticatedSchedulerPrincipal},
		{"response Scheduler ID", response.AuthorityProof.SchedulerID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if err := validateVNextReaderPreparedStatusPrincipalURI(
		response.AuthorityProof.AuthenticatedSchedulerPrincipal); err != nil {
		return err
	}
	proof := response.AuthorityProof
	if err := validateVNextReaderPrepareAcquiredStructure(
		response.Acquired); err != nil {
		return fmt.Errorf("validate queried STATUS_AND_FENCE ACQUIRED: %w", err)
	}
	if allVNextReaderZero(response.RequestDigest[:]) ||
		proof.SchedulerFenceRevision == 0 ||
		proof.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		proof.LeaderLeaseID == 0 ||
		proof.LeaderLeaseID > cxlcheckpoint.MaxSignedLong ||
		allVNextReaderZero(proof.LeaderTermID[:]) ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) ||
		proof.RequestDigest != response.RequestDigest {
		return errors.New(
			"STATUS_AND_FENCE response identity or authority proof is incomplete")
	}
	if response.RequestDigest !=
		vnextReaderPreparedStatusCanonicalRequestDigest(response.Acquired) ||
		response.LocalExecutorNodeID != response.Acquired.Authorization.ExecutorID ||
		response.LocalCxldInstanceID !=
			response.Acquired.Authorization.CxldInstanceID {
		return errors.New(
			"STATUS_AND_FENCE response differs from the queried ACQUIRED identity")
	}
	switch response.Result.State {
	case vnextReaderPreparedStatusExactPrepared:
		if err := validateVNextReaderPrepareAcquiredStructure(
			response.Result.Prepared.Acquired); err != nil {
			return fmt.Errorf("validate PREPARED status response receipt: %w", err)
		}
		if response.Result.Prepared.PreparationState !=
			vnextReaderPreparationPrepared {
			return errors.New("PREPARED status response state is incomplete")
		}
		acquired := response.Result.Prepared.Acquired
		if !equalVNextReaderAcquiredAuthorization(acquired, response.Acquired) {
			return errors.New(
				"PREPARED status response differs from its exact ACQUIRED receipt")
		}
	case vnextReaderPreparedStatusNotPreparedFenced:
		if !reflect.DeepEqual(
			response.Result.Prepared, vnextReaderPreparedAuthorization{}) {
			return errors.New(
				"NOT_PREPARED_FENCED response carries a prepared receipt")
		}
	default:
		return errors.New("STATUS_AND_FENCE response state is invalid")
	}
	if response.Receipt !=
		vnextReaderPreparedStatusCanonicalResponseReceipt(response) {
		return errors.New("STATUS_AND_FENCE response receipt is inconsistent")
	}
	return nil
}

func (wire vnextReaderPreparedStatusAuthorityWire) internal() (
	vnextReaderPreparedStatusAuthorityEnvelope,
	error,
) {
	termID, err := decodeVNextReaderPreparedStatusHexDigest(
		"authority leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityEnvelope{}, err
	}
	keyID, err := decodeVNextReaderPreparedStatusHexDigest(
		"authority key ID", wire.KeyID)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityEnvelope{}, err
	}
	requestDigest, err := decodeVNextReaderPreparedStatusHexDigest(
		"authority request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityEnvelope{}, err
	}
	signature, err := decodeVNextReaderPreparedStatusHexSignature(
		"authority signature", wire.Signature)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityEnvelope{}, err
	}
	return vnextReaderPreparedStatusAuthorityEnvelope{
		Domain:                 wire.Domain,
		ClusterID:              wire.ClusterID,
		SchedulerID:            wire.SchedulerID,
		SchedulerFenceRevision: wire.SchedulerFenceRevision,
		LeaderLeaseID:          wire.LeaderLeaseID,
		LeaderTermID:           termID,
		KeyID:                  keyID,
		RequestDigest:          requestDigest,
		Signature:              signature,
	}, nil
}

func (wire vnextReaderPreparedStatusAuthorityProofWire) internal() (
	vnextReaderPreparedStatusAuthorityProof,
	error,
) {
	termID, err := decodeVNextReaderPreparedStatusHexDigest(
		"response authority leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityProof{}, err
	}
	requestDigest, err := decodeVNextReaderPreparedStatusHexDigest(
		"response authority request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityProof{}, err
	}
	receipt, err := decodeVNextReaderPreparedStatusHexDigest(
		"response authority receipt", wire.AuthorityReceipt)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityProof{}, err
	}
	return vnextReaderPreparedStatusAuthorityProof{
		AuthenticatedSchedulerPrincipal: wire.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     wire.SchedulerID,
		SchedulerFenceRevision:          wire.SchedulerFenceRevision,
		LeaderLeaseID:                   wire.LeaderLeaseID,
		LeaderTermID:                    termID,
		RequestDigest:                   requestDigest,
		AuthorityReceipt:                receipt,
	}, nil
}

func vnextReaderPreparedStatusAuthorityWireFromInternal(
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) vnextReaderPreparedStatusAuthorityWire {
	return vnextReaderPreparedStatusAuthorityWire{
		Domain:                 authority.Domain,
		ClusterID:              authority.ClusterID,
		SchedulerID:            authority.SchedulerID,
		SchedulerFenceRevision: authority.SchedulerFenceRevision,
		LeaderLeaseID:          authority.LeaderLeaseID,
		LeaderTermID:           hex.EncodeToString(authority.LeaderTermID[:]),
		KeyID:                  hex.EncodeToString(authority.KeyID[:]),
		RequestDigest:          hex.EncodeToString(authority.RequestDigest[:]),
		Signature:              hex.EncodeToString(authority.Signature[:]),
	}
}

func vnextReaderPreparedStatusAuthorityProofWireFromInternal(
	proof vnextReaderPreparedStatusAuthorityProof,
) vnextReaderPreparedStatusAuthorityProofWire {
	return vnextReaderPreparedStatusAuthorityProofWire{
		AuthenticatedSchedulerPrincipal: proof.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     proof.SchedulerID,
		SchedulerFenceRevision:          proof.SchedulerFenceRevision,
		LeaderLeaseID:                   proof.LeaderLeaseID,
		LeaderTermID:                    hex.EncodeToString(proof.LeaderTermID[:]),
		RequestDigest:                   hex.EncodeToString(proof.RequestDigest[:]),
		AuthorityReceipt:                hex.EncodeToString(proof.AuthorityReceipt[:]),
	}
}

func decodeVNextReaderPreparedStatusHexDigest(
	name string,
	value string,
) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(digest)) ||
		value != strings.ToLower(value) {
		return digest, fmt.Errorf(
			"STATUS_AND_FENCE %s is not canonical 64-character lowercase hex", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, fmt.Errorf("decode STATUS_AND_FENCE %s: %w", name, err)
	}
	copy(digest[:], decoded)
	if allVNextReaderZero(digest[:]) {
		return digest, fmt.Errorf("STATUS_AND_FENCE %s is zero", name)
	}
	return digest, nil
}

func decodeVNextReaderPreparedStatusHexSignature(
	name string,
	value string,
) ([ed25519.SignatureSize]byte, error) {
	var signature [ed25519.SignatureSize]byte
	if len(value) != hex.EncodedLen(len(signature)) ||
		value != strings.ToLower(value) {
		return signature, fmt.Errorf(
			"STATUS_AND_FENCE %s is not canonical %d-character lowercase hex",
			name, hex.EncodedLen(len(signature)))
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(signature) {
		return signature, fmt.Errorf("decode STATUS_AND_FENCE %s: %w", name, err)
	}
	copy(signature[:], decoded)
	if allVNextReaderZero(signature[:]) {
		return signature, fmt.Errorf("STATUS_AND_FENCE %s is zero", name)
	}
	return signature, nil
}

func marshalBoundedVNextReaderPreparedStatusJSON(value interface{}) (
	[]byte,
	error,
) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w",
			vnextReaderPreparedStatusProtocol, err)
	}
	if len(body) == 0 || len(body) > vnextReaderPreparedStatusMaxFrameBytes {
		return nil, fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			vnextReaderPreparedStatusProtocol,
			len(body), vnextReaderPreparedStatusMaxFrameBytes)
	}
	return body, nil
}

func decodeStrictVNextReaderPreparedStatusJSON(
	raw []byte,
	target interface{},
) error {
	if len(raw) == 0 || len(raw) > vnextReaderPreparedStatusMaxFrameBytes {
		return fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			vnextReaderPreparedStatusProtocol,
			len(raw), vnextReaderPreparedStatusMaxFrameBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("decode %s: JSON is not valid UTF-8",
			vnextReaderPreparedStatusProtocol)
	}
	if err := validateVNextReaderPreparedStatusJSONShape(raw, target); err != nil {
		return fmt.Errorf("decode %s: %w",
			vnextReaderPreparedStatusProtocol, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w",
			vnextReaderPreparedStatusProtocol, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value",
				vnextReaderPreparedStatusProtocol)
		}
		return fmt.Errorf("decode %s trailer: %w",
			vnextReaderPreparedStatusProtocol, err)
	}
	return nil
}

func validateVNextReaderPreparedStatusJSONShape(
	raw []byte,
	target interface{},
) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Ptr ||
		targetType.Elem().Kind() != reflect.Struct {
		return errors.New(
			"strict Reader STATUS_AND_FENCE target must be a pointer to a struct")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateVNextReaderPreparedStatusJSONValue(
		decoder, targetType.Elem(), "message"); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("decode JSON trailer: %w", err)
	}
	return nil
}

func validateVNextReaderPreparedStatusJSONValue(
	decoder *json.Decoder,
	valueType reflect.Type,
	path string,
) error {
	if valueType.Kind() == reflect.Ptr {
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		trimmed := bytes.TrimSpace(raw)
		if bytes.Equal(trimmed, []byte("null")) {
			return nil
		}
		nested := json.NewDecoder(bytes.NewReader(trimmed))
		nested.UseNumber()
		if err := validateVNextReaderPreparedStatusJSONValue(
			nested, valueType.Elem(), path); err != nil {
			return err
		}
		var trailing interface{}
		if err := nested.Decode(&trailing); !errors.Is(err, io.EOF) {
			return fmt.Errorf("%s has a trailing JSON value", path)
		}
		return nil
	}
	switch valueType.Kind() {
	case reflect.Struct:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '{' {
			return fmt.Errorf("%s must be a JSON object", path)
		}
		fields := make(map[string]reflect.Type, valueType.NumField())
		order := make([]string, 0, valueType.NumField())
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field.Type
				order = append(order, name)
			}
		}
		seen := make(map[string]struct{}, len(fields))
		count := 0
		for decoder.More() {
			if count >= vnextReaderPreparedStatusMaxObjectFields {
				return fmt.Errorf("%s contains more than %d fields",
					path, vnextReaderPreparedStatusMaxObjectFields)
			}
			token, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%s field: %w", path, err)
			}
			name, ok := token.(string)
			if !ok {
				return fmt.Errorf("%s field name is not a string", path)
			}
			fieldType, allowed := fields[name]
			if !allowed {
				return fmt.Errorf("%s has unknown field %q", path, name)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("%s has duplicate field %q", path, name)
			}
			seen[name] = struct{}{}
			if err := validateVNextReaderPreparedStatusJSONValue(
				decoder, fieldType, path+"."+name); err != nil {
				return err
			}
			count++
		}
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%s closing token: %w", path, err)
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
			return fmt.Errorf("%s has an invalid object terminator", path)
		}
		for _, name := range order {
			if _, present := seen[name]; !present {
				return fmt.Errorf("%s is missing required field %q", path, name)
			}
		}
		return nil
	case reflect.Slice:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '[' {
			return fmt.Errorf("%s must be a JSON array", path)
		}
		limit := 0
		if valueType == reflect.TypeOf(vnextReaderPreparePageRunsWire{}) {
			limit = vnextReaderMaxLocatorRuns
		}
		count := 0
		for decoder.More() {
			if limit != 0 && count >= limit {
				return fmt.Errorf("%s contains more than %d elements", path, limit)
			}
			if err := validateVNextReaderPreparedStatusJSONValue(
				decoder, valueType.Elem(), fmt.Sprintf("%s[%d]", path, count)); err != nil {
				return err
			}
			count++
		}
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%s closing token: %w", path, err)
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
			return fmt.Errorf("%s has an invalid array terminator", path)
		}
		return nil
	case reflect.String:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := token.(string); !ok {
			return fmt.Errorf("%s must be a JSON string", path)
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("%s must be a JSON number", path)
		}
		return nil
	default:
		return fmt.Errorf("%s has unsupported JSON type %s", path, valueType)
	}
}
