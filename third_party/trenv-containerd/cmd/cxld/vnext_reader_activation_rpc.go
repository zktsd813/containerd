package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type vnextReaderActivationErrorCode string

const (
	vnextReaderActivationInvalidRequest vnextReaderActivationErrorCode = "INVALID_REQUEST"
	vnextReaderActivationAuthorityError vnextReaderActivationErrorCode = "AUTHORITY_REJECTED"
	vnextReaderActivationIdentityError  vnextReaderActivationErrorCode = "IDENTITY_REJECTED"
	vnextReaderActivationIncarnation    vnextReaderActivationErrorCode = "INCARNATION_MISMATCH"
	vnextReaderActivationConflictError  vnextReaderActivationErrorCode = "CONFLICT"
	vnextReaderActivationNotFound       vnextReaderActivationErrorCode = "NOT_FOUND_FENCED"
	vnextReaderActivationCapacityError  vnextReaderActivationErrorCode = "CAPACITY_EXHAUSTED"
	vnextReaderActivationUnavailable    vnextReaderActivationErrorCode = "UNAVAILABLE"
)

type vnextReaderActivationAcceptance string

const (
	vnextReaderActivationDefinitelyNotAccepted vnextReaderActivationAcceptance = "DEFINITELY_NOT_ACCEPTED"
	vnextReaderActivationAcceptanceUnknown     vnextReaderActivationAcceptance = "UNKNOWN"
)

type vnextReaderActivationRPCError struct {
	Protocol   string
	Code       vnextReaderActivationErrorCode
	Acceptance vnextReaderActivationAcceptance
	Cause      error
}

func (failure *vnextReaderActivationRPCError) Error() string {
	if failure == nil {
		return "VNext Reader activation failure is unavailable"
	}
	return fmt.Sprintf("VNext Reader activation %s %s (%s): %v",
		failure.Protocol, failure.Code, failure.Acceptance, failure.Cause)
}

func (failure *vnextReaderActivationRPCError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

func vnextReaderActivationFailure(
	spec vnextReaderActivationOperationSpec,
	code vnextReaderActivationErrorCode,
	acceptance vnextReaderActivationAcceptance,
	cause error,
) *vnextReaderActivationRPCError {
	if cause == nil {
		cause = errors.New("unspecified VNext Reader activation failure")
	}
	return &vnextReaderActivationRPCError{
		Protocol: spec.protocol, Code: code, Acceptance: acceptance, Cause: cause,
	}
}

type vnextReaderActivationProposalRequest struct {
	Request   vnextReaderActivationRequestIdentity
	Authority vnextReaderActivationAuthorityEnvelope
}

type vnextReaderActivationProposalResponse struct {
	RequestDigest           [sha256.Size]byte
	AuthorityProof          vnextReaderActivationAuthorityProof
	LocalExecutorNodeID     string
	LocalCxldLogicalID      string
	LocalProcessIncarnation vnextReaderProcessIncarnation
	State                   vnextReaderActivationState
	Disposition             vnextReaderActivationProposalDisposition
	Acquired                vnextReaderAcquiredAuthorization
	Activation              vnextReaderActivationIntent
	Receipt                 [sha256.Size]byte
}

type vnextReaderActivationCommitRequest struct {
	Acquired    vnextReaderAcquiredAuthorization
	Activation  vnextReaderActivationIntent
	ActiveState vnextReaderActivationActiveState
	Authority   vnextReaderActivationAuthorityEnvelope
}

type vnextReaderActivationCommitResponse struct {
	RequestDigest           [sha256.Size]byte
	AuthorityProof          vnextReaderActivationAuthorityProof
	LocalExecutorNodeID     string
	LocalCxldLogicalID      string
	LocalProcessIncarnation vnextReaderProcessIncarnation
	State                   vnextReaderActivationState
	Disposition             vnextReaderActivationCommitDisposition
	Acquired                vnextReaderAcquiredAuthorization
	Activation              vnextReaderActivationIntent
	ActiveState             vnextReaderActivationActiveState
	Receipt                 [sha256.Size]byte
}

type vnextReaderActivationStatusRequest struct {
	Request   vnextReaderActivationRequestIdentity
	Authority vnextReaderActivationAuthorityEnvelope
}

type vnextReaderActivationStatusState string

const (
	vnextReaderActivationStatusNotFoundState            vnextReaderActivationStatusState = "NOT_FOUND"
	vnextReaderActivationStatusPendingState             vnextReaderActivationStatusState = "PENDING"
	vnextReaderActivationStatusArmedState               vnextReaderActivationStatusState = "ACTIVE_ARMED"
	vnextReaderActivationStatusConflictState            vnextReaderActivationStatusState = "CONFLICT"
	vnextReaderActivationStatusIncarnationMismatchState vnextReaderActivationStatusState = "INCARNATION_MISMATCH"
)

type vnextReaderActivationStatusResponse struct {
	RequestDigest           [sha256.Size]byte
	AuthorityProof          vnextReaderActivationAuthorityProof
	LocalExecutorNodeID     string
	LocalCxldLogicalID      string
	LocalProcessIncarnation vnextReaderProcessIncarnation
	State                   vnextReaderActivationStatusState
	Acquired                vnextReaderAcquiredAuthorization
	Activation              *vnextReaderActivationIntent
	ActiveState             *vnextReaderActivationActiveState
	Receipt                 [sha256.Size]byte
}

type vnextReaderActivationService struct {
	store             *vnextReaderActivationStore
	clock             vnextReaderPrepareClock
	authorityVerifier vnextReaderActivationAuthorityVerifier
}

func newVNextReaderActivationService(
	store *vnextReaderActivationStore,
	clock vnextReaderPrepareClock,
	authorityVerifier vnextReaderActivationAuthorityVerifier,
) (*vnextReaderActivationService, error) {
	if store == nil {
		return nil, errors.New("VNext Reader activation store is unavailable")
	}
	if clock == nil {
		return nil, errors.New("VNext Reader activation local clock is unavailable")
	}
	if vnextReaderPreparedStatusNilInterface(authorityVerifier) {
		return nil, errors.New("VNext Reader activation authority verifier is unavailable")
	}
	return &vnextReaderActivationService{
		store: store, clock: clock, authorityVerifier: authorityVerifier,
	}, nil
}

// Propose installs only a process-local PENDING intent. It neither marks the
// Scheduler catalog ACTIVE nor performs any DAX, mapping, read, CRIU, or
// release operation.
func (service *vnextReaderActivationService) Propose(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	request vnextReaderActivationProposalRequest,
) (vnextReaderActivationProposalResponse, *vnextReaderActivationRPCError) {
	spec := vnextReaderActivationProposalSpec
	if failure := service.validateCall(
		ctx, spec, authenticatedSchedulerPrincipal); failure != nil {
		return vnextReaderActivationProposalResponse{}, failure
	}
	request.Request = cloneVNextReaderActivationRequestIdentity(request.Request)
	request.Authority = cloneVNextReaderActivationAuthorityEnvelope(request.Authority)
	if err := validateVNextReaderActivationRequestIdentity(request.Request); err != nil {
		return vnextReaderActivationProposalResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	digest := vnextReaderActivationCanonicalProposalRequestDigest(request.Request)
	proof, failure := service.verifyAuthority(
		ctx, spec, authenticatedSchedulerPrincipal, digest, request.Authority)
	if failure != nil {
		return vnextReaderActivationProposalResponse{}, failure
	}
	// Initial PROPOSE is intentionally tied to the same Scheduler/fence that
	// produced PREPARED. Unlike STATUS_AND_FENCE, it is not a failover
	// reconciliation operation.
	if proof.SchedulerID != request.Request.Acquired.SchedulerID ||
		proof.SchedulerFenceRevision !=
			request.Request.Acquired.SchedulerFenceRevision {
		return vnextReaderActivationProposalResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationAuthorityError,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New(
					"activation proposal authority differs from PREPARED Scheduler term"))
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderActivationProposalResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	intent, disposition, err := service.store.Propose(
		request.Request, service.clock.NowEpochMillis())
	if err != nil {
		return vnextReaderActivationProposalResponse{},
			mapVNextReaderActivationStoreError(spec, err)
	}
	response := vnextReaderActivationProposalResponse{
		RequestDigest:           digest,
		AuthorityProof:          proof,
		LocalExecutorNodeID:     service.store.localExecutorNodeID,
		LocalCxldLogicalID:      service.store.localCxldLogicalID,
		LocalProcessIncarnation: service.store.localProcess,
		State:                   vnextReaderActivationPending,
		Disposition:             disposition,
		Acquired:                cloneVNextReaderAcquiredAuthorization(request.Request.Acquired),
		Activation:              intent,
	}
	response.Receipt = vnextReaderActivationCanonicalProposalReceipt(response)
	return response, nil
}

// Commit accepts exact durable ACTIVE evidence and changes PENDING only to
// ACTIVE_ARMED. ACTIVE_ARMED remains a zero-I/O logical hold in this wave.
func (service *vnextReaderActivationService) Commit(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	request vnextReaderActivationCommitRequest,
) (vnextReaderActivationCommitResponse, *vnextReaderActivationRPCError) {
	spec := vnextReaderActivationCommitSpec
	if failure := service.validateCall(
		ctx, spec, authenticatedSchedulerPrincipal); failure != nil {
		return vnextReaderActivationCommitResponse{}, failure
	}
	request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
	request.Activation = cloneVNextReaderActivationIntent(request.Activation)
	request.Authority = cloneVNextReaderActivationAuthorityEnvelope(request.Authority)
	identity := vnextReaderActivationRequestIdentity{
		Acquired:            request.Acquired,
		ActivationRequestID: request.Activation.Request.ActivationRequestID,
	}
	if !equalVNextReaderActivationRequestIdentity(
		request.Activation.Request, identity) {
		return vnextReaderActivationCommitResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationConflictError,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New(
					"activation commit nested request identity differs from top-level ACQUIRED"))
	}
	if err := validateVNextReaderActivationRequestIdentity(identity); err != nil {
		return vnextReaderActivationCommitResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	if err := validateVNextReaderActivationEvidence(
		request.Activation, identity); err != nil {
		return vnextReaderActivationCommitResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	if request.Activation.State != vnextReaderActivationPending {
		return vnextReaderActivationCommitResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New("activation commit request evidence is not PENDING"))
	}
	if err := validateVNextReaderActivationActiveState(
		request.ActiveState, identity.ActivationRequestID); err != nil {
		return vnextReaderActivationCommitResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	digest := vnextReaderActivationCanonicalCommitRequestDigest(
		request.Acquired, request.Activation, request.ActiveState)
	proof, failure := service.verifyAuthority(
		ctx, spec, authenticatedSchedulerPrincipal, digest, request.Authority)
	if failure != nil {
		return vnextReaderActivationCommitResponse{}, failure
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderActivationCommitResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	active := cloneVNextReaderAcquiredAuthorization(request.Acquired)
	active.CatalogState = request.ActiveState.CatalogState
	active.LastMutationID = request.ActiveState.LastMutationID
	armed, disposition, err := service.store.Commit(active, request.Activation)
	if err != nil {
		return vnextReaderActivationCommitResponse{},
			mapVNextReaderActivationStoreError(spec, err)
	}
	response := vnextReaderActivationCommitResponse{
		RequestDigest:           digest,
		AuthorityProof:          proof,
		LocalExecutorNodeID:     service.store.localExecutorNodeID,
		LocalCxldLogicalID:      service.store.localCxldLogicalID,
		LocalProcessIncarnation: service.store.localProcess,
		State:                   vnextReaderActivationActiveArmed,
		Disposition:             disposition,
		Acquired:                cloneVNextReaderAcquiredAuthorization(request.Acquired),
		Activation:              armed,
		ActiveState:             request.ActiveState,
	}
	response.Receipt = vnextReaderActivationCanonicalCommitReceipt(response)
	return response, nil
}

// Status authenticates current Scheduler term B independently from retained
// ACQUIRED term A. A miss installs a permanent exact NOT_FOUND tombstone.
func (service *vnextReaderActivationService) Status(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	request vnextReaderActivationStatusRequest,
) (vnextReaderActivationStatusResponse, *vnextReaderActivationRPCError) {
	spec := vnextReaderActivationStatusSpec
	if failure := service.validateCall(
		ctx, spec, authenticatedSchedulerPrincipal); failure != nil {
		return vnextReaderActivationStatusResponse{}, failure
	}
	request.Request = cloneVNextReaderActivationRequestIdentity(request.Request)
	request.Authority = cloneVNextReaderActivationAuthorityEnvelope(request.Authority)
	if err := validateVNextReaderActivationRequestIdentity(request.Request); err != nil {
		return vnextReaderActivationStatusResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	digest := vnextReaderActivationCanonicalStatusRequestDigest(request.Request)
	proof, failure := service.verifyAuthority(
		ctx, spec, authenticatedSchedulerPrincipal, digest, request.Authority)
	if failure != nil {
		return vnextReaderActivationStatusResponse{}, failure
	}
	if request.Request.Acquired.Authorization.ExecutorID !=
		service.store.localExecutorNodeID ||
		request.Request.Acquired.Authorization.CxldLogicalID !=
			service.store.localCxldLogicalID {
		return vnextReaderActivationStatusResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationIdentityError,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New(
					"activation STATUS executor or logical cxld differs from local identity"))
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderActivationStatusResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	result, err := service.store.Status(request.Request)
	response := vnextReaderActivationStatusResponse{
		RequestDigest:           digest,
		AuthorityProof:          proof,
		LocalExecutorNodeID:     service.store.localExecutorNodeID,
		LocalCxldLogicalID:      service.store.localCxldLogicalID,
		LocalProcessIncarnation: service.store.localProcess,
		Acquired:                cloneVNextReaderAcquiredAuthorization(request.Request.Acquired),
	}
	switch {
	case errors.Is(err, errVNextReaderActivationIncarnationMismatch):
		response.State = vnextReaderActivationStatusIncarnationMismatchState
	case errors.Is(err, errVNextReaderActivationConflict):
		response.State = vnextReaderActivationStatusConflictState
	case err != nil:
		return vnextReaderActivationStatusResponse{},
			mapVNextReaderActivationStoreError(spec, err)
	case result.Disposition == vnextReaderActivationStatusNotFoundFenced:
		response.State = vnextReaderActivationStatusNotFoundState
	case result.Disposition == vnextReaderActivationStatusPresent &&
		result.Intent != nil:
		intent := cloneVNextReaderActivationIntent(*result.Intent)
		response.Activation = &intent
		switch intent.State {
		case vnextReaderActivationPending:
			response.State = vnextReaderActivationStatusPendingState
		case vnextReaderActivationActiveArmed:
			response.State = vnextReaderActivationStatusArmedState
			active := vnextReaderActivationActiveState{
				CatalogState:   vnextReaderCatalogAuthorizationActive,
				LastMutationID: intent.Request.ActivationRequestID,
			}
			response.ActiveState = &active
		default:
			return vnextReaderActivationStatusResponse{},
				vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
					vnextReaderActivationDefinitelyNotAccepted,
					errors.New("activation status store returned invalid state"))
		}
	default:
		return vnextReaderActivationStatusResponse{},
			vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New("activation status store returned invalid result"))
	}
	response.Receipt = vnextReaderActivationCanonicalStatusReceipt(response)
	return response, nil
}

func (service *vnextReaderActivationService) validateCall(
	ctx context.Context,
	spec vnextReaderActivationOperationSpec,
	authenticatedSchedulerPrincipal string,
) *vnextReaderActivationRPCError {
	if service == nil || service.store == nil || service.clock == nil ||
		vnextReaderPreparedStatusNilInterface(service.authorityVerifier) {
		return vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted,
			errors.New("VNext Reader activation service is unavailable"))
	}
	if ctx == nil {
		return vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted,
			errors.New("VNext Reader activation context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted, err)
	}
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return vnextReaderActivationFailure(spec, vnextReaderActivationAuthorityError,
			vnextReaderActivationDefinitelyNotAccepted, err)
	}
	return nil
}

func (service *vnextReaderActivationService) verifyAuthority(
	ctx context.Context,
	spec vnextReaderActivationOperationSpec,
	authenticatedSchedulerPrincipal string,
	digest [sha256.Size]byte,
	authority vnextReaderActivationAuthorityEnvelope,
) (vnextReaderActivationAuthorityProof, *vnextReaderActivationRPCError) {
	if err := validateVNextReaderActivationAuthorityEnvelope(spec, authority); err != nil {
		return vnextReaderActivationAuthorityProof{},
			vnextReaderActivationFailure(spec, vnextReaderActivationAuthorityError,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	if authority.RequestDigest != digest {
		return vnextReaderActivationAuthorityProof{},
			vnextReaderActivationFailure(spec, vnextReaderActivationAuthorityError,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New("activation authority has a different request digest"))
	}
	proof, err := service.authorityVerifier.VerifyVNextReaderActivationAuthority(
		ctx, authenticatedSchedulerPrincipal, spec, digest, authority)
	if err != nil {
		return vnextReaderActivationAuthorityProof{},
			vnextReaderActivationFailure(spec, vnextReaderActivationAuthorityError,
				vnextReaderActivationDefinitelyNotAccepted,
				fmt.Errorf("verify current Reader activation Scheduler authority: %w", err))
	}
	if err := validateVNextReaderActivationAuthorityProof(
		spec, proof, authenticatedSchedulerPrincipal, digest, authority); err != nil {
		return vnextReaderActivationAuthorityProof{},
			vnextReaderActivationFailure(spec, vnextReaderActivationAuthorityError,
				vnextReaderActivationDefinitelyNotAccepted, err)
	}
	return cloneVNextReaderActivationAuthorityProof(proof), nil
}

func mapVNextReaderActivationStoreError(
	spec vnextReaderActivationOperationSpec,
	err error,
) *vnextReaderActivationRPCError {
	code := vnextReaderActivationUnavailable
	acceptance := vnextReaderActivationAcceptanceUnknown
	switch {
	case errors.Is(err, errVNextReaderActivationStoreFull),
		errors.Is(err, errVNextReaderActivationStoreRetainedBytesFull),
		errors.Is(err, errVNextReaderActivationMappingGenerationExhausted):
		code = vnextReaderActivationCapacityError
		acceptance = vnextReaderActivationDefinitelyNotAccepted
	case errors.Is(err, errVNextReaderActivationIncarnationMismatch):
		code = vnextReaderActivationIncarnation
		acceptance = vnextReaderActivationDefinitelyNotAccepted
	case errors.Is(err, errVNextReaderActivationConflict),
		errors.Is(err, errVNextReaderAuthorizationIdentityMismatch):
		code = vnextReaderActivationConflictError
		acceptance = vnextReaderActivationDefinitelyNotAccepted
	case errors.Is(err, errVNextReaderActivationNotFoundFenced):
		code = vnextReaderActivationNotFound
		acceptance = vnextReaderActivationDefinitelyNotAccepted
	case errors.Is(err, errVNextReaderActivationNotPending):
		code = vnextReaderActivationIdentityError
		acceptance = vnextReaderActivationDefinitelyNotAccepted
	}
	return vnextReaderActivationFailure(
		spec, code, acceptance, err)
}

func vnextReaderActivationCanonicalProposalReceipt(
	response vnextReaderActivationProposalResponse,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderActivationWriteCanonicalResponsePrefix(
		&buffer, vnextReaderActivationProposalSpec,
		response.RequestDigest, response.AuthorityProof,
		response.LocalExecutorNodeID, response.LocalCxldLogicalID,
		response.LocalProcessIncarnation, string(response.State))
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationProposalDispositionName(response.Disposition))
	vnextReaderWriteCanonicalAcquired(&buffer, response.Acquired)
	vnextReaderActivationWriteCanonicalEvidence(&buffer, response.Activation)
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderActivationCanonicalCommitReceipt(
	response vnextReaderActivationCommitResponse,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderActivationWriteCanonicalResponsePrefix(
		&buffer, vnextReaderActivationCommitSpec,
		response.RequestDigest, response.AuthorityProof,
		response.LocalExecutorNodeID, response.LocalCxldLogicalID,
		response.LocalProcessIncarnation, string(response.State))
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationCommitDispositionName(response.Disposition))
	vnextReaderWriteCanonicalAcquired(&buffer, response.Acquired)
	vnextReaderActivationWriteCanonicalEvidence(&buffer, response.Activation)
	vnextReaderActivationWriteCanonicalActiveState(&buffer, response.ActiveState)
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderActivationCanonicalStatusReceipt(
	response vnextReaderActivationStatusResponse,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderActivationWriteCanonicalResponsePrefix(
		&buffer, vnextReaderActivationStatusSpec,
		response.RequestDigest, response.AuthorityProof,
		response.LocalExecutorNodeID, response.LocalCxldLogicalID,
		response.LocalProcessIncarnation, string(response.State))
	vnextReaderWriteCanonicalAcquired(&buffer, response.Acquired)
	if response.Activation == nil {
		vnextReaderActivationWriteU32(&buffer, 0)
	} else {
		vnextReaderActivationWriteU32(&buffer, 1)
		vnextReaderActivationWriteCanonicalEvidence(&buffer, *response.Activation)
	}
	if response.ActiveState == nil {
		vnextReaderActivationWriteU32(&buffer, 0)
	} else {
		vnextReaderActivationWriteU32(&buffer, 1)
		vnextReaderActivationWriteCanonicalActiveState(&buffer, *response.ActiveState)
	}
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderActivationWriteCanonicalResponsePrefix(
	buffer *bytes.Buffer,
	spec vnextReaderActivationOperationSpec,
	requestDigest [sha256.Size]byte,
	proof vnextReaderActivationAuthorityProof,
	localExecutorNodeID string,
	localCxldLogicalID string,
	localProcess vnextReaderProcessIncarnation,
	state string,
) {
	vnextReaderPrepareWriteString(buffer, spec.receiptDomain)
	vnextReaderPrepareWriteString(buffer, spec.protocol)
	vnextReaderPrepareWriteString(buffer, spec.operation)
	buffer.Write(requestDigest[:])
	vnextReaderActivationWriteCanonicalAuthorityProof(buffer, proof)
	vnextReaderPrepareWriteString(buffer, localExecutorNodeID)
	vnextReaderPrepareWriteString(buffer, localCxldLogicalID)
	vnextReaderPrepareWriteString(buffer, localProcess.String())
	vnextReaderPrepareWriteString(buffer, state)
}

func vnextReaderActivationWriteCanonicalActiveState(
	buffer *bytes.Buffer,
	activeState vnextReaderActivationActiveState,
) {
	vnextReaderPrepareWriteString(buffer, string(activeState.CatalogState))
	vnextReaderPrepareWriteString(buffer, activeState.LastMutationID)
}

func vnextReaderActivationWriteU32(buffer *bytes.Buffer, value uint32) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], value)
	buffer.Write(raw[:])
}

func vnextReaderActivationProposalDispositionName(
	disposition vnextReaderActivationProposalDisposition,
) string {
	switch disposition {
	case vnextReaderActivationProposalInstalled:
		return "INSTALLED"
	case vnextReaderActivationProposalExactReplay:
		return "EXACT_REPLAY"
	default:
		return ""
	}
}

func vnextReaderActivationProposalDispositionFromName(
	value string,
) (vnextReaderActivationProposalDisposition, bool) {
	switch value {
	case "INSTALLED":
		return vnextReaderActivationProposalInstalled, true
	case "EXACT_REPLAY":
		return vnextReaderActivationProposalExactReplay, true
	default:
		return 0, false
	}
}

func vnextReaderActivationCommitDispositionName(
	disposition vnextReaderActivationCommitDisposition,
) string {
	switch disposition {
	case vnextReaderActivationCommitArmed:
		return "ARMED"
	case vnextReaderActivationCommitExactReplay:
		return "EXACT_REPLAY"
	default:
		return ""
	}
}

func vnextReaderActivationCommitDispositionFromName(
	value string,
) (vnextReaderActivationCommitDisposition, bool) {
	switch value {
	case "ARMED":
		return vnextReaderActivationCommitArmed, true
	case "EXACT_REPLAY":
		return vnextReaderActivationCommitExactReplay, true
	default:
		return 0, false
	}
}

type vnextReaderActivationProposalRequestWire struct {
	Protocol            string                             `json:"protocol"`
	Operation           string                             `json:"operation"`
	Acquired            vnextReaderPrepareAcquiredWire     `json:"acquired"`
	ActivationRequestID string                             `json:"activationRequestId"`
	Authority           vnextReaderActivationAuthorityWire `json:"authority"`
}

type vnextReaderActivationProposalResponseWire struct {
	Protocol                  string                                  `json:"protocol"`
	Operation                 string                                  `json:"operation"`
	RequestDigest             string                                  `json:"requestDigest"`
	AuthorityProof            vnextReaderActivationAuthorityProofWire `json:"authorityProof"`
	LocalExecutorNodeID       string                                  `json:"localExecutorNodeId"`
	LocalCxldLogicalID        string                                  `json:"localCxldLogicalId"`
	LocalProcessIncarnationID string                                  `json:"localProcessIncarnationId"`
	State                     string                                  `json:"state"`
	Disposition               string                                  `json:"disposition"`
	Acquired                  vnextReaderPrepareAcquiredWire          `json:"acquired"`
	Activation                vnextReaderActivationEvidenceWire       `json:"activation"`
	Receipt                   string                                  `json:"receipt"`
}

type vnextReaderActivationCommitRequestWire struct {
	Protocol    string                               `json:"protocol"`
	Operation   string                               `json:"operation"`
	Acquired    vnextReaderPrepareAcquiredWire       `json:"acquired"`
	Activation  vnextReaderActivationEvidenceWire    `json:"activation"`
	ActiveState vnextReaderActivationActiveStateWire `json:"activeState"`
	Authority   vnextReaderActivationAuthorityWire   `json:"authority"`
}

type vnextReaderActivationCommitResponseWire struct {
	Protocol                  string                                  `json:"protocol"`
	Operation                 string                                  `json:"operation"`
	RequestDigest             string                                  `json:"requestDigest"`
	AuthorityProof            vnextReaderActivationAuthorityProofWire `json:"authorityProof"`
	LocalExecutorNodeID       string                                  `json:"localExecutorNodeId"`
	LocalCxldLogicalID        string                                  `json:"localCxldLogicalId"`
	LocalProcessIncarnationID string                                  `json:"localProcessIncarnationId"`
	State                     string                                  `json:"state"`
	Disposition               string                                  `json:"disposition"`
	Acquired                  vnextReaderPrepareAcquiredWire          `json:"acquired"`
	Activation                vnextReaderActivationEvidenceWire       `json:"activation"`
	ActiveState               vnextReaderActivationActiveStateWire    `json:"activeState"`
	Receipt                   string                                  `json:"receipt"`
}

type vnextReaderActivationStatusRequestWire struct {
	Protocol            string                             `json:"protocol"`
	Operation           string                             `json:"operation"`
	Acquired            vnextReaderPrepareAcquiredWire     `json:"acquired"`
	ActivationRequestID string                             `json:"activationRequestId"`
	Authority           vnextReaderActivationAuthorityWire `json:"authority"`
}

type vnextReaderActivationStatusResponseWire struct {
	Protocol                  string                                  `json:"protocol"`
	Operation                 string                                  `json:"operation"`
	RequestDigest             string                                  `json:"requestDigest"`
	AuthorityProof            vnextReaderActivationAuthorityProofWire `json:"authorityProof"`
	LocalExecutorNodeID       string                                  `json:"localExecutorNodeId"`
	LocalCxldLogicalID        string                                  `json:"localCxldLogicalId"`
	LocalProcessIncarnationID string                                  `json:"localProcessIncarnationId"`
	State                     string                                  `json:"state"`
	Acquired                  vnextReaderPrepareAcquiredWire          `json:"acquired"`
	Activation                *vnextReaderActivationEvidenceWire      `json:"activation"`
	ActiveState               *vnextReaderActivationActiveStateWire   `json:"activeState"`
	Receipt                   string                                  `json:"receipt"`
}

func decodeVNextReaderActivationProposalRequest(
	raw []byte,
) (vnextReaderActivationProposalRequest, error) {
	var wire vnextReaderActivationProposalRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderActivationProposalSpec, raw, &wire); err != nil {
		return vnextReaderActivationProposalRequest{}, err
	}
	if wire.Protocol != vnextReaderActivationProposalProtocol ||
		wire.Operation != vnextReaderActivationProposalOperation {
		return vnextReaderActivationProposalRequest{},
			errors.New("Reader activation proposal protocol or operation is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivationProposalRequest{}, err
	}
	request := vnextReaderActivationRequestIdentity{
		Acquired: acquired, ActivationRequestID: wire.ActivationRequestID,
	}
	if err := validateVNextReaderActivationRequestIdentity(request); err != nil {
		return vnextReaderActivationProposalRequest{}, err
	}
	authority, err := wire.Authority.internal()
	if err != nil {
		return vnextReaderActivationProposalRequest{}, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(
		vnextReaderActivationProposalSpec, authority); err != nil {
		return vnextReaderActivationProposalRequest{}, err
	}
	if authority.RequestDigest !=
		vnextReaderActivationCanonicalProposalRequestDigest(request) {
		return vnextReaderActivationProposalRequest{},
			errors.New("Reader activation proposal authority digest differs from payload")
	}
	return vnextReaderActivationProposalRequest{
		Request: request, Authority: authority,
	}, nil
}

func marshalVNextReaderActivationProposalRequest(
	request vnextReaderActivationProposalRequest,
) ([]byte, error) {
	if err := validateVNextReaderActivationRequestIdentity(request.Request); err != nil {
		return nil, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(
		vnextReaderActivationProposalSpec, request.Authority); err != nil {
		return nil, err
	}
	if request.Authority.RequestDigest !=
		vnextReaderActivationCanonicalProposalRequestDigest(request.Request) {
		return nil, errors.New("Reader activation proposal authority does not bind payload")
	}
	wire := vnextReaderActivationProposalRequestWire{
		Protocol:            vnextReaderActivationProposalProtocol,
		Operation:           vnextReaderActivationProposalOperation,
		Acquired:            vnextReaderPrepareAcquiredWireFromInternal(request.Request.Acquired),
		ActivationRequestID: request.Request.ActivationRequestID,
		Authority:           vnextReaderActivationAuthorityWireFromInternal(request.Authority),
	}
	return marshalBoundedVNextReaderActivationJSON(
		vnextReaderActivationProposalSpec, wire)
}

func marshalVNextReaderActivationProposalResponse(
	response vnextReaderActivationProposalResponse,
) ([]byte, error) {
	if err := validateVNextReaderActivationProposalResponse(response); err != nil {
		return nil, err
	}
	wire := vnextReaderActivationProposalResponseWire{
		Protocol:                  vnextReaderActivationProposalProtocol,
		Operation:                 vnextReaderActivationProposalOperation,
		RequestDigest:             hex.EncodeToString(response.RequestDigest[:]),
		AuthorityProof:            vnextReaderActivationAuthorityProofWireFromInternal(response.AuthorityProof),
		LocalExecutorNodeID:       response.LocalExecutorNodeID,
		LocalCxldLogicalID:        response.LocalCxldLogicalID,
		LocalProcessIncarnationID: response.LocalProcessIncarnation.String(),
		State:                     string(response.State),
		Disposition:               vnextReaderActivationProposalDispositionName(response.Disposition),
		Acquired:                  vnextReaderPrepareAcquiredWireFromInternal(response.Acquired),
		Activation:                vnextReaderActivationEvidenceWireFromInternal(response.Activation),
		Receipt:                   hex.EncodeToString(response.Receipt[:]),
	}
	return marshalBoundedVNextReaderActivationJSON(
		vnextReaderActivationProposalSpec, wire)
}

func decodeVNextReaderActivationProposalResponse(
	raw []byte,
) (vnextReaderActivationProposalResponse, error) {
	var wire vnextReaderActivationProposalResponseWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderActivationProposalSpec, raw, &wire); err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	if wire.Protocol != vnextReaderActivationProposalProtocol ||
		wire.Operation != vnextReaderActivationProposalOperation ||
		wire.State != string(vnextReaderActivationPending) {
		return vnextReaderActivationProposalResponse{},
			errors.New("Reader activation proposal response protocol, operation, or state is invalid")
	}
	disposition, ok := vnextReaderActivationProposalDispositionFromName(wire.Disposition)
	if !ok {
		return vnextReaderActivationProposalResponse{},
			errors.New("Reader activation proposal response disposition is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	identity := vnextReaderActivationRequestIdentity{
		Acquired: acquired, ActivationRequestID: wire.Activation.ActivationRequestID,
	}
	activation, err := wire.Activation.internal(identity, vnextReaderActivationPending)
	if err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	proof, err := wire.AuthorityProof.internal()
	if err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	process, err := parseVNextReaderProcessIncarnation(wire.LocalProcessIncarnationID)
	if err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation proposal response request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation proposal response receipt", wire.Receipt)
	if err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	response := vnextReaderActivationProposalResponse{
		RequestDigest: digest, AuthorityProof: proof,
		LocalExecutorNodeID:     wire.LocalExecutorNodeID,
		LocalCxldLogicalID:      wire.LocalCxldLogicalID,
		LocalProcessIncarnation: process,
		State:                   vnextReaderActivationPending, Disposition: disposition,
		Acquired: acquired, Activation: activation, Receipt: receipt,
	}
	if err := validateVNextReaderActivationProposalResponse(response); err != nil {
		return vnextReaderActivationProposalResponse{}, err
	}
	return response, nil
}

func validateVNextReaderActivationProposalResponse(
	response vnextReaderActivationProposalResponse,
) error {
	request := vnextReaderActivationRequestIdentity{
		Acquired:            response.Acquired,
		ActivationRequestID: response.Activation.Request.ActivationRequestID,
	}
	if response.State != vnextReaderActivationPending ||
		vnextReaderActivationProposalDispositionName(response.Disposition) == "" {
		return errors.New("Reader activation proposal response state or disposition is invalid")
	}
	if err := validateVNextReaderActivationRequestIdentity(request); err != nil {
		return err
	}
	if err := validateVNextReaderActivationEvidence(response.Activation, request); err != nil {
		return err
	}
	if err := validateVNextReaderActivationResponseCommon(
		response.RequestDigest, response.AuthorityProof,
		response.LocalExecutorNodeID, response.LocalCxldLogicalID,
		response.LocalProcessIncarnation, request); err != nil {
		return err
	}
	if response.RequestDigest !=
		vnextReaderActivationCanonicalProposalRequestDigest(request) {
		return errors.New(
			"Reader activation proposal response request digest is inconsistent")
	}
	wantStable := vnextReaderActivationCanonicalEvidenceReceipt(
		response.Activation, response.LocalExecutorNodeID,
		response.LocalCxldLogicalID, response.LocalProcessIncarnation)
	if response.Activation.CxldReceipt != wantStable {
		return errors.New("Reader activation proposal stable receipt is inconsistent")
	}
	if response.Receipt != vnextReaderActivationCanonicalProposalReceipt(response) {
		return errors.New("Reader activation proposal response receipt is inconsistent")
	}
	return nil
}

func decodeVNextReaderActivationCommitRequest(
	raw []byte,
) (vnextReaderActivationCommitRequest, error) {
	var wire vnextReaderActivationCommitRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderActivationCommitSpec, raw, &wire); err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	if wire.Protocol != vnextReaderActivationCommitProtocol ||
		wire.Operation != vnextReaderActivationCommitOperation {
		return vnextReaderActivationCommitRequest{},
			errors.New("Reader activation commit protocol or operation is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	identity := vnextReaderActivationRequestIdentity{
		Acquired: acquired, ActivationRequestID: wire.Activation.ActivationRequestID,
	}
	if err := validateVNextReaderActivationRequestIdentity(identity); err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	activation, err := wire.Activation.internal(identity, vnextReaderActivationPending)
	if err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	activeState := vnextReaderActivationActiveState{
		CatalogState:   vnextReaderCatalogAuthorizationState(wire.ActiveState.CatalogState),
		LastMutationID: wire.ActiveState.LastMutationID,
	}
	if err := validateVNextReaderActivationActiveState(
		activeState, identity.ActivationRequestID); err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	authority, err := wire.Authority.internal()
	if err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(
		vnextReaderActivationCommitSpec, authority); err != nil {
		return vnextReaderActivationCommitRequest{}, err
	}
	digest := vnextReaderActivationCanonicalCommitRequestDigest(
		acquired, activation, activeState)
	if authority.RequestDigest != digest {
		return vnextReaderActivationCommitRequest{},
			errors.New("Reader activation commit authority digest differs from payload")
	}
	return vnextReaderActivationCommitRequest{
		Acquired: acquired, Activation: activation,
		ActiveState: activeState, Authority: authority,
	}, nil
}

func marshalVNextReaderActivationCommitRequest(
	request vnextReaderActivationCommitRequest,
) ([]byte, error) {
	identity := vnextReaderActivationRequestIdentity{
		Acquired:            request.Acquired,
		ActivationRequestID: request.Activation.Request.ActivationRequestID,
	}
	if err := validateVNextReaderActivationRequestIdentity(identity); err != nil {
		return nil, err
	}
	if err := validateVNextReaderActivationEvidence(request.Activation, identity); err != nil {
		return nil, err
	}
	if request.Activation.State != vnextReaderActivationPending {
		return nil, errors.New("Reader activation commit evidence is not PENDING")
	}
	if err := validateVNextReaderActivationActiveState(
		request.ActiveState, identity.ActivationRequestID); err != nil {
		return nil, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(
		vnextReaderActivationCommitSpec, request.Authority); err != nil {
		return nil, err
	}
	if request.Authority.RequestDigest !=
		vnextReaderActivationCanonicalCommitRequestDigest(
			request.Acquired, request.Activation, request.ActiveState) {
		return nil, errors.New("Reader activation commit authority does not bind payload")
	}
	wire := vnextReaderActivationCommitRequestWire{
		Protocol:    vnextReaderActivationCommitProtocol,
		Operation:   vnextReaderActivationCommitOperation,
		Acquired:    vnextReaderPrepareAcquiredWireFromInternal(request.Acquired),
		Activation:  vnextReaderActivationEvidenceWireFromInternal(request.Activation),
		ActiveState: vnextReaderActivationActiveStateWireFromInternal(request.ActiveState),
		Authority:   vnextReaderActivationAuthorityWireFromInternal(request.Authority),
	}
	return marshalBoundedVNextReaderActivationJSON(vnextReaderActivationCommitSpec, wire)
}

func marshalVNextReaderActivationCommitResponse(
	response vnextReaderActivationCommitResponse,
) ([]byte, error) {
	if err := validateVNextReaderActivationCommitResponse(response); err != nil {
		return nil, err
	}
	wire := vnextReaderActivationCommitResponseWire{
		Protocol:                  vnextReaderActivationCommitProtocol,
		Operation:                 vnextReaderActivationCommitOperation,
		RequestDigest:             hex.EncodeToString(response.RequestDigest[:]),
		AuthorityProof:            vnextReaderActivationAuthorityProofWireFromInternal(response.AuthorityProof),
		LocalExecutorNodeID:       response.LocalExecutorNodeID,
		LocalCxldLogicalID:        response.LocalCxldLogicalID,
		LocalProcessIncarnationID: response.LocalProcessIncarnation.String(),
		State:                     string(response.State),
		Disposition:               vnextReaderActivationCommitDispositionName(response.Disposition),
		Acquired:                  vnextReaderPrepareAcquiredWireFromInternal(response.Acquired),
		Activation:                vnextReaderActivationEvidenceWireFromInternal(response.Activation),
		ActiveState:               vnextReaderActivationActiveStateWireFromInternal(response.ActiveState),
		Receipt:                   hex.EncodeToString(response.Receipt[:]),
	}
	return marshalBoundedVNextReaderActivationJSON(vnextReaderActivationCommitSpec, wire)
}

func decodeVNextReaderActivationCommitResponse(
	raw []byte,
) (vnextReaderActivationCommitResponse, error) {
	var wire vnextReaderActivationCommitResponseWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderActivationCommitSpec, raw, &wire); err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	if wire.Protocol != vnextReaderActivationCommitProtocol ||
		wire.Operation != vnextReaderActivationCommitOperation ||
		wire.State != string(vnextReaderActivationActiveArmed) {
		return vnextReaderActivationCommitResponse{},
			errors.New("Reader activation commit response protocol, operation, or state is invalid")
	}
	disposition, ok := vnextReaderActivationCommitDispositionFromName(wire.Disposition)
	if !ok {
		return vnextReaderActivationCommitResponse{},
			errors.New("Reader activation commit response disposition is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	identity := vnextReaderActivationRequestIdentity{
		Acquired: acquired, ActivationRequestID: wire.Activation.ActivationRequestID,
	}
	activation, err := wire.Activation.internal(identity, vnextReaderActivationActiveArmed)
	if err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	activeState := vnextReaderActivationActiveState{
		CatalogState:   vnextReaderCatalogAuthorizationState(wire.ActiveState.CatalogState),
		LastMutationID: wire.ActiveState.LastMutationID,
	}
	proof, err := wire.AuthorityProof.internal()
	if err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	process, err := parseVNextReaderProcessIncarnation(wire.LocalProcessIncarnationID)
	if err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation commit response request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation commit response receipt", wire.Receipt)
	if err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	response := vnextReaderActivationCommitResponse{
		RequestDigest: digest, AuthorityProof: proof,
		LocalExecutorNodeID:     wire.LocalExecutorNodeID,
		LocalCxldLogicalID:      wire.LocalCxldLogicalID,
		LocalProcessIncarnation: process,
		State:                   vnextReaderActivationActiveArmed,
		Disposition:             disposition, Acquired: acquired,
		Activation: activation, ActiveState: activeState, Receipt: receipt,
	}
	if err := validateVNextReaderActivationCommitResponse(response); err != nil {
		return vnextReaderActivationCommitResponse{}, err
	}
	return response, nil
}

func validateVNextReaderActivationCommitResponse(
	response vnextReaderActivationCommitResponse,
) error {
	request := vnextReaderActivationRequestIdentity{
		Acquired:            response.Acquired,
		ActivationRequestID: response.Activation.Request.ActivationRequestID,
	}
	if response.State != vnextReaderActivationActiveArmed ||
		vnextReaderActivationCommitDispositionName(response.Disposition) == "" {
		return errors.New("Reader activation commit response state or disposition is invalid")
	}
	if err := validateVNextReaderActivationRequestIdentity(request); err != nil {
		return err
	}
	if err := validateVNextReaderActivationEvidence(response.Activation, request); err != nil {
		return err
	}
	if err := validateVNextReaderActivationActiveState(
		response.ActiveState, request.ActivationRequestID); err != nil {
		return err
	}
	if err := validateVNextReaderActivationResponseCommon(
		response.RequestDigest, response.AuthorityProof,
		response.LocalExecutorNodeID, response.LocalCxldLogicalID,
		response.LocalProcessIncarnation, request); err != nil {
		return err
	}
	wantStable := vnextReaderActivationCanonicalEvidenceReceipt(
		response.Activation, response.LocalExecutorNodeID,
		response.LocalCxldLogicalID, response.LocalProcessIncarnation)
	if response.Activation.CxldReceipt != wantStable {
		return errors.New("Reader activation commit stable receipt is inconsistent")
	}
	wantDigest := vnextReaderActivationCanonicalCommitRequestDigest(
		response.Acquired, response.Activation, response.ActiveState)
	if response.RequestDigest != wantDigest {
		return errors.New("Reader activation commit response request digest is inconsistent")
	}
	if response.Receipt != vnextReaderActivationCanonicalCommitReceipt(response) {
		return errors.New("Reader activation commit response receipt is inconsistent")
	}
	return nil
}

func decodeVNextReaderActivationStatusRequest(
	raw []byte,
) (vnextReaderActivationStatusRequest, error) {
	var wire vnextReaderActivationStatusRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderActivationStatusSpec, raw, &wire); err != nil {
		return vnextReaderActivationStatusRequest{}, err
	}
	if wire.Protocol != vnextReaderActivationStatusProtocol ||
		wire.Operation != vnextReaderActivationStatusOperation {
		return vnextReaderActivationStatusRequest{},
			errors.New("Reader activation status protocol or operation is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivationStatusRequest{}, err
	}
	request := vnextReaderActivationRequestIdentity{
		Acquired: acquired, ActivationRequestID: wire.ActivationRequestID,
	}
	if err := validateVNextReaderActivationRequestIdentity(request); err != nil {
		return vnextReaderActivationStatusRequest{}, err
	}
	authority, err := wire.Authority.internal()
	if err != nil {
		return vnextReaderActivationStatusRequest{}, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(
		vnextReaderActivationStatusSpec, authority); err != nil {
		return vnextReaderActivationStatusRequest{}, err
	}
	if authority.RequestDigest !=
		vnextReaderActivationCanonicalStatusRequestDigest(request) {
		return vnextReaderActivationStatusRequest{},
			errors.New("Reader activation status authority digest differs from payload")
	}
	return vnextReaderActivationStatusRequest{
		Request: request, Authority: authority,
	}, nil
}

func marshalVNextReaderActivationStatusRequest(
	request vnextReaderActivationStatusRequest,
) ([]byte, error) {
	if err := validateVNextReaderActivationRequestIdentity(request.Request); err != nil {
		return nil, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(
		vnextReaderActivationStatusSpec, request.Authority); err != nil {
		return nil, err
	}
	if request.Authority.RequestDigest !=
		vnextReaderActivationCanonicalStatusRequestDigest(request.Request) {
		return nil, errors.New("Reader activation status authority does not bind payload")
	}
	wire := vnextReaderActivationStatusRequestWire{
		Protocol:            vnextReaderActivationStatusProtocol,
		Operation:           vnextReaderActivationStatusOperation,
		Acquired:            vnextReaderPrepareAcquiredWireFromInternal(request.Request.Acquired),
		ActivationRequestID: request.Request.ActivationRequestID,
		Authority:           vnextReaderActivationAuthorityWireFromInternal(request.Authority),
	}
	return marshalBoundedVNextReaderActivationJSON(vnextReaderActivationStatusSpec, wire)
}

func marshalVNextReaderActivationStatusResponse(
	response vnextReaderActivationStatusResponse,
) ([]byte, error) {
	if err := validateVNextReaderActivationStatusResponse(response); err != nil {
		return nil, err
	}
	var activation *vnextReaderActivationEvidenceWire
	if response.Activation != nil {
		wire := vnextReaderActivationEvidenceWireFromInternal(*response.Activation)
		activation = &wire
	}
	var activeState *vnextReaderActivationActiveStateWire
	if response.ActiveState != nil {
		wire := vnextReaderActivationActiveStateWireFromInternal(*response.ActiveState)
		activeState = &wire
	}
	wire := vnextReaderActivationStatusResponseWire{
		Protocol:                  vnextReaderActivationStatusProtocol,
		Operation:                 vnextReaderActivationStatusOperation,
		RequestDigest:             hex.EncodeToString(response.RequestDigest[:]),
		AuthorityProof:            vnextReaderActivationAuthorityProofWireFromInternal(response.AuthorityProof),
		LocalExecutorNodeID:       response.LocalExecutorNodeID,
		LocalCxldLogicalID:        response.LocalCxldLogicalID,
		LocalProcessIncarnationID: response.LocalProcessIncarnation.String(),
		State:                     string(response.State),
		Acquired:                  vnextReaderPrepareAcquiredWireFromInternal(response.Acquired),
		Activation:                activation, ActiveState: activeState,
		Receipt: hex.EncodeToString(response.Receipt[:]),
	}
	return marshalBoundedVNextReaderActivationJSON(vnextReaderActivationStatusSpec, wire)
}

func decodeVNextReaderActivationStatusResponse(
	raw []byte,
) (vnextReaderActivationStatusResponse, error) {
	var wire vnextReaderActivationStatusResponseWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderActivationStatusSpec, raw, &wire); err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	if wire.Protocol != vnextReaderActivationStatusProtocol ||
		wire.Operation != vnextReaderActivationStatusOperation {
		return vnextReaderActivationStatusResponse{},
			errors.New("Reader activation status response protocol or operation is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	proof, err := wire.AuthorityProof.internal()
	if err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	process, err := parseVNextReaderProcessIncarnation(wire.LocalProcessIncarnationID)
	if err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation status response request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation status response receipt", wire.Receipt)
	if err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	state := vnextReaderActivationStatusState(wire.State)
	response := vnextReaderActivationStatusResponse{
		RequestDigest: digest, AuthorityProof: proof,
		LocalExecutorNodeID:     wire.LocalExecutorNodeID,
		LocalCxldLogicalID:      wire.LocalCxldLogicalID,
		LocalProcessIncarnation: process,
		State:                   state, Acquired: acquired, Receipt: receipt,
	}
	if wire.Activation != nil {
		identity := vnextReaderActivationRequestIdentity{
			Acquired:            acquired,
			ActivationRequestID: wire.Activation.ActivationRequestID,
		}
		intentState := vnextReaderActivationPending
		if state == vnextReaderActivationStatusArmedState {
			intentState = vnextReaderActivationActiveArmed
		}
		activation, err := wire.Activation.internal(identity, intentState)
		if err != nil {
			return vnextReaderActivationStatusResponse{}, err
		}
		response.Activation = &activation
	}
	if wire.ActiveState != nil {
		active := vnextReaderActivationActiveState{
			CatalogState:   vnextReaderCatalogAuthorizationState(wire.ActiveState.CatalogState),
			LastMutationID: wire.ActiveState.LastMutationID,
		}
		response.ActiveState = &active
	}
	if err := validateVNextReaderActivationStatusResponse(response); err != nil {
		return vnextReaderActivationStatusResponse{}, err
	}
	return response, nil
}

func validateVNextReaderActivationStatusResponse(
	response vnextReaderActivationStatusResponse,
) error {
	if err := validateVNextReaderAcquiredAuthorizationStructure(
		response.Acquired); err != nil {
		return err
	}
	var activationRequestID string
	if response.Activation != nil {
		activationRequestID = response.Activation.Request.ActivationRequestID
	} else {
		// The request ID is bound by RequestDigest and the outer receipt even
		// though the null response payload deliberately does not echo it as a
		// separate field.
		activationRequestID = response.Acquired.Authorization.RestoreAuthorizationID
	}
	request := vnextReaderActivationRequestIdentity{
		Acquired: response.Acquired, ActivationRequestID: activationRequestID,
	}
	if err := validateVNextReaderActivationResponseCommon(
		response.RequestDigest, response.AuthorityProof,
		response.LocalExecutorNodeID, response.LocalCxldLogicalID,
		response.LocalProcessIncarnation, request); err != nil {
		// For null STATUS payloads the request ID cannot be recovered from the
		// response alone, so only common structural proof checks are possible.
		if response.Activation != nil {
			return err
		}
		if err := validateVNextReaderActivationResponseProofOnly(
			response.RequestDigest, response.AuthorityProof,
			response.LocalExecutorNodeID, response.LocalCxldLogicalID,
			response.LocalProcessIncarnation); err != nil {
			return err
		}
	}
	switch response.State {
	case vnextReaderActivationStatusNotFoundState,
		vnextReaderActivationStatusConflictState:
		if response.Activation != nil || response.ActiveState != nil {
			return errors.New("Reader activation terminal status must have null payloads")
		}
		if response.LocalExecutorNodeID != response.Acquired.Authorization.ExecutorID ||
			response.LocalCxldLogicalID != response.Acquired.Authorization.CxldLogicalID ||
			response.LocalProcessIncarnation !=
				response.Acquired.Authorization.CxldProcessIncarnationID {
			return errors.New(
				"Reader activation NOT_FOUND/CONFLICT local identity differs from ACQUIRED")
		}
	case vnextReaderActivationStatusIncarnationMismatchState:
		if response.Activation != nil || response.ActiveState != nil {
			return errors.New("Reader activation incarnation mismatch must have null payloads")
		}
		if response.LocalExecutorNodeID != response.Acquired.Authorization.ExecutorID ||
			response.LocalCxldLogicalID != response.Acquired.Authorization.CxldLogicalID ||
			response.LocalProcessIncarnation ==
				response.Acquired.Authorization.CxldProcessIncarnationID {
			return errors.New(
				"Reader activation incarnation mismatch has invalid local identity relation")
		}
	case vnextReaderActivationStatusPendingState:
		if response.Activation == nil || response.ActiveState != nil ||
			response.Activation.State != vnextReaderActivationPending {
			return errors.New("Reader activation PENDING status payload is invalid")
		}
	case vnextReaderActivationStatusArmedState:
		if response.Activation == nil || response.ActiveState == nil ||
			response.Activation.State != vnextReaderActivationActiveArmed {
			return errors.New("Reader activation ACTIVE_ARMED status payload is invalid")
		}
		if err := validateVNextReaderActivationActiveState(
			*response.ActiveState,
			response.Activation.Request.ActivationRequestID); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Reader activation STATUS state %q is invalid", response.State)
	}
	if response.Activation != nil {
		request := response.Activation.Request
		if err := validateVNextReaderActivationEvidence(
			*response.Activation, request); err != nil {
			return err
		}
		wantStable := vnextReaderActivationCanonicalEvidenceReceipt(
			*response.Activation, response.LocalExecutorNodeID,
			response.LocalCxldLogicalID, response.LocalProcessIncarnation)
		if response.Activation.CxldReceipt != wantStable {
			return errors.New("Reader activation STATUS stable receipt is inconsistent")
		}
	}
	if response.Receipt != vnextReaderActivationCanonicalStatusReceipt(response) {
		return errors.New("Reader activation STATUS response receipt is inconsistent")
	}
	return nil
}

func validateVNextReaderActivationResponseCommon(
	requestDigest [sha256.Size]byte,
	proof vnextReaderActivationAuthorityProof,
	localExecutorNodeID string,
	localCxldLogicalID string,
	localProcess vnextReaderProcessIncarnation,
	request vnextReaderActivationRequestIdentity,
) error {
	if err := validateVNextReaderActivationRequestIdentity(request); err != nil {
		return err
	}
	if localExecutorNodeID != request.Acquired.Authorization.ExecutorID ||
		localCxldLogicalID != request.Acquired.Authorization.CxldLogicalID ||
		localProcess != request.Acquired.Authorization.CxldProcessIncarnationID {
		return errors.New("Reader activation response local identity differs from ACQUIRED")
	}
	return validateVNextReaderActivationResponseProofOnly(
		requestDigest, proof, localExecutorNodeID, localCxldLogicalID, localProcess)
}

func validateVNextReaderActivationResponseProofOnly(
	requestDigest [sha256.Size]byte,
	proof vnextReaderActivationAuthorityProof,
	localExecutorNodeID string,
	localCxldLogicalID string,
	localProcess vnextReaderProcessIncarnation,
) error {
	if err := validateVNextReaderIdentity(
		"Reader activation response local executor", localExecutorNodeID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"Reader activation response local cxld", localCxldLogicalID); err != nil {
		return err
	}
	if err := validateVNextReaderProcessIncarnation(localProcess); err != nil {
		return err
	}
	if allVNextReaderZero(requestDigest[:]) ||
		proof.RequestDigest != requestDigest ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) {
		return errors.New("Reader activation response proof or request digest is incomplete")
	}
	if err := validateVNextReaderPreparePrincipalURI(
		proof.AuthenticatedSchedulerPrincipal); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"Reader activation response Scheduler ID", proof.SchedulerID); err != nil {
		return err
	}
	if proof.SchedulerFenceRevision == 0 ||
		proof.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		proof.LeaderLeaseID == 0 ||
		proof.LeaderLeaseID > cxlcheckpoint.MaxSignedLong ||
		allVNextReaderZero(proof.LeaderTermID[:]) {
		return errors.New("Reader activation response authority proof is incomplete")
	}
	return nil
}

type vnextReaderActivationProposalRPC struct {
	service        *vnextReaderActivationService
	encodeResponse func(vnextReaderActivationProposalResponse) ([]byte, error)
}

type vnextReaderActivationCommitRPC struct {
	service        *vnextReaderActivationService
	encodeResponse func(vnextReaderActivationCommitResponse) ([]byte, error)
}

type vnextReaderActivationStatusRPC struct {
	service        *vnextReaderActivationService
	encodeResponse func(vnextReaderActivationStatusResponse) ([]byte, error)
}

func newVNextReaderActivationProposalRPC(
	service *vnextReaderActivationService,
) *vnextReaderActivationProposalRPC {
	if service == nil {
		return nil
	}
	return &vnextReaderActivationProposalRPC{
		service: service, encodeResponse: marshalVNextReaderActivationProposalResponse,
	}
}

func newVNextReaderActivationCommitRPC(
	service *vnextReaderActivationService,
) *vnextReaderActivationCommitRPC {
	if service == nil {
		return nil
	}
	return &vnextReaderActivationCommitRPC{
		service: service, encodeResponse: marshalVNextReaderActivationCommitResponse,
	}
}

func newVNextReaderActivationStatusRPC(
	service *vnextReaderActivationService,
) *vnextReaderActivationStatusRPC {
	if service == nil {
		return nil
	}
	return &vnextReaderActivationStatusRPC{
		service: service, encodeResponse: marshalVNextReaderActivationStatusResponse,
	}
}

func (rpc *vnextReaderActivationProposalRPC) Handle(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	frame []byte,
) ([]byte, *vnextReaderActivationRPCError) {
	spec := vnextReaderActivationProposalSpec
	if rpc == nil || rpc.service == nil || rpc.encodeResponse == nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted,
			errors.New("VNext Reader activation proposal RPC is unavailable"))
	}
	request, err := decodeVNextReaderActivationProposalRequest(frame)
	if err != nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted, err)
	}
	response, failure := rpc.service.Propose(
		ctx, authenticatedSchedulerPrincipal, request)
	if failure != nil {
		return nil, failure
	}
	body, err := rpc.encodeResponse(response)
	if err != nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationAcceptanceUnknown,
			fmt.Errorf("encode accepted activation proposal response: %w", err))
	}
	return body, nil
}

func (rpc *vnextReaderActivationCommitRPC) Handle(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	frame []byte,
) ([]byte, *vnextReaderActivationRPCError) {
	spec := vnextReaderActivationCommitSpec
	if rpc == nil || rpc.service == nil || rpc.encodeResponse == nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted,
			errors.New("VNext Reader activation commit RPC is unavailable"))
	}
	request, err := decodeVNextReaderActivationCommitRequest(frame)
	if err != nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted, err)
	}
	response, failure := rpc.service.Commit(
		ctx, authenticatedSchedulerPrincipal, request)
	if failure != nil {
		return nil, failure
	}
	body, err := rpc.encodeResponse(response)
	if err != nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationAcceptanceUnknown,
			fmt.Errorf("encode accepted activation commit response: %w", err))
	}
	return body, nil
}

func (rpc *vnextReaderActivationStatusRPC) Handle(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	frame []byte,
) ([]byte, *vnextReaderActivationRPCError) {
	spec := vnextReaderActivationStatusSpec
	if rpc == nil || rpc.service == nil || rpc.encodeResponse == nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted,
			errors.New("VNext Reader activation status RPC is unavailable"))
	}
	request, err := decodeVNextReaderActivationStatusRequest(frame)
	if err != nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted, err)
	}
	response, failure := rpc.service.Status(
		ctx, authenticatedSchedulerPrincipal, request)
	if failure != nil {
		return nil, failure
	}
	body, err := rpc.encodeResponse(response)
	if err != nil {
		return nil, vnextReaderActivationFailure(spec, vnextReaderActivationUnavailable,
			vnextReaderActivationAcceptanceUnknown,
			fmt.Errorf("encode accepted activation status response: %w", err))
	}
	return body, nil
}
