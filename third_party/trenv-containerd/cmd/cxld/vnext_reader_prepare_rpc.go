package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
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
	// Reader PREPARE is deliberately not an Owner operation or an Owner TLS
	// route. A future authenticated transport must negotiate this distinct ALPN
	// and pass the authenticated Scheduler principal to Handle.
	vnextReaderPrepareProtocol  = "cxld.vnext-reader-prepare.v1"
	vnextReaderPrepareOperation = "vnextReaderPrepareAuthorization"
	vnextReaderPrepareALPN      = "cxld-vnext-reader/1"

	vnextReaderPrepareAuthorityDomain          = "cxld-vnext-reader-prepare-authority-v1"
	vnextReaderPrepareAuthoritySignatureDomain = "cxld-vnext-reader-prepare-authority-signature-v1"
	vnextReaderPrepareAuthorityReceiptDomain   = "cxld-vnext-reader-prepare-authority-receipt-v1"
	vnextReaderPrepareRequestDigestDomain      = "cxld-vnext-reader-prepare-request-digest-v1"
	vnextReaderPrepareReceiptDomain            = "cxld-vnext-reader-prepare-receipt-v1"

	// Two maximum-size portable identities per locator run require a little
	// over two MiB before encoding. encoding/json HTML-escapes '<', '>', and
	// '&' to six bytes each, so the valid 256-run worst case is under 13 MiB.
	// Sixteen MiB carries every structurally valid identity while keeping the
	// complete request/response allocation bounded.
	vnextReaderPrepareMaxFrameBytes   = 16 << 20
	vnextReaderPrepareMaxObjectFields = 16
)

type vnextReaderPrepareAuthorityEnvelope struct {
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

// vnextReaderPrepareAuthorityProof is produced only by a fail-closed
// Reader-domain verifier after it has authenticated the peer and established
// current leader/fence authority. It is not an Owner Scheduler proof and does
// not grant DAX, ACTIVE, CRIU, or release authority.
type vnextReaderPrepareAuthorityProof struct {
	AuthenticatedSchedulerPrincipal string
	SchedulerID                     string
	SchedulerFenceRevision          uint64
	LeaderLeaseID                   uint64
	LeaderTermID                    [sha256.Size]byte
	RequestDigest                   [sha256.Size]byte
	AuthorityReceipt                [sha256.Size]byte
}

// vnextReaderPrepareAuthorityVerifier has intentionally no function adapter,
// permissive implementation, or production fallback. A later transport must
// provide a concrete verifier backed by its authenticated Scheduler channel
// and a linearizable current-leader/fence source. That implementation must:
//   - bind the authenticated principal to the current Scheduler identity;
//   - verify Signature over vnextReaderPrepareAuthoritySignaturePreimage using
//     the current leader key identified by KeyID;
//   - match cluster, Scheduler, fence/create revision, lease, term, key, and
//     request digest to that one current leader snapshot; and
//   - return vnextReaderPrepareCanonicalAuthorityReceipt, which binds the
//     authenticated principal and the complete envelope including Signature.
//
// Merely decoding the envelope or accepting its self-asserted fields does not
// satisfy this interface's security contract.
type vnextReaderPrepareAuthorityVerifier interface {
	VerifyVNextReaderPrepareAuthority(
		context.Context,
		string,
		[sha256.Size]byte,
		vnextReaderPrepareAuthorityEnvelope,
	) (vnextReaderPrepareAuthorityProof, error)
}

// vnextReaderPrepareClock is receiver-local. Wire input can never select the
// instant used for the ACQUIRED half-open validity check.
type vnextReaderPrepareClock interface {
	NowEpochMillis() int64
}

type vnextReaderPrepareRequest struct {
	Acquired  vnextReaderAcquiredAuthorization
	Authority vnextReaderPrepareAuthorityEnvelope
}

type vnextReaderPrepareResponse struct {
	RequestDigest       [sha256.Size]byte
	AuthorityProof      vnextReaderPrepareAuthorityProof
	LocalExecutorNodeID string
	LocalCxldInstanceID string
	Prepared            vnextReaderPreparedAuthorization
	Disposition         vnextReaderPreparationDisposition
	Receipt             [sha256.Size]byte
}

type vnextReaderPrepareErrorCode string

const (
	vnextReaderPrepareInvalidRequest vnextReaderPrepareErrorCode = "INVALID_REQUEST"
	vnextReaderPrepareAuthorityError vnextReaderPrepareErrorCode = "AUTHORITY_REJECTED"
	vnextReaderPrepareIdentityError  vnextReaderPrepareErrorCode = "IDENTITY_REJECTED"
	vnextReaderPrepareConflictError  vnextReaderPrepareErrorCode = "CONFLICT"
	vnextReaderPrepareCapacityError  vnextReaderPrepareErrorCode = "CAPACITY_EXHAUSTED"
	vnextReaderPrepareUnavailable    vnextReaderPrepareErrorCode = "UNAVAILABLE"
)

type vnextReaderPrepareAcceptance string

const (
	// A definitive rejection is safe only when the service knows no PREPARED
	// entry was installed by this call.
	vnextReaderPrepareDefinitelyNotAccepted vnextReaderPrepareAcceptance = "DEFINITELY_NOT_ACCEPTED"
	// UNKNOWN is deliberately ambiguous. In particular, it is used when the
	// store accepted PREPARED but the response could not be encoded.
	vnextReaderPrepareAcceptanceUnknown vnextReaderPrepareAcceptance = "UNKNOWN"
)

type vnextReaderPrepareRPCError struct {
	Code       vnextReaderPrepareErrorCode
	Acceptance vnextReaderPrepareAcceptance
	Cause      error
}

func (failure *vnextReaderPrepareRPCError) Error() string {
	if failure == nil {
		return "VNext Reader PREPARE failure is unavailable"
	}
	return fmt.Sprintf("VNext Reader PREPARE %s (%s): %v",
		failure.Code, failure.Acceptance, failure.Cause)
}

func (failure *vnextReaderPrepareRPCError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

func vnextReaderPrepareFailure(
	code vnextReaderPrepareErrorCode,
	acceptance vnextReaderPrepareAcceptance,
	cause error,
) *vnextReaderPrepareRPCError {
	if cause == nil {
		cause = errors.New("unspecified VNext Reader PREPARE failure")
	}
	return &vnextReaderPrepareRPCError{
		Code: code, Acceptance: acceptance, Cause: cause,
	}
}

type vnextReaderPrepareService struct {
	localExecutorNodeID string
	localCxldInstanceID string
	store               *vnextReaderAuthorizationStore
	clock               vnextReaderPrepareClock
	authorityVerifier   vnextReaderPrepareAuthorityVerifier
}

func newVNextReaderPrepareService(
	localExecutorNodeID string,
	localCxldInstanceID string,
	store *vnextReaderAuthorizationStore,
	clock vnextReaderPrepareClock,
	authorityVerifier vnextReaderPrepareAuthorityVerifier,
) (*vnextReaderPrepareService, error) {
	if err := validateVNextReaderIdentity(
		"local Reader executor node ID", localExecutorNodeID); err != nil {
		return nil, err
	}
	if err := validateVNextReaderIdentity(
		"local Reader cxld instance ID", localCxldInstanceID); err != nil {
		return nil, err
	}
	if store == nil {
		return nil, errors.New("VNext Reader PREPARE authorization store is unavailable")
	}
	if clock == nil {
		return nil, errors.New("VNext Reader PREPARE local clock is unavailable")
	}
	if authorityVerifier == nil {
		return nil, errors.New("VNext Reader PREPARE authority verifier is unavailable")
	}
	return &vnextReaderPrepareService{
		localExecutorNodeID: cloneVNextReaderRetainedString(localExecutorNodeID),
		localCxldInstanceID: cloneVNextReaderRetainedString(localCxldInstanceID),
		store:               store,
		clock:               clock,
		authorityVerifier:   authorityVerifier,
	}, nil
}

// Prepare verifies an exact durable ACQUIRED record and installs only a
// process-local PREPARED receipt. No field or dependency in this service can
// resolve, open, map, or read DAX, invoke CRIU, mark ACTIVE, or release a hold.
func (service *vnextReaderPrepareService) Prepare(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	request vnextReaderPrepareRequest,
) (vnextReaderPrepareResponse, *vnextReaderPrepareRPCError) {
	if service == nil || service.store == nil || service.clock == nil ||
		service.authorityVerifier == nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareDefinitelyNotAccepted,
			errors.New("VNext Reader PREPARE service is unavailable"))
	}
	if ctx == nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted,
			errors.New("VNext Reader PREPARE context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}
	if err := validateVNextReaderIdentity(
		"authenticated Scheduler principal", authenticatedSchedulerPrincipal); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareAuthorityError,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}

	// Clone before validation so a caller cannot race mutation of PageRuns with
	// digesting, verification, or storage.
	request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
	authenticatedSchedulerPrincipal = cloneVNextReaderRetainedString(
		authenticatedSchedulerPrincipal)

	firstNow := service.clock.NowEpochMillis()
	if err := validateVNextReaderPrepareAcquired(request.Acquired, firstNow); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}
	if request.Acquired.Authorization.ExecutorID != service.localExecutorNodeID ||
		request.Acquired.Authorization.CxldInstanceID != service.localCxldInstanceID {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareIdentityError,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf(
				"authorization targets executor/cxld %q/%q, local identity is %q/%q",
				request.Acquired.Authorization.ExecutorID,
				request.Acquired.Authorization.CxldInstanceID,
				service.localExecutorNodeID,
				service.localCxldInstanceID))
	}
	if err := validateVNextReaderPrepareAuthorityEnvelope(request.Authority); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareAuthorityError,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}
	if request.Authority.SchedulerID != request.Acquired.SchedulerID ||
		request.Authority.SchedulerFenceRevision !=
			request.Acquired.SchedulerFenceRevision {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareAuthorityError,
			vnextReaderPrepareDefinitelyNotAccepted,
			errors.New(
				"Reader authority Scheduler ID or fence differs from the ACQUIRED payload"))
	}
	requestDigest := vnextReaderPrepareCanonicalRequestDigest(request.Acquired)
	if request.Authority.RequestDigest != requestDigest {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareAuthorityError,
			vnextReaderPrepareDefinitelyNotAccepted,
			errors.New("Reader authority envelope has a different request digest"))
	}

	proof, err := service.authorityVerifier.VerifyVNextReaderPrepareAuthority(
		ctx, authenticatedSchedulerPrincipal, requestDigest, request.Authority)
	if err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareAuthorityError,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("verify current Reader Scheduler authority: %w", err))
	}
	if err := validateVNextReaderPrepareAuthorityProof(
		proof,
		authenticatedSchedulerPrincipal,
		requestDigest,
		request.Authority,
		request.Acquired); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareAuthorityError,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}

	// Authority verification may block on a linearizable leader read. Take a
	// fresh receiver-local time immediately before the only store mutation.
	secondNow := service.clock.NowEpochMillis()
	if err := validateVNextReaderPrepareAcquired(request.Acquired, secondNow); err != nil {
		return vnextReaderPrepareResponse{}, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("revalidate ACQUIRED before PREPARED install: %w", err))
	}
	prepared, disposition, err := service.store.Prepare(request.Acquired, secondNow)
	if err != nil {
		return vnextReaderPrepareResponse{}, mapVNextReaderPrepareStoreError(err)
	}
	response := vnextReaderPrepareResponse{
		RequestDigest:       requestDigest,
		AuthorityProof:      cloneVNextReaderPrepareAuthorityProof(proof),
		LocalExecutorNodeID: service.localExecutorNodeID,
		LocalCxldInstanceID: service.localCxldInstanceID,
		Prepared:            prepared,
		Disposition:         disposition,
	}
	response.Receipt = vnextReaderPrepareCanonicalReceipt(response)
	return response, nil
}

func mapVNextReaderPrepareStoreError(err error) *vnextReaderPrepareRPCError {
	code := vnextReaderPrepareInvalidRequest
	acceptance := vnextReaderPrepareDefinitelyNotAccepted
	switch {
	case errors.Is(err, errVNextReaderAuthorizationConflict),
		errors.Is(err, errVNextReaderAuthorizationNotPreparedFenced):
		code = vnextReaderPrepareConflictError
	case errors.Is(err, errVNextReaderAuthorizationStoreFull),
		errors.Is(err, errVNextReaderAuthorizationStoreRetainedBytesFull):
		code = vnextReaderPrepareCapacityError
	case errors.Is(err, errVNextReaderAuthorizationIdentityMismatch),
		errors.Is(err, errVNextReaderAuthorizationNotFound):
		code = vnextReaderPrepareIdentityError
	default:
		// The current store validates and returns before mutation on every
		// documented error. An unknown future error must not be represented as
		// a definitive rejection without preserving that contract explicitly.
		code = vnextReaderPrepareUnavailable
		acceptance = vnextReaderPrepareAcceptanceUnknown
	}
	return vnextReaderPrepareFailure(code, acceptance, err)
}

type vnextReaderPrepareResponseEncoder func(vnextReaderPrepareResponse) ([]byte, error)

type vnextReaderPrepareRPC struct {
	service        *vnextReaderPrepareService
	encodeResponse vnextReaderPrepareResponseEncoder
}

func newVNextReaderPrepareRPC(service *vnextReaderPrepareService) *vnextReaderPrepareRPC {
	if service == nil {
		return nil
	}
	return &vnextReaderPrepareRPC{
		service: service, encodeResponse: marshalVNextReaderPrepareResponse,
	}
}

// Handle is transport-neutral. The authenticated principal is channel
// evidence and is never decoded from the request body. A future listener must
// enforce the distinct Reader ALPN before calling this method.
func (rpc *vnextReaderPrepareRPC) Handle(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	frame []byte,
) ([]byte, *vnextReaderPrepareRPCError) {
	if rpc == nil || rpc.service == nil || rpc.encodeResponse == nil {
		return nil, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareDefinitelyNotAccepted,
			errors.New("VNext Reader PREPARE RPC is unavailable"))
	}
	request, err := decodeVNextReaderPrepareRequest(frame)
	if err != nil {
		return nil, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted, err)
	}
	response, failure := rpc.service.Prepare(
		ctx, authenticatedSchedulerPrincipal, request)
	if failure != nil {
		return nil, failure
	}
	body, err := rpc.encodeResponse(response)
	if err != nil {
		// PREPARED is already stored. Reporting a definitive rejection here
		// would permit an unsafe retry/release decision by the caller.
		return nil, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareAcceptanceUnknown,
			fmt.Errorf("encode accepted VNext Reader PREPARE response: %w", err))
	}
	return body, nil
}

func validateVNextReaderPrepareAcquired(
	acquired vnextReaderAcquiredAuthorization,
	nowEpochMillis int64,
) error {
	return validateVNextReaderPrepareAcquiredAtOptionalTime(
		acquired, &nowEpochMillis)
}

// validateVNextReaderPrepareAcquiredStructure applies the complete portable
// PREPARE ACQUIRED contract without consulting a receiver wall clock. It is
// shared with reconciliation so a malformed record can neither become
// PREPARED nor consume a permanent NOT_PREPARED_FENCED store entry.
func validateVNextReaderPrepareAcquiredStructure(
	acquired vnextReaderAcquiredAuthorization,
) error {
	return validateVNextReaderPrepareAcquiredAtOptionalTime(acquired, nil)
}

// validateVNextReaderPrepareAcquiredAtOptionalTime keeps the time-aware
// PREPARE and clock-free status paths on one structural validation contract.
// A nil validationTime omits only the comparison with receiver wall time; the
// ACQUIRED interval itself and every portable root/digest field remain
// mandatory.
func validateVNextReaderPrepareAcquiredAtOptionalTime(
	acquired vnextReaderAcquiredAuthorization,
	validationTime *int64,
) error {
	var err error
	if validationTime == nil {
		err = validateVNextReaderAcquiredAuthorizationStructure(acquired)
	} else {
		err = validateVNextReaderAcquiredAuthorization(acquired, *validationTime)
	}
	if err != nil {
		return err
	}
	if allVNextReaderZero(acquired.Authorization.Root.DeviceTableDigest[:]) {
		return errors.New("VNext Reader ACQUIRED device-table digest is zero")
	}
	if allVNextReaderZero(
		acquired.Authorization.Root.PublicationLocator.PublicationSHA256[:]) {
		return errors.New("VNext Reader ACQUIRED publication digest is zero")
	}
	return nil
}

func validateVNextReaderPrepareAuthorityEnvelope(
	authority vnextReaderPrepareAuthorityEnvelope,
) error {
	if err := validateVNextReaderPrepareUnsignedAuthorityEnvelope(authority); err != nil {
		return err
	}
	if allVNextReaderZero(authority.Signature[:]) {
		return errors.New("Reader authority signature is zero")
	}
	return nil
}

func validateVNextReaderPrepareUnsignedAuthorityEnvelope(
	authority vnextReaderPrepareAuthorityEnvelope,
) error {
	if authority.Domain != vnextReaderPrepareAuthorityDomain {
		return fmt.Errorf("Reader authority domain is %q, expected %q",
			authority.Domain, vnextReaderPrepareAuthorityDomain)
	}
	if err := validateVNextReaderPrepareClusterID(authority.ClusterID); err != nil {
		return err
	}
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"Reader authority Scheduler ID", authority.SchedulerID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if authority.SchedulerFenceRevision == 0 ||
		authority.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		authority.LeaderLeaseID == 0 ||
		authority.LeaderLeaseID > cxlcheckpoint.MaxSignedLong {
		return errors.New("Reader authority fence or leader lease is outside the positive ABI")
	}
	if allVNextReaderZero(authority.LeaderTermID[:]) ||
		allVNextReaderZero(authority.KeyID[:]) ||
		allVNextReaderZero(authority.RequestDigest[:]) {
		return errors.New("Reader authority term, key, or request digest is zero")
	}
	return nil
}

func validateVNextReaderPrepareClusterID(value string) error {
	if len(value) != 16 || value != strings.ToLower(value) {
		return errors.New(
			"Reader authority cluster ID is not canonical 16-character lowercase hex")
	}
	decoded, err := strconv.ParseUint(value, 16, 64)
	if err != nil || decoded == 0 {
		return errors.New("Reader authority cluster ID is outside the positive ABI")
	}
	return nil
}

func validateVNextReaderPrepareAuthorityProof(
	proof vnextReaderPrepareAuthorityProof,
	authenticatedSchedulerPrincipal string,
	requestDigest [sha256.Size]byte,
	authority vnextReaderPrepareAuthorityEnvelope,
	acquired vnextReaderAcquiredAuthorization,
) error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"verified Scheduler principal", proof.AuthenticatedSchedulerPrincipal},
		{"verified Scheduler ID", proof.SchedulerID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if proof.SchedulerFenceRevision == 0 ||
		proof.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		proof.LeaderLeaseID == 0 || proof.LeaderLeaseID > cxlcheckpoint.MaxSignedLong ||
		allVNextReaderZero(proof.LeaderTermID[:]) ||
		allVNextReaderZero(proof.RequestDigest[:]) ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) {
		return errors.New("verified Reader Scheduler proof is incomplete")
	}
	if proof.AuthenticatedSchedulerPrincipal != authenticatedSchedulerPrincipal ||
		proof.SchedulerID != acquired.SchedulerID ||
		proof.SchedulerID != authority.SchedulerID ||
		proof.SchedulerFenceRevision != acquired.SchedulerFenceRevision ||
		proof.SchedulerFenceRevision != authority.SchedulerFenceRevision ||
		proof.LeaderLeaseID != authority.LeaderLeaseID ||
		proof.LeaderTermID != authority.LeaderTermID ||
		proof.RequestDigest != requestDigest ||
		proof.RequestDigest != authority.RequestDigest {
		return errors.New(
			"verified Reader Scheduler principal, leader, fence, or request digest differs from the payload")
	}
	wantReceipt, err := vnextReaderPrepareCanonicalAuthorityReceipt(
		authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return fmt.Errorf("derive verified Reader authority receipt: %w", err)
	}
	if proof.AuthorityReceipt != wantReceipt {
		return errors.New(
			"verified Reader authority receipt does not bind the principal and complete envelope")
	}
	return nil
}

func cloneVNextReaderPrepareAuthorityProof(
	proof vnextReaderPrepareAuthorityProof,
) vnextReaderPrepareAuthorityProof {
	cloned := proof
	cloned.AuthenticatedSchedulerPrincipal = cloneVNextReaderRetainedString(
		proof.AuthenticatedSchedulerPrincipal)
	cloned.SchedulerID = cloneVNextReaderRetainedString(proof.SchedulerID)
	return cloned
}

func vnextReaderPrepareCanonicalRequestDigest(
	acquired vnextReaderAcquiredAuthorization,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareRequestDigestDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareOperation)
	vnextReaderWriteCanonicalAcquired(&buffer, acquired)
	return sha256.Sum256(buffer.Bytes())
}

// vnextReaderWriteCanonicalAcquired is the one operation-neutral canonical
// writer for the durable Scheduler ACQUIRED identity. Callers must prepend
// their own distinct domain, protocol, and operation. Keeping those fields out
// of this helper prevents PREPARE and STATUS_AND_FENCE digest substitution.
func vnextReaderWriteCanonicalAcquired(
	buffer *bytes.Buffer,
	acquired vnextReaderAcquiredAuthorization,
) {
	authorization := acquired.Authorization
	vnextReaderPrepareWriteString(buffer, authorization.RestoreAuthorizationID)
	vnextReaderPrepareWriteString(buffer, authorization.CheckpointID)
	vnextReaderPrepareWriteString(buffer, authorization.ExecutorID)
	vnextReaderPrepareWriteString(buffer, authorization.CxldInstanceID)
	vnextReaderPrepareWriteString(buffer, authorization.TargetContainerID)
	root := authorization.Root
	vnextReaderPrepareWriteString(buffer, root.RootID)
	vnextReaderPrepareWriteU64(buffer, root.RootVersion)
	vnextReaderPrepareWriteString(buffer, root.MMTemplateID)
	vnextReaderPrepareWriteString(buffer, root.PageMapID)
	vnextReaderPrepareWriteU64(buffer, root.PageMapVersion)
	buffer.Write(root.DeviceTableDigest[:])
	vnextReaderPrepareWriteString(buffer, root.ContractID)
	locator := root.PublicationLocator
	vnextReaderPrepareWriteU64(buffer, locator.PublicationByteLength)
	buffer.Write(locator.PublicationSHA256[:])
	vnextReaderPrepareWriteU64(buffer, uint64(len(locator.PageRuns)))
	for _, run := range locator.PageRuns {
		vnextReaderPrepareWriteString(buffer, run.FirstPage.OwnerID)
		vnextReaderPrepareWriteString(buffer, run.FirstPage.DeviceUUID)
		vnextReaderPrepareWriteU64(buffer, run.FirstPage.AllocationRecordID)
		vnextReaderPrepareWriteU64(buffer, run.FirstPage.DataPageIndex)
		vnextReaderPrepareWriteU64(buffer, run.PageCount)
	}
	vnextReaderPrepareWriteString(buffer, acquired.SchedulerID)
	vnextReaderPrepareWriteU64(buffer, acquired.SchedulerFenceRevision)
	vnextReaderPrepareWriteU64(buffer, uint64(acquired.IssuedAtEpochMillis))
	vnextReaderPrepareWriteU64(buffer, uint64(acquired.ExpiresAtEpochMillis))
	vnextReaderPrepareWriteString(buffer, string(acquired.CatalogState))
	vnextReaderPrepareWriteString(buffer, acquired.LastMutationID)
}

// vnextReaderPrepareAuthoritySignaturePreimage is the only Reader PREPARE
// signature ABI. It intentionally excludes Signature itself and never reuses
// the Owner authority/signature domain. A future Scheduler signer and current-
// leader verifier must use these exact length-prefixed fields in this order.
func vnextReaderPrepareAuthoritySignaturePreimage(
	authority vnextReaderPrepareAuthorityEnvelope,
) ([]byte, error) {
	if err := validateVNextReaderPrepareUnsignedAuthorityEnvelope(authority); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer,
		vnextReaderPrepareAuthoritySignatureDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareOperation)
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

// vnextReaderPrepareCanonicalAuthorityReceipt is an unkeyed receipt over an
// already verified signature. It prevents a trusted verifier implementation
// from returning a proof for a different principal or envelope. It does not
// replace Ed25519 verification or authenticated transport.
func vnextReaderPrepareCanonicalAuthorityReceipt(
	authenticatedSchedulerPrincipal string,
	authority vnextReaderPrepareAuthorityEnvelope,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validateVNextReaderIdentity(
		"authenticated Scheduler principal", authenticatedSchedulerPrincipal); err != nil {
		return zero, err
	}
	if err := validateVNextReaderPrepareAuthorityEnvelope(authority); err != nil {
		return zero, err
	}
	preimage, err := vnextReaderPrepareAuthoritySignaturePreimage(authority)
	if err != nil {
		return zero, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer,
		vnextReaderPrepareAuthorityReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, authenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteU64(&buffer, uint64(len(preimage)))
	buffer.Write(preimage)
	buffer.Write(authority.Signature[:])
	return sha256.Sum256(buffer.Bytes()), nil
}

func vnextReaderPrepareCanonicalReceipt(
	response vnextReaderPrepareResponse,
) [sha256.Size]byte {
	// This is an unkeyed canonical binding hash, not a cxld signature or MAC.
	// Its security boundary is the verifier-produced authority receipt plus the
	// future authenticated transport that binds the response to this Reader.
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderPrepareOperation)
	buffer.Write(response.RequestDigest[:])
	proof := response.AuthorityProof
	vnextReaderPrepareWriteString(&buffer, proof.AuthenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteString(&buffer, proof.SchedulerID)
	vnextReaderPrepareWriteU64(&buffer, proof.SchedulerFenceRevision)
	vnextReaderPrepareWriteU64(&buffer, proof.LeaderLeaseID)
	buffer.Write(proof.LeaderTermID[:])
	buffer.Write(proof.RequestDigest[:])
	buffer.Write(proof.AuthorityReceipt[:])
	vnextReaderPrepareWriteString(&buffer, response.LocalExecutorNodeID)
	vnextReaderPrepareWriteString(&buffer, response.LocalCxldInstanceID)
	vnextReaderPrepareWriteString(&buffer, string(vnextReaderPreparationPrepared))
	vnextReaderPrepareWriteString(&buffer,
		vnextReaderPrepareDispositionName(response.Disposition))
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderPrepareWriteU64(buffer *bytes.Buffer, value uint64) {
	var raw [8]byte
	binary.LittleEndian.PutUint64(raw[:], value)
	buffer.Write(raw[:])
}

func vnextReaderPrepareWriteString(buffer *bytes.Buffer, value string) {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], uint32(len(value)))
	buffer.Write(raw[:])
	buffer.WriteString(value)
}

func vnextReaderPrepareDispositionName(
	disposition vnextReaderPreparationDisposition,
) string {
	switch disposition {
	case vnextReaderPreparationInstalled:
		return "INSTALLED"
	case vnextReaderPreparationExactReplay:
		return "EXACT_REPLAY"
	default:
		return ""
	}
}

func vnextReaderPrepareDisposition(value string) (
	vnextReaderPreparationDisposition,
	bool,
) {
	switch value {
	case "INSTALLED":
		return vnextReaderPreparationInstalled, true
	case "EXACT_REPLAY":
		return vnextReaderPreparationExactReplay, true
	default:
		return 0, false
	}
}

type vnextReaderPreparePageIDWire struct {
	OwnerID            string `json:"ownerId"`
	DeviceUUID         string `json:"deviceUuid"`
	AllocationRecordID uint64 `json:"allocationRecordId"`
	DataPageIndex      uint64 `json:"dataPageIndex"`
}

type vnextReaderPreparePageRunWire struct {
	FirstPage vnextReaderPreparePageIDWire `json:"firstPage"`
	PageCount uint64                       `json:"pageCount"`
}

type vnextReaderPreparePageRunsWire []vnextReaderPreparePageRunWire

type vnextReaderPrepareLocatorWire struct {
	PublicationByteLength uint64                         `json:"publicationByteLength"`
	PublicationSHA256     string                         `json:"publicationSha256"`
	PageRuns              vnextReaderPreparePageRunsWire `json:"pageRuns"`
}

type vnextReaderPrepareRootWire struct {
	RootID             string                        `json:"rootId"`
	RootVersion        uint64                        `json:"rootVersion"`
	MMTemplateID       string                        `json:"mmTemplateId"`
	PageMapID          string                        `json:"pageMapId"`
	PageMapVersion     uint64                        `json:"pageMapVersion"`
	DeviceTableDigest  string                        `json:"deviceTableDigest"`
	ContractID         string                        `json:"contractId"`
	PublicationLocator vnextReaderPrepareLocatorWire `json:"publicationLocator"`
}

type vnextReaderPrepareAuthorizationWire struct {
	RestoreAuthorizationID string                     `json:"restoreAuthorizationId"`
	CheckpointID           string                     `json:"checkpointId"`
	ExecutorNodeID         string                     `json:"executorNodeId"`
	ExecutorCxldID         string                     `json:"executorCxldId"`
	TargetContainerID      string                     `json:"targetContainerId"`
	Root                   vnextReaderPrepareRootWire `json:"root"`
}

type vnextReaderPrepareAcquiredWire struct {
	Authorization          vnextReaderPrepareAuthorizationWire `json:"authorization"`
	SchedulerID            string                              `json:"schedulerId"`
	SchedulerFenceRevision uint64                              `json:"schedulerFenceRevision"`
	IssuedAtEpochMillis    int64                               `json:"issuedAtEpochMillis"`
	ExpiresAtEpochMillis   int64                               `json:"expiresAtEpochMillis"`
	CatalogState           string                              `json:"catalogState"`
	LastMutationID         string                              `json:"lastMutationId"`
}

type vnextReaderPrepareAuthorityWire struct {
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

type vnextReaderPrepareRequestWire struct {
	Protocol  string                          `json:"protocol"`
	Operation string                          `json:"operation"`
	Acquired  vnextReaderPrepareAcquiredWire  `json:"acquired"`
	Authority vnextReaderPrepareAuthorityWire `json:"authority"`
}

type vnextReaderPrepareAuthorityProofWire struct {
	AuthenticatedSchedulerPrincipal string `json:"authenticatedSchedulerPrincipal"`
	SchedulerID                     string `json:"schedulerId"`
	SchedulerFenceRevision          uint64 `json:"schedulerFenceRevision"`
	LeaderLeaseID                   uint64 `json:"leaderLeaseId"`
	LeaderTermID                    string `json:"leaderTermId"`
	RequestDigest                   string `json:"requestDigest"`
	AuthorityReceipt                string `json:"authorityReceipt"`
}

type vnextReaderPrepareResponseWire struct {
	Protocol            string                               `json:"protocol"`
	Operation           string                               `json:"operation"`
	RequestDigest       string                               `json:"requestDigest"`
	AuthorityProof      vnextReaderPrepareAuthorityProofWire `json:"authorityProof"`
	LocalExecutorNodeID string                               `json:"localExecutorNodeId"`
	LocalCxldInstanceID string                               `json:"localCxldInstanceId"`
	State               string                               `json:"state"`
	Disposition         string                               `json:"disposition"`
	Acquired            vnextReaderPrepareAcquiredWire       `json:"acquired"`
	Receipt             string                               `json:"receipt"`
}

func decodeVNextReaderPrepareRequest(raw []byte) (
	vnextReaderPrepareRequest,
	error,
) {
	var wire vnextReaderPrepareRequestWire
	if err := decodeStrictVNextReaderPrepareJSON(raw, &wire); err != nil {
		return vnextReaderPrepareRequest{}, err
	}
	if wire.Protocol != vnextReaderPrepareProtocol ||
		wire.Operation != vnextReaderPrepareOperation {
		return vnextReaderPrepareRequest{}, fmt.Errorf(
			"Reader PREPARE protocol/operation is %q/%q, expected %q/%q",
			wire.Protocol, wire.Operation,
			vnextReaderPrepareProtocol, vnextReaderPrepareOperation)
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderPrepareRequest{}, err
	}
	// IssuedAt is the earliest valid instant and provides a clock-independent
	// structural check. The service repeats this with its local clock.
	if err := validateVNextReaderPrepareAcquired(
		acquired, acquired.IssuedAtEpochMillis); err != nil {
		return vnextReaderPrepareRequest{}, err
	}
	authority, err := wire.Authority.internal()
	if err != nil {
		return vnextReaderPrepareRequest{}, err
	}
	if err := validateVNextReaderPrepareAuthorityEnvelope(authority); err != nil {
		return vnextReaderPrepareRequest{}, err
	}
	digest := vnextReaderPrepareCanonicalRequestDigest(acquired)
	if authority.RequestDigest != digest {
		return vnextReaderPrepareRequest{}, errors.New(
			"Reader PREPARE authority request digest does not match the canonical payload")
	}
	return vnextReaderPrepareRequest{Acquired: acquired, Authority: authority}, nil
}

func marshalVNextReaderPrepareRequest(request vnextReaderPrepareRequest) ([]byte, error) {
	if err := validateVNextReaderPrepareAcquired(
		request.Acquired, request.Acquired.IssuedAtEpochMillis); err != nil {
		return nil, err
	}
	if err := validateVNextReaderPrepareAuthorityEnvelope(request.Authority); err != nil {
		return nil, err
	}
	if request.Authority.RequestDigest !=
		vnextReaderPrepareCanonicalRequestDigest(request.Acquired) {
		return nil, errors.New("Reader authority does not bind the request payload")
	}
	wire := vnextReaderPrepareRequestWire{
		Protocol:  vnextReaderPrepareProtocol,
		Operation: vnextReaderPrepareOperation,
		Acquired:  vnextReaderPrepareAcquiredWireFromInternal(request.Acquired),
		Authority: vnextReaderPrepareAuthorityWireFromInternal(request.Authority),
	}
	return marshalBoundedVNextReaderPrepareJSON(wire)
}

func marshalVNextReaderPrepareResponse(
	response vnextReaderPrepareResponse,
) ([]byte, error) {
	if response.Prepared.PreparationState != vnextReaderPreparationPrepared {
		return nil, errors.New("Reader PREPARE response has no exact PREPARED value")
	}
	// Response encoding is not allowed to turn an internally malformed value
	// into an acknowledgement. IssuedAt is the clock-independent earliest valid
	// instant; the service already performed its fresh local-time gate before
	// installing the store entry.
	if err := validateVNextReaderPrepareAcquired(
		response.Prepared.Acquired,
		response.Prepared.Acquired.IssuedAtEpochMillis); err != nil {
		return nil, fmt.Errorf("validate Reader PREPARE response ACQUIRED echo: %w", err)
	}
	disposition := vnextReaderPrepareDispositionName(response.Disposition)
	if disposition == "" {
		return nil, errors.New("Reader PREPARE response disposition is invalid")
	}
	wantRequestDigest := vnextReaderPrepareCanonicalRequestDigest(
		response.Prepared.Acquired)
	if response.RequestDigest != wantRequestDigest {
		return nil, errors.New("Reader PREPARE response request digest differs from its echo")
	}
	if err := validateVNextReaderPrepareResponseIdentity(response); err != nil {
		return nil, err
	}
	if response.Receipt != vnextReaderPrepareCanonicalReceipt(response) {
		return nil, errors.New("Reader PREPARE response receipt is inconsistent")
	}
	wire := vnextReaderPrepareResponseWire{
		Protocol:            vnextReaderPrepareProtocol,
		Operation:           vnextReaderPrepareOperation,
		RequestDigest:       hex.EncodeToString(response.RequestDigest[:]),
		AuthorityProof:      vnextReaderPrepareAuthorityProofWireFromInternal(response.AuthorityProof),
		LocalExecutorNodeID: response.LocalExecutorNodeID,
		LocalCxldInstanceID: response.LocalCxldInstanceID,
		State:               string(vnextReaderPreparationPrepared),
		Disposition:         disposition,
		Acquired:            vnextReaderPrepareAcquiredWireFromInternal(response.Prepared.Acquired),
		Receipt:             hex.EncodeToString(response.Receipt[:]),
	}
	return marshalBoundedVNextReaderPrepareJSON(wire)
}

func decodeVNextReaderPrepareResponse(raw []byte) (
	vnextReaderPrepareResponse,
	error,
) {
	var wire vnextReaderPrepareResponseWire
	if err := decodeStrictVNextReaderPrepareJSON(raw, &wire); err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	if wire.Protocol != vnextReaderPrepareProtocol ||
		wire.Operation != vnextReaderPrepareOperation ||
		wire.State != string(vnextReaderPreparationPrepared) {
		return vnextReaderPrepareResponse{}, errors.New(
			"Reader PREPARE response protocol, operation, or state is invalid")
	}
	disposition, ok := vnextReaderPrepareDisposition(wire.Disposition)
	if !ok {
		return vnextReaderPrepareResponse{}, errors.New(
			"Reader PREPARE response disposition is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	if err := validateVNextReaderPrepareAcquired(
		acquired, acquired.IssuedAtEpochMillis); err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	requestDigest, err := decodeVNextReaderPrepareHexDigest(
		"response request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	proof, err := wire.AuthorityProof.internal()
	if err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"response receipt", wire.Receipt)
	if err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	response := vnextReaderPrepareResponse{
		RequestDigest:       requestDigest,
		AuthorityProof:      proof,
		LocalExecutorNodeID: wire.LocalExecutorNodeID,
		LocalCxldInstanceID: wire.LocalCxldInstanceID,
		Prepared: vnextReaderPreparedAuthorization{
			Acquired: acquired, PreparationState: vnextReaderPreparationPrepared,
		},
		Disposition: disposition,
		Receipt:     receipt,
	}
	if requestDigest != vnextReaderPrepareCanonicalRequestDigest(acquired) {
		return vnextReaderPrepareResponse{}, errors.New(
			"Reader PREPARE response digest differs from the authorization echo")
	}
	if err := validateVNextReaderPrepareResponseIdentity(response); err != nil {
		return vnextReaderPrepareResponse{}, err
	}
	if response.Receipt != vnextReaderPrepareCanonicalReceipt(response) {
		return vnextReaderPrepareResponse{}, errors.New(
			"Reader PREPARE response receipt is invalid")
	}
	return response, nil
}

func validateVNextReaderPrepareResponseIdentity(
	response vnextReaderPrepareResponse,
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
	acquired := response.Prepared.Acquired
	proof := response.AuthorityProof
	if response.LocalExecutorNodeID != acquired.Authorization.ExecutorID ||
		response.LocalCxldInstanceID != acquired.Authorization.CxldInstanceID ||
		proof.SchedulerID != acquired.SchedulerID ||
		proof.SchedulerFenceRevision != acquired.SchedulerFenceRevision ||
		proof.RequestDigest != response.RequestDigest ||
		proof.LeaderLeaseID == 0 || proof.LeaderLeaseID > cxlcheckpoint.MaxSignedLong ||
		allVNextReaderZero(proof.LeaderTermID[:]) ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) {
		return errors.New("Reader PREPARE response identity or authority proof differs")
	}
	return nil
}

func (wire vnextReaderPrepareAcquiredWire) internal() (
	vnextReaderAcquiredAuthorization,
	error,
) {
	authorization, err := wire.Authorization.internal()
	if err != nil {
		return vnextReaderAcquiredAuthorization{}, err
	}
	return vnextReaderAcquiredAuthorization{
		Authorization:          authorization,
		SchedulerID:            wire.SchedulerID,
		SchedulerFenceRevision: wire.SchedulerFenceRevision,
		IssuedAtEpochMillis:    wire.IssuedAtEpochMillis,
		ExpiresAtEpochMillis:   wire.ExpiresAtEpochMillis,
		CatalogState:           vnextReaderCatalogAuthorizationState(wire.CatalogState),
		LastMutationID:         wire.LastMutationID,
	}, nil
}

func (wire vnextReaderPrepareAuthorizationWire) internal() (
	vnextReaderAuthorization,
	error,
) {
	root, err := wire.Root.internal()
	if err != nil {
		return vnextReaderAuthorization{}, err
	}
	return vnextReaderAuthorization{
		RestoreAuthorizationID: wire.RestoreAuthorizationID,
		CheckpointID:           wire.CheckpointID,
		ExecutorID:             wire.ExecutorNodeID,
		CxldInstanceID:         wire.ExecutorCxldID,
		TargetContainerID:      wire.TargetContainerID,
		Root:                   root,
	}, nil
}

func (wire vnextReaderPrepareRootWire) internal() (vnextReaderTrustedRoot, error) {
	deviceDigest, err := decodeVNextReaderPrepareHexDigest(
		"device-table digest", wire.DeviceTableDigest)
	if err != nil {
		return vnextReaderTrustedRoot{}, err
	}
	publicationDigest, err := decodeVNextReaderPrepareHexDigest(
		"publication digest", wire.PublicationLocator.PublicationSHA256)
	if err != nil {
		return vnextReaderTrustedRoot{}, err
	}
	if len(wire.PublicationLocator.PageRuns) == 0 ||
		len(wire.PublicationLocator.PageRuns) > vnextReaderMaxLocatorRuns {
		return vnextReaderTrustedRoot{}, fmt.Errorf(
			"Reader PREPARE locator run count is outside 1..%d",
			vnextReaderMaxLocatorRuns)
	}
	runs := make([]cxlcheckpoint.PublicationPageRun,
		len(wire.PublicationLocator.PageRuns))
	for index, run := range wire.PublicationLocator.PageRuns {
		runs[index] = cxlcheckpoint.PublicationPageRun{
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            run.FirstPage.OwnerID,
				DeviceUUID:         run.FirstPage.DeviceUUID,
				AllocationRecordID: run.FirstPage.AllocationRecordID,
				DataPageIndex:      run.FirstPage.DataPageIndex,
			},
			PageCount: run.PageCount,
		}
	}
	return vnextReaderTrustedRoot{
		RootID:            wire.RootID,
		RootVersion:       wire.RootVersion,
		MMTemplateID:      wire.MMTemplateID,
		PageMapID:         wire.PageMapID,
		PageMapVersion:    wire.PageMapVersion,
		DeviceTableDigest: deviceDigest,
		ContractID:        wire.ContractID,
		PublicationLocator: vnextReaderPublicationLocator{
			PublicationByteLength: wire.PublicationLocator.PublicationByteLength,
			PublicationSHA256:     publicationDigest,
			PageRuns:              runs,
		},
	}, nil
}

func (wire vnextReaderPrepareAuthorityWire) internal() (
	vnextReaderPrepareAuthorityEnvelope,
	error,
) {
	termID, err := decodeVNextReaderPrepareHexDigest(
		"Reader authority leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderPrepareAuthorityEnvelope{}, err
	}
	keyID, err := decodeVNextReaderPrepareHexDigest(
		"Reader authority key ID", wire.KeyID)
	if err != nil {
		return vnextReaderPrepareAuthorityEnvelope{}, err
	}
	requestDigest, err := decodeVNextReaderPrepareHexDigest(
		"Reader authority request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderPrepareAuthorityEnvelope{}, err
	}
	signature, err := decodeVNextReaderPrepareHexSignature(
		"Reader authority signature", wire.Signature)
	if err != nil {
		return vnextReaderPrepareAuthorityEnvelope{}, err
	}
	return vnextReaderPrepareAuthorityEnvelope{
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

func (wire vnextReaderPrepareAuthorityProofWire) internal() (
	vnextReaderPrepareAuthorityProof,
	error,
) {
	termID, err := decodeVNextReaderPrepareHexDigest(
		"response authority leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderPrepareAuthorityProof{}, err
	}
	requestDigest, err := decodeVNextReaderPrepareHexDigest(
		"response authority request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderPrepareAuthorityProof{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"response authority receipt", wire.AuthorityReceipt)
	if err != nil {
		return vnextReaderPrepareAuthorityProof{}, err
	}
	return vnextReaderPrepareAuthorityProof{
		AuthenticatedSchedulerPrincipal: wire.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     wire.SchedulerID,
		SchedulerFenceRevision:          wire.SchedulerFenceRevision,
		LeaderLeaseID:                   wire.LeaderLeaseID,
		LeaderTermID:                    termID,
		RequestDigest:                   requestDigest,
		AuthorityReceipt:                receipt,
	}, nil
}

func vnextReaderPrepareAcquiredWireFromInternal(
	acquired vnextReaderAcquiredAuthorization,
) vnextReaderPrepareAcquiredWire {
	authorization := acquired.Authorization
	root := authorization.Root
	runs := make(vnextReaderPreparePageRunsWire,
		len(root.PublicationLocator.PageRuns))
	for index, run := range root.PublicationLocator.PageRuns {
		runs[index] = vnextReaderPreparePageRunWire{
			FirstPage: vnextReaderPreparePageIDWire{
				OwnerID:            run.FirstPage.OwnerID,
				DeviceUUID:         run.FirstPage.DeviceUUID,
				AllocationRecordID: run.FirstPage.AllocationRecordID,
				DataPageIndex:      run.FirstPage.DataPageIndex,
			},
			PageCount: run.PageCount,
		}
	}
	return vnextReaderPrepareAcquiredWire{
		Authorization: vnextReaderPrepareAuthorizationWire{
			RestoreAuthorizationID: authorization.RestoreAuthorizationID,
			CheckpointID:           authorization.CheckpointID,
			ExecutorNodeID:         authorization.ExecutorID,
			ExecutorCxldID:         authorization.CxldInstanceID,
			TargetContainerID:      authorization.TargetContainerID,
			Root: vnextReaderPrepareRootWire{
				RootID:            root.RootID,
				RootVersion:       root.RootVersion,
				MMTemplateID:      root.MMTemplateID,
				PageMapID:         root.PageMapID,
				PageMapVersion:    root.PageMapVersion,
				DeviceTableDigest: hex.EncodeToString(root.DeviceTableDigest[:]),
				ContractID:        root.ContractID,
				PublicationLocator: vnextReaderPrepareLocatorWire{
					PublicationByteLength: root.PublicationLocator.PublicationByteLength,
					PublicationSHA256: hex.EncodeToString(
						root.PublicationLocator.PublicationSHA256[:]),
					PageRuns: runs,
				},
			},
		},
		SchedulerID:            acquired.SchedulerID,
		SchedulerFenceRevision: acquired.SchedulerFenceRevision,
		IssuedAtEpochMillis:    acquired.IssuedAtEpochMillis,
		ExpiresAtEpochMillis:   acquired.ExpiresAtEpochMillis,
		CatalogState:           string(acquired.CatalogState),
		LastMutationID:         acquired.LastMutationID,
	}
}

func vnextReaderPrepareAuthorityWireFromInternal(
	authority vnextReaderPrepareAuthorityEnvelope,
) vnextReaderPrepareAuthorityWire {
	return vnextReaderPrepareAuthorityWire{
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

func vnextReaderPrepareAuthorityProofWireFromInternal(
	proof vnextReaderPrepareAuthorityProof,
) vnextReaderPrepareAuthorityProofWire {
	return vnextReaderPrepareAuthorityProofWire{
		AuthenticatedSchedulerPrincipal: proof.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     proof.SchedulerID,
		SchedulerFenceRevision:          proof.SchedulerFenceRevision,
		LeaderLeaseID:                   proof.LeaderLeaseID,
		LeaderTermID:                    hex.EncodeToString(proof.LeaderTermID[:]),
		RequestDigest:                   hex.EncodeToString(proof.RequestDigest[:]),
		AuthorityReceipt:                hex.EncodeToString(proof.AuthorityReceipt[:]),
	}
}

func decodeVNextReaderPrepareHexDigest(
	name string,
	value string,
) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if len(value) != hex.EncodedLen(len(digest)) || value != strings.ToLower(value) {
		return digest, fmt.Errorf("%s is not canonical 64-character lowercase hex", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, fmt.Errorf("decode %s: %w", name, err)
	}
	copy(digest[:], decoded)
	if allVNextReaderZero(digest[:]) {
		return digest, fmt.Errorf("%s is zero", name)
	}
	return digest, nil
}

func decodeVNextReaderPrepareHexSignature(
	name string,
	value string,
) ([ed25519.SignatureSize]byte, error) {
	var signature [ed25519.SignatureSize]byte
	if len(value) != hex.EncodedLen(len(signature)) || value != strings.ToLower(value) {
		return signature, fmt.Errorf(
			"%s is not canonical %d-character lowercase hex",
			name, hex.EncodedLen(len(signature)))
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(signature) {
		return signature, fmt.Errorf("decode %s: %w", name, err)
	}
	copy(signature[:], decoded)
	if allVNextReaderZero(signature[:]) {
		return signature, fmt.Errorf("%s is zero", name)
	}
	return signature, nil
}

func marshalBoundedVNextReaderPrepareJSON(value interface{}) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", vnextReaderPrepareProtocol, err)
	}
	if len(body) == 0 || len(body) > vnextReaderPrepareMaxFrameBytes {
		return nil, fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			vnextReaderPrepareProtocol, len(body), vnextReaderPrepareMaxFrameBytes)
	}
	return body, nil
}

func decodeStrictVNextReaderPrepareJSON(raw []byte, target interface{}) error {
	if len(raw) == 0 || len(raw) > vnextReaderPrepareMaxFrameBytes {
		return fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			vnextReaderPrepareProtocol, len(raw), vnextReaderPrepareMaxFrameBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("decode %s: JSON is not valid UTF-8",
			vnextReaderPrepareProtocol)
	}
	if err := validateVNextReaderPrepareJSONShape(raw, target); err != nil {
		return fmt.Errorf("decode %s: %w", vnextReaderPrepareProtocol, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", vnextReaderPrepareProtocol, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value",
				vnextReaderPrepareProtocol)
		}
		return fmt.Errorf("decode %s trailer: %w",
			vnextReaderPrepareProtocol, err)
	}
	return nil
}

func validateVNextReaderPrepareJSONShape(raw []byte, target interface{}) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Ptr ||
		targetType.Elem().Kind() != reflect.Struct {
		return errors.New("strict Reader PREPARE target must be a pointer to a struct")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateVNextReaderPrepareJSONValue(
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

func validateVNextReaderPrepareJSONValue(
	decoder *json.Decoder,
	valueType reflect.Type,
	path string,
) error {
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
			if count >= vnextReaderPrepareMaxObjectFields {
				return fmt.Errorf("%s contains more than %d fields",
					path, vnextReaderPrepareMaxObjectFields)
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
			if err := validateVNextReaderPrepareJSONValue(
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
			if err := validateVNextReaderPrepareJSONValue(
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
