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
	"unicode/utf8"
)

const (
	vnextReaderIdentifyProtocol  = "cxld.vnext-reader-identify.v1"
	vnextReaderIdentifyOperation = "vnextReaderIdentify"
	vnextReaderIdentifyALPN      = "cxld-vnext-reader-identify/1"

	vnextReaderIdentifyAuthorityDomain          = "cxld-vnext-reader-identify-authority-v1"
	vnextReaderIdentifyAuthoritySignatureDomain = "cxld-vnext-reader-identify-authority-signature-v1"
	vnextReaderIdentifyAuthorityReceiptDomain   = "cxld-vnext-reader-identify-authority-receipt-v1"
	vnextReaderIdentifyRequestDigestDomain      = "cxld-vnext-reader-identify-request-digest-v1"
	vnextReaderIdentifyCapabilitiesDigestDomain = "cxld-vnext-reader-identify-capabilities-digest-v1"
	vnextReaderIdentifyReceiptDomain            = "cxld-vnext-reader-identify-receipt-v1"

	vnextReaderIdentifyMaxFrameBytes   = 64 << 10
	vnextReaderIdentifyCapabilityCount = 6
)

type vnextReaderIdentifyNonce [sha256.Size]byte

type vnextReaderIdentifyAuthorityEnvelope struct {
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

type vnextReaderIdentifyAuthorityProof struct {
	AuthenticatedSchedulerPrincipal string
	SchedulerID                     string
	SchedulerFenceRevision          uint64
	LeaderLeaseID                   uint64
	LeaderTermID                    [sha256.Size]byte
	RequestDigest                   [sha256.Size]byte
	AuthorityReceipt                [sha256.Size]byte
}

type vnextReaderIdentifyAuthorityVerifier interface {
	VerifyVNextReaderIdentifyAuthority(
		context.Context,
		string,
		[sha256.Size]byte,
		vnextReaderIdentifyAuthorityEnvelope,
	) (vnextReaderIdentifyAuthorityProof, error)
}

type vnextReaderIdentifyCapability struct {
	Protocol  string
	Operation string
	ALPN      string
}

type vnextReaderIdentifyRequest struct {
	ExpectedExecutorNodeID string
	ExpectedCxldLogicalID  string
	ChallengeNonce         vnextReaderIdentifyNonce
	Authority              vnextReaderIdentifyAuthorityEnvelope
}

type vnextReaderIdentifyResponse struct {
	RequestDigest           [sha256.Size]byte
	AuthorityProof          vnextReaderIdentifyAuthorityProof
	LocalExecutorNodeID     string
	LocalCxldLogicalID      string
	LocalProcessIncarnation vnextReaderProcessIncarnation
	ServerURISAN            string
	SupportedProtocols      []vnextReaderIdentifyCapability
	CapabilitiesDigest      [sha256.Size]byte
	Receipt                 [sha256.Size]byte
}

type vnextReaderIdentifyErrorCode string

const (
	vnextReaderIdentifyInvalidRequest vnextReaderIdentifyErrorCode = "INVALID_REQUEST"
	vnextReaderIdentifyAuthorityError vnextReaderIdentifyErrorCode = "AUTHORITY_REJECTED"
	vnextReaderIdentifyIdentityError  vnextReaderIdentifyErrorCode = "IDENTITY_REJECTED"
	vnextReaderIdentifyCapacityError  vnextReaderIdentifyErrorCode = "CAPACITY_EXHAUSTED"
	vnextReaderIdentifyUnavailable    vnextReaderIdentifyErrorCode = "UNAVAILABLE"
)

type vnextReaderIdentifyRPCError struct {
	Code  vnextReaderIdentifyErrorCode
	Cause error
}

func (failure *vnextReaderIdentifyRPCError) Error() string {
	if failure == nil {
		return "VNext Reader IDENTIFY failure is unavailable"
	}
	return fmt.Sprintf("VNext Reader IDENTIFY %s: %v", failure.Code, failure.Cause)
}

func (failure *vnextReaderIdentifyRPCError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.Cause
}

func vnextReaderIdentifyFailure(
	code vnextReaderIdentifyErrorCode,
	cause error,
) *vnextReaderIdentifyRPCError {
	if cause == nil {
		cause = errors.New("unspecified VNext Reader IDENTIFY failure")
	}
	return &vnextReaderIdentifyRPCError{Code: code, Cause: cause}
}

type vnextReaderIdentifyService struct {
	localExecutorNodeID string
	localCxldLogicalID  string
	processIncarnation  vnextReaderProcessIncarnation
	serverURISAN        string
	supportedProtocols  []vnextReaderIdentifyCapability
	capabilitiesDigest  [sha256.Size]byte
	authorityVerifier   vnextReaderIdentifyAuthorityVerifier
}

func newVNextReaderIdentifyService(
	localExecutorNodeID string,
	localCxldLogicalID string,
	processIncarnation vnextReaderProcessIncarnation,
	serverURISAN string,
	authorityVerifier vnextReaderIdentifyAuthorityVerifier,
) (*vnextReaderIdentifyService, error) {
	if err := validateVNextReaderIdentity(
		"local Reader IDENTIFY executor node ID", localExecutorNodeID); err != nil {
		return nil, err
	}
	if err := validateVNextReaderIdentity(
		"local Reader IDENTIFY cxld logical ID", localCxldLogicalID); err != nil {
		return nil, err
	}
	if err := validateVNextReaderProcessIncarnation(processIncarnation); err != nil {
		return nil, err
	}
	if err := validateVNextReaderPreparePrincipalURI(serverURISAN); err != nil {
		return nil, fmt.Errorf("validate Reader IDENTIFY server URI SAN: %w", err)
	}
	if vnextReaderPreparedStatusNilInterface(authorityVerifier) {
		return nil, errors.New("VNext Reader IDENTIFY authority verifier is unavailable")
	}
	capabilities := vnextReaderIdentifyCurrentCapabilities()
	if err := validateVNextReaderIdentifyCapabilities(capabilities); err != nil {
		return nil, err
	}
	return &vnextReaderIdentifyService{
		localExecutorNodeID: cloneVNextReaderRetainedString(localExecutorNodeID),
		localCxldLogicalID:  cloneVNextReaderRetainedString(localCxldLogicalID),
		processIncarnation:  processIncarnation,
		serverURISAN:        cloneVNextReaderRetainedString(serverURISAN),
		supportedProtocols:  cloneVNextReaderIdentifyCapabilities(capabilities),
		capabilitiesDigest:  vnextReaderIdentifyCanonicalCapabilitiesDigest(capabilities),
		authorityVerifier:   authorityVerifier,
	}, nil
}

func (service *vnextReaderIdentifyService) Identify(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	request vnextReaderIdentifyRequest,
) (vnextReaderIdentifyResponse, *vnextReaderIdentifyRPCError) {
	if service == nil ||
		vnextReaderPreparedStatusNilInterface(service.authorityVerifier) {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			errors.New("VNext Reader IDENTIFY service is unavailable"))
	}
	if ctx == nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyInvalidRequest,
			errors.New("VNext Reader IDENTIFY context is nil"))
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable, err)
	}
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyAuthorityError, err)
	}
	if err := validateVNextReaderIdentifyRequestPayload(request); err != nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyInvalidRequest, err)
	}
	if request.ExpectedExecutorNodeID != service.localExecutorNodeID ||
		request.ExpectedCxldLogicalID != service.localCxldLogicalID {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyIdentityError,
			fmt.Errorf(
				"IDENTIFY expects executor/logical cxld %q/%q, local identity is %q/%q",
				request.ExpectedExecutorNodeID, request.ExpectedCxldLogicalID,
				service.localExecutorNodeID, service.localCxldLogicalID))
	}
	requestDigest := vnextReaderIdentifyCanonicalRequestDigest(request)
	if request.Authority.RequestDigest != requestDigest {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyAuthorityError,
			errors.New("IDENTIFY authority envelope has a different request digest"))
	}
	proof, err := service.authorityVerifier.VerifyVNextReaderIdentifyAuthority(
		ctx, authenticatedSchedulerPrincipal, requestDigest, request.Authority)
	if err != nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyAuthorityError,
			fmt.Errorf("verify current IDENTIFY Scheduler authority: %w", err))
	}
	if err := validateVNextReaderIdentifyAuthorityProof(
		proof, authenticatedSchedulerPrincipal, requestDigest, request.Authority); err != nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyAuthorityError, err)
	}
	if err := ctx.Err(); err != nil {
		return vnextReaderIdentifyResponse{}, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable, err)
	}
	response := vnextReaderIdentifyResponse{
		RequestDigest:           requestDigest,
		AuthorityProof:          cloneVNextReaderIdentifyAuthorityProof(proof),
		LocalExecutorNodeID:     service.localExecutorNodeID,
		LocalCxldLogicalID:      service.localCxldLogicalID,
		LocalProcessIncarnation: service.processIncarnation,
		ServerURISAN:            service.serverURISAN,
		SupportedProtocols: cloneVNextReaderIdentifyCapabilities(
			service.supportedProtocols),
		CapabilitiesDigest: service.capabilitiesDigest,
	}
	response.Receipt = vnextReaderIdentifyCanonicalReceipt(response)
	return response, nil
}

type vnextReaderIdentifyResponseEncoder func(vnextReaderIdentifyResponse) ([]byte, error)

type vnextReaderIdentifyRPC struct {
	service        *vnextReaderIdentifyService
	encodeResponse vnextReaderIdentifyResponseEncoder
}

func newVNextReaderIdentifyRPC(
	service *vnextReaderIdentifyService,
) *vnextReaderIdentifyRPC {
	if service == nil {
		return nil
	}
	return &vnextReaderIdentifyRPC{
		service: service, encodeResponse: marshalVNextReaderIdentifyResponse,
	}
}

func (rpc *vnextReaderIdentifyRPC) Handle(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	frame []byte,
) ([]byte, *vnextReaderIdentifyRPCError) {
	if rpc == nil || rpc.service == nil || rpc.encodeResponse == nil {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			errors.New("VNext Reader IDENTIFY RPC is unavailable"))
	}
	request, err := decodeVNextReaderIdentifyRequest(frame)
	if err != nil {
		return nil, vnextReaderIdentifyFailure(vnextReaderIdentifyInvalidRequest, err)
	}
	response, failure := rpc.service.Identify(
		ctx, authenticatedSchedulerPrincipal, request)
	if failure != nil {
		return nil, failure
	}
	body, err := rpc.encodeResponse(response)
	if err != nil {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			fmt.Errorf("encode VNext Reader IDENTIFY response: %w", err))
	}
	return body, nil
}

func validateVNextReaderIdentifyRequestPayload(
	request vnextReaderIdentifyRequest,
) error {
	if err := validateVNextReaderIdentity(
		"IDENTIFY expected executor node ID", request.ExpectedExecutorNodeID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"IDENTIFY expected cxld logical ID", request.ExpectedCxldLogicalID); err != nil {
		return err
	}
	if allVNextReaderZero(request.ChallengeNonce[:]) {
		return errors.New("IDENTIFY challenge nonce is zero")
	}
	return validateVNextReaderIdentifyAuthorityEnvelope(request.Authority)
}

func validateVNextReaderIdentifyAuthorityEnvelope(
	authority vnextReaderIdentifyAuthorityEnvelope,
) error {
	if err := validateVNextReaderIdentifyUnsignedAuthorityEnvelope(authority); err != nil {
		return err
	}
	if allVNextReaderZero(authority.Signature[:]) {
		return errors.New("IDENTIFY authority signature is zero")
	}
	return nil
}

func validateVNextReaderIdentifyUnsignedAuthorityEnvelope(
	authority vnextReaderIdentifyAuthorityEnvelope,
) error {
	if authority.Domain != vnextReaderIdentifyAuthorityDomain {
		return fmt.Errorf("IDENTIFY authority domain is %q, expected %q",
			authority.Domain, vnextReaderIdentifyAuthorityDomain)
	}
	if err := validateVNextReaderPrepareClusterID(authority.ClusterID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"IDENTIFY authority Scheduler ID", authority.SchedulerID); err != nil {
		return err
	}
	if authority.SchedulerFenceRevision == 0 || authority.LeaderLeaseID == 0 ||
		authority.SchedulerFenceRevision > uint64(^uint64(0)>>1) ||
		authority.LeaderLeaseID > uint64(^uint64(0)>>1) {
		return errors.New("IDENTIFY authority fence or lease is outside the positive ABI")
	}
	if allVNextReaderZero(authority.LeaderTermID[:]) ||
		allVNextReaderZero(authority.KeyID[:]) ||
		allVNextReaderZero(authority.RequestDigest[:]) {
		return errors.New("IDENTIFY authority term, key, or request digest is zero")
	}
	return nil
}

func validateVNextReaderIdentifyAuthorityProof(
	proof vnextReaderIdentifyAuthorityProof,
	authenticatedSchedulerPrincipal string,
	requestDigest [sha256.Size]byte,
	authority vnextReaderIdentifyAuthorityEnvelope,
) error {
	if err := validateVNextReaderPreparePrincipalURI(
		proof.AuthenticatedSchedulerPrincipal); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"IDENTIFY proof Scheduler ID", proof.SchedulerID); err != nil {
		return err
	}
	if proof.AuthenticatedSchedulerPrincipal != authenticatedSchedulerPrincipal ||
		proof.SchedulerID != authority.SchedulerID ||
		proof.SchedulerFenceRevision != authority.SchedulerFenceRevision ||
		proof.LeaderLeaseID != authority.LeaderLeaseID ||
		proof.LeaderTermID != authority.LeaderTermID ||
		proof.RequestDigest != requestDigest ||
		proof.RequestDigest != authority.RequestDigest ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) {
		return errors.New("IDENTIFY authority proof differs from the request authority")
	}
	want, err := vnextReaderIdentifyCanonicalAuthorityReceipt(
		authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return err
	}
	if proof.AuthorityReceipt != want {
		return errors.New("IDENTIFY authority proof receipt is invalid")
	}
	return nil
}

func cloneVNextReaderIdentifyAuthorityProof(
	proof vnextReaderIdentifyAuthorityProof,
) vnextReaderIdentifyAuthorityProof {
	cloned := proof
	cloned.AuthenticatedSchedulerPrincipal = cloneVNextReaderRetainedString(
		proof.AuthenticatedSchedulerPrincipal)
	cloned.SchedulerID = cloneVNextReaderRetainedString(proof.SchedulerID)
	return cloned
}

func vnextReaderIdentifyCanonicalRequestDigest(
	request vnextReaderIdentifyRequest,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyRequestDigestDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyOperation)
	vnextReaderPrepareWriteString(&buffer, request.ExpectedExecutorNodeID)
	vnextReaderPrepareWriteString(&buffer, request.ExpectedCxldLogicalID)
	buffer.Write(request.ChallengeNonce[:])
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderIdentifyAuthoritySignaturePreimage(
	authority vnextReaderIdentifyAuthorityEnvelope,
) ([]byte, error) {
	if err := validateVNextReaderIdentifyUnsignedAuthorityEnvelope(authority); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderIdentifyAuthoritySignatureDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyOperation)
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

func vnextReaderIdentifyCanonicalAuthorityReceipt(
	authenticatedSchedulerPrincipal string,
	authority vnextReaderIdentifyAuthorityEnvelope,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, err
	}
	if err := validateVNextReaderIdentifyAuthorityEnvelope(authority); err != nil {
		return zero, err
	}
	preimage, err := vnextReaderIdentifyAuthoritySignaturePreimage(authority)
	if err != nil {
		return zero, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderIdentifyAuthorityReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, authenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteU64(&buffer, uint64(len(preimage)))
	buffer.Write(preimage)
	buffer.Write(authority.Signature[:])
	return sha256.Sum256(buffer.Bytes()), nil
}

func vnextReaderIdentifyCurrentCapabilities() []vnextReaderIdentifyCapability {
	// This order is part of the canonical IDENTIFY v1 ABI. Only protocols
	// actually served by this listener are advertised.
	return []vnextReaderIdentifyCapability{
		{Protocol: vnextReaderActivationCommitProtocol,
			Operation: vnextReaderActivationCommitOperation,
			ALPN:      vnextReaderActivationCommitALPN},
		{Protocol: vnextReaderActivationProposalProtocol,
			Operation: vnextReaderActivationProposalOperation,
			ALPN:      vnextReaderActivationProposalALPN},
		{Protocol: vnextReaderActivationStatusProtocol,
			Operation: vnextReaderActivationStatusOperation,
			ALPN:      vnextReaderActivationStatusALPN},
		{Protocol: vnextReaderIdentifyProtocol,
			Operation: vnextReaderIdentifyOperation, ALPN: vnextReaderIdentifyALPN},
		{Protocol: vnextReaderPrepareProtocol,
			Operation: vnextReaderPrepareOperation, ALPN: vnextReaderPrepareALPN},
		{Protocol: vnextReaderPreparedStatusProtocol,
			Operation: vnextReaderPreparedStatusOperation,
			ALPN:      vnextReaderPreparedStatusALPN},
	}
}

func cloneVNextReaderIdentifyCapabilities(
	capabilities []vnextReaderIdentifyCapability,
) []vnextReaderIdentifyCapability {
	cloned := make([]vnextReaderIdentifyCapability, len(capabilities))
	for index, capability := range capabilities {
		cloned[index] = vnextReaderIdentifyCapability{
			Protocol:  cloneVNextReaderRetainedString(capability.Protocol),
			Operation: cloneVNextReaderRetainedString(capability.Operation),
			ALPN:      cloneVNextReaderRetainedString(capability.ALPN),
		}
	}
	return cloned
}

func validateVNextReaderIdentifyCapabilities(
	capabilities []vnextReaderIdentifyCapability,
) error {
	want := vnextReaderIdentifyCurrentCapabilities()
	if len(capabilities) != vnextReaderIdentifyCapabilityCount ||
		len(capabilities) != len(want) {
		return fmt.Errorf(
			"IDENTIFY capability count is %d, expected %d",
			len(capabilities), len(want))
	}
	for index := range want {
		if capabilities[index] != want[index] {
			return fmt.Errorf("IDENTIFY capability %d is not canonical", index)
		}
	}
	return nil
}

func vnextReaderIdentifyCanonicalCapabilitiesDigest(
	capabilities []vnextReaderIdentifyCapability,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderIdentifyCapabilitiesDigestDomain)
	vnextReaderPrepareWriteU64(&buffer, uint64(len(capabilities)))
	for _, capability := range capabilities {
		vnextReaderPrepareWriteString(&buffer, capability.Protocol)
		vnextReaderPrepareWriteString(&buffer, capability.Operation)
		vnextReaderPrepareWriteString(&buffer, capability.ALPN)
	}
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderIdentifyCanonicalReceipt(
	response vnextReaderIdentifyResponse,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyProtocol)
	vnextReaderPrepareWriteString(&buffer, vnextReaderIdentifyOperation)
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
	vnextReaderPrepareWriteString(&buffer, response.LocalCxldLogicalID)
	buffer.Write(response.LocalProcessIncarnation[:])
	vnextReaderPrepareWriteString(&buffer, response.ServerURISAN)
	buffer.Write(response.CapabilitiesDigest[:])
	vnextReaderPrepareWriteU64(&buffer, uint64(len(response.SupportedProtocols)))
	for _, capability := range response.SupportedProtocols {
		vnextReaderPrepareWriteString(&buffer, capability.Protocol)
		vnextReaderPrepareWriteString(&buffer, capability.Operation)
		vnextReaderPrepareWriteString(&buffer, capability.ALPN)
	}
	return sha256.Sum256(buffer.Bytes())
}

type vnextReaderIdentifyAuthorityWire struct {
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

type vnextReaderIdentifyAuthorityProofWire struct {
	AuthenticatedSchedulerPrincipal string `json:"authenticatedSchedulerPrincipal"`
	SchedulerID                     string `json:"schedulerId"`
	SchedulerFenceRevision          uint64 `json:"schedulerFenceRevision"`
	LeaderLeaseID                   uint64 `json:"leaderLeaseId"`
	LeaderTermID                    string `json:"leaderTermId"`
	RequestDigest                   string `json:"requestDigest"`
	AuthorityReceipt                string `json:"authorityReceipt"`
}

type vnextReaderIdentifyCapabilityWire struct {
	Protocol  string `json:"protocol"`
	Operation string `json:"operation"`
	ALPN      string `json:"alpn"`
}

type vnextReaderIdentifyCapabilitiesWire []vnextReaderIdentifyCapabilityWire

type vnextReaderIdentifyRequestWire struct {
	Protocol               string                           `json:"protocol"`
	Operation              string                           `json:"operation"`
	ExpectedExecutorNodeID string                           `json:"expectedExecutorNodeId"`
	ExpectedCxldLogicalID  string                           `json:"expectedCxldLogicalId"`
	ChallengeNonce         string                           `json:"challengeNonce"`
	Authority              vnextReaderIdentifyAuthorityWire `json:"authority"`
}

type vnextReaderIdentifyResponseWire struct {
	Protocol                  string                                `json:"protocol"`
	Operation                 string                                `json:"operation"`
	RequestDigest             string                                `json:"requestDigest"`
	AuthorityProof            vnextReaderIdentifyAuthorityProofWire `json:"authorityProof"`
	LocalExecutorNodeID       string                                `json:"localExecutorNodeId"`
	LocalCxldLogicalID        string                                `json:"localCxldLogicalId"`
	LocalProcessIncarnationID string                                `json:"localProcessIncarnationId"`
	ServerURISAN              string                                `json:"serverUriSan"`
	SupportedProtocols        vnextReaderIdentifyCapabilitiesWire   `json:"supportedProtocols"`
	CapabilitiesDigest        string                                `json:"capabilitiesDigest"`
	Receipt                   string                                `json:"receipt"`
}

func decodeVNextReaderIdentifyRequest(
	raw []byte,
) (vnextReaderIdentifyRequest, error) {
	var wire vnextReaderIdentifyRequestWire
	if err := decodeStrictVNextReaderIdentifyJSON(raw, &wire); err != nil {
		return vnextReaderIdentifyRequest{}, err
	}
	if wire.Protocol != vnextReaderIdentifyProtocol ||
		wire.Operation != vnextReaderIdentifyOperation {
		return vnextReaderIdentifyRequest{}, errors.New(
			"Reader IDENTIFY protocol or operation is invalid")
	}
	nonceDigest, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY challenge nonce", wire.ChallengeNonce)
	if err != nil {
		return vnextReaderIdentifyRequest{}, err
	}
	authority, err := wire.Authority.internal()
	if err != nil {
		return vnextReaderIdentifyRequest{}, err
	}
	request := vnextReaderIdentifyRequest{
		ExpectedExecutorNodeID: wire.ExpectedExecutorNodeID,
		ExpectedCxldLogicalID:  wire.ExpectedCxldLogicalID,
		ChallengeNonce:         vnextReaderIdentifyNonce(nonceDigest),
		Authority:              authority,
	}
	if err := validateVNextReaderIdentifyRequestPayload(request); err != nil {
		return vnextReaderIdentifyRequest{}, err
	}
	if authority.RequestDigest != vnextReaderIdentifyCanonicalRequestDigest(request) {
		return vnextReaderIdentifyRequest{}, errors.New(
			"IDENTIFY authority request digest does not match the canonical challenge")
	}
	return request, nil
}

func marshalVNextReaderIdentifyRequest(
	request vnextReaderIdentifyRequest,
) ([]byte, error) {
	if err := validateVNextReaderIdentifyRequestPayload(request); err != nil {
		return nil, err
	}
	if request.Authority.RequestDigest !=
		vnextReaderIdentifyCanonicalRequestDigest(request) {
		return nil, errors.New("IDENTIFY authority does not bind the request")
	}
	return marshalBoundedVNextReaderIdentifyJSON(vnextReaderIdentifyRequestWire{
		Protocol:               vnextReaderIdentifyProtocol,
		Operation:              vnextReaderIdentifyOperation,
		ExpectedExecutorNodeID: request.ExpectedExecutorNodeID,
		ExpectedCxldLogicalID:  request.ExpectedCxldLogicalID,
		ChallengeNonce:         hex.EncodeToString(request.ChallengeNonce[:]),
		Authority:              vnextReaderIdentifyAuthorityWireFromInternal(request.Authority),
	})
}

func marshalVNextReaderIdentifyResponse(
	response vnextReaderIdentifyResponse,
) ([]byte, error) {
	if err := validateVNextReaderIdentifyResponse(response); err != nil {
		return nil, err
	}
	capabilities := make(vnextReaderIdentifyCapabilitiesWire,
		len(response.SupportedProtocols))
	for index, capability := range response.SupportedProtocols {
		capabilities[index] = vnextReaderIdentifyCapabilityWire{
			Protocol: capability.Protocol, Operation: capability.Operation,
			ALPN: capability.ALPN,
		}
	}
	return marshalBoundedVNextReaderIdentifyJSON(vnextReaderIdentifyResponseWire{
		Protocol:                  vnextReaderIdentifyProtocol,
		Operation:                 vnextReaderIdentifyOperation,
		RequestDigest:             hex.EncodeToString(response.RequestDigest[:]),
		AuthorityProof:            vnextReaderIdentifyAuthorityProofWireFromInternal(response.AuthorityProof),
		LocalExecutorNodeID:       response.LocalExecutorNodeID,
		LocalCxldLogicalID:        response.LocalCxldLogicalID,
		LocalProcessIncarnationID: response.LocalProcessIncarnation.String(),
		ServerURISAN:              response.ServerURISAN,
		SupportedProtocols:        capabilities,
		CapabilitiesDigest:        hex.EncodeToString(response.CapabilitiesDigest[:]),
		Receipt:                   hex.EncodeToString(response.Receipt[:]),
	})
}

func decodeVNextReaderIdentifyResponse(
	raw []byte,
) (vnextReaderIdentifyResponse, error) {
	var wire vnextReaderIdentifyResponseWire
	if err := decodeStrictVNextReaderIdentifyJSON(raw, &wire); err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	if wire.Protocol != vnextReaderIdentifyProtocol ||
		wire.Operation != vnextReaderIdentifyOperation {
		return vnextReaderIdentifyResponse{}, errors.New(
			"Reader IDENTIFY response protocol or operation is invalid")
	}
	requestDigest, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY response request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	proof, err := wire.AuthorityProof.internal()
	if err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	incarnation, err := parseVNextReaderProcessIncarnation(
		wire.LocalProcessIncarnationID)
	if err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	capabilities := make([]vnextReaderIdentifyCapability,
		len(wire.SupportedProtocols))
	for index, capability := range wire.SupportedProtocols {
		capabilities[index] = vnextReaderIdentifyCapability{
			Protocol: capability.Protocol, Operation: capability.Operation,
			ALPN: capability.ALPN,
		}
	}
	capabilitiesDigest, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY response capabilities digest", wire.CapabilitiesDigest)
	if err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY response receipt", wire.Receipt)
	if err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	response := vnextReaderIdentifyResponse{
		RequestDigest: requestDigest, AuthorityProof: proof,
		LocalExecutorNodeID:     wire.LocalExecutorNodeID,
		LocalCxldLogicalID:      wire.LocalCxldLogicalID,
		LocalProcessIncarnation: incarnation,
		ServerURISAN:            wire.ServerURISAN,
		SupportedProtocols:      capabilities,
		CapabilitiesDigest:      capabilitiesDigest,
		Receipt:                 receipt,
	}
	if err := validateVNextReaderIdentifyResponse(response); err != nil {
		return vnextReaderIdentifyResponse{}, err
	}
	return response, nil
}

func validateVNextReaderIdentifyResponse(
	response vnextReaderIdentifyResponse,
) error {
	if allVNextReaderZero(response.RequestDigest[:]) ||
		response.AuthorityProof.RequestDigest != response.RequestDigest {
		return errors.New("IDENTIFY response request digest or proof is invalid")
	}
	if err := validateVNextReaderIdentity(
		"IDENTIFY response executor node ID", response.LocalExecutorNodeID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"IDENTIFY response cxld logical ID", response.LocalCxldLogicalID); err != nil {
		return err
	}
	if err := validateVNextReaderProcessIncarnation(
		response.LocalProcessIncarnation); err != nil {
		return err
	}
	if err := validateVNextReaderPreparePrincipalURI(response.ServerURISAN); err != nil {
		return err
	}
	if err := validateVNextReaderPreparePrincipalURI(
		response.AuthorityProof.AuthenticatedSchedulerPrincipal); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"IDENTIFY response Scheduler ID",
		response.AuthorityProof.SchedulerID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentifyCapabilities(
		response.SupportedProtocols); err != nil {
		return err
	}
	if response.CapabilitiesDigest !=
		vnextReaderIdentifyCanonicalCapabilitiesDigest(response.SupportedProtocols) {
		return errors.New("IDENTIFY response capabilities digest is invalid")
	}
	if allVNextReaderZero(response.AuthorityProof.AuthorityReceipt[:]) ||
		response.AuthorityProof.SchedulerFenceRevision == 0 ||
		response.AuthorityProof.LeaderLeaseID == 0 ||
		allVNextReaderZero(response.AuthorityProof.LeaderTermID[:]) {
		return errors.New("IDENTIFY response authority proof is incomplete")
	}
	if response.Receipt != vnextReaderIdentifyCanonicalReceipt(response) {
		return errors.New("IDENTIFY response receipt is invalid")
	}
	return nil
}

func (wire vnextReaderIdentifyAuthorityWire) internal() (
	vnextReaderIdentifyAuthorityEnvelope,
	error,
) {
	term, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY authority leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderIdentifyAuthorityEnvelope{}, err
	}
	key, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY authority key ID", wire.KeyID)
	if err != nil {
		return vnextReaderIdentifyAuthorityEnvelope{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY authority request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderIdentifyAuthorityEnvelope{}, err
	}
	signature, err := decodeVNextReaderPrepareHexSignature(
		"IDENTIFY authority signature", wire.Signature)
	if err != nil {
		return vnextReaderIdentifyAuthorityEnvelope{}, err
	}
	return vnextReaderIdentifyAuthorityEnvelope{
		Domain: wire.Domain, ClusterID: wire.ClusterID,
		SchedulerID:            wire.SchedulerID,
		SchedulerFenceRevision: wire.SchedulerFenceRevision,
		LeaderLeaseID:          wire.LeaderLeaseID, LeaderTermID: term, KeyID: key,
		RequestDigest: digest, Signature: signature,
	}, nil
}

func (wire vnextReaderIdentifyAuthorityProofWire) internal() (
	vnextReaderIdentifyAuthorityProof,
	error,
) {
	term, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY proof leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderIdentifyAuthorityProof{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY proof request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderIdentifyAuthorityProof{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"IDENTIFY proof authority receipt", wire.AuthorityReceipt)
	if err != nil {
		return vnextReaderIdentifyAuthorityProof{}, err
	}
	return vnextReaderIdentifyAuthorityProof{
		AuthenticatedSchedulerPrincipal: wire.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     wire.SchedulerID,
		SchedulerFenceRevision:          wire.SchedulerFenceRevision,
		LeaderLeaseID:                   wire.LeaderLeaseID, LeaderTermID: term,
		RequestDigest: digest, AuthorityReceipt: receipt,
	}, nil
}

func vnextReaderIdentifyAuthorityWireFromInternal(
	authority vnextReaderIdentifyAuthorityEnvelope,
) vnextReaderIdentifyAuthorityWire {
	return vnextReaderIdentifyAuthorityWire{
		Domain: authority.Domain, ClusterID: authority.ClusterID,
		SchedulerID:            authority.SchedulerID,
		SchedulerFenceRevision: authority.SchedulerFenceRevision,
		LeaderLeaseID:          authority.LeaderLeaseID,
		LeaderTermID:           hex.EncodeToString(authority.LeaderTermID[:]),
		KeyID:                  hex.EncodeToString(authority.KeyID[:]),
		RequestDigest:          hex.EncodeToString(authority.RequestDigest[:]),
		Signature:              hex.EncodeToString(authority.Signature[:]),
	}
}

func vnextReaderIdentifyAuthorityProofWireFromInternal(
	proof vnextReaderIdentifyAuthorityProof,
) vnextReaderIdentifyAuthorityProofWire {
	return vnextReaderIdentifyAuthorityProofWire{
		AuthenticatedSchedulerPrincipal: proof.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     proof.SchedulerID,
		SchedulerFenceRevision:          proof.SchedulerFenceRevision,
		LeaderLeaseID:                   proof.LeaderLeaseID,
		LeaderTermID:                    hex.EncodeToString(proof.LeaderTermID[:]),
		RequestDigest:                   hex.EncodeToString(proof.RequestDigest[:]),
		AuthorityReceipt:                hex.EncodeToString(proof.AuthorityReceipt[:]),
	}
}

func marshalBoundedVNextReaderIdentifyJSON(value interface{}) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", vnextReaderIdentifyProtocol, err)
	}
	if len(body) == 0 || len(body) > vnextReaderIdentifyMaxFrameBytes {
		return nil, fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			vnextReaderIdentifyProtocol, len(body), vnextReaderIdentifyMaxFrameBytes)
	}
	return body, nil
}

func decodeStrictVNextReaderIdentifyJSON(raw []byte, target interface{}) error {
	if len(raw) == 0 || len(raw) > vnextReaderIdentifyMaxFrameBytes {
		return fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			vnextReaderIdentifyProtocol, len(raw), vnextReaderIdentifyMaxFrameBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("decode %s: JSON is not valid UTF-8",
			vnextReaderIdentifyProtocol)
	}
	if err := validateVNextReaderPrepareJSONShape(raw, target); err != nil {
		return fmt.Errorf("decode %s: %w", vnextReaderIdentifyProtocol, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", vnextReaderIdentifyProtocol, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value",
				vnextReaderIdentifyProtocol)
		}
		return fmt.Errorf("decode %s trailer: %w", vnextReaderIdentifyProtocol, err)
	}
	return nil
}

var _ vnextReaderIdentifyAuthorityVerifier = (*vnextReaderIdentifyCurrentAuthorityVerifier)(nil)
var _ vnextReaderIdentifyTransportRPC = (*vnextReaderIdentifyRPC)(nil)
