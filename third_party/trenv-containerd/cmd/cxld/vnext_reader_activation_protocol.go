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
	"strings"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderActivationCommitProtocol  = "cxld.vnext-reader-activation-commit.v1"
	vnextReaderActivationCommitOperation = "vnextReaderCommitActivation"
	vnextReaderActivationCommitALPN      = "cxld-vnext-reader-activation-commit/1"

	vnextReaderActivationStatusProtocol  = "cxld.vnext-reader-activation-status-and-fence.v1"
	vnextReaderActivationStatusOperation = "vnextReaderActivationStatusAndFence"
	vnextReaderActivationStatusALPN      = "cxld-vnext-reader-activation-status/1"

	vnextReaderActivationProposalRequestDigestDomain      = "cxld-vnext-reader-activation-proposal-request-digest-v1"
	vnextReaderActivationProposalAuthorityDomain          = "cxld-vnext-reader-activation-proposal-authority-v1"
	vnextReaderActivationProposalAuthoritySignatureDomain = "cxld-vnext-reader-activation-proposal-authority-signature-v1"
	vnextReaderActivationProposalAuthorityReceiptDomain   = "cxld-vnext-reader-activation-proposal-authority-receipt-v1"
	vnextReaderActivationProposalReceiptDomain            = "cxld-vnext-reader-activation-proposal-receipt-v1"

	vnextReaderActivationCommitRequestDigestDomain      = "cxld-vnext-reader-activation-commit-request-digest-v1"
	vnextReaderActivationCommitAuthorityDomain          = "cxld-vnext-reader-activation-commit-authority-v1"
	vnextReaderActivationCommitAuthoritySignatureDomain = "cxld-vnext-reader-activation-commit-authority-signature-v1"
	vnextReaderActivationCommitAuthorityReceiptDomain   = "cxld-vnext-reader-activation-commit-authority-receipt-v1"
	vnextReaderActivationCommitReceiptDomain            = "cxld-vnext-reader-activation-commit-receipt-v1"

	vnextReaderActivationStatusRequestDigestDomain      = "cxld-vnext-reader-activation-status-and-fence-request-digest-v1"
	vnextReaderActivationStatusAuthorityDomain          = "cxld-vnext-reader-activation-status-and-fence-authority-v1"
	vnextReaderActivationStatusAuthoritySignatureDomain = "cxld-vnext-reader-activation-status-and-fence-authority-signature-v1"
	vnextReaderActivationStatusAuthorityReceiptDomain   = "cxld-vnext-reader-activation-status-and-fence-authority-receipt-v1"
	vnextReaderActivationStatusReceiptDomain            = "cxld-vnext-reader-activation-status-and-fence-receipt-v1"

	vnextReaderActivationMaxFrameBytes   = 16 << 20
	vnextReaderActivationMaxObjectFields = 16
	vnextReaderActivationMaxJSONDepth    = 32
)

type vnextReaderActivationOperationSpec struct {
	protocol                 string
	operation                string
	alpn                     string
	requestDigestDomain      string
	authorityDomain          string
	authoritySignatureDomain string
	authorityReceiptDomain   string
	receiptDomain            string
}

var (
	vnextReaderActivationProposalSpec = vnextReaderActivationOperationSpec{
		protocol:                 vnextReaderActivationProposalProtocol,
		operation:                vnextReaderActivationProposalOperation,
		alpn:                     vnextReaderActivationProposalALPN,
		requestDigestDomain:      vnextReaderActivationProposalRequestDigestDomain,
		authorityDomain:          vnextReaderActivationProposalAuthorityDomain,
		authoritySignatureDomain: vnextReaderActivationProposalAuthoritySignatureDomain,
		authorityReceiptDomain:   vnextReaderActivationProposalAuthorityReceiptDomain,
		receiptDomain:            vnextReaderActivationProposalReceiptDomain,
	}
	vnextReaderActivationCommitSpec = vnextReaderActivationOperationSpec{
		protocol:                 vnextReaderActivationCommitProtocol,
		operation:                vnextReaderActivationCommitOperation,
		alpn:                     vnextReaderActivationCommitALPN,
		requestDigestDomain:      vnextReaderActivationCommitRequestDigestDomain,
		authorityDomain:          vnextReaderActivationCommitAuthorityDomain,
		authoritySignatureDomain: vnextReaderActivationCommitAuthoritySignatureDomain,
		authorityReceiptDomain:   vnextReaderActivationCommitAuthorityReceiptDomain,
		receiptDomain:            vnextReaderActivationCommitReceiptDomain,
	}
	vnextReaderActivationStatusSpec = vnextReaderActivationOperationSpec{
		protocol:                 vnextReaderActivationStatusProtocol,
		operation:                vnextReaderActivationStatusOperation,
		alpn:                     vnextReaderActivationStatusALPN,
		requestDigestDomain:      vnextReaderActivationStatusRequestDigestDomain,
		authorityDomain:          vnextReaderActivationStatusAuthorityDomain,
		authoritySignatureDomain: vnextReaderActivationStatusAuthoritySignatureDomain,
		authorityReceiptDomain:   vnextReaderActivationStatusAuthorityReceiptDomain,
		receiptDomain:            vnextReaderActivationStatusReceiptDomain,
	}
)

type vnextReaderActivationAuthorityEnvelope struct {
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

type vnextReaderActivationAuthorityProof struct {
	AuthenticatedSchedulerPrincipal string
	SchedulerID                     string
	SchedulerFenceRevision          uint64
	LeaderLeaseID                   uint64
	LeaderTermID                    [sha256.Size]byte
	RequestDigest                   [sha256.Size]byte
	AuthorityReceipt                [sha256.Size]byte
}

// The verifier must authenticate one current Scheduler term B. Historical
// ACQUIRED term A is intentionally absent from this interface: current term B
// may reconcile and advance exact retained work from an older term A.
type vnextReaderActivationAuthorityVerifier interface {
	VerifyVNextReaderActivationAuthority(
		context.Context,
		string,
		vnextReaderActivationOperationSpec,
		[sha256.Size]byte,
		vnextReaderActivationAuthorityEnvelope,
	) (vnextReaderActivationAuthorityProof, error)
}

type vnextReaderActivationActiveState struct {
	CatalogState   vnextReaderCatalogAuthorizationState
	LastMutationID string
}

func validateVNextReaderActivationAuthorityEnvelope(
	spec vnextReaderActivationOperationSpec,
	authority vnextReaderActivationAuthorityEnvelope,
) error {
	if err := validateVNextReaderActivationOperationSpec(spec); err != nil {
		return err
	}
	if authority.Domain != spec.authorityDomain {
		return fmt.Errorf("Reader activation authority domain is %q, expected %q",
			authority.Domain, spec.authorityDomain)
	}
	if err := validateVNextReaderPrepareClusterID(authority.ClusterID); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"Reader activation authority Scheduler ID", authority.SchedulerID); err != nil {
		return err
	}
	if authority.SchedulerFenceRevision == 0 ||
		authority.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		authority.LeaderLeaseID == 0 ||
		authority.LeaderLeaseID > cxlcheckpoint.MaxSignedLong {
		return errors.New(
			"Reader activation authority fence or leader lease is outside the positive ABI")
	}
	if allVNextReaderZero(authority.LeaderTermID[:]) ||
		allVNextReaderZero(authority.KeyID[:]) ||
		allVNextReaderZero(authority.RequestDigest[:]) ||
		allVNextReaderZero(authority.Signature[:]) {
		return errors.New(
			"Reader activation authority term, key, request digest, or signature is zero")
	}
	return nil
}

func validateVNextReaderActivationAuthorityProof(
	spec vnextReaderActivationOperationSpec,
	proof vnextReaderActivationAuthorityProof,
	authenticatedSchedulerPrincipal string,
	requestDigest [sha256.Size]byte,
	authority vnextReaderActivationAuthorityEnvelope,
) error {
	if err := validateVNextReaderPreparePrincipalURI(
		proof.AuthenticatedSchedulerPrincipal); err != nil {
		return err
	}
	if err := validateVNextReaderIdentity(
		"verified activation Scheduler ID", proof.SchedulerID); err != nil {
		return err
	}
	if proof.SchedulerFenceRevision == 0 ||
		proof.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong ||
		proof.LeaderLeaseID == 0 ||
		proof.LeaderLeaseID > cxlcheckpoint.MaxSignedLong ||
		allVNextReaderZero(proof.LeaderTermID[:]) ||
		allVNextReaderZero(proof.RequestDigest[:]) ||
		allVNextReaderZero(proof.AuthorityReceipt[:]) {
		return errors.New("verified Reader activation Scheduler proof is incomplete")
	}
	if proof.AuthenticatedSchedulerPrincipal != authenticatedSchedulerPrincipal ||
		proof.SchedulerID != authority.SchedulerID ||
		proof.SchedulerFenceRevision != authority.SchedulerFenceRevision ||
		proof.LeaderLeaseID != authority.LeaderLeaseID ||
		proof.LeaderTermID != authority.LeaderTermID ||
		proof.RequestDigest != requestDigest ||
		proof.RequestDigest != authority.RequestDigest {
		return errors.New(
			"verified Reader activation Scheduler principal, leader, fence, or request digest differs from current authority")
	}
	wantReceipt, err := vnextReaderActivationCanonicalAuthorityReceipt(
		spec, authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return fmt.Errorf("derive verified Reader activation authority receipt: %w", err)
	}
	if proof.AuthorityReceipt != wantReceipt {
		return errors.New(
			"verified Reader activation authority receipt does not bind the principal and complete envelope")
	}
	return nil
}

func vnextReaderActivationAuthoritySignaturePreimage(
	spec vnextReaderActivationOperationSpec,
	authority vnextReaderActivationAuthorityEnvelope,
) ([]byte, error) {
	if err := validateVNextReaderActivationAuthorityEnvelopeWithoutSignature(
		spec, authority); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, spec.authoritySignatureDomain)
	vnextReaderPrepareWriteString(&buffer, spec.protocol)
	vnextReaderPrepareWriteString(&buffer, spec.operation)
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

func validateVNextReaderActivationAuthorityEnvelopeWithoutSignature(
	spec vnextReaderActivationOperationSpec,
	authority vnextReaderActivationAuthorityEnvelope,
) error {
	signature := authority.Signature
	authority.Signature = [ed25519.SignatureSize]byte{1}
	err := validateVNextReaderActivationAuthorityEnvelope(spec, authority)
	authority.Signature = signature
	return err
}

func vnextReaderActivationCanonicalAuthorityReceipt(
	spec vnextReaderActivationOperationSpec,
	authenticatedSchedulerPrincipal string,
	authority vnextReaderActivationAuthorityEnvelope,
) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, err
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(spec, authority); err != nil {
		return zero, err
	}
	preimage, err := vnextReaderActivationAuthoritySignaturePreimage(spec, authority)
	if err != nil {
		return zero, err
	}
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, spec.authorityReceiptDomain)
	vnextReaderPrepareWriteString(&buffer, authenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteU64(&buffer, uint64(len(preimage)))
	buffer.Write(preimage)
	buffer.Write(authority.Signature[:])
	return sha256.Sum256(buffer.Bytes()), nil
}

func vnextReaderActivationCanonicalProposalRequestDigest(
	request vnextReaderActivationRequestIdentity,
) [sha256.Size]byte {
	return vnextReaderActivationCanonicalIdentityRequestDigest(
		vnextReaderActivationProposalSpec, request)
}

func vnextReaderActivationCanonicalStatusRequestDigest(
	request vnextReaderActivationRequestIdentity,
) [sha256.Size]byte {
	return vnextReaderActivationCanonicalIdentityRequestDigest(
		vnextReaderActivationStatusSpec, request)
}

func vnextReaderActivationCanonicalIdentityRequestDigest(
	spec vnextReaderActivationOperationSpec,
	request vnextReaderActivationRequestIdentity,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(&buffer, spec.requestDigestDomain)
	vnextReaderPrepareWriteString(&buffer, spec.protocol)
	vnextReaderPrepareWriteString(&buffer, spec.operation)
	vnextReaderWriteCanonicalAcquired(&buffer, request.Acquired)
	vnextReaderPrepareWriteString(&buffer, request.ActivationRequestID)
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderActivationCanonicalCommitRequestDigest(
	acquired vnextReaderAcquiredAuthorization,
	activation vnextReaderActivationIntent,
	activeState vnextReaderActivationActiveState,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationCommitSpec.requestDigestDomain)
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationCommitSpec.protocol)
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationCommitSpec.operation)
	vnextReaderWriteCanonicalAcquired(&buffer, acquired)
	vnextReaderActivationWriteCanonicalEvidence(&buffer, activation)
	vnextReaderPrepareWriteString(&buffer, string(activeState.CatalogState))
	vnextReaderPrepareWriteString(&buffer, activeState.LastMutationID)
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderActivationCanonicalEvidenceReceipt(
	activation vnextReaderActivationIntent,
	localExecutorNodeID string,
	localCxldLogicalID string,
	localProcess vnextReaderProcessIncarnation,
) [sha256.Size]byte {
	var buffer bytes.Buffer
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationEvidenceReceiptDomain)
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationProposalProtocol)
	vnextReaderPrepareWriteString(
		&buffer, vnextReaderActivationProposalOperation)
	vnextReaderWriteCanonicalAcquired(&buffer, activation.Request.Acquired)
	vnextReaderPrepareWriteString(
		&buffer, activation.Request.ActivationRequestID)
	vnextReaderPrepareWriteString(&buffer, localExecutorNodeID)
	vnextReaderPrepareWriteString(&buffer, localCxldLogicalID)
	vnextReaderPrepareWriteString(&buffer, localProcess.String())
	vnextReaderPrepareWriteString(&buffer, activation.MappingID)
	vnextReaderPrepareWriteU64(&buffer, activation.MappingGeneration)
	vnextReaderPrepareWriteU64(
		&buffer, uint64(activation.ActivatedAtEpochMillis))
	vnextReaderPrepareWriteString(
		&buffer, string(vnextReaderActivationPending))
	return sha256.Sum256(buffer.Bytes())
}

func vnextReaderActivationWriteCanonicalEvidence(
	buffer *bytes.Buffer,
	activation vnextReaderActivationIntent,
) {
	vnextReaderPrepareWriteString(
		buffer, activation.Request.ActivationRequestID)
	vnextReaderPrepareWriteString(buffer, activation.MappingID)
	vnextReaderPrepareWriteU64(buffer, activation.MappingGeneration)
	vnextReaderPrepareWriteU64(
		buffer, uint64(activation.ActivatedAtEpochMillis))
	buffer.Write(activation.CxldReceipt[:])
}

func vnextReaderActivationWriteCanonicalAuthorityProof(
	buffer *bytes.Buffer,
	proof vnextReaderActivationAuthorityProof,
) {
	vnextReaderPrepareWriteString(
		buffer, proof.AuthenticatedSchedulerPrincipal)
	vnextReaderPrepareWriteString(buffer, proof.SchedulerID)
	vnextReaderPrepareWriteU64(buffer, proof.SchedulerFenceRevision)
	vnextReaderPrepareWriteU64(buffer, proof.LeaderLeaseID)
	buffer.Write(proof.LeaderTermID[:])
	buffer.Write(proof.RequestDigest[:])
	buffer.Write(proof.AuthorityReceipt[:])
}

func validateVNextReaderActivationRequestIdentity(
	request vnextReaderActivationRequestIdentity,
) error {
	if err := validateVNextReaderAcquiredAuthorizationStructure(request.Acquired); err != nil {
		return fmt.Errorf("validate Reader activation ACQUIRED: %w", err)
	}
	if err := validateVNextReaderIdentity(
		"activation request ID", request.ActivationRequestID); err != nil {
		return err
	}
	return nil
}

func validateVNextReaderActivationEvidence(
	activation vnextReaderActivationIntent,
	request vnextReaderActivationRequestIdentity,
) error {
	if !equalVNextReaderActivationRequestIdentity(activation.Request, request) {
		return errors.New("Reader activation evidence request identity differs")
	}
	if err := validateVNextReaderIdentity(
		"Reader activation mapping ID", activation.MappingID); err != nil {
		return err
	}
	if activation.MappingGeneration == 0 ||
		activation.MappingGeneration > cxlcheckpoint.MaxSignedLong {
		return errors.New(
			"Reader activation mapping generation is outside the positive signed ABI")
	}
	if activation.ActivatedAtEpochMillis < 0 {
		return errors.New("Reader activation time is negative")
	}
	if allVNextReaderZero(activation.CxldReceipt[:]) {
		return errors.New("Reader activation cxld receipt is zero")
	}
	if activation.State != vnextReaderActivationPending &&
		activation.State != vnextReaderActivationActiveArmed {
		return fmt.Errorf("Reader activation state %q is invalid", activation.State)
	}
	return nil
}

func validateVNextReaderActivationActiveState(
	activeState vnextReaderActivationActiveState,
	activationRequestID string,
) error {
	if activeState.CatalogState != vnextReaderCatalogAuthorizationActive {
		return fmt.Errorf("Reader activation catalog state %q is not ACTIVE",
			activeState.CatalogState)
	}
	if activeState.LastMutationID != activationRequestID {
		return errors.New(
			"Reader activation ACTIVE last mutation ID differs from activation request ID")
	}
	return validateVNextReaderIdentity(
		"Reader activation ACTIVE last mutation ID", activeState.LastMutationID)
}

func cloneVNextReaderActivationAuthorityEnvelope(
	authority vnextReaderActivationAuthorityEnvelope,
) vnextReaderActivationAuthorityEnvelope {
	cloned := authority
	cloned.Domain = cloneVNextReaderRetainedString(authority.Domain)
	cloned.ClusterID = cloneVNextReaderRetainedString(authority.ClusterID)
	cloned.SchedulerID = cloneVNextReaderRetainedString(authority.SchedulerID)
	return cloned
}

func cloneVNextReaderActivationAuthorityProof(
	proof vnextReaderActivationAuthorityProof,
) vnextReaderActivationAuthorityProof {
	cloned := proof
	cloned.AuthenticatedSchedulerPrincipal = cloneVNextReaderRetainedString(
		proof.AuthenticatedSchedulerPrincipal)
	cloned.SchedulerID = cloneVNextReaderRetainedString(proof.SchedulerID)
	return cloned
}

func validateVNextReaderActivationOperationSpec(
	spec vnextReaderActivationOperationSpec,
) error {
	if spec != vnextReaderActivationProposalSpec &&
		spec != vnextReaderActivationCommitSpec &&
		spec != vnextReaderActivationStatusSpec {
		return errors.New("Reader activation operation specification is invalid")
	}
	return nil
}

type vnextReaderActivationAuthorityWire struct {
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

type vnextReaderActivationAuthorityProofWire struct {
	AuthenticatedSchedulerPrincipal string `json:"authenticatedSchedulerPrincipal"`
	SchedulerID                     string `json:"schedulerId"`
	SchedulerFenceRevision          uint64 `json:"schedulerFenceRevision"`
	LeaderLeaseID                   uint64 `json:"leaderLeaseId"`
	LeaderTermID                    string `json:"leaderTermId"`
	RequestDigest                   string `json:"requestDigest"`
	AuthorityReceipt                string `json:"authorityReceipt"`
}

type vnextReaderActivationEvidenceWire struct {
	ActivationRequestID    string `json:"activationRequestId"`
	MappingID              string `json:"mappingId"`
	MappingGeneration      uint64 `json:"mappingGeneration"`
	ActivatedAtEpochMillis int64  `json:"activatedAtEpochMillis"`
	CxldReceipt            string `json:"cxldReceipt"`
}

type vnextReaderActivationActiveStateWire struct {
	CatalogState   string `json:"catalogState"`
	LastMutationID string `json:"lastMutationId"`
}

func (wire vnextReaderActivationAuthorityWire) internal() (
	vnextReaderActivationAuthorityEnvelope,
	error,
) {
	term, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation authority leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderActivationAuthorityEnvelope{}, err
	}
	key, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation authority key ID", wire.KeyID)
	if err != nil {
		return vnextReaderActivationAuthorityEnvelope{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation authority request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderActivationAuthorityEnvelope{}, err
	}
	signature, err := decodeVNextReaderPrepareHexSignature(
		"Reader activation authority signature", wire.Signature)
	if err != nil {
		return vnextReaderActivationAuthorityEnvelope{}, err
	}
	return vnextReaderActivationAuthorityEnvelope{
		Domain:                 wire.Domain,
		ClusterID:              wire.ClusterID,
		SchedulerID:            wire.SchedulerID,
		SchedulerFenceRevision: wire.SchedulerFenceRevision,
		LeaderLeaseID:          wire.LeaderLeaseID,
		LeaderTermID:           term,
		KeyID:                  key,
		RequestDigest:          digest,
		Signature:              signature,
	}, nil
}

func (wire vnextReaderActivationAuthorityProofWire) internal() (
	vnextReaderActivationAuthorityProof,
	error,
) {
	term, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation proof leader term ID", wire.LeaderTermID)
	if err != nil {
		return vnextReaderActivationAuthorityProof{}, err
	}
	digest, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation proof request digest", wire.RequestDigest)
	if err != nil {
		return vnextReaderActivationAuthorityProof{}, err
	}
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation proof authority receipt", wire.AuthorityReceipt)
	if err != nil {
		return vnextReaderActivationAuthorityProof{}, err
	}
	return vnextReaderActivationAuthorityProof{
		AuthenticatedSchedulerPrincipal: wire.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     wire.SchedulerID,
		SchedulerFenceRevision:          wire.SchedulerFenceRevision,
		LeaderLeaseID:                   wire.LeaderLeaseID,
		LeaderTermID:                    term,
		RequestDigest:                   digest,
		AuthorityReceipt:                receipt,
	}, nil
}

func (wire vnextReaderActivationEvidenceWire) internal(
	request vnextReaderActivationRequestIdentity,
	state vnextReaderActivationState,
) (vnextReaderActivationIntent, error) {
	receipt, err := decodeVNextReaderPrepareHexDigest(
		"Reader activation cxld receipt", wire.CxldReceipt)
	if err != nil {
		return vnextReaderActivationIntent{}, err
	}
	activation := vnextReaderActivationIntent{
		Request:                cloneVNextReaderActivationRequestIdentity(request),
		MappingID:              wire.MappingID,
		MappingGeneration:      wire.MappingGeneration,
		ActivatedAtEpochMillis: wire.ActivatedAtEpochMillis,
		CxldReceipt:            receipt,
		State:                  state,
	}
	if wire.ActivationRequestID != request.ActivationRequestID {
		return vnextReaderActivationIntent{}, errors.New(
			"Reader activation wire request ID differs from request identity")
	}
	if err := validateVNextReaderActivationEvidence(activation, request); err != nil {
		return vnextReaderActivationIntent{}, err
	}
	return activation, nil
}

func vnextReaderActivationAuthorityWireFromInternal(
	authority vnextReaderActivationAuthorityEnvelope,
) vnextReaderActivationAuthorityWire {
	return vnextReaderActivationAuthorityWire{
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

func vnextReaderActivationAuthorityProofWireFromInternal(
	proof vnextReaderActivationAuthorityProof,
) vnextReaderActivationAuthorityProofWire {
	return vnextReaderActivationAuthorityProofWire{
		AuthenticatedSchedulerPrincipal: proof.AuthenticatedSchedulerPrincipal,
		SchedulerID:                     proof.SchedulerID,
		SchedulerFenceRevision:          proof.SchedulerFenceRevision,
		LeaderLeaseID:                   proof.LeaderLeaseID,
		LeaderTermID:                    hex.EncodeToString(proof.LeaderTermID[:]),
		RequestDigest:                   hex.EncodeToString(proof.RequestDigest[:]),
		AuthorityReceipt:                hex.EncodeToString(proof.AuthorityReceipt[:]),
	}
}

func vnextReaderActivationEvidenceWireFromInternal(
	activation vnextReaderActivationIntent,
) vnextReaderActivationEvidenceWire {
	return vnextReaderActivationEvidenceWire{
		ActivationRequestID:    activation.Request.ActivationRequestID,
		MappingID:              activation.MappingID,
		MappingGeneration:      activation.MappingGeneration,
		ActivatedAtEpochMillis: activation.ActivatedAtEpochMillis,
		CxldReceipt:            hex.EncodeToString(activation.CxldReceipt[:]),
	}
}

func vnextReaderActivationActiveStateWireFromInternal(
	activeState vnextReaderActivationActiveState,
) vnextReaderActivationActiveStateWire {
	return vnextReaderActivationActiveStateWire{
		CatalogState:   string(activeState.CatalogState),
		LastMutationID: activeState.LastMutationID,
	}
}

func marshalBoundedVNextReaderActivationJSON(
	spec vnextReaderActivationOperationSpec,
	value interface{},
) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s: %w", spec.protocol, err)
	}
	if len(body) == 0 || len(body) > vnextReaderActivationMaxFrameBytes {
		return nil, fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			spec.protocol, len(body), vnextReaderActivationMaxFrameBytes)
	}
	return body, nil
}

func decodeStrictVNextReaderActivationJSON(
	spec vnextReaderActivationOperationSpec,
	raw []byte,
	target interface{},
) error {
	if len(raw) == 0 || len(raw) > vnextReaderActivationMaxFrameBytes {
		return fmt.Errorf("%s frame has %d bytes, allowed range is 1..%d",
			spec.protocol, len(raw), vnextReaderActivationMaxFrameBytes)
	}
	if !utf8.Valid(raw) {
		return fmt.Errorf("decode %s: JSON is not valid UTF-8", spec.protocol)
	}
	if err := validateVNextReaderActivationJSONShape(raw, target); err != nil {
		return fmt.Errorf("decode %s: %w", spec.protocol, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", spec.protocol, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", spec.protocol)
		}
		return fmt.Errorf("decode %s trailer: %w", spec.protocol, err)
	}
	return nil
}

func validateVNextReaderActivationJSONShape(raw []byte, target interface{}) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Ptr ||
		targetType.Elem().Kind() != reflect.Struct {
		return errors.New(
			"strict Reader activation target must be a pointer to a struct")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateVNextReaderActivationJSONValue(
		decoder, targetType.Elem(), "message", 1); err != nil {
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

func validateVNextReaderActivationJSONValue(
	decoder *json.Decoder,
	valueType reflect.Type,
	path string,
	depth int,
) error {
	if depth > vnextReaderActivationMaxJSONDepth {
		return fmt.Errorf("%s exceeds maximum JSON nesting depth %d",
			path, vnextReaderActivationMaxJSONDepth)
	}
	switch valueType.Kind() {
	case reflect.Ptr:
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return nil
		}
		nested := json.NewDecoder(bytes.NewReader(raw))
		nested.UseNumber()
		if err := validateVNextReaderActivationJSONValue(
			nested, valueType.Elem(), path, depth+1); err != nil {
			return err
		}
		var trailing interface{}
		if err := nested.Decode(&trailing); !errors.Is(err, io.EOF) {
			return fmt.Errorf("%s has trailing JSON", path)
		}
		return nil
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
			if count >= vnextReaderActivationMaxObjectFields {
				return fmt.Errorf("%s contains more than %d fields",
					path, vnextReaderActivationMaxObjectFields)
			}
			fieldToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%s field: %w", path, err)
			}
			name, ok := fieldToken.(string)
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
			if err := validateVNextReaderActivationJSONValue(
				decoder, fieldType, path+"."+name, depth+1); err != nil {
				return err
			}
			count++
		}
		closing, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s closing token: %w", path, err)
		}
		if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
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
			if limit == 0 || count >= limit {
				return fmt.Errorf("%s has an unsupported or oversized array", path)
			}
			if err := validateVNextReaderActivationJSONValue(
				decoder, valueType.Elem(), fmt.Sprintf("%s[%d]", path, count), depth+1); err != nil {
				return err
			}
			count++
		}
		closing, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s closing token: %w", path, err)
		}
		if delimiter, ok := closing.(json.Delim); !ok || delimiter != ']' {
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
			return fmt.Errorf("%s must be a JSON integer", path)
		}
		return nil
	default:
		return fmt.Errorf("%s has unsupported JSON type %s", path, valueType)
	}
}
