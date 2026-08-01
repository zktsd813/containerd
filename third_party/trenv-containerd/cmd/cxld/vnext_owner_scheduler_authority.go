package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	vnextOwnerSchedulerAuthorityProtocol = "cxld.vnext-owner.v4"
	vnextOwnerSchedulerLeaderValuePrefix = "cxld-scheduler-leader-v1"
	vnextOwnerSchedulerLeaderKeySuffix   = "/cxl-checkpoint/global-orchestrator-leader"

	vnextOwnerSchedulerTermDomain      = "cxld-vnext-owner-scheduler-term-v1"
	vnextOwnerSchedulerMutationDomain  = "cxld-vnext-owner-scheduler-mutation-v1"
	vnextOwnerSchedulerSignatureDomain = "cxld-vnext-owner-scheduler-signature-v1"
	vnextOwnerSchedulerReceiptDomain   = "cxld-vnext-owner-scheduler-receipt-v1"

	vnextOwnerSchedulerNonceBytes     = 32
	vnextOwnerSchedulerDigestBytes    = sha256.Size
	vnextOwnerSchedulerSignatureBytes = ed25519.SignatureSize
	vnextOwnerSchedulerMaxLeaderBytes = 4096
)

var (
	errVNextOwnerSchedulerAuthority       = errors.New("VNext Owner Scheduler authority is invalid")
	errVNextOwnerSchedulerFenced          = errors.New("VNext Owner Scheduler term is fenced")
	errVNextOwnerSchedulerReceiptConflict = errors.New(
		"VNext Owner Scheduler mutation receipt conflicts with durable state")
)

// vnextOwnerSchedulerAuthority is the complete signed Scheduler authority
// envelope carried only by Scheduler mutation RPCs. LeaderKey is deliberately
// absent: every Owner reads one exact locally configured key and commits that
// key to TermID.
type vnextOwnerSchedulerAuthority struct {
	ClusterID      string `json:"clusterId"`
	CreateRevision uint64 `json:"createRevision"`
	ModRevision    uint64 `json:"modRevision"`
	LeaseID        string `json:"leaseId"`
	LeaderValue    string `json:"leaderValue"`
	KeyID          string `json:"keyId"`
	TermID         string `json:"termId"`
	Signature      string `json:"signature"`
}

type vnextOwnerSchedulerLeaderTerm struct {
	SchedulerID string
	LeaseID     uint64
	Nonce       [vnextOwnerSchedulerNonceBytes]byte
	SPKI        []byte
	PublicKey   ed25519.PublicKey
	KeyID       [vnextOwnerSchedulerDigestBytes]byte
}

type vnextOwnerSchedulerParsedAuthority struct {
	ClusterID      uint64
	CreateRevision uint64
	ModRevision    uint64
	LeaseID        uint64
	LeaderValue    string
	Leader         vnextOwnerSchedulerLeaderTerm
	TermID         [vnextOwnerSchedulerDigestBytes]byte
	Signature      [vnextOwnerSchedulerSignatureBytes]byte
}

type vnextOwnerSchedulerVerifiedAuthority struct {
	Parsed         vnextOwnerSchedulerParsedAuthority
	MutationDigest [vnextOwnerSchedulerDigestBytes]byte
	Receipt        [vnextOwnerSchedulerDigestBytes]byte
	HighWater      vnextOwnerSchedulerHighWater
}

type vnextOwnerSchedulerProof struct {
	TermID         [vnextOwnerSchedulerDigestBytes]byte
	MutationDigest [vnextOwnerSchedulerDigestBytes]byte
	Receipt        [vnextOwnerSchedulerDigestBytes]byte
}

func (verified vnextOwnerSchedulerVerifiedAuthority) proof() vnextOwnerSchedulerProof {
	return vnextOwnerSchedulerProof{
		TermID:         verified.Parsed.TermID,
		MutationDigest: verified.MutationDigest,
		Receipt:        verified.Receipt,
	}
}

func (proof vnextOwnerSchedulerProof) valid() bool {
	return !vnextAllZero(proof.TermID[:]) &&
		!vnextAllZero(proof.MutationDigest[:]) &&
		!vnextAllZero(proof.Receipt[:])
}

// vnextOwnerSchedulerHighWater is Owner control metadata. It must never be
// copied into page descriptors, publication metadata, or the restore path.
type vnextOwnerSchedulerHighWater struct {
	Initialized       bool
	LeaderKeyDigest   [vnextOwnerSchedulerDigestBytes]byte
	ClusterID         uint64
	CreateRevision    uint64
	ModRevision       uint64
	LeaseID           uint64
	LeaderValueDigest [vnextOwnerSchedulerDigestBytes]byte
	PublicKeyDigest   [vnextOwnerSchedulerDigestBytes]byte
	SchedulerTermID   [vnextOwnerSchedulerDigestBytes]byte
}

func validateVNextOwnerVerifiedSchedulerAuthority(
	authority *vnextOwnerSchedulerVerifiedAuthority,
) error {
	if authority == nil || !authority.proof().valid() {
		return fmt.Errorf("%w: verified Scheduler proof is unavailable",
			errVNextOwnerSchedulerAuthority)
	}
	if err := authority.HighWater.validate(); err != nil {
		return fmt.Errorf("%w: %v", errVNextOwnerSchedulerAuthority, err)
	}
	parsed := authority.Parsed
	leaderValueDigest := sha256.Sum256([]byte(parsed.LeaderValue))
	if parsed.TermID != authority.HighWater.SchedulerTermID ||
		parsed.ClusterID != authority.HighWater.ClusterID ||
		parsed.CreateRevision != authority.HighWater.CreateRevision ||
		parsed.ModRevision != authority.HighWater.ModRevision ||
		parsed.LeaseID != authority.HighWater.LeaseID ||
		leaderValueDigest != authority.HighWater.LeaderValueDigest ||
		parsed.Leader.KeyID != authority.HighWater.PublicKeyDigest {
		return fmt.Errorf("%w: verified Scheduler term and high-water differ",
			errVNextOwnerSchedulerAuthority)
	}
	wantReceipt := vnextOwnerSchedulerReceipt(
		parsed.TermID, authority.MutationDigest, parsed.Signature)
	if wantReceipt != authority.Receipt {
		return fmt.Errorf("%w: verified Scheduler receipt is inconsistent",
			errVNextOwnerSchedulerAuthority)
	}
	return nil
}

func formatVNextOwnerSchedulerLeaderValue(
	schedulerID string,
	leaseID uint64,
	nonce [vnextOwnerSchedulerNonceBytes]byte,
	publicKey ed25519.PublicKey,
) (string, error) {
	if err := validateVNextOwnerClientText("Scheduler ID", schedulerID); err != nil {
		return "", err
	}
	if leaseID == 0 || leaseID > uint64(math.MaxInt64) {
		return "", errors.New("Scheduler lease ID is outside the positive signed ABI")
	}
	if vnextAllZero(nonce[:]) {
		return "", errors.New("Scheduler term nonce is zero")
	}
	if len(publicKey) != ed25519.PublicKeySize || vnextAllZero(publicKey) {
		return "", errors.New("Scheduler Ed25519 public key is invalid")
	}
	spki, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal Scheduler Ed25519 SPKI: %w", err)
	}
	encode := base64.RawURLEncoding.EncodeToString
	value := strings.Join([]string{
		vnextOwnerSchedulerLeaderValuePrefix,
		encode([]byte(schedulerID)),
		fmt.Sprintf("%016x", leaseID),
		encode(nonce[:]),
		encode(spki),
	}, ":")
	if len(value) > vnextOwnerSchedulerMaxLeaderBytes {
		return "", errors.New("Scheduler leader value is too long")
	}
	return value, nil
}

func parseVNextOwnerSchedulerLeaderValue(
	value string,
) (vnextOwnerSchedulerLeaderTerm, error) {
	var term vnextOwnerSchedulerLeaderTerm
	if value == "" || len(value) > vnextOwnerSchedulerMaxLeaderBytes {
		return term, errors.New("Scheduler leader value is empty or too long")
	}
	fields := strings.Split(value, ":")
	if len(fields) != 5 || fields[0] != vnextOwnerSchedulerLeaderValuePrefix {
		return term, errors.New("Scheduler leader value has the wrong schema")
	}
	schedulerRaw, err := decodeVNextOwnerSchedulerRawURL("Scheduler ID", fields[1])
	if err != nil {
		return term, err
	}
	term.SchedulerID = string(schedulerRaw)
	if err := validateVNextOwnerClientText("Scheduler ID", term.SchedulerID); err != nil {
		return term, err
	}
	term.LeaseID, err = decodeVNextOwnerSchedulerHexU64("Scheduler lease ID", fields[2], true)
	if err != nil {
		return term, err
	}
	nonce, err := decodeVNextOwnerSchedulerRawURL("Scheduler term nonce", fields[3])
	if err != nil {
		return term, err
	}
	if len(nonce) != len(term.Nonce) || vnextAllZero(nonce) {
		return term, errors.New("Scheduler term nonce is not exactly 32 non-zero bytes")
	}
	copy(term.Nonce[:], nonce)
	term.SPKI, err = decodeVNextOwnerSchedulerRawURL("Scheduler Ed25519 SPKI", fields[4])
	if err != nil {
		return term, err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(term.SPKI)
	if err != nil {
		return term, fmt.Errorf("parse Scheduler Ed25519 SPKI: %w", err)
	}
	publicKey, ok := parsedKey.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize || vnextAllZero(publicKey) {
		return term, errors.New("Scheduler SPKI does not contain an Ed25519 public key")
	}
	canonicalSPKI, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil || !bytes.Equal(canonicalSPKI, term.SPKI) {
		return term, errors.New("Scheduler Ed25519 SPKI is not canonical DER")
	}
	term.PublicKey = append(ed25519.PublicKey(nil), publicKey...)
	term.KeyID = sha256.Sum256(term.SPKI)
	return term, nil
}

func parseVNextOwnerSchedulerAuthority(
	leaderKey string,
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerParsedAuthority, error) {
	var parsed vnextOwnerSchedulerParsedAuthority
	if err := validateVNextOwnerSchedulerLeaderKey(leaderKey); err != nil {
		return parsed, err
	}
	var err error
	parsed.ClusterID, err = decodeVNextOwnerSchedulerHexU64(
		"Scheduler cluster ID", authority.ClusterID, false)
	if err != nil {
		return parsed, err
	}
	if authority.CreateRevision == 0 || authority.CreateRevision > uint64(math.MaxInt64) ||
		authority.ModRevision == 0 || authority.ModRevision > uint64(math.MaxInt64) ||
		authority.ModRevision != authority.CreateRevision {
		return parsed, errors.New("Scheduler revisions are not one positive immutable-key revision")
	}
	parsed.CreateRevision = authority.CreateRevision
	parsed.ModRevision = authority.ModRevision
	parsed.LeaseID, err = decodeVNextOwnerSchedulerHexU64(
		"Scheduler lease ID", authority.LeaseID, true)
	if err != nil {
		return parsed, err
	}
	parsed.Leader, err = parseVNextOwnerSchedulerLeaderValue(authority.LeaderValue)
	if err != nil {
		return parsed, err
	}
	if parsed.Leader.LeaseID != parsed.LeaseID {
		return parsed, errors.New("Scheduler envelope and leader value lease IDs differ")
	}
	parsed.LeaderValue = authority.LeaderValue
	keyID, err := decodeVNextOwnerSchedulerHexDigest("Scheduler key ID", authority.KeyID)
	if err != nil {
		return parsed, err
	}
	if keyID != parsed.Leader.KeyID {
		return parsed, errors.New("Scheduler key ID does not match the leader SPKI")
	}
	parsed.TermID, err = decodeVNextOwnerSchedulerHexDigest("Scheduler term ID", authority.TermID)
	if err != nil {
		return parsed, err
	}
	wantTermID := vnextOwnerSchedulerTermDigest(leaderKey, parsed)
	if parsed.TermID != wantTermID {
		return parsed, errors.New("Scheduler term ID does not match the canonical term")
	}
	signature, err := decodeVNextOwnerSchedulerRawURL("Scheduler signature", authority.Signature)
	if err != nil {
		return parsed, err
	}
	if len(signature) != len(parsed.Signature) {
		return parsed, errors.New("Scheduler signature is not exactly 64 bytes")
	}
	copy(parsed.Signature[:], signature)
	return parsed, nil
}

func vnextOwnerSchedulerTermDigest(
	leaderKey string,
	parsed vnextOwnerSchedulerParsedAuthority,
) [vnextOwnerSchedulerDigestBytes]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, vnextOwnerSchedulerTermDomain)
	vnextWriteString(&buffer, vnextOwnerSchedulerAuthorityProtocol)
	vnextWriteString(&buffer, leaderKey)
	vnextWriteU64(&buffer, parsed.ClusterID)
	vnextWriteU64(&buffer, parsed.CreateRevision)
	vnextWriteU64(&buffer, parsed.ModRevision)
	vnextWriteU64(&buffer, parsed.LeaseID)
	vnextWriteString(&buffer, parsed.LeaderValue)
	buffer.Write(parsed.Leader.KeyID[:])
	return sha256.Sum256(buffer.Bytes())
}

func vnextOwnerSchedulerMutationDigest(
	operation string,
	mutation interface{},
) ([vnextOwnerSchedulerDigestBytes]byte, error) {
	var zero [vnextOwnerSchedulerDigestBytes]byte
	var buffer bytes.Buffer
	vnextWriteString(&buffer, vnextOwnerSchedulerMutationDomain)
	vnextWriteString(&buffer, vnextOwnerSchedulerAuthorityProtocol)
	vnextWriteString(&buffer, operation)
	switch operation {
	case vnextOwnerRPCOperationSetAdmission:
		request, ok := mutation.(vnextOwnerSetAdmissionRequest)
		if !ok {
			return zero, errors.New("Scheduler SetAdmission mutation has the wrong type")
		}
		vnextWriteString(&buffer, request.RequestID)
		vnextWriteString(&buffer, request.OwnerID)
		vnextWriteU64(&buffer, request.OwnerEpoch)
		vnextWriteU32(&buffer, uint32(request.From))
		vnextWriteU32(&buffer, uint32(request.Target))
		vnextWriteU64(&buffer, request.ExpectedSequence)
	case vnextOwnerRPCOperationReserve:
		request, ok := mutation.(vnextOwnerReserveRequest)
		if !ok {
			return zero, errors.New("Scheduler Reserve mutation has the wrong type")
		}
		vnextWriteString(&buffer, request.RequestID)
		vnextWriteString(&buffer, request.CheckpointID)
		vnextWriteString(&buffer, request.ProducerID)
		vnextWriteString(&buffer, request.OwnerID)
		vnextWriteU64(&buffer, request.OwnerEpoch)
		vnextWriteU32(&buffer, request.MaxExtents)
		vnextWriteU32(&buffer, uint32(len(request.Contents)))
		for _, content := range request.Contents {
			vnextWriteU32(&buffer, uint32(content.Kind))
			vnextWriteU64(&buffer, content.ObjectID)
			vnextWriteU64(&buffer, content.ByteLength)
			vnextWriteU64(&buffer, content.CapacityPages)
		}
	case vnextOwnerRPCOperationIssueProducerCapability:
		request, ok := mutation.(vnextOwnerIssueProducerCapabilityRequest)
		if !ok {
			return zero, errors.New("Scheduler Issue mutation has the wrong type")
		}
		vnextWriteString(&buffer, request.RequestID)
		vnextWriteOwnerSchedulerOperationIdentity(&buffer, request.Operation)
		vnextWriteString(&buffer, request.ProducerPrincipal)
		vnextWriteU32(&buffer, uint32(request.AllowedOperations))
		vnextWriteU64(&buffer, request.RequestedTTLMillis)
		buffer.Write(request.Nonce[:])
	case vnextOwnerRPCOperationRevokeProducerCapability:
		request, ok := mutation.(vnextOwnerRevokeProducerCapabilityRequest)
		if !ok {
			return zero, errors.New("Scheduler Revoke mutation has the wrong type")
		}
		vnextWriteString(&buffer, request.RequestID)
		vnextWriteOwnerSchedulerOperationIdentity(&buffer, request.Operation)
		vnextWriteString(&buffer, request.CapabilityID)
	case vnextOwnerRPCOperationCommit, vnextOwnerRPCOperationAbort:
		identity, ok := mutation.(vnextOwnerOperationIdentity)
		if !ok {
			return zero, errors.New("Scheduler lifecycle mutation has the wrong type")
		}
		vnextWriteOwnerSchedulerOperationIdentity(&buffer, identity)
	default:
		return zero, fmt.Errorf("operation %q is not a Scheduler mutation", operation)
	}
	return sha256.Sum256(buffer.Bytes()), nil
}

func verifyVNextOwnerSchedulerAuthoritySignature(
	leaderKey string,
	authority vnextOwnerSchedulerAuthority,
	mutationDigest [vnextOwnerSchedulerDigestBytes]byte,
) (vnextOwnerSchedulerVerifiedAuthority, error) {
	var verified vnextOwnerSchedulerVerifiedAuthority
	parsed, err := parseVNextOwnerSchedulerAuthority(leaderKey, authority)
	if err != nil {
		return verified, fmt.Errorf("%w: %v", errVNextOwnerSchedulerAuthority, err)
	}
	preimage := vnextOwnerSchedulerSignaturePreimage(parsed.TermID, mutationDigest)
	if !ed25519.Verify(parsed.Leader.PublicKey, preimage, parsed.Signature[:]) {
		return verified, fmt.Errorf("%w: Ed25519 signature verification failed",
			errVNextOwnerSchedulerAuthority)
	}
	verified.Parsed = parsed
	verified.MutationDigest = mutationDigest
	verified.Receipt = vnextOwnerSchedulerReceipt(
		parsed.TermID, mutationDigest, parsed.Signature)
	return verified, nil
}

func vnextOwnerSchedulerSignaturePreimage(
	termID [vnextOwnerSchedulerDigestBytes]byte,
	mutationDigest [vnextOwnerSchedulerDigestBytes]byte,
) []byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, vnextOwnerSchedulerSignatureDomain)
	buffer.Write(termID[:])
	buffer.Write(mutationDigest[:])
	return buffer.Bytes()
}

func vnextOwnerSchedulerReceipt(
	termID [vnextOwnerSchedulerDigestBytes]byte,
	mutationDigest [vnextOwnerSchedulerDigestBytes]byte,
	signature [vnextOwnerSchedulerSignatureBytes]byte,
) [vnextOwnerSchedulerDigestBytes]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, vnextOwnerSchedulerReceiptDomain)
	buffer.Write(termID[:])
	buffer.Write(mutationDigest[:])
	buffer.Write(signature[:])
	return sha256.Sum256(buffer.Bytes())
}

// vnextOwnerSchedulerExpectedProof derives the proof a strict Scheduler
// client must receive for the exact mutation it sent. This is response
// binding, not Owner-side authority verification: the Owner still performs
// the linearizable etcd read and Ed25519 verification before mutation.
func vnextOwnerSchedulerExpectedProof(
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerProof, error) {
	termID, err := decodeVNextOwnerSchedulerHexDigest(
		"Scheduler term ID", authority.TermID)
	if err != nil {
		return vnextOwnerSchedulerProof{}, err
	}
	mutationDigest, err := vnextOwnerSchedulerMutationDigest(operation, mutation)
	if err != nil {
		return vnextOwnerSchedulerProof{}, err
	}
	signatureBytes, err := decodeVNextOwnerSchedulerRawURL(
		"Scheduler signature", authority.Signature)
	if err != nil {
		return vnextOwnerSchedulerProof{}, err
	}
	var signature [vnextOwnerSchedulerSignatureBytes]byte
	if len(signatureBytes) != len(signature) {
		return vnextOwnerSchedulerProof{}, errors.New(
			"Scheduler signature is not exactly 64 bytes")
	}
	copy(signature[:], signatureBytes)
	return vnextOwnerSchedulerProof{
		TermID:         termID,
		MutationDigest: mutationDigest,
		Receipt:        vnextOwnerSchedulerReceipt(termID, mutationDigest, signature),
	}, nil
}

func vnextWriteOwnerSchedulerOperationIdentity(
	buffer *bytes.Buffer,
	identity vnextOwnerOperationIdentity,
) {
	vnextWriteString(buffer, identity.RequestID)
	vnextWriteString(buffer, identity.CheckpointID)
	vnextWriteString(buffer, identity.ProducerID)
	vnextWriteString(buffer, identity.OwnerID)
	vnextWriteU64(buffer, identity.OwnerEpoch)
	vnextWriteU64(buffer, identity.AllocationRecordID)
}

func vnextOwnerSchedulerPrincipal(
	verified vnextOwnerSchedulerVerifiedAuthority,
) string {
	return "cxld-scheduler://authority/" +
		base64.RawURLEncoding.EncodeToString([]byte(verified.Parsed.Leader.SchedulerID))
}

func validateVNextOwnerSchedulerLeaderKey(leaderKey string) error {
	if err := validateVNextOwnerClientText("Scheduler leader key", leaderKey); err != nil {
		return err
	}
	if !strings.HasSuffix(leaderKey, vnextOwnerSchedulerLeaderKeySuffix) {
		return errors.New("Scheduler leader key does not use the global-orchestrator schema")
	}
	clusterPath := strings.TrimSuffix(leaderKey, vnextOwnerSchedulerLeaderKeySuffix)
	if len(clusterPath) < 2 || clusterPath[0] != '/' ||
		strings.Contains(clusterPath[1:], "/") {
		return errors.New("Scheduler leader key must contain exactly one non-empty cluster segment")
	}
	return nil
}

func decodeVNextOwnerSchedulerRawURL(name, value string) ([]byte, error) {
	if value == "" {
		return nil, fmt.Errorf("%s is empty", name)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("%s is not canonical raw-url-base64", name)
	}
	return decoded, nil
}

func decodeVNextOwnerSchedulerHexU64(
	name string,
	value string,
	requireSigned bool,
) (uint64, error) {
	if len(value) != 16 || value != strings.ToLower(value) {
		return 0, fmt.Errorf("%s is not canonical 16-character lowercase hex", name)
	}
	decoded, err := strconv.ParseUint(value, 16, 64)
	if err != nil || decoded == 0 || requireSigned && decoded > uint64(math.MaxInt64) {
		return 0, fmt.Errorf("%s is outside the positive ABI", name)
	}
	return decoded, nil
}

func decodeVNextOwnerSchedulerHexDigest(
	name string,
	value string,
) ([vnextOwnerSchedulerDigestBytes]byte, error) {
	var digest [vnextOwnerSchedulerDigestBytes]byte
	if len(value) != hex.EncodedLen(len(digest)) || value != strings.ToLower(value) {
		return digest, fmt.Errorf("%s is not canonical 64-character lowercase hex", name)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(digest) {
		return digest, fmt.Errorf("decode %s: %w", name, err)
	}
	copy(digest[:], decoded)
	return digest, nil
}

type vnextOwnerSchedulerReceiptStatus uint8

const (
	vnextOwnerSchedulerReceiptMissing vnextOwnerSchedulerReceiptStatus = iota
	vnextOwnerSchedulerReceiptExact
	vnextOwnerSchedulerReceiptConflict
)

func (group *vnextOwnerGroup) schedulerProofStatus(
	operation string,
	mutation interface{},
	receipt [vnextOwnerSchedulerDigestBytes]byte,
) (vnextOwnerSchedulerProof, vnextOwnerSchedulerReceiptStatus) {
	if group == nil || vnextAllZero(receipt[:]) {
		return vnextOwnerSchedulerProof{}, vnextOwnerSchedulerReceiptMissing
	}
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.journal == nil || group.checkUsableLocked() != nil {
		return vnextOwnerSchedulerProof{}, vnextOwnerSchedulerReceiptMissing
	}
	var proof vnextOwnerSchedulerProof
	found := false
	switch operation {
	case vnextOwnerRPCOperationSetAdmission:
		request, ok := mutation.(vnextOwnerSetAdmissionRequest)
		if !ok {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		for _, record := range group.journal.AdmissionTransitions {
			if record.RequestID == request.RequestID {
				proof = record.SchedulerProof
				found = true
				break
			}
		}
	case vnextOwnerRPCOperationReserve:
		request, ok := mutation.(vnextOwnerReserveRequest)
		if !ok {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		allocationID, exists := group.journal.RequestIndex[request.RequestID]
		if !exists {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		transaction := group.journal.Transactions[allocationID]
		if transaction != nil {
			proof = transaction.SchedulerReserveProof
			found = true
		}
	case vnextOwnerRPCOperationIssueProducerCapability:
		request, ok := mutation.(vnextOwnerIssueProducerCapabilityRequest)
		if !ok {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		transaction := group.journal.Transactions[request.Operation.AllocationRecordID]
		if transaction != nil && transaction.ProducerCapability != nil {
			proof = transaction.ProducerCapability.IssueSchedulerProof
			found = true
		}
	case vnextOwnerRPCOperationRevokeProducerCapability:
		request, ok := mutation.(vnextOwnerRevokeProducerCapabilityRequest)
		if !ok {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		transaction := group.journal.Transactions[request.Operation.AllocationRecordID]
		if transaction != nil && transaction.ProducerCapability != nil &&
			transaction.ProducerCapability.Revoked {
			proof = transaction.ProducerCapability.RevokeSchedulerProof
			found = true
		}
	case vnextOwnerRPCOperationCommit, vnextOwnerRPCOperationAbort:
		identity, ok := mutation.(vnextOwnerOperationIdentity)
		if !ok {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		transaction := group.journal.Transactions[identity.AllocationRecordID]
		if transaction == nil {
			return proof, vnextOwnerSchedulerReceiptMissing
		}
		if operation == vnextOwnerRPCOperationCommit {
			proof = transaction.SchedulerCommitProof
		} else {
			proof = transaction.SchedulerAbortProof
		}
		found = true
	}
	if !found || proof == (vnextOwnerSchedulerProof{}) {
		return proof, vnextOwnerSchedulerReceiptMissing
	}
	if proof.Receipt == receipt {
		return proof, vnextOwnerSchedulerReceiptExact
	}
	return proof, vnextOwnerSchedulerReceiptConflict
}
