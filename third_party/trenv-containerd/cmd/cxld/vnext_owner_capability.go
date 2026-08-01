package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"time"
)

// Producer capabilities authorize cxld control-plane mutations only. They do
// not fence a malicious process that retains an independent writable devdax
// mapping; physical CXL access revocation is a separate platform mechanism.

var (
	errVNextProducerCapabilityConflict = errors.New("VNext Producer capability request conflicts with durable state")
	errVNextProducerCapabilityDenied   = errors.New("VNext Producer capability does not authorize this operation")
	errVNextProducerCapabilityExpired  = errors.New("VNext Producer capability has expired")
	errVNextProducerCapabilityRevoked  = errors.New("VNext Producer capability is revoked")
)

const (
	vnextProducerCapabilityTokenBytes = 32
	vnextProducerCapabilityIDBytes    = 16

	// Capabilities are intentionally short-lived. This version permits exactly
	// one durable capability record per allocation: it supports neither renewal
	// nor replacement after expiry or revocation.
	vnextProducerCapabilityMaxLifetime = 24 * time.Hour
)

type vnextProducerCapabilityOperations uint8

const (
	vnextProducerCapabilitySeal vnextProducerCapabilityOperations = 1 << iota
	vnextProducerCapabilityAbort

	vnextProducerCapabilityAll = vnextProducerCapabilitySeal | vnextProducerCapabilityAbort
)

func (operations vnextProducerCapabilityOperations) valid() bool {
	return operations != 0 && operations&^vnextProducerCapabilityAll == 0
}

func (operations vnextProducerCapabilityOperations) allows(
	operation vnextProducerCapabilityOperations,
) bool {
	return operation.valid() && operation&(operation-1) == 0 && operations&operation == operation
}

// vnextProducerCapabilityProof is the only bearer material a Producer sends.
// Token is never stored in a page descriptor, publication, Reserve response,
// ReservationStatus response, or the durable Owner journal. The journal keeps
// only its scope-bound SHA-256 digest.
type vnextProducerCapabilityProof struct {
	CapabilityID string
	Token        [vnextProducerCapabilityTokenBytes]byte
}

type vnextOwnerIssueProducerCapabilityRequest struct {
	RequestID          string
	Operation          vnextOwnerOperationIdentity
	ProducerPrincipal  string
	AllowedOperations  vnextProducerCapabilityOperations
	RequestedTTLMillis uint64
	Nonce              [vnextProducerCapabilityTokenBytes]byte
	SchedulerReceipt   [vnextOwnerSchedulerDigestBytes]byte
	SchedulerAuthority vnextOwnerSchedulerAuthority
}

type vnextOwnerIssueProducerCapabilityResponse struct {
	RequestID         string
	Capability        vnextProducerCapabilityProof
	Operation         vnextOwnerOperationIdentity
	ProducerPrincipal string
	AllowedOperations vnextProducerCapabilityOperations
	IssuedAtUnixNano  uint64
	ExpiresAtUnixNano uint64
	Replayed          bool
	SchedulerProof    vnextOwnerSchedulerProof
}

type vnextOwnerRevokeProducerCapabilityRequest struct {
	RequestID          string
	Operation          vnextOwnerOperationIdentity
	CapabilityID       string
	SchedulerReceipt   [vnextOwnerSchedulerDigestBytes]byte
	SchedulerAuthority vnextOwnerSchedulerAuthority
}

type vnextOwnerRevokeProducerCapabilityResponse struct {
	RequestID         string
	CapabilityID      string
	Operation         vnextOwnerOperationIdentity
	RevokedAtUnixNano uint64
	Replayed          bool
	SchedulerProof    vnextOwnerSchedulerProof
}

// vnextProducerCapabilityRecord is Owner control metadata. In the
// current implementation it is persisted only in the Owner control journal,
// never in globally readable CXL page metadata. The journal is not assumed to
// be secret: TokenDigest is a one-way, scope-bound verifier and the 32-byte
// nonce/bearer is not stored.
type vnextProducerCapabilityRecord struct {
	IssueRequestID      string
	IssueRequestDigest  [32]byte
	CapabilityID        string
	TokenDigest         [32]byte
	ScopeDigest         [32]byte
	ProducerPrincipal   string
	IssuerPrincipal     string
	AllowedOperations   vnextProducerCapabilityOperations
	IssueSchedulerProof vnextOwnerSchedulerProof
	IssuedAtUnixNano    uint64
	ExpiresAtUnixNano   uint64

	Revoked              bool
	RevokeRequestID      string
	RevokeRequestDigest  [32]byte
	RevokedByPrincipal   string
	RevokeSchedulerProof vnextOwnerSchedulerProof
	RevokedAtUnixNano    uint64
}

func vnextOwnerUnixPrincipal(role vnextOwnerCallerRole, uid uint32) (string, error) {
	var boundary string
	switch role {
	case vnextOwnerCallerScheduler:
		boundary = "control"
	case vnextOwnerCallerProducer:
		boundary = "runtime"
	default:
		return "", fmt.Errorf("Unix caller role %s has no principal namespace", role)
	}
	principal := "unix://cxld/" + boundary + "/uid/" + strconv.FormatUint(uint64(uid), 10)
	if err := validateVNextOwnerPrincipal(principal); err != nil {
		return "", err
	}
	return principal, nil
}

func validateVNextOwnerPrincipal(principal string) error {
	if principal == "" || len(principal) > vnextMaxIdentityBytes {
		return errors.New("caller principal is empty or too long")
	}
	for _, character := range principal {
		if character < 0x20 || character == 0x7f {
			return errors.New("caller principal contains a control character")
		}
	}
	parsed, err := url.Parse(principal)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" || parsed.String() != principal {
		return errors.New("caller principal is not a canonical absolute URI")
	}
	return nil
}

func validateVNextProducerCapabilityProof(proof vnextProducerCapabilityProof) error {
	if err := validateVNextProducerCapabilityID(proof.CapabilityID); err != nil {
		return err
	}
	if vnextAllZero(proof.Token[:]) {
		return errors.New("Producer capability token is zero")
	}
	return nil
}

func validateVNextProducerCapabilityID(capabilityID string) error {
	if len(capabilityID) != 2*vnextProducerCapabilityIDBytes {
		return errors.New("Producer capability ID has the wrong length")
	}
	decoded, err := hex.DecodeString(capabilityID)
	if err != nil || len(decoded) != vnextProducerCapabilityIDBytes ||
		hex.EncodeToString(decoded) != capabilityID {
		return errors.New("Producer capability ID is not canonical lowercase hexadecimal")
	}
	return nil
}

func validateVNextOwnerIssueProducerCapabilityRequest(
	request vnextOwnerIssueProducerCapabilityRequest,
	nowUnixNano uint64,
) error {
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes {
		return errors.New("Producer capability issue request ID is empty or too long")
	}
	if err := validateVNextOwnerClientOperationIdentity(request.Operation); err != nil {
		return fmt.Errorf("Producer capability allocation identity: %w", err)
	}
	if err := validateVNextOwnerPrincipal(request.ProducerPrincipal); err != nil {
		return fmt.Errorf("Producer capability principal: %w", err)
	}
	if !request.AllowedOperations.valid() {
		return errors.New("Producer capability allowed operations are invalid")
	}
	if vnextAllZero(request.SchedulerReceipt[:]) {
		return errors.New("Producer capability Scheduler receipt is zero")
	}
	if request.RequestedTTLMillis == 0 ||
		request.RequestedTTLMillis > uint64(vnextProducerCapabilityMaxLifetime/time.Millisecond) ||
		nowUnixNano == 0 || nowUnixNano > uint64(math.MaxInt64) {
		return errors.New("Producer capability TTL or Owner time is outside the signed ABI")
	}
	if vnextAllZero(request.Nonce[:]) {
		return errors.New("Producer capability nonce is zero")
	}
	return nil
}

func vnextProducerCapabilityScopeDigest(
	ownerID string,
	ownerEpoch uint64,
	transaction *vnextOwnerTransaction,
) [32]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, "cxld-vnext-producer-capability-scope-v1")
	vnextWriteString(&buffer, ownerID)
	vnextWriteU64(&buffer, ownerEpoch)
	vnextWriteU64(&buffer, transaction.AllocationRecordID)
	vnextWriteString(&buffer, transaction.RequestID)
	vnextWriteString(&buffer, transaction.CheckpointID)
	vnextWriteString(&buffer, transaction.ProducerID)
	buffer.Write(transaction.RequestDigest[:])
	vnextWriteU64(&buffer, transaction.TotalPages)
	vnextWriteU32(&buffer, transaction.MaxExtents)
	vnextWriteU32(&buffer, uint32(len(transaction.Contents)))
	for _, content := range transaction.Contents {
		buffer.WriteByte(byte(content.Kind))
		buffer.Write(make([]byte, 7))
		vnextWriteU64(&buffer, content.ObjectID)
		vnextWriteU64(&buffer, content.ByteLength)
		vnextWriteU64(&buffer, content.LogicalPageStart)
		vnextWriteU64(&buffer, content.PageCount)
	}
	vnextWriteU32(&buffer, uint32(len(transaction.Fragments)))
	for _, fragment := range transaction.Fragments {
		vnextWriteString(&buffer, fragment.DeviceUUID)
		vnextWriteU64(&buffer, fragment.GlobalLogicalStart)
		vnextWriteU64(&buffer, fragment.PageCount)
		vnextWriteU32(&buffer, uint32(len(fragment.Extents)))
		for _, extent := range fragment.Extents {
			vnextWriteU64(&buffer, extent.StartDataPageIndex)
			vnextWriteU64(&buffer, extent.PageCount)
			vnextWriteU64(&buffer, extent.GlobalLogicalStart)
		}
	}
	return sha256.Sum256(buffer.Bytes())
}

func vnextProducerCapabilityIssueDigest(
	request vnextOwnerIssueProducerCapabilityRequest,
	issuerPrincipal string,
	scopeDigest [32]byte,
) [32]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, "cxld-vnext-producer-capability-issue-v1")
	vnextWriteString(&buffer, request.RequestID)
	vnextWriteString(&buffer, issuerPrincipal)
	vnextWriteString(&buffer, request.ProducerPrincipal)
	buffer.Write(request.SchedulerReceipt[:])
	vnextWriteU64(&buffer, request.RequestedTTLMillis)
	buffer.WriteByte(byte(request.AllowedOperations))
	buffer.Write(make([]byte, 7))
	buffer.Write(scopeDigest[:])
	buffer.Write(request.Nonce[:])
	return sha256.Sum256(buffer.Bytes())
}

func vnextProducerCapabilityID(issueDigest [32]byte) string {
	return hex.EncodeToString(issueDigest[:vnextProducerCapabilityIDBytes])
}

func vnextProducerCapabilityTokenDigest(
	capabilityID string,
	token [vnextProducerCapabilityTokenBytes]byte,
	scopeDigest [32]byte,
	producerPrincipal string,
	operations vnextProducerCapabilityOperations,
	schedulerReceipt [vnextOwnerSchedulerDigestBytes]byte,
	expiresAtUnixNano uint64,
) [32]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, "cxld-vnext-producer-capability-token-v1")
	vnextWriteString(&buffer, capabilityID)
	buffer.Write(token[:])
	buffer.Write(scopeDigest[:])
	vnextWriteString(&buffer, producerPrincipal)
	buffer.WriteByte(byte(operations))
	buffer.Write(make([]byte, 7))
	buffer.Write(schedulerReceipt[:])
	vnextWriteU64(&buffer, expiresAtUnixNano)
	return sha256.Sum256(buffer.Bytes())
}

func vnextProducerCapabilityRevokeDigest(
	request vnextOwnerRevokeProducerCapabilityRequest,
	revokerPrincipal string,
) [32]byte {
	var buffer bytes.Buffer
	vnextWriteString(&buffer, "cxld-vnext-producer-capability-revoke-v1")
	vnextWriteString(&buffer, request.RequestID)
	vnextWriteString(&buffer, revokerPrincipal)
	vnextWriteString(&buffer, request.CapabilityID)
	vnextWriteString(&buffer, request.Operation.RequestID)
	vnextWriteString(&buffer, request.Operation.CheckpointID)
	vnextWriteString(&buffer, request.Operation.ProducerID)
	vnextWriteString(&buffer, request.Operation.OwnerID)
	vnextWriteU64(&buffer, request.Operation.OwnerEpoch)
	vnextWriteU64(&buffer, request.Operation.AllocationRecordID)
	buffer.Write(request.SchedulerReceipt[:])
	return sha256.Sum256(buffer.Bytes())
}

func unixNanoForVNextProducerCapability(now time.Time) (uint64, error) {
	nanos := now.UnixNano()
	if nanos <= 0 {
		return 0, errors.New("Owner capability clock is outside the positive signed ABI")
	}
	return uint64(nanos), nil
}

func (group *vnextOwnerGroup) issueProducerCapabilityWithScheduler(
	request vnextOwnerIssueProducerCapabilityRequest,
	issuerPrincipal string,
	nowUnixNano uint64,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) (vnextProducerCapabilityRecord, bool, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if request.SchedulerReceipt != authority.Receipt {
		return vnextProducerCapabilityRecord{}, false,
			errVNextOwnerSchedulerReceiptConflict
	}
	if err := validateVNextOwnerPrincipal(issuerPrincipal); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := validateVNextOwnerIssueProducerCapabilityRequest(request, nowUnixNano); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	transaction, err := group.resolveCapabilityTransactionLocked(request.Operation)
	if err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	scopeDigest := vnextProducerCapabilityScopeDigest(group.ownerID, group.ownerEpoch, transaction)
	issueDigest := vnextProducerCapabilityIssueDigest(request, issuerPrincipal, scopeDigest)
	capabilityID := vnextProducerCapabilityID(issueDigest)
	if existing := transaction.ProducerCapability; existing != nil {
		expectedTokenDigest := vnextProducerCapabilityTokenDigest(
			capabilityID,
			request.Nonce,
			scopeDigest,
			request.ProducerPrincipal,
			request.AllowedOperations,
			request.SchedulerReceipt,
			existing.ExpiresAtUnixNano)
		if existing.IssueRequestID != request.RequestID ||
			existing.IssueRequestDigest != issueDigest ||
			existing.CapabilityID != capabilityID ||
			subtle.ConstantTimeCompare(existing.ScopeDigest[:], scopeDigest[:]) != 1 ||
			subtle.ConstantTimeCompare(existing.TokenDigest[:], expectedTokenDigest[:]) != 1 {
			return vnextProducerCapabilityRecord{}, false, fmt.Errorf(
				"Producer capability issue request conflicts with allocation %d: %w",
				transaction.AllocationRecordID, errVNextProducerCapabilityConflict)
		}
		if existing.IssueSchedulerProof != authority.proof() {
			return vnextProducerCapabilityRecord{}, false,
				errVNextOwnerSchedulerReceiptConflict
		}
		// Persist-before-ack replay is an acknowledgement protocol, not a new
		// authority decision. The Scheduler must be able to reconstruct the
		// exact response after COMMITTED, ABORTED, expiry, or revocation. A
		// replayed proof remains subject to current lifecycle and live-authority
		// checks when a Producer later attempts Seal or Abort.
		return *existing, true, nil
	}
	if transaction.State != vnextOwnerGranted {
		return vnextProducerCapabilityRecord{}, false, fmt.Errorf(
			"Owner allocation %d is state %d: %w",
			transaction.AllocationRecordID, transaction.State, errVNextInvalidState)
	}
	// Admission can close after an issuance was durably acknowledged. Exact
	// retry above must remain replayable without mutation; only a new issuance
	// is subject to the current producer-mutation admission state.
	if err := group.requireProducerMutationAllowedLocked("issue-producer-capability"); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}

	ttlNanos, ok := vnextMul(request.RequestedTTLMillis, uint64(time.Millisecond))
	if !ok {
		return vnextProducerCapabilityRecord{}, false, errors.New("Producer capability TTL overflows")
	}
	expiresAtUnixNano, ok := vnextAdd(nowUnixNano, ttlNanos)
	if !ok || expiresAtUnixNano > uint64(math.MaxInt64) {
		return vnextProducerCapabilityRecord{}, false, errors.New("Producer capability expiry overflows")
	}
	record := vnextProducerCapabilityRecord{
		IssueRequestID:      request.RequestID,
		IssueRequestDigest:  issueDigest,
		CapabilityID:        capabilityID,
		ScopeDigest:         scopeDigest,
		ProducerPrincipal:   request.ProducerPrincipal,
		IssuerPrincipal:     issuerPrincipal,
		AllowedOperations:   request.AllowedOperations,
		IssueSchedulerProof: authority.proof(),
		IssuedAtUnixNano:    nowUnixNano,
		ExpiresAtUnixNano:   expiresAtUnixNano,
	}
	record.TokenDigest = vnextProducerCapabilityTokenDigest(
		record.CapabilityID,
		request.Nonce,
		record.ScopeDigest,
		record.ProducerPrincipal,
		record.AllowedOperations,
		record.IssueSchedulerProof.Receipt,
		record.ExpiresAtUnixNano)
	candidate := group.journal.clone()
	copied := record
	candidate.Transactions[transaction.AllocationRecordID].ProducerCapability = &copied
	if err := group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := group.persistJournalLocked(candidate); err != nil {
		return vnextProducerCapabilityRecord{}, false, group.poisonLocked(fmt.Errorf(
			"persist Producer capability issuance: %w", err))
	}
	return record, false, nil
}

func (group *vnextOwnerGroup) revokeProducerCapabilityWithScheduler(
	request vnextOwnerRevokeProducerCapabilityRequest,
	revokerPrincipal string,
	nowUnixNano uint64,
	authority *vnextOwnerSchedulerVerifiedAuthority,
) (vnextProducerCapabilityRecord, bool, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := validateVNextOwnerVerifiedSchedulerAuthority(authority); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if request.SchedulerReceipt != authority.Receipt {
		return vnextProducerCapabilityRecord{}, false,
			errVNextOwnerSchedulerReceiptConflict
	}
	if request.RequestID == "" || len(request.RequestID) > vnextMaxIdentityBytes ||
		vnextAllZero(request.SchedulerReceipt[:]) ||
		nowUnixNano == 0 || nowUnixNano > uint64(math.MaxInt64) {
		return vnextProducerCapabilityRecord{}, false, errors.New(
			"Producer capability revocation identity, term, or time is invalid")
	}
	if err := validateVNextOwnerPrincipal(revokerPrincipal); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := validateVNextOwnerClientOperationIdentity(request.Operation); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := validateVNextProducerCapabilityID(request.CapabilityID); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	transaction, err := group.resolveCapabilityTransactionLocked(request.Operation)
	if err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	record := transaction.ProducerCapability
	if record == nil || record.CapabilityID != request.CapabilityID {
		return vnextProducerCapabilityRecord{}, false, fmt.Errorf(
			"Producer capability does not match allocation %d: %w",
			transaction.AllocationRecordID, errVNextProducerCapabilityDenied)
	}
	if nowUnixNano < record.IssuedAtUnixNano {
		return vnextProducerCapabilityRecord{}, false, fmt.Errorf(
			"Owner clock precedes capability issuance: %w",
			errVNextProducerCapabilityDenied)
	}
	revokeDigest := vnextProducerCapabilityRevokeDigest(request, revokerPrincipal)
	if record.Revoked {
		if record.RevokeRequestID != request.RequestID ||
			record.RevokeRequestDigest != revokeDigest ||
			record.RevokedByPrincipal != revokerPrincipal ||
			record.RevokeSchedulerProof.Receipt != request.SchedulerReceipt {
			return vnextProducerCapabilityRecord{}, false, fmt.Errorf(
				"Producer capability revocation conflicts with durable history: %w",
				errVNextProducerCapabilityConflict)
		}
		if record.RevokeSchedulerProof != authority.proof() {
			return vnextProducerCapabilityRecord{}, false,
				errVNextOwnerSchedulerReceiptConflict
		}
		return *record, true, nil
	}
	candidate := group.journal.clone()
	updated := candidate.Transactions[transaction.AllocationRecordID].ProducerCapability
	updated.Revoked = true
	updated.RevokeRequestID = request.RequestID
	updated.RevokeRequestDigest = revokeDigest
	updated.RevokedByPrincipal = revokerPrincipal
	updated.RevokeSchedulerProof = authority.proof()
	updated.RevokedAtUnixNano = nowUnixNano
	if err := group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
		return vnextProducerCapabilityRecord{}, false, err
	}
	if err := group.persistJournalLocked(candidate); err != nil {
		return vnextProducerCapabilityRecord{}, false, group.poisonLocked(fmt.Errorf(
			"persist Producer capability revocation: %w", err))
	}
	return *group.journal.Transactions[transaction.AllocationRecordID].ProducerCapability, false, nil
}

func (group *vnextOwnerGroup) validateProducerCapability(
	identity vnextOwnerOperationIdentity,
	proof vnextProducerCapabilityProof,
	callerPrincipal string,
	operation vnextProducerCapabilityOperations,
	nowUnixNano uint64,
) error {
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return err
	}
	_, record, err := group.validateProducerCapabilityProofLocked(
		identity, proof, callerPrincipal, operation)
	if err != nil {
		return err
	}
	return validateVNextProducerCapabilityLiveAuthority(record, nowUnixNano)
}

// validateProducerCapabilityProofLocked authenticates immutable capability
// structure and bearer proof only. It deliberately does not inspect lifecycle
// state, revocation, or time. Callers must complete proof validation before
// consulting transaction.State so a failed secret cannot be used as a
// lifecycle-state oracle.
func (group *vnextOwnerGroup) validateProducerCapabilityProofLocked(
	identity vnextOwnerOperationIdentity,
	proof vnextProducerCapabilityProof,
	callerPrincipal string,
	operation vnextProducerCapabilityOperations,
) (*vnextOwnerTransaction, *vnextProducerCapabilityRecord, error) {
	if err := validateVNextProducerCapabilityProof(proof); err != nil {
		return nil, nil, fmt.Errorf("invalid Producer capability proof: %w: %v",
			errVNextProducerCapabilityDenied, err)
	}
	if err := validateVNextOwnerPrincipal(callerPrincipal); err != nil {
		return nil, nil, fmt.Errorf("invalid Producer principal: %w: %v",
			errVNextProducerCapabilityDenied, err)
	}
	if err := validateVNextOwnerClientOperationIdentity(identity); err != nil {
		return nil, nil, fmt.Errorf("invalid Producer allocation identity: %w: %v",
			errVNextProducerCapabilityDenied, err)
	}
	if !operation.valid() || operation&(operation-1) != 0 {
		return nil, nil, errors.New("Producer capability validation operation is invalid")
	}

	// AllocationRecordID is used only to locate a candidate verifier. Every
	// mismatch below maps to the same denial until the secret proof is exact.
	transaction := group.journal.Transactions[identity.AllocationRecordID]
	if transaction == nil {
		return nil, nil, errVNextProducerCapabilityDenied
	}
	record := transaction.ProducerCapability
	if record == nil {
		return nil, nil, errVNextProducerCapabilityDenied
	}
	scopeDigest := vnextProducerCapabilityScopeDigest(group.ownerID, group.ownerEpoch, transaction)
	expectedTokenDigest := vnextProducerCapabilityTokenDigest(
		record.CapabilityID, proof.Token, scopeDigest, record.ProducerPrincipal,
		record.AllowedOperations, record.IssueSchedulerProof.Receipt, record.ExpiresAtUnixNano)
	principalMask := 0
	if record.ProducerPrincipal == callerPrincipal {
		principalMask = 1
	}
	operationMask := 0
	if record.AllowedOperations.allows(operation) {
		operationMask = 1
	}
	proofMask := subtle.ConstantTimeCompare(
		[]byte(record.CapabilityID), []byte(proof.CapabilityID))
	proofMask &= principalMask
	proofMask &= operationMask
	proofMask &= subtle.ConstantTimeCompare(record.ScopeDigest[:], scopeDigest[:])
	proofMask &= subtle.ConstantTimeCompare(record.TokenDigest[:], expectedTokenDigest[:])
	if proofMask != 1 {
		return nil, nil, errVNextProducerCapabilityDenied
	}
	if identity.OwnerID != group.ownerID || identity.OwnerEpoch != group.ownerEpoch ||
		identity.RequestID != transaction.RequestID ||
		identity.CheckpointID != transaction.CheckpointID ||
		identity.ProducerID != transaction.ProducerID {
		return nil, nil, errVNextProducerCapabilityDenied
	}
	return transaction, record, nil
}

func validateVNextProducerCapabilityLiveAuthority(
	record *vnextProducerCapabilityRecord,
	nowUnixNano uint64,
) error {
	if record == nil || nowUnixNano == 0 || nowUnixNano > uint64(math.MaxInt64) {
		return errors.New("Producer capability live-authority time is invalid")
	}
	if record.Revoked {
		return errVNextProducerCapabilityRevoked
	}
	if nowUnixNano < record.IssuedAtUnixNano {
		return errVNextProducerCapabilityDenied
	}
	if nowUnixNano >= record.ExpiresAtUnixNano {
		return errVNextProducerCapabilityExpired
	}
	return nil
}

func (group *vnextOwnerGroup) resolveCapabilityTransactionLocked(
	identity vnextOwnerOperationIdentity,
) (*vnextOwnerTransaction, error) {
	if identity.OwnerID != group.ownerID || identity.OwnerEpoch != group.ownerEpoch {
		return nil, errVNextAuthority
	}
	transaction := group.journal.Transactions[identity.AllocationRecordID]
	if transaction == nil {
		return nil, errVNextInvalidState
	}
	if transaction.RequestID != identity.RequestID ||
		transaction.CheckpointID != identity.CheckpointID ||
		transaction.ProducerID != identity.ProducerID {
		return nil, errVNextAuthority
	}
	return transaction, nil
}

func validateVNextProducerCapabilityRecord(
	record *vnextProducerCapabilityRecord,
	ownerID string,
	ownerEpoch uint64,
	transaction *vnextOwnerTransaction,
) error {
	if record == nil {
		return nil
	}
	if transaction == nil || transaction.State == vnextOwnerRejectedNoSpace {
		return fmt.Errorf("negative or missing allocation has a Producer capability: %w", errVNextCorrupt)
	}
	if record.IssueRequestID == "" || len(record.IssueRequestID) > vnextMaxIdentityBytes ||
		!record.IssueSchedulerProof.valid() ||
		!record.AllowedOperations.valid() ||
		record.IssuedAtUnixNano == 0 || record.IssuedAtUnixNano > uint64(math.MaxInt64) ||
		record.ExpiresAtUnixNano <= record.IssuedAtUnixNano ||
		record.ExpiresAtUnixNano > uint64(math.MaxInt64) ||
		record.ExpiresAtUnixNano-record.IssuedAtUnixNano < uint64(time.Millisecond) ||
		(record.ExpiresAtUnixNano-record.IssuedAtUnixNano)%uint64(time.Millisecond) != 0 ||
		record.ExpiresAtUnixNano-record.IssuedAtUnixNano > uint64(vnextProducerCapabilityMaxLifetime) ||
		vnextAllZero(record.IssueRequestDigest[:]) || vnextAllZero(record.TokenDigest[:]) ||
		vnextAllZero(record.ScopeDigest[:]) {
		return fmt.Errorf("Producer capability record is incomplete: %w", errVNextCorrupt)
	}
	if err := validateVNextOwnerPrincipal(record.ProducerPrincipal); err != nil {
		return fmt.Errorf("Producer capability principal is invalid: %w", errVNextCorrupt)
	}
	if err := validateVNextOwnerPrincipal(record.IssuerPrincipal); err != nil {
		return fmt.Errorf("Producer capability issuer is invalid: %w", errVNextCorrupt)
	}
	if err := validateVNextProducerCapabilityID(record.CapabilityID); err != nil {
		return fmt.Errorf("Producer capability ID is invalid: %w", errVNextCorrupt)
	}
	if record.CapabilityID != vnextProducerCapabilityID(record.IssueRequestDigest) {
		return fmt.Errorf("Producer capability ID is not bound to its issue digest: %w", errVNextCorrupt)
	}
	if record.ScopeDigest != vnextProducerCapabilityScopeDigest(ownerID, ownerEpoch, transaction) {
		return fmt.Errorf("Producer capability allocation scope changed: %w", errVNextCorrupt)
	}
	if !record.Revoked {
		if record.RevokeRequestID != "" || record.RevokeRequestDigest != ([32]byte{}) ||
			record.RevokedByPrincipal != "" ||
			record.RevokeSchedulerProof != (vnextOwnerSchedulerProof{}) ||
			record.RevokedAtUnixNano != 0 {
			return fmt.Errorf("active Producer capability has revocation metadata: %w", errVNextCorrupt)
		}
		return nil
	}
	if record.RevokeRequestID == "" || len(record.RevokeRequestID) > vnextMaxIdentityBytes ||
		!record.RevokeSchedulerProof.valid() ||
		vnextAllZero(record.RevokeRequestDigest[:]) ||
		record.RevokedAtUnixNano < record.IssuedAtUnixNano ||
		record.RevokedAtUnixNano > uint64(math.MaxInt64) {
		return fmt.Errorf("revoked Producer capability lacks durable proof: %w", errVNextCorrupt)
	}
	if err := validateVNextOwnerPrincipal(record.RevokedByPrincipal); err != nil {
		return fmt.Errorf("Producer capability revoker is invalid: %w", errVNextCorrupt)
	}
	expectedRevokeDigest := vnextProducerCapabilityRevokeDigest(
		vnextOwnerRevokeProducerCapabilityRequest{
			RequestID: record.RevokeRequestID,
			Operation: vnextOwnerOperationIdentity{
				RequestID:          transaction.RequestID,
				CheckpointID:       transaction.CheckpointID,
				ProducerID:         transaction.ProducerID,
				OwnerID:            ownerID,
				OwnerEpoch:         ownerEpoch,
				AllocationRecordID: transaction.AllocationRecordID,
			},
			CapabilityID:     record.CapabilityID,
			SchedulerReceipt: record.RevokeSchedulerProof.Receipt,
		},
		record.RevokedByPrincipal)
	if subtle.ConstantTimeCompare(
		record.RevokeRequestDigest[:], expectedRevokeDigest[:]) != 1 {
		return fmt.Errorf("Producer capability revoke digest is invalid: %w", errVNextCorrupt)
	}
	return nil
}
