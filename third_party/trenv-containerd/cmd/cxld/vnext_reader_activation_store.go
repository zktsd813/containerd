package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderActivationStoreMaxEntries       = 4096
	vnextReaderActivationStoreMaxRetainedBytes = 64 << 20

	// The authorization store already charges its complete ACQUIRED graph.
	// This additional conservative charge covers the activation map entry,
	// intent, state, map/slice headers, and allocator overhead. Retained string
	// bytes are charged separately, including both independently cloned copies
	// of the activation request ID (entry identity and map key).
	vnextReaderActivationStoreFixedChargeBytes = 4 << 10

	vnextReaderActivationMappingIDPrefix = "reader-mapping:"

	vnextReaderActivationProposalProtocol  = "cxld.vnext-reader-activation-proposal.v1"
	vnextReaderActivationProposalOperation = "vnextReaderProposeActivation"
	vnextReaderActivationProposalALPN      = "cxld-vnext-reader-activation-proposal/1"

	vnextReaderActivationEvidenceReceiptDomain = "cxld-vnext-reader-activation-proposal-activation-receipt-v1"
)

type vnextReaderActivationState string

const (
	vnextReaderActivationPending     vnextReaderActivationState = "PENDING"
	vnextReaderActivationActiveArmed vnextReaderActivationState = "ACTIVE_ARMED"
)

const vnextReaderCatalogAuthorizationActive vnextReaderCatalogAuthorizationState = "ACTIVE"

type vnextReaderActivationProposalDisposition uint8

const (
	vnextReaderActivationProposalInstalled vnextReaderActivationProposalDisposition = iota + 1
	vnextReaderActivationProposalExactReplay
)

type vnextReaderActivationCommitDisposition uint8

const (
	vnextReaderActivationCommitArmed vnextReaderActivationCommitDisposition = iota + 1
	vnextReaderActivationCommitExactReplay
)

type vnextReaderActivationStatusDisposition uint8

const (
	vnextReaderActivationStatusPresent vnextReaderActivationStatusDisposition = iota + 1
	vnextReaderActivationStatusNotFoundFenced
)

var (
	errVNextReaderActivationStoreFull = errors.New(
		"VNext Reader activation store is full")
	errVNextReaderActivationStoreRetainedBytesFull = errors.New(
		"VNext Reader activation store retained-byte budget is full")
	errVNextReaderActivationConflict = errors.New(
		"VNext Reader activation request ID already has different data")
	errVNextReaderActivationIncarnationMismatch = errors.New(
		"VNext Reader activation process incarnation does not match")
	errVNextReaderActivationNotFoundFenced = errors.New(
		"VNext Reader activation request is permanently fenced as not found")
	errVNextReaderActivationNotPending = errors.New(
		"VNext Reader activation request is not pending")
	errVNextReaderActivationMappingGenerationExhausted = errors.New(
		"VNext Reader activation mapping generation is exhausted")
	errVNextReaderActivationNotActiveArmed = errors.New(
		"VNext Reader activation is not ACTIVE_ARMED")
	errVNextReaderFirstReadAlreadyClaimed = errors.New(
		"VNext Reader activation first read is already claimed")
	errVNextReaderFirstReadAdmissionClosed = errors.New(
		"VNext Reader activation first-read admission is closed")
)

// vnextReaderActivationRequestIdentity is the exact request that is safe to
// retry after a lost proposal response. ACQUIRED is retained in full; an
// authorization-ID-only lookup is deliberately unavailable.
type vnextReaderActivationRequestIdentity struct {
	Acquired            vnextReaderAcquiredAuthorization
	ActivationRequestID string
}

// vnextReaderActivationIntent is process-local evidence only. PENDING and
// ACTIVE_ARMED both perform zero device resolution, open, mapping, read, CRIU,
// or release work. A later data-plane implementation may proceed only from an
// exact ACTIVE_ARMED value and a separately reviewed mapping boundary.
type vnextReaderActivationIntent struct {
	Request                vnextReaderActivationRequestIdentity
	MappingID              string
	MappingGeneration      uint64
	ActivatedAtEpochMillis int64
	CxldReceipt            [sha256.Size]byte
	State                  vnextReaderActivationState
}

type vnextReaderActivationStatusResult struct {
	Request     vnextReaderActivationRequestIdentity
	Disposition vnextReaderActivationStatusDisposition
	Intent      *vnextReaderActivationIntent
}

type vnextReaderActivationStoreEntryKind uint8

const (
	vnextReaderActivationStoreEntryIntent vnextReaderActivationStoreEntryKind = iota + 1
	vnextReaderActivationStoreEntryNotFoundFenced
)

type vnextReaderActivationStoreEntry struct {
	kind             vnextReaderActivationStoreEntryKind
	request          vnextReaderActivationRequestIdentity
	intent           vnextReaderActivationIntent
	firstReadClaimed bool
}

// vnextReaderFirstReadPermit is an unforgeable process-local handoff between
// read-free activation/locator validation and the first DAX descriptor read.
// It is consumed under the same mutex that protects the retained activation.
type vnextReaderFirstReadPermit struct {
	store  *vnextReaderActivationStore
	intent vnextReaderActivationIntent
}

type vnextReaderActivationStoreConfig struct {
	MaxEntries       int
	MaxRetainedBytes uint64
}

type vnextReaderActivationPreparedStore interface {
	LookupPreparedExact(
		vnextReaderAcquiredAuthorization,
		int64,
	) (vnextReaderPreparedAuthorization, error)
}

// vnextReaderActivationStore is process-lifetime, bounded, and never evicts.
// A status miss installs a permanent exact tombstone. Consequently a delayed
// proposal cannot turn a definitive NOT_FOUND response into PENDING.
//
// Mapping generations are monotonically allocated inside one process
// incarnation and never wrap. A new process may begin at generation one
// because its independent 256-bit incarnation is part of every request and
// generated mapping ID.
type vnextReaderActivationStore struct {
	mu                       sync.RWMutex
	localExecutorNodeID      string
	localCxldLogicalID       string
	localProcess             vnextReaderProcessIncarnation
	prepared                 vnextReaderActivationPreparedStore
	maxEntries               int
	maxRetainedBytes         uint64
	retainedBytes            uint64
	lastMappingGeneration    uint64
	byRequestID              map[string]vnextReaderActivationStoreEntry
	firstReadAdmissionClosed bool
}

func newVNextReaderActivationStore(
	config vnextReaderActivationStoreConfig,
	localExecutorNodeID string,
	localCxldLogicalID string,
	localProcess vnextReaderProcessIncarnation,
	prepared vnextReaderActivationPreparedStore,
) (*vnextReaderActivationStore, error) {
	if config.MaxEntries <= 0 || config.MaxEntries > vnextReaderActivationStoreMaxEntries {
		return nil, fmt.Errorf(
			"VNext Reader activation store capacity %d is outside 1..%d",
			config.MaxEntries, vnextReaderActivationStoreMaxEntries)
	}
	if config.MaxRetainedBytes == 0 ||
		config.MaxRetainedBytes > vnextReaderActivationStoreMaxRetainedBytes {
		return nil, fmt.Errorf(
			"VNext Reader activation store retained-byte capacity %d is outside 1..%d",
			config.MaxRetainedBytes, vnextReaderActivationStoreMaxRetainedBytes)
	}
	if err := validateVNextReaderProcessIncarnation(localProcess); err != nil {
		return nil, fmt.Errorf("validate local VNext Reader activation process: %w", err)
	}
	if err := validateVNextReaderIdentity(
		"local VNext Reader activation executor node ID", localExecutorNodeID); err != nil {
		return nil, err
	}
	if err := validateVNextReaderIdentity(
		"local VNext Reader activation cxld logical ID", localCxldLogicalID); err != nil {
		return nil, err
	}
	if vnextReaderPreparedStatusNilInterface(prepared) {
		return nil, errors.New("VNext Reader activation PREPARED store is unavailable")
	}
	initialMapCapacity := config.MaxEntries
	maxEntriesByFixedCharge := config.MaxRetainedBytes /
		vnextReaderActivationStoreFixedChargeBytes
	if uint64(initialMapCapacity) > maxEntriesByFixedCharge {
		initialMapCapacity = int(maxEntriesByFixedCharge)
	}
	return &vnextReaderActivationStore{
		localExecutorNodeID: cloneVNextReaderRetainedString(localExecutorNodeID),
		localCxldLogicalID:  cloneVNextReaderRetainedString(localCxldLogicalID),
		localProcess:        localProcess,
		prepared:            prepared,
		maxEntries:          config.MaxEntries,
		maxRetainedBytes:    config.MaxRetainedBytes,
		byRequestID:         make(map[string]vnextReaderActivationStoreEntry, initialMapCapacity),
	}, nil
}

// Propose first proves that the complete request still names an exact
// process-local PREPARED entry. It then installs PENDING atomically. A mapping
// generation is consumed only when an entry is installed; response loss does
// not reuse it because the entry remains replayable for the process lifetime.
func (store *vnextReaderActivationStore) Propose(
	request vnextReaderActivationRequestIdentity,
	nowEpochMillis int64,
) (vnextReaderActivationIntent, vnextReaderActivationProposalDisposition, error) {
	if store == nil || vnextReaderPreparedStatusNilInterface(store.prepared) {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation store is unavailable")
	}
	if nowEpochMillis < 0 {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation proposal time is negative")
	}
	if err := store.validateRequest(request); err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	request = cloneVNextReaderActivationRequestIdentity(request)

	// A retained process-lifetime decision is authoritative even after the
	// ACQUIRED interval expires. Check it before the time-aware PREPARED lookup
	// so a lost response remains exactly replayable.
	store.mu.RLock()
	if current, exists := store.byRequestID[request.ActivationRequestID]; exists {
		intent, disposition, err := store.replayProposalLocked(current, request)
		store.mu.RUnlock()
		return intent, disposition, err
	}
	store.mu.RUnlock()

	prepared, err := store.prepared.LookupPreparedExact(request.Acquired, nowEpochMillis)
	if err != nil {
		return vnextReaderActivationIntent{}, 0,
			fmt.Errorf("lookup exact PREPARED activation authority: %w", err)
	}
	if prepared.PreparationState != vnextReaderPreparationPrepared ||
		!equalVNextReaderAcquiredAuthorization(prepared.Acquired, request.Acquired) {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation PREPARED lookup returned different data")
	}
	// STATUS may have installed a NOT_FOUND fence, or another proposal may
	// have installed this intent, while PREPARED was being checked. Recheck
	// under the installation lock before allocating a generation.
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, exists := store.byRequestID[request.ActivationRequestID]; exists {
		return store.replayProposalLocked(current, request)
	}
	if store.lastMappingGeneration >= cxlcheckpoint.MaxSignedLong {
		return vnextReaderActivationIntent{}, 0,
			errVNextReaderActivationMappingGenerationExhausted
	}
	generation := store.lastMappingGeneration + 1
	mappingID := vnextReaderActivationMappingID(store.localProcess, generation)
	intent := vnextReaderActivationIntent{
		Request:                request,
		MappingID:              mappingID,
		MappingGeneration:      generation,
		ActivatedAtEpochMillis: nowEpochMillis,
		State:                  vnextReaderActivationPending,
	}
	intent.CxldReceipt = store.canonicalEvidenceReceipt(intent)
	charge, err := vnextReaderActivationRetainedCharge(request, mappingID)
	if err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	entry := vnextReaderActivationStoreEntry{
		kind:    vnextReaderActivationStoreEntryIntent,
		request: request,
		intent:  intent,
	}
	if err := store.installLocked(request.ActivationRequestID, entry, charge); err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	store.lastMappingGeneration = generation
	return cloneVNextReaderActivationIntent(intent),
		vnextReaderActivationProposalInstalled, nil
}

// Status is mutating only for an absent request. It records an exact retained
// NOT_FOUND fence before returning a definitive miss. Status never allocates a
// mapping generation and never changes PENDING or ACTIVE_ARMED.
func (store *vnextReaderActivationStore) Status(
	request vnextReaderActivationRequestIdentity,
) (vnextReaderActivationStatusResult, error) {
	if store == nil {
		return vnextReaderActivationStatusResult{},
			errors.New("VNext Reader activation store is unavailable")
	}
	if err := store.validateRequest(request); err != nil {
		return vnextReaderActivationStatusResult{}, err
	}
	request = cloneVNextReaderActivationRequestIdentity(request)
	store.mu.Lock()
	defer store.mu.Unlock()
	if current, exists := store.byRequestID[request.ActivationRequestID]; exists {
		if err := store.validateExistingRequest(current.request, request); err != nil {
			return vnextReaderActivationStatusResult{}, err
		}
		if current.kind == vnextReaderActivationStoreEntryNotFoundFenced {
			return vnextReaderActivationStatusResult{
				Request:     cloneVNextReaderActivationRequestIdentity(current.request),
				Disposition: vnextReaderActivationStatusNotFoundFenced,
			}, nil
		}
		if current.kind != vnextReaderActivationStoreEntryIntent {
			return vnextReaderActivationStatusResult{},
				errors.New("VNext Reader activation store entry kind is invalid")
		}
		intent := cloneVNextReaderActivationIntent(current.intent)
		return vnextReaderActivationStatusResult{
			Request:     cloneVNextReaderActivationRequestIdentity(current.request),
			Disposition: vnextReaderActivationStatusPresent,
			Intent:      &intent,
		}, nil
	}
	charge, err := vnextReaderActivationRetainedCharge(request, "")
	if err != nil {
		return vnextReaderActivationStatusResult{}, err
	}
	entry := vnextReaderActivationStoreEntry{
		kind:    vnextReaderActivationStoreEntryNotFoundFenced,
		request: request,
	}
	if err := store.installLocked(request.ActivationRequestID, entry, charge); err != nil {
		return vnextReaderActivationStatusResult{}, err
	}
	return vnextReaderActivationStatusResult{
		Request:     cloneVNextReaderActivationRequestIdentity(request),
		Disposition: vnextReaderActivationStatusNotFoundFenced,
	}, nil
}

// Commit accepts only the exact catalog-returned ACTIVE authorization and the
// exact evidence previously returned for this PENDING intent. It changes no
// catalog or device state; ACTIVE_ARMED is merely the local prerequisite for a
// separately implemented physical mapping boundary.
func (store *vnextReaderActivationStore) Commit(
	active vnextReaderAcquiredAuthorization,
	evidence vnextReaderActivationIntent,
) (vnextReaderActivationIntent, vnextReaderActivationCommitDisposition, error) {
	if store == nil {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation store is unavailable")
	}
	if err := store.validateRequest(evidence.Request); err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	if evidence.State != vnextReaderActivationPending {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation commit evidence is not PENDING")
	}
	if err := validateVNextReaderActivationActiveAuthorization(
		active, evidence.Request); err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	evidence = cloneVNextReaderActivationIntent(evidence)

	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.byRequestID[evidence.Request.ActivationRequestID]
	if !exists {
		return vnextReaderActivationIntent{}, 0,
			errVNextReaderActivationNotPending
	}
	if err := store.validateExistingRequest(current.request, evidence.Request); err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	if current.kind == vnextReaderActivationStoreEntryNotFoundFenced {
		return vnextReaderActivationIntent{}, 0,
			errVNextReaderActivationNotFoundFenced
	}
	if current.kind != vnextReaderActivationStoreEntryIntent {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation store entry kind is invalid")
	}
	if !equalVNextReaderActivationIntentIgnoringState(current.intent, evidence) {
		return vnextReaderActivationIntent{}, 0,
			errVNextReaderActivationConflict
	}
	switch current.intent.State {
	case vnextReaderActivationPending:
		current.intent.State = vnextReaderActivationActiveArmed
		store.byRequestID[evidence.Request.ActivationRequestID] = current
		return cloneVNextReaderActivationIntent(current.intent),
			vnextReaderActivationCommitArmed, nil
	case vnextReaderActivationActiveArmed:
		return cloneVNextReaderActivationIntent(current.intent),
			vnextReaderActivationCommitExactReplay, nil
	default:
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation state is invalid")
	}
}

// authorizeFirstRead is the read-free half of the VNext data-plane boundary.
// It accepts no short authorization-ID lookup: the caller must present the
// complete retained ACTIVE_ARMED intent and the portable restore request. The
// returned permit still grants no read until consume rechecks and claims the
// exact entry under the activation-store mutex.
func (store *vnextReaderActivationStore) authorizeFirstRead(
	request vnextReaderActivatedRestoreRequest,
) (vnextReaderAuthorization, *vnextReaderFirstReadPermit, error) {
	if store == nil {
		return vnextReaderAuthorization{}, nil,
			errors.New("VNext Reader activation store is unavailable")
	}
	if err := validateVNextReaderRequest(request.Request); err != nil {
		return vnextReaderAuthorization{}, nil, err
	}
	if err := store.validateRequest(request.Activation.Request); err != nil {
		return vnextReaderAuthorization{}, nil, err
	}
	if err := validateVNextReaderActivationEvidence(
		request.Activation, request.Activation.Request); err != nil {
		return vnextReaderAuthorization{}, nil,
			fmt.Errorf("validate VNext Reader activation evidence: %w", err)
	}
	if request.Activation.State != vnextReaderActivationActiveArmed {
		return vnextReaderAuthorization{}, nil,
			errVNextReaderActivationNotActiveArmed
	}
	if request.Activation.CxldReceipt !=
		store.canonicalEvidenceReceipt(request.Activation) {
		return vnextReaderAuthorization{}, nil,
			errors.New("VNext Reader activation evidence receipt is not canonical")
	}
	authorization := request.Activation.Request.Acquired.Authorization
	if err := validateVNextReaderActivationRestoreIdentity(
		request.Request, authorization); err != nil {
		return vnextReaderAuthorization{}, nil, err
	}

	intent := cloneVNextReaderActivationIntent(request.Activation)
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.firstReadAdmissionClosed {
		return vnextReaderAuthorization{}, nil,
			errVNextReaderFirstReadAdmissionClosed
	}
	current, exists := store.byRequestID[intent.Request.ActivationRequestID]
	if !exists || current.kind == vnextReaderActivationStoreEntryNotFoundFenced {
		return vnextReaderAuthorization{}, nil,
			errVNextReaderActivationNotActiveArmed
	}
	if current.kind != vnextReaderActivationStoreEntryIntent {
		return vnextReaderAuthorization{}, nil,
			errors.New("VNext Reader activation store entry kind is invalid")
	}
	if err := store.validateExistingRequest(current.request, intent.Request); err != nil {
		return vnextReaderAuthorization{}, nil, err
	}
	if current.intent.State != vnextReaderActivationActiveArmed {
		return vnextReaderAuthorization{}, nil,
			errVNextReaderActivationNotActiveArmed
	}
	if intent.State != current.intent.State ||
		!equalVNextReaderActivationIntentIgnoringState(current.intent, intent) ||
		current.intent.CxldReceipt != store.canonicalEvidenceReceipt(current.intent) {
		return vnextReaderAuthorization{}, nil,
			errVNextReaderActivationConflict
	}
	if current.firstReadClaimed {
		return vnextReaderAuthorization{}, nil,
			errVNextReaderFirstReadAlreadyClaimed
	}
	return cloneVNextReaderAuthorization(current.intent.Request.Acquired.Authorization),
		&vnextReaderFirstReadPermit{
			store:  store,
			intent: cloneVNextReaderActivationIntent(current.intent),
		}, nil
}

// consume performs the only state transition that grants the first source
// operation. The claim is one-shot and is never rolled back, including when a
// descriptor/content read or the restore runner later fails.
func (permit *vnextReaderFirstReadPermit) consume() error {
	if permit == nil || permit.store == nil {
		return errors.New("VNext Reader first-read permit is unavailable")
	}
	store := permit.store
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.firstReadAdmissionClosed {
		return errVNextReaderFirstReadAdmissionClosed
	}
	current, exists := store.byRequestID[permit.intent.Request.ActivationRequestID]
	if !exists || current.kind == vnextReaderActivationStoreEntryNotFoundFenced {
		return errVNextReaderActivationNotActiveArmed
	}
	if current.kind != vnextReaderActivationStoreEntryIntent {
		return errors.New("VNext Reader activation store entry kind is invalid")
	}
	if current.intent.State != vnextReaderActivationActiveArmed {
		return errVNextReaderActivationNotActiveArmed
	}
	if permit.intent.State != current.intent.State ||
		!equalVNextReaderActivationIntentIgnoringState(current.intent, permit.intent) ||
		current.intent.CxldReceipt != store.canonicalEvidenceReceipt(current.intent) {
		return errVNextReaderActivationConflict
	}
	if current.firstReadClaimed {
		return errVNextReaderFirstReadAlreadyClaimed
	}
	current.firstReadClaimed = true
	store.byRequestID[permit.intent.Request.ActivationRequestID] = current
	return nil
}

// CloseFirstReadAdmission prevents both new authorization and consumption of
// a permit that was validated before shutdown. It is idempotent and does not
// erase retained activation history.
func (store *vnextReaderActivationStore) CloseFirstReadAdmission() {
	if store == nil {
		return
	}
	store.mu.Lock()
	store.firstReadAdmissionClosed = true
	store.mu.Unlock()
}

func validateVNextReaderActivationRestoreIdentity(
	request vnextReaderRequest,
	authorization vnextReaderAuthorization,
) error {
	for _, identity := range []struct {
		name      string
		requested string
		activated string
	}{
		{"restore authorization ID", request.RestoreAuthorizationID, authorization.RestoreAuthorizationID},
		{"checkpoint ID", request.CheckpointID, authorization.CheckpointID},
		{"executor ID", request.ExecutorID, authorization.ExecutorID},
		{"cxld logical ID", request.CxldLogicalID, authorization.CxldLogicalID},
		{"target container ID", request.TargetContainerID, authorization.TargetContainerID},
	} {
		if identity.requested != identity.activated {
			return fmt.Errorf(
				"activated %s %q does not match restore request %q: %w",
				identity.name, identity.activated, identity.requested,
				errVNextReaderActivationConflict)
		}
	}
	return nil
}

func (store *vnextReaderActivationStore) replayProposalLocked(
	current vnextReaderActivationStoreEntry,
	request vnextReaderActivationRequestIdentity,
) (vnextReaderActivationIntent, vnextReaderActivationProposalDisposition, error) {
	if err := store.validateExistingRequest(current.request, request); err != nil {
		return vnextReaderActivationIntent{}, 0, err
	}
	if current.kind == vnextReaderActivationStoreEntryNotFoundFenced {
		return vnextReaderActivationIntent{}, 0,
			errVNextReaderActivationNotFoundFenced
	}
	if current.kind != vnextReaderActivationStoreEntryIntent {
		return vnextReaderActivationIntent{}, 0,
			errors.New("VNext Reader activation store entry kind is invalid")
	}
	proposal := cloneVNextReaderActivationIntent(current.intent)
	proposal.State = vnextReaderActivationPending
	return proposal,
		vnextReaderActivationProposalExactReplay, nil
}

func (store *vnextReaderActivationStore) validateRequest(
	request vnextReaderActivationRequestIdentity,
) error {
	if err := validateVNextReaderIdentity(
		"activation request ID", request.ActivationRequestID); err != nil {
		return err
	}
	// Propose repeats the time-aware check in the PREPARED store using its
	// caller-supplied local instant. Status and Commit must remain usable after
	// expiry, so this common pass is deliberately structural.
	if err := validateVNextReaderAcquiredAuthorizationStructure(
		request.Acquired); err != nil {
		return fmt.Errorf("validate VNext Reader activation ACQUIRED identity: %w", err)
	}
	if request.Acquired.Authorization.CxldProcessIncarnationID != store.localProcess {
		return fmt.Errorf(
			"request process %q, local process %q: %w",
			request.Acquired.Authorization.CxldProcessIncarnationID.String(),
			store.localProcess.String(),
			errVNextReaderActivationIncarnationMismatch)
	}
	if request.Acquired.Authorization.ExecutorID != store.localExecutorNodeID ||
		request.Acquired.Authorization.CxldLogicalID != store.localCxldLogicalID {
		return fmt.Errorf(
			"request executor/cxld %q/%q, local identity %q/%q: %w",
			request.Acquired.Authorization.ExecutorID,
			request.Acquired.Authorization.CxldLogicalID,
			store.localExecutorNodeID,
			store.localCxldLogicalID,
			errVNextReaderActivationConflict)
	}
	return nil
}

func (store *vnextReaderActivationStore) validateExistingRequest(
	current vnextReaderActivationRequestIdentity,
	supplied vnextReaderActivationRequestIdentity,
) error {
	if current.Acquired.Authorization.CxldProcessIncarnationID !=
		supplied.Acquired.Authorization.CxldProcessIncarnationID {
		return errVNextReaderActivationIncarnationMismatch
	}
	if !equalVNextReaderActivationRequestIdentity(current, supplied) {
		return errVNextReaderActivationConflict
	}
	return nil
}

func (store *vnextReaderActivationStore) installLocked(
	requestID string,
	entry vnextReaderActivationStoreEntry,
	retainedCharge uint64,
) error {
	if len(store.byRequestID) >= store.maxEntries {
		return fmt.Errorf("capacity %d: %w",
			store.maxEntries, errVNextReaderActivationStoreFull)
	}
	if store.retainedBytes > store.maxRetainedBytes ||
		retainedCharge > store.maxRetainedBytes-store.retainedBytes {
		return fmt.Errorf(
			"retained %d bytes plus activation charge %d exceeds capacity %d: %w",
			store.retainedBytes, retainedCharge, store.maxRetainedBytes,
			errVNextReaderActivationStoreRetainedBytesFull)
	}
	key := cloneVNextReaderRetainedString(requestID)
	store.byRequestID[key] = entry
	store.retainedBytes += retainedCharge
	return nil
}

func validateVNextReaderActivationActiveAuthorization(
	active vnextReaderAcquiredAuthorization,
	request vnextReaderActivationRequestIdentity,
) error {
	if active.CatalogState != vnextReaderCatalogAuthorizationActive {
		return fmt.Errorf(
			"VNext Reader activation catalog state %q is not ACTIVE",
			active.CatalogState)
	}
	if active.LastMutationID != request.ActivationRequestID {
		return errors.New(
			"VNext Reader ACTIVE last mutation ID does not match the activation request ID")
	}
	want := cloneVNextReaderAcquiredAuthorization(request.Acquired)
	want.CatalogState = active.CatalogState
	want.LastMutationID = active.LastMutationID
	if !equalVNextReaderAcquiredAuthorization(active, want) {
		return errVNextReaderActivationConflict
	}
	return nil
}

func vnextReaderActivationMappingID(
	process vnextReaderProcessIncarnation,
	generation uint64,
) string {
	return vnextReaderActivationMappingIDPrefix + process.String() + ":" +
		strconv.FormatUint(generation, 10)
}

func (store *vnextReaderActivationStore) canonicalEvidenceReceipt(
	intent vnextReaderActivationIntent,
) [sha256.Size]byte {
	return vnextReaderActivationCanonicalEvidenceReceipt(
		intent,
		store.localExecutorNodeID,
		store.localCxldLogicalID,
		store.localProcess)
}

func vnextReaderActivationRetainedCharge(
	request vnextReaderActivationRequestIdentity,
	mappingID string,
) (uint64, error) {
	acquiredCharge, err := vnextReaderAuthorizationRetainedCharge(request.Acquired)
	if err != nil {
		return 0, err
	}
	charge := acquiredCharge
	add := func(amount uint64) error {
		if amount > ^uint64(0)-charge {
			return errors.New("VNext Reader activation retained-byte charge overflows")
		}
		charge += amount
		return nil
	}
	if err := add(vnextReaderActivationStoreFixedChargeBytes); err != nil {
		return 0, err
	}
	if err := add(uint64(len(request.ActivationRequestID))); err != nil {
		return 0, err
	}
	// installLocked clones a distinct map key in addition to the copy retained
	// by entry.request. Charge both byte backings explicitly; the fixed charge
	// must not be used to hide a maximum-size identifier allocation.
	if err := add(uint64(len(request.ActivationRequestID))); err != nil {
		return 0, err
	}
	if err := add(uint64(len(mappingID))); err != nil {
		return 0, err
	}
	return charge, nil
}

func cloneVNextReaderActivationRequestIdentity(
	request vnextReaderActivationRequestIdentity,
) vnextReaderActivationRequestIdentity {
	cloned := request
	cloned.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
	cloned.ActivationRequestID = cloneVNextReaderRetainedString(
		request.ActivationRequestID)
	return cloned
}

func cloneVNextReaderActivationIntent(
	intent vnextReaderActivationIntent,
) vnextReaderActivationIntent {
	cloned := intent
	cloned.Request = cloneVNextReaderActivationRequestIdentity(intent.Request)
	cloned.MappingID = cloneVNextReaderRetainedString(intent.MappingID)
	cloned.State = vnextReaderActivationState(
		cloneVNextReaderRetainedString(string(intent.State)))
	return cloned
}

func equalVNextReaderActivationRequestIdentity(
	left vnextReaderActivationRequestIdentity,
	right vnextReaderActivationRequestIdentity,
) bool {
	return left.ActivationRequestID == right.ActivationRequestID &&
		equalVNextReaderAcquiredAuthorization(left.Acquired, right.Acquired)
}

func equalVNextReaderActivationIntentIgnoringState(
	left vnextReaderActivationIntent,
	right vnextReaderActivationIntent,
) bool {
	return equalVNextReaderActivationRequestIdentity(left.Request, right.Request) &&
		left.MappingID == right.MappingID &&
		left.MappingGeneration == right.MappingGeneration &&
		left.ActivatedAtEpochMillis == right.ActivatedAtEpochMillis &&
		left.CxldReceipt == right.CxldReceipt
}
