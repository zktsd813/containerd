package main

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderAuthorizationStoreMaxEntries       = 4096
	vnextReaderAuthorizationStoreMaxRetainedBytes = 64 << 20

	// Retained-byte accounting is deliberately conservative rather than an
	// unsafe.Sizeof snapshot of one Go release. The fixed charge covers the map
	// entry, prepared/authorization/root structs, digests, slice header, and
	// allocator overhead. The per-run charge covers the PageRun/PageID structs,
	// slice backing, and allocator overhead. Every retained UTF-8 byte is charged
	// separately below.
	vnextReaderAuthorizationStoreFixedChargeBytes  = 16 << 10
	vnextReaderAuthorizationStorePerRunChargeBytes = 2 << 10
)

type vnextReaderCatalogAuthorizationState string

const vnextReaderCatalogAuthorizationAcquired vnextReaderCatalogAuthorizationState = "ACQUIRED"

type vnextReaderPreparationState string

const vnextReaderPreparationPrepared vnextReaderPreparationState = "PREPARED"

type vnextReaderPreparationDisposition uint8

const (
	vnextReaderPreparationInstalled vnextReaderPreparationDisposition = iota + 1
	vnextReaderPreparationExactReplay
)

var (
	errVNextReaderAuthorizationStoreFull = errors.New(
		"VNext Reader authorization store is full")
	errVNextReaderAuthorizationStoreRetainedBytesFull = errors.New(
		"VNext Reader authorization store retained-byte budget is full")
	errVNextReaderAuthorizationConflict = errors.New(
		"VNext Reader authorization ID already has different prepared data")
	errVNextReaderAuthorizationNotFound = errors.New(
		"VNext Reader authorization is not prepared")
	errVNextReaderAuthorizationIdentityMismatch = errors.New(
		"VNext Reader prepared authorization identity does not match")
)

// vnextReaderAcquiredAuthorization is the exact durable Scheduler record
// delivered to a reader-local cxld. Authorization retains the existing
// portable Reader and root identities. The remaining fields mirror the
// Scheduler's durable ACQUIRED record; none is inferred from local DAX state.
type vnextReaderAcquiredAuthorization struct {
	Authorization          vnextReaderAuthorization
	SchedulerID            string
	SchedulerFenceRevision uint64
	IssuedAtEpochMillis    int64
	ExpiresAtEpochMillis   int64
	CatalogState           vnextReaderCatalogAuthorizationState
	LastMutationID         string
}

// vnextReaderPreparedAuthorization is a process-local, read-free receipt that
// an exact ACQUIRED record passed structural and time validation. PREPARED is
// not ACTIVE mapping evidence and grants no DAX, Owner, or CRIU authority.
// The Scheduler's ACQUIRED state and last mutation ID remain unchanged.
type vnextReaderPreparedAuthorization struct {
	Acquired         vnextReaderAcquiredAuthorization
	PreparationState vnextReaderPreparationState
}

type vnextReaderAuthorizationStoreEntryKind uint8

const (
	vnextReaderAuthorizationStoreEntryPrepared vnextReaderAuthorizationStoreEntryKind = iota + 1
	vnextReaderAuthorizationStoreEntryNotPreparedFenced
)

// vnextReaderAuthorizationStoreEntry is one process-lifetime, never-evicted
// decision for an authorization ID. A fenced entry retains the same full
// ACQUIRED identity and conservative charge as a PREPARED entry, but is not a
// prepared receipt and grants no mapping or lifecycle authority.
type vnextReaderAuthorizationStoreEntry struct {
	kind     vnextReaderAuthorizationStoreEntryKind
	acquired vnextReaderAcquiredAuthorization
}

type vnextReaderAuthorizationStoreConfig struct {
	MaxEntries       int
	MaxRetainedBytes uint64
}

// vnextReaderAuthorizationStore is deliberately an in-memory preparation
// boundary. Entries are keyed internally by authorization ID, but callers can
// retrieve one only by supplying the complete exact ACQUIRED identity again.
//
// The store never evicts. In particular, an expired entry is not silently
// replaced by another record with the same ID and is not removed merely to
// admit new work. Capacity exhaustion therefore fails closed and requires an
// explicit future lifecycle/compaction design.
//
// This type deliberately does not implement vnextReaderAuthorizer. Doing so
// would let the current Reader proceed directly to DAX before a durable ACTIVE
// transition exists.
type vnextReaderAuthorizationStore struct {
	mu               sync.RWMutex
	maxEntries       int
	maxRetainedBytes uint64
	retainedBytes    uint64
	byID             map[string]vnextReaderAuthorizationStoreEntry
}

func newVNextReaderAuthorizationStore(
	config vnextReaderAuthorizationStoreConfig,
) (*vnextReaderAuthorizationStore, error) {
	if config.MaxEntries <= 0 ||
		config.MaxEntries > vnextReaderAuthorizationStoreMaxEntries {
		return nil, fmt.Errorf(
			"VNext Reader authorization store capacity %d is outside 1..%d",
			config.MaxEntries, vnextReaderAuthorizationStoreMaxEntries)
	}
	if config.MaxRetainedBytes == 0 ||
		config.MaxRetainedBytes > vnextReaderAuthorizationStoreMaxRetainedBytes {
		return nil, fmt.Errorf(
			"VNext Reader authorization store retained-byte capacity %d is outside 1..%d",
			config.MaxRetainedBytes,
			vnextReaderAuthorizationStoreMaxRetainedBytes)
	}
	// A small retained-byte budget must not trigger a MaxEntries-sized map
	// allocation before the first authorization is admitted.
	initialMapCapacity := config.MaxEntries
	maxEntriesByFixedCharge := config.MaxRetainedBytes /
		vnextReaderAuthorizationStoreFixedChargeBytes
	if uint64(initialMapCapacity) > maxEntriesByFixedCharge {
		initialMapCapacity = int(maxEntriesByFixedCharge)
	}
	return &vnextReaderAuthorizationStore{
		maxEntries:       config.MaxEntries,
		maxRetainedBytes: config.MaxRetainedBytes,
		byID:             make(map[string]vnextReaderAuthorizationStoreEntry, initialMapCapacity),
	}, nil
}

// Prepare installs one exact Scheduler ACQUIRED record without opening,
// resolving, mapping, or reading any DAX device. An exact replay returns the
// original PREPARED receipt. A conflicting replay is rejected even when the
// store has remaining capacity.
func (store *vnextReaderAuthorizationStore) Prepare(
	acquired vnextReaderAcquiredAuthorization,
	nowEpochMillis int64,
) (vnextReaderPreparedAuthorization, vnextReaderPreparationDisposition, error) {
	if store == nil {
		return vnextReaderPreparedAuthorization{}, 0,
			errors.New("VNext Reader authorization store is unavailable")
	}
	if err := validateVNextReaderAcquiredAuthorization(acquired, nowEpochMillis); err != nil {
		return vnextReaderPreparedAuthorization{}, 0, err
	}
	retainedCharge, err := vnextReaderAuthorizationRetainedCharge(acquired)
	if err != nil {
		return vnextReaderPreparedAuthorization{}, 0, err
	}
	acquired = cloneVNextReaderAcquiredAuthorization(acquired)
	authorizationID := acquired.Authorization.RestoreAuthorizationID

	store.mu.Lock()
	defer store.mu.Unlock()
	if current, exists := store.byID[authorizationID]; exists {
		if !equalVNextReaderAcquiredAuthorization(current.acquired, acquired) {
			return vnextReaderPreparedAuthorization{}, 0, fmt.Errorf(
				"authorization %q: %w",
				authorizationID, errVNextReaderAuthorizationConflict)
		}
		switch current.kind {
		case vnextReaderAuthorizationStoreEntryPrepared:
			return vnextReaderPreparedAuthorizationFromStoreEntry(current),
				vnextReaderPreparationExactReplay, nil
		case vnextReaderAuthorizationStoreEntryNotPreparedFenced:
			return vnextReaderPreparedAuthorization{}, 0, fmt.Errorf(
				"authorization %q: %w",
				authorizationID, errVNextReaderAuthorizationNotPreparedFenced)
		default:
			return vnextReaderPreparedAuthorization{}, 0, fmt.Errorf(
				"authorization %q has an invalid internal store entry", authorizationID)
		}
	}
	entry := vnextReaderAuthorizationStoreEntry{
		kind:     vnextReaderAuthorizationStoreEntryPrepared,
		acquired: acquired,
	}
	if err := store.installVNextReaderAuthorizationEntryLocked(
		authorizationID, entry, retainedCharge); err != nil {
		return vnextReaderPreparedAuthorization{}, 0, err
	}
	return vnextReaderPreparedAuthorizationFromStoreEntry(entry),
		vnextReaderPreparationInstalled, nil
}

// LookupPreparedExact intentionally has no authorization-ID-only variant.
// The complete Scheduler record must match byte-for-byte at the typed field
// level and must still be inside its half-open validity interval.
func (store *vnextReaderAuthorizationStore) LookupPreparedExact(
	acquired vnextReaderAcquiredAuthorization,
	nowEpochMillis int64,
) (vnextReaderPreparedAuthorization, error) {
	if store == nil {
		return vnextReaderPreparedAuthorization{},
			errors.New("VNext Reader authorization store is unavailable")
	}
	if err := validateVNextReaderAcquiredAuthorization(acquired, nowEpochMillis); err != nil {
		return vnextReaderPreparedAuthorization{}, err
	}
	acquired = cloneVNextReaderAcquiredAuthorization(acquired)
	authorizationID := acquired.Authorization.RestoreAuthorizationID

	store.mu.RLock()
	defer store.mu.RUnlock()
	current, exists := store.byID[authorizationID]
	if !exists {
		return vnextReaderPreparedAuthorization{}, fmt.Errorf(
			"authorization %q: %w", authorizationID, errVNextReaderAuthorizationNotFound)
	}
	if !equalVNextReaderAcquiredAuthorization(current.acquired, acquired) {
		return vnextReaderPreparedAuthorization{}, fmt.Errorf(
			"authorization %q: %w",
			authorizationID, errVNextReaderAuthorizationIdentityMismatch)
	}
	switch current.kind {
	case vnextReaderAuthorizationStoreEntryPrepared:
		return vnextReaderPreparedAuthorizationFromStoreEntry(current), nil
	case vnextReaderAuthorizationStoreEntryNotPreparedFenced:
		return vnextReaderPreparedAuthorization{}, fmt.Errorf(
			"authorization %q: %w",
			authorizationID, errVNextReaderAuthorizationNotPreparedFenced)
	default:
		return vnextReaderPreparedAuthorization{}, fmt.Errorf(
			"authorization %q has an invalid internal store entry", authorizationID)
	}
}

// installVNextReaderAuthorizationEntryLocked atomically charges and installs
// one new never-evicted decision. The caller must hold store.mu and must have
// checked that authorizationID is absent.
func (store *vnextReaderAuthorizationStore) installVNextReaderAuthorizationEntryLocked(
	authorizationID string,
	entry vnextReaderAuthorizationStoreEntry,
	retainedCharge uint64,
) error {
	if len(store.byID) >= store.maxEntries {
		return fmt.Errorf(
			"capacity %d: %w", store.maxEntries, errVNextReaderAuthorizationStoreFull)
	}
	if store.retainedBytes > store.maxRetainedBytes ||
		retainedCharge > store.maxRetainedBytes-store.retainedBytes {
		return fmt.Errorf(
			"retained %d bytes plus authorization charge %d exceeds capacity %d: %w",
			store.retainedBytes,
			retainedCharge,
			store.maxRetainedBytes,
			errVNextReaderAuthorizationStoreRetainedBytesFull)
	}
	store.byID[authorizationID] = entry
	store.retainedBytes += retainedCharge
	return nil
}

func validateVNextReaderAcquiredAuthorization(
	acquired vnextReaderAcquiredAuthorization,
	nowEpochMillis int64,
) error {
	if nowEpochMillis < 0 {
		return errors.New("VNext Reader authorization validation time is negative")
	}
	if err := validateVNextReaderAcquiredAuthorizationIdentityAndInterval(
		acquired); err != nil {
		return err
	}
	if nowEpochMillis < acquired.IssuedAtEpochMillis {
		return errors.New("VNext Reader authorization issue time is in the future")
	}
	if nowEpochMillis >= acquired.ExpiresAtEpochMillis {
		return errors.New("VNext Reader authorization is expired")
	}
	if err := validateVNextReaderPreparedRoot(acquired.Authorization.Root); err != nil {
		return fmt.Errorf("validate VNext Reader ACQUIRED root: %w", err)
	}
	return nil
}

// validateVNextReaderAcquiredAuthorizationStructure validates the full exact
// Scheduler ACQUIRED identity and its internally valid time interval without
// comparing that interval with a receiver wall clock. Reconciliation/status
// may therefore preserve a permanent decision after expiry, while Prepare and
// LookupPreparedExact continue to use the time-aware wrapper above.
func validateVNextReaderAcquiredAuthorizationStructure(
	acquired vnextReaderAcquiredAuthorization,
) error {
	if err := validateVNextReaderAcquiredAuthorizationIdentityAndInterval(
		acquired); err != nil {
		return err
	}
	if err := validateVNextReaderPreparedRoot(acquired.Authorization.Root); err != nil {
		return fmt.Errorf("validate VNext Reader ACQUIRED root: %w", err)
	}
	return nil
}

func validateVNextReaderAcquiredAuthorizationIdentityAndInterval(
	acquired vnextReaderAcquiredAuthorization,
) error {
	if err := validateVNextReaderRequest(vnextReaderRequest{
		RestoreAuthorizationID: acquired.Authorization.RestoreAuthorizationID,
		CheckpointID:           acquired.Authorization.CheckpointID,
		ExecutorID:             acquired.Authorization.ExecutorID,
		CxldLogicalID:          acquired.Authorization.CxldLogicalID,
		TargetContainerID:      acquired.Authorization.TargetContainerID,
	}); err != nil {
		return fmt.Errorf("validate VNext Reader ACQUIRED identity: %w", err)
	}
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"Scheduler ID", acquired.SchedulerID},
		{"last mutation ID", acquired.LastMutationID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return fmt.Errorf("validate VNext Reader ACQUIRED identity: %w", err)
		}
	}
	if acquired.LastMutationID != acquired.Authorization.RestoreAuthorizationID {
		return errors.New(
			"VNext Reader ACQUIRED last mutation ID does not match the authorization ID")
	}
	if acquired.SchedulerFenceRevision == 0 ||
		acquired.SchedulerFenceRevision > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf(
			"Scheduler fence revision %d is outside 1..%d",
			acquired.SchedulerFenceRevision, cxlcheckpoint.MaxSignedLong)
	}
	if err := validateVNextReaderProcessIncarnation(
		acquired.Authorization.CxldProcessIncarnationID); err != nil {
		return fmt.Errorf(
			"validate VNext Reader ACQUIRED process incarnation: %w", err)
	}
	if acquired.Authorization.ReaderInitialRegistrationCatalogRevision == 0 ||
		acquired.Authorization.ReaderInitialRegistrationCatalogRevision >
			cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf(
			"Reader initial registration catalog revision %d is outside 1..%d",
			acquired.Authorization.ReaderInitialRegistrationCatalogRevision,
			cxlcheckpoint.MaxSignedLong)
	}
	if acquired.CatalogState != vnextReaderCatalogAuthorizationAcquired {
		return fmt.Errorf(
			"Scheduler authorization state %q is not ACQUIRED", acquired.CatalogState)
	}
	if acquired.IssuedAtEpochMillis < 0 ||
		acquired.ExpiresAtEpochMillis <= acquired.IssuedAtEpochMillis {
		return errors.New("VNext Reader authorization time interval is invalid")
	}
	return nil
}

// validateVNextReaderPreparedRoot performs only portable structural checks.
// It intentionally does not resolve a device UUID into a local path or check
// a descriptor. Those operations belong after durable ACTIVE evidence.
func validateVNextReaderPreparedRoot(root vnextReaderTrustedRoot) error {
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"authorized root ID", root.RootID},
		{"authorized MM template ID", root.MMTemplateID},
		{"authorized PageMap ID", root.PageMapID},
	} {
		if err := validateVNextReaderIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if root.RootVersion == 0 || root.RootVersion > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("authorized root version %d is invalid", root.RootVersion)
	}
	if root.PageMapVersion == 0 || root.PageMapVersion > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("authorized PageMap version %d is invalid", root.PageMapVersion)
	}
	if root.ContractID != cxlcheckpoint.V6CompatibilityID {
		return fmt.Errorf(
			"authorized contract %q is not the exact V6 compatibility identity",
			root.ContractID)
	}

	locator := root.PublicationLocator
	maxPublicationBytes := uint64(cxlcheckpoint.PublicationEnvelopeHeaderBytes) +
		cxlcheckpoint.MaxPayloadBytes
	if locator.PublicationByteLength == 0 ||
		locator.PublicationByteLength > maxPublicationBytes {
		return fmt.Errorf(
			"authorized publication length %d is outside the V6 envelope limit",
			locator.PublicationByteLength)
	}
	if len(locator.PageRuns) == 0 || len(locator.PageRuns) > vnextReaderMaxLocatorRuns {
		return fmt.Errorf(
			"authorized locator run count %d is outside 1..%d",
			len(locator.PageRuns), vnextReaderMaxLocatorRuns)
	}

	expectedPages := (locator.PublicationByteLength + cxlcheckpoint.PageSize - 1) /
		cxlcheckpoint.PageSize
	locatedPages := uint64(0)
	type physicalRange struct {
		start uint64
		end   uint64
	}
	byDevice := make(map[string][]physicalRange)
	for index, run := range locator.PageRuns {
		pageID := run.FirstPage
		if err := validateVNextReaderIdentity("locator Owner ID", pageID.OwnerID); err != nil {
			return fmt.Errorf("locator run %d: %w", index, err)
		}
		if err := validateVNextReaderDeviceID(pageID.DeviceUUID); err != nil {
			return fmt.Errorf("locator run %d: %w", index, err)
		}
		if pageID.AllocationRecordID == 0 ||
			pageID.AllocationRecordID > cxlcheckpoint.MaxSignedLong {
			return fmt.Errorf("locator run %d has invalid allocation record ID", index)
		}
		if run.PageCount == 0 || run.PageCount > cxlcheckpoint.MaxSignedLong ||
			pageID.DataPageIndex > cxlcheckpoint.MaxSignedLong-run.PageCount {
			return fmt.Errorf("locator run %d has an invalid or overflowing page range", index)
		}
		if locatedPages > expectedPages || run.PageCount > expectedPages-locatedPages {
			return fmt.Errorf(
				"locator run %d exceeds the %d pages required by the exact length",
				index, expectedPages)
		}
		locatedPages += run.PageCount
		if index > 0 {
			previous := locator.PageRuns[index-1]
			if previous.FirstPage.OwnerID == pageID.OwnerID &&
				previous.FirstPage.DeviceUUID == pageID.DeviceUUID &&
				previous.FirstPage.AllocationRecordID == pageID.AllocationRecordID &&
				previous.FirstPage.DataPageIndex+previous.PageCount == pageID.DataPageIndex {
				return fmt.Errorf("locator runs %d and %d are not coalesced", index-1, index)
			}
		}
		key := pageID.OwnerID + "\x00" + pageID.DeviceUUID
		byDevice[key] = append(byDevice[key], physicalRange{
			start: pageID.DataPageIndex,
			end:   pageID.DataPageIndex + run.PageCount,
		})
	}
	if locatedPages != expectedPages {
		return fmt.Errorf(
			"authorized locator covers %d pages, exact length requires %d",
			locatedPages, expectedPages)
	}
	for key, ranges := range byDevice {
		sort.Slice(ranges, func(left, right int) bool {
			if ranges[left].start == ranges[right].start {
				return ranges[left].end < ranges[right].end
			}
			return ranges[left].start < ranges[right].start
		})
		for index := 1; index < len(ranges); index++ {
			if ranges[index-1].end > ranges[index].start {
				return fmt.Errorf("authorized locator has overlapping ranges on %q", key)
			}
		}
	}
	return nil
}

func vnextReaderAuthorizationRetainedCharge(
	acquired vnextReaderAcquiredAuthorization,
) (uint64, error) {
	charge := uint64(vnextReaderAuthorizationStoreFixedChargeBytes)
	add := func(amount uint64) error {
		if amount > ^uint64(0)-charge {
			return errors.New("VNext Reader authorization retained-byte charge overflows")
		}
		charge += amount
		return nil
	}
	addString := func(value string) error {
		return add(uint64(len(value)))
	}

	authorization := acquired.Authorization
	root := authorization.Root
	stringsToRetain := []string{
		authorization.RestoreAuthorizationID,
		authorization.CheckpointID,
		authorization.ExecutorID,
		authorization.CxldLogicalID,
		authorization.CxldProcessIncarnationID.String(),
		authorization.TargetContainerID,
		root.RootID,
		root.MMTemplateID,
		root.PageMapID,
		root.ContractID,
		acquired.SchedulerID,
		string(acquired.CatalogState),
		acquired.LastMutationID,
	}
	for _, value := range stringsToRetain {
		if err := addString(value); err != nil {
			return 0, err
		}
	}
	// Explicitly charge the immutable birth revision. The canonical 64-byte
	// incarnation text above is deliberately more conservative than the compact
	// 32-byte in-memory representation.
	if err := add(8); err != nil {
		return 0, err
	}
	runCount := uint64(len(root.PublicationLocator.PageRuns))
	if runCount > ^uint64(0)/vnextReaderAuthorizationStorePerRunChargeBytes {
		return 0, errors.New("VNext Reader authorization locator charge overflows")
	}
	if err := add(runCount * vnextReaderAuthorizationStorePerRunChargeBytes); err != nil {
		return 0, err
	}
	for _, run := range root.PublicationLocator.PageRuns {
		if err := addString(run.FirstPage.OwnerID); err != nil {
			return 0, err
		}
		if err := addString(run.FirstPage.DeviceUUID); err != nil {
			return 0, err
		}
	}
	return charge, nil
}

func cloneVNextReaderAcquiredAuthorization(
	acquired vnextReaderAcquiredAuthorization,
) vnextReaderAcquiredAuthorization {
	cloned := acquired
	cloned.SchedulerID = cloneVNextReaderRetainedString(acquired.SchedulerID)
	cloned.CatalogState = vnextReaderCatalogAuthorizationState(
		cloneVNextReaderRetainedString(string(acquired.CatalogState)))
	cloned.LastMutationID = cloneVNextReaderRetainedString(acquired.LastMutationID)

	authorization := acquired.Authorization
	cloned.Authorization = authorization
	cloned.Authorization.RestoreAuthorizationID = cloneVNextReaderRetainedString(
		authorization.RestoreAuthorizationID)
	cloned.Authorization.CheckpointID = cloneVNextReaderRetainedString(
		authorization.CheckpointID)
	cloned.Authorization.ExecutorID = cloneVNextReaderRetainedString(
		authorization.ExecutorID)
	cloned.Authorization.CxldLogicalID = cloneVNextReaderRetainedString(
		authorization.CxldLogicalID)
	cloned.Authorization.CxldProcessIncarnationID =
		authorization.CxldProcessIncarnationID
	cloned.Authorization.ReaderInitialRegistrationCatalogRevision =
		authorization.ReaderInitialRegistrationCatalogRevision
	cloned.Authorization.TargetContainerID = cloneVNextReaderRetainedString(
		authorization.TargetContainerID)

	root := authorization.Root
	cloned.Authorization.Root = root
	cloned.Authorization.Root.RootID = cloneVNextReaderRetainedString(root.RootID)
	cloned.Authorization.Root.MMTemplateID = cloneVNextReaderRetainedString(root.MMTemplateID)
	cloned.Authorization.Root.PageMapID = cloneVNextReaderRetainedString(root.PageMapID)
	cloned.Authorization.Root.ContractID = cloneVNextReaderRetainedString(root.ContractID)
	runs := root.PublicationLocator.PageRuns
	cloned.Authorization.Root.PublicationLocator.PageRuns = make(
		[]cxlcheckpoint.PublicationPageRun, len(runs))
	for index, run := range runs {
		clonedRun := run
		clonedRun.FirstPage.OwnerID = cloneVNextReaderRetainedString(run.FirstPage.OwnerID)
		clonedRun.FirstPage.DeviceUUID = cloneVNextReaderRetainedString(run.FirstPage.DeviceUUID)
		cloned.Authorization.Root.PublicationLocator.PageRuns[index] = clonedRun
	}
	return cloned
}

func cloneVNextReaderRetainedString(value string) string {
	if value == "" {
		return ""
	}
	bytes := make([]byte, len(value))
	copy(bytes, value)
	return string(bytes)
}

func cloneVNextReaderPreparedAuthorization(
	prepared vnextReaderPreparedAuthorization,
) vnextReaderPreparedAuthorization {
	cloned := prepared
	cloned.Acquired = cloneVNextReaderAcquiredAuthorization(prepared.Acquired)
	return cloned
}

func vnextReaderPreparedAuthorizationFromStoreEntry(
	entry vnextReaderAuthorizationStoreEntry,
) vnextReaderPreparedAuthorization {
	return cloneVNextReaderPreparedAuthorization(vnextReaderPreparedAuthorization{
		Acquired:         entry.acquired,
		PreparationState: vnextReaderPreparationPrepared,
	})
}

func equalVNextReaderAcquiredAuthorization(
	left vnextReaderAcquiredAuthorization,
	right vnextReaderAcquiredAuthorization,
) bool {
	if left.SchedulerID != right.SchedulerID ||
		left.SchedulerFenceRevision != right.SchedulerFenceRevision ||
		left.IssuedAtEpochMillis != right.IssuedAtEpochMillis ||
		left.ExpiresAtEpochMillis != right.ExpiresAtEpochMillis ||
		left.CatalogState != right.CatalogState ||
		left.LastMutationID != right.LastMutationID {
		return false
	}
	leftAuthorization := left.Authorization
	rightAuthorization := right.Authorization
	if leftAuthorization.RestoreAuthorizationID != rightAuthorization.RestoreAuthorizationID ||
		leftAuthorization.CheckpointID != rightAuthorization.CheckpointID ||
		leftAuthorization.ExecutorID != rightAuthorization.ExecutorID ||
		leftAuthorization.CxldLogicalID != rightAuthorization.CxldLogicalID ||
		leftAuthorization.CxldProcessIncarnationID !=
			rightAuthorization.CxldProcessIncarnationID ||
		leftAuthorization.ReaderInitialRegistrationCatalogRevision !=
			rightAuthorization.ReaderInitialRegistrationCatalogRevision ||
		leftAuthorization.TargetContainerID != rightAuthorization.TargetContainerID {
		return false
	}
	leftRoot := leftAuthorization.Root
	rightRoot := rightAuthorization.Root
	if leftRoot.RootID != rightRoot.RootID ||
		leftRoot.RootVersion != rightRoot.RootVersion ||
		leftRoot.MMTemplateID != rightRoot.MMTemplateID ||
		leftRoot.PageMapID != rightRoot.PageMapID ||
		leftRoot.PageMapVersion != rightRoot.PageMapVersion ||
		leftRoot.DeviceTableDigest != rightRoot.DeviceTableDigest ||
		leftRoot.ContractID != rightRoot.ContractID ||
		leftRoot.PublicationLocator.PublicationByteLength !=
			rightRoot.PublicationLocator.PublicationByteLength ||
		leftRoot.PublicationLocator.PublicationSHA256 !=
			rightRoot.PublicationLocator.PublicationSHA256 ||
		len(leftRoot.PublicationLocator.PageRuns) !=
			len(rightRoot.PublicationLocator.PageRuns) {
		return false
	}
	for index := range leftRoot.PublicationLocator.PageRuns {
		if leftRoot.PublicationLocator.PageRuns[index] !=
			rightRoot.PublicationLocator.PageRuns[index] {
			return false
		}
	}
	return true
}
