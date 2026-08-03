package main

import (
	"errors"
	"fmt"
)

var errVNextReaderAuthorizationNotPreparedFenced = errors.New(
	"VNext Reader authorization is permanently fenced as not prepared")

// vnextReaderPreparedStatusAndFenceState is only a process-local observation
// of the PREPARED store. It is not an ACTIVE state, mapping authorization,
// reader lease, or release/reclaim proof.
type vnextReaderPreparedStatusAndFenceState string

const (
	vnextReaderPreparedStatusExactPrepared     vnextReaderPreparedStatusAndFenceState = "PREPARED"
	vnextReaderPreparedStatusNotPreparedFenced vnextReaderPreparedStatusAndFenceState = "NOT_PREPARED_FENCED"
)

// vnextReaderPreparedStatusAndFenceResult contains an exact PREPARED receipt
// only when State is PREPARED. NOT_PREPARED_FENCED always carries a zero
// Prepared value and proves only that this process-local store permanently
// prevents a later PREPARED install for the exact ACQUIRED identity.
type vnextReaderPreparedStatusAndFenceResult struct {
	State    vnextReaderPreparedStatusAndFenceState
	Prepared vnextReaderPreparedAuthorization
}

// StatusAndFencePreparedExact performs one read-free linearization under the
// store mutex. It returns an exact PREPARED receipt when already installed, or
// installs/replays a full-identity NOT_PREPARED_FENCED tombstone. It never
// reports NOT_PREPARED_FENCED unless that tombstone is retained within both
// entry and byte budgets.
//
// This reconciliation primitive validates the complete structural ACQUIRED
// identity and interval, but deliberately has no wall-clock parameter. Expiry
// or a later Scheduler term cannot evict or replace either store decision.
func (store *vnextReaderAuthorizationStore) StatusAndFencePreparedExact(
	acquired vnextReaderAcquiredAuthorization,
) (vnextReaderPreparedStatusAndFenceResult, error) {
	if store == nil {
		return vnextReaderPreparedStatusAndFenceResult{},
			errors.New("VNext Reader authorization store is unavailable")
	}
	if err := validateVNextReaderPrepareAcquiredStructure(acquired); err != nil {
		return vnextReaderPreparedStatusAndFenceResult{}, err
	}
	retainedCharge, err := vnextReaderAuthorizationRetainedCharge(acquired)
	if err != nil {
		return vnextReaderPreparedStatusAndFenceResult{}, err
	}
	acquired = cloneVNextReaderAcquiredAuthorization(acquired)
	authorizationID := acquired.Authorization.RestoreAuthorizationID

	store.mu.Lock()
	defer store.mu.Unlock()
	if current, exists := store.byID[authorizationID]; exists {
		if !equalVNextReaderAcquiredAuthorization(current.acquired, acquired) {
			return vnextReaderPreparedStatusAndFenceResult{}, fmt.Errorf(
				"authorization %q: %w",
				authorizationID, errVNextReaderAuthorizationConflict)
		}
		switch current.kind {
		case vnextReaderAuthorizationStoreEntryPrepared:
			return vnextReaderPreparedStatusAndFenceResult{
				State: vnextReaderPreparedStatusExactPrepared,
				Prepared: vnextReaderPreparedAuthorizationFromStoreEntry(
					current),
			}, nil
		case vnextReaderAuthorizationStoreEntryNotPreparedFenced:
			return vnextReaderPreparedStatusAndFenceResult{
				State: vnextReaderPreparedStatusNotPreparedFenced,
			}, nil
		default:
			return vnextReaderPreparedStatusAndFenceResult{}, fmt.Errorf(
				"authorization %q has an invalid internal store entry", authorizationID)
		}
	}
	entry := vnextReaderAuthorizationStoreEntry{
		kind:     vnextReaderAuthorizationStoreEntryNotPreparedFenced,
		acquired: acquired,
	}
	if err := store.installVNextReaderAuthorizationEntryLocked(
		authorizationID, entry, retainedCharge); err != nil {
		return vnextReaderPreparedStatusAndFenceResult{}, err
	}
	return vnextReaderPreparedStatusAndFenceResult{
		State: vnextReaderPreparedStatusNotPreparedFenced,
	}, nil
}
