package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func assertVNextReaderStatusNotPreparedFenced(
	t *testing.T,
	result vnextReaderPreparedStatusAndFenceResult,
	err error,
) {
	t.Helper()
	if err != nil {
		t.Fatalf("status-and-fence NOT_PREPARED_FENCED: %v", err)
	}
	if result.State != vnextReaderPreparedStatusNotPreparedFenced {
		t.Fatalf("status-and-fence state = %q, want NOT_PREPARED_FENCED", result.State)
	}
	if !reflect.DeepEqual(result.Prepared, vnextReaderPreparedAuthorization{}) {
		t.Fatalf("NOT_PREPARED_FENCED returned a prepared receipt: %#v", result.Prepared)
	}
}

func assertVNextReaderStatusExactPrepared(
	t *testing.T,
	result vnextReaderPreparedStatusAndFenceResult,
	err error,
	want vnextReaderAcquiredAuthorization,
) {
	t.Helper()
	if err != nil {
		t.Fatalf("status-and-fence PREPARED: %v", err)
	}
	if result.State != vnextReaderPreparedStatusExactPrepared ||
		result.Prepared.PreparationState != vnextReaderPreparationPrepared ||
		!equalVNextReaderAcquiredAuthorization(result.Prepared.Acquired, want) {
		t.Fatalf("status-and-fence PREPARED result lost exact identity: %#v", result)
	}
}

func TestVNextReaderStatusAndFenceInstallsPermanentExactTombstone(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new status-and-fence store: %v", err)
	}
	caller := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-status-fenced")
	// The interval is structurally valid but long expired relative to any real
	// current clock. StatusAndFencePreparedExact intentionally has no wall-clock
	// input and must still install and replay the permanent decision.
	caller.IssuedAtEpochMillis = 1
	caller.ExpiresAtEpochMillis = 2
	want := cloneVNextReaderAcquiredAuthorization(caller)
	wantCharge, err := vnextReaderAuthorizationRetainedCharge(want)
	if err != nil {
		t.Fatalf("calculate tombstone retained charge: %v", err)
	}
	callerIDData := vnextReaderAuthorizationStoreTestStringData(
		caller.Authorization.RestoreAuthorizationID)
	callerRun := &caller.Authorization.Root.PublicationLocator.PageRuns[0]

	result, err := store.StatusAndFencePreparedExact(caller)
	assertVNextReaderStatusNotPreparedFenced(t, result, err)
	if len(store.byID) != 1 || store.retainedBytes != wantCharge {
		t.Fatalf("tombstone store entries/bytes = %d/%d, want 1/%d",
			len(store.byID), store.retainedBytes, wantCharge)
	}
	entry := store.byID[want.Authorization.RestoreAuthorizationID]
	if entry.kind != vnextReaderAuthorizationStoreEntryNotPreparedFenced ||
		!equalVNextReaderAcquiredAuthorization(entry.acquired, want) {
		t.Fatalf("stored tombstone lost exact identity: %#v", entry)
	}
	if &entry.acquired.Authorization.Root.PublicationLocator.PageRuns[0] == callerRun {
		t.Fatal("stored tombstone retained the caller's PageRuns backing")
	}
	if vnextReaderAuthorizationStoreTestStringData(
		entry.acquired.Authorization.RestoreAuthorizationID) == callerIDData {
		t.Fatal("stored tombstone retained the caller's authorization-ID backing")
	}
	for key := range store.byID {
		if vnextReaderAuthorizationStoreTestStringData(key) == callerIDData {
			t.Fatal("tombstone map key retained the caller's authorization-ID backing")
		}
	}

	caller.Authorization.RestoreAuthorizationID = "mutated-caller-id"
	caller.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
		"mutated-caller-owner"
	replayed, err := store.StatusAndFencePreparedExact(want)
	assertVNextReaderStatusNotPreparedFenced(t, replayed, err)
	if len(store.byID) != 1 || store.retainedBytes != wantCharge {
		t.Fatal("exact tombstone replay changed entry or retained-byte accounting")
	}

	if _, err := store.LookupPreparedExact(want, want.IssuedAtEpochMillis); !errors.Is(
		err, errVNextReaderAuthorizationNotPreparedFenced) {
		t.Fatalf("LookupPreparedExact tombstone error = %v, want fenced", err)
	}
	if _, _, err := store.Prepare(want, want.IssuedAtEpochMillis); !errors.Is(
		err, errVNextReaderAuthorizationNotPreparedFenced) {
		t.Fatalf("late PREPARE error = %v, want permanent fence", err)
	}
	if store.byID[want.Authorization.RestoreAuthorizationID].kind !=
		vnextReaderAuthorizationStoreEntryNotPreparedFenced {
		t.Fatal("late PREPARE replaced the permanent tombstone")
	}

	newTerm := cloneVNextReaderAcquiredAuthorization(want)
	newTerm.SchedulerFenceRevision++
	if result, err := store.StatusAndFencePreparedExact(newTerm); !errors.Is(
		err, errVNextReaderAuthorizationConflict) ||
		!reflect.DeepEqual(result, vnextReaderPreparedStatusAndFenceResult{}) {
		t.Fatalf("new-term identity status result=%#v err=%v, want conflict", result, err)
	}
	if !equalVNextReaderAcquiredAuthorization(
		store.byID[want.Authorization.RestoreAuthorizationID].acquired, want) {
		t.Fatal("new-term conflict replaced the original tombstone identity")
	}
	if _, _, err := store.Prepare(newTerm, newTerm.IssuedAtEpochMillis); !errors.Is(
		err, errVNextReaderAuthorizationConflict) {
		t.Fatalf("new-term PREPARE error = %v, want conflict", err)
	}
}

func TestVNextReaderStatusAndFenceReturnsExactPreparedAfterExpiry(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new prepared-first store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-status-prepared")
	charge, err := vnextReaderAuthorizationRetainedCharge(acquired)
	if err != nil {
		t.Fatalf("calculate prepared charge: %v", err)
	}
	prepared, disposition, err := store.Prepare(acquired, 150)
	if err != nil || disposition != vnextReaderPreparationInstalled {
		t.Fatalf("prepare before status: prepared=%#v disposition=%v err=%v",
			prepared, disposition, err)
	}

	if _, err := store.LookupPreparedExact(
		acquired, acquired.ExpiresAtEpochMillis); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("time-aware lookup at expiry = %v, want expired", err)
	}
	result, err := store.StatusAndFencePreparedExact(acquired)
	assertVNextReaderStatusExactPrepared(t, result, err, acquired)
	if len(store.byID) != 1 || store.retainedBytes != charge {
		t.Fatal("prepared status changed entry or retained-byte accounting")
	}

	result.Prepared.Acquired.Authorization.Root.PublicationLocator.
		PageRuns[0].FirstPage.OwnerID = "mutated-returned-status"
	again, err := store.StatusAndFencePreparedExact(acquired)
	assertVNextReaderStatusExactPrepared(t, again, err, acquired)
	if again.Prepared.Acquired.Authorization.Root.PublicationLocator.
		PageRuns[0].FirstPage.OwnerID == "mutated-returned-status" {
		t.Fatal("returned PREPARED status receipt aliases the stored entry")
	}

	conflict := cloneVNextReaderAcquiredAuthorization(acquired)
	conflict.Authorization.TargetContainerID = "different-target"
	if result, err := store.StatusAndFencePreparedExact(conflict); !errors.Is(
		err, errVNextReaderAuthorizationConflict) ||
		!reflect.DeepEqual(result, vnextReaderPreparedStatusAndFenceResult{}) {
		t.Fatalf("prepared identity conflict result=%#v err=%v", result, err)
	}
	if store.byID[acquired.Authorization.RestoreAuthorizationID].kind !=
		vnextReaderAuthorizationStoreEntryPrepared {
		t.Fatal("status conflict replaced the PREPARED entry")
	}
}

type vnextReaderStatusFencePrepareOutcome struct {
	prepared    vnextReaderPreparedAuthorization
	disposition vnextReaderPreparationDisposition
	err         error
}

type vnextReaderStatusFenceOutcome struct {
	result vnextReaderPreparedStatusAndFenceResult
	err    error
}

func TestVNextReaderStatusAndFenceDeterministicLinearizationOrders(t *testing.T) {
	t.Run("prepare-first", func(t *testing.T) {
		store, err := newVNextReaderAuthorizationStore(
			vnextReaderAuthorizationStoreTestConfig(1))
		if err != nil {
			t.Fatalf("new prepare-first store: %v", err)
		}
		acquired := vnextReaderAuthorizationStoreTestAcquired(
			"authorization-ordered-prepare-first")
		prepareDone := make(chan struct{})
		prepareResult := make(chan vnextReaderStatusFencePrepareOutcome, 1)
		statusResult := make(chan vnextReaderStatusFenceOutcome, 1)
		go func() {
			prepared, disposition, err := store.Prepare(acquired, 150)
			prepareResult <- vnextReaderStatusFencePrepareOutcome{
				prepared: prepared, disposition: disposition, err: err,
			}
			close(prepareDone)
		}()
		go func() {
			<-prepareDone
			result, err := store.StatusAndFencePreparedExact(acquired)
			statusResult <- vnextReaderStatusFenceOutcome{result: result, err: err}
		}()
		prepared := <-prepareResult
		status := <-statusResult
		if prepared.err != nil ||
			prepared.disposition != vnextReaderPreparationInstalled {
			t.Fatalf("ordered prepare result = %#v", prepared)
		}
		assertVNextReaderStatusExactPrepared(t, status.result, status.err, acquired)
	})

	t.Run("fence-first", func(t *testing.T) {
		store, err := newVNextReaderAuthorizationStore(
			vnextReaderAuthorizationStoreTestConfig(1))
		if err != nil {
			t.Fatalf("new fence-first store: %v", err)
		}
		acquired := vnextReaderAuthorizationStoreTestAcquired(
			"authorization-ordered-fence-first")
		statusDone := make(chan struct{})
		statusResult := make(chan vnextReaderStatusFenceOutcome, 1)
		prepareResult := make(chan vnextReaderStatusFencePrepareOutcome, 1)
		go func() {
			result, err := store.StatusAndFencePreparedExact(acquired)
			statusResult <- vnextReaderStatusFenceOutcome{result: result, err: err}
			close(statusDone)
		}()
		go func() {
			<-statusDone
			prepared, disposition, err := store.Prepare(acquired, 150)
			prepareResult <- vnextReaderStatusFencePrepareOutcome{
				prepared: prepared, disposition: disposition, err: err,
			}
		}()
		status := <-statusResult
		prepared := <-prepareResult
		assertVNextReaderStatusNotPreparedFenced(t, status.result, status.err)
		if !errors.Is(prepared.err, errVNextReaderAuthorizationNotPreparedFenced) ||
			prepared.disposition != 0 ||
			!reflect.DeepEqual(prepared.prepared, vnextReaderPreparedAuthorization{}) {
			t.Fatalf("ordered late PREPARE result = %#v", prepared)
		}
	})
}

func TestVNextReaderStatusAndFenceConcurrentRaceHasOneExactOutcome(t *testing.T) {
	const iterations = 256
	var prepareFirst int
	var fenceFirst int
	for iteration := 0; iteration < iterations; iteration++ {
		store, err := newVNextReaderAuthorizationStore(
			vnextReaderAuthorizationStoreTestConfig(1))
		if err != nil {
			t.Fatalf("iteration %d: new race store: %v", iteration, err)
		}
		acquired := vnextReaderAuthorizationStoreTestAcquired(
			fmt.Sprintf("authorization-status-race-%03d", iteration))
		charge, err := vnextReaderAuthorizationRetainedCharge(acquired)
		if err != nil {
			t.Fatalf("iteration %d: retained charge: %v", iteration, err)
		}
		start := make(chan struct{})
		prepareResult := make(chan vnextReaderStatusFencePrepareOutcome, 1)
		statusResult := make(chan vnextReaderStatusFenceOutcome, 1)
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			prepared, disposition, err := store.Prepare(acquired, 150)
			prepareResult <- vnextReaderStatusFencePrepareOutcome{
				prepared: prepared, disposition: disposition, err: err,
			}
		}()
		go func() {
			defer wait.Done()
			<-start
			result, err := store.StatusAndFencePreparedExact(acquired)
			statusResult <- vnextReaderStatusFenceOutcome{result: result, err: err}
		}()
		close(start)
		wait.Wait()
		prepared := <-prepareResult
		status := <-statusResult
		switch {
		case prepared.err == nil &&
			prepared.disposition == vnextReaderPreparationInstalled &&
			status.err == nil &&
			status.result.State == vnextReaderPreparedStatusExactPrepared:
			prepareFirst++
			assertVNextReaderStatusExactPrepared(t, status.result, nil, acquired)
			if store.byID[acquired.Authorization.RestoreAuthorizationID].kind !=
				vnextReaderAuthorizationStoreEntryPrepared {
				t.Fatalf("iteration %d: PREPARED result stored another kind", iteration)
			}
		case errors.Is(prepared.err, errVNextReaderAuthorizationNotPreparedFenced) &&
			prepared.disposition == 0 &&
			status.err == nil &&
			status.result.State == vnextReaderPreparedStatusNotPreparedFenced:
			fenceFirst++
			assertVNextReaderStatusNotPreparedFenced(t, status.result, nil)
			if store.byID[acquired.Authorization.RestoreAuthorizationID].kind !=
				vnextReaderAuthorizationStoreEntryNotPreparedFenced {
				t.Fatalf("iteration %d: fenced result stored another kind", iteration)
			}
		default:
			t.Fatalf("iteration %d: impossible race result prepare=%#v status=%#v",
				iteration, prepared, status)
		}
		if len(store.byID) != 1 || store.retainedBytes != charge {
			t.Fatalf("iteration %d: entries/bytes=%d/%d, want 1/%d",
				iteration, len(store.byID), store.retainedBytes, charge)
		}
	}
	if prepareFirst+fenceFirst != iterations {
		t.Fatalf("race outcomes prepare-first=%d fence-first=%d, want %d total",
			prepareFirst, fenceFirst, iterations)
	}
}

func TestVNextReaderStatusAndFenceCapacityFailuresAreAtomic(t *testing.T) {
	seed := vnextReaderAuthorizationStoreTestAcquired("authorization-fence-capacity-a")
	seedCharge, err := vnextReaderAuthorizationRetainedCharge(seed)
	if err != nil {
		t.Fatalf("seed retained charge: %v", err)
	}
	entryStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreConfig{
			MaxEntries:       1,
			MaxRetainedBytes: vnextReaderAuthorizationStoreMaxRetainedBytes,
		})
	if err != nil {
		t.Fatalf("new entry-bound status store: %v", err)
	}
	seedResult, err := entryStore.StatusAndFencePreparedExact(seed)
	assertVNextReaderStatusNotPreparedFenced(t, seedResult, err)
	other := vnextReaderAuthorizationStoreTestAcquired("authorization-fence-capacity-b")
	result, err := entryStore.StatusAndFencePreparedExact(other)
	if !errors.Is(err, errVNextReaderAuthorizationStoreFull) ||
		!reflect.DeepEqual(result, vnextReaderPreparedStatusAndFenceResult{}) {
		t.Fatalf("entry exhaustion result=%#v err=%v, want zero/full", result, err)
	}
	if len(entryStore.byID) != 1 || entryStore.retainedBytes != seedCharge {
		t.Fatal("entry exhaustion changed the retained store")
	}
	if _, exists := entryStore.byID[other.Authorization.RestoreAuthorizationID]; exists {
		t.Fatal("entry exhaustion installed a false NOT_PREPARED_FENCED tombstone")
	}
	replayed, err := entryStore.StatusAndFencePreparedExact(seed)
	assertVNextReaderStatusNotPreparedFenced(t, replayed, err)

	byteCandidate := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-fence-byte-capacity")
	byteCharge, err := vnextReaderAuthorizationRetainedCharge(byteCandidate)
	if err != nil || byteCharge <= 1 {
		t.Fatalf("byte candidate charge = %d/%v", byteCharge, err)
	}
	byteStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreConfig{
			MaxEntries:       1,
			MaxRetainedBytes: byteCharge - 1,
		})
	if err != nil {
		t.Fatalf("new byte-bound status store: %v", err)
	}
	result, err = byteStore.StatusAndFencePreparedExact(byteCandidate)
	if !errors.Is(err, errVNextReaderAuthorizationStoreRetainedBytesFull) ||
		!reflect.DeepEqual(result, vnextReaderPreparedStatusAndFenceResult{}) {
		t.Fatalf("byte exhaustion result=%#v err=%v, want zero/byte-full", result, err)
	}
	if len(byteStore.byID) != 0 || byteStore.retainedBytes != 0 {
		t.Fatalf("byte exhaustion changed store entries/bytes=%d/%d",
			len(byteStore.byID), byteStore.retainedBytes)
	}

	exactByteStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreConfig{
			MaxEntries:       2,
			MaxRetainedBytes: byteCharge,
		})
	if err != nil {
		t.Fatalf("new exact-byte status store: %v", err)
	}
	exact, err := exactByteStore.StatusAndFencePreparedExact(byteCandidate)
	assertVNextReaderStatusNotPreparedFenced(t, exact, err)
	exactReplay, err := exactByteStore.StatusAndFencePreparedExact(byteCandidate)
	assertVNextReaderStatusNotPreparedFenced(t, exactReplay, err)
	if len(exactByteStore.byID) != 1 || exactByteStore.retainedBytes != byteCharge {
		t.Fatalf("exact-byte replay entries/bytes=%d/%d, want 1/%d",
			len(exactByteStore.byID), exactByteStore.retainedBytes, byteCharge)
	}
	secondAtLimit := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-fence-byte-capacity-other")
	result, err = exactByteStore.StatusAndFencePreparedExact(secondAtLimit)
	if !errors.Is(err, errVNextReaderAuthorizationStoreRetainedBytesFull) ||
		!reflect.DeepEqual(result, vnextReaderPreparedStatusAndFenceResult{}) {
		t.Fatalf("exact-byte second result=%#v err=%v, want zero/byte-full", result, err)
	}
}

func TestVNextReaderStatusAndFenceRequiresFullStructuralIdentity(t *testing.T) {
	for name, mutate := range map[string]func(*vnextReaderAcquiredAuthorization){
		"invalid interval": func(value *vnextReaderAcquiredAuthorization) {
			value.ExpiresAtEpochMillis = value.IssuedAtEpochMillis
		},
		"wrong catalog state": func(value *vnextReaderAcquiredAuthorization) {
			value.CatalogState = "PREPARED"
		},
		"wrong last mutation": func(value *vnextReaderAcquiredAuthorization) {
			value.LastMutationID = "different-mutation"
		},
		"invalid root contract": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.ContractID = "invalid-contract"
		},
		"invalid locator": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PageRuns[0].PageCount = 0
		},
		"zero device-table digest": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.DeviceTableDigest = [sha256.Size]byte{}
		},
		"zero publication digest": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PublicationSHA256 =
				[sha256.Size]byte{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := newVNextReaderAuthorizationStore(
				vnextReaderAuthorizationStoreTestConfig(1))
			if err != nil {
				t.Fatalf("new structural status store: %v", err)
			}
			candidate := vnextReaderAuthorizationStoreTestAcquired(
				"authorization-fence-invalid")
			mutate(&candidate)
			result, err := store.StatusAndFencePreparedExact(candidate)
			if err == nil ||
				!reflect.DeepEqual(result, vnextReaderPreparedStatusAndFenceResult{}) {
				t.Fatalf("invalid structural identity result=%#v err=%v", result, err)
			}
			if len(store.byID) != 0 || store.retainedBytes != 0 {
				t.Fatal("invalid structural identity consumed store capacity")
			}
		})
	}

	var nilStore *vnextReaderAuthorizationStore
	result, err := nilStore.StatusAndFencePreparedExact(
		vnextReaderAuthorizationStoreTestAcquired("authorization-fence-nil-store"))
	if err == nil || !reflect.DeepEqual(
		result, vnextReaderPreparedStatusAndFenceResult{}) {
		t.Fatalf("nil store result=%#v err=%v", result, err)
	}
}

func TestVNextReaderStatusAndFenceIsReadFreeAndHasNoLifecycleAuthority(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new read-free status store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-fence-no-device")
	acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID =
		"nonexistent-portable-device"
	result, err := store.StatusAndFencePreparedExact(acquired)
	assertVNextReaderStatusNotPreparedFenced(t, result, err)

	resultType := reflect.TypeOf(vnextReaderPreparedStatusAndFenceResult{})
	for index := 0; index < resultType.NumField(); index++ {
		field := resultType.Field(index)
		text := strings.ToLower(field.Name + " " + field.Type.String())
		for _, forbidden := range []string{
			"dax", "criu", "active", "release", "reclaim", "mapping", "lease",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("status result field %s carries forbidden lifecycle authority", field.Name)
			}
		}
	}
}
