package main

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func vnextReaderActivationStoreTestConfig(
	maxEntries int,
) vnextReaderActivationStoreConfig {
	return vnextReaderActivationStoreConfig{
		MaxEntries:       maxEntries,
		MaxRetainedBytes: vnextReaderActivationStoreMaxRetainedBytes,
	}
}

func vnextReaderActivationStoreTestFixture(
	t *testing.T,
	maxEntries int,
) (*vnextReaderAuthorizationStore, *vnextReaderActivationStore) {
	t.Helper()
	prepared, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(maxEntries))
	if err != nil {
		t.Fatalf("new PREPARED store: %v", err)
	}
	process := vnextReaderAuthorizationStoreTestAcquired(
		"activation-fixture-process").Authorization.CxldProcessIncarnationID
	store, err := newVNextReaderActivationStore(
		vnextReaderActivationStoreTestConfig(maxEntries),
		"executor-a",
		"reader-cxld-a",
		process,
		prepared)
	if err != nil {
		t.Fatalf("new activation store: %v", err)
	}
	return prepared, store
}

func vnextReaderActivationStoreTestPrepare(
	t *testing.T,
	prepared *vnextReaderAuthorizationStore,
	authorizationID string,
) vnextReaderAcquiredAuthorization {
	t.Helper()
	acquired := vnextReaderAuthorizationStoreTestAcquired(authorizationID)
	if _, disposition, err := prepared.Prepare(acquired, 150); err != nil ||
		disposition != vnextReaderPreparationInstalled {
		t.Fatalf("prepare activation authorization %q: disposition=%v err=%v",
			authorizationID, disposition, err)
	}
	return acquired
}

func vnextReaderActivationStoreTestRequest(
	acquired vnextReaderAcquiredAuthorization,
	activationRequestID string,
) vnextReaderActivationRequestIdentity {
	return vnextReaderActivationRequestIdentity{
		Acquired:            acquired,
		ActivationRequestID: activationRequestID,
	}
}

func vnextReaderActivationStoreTestActive(
	request vnextReaderActivationRequestIdentity,
) vnextReaderAcquiredAuthorization {
	active := cloneVNextReaderAcquiredAuthorization(request.Acquired)
	active.CatalogState = vnextReaderCatalogAuthorizationActive
	active.LastMutationID = request.ActivationRequestID
	return active
}

func TestVNextReaderActivationStoreProposalExactReplayAndIsolation(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 2)
	acquired := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-auth-a")
	request := vnextReaderActivationStoreTestRequest(acquired, "activation-request-a")
	wantRequest := cloneVNextReaderActivationRequestIdentity(request)

	intent, disposition, err := store.Propose(request, 150)
	if err != nil || disposition != vnextReaderActivationProposalInstalled {
		t.Fatalf("first proposal: intent=%#v disposition=%v err=%v",
			intent, disposition, err)
	}
	if intent.State != vnextReaderActivationPending || intent.MappingGeneration != 1 ||
		intent.MappingID != vnextReaderActivationMappingID(
			acquired.Authorization.CxldProcessIncarnationID, 1) ||
		intent.ActivatedAtEpochMillis != 150 ||
		!equalVNextReaderActivationRequestIdentity(intent.Request, wantRequest) {
		t.Fatalf("first proposal lost exact identity: %#v", intent)
	}

	request.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
		"mutated-input"
	intent.Request.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
		"mutated-result"
	intent.MappingID = "mutated-result"
	replay, disposition, err := store.Propose(wantRequest, 250)
	if err != nil || disposition != vnextReaderActivationProposalExactReplay {
		t.Fatalf("proposal replay: intent=%#v disposition=%v err=%v",
			replay, disposition, err)
	}
	if replay.State != vnextReaderActivationPending || replay.MappingGeneration != 1 ||
		replay.MappingID != vnextReaderActivationMappingID(
			acquired.Authorization.CxldProcessIncarnationID, 1) ||
		!equalVNextReaderActivationRequestIdentity(replay.Request, wantRequest) {
		t.Fatalf("proposal replay changed retained intent: %#v", replay)
	}
	if store.lastMappingGeneration != 1 || len(store.byRequestID) != 1 {
		t.Fatalf("proposal replay consumed state: generation=%d entries=%d",
			store.lastMappingGeneration, len(store.byRequestID))
	}
}

func TestVNextReaderActivationStoreRequiresExactPrepared(t *testing.T) {
	_, store := vnextReaderActivationStoreTestFixture(t, 2)
	acquired := vnextReaderAuthorizationStoreTestAcquired("activation-unprepared")
	request := vnextReaderActivationStoreTestRequest(acquired, "activation-request-unprepared")
	if _, _, err := store.Propose(request, 150); err == nil {
		t.Fatal("proposal without exact PREPARED authorization succeeded")
	}
	if len(store.byRequestID) != 0 || store.lastMappingGeneration != 0 ||
		store.retainedBytes != 0 {
		t.Fatalf("rejected unprepared proposal changed store: entries=%d generation=%d retained=%d",
			len(store.byRequestID), store.lastMappingGeneration, store.retainedBytes)
	}
}

func TestVNextReaderActivationStoreRejectsNegativeProposalTimeBeforeMutation(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 1)
	acquired := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-negative-time")
	request := vnextReaderActivationStoreTestRequest(
		acquired, "activation-negative-time-request")
	if _, _, err := store.Propose(request, -1); err == nil {
		t.Fatal("negative activation proposal time was accepted")
	}
	if len(store.byRequestID) != 0 || store.lastMappingGeneration != 0 ||
		store.retainedBytes != 0 {
		t.Fatalf("negative proposal time changed store: entries=%d generation=%d retained=%d",
			len(store.byRequestID), store.lastMappingGeneration, store.retainedBytes)
	}
}

func TestVNextReaderActivationStoreStatusMissPermanentlyFencesDelayedProposal(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 2)
	acquired := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-status-miss")
	request := vnextReaderActivationStoreTestRequest(acquired, "activation-status-miss-request")

	status, err := store.Status(request)
	if err != nil || status.Disposition != vnextReaderActivationStatusNotFoundFenced ||
		status.Intent != nil ||
		!equalVNextReaderActivationRequestIdentity(status.Request, request) {
		t.Fatalf("first status miss: status=%#v err=%v", status, err)
	}
	replay, err := store.Status(request)
	if err != nil || replay.Disposition != vnextReaderActivationStatusNotFoundFenced ||
		replay.Intent != nil {
		t.Fatalf("status tombstone replay: status=%#v err=%v", replay, err)
	}
	if _, _, err := store.Propose(request, 150); !errors.Is(
		err, errVNextReaderActivationNotFoundFenced) {
		t.Fatalf("delayed proposal error=%v, want permanent NOT_FOUND fence", err)
	}
	if store.lastMappingGeneration != 0 || len(store.byRequestID) != 1 {
		t.Fatalf("status tombstone allocated mapping state: generation=%d entries=%d",
			store.lastMappingGeneration, len(store.byRequestID))
	}
}

func TestVNextReaderActivationStoreCommitOrdersAndExactReplay(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 2)
	acquired := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-commit")
	request := vnextReaderActivationStoreTestRequest(acquired, "activation-commit-request")

	missingEvidence := vnextReaderActivationIntent{
		Request:                request,
		MappingID:              vnextReaderActivationMappingID(store.localProcess, 1),
		MappingGeneration:      1,
		ActivatedAtEpochMillis: 150,
		State:                  vnextReaderActivationPending,
	}
	if _, _, err := store.Commit(
		vnextReaderActivationStoreTestActive(request), missingEvidence); !errors.Is(
		err, errVNextReaderActivationNotPending) {
		t.Fatalf("commit before proposal error=%v, want not pending", err)
	}

	proposal, _, err := store.Propose(request, 150)
	if err != nil {
		t.Fatalf("proposal before commit: %v", err)
	}
	active := vnextReaderActivationStoreTestActive(request)
	armed, disposition, err := store.Commit(active, proposal)
	if err != nil || disposition != vnextReaderActivationCommitArmed ||
		armed.State != vnextReaderActivationActiveArmed ||
		!equalVNextReaderActivationIntentIgnoringState(armed, proposal) {
		t.Fatalf("first commit: armed=%#v disposition=%v err=%v",
			armed, disposition, err)
	}
	status, err := store.Status(request)
	if err != nil || status.Disposition != vnextReaderActivationStatusPresent ||
		status.Intent == nil || status.Intent.State != vnextReaderActivationActiveArmed {
		t.Fatalf("armed status: status=%#v err=%v", status, err)
	}
	postArmProposal, proposalDisposition, err := store.Propose(request, 250)
	if err != nil ||
		proposalDisposition != vnextReaderActivationProposalExactReplay ||
		postArmProposal.State != vnextReaderActivationPending ||
		!equalVNextReaderActivationIntentIgnoringState(postArmProposal, proposal) {
		t.Fatalf("post-arm proposal replay: intent=%#v disposition=%v err=%v",
			postArmProposal, proposalDisposition, err)
	}

	armed.MappingID = "mutated-output"
	replay, disposition, err := store.Commit(active, proposal)
	if err != nil || disposition != vnextReaderActivationCommitExactReplay ||
		replay.State != vnextReaderActivationActiveArmed ||
		replay.MappingID != proposal.MappingID {
		t.Fatalf("commit replay: armed=%#v disposition=%v err=%v",
			replay, disposition, err)
	}
}

func TestVNextReaderActivationStoreRejectsCommitSubstitutions(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 2)
	acquired := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-substitution")
	request := vnextReaderActivationStoreTestRequest(acquired, "activation-substitution-request")
	proposal, _, err := store.Propose(request, 150)
	if err != nil {
		t.Fatalf("seed proposal: %v", err)
	}
	active := vnextReaderActivationStoreTestActive(request)

	for name, mutate := range map[string]func(*vnextReaderAcquiredAuthorization){
		"state": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.CatalogState = vnextReaderCatalogAuthorizationAcquired
		},
		"last mutation": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.LastMutationID = "different-activation-request"
		},
		"checkpoint": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.CheckpointID = "different-checkpoint"
		},
		"process": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.CxldProcessIncarnationID[0] ^= 0xff
		},
		"birth revision": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.ReaderInitialRegistrationCatalogRevision++
		},
		"root": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.RootVersion++
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneVNextReaderAcquiredAuthorization(active)
			mutate(&candidate)
			if _, _, err := store.Commit(candidate, proposal); err == nil {
				t.Fatalf("commit accepted substituted %s", name)
			}
		})
	}
	for name, mutate := range map[string]func(*vnextReaderActivationIntent){
		"activation request": func(candidate *vnextReaderActivationIntent) {
			candidate.Request.ActivationRequestID = "different-request"
		},
		"mapping ID": func(candidate *vnextReaderActivationIntent) {
			candidate.MappingID = "different-mapping"
		},
		"mapping generation": func(candidate *vnextReaderActivationIntent) {
			candidate.MappingGeneration++
		},
		"activation time": func(candidate *vnextReaderActivationIntent) {
			candidate.ActivatedAtEpochMillis++
		},
		"evidence state": func(candidate *vnextReaderActivationIntent) {
			candidate.State = vnextReaderActivationActiveArmed
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneVNextReaderActivationIntent(proposal)
			mutate(&candidate)
			if _, _, err := store.Commit(active, candidate); err == nil {
				t.Fatalf("commit accepted substituted %s", name)
			}
		})
	}
	status, err := store.Status(request)
	if err != nil || status.Intent == nil || status.Intent.State != vnextReaderActivationPending {
		t.Fatalf("rejected commit substitution changed PENDING: status=%#v err=%v", status, err)
	}
}

func TestVNextReaderActivationStoreConflictsAndIncarnationMismatch(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 3)
	acquired := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-conflict")
	request := vnextReaderActivationStoreTestRequest(acquired, "activation-conflict-request")
	if _, _, err := store.Propose(request, 150); err != nil {
		t.Fatalf("seed proposal: %v", err)
	}

	conflict := cloneVNextReaderActivationRequestIdentity(request)
	conflict.Acquired.Authorization.TargetContainerID = "different-target"
	if _, err := store.Status(conflict); !errors.Is(err, errVNextReaderActivationConflict) {
		t.Fatalf("conflicting status error=%v, want conflict", err)
	}
	if _, _, err := store.Propose(conflict, 150); !errors.Is(
		err, errVNextReaderAuthorizationIdentityMismatch) &&
		!errors.Is(err, errVNextReaderActivationConflict) {
		// PREPARED exact lookup rejects this before the activation-store conflict.
		t.Fatalf("conflicting proposal error=%v", err)
	}

	wrongProcess := cloneVNextReaderActivationRequestIdentity(request)
	wrongProcess.Acquired.Authorization.CxldProcessIncarnationID[0] ^= 0xff
	if _, err := store.Status(wrongProcess); !errors.Is(
		err, errVNextReaderActivationIncarnationMismatch) {
		t.Fatalf("wrong-process status error=%v, want incarnation mismatch", err)
	}
	if _, _, err := store.Propose(wrongProcess, 150); !errors.Is(
		err, errVNextReaderActivationIncarnationMismatch) {
		t.Fatalf("wrong-process proposal error=%v, want incarnation mismatch", err)
	}
	if len(store.byRequestID) != 1 || store.lastMappingGeneration != 1 {
		t.Fatalf("conflicts changed activation store: entries=%d generation=%d",
			len(store.byRequestID), store.lastMappingGeneration)
	}
}

func TestVNextReaderActivationStoreMappingGenerationNeverReused(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 5)
	first := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-generation-a")
	second := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-generation-b")
	third := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-generation-c")

	firstIntent, _, err := store.Propose(
		vnextReaderActivationStoreTestRequest(first, "activation-generation-request-a"), 150)
	if err != nil {
		t.Fatalf("first generation: %v", err)
	}
	if _, err := store.Status(vnextReaderActivationStoreTestRequest(
		second, "activation-generation-status-fence")); err != nil {
		t.Fatalf("status fence between generations: %v", err)
	}
	secondIntent, _, err := store.Propose(
		vnextReaderActivationStoreTestRequest(second, "activation-generation-request-b"), 150)
	if err != nil {
		t.Fatalf("second generation: %v", err)
	}
	thirdIntent, _, err := store.Propose(
		vnextReaderActivationStoreTestRequest(third, "activation-generation-request-c"), 150)
	if err != nil {
		t.Fatalf("third generation: %v", err)
	}
	if firstIntent.MappingGeneration != 1 || secondIntent.MappingGeneration != 2 ||
		thirdIntent.MappingGeneration != 3 ||
		firstIntent.MappingID == secondIntent.MappingID ||
		secondIntent.MappingID == thirdIntent.MappingID {
		t.Fatalf("mapping generation sequence = %d/%d/%d IDs=%q/%q/%q",
			firstIntent.MappingGeneration, secondIntent.MappingGeneration,
			thirdIntent.MappingGeneration, firstIntent.MappingID,
			secondIntent.MappingID, thirdIntent.MappingID)
	}

	store.lastMappingGeneration = cxlcheckpoint.MaxSignedLong
	fourth := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-generation-d")
	if _, _, err := store.Propose(vnextReaderActivationStoreTestRequest(
		fourth, "activation-generation-request-d"), 150); !errors.Is(
		err, errVNextReaderActivationMappingGenerationExhausted) {
		t.Fatalf("generation overflow error=%v, want exhausted", err)
	}
	if len(store.byRequestID) != 4 {
		t.Fatalf("generation overflow installed entry: entries=%d", len(store.byRequestID))
	}
}

func TestVNextReaderActivationStoreEntryAndRetainedByteCapacity(t *testing.T) {
	prepared, store := vnextReaderActivationStoreTestFixture(t, 1)
	first := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-capacity-a")
	firstRequest := vnextReaderActivationStoreTestRequest(first, "activation-capacity-request-a")
	if _, _, err := store.Propose(firstRequest, 150); err != nil {
		t.Fatalf("first capacity proposal: %v", err)
	}
	second := vnextReaderAuthorizationStoreTestAcquired("activation-capacity-b")
	secondRequest := vnextReaderActivationStoreTestRequest(second, "activation-capacity-request-b")
	if _, err := store.Status(secondRequest); !errors.Is(
		err, errVNextReaderActivationStoreFull) {
		t.Fatalf("entry capacity error=%v, want full", err)
	}
	if len(store.byRequestID) != 1 || store.lastMappingGeneration != 1 {
		t.Fatalf("entry capacity failure changed store: entries=%d generation=%d",
			len(store.byRequestID), store.lastMappingGeneration)
	}

	preparedBytes, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("new byte PREPARED store: %v", err)
	}
	byteAcquired := vnextReaderActivationStoreTestPrepare(
		t, preparedBytes, "activation-byte-budget")
	byteRequest := vnextReaderActivationStoreTestRequest(
		byteAcquired, "activation-byte-budget-request")
	charge, err := vnextReaderActivationRetainedCharge(
		byteRequest, vnextReaderActivationMappingID(
			byteAcquired.Authorization.CxldProcessIncarnationID, 1))
	if err != nil || charge <= 1 {
		t.Fatalf("retained charge=%d err=%v", charge, err)
	}
	acquiredCharge, err := vnextReaderAuthorizationRetainedCharge(byteAcquired)
	if err != nil {
		t.Fatalf("base ACQUIRED retained charge: %v", err)
	}
	wantCharge := acquiredCharge + vnextReaderActivationStoreFixedChargeBytes +
		2*uint64(len(byteRequest.ActivationRequestID)) +
		uint64(len(vnextReaderActivationMappingID(
			byteAcquired.Authorization.CxldProcessIncarnationID, 1)))
	if charge != wantCharge {
		t.Fatalf("activation retained charge=%d, want explicit two-ID charge %d",
			charge, wantCharge)
	}
	byteStore, err := newVNextReaderActivationStore(vnextReaderActivationStoreConfig{
		MaxEntries:       2,
		MaxRetainedBytes: charge - 1,
	}, "executor-a", "reader-cxld-a",
		byteAcquired.Authorization.CxldProcessIncarnationID, preparedBytes)
	if err != nil {
		t.Fatalf("new byte activation store: %v", err)
	}
	if _, _, err := byteStore.Propose(byteRequest, 150); !errors.Is(
		err, errVNextReaderActivationStoreRetainedBytesFull) {
		t.Fatalf("retained-byte proposal error=%v, want byte full", err)
	}
	if len(byteStore.byRequestID) != 0 || byteStore.lastMappingGeneration != 0 ||
		byteStore.retainedBytes != 0 {
		t.Fatalf("retained-byte failure changed store: entries=%d generation=%d retained=%d",
			len(byteStore.byRequestID), byteStore.lastMappingGeneration,
			byteStore.retainedBytes)
	}
}

func TestVNextReaderActivationStoreConcurrentProposalAndGeneration(t *testing.T) {
	const callers = 64
	prepared, store := vnextReaderActivationStoreTestFixture(t, callers)
	shared := vnextReaderActivationStoreTestPrepare(t, prepared, "activation-concurrent-shared")
	sharedRequest := vnextReaderActivationStoreTestRequest(
		shared, "activation-concurrent-shared-request")
	var installed int64
	var replay int64
	var failures int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			intent, disposition, err := store.Propose(sharedRequest, 150)
			if err != nil || intent.MappingGeneration != 1 {
				atomic.AddInt64(&failures, 1)
				return
			}
			switch disposition {
			case vnextReaderActivationProposalInstalled:
				atomic.AddInt64(&installed, 1)
			case vnextReaderActivationProposalExactReplay:
				atomic.AddInt64(&replay, 1)
			default:
				atomic.AddInt64(&failures, 1)
			}
		}()
	}
	wait.Wait()
	if installed != 1 || replay != callers-1 || failures != 0 {
		t.Fatalf("concurrent replay installed=%d replay=%d failures=%d",
			installed, replay, failures)
	}

	// Use a fresh store because the shared replay already consumed one entry.
	prepared, store = vnextReaderActivationStoreTestFixture(t, callers)
	requests := make([]vnextReaderActivationRequestIdentity, callers)
	for index := range requests {
		acquired := vnextReaderActivationStoreTestPrepare(
			t, prepared, fmt.Sprintf("activation-concurrent-%03d", index))
		requests[index] = vnextReaderActivationStoreTestRequest(
			acquired, fmt.Sprintf("activation-concurrent-request-%03d", index))
	}
	generations := make(chan uint64, callers)
	failures = 0
	wait.Add(callers)
	for index := range requests {
		index := index
		go func() {
			defer wait.Done()
			intent, disposition, err := store.Propose(requests[index], 150)
			if err != nil || disposition != vnextReaderActivationProposalInstalled {
				atomic.AddInt64(&failures, 1)
				return
			}
			generations <- intent.MappingGeneration
		}()
	}
	wait.Wait()
	close(generations)
	seen := make(map[uint64]struct{}, callers)
	for generation := range generations {
		seen[generation] = struct{}{}
	}
	if failures != 0 || len(seen) != callers ||
		store.lastMappingGeneration != callers {
		t.Fatalf("concurrent unique proposals failures=%d unique=%d last=%d",
			failures, len(seen), store.lastMappingGeneration)
	}
	for generation := uint64(1); generation <= callers; generation++ {
		if _, ok := seen[generation]; !ok {
			t.Fatalf("concurrent proposals skipped or reused generation %d", generation)
		}
	}
}

func TestVNextReaderActivationStoreConcurrentStatusProposalOrdering(t *testing.T) {
	for iteration := 0; iteration < 64; iteration++ {
		prepared, store := vnextReaderActivationStoreTestFixture(t, 1)
		acquired := vnextReaderActivationStoreTestPrepare(
			t, prepared, fmt.Sprintf("activation-order-%03d", iteration))
		request := vnextReaderActivationStoreTestRequest(
			acquired, fmt.Sprintf("activation-order-request-%03d", iteration))
		start := make(chan struct{})
		var proposalErr error
		var status vnextReaderActivationStatusResult
		var statusErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			_, _, proposalErr = store.Propose(request, 150)
		}()
		go func() {
			defer wait.Done()
			<-start
			status, statusErr = store.Status(request)
		}()
		close(start)
		wait.Wait()
		if statusErr != nil {
			t.Fatalf("iteration %d status error: %v", iteration, statusErr)
		}
		switch status.Disposition {
		case vnextReaderActivationStatusPresent:
			if proposalErr != nil || status.Intent == nil ||
				status.Intent.State != vnextReaderActivationPending {
				t.Fatalf("iteration %d present ordering: status=%#v proposalErr=%v",
					iteration, status, proposalErr)
			}
		case vnextReaderActivationStatusNotFoundFenced:
			if !errors.Is(proposalErr, errVNextReaderActivationNotFoundFenced) ||
				status.Intent != nil || store.lastMappingGeneration != 0 {
				t.Fatalf("iteration %d fenced ordering: status=%#v proposalErr=%v generation=%d",
					iteration, status, proposalErr, store.lastMappingGeneration)
			}
		default:
			t.Fatalf("iteration %d invalid status disposition %v", iteration, status.Disposition)
		}
		if len(store.byRequestID) != 1 {
			t.Fatalf("iteration %d installed %d decisions", iteration, len(store.byRequestID))
		}
	}
}
