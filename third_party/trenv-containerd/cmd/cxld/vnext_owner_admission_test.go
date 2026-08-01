package main

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func vnextOwnerAdmissionTestRequest(
	id string,
	from vnextOwnerAdmissionState,
	target vnextOwnerAdmissionState,
	expectedSequence uint64,
) vnextOwnerAdmissionTransitionRequest {
	return vnextOwnerAdmissionTransitionRequest{
		RequestID:        "owner-admission-" + id,
		OwnerID:          "owner-0",
		OwnerEpoch:       7,
		From:             from,
		Target:           target,
		ExpectedSequence: expectedSequence,
	}
}

func TestVNextOwnerAdmissionHeadPairsAreCanonical(t *testing.T) {
	for _, test := range []struct {
		name     string
		state    vnextOwnerAdmissionState
		sequence uint64
		valid    bool
	}{
		{name: "active-1", state: vnextOwnerAdmissionActive, sequence: 1, valid: true},
		{name: "read-only-2", state: vnextOwnerAdmissionReadOnly, sequence: 2, valid: true},
		{name: "direct-fenced-2", state: vnextOwnerAdmissionFenced, sequence: 2, valid: true},
		{name: "read-only-fenced-3", state: vnextOwnerAdmissionFenced, sequence: 3, valid: true},
		{name: "active-2", state: vnextOwnerAdmissionActive, sequence: 2},
		{name: "read-only-1", state: vnextOwnerAdmissionReadOnly, sequence: 1},
		{name: "read-only-3", state: vnextOwnerAdmissionReadOnly, sequence: 3},
		{name: "fenced-1", state: vnextOwnerAdmissionFenced, sequence: 1},
		{name: "fenced-4", state: vnextOwnerAdmissionFenced, sequence: 4},
		{name: "unknown", state: 0, sequence: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateVNextOwnerAdmissionHeadPair(test.state, test.sequence)
			if test.valid && err != nil {
				t.Fatalf("canonical pair was rejected: %v", err)
			}
			if !test.valid && !errors.Is(err, errVNextCorrupt) {
				t.Fatalf("impossible pair returned %v", err)
			}
		})
	}
}

func TestVNextOwnerAdmissionTransitionsPersistReplayAndNeverReopen(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "admission-persist", Size: 256 << 10,
	}})
	initial, err := fixture.group.admissionStatus("owner-0", 7)
	if err != nil {
		t.Fatalf("read initial admission status: %v", err)
	}
	if initial.State != vnextOwnerAdmissionActive || initial.AdmissionSequence != 1 ||
		initial.SnapshotSequence == 0 || initial.HasLastTransition ||
		initial.LastTransition != (vnextOwnerAdmissionTransitionRecord{}) {
		t.Fatalf("fresh Owner admission is not ACTIVE/1: %#v", initial)
	}

	readOnly := vnextOwnerAdmissionTestRequest(
		"read-only", vnextOwnerAdmissionActive, vnextOwnerAdmissionReadOnly, 1)
	first, err := fixture.group.setAdmission(readOnly)
	if err != nil {
		t.Fatalf("persist READ_ONLY admission: %v", err)
	}
	if first.Replayed || first.Record.From != vnextOwnerAdmissionActive ||
		first.Record.Target != vnextOwnerAdmissionReadOnly ||
		first.Record.ExpectedSequence != 1 || first.Record.ResultSequence != 2 ||
		first.Record.RequestDigest != vnextOwnerAdmissionRequestDigest(readOnly) {
		t.Fatalf("unexpected READ_ONLY transition proof: %#v", first)
	}
	afterReadOnlySequence := fixture.group.journal.SnapshotSequence
	replayed, err := fixture.group.setAdmission(readOnly)
	if err != nil {
		t.Fatalf("replay exact READ_ONLY admission: %v", err)
	}
	if !replayed.Replayed || replayed.Record != first.Record ||
		fixture.group.journal.SnapshotSequence != afterReadOnlySequence {
		t.Fatalf("exact admission replay changed its proof or journal: %#v", replayed)
	}

	conflict := readOnly
	conflict.Target = vnextOwnerAdmissionFenced
	_, err = fixture.group.setAdmission(conflict)
	var requestConflict *vnextOwnerAdmissionRequestConflictError
	if !errors.Is(err, errVNextOwnerAdmissionRequestConflict) ||
		!errors.As(err, &requestConflict) || requestConflict.RequestID != conflict.RequestID {
		t.Fatalf("same request ID with a different digest returned %v", err)
	}
	stale := vnextOwnerAdmissionTestRequest(
		"stale", vnextOwnerAdmissionActive, vnextOwnerAdmissionFenced, 1)
	_, err = fixture.group.setAdmission(stale)
	var sequenceConflict *vnextOwnerAdmissionSequenceConflictError
	if !errors.Is(err, errVNextOwnerAdmissionSequenceConflict) ||
		!errors.As(err, &sequenceConflict) ||
		sequenceConflict.CurrentState != vnextOwnerAdmissionReadOnly ||
		sequenceConflict.CurrentSequence != 2 ||
		sequenceConflict.RequestedFrom != vnextOwnerAdmissionActive ||
		sequenceConflict.ExpectedSequence != 1 {
		t.Fatalf("stale admission head returned %v", err)
	}
	if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
		"reopen", vnextOwnerAdmissionReadOnly, vnextOwnerAdmissionActive, 2)); err == nil ||
		!strings.Contains(err.Error(), "not monotonic") {
		t.Fatalf("same-epoch admission reopen returned %v", err)
	}

	fenced := vnextOwnerAdmissionTestRequest(
		"fenced", vnextOwnerAdmissionReadOnly, vnextOwnerAdmissionFenced, 2)
	second, err := fixture.group.setAdmission(fenced)
	if err != nil {
		t.Fatalf("persist FENCED admission: %v", err)
	}
	if second.Record.ResultSequence != 3 || len(fixture.group.journal.AdmissionTransitions) != 2 {
		t.Fatalf("unexpected FENCED transition proof/history: %#v / %#v",
			second, fixture.group.journal.AdmissionTransitions)
	}
	// An exact old transition proof remains recoverable after the head advances.
	replayedAfterFence, err := fixture.group.setAdmission(readOnly)
	if err != nil || !replayedAfterFence.Replayed || replayedAfterFence.Record != first.Record {
		t.Fatalf("replay READ_ONLY proof after FENCED: %#v / %v", replayedAfterFence, err)
	}

	expectedTransitions := append(
		[]vnextOwnerAdmissionTransitionRecord(nil),
		fixture.group.journal.AdmissionTransitions...)
	reopened := fixture.reopen(t)
	restarted, err := reopened.admissionStatus("owner-0", 7)
	if err != nil {
		t.Fatalf("read restarted admission status: %v", err)
	}
	if restarted.State != vnextOwnerAdmissionFenced || restarted.AdmissionSequence != 3 ||
		!restarted.HasLastTransition || restarted.LastTransition != second.Record ||
		len(reopened.journal.AdmissionTransitions) != 2 ||
		!reflect.DeepEqual(reopened.journal.AdmissionTransitions, expectedTransitions) {
		t.Fatalf("admission history did not survive restart: %#v / %#v",
			restarted, reopened.journal.AdmissionTransitions)
	}
}

func TestVNextOwnerReadOnlyRejectsOnlyUnseenReserveAndDrainsExistingGrant(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "admission-read-only", Size: 256 << 10,
	}})
	request := vnextOwnerMemoryRequest("read-only-existing", 2, 1)
	grant, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("reserve before READ_ONLY: %v", err)
	}
	if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
		"close-for-drain", vnextOwnerAdmissionActive, vnextOwnerAdmissionReadOnly, 1)); err != nil {
		t.Fatalf("set READ_ONLY: %v", err)
	}

	beforeReplaySequence := fixture.group.journal.SnapshotSequence
	replayed, err := fixture.group.reserve(request)
	if err != nil {
		t.Fatalf("replay exact durable Reserve after READ_ONLY: %v", err)
	}
	if replayed.AllocationRecordID != grant.AllocationRecordID ||
		!reflect.DeepEqual(replayed.Extents, grant.Extents) ||
		len(replayed.fragmentGrants) != 0 ||
		fixture.group.journal.SnapshotSequence != beforeReplaySequence {
		t.Fatalf("closed admission replay was not geometry-only and immutable: %#v", replayed)
	}

	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeTransactions := len(fixture.group.journal.Transactions)
	beforeFree := fixture.devices[0].allocator.freePages()
	unseen := vnextOwnerMemoryRequest("read-only-unseen", 1, 1)
	_, err = fixture.group.reserve(unseen)
	var closed *vnextOwnerAdmissionClosedError
	if !errors.As(err, &closed) || closed.State != vnextOwnerAdmissionReadOnly ||
		closed.Sequence != 2 {
		t.Fatalf("unseen READ_ONLY reserve returned %T %v", err, err)
	}
	if fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		len(fixture.group.journal.Transactions) != beforeTransactions ||
		fixture.group.journal.SnapshotSequence != beforeReplaySequence ||
		fixture.devices[0].allocator.freePages() != beforeFree {
		t.Fatal("READ_ONLY rejection mutated journal or allocator state")
	}

	// The original token-bearing grant was issued before close and may drain.
	writeAllVNextOwnerPages(t, fixture.group, grant, 2)
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("commit existing grant under READ_ONLY: %v", err)
	}
}

func TestVNextOwnerReserveAdmissionLinearizationOrders(t *testing.T) {
	t.Run("close-first", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "admission-order-close-first", Size: 256 << 10,
		}})
		if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
			"order-close-first",
			vnextOwnerAdmissionActive,
			vnextOwnerAdmissionReadOnly,
			1)); err != nil {
			t.Fatal(err)
		}
		beforeSequence := fixture.group.journal.SnapshotSequence
		beforeHighWater := fixture.group.journal.NextAllocationRecordID
		beforeTransactions := len(fixture.group.journal.Transactions)
		beforeFree := fixture.devices[0].allocator.freePages()
		request := vnextOwnerMemoryRequest("order-close-first", 1, 1)
		_, err := fixture.group.reserve(request)
		var closed *vnextOwnerAdmissionClosedError
		if !errors.As(err, &closed) || closed.State != vnextOwnerAdmissionReadOnly ||
			closed.Sequence != 2 {
			t.Fatalf("close-first Reserve returned %T %v", err, err)
		}
		if fixture.group.journal.SnapshotSequence != beforeSequence ||
			fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
			len(fixture.group.journal.Transactions) != beforeTransactions ||
			fixture.devices[0].allocator.freePages() != beforeFree {
			t.Fatal("close-first Reserve mutated journal or allocator state")
		}
		if _, exists := fixture.group.journal.RequestIndex[request.RequestID]; exists {
			t.Fatal("close-first Reserve created a request-index entry")
		}
	})

	t.Run("reserve-first", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "admission-order-reserve-first", Size: 256 << 10,
		}})
		request := vnextOwnerMemoryRequest("order-reserve-first", 2, 1)
		preparing := make(chan vnextOwnerTransactionState, 1)
		releaseReserve := make(chan struct{})
		hookBlocked := false
		fixture.group.faultHook = func(stage, _ string) error {
			if stage == vnextOwnerFailAfterPrepare && !hookBlocked {
				hookBlocked = true
				allocationID := fixture.group.journal.RequestIndex[request.RequestID]
				preparing <- fixture.group.journal.Transactions[allocationID].State
				<-releaseReserve
			}
			return nil
		}
		type reserveResult struct {
			grant vnextOwnerWriteGrant
			err   error
		}
		reserveDone := make(chan reserveResult, 1)
		go func() {
			grant, err := fixture.group.reserve(request)
			reserveDone <- reserveResult{grant: grant, err: err}
		}()
		stateAtBarrier := <-preparing

		type transitionResult struct {
			result vnextOwnerAdmissionTransitionResult
			err    error
		}
		transitionStarted := make(chan struct{})
		transitionDone := make(chan transitionResult, 1)
		go func() {
			close(transitionStarted)
			result, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
				"order-after-reserve",
				vnextOwnerAdmissionActive,
				vnextOwnerAdmissionReadOnly,
				1))
			transitionDone <- transitionResult{result: result, err: err}
		}()
		<-transitionStarted
		transitionCrossedLock := false
		var transitioned transitionResult
		select {
		case transitioned = <-transitionDone:
			transitionCrossedLock = true
		default:
		}
		close(releaseReserve)
		reserved := <-reserveDone
		if !transitionCrossedLock {
			transitioned = <-transitionDone
		}

		if stateAtBarrier != vnextOwnerPreparing {
			t.Fatalf("reserve barrier state=%d, want PREPARING", stateAtBarrier)
		}
		if transitionCrossedLock {
			t.Fatal("admission transition crossed the Owner lock during Reserve")
		}
		if reserved.err != nil {
			t.Fatalf("reserve-first Reserve failed: %v", reserved.err)
		}
		if transitioned.err != nil || transitioned.result.Record.Target != vnextOwnerAdmissionReadOnly ||
			transitioned.result.Record.ResultSequence != 2 {
			t.Fatalf("reserve-first transition: %#v / %v", transitioned.result, transitioned.err)
		}
		transaction := fixture.group.journal.Transactions[reserved.grant.AllocationRecordID]
		if transaction == nil || transaction.State != vnextOwnerGranted ||
			fixture.group.journal.AdmissionState != vnextOwnerAdmissionReadOnly {
			t.Fatalf("reserve-first durable order is wrong: transaction=%#v admission=%s",
				transaction, fixture.group.journal.AdmissionState)
		}
		replayed, err := fixture.group.reserve(request)
		if err != nil || replayed.AllocationRecordID != reserved.grant.AllocationRecordID ||
			!reflect.DeepEqual(replayed.Extents, reserved.grant.Extents) ||
			len(replayed.fragmentGrants) != 0 {
			t.Fatalf("reserve-first geometry replay: %#v / %v", replayed, err)
		}
		writeAllVNextOwnerPages(t, fixture.group, reserved.grant, 2)
		if err := fixture.group.commit(reserved.grant); err != nil {
			t.Fatalf("READ_ONLY drain after reserve-first ordering: %v", err)
		}
	})
}

func TestVNextOwnerClosedAdmissionReplaysDurableNoSpaceBeforeGate(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "admission-no-space-replay", Size: 256 << 10,
	}})
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerMemoryRequest("closed-no-space", capacity+1, 1)
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("create durable no-space outcome: %v", err)
	}
	allocationID := fixture.group.journal.RequestIndex[request.RequestID]
	if allocationID == 0 ||
		fixture.group.journal.Transactions[allocationID].State != vnextOwnerRejectedNoSpace {
		t.Fatal("no-space request lacks a durable outcome")
	}
	if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
		"close-after-no-space",
		vnextOwnerAdmissionActive,
		vnextOwnerAdmissionReadOnly,
		1)); err != nil {
		t.Fatal(err)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	beforeTransactions := len(fixture.group.journal.Transactions)
	beforeFree := fixture.devices[0].allocator.freePages()
	if _, err := fixture.group.reserve(request); !errors.Is(err, errVNextNoSpace) {
		t.Fatalf("closed exact no-space replay returned %v", err)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		len(fixture.group.journal.Transactions) != beforeTransactions ||
		fixture.devices[0].allocator.freePages() != beforeFree ||
		fixture.group.journal.RequestIndex[request.RequestID] != allocationID {
		t.Fatal("closed exact no-space replay mutated its durable outcome")
	}
	newRequest := vnextOwnerMemoryRequest("closed-no-space-new", 1, 1)
	_, err := fixture.group.reserve(newRequest)
	var closed *vnextOwnerAdmissionClosedError
	if !errors.As(err, &closed) || closed.State != vnextOwnerAdmissionReadOnly ||
		closed.Sequence != 2 {
		t.Fatalf("new request after durable no-space returned %T %v", err, err)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater ||
		len(fixture.group.journal.Transactions) != beforeTransactions ||
		fixture.devices[0].allocator.freePages() != beforeFree {
		t.Fatal("closed new request mutated state after no-space replay")
	}
}

func TestVNextOwnerFencedBlocksProducerMutationAbortAndReclaimWithoutReuse(t *testing.T) {
	t.Run("granted", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "admission-fenced-granted", Size: 256 << 10,
		}})
		request := vnextOwnerMemoryRequest("fenced-granted", 2, 1)
		grant, err := fixture.group.reserve(request)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
			"fence-granted", vnextOwnerAdmissionActive, vnextOwnerAdmissionFenced, 1)); err != nil {
			t.Fatal(err)
		}
		beforeFree := fixture.devices[0].allocator.freePages()
		page := bytes.Repeat([]byte{1}, int(vnextContentPageSize))
		for name, operation := range map[string]func() error{
			"write":  func() error { return fixture.group.writePage(grant, 0, page) },
			"commit": func() error { return fixture.group.commit(grant) },
			"abort":  func() error { return fixture.group.abort(grant) },
		} {
			err := operation()
			if !errors.Is(err, errVNextOwnerAdmissionClosed) {
				t.Fatalf("FENCED %s returned %v", name, err)
			}
		}
		if fixture.devices[0].allocator.freePages() != beforeFree ||
			fixture.group.journal.Transactions[grant.AllocationRecordID].State != vnextOwnerGranted {
			t.Fatal("FENCED producer/abort path freed or changed the allocation")
		}
		if _, err := fixture.group.inventory("owner-0", 7); err != nil {
			t.Fatalf("FENCED inventory must remain readable: %v", err)
		}
		if _, err := fixture.group.admissionStatus("owner-0", 7); err != nil {
			t.Fatalf("FENCED admission status must remain readable: %v", err)
		}
	})

	t.Run("committed", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "admission-fenced-committed", Size: 256 << 10,
		}})
		request := vnextOwnerMemoryRequest("fenced-committed", 2, 1)
		grant, err := fixture.group.reserve(request)
		if err != nil {
			t.Fatal(err)
		}
		writeAllVNextOwnerPages(t, fixture.group, grant, 2)
		if err := fixture.group.commit(grant); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
			"fence-committed", vnextOwnerAdmissionActive, vnextOwnerAdmissionFenced, 1)); err != nil {
			t.Fatal(err)
		}
		beforeFree := fixture.devices[0].allocator.freePages()
		if err := fixture.group.reclaimCheckpoint(
			request.CheckpointID, grant.AllocationRecordID); !errors.Is(err, errVNextOwnerAdmissionClosed) {
			t.Fatalf("FENCED reclaim returned %v", err)
		}
		if fixture.devices[0].allocator.freePages() != beforeFree ||
			fixture.group.journal.Transactions[grant.AllocationRecordID].State != vnextOwnerCommitted {
			t.Fatal("FENCED reclaim freed or changed the committed allocation")
		}
	})
}

func TestVNextOwnerFencedAllowsOnlyExactTerminalFreeingReplay(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "admission-fenced-terminal-replay", Size: 256 << 10,
	}})

	terminalAbortRequest := vnextOwnerMemoryRequest("fenced-terminal-abort", 1, 1)
	terminalAbort, err := fixture.group.reserve(terminalAbortRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.group.abort(terminalAbort); err != nil {
		t.Fatalf("complete abort before response loss: %v", err)
	}
	liveAbortRequest := vnextOwnerMemoryRequest("fenced-live-abort", 1, 1)
	liveAbort, err := fixture.group.reserve(liveAbortRequest)
	if err != nil {
		t.Fatal(err)
	}

	terminalReclaimRequest := vnextOwnerMemoryRequest("fenced-terminal-reclaim", 1, 1)
	terminalReclaim, err := fixture.group.reserve(terminalReclaimRequest)
	if err != nil {
		t.Fatal(err)
	}
	writeAllVNextOwnerPages(t, fixture.group, terminalReclaim, 1)
	if err := fixture.group.commit(terminalReclaim); err != nil {
		t.Fatal(err)
	}
	if err := fixture.group.reclaimCheckpoint(
		terminalReclaimRequest.CheckpointID,
		terminalReclaim.AllocationRecordID); err != nil {
		t.Fatalf("complete reclaim before response loss: %v", err)
	}
	liveReclaimRequest := vnextOwnerMemoryRequest("fenced-live-reclaim", 1, 1)
	liveReclaim, err := fixture.group.reserve(liveReclaimRequest)
	if err != nil {
		t.Fatal(err)
	}
	writeAllVNextOwnerPages(t, fixture.group, liveReclaim, 1)
	if err := fixture.group.commit(liveReclaim); err != nil {
		t.Fatal(err)
	}

	if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
		"fence-terminal-replay",
		vnextOwnerAdmissionActive,
		vnextOwnerAdmissionFenced,
		1)); err != nil {
		t.Fatal(err)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeFree := vnextOwnerStatusTestFreePages(fixture.group)
	beforeImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)

	if err := fixture.group.abort(terminalAbort); err != nil {
		t.Fatalf("FENCED ABORTED exact retry failed: %v", err)
	}
	if err := fixture.group.reclaimCheckpoint(
		terminalReclaimRequest.CheckpointID,
		terminalReclaim.AllocationRecordID); err != nil {
		t.Fatalf("FENCED RECLAIMED exact retry failed: %v", err)
	}
	if err := fixture.group.abort(liveAbort); !errors.Is(
		err, errVNextOwnerAdmissionClosed) {
		t.Fatalf("FENCED live abort returned %v", err)
	}
	if err := fixture.group.reclaimCheckpoint(
		liveReclaimRequest.CheckpointID,
		liveReclaim.AllocationRecordID); !errors.Is(
		err, errVNextOwnerAdmissionClosed) {
		t.Fatalf("FENCED live reclaim returned %v", err)
	}

	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		vnextOwnerStatusTestFreePages(fixture.group) != beforeFree {
		t.Fatal("FENCED terminal replay or blocked live free changed Owner counters")
	}
	if afterImage := vnextOwnerStatusTestPersistentImage(t, fixture.group); !bytes.Equal(
		afterImage, beforeImage) {
		t.Fatal("FENCED terminal replay or blocked live free changed durable state")
	}
}

func TestVNextOwnerAdmissionPersistFailurePoisonsBeforeAcknowledgement(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "admission-persist-failure", Size: 256 << 10,
	}})
	beforeSequence := fixture.group.journal.SnapshotSequence
	fixture.group.controlSlotBytes = 1
	_, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
		"persist-failure", vnextOwnerAdmissionActive, vnextOwnerAdmissionReadOnly, 1))
	if err == nil || !errors.Is(err, errVNextMetadataFull) {
		t.Fatalf("admission persistence failure returned %v", err)
	}
	if fixture.group.poisoned == nil ||
		fixture.group.journal.AdmissionState != vnextOwnerAdmissionActive ||
		fixture.group.journal.AdmissionSequence != 1 ||
		fixture.group.journal.SnapshotSequence != beforeSequence ||
		len(fixture.group.journal.AdmissionTransitions) != 0 {
		t.Fatalf("failed admission transition was acknowledged or published: %#v",
			fixture.group.journal)
	}
}

func TestVNextOwnerFencedRestartNeverCompletesFreeingRecovery(t *testing.T) {
	for _, test := range []struct {
		name              string
		state             vnextOwnerTransactionState
		commitBeforeFence bool
	}{
		{name: "aborting", state: vnextOwnerAborting},
		{name: "reclaiming", state: vnextOwnerReclaiming, commitBeforeFence: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
				UUID: "admission-recovery-" + test.name, Size: 256 << 10,
			}})
			request := vnextOwnerMemoryRequest("fenced-recovery-"+test.name, 2, 1)
			grant, err := fixture.group.reserve(request)
			if err != nil {
				t.Fatal(err)
			}
			if test.commitBeforeFence {
				writeAllVNextOwnerPages(t, fixture.group, grant, 2)
				if err := fixture.group.commit(grant); err != nil {
					t.Fatal(err)
				}
			}
			var reclaimRequest vnextOwnerReclaimRequest
			var reclaimAuthority *vnextOwnerSchedulerVerifiedAuthority
			if test.state == vnextOwnerReclaiming {
				reclaimRequest, err = vnextOwnerTestReclaimRequest(
					fixture.group, request.CheckpointID, grant.AllocationRecordID,
					"fenced-recovery-reclaim")
				if err != nil {
					t.Fatal(err)
				}
				reclaimAuthority = vnextOwnerTestVerifiedAuthority(
					vnextOwnerRPCOperationReclaim, reclaimRequest)
			}
			if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
				"recovery-"+test.name,
				vnextOwnerAdmissionActive,
				vnextOwnerAdmissionFenced,
				1)); err != nil {
				t.Fatal(err)
			}
			fixture.group.mu.Lock()
			candidate := fixture.group.journal.clone()
			candidate.Transactions[grant.AllocationRecordID].State = test.state
			if test.state == vnextOwnerAborting {
				candidate.Transactions[grant.AllocationRecordID].AbortOrigin =
					vnextOwnerAbortByRecovery
			} else {
				candidate.Transactions[grant.AllocationRecordID].Reclaim =
					&vnextOwnerReclaimRecord{
						RequestID:                        reclaimRequest.RequestID,
						RequestDigest:                    reclaimAuthority.MutationDigest,
						Allocation:                       reclaimRequest.Allocation,
						ExpectedCheckpointRoot:           cloneVNextOwnerCheckpointRoot(reclaimRequest.ExpectedCheckpointRoot),
						RetirementEpoch:                  reclaimRequest.RetirementEpoch,
						CatalogRevisionBarrier:           reclaimRequest.CatalogRevisionBarrier,
						ActiveRestoreCount:               reclaimRequest.ActiveRestoreCount,
						ReaderDrainEvidenceDigest:        reclaimRequest.ReaderDrainEvidenceDigest,
						ProducerWriteFenceEvidenceDigest: reclaimRequest.ProducerWriteFenceEvidenceDigest,
						DedupReferenceDispositionDigest:  reclaimRequest.DedupReferenceDispositionDigest,
						SchedulerProof:                   reclaimAuthority.proof(),
					}
			}
			err = fixture.group.persistJournalLocked(candidate)
			fixture.group.mu.Unlock()
			if err != nil {
				t.Fatalf("persist simulated interrupted state: %v", err)
			}
			beforeFree := fixture.devices[0].allocator.freePages()
			reopenedDevice, err := openVNextFileDevice(fixture.deviceFiles[0])
			if err != nil {
				t.Fatalf("reopen device: %v", err)
			}
			_, err = openVNextOwnerGroup(
				fixture.controlFile,
				testVNextOwnerControlSlotBytes,
				[]*vnextPersistentDevice{reopenedDevice})
			if !errors.Is(err, errVNextOwnerAdmissionClosed) {
				t.Fatalf("FENCED %s restart returned %v", test.name, err)
			}
			if reopenedDevice.allocator.freePages() != beforeFree {
				t.Fatalf("FENCED %s restart reused pages: before=%d after=%d",
					test.name, beforeFree, reopenedDevice.allocator.freePages())
			}
		})
	}
}
