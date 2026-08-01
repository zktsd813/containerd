package main

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type vnextOwnerStatusFenceBlockingVerifier struct {
	delegate  *vnextOwnerTermFenceTestVerifier
	blockTerm [vnextOwnerSchedulerDigestBytes]byte
	entered   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (verifier *vnextOwnerStatusFenceBlockingVerifier) Prepare(
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerVerifiedAuthority, error) {
	return verifier.delegate.Prepare(operation, mutation, authority)
}

func (verifier *vnextOwnerStatusFenceBlockingVerifier) VerifyCurrent(
	ctx context.Context,
	verified vnextOwnerSchedulerVerifiedAuthority,
) error {
	if verified.Parsed.TermID == verifier.blockTerm {
		verifier.once.Do(func() { close(verifier.entered) })
		select {
		case <-verifier.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return verifier.delegate.VerifyCurrent(ctx, verified)
}

func vnextOwnerStatusFenceFixture(
	t *testing.T,
	name string,
) (*vnextOwnerTestFixture, *vnextOwnerService, vnextOwnerOperationIdentity) {
	t.Helper()
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "status-fence-" + name, Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	reserved, err := service.reserve(vnextOwnerStatusTestRequest("status-fence-"+name, 2))
	if err != nil {
		t.Fatalf("reserve status-and-fence allocation: %v", err)
	}
	return fixture, service, reserved.Operation
}

func vnextOwnerStatusFenceIssue(
	t *testing.T,
	identity vnextOwnerOperationIdentity,
	requestID string,
	revision uint64,
) (vnextOwnerIssueProducerCapabilityRequest, vnextOwnerSchedulerVerifiedAuthority) {
	t.Helper()
	request := vnextOwnerTestCapabilityIssueRequest(identity, vnextProducerCapabilityAll)
	request.RequestID = requestID
	authority, verified := vnextOwnerTermFenceTestAuthority(
		t, vnextOwnerRPCOperationIssueProducerCapability, request, revision)
	request.SchedulerAuthority = authority
	return request, verified
}

func vnextOwnerStatusFenceRequest(
	t *testing.T,
	identity vnextOwnerOperationIdentity,
	requestID string,
	issueRequestID string,
	issueProof vnextOwnerSchedulerProof,
	issueRevision uint64,
	fenceRevision uint64,
) (vnextOwnerProducerCapabilityIssueStatusAndFenceRequest,
	vnextOwnerSchedulerVerifiedAuthority) {
	t.Helper()
	request := vnextOwnerProducerCapabilityIssueStatusAndFenceRequest{
		RequestID:                   requestID,
		Operation:                   identity,
		ExpectedIssueRequestID:      issueRequestID,
		ExpectedIssueSchedulerProof: issueProof,
		ExpectedIssueCreateRevision: issueRevision,
	}
	authority, verified := vnextOwnerTermFenceTestAuthority(
		t,
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
		request,
		fenceRevision)
	request.SchedulerAuthority = authority
	return request, verified
}

func vnextOwnerStatusFenceCapabilityRecord(
	fixture *vnextOwnerTestFixture,
	allocationRecordID uint64,
) *vnextProducerCapabilityRecord {
	fixture.group.mu.Lock()
	defer fixture.group.mu.Unlock()
	transaction := fixture.group.journal.Transactions[allocationRecordID]
	if transaction == nil || transaction.ProducerCapability == nil {
		return nil
	}
	copy := *transaction.ProducerCapability
	return &copy
}

func TestVNextOwnerProducerCapabilityDelayedOldIssueIsDeniedAfterNewerFence(t *testing.T) {
	fixture, service, identity := vnextOwnerStatusFenceFixture(t, "delayed-old")
	oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-delayed-old-issue", 2)
	statusRequest, fenceVerified := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-delayed-old-query", oldIssue.RequestID,
		oldVerified.proof(), 2, 3)
	verifier := &vnextOwnerTermFenceTestVerifier{}
	service.schedulerAuthority = verifier
	beforeSequence := fixture.group.journal.SnapshotSequence
	status, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		statusRequest, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("newer status-and-fence: %v", err)
	}
	if status.State != vnextOwnerProducerCapabilityIssueNotFound ||
		!status.ReplacementEligible || status.Capability != nil ||
		status.FenceCreateRevision != 3 || status.SnapshotSequence != beforeSequence+1 {
		t.Fatalf("unexpected newer-term absence: %#v", status)
	}
	if fixture.group.journal.SchedulerHighWater != fenceVerified.HighWater {
		t.Fatal("newer status response preceded durable Scheduler high-water")
	}
	sequenceAfterFence := fixture.group.journal.SnapshotSequence
	_, err = service.issueProducerCapabilityScheduler(oldIssue, vnextOwnerTestSchedulerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServicePermissionDenied)
	if !errors.Is(err, errVNextOwnerSchedulerFenced) {
		t.Fatalf("delayed old Issue was not rejected by durable high-water: %v", err)
	}
	if vnextOwnerStatusFenceCapabilityRecord(fixture, identity.AllocationRecordID) != nil ||
		fixture.group.journal.SnapshotSequence != sequenceAfterFence {
		t.Fatal("delayed old Issue changed capability state after the fence")
	}
}

func TestVNextOwnerProducerCapabilityIssueFirstRaceReturnsIssuedAndExactAckReplays(t *testing.T) {
	_, service, identity := vnextOwnerStatusFenceFixture(t, "issue-first")
	oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-issue-first", 2)
	statusRequest, _ := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-issue-first-query", oldIssue.RequestID,
		oldVerified.proof(), 2, 3)
	delegate := &vnextOwnerTermFenceTestVerifier{}
	verifier := &vnextOwnerStatusFenceBlockingVerifier{
		delegate: delegate, blockTerm: oldVerified.Parsed.TermID,
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	service.schedulerAuthority = verifier
	type issueResult struct {
		response vnextOwnerIssueProducerCapabilityResponse
		err      error
	}
	issuedResult := make(chan issueResult, 1)
	go func() {
		response, err := service.issueProducerCapabilityScheduler(
			oldIssue, vnextOwnerTestSchedulerCaller)
		issuedResult <- issueResult{response: response, err: err}
	}()
	select {
	case <-verifier.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("old Issue did not reach the deterministic authority barrier")
	}
	type statusResult struct {
		response vnextOwnerProducerCapabilityIssueStatusAndFenceResponse
		err      error
	}
	statusResultChannel := make(chan statusResult, 1)
	go func() {
		response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
			statusRequest, vnextOwnerTestSchedulerCaller)
		statusResultChannel <- statusResult{response: response, err: err}
	}()
	select {
	case result := <-statusResultChannel:
		t.Fatalf("status bypassed the in-flight Issue service lock: %#v / %v",
			result.response, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(verifier.release)
	issued := <-issuedResult
	if issued.err != nil || issued.response.Replayed {
		t.Fatalf("old Issue first result: %#v / %v", issued.response, issued.err)
	}
	status := <-statusResultChannel
	if status.err != nil ||
		status.response.State != vnextOwnerProducerCapabilityIssueIssued ||
		status.response.ReplacementEligible || status.response.Capability == nil ||
		status.response.Capability.CapabilityID != issued.response.Capability.CapabilityID {
		t.Fatalf("status after Issue-first race: %#v / %v", status.response, status.err)
	}
	verifyCalls := delegate.verifyCurrentCalls
	replayed, err := service.issueProducerCapabilityScheduler(
		oldIssue, vnextOwnerTestSchedulerCaller)
	if err != nil || !replayed.Replayed ||
		replayed.Capability != issued.response.Capability {
		t.Fatalf("exact old Issue ACK replay after newer high-water: %#v / %v", replayed, err)
	}
	if delegate.verifyCurrentCalls != verifyCalls {
		t.Fatal("exact old Issue ACK replay consulted live Scheduler authority")
	}
	statusSequence := status.response.SnapshotSequence
	repeatedStatus, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		statusRequest, vnextOwnerTestSchedulerCaller)
	if err != nil || repeatedStatus.State != vnextOwnerProducerCapabilityIssueIssued ||
		repeatedStatus.SnapshotSequence != statusSequence {
		t.Fatalf("repeat issued status-and-fence: %#v / %v", repeatedStatus, err)
	}
	if delegate.verifyCurrentCalls != verifyCalls+1 {
		t.Fatal("repeat issued status used a receipt shortcut instead of VerifyCurrent")
	}
}

func TestVNextOwnerProducerCapabilityFencePersistenceFailureIsNeverNotFound(t *testing.T) {
	fixture, service, identity := vnextOwnerStatusFenceFixture(t, "persist-failure")
	oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-persist-failure-issue", 1)
	request, _ := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-persist-failure-query", oldIssue.RequestID,
		oldVerified.proof(), 1, 2)
	service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.SchedulerHighWater
	fixture.group.controlSlotBytes = 1
	response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		request, vnextOwnerTestSchedulerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceUnavailable)
	if response.State.valid() || fixture.group.poisoned == nil ||
		fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.SchedulerHighWater != beforeHighWater {
		t.Fatalf("failed fence was exposed as definitive status: %#v / %v", response, err)
	}
}

func TestVNextOwnerProducerCapabilityFenceSurvivesRestart(t *testing.T) {
	fixture, service, identity := vnextOwnerStatusFenceFixture(t, "restart")
	oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-restart-issue", 2)
	request, fenceVerified := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-restart-query", oldIssue.RequestID,
		oldVerified.proof(), 2, 3)
	service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
	if response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		request, vnextOwnerTestSchedulerCaller); err != nil ||
		response.State != vnextOwnerProducerCapabilityIssueNotFound ||
		!response.ReplacementEligible {
		t.Fatalf("persist restart fence: %#v / %v", response, err)
	}
	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	restarted.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
	if fixture.group.journal.SchedulerHighWater != fenceVerified.HighWater {
		t.Fatal("restart lost Producer capability Issue status fence")
	}
	_, err := restarted.issueProducerCapabilityScheduler(
		oldIssue, vnextOwnerTestSchedulerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServicePermissionDenied)
	if !errors.Is(err, errVNextOwnerSchedulerFenced) {
		t.Fatalf("restart did not fence delayed old Issue: %v", err)
	}
}

func TestVNextOwnerProducerCapabilitySameTermAbsenceIsNotReplacementEligible(t *testing.T) {
	_, service, identity := vnextOwnerStatusFenceFixture(t, "same-term")
	oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-same-term-issue", 2)
	request, _ := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-same-term-query", oldIssue.RequestID,
		oldVerified.proof(), 2, 2)
	verifier := &vnextOwnerTermFenceTestVerifier{}
	service.schedulerAuthority = verifier
	response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		request, vnextOwnerTestSchedulerCaller)
	if err != nil || response.State != vnextOwnerProducerCapabilityIssueNotFound ||
		response.ReplacementEligible {
		t.Fatalf("same-term absence became replacement-eligible: %#v / %v", response, err)
	}
	sequence := response.SnapshotSequence
	repeated, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		request, vnextOwnerTestSchedulerCaller)
	if err != nil || repeated.State != vnextOwnerProducerCapabilityIssueNotFound ||
		repeated.ReplacementEligible || repeated.SnapshotSequence != sequence ||
		verifier.verifyCurrentCalls != 2 {
		t.Fatalf("repeat same-term status did not revalidate current authority: %#v / %v calls=%d",
			repeated, err, verifier.verifyCurrentCalls)
	}
	issued, err := service.issueProducerCapabilityScheduler(
		oldIssue, vnextOwnerTestSchedulerCaller)
	if err != nil || issued.Replayed {
		t.Fatalf("same-term exact resend did not remain eligible: %#v / %v", issued, err)
	}
}

func TestVNextOwnerProducerCapabilityRevokedStatusIsExactAndPublicOnly(t *testing.T) {
	_, service, identity := vnextOwnerStatusFenceFixture(t, "revoked")
	issue, issueVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-revoked-issue", 2)
	verifier := &vnextOwnerTermFenceTestVerifier{}
	service.schedulerAuthority = verifier
	issued, err := service.issueProducerCapabilityScheduler(
		issue, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("issue capability before revoke status: %v", err)
	}
	revoke := vnextOwnerRevokeProducerCapabilityRequest{
		RequestID:    "status-fence-revoked-mutation",
		Operation:    identity,
		CapabilityID: issued.Capability.CapabilityID,
	}
	revokeAuthority, _ := vnextOwnerTermFenceTestAuthority(
		t, vnextOwnerRPCOperationRevokeProducerCapability, revoke, 3)
	revoke.SchedulerAuthority = revokeAuthority
	revoked, err := service.revokeProducerCapabilityScheduler(
		revoke, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("revoke capability before status: %v", err)
	}
	request, _ := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-revoked-query", issue.RequestID,
		issueVerified.proof(), 2, 4)
	response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
		request, vnextOwnerTestSchedulerCaller)
	if err != nil || response.State != vnextOwnerProducerCapabilityIssueRevoked ||
		response.ReplacementEligible || response.Capability == nil ||
		response.Capability.CapabilityID != issued.Capability.CapabilityID ||
		response.Capability.RevokedAtUnixNano != revoked.RevokedAtUnixNano {
		t.Fatalf("exact revoked status: %#v / %v", response, err)
	}
}

func TestVNextOwnerProducerCapabilityStatusPoisonAndCorruptionAreUnavailable(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*vnextOwnerTestFixture)
	}{
		{
			name: "poisoned",
			mutate: func(fixture *vnextOwnerTestFixture) {
				fixture.group.poisoned = errors.New("injected status poison")
			},
		},
		{
			name: "corrupt-journal",
			mutate: func(fixture *vnextOwnerTestFixture) {
				fixture.group.journal.AdmissionSequence = 0
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture, service, identity := vnextOwnerStatusFenceFixture(t, test.name)
			issue, issueVerified := vnextOwnerStatusFenceIssue(
				t, identity, "status-fence-"+test.name+"-issue", 1)
			request, _ := vnextOwnerStatusFenceRequest(
				t, identity, "status-fence-"+test.name+"-query", issue.RequestID,
				issueVerified.proof(), 1, 2)
			service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
			beforeSequence := fixture.group.journal.SnapshotSequence
			beforeHighWater := fixture.group.journal.SchedulerHighWater
			test.mutate(fixture)
			response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
				request, vnextOwnerTestSchedulerCaller)
			requireVNextOwnerServiceCode(t, err, vnextOwnerServiceUnavailable)
			if response.State.valid() ||
				fixture.group.journal.SnapshotSequence != beforeSequence ||
				fixture.group.journal.SchedulerHighWater != beforeHighWater {
				t.Fatalf("unusable journal returned status or mutated: %#v / %v", response, err)
			}
		})
	}
}

func TestVNextOwnerProducerCapabilityStatusIdentityConflictAndTerminalAreTyped(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		_, service, identity := vnextOwnerStatusFenceFixture(t, "missing")
		oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
			t, identity, "status-fence-missing-issue", 1)
		identity.AllocationRecordID++
		request, _ := vnextOwnerStatusFenceRequest(
			t, identity, "status-fence-missing-query", oldIssue.RequestID,
			oldVerified.proof(), 1, 2)
		service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
		_, err := service.producerCapabilityIssueStatusAndFenceScheduler(
			request, vnextOwnerTestSchedulerCaller)
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceTransactionNotFound)
	})

	t.Run("identity-mismatch", func(t *testing.T) {
		_, service, identity := vnextOwnerStatusFenceFixture(t, "identity")
		oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
			t, identity, "status-fence-identity-issue", 1)
		identity.ProducerID += "-wrong"
		request, _ := vnextOwnerStatusFenceRequest(
			t, identity, "status-fence-identity-query", oldIssue.RequestID,
			oldVerified.proof(), 1, 2)
		service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
		_, err := service.producerCapabilityIssueStatusAndFenceScheduler(
			request, vnextOwnerTestSchedulerCaller)
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceIdentityMismatch)
	})

	t.Run("terminal-without-capability", func(t *testing.T) {
		_, service, identity := vnextOwnerStatusFenceFixture(t, "terminal")
		if err := service.abort(identity); err != nil {
			t.Fatalf("abort capability-free allocation: %v", err)
		}
		oldIssue, oldVerified := vnextOwnerStatusFenceIssue(
			t, identity, "status-fence-terminal-issue", 1)
		request, _ := vnextOwnerStatusFenceRequest(
			t, identity, "status-fence-terminal-query", oldIssue.RequestID,
			oldVerified.proof(), 1, 2)
		service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
		_, err := service.producerCapabilityIssueStatusAndFenceScheduler(
			request, vnextOwnerTestSchedulerCaller)
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceTransactionState)
	})

	t.Run("terminal-with-capability", func(t *testing.T) {
		_, service, identity := vnextOwnerStatusFenceFixture(t, "terminal-capability")
		issuedRequest, issuedVerified := vnextOwnerStatusFenceIssue(
			t, identity, "status-fence-terminal-capability-issue", 2)
		service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
		issued, err := service.issueProducerCapabilityScheduler(
			issuedRequest, vnextOwnerTestSchedulerCaller)
		if err != nil {
			t.Fatalf("seed capability before terminal transition: %v", err)
		}
		if err := service.producerAbort(
			identity, issued.Capability, vnextOwnerTestProducerCaller); err != nil {
			t.Fatalf("abort capability-bearing allocation: %v", err)
		}
		request, _ := vnextOwnerStatusFenceRequest(
			t, identity, "status-fence-terminal-capability-query",
			issuedRequest.RequestID, issuedVerified.proof(), 2, 3)
		_, err = service.producerCapabilityIssueStatusAndFenceScheduler(
			request, vnextOwnerTestSchedulerCaller)
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceTransactionState)
	})

	t.Run("different-capability", func(t *testing.T) {
		_, service, identity := vnextOwnerStatusFenceFixture(t, "conflict")
		issuedRequest, _ := vnextOwnerStatusFenceIssue(
			t, identity, "status-fence-existing-issue", 2)
		service.schedulerAuthority = &vnextOwnerTermFenceTestVerifier{}
		if _, err := service.issueProducerCapabilityScheduler(
			issuedRequest, vnextOwnerTestSchedulerCaller); err != nil {
			t.Fatalf("seed different durable capability: %v", err)
		}
		expectedRequest, expectedVerified := vnextOwnerStatusFenceIssue(
			t, identity, "status-fence-expected-other-issue", 2)
		issuedProof, err := vnextOwnerSchedulerExpectedProof(
			vnextOwnerRPCOperationIssueProducerCapability,
			issuedRequest,
			issuedRequest.SchedulerAuthority)
		if err != nil {
			t.Fatal(err)
		}
		for _, mismatch := range []struct {
			name      string
			requestID string
			proof     vnextOwnerSchedulerProof
		}{
			{
				name: "request-id-only", requestID: expectedRequest.RequestID,
				proof: issuedProof,
			},
			{
				name: "proof-only", requestID: issuedRequest.RequestID,
				proof: expectedVerified.proof(),
			},
		} {
			t.Run(mismatch.name, func(t *testing.T) {
				request, _ := vnextOwnerStatusFenceRequest(
					t, identity, "status-fence-conflict-query-"+mismatch.name,
					mismatch.requestID, mismatch.proof, 2, 3)
				response, err := service.producerCapabilityIssueStatusAndFenceScheduler(
					request, vnextOwnerTestSchedulerCaller)
				if err != nil || response.State != vnextOwnerProducerCapabilityIssueConflict ||
					response.ReplacementEligible || response.Capability != nil {
					t.Fatalf("different capability status: %#v / %v", response, err)
				}
			})
		}
	})
}
