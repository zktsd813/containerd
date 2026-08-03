package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

const vnextReaderActivationTestPrincipal = "spiffe://test.example/scheduler-a"

type vnextReaderActivationTestClock struct {
	mu  sync.Mutex
	now int64
}

func (clock *vnextReaderActivationTestClock) NowEpochMillis() int64 {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *vnextReaderActivationTestClock) set(value int64) {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	clock.now = value
}

type vnextReaderActivationTestVerifier struct {
	mu     sync.Mutex
	calls  int
	reject error
	mutate func(*vnextReaderActivationAuthorityProof)
}

func (verifier *vnextReaderActivationTestVerifier) VerifyVNextReaderActivationAuthority(
	_ context.Context,
	authenticatedSchedulerPrincipal string,
	spec vnextReaderActivationOperationSpec,
	digest [sha256.Size]byte,
	authority vnextReaderActivationAuthorityEnvelope,
) (vnextReaderActivationAuthorityProof, error) {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	verifier.calls++
	if verifier.reject != nil {
		return vnextReaderActivationAuthorityProof{}, verifier.reject
	}
	receipt, err := vnextReaderActivationCanonicalAuthorityReceipt(
		spec, authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return vnextReaderActivationAuthorityProof{}, err
	}
	proof := vnextReaderActivationAuthorityProof{
		AuthenticatedSchedulerPrincipal: authenticatedSchedulerPrincipal,
		SchedulerID:                     authority.SchedulerID,
		SchedulerFenceRevision:          authority.SchedulerFenceRevision,
		LeaderLeaseID:                   authority.LeaderLeaseID,
		LeaderTermID:                    authority.LeaderTermID,
		RequestDigest:                   digest,
		AuthorityReceipt:                receipt,
	}
	if verifier.mutate != nil {
		verifier.mutate(&proof)
	}
	return proof, nil
}

type vnextReaderActivationRPCTestFixture struct {
	prepared *vnextReaderAuthorizationStore
	store    *vnextReaderActivationStore
	clock    *vnextReaderActivationTestClock
	verifier *vnextReaderActivationTestVerifier
	service  *vnextReaderActivationService
	acquired vnextReaderAcquiredAuthorization
	request  vnextReaderActivationRequestIdentity
}

func vnextReaderActivationRPCTestNewFixture(
	t *testing.T,
	maxEntries int,
) *vnextReaderActivationRPCTestFixture {
	t.Helper()
	prepared, store := vnextReaderActivationStoreTestFixture(t, maxEntries)
	acquired := vnextReaderActivationStoreTestPrepare(
		t, prepared, "activation-rpc-authorization")
	request := vnextReaderActivationStoreTestRequest(
		acquired, "activation-rpc-request")
	clock := &vnextReaderActivationTestClock{now: 150}
	verifier := &vnextReaderActivationTestVerifier{}
	service, err := newVNextReaderActivationService(store, clock, verifier)
	if err != nil {
		t.Fatalf("new activation service: %v", err)
	}
	return &vnextReaderActivationRPCTestFixture{
		prepared: prepared,
		store:    store,
		clock:    clock,
		verifier: verifier,
		service:  service,
		acquired: acquired,
		request:  request,
	}
}

func vnextReaderActivationRPCTestAuthority(
	spec vnextReaderActivationOperationSpec,
	digest [sha256.Size]byte,
	schedulerID string,
	fence uint64,
) vnextReaderActivationAuthorityEnvelope {
	term := sha256.Sum256([]byte(spec.protocol + "-term-" + schedulerID))
	key := sha256.Sum256([]byte(spec.protocol + "-key-" + schedulerID))
	var signature [ed25519.SignatureSize]byte
	for index := range signature {
		signature[index] = byte(index + 1)
	}
	return vnextReaderActivationAuthorityEnvelope{
		Domain:                 spec.authorityDomain,
		ClusterID:              "0123456789abcdef",
		SchedulerID:            schedulerID,
		SchedulerFenceRevision: fence,
		LeaderLeaseID:          31,
		LeaderTermID:           term,
		KeyID:                  key,
		RequestDigest:          digest,
		Signature:              signature,
	}
}

func vnextReaderActivationRPCTestProposalRequest(
	fixture *vnextReaderActivationRPCTestFixture,
) vnextReaderActivationProposalRequest {
	return vnextReaderActivationProposalRequest{
		Request: fixture.request,
		Authority: vnextReaderActivationRPCTestAuthority(
			vnextReaderActivationProposalSpec,
			vnextReaderActivationCanonicalProposalRequestDigest(fixture.request),
			fixture.acquired.SchedulerID,
			fixture.acquired.SchedulerFenceRevision),
	}
}

func vnextReaderActivationRPCTestCommitRequest(
	fixture *vnextReaderActivationRPCTestFixture,
	proposal vnextReaderActivationProposalResponse,
) vnextReaderActivationCommitRequest {
	activeState := vnextReaderActivationActiveState{
		CatalogState:   vnextReaderCatalogAuthorizationActive,
		LastMutationID: fixture.request.ActivationRequestID,
	}
	request := vnextReaderActivationCommitRequest{
		Acquired:    fixture.acquired,
		Activation:  proposal.Activation,
		ActiveState: activeState,
	}
	request.Authority = vnextReaderActivationRPCTestAuthority(
		vnextReaderActivationCommitSpec,
		vnextReaderActivationCanonicalCommitRequestDigest(
			request.Acquired, request.Activation, request.ActiveState),
		"scheduler-current-commit", 41)
	return request
}

func vnextReaderActivationRPCTestStatusRequest(
	request vnextReaderActivationRequestIdentity,
) vnextReaderActivationStatusRequest {
	return vnextReaderActivationStatusRequest{
		Request: request,
		Authority: vnextReaderActivationRPCTestAuthority(
			vnextReaderActivationStatusSpec,
			vnextReaderActivationCanonicalStatusRequestDigest(request),
			"scheduler-current-status", 43),
	}
}

func TestVNextReaderActivationRPCProposalCommitStatusRoundTrip(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 4)
	proposalRequest := vnextReaderActivationRPCTestProposalRequest(fixture)
	proposalFrame, err := marshalVNextReaderActivationProposalRequest(proposalRequest)
	if err != nil {
		t.Fatalf("marshal proposal request: %v", err)
	}
	decodedProposalRequest, err := decodeVNextReaderActivationProposalRequest(proposalFrame)
	if err != nil ||
		!equalVNextReaderActivationRequestIdentity(
			decodedProposalRequest.Request, proposalRequest.Request) ||
		decodedProposalRequest.Authority != proposalRequest.Authority {
		t.Fatalf("decode proposal request: request=%#v err=%v",
			decodedProposalRequest, err)
	}
	proposal, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal, proposalRequest)
	if failure != nil {
		t.Fatalf("propose activation: %v", failure)
	}
	if proposal.State != vnextReaderActivationPending ||
		proposal.Disposition != vnextReaderActivationProposalInstalled ||
		proposal.Activation.CxldReceipt !=
			vnextReaderActivationCanonicalEvidenceReceipt(
				proposal.Activation, proposal.LocalExecutorNodeID,
				proposal.LocalCxldLogicalID, proposal.LocalProcessIncarnation) {
		t.Fatalf("proposal response = %#v", proposal)
	}
	proposalBody, err := marshalVNextReaderActivationProposalResponse(proposal)
	if err != nil {
		t.Fatalf("marshal proposal response: %v", err)
	}
	decodedProposal, err := decodeVNextReaderActivationProposalResponse(proposalBody)
	if err != nil || decodedProposal.Receipt != proposal.Receipt ||
		decodedProposal.Activation.CxldReceipt != proposal.Activation.CxldReceipt {
		t.Fatalf("decode proposal response: response=%#v err=%v", decodedProposal, err)
	}

	replayedProposal, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal, proposalRequest)
	if failure != nil ||
		replayedProposal.Disposition != vnextReaderActivationProposalExactReplay ||
		replayedProposal.State != vnextReaderActivationPending ||
		!equalVNextReaderActivationIntentIgnoringState(
			replayedProposal.Activation, proposal.Activation) ||
		replayedProposal.Activation.CxldReceipt != proposal.Activation.CxldReceipt ||
		replayedProposal.Receipt == proposal.Receipt {
		t.Fatalf("proposal replay: response=%#v failure=%v", replayedProposal, failure)
	}

	commitRequest := vnextReaderActivationRPCTestCommitRequest(fixture, proposal)
	commitFrame, err := marshalVNextReaderActivationCommitRequest(commitRequest)
	if err != nil {
		t.Fatalf("marshal commit request: %v", err)
	}
	decodedCommitRequest, err := decodeVNextReaderActivationCommitRequest(commitFrame)
	if err != nil ||
		!equalVNextReaderActivationIntentIgnoringState(
			decodedCommitRequest.Activation, commitRequest.Activation) {
		t.Fatalf("decode commit request: request=%#v err=%v", decodedCommitRequest, err)
	}
	commit, failure := fixture.service.Commit(
		context.Background(), vnextReaderActivationTestPrincipal, commitRequest)
	if failure != nil || commit.State != vnextReaderActivationActiveArmed ||
		commit.Disposition != vnextReaderActivationCommitArmed ||
		commit.Activation.CxldReceipt != proposal.Activation.CxldReceipt {
		t.Fatalf("commit activation: response=%#v failure=%v", commit, failure)
	}
	commitBody, err := marshalVNextReaderActivationCommitResponse(commit)
	if err != nil {
		t.Fatalf("marshal commit response: %v", err)
	}
	decodedCommit, err := decodeVNextReaderActivationCommitResponse(commitBody)
	if err != nil || decodedCommit.Receipt != commit.Receipt ||
		decodedCommit.State != vnextReaderActivationActiveArmed {
		t.Fatalf("decode commit response: response=%#v err=%v", decodedCommit, err)
	}

	statusRequest := vnextReaderActivationRPCTestStatusRequest(fixture.request)
	statusFrame, err := marshalVNextReaderActivationStatusRequest(statusRequest)
	if err != nil {
		t.Fatalf("marshal status request: %v", err)
	}
	decodedStatusRequest, err := decodeVNextReaderActivationStatusRequest(statusFrame)
	if err != nil ||
		!equalVNextReaderActivationRequestIdentity(
			decodedStatusRequest.Request, statusRequest.Request) {
		t.Fatalf("decode status request: request=%#v err=%v", decodedStatusRequest, err)
	}
	status, failure := fixture.service.Status(
		context.Background(), vnextReaderActivationTestPrincipal, statusRequest)
	if failure != nil || status.State != vnextReaderActivationStatusArmedState ||
		status.Activation == nil || status.ActiveState == nil ||
		status.Activation.CxldReceipt != proposal.Activation.CxldReceipt ||
		status.AuthorityProof.SchedulerID == fixture.acquired.SchedulerID {
		t.Fatalf("armed status: response=%#v failure=%v", status, failure)
	}
	statusBody, err := marshalVNextReaderActivationStatusResponse(status)
	if err != nil {
		t.Fatalf("marshal status response: %v", err)
	}
	decodedStatus, err := decodeVNextReaderActivationStatusResponse(statusBody)
	if err != nil || decodedStatus.Receipt != status.Receipt ||
		decodedStatus.Activation == nil || decodedStatus.ActiveState == nil {
		t.Fatalf("decode status response: response=%#v err=%v", decodedStatus, err)
	}

	fixture.clock.set(250)
	postArmProposal, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal, proposalRequest)
	if failure != nil || postArmProposal.State != vnextReaderActivationPending ||
		postArmProposal.Activation.State != vnextReaderActivationPending ||
		postArmProposal.Activation.CxldReceipt != proposal.Activation.CxldReceipt {
		t.Fatalf("post-arm expired proposal replay: response=%#v failure=%v",
			postArmProposal, failure)
	}
}

func TestVNextReaderActivationRPCStatusFencesAndTypedStates(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 3)
	missingRequest := cloneVNextReaderActivationRequestIdentity(fixture.request)
	missingRequest.ActivationRequestID = "activation-status-missing"
	missing, failure := fixture.service.Status(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationRPCTestStatusRequest(missingRequest))
	if failure != nil || missing.State != vnextReaderActivationStatusNotFoundState ||
		missing.Activation != nil || missing.ActiveState != nil {
		t.Fatalf("missing status: response=%#v failure=%v", missing, failure)
	}
	if _, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationProposalRequest{
			Request: missingRequest,
			Authority: vnextReaderActivationRPCTestAuthority(
				vnextReaderActivationProposalSpec,
				vnextReaderActivationCanonicalProposalRequestDigest(missingRequest),
				fixture.acquired.SchedulerID,
				fixture.acquired.SchedulerFenceRevision),
		}); failure == nil || failure.Code != vnextReaderActivationNotFound {
		t.Fatalf("proposal after NOT_FOUND fence failure=%v", failure)
	}

	proposal, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationRPCTestProposalRequest(fixture))
	if failure != nil {
		t.Fatalf("seed proposal for conflict: %v", failure)
	}
	_ = proposal
	conflicting := cloneVNextReaderActivationRequestIdentity(fixture.request)
	conflicting.Acquired.Authorization.TargetContainerID = "different-target"
	conflict, failure := fixture.service.Status(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationRPCTestStatusRequest(conflicting))
	if failure != nil || conflict.State != vnextReaderActivationStatusConflictState ||
		conflict.Activation != nil || conflict.ActiveState != nil {
		t.Fatalf("conflicting status: response=%#v failure=%v", conflict, failure)
	}
	if _, err := marshalVNextReaderActivationStatusResponse(conflict); err != nil {
		t.Fatalf("marshal conflict status: %v", err)
	}

	wrongProcess := cloneVNextReaderActivationRequestIdentity(fixture.request)
	wrongProcess.Acquired.Authorization.CxldProcessIncarnationID[0] ^= 0xff
	incarnation, failure := fixture.service.Status(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationRPCTestStatusRequest(wrongProcess))
	if failure != nil ||
		incarnation.State != vnextReaderActivationStatusIncarnationMismatchState ||
		incarnation.LocalProcessIncarnation ==
			wrongProcess.Acquired.Authorization.CxldProcessIncarnationID {
		t.Fatalf("incarnation status: response=%#v failure=%v", incarnation, failure)
	}
	if _, err := marshalVNextReaderActivationStatusResponse(incarnation); err != nil {
		t.Fatalf("marshal incarnation status: %v", err)
	}
}

func TestVNextReaderActivationRPCCommitRejectsNestedIdentitySubstitution(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	proposal, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationRPCTestProposalRequest(fixture))
	if failure != nil {
		t.Fatalf("seed proposal: %v", failure)
	}
	commit := vnextReaderActivationRPCTestCommitRequest(fixture, proposal)
	commit.Activation.Request.Acquired.Authorization.TargetContainerID = "different-target"
	if _, failure := fixture.service.Commit(
		context.Background(), vnextReaderActivationTestPrincipal, commit); failure == nil ||
		failure.Code != vnextReaderActivationConflictError ||
		failure.Acceptance != vnextReaderActivationDefinitelyNotAccepted {
		t.Fatalf("nested identity substitution failure=%v", failure)
	}
	commit = vnextReaderActivationRPCTestCommitRequest(fixture, proposal)
	commit.Activation.Request.Acquired = vnextReaderAcquiredAuthorization{}
	if _, failure := fixture.service.Commit(
		context.Background(), vnextReaderActivationTestPrincipal, commit); failure == nil ||
		failure.Code != vnextReaderActivationConflictError {
		t.Fatalf("zero nested identity failure=%v", failure)
	}
	status, err := fixture.store.Status(fixture.request)
	if err != nil || status.Intent == nil ||
		status.Intent.State != vnextReaderActivationPending {
		t.Fatalf("rejected nested commit changed state: status=%#v err=%v", status, err)
	}
}

func TestVNextReaderActivationRPCAuthorityAndCrossOperationSeparation(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	proposalDigest := vnextReaderActivationCanonicalProposalRequestDigest(fixture.request)
	statusDigest := vnextReaderActivationCanonicalStatusRequestDigest(fixture.request)
	if proposalDigest == statusDigest {
		t.Fatal("proposal and status request digests collide")
	}
	proposalAuthority := vnextReaderActivationRPCTestAuthority(
		vnextReaderActivationProposalSpec, proposalDigest,
		fixture.acquired.SchedulerID, fixture.acquired.SchedulerFenceRevision)
	proposalPreimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationProposalSpec, proposalAuthority)
	if err != nil {
		t.Fatalf("proposal signature preimage: %v", err)
	}
	statusAuthority := proposalAuthority
	statusAuthority.Domain = vnextReaderActivationStatusSpec.authorityDomain
	statusAuthority.RequestDigest = statusDigest
	statusPreimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationStatusSpec, statusAuthority)
	if err != nil {
		t.Fatalf("status signature preimage: %v", err)
	}
	if bytes.Equal(proposalPreimage, statusPreimage) {
		t.Fatal("proposal and status authority signature preimages collide")
	}

	proposalFrame, err := marshalVNextReaderActivationProposalRequest(
		vnextReaderActivationRPCTestProposalRequest(fixture))
	if err != nil {
		t.Fatalf("marshal proposal: %v", err)
	}
	if _, err := decodeVNextReaderActivationStatusRequest(proposalFrame); err == nil {
		t.Fatal("proposal frame decoded as status")
	}
	if _, err := vnextReaderActivationCanonicalAuthorityReceipt(
		vnextReaderActivationProposalSpec, "scheduler-not-a-uri", proposalAuthority); err == nil {
		t.Fatal("non-URI Scheduler principal produced authority receipt")
	}

	wrongTerm := vnextReaderActivationRPCTestProposalRequest(fixture)
	wrongTerm.Authority.SchedulerID = "different-scheduler"
	wrongTerm.Authority.SchedulerFenceRevision++
	// Recompute verifier-bound request signature envelope fields; the service
	// must still reject because PROPOSE is tied to PREPARED term A.
	if _, failure := fixture.service.Propose(
		context.Background(), vnextReaderActivationTestPrincipal, wrongTerm); failure == nil ||
		failure.Code != vnextReaderActivationAuthorityError {
		t.Fatalf("proposal under different current term failure=%v", failure)
	}
}

func TestVNextReaderActivationRPCStrictJSON(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	frame, err := marshalVNextReaderActivationProposalRequest(
		vnextReaderActivationRPCTestProposalRequest(fixture))
	if err != nil {
		t.Fatalf("marshal strict fixture: %v", err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(frame, &object); err != nil {
		t.Fatalf("decode fixture map: %v", err)
	}
	withoutOperation := make(map[string]json.RawMessage, len(object)-1)
	for key, value := range object {
		if key != "operation" {
			withoutOperation[key] = value
		}
	}
	missing, _ := json.Marshal(withoutOperation)
	unknown := append(append([]byte(nil), frame[:len(frame)-1]...),
		[]byte(`,"unknown":true}`)...)
	duplicate := append([]byte(`{"protocol":"duplicate",`), frame[1:]...)
	nullAcquired := bytes.Replace(frame, object["acquired"], []byte("null"), 1)
	wrongType := bytes.Replace(frame,
		[]byte(`"activationRequestId":"activation-rpc-request"`),
		[]byte(`"activationRequestId":7`), 1)
	trailing := append(append([]byte(nil), frame...), []byte(` {}`)...)
	invalidUTF8 := append([]byte(nil), frame...)
	invalidUTF8[len(invalidUTF8)/2] = 0xff
	for name, candidate := range map[string][]byte{
		"missing":       missing,
		"unknown":       unknown,
		"duplicate":     duplicate,
		"null":          nullAcquired,
		"wrong type":    wrongType,
		"trailing":      trailing,
		"invalid UTF-8": invalidUTF8,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeVNextReaderActivationProposalRequest(candidate); err == nil {
				t.Fatalf("strict decoder accepted %s JSON: %s", name, candidate)
			}
		})
	}
	oversized := bytes.Repeat([]byte{' '}, vnextReaderActivationMaxFrameBytes+1)
	if _, err := decodeVNextReaderActivationProposalRequest(oversized); err == nil {
		t.Fatal("strict decoder accepted oversized frame")
	}
}

func TestVNextReaderActivationRPCResponseEncodingFailureIsUnknownAfterMutation(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	request := vnextReaderActivationRPCTestProposalRequest(fixture)
	frame, err := marshalVNextReaderActivationProposalRequest(request)
	if err != nil {
		t.Fatalf("marshal proposal request: %v", err)
	}
	rpc := newVNextReaderActivationProposalRPC(fixture.service)
	rpc.encodeResponse = func(vnextReaderActivationProposalResponse) ([]byte, error) {
		return nil, errors.New("forced proposal encoder failure")
	}
	if body, failure := rpc.Handle(
		context.Background(), vnextReaderActivationTestPrincipal, frame); body != nil ||
		failure == nil || failure.Acceptance != vnextReaderActivationAcceptanceUnknown {
		t.Fatalf("proposal encoder failure body=%q failure=%v", body, failure)
	}
	intent, disposition, err := fixture.store.Propose(fixture.request, 150)
	if err != nil || disposition != vnextReaderActivationProposalExactReplay ||
		intent.State != vnextReaderActivationPending {
		t.Fatalf("accepted proposal was not retained: intent=%#v disposition=%v err=%v",
			intent, disposition, err)
	}

	unknown := mapVNextReaderActivationStoreError(
		vnextReaderActivationCommitSpec, errors.New("future ambiguous store failure"))
	if unknown.Acceptance != vnextReaderActivationAcceptanceUnknown ||
		unknown.Code != vnextReaderActivationUnavailable {
		t.Fatalf("unknown store failure classification=%#v", unknown)
	}
}

func TestVNextReaderActivationRPCStatusNullIdentityRelations(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	missing, failure := fixture.service.Status(
		context.Background(), vnextReaderActivationTestPrincipal,
		vnextReaderActivationRPCTestStatusRequest(fixture.request))
	if failure != nil {
		t.Fatalf("missing status: %v", failure)
	}
	wrongLocal := missing
	wrongLocal.LocalProcessIncarnation[0] ^= 0xff
	wrongLocal.Receipt = vnextReaderActivationCanonicalStatusReceipt(wrongLocal)
	if _, err := marshalVNextReaderActivationStatusResponse(wrongLocal); err == nil ||
		!strings.Contains(err.Error(), "local identity") {
		t.Fatalf("NOT_FOUND accepted wrong local process: %v", err)
	}

	incarnation := missing
	incarnation.State = vnextReaderActivationStatusIncarnationMismatchState
	incarnation.LocalProcessIncarnation = fixture.acquired.Authorization.CxldProcessIncarnationID
	incarnation.Receipt = vnextReaderActivationCanonicalStatusReceipt(incarnation)
	if _, err := marshalVNextReaderActivationStatusResponse(incarnation); err == nil ||
		!strings.Contains(err.Error(), "incarnation mismatch") {
		t.Fatalf("INCARNATION_MISMATCH accepted equal process: %v", err)
	}
}

func TestVNextReaderActivationRPCRequestDigestEveryFieldSubstitution(t *testing.T) {
	fixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	base := fixture.request
	want := vnextReaderActivationCanonicalProposalRequestDigest(base)
	mutations := map[string]func(*vnextReaderActivationRequestIdentity){
		"authorization ID": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.RestoreAuthorizationID = "different-authorization"
		},
		"checkpoint ID": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.CheckpointID = "different-checkpoint"
		},
		"executor": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.ExecutorID = "different-executor"
		},
		"logical cxld": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.CxldLogicalID = "different-cxld"
		},
		"process": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.CxldProcessIncarnationID[0] ^= 0xff
		},
		"registration revision": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.ReaderInitialRegistrationCatalogRevision++
		},
		"target": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.TargetContainerID = "different-target"
		},
		"root ID": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.RootID = "different-root"
		},
		"root version": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.RootVersion++
		},
		"MM template": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.MMTemplateID = "different-mm"
		},
		"PageMap ID": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PageMapID = "different-page-map"
		},
		"PageMap version": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PageMapVersion++
		},
		"device digest": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.DeviceTableDigest[0] ^= 0xff
		},
		"contract": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.ContractID = "different-contract"
		},
		"publication length": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PublicationByteLength++
		},
		"publication digest": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PublicationSHA256[0] ^= 0xff
		},
		"run owner": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
				"different-owner"
		},
		"run device": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID =
				"different-device"
		},
		"allocation record": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.AllocationRecordID++
		},
		"data page": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DataPageIndex++
		},
		"page count": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].PageCount++
		},
		"Scheduler": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.SchedulerID = "different-scheduler"
		},
		"Scheduler fence": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.SchedulerFenceRevision++
		},
		"issued at": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.IssuedAtEpochMillis++
		},
		"expires at": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.ExpiresAtEpochMillis++
		},
		"catalog state": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.CatalogState = vnextReaderCatalogAuthorizationState("OTHER")
		},
		"last mutation": func(value *vnextReaderActivationRequestIdentity) {
			value.Acquired.LastMutationID = "different-last-mutation"
		},
		"activation request": func(value *vnextReaderActivationRequestIdentity) {
			value.ActivationRequestID = "different-activation-request"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneVNextReaderActivationRequestIdentity(base)
			mutate(&candidate)
			if got := vnextReaderActivationCanonicalProposalRequestDigest(candidate); got == want {
				t.Fatalf("proposal request digest did not bind %s", name)
			}
		})
	}
}

func TestVNextReaderActivationRPCCanonicalEveryFieldSubstitution(t *testing.T) {
	fixture := vnextReaderActivationGoldenFixtureValue(t)
	activeState := vnextReaderActivationActiveState{
		CatalogState:   vnextReaderCatalogAuthorizationActive,
		LastMutationID: fixture.request.ActivationRequestID,
	}

	stable := fixture.activation.CxldReceipt
	assertStableChanged := func(name string,
		activation vnextReaderActivationIntent,
		executor string,
		logical string,
		process vnextReaderProcessIncarnation) {
		t.Helper()
		if got := vnextReaderActivationCanonicalEvidenceReceipt(
			activation, executor, logical, process); got == stable {
			t.Fatalf("stable activation receipt did not bind %s", name)
		}
	}
	candidateActivation := cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.Request.ActivationRequestID = "different-activation-request"
	assertStableChanged("activation request ID", candidateActivation,
		"executor-a", "reader-cxld-a", fixture.localProcess)
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.MappingID = "different-mapping"
	assertStableChanged("mapping ID", candidateActivation,
		"executor-a", "reader-cxld-a", fixture.localProcess)
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.MappingGeneration++
	assertStableChanged("mapping generation", candidateActivation,
		"executor-a", "reader-cxld-a", fixture.localProcess)
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.ActivatedAtEpochMillis++
	assertStableChanged("activation time", candidateActivation,
		"executor-a", "reader-cxld-a", fixture.localProcess)
	assertStableChanged("local executor", fixture.activation,
		"different-executor", "reader-cxld-a", fixture.localProcess)
	assertStableChanged("local logical cxld", fixture.activation,
		"executor-a", "different-cxld", fixture.localProcess)
	differentProcess := fixture.localProcess
	differentProcess[0] ^= 0xff
	assertStableChanged("local process", fixture.activation,
		"executor-a", "reader-cxld-a", differentProcess)

	commitDigest := vnextReaderActivationCanonicalCommitRequestDigest(
		fixture.request.Acquired, fixture.activation, activeState)
	assertCommitChanged := func(name string,
		acquired vnextReaderAcquiredAuthorization,
		activation vnextReaderActivationIntent,
		state vnextReaderActivationActiveState) {
		t.Helper()
		if got := vnextReaderActivationCanonicalCommitRequestDigest(
			acquired, activation, state); got == commitDigest {
			t.Fatalf("commit request digest did not bind %s", name)
		}
	}
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.MappingID = "different-mapping"
	assertCommitChanged("mapping ID", fixture.request.Acquired,
		candidateActivation, activeState)
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.MappingGeneration++
	assertCommitChanged("mapping generation", fixture.request.Acquired,
		candidateActivation, activeState)
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.ActivatedAtEpochMillis++
	assertCommitChanged("activation time", fixture.request.Acquired,
		candidateActivation, activeState)
	candidateActivation = cloneVNextReaderActivationIntent(fixture.activation)
	candidateActivation.CxldReceipt[0] ^= 0xff
	assertCommitChanged("stable cxld receipt", fixture.request.Acquired,
		candidateActivation, activeState)
	candidateState := activeState
	candidateState.CatalogState = vnextReaderCatalogAuthorizationState("OTHER")
	assertCommitChanged("ACTIVE state", fixture.request.Acquired,
		fixture.activation, candidateState)
	candidateState = activeState
	candidateState.LastMutationID = "different-mutation"
	assertCommitChanged("ACTIVE mutation", fixture.request.Acquired,
		fixture.activation, candidateState)

	authority := fixture.proposalAuthority
	preimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationProposalSpec, authority)
	if err != nil {
		t.Fatalf("base authority preimage: %v", err)
	}
	for name, mutate := range map[string]func(*vnextReaderActivationAuthorityEnvelope){
		"cluster": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.ClusterID = "0000000000000002"
		},
		"Scheduler": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.SchedulerID = "different-scheduler"
		},
		"fence": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.SchedulerFenceRevision++
		},
		"lease": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.LeaderLeaseID++
		},
		"term": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.LeaderTermID[0] ^= 0xff
		},
		"key": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.KeyID[0] ^= 0xff
		},
		"request digest": func(value *vnextReaderActivationAuthorityEnvelope) {
			value.RequestDigest[0] ^= 0xff
		},
	} {
		t.Run("authority "+name, func(t *testing.T) {
			candidate := authority
			mutate(&candidate)
			got, err := vnextReaderActivationAuthoritySignaturePreimage(
				vnextReaderActivationProposalSpec, candidate)
			if err != nil || bytes.Equal(got, preimage) {
				t.Fatalf("authority preimage %s: equal=%v err=%v",
					name, bytes.Equal(got, preimage), err)
			}
		})
	}
	invalidDomain := authority
	invalidDomain.Domain = vnextReaderActivationCommitAuthorityDomain
	if _, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationProposalSpec, invalidDomain); err == nil {
		t.Fatal("proposal signature preimage accepted commit authority domain")
	}
	authorityReceipt, err := vnextReaderActivationCanonicalAuthorityReceipt(
		vnextReaderActivationProposalSpec,
		vnextReaderActivationGoldenPrincipal, authority)
	if err != nil {
		t.Fatalf("base authority receipt: %v", err)
	}
	signatureChanged := authority
	signatureChanged.Signature[0] ^= 0xff
	if got, err := vnextReaderActivationCanonicalAuthorityReceipt(
		vnextReaderActivationProposalSpec,
		vnextReaderActivationGoldenPrincipal, signatureChanged); err != nil ||
		got == authorityReceipt {
		t.Fatalf("authority receipt did not bind signature: got=%x err=%v", got, err)
	}
	if got, err := vnextReaderActivationCanonicalAuthorityReceipt(
		vnextReaderActivationProposalSpec,
		"spiffe://test.example/scheduler/different", authority); err != nil ||
		got == authorityReceipt {
		t.Fatalf("authority receipt did not bind principal: got=%x err=%v", got, err)
	}

	proof := vnextReaderActivationGoldenProof(
		t, vnextReaderActivationProposalSpec, authority)
	proposal := vnextReaderActivationProposalResponse{
		RequestDigest:           vnextReaderActivationCanonicalProposalRequestDigest(fixture.request),
		AuthorityProof:          proof,
		LocalExecutorNodeID:     "executor-a",
		LocalCxldLogicalID:      "reader-cxld-a",
		LocalProcessIncarnation: fixture.localProcess,
		State:                   vnextReaderActivationPending,
		Disposition:             vnextReaderActivationProposalInstalled,
		Acquired:                fixture.request.Acquired,
		Activation:              fixture.activation,
	}
	outer := vnextReaderActivationCanonicalProposalReceipt(proposal)
	assertOuterChanged := func(name string, candidate vnextReaderActivationProposalResponse) {
		t.Helper()
		if got := vnextReaderActivationCanonicalProposalReceipt(candidate); got == outer {
			t.Fatalf("proposal outer receipt did not bind %s", name)
		}
	}
	candidateProposal := proposal
	candidateProposal.RequestDigest[0] ^= 0xff
	assertOuterChanged("request digest", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.AuthenticatedSchedulerPrincipal =
		"spiffe://test.example/scheduler/different"
	assertOuterChanged("proof principal", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.SchedulerID = "different-scheduler"
	assertOuterChanged("proof Scheduler", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.SchedulerFenceRevision++
	assertOuterChanged("proof fence", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.LeaderLeaseID++
	assertOuterChanged("proof lease", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.LeaderTermID[0] ^= 0xff
	assertOuterChanged("proof term", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.RequestDigest[0] ^= 0xff
	assertOuterChanged("proof request digest", candidateProposal)
	candidateProposal = proposal
	candidateProposal.AuthorityProof.AuthorityReceipt[0] ^= 0xff
	assertOuterChanged("proof authority receipt", candidateProposal)
	candidateProposal = proposal
	candidateProposal.LocalExecutorNodeID = "different-executor"
	assertOuterChanged("local executor", candidateProposal)
	candidateProposal = proposal
	candidateProposal.LocalCxldLogicalID = "different-cxld"
	assertOuterChanged("local cxld", candidateProposal)
	candidateProposal = proposal
	candidateProposal.LocalProcessIncarnation[0] ^= 0xff
	assertOuterChanged("local process", candidateProposal)
	candidateProposal = proposal
	candidateProposal.State = vnextReaderActivationActiveArmed
	assertOuterChanged("state", candidateProposal)
	candidateProposal = proposal
	candidateProposal.Disposition = vnextReaderActivationProposalExactReplay
	assertOuterChanged("disposition", candidateProposal)
	candidateProposal = proposal
	candidateProposal.Acquired.Authorization.Root.RootVersion++
	assertOuterChanged("ACQUIRED", candidateProposal)
	candidateProposal = proposal
	candidateProposal.Activation.MappingGeneration++
	assertOuterChanged("activation", candidateProposal)

	status := vnextReaderActivationStatusResponse{
		RequestDigest: vnextReaderActivationCanonicalStatusRequestDigest(fixture.request),
		AuthorityProof: vnextReaderActivationGoldenProof(
			t, vnextReaderActivationStatusSpec, fixture.statusAuthority),
		LocalExecutorNodeID:     "executor-a",
		LocalCxldLogicalID:      "reader-cxld-a",
		LocalProcessIncarnation: fixture.localProcess,
		State:                   vnextReaderActivationStatusPendingState,
		Acquired:                fixture.request.Acquired,
	}
	statusWithoutPayload := vnextReaderActivationCanonicalStatusReceipt(status)
	status.Activation = &fixture.activation
	if got := vnextReaderActivationCanonicalStatusReceipt(status); got == statusWithoutPayload {
		t.Fatal("STATUS receipt did not bind activation-present marker")
	}
	status.State = vnextReaderActivationStatusArmedState
	status.ActiveState = &activeState
	withActive := vnextReaderActivationCanonicalStatusReceipt(status)
	status.ActiveState = nil
	if got := vnextReaderActivationCanonicalStatusReceipt(status); got == withActive {
		t.Fatal("STATUS receipt did not bind activeState-present marker")
	}
}

func Example_vnextReaderActivationProtocols() {
	fmt.Println(vnextReaderActivationProposalProtocol)
	fmt.Println(vnextReaderActivationCommitProtocol)
	fmt.Println(vnextReaderActivationStatusProtocol)
	// Output:
	// cxld.vnext-reader-activation-proposal.v1
	// cxld.vnext-reader-activation-commit.v1
	// cxld.vnext-reader-activation-status-and-fence.v1
}
