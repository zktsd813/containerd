package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// reclaimCheckpoint preserves the old low-level test spelling without
// restoring an unsigned production entry point. The method exists only in the
// test binary and drives the same signed hard-cut path as the RPC service.
func (group *vnextOwnerGroup) reclaimCheckpoint(
	checkpointID string,
	allocationRecordID uint64,
) error {
	request, err := vnextOwnerTestReclaimRequest(
		group, checkpointID, allocationRecordID,
		fmt.Sprintf("test-reclaim-%d", allocationRecordID))
	if err != nil {
		return err
	}
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReclaim, request)
	_, _, err = group.reclaimCheckpointWithScheduler(request, authority)
	return err
}

func vnextOwnerTestReclaimRequest(
	group *vnextOwnerGroup,
	checkpointID string,
	allocationRecordID uint64,
	requestID string,
) (vnextOwnerReclaimRequest, error) {
	group.mu.Lock()
	defer group.mu.Unlock()
	transaction := group.journal.Transactions[allocationRecordID]
	if transaction == nil || transaction.CheckpointID != checkpointID ||
		len(transaction.Fragments) == 0 ||
		len(transaction.Fragments[0].Extents) == 0 {
		return vnextOwnerReclaimRequest{}, fmt.Errorf(
			"test reclaim does not name an allocation")
	}
	allocation := vnextOwnerOperationIdentity{
		RequestID:          transaction.RequestID,
		CheckpointID:       transaction.CheckpointID,
		ProducerID:         transaction.ProducerID,
		OwnerID:            group.ownerID,
		OwnerEpoch:         group.ownerEpoch,
		AllocationRecordID: transaction.AllocationRecordID,
	}
	firstFragment := transaction.Fragments[0]
	firstExtent := firstFragment.Extents[0]

	request := vnextOwnerReclaimRequest{
		RequestID:                        requestID,
		Allocation:                       allocation,
		RetirementEpoch:                  1,
		CatalogRevisionBarrier:           1,
		ActiveRestoreCount:               0,
		ReaderDrainEvidenceDigest:        [32]byte{1},
		ProducerWriteFenceEvidenceDigest: [32]byte{2},
		DedupReferenceDispositionDigest:  [32]byte{3},
		ExpectedCheckpointRoot: vnextOwnerCheckpointRoot{
			RootID:            fmt.Sprintf("test-root-%d", allocationRecordID),
			RootVersion:       1,
			MMTemplateID:      fmt.Sprintf("test-mm-%d", allocationRecordID),
			PageMapID:         fmt.Sprintf("test-page-map-%d", allocationRecordID),
			PageMapVersion:    1,
			DeviceTableDigest: [32]byte{4},
			ContractID:        cxlcheckpoint.V6CompatibilityID,
			Locator: vnextOwnerCheckpointRootLocator{
				PublicationByteLength: 1,
				PublicationSHA256:     [32]byte{5},
				PageRuns: []vnextOwnerPublicationPageRun{{
					FirstPage: cxlcheckpoint.PageID{
						OwnerID:            allocation.OwnerID,
						DeviceUUID:         firstFragment.DeviceUUID,
						DataPageIndex:      firstExtent.StartDataPageIndex,
						AllocationRecordID: allocationRecordID,
					},
					PageCount: 1,
				}},
			},
		},
	}
	return request, nil
}

func vnextOwnerTestCommittedReclaim(
	t *testing.T,
	id string,
) (*vnextOwnerTestFixture, vnextOwnerReclaimRequest) {
	t.Helper()
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "reclaim-device-" + id,
		Size: 256 << 10,
	}})
	allocation := vnextOwnerMemoryRequest(id, 1, 1)
	grant, err := fixture.group.reserve(allocation)
	if err != nil {
		t.Fatalf("reserve reclaim fixture: %v", err)
	}
	writeAllVNextOwnerPages(t, fixture.group, grant, 1)
	if err := fixture.group.commit(grant); err != nil {
		t.Fatalf("commit reclaim fixture: %v", err)
	}
	request, err := vnextOwnerTestReclaimRequest(
		fixture.group,
		allocation.CheckpointID,
		grant.AllocationRecordID,
		"reclaim-request-"+id)
	if err != nil {
		t.Fatal(err)
	}
	request.RetirementEpoch = 11
	request.CatalogRevisionBarrier = 29
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReclaim, request)
	return fixture, request
}

func TestVNextOwnerReclaimRootUsesV6PublicationBoundNotSealFrameBound(t *testing.T) {
	_, request := vnextOwnerTestCommittedReclaim(t, "root-publication-bound")

	aboveSealFrame := uint64(vnextOwnerRPCMaxPublicationBytes + 1)
	request.ExpectedCheckpointRoot.Locator.PublicationByteLength = aboveSealFrame
	request.ExpectedCheckpointRoot.Locator.PageRuns[0].PageCount =
		(aboveSealFrame + cxlcheckpoint.PageSize - 1) / cxlcheckpoint.PageSize
	if err := validateVNextOwnerCheckpointRoot(
		request.Allocation, request.ExpectedCheckpointRoot); err != nil {
		t.Fatalf("V6 root above the seal frame limit was rejected: %v", err)
	}

	maxPublication := uint64(cxlcheckpoint.MaxPayloadBytes) +
		uint64(cxlcheckpoint.PublicationEnvelopeHeaderBytes)
	request.ExpectedCheckpointRoot.Locator.PublicationByteLength = maxPublication
	request.ExpectedCheckpointRoot.Locator.PageRuns[0].PageCount =
		(maxPublication + cxlcheckpoint.PageSize - 1) / cxlcheckpoint.PageSize
	if err := validateVNextOwnerCheckpointRoot(
		request.Allocation, request.ExpectedCheckpointRoot); err != nil {
		t.Fatalf("maximum V6 root publication was rejected: %v", err)
	}

	request.ExpectedCheckpointRoot.Locator.PublicationByteLength = maxPublication + 1
	request.ExpectedCheckpointRoot.Locator.PageRuns[0].PageCount =
		(maxPublication + cxlcheckpoint.PageSize) / cxlcheckpoint.PageSize
	if err := validateVNextOwnerCheckpointRoot(
		request.Allocation, request.ExpectedCheckpointRoot); err == nil {
		t.Fatal("root beyond the V6 publication bound was accepted")
	}
}

func TestVNextOwnerReclaimRootAcceptsExactly256PageRuns(t *testing.T) {
	_, request := vnextOwnerTestCommittedReclaim(t, "root-page-run-bound")
	if vnextOwnerRPCMaxExtents != 256 {
		t.Fatalf("V6 root PageRun bound = %d, want 256", vnextOwnerRPCMaxExtents)
	}

	firstPage := request.ExpectedCheckpointRoot.Locator.PageRuns[0].FirstPage
	pageRuns := make([]vnextOwnerPublicationPageRun, vnextOwnerRPCMaxExtents)
	for index := range pageRuns {
		page := firstPage
		page.DataPageIndex = uint64(index * 2)
		pageRuns[index] = vnextOwnerPublicationPageRun{
			FirstPage: page,
			PageCount: 1,
		}
	}
	request.ExpectedCheckpointRoot.Locator.PublicationByteLength =
		uint64(len(pageRuns)) * cxlcheckpoint.PageSize
	request.ExpectedCheckpointRoot.Locator.PageRuns = pageRuns
	if err := validateVNextOwnerCheckpointRoot(
		request.Allocation, request.ExpectedCheckpointRoot); err != nil {
		t.Fatalf("V6 root with exactly 256 PageRuns was rejected: %v", err)
	}

	nextPage := firstPage
	nextPage.DataPageIndex = uint64(len(pageRuns) * 2)
	request.ExpectedCheckpointRoot.Locator.PageRuns = append(
		request.ExpectedCheckpointRoot.Locator.PageRuns,
		vnextOwnerPublicationPageRun{FirstPage: nextPage, PageCount: 1})
	request.ExpectedCheckpointRoot.Locator.PublicationByteLength += cxlcheckpoint.PageSize
	if err := validateVNextOwnerCheckpointRoot(
		request.Allocation, request.ExpectedCheckpointRoot); err == nil {
		t.Fatal("V6 root with 257 PageRuns was accepted")
	}
}

func vnextOwnerTestReclaimStatusRequest(
	reclaim vnextOwnerReclaimRequest,
	requestID string,
) vnextOwnerReclaimStatusAndFenceRequest {
	verified := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReclaim, reclaim)
	request := vnextOwnerReclaimStatusAndFenceRequest{
		RequestID:                     requestID,
		Allocation:                    reclaim.Allocation,
		ExpectedReclaimRequestID:      reclaim.RequestID,
		ExpectedReclaimRequestDigest:  verified.MutationDigest,
		ExpectedReclaimSchedulerProof: verified.proof(),
	}
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReclaimStatusAndFence, request)
	return request
}

func vnextOwnerTestStageReclaiming(
	t *testing.T,
	fixture *vnextOwnerTestFixture,
	request vnextOwnerReclaimRequest,
) {
	t.Helper()
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReclaim, request)
	fixture.group.mu.Lock()
	defer fixture.group.mu.Unlock()
	candidate := fixture.group.journal.clone()
	transaction := candidate.Transactions[request.Allocation.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted ||
		transaction.Reclaim != nil {
		t.Fatalf("cannot stage RECLAIMING from transaction %#v", transaction)
	}
	transaction.State = vnextOwnerReclaiming
	transaction.Reclaim = &vnextOwnerReclaimRecord{
		RequestID:                        request.RequestID,
		RequestDigest:                    authority.MutationDigest,
		Allocation:                       request.Allocation,
		ExpectedCheckpointRoot:           cloneVNextOwnerCheckpointRoot(request.ExpectedCheckpointRoot),
		RetirementEpoch:                  request.RetirementEpoch,
		CatalogRevisionBarrier:           request.CatalogRevisionBarrier,
		ActiveRestoreCount:               request.ActiveRestoreCount,
		ReaderDrainEvidenceDigest:        request.ReaderDrainEvidenceDigest,
		ProducerWriteFenceEvidenceDigest: request.ProducerWriteFenceEvidenceDigest,
		DedupReferenceDispositionDigest:  request.DedupReferenceDispositionDigest,
		SchedulerProof:                   authority.proof(),
	}
	if err := fixture.group.applySchedulerAuthorityLocked(candidate, authority); err != nil {
		t.Fatalf("stage RECLAIMING Scheduler authority: %v", err)
	}
	if err := fixture.group.persistJournalLocked(candidate); err != nil {
		t.Fatalf("persist staged RECLAIMING journal: %v", err)
	}
}

func vnextOwnerTestReclaimStatusClient(
	t *testing.T,
	service *vnextOwnerService,
	request vnextOwnerReclaimStatusAndFenceRequest,
	mutate func(execResponse) execResponse,
) (vnextOwnerReclaimStatusAndFenceResponse, error) {
	t.Helper()
	rpc := newVNextOwnerRPC(service)
	transport := vnextOwnerClientRoundTripFunc(func(
		ctx context.Context,
		envelope daemonRequest,
	) (execResponse, error) {
		if err := ctx.Err(); err != nil {
			return execResponse{}, err
		}
		response := runCommandWithVNextOwnerRPCTestRole(envelope, rpc)
		if mutate != nil {
			response = mutate(response)
		}
		return response, nil
	})
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatalf("create strict Owner status client: %v", err)
	}
	return client.ReclaimStatusAndFence(context.Background(), request)
}

func vnextOwnerTestRewriteReclaimStatusObject(
	t *testing.T,
	response execResponse,
	mutate func(map[string]json.RawMessage),
) execResponse {
	t.Helper()
	if !response.Ok {
		t.Fatalf("cannot rewrite failed status response: %#v", response)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal([]byte(response.Stdout), &object); err != nil {
		t.Fatalf("decode status response for rewrite: %v", err)
	}
	mutate(object)
	encoded, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("encode rewritten status response: %v", err)
	}
	response.Stdout = string(encoded) + "\n"
	return response
}

func vnextOwnerTestRewriteReclaimStatusWire(
	t *testing.T,
	response execResponse,
	mutate func(*vnextOwnerRPCReclaimStatusAndFenceResponse),
) execResponse {
	t.Helper()
	if !response.Ok {
		t.Fatalf("cannot rewrite failed status response: %#v", response)
	}
	var wire vnextOwnerRPCReclaimStatusAndFenceResponse
	if err := json.Unmarshal([]byte(response.Stdout), &wire); err != nil {
		t.Fatalf("decode status response for semantic rewrite: %v", err)
	}
	mutate(&wire)
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatalf("encode rewritten status response: %v", err)
	}
	response.Stdout = string(encoded) + "\n"
	return response
}

func TestVNextOwnerReclaimSchedulerDigestBindsEverySafetyField(t *testing.T) {
	_, request := vnextOwnerTestCommittedReclaim(t, "digest")
	want, err := vnextOwnerSchedulerMutationDigest(
		vnextOwnerRPCOperationReclaim, request)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*vnextOwnerReclaimRequest){
		"independent request ID": func(candidate *vnextOwnerReclaimRequest) {
			candidate.RequestID += "-other"
		},
		"allocation identity": func(candidate *vnextOwnerReclaimRequest) {
			candidate.Allocation.CheckpointID += "-other"
		},
		"expected root": func(candidate *vnextOwnerReclaimRequest) {
			candidate.ExpectedCheckpointRoot.RootVersion++
		},
		"retirement epoch": func(candidate *vnextOwnerReclaimRequest) {
			candidate.RetirementEpoch++
		},
		"catalog barrier": func(candidate *vnextOwnerReclaimRequest) {
			candidate.CatalogRevisionBarrier++
		},
		"active restore count": func(candidate *vnextOwnerReclaimRequest) {
			candidate.ActiveRestoreCount = 1
		},
		"reader drain": func(candidate *vnextOwnerReclaimRequest) {
			candidate.ReaderDrainEvidenceDigest[0]++
		},
		"producer fence": func(candidate *vnextOwnerReclaimRequest) {
			candidate.ProducerWriteFenceEvidenceDigest[0]++
		},
		"dedup disposition": func(candidate *vnextOwnerReclaimRequest) {
			candidate.DedupReferenceDispositionDigest[0]++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := request
			candidate.ExpectedCheckpointRoot = cloneVNextOwnerCheckpointRoot(
				request.ExpectedCheckpointRoot)
			mutate(&candidate)
			got, err := vnextOwnerSchedulerMutationDigest(
				vnextOwnerRPCOperationReclaim, candidate)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("reclaim mutation digest did not bind changed field")
			}
		})
	}
}

func TestVNextOwnerReclaimClientRPCReplayAndStatusFence(t *testing.T) {
	fixture, request := vnextOwnerTestCommittedReclaim(t, "client")
	service := newVNextOwnerServiceForFixture(t, fixture)
	transport := &vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(service),
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.ReclaimVNextCheckpoint(context.Background(), request)
	if err != nil {
		t.Fatalf("reclaim through strict client/RPC: %v", err)
	}
	if first.Replayed || first.OwnerJournalSequence == 0 ||
		vnextAllZero(first.OwnerReceipt[:]) ||
		first.RequestDigest != first.SchedulerProof.MutationDigest {
		t.Fatalf("first reclaim lacks terminal evidence: %#v", first)
	}
	replay, err := client.ReclaimVNextCheckpoint(context.Background(), request)
	if err != nil {
		t.Fatalf("exact reclaim replay: %v", err)
	}
	if !replay.Replayed || replay.OwnerJournalSequence != first.OwnerJournalSequence ||
		replay.OwnerReceipt != first.OwnerReceipt ||
		replay.SchedulerProof != first.SchedulerProof {
		t.Fatalf("reclaim replay changed terminal evidence: %#v / %#v", first, replay)
	}
	statusRequest := vnextOwnerReclaimStatusAndFenceRequest{
		RequestID:                     "reclaim-status-client",
		Allocation:                    request.Allocation,
		ExpectedReclaimRequestID:      request.RequestID,
		ExpectedReclaimRequestDigest:  first.RequestDigest,
		ExpectedReclaimSchedulerProof: first.SchedulerProof,
	}
	statusRequest.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReclaimStatusAndFence, statusRequest)
	status, err := client.ReclaimStatusAndFence(context.Background(), statusRequest)
	if err != nil {
		t.Fatalf("reclaim status-and-fence through strict client/RPC: %v", err)
	}
	if status.State != vnextOwnerReclaimDone || status.Reclaim == nil ||
		status.SnapshotSequence < first.OwnerJournalSequence ||
		status.Reclaim.OwnerJournalSequence != first.OwnerJournalSequence ||
		status.Reclaim.OwnerReceipt != first.OwnerReceipt ||
		status.Reclaim.SchedulerProof != first.SchedulerProof {
		t.Fatalf("status did not return exact terminal evidence: %#v", status)
	}
	conflict := request
	conflict.CatalogRevisionBarrier++
	conflict.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReclaim, conflict)
	if _, err := client.ReclaimVNextCheckpoint(
		context.Background(), conflict); err == nil {
		t.Fatal("same reclaim ID with a different signed body was accepted")
	}
	if len(transport.requests) != 4 ||
		len(transport.requests[0].VNextOwnerReclaim) == 0 ||
		len(transport.requests[2].VNextOwnerReclaimStatusAndFence) == 0 {
		t.Fatalf("strict daemon envelope did not retain reclaim payloads: %#v",
			transport.requests)
	}
}

func TestVNextOwnerReclaimStatusAndFenceStrictRPCAllStates(t *testing.T) {
	tests := []struct {
		name string
		want vnextOwnerReclaimStatus
	}{
		{name: "not-found", want: vnextOwnerReclaimNotFound},
		{name: "conflict", want: vnextOwnerReclaimConflict},
		{name: "reclaiming", want: vnextOwnerReclaimInProgress},
		{name: "reclaimed", want: vnextOwnerReclaimDone},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, reclaim := vnextOwnerTestCommittedReclaim(
				t, "status-"+test.name)
			var terminalSequence uint64
			switch test.want {
			case vnextOwnerReclaimConflict, vnextOwnerReclaimDone:
				record, replayed, err := fixture.group.reclaimCheckpointWithScheduler(
					reclaim,
					vnextOwnerTestVerifiedAuthority(
						vnextOwnerRPCOperationReclaim, reclaim))
				if err != nil || replayed {
					t.Fatalf("prepare terminal reclaim: record=%#v replayed=%v err=%v",
						record, replayed, err)
				}
				terminalSequence = record.TerminalJournalSequence
			case vnextOwnerReclaimInProgress:
				vnextOwnerTestStageReclaiming(t, fixture, reclaim)
			}

			statusRequest := vnextOwnerTestReclaimStatusRequest(
				reclaim, "status-query-"+test.name)
			if test.want == vnextOwnerReclaimConflict {
				statusRequest.ExpectedReclaimRequestID += "-different"
				statusRequest.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
					vnextOwnerRPCOperationReclaimStatusAndFence, statusRequest)
			}
			status, err := vnextOwnerTestReclaimStatusClient(
				t,
				newVNextOwnerServiceForFixture(t, fixture),
				statusRequest,
				nil)
			if err != nil {
				t.Fatalf("strict %s status round trip: %v", test.want, err)
			}
			if status.State != test.want || status.SnapshotSequence == 0 ||
				status.FenceCreateRevision !=
					statusRequest.SchedulerAuthority.CreateRevision {
				t.Fatalf("unexpected strict status response: %#v", status)
			}
			if test.want != vnextOwnerReclaimDone {
				if status.Reclaim != nil {
					t.Fatalf("nonterminal status exposed reclaim evidence: %#v", status)
				}
				return
			}
			if status.Reclaim == nil ||
				status.Reclaim.OwnerJournalSequence != terminalSequence ||
				status.SnapshotSequence < terminalSequence {
				t.Fatalf("terminal status omitted durable evidence: %#v", status)
			}
		})
	}
}

func TestVNextOwnerReclaimStatusClientRejectsMalformedStrictJSON(t *testing.T) {
	tests := []struct {
		name    string
		wantErr string
		mutate  func(*testing.T, execResponse) execResponse
	}{
		{
			name:    "omitted required field",
			wantErr: "decode strict VNext Owner",
			mutate: func(t *testing.T, response execResponse) execResponse {
				return vnextOwnerTestRewriteReclaimStatusObject(
					t, response, func(object map[string]json.RawMessage) {
						delete(object, "hasReclaim")
					})
			},
		},
		{
			name:    "null nested reclaim",
			wantErr: "decode strict VNext Owner",
			mutate: func(t *testing.T, response execResponse) execResponse {
				return vnextOwnerTestRewriteReclaimStatusObject(
					t, response, func(object map[string]json.RawMessage) {
						object["reclaim"] = json.RawMessage("null")
					})
			},
		},
		{
			name:    "unknown field",
			wantErr: "decode strict VNext Owner",
			mutate: func(t *testing.T, response execResponse) execResponse {
				return vnextOwnerTestRewriteReclaimStatusObject(
					t, response, func(object map[string]json.RawMessage) {
						object["unknown"] = json.RawMessage("true")
					})
			},
		},
		{
			name:    "duplicate field",
			wantErr: "decode strict VNext Owner",
			mutate: func(t *testing.T, response execResponse) execResponse {
				t.Helper()
				if !response.Ok {
					t.Fatalf("cannot duplicate field in failed response: %#v", response)
				}
				raw := strings.TrimSpace(response.Stdout)
				if !strings.HasSuffix(raw, "}") {
					t.Fatalf("status response is not a JSON object: %q", raw)
				}
				response.Stdout = strings.TrimSuffix(raw, "}") +
					`,"hasReclaim":false}` + "\n"
				return response
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture, reclaim := vnextOwnerTestCommittedReclaim(
				t, "malformed-"+strings.ReplaceAll(test.name, " ", "-"))
			request := vnextOwnerTestReclaimStatusRequest(
				reclaim, "malformed-query-"+strings.ReplaceAll(test.name, " ", "-"))
			_, err := vnextOwnerTestReclaimStatusClient(
				t,
				newVNextOwnerServiceForFixture(t, fixture),
				request,
				func(response execResponse) execResponse {
					return test.mutate(t, response)
				})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("malformed status error = %v, want substring %q",
					err, test.wantErr)
			}
		})
	}
}

func TestVNextOwnerReclaimStatusClientRejectsSemanticTampering(t *testing.T) {
	tests := []struct {
		name     string
		terminal bool
		wantErr  string
		mutate   func(*vnextOwnerRPCReclaimStatusAndFenceResponse)
	}{
		{
			name:    "hasReclaim state mismatch",
			wantErr: "identity, state, or fence is invalid",
			mutate: func(wire *vnextOwnerRPCReclaimStatusAndFenceResponse) {
				wire.HasReclaim = true
			},
		},
		{
			name:    "nonzero reclaim when absent",
			wantErr: "non-terminal reclaim status exposed terminal evidence",
			mutate: func(wire *vnextOwnerRPCReclaimStatusAndFenceResponse) {
				wire.Reclaim.Protocol = vnextOwnerRPCProtocol
			},
		},
		{
			name:    "wrong fence revision",
			wantErr: "identity, state, or fence is invalid",
			mutate: func(wire *vnextOwnerRPCReclaimStatusAndFenceResponse) {
				wire.FenceCreateRevision++
			},
		},
		{
			name:     "snapshot predates terminal sequence",
			terminal: true,
			wantErr:  "snapshot predates terminal Owner evidence",
			mutate: func(wire *vnextOwnerRPCReclaimStatusAndFenceResponse) {
				wire.SnapshotSequence = wire.Reclaim.OwnerJournalSequence - 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id := "tamper-" + strings.ReplaceAll(test.name, " ", "-")
			fixture, reclaim := vnextOwnerTestCommittedReclaim(t, id)
			if test.terminal {
				if _, _, err := fixture.group.reclaimCheckpointWithScheduler(
					reclaim,
					vnextOwnerTestVerifiedAuthority(
						vnextOwnerRPCOperationReclaim, reclaim)); err != nil {
					t.Fatalf("prepare terminal reclaim: %v", err)
				}
			}
			request := vnextOwnerTestReclaimStatusRequest(
				reclaim, "tamper-query-"+strings.ReplaceAll(test.name, " ", "-"))
			_, err := vnextOwnerTestReclaimStatusClient(
				t,
				newVNextOwnerServiceForFixture(t, fixture),
				request,
				func(response execResponse) execResponse {
					return vnextOwnerTestRewriteReclaimStatusWire(
						t, response, test.mutate)
				})
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("tampered status error = %v, want substring %q",
					err, test.wantErr)
			}
		})
	}
}

func TestVNextOwnerReclaimFormatRoundTripAndReceiptTamperFailClosed(t *testing.T) {
	fixture, request := vnextOwnerTestCommittedReclaim(t, "format")
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReclaim, request)
	record, replayed, err := fixture.group.reclaimCheckpointWithScheduler(
		request, authority)
	if err != nil || replayed {
		t.Fatalf("signed reclaim failed: record=%#v replayed=%v err=%v",
			record, replayed, err)
	}
	encoded, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatalf("marshal TROWN010 reclaim journal: %v", err)
	}
	decoded, err := parseVNextOwnerJournal(encoded, fixture.group.devices)
	if err != nil {
		t.Fatalf("parse TROWN010 reclaim journal: %v", err)
	}
	decodedRecord := decoded.Transactions[request.Allocation.AllocationRecordID].Reclaim
	if !reflect.DeepEqual(decodedRecord, record) {
		t.Fatalf("TROWN010 reclaim record changed: %#v / %#v", record, decodedRecord)
	}
	tampered := fixture.group.journal.clone()
	tampered.Transactions[request.Allocation.AllocationRecordID].Reclaim.OwnerReceipt[0] ^= 0xff
	if _, err := tampered.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices); err == nil {
		t.Fatal("TROWN010 encoder accepted a tampered Owner reclaim receipt")
	}
}

func TestVNextOwnerReclaimServiceRejectsUndrainedOrUnfencedEvidence(t *testing.T) {
	fixture, request := vnextOwnerTestCommittedReclaim(t, "gates")
	service := newVNextOwnerServiceForFixture(t, fixture)
	caller := vnextOwnerTestSchedulerCaller

	undrained := request
	undrained.ActiveRestoreCount = 1
	undrained.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReclaim, undrained)
	_, err := service.reclaimScheduler(undrained, caller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceInvalidRequest)

	unfenced := request
	unfenced.ProducerWriteFenceEvidenceDigest = [32]byte{}
	unfenced.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReclaim, unfenced)
	_, err = service.reclaimScheduler(unfenced, caller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceInvalidRequest)

	fixture.group.mu.Lock()
	state := fixture.group.journal.Transactions[request.Allocation.AllocationRecordID].State
	fixture.group.mu.Unlock()
	if state != vnextOwnerCommitted {
		t.Fatalf("invalid reclaim request changed transaction state to %d", state)
	}
}

func TestVNextOwnerReclaimExactGroupReplayRejectsDifferentBody(t *testing.T) {
	fixture, request := vnextOwnerTestCommittedReclaim(t, "conflict")
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReclaim, request)
	if _, _, err := fixture.group.reclaimCheckpointWithScheduler(
		request, authority); err != nil {
		t.Fatal(err)
	}
	conflict := request
	conflict.ReaderDrainEvidenceDigest[0]++
	conflictAuthority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReclaim, conflict)
	if _, _, err := fixture.group.reclaimCheckpointWithScheduler(
		conflict, conflictAuthority); !errors.Is(
		err, errVNextOwnerSchedulerReceiptConflict) {
		t.Fatalf("different reclaim body returned %v", err)
	}
}
