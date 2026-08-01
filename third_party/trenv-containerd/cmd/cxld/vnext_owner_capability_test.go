package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	vnextOwnerTestSchedulerCaller = vnextOwnerCallerContext{
		Role:      vnextOwnerCallerScheduler,
		Principal: "spiffe://trenv.test/scheduler/scheduler-0",
	}
	vnextOwnerTestProducerCaller = vnextOwnerCallerContext{
		Role:      vnextOwnerCallerProducer,
		Principal: "spiffe://trenv.test/producer/node-0",
	}
)

func vnextOwnerTestCapabilityIssueRequest(
	identity vnextOwnerOperationIdentity,
	operations vnextProducerCapabilityOperations,
) vnextOwnerIssueProducerCapabilityRequest {
	nonce := sha256.Sum256([]byte(fmt.Sprintf(
		"vnext-owner-test-capability/%s/%d/%d",
		identity.CheckpointID, identity.AllocationRecordID, operations)))
	return vnextOwnerIssueProducerCapabilityRequest{
		RequestID: fmt.Sprintf(
			"test-capability-%d-%d", identity.AllocationRecordID, operations),
		Operation:          identity,
		ProducerPrincipal:  vnextOwnerTestProducerCaller.Principal,
		AllowedOperations:  operations,
		SchedulerTerm:      "test-scheduler/session-1/term-1",
		RequestedTTLMillis: 60 * 60 * 1000,
		Nonce:              nonce,
	}
}

func issueVNextOwnerTestCapability(
	t *testing.T,
	service *vnextOwnerService,
	identity vnextOwnerOperationIdentity,
	operations vnextProducerCapabilityOperations,
) vnextProducerCapabilityProof {
	t.Helper()
	response, err := service.issueProducerCapability(
		vnextOwnerTestCapabilityIssueRequest(identity, operations),
		vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("issue test Producer capability: %v", err)
	}
	return response.Capability
}

func sealVNextOwnerServiceForTest(
	t *testing.T,
	service *vnextOwnerService,
	request vnextOwnerExternalSealRequest,
) (vnextOwnerSealResponse, error) {
	t.Helper()
	if request.Capability.CapabilityID == "" {
		request.Capability = issueVNextOwnerTestCapability(
			t, service, request.Operation, vnextProducerCapabilityAll)
	}
	return service.sealExternal(request, vnextOwnerTestProducerCaller)
}

func vnextOwnerCapabilityPersistentState(
	t *testing.T,
	group *vnextOwnerGroup,
) []byte {
	t.Helper()
	image := vnextOwnerStatusTestPersistentImage(t, group)
	group.mu.Lock()
	deviceOrder := append([]string(nil), group.deviceOrder...)
	devices := make(map[string]*vnextPersistentDevice, len(deviceOrder))
	for _, deviceUUID := range deviceOrder {
		devices[deviceUUID] = group.devices[deviceUUID]
	}
	group.mu.Unlock()
	for _, deviceUUID := range deviceOrder {
		device := devices[deviceUUID]
		device.mu.Lock()
		descriptors := make([]byte, int(device.superblock.Geometry.DescriptorRegionBytes))
		err := vnextReadAtFull(
			device.storage, descriptors, device.superblock.Geometry.DescriptorRegionBase)
		device.mu.Unlock()
		if err != nil {
			t.Fatalf("read capability-test descriptors for %q: %v", deviceUUID, err)
		}
		image = append(image, descriptors...)
	}
	return image
}

func assertVNextOwnerIssueReplayIsExactAndReadOnly(
	t *testing.T,
	service *vnextOwnerService,
	request vnextOwnerIssueProducerCapabilityRequest,
	issued vnextOwnerIssueProducerCapabilityResponse,
) {
	t.Helper()
	beforeSequence := service.group.journal.SnapshotSequence
	replayed, err := service.issueProducerCapability(request, vnextOwnerTestSchedulerCaller)
	want := issued
	want.Replayed = true
	if err != nil || replayed != want {
		t.Fatalf("exact issue replay changed persisted response: %#v / %v; want %#v",
			replayed, err, want)
	}
	if service.group.journal.SnapshotSequence != beforeSequence {
		t.Fatal("exact issue replay mutated the Owner journal")
	}
}

func TestVNextProducerCapabilityIssueReplayRestartAndNoBearerLeak(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "capability-replay-device", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	now := time.Unix(1_700_000_000, 123)
	service.now = func() time.Time { return now }
	reserveRequest := vnextOwnerStatusTestRequest("capability-replay", 2)
	reserved, err := service.reserve(reserveRequest)
	if err != nil {
		t.Fatal(err)
	}
	request := vnextOwnerTestCapabilityIssueRequest(
		reserved.Operation, vnextProducerCapabilityAll)
	beforeIssueSequence := fixture.group.journal.SnapshotSequence
	issued, err := service.issueProducerCapability(request, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("issue Producer capability: %v", err)
	}
	wantIssuedAt := uint64(now.UnixNano())
	wantExpiry := wantIssuedAt + request.RequestedTTLMillis*uint64(time.Millisecond)
	if issued.Replayed || issued.RequestID != request.RequestID ||
		issued.Operation != reserved.Operation ||
		issued.ProducerPrincipal != request.ProducerPrincipal ||
		issued.AllowedOperations != request.AllowedOperations ||
		issued.SchedulerTerm != request.SchedulerTerm ||
		issued.IssuedAtUnixNano != wantIssuedAt || issued.ExpiresAtUnixNano != wantExpiry ||
		issued.Capability.Token != request.Nonce {
		t.Fatalf("unexpected issued capability: %#v", issued)
	}
	if fixture.group.journal.SnapshotSequence != beforeIssueSequence+1 {
		t.Fatalf("capability issuance sequence=%d, want %d",
			fixture.group.journal.SnapshotSequence, beforeIssueSequence+1)
	}

	journalBytes, err := fixture.group.journal.marshalAtSequence(
		fixture.group.journal.SnapshotSequence, fixture.group.devices)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(journalBytes, request.Nonce[:]) {
		t.Fatal("Owner journal contains the plaintext Producer bearer nonce")
	}
	status, err := service.reservationStatus(reserveRequest)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]interface{}{
		"reserve": reserved,
		"status":  status,
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range [][]byte{
			[]byte(`"Capability":`), []byte(`"capability":`),
			[]byte(`"Token":`), []byte(`"token":`),
		} {
			if bytes.Contains(raw, forbidden) {
				t.Fatalf("%s response exposes capability material: %s", name, raw)
			}
		}
	}

	beforeReplaySequence := fixture.group.journal.SnapshotSequence
	replayed, err := service.issueProducerCapability(request, vnextOwnerTestSchedulerCaller)
	if err != nil || !replayed.Replayed || replayed.Capability != issued.Capability ||
		replayed.IssuedAtUnixNano != issued.IssuedAtUnixNano ||
		replayed.ExpiresAtUnixNano != issued.ExpiresAtUnixNano {
		t.Fatalf("exact issue replay changed response: %#v / %v", replayed, err)
	}
	if fixture.group.journal.SnapshotSequence != beforeReplaySequence {
		t.Fatal("exact issue replay advanced the Owner journal")
	}

	if _, err := service.setAdmission(vnextOwnerSetAdmissionRequest{
		RequestID:        "capability-replay-close-admission",
		OwnerID:          reserved.Operation.OwnerID,
		OwnerEpoch:       reserved.Operation.OwnerEpoch,
		From:             vnextOwnerAdmissionActive,
		Target:           vnextOwnerAdmissionReadOnly,
		ExpectedSequence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	closedSequence := fixture.group.journal.SnapshotSequence
	replayed, err = service.issueProducerCapability(request, vnextOwnerTestSchedulerCaller)
	if err != nil || !replayed.Replayed || replayed.Capability != issued.Capability {
		t.Fatalf("closed-admission exact replay failed: %#v / %v", replayed, err)
	}
	if fixture.group.journal.SnapshotSequence != closedSequence {
		t.Fatal("closed-admission exact replay mutated the journal")
	}
	for name, mutate := range map[string]func(*vnextOwnerIssueProducerCapabilityRequest){
		"request ID": func(conflict *vnextOwnerIssueProducerCapabilityRequest) {
			conflict.RequestID += "-other"
		},
		"nonce": func(conflict *vnextOwnerIssueProducerCapabilityRequest) {
			conflict.Nonce[0] ^= 0xff
		},
		"principal": func(conflict *vnextOwnerIssueProducerCapabilityRequest) {
			conflict.ProducerPrincipal = "spiffe://trenv.test/producer/node-1"
		},
		"operation": func(conflict *vnextOwnerIssueProducerCapabilityRequest) {
			conflict.AllowedOperations = vnextProducerCapabilitySeal
		},
		"Scheduler term": func(conflict *vnextOwnerIssueProducerCapabilityRequest) {
			conflict.SchedulerTerm = "test-scheduler/other-session/term-0"
		},
	} {
		t.Run("conflicting "+name, func(t *testing.T) {
			conflict := request
			mutate(&conflict)
			_, err := service.issueProducerCapability(
				conflict, vnextOwnerTestSchedulerCaller)
			requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityConflict)
			if fixture.group.journal.SnapshotSequence != closedSequence {
				t.Fatal("conflicting issue retry mutated the journal")
			}
		})
	}

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	restarted.now = func() time.Time { return now.Add(time.Minute) }
	restartedReplay, err := restarted.issueProducerCapability(
		request, vnextOwnerTestSchedulerCaller)
	if err != nil || !restartedReplay.Replayed ||
		restartedReplay.Capability != issued.Capability ||
		restartedReplay.IssuedAtUnixNano != issued.IssuedAtUnixNano ||
		restartedReplay.ExpiresAtUnixNano != issued.ExpiresAtUnixNano {
		t.Fatalf("restart issue replay changed durable proof: %#v / %v", restartedReplay, err)
	}
}

func TestVNextProducerCapabilityIssueReplaySurvivesLifecycleProgress(t *testing.T) {
	t.Run("committed", func(t *testing.T) {
		fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
		service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Unix(1_700_010_000, 0)
		service.now = func() time.Time { return now }
		identity := vnextOwnerServiceIdentity(fixture.grant)
		request := vnextOwnerTestCapabilityIssueRequest(
			identity, vnextProducerCapabilityAll)
		issued, err := service.issueProducerCapability(
			request, vnextOwnerTestSchedulerCaller)
		if err != nil {
			t.Fatal(err)
		}
		externalRecords := vnextPrepareCompleteExternalContent(t, fixture)
		envelope, err := cxlcheckpoint.Encode(fixture.publication)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := service.sealExternal(vnextOwnerExternalSealRequest{
			Operation:               identity,
			Capability:              issued.Capability,
			PublicationEnvelope:     envelope,
			CRCPageSidecars:         fixture.cloneSidecars(),
			ExternalContentPageCRCs: externalRecords,
		}, vnextOwnerTestProducerCaller); err != nil {
			t.Fatalf("seal before COMMITTED replay: %v", err)
		}
		if err := service.commit(identity); err != nil {
			t.Fatalf("commit before issue replay: %v", err)
		}
		assertVNextOwnerIssueReplayIsExactAndReadOnly(t, service, request, issued)

		fixture.owner.reopen(t)
		restarted := newVNextOwnerServiceForFixture(t, fixture.owner)
		restarted.now = func() time.Time { return now.Add(2 * time.Hour) }
		assertVNextOwnerIssueReplayIsExactAndReadOnly(t, restarted, request, issued)
	})

	t.Run("aborted", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "capability-replay-aborted", Size: 256 << 10,
		}})
		service := newVNextOwnerServiceForFixture(t, fixture)
		now := time.Unix(1_700_020_000, 0)
		service.now = func() time.Time { return now }
		reserved, err := service.reserve(vnextOwnerStatusTestRequest(
			"capability-replay-aborted", 1))
		if err != nil {
			t.Fatal(err)
		}
		request := vnextOwnerTestCapabilityIssueRequest(
			reserved.Operation, vnextProducerCapabilityAll)
		issued, err := service.issueProducerCapability(
			request, vnextOwnerTestSchedulerCaller)
		if err != nil {
			t.Fatal(err)
		}
		if err := service.abort(reserved.Operation); err != nil {
			t.Fatalf("abort before issue replay: %v", err)
		}
		assertVNextOwnerIssueReplayIsExactAndReadOnly(t, service, request, issued)

		fixture.reopen(t)
		restarted := newVNextOwnerServiceForFixture(t, fixture)
		restarted.now = func() time.Time { return now.Add(2 * time.Hour) }
		assertVNextOwnerIssueReplayIsExactAndReadOnly(t, restarted, request, issued)
	})

	t.Run("revoked", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "capability-replay-revoked", Size: 256 << 10,
		}})
		service := newVNextOwnerServiceForFixture(t, fixture)
		now := time.Unix(1_700_030_000, 0)
		service.now = func() time.Time { return now }
		reserved, err := service.reserve(vnextOwnerStatusTestRequest(
			"capability-replay-revoked", 1))
		if err != nil {
			t.Fatal(err)
		}
		request := vnextOwnerTestCapabilityIssueRequest(
			reserved.Operation, vnextProducerCapabilityAll)
		issued, err := service.issueProducerCapability(
			request, vnextOwnerTestSchedulerCaller)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
		if _, err := service.revokeProducerCapability(
			vnextOwnerRevokeProducerCapabilityRequest{
				RequestID:     "capability-replay-revoked-request",
				Operation:     reserved.Operation,
				CapabilityID:  issued.Capability.CapabilityID,
				SchedulerTerm: "test-scheduler/session-1/term-2",
			},
			vnextOwnerTestSchedulerCaller); err != nil {
			t.Fatalf("revoke before issue replay: %v", err)
		}
		assertVNextOwnerIssueReplayIsExactAndReadOnly(t, service, request, issued)

		fixture.reopen(t)
		restarted := newVNextOwnerServiceForFixture(t, fixture)
		restarted.now = func() time.Time { return now.Add(2 * time.Hour) }
		assertVNextOwnerIssueReplayIsExactAndReadOnly(t, restarted, request, issued)
	})
}

func TestVNextProducerCapabilityValidationIsExactAndOwnerClockBound(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "capability-validation-device", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	now := time.Unix(1_700_100_000, 0)
	service.now = func() time.Time { return now }
	reserved, err := service.reserve(vnextOwnerStatusTestRequest("capability-validation", 1))
	if err != nil {
		t.Fatal(err)
	}
	request := vnextOwnerTestCapabilityIssueRequest(
		reserved.Operation, vnextProducerCapabilitySeal)
	issued, err := service.issueProducerCapability(request, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatal(err)
	}
	issuedAt := issued.IssuedAtUnixNano
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeFree := fixture.devices[0].allocator.freePages()
	if err := fixture.group.validateProducerCapability(
		reserved.Operation, issued.Capability, request.ProducerPrincipal,
		vnextProducerCapabilitySeal, issuedAt); err != nil {
		t.Fatalf("valid exact Producer capability was rejected: %v", err)
	}

	tests := []struct {
		name      string
		identity  vnextOwnerOperationIdentity
		proof     vnextProducerCapabilityProof
		principal string
		operation vnextProducerCapabilityOperations
		now       uint64
		want      error
	}{
		{
			name: "wrong principal", identity: reserved.Operation,
			proof: issued.Capability, principal: "spiffe://trenv.test/producer/node-1",
			operation: vnextProducerCapabilitySeal, now: issuedAt,
			want: errVNextProducerCapabilityDenied,
		},
		{
			name: "wrong operation", identity: reserved.Operation,
			proof: issued.Capability, principal: request.ProducerPrincipal,
			operation: vnextProducerCapabilityAbort, now: issuedAt,
			want: errVNextProducerCapabilityDenied,
		},
		{
			name: "stale Owner epoch", identity: func() vnextOwnerOperationIdentity {
				identity := reserved.Operation
				identity.OwnerEpoch++
				return identity
			}(),
			proof: issued.Capability, principal: request.ProducerPrincipal,
			operation: vnextProducerCapabilitySeal, now: issuedAt,
			want: errVNextProducerCapabilityDenied,
		},
		{
			name: "wrong allocation", identity: func() vnextOwnerOperationIdentity {
				identity := reserved.Operation
				identity.AllocationRecordID++
				return identity
			}(),
			proof: issued.Capability, principal: request.ProducerPrincipal,
			operation: vnextProducerCapabilitySeal, now: issuedAt,
			want: errVNextProducerCapabilityDenied,
		},
		{
			name: "wrong checkpoint", identity: func() vnextOwnerOperationIdentity {
				identity := reserved.Operation
				identity.CheckpointID += "-other"
				return identity
			}(),
			proof: issued.Capability, principal: request.ProducerPrincipal,
			operation: vnextProducerCapabilitySeal, now: issuedAt,
			want: errVNextProducerCapabilityDenied,
		},
		{
			name: "clock rollback", identity: reserved.Operation,
			proof: issued.Capability, principal: request.ProducerPrincipal,
			operation: vnextProducerCapabilitySeal, now: issuedAt - 1,
			want: errVNextProducerCapabilityDenied,
		},
		{
			name: "expired", identity: reserved.Operation,
			proof: issued.Capability, principal: request.ProducerPrincipal,
			operation: vnextProducerCapabilitySeal, now: issued.ExpiresAtUnixNano,
			want: errVNextProducerCapabilityExpired,
		},
	}
	altered := issued.Capability
	altered.Token[0] ^= 0xff
	tests = append(tests, struct {
		name      string
		identity  vnextOwnerOperationIdentity
		proof     vnextProducerCapabilityProof
		principal string
		operation vnextProducerCapabilityOperations
		now       uint64
		want      error
	}{
		name: "altered token", identity: reserved.Operation, proof: altered,
		principal: request.ProducerPrincipal, operation: vnextProducerCapabilitySeal,
		now: issuedAt, want: errVNextProducerCapabilityDenied,
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := fixture.group.validateProducerCapability(
				test.identity, test.proof, test.principal, test.operation, test.now)
			if !errors.Is(err, test.want) {
				t.Fatalf("validation error=%v, want %v", err, test.want)
			}
		})
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.devices[0].allocator.freePages() != beforeFree ||
		fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID].State != vnextOwnerGranted {
		t.Fatal("failed capability validation mutated Owner state")
	}
}

func TestVNextProducerCapabilityRevocationIsDurableAndFailClosed(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "capability-revoke-device", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	now := time.Unix(1_700_200_000, 0)
	service.now = func() time.Time { return now }
	reserved, err := service.reserve(vnextOwnerStatusTestRequest("capability-revoke", 1))
	if err != nil {
		t.Fatal(err)
	}
	issueRequest := vnextOwnerTestCapabilityIssueRequest(
		reserved.Operation, vnextProducerCapabilityAll)
	issued, err := service.issueProducerCapability(issueRequest, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatal(err)
	}
	revokeRequest := vnextOwnerRevokeProducerCapabilityRequest{
		RequestID:     "test-revoke-capability",
		Operation:     reserved.Operation,
		CapabilityID:  issued.Capability.CapabilityID,
		SchedulerTerm: "test-scheduler/session-1/term-2",
	}
	now = now.Add(time.Second)
	revoked, err := service.revokeProducerCapability(
		revokeRequest, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("revoke Producer capability: %v", err)
	}
	if revoked.Replayed || revoked.RequestID != revokeRequest.RequestID ||
		revoked.Operation != reserved.Operation ||
		revoked.CapabilityID != issued.Capability.CapabilityID ||
		revoked.SchedulerTerm != revokeRequest.SchedulerTerm ||
		revoked.RevokedAtUnixNano != uint64(now.UnixNano()) {
		t.Fatalf("unexpected revoke proof: %#v", revoked)
	}
	beforeReplaySequence := fixture.group.journal.SnapshotSequence
	replayed, err := service.revokeProducerCapability(
		revokeRequest, vnextOwnerTestSchedulerCaller)
	if err != nil || !replayed.Replayed || replayed != func() vnextOwnerRevokeProducerCapabilityResponse {
		want := revoked
		want.Replayed = true
		return want
	}() {
		t.Fatalf("exact revoke replay changed proof: %#v / %v", replayed, err)
	}
	if fixture.group.journal.SnapshotSequence != beforeReplaySequence {
		t.Fatal("exact revoke replay advanced the journal")
	}
	if err := fixture.group.validateProducerCapability(
		reserved.Operation, issued.Capability, issueRequest.ProducerPrincipal,
		vnextProducerCapabilitySeal, uint64(now.UnixNano())); !errors.Is(err, errVNextProducerCapabilityRevoked) {
		t.Fatalf("revoked capability validation returned %v", err)
	}
	beforeFree := fixture.devices[0].allocator.freePages()
	err = service.producerAbort(
		reserved.Operation, issued.Capability, vnextOwnerTestProducerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityRevoked)
	if fixture.group.journal.SnapshotSequence != beforeReplaySequence ||
		fixture.devices[0].allocator.freePages() != beforeFree ||
		fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID].State != vnextOwnerGranted {
		t.Fatal("revoked Producer request mutated Owner state")
	}

	conflict := revokeRequest
	conflict.SchedulerTerm = "test-scheduler/other-session/term-0"
	_, err = service.revokeProducerCapability(conflict, vnextOwnerTestSchedulerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityConflict)
	rollbackNow := time.Unix(0, int64(issued.IssuedAtUnixNano-1))
	service.now = func() time.Time { return rollbackNow }
	_, err = service.revokeProducerCapability(revokeRequest, vnextOwnerTestSchedulerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityDenied)

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	restarted.now = func() time.Time { return now.Add(time.Second) }
	restartReplay, err := restarted.revokeProducerCapability(
		revokeRequest, vnextOwnerTestSchedulerCaller)
	if err != nil || !restartReplay.Replayed ||
		restartReplay.RevokedAtUnixNano != revoked.RevokedAtUnixNano ||
		restartReplay.CapabilityID != revoked.CapabilityID {
		t.Fatalf("restart revoke replay changed durable proof: %#v / %v", restartReplay, err)
	}
	if err := restarted.group.validateProducerCapability(
		reserved.Operation, issued.Capability, issueRequest.ProducerPrincipal,
		vnextProducerCapabilityAbort, uint64(now.Add(time.Second).UnixNano())); !errors.Is(err, errVNextProducerCapabilityRevoked) {
		t.Fatalf("restart lost durable revocation: %v", err)
	}
	corrupt := restarted.group.journal.clone()
	record := corrupt.Transactions[reserved.Operation.AllocationRecordID].ProducerCapability
	record.CapabilityID = "00000000000000000000000000000001"
	if err := corrupt.validate(restarted.group.devices); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("journal accepted capability ID not bound to issue digest: %v", err)
	}
	corrupt = restarted.group.journal.clone()
	record = corrupt.Transactions[reserved.Operation.AllocationRecordID].ProducerCapability
	record.RevokeRequestDigest[0] ^= 0xff
	if err := corrupt.validate(restarted.group.devices); !errors.Is(err, errVNextCorrupt) {
		t.Fatalf("journal accepted altered revoke digest: %v", err)
	}
}

func TestVNextProducerCapabilityRequiredBeforeOwnerMutation(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "capability-required-device", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	now := time.Unix(1_700_300_000, 0)
	service.now = func() time.Time { return now }
	reserved, err := service.reserve(vnextOwnerStatusTestRequest("capability-required", 1))
	if err != nil {
		t.Fatal(err)
	}
	capability := issueVNextOwnerTestCapability(
		t, service, reserved.Operation, vnextProducerCapabilityAll)
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeFree := fixture.devices[0].allocator.freePages()
	_, err = service.sealExternal(
		vnextOwnerExternalSealRequest{Operation: reserved.Operation},
		vnextOwnerTestProducerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityDenied)
	wrongCaller := vnextOwnerTestProducerCaller
	wrongCaller.Principal = "spiffe://trenv.test/producer/node-1"
	err = service.producerAbort(reserved.Operation, capability, wrongCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityDenied)
	err = service.producerAbort(
		reserved.Operation, capability, vnextOwnerTestSchedulerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServicePermissionDenied)
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.devices[0].allocator.freePages() != beforeFree ||
		fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID].State != vnextOwnerGranted {
		t.Fatal("denied Producer request mutated Owner state")
	}
	if err := service.producerAbort(
		reserved.Operation, capability, vnextOwnerTestProducerCaller); err != nil {
		t.Fatalf("valid Producer abort failed: %v", err)
	}
	if fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID].State != vnextOwnerAborted {
		t.Fatal("valid Producer abort did not reach ABORTED")
	}

	afterAbortSequence := fixture.group.journal.SnapshotSequence
	afterAbortFree := fixture.devices[0].allocator.freePages()
	afterAbortImage := vnextOwnerCapabilityPersistentState(t, fixture.group)
	if err := service.producerAbort(
		reserved.Operation, capability, vnextOwnerTestProducerCaller); err != nil {
		t.Fatalf("exact Producer abort retry after response loss failed: %v", err)
	}
	if fixture.group.journal.SnapshotSequence != afterAbortSequence ||
		fixture.devices[0].allocator.freePages() != afterAbortFree ||
		!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), afterAbortImage) {
		t.Fatal("exact Producer abort retry changed journal, bitmap, or descriptors")
	}

	// Expiry is live authority for GRANTED, not a reason to lose an exact
	// persist-before-ack replay of an already completed abort.
	now = now.Add(2 * time.Hour)
	if err := service.producerAbort(
		reserved.Operation, capability, vnextOwnerTestProducerCaller); err != nil {
		t.Fatalf("expired exact Producer abort replay failed: %v", err)
	}
	if fixture.group.journal.SnapshotSequence != afterAbortSequence ||
		fixture.devices[0].allocator.freePages() != afterAbortFree ||
		!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), afterAbortImage) {
		t.Fatal("expired Producer abort replay changed terminal persistent state")
	}

	if _, err := service.revokeProducerCapability(
		vnextOwnerRevokeProducerCapabilityRequest{
			RequestID:     "capability-aborted-revoke",
			Operation:     reserved.Operation,
			CapabilityID:  capability.CapabilityID,
			SchedulerTerm: "test-scheduler/session-1/term-2",
		},
		vnextOwnerTestSchedulerCaller); err != nil {
		t.Fatalf("revoke terminal Producer capability: %v", err)
	}
	afterRevokeSequence := fixture.group.journal.SnapshotSequence
	afterRevokeFree := fixture.devices[0].allocator.freePages()
	afterRevokeImage := vnextOwnerCapabilityPersistentState(t, fixture.group)
	if err := service.producerAbort(
		reserved.Operation, capability, vnextOwnerTestProducerCaller); err != nil {
		t.Fatalf("revoked exact Producer abort replay failed: %v", err)
	}
	if fixture.group.journal.SnapshotSequence != afterRevokeSequence ||
		fixture.devices[0].allocator.freePages() != afterRevokeFree ||
		!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), afterRevokeImage) {
		t.Fatal("revoked Producer abort replay changed terminal persistent state")
	}

	wrongToken := capability
	wrongToken.Token[0] ^= 0xff
	wrongCapabilityID := capability
	if wrongCapabilityID.CapabilityID[0] == '0' {
		wrongCapabilityID.CapabilityID = "1" + wrongCapabilityID.CapabilityID[1:]
	} else {
		wrongCapabilityID.CapabilityID = "0" + wrongCapabilityID.CapabilityID[1:]
	}
	wrongScope := reserved.Operation
	wrongScope.CheckpointID += "-other"
	wrongOwner := reserved.Operation
	wrongOwner.OwnerEpoch++
	wrongAllocation := reserved.Operation
	wrongAllocation.AllocationRecordID++
	wrongPrincipal := vnextOwnerTestProducerCaller
	wrongPrincipal.Principal = "spiffe://trenv.test/producer/node-1"
	denied := []struct {
		name       string
		identity   vnextOwnerOperationIdentity
		capability vnextProducerCapabilityProof
		caller     vnextOwnerCallerContext
	}{
		{"principal", reserved.Operation, capability, wrongPrincipal},
		{"token", reserved.Operation, wrongToken, vnextOwnerTestProducerCaller},
		{"capability ID", reserved.Operation, wrongCapabilityID, vnextOwnerTestProducerCaller},
		{"scope", wrongScope, capability, vnextOwnerTestProducerCaller},
		{"Owner identity", wrongOwner, capability, vnextOwnerTestProducerCaller},
		{"allocation identity", wrongAllocation, capability, vnextOwnerTestProducerCaller},
	}
	for _, test := range denied {
		t.Run("terminal replay rejects wrong "+test.name, func(t *testing.T) {
			err := service.producerAbort(test.identity, test.capability, test.caller)
			requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityDenied)
			if fixture.group.journal.SnapshotSequence != afterRevokeSequence ||
				fixture.devices[0].allocator.freePages() != afterRevokeFree ||
				!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), afterRevokeImage) {
				t.Fatal("denied terminal replay changed journal, bitmap, or descriptors")
			}
		})
	}

	sealOnlyReserved, err := service.reserve(
		vnextOwnerStatusTestRequest("capability-terminal-seal-only", 1))
	if err != nil {
		t.Fatal(err)
	}
	sealOnly := issueVNextOwnerTestCapability(
		t, service, sealOnlyReserved.Operation, vnextProducerCapabilitySeal)
	if err := service.abort(sealOnlyReserved.Operation); err != nil {
		t.Fatalf("Scheduler abort seal-only allocation: %v", err)
	}
	sealOnlySequence := fixture.group.journal.SnapshotSequence
	sealOnlyFree := fixture.devices[0].allocator.freePages()
	sealOnlyImage := vnextOwnerCapabilityPersistentState(t, fixture.group)
	err = service.producerAbort(
		sealOnlyReserved.Operation, sealOnly, vnextOwnerTestProducerCaller)
	requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityDenied)
	if fixture.group.journal.SnapshotSequence != sealOnlySequence ||
		fixture.devices[0].allocator.freePages() != sealOnlyFree ||
		!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), sealOnlyImage) {
		t.Fatal("terminal replay without Abort permission changed persistent state")
	}

	fixture.reopen(t)
	restarted := newVNextOwnerServiceForFixture(t, fixture)
	restarted.now = func() time.Time { return now }
	restartSequence := restarted.group.journal.SnapshotSequence
	restartFree := fixture.devices[0].allocator.freePages()
	restartImage := vnextOwnerCapabilityPersistentState(t, restarted.group)
	if err := restarted.producerAbort(
		reserved.Operation, capability, vnextOwnerTestProducerCaller); err != nil {
		t.Fatalf("expired and revoked restart Producer abort retry failed: %v", err)
	}
	if restarted.group.journal.SnapshotSequence != restartSequence ||
		fixture.devices[0].allocator.freePages() != restartFree ||
		!bytes.Equal(vnextOwnerCapabilityPersistentState(t, restarted.group), restartImage) {
		t.Fatal("restart Producer abort replay changed journal, bitmap, or descriptors")
	}
	if err := restarted.producerAbort(
		reserved.Operation, wrongToken, vnextOwnerTestProducerCaller); err == nil {
		t.Fatal("restart terminal replay accepted a wrong bearer token")
	} else {
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityDenied)
	}
	if restarted.group.journal.SnapshotSequence != restartSequence ||
		fixture.devices[0].allocator.freePages() != restartFree ||
		!bytes.Equal(vnextOwnerCapabilityPersistentState(t, restarted.group), restartImage) {
		t.Fatal("denied restart replay changed journal, bitmap, or descriptors")
	}
}

func TestVNextProducerAbortGrantedRequiresLiveAuthorityAndReclaimSafety(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "capability-abort-expired", Size: 256 << 10,
		}})
		service := newVNextOwnerServiceForFixture(t, fixture)
		now := time.Unix(1_700_400_000, 0)
		service.now = func() time.Time { return now }
		reserved, err := service.reserve(vnextOwnerStatusTestRequest(
			"capability-abort-expired", 1))
		if err != nil {
			t.Fatal(err)
		}
		request := vnextOwnerTestCapabilityIssueRequest(
			reserved.Operation, vnextProducerCapabilityAll)
		request.RequestedTTLMillis = 1
		issued, err := service.issueProducerCapability(
			request, vnextOwnerTestSchedulerCaller)
		if err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Millisecond)
		beforeSequence := fixture.group.journal.SnapshotSequence
		beforeFree := fixture.devices[0].allocator.freePages()
		beforeImage := vnextOwnerCapabilityPersistentState(t, fixture.group)
		err = service.producerAbort(
			reserved.Operation, issued.Capability, vnextOwnerTestProducerCaller)
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceCapabilityExpired)
		if fixture.group.journal.SnapshotSequence != beforeSequence ||
			fixture.devices[0].allocator.freePages() != beforeFree ||
			fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID].State != vnextOwnerGranted ||
			!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), beforeImage) {
			t.Fatal("expired GRANTED Producer abort changed persistent state")
		}
	})

	t.Run("fenced", func(t *testing.T) {
		fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
			UUID: "capability-abort-fenced", Size: 256 << 10,
		}})
		service := newVNextOwnerServiceForFixture(t, fixture)
		reserved, err := service.reserve(vnextOwnerStatusTestRequest(
			"capability-abort-fenced", 1))
		if err != nil {
			t.Fatal(err)
		}
		capability := issueVNextOwnerTestCapability(
			t, service, reserved.Operation, vnextProducerCapabilityAll)
		if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
			"capability-abort-read-only",
			vnextOwnerAdmissionActive,
			vnextOwnerAdmissionReadOnly,
			1)); err != nil {
			t.Fatal(err)
		}
		if _, err := fixture.group.setAdmission(vnextOwnerAdmissionTestRequest(
			"capability-abort-fenced",
			vnextOwnerAdmissionReadOnly,
			vnextOwnerAdmissionFenced,
			2)); err != nil {
			t.Fatal(err)
		}
		beforeSequence := fixture.group.journal.SnapshotSequence
		beforeFree := fixture.devices[0].allocator.freePages()
		beforeImage := vnextOwnerCapabilityPersistentState(t, fixture.group)
		err = service.producerAbort(
			reserved.Operation, capability, vnextOwnerTestProducerCaller)
		requireVNextOwnerServiceCode(t, err, vnextOwnerServiceAdmissionClosed)
		if fixture.group.journal.SnapshotSequence != beforeSequence ||
			fixture.devices[0].allocator.freePages() != beforeFree ||
			fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID].State != vnextOwnerGranted ||
			!bytes.Equal(vnextOwnerCapabilityPersistentState(t, fixture.group), beforeImage) {
			t.Fatal("FENCED GRANTED Producer abort changed persistent state")
		}
	})
}
