package main

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestVNextOwnerProtocolV6AndALPNV7AreHardCut(t *testing.T) {
	if vnextOwnerRPCProtocol != "cxld.vnext-owner.v6" ||
		vnextOwnerSchedulerAuthorityProtocol != "cxld.vnext-owner.v6" ||
		vnextOwnerTLSALPN != "cxld-vnext-owner/7" {
		t.Fatalf("unexpected VNext Owner hard-cut constants: protocol=%q authority=%q ALPN=%q",
			vnextOwnerRPCProtocol, vnextOwnerSchedulerAuthorityProtocol, vnextOwnerTLSALPN)
	}
}

func vnextOwnerStatusFenceRPCRequest(
	t *testing.T,
	request vnextOwnerProducerCapabilityIssueStatusAndFenceRequest,
) daemonRequest {
	t.Helper()
	expectedProof, err := vnextOwnerRPCSchedulerProofWire(
		request.ExpectedIssueSchedulerProof)
	if err != nil {
		t.Fatal(err)
	}
	raw := marshalVNextOwnerRPCTestPayload(
		t,
		vnextOwnerRPCProducerCapabilityIssueStatusAndFenceRequest{
			Protocol:                    vnextOwnerRPCProtocol,
			RequestID:                   request.RequestID,
			Identity:                    vnextOwnerRPCIdentityFromInternal(request.Operation),
			ExpectedIssueRequestID:      request.ExpectedIssueRequestID,
			ExpectedIssueSchedulerProof: expectedProof,
			ExpectedIssueCreateRevision: request.ExpectedIssueCreateRevision,
			SchedulerAuthority:          request.SchedulerAuthority,
		})
	return daemonRequest{
		CommandLabel:                         "status-and-fence-rpc-test",
		Operation:                            vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
		VNextOwnerCapabilityIssueStatusFence: raw,
	}
}

func TestVNextOwnerProducerCapabilityStatusTraversesGatewayAndRealTLS(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, _, _ := startVNextOwnerTLSTestServer(t, material, nil)
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatalf("create real TLS gateway transport: %v", err)
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	reserve := vnextOwnerTLSTestReserveRequest("status-gateway")
	vnextOwnerTestAuthorizeReserve(&reserve)
	reserved, err := client.Reserve(context.Background(), reserve)
	if err != nil {
		t.Fatalf("seed remote allocation through real TLS: %v", err)
	}
	issue := vnextOwnerTestCapabilityIssueRequest(
		reserved.Operation, vnextProducerCapabilityAll)
	issue.RequestID = "status-gateway-expected-issue"
	vnextOwnerTestAuthorizeIssue(&issue)
	expectedProof, err := vnextOwnerSchedulerExpectedProof(
		vnextOwnerRPCOperationIssueProducerCapability,
		issue,
		issue.SchedulerAuthority)
	if err != nil {
		t.Fatal(err)
	}
	status := vnextOwnerProducerCapabilityIssueStatusAndFenceRequest{
		RequestID:                   "status-gateway-query",
		Operation:                   reserved.Operation,
		ExpectedIssueRequestID:      issue.RequestID,
		ExpectedIssueSchedulerProof: expectedProof,
		ExpectedIssueCreateRevision: issue.SchedulerAuthority.CreateRevision,
	}
	vnextOwnerTestAuthorizeProducerCapabilityIssueStatusAndFence(&status)
	daemon := vnextOwnerStatusFenceRPCRequest(t, status)
	gateway := openVNextOwnerGatewayForTest(
		t,
		vnextOwnerGatewayTestRouteFile("owner-0", 7, server.Addr().String()),
		nil,
		transport)
	response := gateway.dispatchCaller(daemon, vnextOwnerTestSchedulerCaller)
	if !response.Ok || response.Operation !=
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence {
		t.Fatalf("gateway/real-TLS status-and-fence failed: %#v", response)
	}
	requireVNextOwnerStatusResponseHasNoSecretKeys(t, []byte(response.Stdout))
	var wire vnextOwnerRPCProducerCapabilityIssueStatusAndFenceResponse
	if err := decodeStrictVNextOwnerRPC([]byte(response.Stdout), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.State != string(vnextOwnerProducerCapabilityIssueNotFound) ||
		wire.ReplacementEligible || wire.HasCapability {
		t.Fatalf("unexpected remote status-and-fence result: %#v", wire)
	}
	denied := gateway.dispatchCaller(daemon, vnextOwnerTestProducerCaller)
	if denied.Ok || denied.ErrorCode != string(vnextOwnerServicePermissionDenied) {
		t.Fatalf("Producer gateway identity invoked Scheduler status operation: %#v", denied)
	}
}

func TestVNextOwnerTLSRejectsStaleALPNHardCut(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	transport.tlsConfig.NextProtos = []string{"cxld-vnext-owner/5"}
	_, err = transport.RoundTrip(
		context.Background(), vnextOwnerTLSTestDaemonRequest(t, "stale-alpn"))
	if err == nil {
		t.Fatal("stale cxld-vnext-owner/5 ALPN completed a v6 transport request")
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("stale ALPN reached Owner dispatch and created %d transactions", count)
	}
}

func requireVNextOwnerStatusResponseHasNoSecretKeys(
	t *testing.T,
	raw []byte,
) {
	t.Helper()
	var value interface{}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode status response for secret-key audit: %v", err)
	}
	var walk func(interface{})
	walk = func(current interface{}) {
		switch typed := current.(type) {
		case map[string]interface{}:
			for key, child := range typed {
				lower := strings.ToLower(key)
				for _, forbidden := range []string{"token", "nonce", "digest", "receipt", "proof"} {
					if strings.Contains(lower, forbidden) {
						t.Fatalf("status response exposed forbidden key %q", key)
					}
				}
				walk(child)
			}
		case []interface{}:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
}

func TestVNextOwnerProducerCapabilityStatusRPCIsStrictAndSecretFree(t *testing.T) {
	_, service, identity := vnextOwnerStatusFenceFixture(t, "rpc-secret")
	rpc := newVNextOwnerRPC(service)
	issue := vnextOwnerTestCapabilityIssueRequest(identity, vnextProducerCapabilityAll)
	issue.RequestID = "status-fence-rpc-issue"
	vnextOwnerTestAuthorizeIssue(&issue)
	expectedProof, err := vnextOwnerSchedulerExpectedProof(
		vnextOwnerRPCOperationIssueProducerCapability,
		issue,
		issue.SchedulerAuthority)
	if err != nil {
		t.Fatal(err)
	}
	request := vnextOwnerProducerCapabilityIssueStatusAndFenceRequest{
		RequestID:                   "status-fence-rpc-query",
		Operation:                   identity,
		ExpectedIssueRequestID:      issue.RequestID,
		ExpectedIssueSchedulerProof: expectedProof,
		ExpectedIssueCreateRevision: issue.SchedulerAuthority.CreateRevision,
	}
	vnextOwnerTestAuthorizeProducerCapabilityIssueStatusAndFence(&request)
	daemon := vnextOwnerStatusFenceRPCRequest(t, request)
	absent := runCommandWithVNextOwnerRPCCaller(
		daemon, rpc, vnextOwnerTestSchedulerCaller)
	if !absent.Ok || absent.Operation !=
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence {
		t.Fatalf("status-and-fence absence RPC failed: %#v", absent)
	}
	requireVNextOwnerStatusResponseHasNoSecretKeys(t, []byte(absent.Stdout))
	fields := requireVNextOwnerRPCJSONFields(
		t,
		[]byte(absent.Stdout),
		"protocol",
		"operation",
		"requestId",
		"identity",
		"state",
		"replacementEligible",
		"admissionState",
		"admissionSequence",
		"snapshotSequence",
		"fenceCreateRevision",
		"hasCapability",
		"capability")
	if string(fields["hasCapability"]) != "false" {
		t.Fatalf("NOT_FOUND status hasCapability = %s, want false", fields["hasCapability"])
	}
	var absentWire vnextOwnerRPCProducerCapabilityIssueStatusAndFenceResponse
	if err := decodeStrictVNextOwnerRPC([]byte(absent.Stdout), &absentWire); err != nil {
		t.Fatal(err)
	}
	if absentWire.State != string(vnextOwnerProducerCapabilityIssueNotFound) ||
		absentWire.ReplacementEligible {
		t.Fatalf("same-term absence RPC became replacement-eligible: %#v", absentWire)
	}

	issued, err := service.issueProducerCapabilityScheduler(
		issue, vnextOwnerTestSchedulerCaller)
	if err != nil {
		t.Fatalf("seed exact capability for status RPC: %v", err)
	}
	present := runCommandWithVNextOwnerRPCCaller(
		daemon, rpc, vnextOwnerTestSchedulerCaller)
	if !present.Ok {
		t.Fatalf("status-and-fence issued RPC failed: %#v", present)
	}
	requireVNextOwnerStatusResponseHasNoSecretKeys(t, []byte(present.Stdout))
	var presentWire vnextOwnerRPCProducerCapabilityIssueStatusAndFenceResponse
	if err := decodeStrictVNextOwnerRPC([]byte(present.Stdout), &presentWire); err != nil {
		t.Fatal(err)
	}
	if presentWire.State != string(vnextOwnerProducerCapabilityIssueIssued) ||
		!presentWire.HasCapability ||
		presentWire.Capability.CapabilityID != issued.Capability.CapabilityID {
		t.Fatalf("issued status RPC lost minimal public metadata: %#v", presentWire)
	}
	capabilityRaw, err := json.Marshal(presentWire.Capability)
	if err != nil {
		t.Fatal(err)
	}
	requireVNextOwnerRPCJSONFields(
		t,
		capabilityRaw,
		"capabilityId",
		"issuedAtUnixNano",
		"expiresAtUnixNano",
		"revokedAtUnixNano")
}

func TestVNextOwnerProducerCapabilityStatusRejectsStaleProtocolBeforeDispatch(t *testing.T) {
	fixture, service, identity := vnextOwnerStatusFenceFixture(t, "stale-protocol")
	rpc := newVNextOwnerRPC(service)
	issue := vnextOwnerTestCapabilityIssueRequest(identity, vnextProducerCapabilityAll)
	vnextOwnerTestAuthorizeIssue(&issue)
	expectedProof, err := vnextOwnerSchedulerExpectedProof(
		vnextOwnerRPCOperationIssueProducerCapability,
		issue,
		issue.SchedulerAuthority)
	if err != nil {
		t.Fatal(err)
	}
	wireProof, err := vnextOwnerRPCSchedulerProofWire(expectedProof)
	if err != nil {
		t.Fatal(err)
	}
	request := vnextOwnerRPCProducerCapabilityIssueStatusAndFenceRequest{
		Protocol:                    "cxld.vnext-owner.v4",
		RequestID:                   "stale-v4-status",
		Identity:                    vnextOwnerRPCIdentityFromInternal(identity),
		ExpectedIssueRequestID:      issue.RequestID,
		ExpectedIssueSchedulerProof: wireProof,
		ExpectedIssueCreateRevision: 1,
	}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	response := runCommandWithVNextOwnerRPCCaller(daemonRequest{
		Operation:                            vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
		VNextOwnerCapabilityIssueStatusFence: raw,
	}, rpc, vnextOwnerTestSchedulerCaller)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		fixture.group.journal.SnapshotSequence != beforeSequence {
		t.Fatalf("stale v4 status request reached Owner mutation: %#v", response)
	}
}

func TestVNextOwnerProducerCapabilityStatusClientRejectsMalformedResponses(t *testing.T) {
	_, _, identity := vnextOwnerStatusFenceFixture(t, "client-strict")
	issue, issueVerified := vnextOwnerStatusFenceIssue(
		t, identity, "status-fence-client-strict-issue", 2)
	request, _ := vnextOwnerStatusFenceRequest(
		t, identity, "status-fence-client-strict-query", issue.RequestID,
		issueVerified.proof(), 2, 2)
	valid := vnextOwnerRPCProducerCapabilityIssueStatusAndFenceResponse{
		Protocol:            vnextOwnerRPCProtocol,
		Operation:           vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
		RequestID:           request.RequestID,
		Identity:            vnextOwnerRPCIdentityFromInternal(identity),
		State:               string(vnextOwnerProducerCapabilityIssueNotFound),
		ReplacementEligible: false,
		AdmissionState:      vnextOwnerAdmissionActive.String(),
		AdmissionSequence:   1,
		SnapshotSequence:    1,
		FenceCreateRevision: request.SchedulerAuthority.CreateRevision,
		HasCapability:       false,
		Capability:          vnextOwnerRPCProducerCapabilityStatus{},
	}
	marshal := func(value interface{}) []byte {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	withUnknownField := func(field string, value interface{}) []byte {
		t.Helper()
		var object map[string]interface{}
		if err := json.Unmarshal(marshal(valid), &object); err != nil {
			t.Fatal(err)
		}
		object[field] = value
		return marshal(object)
	}
	withCapabilitySecret := func() []byte {
		t.Helper()
		var object map[string]interface{}
		if err := json.Unmarshal(marshal(valid), &object); err != nil {
			t.Fatal(err)
		}
		capability := object["capability"].(map[string]interface{})
		capability["token"] = "must-not-cross-status-response"
		return marshal(object)
	}
	tests := []struct {
		name    string
		payload []byte
	}{
		{
			name: "snapshot-outside-signed-abi",
			payload: func() []byte {
				wire := valid
				wire.SnapshotSequence = uint64(math.MaxInt64) + 1
				return marshal(wire)
			}(),
		},
		{
			name: "non-canonical-admission-head",
			payload: func() []byte {
				wire := valid
				wire.AdmissionSequence = 2
				return marshal(wire)
			}(),
		},
		{
			name:    "unexpected-proof",
			payload: withUnknownField("schedulerProof", map[string]string{"receipt": "forbidden"}),
		},
		{
			name:    "capability-secret",
			payload: withCapabilitySecret(),
		},
		{
			name: "not-found-with-capability",
			payload: func() []byte {
				wire := valid
				wire.HasCapability = true
				wire.Capability = vnextOwnerRPCProducerCapabilityStatus{
					CapabilityID:      "00000000000000000000000000000001",
					IssuedAtUnixNano:  1,
					ExpiresAtUnixNano: 2,
				}
				return marshal(wire)
			}(),
		},
		{
			name: "issued-with-sub-millisecond-lifetime",
			payload: func() []byte {
				wire := valid
				wire.State = string(vnextOwnerProducerCapabilityIssueIssued)
				wire.HasCapability = true
				wire.Capability = vnextOwnerRPCProducerCapabilityStatus{
					CapabilityID:      "00000000000000000000000000000001",
					IssuedAtUnixNano:  1,
					ExpiresAtUnixNano: 2,
				}
				return marshal(wire)
			}(),
		},
		{
			name: "issued-with-non-millisecond-lifetime",
			payload: func() []byte {
				wire := valid
				wire.State = string(vnextOwnerProducerCapabilityIssueIssued)
				wire.HasCapability = true
				wire.Capability = vnextOwnerRPCProducerCapabilityStatus{
					CapabilityID:      "00000000000000000000000000000001",
					IssuedAtUnixNano:  1,
					ExpiresAtUnixNano: 1_000_002,
				}
				return marshal(wire)
			}(),
		},
		{
			name: "issued-with-excessive-lifetime",
			payload: func() []byte {
				wire := valid
				wire.State = string(vnextOwnerProducerCapabilityIssueIssued)
				wire.HasCapability = true
				wire.Capability = vnextOwnerRPCProducerCapabilityStatus{
					CapabilityID:      "00000000000000000000000000000001",
					IssuedAtUnixNano:  1,
					ExpiresAtUnixNano: 2 + uint64(vnextProducerCapabilityMaxLifetime),
				}
				return marshal(wire)
			}(),
		},
		{
			name: "wrong-replacement-eligibility",
			payload: func() []byte {
				wire := valid
				wire.ReplacementEligible = true
				return marshal(wire)
			}(),
		},
		{
			name: "issued-without-capability",
			payload: func() []byte {
				wire := valid
				wire.State = string(vnextOwnerProducerCapabilityIssueIssued)
				return marshal(wire)
			}(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
				func(context.Context, daemonRequest) (execResponse, error) {
					return execResponse{
						Ok: true, Operation: vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
						Stdout: string(test.payload),
					}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ProducerCapabilityIssueStatusAndFence(
				context.Background(), request); err == nil {
				t.Fatal("malformed Producer capability status response was accepted")
			}
		})
	}
}
