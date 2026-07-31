package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func marshalVNextOwnerRPCTestPayload(t *testing.T, value interface{}) json.RawMessage {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal VNext Owner RPC test payload: %v", err)
	}
	return payload
}

func vnextOwnerRPCWireExternalContentCRCs(
	records []vnextExternalContentPageCRC,
) vnextOwnerRPCExternalContentPageCRCs {
	wire := make(vnextOwnerRPCExternalContentPageCRCs, len(records))
	for index, record := range records {
		wire[index] = vnextOwnerRPCExternalContentPageCRC{
			LogicalPage:   record.LogicalPage,
			ContentCRC32C: record.ContentCRC32C,
			CopyEngine:    uint32(record.CopyEngine),
		}
	}
	return wire
}

func requireVNextOwnerRPCJSONFields(
	t *testing.T,
	raw []byte,
	want ...string,
) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode JSON object: %v", err)
	}
	if len(object) != len(want) {
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		t.Fatalf("JSON fields are %v, expected exactly %v", keys, want)
	}
	for _, field := range want {
		if _, exists := object[field]; !exists {
			t.Fatalf("JSON object is missing field %q: %s", field, raw)
		}
	}
	return object
}

func vnextOwnerRPCTestSealJSON(
	sidecars string,
	externalContentPageCRCs string,
) []byte {
	return []byte(`{
		"protocol":"cxld.vnext-owner.v2",
		"identity":{
			"requestId":"request-a",
			"checkpointId":"checkpoint-a",
			"producerId":"producer-a",
			"ownerId":"owner-a",
			"ownerEpoch":7,
			"allocationRecordId":42
		},
		"publicationEnvelope":"eA==",
		"crcPageSidecars":` + sidecars + `,
		"externalContentPageCRCs":` + externalContentPageCRCs + `
	}`)
}

func vnextOwnerRPCTestReserveRequest(ownerID string) vnextOwnerRPCReserveRequest {
	return vnextOwnerRPCReserveRequest{
		Protocol:     vnextOwnerRPCProtocol,
		RequestID:    "rpc-reserve-request",
		CheckpointID: "rpc-reserve-checkpoint",
		ProducerID:   "rpc-reserve-producer",
		OwnerID:      ownerID,
		OwnerEpoch:   7,
		Contents: []vnextOwnerRPCReserveContent{
			{
				Kind:          "memory",
				ObjectID:      1,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
			{
				Kind:          "publication",
				ObjectID:      2,
				ByteLength:    vnextContentPageSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 2,
	}
}

func vnextOwnerRPCTestInventoryRequest(ownerID string) vnextOwnerRPCInventoryRequest {
	return vnextOwnerRPCInventoryRequest{
		Protocol:           vnextOwnerRPCProtocol,
		RequestID:          "rpc-inventory-request",
		ExpectedOwnerID:    ownerID,
		ExpectedOwnerEpoch: 7,
	}
}

func vnextOwnerRPCTestRoundTrip(
	t *testing.T,
	rpc *vnextOwnerRPC,
	request daemonRequest,
) execResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveAuthenticatedDaemonConnWithVNextOwnerGatewayRoleLimits(
			server, rpc, nil, vnextOwnerAuthorizedTestRole(request.Operation),
			daemonLargeAdmission, daemonFrameReadTimeout, daemonFrameWriteTimeout)
		close(done)
	}()
	requestBytes, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal daemon request: %v", err)
	}
	if err := writeFrame(client, requestBytes); err != nil {
		client.Close()
		t.Fatalf("write daemon request: %v", err)
	}
	responseBytes, err := readFrame(client)
	if err != nil {
		client.Close()
		t.Fatalf("read daemon response: %v", err)
	}
	_ = client.Close()
	<-done
	var response execResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		t.Fatalf("decode daemon response: %v", err)
	}
	return response
}

func TestVNextOwnerRPCInventoryUsesStrictDaemonFrameAndMinimalResponse(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-inventory-z", Size: 256 << 10},
		{UUID: "rpc-inventory-a", Size: 384 << 10},
	})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	fixture.group.mu.Lock()
	wantSequence := fixture.group.journal.SnapshotSequence
	fixture.group.mu.Unlock()
	request := vnextOwnerRPCTestInventoryRequest("owner-0")
	response := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		CommandLabel:        "rpc-inventory-test",
		Operation:           vnextOwnerRPCOperationInventory,
		VNextOwnerInventory: marshalVNextOwnerRPCTestPayload(t, request),
	})
	if !response.Ok || response.Operation != vnextOwnerRPCOperationInventory ||
		response.Error != "" || response.ErrorCode != "" {
		t.Fatalf("inventory daemon round trip failed: %#v", response)
	}
	fields := requireVNextOwnerRPCJSONFields(
		t,
		[]byte(response.Stdout),
		"protocol",
		"operation",
		"requestId",
		"ownerId",
		"ownerEpoch",
		"snapshotSequence",
		"devices")
	var wire vnextOwnerRPCInventoryResponse
	if err := decodeStrictVNextOwnerRPC([]byte(response.Stdout), &wire); err != nil {
		t.Fatalf("decode strict inventory response: %v", err)
	}
	if wire.Protocol != vnextOwnerRPCProtocol ||
		wire.Operation != vnextOwnerRPCOperationInventory ||
		wire.RequestID != request.RequestID || wire.OwnerID != request.ExpectedOwnerID ||
		wire.OwnerEpoch != request.ExpectedOwnerEpoch ||
		wire.SnapshotSequence != wantSequence || len(wire.Devices) != 2 ||
		wire.Devices[0].DeviceUUID != "rpc-inventory-a" ||
		wire.Devices[1].DeviceUUID != "rpc-inventory-z" {
		t.Fatalf("inventory response did not echo the exact stable snapshot: %#v", wire)
	}
	var devices []json.RawMessage
	if err := json.Unmarshal(fields["devices"], &devices); err != nil || len(devices) != 2 {
		t.Fatalf("decode inventory device table: %v / %d", err, len(devices))
	}
	for _, device := range devices {
		requireVNextOwnerRPCJSONFields(
			t, device, "deviceUuid", "totalDataPages", "freeDataPages")
	}
	fixture.group.mu.Lock()
	gotSequence := fixture.group.journal.SnapshotSequence
	transactions := len(fixture.group.journal.Transactions)
	fixture.group.mu.Unlock()
	if gotSequence != wantSequence || transactions != 0 {
		t.Fatalf("inventory mutated durable Owner state: sequence=%d/%d transactions=%d",
			gotSequence, wantSequence, transactions)
	}
}

func TestVNextOwnerRPCV2AdmissionStatusAndPersistedTransitionAreStrict(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "rpc-admission", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	statusRequest := vnextOwnerRPCAdmissionStatusRequest{
		Protocol:           vnextOwnerRPCProtocol,
		RequestID:          "rpc-admission-status",
		ExpectedOwnerID:    "owner-0",
		ExpectedOwnerEpoch: 7,
	}
	status := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		CommandLabel:              "rpc-admission-test",
		Operation:                 vnextOwnerRPCOperationAdmissionStatus,
		VNextOwnerAdmissionStatus: marshalVNextOwnerRPCTestPayload(t, statusRequest),
	})
	if !status.Ok || status.Operation != vnextOwnerRPCOperationAdmissionStatus {
		t.Fatalf("initial admission status RPC failed: %#v", status)
	}
	requireVNextOwnerRPCJSONFields(
		t,
		[]byte(status.Stdout),
		"protocol", "operation", "requestId", "ownerId", "ownerEpoch",
		"state", "admissionSequence", "snapshotSequence", "hasLastTransition",
		"lastTransitionRequestId", "lastTransitionRequestDigest",
		"lastTransitionFromState", "lastTransitionTargetState",
		"lastTransitionExpectedAdmissionSequence",
		"lastTransitionResultAdmissionSequence")
	var statusWire vnextOwnerRPCAdmissionStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(status.Stdout), &statusWire); err != nil {
		t.Fatal(err)
	}
	if statusWire.Protocol != vnextOwnerRPCProtocol ||
		statusWire.State != vnextOwnerAdmissionActive.String() ||
		statusWire.AdmissionSequence != 1 || statusWire.SnapshotSequence == 0 ||
		statusWire.HasLastTransition || statusWire.LastTransitionRequestID != "" ||
		statusWire.LastTransitionRequestDigest != "" ||
		statusWire.LastTransitionFromState != "" ||
		statusWire.LastTransitionTargetState != "" ||
		statusWire.LastTransitionExpectedAdmissionSequence != 0 ||
		statusWire.LastTransitionResultAdmissionSequence != 0 {
		t.Fatalf("unexpected initial admission status: %#v", statusWire)
	}

	setRequest := vnextOwnerRPCSetAdmissionRequest{
		Protocol:                  vnextOwnerRPCProtocol,
		RequestID:                 "rpc-admission-close",
		ExpectedOwnerID:           "owner-0",
		ExpectedOwnerEpoch:        7,
		FromState:                 vnextOwnerAdmissionActive.String(),
		TargetState:               vnextOwnerAdmissionReadOnly.String(),
		ExpectedAdmissionSequence: 1,
	}
	setDaemon := daemonRequest{
		CommandLabel:           "rpc-admission-test",
		Operation:              vnextOwnerRPCOperationSetAdmission,
		VNextOwnerSetAdmission: marshalVNextOwnerRPCTestPayload(t, setRequest),
	}
	set := vnextOwnerRPCTestRoundTrip(t, rpc, setDaemon)
	if !set.Ok || set.Operation != vnextOwnerRPCOperationSetAdmission {
		t.Fatalf("set admission RPC failed: %#v", set)
	}
	requireVNextOwnerRPCJSONFields(
		t,
		[]byte(set.Stdout),
		"protocol", "operation", "requestId", "requestDigest", "ownerId", "ownerEpoch",
		"fromState", "targetState", "expectedAdmissionSequence",
		"resultAdmissionSequence", "replayed")
	var setWire vnextOwnerRPCSetAdmissionResponse
	if err := decodeStrictVNextOwnerRPC([]byte(set.Stdout), &setWire); err != nil {
		t.Fatal(err)
	}
	digest := vnextOwnerAdmissionRequestDigest(vnextOwnerAdmissionTransitionRequest{
		RequestID:        setRequest.RequestID,
		OwnerID:          setRequest.ExpectedOwnerID,
		OwnerEpoch:       setRequest.ExpectedOwnerEpoch,
		From:             vnextOwnerAdmissionActive,
		Target:           vnextOwnerAdmissionReadOnly,
		ExpectedSequence: setRequest.ExpectedAdmissionSequence,
	})
	if setWire.Protocol != vnextOwnerRPCProtocol || setWire.Replayed ||
		setWire.RequestDigest != hex.EncodeToString(digest[:]) ||
		setWire.ResultAdmissionSequence != 2 {
		t.Fatalf("unexpected set-admission proof: %#v", setWire)
	}
	transitionSequence := fixture.group.journal.SnapshotSequence
	replay := vnextOwnerRPCTestRoundTrip(t, rpc, setDaemon)
	if !replay.Ok {
		t.Fatalf("replay set admission RPC: %#v", replay)
	}
	var replayWire vnextOwnerRPCSetAdmissionResponse
	if err := decodeStrictVNextOwnerRPC([]byte(replay.Stdout), &replayWire); err != nil {
		t.Fatal(err)
	}
	if !replayWire.Replayed || replayWire.RequestDigest != setWire.RequestDigest ||
		replayWire.ResultAdmissionSequence != setWire.ResultAdmissionSequence ||
		fixture.group.journal.SnapshotSequence != transitionSequence {
		t.Fatalf("set-admission replay changed durable proof: %#v", replayWire)
	}
	status = vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		CommandLabel:              "rpc-admission-test",
		Operation:                 vnextOwnerRPCOperationAdmissionStatus,
		VNextOwnerAdmissionStatus: marshalVNextOwnerRPCTestPayload(t, statusRequest),
	})
	if !status.Ok {
		t.Fatalf("post-transition admission status RPC failed: %#v", status)
	}
	if err := decodeStrictVNextOwnerRPC([]byte(status.Stdout), &statusWire); err != nil {
		t.Fatal(err)
	}
	if statusWire.State != "READ_ONLY" || statusWire.AdmissionSequence != 2 ||
		!statusWire.HasLastTransition ||
		statusWire.LastTransitionRequestID != setRequest.RequestID ||
		statusWire.LastTransitionRequestDigest != hex.EncodeToString(digest[:]) ||
		statusWire.LastTransitionFromState != "ACTIVE" ||
		statusWire.LastTransitionTargetState != "READ_ONLY" ||
		statusWire.LastTransitionExpectedAdmissionSequence != 1 ||
		statusWire.LastTransitionResultAdmissionSequence != 2 {
		t.Fatalf("status lacks the last durable transition proof: %#v", statusWire)
	}

	requestConflict := setRequest
	requestConflict.TargetState = "FENCED"
	conflict := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:              vnextOwnerRPCOperationSetAdmission,
		VNextOwnerSetAdmission: marshalVNextOwnerRPCTestPayload(t, requestConflict),
	})
	if conflict.Ok ||
		conflict.ErrorCode != string(vnextOwnerServiceAdmissionRequestConflict) {
		t.Fatalf("RPC request-id conflict lacks its stable code: %#v", conflict)
	}
	stale := setRequest
	stale.RequestID = "rpc-admission-stale"
	stale.TargetState = "FENCED"
	sequenceConflict := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:              vnextOwnerRPCOperationSetAdmission,
		VNextOwnerSetAdmission: marshalVNextOwnerRPCTestPayload(t, stale),
	})
	if sequenceConflict.Ok ||
		sequenceConflict.ErrorCode != string(vnextOwnerServiceAdmissionSequenceConflict) {
		t.Fatalf("RPC stale-head conflict lacks its stable code: %#v", sequenceConflict)
	}
}

func TestVNextOwnerRPCReservationNotFoundCarriesAtomicClosedAdmissionEvidence(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "rpc-admission-closed", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	set := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation: vnextOwnerRPCOperationSetAdmission,
		VNextOwnerSetAdmission: marshalVNextOwnerRPCTestPayload(t,
			vnextOwnerRPCSetAdmissionRequest{
				Protocol:                  vnextOwnerRPCProtocol,
				RequestID:                 "rpc-close-for-status",
				ExpectedOwnerID:           "owner-0",
				ExpectedOwnerEpoch:        7,
				FromState:                 "ACTIVE",
				TargetState:               "READ_ONLY",
				ExpectedAdmissionSequence: 1,
			}),
	})
	if !set.Ok {
		t.Fatalf("close admission: %#v", set)
	}
	reserveRequest := vnextOwnerRPCTestReserveRequest("owner-0")
	raw := marshalVNextOwnerRPCTestPayload(t, reserveRequest)
	status := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:                   vnextOwnerRPCOperationReservationStatus,
		VNextOwnerReservationStatus: raw,
	})
	if !status.Ok {
		t.Fatalf("closed NOT_FOUND status: %#v", status)
	}
	var wire vnextOwnerRPCReservationStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(status.Stdout), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.State != string(vnextOwnerReservationNotFound) || wire.HasGrant ||
		wire.AdmissionState != "READ_ONLY" || wire.AdmissionSequence != 2 {
		t.Fatalf("NOT_FOUND lacks closed admission evidence: %#v", wire)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	beforeHighWater := fixture.group.journal.NextAllocationRecordID
	reserve := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: raw,
	})
	if reserve.Ok || reserve.ErrorCode != string(vnextOwnerServiceAdmissionClosed) ||
		!strings.Contains(reserve.Error, "admission state=READ_ONLY sequence=2") {
		t.Fatalf("closed reserve did not expose stable rejection evidence: %#v", reserve)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence ||
		fixture.group.journal.NextAllocationRecordID != beforeHighWater {
		t.Fatal("closed reserve RPC mutated Owner journal")
	}
}

func TestVNextOwnerRPCV1AndMalformedAdmissionRequestsFailClosed(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "rpc-admission-strict", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	base := `"requestId":"strict-admission","expectedOwnerId":"owner-0",` +
		`"expectedOwnerEpoch":7,"fromState":"ACTIVE","targetState":"READ_ONLY",` +
		`"expectedAdmissionSequence":1`
	for name, raw := range map[string]string{
		"v1":        `{"protocol":"cxld.vnext-owner.v1",` + base + `}`,
		"unknown":   `{"protocol":"cxld.vnext-owner.v2",` + base + `,"extra":true}`,
		"duplicate": `{"protocol":"cxld.vnext-owner.v2","requestId":"a",` + base + `}`,
		"reopen": `{"protocol":"cxld.vnext-owner.v2","requestId":"reopen",` +
			`"expectedOwnerId":"owner-0","expectedOwnerEpoch":7,` +
			`"fromState":"READ_ONLY","targetState":"ACTIVE","expectedAdmissionSequence":2}`,
		"impossible-sequence-state": `{"protocol":"cxld.vnext-owner.v2",` +
			`"requestId":"impossible-sequence-state","expectedOwnerId":"owner-0",` +
			`"expectedOwnerEpoch":7,"fromState":"ACTIVE","targetState":"FENCED",` +
			`"expectedAdmissionSequence":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			response := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
				Operation:              vnextOwnerRPCOperationSetAdmission,
				VNextOwnerSetAdmission: json.RawMessage(raw),
			}, rpc)
			if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) {
				t.Fatalf("malformed admission request was accepted: %#v", response)
			}
		})
	}
	if fixture.group.journal.AdmissionState != vnextOwnerAdmissionActive ||
		fixture.group.journal.AdmissionSequence != 1 ||
		len(fixture.group.journal.AdmissionTransitions) != 0 {
		t.Fatal("rejected admission request mutated the journal")
	}
}

func TestVNextOwnerRPCReservationStatusUsesCompleteReserveIdentityAndExactGrant(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "rpc-status-device", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	wire := vnextOwnerRPCTestReserveRequest("owner-0")
	statusRequest := daemonRequest{
		CommandLabel: "rpc-status-test", TimeoutMillis: 0,
		Operation:                   vnextOwnerRPCOperationReservationStatus,
		VNextOwnerReservationStatus: marshalVNextOwnerRPCTestPayload(t, wire),
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	missing := vnextOwnerRPCTestRoundTrip(t, rpc, statusRequest)
	if !missing.Ok || missing.Operation != vnextOwnerRPCOperationReservationStatus {
		t.Fatalf("NOT_FOUND status RPC failed: %#v", missing)
	}
	var missingWire vnextOwnerRPCReservationStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(missing.Stdout), &missingWire); err != nil {
		t.Fatalf("decode NOT_FOUND status response: %v", err)
	}
	if missingWire.Protocol != vnextOwnerRPCProtocol ||
		missingWire.Operation != vnextOwnerRPCOperationReservationStatus ||
		missingWire.State != string(vnextOwnerReservationNotFound) ||
		missingWire.AdmissionState != vnextOwnerAdmissionActive.String() ||
		missingWire.AdmissionSequence != 1 ||
		missingWire.HasGrant || missingWire.Identity.AllocationRecordID != 0 ||
		missingWire.TotalPages != 0 || len(missingWire.Contents) != 0 ||
		len(missingWire.Extents) != 0 || len(missingWire.Devices) != 0 {
		t.Fatalf("unexpected NOT_FOUND status wire: %#v", missingWire)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence {
		t.Fatal("NOT_FOUND status RPC mutated Owner journal")
	}

	reserve := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		CommandLabel: "rpc-status-test", TimeoutMillis: 0,
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: marshalVNextOwnerRPCTestPayload(t, wire),
	})
	if !reserve.Ok {
		t.Fatalf("Reserve before lost response failed: %#v", reserve)
	}
	grantedSequence := fixture.group.journal.SnapshotSequence
	recovered := vnextOwnerRPCTestRoundTrip(t, rpc, statusRequest)
	if !recovered.Ok {
		t.Fatalf("recover lost Reserve response: %#v", recovered)
	}
	var recoveredWire vnextOwnerRPCReservationStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(recovered.Stdout), &recoveredWire); err != nil {
		t.Fatalf("decode GRANTED status response: %v", err)
	}
	if recoveredWire.State != string(vnextOwnerReservationGranted) ||
		recoveredWire.AdmissionState != vnextOwnerAdmissionActive.String() ||
		recoveredWire.AdmissionSequence != 1 ||
		!recoveredWire.HasGrant || recoveredWire.Identity.AllocationRecordID == 0 ||
		recoveredWire.TotalPages == 0 || len(recoveredWire.Contents) != len(wire.Contents) ||
		len(recoveredWire.Extents) == 0 || len(recoveredWire.Devices) == 0 {
		t.Fatalf("unexpected GRANTED status wire: %#v", recoveredWire)
	}
	if fixture.group.journal.SnapshotSequence != grantedSequence {
		t.Fatal("GRANTED status RPC mutated Owner journal")
	}
	fields := requireVNextOwnerRPCJSONFields(
		t, []byte(recovered.Stdout),
		"protocol", "operation", "state", "admissionState", "admissionSequence",
		"hasGrant", "identity",
		"totalPages", "contents", "extents", "devices")
	if bytes.Equal(bytes.TrimSpace(fields["contents"]), []byte("null")) ||
		bytes.Equal(bytes.TrimSpace(fields["extents"]), []byte("null")) ||
		bytes.Equal(bytes.TrimSpace(fields["devices"]), []byte("null")) {
		t.Fatal("status response used null for a mandatory bounded array")
	}
}

func TestVNextOwnerRPCReservationStatusRejectsImpossibleAdmissionHeadPairs(t *testing.T) {
	for _, test := range []struct {
		name     string
		state    vnextOwnerAdmissionState
		sequence uint64
	}{
		{name: "active-2", state: vnextOwnerAdmissionActive, sequence: 2},
		{name: "read-only-1", state: vnextOwnerAdmissionReadOnly, sequence: 1},
		{name: "read-only-3", state: vnextOwnerAdmissionReadOnly, sequence: 3},
		{name: "fenced-1", state: vnextOwnerAdmissionFenced, sequence: 1},
		{name: "fenced-4", state: vnextOwnerAdmissionFenced, sequence: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
				UUID: "rpc-status-impossible-" + test.name, Size: 256 << 10,
			}})
			fixture.group.mu.Lock()
			fixture.group.journal.AdmissionState = test.state
			fixture.group.journal.AdmissionSequence = test.sequence
			fixture.group.mu.Unlock()
			rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
			wire := vnextOwnerRPCTestReserveRequest("owner-0")
			response := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
				Operation:                   vnextOwnerRPCOperationReservationStatus,
				VNextOwnerReservationStatus: marshalVNextOwnerRPCTestPayload(t, wire),
			})
			if response.Ok || response.ErrorCode != string(vnextOwnerServiceUnavailable) {
				t.Fatalf("impossible admission head was exposed: %#v", response)
			}
		})
	}
}

func TestVNextOwnerRPCReservationStatusCarriesDurableNoSpaceWithoutGrant(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "rpc-status-no-space", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	request := vnextOwnerRPCTestReserveRequest("owner-0")
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request.RequestID = "rpc-no-space-request"
	request.CheckpointID = "rpc-no-space-checkpoint"
	request.ProducerID = "rpc-no-space-producer"
	request.Contents[0].ByteLength = capacity * vnextContentPageSize
	request.Contents[0].CapacityPages = capacity
	raw := marshalVNextOwnerRPCTestPayload(t, request)
	reserve := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: raw,
	})
	if reserve.Ok || reserve.ErrorCode != string(vnextOwnerServiceNoSpace) {
		t.Fatalf("RPC no-space Reserve did not return definitive no-space: %#v", reserve)
	}
	beforeSequence := fixture.group.journal.SnapshotSequence
	status := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:                   vnextOwnerRPCOperationReservationStatus,
		VNextOwnerReservationStatus: raw,
	})
	if !status.Ok {
		t.Fatalf("RPC REJECTED_NO_SPACE status failed: %#v", status)
	}
	var wire vnextOwnerRPCReservationStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(status.Stdout), &wire); err != nil {
		t.Fatalf("decode RPC REJECTED_NO_SPACE status: %v", err)
	}
	if wire.State != string(vnextOwnerReservationRejectedNoSpace) || wire.HasGrant ||
		wire.Identity.AllocationRecordID == 0 || wire.TotalPages != 0 ||
		len(wire.Contents) != 0 || len(wire.Extents) != 0 || len(wire.Devices) != 0 {
		t.Fatalf("unexpected RPC REJECTED_NO_SPACE status: %#v", wire)
	}
	if fixture.group.journal.SnapshotSequence != beforeSequence {
		t.Fatal("RPC REJECTED_NO_SPACE status mutated Owner journal")
	}
}

func TestVNextOwnerRPCReservationStatusRejectsMixedPayloadBeforeLookup(t *testing.T) {
	wire := marshalVNextOwnerRPCTestPayload(
		t, vnextOwnerRPCTestReserveRequest("owner-0"))
	response := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:                   vnextOwnerRPCOperationReservationStatus,
		VNextOwnerReservationStatus: wire,
		VNextOwnerReserve:           wire,
	}, nil)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "exactly one operation payload") {
		t.Fatalf("mixed status payload was accepted: %#v", response)
	}
}

func TestVNextOwnerRPCReserveUsesActualDaemonFrameAndReturnsPortablePlacement(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-device", Size: 128 << 10},
	})
	service := newVNextOwnerServiceForFixture(t, fixture)
	rpc := newVNextOwnerRPC(service)
	request := vnextOwnerRPCTestReserveRequest("owner-0")
	response := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: marshalVNextOwnerRPCTestPayload(t, request),
	})
	if !response.Ok || response.ErrorCode != "" {
		t.Fatalf("reserve RPC failed: %#v", response)
	}
	if response.Operation != vnextOwnerRPCOperationReserve || response.DurationMicros < 0 {
		t.Fatalf("daemon did not annotate VNext operation timing: %#v", response)
	}
	if strings.Contains(response.Stdout, fixture.deviceFiles[0].Name()) {
		t.Fatalf("portable response leaked local DAX path: %s", response.Stdout)
	}
	var placement vnextOwnerRPCReserveResponse
	if err := json.Unmarshal([]byte(response.Stdout), &placement); err != nil {
		t.Fatalf("decode reserve placement: %v", err)
	}
	if placement.Protocol != vnextOwnerRPCProtocol ||
		placement.Operation != vnextOwnerRPCOperationReserve ||
		placement.Identity.AllocationRecordID == 0 ||
		placement.TotalPages != 2 || len(placement.Contents) != 2 ||
		len(placement.Extents) == 0 || len(placement.Devices) != 1 {
		t.Fatalf("unexpected portable placement: %#v", placement)
	}

	abortPayload := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCLifecycleRequest{
		Protocol: vnextOwnerRPCProtocol,
		Identity: placement.Identity,
	})
	for attempt := 0; attempt < 2; attempt++ {
		aborted := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
			Operation:       vnextOwnerRPCOperationAbort,
			VNextOwnerAbort: abortPayload,
		})
		if !aborted.Ok {
			t.Fatalf("abort RPC attempt %d failed: %#v", attempt, aborted)
		}
		var terminal vnextOwnerRPCLifecycleResponse
		if err := json.Unmarshal([]byte(aborted.Stdout), &terminal); err != nil {
			t.Fatalf("decode abort response: %v", err)
		}
		if terminal.State != "ABORTED" {
			t.Fatalf("abort state is %q", terminal.State)
		}
	}
}

func TestVNextOwnerRPCStrictlyRejectsUnknownAndTrailingJSON(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-strict-device", Size: 128 << 10},
	})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	unknown := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation: vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: json.RawMessage(`{
			"protocol":"cxld.vnext-owner.v2",
			"unknownMandatoryField":true
		}`),
	}, rpc)
	if unknown.Ok || unknown.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(unknown.Error, "unknown field") {
		t.Fatalf("unknown field was not rejected strictly: %#v", unknown)
	}

	valid := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCTestReserveRequest("owner-0"))
	trailingRaw := append(append(json.RawMessage(nil), valid...), []byte(` {}`)...)
	trailing := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: trailingRaw,
	}, rpc)
	if trailing.Ok || trailing.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(trailing.Error, "trailing JSON value") {
		t.Fatalf("trailing JSON was not rejected strictly: %#v", trailing)
	}

	outerWithUnknown := []byte(`{
		"operation":"vnextOwnerReserve",
		"vnextOwnerReserve":` + string(valid) + `,
		"unknownTopLevelField":true
	}`)
	if _, err := decodeDaemonRequest(outerWithUnknown); err == nil ||
		!strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown VNext outer field was not rejected: %v", err)
	}
	outerWithTrailing := append(append([]byte(nil), []byte(`{
		"operation":"vnextOwnerReserve",
		"vnextOwnerReserve":`+string(valid)+`
	}`)...), []byte(` {}`)...)
	if _, err := decodeDaemonRequest(outerWithTrailing); err == nil {
		t.Fatal("trailing VNext daemon JSON value was not rejected")
	}

	mixed := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: valid,
		Container:         &containerRequest{},
	}, rpc)
	if mixed.Ok || mixed.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(mixed.Error, "legacy operation payload") {
		t.Fatalf("mixed VNext/legacy payload was not rejected: %#v", mixed)
	}
}

func TestVNextOwnerRPCInventoryRejectsStaleIdentityBeforeReturningCapacity(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "rpc-inventory-stale", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	request := vnextOwnerRPCTestInventoryRequest("owner-stale")
	response := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		CommandLabel:        "rpc-inventory-stale-test",
		Operation:           vnextOwnerRPCOperationInventory,
		VNextOwnerInventory: marshalVNextOwnerRPCTestPayload(t, request),
	})
	if response.Ok ||
		response.ErrorCode != string(vnextOwnerServiceIdentityMismatch) ||
		response.Stdout != "" || !strings.Contains(response.Error, "identity") {
		t.Fatalf("stale Owner received inventory capacity: %#v", response)
	}
}

func TestVNextOwnerRPCRejectsDuplicateCaseVariantAndMixedEnvelopeBeforeTypedDecode(t *testing.T) {
	reserve := vnextOwnerRPCTestReserveRequest("owner-0")
	valid := string(marshalVNextOwnerRPCTestPayload(t, reserve))
	cases := []struct {
		name    string
		body    string
		contain string
	}{
		{
			name: "duplicate outer operation",
			body: `{"operation":"vnextOwnerReserve","operation":"vnextOwnerReserve",` +
				`"vnextOwnerReserve":` + valid + `}`,
			contain: "duplicate field",
		},
		{
			name:    "case variant outer operation",
			body:    `{"Operation":"vnextOwnerReserve","vnextOwnerReserve":` + valid + `}`,
			contain: "unknown field",
		},
		{
			name: "null outer scalar",
			body: `{"operation":"vnextOwnerReserve","commandLabel":null,` +
				`"vnextOwnerReserve":` + valid + `}`,
			contain: "cannot be null",
		},
		{
			name: "mixed legacy payload rejected as raw",
			body: `{"operation":"vnextOwnerReserve","vnextOwnerReserve":` + valid + `,` +
				`"createContainer":[[[{"largeShape":"` +
				strings.Repeat("x", 1<<20) + `"}]]]}`,
			contain: "legacy operation payload",
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeDaemonRequest([]byte(test.body)); err == nil ||
				!strings.Contains(err.Error(), test.contain) {
				t.Fatalf("invalid envelope error=%v, expected %q", err, test.contain)
			}
		})
	}

	innerCases := []struct {
		name    string
		raw     string
		target  interface{}
		contain string
	}{
		{
			name: "duplicate protocol",
			raw: `{"protocol":"cxld.vnext-owner.v2","protocol":"cxld.vnext-owner.v2",` +
				`"requestId":"r","checkpointId":"c","producerId":"p","ownerId":"o",` +
				`"ownerEpoch":1,"contents":[],"maxExtents":1}`,
			target:  &vnextOwnerRPCReserveRequest{},
			contain: "duplicate field",
		},
		{
			name:    "case variant protocol",
			raw:     `{"Protocol":"cxld.vnext-owner.v2"}`,
			target:  &vnextOwnerRPCReserveRequest{},
			contain: "unknown field",
		},
		{
			name:    "repeated contents",
			raw:     `{"protocol":"cxld.vnext-owner.v2","contents":[],"contents":[]}`,
			target:  &vnextOwnerRPCReserveRequest{},
			contain: "duplicate field",
		},
		{
			name: "duplicate nested identity",
			raw: `{"protocol":"cxld.vnext-owner.v2","identity":{` +
				`"requestId":"a","requestId":"b"}}`,
			target:  &vnextOwnerRPCLifecycleRequest{},
			contain: "duplicate field",
		},
	}
	for _, test := range innerCases {
		t.Run(test.name, func(t *testing.T) {
			if err := decodeStrictVNextOwnerRPC(
				[]byte(test.raw), test.target); err == nil ||
				!strings.Contains(err.Error(), test.contain) {
				t.Fatalf("invalid inner JSON error=%v, expected %q", err, test.contain)
			}
		})
	}

	topLevelFields := make([]string, vnextOwnerRPCMaxDaemonFields+1)
	for index := range topLevelFields {
		topLevelFields[index] = `"ignored":0`
	}
	if _, err := decodeDaemonRequest([]byte(
		"{" + strings.Join(topLevelFields, ",") + "}")); err == nil ||
		!strings.Contains(err.Error(), "top-level fields") {
		t.Fatalf("unbounded daemon field list was retained: %v", err)
	}
}

func TestVNextOwnerRPCRequiresEveryNestedPayloadField(t *testing.T) {
	validRecord := `{"logicalPage":4,"contentCrc32c":0,"copyEngine":1}`
	tests := []struct {
		name    string
		raw     []byte
		target  interface{}
		contain string
	}{
		{
			name: "seal external CRC array",
			raw: []byte(`{
				"protocol":"cxld.vnext-owner.v2",
				"identity":{
					"requestId":"r","checkpointId":"c","producerId":"p",
					"ownerId":"o","ownerEpoch":1,"allocationRecordId":1
				},
				"publicationEnvelope":"eA==",
				"crcPageSidecars":[]
			}`),
			target:  &vnextOwnerRPCSealRequest{},
			contain: `missing required field "externalContentPageCRCs"`,
		},
		{
			name: "external CRC value",
			raw: vnextOwnerRPCTestSealJSON(
				"[]", `[{"logicalPage":4,"copyEngine":1}]`),
			target:  &vnextOwnerRPCSealRequest{},
			contain: `missing required field "contentCrc32c"`,
		},
		{
			name: "external CRC logical page",
			raw: vnextOwnerRPCTestSealJSON(
				"[]", `[{"contentCrc32c":0,"copyEngine":1}]`),
			target:  &vnextOwnerRPCSealRequest{},
			contain: `missing required field "logicalPage"`,
		},
		{
			name: "external CRC copy engine",
			raw: vnextOwnerRPCTestSealJSON(
				"[]", `[{"logicalPage":4,"contentCrc32c":0}]`),
			target:  &vnextOwnerRPCSealRequest{},
			contain: `missing required field "copyEngine"`,
		},
		{
			name: "sidecar bytes",
			raw: vnextOwnerRPCTestSealJSON(
				`[{"pagesImageId":7}]`, "["+validRecord+"]"),
			target:  &vnextOwnerRPCSealRequest{},
			contain: `missing required field "bytes"`,
		},
		{
			name: "reserve content capacity",
			raw: []byte(`{
				"protocol":"cxld.vnext-owner.v2",
				"requestId":"r","checkpointId":"c","producerId":"p","ownerId":"o",
				"ownerEpoch":1,
				"contents":[{"kind":"memory","objectId":1,"byteLength":4096}],
				"maxExtents":1
			}`),
			target:  &vnextOwnerRPCReserveRequest{},
			contain: `missing required field "capacityPages"`,
		},
		{
			name: "lifecycle allocation identity",
			raw: []byte(`{
				"protocol":"cxld.vnext-owner.v2",
				"identity":{
					"requestId":"r","checkpointId":"c","producerId":"p",
					"ownerId":"o","ownerEpoch":1
				}
			}`),
			target:  &vnextOwnerRPCLifecycleRequest{},
			contain: `missing required field "allocationRecordId"`,
		},
		{
			name: "inventory expected Owner epoch",
			raw: []byte(`{
				"protocol":"cxld.vnext-owner.v2",
				"requestId":"r",
				"expectedOwnerId":"owner-a"
			}`),
			target:  &vnextOwnerRPCInventoryRequest{},
			contain: `missing required field "expectedOwnerEpoch"`,
		},
		{
			name: "inventory response device array",
			raw: []byte(`{
				"protocol":"cxld.vnext-owner.v2",
				"operation":"vnextOwnerInventory",
				"requestId":"r",
				"ownerId":"owner-a",
				"ownerEpoch":1,
				"snapshotSequence":1,
				"devices":null
			}`),
			target:  &vnextOwnerRPCInventoryResponse{},
			contain: "must be a JSON array",
		},
		{
			name:    "null external CRC array",
			raw:     vnextOwnerRPCTestSealJSON("[]", "null"),
			target:  &vnextOwnerRPCSealRequest{},
			contain: "must be a JSON array",
		},
		{
			name: "case variant external CRC field",
			raw: vnextOwnerRPCTestSealJSON(
				"[]", `[{"logicalPage":4,"ContentCrc32c":0,"copyEngine":1}]`),
			target:  &vnextOwnerRPCSealRequest{},
			contain: "unknown field",
		},
		{
			name: "duplicate external CRC field",
			raw: vnextOwnerRPCTestSealJSON(
				"[]", `[{"logicalPage":4,"contentCrc32c":0,"contentCrc32c":1,"copyEngine":1}]`),
			target:  &vnextOwnerRPCSealRequest{},
			contain: "duplicate field",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := decodeStrictVNextOwnerRPC(test.raw, test.target); err == nil ||
				!strings.Contains(err.Error(), test.contain) {
				t.Fatalf("strict required-field error=%v, expected %q", err, test.contain)
			}
		})
	}

	// CRC-32C zero is valid evidence, so an explicitly present zero must remain
	// distinguishable from the missing-field case above.
	var decoded vnextOwnerRPCSealRequest
	if err := decodeStrictVNextOwnerRPC(
		vnextOwnerRPCTestSealJSON("[]", "["+validRecord+"]"), &decoded); err != nil {
		t.Fatalf("explicit zero CRC was rejected: %v", err)
	}
	if len(decoded.ExternalContentPageCRCs) != 1 ||
		decoded.ExternalContentPageCRCs[0].ContentCRC32C != 0 {
		t.Fatalf("explicit zero CRC changed during decode: %#v", decoded.ExternalContentPageCRCs)
	}
}

func TestVNextOwnerRPCExternalContentCRCUnsignedAndEngineContract(t *testing.T) {
	valid := []struct {
		name   string
		record string
	}{
		{
			name:   "zero CRC and first logical page",
			record: `{"logicalPage":0,"contentCrc32c":0,"copyEngine":1}`,
		},
		{
			name: "maximum public values",
			record: `{"logicalPage":9223372036854775807,` +
				`"contentCrc32c":4294967295,"copyEngine":3}`,
		},
		{
			name:   "DML software engine",
			record: `{"logicalPage":4,"contentCrc32c":1,"copyEngine":2}`,
		},
	}
	for _, test := range valid {
		t.Run("accept "+test.name, func(t *testing.T) {
			var request vnextOwnerRPCSealRequest
			if err := decodeStrictVNextOwnerRPC(
				vnextOwnerRPCTestSealJSON("[]", "["+test.record+"]"), &request); err != nil {
				t.Fatalf("valid unsigned record was rejected: %v", err)
			}
		})
	}

	invalidTyped := []struct {
		name   string
		record string
	}{
		{"negative logical page", `{"logicalPage":-1,"contentCrc32c":0,"copyEngine":1}`},
		{"logical page uint64 overflow", `{"logicalPage":18446744073709551616,"contentCrc32c":0,"copyEngine":1}`},
		{"fractional logical page", `{"logicalPage":1.0,"contentCrc32c":0,"copyEngine":1}`},
		{"exponent logical page", `{"logicalPage":1e0,"contentCrc32c":0,"copyEngine":1}`},
		{"string logical page", `{"logicalPage":"1","contentCrc32c":0,"copyEngine":1}`},
		{"null logical page", `{"logicalPage":null,"contentCrc32c":0,"copyEngine":1}`},
		{"negative CRC", `{"logicalPage":1,"contentCrc32c":-1,"copyEngine":1}`},
		{"CRC uint32 overflow", `{"logicalPage":1,"contentCrc32c":4294967296,"copyEngine":1}`},
		{"fractional CRC", `{"logicalPage":1,"contentCrc32c":1.0,"copyEngine":1}`},
		{"exponent CRC", `{"logicalPage":1,"contentCrc32c":1e0,"copyEngine":1}`},
		{"string CRC", `{"logicalPage":1,"contentCrc32c":"1","copyEngine":1}`},
		{"null CRC", `{"logicalPage":1,"contentCrc32c":null,"copyEngine":1}`},
		{"negative copy engine", `{"logicalPage":1,"contentCrc32c":1,"copyEngine":-1}`},
		{"copy engine uint32 overflow", `{"logicalPage":1,"contentCrc32c":1,"copyEngine":4294967296}`},
		{"fractional copy engine", `{"logicalPage":1,"contentCrc32c":1,"copyEngine":1.0}`},
		{"exponent copy engine", `{"logicalPage":1,"contentCrc32c":1,"copyEngine":1e0}`},
		{"string copy engine", `{"logicalPage":1,"contentCrc32c":1,"copyEngine":"1"}`},
		{"null copy engine", `{"logicalPage":1,"contentCrc32c":1,"copyEngine":null}`},
	}
	for _, test := range invalidTyped {
		t.Run("reject "+test.name, func(t *testing.T) {
			var request vnextOwnerRPCSealRequest
			if err := decodeStrictVNextOwnerRPC(
				vnextOwnerRPCTestSealJSON("[]", "["+test.record+"]"), &request); err == nil {
				t.Fatalf("invalid unsigned record was accepted: %s", test.record)
			}
		})
	}

	rpc := &vnextOwnerRPC{service: &vnextOwnerService{}}
	semanticInvalid := []struct {
		name    string
		records string
		contain string
	}{
		{
			name: "signed ABI overflow",
			records: `[{"logicalPage":9223372036854775808,` +
				`"contentCrc32c":0,"copyEngine":1}]`,
			contain: "signed ABI",
		},
		{
			name:    "zero copy engine",
			records: `[{"logicalPage":1,"contentCrc32c":0,"copyEngine":0}]`,
			contain: "copy engine",
		},
		{
			name:    "unknown copy engine",
			records: `[{"logicalPage":1,"contentCrc32c":0,"copyEngine":4}]`,
			contain: "copy engine",
		},
		{
			name: "identical duplicate logical page",
			records: `[{"logicalPage":1,"contentCrc32c":0,"copyEngine":1},` +
				`{"logicalPage":1,"contentCrc32c":0,"copyEngine":1}]`,
			contain: "duplicated",
		},
		{
			name: "conflicting duplicate logical page",
			records: `[{"logicalPage":1,"contentCrc32c":0,"copyEngine":1},` +
				`{"logicalPage":1,"contentCrc32c":1,"copyEngine":2}]`,
			contain: "duplicated",
		},
	}
	for _, test := range semanticInvalid {
		t.Run("reject "+test.name, func(t *testing.T) {
			response := rpc.seal(vnextOwnerRPCTestSealJSON("[]", test.records))
			if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
				!strings.Contains(response.Error, test.contain) {
				t.Fatalf("semantic record error=%#v, expected %q", response, test.contain)
			}
		})
	}
}

func TestVNextOwnerRPCFailsClosedWhenUnavailableOrPayloadShapeIsAmbiguous(t *testing.T) {
	reserve := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCTestReserveRequest("owner-0"))
	unavailable := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: reserve,
	}, nil)
	if unavailable.Ok || unavailable.ErrorCode != string(vnextOwnerServiceUnavailable) {
		t.Fatalf("unconfigured VNext Owner did not fail closed: %#v", unavailable)
	}

	ambiguous := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: reserve,
		VNextOwnerAbort:   json.RawMessage(`{}`),
	}, nil)
	if ambiguous.Ok || ambiguous.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(ambiguous.Error, "exactly one operation payload") {
		t.Fatalf("ambiguous operation payload did not fail closed: %#v", ambiguous)
	}

	timeout := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		TimeoutMillis:     1,
		VNextOwnerReserve: reserve,
	}, nil)
	if timeout.Ok || timeout.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(timeout.Error, "must be zero") {
		t.Fatalf("unsupported VNext timeout was silently ignored: %#v", timeout)
	}
}

func TestVNextOwnerRPCActiveModeRejectsEveryLegacyDAXOperation(t *testing.T) {
	rpc := &vnextOwnerRPC{service: &vnextOwnerService{}}
	for _, operation := range []string{
		"checkpointContainer",
		"restoreIntoContainer",
		"switchIntoCandidate",
		"metadataResolve",
	} {
		t.Run(operation, func(t *testing.T) {
			response := runCommandWithVNextOwnerRPCTestRole(
				daemonRequest{Operation: operation}, rpc)
			if response.Ok ||
				response.ErrorCode != string(vnextOwnerServicePublicationIncompatible) ||
				!strings.Contains(response.Error, "disabled") {
				t.Fatalf("legacy DAX operation was not rejected before dispatch: %#v", response)
			}
		})
	}
}

func TestVNextOwnerExclusiveConfigRejectsLegacyDAXAndMetadataSettings(t *testing.T) {
	if err := validateVNextOwnerExclusiveLegacyConfig(daemonConfig{
		DedupCheckpointMode: "off",
	}); err != nil {
		t.Fatalf("empty legacy configuration was rejected: %v", err)
	}
	conflicts := []daemonConfig{
		{DaxDevice: "/dev/dax0.0", DedupCheckpointMode: "off"},
		{DaxShards: []daxShardConfig{{ShardID: "page0", DaxDevice: "/dev/dax0.0"}}, DedupCheckpointMode: "off"},
		{ArtifactDaxShards: []daxShardConfig{{ShardID: "artifact0", DaxDevice: "/dev/dax1.0"}}, DedupCheckpointMode: "off"},
		{ReaderDaxShards: []daxShardConfig{{ShardID: "page0", DaxDevice: "/dev/dax0.0"}}, DedupCheckpointMode: "off"},
		{ReaderArtifactDaxShards: []daxShardConfig{{ShardID: "artifact0", DaxDevice: "/dev/dax1.0"}}, DedupCheckpointMode: "off"},
		{MetadataListen: "127.0.0.1:18080", DedupCheckpointMode: "off"},
		{MetadataPeers: []string{"http://127.0.0.1:18080"}, DedupCheckpointMode: "off"},
		{DedupCheckpointMode: "sync-required"},
	}
	for index, config := range conflicts {
		if err := validateVNextOwnerExclusiveLegacyConfig(config); err == nil {
			t.Fatalf("legacy conflict %d was accepted: %#v", index, config)
		}
	}
}

func TestVNextOwnerRPCPreservesTypedOwnerServiceErrors(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-error-device", Size: 128 << 10},
	})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	wrongOwner := vnextOwnerRPCTestReserveRequest("different-owner")
	response := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: marshalVNextOwnerRPCTestPayload(t, wrongOwner),
	}, rpc)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceIdentityMismatch) {
		t.Fatalf("service error code was not preserved: %#v", response)
	}
}

func TestVNextOwnerRPCRejectsResponseUnsafeExtentBudgetBeforeReservation(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-extent-device", Size: 128 << 10},
	})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	request := vnextOwnerRPCTestReserveRequest("owner-0")
	request.MaxExtents = vnextOwnerRPCMaxExtents + 1
	response := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: marshalVNextOwnerRPCTestPayload(t, request),
	}, rpc)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "response-safe") {
		t.Fatalf("unsafe extent budget was not rejected: %#v", response)
	}
	if len(fixture.group.journal.Transactions) != 0 {
		t.Fatalf("unsafe extent budget mutated durable Owner state: %#v",
			fixture.group.journal.Transactions)
	}
}

func TestVNextOwnerRPCReserveBoundsFutureExternalSealEvidenceBeforeMutation(t *testing.T) {
	rpc := &vnextOwnerRPC{service: &vnextOwnerService{}}
	requestWithPages := func(kind string, pages uint64) vnextOwnerRPCReserveRequest {
		return vnextOwnerRPCReserveRequest{
			Protocol:   vnextOwnerRPCProtocol,
			OwnerEpoch: 1,
			Contents: []vnextOwnerRPCReserveContent{
				{
					Kind:          kind,
					ObjectID:      1,
					ByteLength:    0,
					CapacityPages: pages,
				},
				{
					Kind:          "publication",
					ObjectID:      2,
					ByteLength:    vnextContentPageSize,
					CapacityPages: 1,
				},
			},
			MaxExtents: 1,
		}
	}

	exact := rpc.reserve(marshalVNextOwnerRPCTestPayload(
		t,
		requestWithPages("page_map", vnextOwnerRPCMaxExternalContentPageCRCs)))
	if exact.Ok || exact.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		strings.Contains(exact.Error, "RPC seal limit") {
		t.Fatalf("exact external evidence limit was rejected by the adapter: %#v", exact)
	}

	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-external-limit-device", Size: 128 << 10},
	})
	boundedRPC := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	oversized := boundedRPC.reserve(marshalVNextOwnerRPCTestPayload(
		t,
		requestWithPages("page_map", vnextOwnerRPCMaxExternalContentPageCRCs+1)))
	if oversized.Ok || oversized.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(oversized.Error, "RPC seal limit") {
		t.Fatalf("unsealable external allocation crossed the adapter: %#v", oversized)
	}
	if len(fixture.group.journal.Transactions) != 0 {
		t.Fatalf("unsealable external allocation mutated durable Owner state: %#v",
			fixture.group.journal.Transactions)
	}

	// Memory retains its separate bounded TRCRC006 transport and publication is
	// Owner-written. Neither belongs in externalContentPageCRCs.
	memory := rpc.reserve(marshalVNextOwnerRPCTestPayload(
		t,
		requestWithPages("memory", vnextOwnerRPCMaxExternalContentPageCRCs+1)))
	if memory.Ok || memory.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		strings.Contains(memory.Error, "RPC seal limit") {
		t.Fatalf("memory pages were counted as external CRC records: %#v", memory)
	}
}

func TestVNextOwnerRPCSealReturnsCompleteCandidateRoot(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	// RootVersion is the publication sequence, not the PageMap version.
	fixture.publication.Root.PublicationSequence = 11
	service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
	if err != nil {
		t.Fatalf("build RPC seal service: %v", err)
	}
	externalContentPageCRCs := vnextPrepareCompleteExternalContent(t, fixture)
	storage, err := cxlcheckpoint.EncodeForStorage(fixture.publication)
	if err != nil {
		t.Fatalf("encode RPC seal publication storage: %v", err)
	}
	envelope := storage.ExactBytes
	imageIDs := make([]int, 0, len(fixture.sidecars))
	for imageID := range fixture.sidecars {
		imageIDs = append(imageIDs, int(imageID))
	}
	sort.Ints(imageIDs)
	sidecars := make([]vnextOwnerRPCSidecar, 0, len(imageIDs))
	for _, imageID := range imageIDs {
		sidecars = append(sidecars, vnextOwnerRPCSidecar{
			PagesImageID: uint32(imageID),
			Bytes:        fixture.sidecars[uint32(imageID)],
		})
	}
	rpc := newVNextOwnerRPC(service)
	response := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
		Operation: vnextOwnerRPCOperationSeal,
		VNextOwnerSeal: marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCSealRequest{
			Protocol:            vnextOwnerRPCProtocol,
			Identity:            vnextOwnerRPCIdentityFromInternal(vnextOwnerServiceIdentity(fixture.grant)),
			PublicationEnvelope: envelope,
			CRCPageSidecars:     sidecars,
			ExternalContentPageCRCs: vnextOwnerRPCWireExternalContentCRCs(
				externalContentPageCRCs),
		}),
	})
	if !response.Ok {
		t.Fatalf("seal RPC failed: %#v", response)
	}
	var sealed vnextOwnerRPCSealResponse
	if err := json.Unmarshal([]byte(response.Stdout), &sealed); err != nil {
		t.Fatalf("decode seal root: %v", err)
	}
	wantRoot := fixture.publication.Root
	if sealed.Protocol != vnextOwnerRPCProtocol ||
		sealed.Operation != vnextOwnerRPCOperationSeal ||
		sealed.Root.RootID != wantRoot.RootID ||
		sealed.Root.RootVersion != wantRoot.PublicationSequence ||
		sealed.Root.MMTemplateID != wantRoot.MMTemplateID ||
		sealed.Root.PageMapID != wantRoot.PageMapID ||
		sealed.Root.PageMapVersion != wantRoot.PageMapVersion ||
		sealed.Root.DeviceTableDigest != hex.EncodeToString(wantRoot.DeviceTableDigest[:]) ||
		sealed.Root.ContractID != cxlcheckpoint.V6CompatibilityID ||
		sealed.Root.Locator.PublicationByteLength != uint64(len(envelope)) ||
		sealed.Root.Locator.PublicationSHA256 != hex.EncodeToString(storage.SHA256[:]) ||
		len(sealed.Root.Locator.PageRuns) != len(storage.PageRuns) ||
		len(storage.PageRuns) == 0 {
		t.Fatalf("seal RPC returned incomplete candidate root: %#v", sealed)
	}
	for index, wantRun := range storage.PageRuns {
		gotRun := sealed.Root.Locator.PageRuns[index]
		if gotRun.PageCount != wantRun.PageCount ||
			gotRun.FirstPage.OwnerID != wantRun.FirstPage.OwnerID ||
			gotRun.FirstPage.DeviceID != wantRun.FirstPage.DeviceUUID ||
			gotRun.FirstPage.DataPageIndex != wantRun.FirstPage.DataPageIndex ||
			gotRun.FirstPage.AllocationRecordID != wantRun.FirstPage.AllocationRecordID {
			t.Fatalf("seal RPC page run %d=%#v, expected %#v", index, gotRun, wantRun)
		}
	}

	responseFields := requireVNextOwnerRPCJSONFields(
		t, []byte(response.Stdout), "protocol", "operation", "root")
	rootFields := requireVNextOwnerRPCJSONFields(
		t,
		responseFields["root"],
		"rootId",
		"rootVersion",
		"mmTemplateId",
		"pageMapId",
		"pageMapVersion",
		"deviceTableDigest",
		"contractId",
		"locator")
	locatorFields := requireVNextOwnerRPCJSONFields(
		t,
		rootFields["locator"],
		"publicationByteLength",
		"publicationSha256",
		"pageRuns")
	var pageRuns []json.RawMessage
	if err := json.Unmarshal(locatorFields["pageRuns"], &pageRuns); err != nil || len(pageRuns) == 0 {
		t.Fatalf("decode exact root PageID runs: %v / %d", err, len(pageRuns))
	}
	pageRunFields := requireVNextOwnerRPCJSONFields(t, pageRuns[0], "firstPage", "pageCount")
	requireVNextOwnerRPCJSONFields(
		t,
		pageRunFields["firstPage"],
		"ownerId",
		"deviceId",
		"dataPageIndex",
		"allocationRecordId")

	transaction := fixture.owner.group.journal.Transactions[fixture.grant.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerGranted {
		t.Fatalf("seal published rather than returning a candidate root: %#v", transaction)
	}
	commitPayload := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCLifecycleRequest{
		Protocol: vnextOwnerRPCProtocol,
		Identity: vnextOwnerRPCIdentityFromInternal(vnextOwnerServiceIdentity(fixture.grant)),
	})
	for attempt := 0; attempt < 2; attempt++ {
		committed := vnextOwnerRPCTestRoundTrip(t, rpc, daemonRequest{
			Operation:        vnextOwnerRPCOperationCommit,
			VNextOwnerCommit: commitPayload,
		})
		if !committed.Ok {
			t.Fatalf("commit RPC attempt %d failed: %#v", attempt, committed)
		}
		var terminal vnextOwnerRPCLifecycleResponse
		if err := json.Unmarshal([]byte(committed.Stdout), &terminal); err != nil {
			t.Fatalf("decode commit response: %v", err)
		}
		if terminal.State != "COMMITTED" {
			t.Fatalf("commit state is %q", terminal.State)
		}
	}
}

func TestVNextOwnerRPCSealRejectsDuplicateSidecarBeforeServiceMutation(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "rpc-sidecar-device", Size: 128 << 10},
	})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	response := runCommandWithVNextOwnerRPCTestRole(daemonRequest{
		Operation: vnextOwnerRPCOperationSeal,
		VNextOwnerSeal: marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCSealRequest{
			Protocol:            vnextOwnerRPCProtocol,
			PublicationEnvelope: []byte(cxlcheckpoint.MagicString),
			CRCPageSidecars: []vnextOwnerRPCSidecar{
				{PagesImageID: 7, Bytes: []byte{1}},
				{PagesImageID: 7, Bytes: []byte{2}},
			},
			ExternalContentPageCRCs: vnextOwnerRPCExternalContentPageCRCs{},
		}),
	}, rpc)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "duplicated") {
		t.Fatalf("duplicate sidecar did not fail in transport adapter: %#v", response)
	}
}

func TestDaemonFrameBoundRejectsOversizeBeforeReadingBody(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveConnWithVNextOwnerRPC(server, nil)
		close(done)
	}()
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(maxDaemonFrameBytes+1))
	if _, err := client.Write(header); err != nil {
		client.Close()
		t.Fatalf("write oversized frame header: %v", err)
	}
	responseBytes, err := readFrame(client)
	if err != nil {
		client.Close()
		t.Fatalf("read oversized-frame rejection: %v", err)
	}
	_ = client.Close()
	<-done
	var response execResponse
	if err := json.Unmarshal(responseBytes, &response); err != nil {
		t.Fatalf("decode oversized-frame rejection: %v", err)
	}
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "maximum") {
		t.Fatalf("oversized frame did not fail closed: %#v", response)
	}
}

func TestDaemonConnectionAdmissionAndIncompleteFrameDeadlinesFailClosed(t *testing.T) {
	t.Run("connection admission", func(t *testing.T) {
		requestAdmission := make(chan struct{}, 1)
		requestAdmission <- struct{}{}
		largeAdmission := make(chan struct{}, 1)
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			serveConnWithVNextOwnerRPCLimits(
				server, nil, requestAdmission, largeAdmission, 20*time.Millisecond, time.Second)
			close(done)
		}()
		_ = client.SetReadDeadline(time.Now().Add(time.Second))
		one := make([]byte, 1)
		if _, err := client.Read(one); err == nil {
			client.Close()
			t.Fatal("saturated admission did not close the excess connection")
		}
		_ = client.Close()
		<-done
	})

	t.Run("incomplete body", func(t *testing.T) {
		requestAdmission := make(chan struct{}, 1)
		largeAdmission := make(chan struct{}, 1)
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			serveConnWithVNextOwnerRPCLimits(
				server, nil, requestAdmission, largeAdmission, 20*time.Millisecond, time.Second)
			close(done)
		}()
		headerAndPrefix := make([]byte, 5)
		binary.BigEndian.PutUint32(headerAndPrefix[:4], 16)
		headerAndPrefix[4] = '{'
		if _, err := client.Write(headerAndPrefix); err != nil {
			client.Close()
			t.Fatalf("write partial request frame: %v", err)
		}
		responseBytes, err := readFrame(client)
		if err != nil {
			client.Close()
			t.Fatalf("read incomplete-frame rejection: %v", err)
		}
		_ = client.Close()
		<-done
		var response execResponse
		if err := json.Unmarshal(responseBytes, &response); err != nil {
			t.Fatalf("decode incomplete-frame rejection: %v", err)
		}
		if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
			!strings.Contains(response.Error, "invalid request frame") {
			t.Fatalf("incomplete frame did not fail closed: %#v", response)
		}
	})

	t.Run("large body admission", func(t *testing.T) {
		requestAdmission := make(chan struct{}, 1)
		largeAdmission := make(chan struct{}, 1)
		largeAdmission <- struct{}{}
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			serveConnWithVNextOwnerRPCLimits(
				server, nil, requestAdmission, largeAdmission, 20*time.Millisecond, time.Second)
			close(done)
		}()
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(daemonLargeFrameThreshold+1))
		if _, err := client.Write(header); err != nil {
			client.Close()
			t.Fatalf("write large-frame header: %v", err)
		}
		responseBytes, err := readFrame(client)
		if err != nil {
			client.Close()
			t.Fatalf("read large-admission rejection: %v", err)
		}
		_ = client.Close()
		<-done
		var response execResponse
		if err := json.Unmarshal(responseBytes, &response); err != nil {
			t.Fatalf("decode large-admission rejection: %v", err)
		}
		if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
			!strings.Contains(response.Error, "memory budget") {
			t.Fatalf("large-frame admission did not fail closed: %#v", response)
		}
	})
}

func TestDaemonConnectionAdmissionCapsThirtyTwoIncompleteSmallFrames(t *testing.T) {
	requestAdmission := make(chan struct{}, daemonMaxConcurrentRequests)
	largeAdmission := make(chan struct{}, daemonMaxConcurrentLargeBody)
	clients := make([]net.Conn, 0, daemonMaxConcurrentRequests)
	var servers sync.WaitGroup
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, 1)
	for index := 0; index < daemonMaxConcurrentRequests; index++ {
		server, client := net.Pipe()
		clients = append(clients, client)
		servers.Add(1)
		go func() {
			defer servers.Done()
			serveConnWithVNextOwnerRPCLimits(
				server, nil, requestAdmission, largeAdmission, 2*time.Second, time.Second)
		}()
		if _, err := client.Write(header); err != nil {
			t.Fatalf("write incomplete small-frame header %d: %v", index, err)
		}
	}
	if got := len(requestAdmission); got != daemonMaxConcurrentRequests {
		t.Fatalf("admitted small-frame connections=%d, expected %d",
			got, daemonMaxConcurrentRequests)
	}

	excessServer, excessClient := net.Pipe()
	excessDone := make(chan struct{})
	go func() {
		serveConnWithVNextOwnerRPCLimits(
			excessServer, nil, requestAdmission, largeAdmission, time.Second, time.Second)
		close(excessDone)
	}()
	_ = excessClient.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := excessClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("thirty-third incomplete small frame was admitted")
	}
	_ = excessClient.Close()
	<-excessDone

	for _, client := range clients {
		_ = client.Close()
	}
	servers.Wait()
	if got := len(requestAdmission); got != 0 {
		t.Fatalf("small-frame admission tokens leaked: %d", got)
	}
}

func TestVNextOwnerRPCRejectsBulkPayloadAboveControlTransportLimit(t *testing.T) {
	rpc := &vnextOwnerRPC{service: &vnextOwnerService{}}
	response := rpc.seal(marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCSealRequest{
		Protocol:                vnextOwnerRPCProtocol,
		PublicationEnvelope:     make([]byte, vnextOwnerRPCMaxPublicationBytes+1),
		CRCPageSidecars:         vnextOwnerRPCSidecars{},
		ExternalContentPageCRCs: vnextOwnerRPCExternalContentPageCRCs{},
	}))
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "allowed range") {
		t.Fatalf("oversized publication crossed the control transport: %#v", response)
	}
}

func TestVNextOwnerRPCBoundsStructuralArraysDuringJSONDecode(t *testing.T) {
	content := `{"kind":"memory","objectId":1,"byteLength":4096,"capacityPages":1}`
	tooManyContents := "[" +
		strings.TrimSuffix(strings.Repeat(content+",", vnextOwnerRPCMaxContents+1), ",") +
		"]"
	reserve := (&vnextOwnerRPC{}).reserve(json.RawMessage(
		`{"protocol":"` + vnextOwnerRPCProtocol + `",` +
			`"requestId":"r","checkpointId":"c","producerId":"p","ownerId":"o",` +
			`"ownerEpoch":1,"contents":` + tooManyContents + `,"maxExtents":1}`))
	if reserve.Ok || reserve.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(reserve.Error, "more than") {
		t.Fatalf("oversized contents array was fully decoded: %#v", reserve)
	}

	sidecar := `{"pagesImageId":1,"bytes":"AQ=="}`
	tooManySidecars := "[" +
		strings.TrimSuffix(strings.Repeat(sidecar+",", vnextOwnerRPCMaxSidecars+1), ",") +
		"]"
	seal := (&vnextOwnerRPC{}).seal(vnextOwnerRPCTestSealJSON(tooManySidecars, "[]"))
	if seal.Ok || seal.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(seal.Error, "more than") {
		t.Fatalf("oversized sidecar array was fully decoded: %#v", seal)
	}

	externalRecord := `{"logicalPage":1,"contentCrc32c":0,"copyEngine":1}`
	tooManyExternalRecords := "[" + strings.TrimSuffix(
		strings.Repeat(
			externalRecord+",", vnextOwnerRPCMaxExternalContentPageCRCs+1), ",") + "]"
	external := (&vnextOwnerRPC{}).seal(
		vnextOwnerRPCTestSealJSON("[]", tooManyExternalRecords))
	if external.Ok || external.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(external.Error, "more than") {
		t.Fatalf("oversized external CRC array was fully decoded: %#v", external)
	}
}
