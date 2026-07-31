package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type vnextOwnerClientRoundTripFunc func(
	context.Context,
	daemonRequest,
) (execResponse, error)

func (roundTrip vnextOwnerClientRoundTripFunc) RoundTrip(
	ctx context.Context,
	request daemonRequest,
) (execResponse, error) {
	return roundTrip(ctx, request)
}

type vnextOwnerClientRecordingTransport struct {
	rpc      *vnextOwnerRPC
	requests []daemonRequest
}

func (transport *vnextOwnerClientRecordingTransport) RoundTrip(
	ctx context.Context,
	request daemonRequest,
) (execResponse, error) {
	if err := ctx.Err(); err != nil {
		return execResponse{}, err
	}
	transport.requests = append(transport.requests, request)
	return runCommandWithVNextOwnerRPC(request, transport.rpc), nil
}

func TestVNextOwnerClientReserveSealCommitThroughDaemonRoundTrip(t *testing.T) {
	environment := newVNextProducerTestEnvironment(t)
	// The shared producer fixture creates allocation 1 while deriving its
	// publication. Abort it, then prove that this client's reserve is the
	// operation that creates the allocation used below.
	if err := environment.producer.Abort(
		context.Background(), environment.reserve.Operation); err != nil {
		t.Fatalf("abort seed producer allocation: %v", err)
	}

	transport := &vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(environment.service),
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatalf("create strict Owner client: %v", err)
	}
	reserveRequest := vnextOwnerReserveRequest{
		RequestID:    "owner-client-reserve-request",
		CheckpointID: "owner-client-checkpoint",
		ProducerID:   "owner-client-producer",
		OwnerID:      environment.reserve.Operation.OwnerID,
		OwnerEpoch:   environment.reserve.Operation.OwnerEpoch,
		MaxExtents:   2,
		Contents:     make([]vnextOwnerReserveContent, len(environment.reserve.Contents)),
	}
	for index, content := range environment.reserve.Contents {
		reserveRequest.Contents[index] = vnextOwnerReserveContent{
			Kind:          content.Kind,
			ObjectID:      content.ObjectID,
			ByteLength:    content.ByteLength,
			CapacityPages: content.PageCount,
		}
	}
	reserved, err := client.Reserve(context.Background(), reserveRequest)
	if err != nil {
		t.Fatalf("reserve through strict Owner client: %v", err)
	}
	if reserved.Operation.AllocationRecordID == environment.reserve.Operation.AllocationRecordID ||
		reserved.Operation.CheckpointID != reserveRequest.CheckpointID ||
		len(reserved.Extents) != 2 {
		t.Fatalf("unexpected client reserve response: %#v", reserved)
	}
	// Close admission after GRANTED is durable. The already-started producer
	// must still be able to finish its external seal and commit under READ_ONLY.
	if _, err := environment.ownerFixture.group.setAdmission(
		vnextOwnerAdmissionTransitionRequest{
			RequestID:        "owner-client-read-only-drain",
			OwnerID:          reserved.Operation.OwnerID,
			OwnerEpoch:       reserved.Operation.OwnerEpoch,
			From:             vnextOwnerAdmissionActive,
			Target:           vnextOwnerAdmissionReadOnly,
			ExpectedSequence: 1,
		}); err != nil {
		t.Fatalf("close admission before producer drain: %v", err)
	}

	publication, sidecars := vnextOwnerClientPublicationForReserve(
		t, environment, reserved)
	producer, err := newVNextFileBackedProducer(environment.service.directory, client)
	if err != nil {
		t.Fatalf("create producer with strict Owner client: %v", err)
	}
	sealed, err := producer.Seal(context.Background(), vnextProducerSealRequest{
		Reserve:            reserved,
		Publication:        publication,
		CRCPageSidecars:    sidecars,
		ExternalCopyEngine: vnextCRCCopyEngineCPU,
		Sources: []vnextProducerContentSource{
			{ObjectID: 101, Reader: bytes.NewReader(environment.payloads[101])},
			{ObjectID: 102, Reader: bytes.NewReader(environment.payloads[102])},
			{ObjectID: 105, Reader: bytes.NewReader(environment.payloads[105])},
			{ObjectID: 106, Reader: bytes.NewReader(environment.payloads[106])},
		},
	})
	if err != nil {
		t.Fatalf("seal producer through strict Owner client: %v", err)
	}
	transaction := environment.ownerFixture.group.journal.Transactions[reserved.Operation.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerGranted {
		t.Fatalf("client seal changed transaction before commit: %#v", transaction)
	}
	if sealed.Root.RootID != publication.Root.RootID ||
		sealed.Root.ContractID != cxlcheckpoint.V6CompatibilityID {
		t.Fatalf("client returned wrong candidate root: %#v", sealed.Root)
	}
	if err := producer.Commit(context.Background(), sealed); err != nil {
		t.Fatalf("commit through strict Owner client: %v", err)
	}
	transaction = environment.ownerFixture.group.journal.Transactions[reserved.Operation.AllocationRecordID]
	if transaction == nil || transaction.State != vnextOwnerCommitted {
		t.Fatalf("client commit did not reach COMMITTED: %#v", transaction)
	}

	wantOperations := []string{
		vnextOwnerRPCOperationReserve,
		vnextOwnerRPCOperationSeal,
		vnextOwnerRPCOperationCommit,
	}
	if len(transport.requests) != len(wantOperations) {
		t.Fatalf("daemon round trips = %d, want %d", len(transport.requests), len(wantOperations))
	}
	for index, request := range transport.requests {
		if request.Operation != wantOperations[index] ||
			request.CommandLabel != "vnext-owner-client" || request.TimeoutMillis != 0 {
			t.Fatalf("round trip %d has unexpected envelope: %#v", index, request)
		}
	}
}

func TestVNextOwnerClientInventoryRoundTripsExactReadOnlyRequest(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{
		{UUID: "client-inventory-z", Size: 256 << 10},
		{UUID: "client-inventory-a", Size: 384 << 10},
	})
	transport := &vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture)),
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatalf("create inventory client: %v", err)
	}
	request := vnextOwnerInventoryRequest{
		RequestID:  "client-inventory-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	fixture.group.mu.Lock()
	wantSequence := fixture.group.journal.SnapshotSequence
	fixture.group.mu.Unlock()
	response, err := client.Inventory(context.Background(), request)
	if err != nil {
		t.Fatalf("read inventory through strict Owner client: %v", err)
	}
	if response.RequestID != request.RequestID || response.OwnerID != request.OwnerID ||
		response.OwnerEpoch != request.OwnerEpoch ||
		response.SnapshotSequence != wantSequence || len(response.Devices) != 2 ||
		response.Devices[0].DeviceUUID != "client-inventory-a" ||
		response.Devices[1].DeviceUUID != "client-inventory-z" {
		t.Fatalf("unexpected strict inventory response: %#v", response)
	}
	if len(transport.requests) != 1 {
		t.Fatalf("inventory transport calls = %d, want 1", len(transport.requests))
	}
	captured := transport.requests[0]
	if captured.Operation != vnextOwnerRPCOperationInventory ||
		captured.CommandLabel != "vnext-owner-client" || captured.TimeoutMillis != 0 ||
		len(captured.VNextOwnerInventory) == 0 || len(captured.VNextOwnerReserve) != 0 ||
		len(captured.VNextOwnerSeal) != 0 || len(captured.VNextOwnerCommit) != 0 ||
		len(captured.VNextOwnerAbort) != 0 {
		t.Fatalf("inventory client sent an invalid daemon envelope: %#v", captured)
	}
	var wire vnextOwnerRPCInventoryRequest
	if err := decodeStrictVNextOwnerRPC(captured.VNextOwnerInventory, &wire); err != nil {
		t.Fatalf("decode mandatory inventory request: %v", err)
	}
	if wire.Protocol != vnextOwnerRPCProtocol || wire.RequestID != request.RequestID ||
		wire.ExpectedOwnerID != request.OwnerID ||
		wire.ExpectedOwnerEpoch != request.OwnerEpoch {
		t.Fatalf("inventory client changed expected identity: %#v", wire)
	}
	fixture.group.mu.Lock()
	gotSequence := fixture.group.journal.SnapshotSequence
	fixture.group.mu.Unlock()
	if gotSequence != wantSequence {
		t.Fatalf("inventory client advanced journal sequence %d -> %d", wantSequence, gotSequence)
	}
}

func TestVNextOwnerClientAdmissionV2RoundTripsExactStatusAndTransition(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "client-admission", Size: 256 << 10,
	}})
	transport := &vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture)),
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	statusRequest := vnextOwnerAdmissionStatusRequest{
		RequestID:  "client-admission-status",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	initial, err := client.AdmissionStatus(context.Background(), statusRequest)
	if err != nil {
		t.Fatalf("client admission status: %v", err)
	}
	if initial.State != vnextOwnerAdmissionActive || initial.AdmissionSequence != 1 ||
		initial.SnapshotSequence == 0 || initial.HasLastTransition ||
		initial.LastTransition != (vnextOwnerAdmissionTransitionRecord{}) {
		t.Fatalf("unexpected client admission status: %#v", initial)
	}
	transition := vnextOwnerSetAdmissionRequest{
		RequestID:        "client-admission-close",
		OwnerID:          "owner-0",
		OwnerEpoch:       7,
		From:             vnextOwnerAdmissionActive,
		Target:           vnextOwnerAdmissionReadOnly,
		ExpectedSequence: 1,
	}
	closed, err := client.SetAdmission(context.Background(), transition)
	if err != nil {
		t.Fatalf("client set admission: %v", err)
	}
	if closed.Replayed || closed.ResultSequence != 2 ||
		closed.RequestDigest != vnextOwnerAdmissionRequestDigest(
			vnextOwnerAdmissionTransitionRequest{
				RequestID:        transition.RequestID,
				OwnerID:          transition.OwnerID,
				OwnerEpoch:       transition.OwnerEpoch,
				From:             transition.From,
				Target:           transition.Target,
				ExpectedSequence: transition.ExpectedSequence,
			}) {
		t.Fatalf("unexpected client transition proof: %#v", closed)
	}
	replayed, err := client.SetAdmission(context.Background(), transition)
	if err != nil || !replayed.Replayed || replayed.RequestDigest != closed.RequestDigest {
		t.Fatalf("client transition replay: %#v / %v", replayed, err)
	}
	final, err := client.AdmissionStatus(context.Background(), statusRequest)
	if err != nil || final.State != vnextOwnerAdmissionReadOnly ||
		final.AdmissionSequence != 2 || final.SnapshotSequence <= initial.SnapshotSequence ||
		!final.HasLastTransition ||
		final.LastTransition.RequestID != transition.RequestID ||
		final.LastTransition.RequestDigest != closed.RequestDigest ||
		final.LastTransition.From != transition.From ||
		final.LastTransition.Target != transition.Target ||
		final.LastTransition.ExpectedSequence != transition.ExpectedSequence ||
		final.LastTransition.ResultSequence != closed.ResultSequence {
		t.Fatalf("client final admission status: %#v / %v", final, err)
	}
	if len(transport.requests) != 4 ||
		transport.requests[0].Operation != vnextOwnerRPCOperationAdmissionStatus ||
		len(transport.requests[0].VNextOwnerAdmissionStatus) == 0 ||
		transport.requests[1].Operation != vnextOwnerRPCOperationSetAdmission ||
		len(transport.requests[1].VNextOwnerSetAdmission) == 0 ||
		transport.requests[2].Operation != vnextOwnerRPCOperationSetAdmission ||
		transport.requests[3].Operation != vnextOwnerRPCOperationAdmissionStatus {
		t.Fatalf("unexpected client admission envelopes: %#v", transport.requests)
	}
}

func TestVNextOwnerClientAdmissionRejectsMalformedProofs(t *testing.T) {
	statusRequest := vnextOwnerAdmissionStatusRequest{
		RequestID:  "client-admission-malformed-status",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	validStatus := vnextOwnerRPCAdmissionStatusResponse{
		Protocol:          vnextOwnerRPCProtocol,
		Operation:         vnextOwnerRPCOperationAdmissionStatus,
		RequestID:         statusRequest.RequestID,
		OwnerID:           statusRequest.OwnerID,
		OwnerEpoch:        statusRequest.OwnerEpoch,
		State:             "ACTIVE",
		AdmissionSequence: 1,
		SnapshotSequence:  2,
	}
	impossibleRequest := vnextOwnerAdmissionTransitionRequest{
		RequestID:        "client-impossible-last-transition",
		OwnerID:          statusRequest.OwnerID,
		OwnerEpoch:       statusRequest.OwnerEpoch,
		From:             vnextOwnerAdmissionActive,
		Target:           vnextOwnerAdmissionFenced,
		ExpectedSequence: 2,
	}
	impossibleDigest := vnextOwnerAdmissionRequestDigest(impossibleRequest)
	for _, test := range []struct {
		name   string
		mutate func(vnextOwnerRPCAdmissionStatusResponse) vnextOwnerRPCAdmissionStatusResponse
	}{
		{
			name: "unknown-head-state",
			mutate: func(invalid vnextOwnerRPCAdmissionStatusResponse) vnextOwnerRPCAdmissionStatusResponse {
				invalid.State = "UNKNOWN"
				return invalid
			},
		},
		{
			name: "fresh-with-nonempty-proof",
			mutate: func(invalid vnextOwnerRPCAdmissionStatusResponse) vnextOwnerRPCAdmissionStatusResponse {
				invalid.LastTransitionRequestID = "unexpected"
				return invalid
			},
		},
		{
			name: "transition-flag-with-empty-proof",
			mutate: func(invalid vnextOwnerRPCAdmissionStatusResponse) vnextOwnerRPCAdmissionStatusResponse {
				invalid.HasLastTransition = true
				return invalid
			},
		},
		{
			name: "impossible-state-sequence-proof",
			mutate: func(invalid vnextOwnerRPCAdmissionStatusResponse) vnextOwnerRPCAdmissionStatusResponse {
				invalid.State = "FENCED"
				invalid.AdmissionSequence = 3
				invalid.HasLastTransition = true
				invalid.LastTransitionRequestID = impossibleRequest.RequestID
				invalid.LastTransitionRequestDigest = hex.EncodeToString(impossibleDigest[:])
				invalid.LastTransitionFromState = "ACTIVE"
				invalid.LastTransitionTargetState = "FENCED"
				invalid.LastTransitionExpectedAdmissionSequence = 2
				invalid.LastTransitionResultAdmissionSequence = 3
				return invalid
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			statusClient, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
				func(context.Context, daemonRequest) (execResponse, error) {
					return execResponse{
						Ok:        true,
						Operation: vnextOwnerRPCOperationAdmissionStatus,
						Stdout: string(vnextOwnerClientMarshalJSON(
							t, test.mutate(validStatus))),
					}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := statusClient.AdmissionStatus(
				context.Background(), statusRequest); err == nil {
				t.Fatal("client accepted a malformed admission status proof")
			}
		})
	}

	transition := vnextOwnerSetAdmissionRequest{
		RequestID:        "client-admission-malformed-transition",
		OwnerID:          "owner-0",
		OwnerEpoch:       7,
		From:             vnextOwnerAdmissionActive,
		Target:           vnextOwnerAdmissionReadOnly,
		ExpectedSequence: 1,
	}
	internal := vnextOwnerAdmissionTransitionRequest{
		RequestID:        transition.RequestID,
		OwnerID:          transition.OwnerID,
		OwnerEpoch:       transition.OwnerEpoch,
		From:             transition.From,
		Target:           transition.Target,
		ExpectedSequence: transition.ExpectedSequence,
	}
	digest := vnextOwnerAdmissionRequestDigest(internal)
	validSet := vnextOwnerRPCSetAdmissionResponse{
		Protocol:                  vnextOwnerRPCProtocol,
		Operation:                 vnextOwnerRPCOperationSetAdmission,
		RequestID:                 transition.RequestID,
		RequestDigest:             hex.EncodeToString(digest[:]),
		OwnerID:                   transition.OwnerID,
		OwnerEpoch:                transition.OwnerEpoch,
		FromState:                 "ACTIVE",
		TargetState:               "READ_ONLY",
		ExpectedAdmissionSequence: 1,
		ResultAdmissionSequence:   2,
		Replayed:                  false,
	}
	setClient, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
		func(context.Context, daemonRequest) (execResponse, error) {
			invalid := validSet
			invalid.RequestDigest = strings.Repeat("0", 64)
			return execResponse{
				Ok:        true,
				Operation: vnextOwnerRPCOperationSetAdmission,
				Stdout:    string(vnextOwnerClientMarshalJSON(t, invalid)),
			}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := setClient.SetAdmission(context.Background(), transition); err == nil {
		t.Fatal("client accepted a mismatched admission transition digest")
	}
}

func TestVNextOwnerClientAdmissionPreservesConflictCodes(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "client-admission-conflicts", Size: 256 << 10,
	}})
	client, err := newVNextOwnerClient(&vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture)),
	})
	if err != nil {
		t.Fatal(err)
	}
	transition := vnextOwnerSetAdmissionRequest{
		RequestID:        "client-admission-conflict-base",
		OwnerID:          "owner-0",
		OwnerEpoch:       7,
		From:             vnextOwnerAdmissionActive,
		Target:           vnextOwnerAdmissionReadOnly,
		ExpectedSequence: 1,
	}
	if _, err := client.SetAdmission(context.Background(), transition); err != nil {
		t.Fatal(err)
	}
	requestConflict := transition
	requestConflict.Target = vnextOwnerAdmissionFenced
	_, err = client.SetAdmission(context.Background(), requestConflict)
	var remote *vnextOwnerClientRemoteError
	if !errors.As(err, &remote) ||
		remote.ErrorCode != string(vnextOwnerServiceAdmissionRequestConflict) {
		t.Fatalf("client request conflict returned %#v / %v", remote, err)
	}
	stale := transition
	stale.RequestID = "client-admission-sequence-conflict"
	stale.Target = vnextOwnerAdmissionFenced
	_, err = client.SetAdmission(context.Background(), stale)
	remote = nil
	if !errors.As(err, &remote) ||
		remote.ErrorCode != string(vnextOwnerServiceAdmissionSequenceConflict) {
		t.Fatalf("client sequence conflict returned %#v / %v", remote, err)
	}
}

func TestVNextOwnerClientReservationStatusRecoversExactLostGrant(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "client-status-device", Size: 256 << 10,
	}})
	transport := &vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture)),
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	request := vnextOwnerStatusTestRequest("client", 2)
	missing, err := client.ReservationStatus(context.Background(), request)
	if err != nil || missing.State != vnextOwnerReservationNotFound ||
		missing.Identity.AllocationRecordID != 0 || missing.Grant != nil {
		t.Fatalf("client NOT_FOUND status: %#v / %v", missing, err)
	}
	reserved, err := client.Reserve(context.Background(), request)
	if err != nil {
		t.Fatalf("client Reserve before response loss: %v", err)
	}
	recovered, err := client.ReservationStatus(context.Background(), request)
	if err != nil || recovered.State != vnextOwnerReservationGranted ||
		recovered.Grant == nil ||
		!reflect.DeepEqual(*recovered.Grant, reserved) {
		t.Fatalf("client recovered grant: %#v, want %#v / %v", recovered, reserved, err)
	}
	if len(transport.requests) != 3 ||
		transport.requests[0].Operation != vnextOwnerRPCOperationReservationStatus ||
		len(transport.requests[0].VNextOwnerReservationStatus) == 0 ||
		transport.requests[1].Operation != vnextOwnerRPCOperationReserve ||
		transport.requests[2].Operation != vnextOwnerRPCOperationReservationStatus ||
		len(transport.requests[2].VNextOwnerReservationStatus) == 0 {
		t.Fatalf("unexpected reservation-status envelopes: %#v", transport.requests)
	}
}

func TestVNextOwnerClientReservationStatusAcceptsDurableNoSpace(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "client-status-no-space", Size: 256 << 10,
	}})
	transport := &vnextOwnerClientRecordingTransport{
		rpc: newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture)),
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	capacity := fixture.devices[0].superblock.Geometry.DataPageCount
	request := vnextOwnerStatusTestRequest("client-no-space", capacity)
	if _, err := client.Reserve(context.Background(), request); err == nil {
		t.Fatal("client no-space Reserve unexpectedly succeeded")
	} else {
		var remote *vnextOwnerClientRemoteError
		if !errors.As(err, &remote) || remote.ErrorCode != string(vnextOwnerServiceNoSpace) {
			t.Fatalf("client no-space Reserve returned %v", err)
		}
	}
	status, err := client.ReservationStatus(context.Background(), request)
	if err != nil || status.State != vnextOwnerReservationRejectedNoSpace ||
		status.Identity.AllocationRecordID == 0 || status.Grant != nil {
		t.Fatalf("client REJECTED_NO_SPACE status: %#v / %v", status, err)
	}
}

func TestVNextOwnerClientReservationStatusRejectsMalformedStrictResponse(t *testing.T) {
	request := vnextOwnerStatusTestRequest("client-malformed", 1)
	valid := vnextOwnerRPCReservationStatusResponse{
		Protocol:          vnextOwnerRPCProtocol,
		Operation:         vnextOwnerRPCOperationReservationStatus,
		State:             string(vnextOwnerReservationNotFound),
		AdmissionState:    vnextOwnerAdmissionActive.String(),
		AdmissionSequence: 1,
		HasGrant:          false,
		Identity: vnextOwnerRPCOperationIdentity{
			RequestID: request.RequestID, CheckpointID: request.CheckpointID,
			ProducerID: request.ProducerID, OwnerID: request.OwnerID,
			OwnerEpoch: request.OwnerEpoch,
		},
		Contents: vnextOwnerRPCPortableContents{},
		Extents:  vnextOwnerRPCPortableExtents{},
		Devices:  vnextOwnerRPCPortableDevices{},
	}
	validRaw := vnextOwnerClientMarshalJSON(t, valid)
	tests := map[string]func([]byte) []byte{
		"unknown state": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["state"] = "MAYBE"
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"grant flag mismatch": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["hasGrant"] = true
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"active sequence 2": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["admissionSequence"] = 2
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"read-only sequence 1": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["admissionState"] = "READ_ONLY"
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"read-only sequence 3": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["admissionState"] = "READ_ONLY"
			object["admissionSequence"] = 3
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"fenced sequence 1": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["admissionState"] = "FENCED"
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"fenced sequence 4": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["admissionState"] = "FENCED"
			object["admissionSequence"] = 4
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"null contents": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["contents"] = nil
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"unknown field": func(raw []byte) []byte {
			object := vnextOwnerClientJSONMap(t, raw)
			object["extra"] = true
			return vnextOwnerClientMarshalJSON(t, object)
		},
		"trailing JSON": func(raw []byte) []byte {
			return append(append([]byte(nil), raw...), []byte(`{}`)...)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
				func(context.Context, daemonRequest) (execResponse, error) {
					return execResponse{
						Ok:        true,
						Operation: vnextOwnerRPCOperationReservationStatus,
						Stdout:    string(mutate(validRaw)),
					}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ReservationStatus(
				context.Background(), request); err == nil {
				t.Fatal("malformed reservation status was accepted")
			}
		})
	}
}

func TestVNextOwnerClientRejectsMismatchedInventoryResponses(t *testing.T) {
	request := vnextOwnerInventoryRequest{
		RequestID:  "client-inventory-response-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	valid := vnextOwnerRPCInventoryResponse{
		Protocol:         vnextOwnerRPCProtocol,
		Operation:        vnextOwnerRPCOperationInventory,
		RequestID:        request.RequestID,
		OwnerID:          request.OwnerID,
		OwnerEpoch:       request.OwnerEpoch,
		SnapshotSequence: 11,
		Devices: vnextOwnerRPCInventoryDevices{
			{DeviceUUID: "inventory-a", TotalDataPages: 10, FreeDataPages: 7},
			{DeviceUUID: "inventory-b", TotalDataPages: 20, FreeDataPages: 12},
		},
	}
	tests := []struct {
		name   string
		mutate func(vnextOwnerRPCInventoryResponse) []byte
	}{
		{
			name: "mismatched-request-ID",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.RequestID = "other-request"
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "mismatched-Owner-epoch",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.OwnerEpoch++
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "journal-sequence-exceeds-signed-ABI",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.SnapshotSequence = uint64(math.MaxInt64) + 1
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "device-capacity-exceeds-signed-ABI",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.Devices[0].TotalDataPages = uint64(math.MaxInt64) + 1
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "free-pages-exceed-total",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.Devices[0].FreeDataPages = wire.Devices[0].TotalDataPages + 1
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "device-order-is-not-stable",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.Devices[0], wire.Devices[1] = wire.Devices[1], wire.Devices[0]
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "local-path-device-ID",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				wire.Devices[0].DeviceUUID = "/dev/dax0.0"
				return vnextOwnerClientMarshalJSON(t, wire)
			},
		},
		{
			name: "missing-device-table",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				object := vnextOwnerClientJSONMap(t, vnextOwnerClientMarshalJSON(t, wire))
				delete(object, "devices")
				return vnextOwnerClientMarshalJSON(t, object)
			},
		},
		{
			name: "unknown-response-field",
			mutate: func(wire vnextOwnerRPCInventoryResponse) []byte {
				raw := vnextOwnerClientMarshalJSON(t, wire)
				return append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"grant":"forbidden"}`)...)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.Devices = append(
				vnextOwnerRPCInventoryDevices(nil), valid.Devices...)
			payload := test.mutate(candidate)
			client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
				func(context.Context, daemonRequest) (execResponse, error) {
					return execResponse{
						Ok:        true,
						Operation: vnextOwnerRPCOperationInventory,
						Stdout:    string(payload),
					}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Inventory(context.Background(), request); err == nil {
				t.Fatal("malformed or mismatched inventory response was accepted")
			}
		})
	}
}

func TestVNextOwnerClientAllowsBigIntAggregateAcrossSignedDevices(t *testing.T) {
	request := vnextOwnerInventoryRequest{
		RequestID:  "client-inventory-bigint-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	wire := vnextOwnerRPCInventoryResponse{
		Protocol:         vnextOwnerRPCProtocol,
		Operation:        vnextOwnerRPCOperationInventory,
		RequestID:        request.RequestID,
		OwnerID:          request.OwnerID,
		OwnerEpoch:       request.OwnerEpoch,
		SnapshotSequence: uint64(math.MaxInt64),
		Devices: vnextOwnerRPCInventoryDevices{
			{
				DeviceUUID:     "aggregate-a",
				TotalDataPages: uint64(math.MaxInt64),
				FreeDataPages:  uint64(math.MaxInt64),
			},
			{DeviceUUID: "aggregate-b", TotalDataPages: 1, FreeDataPages: 1},
		},
	}
	payload := vnextOwnerClientMarshalJSON(t, wire)
	client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
		func(context.Context, daemonRequest) (execResponse, error) {
			return execResponse{
				Ok:        true,
				Operation: vnextOwnerRPCOperationInventory,
				Stdout:    string(payload),
			}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Inventory(context.Background(), request)
	if err != nil {
		t.Fatalf("valid per-device Long values with BigInt aggregate were rejected: %v", err)
	}
	if len(response.Devices) != 2 ||
		response.Devices[0].TotalDataPages != uint64(math.MaxInt64) ||
		response.Devices[1].TotalDataPages != 1 {
		t.Fatalf("BigInt aggregate conversion changed device counts: %#v", response)
	}
}

func TestVNextOwnerClientBoundsInventoryDeviceArrayBeforeConversion(t *testing.T) {
	request := vnextOwnerInventoryRequest{
		RequestID:  "client-inventory-bounded-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	}
	devices := make(vnextOwnerRPCInventoryDevices, vnextOwnerRPCMaxInventoryDevices+1)
	for index := range devices {
		devices[index] = vnextOwnerRPCInventoryDevice{
			DeviceUUID:     fmt.Sprintf("bounded-%04d", index),
			TotalDataPages: 1,
			FreeDataPages:  1,
		}
	}
	payload := vnextOwnerClientMarshalJSON(t, vnextOwnerRPCInventoryResponse{
		Protocol:         vnextOwnerRPCProtocol,
		Operation:        vnextOwnerRPCOperationInventory,
		RequestID:        request.RequestID,
		OwnerID:          request.OwnerID,
		OwnerEpoch:       request.OwnerEpoch,
		SnapshotSequence: 1,
		Devices:          devices,
	})
	client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
		func(context.Context, daemonRequest) (execResponse, error) {
			return execResponse{
				Ok:        true,
				Operation: vnextOwnerRPCOperationInventory,
				Stdout:    string(payload),
			}, nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Inventory(context.Background(), request); err == nil ||
		!strings.Contains(err.Error(), "more than") {
		t.Fatalf("oversized inventory device table was not rejected before conversion: %v", err)
	}
}

func TestVNextOwnerClientRejectsNonCanonicalResponses(t *testing.T) {
	identity := vnextOwnerOperationIdentity{
		RequestID:          "client-response-request",
		CheckpointID:       "client-response-checkpoint",
		ProducerID:         "client-response-producer",
		OwnerID:            "owner-0",
		OwnerEpoch:         7,
		AllocationRecordID: 19,
	}
	valid := vnextOwnerClientValidSealResponse(t, identity)
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "unknown-field",
			mutate: func(raw []byte) []byte {
				return append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":0}`)...)
			},
		},
		{
			name: "missing-field",
			mutate: func(raw []byte) []byte {
				object := vnextOwnerClientJSONMap(t, raw)
				delete(object, "operation")
				return vnextOwnerClientMarshalJSON(t, object)
			},
		},
		{
			name: "duplicate-field",
			mutate: func(raw []byte) []byte {
				prefix := []byte(`{"protocol":"cxld.vnext-owner.v2",`)
				return append(prefix, raw[1:]...)
			},
		},
		{
			name: "null-root",
			mutate: func(raw []byte) []byte {
				object := vnextOwnerClientJSONMap(t, raw)
				object["root"] = nil
				return vnextOwnerClientMarshalJSON(t, object)
			},
		},
		{
			name: "null-page-runs",
			mutate: func(raw []byte) []byte {
				object := vnextOwnerClientJSONMap(t, raw)
				root := object["root"].(map[string]interface{})
				locator := root["locator"].(map[string]interface{})
				locator["pageRuns"] = nil
				return vnextOwnerClientMarshalJSON(t, object)
			},
		},
		{
			name: "trailing-json",
			mutate: func(raw []byte) []byte {
				return append(append([]byte(nil), raw...), []byte(`{}`)...)
			},
		},
		{
			name: "uppercase-digest",
			mutate: func(raw []byte) []byte {
				object := vnextOwnerClientJSONMap(t, raw)
				root := object["root"].(map[string]interface{})
				root["deviceTableDigest"] = strings.Repeat("A", 64)
				return vnextOwnerClientMarshalJSON(t, object)
			},
		},
		{
			name: "wrong-locator-coverage",
			mutate: func(raw []byte) []byte {
				object := vnextOwnerClientJSONMap(t, raw)
				root := object["root"].(map[string]interface{})
				locator := root["locator"].(map[string]interface{})
				locator["publicationByteLength"] = float64(cxlcheckpoint.PageSize + 1)
				return vnextOwnerClientMarshalJSON(t, object)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := test.mutate(append([]byte(nil), valid...))
			client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
				func(context.Context, daemonRequest) (execResponse, error) {
					return execResponse{
						Ok:        true,
						Operation: vnextOwnerRPCOperationSeal,
						Stdout:    string(payload),
					}, nil
				}))
			if err != nil {
				t.Fatalf("create malformed-response client: %v", err)
			}
			if _, err := client.SealVNextCheckpoint(
				context.Background(), vnextOwnerClientTestSealRequest(identity)); err == nil {
				t.Fatal("malformed strict Owner response was accepted")
			}
		})
	}
}

func TestVNextOwnerClientPreservesRemoteErrorCodeAndMandatoryRequest(t *testing.T) {
	identity := vnextOwnerOperationIdentity{
		RequestID:          "client-error-request",
		CheckpointID:       "client-error-checkpoint",
		ProducerID:         "client-error-producer",
		OwnerID:            "owner-0",
		OwnerEpoch:         7,
		AllocationRecordID: 41,
	}
	var captured daemonRequest
	client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
		func(_ context.Context, request daemonRequest) (execResponse, error) {
			captured = request
			return execResponse{
				Ok:        false,
				Operation: request.Operation,
				Error:     "Owner has no free content pages",
				ErrorCode: string(vnextOwnerServiceNoSpace),
			}, nil
		}))
	if err != nil {
		t.Fatalf("create remote-error client: %v", err)
	}
	err = client.CommitVNextCheckpoint(context.Background(), identity)
	var remote *vnextOwnerClientRemoteError
	if !errors.As(err, &remote) || remote.ErrorCode != string(vnextOwnerServiceNoSpace) ||
		remote.Message != "Owner has no free content pages" {
		t.Fatalf("remote error did not preserve code/message: %#v / %v", remote, err)
	}
	if captured.Operation != vnextOwnerRPCOperationCommit ||
		len(captured.VNextOwnerCommit) == 0 || len(captured.VNextOwnerAbort) != 0 ||
		captured.TimeoutMillis != 0 {
		t.Fatalf("captured lifecycle envelope is invalid: %#v", captured)
	}
	var wire vnextOwnerRPCLifecycleRequest
	if err := decodeStrictVNextOwnerRPC(captured.VNextOwnerCommit, &wire); err != nil {
		t.Fatalf("client did not encode a mandatory-field lifecycle payload: %v", err)
	}
	if wire.Protocol != vnextOwnerRPCProtocol || wire.Identity.internal() != identity {
		t.Fatalf("encoded lifecycle identity differs: %#v", wire)
	}
}

func TestVNextOwnerClientCancellationAndTransportFailure(t *testing.T) {
	identity := vnextOwnerOperationIdentity{
		RequestID:          "client-cancel-request",
		CheckpointID:       "client-cancel-checkpoint",
		ProducerID:         "client-cancel-producer",
		OwnerID:            "owner-0",
		OwnerEpoch:         7,
		AllocationRecordID: 42,
	}
	t.Run("cancelled-before-round-trip", func(t *testing.T) {
		calls := 0
		client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
			func(context.Context, daemonRequest) (execResponse, error) {
				calls++
				return execResponse{}, nil
			}))
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := client.AbortVNextCheckpoint(ctx, identity); !errors.Is(err, context.Canceled) {
			t.Fatalf("pre-cancelled client returned %v", err)
		}
		if calls != 0 {
			t.Fatalf("pre-cancelled client made %d transport calls", calls)
		}
	})

	t.Run("cancelled-during-round-trip", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
			func(context.Context, daemonRequest) (execResponse, error) {
				cancel()
				wire := vnextOwnerRPCLifecycleResponse{
					Protocol:  vnextOwnerRPCProtocol,
					Operation: vnextOwnerRPCOperationAbort,
					State:     "ABORTED",
				}
				payload, _ := json.Marshal(wire)
				return execResponse{
					Ok:        true,
					Operation: vnextOwnerRPCOperationAbort,
					Stdout:    string(payload),
				}, nil
			}))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.AbortVNextCheckpoint(ctx, identity); !errors.Is(err, context.Canceled) {
			t.Fatalf("mid-flight cancellation returned %v", err)
		}
	})

	t.Run("transport-error", func(t *testing.T) {
		transportFailure := errors.New("framed transport unavailable")
		client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
			func(context.Context, daemonRequest) (execResponse, error) {
				return execResponse{}, transportFailure
			}))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.CommitVNextCheckpoint(
			context.Background(), identity); !errors.Is(err, transportFailure) {
			t.Fatalf("transport error was not preserved: %v", err)
		}
	})
}

func TestVNextOwnerClientRejectsOutgoingIdentityBeforeTransport(t *testing.T) {
	validIdentity := vnextOwnerOperationIdentity{
		RequestID:          "client-identity-request",
		CheckpointID:       "client-identity-checkpoint",
		ProducerID:         "client-identity-producer",
		OwnerID:            "owner-0",
		OwnerEpoch:         7,
		AllocationRecordID: 43,
	}
	tests := []struct {
		name string
		run  func(*vnextOwnerClient) error
	}{
		{
			name: "seal-surrounding-whitespace",
			run: func(client *vnextOwnerClient) error {
				identity := validIdentity
				identity.RequestID = " client-identity-request"
				_, err := client.SealVNextCheckpoint(
					context.Background(), vnextOwnerClientTestSealRequest(identity))
				return err
			},
		},
		{
			name: "commit-invalid-utf8",
			run: func(client *vnextOwnerClient) error {
				identity := validIdentity
				identity.ProducerID = string([]byte{0xff})
				return client.CommitVNextCheckpoint(context.Background(), identity)
			},
		},
		{
			name: "reserve-control-character",
			run: func(client *vnextOwnerClient) error {
				_, err := client.Reserve(context.Background(), vnextOwnerReserveRequest{
					RequestID:    "identity-reserve-request",
					CheckpointID: "identity\nreserve-checkpoint",
					ProducerID:   "identity-reserve-producer",
					OwnerID:      "owner-0",
					OwnerEpoch:   7,
					Contents: []vnextOwnerReserveContent{
						{
							Kind:          vnextOwnerServiceContentMemory,
							ObjectID:      1,
							ByteLength:    cxlcheckpoint.PageSize,
							CapacityPages: 1,
						},
						{
							Kind:          vnextOwnerServiceContentPublication,
							ObjectID:      2,
							ByteLength:    cxlcheckpoint.PageSize,
							CapacityPages: 1,
						},
					},
					MaxExtents: 1,
				})
				return err
			},
		},
		{
			name: "inventory-surrounding-whitespace",
			run: func(client *vnextOwnerClient) error {
				_, err := client.Inventory(context.Background(), vnextOwnerInventoryRequest{
					RequestID:  " inventory-request",
					OwnerID:    "owner-0",
					OwnerEpoch: 7,
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client, err := newVNextOwnerClient(vnextOwnerClientRoundTripFunc(
				func(context.Context, daemonRequest) (execResponse, error) {
					calls++
					return execResponse{}, nil
				}))
			if err != nil {
				t.Fatal(err)
			}
			if err := test.run(client); err == nil {
				t.Fatal("invalid outgoing identity was accepted")
			}
			if calls != 0 {
				t.Fatalf("invalid outgoing identity made %d transport calls", calls)
			}
		})
	}
}

func TestVNextOwnerClientReserveRejectsAdjacentSameDeviceExtents(t *testing.T) {
	request := vnextOwnerReserveRequest{
		RequestID:    "client-adjacent-request",
		CheckpointID: "client-adjacent-checkpoint",
		ProducerID:   "client-adjacent-producer",
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      1,
				ByteLength:    2 * cxlcheckpoint.PageSize,
				CapacityPages: 2,
			},
			{
				Kind:          vnextOwnerServiceContentPublication,
				ObjectID:      2,
				ByteLength:    cxlcheckpoint.PageSize,
				CapacityPages: 1,
			},
		},
		MaxExtents: 2,
	}
	internal, err := request.internal()
	if err != nil {
		t.Fatalf("build adjacent-extent request: %v", err)
	}
	wire := vnextOwnerRPCReserveResponse{
		Protocol:  vnextOwnerRPCProtocol,
		Operation: vnextOwnerRPCOperationReserve,
		Identity: vnextOwnerRPCOperationIdentity{
			RequestID:          request.RequestID,
			CheckpointID:       request.CheckpointID,
			ProducerID:         request.ProducerID,
			OwnerID:            request.OwnerID,
			OwnerEpoch:         request.OwnerEpoch,
			AllocationRecordID: 1,
		},
		TotalPages: 3,
		Contents: []vnextOwnerRPCPortableContent{
			{
				Kind:             "memory",
				ObjectID:         1,
				ByteLength:       2 * cxlcheckpoint.PageSize,
				LogicalPageStart: 0,
				PageCount:        2,
			},
			{
				Kind:             "publication",
				ObjectID:         2,
				ByteLength:       cxlcheckpoint.PageSize,
				LogicalPageStart: 2,
				PageCount:        1,
			},
		},
		Extents: []vnextOwnerRPCPortableExtent{
			{
				DeviceUUID:         "client-adjacent-device",
				StartDataPageIndex: 10,
				PageCount:          1,
				LogicalPageStart:   0,
			},
			{
				DeviceUUID:         "client-adjacent-device",
				StartDataPageIndex: 11,
				PageCount:          2,
				LogicalPageStart:   1,
			},
		},
		Devices: []vnextOwnerRPCPortableDevice{{
			DeviceUUID:        "client-adjacent-device",
			DataPageCount:     128,
			ContentRegionBase: 4096,
		}},
	}
	if _, err := convertVNextOwnerClientReserveResponse(
		request, internal, wire); err == nil ||
		!strings.Contains(err.Error(), "not coalesced") {
		t.Fatalf("adjacent same-device extents returned %v", err)
	}
}

func vnextOwnerClientPublicationForReserve(
	t *testing.T,
	environment *vnextProducerTestEnvironment,
	reserve vnextOwnerReserveResponse,
) (cxlcheckpoint.Publication, map[uint32][]byte) {
	t.Helper()
	encoded, err := cxlcheckpoint.Encode(environment.publication)
	if err != nil {
		t.Fatalf("clone source publication: %v", err)
	}
	publication, err := cxlcheckpoint.Decode(encoded)
	if err != nil {
		t.Fatalf("decode cloned publication: %v", err)
	}
	publication.CheckpointID = reserve.Operation.CheckpointID
	publication.ContentObjects = publication.ContentObjects[:0]
	for _, content := range reserve.Contents {
		kind, ok := vnextProducerTestPortableKind(content.Kind)
		if !ok {
			t.Fatalf("unknown client reserve content kind %d", content.Kind)
		}
		publication.ContentObjects = append(publication.ContentObjects, cxlcheckpoint.ContentObject{
			ObjectID:         content.ObjectID,
			Kind:             kind,
			ByteLength:       content.ByteLength,
			LogicalPageStart: content.LogicalPageStart,
			PageCount:        content.PageCount,
		})
	}
	publication.Devices = publication.Devices[:0]
	for _, device := range reserve.Devices {
		publication.Devices = append(publication.Devices, cxlcheckpoint.Device{
			DeviceUUID:    device.DeviceUUID,
			OwnerID:       reserve.Operation.OwnerID,
			OwnerEpoch:    reserve.Operation.OwnerEpoch,
			DataPageCount: device.DataPageCount,
		})
	}
	publication.Allocation = cxlcheckpoint.InitialAllocation{
		OwnerID:            reserve.Operation.OwnerID,
		OwnerEpoch:         reserve.Operation.OwnerEpoch,
		AllocationRecordID: reserve.Operation.AllocationRecordID,
		TotalPages:         reserve.TotalPages,
	}
	for _, extent := range reserve.Extents {
		publication.Allocation.Extents = append(
			publication.Allocation.Extents,
			cxlcheckpoint.AllocationExtent{
				DeviceUUID:         extent.DeviceUUID,
				StartDataPageIndex: extent.StartDataPageIndex,
				PageCount:          extent.PageCount,
				LogicalPageStart:   extent.LogicalPageStart,
			})
	}
	memoryPages := reserve.Contents[0].PageCount
	publication.PageMap.Runs = vnextProducerMemoryRuns(
		t, reserve, memoryPages, 17, publication.MMTemplate.VMAs[0].StartVAddr)
	publication.MMTemplate.VMAs[0].PageMapRunCount = uint64(len(publication.PageMap.Runs))
	publication.Root.RootID = "owner-client-root"
	publication.Root.CheckpointID = reserve.Operation.CheckpointID
	publication.Root.OwnerID = reserve.Operation.OwnerID
	publication.Root.AllocationRecordID = reserve.Operation.AllocationRecordID
	publication.Root.PublicationSequence = 10
	digest, err := cxlcheckpoint.DeviceTableDigest(publication.Devices)
	if err != nil {
		t.Fatalf("digest client publication devices: %v", err)
	}
	publication.Root.DeviceTableDigest = digest
	if err := publication.Validate(); err != nil {
		t.Fatalf("validate client publication: %v", err)
	}

	sidecars := vnextTestCRCPageSidecars(t, publication, environment.service.directory)
	data := sidecars[17]
	for page := uint64(0); page < memoryPages; page++ {
		offset := vnextCRCPageSidecarHeaderSize + int(page)*vnextCRCPageSidecarRecordSize
		start := page * cxlcheckpoint.PageSize
		checksum := crc32.Checksum(
			environment.payloads[101][int(start):int(start+cxlcheckpoint.PageSize)],
			vnextCRCTable)
		binary.LittleEndian.PutUint32(data[offset+28:offset+32], checksum)
	}
	return publication, sidecars
}

func vnextOwnerClientValidSealResponse(
	t *testing.T,
	identity vnextOwnerOperationIdentity,
) []byte {
	t.Helper()
	digest := strings.Repeat("00", 32)
	wire := vnextOwnerRPCSealResponse{
		Protocol:  vnextOwnerRPCProtocol,
		Operation: vnextOwnerRPCOperationSeal,
		Root: vnextOwnerRPCCheckpointRoot{
			RootID:            "client-response-root",
			RootVersion:       1,
			MMTemplateID:      "client-response-mm",
			PageMapID:         "client-response-map",
			PageMapVersion:    1,
			DeviceTableDigest: digest,
			ContractID:        cxlcheckpoint.V6CompatibilityID,
			Locator: vnextOwnerRPCRootLocator{
				PublicationByteLength: 123,
				PublicationSHA256:     digest,
				PageRuns: []vnextOwnerRPCPublicationPageRun{{
					FirstPage: vnextOwnerRPCPageID{
						OwnerID:            identity.OwnerID,
						DeviceID:           "client-response-device",
						DataPageIndex:      5,
						AllocationRecordID: identity.AllocationRecordID,
					},
					PageCount: 1,
				}},
			},
		},
	}
	return vnextOwnerClientMarshalJSON(t, wire)
}

func vnextOwnerClientTestSealRequest(
	identity vnextOwnerOperationIdentity,
) vnextOwnerExternalSealRequest {
	return vnextOwnerExternalSealRequest{
		Operation:           identity,
		PublicationEnvelope: []byte("test-publication"),
		CRCPageSidecars: map[uint32][]byte{
			1: []byte("test-sidecar"),
		},
		ExternalContentPageCRCs: []vnextExternalContentPageCRC{},
	}
}

func vnextOwnerClientJSONMap(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	var object map[string]interface{}
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatalf("decode JSON mutation object: %v", err)
	}
	return object
}

func vnextOwnerClientMarshalJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal Owner client test JSON: %v", err)
	}
	return raw
}

func TestVNextOwnerClientDigestDecoderKnownAnswer(t *testing.T) {
	known := strings.Repeat("ab", 32)
	digest, err := decodeCanonicalVNextOwnerClientDigest("known", known)
	if err != nil {
		t.Fatalf("decode known digest: %v", err)
	}
	want, _ := hex.DecodeString(known)
	if !reflect.DeepEqual(digest[:], want) {
		t.Fatalf("decoded digest differs: %x / %x", digest, want)
	}
	if _, err := decodeCanonicalVNextOwnerClientDigest(
		"short", fmt.Sprintf("%062x", 1)); err == nil {
		t.Fatal("short digest was accepted")
	}
}
