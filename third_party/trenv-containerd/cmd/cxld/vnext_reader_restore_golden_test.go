package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderRestoreScalaContractMarker = "$GO_V6_COMPATIBILITY_ID"

	// Copied from CxldVNextReaderRestoreClientTests.scala. The contract marker
	// is replaced with the authoritative Go identity below so either language
	// changing a V6 component requires an explicit cross-language update.
	vnextReaderRestoreScalaGoldenPayloadTemplate = `{"protocol":"cxld.vnext-reader-restore.v1","operation":"vnextReaderRestore","request":{"restoreAuthorizationId":"authorization-activation-a","checkpointId":"checkpoint-a","executorNodeId":"executor-a","executorCxldLogicalId":"reader-cxld-a","targetContainerId":"target-container-a"},"acquired":{"authorization":{"restoreAuthorizationId":"authorization-activation-a","checkpointId":"checkpoint-a","executorNodeId":"executor-a","executorCxldLogicalId":"reader-cxld-a","executorCxldProcessIncarnationId":"58d5ba587f0128968a26f3bd32c69bfbe8a01fdd69738b9137f34ec6343e95c4","readerInitialRegistrationCatalogRevision":47,"targetContainerId":"target-container-a","root":{"rootId":"root-a","rootVersion":7,"mmTemplateId":"mm-template-a","pageMapId":"page-map-a","pageMapVersion":11,"deviceTableDigest":"ce03c6dc31b76bde4e91d53ed53bc4cc5789b25201ca1951e5bcc6296621dd5e","contractId":"$GO_V6_COMPATIBILITY_ID","publicationLocator":{"publicationByteLength":4096,"publicationSha256":"fa63a5b64742c4a39fd076c5d94cd3c17054ced0e7dd3c520651bff6db3f5f85","pageRuns":[{"firstPage":{"ownerId":"owner-a","deviceUuid":"device-a","allocationRecordId":13,"dataPageIndex":17},"pageCount":1}]}}},"schedulerId":"scheduler-activation-a","schedulerFenceRevision":41,"issuedAtEpochMillis":100,"expiresAtEpochMillis":200,"catalogState":"ACQUIRED","lastMutationId":"authorization-activation-a"},"activation":{"activationRequestId":"activation-request-a","mappingId":"mapping-a","mappingGeneration":53,"activatedAtEpochMillis":150,"cxldReceipt":"a00113cb2573111703761231bf444bc8e0df640356e92bf899c1b49c89890f03"},"state":"ACTIVE_ARMED"}`

	vnextReaderRestoreScalaGoldenSuccess = `{"protocol":"cxld.vnext-reader-restore.v1","operation":"vnextReaderRestore","restoreAuthorizationId":"authorization-activation-a","checkpointId":"checkpoint-a","targetContainerId":"target-container-a","rootId":"root-a","rootVersion":7,"mappingId":"mapping-a","mappingGeneration":53}`
)

func vnextReaderRestoreScalaGoldenPayload(t *testing.T) []byte {
	t.Helper()
	if strings.Count(
		vnextReaderRestoreScalaGoldenPayloadTemplate,
		vnextReaderRestoreScalaContractMarker,
	) != 1 {
		t.Fatal("Scala restore golden must contain exactly one V6 contract marker")
	}
	return []byte(strings.Replace(
		vnextReaderRestoreScalaGoldenPayloadTemplate,
		vnextReaderRestoreScalaContractMarker,
		cxlcheckpoint.V6CompatibilityID,
		1))
}

func vnextReaderRestoreScalaGoldenEnvelope(t *testing.T) []byte {
	t.Helper()
	return []byte(`{"commandLabel":"runtime-reader-restore","timeoutMillis":1000,"operation":"vnextReaderRestore","vnextReaderRestore":` +
		string(vnextReaderRestoreScalaGoldenPayload(t)) + `}`)
}

func vnextReaderRestoreScalaGoldenExpected(
	t *testing.T,
) vnextReaderActivatedRestoreRequest {
	t.Helper()
	activationFixture := vnextReaderActivationGoldenFixtureValue(t)
	activation := activationFixture.activation
	activation.State = vnextReaderActivationActiveArmed
	return vnextReaderActivatedRestoreRequest{
		Request: vnextReaderRequest{
			RestoreAuthorizationID: "authorization-activation-a",
			CheckpointID:           "checkpoint-a",
			ExecutorID:             "executor-a",
			CxldLogicalID:          "reader-cxld-a",
			TargetContainerID:      "target-container-a",
		},
		Activation: activation,
	}
}

func TestVNextReaderRestoreScalaGoldenRequestCrossLanguage(t *testing.T) {
	payload := vnextReaderRestoreScalaGoldenPayload(t)
	envelope := vnextReaderRestoreScalaGoldenEnvelope(t)

	daemon, err := decodeDaemonRequestWithVNextReaderRestore(envelope)
	if err != nil {
		t.Fatalf("strictly decode Scala daemon envelope: %v", err)
	}
	if daemon.CommandLabel != "runtime-reader-restore" ||
		daemon.TimeoutMillis != 1000 ||
		daemon.Operation != vnextReaderRestoreOperation {
		t.Fatalf("Scala daemon envelope identity changed: %#v", daemon)
	}
	if !bytes.Equal(daemon.VNextReaderRestore, payload) {
		t.Fatalf("Go daemon canonical payload differs from Scala golden:\n got=%s\nwant=%s",
			daemon.VNextReaderRestore, payload)
	}

	decoded, err := decodeVNextReaderRestoreRequest(
		daemon.VNextReaderRestore)
	if err != nil {
		t.Fatalf("strictly decode Scala restore payload: %v", err)
	}
	expected := vnextReaderRestoreScalaGoldenExpected(t)
	if !reflect.DeepEqual(decoded, expected) {
		t.Fatalf("Scala restore payload changed identity or ACTIVE_ARMED evidence:\n got=%#v\nwant=%#v",
			decoded, expected)
	}
	if got := decoded.Activation.Request.Acquired.Authorization.Root.ContractID; got != cxlcheckpoint.V6CompatibilityID {
		t.Fatalf("Scala restore contract identity=%q, want authoritative Go identity %q",
			got, cxlcheckpoint.V6CompatibilityID)
	}

	encoded, err := marshalVNextReaderRestoreRequest(decoded)
	if err != nil {
		t.Fatalf("marshal decoded Scala restore request: %v", err)
	}
	if !bytes.Equal(encoded, payload) {
		t.Fatalf("Go canonical restore payload differs from exact Scala golden:\n got=%s\nwant=%s",
			encoded, payload)
	}

	var requestWire vnextReaderRestoreRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderRestoreSpec, payload, &requestWire); err != nil {
		t.Fatalf("strictly decode Scala request wire for envelope encoding: %v", err)
	}
	encodedEnvelope, err := marshalBoundedVNextReaderActivationJSON(
		vnextReaderRestoreSpec,
		vnextReaderRestoreDaemonRequestWire{
			CommandLabel:       "runtime-reader-restore",
			TimeoutMillis:      1000,
			Operation:          vnextReaderRestoreOperation,
			VNextReaderRestore: requestWire,
		})
	if err != nil {
		t.Fatalf("marshal Go daemon restore envelope: %v", err)
	}
	if !bytes.Equal(encodedEnvelope, envelope) {
		t.Fatalf("Go daemon envelope differs from exact Scala golden:\n got=%s\nwant=%s",
			encodedEnvelope, envelope)
	}
}

func TestVNextReaderRestoreScalaGoldenStrictlyRejectsDuplicateAndUnknown(
	t *testing.T,
) {
	payload := vnextReaderRestoreScalaGoldenPayload(t)
	envelope := vnextReaderRestoreScalaGoldenEnvelope(t)
	outerCases := map[string][]byte{
		"duplicate": bytes.Replace(
			envelope,
			[]byte(`"timeoutMillis":1000`),
			[]byte(`"timeoutMillis":1000,"timeoutMillis":1000`),
			1),
		"unknown": bytes.Replace(
			envelope,
			[]byte(`{"commandLabel"`),
			[]byte(`{"unknown":true,"commandLabel"`),
			1),
	}
	for name, malformed := range outerCases {
		t.Run("outer-"+name, func(t *testing.T) {
			if _, err := decodeDaemonRequestWithVNextReaderRestore(
				malformed); err == nil {
				t.Fatal("Go daemon accepted malformed Scala envelope")
			}
		})
	}

	innerCases := map[string][]byte{
		"duplicate": bytes.Replace(
			payload,
			[]byte(`"state":"ACTIVE_ARMED"`),
			[]byte(`"state":"ACTIVE_ARMED","state":"ACTIVE_ARMED"`),
			1),
		"unknown": bytes.Replace(
			payload,
			[]byte(`{"protocol"`),
			[]byte(`{"unknown":true,"protocol"`),
			1),
	}
	for name, malformed := range innerCases {
		t.Run("inner-"+name, func(t *testing.T) {
			if _, err := decodeVNextReaderRestoreRequest(malformed); err == nil {
				t.Fatal("Go daemon accepted malformed Scala restore payload")
			}
		})
	}
}

func TestVNextReaderRestoreScalaGoldenSuccessCrossLanguage(t *testing.T) {
	request, err := decodeVNextReaderRestoreRequest(
		vnextReaderRestoreScalaGoldenPayload(t))
	if err != nil {
		t.Fatalf("decode Scala restore payload for success: %v", err)
	}
	root := request.Activation.Request.Acquired.Authorization.Root
	want := vnextReaderRestoreSuccessWire{
		Protocol:               vnextReaderRestoreProtocol,
		Operation:              vnextReaderRestoreOperation,
		RestoreAuthorizationID: request.Request.RestoreAuthorizationID,
		CheckpointID:           request.Request.CheckpointID,
		TargetContainerID:      request.Request.TargetContainerID,
		RootID:                 root.RootID,
		RootVersion:            root.RootVersion,
		MappingID:              request.Activation.MappingID,
		MappingGeneration:      request.Activation.MappingGeneration,
	}
	encoded, err := marshalBoundedVNextReaderActivationJSON(
		vnextReaderRestoreSpec, want)
	if err != nil {
		t.Fatalf("marshal Go restore success: %v", err)
	}
	golden := []byte(vnextReaderRestoreScalaGoldenSuccess)
	if !bytes.Equal(encoded, golden) {
		t.Fatalf("Go restore success differs from exact Scala golden:\n got=%s\nwant=%s",
			encoded, golden)
	}
	var decoded vnextReaderRestoreSuccessWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderRestoreSpec, golden, &decoded); err != nil {
		t.Fatalf("strictly decode Scala restore success: %v", err)
	}
	if !reflect.DeepEqual(decoded, want) {
		t.Fatalf("Scala restore success changed bounded identity:\n got=%#v\nwant=%#v",
			decoded, want)
	}

	for name, malformed := range map[string][]byte{
		"duplicate": bytes.Replace(
			golden,
			[]byte(`"mappingGeneration":53`),
			[]byte(`"mappingGeneration":53,"mappingGeneration":53`),
			1),
		"unknown": bytes.Replace(
			golden,
			[]byte(`{"protocol"`),
			[]byte(`{"unknown":true,"protocol"`),
			1),
	} {
		t.Run(name, func(t *testing.T) {
			var malformedWire vnextReaderRestoreSuccessWire
			if err := decodeStrictVNextReaderActivationJSON(
				vnextReaderRestoreSpec, malformed, &malformedWire); err == nil {
				t.Fatal("Go decoder accepted malformed Scala restore success")
			}
		})
	}
}
