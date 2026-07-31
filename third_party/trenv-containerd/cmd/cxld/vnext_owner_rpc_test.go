package main

import (
	"encoding/binary"
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

func vnextOwnerRPCTestRoundTrip(
	t *testing.T,
	rpc *vnextOwnerRPC,
	request daemonRequest,
) execResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveConnWithVNextOwnerRPC(server, rpc)
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
	unknown := runCommandWithVNextOwnerRPC(daemonRequest{
		Operation: vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: json.RawMessage(`{
			"protocol":"cxld.vnext-owner.v1",
			"unknownMandatoryField":true
		}`),
	}, rpc)
	if unknown.Ok || unknown.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(unknown.Error, "unknown field") {
		t.Fatalf("unknown field was not rejected strictly: %#v", unknown)
	}

	valid := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCTestReserveRequest("owner-0"))
	trailingRaw := append(append(json.RawMessage(nil), valid...), []byte(` {}`)...)
	trailing := runCommandWithVNextOwnerRPC(daemonRequest{
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

	mixed := runCommandWithVNextOwnerRPC(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: valid,
		Container:         &containerRequest{},
	}, rpc)
	if mixed.Ok || mixed.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(mixed.Error, "legacy operation payload") {
		t.Fatalf("mixed VNext/legacy payload was not rejected: %#v", mixed)
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
			raw: `{"protocol":"cxld.vnext-owner.v1","protocol":"cxld.vnext-owner.v1",` +
				`"requestId":"r","checkpointId":"c","producerId":"p","ownerId":"o",` +
				`"ownerEpoch":1,"contents":[],"maxExtents":1}`,
			target:  &vnextOwnerRPCReserveRequest{},
			contain: "duplicate field",
		},
		{
			name:    "case variant protocol",
			raw:     `{"Protocol":"cxld.vnext-owner.v1"}`,
			target:  &vnextOwnerRPCReserveRequest{},
			contain: "unknown field",
		},
		{
			name:    "repeated contents",
			raw:     `{"protocol":"cxld.vnext-owner.v1","contents":[],"contents":[]}`,
			target:  &vnextOwnerRPCReserveRequest{},
			contain: "duplicate field",
		},
		{
			name: "duplicate nested identity",
			raw: `{"protocol":"cxld.vnext-owner.v1","identity":{` +
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

func TestVNextOwnerRPCFailsClosedWhenUnavailableOrPayloadShapeIsAmbiguous(t *testing.T) {
	reserve := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCTestReserveRequest("owner-0"))
	unavailable := runCommandWithVNextOwnerRPC(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: reserve,
	}, nil)
	if unavailable.Ok || unavailable.ErrorCode != string(vnextOwnerServiceUnavailable) {
		t.Fatalf("unconfigured VNext Owner did not fail closed: %#v", unavailable)
	}

	ambiguous := runCommandWithVNextOwnerRPC(daemonRequest{
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: reserve,
		VNextOwnerAbort:   json.RawMessage(`{}`),
	}, nil)
	if ambiguous.Ok || ambiguous.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(ambiguous.Error, "exactly one operation payload") {
		t.Fatalf("ambiguous operation payload did not fail closed: %#v", ambiguous)
	}

	timeout := runCommandWithVNextOwnerRPC(daemonRequest{
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
			response := runCommandWithVNextOwnerRPC(
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
	response := runCommandWithVNextOwnerRPC(daemonRequest{
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
	response := runCommandWithVNextOwnerRPC(daemonRequest{
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

func TestVNextOwnerRPCSealReturnsExactPublicationLocator(t *testing.T) {
	fixture := newVNextExternalSealTestFixture(t, vnextCRCCopyEngineCPU)
	service, err := newVNextOwnerService(fixture.owner.group, fixture.directory)
	if err != nil {
		t.Fatalf("build RPC seal service: %v", err)
	}
	envelope, err := cxlcheckpoint.Encode(fixture.publication)
	if err != nil {
		t.Fatalf("encode RPC seal publication: %v", err)
	}
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
		}),
	})
	if !response.Ok {
		t.Fatalf("seal RPC failed: %#v", response)
	}
	var locator vnextOwnerRPCSealResponse
	if err := json.Unmarshal([]byte(response.Stdout), &locator); err != nil {
		t.Fatalf("decode seal locator: %v", err)
	}
	if locator.PublicationByteLength != uint64(len(envelope)) ||
		len(locator.PublicationSHA256) != 64 || len(locator.PageRuns) == 0 {
		t.Fatalf("seal RPC returned incomplete exact locator: %#v", locator)
	}

	// The bounded Owner service does not yet expose direct writes for these
	// remaining control objects. Seal them through the existing test-only
	// Owner helper, then prove that the actual RPC dispatcher reaches commit
	// and that its terminal retry is idempotent.
	fixture.sealControlPages(t)
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
	response := runCommandWithVNextOwnerRPC(daemonRequest{
		Operation: vnextOwnerRPCOperationSeal,
		VNextOwnerSeal: marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCSealRequest{
			Protocol:            vnextOwnerRPCProtocol,
			PublicationEnvelope: []byte(cxlcheckpoint.MagicString),
			CRCPageSidecars: []vnextOwnerRPCSidecar{
				{PagesImageID: 7, Bytes: []byte{1}},
				{PagesImageID: 7, Bytes: []byte{2}},
			},
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
		Protocol:            vnextOwnerRPCProtocol,
		PublicationEnvelope: make([]byte, vnextOwnerRPCMaxPublicationBytes+1),
		CRCPageSidecars:     vnextOwnerRPCSidecars{},
	}))
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "allowed range") {
		t.Fatalf("oversized publication crossed the control transport: %#v", response)
	}
}

func TestVNextOwnerRPCBoundsStructuralArraysDuringJSONDecode(t *testing.T) {
	tooManyContents := "[" +
		strings.TrimSuffix(strings.Repeat("{},", vnextOwnerRPCMaxContents+1), ",") +
		"]"
	reserve := (&vnextOwnerRPC{}).reserve(json.RawMessage(
		`{"protocol":"` + vnextOwnerRPCProtocol + `","contents":` + tooManyContents + `}`))
	if reserve.Ok || reserve.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(reserve.Error, "more than") {
		t.Fatalf("oversized contents array was fully decoded: %#v", reserve)
	}

	tooManySidecars := "[" +
		strings.TrimSuffix(strings.Repeat("{},", vnextOwnerRPCMaxSidecars+1), ",") +
		"]"
	seal := (&vnextOwnerRPC{}).seal(json.RawMessage(
		`{"protocol":"` + vnextOwnerRPCProtocol + `","crcPageSidecars":` + tooManySidecars + `}`))
	if seal.Ok || seal.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(seal.Error, "more than") {
		t.Fatalf("oversized sidecar array was fully decoded: %#v", seal)
	}
}
