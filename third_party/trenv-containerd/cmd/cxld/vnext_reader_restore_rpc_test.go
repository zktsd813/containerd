package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type vnextReaderRestoreRPCTestHarness struct {
	fixture *vnextReaderTestFixture
	request vnextReaderActivatedRestoreRequest
	source  *vnextReaderCountingSource
	runner  *vnextReaderTestRunner
	rpc     *vnextReaderRestoreRPC
	raw     json.RawMessage
}

func newVNextReaderRestoreRPCTestHarness(
	t *testing.T,
) *vnextReaderRestoreRPCTestHarness {
	t.Helper()
	fixture := newVNextReaderTestFixture(t)
	store, request := vnextReaderArmTestRestore(t, fixture)
	source := &vnextReaderCountingSource{
		delegate: vnextRegularFileReaderDAXSource{},
	}
	runner := &vnextReaderTestRunner{}
	reader := vnextReaderFirstReadNewReader(
		t, fixture, store, source, runner)
	rpc, err := newVNextReaderRestoreRPC(reader)
	if err != nil {
		t.Fatalf("construct local VNext Reader restore RPC: %v", err)
	}
	raw, err := marshalVNextReaderRestoreRequest(request)
	if err != nil {
		t.Fatalf("marshal local VNext Reader restore request: %v", err)
	}
	return &vnextReaderRestoreRPCTestHarness{
		fixture: fixture,
		request: request,
		source:  source,
		runner:  runner,
		rpc:     rpc,
		raw:     raw,
	}
}

func (harness *vnextReaderRestoreRPCTestHarness) runnerCalls() int {
	harness.runner.mu.Lock()
	defer harness.runner.mu.Unlock()
	return harness.runner.calls
}

func (harness *vnextReaderRestoreRPCTestHarness) assertCalls(
	t *testing.T,
	wantDescriptors int,
	wantContents int,
	wantRunner int,
) {
	t.Helper()
	descriptors, contents := harness.source.counts()
	runner := harness.runnerCalls()
	if descriptors != wantDescriptors || contents != wantContents ||
		runner != wantRunner {
		t.Fatalf("Reader source/runner calls=%d/%d/%d, want %d/%d/%d",
			descriptors, contents, runner,
			wantDescriptors, wantContents, wantRunner)
	}
}

func vnextReaderRestoreDaemonBody(
	t *testing.T,
	raw json.RawMessage,
) []byte {
	t.Helper()
	var payload vnextReaderRestoreRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderRestoreSpec, raw, &payload); err != nil {
		t.Fatalf("decode test restore payload: %v", err)
	}
	body, err := marshalBoundedVNextReaderActivationJSON(
		vnextReaderRestoreSpec,
		vnextReaderRestoreDaemonRequestWire{
			CommandLabel:       "runtime-reader-restore",
			TimeoutMillis:      1000,
			Operation:          vnextReaderRestoreOperation,
			VNextReaderRestore: payload,
		})
	if err != nil {
		t.Fatalf("marshal test restore daemon request: %v", err)
	}
	return body
}

func vnextReaderRestoreDaemonRoundTrip(
	t *testing.T,
	body []byte,
	rpc *vnextReaderRestoreRPC,
	caller vnextOwnerCallerContext,
) execResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveAuthenticatedDaemonConnWithVNextRuntimeBoundariesCallerLimits(
			server, nil, nil, rpc, caller,
			make(chan struct{}, daemonMaxConcurrentLargeBody),
			daemonFrameReadTimeout, daemonFrameWriteTimeout)
		close(done)
	}()
	if err := writeFrame(client, body); err != nil {
		_ = client.Close()
		t.Fatalf("write local Reader daemon frame: %v", err)
	}
	responseBody, err := readFrame(client)
	_ = client.Close()
	if err != nil {
		t.Fatalf("read local Reader daemon response: %v", err)
	}
	<-done
	var response execResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("decode local Reader daemon response: %v", err)
	}
	return response
}

func TestVNextReaderRestoreRPCStrictRoundTripAndMetadataOnlySuccess(
	t *testing.T,
) {
	harness := newVNextReaderRestoreRPCTestHarness(t)
	decoded, err := decodeVNextReaderRestoreRequest(harness.raw)
	if err != nil {
		t.Fatalf("decode strict local VNext Reader restore request: %v", err)
	}
	if !reflect.DeepEqual(decoded, harness.request) {
		t.Fatalf("strict restore round trip changed request:\n got=%#v\nwant=%#v",
			decoded, harness.request)
	}

	response := runVNextReaderRestoreRPC(harness.raw, 1000, harness.rpc)
	if !response.Ok || response.Error != "" || response.ErrorCode != "" {
		t.Fatalf("local VNext Reader restore response=%#v", response)
	}
	var success vnextReaderRestoreSuccessWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderRestoreSpec,
		[]byte(strings.TrimSuffix(response.Stdout, "\n")),
		&success); err != nil {
		t.Fatalf("decode bounded restore success: %v", err)
	}
	root := harness.request.Activation.Request.Acquired.Authorization.Root
	if success.Protocol != vnextReaderRestoreProtocol ||
		success.Operation != vnextReaderRestoreOperation ||
		success.RestoreAuthorizationID !=
			harness.request.Request.RestoreAuthorizationID ||
		success.CheckpointID != harness.request.Request.CheckpointID ||
		success.TargetContainerID != harness.request.Request.TargetContainerID ||
		success.RootID != root.RootID || success.RootVersion != root.RootVersion ||
		success.MappingID != harness.request.Activation.MappingID ||
		success.MappingGeneration != harness.request.Activation.MappingGeneration {
		t.Fatalf("bounded restore success changed identity: %#v", success)
	}
	for _, binding := range harness.fixture.directory.byUUID {
		if strings.Contains(response.Stdout, binding.DevicePath) {
			t.Fatalf("restore success leaked local DAX path %q", binding.DevicePath)
		}
	}
	for _, forbidden := range []string{
		"exactBytes", "pageRuns", "publicationLocator", "deviceUuid",
		"dataPageIndex", "fileDescriptor", "mappingOffset",
	} {
		if strings.Contains(response.Stdout, forbidden) {
			t.Fatalf("restore success leaked payload/location field %q: %s",
				forbidden, response.Stdout)
		}
	}
	harness.assertCalls(t, 4, 2, 1)
}

func TestVNextReaderRestoreRPCRejectsMalformedAndSubstitutedBeforeSource(
	t *testing.T,
) {
	harness := newVNextReaderRestoreRPCTestHarness(t)
	var wire vnextReaderRestoreRequestWire
	if err := json.Unmarshal(harness.raw, &wire); err != nil {
		t.Fatalf("decode test wire: %v", err)
	}
	encode := func(value interface{}) json.RawMessage {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("encode malformed test request: %v", err)
		}
		return raw
	}
	pending := wire
	pending.State = vnextReaderActivationPending
	substituted := wire
	substituted.Request.TargetContainerID = "substituted-target"
	var missingAcquired map[string]interface{}
	if err := json.Unmarshal(harness.raw, &missingAcquired); err != nil {
		t.Fatalf("decode missing-field test request: %v", err)
	}
	delete(missingAcquired, "acquired")
	unknown := bytes.Replace(
		harness.raw,
		[]byte(`"state":"ACTIVE_ARMED"`),
		[]byte(`"state":"ACTIVE_ARMED","unknown":true`), 1)
	duplicate := bytes.Replace(
		harness.raw,
		[]byte(`"state":"ACTIVE_ARMED"`),
		[]byte(`"state":"ACTIVE_ARMED","state":"ACTIVE_ARMED"`), 1)
	shortIDOnly := json.RawMessage(
		`{"protocol":"cxld.vnext-reader-restore.v1",` +
			`"operation":"vnextReaderRestore",` +
			`"restoreAuthorizationId":"reader-restore-authorization"}`)
	oversized := bytes.Repeat(
		[]byte{' '}, vnextReaderActivationMaxFrameBytes+1)

	tests := []struct {
		name    string
		raw     json.RawMessage
		timeout int64
	}{
		{name: "PENDING", raw: encode(pending), timeout: 1000},
		{name: "outer-target-substitution", raw: encode(substituted), timeout: 1000},
		{name: "missing-historical-ACQUIRED", raw: encode(missingAcquired), timeout: 1000},
		{name: "short-ID-only", raw: shortIDOnly, timeout: 1000},
		{name: "unknown-field", raw: unknown, timeout: 1000},
		{name: "duplicate-field", raw: duplicate, timeout: 1000},
		{name: "trailing-value", raw: append(append([]byte(nil), harness.raw...), []byte(` {}`)...), timeout: 1000},
		{name: "oversized", raw: oversized, timeout: 1000},
		{name: "negative-timeout", raw: harness.raw, timeout: -1},
		{name: "oversized-timeout", raw: harness.raw, timeout: int64(vnextReaderRestoreMaxTimeout/time.Millisecond) + 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := runVNextReaderRestoreRPC(
				test.raw, test.timeout, harness.rpc)
			if response.Ok || response.ErrorCode !=
				string(vnextReaderRestoreInvalidRequest) {
				t.Fatalf("invalid restore response=%#v", response)
			}
		})
	}
	harness.assertCalls(t, 0, 0, 0)
}

func TestVNextReaderRestoreRPCUnavailableDoesNotConsumeActivation(
	t *testing.T,
) {
	harness := newVNextReaderRestoreRPCTestHarness(t)
	response := runVNextReaderRestoreRPC(harness.raw, 1000, nil)
	if response.Ok || response.ErrorCode != string(vnextReaderRestoreUnavailable) {
		t.Fatalf("unconfigured restore response=%#v", response)
	}
	harness.assertCalls(t, 0, 0, 0)

	response = runVNextReaderRestoreRPC(harness.raw, 1000, harness.rpc)
	if !response.Ok {
		t.Fatalf("configured restore after unavailable response=%#v", response)
	}
	harness.assertCalls(t, 4, 2, 1)
}

func TestVNextReaderRestoreRPCHidesDAXAndCRIUInternalErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*vnextReaderRestoreRPCTestHarness, error)
	}{
		{
			name: "DAX-source",
			mutate: func(
				harness *vnextReaderRestoreRPCTestHarness,
				failure error,
			) {
				harness.rpc.reader.source =
					vnextReaderFirstReadDescriptorErrorSource{err: failure}
			},
		},
		{
			name: "CRIU-runner",
			mutate: func(
				harness *vnextReaderRestoreRPCTestHarness,
				failure error,
			) {
				harness.runner.err = failure
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			harness := newVNextReaderRestoreRPCTestHarness(t)
			secretPath := harness.fixture.directory.byUUID["reader-device-a"].DevicePath +
				"/private-criu-work"
			failure := errors.New("internal host failure at " + secretPath)
			test.mutate(harness, failure)
			response := runVNextReaderRestoreRPC(
				harness.raw, 1000, harness.rpc)
			if response.Ok || response.ErrorCode !=
				string(vnextReaderRestoreFailed) ||
				response.Error != "VNext Reader restore failed" {
				t.Fatalf("internal failure response=%#v", response)
			}
			encoded, err := json.Marshal(response)
			if err != nil {
				t.Fatalf("encode internal failure response: %v", err)
			}
			if bytes.Contains(encoded, []byte(secretPath)) ||
				bytes.Contains(encoded, []byte(failure.Error())) {
				t.Fatalf("internal failure leaked through response: %#v", response)
			}
		})
	}
}

func TestVNextReaderRestoreTimeoutMatchesBoundedShutdownDrain(t *testing.T) {
	if vnextReaderRestoreDefaultTimeout != daemonFrameReadTimeout {
		t.Fatalf("Reader default timeout=%s, daemon read timeout=%s",
			vnextReaderRestoreDefaultTimeout, daemonFrameReadTimeout)
	}
	if vnextReaderRestoreMaxTimeout != daemonFrameReadTimeout {
		t.Fatalf("Reader maximum timeout=%s, daemon read timeout=%s",
			vnextReaderRestoreMaxTimeout, daemonFrameReadTimeout)
	}
	if vnextReaderRestoreMaxTimeout != daemonFrameWriteTimeout {
		t.Fatalf("Reader timeout default/max=%s/%s, daemon read/write=%s/%s",
			vnextReaderRestoreDefaultTimeout, vnextReaderRestoreMaxTimeout,
			daemonFrameReadTimeout, daemonFrameWriteTimeout)
	}
	if timeout, err := vnextReaderRestoreTimeout(0); err != nil ||
		timeout != 30*time.Second {
		t.Fatalf("default bounded Reader timeout=%s err=%v", timeout, err)
	}
	if timeout, err := vnextReaderRestoreTimeout(30_000); err != nil ||
		timeout != 30*time.Second {
		t.Fatalf("maximum bounded Reader timeout=%s err=%v", timeout, err)
	}
	if _, err := vnextReaderRestoreTimeout(30_001); err == nil {
		t.Fatal("Reader timeout accepted a shutdown drain above 30 seconds")
	}
}

func TestVNextReaderRestoreRPCReplayHasNoSecondSourceCall(t *testing.T) {
	harness := newVNextReaderRestoreRPCTestHarness(t)
	if response := runVNextReaderRestoreRPC(
		harness.raw, 1000, harness.rpc); !response.Ok {
		t.Fatalf("first restore response=%#v", response)
	}
	harness.assertCalls(t, 4, 2, 1)
	response := runVNextReaderRestoreRPC(harness.raw, 1000, harness.rpc)
	if response.Ok || response.ErrorCode !=
		string(vnextReaderRestoreActivationRejected) {
		t.Fatalf("replayed restore response=%#v", response)
	}
	harness.assertCalls(t, 4, 2, 1)
}

func TestVNextReaderRestoreRPCConcurrentReplayHasExactlyOneWinner(
	t *testing.T,
) {
	const callers = 64
	harness := newVNextReaderRestoreRPCTestHarness(t)
	start := make(chan struct{})
	var successes int64
	var rejected int64
	var unexpected int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			<-start
			response := runVNextReaderRestoreRPC(
				harness.raw, 1000, harness.rpc)
			switch {
			case response.Ok:
				atomic.AddInt64(&successes, 1)
			case response.ErrorCode ==
				string(vnextReaderRestoreActivationRejected):
				atomic.AddInt64(&rejected, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if successes != 1 || rejected != callers-1 || unexpected != 0 {
		t.Fatalf("concurrent restore results success=%d rejected=%d unexpected=%d",
			successes, rejected, unexpected)
	}
	harness.assertCalls(t, 4, 2, 1)
}

func TestVNextReaderRestoreDaemonEnvelopeRejectsMixedRequests(
	t *testing.T,
) {
	harness := newVNextReaderRestoreRPCTestHarness(t)
	valid := vnextReaderRestoreDaemonBody(t, harness.raw)
	request, err := decodeDaemonRequestWithVNextReaderRestore(valid)
	if err != nil {
		t.Fatalf("decode exact Reader daemon envelope: %v", err)
	}
	if request.Operation != vnextReaderRestoreOperation ||
		len(request.VNextReaderRestore) == 0 {
		t.Fatalf("decoded Reader daemon request=%#v", request)
	}

	mixedOwner := append([]byte(nil), valid[:len(valid)-1]...)
	mixedOwner = append(mixedOwner, []byte(
		`,"vnextOwnerInventory":{"protocol":"ignored"}}`)...)
	duplicateOperation := bytes.Replace(
		valid,
		[]byte(`"operation":"vnextReaderRestore"`),
		[]byte(`"operation":"vnextReaderRestore",`+
			`"operation":"vnextReaderRestore"`), 1)
	wrongOperation := bytes.Replace(
		valid,
		[]byte(`"operation":"vnextReaderRestore"`),
		[]byte(`"operation":"vnextOwnerInventory"`), 1)
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "mixed-Owner", body: mixedOwner},
		{name: "duplicate-operation", body: duplicateOperation},
		{name: "Reader-payload-with-Owner-operation", body: wrongOperation},
		{name: "trailing", body: append(append([]byte(nil), valid...), []byte(` {}`)...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeDaemonRequestWithVNextReaderRestore(
				test.body); err == nil {
				t.Fatal("mixed or malformed Reader daemon envelope was accepted")
			}
		})
	}
	harness.assertCalls(t, 0, 0, 0)
}

func TestVNextReaderRestoreDispatchIsProducerLocalAndNeverOwnerGateway(
	t *testing.T,
) {
	producer := newVNextReaderRestoreRPCTestHarness(t)
	body := vnextReaderRestoreDaemonBody(t, producer.raw)
	request, err := decodeDaemonRequestWithVNextReaderRestore(body)
	if err != nil {
		t.Fatalf("decode producer Reader request: %v", err)
	}
	// An empty Owner gateway would be unusable if dispatch reached it. Success
	// therefore also proves that this operation stays on the local Reader path.
	response := runCommandWithVNextRuntimeBoundariesCaller(
		request, nil, &vnextOwnerGateway{}, producer.rpc,
		vnextOwnerInternalCaller(vnextOwnerCallerProducer))
	if !response.Ok {
		t.Fatalf("producer-local Reader restore response=%#v", response)
	}
	producer.assertCalls(t, 4, 2, 1)

	scheduler := newVNextReaderRestoreRPCTestHarness(t)
	schedulerRequest, err := decodeDaemonRequestWithVNextReaderRestore(
		vnextReaderRestoreDaemonBody(t, scheduler.raw))
	if err != nil {
		t.Fatalf("decode scheduler Reader request: %v", err)
	}
	response = runCommandWithVNextRuntimeBoundariesCaller(
		schedulerRequest, nil, &vnextOwnerGateway{}, scheduler.rpc,
		vnextOwnerInternalCaller(vnextOwnerCallerScheduler))
	if response.Ok || response.ErrorCode !=
		string(vnextOwnerServicePermissionDenied) {
		t.Fatalf("Scheduler control Reader restore response=%#v", response)
	}
	scheduler.assertCalls(t, 0, 0, 0)
}

func TestVNextReaderRestoreAuthenticatedDaemonFrameIsProducerOnly(
	t *testing.T,
) {
	producer := newVNextReaderRestoreRPCTestHarness(t)
	response := vnextReaderRestoreDaemonRoundTrip(
		t, vnextReaderRestoreDaemonBody(t, producer.raw), producer.rpc,
		vnextOwnerInternalCaller(vnextOwnerCallerProducer))
	if !response.Ok || response.Operation != vnextReaderRestoreOperation {
		t.Fatalf("Producer Reader daemon response=%#v", response)
	}
	producer.assertCalls(t, 4, 2, 1)

	scheduler := newVNextReaderRestoreRPCTestHarness(t)
	response = vnextReaderRestoreDaemonRoundTrip(
		t, vnextReaderRestoreDaemonBody(t, scheduler.raw), scheduler.rpc,
		vnextOwnerInternalCaller(vnextOwnerCallerScheduler))
	if response.Ok || response.ErrorCode !=
		string(vnextOwnerServicePermissionDenied) ||
		response.Operation != vnextReaderRestoreOperation {
		t.Fatalf("Scheduler Reader daemon response=%#v", response)
	}
	scheduler.assertCalls(t, 0, 0, 0)
}
