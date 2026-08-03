package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type vnextReaderPreparedStatusTLSTestHandler struct {
	mu         sync.Mutex
	calls      int
	principals []string
	frames     [][]byte
	responses  [][]byte
	inner      vnextReaderPreparedStatusTransportRPC
	handle     func(context.Context, string, []byte) (
		[]byte, *vnextReaderPreparedStatusRPCError)
}

func (handler *vnextReaderPreparedStatusTLSTestHandler) Handle(
	ctx context.Context,
	principal string,
	frame []byte,
) ([]byte, *vnextReaderPreparedStatusRPCError) {
	handler.mu.Lock()
	handler.calls++
	handler.principals = append(handler.principals,
		cloneVNextReaderRetainedString(principal))
	handler.frames = append(handler.frames, append([]byte(nil), frame...))
	handle := handler.handle
	inner := handler.inner
	handler.mu.Unlock()
	var body []byte
	var failure *vnextReaderPreparedStatusRPCError
	if handle != nil {
		body, failure = handle(ctx, principal, frame)
	} else {
		body, failure = inner.Handle(ctx, principal, frame)
	}
	handler.mu.Lock()
	handler.responses = append(
		handler.responses, append([]byte(nil), body...))
	handler.mu.Unlock()
	return body, failure
}

func (handler *vnextReaderPreparedStatusTLSTestHandler) snapshot() (
	int, []string, [][]byte, [][]byte,
) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	cloneBytes := func(values [][]byte) [][]byte {
		cloned := make([][]byte, len(values))
		for index, value := range values {
			cloned[index] = append([]byte(nil), value...)
		}
		return cloned
	}
	return handler.calls,
		append([]string(nil), handler.principals...),
		cloneBytes(handler.frames), cloneBytes(handler.responses)
}

func startVNextReaderPrepareAndStatusTLSTestServer(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	prepareRPC vnextReaderPrepareTransportRPC,
	statusRPC vnextReaderPreparedStatusTransportRPC,
	mutate func(*vnextReaderPrepareTLSServerConfig),
) (*vnextReaderPrepareTLSServer, chan struct{}, chan struct{}) {
	t.Helper()
	config := vnextReaderPrepareTLSTestConfig(material)
	if mutate != nil {
		mutate(&config)
	}
	requestAdmission := make(chan struct{}, 64)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareAndStatusTLSServer(
		config, prepareRPC, statusRPC, requestAdmission, largeAdmission)
	if err != nil {
		t.Fatalf("start VNext Reader PREPARE/STATUS TLS test server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close VNext Reader PREPARE/STATUS TLS test server: %v", err)
		}
	})
	return server, requestAdmission, largeAdmission
}

func vnextReaderPreparedStatusTLSTestClientConfig(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
) *tls.Config {
	t.Helper()
	config := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath,
		material.clientPrivateKeyPath)
	config.NextProtos = []string{vnextReaderPreparedStatusALPN}
	return config
}

func readVNextReaderPreparedStatusTLSTestFailure(
	t *testing.T,
	conn net.Conn,
) vnextReaderPreparedStatusTLSFailureWire {
	t.Helper()
	body, err := readVNextReaderPrepareTLSTestFrame(conn)
	if err != nil {
		t.Fatalf("read Reader STATUS_AND_FENCE TLS failure frame: %v", err)
	}
	wire, err := decodeStrictVNextReaderPreparedStatusTLSFailure(body)
	if err != nil {
		t.Fatalf("decode Reader STATUS_AND_FENCE TLS failure: %v; body=%s", err, body)
	}
	return wire
}

func vnextReaderPreparedStatusTLSTestValidResponseBody(t *testing.T) []byte {
	t.Helper()
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal,
		fixture.frame)
	if failure != nil {
		t.Fatalf("create valid STATUS_AND_FENCE TLS response fixture: %v", failure)
	}
	if _, err := decodeVNextReaderPreparedStatusResponse(body); err != nil {
		t.Fatalf("validate STATUS_AND_FENCE TLS response fixture: %v", err)
	}
	return body
}

func TestVNextReaderPrepareAndStatusTLSExactALPNDispatchesRealMTLSRPCs(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	prepareFixture := newVNextReaderPrepareTestFixture(t)
	statusFixture := newVNextReaderPreparedStatusTestFixture(t)
	statusFixture.verifier.wantPrincipal = vnextReaderPrepareTestPrincipal
	prepareHandler := &vnextReaderPrepareTLSTestHandler{inner: prepareFixture.rpc}
	statusHandler := &vnextReaderPreparedStatusTLSTestHandler{inner: statusFixture.rpc}
	server, requestAdmission, largeAdmission :=
		startVNextReaderPrepareAndStatusTLSTestServer(
			t, material, prepareHandler, statusHandler, nil)
	if server.tlsConfig.MinVersion != tls.VersionTLS13 ||
		server.tlsConfig.MaxVersion != tls.VersionTLS13 ||
		server.tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert ||
		!server.tlsConfig.SessionTicketsDisabled ||
		len(server.tlsConfig.NextProtos) != 2 ||
		server.tlsConfig.NextProtos[0] != vnextReaderPrepareALPN ||
		server.tlsConfig.NextProtos[1] != vnextReaderPreparedStatusALPN {
		t.Fatalf("dual Reader TLS config is not exact and fail-closed: %#v",
			server.tlsConfig)
	}

	statusConn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderPreparedStatusTLSTestClientConfig(t, material))
	if statusConn.ConnectionState().NegotiatedProtocol !=
		vnextReaderPreparedStatusALPN {
		statusConn.Close()
		t.Fatalf("status negotiated ALPN = %q",
			statusConn.ConnectionState().NegotiatedProtocol)
	}
	if err := writeVNextReaderPrepareTLSTestFrame(
		statusConn, statusFixture.frame); err != nil {
		statusConn.Close()
		t.Fatalf("write STATUS_AND_FENCE TLS request: %v", err)
	}
	statusBody, err := readVNextReaderPrepareTLSTestFrame(statusConn)
	statusConn.Close()
	if err != nil {
		t.Fatalf("read STATUS_AND_FENCE TLS response: %v", err)
	}
	statusResponse, err := decodeVNextReaderPreparedStatusResponse(statusBody)
	if err != nil {
		t.Fatalf("decode STATUS_AND_FENCE TLS response: %v", err)
	}
	if statusResponse.Result.State != vnextReaderPreparedStatusNotPreparedFenced {
		t.Fatalf("status result = %#v", statusResponse.Result)
	}
	if prepareCalls, _, _, _ := prepareHandler.snapshot(); prepareCalls != 0 {
		t.Fatalf("status ALPN dispatched %d PREPARE calls", prepareCalls)
	}
	statusCalls, statusPrincipals, statusFrames, statusResponses :=
		statusHandler.snapshot()
	if statusCalls != 1 || len(statusPrincipals) != 1 ||
		statusPrincipals[0] != vnextReaderPrepareTestPrincipal ||
		len(statusFrames) != 1 ||
		!bytes.Equal(statusFrames[0], statusFixture.frame) ||
		len(statusResponses) != 1 ||
		!bytes.Equal(statusResponses[0], statusBody) {
		t.Fatalf("status TLS boundary changed: calls=%d principals=%#v",
			statusCalls, statusPrincipals)
	}

	prepareConfig := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath,
		material.clientPrivateKeyPath)
	prepareConn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(), prepareConfig)
	if err := writeVNextReaderPrepareTLSTestFrame(
		prepareConn, prepareFixture.frame); err != nil {
		prepareConn.Close()
		t.Fatalf("write PREPARE request to dual listener: %v", err)
	}
	prepareBody, err := readVNextReaderPrepareTLSTestFrame(prepareConn)
	prepareConn.Close()
	if err != nil {
		t.Fatalf("read PREPARE response from dual listener: %v", err)
	}
	if _, err := decodeVNextReaderPrepareResponse(prepareBody); err != nil {
		t.Fatalf("decode PREPARE response from dual listener: %v", err)
	}
	prepareCalls, preparePrincipals, prepareFrames, _ := prepareHandler.snapshot()
	if prepareCalls != 1 || len(preparePrincipals) != 1 ||
		preparePrincipals[0] != vnextReaderPrepareTestPrincipal ||
		len(prepareFrames) != 1 ||
		!bytes.Equal(prepareFrames[0], prepareFixture.frame) {
		t.Fatalf("PREPARE TLS boundary changed: calls=%d principals=%#v",
			prepareCalls, preparePrincipals)
	}
	if statusCalls, _, _, _ := statusHandler.snapshot(); statusCalls != 1 {
		t.Fatalf("PREPARE ALPN changed status calls to %d", statusCalls)
	}
	waitVNextReaderPrepareTLSTestCondition(t, "dual Reader admission release", func() bool {
		return len(requestAdmission) == 0 && len(largeAdmission) == 0
	})
}

func TestVNextReaderPrepareAndStatusTLSNeverInfersOperationFromJSON(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	prepareFixture := newVNextReaderPrepareTestFixture(t)
	statusFixture := newVNextReaderPreparedStatusTestFixture(t)
	statusFixture.verifier.wantPrincipal = vnextReaderPrepareTestPrincipal
	prepareHandler := &vnextReaderPrepareTLSTestHandler{inner: prepareFixture.rpc}
	statusHandler := &vnextReaderPreparedStatusTLSTestHandler{inner: statusFixture.rpc}
	server, _, _ := startVNextReaderPrepareAndStatusTLSTestServer(
		t, material, prepareHandler, statusHandler, nil)

	t.Run("PREPARE body under STATUS ALPN", func(t *testing.T) {
		conn := dialVNextReaderPrepareTLSTest(
			t, server.Addr().String(),
			vnextReaderPreparedStatusTLSTestClientConfig(t, material))
		defer conn.Close()
		if err := writeVNextReaderPrepareTLSTestFrame(
			conn, prepareFixture.frame); err != nil {
			t.Fatal(err)
		}
		failure := readVNextReaderPreparedStatusTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPreparedStatusInvalidRequest ||
			failure.Acceptance !=
				vnextReaderPreparedStatusDefinitelyNotAccepted {
			t.Fatalf("cross-protocol status failure = %#v", failure)
		}
	})
	if prepareCalls, _, _, _ := prepareHandler.snapshot(); prepareCalls != 0 {
		t.Fatalf("status ALPN with PREPARE JSON dispatched PREPARE %d times",
			prepareCalls)
	}

	t.Run("STATUS body under PREPARE ALPN", func(t *testing.T) {
		config := vnextReaderPrepareTLSTestClientConfig(
			t, material, material.clientCertificatePath,
			material.clientPrivateKeyPath)
		conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), config)
		defer conn.Close()
		if err := writeVNextReaderPrepareTLSTestFrame(
			conn, statusFixture.frame); err != nil {
			t.Fatal(err)
		}
		failure := readVNextReaderPrepareTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPrepareInvalidRequest ||
			failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("cross-protocol PREPARE failure = %#v", failure)
		}
	})
	if statusCalls, _, _, _ := statusHandler.snapshot(); statusCalls != 1 {
		t.Fatalf("cross-protocol JSON changed status dispatch count to %d",
			statusCalls)
	}
	if prepareCalls, _, _, _ := prepareHandler.snapshot(); prepareCalls != 1 {
		t.Fatalf("cross-protocol JSON changed PREPARE dispatch count to %d",
			prepareCalls)
	}
}

func TestVNextReaderPrepareAndStatusTLSRejectsWrongOrMissingALPNBeforeDispatch(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	prepareHandler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderPrepareRPCError,
		) {
			return []byte(`{}`), nil
		},
	}
	statusHandler := &vnextReaderPreparedStatusTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderPreparedStatusRPCError,
		) {
			return []byte(`{}`), nil
		},
	}
	server, _, _ := startVNextReaderPrepareAndStatusTLSTestServer(
		t, material, prepareHandler, statusHandler, nil)
	for name, protocols := range map[string][]string{
		"wrong":   {vnextOwnerTLSALPN},
		"missing": nil,
	} {
		t.Run(name, func(t *testing.T) {
			config := vnextReaderPrepareTLSTestClientConfig(
				t, material, material.clientCertificatePath,
				material.clientPrivateKeyPath)
			config.NextProtos = protocols
			dialer := &net.Dialer{Timeout: time.Second}
			conn, err := tls.DialWithDialer(
				dialer, "tcp", server.Addr().String(), config)
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_ = writeVNextReaderPrepareTLSTestFrame(conn, []byte(`{}`))
				if body, readErr := readVNextReaderPrepareTLSTestFrame(conn); readErr == nil {
					conn.Close()
					t.Fatalf("invalid ALPN received application frame %s", body)
				}
				conn.Close()
			}
		})
	}
	if calls, _, _, _ := prepareHandler.snapshot(); calls != 0 {
		t.Fatalf("wrong/missing ALPN dispatched %d PREPARE calls", calls)
	}
	if calls, _, _, _ := statusHandler.snapshot(); calls != 0 {
		t.Fatalf("wrong/missing ALPN dispatched %d status calls", calls)
	}
}

func TestVNextReaderPreparedStatusTLSFailureCodecIsOperationSpecific(
	t *testing.T,
) {
	statusBody, err := marshalVNextReaderPreparedStatusTLSFailure(
		vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusAcceptanceUnknown,
			errors.New("status failure")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStrictVNextReaderPrepareTLSFailure(statusBody); err == nil {
		t.Fatal("PREPARE failure codec accepted STATUS_AND_FENCE identity")
	}
	prepareBody, err := marshalVNextReaderPrepareTLSFailure(
		vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareAcceptanceUnknown,
			errors.New("prepare failure")))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeStrictVNextReaderPreparedStatusTLSFailure(prepareBody); err == nil {
		t.Fatal("STATUS_AND_FENCE failure codec accepted PREPARE identity")
	}
}

func TestVNextReaderPreparedStatusTLSEncodeFailureAfterDecisionIsUnknown(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	fixture.verifier.wantPrincipal = vnextReaderPrepareTestPrincipal
	fixture.rpc.encodeResponse = func(vnextReaderPreparedStatusResponse) (
		[]byte, error,
	) {
		return nil, errors.New("test post-decision response encoder failure")
	}
	prepareHandler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderPrepareRPCError,
		) {
			return nil, vnextReaderPrepareFailure(
				vnextReaderPrepareUnavailable,
				vnextReaderPrepareDefinitelyNotAccepted,
				errors.New("unused PREPARE handler"))
		},
	}
	server, _, _ := startVNextReaderPrepareAndStatusTLSTestServer(
		t, material, prepareHandler, fixture.rpc, nil)
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderPreparedStatusTLSTestClientConfig(t, material))
	defer conn.Close()
	if err := writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame); err != nil {
		t.Fatal(err)
	}
	failure := readVNextReaderPreparedStatusTLSTestFailure(t, conn)
	if failure.ErrorCode != vnextReaderPreparedStatusUnavailable ||
		failure.Acceptance != vnextReaderPreparedStatusAcceptanceUnknown ||
		fixture.store.callCount() != 1 || len(fixture.inner.byID) != 1 {
		t.Fatalf("post-decision encode failure=%#v calls=%d entries=%d",
			failure, fixture.store.callCount(), len(fixture.inner.byID))
	}
}

func TestVNextReaderPreparedStatusTLSHandlerTimeoutKeepsTruthfulDrain(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	lateSuccessBody := vnextReaderPreparedStatusTLSTestValidResponseBody(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	var releaseOnce sync.Once
	statusHandler := &vnextReaderPreparedStatusTLSTestHandler{
		handle: func(ctx context.Context, _ string, _ []byte) (
			[]byte, *vnextReaderPreparedStatusRPCError,
		) {
			close(entered)
			<-release // Model a verifier that cannot be interrupted locally.
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Errorf("late status handler context = %v", ctx.Err())
			}
			close(returned)
			return append([]byte(nil), lateSuccessBody...), nil
		},
	}
	prepareHandler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderPrepareRPCError,
		) {
			return nil, vnextReaderPrepareFailure(
				vnextReaderPrepareUnavailable,
				vnextReaderPrepareDefinitelyNotAccepted,
				errors.New("unused PREPARE handler"))
		},
	}
	config := vnextReaderPrepareTLSTestConfig(material)
	config.HandlerTimeout = 40 * time.Millisecond
	requestAdmission := make(chan struct{}, 1)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareAndStatusTLSServer(
		config, prepareHandler, statusHandler, requestAdmission, largeAdmission)
	if err != nil {
		t.Fatalf("start hung status handler server: %v", err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		_ = server.Close()
	})
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderPreparedStatusTLSTestClientConfig(t, material))
	largeBody := bytes.Repeat(
		[]byte{'x'}, vnextReaderPrepareTLSLargeFrameThreshold+1)
	if err := writeVNextReaderPrepareTLSTestFrame(conn, largeBody); err != nil {
		t.Fatalf("write hung status frame: %v", err)
	}
	<-entered
	failure := readVNextReaderPreparedStatusTLSTestFailure(t, conn)
	if failure.ErrorCode != vnextReaderPreparedStatusUnavailable ||
		failure.Acceptance != vnextReaderPreparedStatusAcceptanceUnknown {
		t.Fatalf("status handler timeout failure = %#v", failure)
	}
	if len(requestAdmission) != 1 || len(largeAdmission) != 1 {
		t.Fatalf("status timeout released live admissions: request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
	var secondHeader [4]byte
	if _, err := io.ReadFull(conn, secondHeader[:]); err == nil {
		t.Fatal("status TLS emitted a second response after timeout")
	}
	_ = conn.Close()

	secondConn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderPreparedStatusTLSTestClientConfig(t, material))
	secondFailure := readVNextReaderPreparedStatusTLSTestFailure(t, secondConn)
	_ = secondConn.Close()
	if secondFailure.ErrorCode != vnextReaderPreparedStatusCapacityError ||
		secondFailure.Acceptance !=
			vnextReaderPreparedStatusDefinitelyNotAccepted {
		t.Fatalf("live status handler capacity failure = %#v", secondFailure)
	}
	if calls, _, _, _ := statusHandler.snapshot(); calls != 1 {
		t.Fatalf("capacity-rejected status request reached handler; calls=%d", calls)
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("stop hung status handler server: %v", err)
	}
	waitDone := make(chan struct{})
	go func() { server.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
		t.Fatal("status server Wait completed before timed-out handler returned")
	case <-time.After(60 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("late status handler did not return")
	}
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("status server Wait did not drain returned handler")
	}
	if len(requestAdmission) != 0 || len(largeAdmission) != 0 {
		t.Fatalf("returned status handler leaked admissions: request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
}

func TestVNextReaderPrepareAndStatusTLSStopWaitDrainsBothActualHandlers(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	prepareBody := vnextReaderPrepareTLSTestValidResponseBody(t)
	statusBody := vnextReaderPreparedStatusTLSTestValidResponseBody(t)
	prepareEntered := make(chan struct{})
	statusEntered := make(chan struct{})
	prepareRelease := make(chan struct{})
	statusRelease := make(chan struct{})
	var prepareReleaseOnce sync.Once
	var statusReleaseOnce sync.Once
	prepareHandler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderPrepareRPCError,
		) {
			close(prepareEntered)
			<-prepareRelease
			return append([]byte(nil), prepareBody...), nil
		},
	}
	statusHandler := &vnextReaderPreparedStatusTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderPreparedStatusRPCError,
		) {
			close(statusEntered)
			<-statusRelease
			return append([]byte(nil), statusBody...), nil
		},
	}
	config := vnextReaderPrepareTLSTestConfig(material)
	config.HandlerTimeout = 3 * time.Second
	requestAdmission := make(chan struct{}, 4)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareAndStatusTLSServer(
		config, prepareHandler, statusHandler, requestAdmission, largeAdmission)
	if err != nil {
		t.Fatalf("start dual drain server: %v", err)
	}
	t.Cleanup(func() {
		prepareReleaseOnce.Do(func() { close(prepareRelease) })
		statusReleaseOnce.Do(func() { close(statusRelease) })
		_ = server.Close()
	})

	prepareConfig := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath,
		material.clientPrivateKeyPath)
	prepareConn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(), prepareConfig)
	statusConn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderPreparedStatusTLSTestClientConfig(t, material))
	if err := writeVNextReaderPrepareTLSTestFrame(prepareConn, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := writeVNextReaderPrepareTLSTestFrame(statusConn, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	<-prepareEntered
	<-statusEntered
	if err := server.Stop(); err != nil {
		t.Fatalf("stop dual drain server: %v", err)
	}
	waitDone := make(chan struct{})
	go func() { server.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
		t.Fatal("dual server Wait completed with both handlers running")
	case <-time.After(50 * time.Millisecond):
	}
	prepareReleaseOnce.Do(func() { close(prepareRelease) })
	select {
	case <-waitDone:
		t.Fatal("dual server Wait completed while status handler remained")
	case <-time.After(50 * time.Millisecond):
	}
	statusReleaseOnce.Do(func() { close(statusRelease) })
	prepareResponse, prepareReadErr := readVNextReaderPrepareTLSTestFrame(prepareConn)
	statusResponse, statusReadErr := readVNextReaderPrepareTLSTestFrame(statusConn)
	_ = prepareConn.Close()
	_ = statusConn.Close()
	if prepareReadErr != nil || !bytes.Equal(prepareResponse, prepareBody) {
		t.Fatalf("drained PREPARE response=%q err=%v", prepareResponse, prepareReadErr)
	}
	if statusReadErr != nil || !bytes.Equal(statusResponse, statusBody) {
		t.Fatalf("drained status response=%q err=%v", statusResponse, statusReadErr)
	}
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("dual server Wait did not drain both handlers")
	}
	if len(requestAdmission) != 0 || len(largeAdmission) != 0 {
		t.Fatalf("dual drain leaked admissions: request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
}
