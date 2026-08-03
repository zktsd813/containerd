package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

type vnextReaderIdentifyTLSTestHandler struct {
	mu        sync.Mutex
	calls     int
	principal string
	inner     vnextReaderIdentifyTransportRPC
	handle    func(context.Context, string, []byte) (
		[]byte, *vnextReaderIdentifyRPCError)
}

func (handler *vnextReaderIdentifyTLSTestHandler) Handle(
	ctx context.Context,
	principal string,
	frame []byte,
) ([]byte, *vnextReaderIdentifyRPCError) {
	handler.mu.Lock()
	handler.calls++
	handler.principal = principal
	custom := handler.handle
	inner := handler.inner
	handler.mu.Unlock()
	if custom != nil {
		return custom(ctx, principal, frame)
	}
	return inner.Handle(ctx, principal, frame)
}

func (handler *vnextReaderIdentifyTLSTestHandler) snapshot() (int, string) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.calls, handler.principal
}

func startVNextReaderIdentifyTLSTestServer(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	identifyRPC vnextReaderIdentifyTransportRPC,
	mutate func(*vnextReaderPrepareTLSServerConfig),
) (*vnextReaderPrepareTLSServer, chan struct{}, chan struct{}) {
	t.Helper()
	prepareFixture := newVNextReaderPrepareTestFixture(t)
	statusFixture := newVNextReaderPreparedStatusTestFixture(t)
	activationFixture := vnextReaderActivationRPCTestNewFixture(t, 8)
	config := vnextReaderPrepareTLSTestConfig(material)
	if mutate != nil {
		mutate(&config)
	}
	requestAdmission := make(chan struct{}, 8)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareStatusIdentifyAndActivationTLSServer(
		config, prepareFixture.rpc, statusFixture.rpc, identifyRPC,
		newVNextReaderActivationProposalRPC(activationFixture.service),
		newVNextReaderActivationCommitRPC(activationFixture.service),
		newVNextReaderActivationStatusRPC(activationFixture.service),
		requestAdmission, largeAdmission)
	if err != nil {
		t.Fatalf("start VNext Reader six-ALPN TLS test server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close VNext Reader three-ALPN TLS test server: %v", err)
		}
	})
	return server, requestAdmission, largeAdmission
}

func vnextReaderIdentifyTLSTestClientConfig(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
) *tls.Config {
	t.Helper()
	config := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath,
		material.clientPrivateKeyPath)
	config.NextProtos = []string{vnextReaderIdentifyALPN}
	return config
}

func readVNextReaderIdentifyTLSTestFailure(
	t *testing.T,
	conn net.Conn,
) vnextReaderIdentifyTLSFailureWire {
	t.Helper()
	body, err := readVNextReaderPrepareTLSTestFrame(conn)
	if err != nil {
		t.Fatalf("read Reader IDENTIFY TLS failure frame: %v", err)
	}
	wire, err := decodeStrictVNextReaderIdentifyTLSFailure(body)
	if err != nil {
		t.Fatalf("decode Reader IDENTIFY TLS failure: %v; body=%s", err, body)
	}
	return wire
}

func TestVNextReaderIdentifyTLSExactALPNDispatchesAuthenticatedRPC(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderIdentifyTestFixture(t)
	handler := &vnextReaderIdentifyTLSTestHandler{inner: fixture.rpc}
	server, requestAdmission, largeAdmission :=
		startVNextReaderIdentifyTLSTestServer(t, material, handler, nil)
	if len(server.tlsConfig.NextProtos) != 6 ||
		server.tlsConfig.NextProtos[0] != vnextReaderPrepareALPN ||
		server.tlsConfig.NextProtos[1] != vnextReaderPreparedStatusALPN ||
		server.tlsConfig.NextProtos[2] != vnextReaderIdentifyALPN ||
		server.tlsConfig.NextProtos[3] != vnextReaderActivationProposalALPN ||
		server.tlsConfig.NextProtos[4] != vnextReaderActivationCommitALPN ||
		server.tlsConfig.NextProtos[5] != vnextReaderActivationStatusALPN {
		t.Fatalf("six-operation Reader ALPNs = %#v", server.tlsConfig.NextProtos)
	}
	servedALPNs := make(map[string]struct{}, len(server.tlsConfig.NextProtos))
	for _, alpn := range server.tlsConfig.NextProtos {
		servedALPNs[alpn] = struct{}{}
	}
	capabilities := vnextReaderIdentifyCurrentCapabilities()
	if len(capabilities) != len(servedALPNs) {
		t.Fatalf("advertised capabilities=%d served ALPNs=%d",
			len(capabilities), len(servedALPNs))
	}
	for _, capability := range capabilities {
		if _, served := servedALPNs[capability.ALPN]; !served {
			t.Fatalf("IDENTIFY advertised unserved ALPN %q", capability.ALPN)
		}
	}
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderIdentifyTLSTestClientConfig(t, material))
	if conn.ConnectionState().NegotiatedProtocol != vnextReaderIdentifyALPN {
		conn.Close()
		t.Fatalf("negotiated IDENTIFY ALPN = %q",
			conn.ConnectionState().NegotiatedProtocol)
	}
	if err := writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame); err != nil {
		conn.Close()
		t.Fatalf("write IDENTIFY request: %v", err)
	}
	body, err := readVNextReaderPrepareTLSTestFrame(conn)
	conn.Close()
	if err != nil {
		t.Fatalf("read IDENTIFY response: %v", err)
	}
	response, err := decodeVNextReaderIdentifyResponse(body)
	if err != nil {
		t.Fatalf("decode IDENTIFY TLS response: %v", err)
	}
	if response.LocalProcessIncarnation != fixture.incarnation {
		t.Fatalf("IDENTIFY TLS incarnation = %s", response.LocalProcessIncarnation)
	}
	calls, principal := handler.snapshot()
	if calls != 1 || principal != vnextReaderPrepareTestPrincipal {
		t.Fatalf("IDENTIFY TLS handler calls=%d principal=%q", calls, principal)
	}
	if len(requestAdmission) != 0 || len(largeAdmission) != 0 {
		t.Fatalf("IDENTIFY leaked admissions request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
}

func TestVNextReaderIdentifyTLSRejectsWrongALPNPrincipalAndServerURI(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderIdentifyTestFixture(t)
	handler := &vnextReaderIdentifyTLSTestHandler{inner: fixture.rpc}
	server, _, _ := startVNextReaderIdentifyTLSTestServer(
		t, material, handler, nil)

	wrongALPN := vnextReaderIdentifyTLSTestClientConfig(t, material)
	wrongALPN.NextProtos = []string{"cxld-reader-unknown/1"}
	if conn, err := tls.Dial("tcp", server.Addr().String(), wrongALPN); err == nil {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_ = writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame)
		if body, readErr := readVNextReaderPrepareTLSTestFrame(conn); readErr == nil {
			conn.Close()
			t.Fatalf("unknown IDENTIFY ALPN received application body %s", body)
		}
		conn.Close()
	}

	denied := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.deniedCertificatePath, material.deniedPrivateKeyPath)
	denied.NextProtos = []string{vnextReaderIdentifyALPN}
	if conn, err := tls.Dial("tcp", server.Addr().String(), denied); err == nil {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		_ = writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame)
		if body, readErr := readVNextReaderPrepareTLSTestFrame(conn); readErr == nil {
			conn.Close()
			t.Fatalf("unbound IDENTIFY principal received application body %s", body)
		}
		conn.Close()
	}
	if calls, _ := handler.snapshot(); calls != 0 {
		t.Fatalf("invalid ALPN/principal dispatched %d IDENTIFY calls", calls)
	}

	config := vnextReaderPrepareTLSTestConfig(material)
	config.ExpectedServerURISAN = "spiffe://test.example/cxld/other"
	if invalid, err := startVNextReaderPrepareStatusAndIdentifyTLSServer(
		config,
		newVNextReaderPrepareTestFixture(t).rpc,
		newVNextReaderPreparedStatusTestFixture(t).rpc,
		fixture.rpc, make(chan struct{}, 1), make(chan struct{}, 1)); err == nil || invalid != nil {
		if invalid != nil {
			_ = invalid.Close()
		}
		t.Fatalf("wrong configured server URI returned server=%#v err=%v", invalid, err)
	}
}

func TestVNextReaderIdentifyTLSRejectsCrossProtocolAndIdentityMismatch(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderIdentifyTestFixture(t)
	handler := &vnextReaderIdentifyTLSTestHandler{inner: fixture.rpc}
	server, _, _ := startVNextReaderIdentifyTLSTestServer(
		t, material, handler, nil)
	roundTripFailure := func(t *testing.T, frame []byte) vnextReaderIdentifyTLSFailureWire {
		t.Helper()
		conn := dialVNextReaderPrepareTLSTest(
			t, server.Addr().String(),
			vnextReaderIdentifyTLSTestClientConfig(t, material))
		if err := writeVNextReaderPrepareTLSTestFrame(conn, frame); err != nil {
			conn.Close()
			t.Fatalf("write invalid IDENTIFY request: %v", err)
		}
		failure := readVNextReaderIdentifyTLSTestFailure(t, conn)
		conn.Close()
		return failure
	}
	prepareFrame := newVNextReaderPrepareTestFixture(t).frame
	if failure := roundTripFailure(t, prepareFrame); failure.ErrorCode != vnextReaderIdentifyInvalidRequest {
		t.Fatalf("cross-protocol IDENTIFY error = %q", failure.ErrorCode)
	}
	for name, mutate := range map[string]func(*vnextReaderIdentifyRequest){
		"node": func(request *vnextReaderIdentifyRequest) {
			request.ExpectedExecutorNodeID = "reader-node-other"
		},
		"logical": func(request *vnextReaderIdentifyRequest) {
			request.ExpectedCxldLogicalID = "reader-cxld-other"
		},
	} {
		t.Run(name, func(t *testing.T) {
			request := fixture.request
			mutate(&request)
			request.Authority.RequestDigest =
				vnextReaderIdentifyCanonicalRequestDigest(request)
			frame, err := marshalVNextReaderIdentifyRequest(request)
			if err != nil {
				t.Fatalf("marshal wrong-%s IDENTIFY request: %v", name, err)
			}
			failure := roundTripFailure(t, frame)
			if failure.ErrorCode != vnextReaderIdentifyIdentityError {
				t.Fatalf("wrong-%s IDENTIFY error = %q", name, failure.ErrorCode)
			}
		})
	}
	request := fixture.request
	request.ChallengeNonce[0] ^= 1
	frame := append([]byte(nil), fixture.frame...)
	// Changing the challenge without changing the signed digest is rejected by
	// the strict request decoder. Build the wire mutation directly so the test
	// does not accidentally re-sign the authority.
	oldNonce := []byte(fixture.request.ChallengeNonceString())
	newNonce := []byte(request.ChallengeNonceString())
	frame = bytes.Replace(frame, oldNonce, newNonce, 1)
	if failure := roundTripFailure(t, frame); failure.ErrorCode != vnextReaderIdentifyInvalidRequest {
		t.Fatalf("wrong-nonce IDENTIFY error = %q", failure.ErrorCode)
	}
}

func (nonce vnextReaderIdentifyNonce) String() string {
	return vnextReaderProcessIncarnation(nonce).String()
}

func (request vnextReaderIdentifyRequest) ChallengeNonceString() string {
	return request.ChallengeNonce.String()
}

func TestVNextReaderIdentifyTLSRejectsNonCanonicalHandlerCapabilities(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderIdentifyTestFixture(t)
	validBody, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderIdentifyTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatal(failure)
	}
	mutated := bytes.Replace(validBody,
		[]byte(vnextReaderIdentifyALPN), []byte(vnextReaderPrepareALPN), 1)
	handler := &vnextReaderIdentifyTLSTestHandler{
		handle: func(context.Context, string, []byte) (
			[]byte, *vnextReaderIdentifyRPCError) {
			return mutated, nil
		},
	}
	server, _, _ := startVNextReaderIdentifyTLSTestServer(
		t, material, handler, nil)
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderIdentifyTLSTestClientConfig(t, material))
	if err := writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	wire := readVNextReaderIdentifyTLSTestFailure(t, conn)
	conn.Close()
	if wire.ErrorCode != vnextReaderIdentifyUnavailable {
		t.Fatalf("invalid handler capabilities error = %q", wire.ErrorCode)
	}
}

func TestVNextReaderIdentifyTLSShutdownWaitsForActualHandler(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderIdentifyTestFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	handler := &vnextReaderIdentifyTLSTestHandler{
		handle: func(ctx context.Context, principal string, frame []byte) (
			[]byte, *vnextReaderIdentifyRPCError) {
			close(entered)
			<-release
			return fixture.rpc.Handle(ctx, principal, frame)
		},
	}
	server, requestAdmission, _ := startVNextReaderIdentifyTLSTestServer(
		t, material, handler, func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandlerTimeout = 50 * time.Millisecond
		})
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderIdentifyTLSTestClientConfig(t, material))
	if err := writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame); err != nil {
		conn.Close()
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("IDENTIFY handler did not start")
	}
	if err := server.Stop(); err != nil {
		conn.Close()
		t.Fatalf("stop IDENTIFY listener: %v", err)
	}
	waitDone := make(chan struct{})
	go func() { server.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
		conn.Close()
		t.Fatal("server Wait returned before IDENTIFY handler terminated")
	case <-time.After(100 * time.Millisecond):
	}
	if len(requestAdmission) != 1 {
		conn.Close()
		t.Fatalf("request admission released during timed-out handler: %d",
			len(requestAdmission))
	}
	close(release)
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		conn.Close()
		t.Fatal("server Wait did not finish after IDENTIFY handler termination")
	}
	conn.Close()
}

type vnextReaderIdentifyTLSBlockingWriteConn struct {
	reader       *bytes.Reader
	writeStarted chan struct{}
	writeRelease chan struct{}
	startOnce    sync.Once
}

func (conn *vnextReaderIdentifyTLSBlockingWriteConn) Read(body []byte) (int, error) {
	return conn.reader.Read(body)
}

func (conn *vnextReaderIdentifyTLSBlockingWriteConn) Write(body []byte) (int, error) {
	conn.startOnce.Do(func() { close(conn.writeStarted) })
	<-conn.writeRelease
	return len(body), nil
}

func (*vnextReaderIdentifyTLSBlockingWriteConn) Close() error { return nil }
func (*vnextReaderIdentifyTLSBlockingWriteConn) LocalAddr() net.Addr {
	return vnextReaderIdentifyTLSTestAddr("local")
}
func (*vnextReaderIdentifyTLSBlockingWriteConn) RemoteAddr() net.Addr {
	return vnextReaderIdentifyTLSTestAddr("remote")
}
func (*vnextReaderIdentifyTLSBlockingWriteConn) SetDeadline(time.Time) error {
	return nil
}
func (*vnextReaderIdentifyTLSBlockingWriteConn) SetReadDeadline(time.Time) error {
	return nil
}
func (*vnextReaderIdentifyTLSBlockingWriteConn) SetWriteDeadline(time.Time) error {
	return nil
}

type vnextReaderIdentifyTLSTestAddr string

func (address vnextReaderIdentifyTLSTestAddr) Network() string { return "test" }
func (address vnextReaderIdentifyTLSTestAddr) String() string  { return string(address) }

func TestVNextReaderIdentifyMalformedFrameRetainsAdmissionThroughFailureWrite(
	t *testing.T,
) {
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 0)
	conn := &vnextReaderIdentifyTLSBlockingWriteConn{
		reader:       bytes.NewReader(header[:]),
		writeStarted: make(chan struct{}),
		writeRelease: make(chan struct{}),
	}
	requestAdmission := make(chan struct{}, 1)
	requestAdmission <- struct{}{}
	server := &vnextReaderPrepareTLSServer{
		requestReadTimeout:   time.Second,
		responseWriteTimeout: time.Second,
	}
	done := make(chan struct{})
	go func() {
		server.serveAuthenticatedIdentify(
			conn, vnextReaderIdentifyTestPrincipal,
			func() { <-requestAdmission })
		close(done)
	}()
	select {
	case <-conn.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("malformed IDENTIFY failure write did not start")
	}
	if len(requestAdmission) != 1 {
		t.Fatal("malformed IDENTIFY released admission before failure write")
	}
	close(conn.writeRelease)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("malformed IDENTIFY serve did not finish")
	}
	if len(requestAdmission) != 0 {
		t.Fatal("malformed IDENTIFY did not release admission after failure write")
	}
}

var _ net.Conn = (*vnextReaderIdentifyTLSBlockingWriteConn)(nil)
