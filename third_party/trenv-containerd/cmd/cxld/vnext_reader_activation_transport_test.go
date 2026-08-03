package main

import (
	"context"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
	"time"
)

type vnextReaderActivationTLSTestHandler struct {
	mu        sync.Mutex
	calls     int
	principal string
	inner     vnextReaderActivationTransportRPC
	handle    func(context.Context, string, []byte) (
		[]byte, *vnextReaderActivationRPCError)
}

func (handler *vnextReaderActivationTLSTestHandler) Handle(
	ctx context.Context,
	principal string,
	frame []byte,
) ([]byte, *vnextReaderActivationRPCError) {
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

func (handler *vnextReaderActivationTLSTestHandler) snapshot() (int, string) {
	handler.mu.Lock()
	defer handler.mu.Unlock()
	return handler.calls, handler.principal
}

type vnextReaderActivationTLSTestServer struct {
	server           *vnextReaderPrepareTLSServer
	requestAdmission chan struct{}
	largeAdmission   chan struct{}
	fixture          *vnextReaderActivationRPCTestFixture
	proposal         *vnextReaderActivationTLSTestHandler
	commit           *vnextReaderActivationTLSTestHandler
	status           *vnextReaderActivationTLSTestHandler
}

func startVNextReaderActivationTLSTestServer(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	mutateHandlers func(
		*vnextReaderActivationTLSTestHandler,
		*vnextReaderActivationTLSTestHandler,
		*vnextReaderActivationTLSTestHandler),
	mutateConfig func(*vnextReaderPrepareTLSServerConfig),
) vnextReaderActivationTLSTestServer {
	t.Helper()
	prepareFixture := newVNextReaderPrepareTestFixture(t)
	statusFixture := newVNextReaderPreparedStatusTestFixture(t)
	statusFixture.verifier.wantPrincipal = vnextReaderPrepareTestPrincipal
	identifyFixture := newVNextReaderIdentifyTestFixture(t)
	activationFixture := vnextReaderActivationRPCTestNewFixture(t, 8)
	proposal := &vnextReaderActivationTLSTestHandler{
		inner: newVNextReaderActivationProposalRPC(activationFixture.service),
	}
	commit := &vnextReaderActivationTLSTestHandler{
		inner: newVNextReaderActivationCommitRPC(activationFixture.service),
	}
	status := &vnextReaderActivationTLSTestHandler{
		inner: newVNextReaderActivationStatusRPC(activationFixture.service),
	}
	if mutateHandlers != nil {
		mutateHandlers(proposal, commit, status)
	}
	config := vnextReaderPrepareTLSTestConfig(material)
	if mutateConfig != nil {
		mutateConfig(&config)
	}
	requestAdmission := make(chan struct{}, 8)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareStatusIdentifyAndActivationTLSServer(
		config,
		prepareFixture.rpc,
		statusFixture.rpc,
		identifyFixture.rpc,
		proposal,
		commit,
		status,
		requestAdmission,
		largeAdmission)
	if err != nil {
		t.Fatalf("start VNext Reader six-route TLS test server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close VNext Reader activation TLS test server: %v", err)
		}
	})
	return vnextReaderActivationTLSTestServer{
		server:           server,
		requestAdmission: requestAdmission,
		largeAdmission:   largeAdmission,
		fixture:          activationFixture,
		proposal:         proposal,
		commit:           commit,
		status:           status,
	}
}

func vnextReaderActivationTLSTestClientConfig(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	spec vnextReaderActivationOperationSpec,
) *tls.Config {
	t.Helper()
	config := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath,
		material.clientPrivateKeyPath)
	config.NextProtos = []string{spec.alpn}
	return config
}

func vnextReaderActivationTLSTestRoundTrip(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	server *vnextReaderPrepareTLSServer,
	spec vnextReaderActivationOperationSpec,
	frame []byte,
) []byte {
	t.Helper()
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(),
		vnextReaderActivationTLSTestClientConfig(t, material, spec))
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != spec.alpn {
		t.Fatalf("activation negotiated ALPN = %q, want %q",
			conn.ConnectionState().NegotiatedProtocol, spec.alpn)
	}
	if err := writeVNextReaderPrepareTLSTestFrame(conn, frame); err != nil {
		t.Fatalf("write %s activation request: %v", spec.operation, err)
	}
	body, err := readVNextReaderPrepareTLSTestFrame(conn)
	if err != nil {
		t.Fatalf("read %s activation response: %v", spec.operation, err)
	}
	return body
}

func TestVNextReaderActivationTLSAllSixRoutesDispatchExactRealMTLSRPCs(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	boundary := startVNextReaderActivationTLSTestServer(
		t, material, nil, nil)
	wantALPNs := []string{
		vnextReaderPrepareALPN,
		vnextReaderPreparedStatusALPN,
		vnextReaderIdentifyALPN,
		vnextReaderActivationProposalALPN,
		vnextReaderActivationCommitALPN,
		vnextReaderActivationStatusALPN,
	}
	if got := boundary.server.tlsConfig.NextProtos; len(got) != len(wantALPNs) {
		t.Fatalf("six-route Reader ALPNs = %#v", got)
	} else {
		for index := range wantALPNs {
			if got[index] != wantALPNs[index] {
				t.Fatalf("six-route Reader ALPNs = %#v", got)
			}
		}
	}

	proposalRequest := vnextReaderActivationRPCTestProposalRequest(
		boundary.fixture)
	proposalFrame, err := marshalVNextReaderActivationProposalRequest(
		proposalRequest)
	if err != nil {
		t.Fatalf("marshal activation proposal: %v", err)
	}
	proposalBody := vnextReaderActivationTLSTestRoundTrip(
		t, material, boundary.server,
		vnextReaderActivationProposalSpec, proposalFrame)
	proposal, err := decodeVNextReaderActivationProposalResponse(proposalBody)
	if err != nil || proposal.State != vnextReaderActivationPending {
		t.Fatalf("decode activation proposal response: %#v err=%v",
			proposal, err)
	}

	commitRequest := vnextReaderActivationRPCTestCommitRequest(
		boundary.fixture, proposal)
	commitFrame, err := marshalVNextReaderActivationCommitRequest(commitRequest)
	if err != nil {
		t.Fatalf("marshal activation commit: %v", err)
	}
	commitBody := vnextReaderActivationTLSTestRoundTrip(
		t, material, boundary.server,
		vnextReaderActivationCommitSpec, commitFrame)
	commit, err := decodeVNextReaderActivationCommitResponse(commitBody)
	if err != nil || commit.State != vnextReaderActivationActiveArmed {
		t.Fatalf("decode activation commit response: %#v err=%v", commit, err)
	}

	statusRequest := vnextReaderActivationRPCTestStatusRequest(
		boundary.fixture.request)
	statusFrame, err := marshalVNextReaderActivationStatusRequest(statusRequest)
	if err != nil {
		t.Fatalf("marshal activation status: %v", err)
	}
	statusBody := vnextReaderActivationTLSTestRoundTrip(
		t, material, boundary.server,
		vnextReaderActivationStatusSpec, statusFrame)
	statusResponse, err := decodeVNextReaderActivationStatusResponse(statusBody)
	if err != nil || statusResponse.State != vnextReaderActivationStatusArmedState {
		t.Fatalf("decode activation status response: %#v err=%v",
			statusResponse, err)
	}

	for name, handler := range map[string]*vnextReaderActivationTLSTestHandler{
		"proposal": boundary.proposal,
		"commit":   boundary.commit,
		"status":   boundary.status,
	} {
		calls, principal := handler.snapshot()
		if calls != 1 || principal != vnextReaderPrepareTestPrincipal {
			t.Fatalf("%s activation dispatch calls=%d principal=%q",
				name, calls, principal)
		}
	}
	waitVNextReaderPrepareTLSTestCondition(
		t, "activation Reader admission release", func() bool {
			return len(boundary.requestAdmission) == 0 &&
				len(boundary.largeAdmission) == 0
		})
}

func TestVNextReaderActivationTLSNeverInfersOperationFromJSON(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	boundary := startVNextReaderActivationTLSTestServer(t, material, nil, nil)
	proposalFrame, err := marshalVNextReaderActivationProposalRequest(
		vnextReaderActivationRPCTestProposalRequest(boundary.fixture))
	if err != nil {
		t.Fatal(err)
	}
	body := vnextReaderActivationTLSTestRoundTrip(
		t, material, boundary.server,
		vnextReaderActivationCommitSpec, proposalFrame)
	failure, err := decodeStrictVNextReaderActivationTLSFailure(
		vnextReaderActivationCommitSpec, body)
	if err != nil {
		t.Fatalf("decode cross-operation activation failure: %v; body=%s",
			err, body)
	}
	if failure.ErrorCode != vnextReaderActivationInvalidRequest ||
		failure.Acceptance != vnextReaderActivationDefinitelyNotAccepted {
		t.Fatalf("cross-operation activation failure = %#v", failure)
	}
	if proposalCalls, _ := boundary.proposal.snapshot(); proposalCalls != 0 {
		t.Fatalf("commit ALPN dispatched %d proposal calls", proposalCalls)
	}
	if commitCalls, _ := boundary.commit.snapshot(); commitCalls != 1 {
		t.Fatalf("commit ALPN dispatched %d commit calls", commitCalls)
	}
}

func TestVNextReaderActivationTLSPartialRoutesAndFailureDomainsFailClosed(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	prepareFixture := newVNextReaderPrepareTestFixture(t)
	statusFixture := newVNextReaderPreparedStatusTestFixture(t)
	identifyFixture := newVNextReaderIdentifyTestFixture(t)
	activationFixture := vnextReaderActivationRPCTestNewFixture(t, 2)
	proposal := newVNextReaderActivationProposalRPC(activationFixture.service)
	config := vnextReaderPrepareTLSTestConfig(material)
	server, err := startVNextReaderPrepareTLSServerCommon(
		config, prepareFixture.rpc, statusFixture.rpc, identifyFixture.rpc,
		proposal, nil, nil, make(chan struct{}, 2), make(chan struct{}, 1))
	if err == nil || server != nil {
		if server != nil {
			_ = server.Close()
		}
		t.Fatalf("partial activation routes returned server=%#v err=%v", server, err)
	}

	failure := vnextReaderActivationFailure(
		vnextReaderActivationProposalSpec,
		vnextReaderActivationConflictError,
		vnextReaderActivationDefinitelyNotAccepted,
		errors.New("test conflict"))
	body, err := marshalVNextReaderActivationTLSFailure(
		vnextReaderActivationProposalSpec, failure)
	if err != nil {
		t.Fatalf("marshal activation failure: %v", err)
	}
	if _, err := decodeStrictVNextReaderActivationTLSFailure(
		vnextReaderActivationCommitSpec, body); err == nil {
		t.Fatal("commit route accepted proposal failure identity")
	}
}

func TestVNextReaderActivationTLSHandlerTimeoutRetainsAdmissionUntilTerminal(
	t *testing.T,
) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	handlerStarted := make(chan struct{})
	handlerRelease := make(chan struct{})
	boundary := startVNextReaderActivationTLSTestServer(
		t, material,
		func(proposal, _ *vnextReaderActivationTLSTestHandler,
			_ *vnextReaderActivationTLSTestHandler) {
			proposal.handle = func(context.Context, string, []byte) (
				[]byte, *vnextReaderActivationRPCError,
			) {
				close(handlerStarted)
				<-handlerRelease
				return nil, vnextReaderActivationFailure(
					vnextReaderActivationProposalSpec,
					vnextReaderActivationUnavailable,
					vnextReaderActivationAcceptanceUnknown,
					errors.New("late handler result"))
			}
		},
		func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandlerTimeout = 20 * time.Millisecond
		})
	proposalFrame, err := marshalVNextReaderActivationProposalRequest(
		vnextReaderActivationRPCTestProposalRequest(boundary.fixture))
	if err != nil {
		t.Fatal(err)
	}
	body := vnextReaderActivationTLSTestRoundTrip(
		t, material, boundary.server,
		vnextReaderActivationProposalSpec, proposalFrame)
	<-handlerStarted
	failure, err := decodeStrictVNextReaderActivationTLSFailure(
		vnextReaderActivationProposalSpec, body)
	if err != nil || failure.Acceptance != vnextReaderActivationAcceptanceUnknown {
		t.Fatalf("activation timeout failure=%#v err=%v", failure, err)
	}
	if len(boundary.requestAdmission) != 1 {
		t.Fatalf("activation timeout released request admission early: %d",
			len(boundary.requestAdmission))
	}
	waitDone := make(chan struct{})
	if err := boundary.server.Stop(); err != nil {
		t.Fatalf("stop activation listener: %v", err)
	}
	go func() {
		boundary.server.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
		t.Fatal("activation listener Wait returned before actual handler")
	case <-time.After(30 * time.Millisecond):
	}
	close(handlerRelease)
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("activation listener Wait did not finish after handler terminal")
	}
	if len(boundary.requestAdmission) != 0 || len(boundary.largeAdmission) != 0 {
		t.Fatalf("activation admission remained held: request=%d large=%d",
			len(boundary.requestAdmission), len(boundary.largeAdmission))
	}
}
