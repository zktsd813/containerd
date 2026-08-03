package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	vnextReaderPrepareTLSTestServerName = "reader.test"
	vnextReaderPrepareTLSTestServerURI  = "spiffe://test.example/cxld/reader-0"
	vnextReaderPrepareTLSTestDeniedURI  = "spiffe://test.example/scheduler/denied"
)

type vnextReaderPrepareTLSTestMaterial struct {
	caPath                          string
	serverCertificatePath           string
	serverPrivateKeyPath            string
	mismatchedServerCertificatePath string
	mismatchedServerPrivateKeyPath  string
	multipleServerCertificatePath   string
	multipleServerPrivateKeyPath    string
	noURIServerCertificatePath      string
	noURIServerPrivateKeyPath       string
	clientCertificatePath           string
	clientPrivateKeyPath            string
	deniedCertificatePath           string
	deniedPrivateKeyPath            string
	multipleClientCertificatePath   string
	multipleClientPrivateKeyPath    string
	noURIClientCertificatePath      string
	noURIClientPrivateKeyPath       string
	wrongCAClientCertificatePath    string
	wrongCAClientPrivateKeyPath     string
}

type vnextReaderPrepareTLSTestHandler struct {
	mu         sync.Mutex
	calls      int
	principals []string
	frames     [][]byte
	responses  [][]byte
	inner      vnextReaderPrepareTransportRPC
	handle     func(context.Context, string, []byte) (
		[]byte, *vnextReaderPrepareRPCError)
}

func (handler *vnextReaderPrepareTLSTestHandler) Handle(
	ctx context.Context,
	principal string,
	frame []byte,
) ([]byte, *vnextReaderPrepareRPCError) {
	handler.mu.Lock()
	handler.calls++
	handler.principals = append(handler.principals,
		cloneVNextReaderRetainedString(principal))
	handler.frames = append(handler.frames, append([]byte(nil), frame...))
	handle := handler.handle
	inner := handler.inner
	handler.mu.Unlock()
	var body []byte
	var failure *vnextReaderPrepareRPCError
	if handle != nil {
		body, failure = handle(ctx, principal, frame)
	} else {
		body, failure = inner.Handle(ctx, principal, frame)
	}
	handler.mu.Lock()
	handler.responses = append(handler.responses, append([]byte(nil), body...))
	handler.mu.Unlock()
	return body, failure
}

func (handler *vnextReaderPrepareTLSTestHandler) snapshot() (
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

func newVNextReaderPrepareTLSTestMaterial(
	t *testing.T,
) vnextReaderPrepareTLSTestMaterial {
	t.Helper()
	directory := t.TempDir()
	authority := newVNextOwnerTLSTestAuthority(t, "VNext Reader PREPARE test CA")
	wrongAuthority := newVNextOwnerTLSTestAuthority(
		t, "wrong VNext Reader PREPARE test CA")
	issue := func(
		serial int64,
		name string,
		dnsNames []string,
		uriSANs []string,
		usage x509.ExtKeyUsage,
	) (string, string) {
		certificate, key := issueVNextOwnerTLSTestCertificateWithURISANs(
			t, authority, serial, name, dnsNames, uriSANs, usage)
		return writeVNextOwnerTLSTestFile(
				t, directory, fmt.Sprintf("%d-cert.pem", serial), certificate),
			writeVNextOwnerTLSTestFile(
				t, directory, fmt.Sprintf("%d-key.pem", serial), key)
	}
	serverCertificate, serverKey := issue(
		2, "reader-server", []string{vnextReaderPrepareTLSTestServerName},
		[]string{vnextReaderPrepareTLSTestServerURI}, x509.ExtKeyUsageServerAuth)
	mismatchedServerCertificate, mismatchedServerKey := issue(
		3, "reader-server-mismatch", []string{vnextReaderPrepareTLSTestServerName},
		[]string{"spiffe://test.example/cxld/other"}, x509.ExtKeyUsageServerAuth)
	multipleServerCertificate, multipleServerKey := issue(
		4, "reader-server-multiple", []string{vnextReaderPrepareTLSTestServerName},
		[]string{
			vnextReaderPrepareTLSTestServerURI,
			"spiffe://test.example/cxld/other",
		}, x509.ExtKeyUsageServerAuth)
	noURIServerCertificate, noURIServerKey := issue(
		5, "reader-server-no-uri", []string{vnextReaderPrepareTLSTestServerName},
		nil, x509.ExtKeyUsageServerAuth)
	clientCertificate, clientKey := issue(
		6, "reader-scheduler", nil,
		[]string{vnextReaderPrepareTestPrincipal}, x509.ExtKeyUsageClientAuth)
	deniedCertificate, deniedKey := issue(
		7, "reader-denied", nil,
		[]string{vnextReaderPrepareTLSTestDeniedURI}, x509.ExtKeyUsageClientAuth)
	multipleClientCertificate, multipleClientKey := issue(
		8, "reader-multiple", nil,
		[]string{vnextReaderPrepareTestPrincipal, vnextReaderPrepareTLSTestDeniedURI},
		x509.ExtKeyUsageClientAuth)
	noURIClientCertificate, noURIClientKey := issue(
		9, "reader-no-uri", nil, nil, x509.ExtKeyUsageClientAuth)
	wrongCertificate, wrongKey := issueVNextOwnerTLSTestCertificateWithURISANs(
		t, wrongAuthority, 10, "reader-wrong-ca", nil,
		[]string{vnextReaderPrepareTestPrincipal}, x509.ExtKeyUsageClientAuth)
	return vnextReaderPrepareTLSTestMaterial{
		caPath: writeVNextOwnerTLSTestFile(
			t, directory, "ca.pem", authority.certificatePEM),
		serverCertificatePath:           serverCertificate,
		serverPrivateKeyPath:            serverKey,
		mismatchedServerCertificatePath: mismatchedServerCertificate,
		mismatchedServerPrivateKeyPath:  mismatchedServerKey,
		multipleServerCertificatePath:   multipleServerCertificate,
		multipleServerPrivateKeyPath:    multipleServerKey,
		noURIServerCertificatePath:      noURIServerCertificate,
		noURIServerPrivateKeyPath:       noURIServerKey,
		clientCertificatePath:           clientCertificate,
		clientPrivateKeyPath:            clientKey,
		deniedCertificatePath:           deniedCertificate,
		deniedPrivateKeyPath:            deniedKey,
		multipleClientCertificatePath:   multipleClientCertificate,
		multipleClientPrivateKeyPath:    multipleClientKey,
		noURIClientCertificatePath:      noURIClientCertificate,
		noURIClientPrivateKeyPath:       noURIClientKey,
		wrongCAClientCertificatePath: writeVNextOwnerTLSTestFile(
			t, directory, "wrong-client.pem", wrongCertificate),
		wrongCAClientPrivateKeyPath: writeVNextOwnerTLSTestFile(
			t, directory, "wrong-client-key.pem", wrongKey),
	}
}

func vnextReaderPrepareTLSTestConfig(
	material vnextReaderPrepareTLSTestMaterial,
) vnextReaderPrepareTLSServerConfig {
	return vnextReaderPrepareTLSServerConfig{
		ListenAddress:         "127.0.0.1:0",
		ServerCertificatePath: material.serverCertificatePath,
		ServerPrivateKeyPath:  material.serverPrivateKeyPath,
		ClientCAPath:          material.caPath,
		ExpectedServerURISAN:  vnextReaderPrepareTLSTestServerURI,
		SchedulerByPrincipal: map[string]string{
			vnextReaderPrepareTestPrincipal: "scheduler-a",
		},
		HandshakeTimeout:     time.Second,
		RequestReadTimeout:   time.Second,
		HandlerTimeout:       time.Second,
		ResponseWriteTimeout: time.Second,
	}
}

func startVNextReaderPrepareTLSTestServer(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	handler vnextReaderPrepareTransportRPC,
	mutate func(*vnextReaderPrepareTLSServerConfig),
) (*vnextReaderPrepareTLSServer, chan struct{}, chan struct{}) {
	t.Helper()
	config := vnextReaderPrepareTLSTestConfig(material)
	if mutate != nil {
		mutate(&config)
	}
	requestAdmission := make(chan struct{}, 64)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareTLSServer(
		config, handler, requestAdmission, largeAdmission)
	if err != nil {
		t.Fatalf("start VNext Reader PREPARE TLS test server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close VNext Reader PREPARE TLS test server: %v", err)
		}
	})
	return server, requestAdmission, largeAdmission
}

func vnextReaderPrepareTLSTestClientConfig(
	t *testing.T,
	material vnextReaderPrepareTLSTestMaterial,
	certificatePath string,
	keyPath string,
) *tls.Config {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certificatePath, keyPath)
	if err != nil {
		t.Fatalf("load Reader PREPARE TLS test client key pair: %v", err)
	}
	caPEM, err := os.ReadFile(material.caPath)
	if err != nil {
		t.Fatalf("read Reader PREPARE TLS test CA: %v", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("append Reader PREPARE TLS test CA")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   vnextReaderPrepareTLSTestServerName,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{vnextReaderPrepareALPN},
	}
}

func dialVNextReaderPrepareTLSTest(
	t *testing.T,
	endpoint string,
	config *tls.Config,
) *tls.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", endpoint, config)
	if err != nil {
		t.Fatalf("dial VNext Reader PREPARE TLS test server: %v", err)
	}
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		conn.Close()
		t.Fatalf("set VNext Reader PREPARE TLS test deadline: %v", err)
	}
	return conn
}

func writeVNextReaderPrepareTLSTestFrame(
	conn net.Conn,
	body []byte,
) error {
	if len(body) == 0 || len(body) > vnextReaderPrepareMaxFrameBytes {
		return fmt.Errorf("test frame length %d is outside Reader PREPARE bounds", len(body))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeVNextReaderPrepareTLSFull(conn, header[:]); err != nil {
		return err
	}
	return writeVNextReaderPrepareTLSFull(conn, body)
}

func readVNextReaderPrepareTLSTestFrame(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(vnextReaderPrepareMaxFrameBytes) {
		return nil, fmt.Errorf("Reader PREPARE TLS test response size %d is invalid", size)
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

func readVNextReaderPrepareTLSTestFailure(
	t *testing.T,
	conn net.Conn,
) vnextReaderPrepareTLSFailureWire {
	t.Helper()
	body, err := readVNextReaderPrepareTLSTestFrame(conn)
	if err != nil {
		t.Fatalf("read Reader PREPARE TLS failure frame: %v", err)
	}
	wire, err := decodeStrictVNextReaderPrepareTLSFailure(body)
	if err != nil {
		t.Fatalf("decode Reader PREPARE TLS failure frame: %v; body=%s", err, body)
	}
	return wire
}

func vnextReaderPrepareTLSTestValidResponseBody(t *testing.T) []byte {
	t.Helper()
	fixture := newVNextReaderPrepareTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("create valid Reader PREPARE TLS response fixture: %v", failure)
	}
	if _, err := decodeVNextReaderPrepareResponse(body); err != nil {
		t.Fatalf("validate Reader PREPARE TLS response fixture: %v", err)
	}
	return body
}

func waitVNextReaderPrepareTLSTestCondition(
	t *testing.T,
	description string,
	condition func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestVNextReaderPrepareTLSRealMutualTLSReturnsExactRPCBody(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	fixture := newVNextReaderPrepareTestFixture(t)
	handler := &vnextReaderPrepareTLSTestHandler{inner: fixture.rpc}
	server, requestAdmission, largeAdmission :=
		startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
	if server.tlsConfig.MinVersion != tls.VersionTLS13 ||
		server.tlsConfig.MaxVersion != tls.VersionTLS13 ||
		server.tlsConfig.ClientAuth != tls.RequireAndVerifyClientCert ||
		len(server.tlsConfig.NextProtos) != 1 ||
		server.tlsConfig.NextProtos[0] != vnextReaderPrepareALPN ||
		!server.tlsConfig.SessionTicketsDisabled {
		t.Fatalf("Reader PREPARE TLS config is not fail-closed: %#v", server.tlsConfig)
	}
	clientConfig := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath, material.clientPrivateKeyPath)
	conn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(), clientConfig)
	defer conn.Close()
	if conn.ConnectionState().NegotiatedProtocol != vnextReaderPrepareALPN {
		t.Fatalf("negotiated ALPN = %q", conn.ConnectionState().NegotiatedProtocol)
	}
	if err := writeVNextReaderPrepareTLSTestFrame(conn, fixture.frame); err != nil {
		t.Fatalf("write Reader PREPARE TLS request: %v", err)
	}
	body, err := readVNextReaderPrepareTLSTestFrame(conn)
	if err != nil {
		t.Fatalf("read Reader PREPARE TLS response: %v", err)
	}
	response, err := decodeVNextReaderPrepareResponse(body)
	if err != nil {
		t.Fatalf("decode exact Reader PREPARE response: %v", err)
	}
	if response.Prepared.Acquired.Authorization.RestoreAuthorizationID !=
		fixture.acquired.Authorization.RestoreAuthorizationID {
		t.Fatalf("Reader PREPARE response lost authorization: %#v", response.Prepared)
	}
	calls, principals, frames, responses := handler.snapshot()
	if calls != 1 || len(principals) != 1 ||
		principals[0] != vnextReaderPrepareTestPrincipal ||
		len(frames) != 1 || !bytes.Equal(frames[0], fixture.frame) ||
		len(responses) != 1 || !bytes.Equal(responses[0], body) {
		t.Fatalf("TLS-derived exact RPC boundary changed: calls=%d principals=%#v", calls, principals)
	}
	var oneByte [1]byte
	if _, err := conn.Read(oneByte[:]); err == nil {
		t.Fatal("Reader PREPARE TLS connection remained open for a second frame")
	}
	if len(requestAdmission) != 0 || len(largeAdmission) != 0 {
		t.Fatalf("Reader PREPARE admissions leaked: request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
}

func TestVNextReaderPrepareTLSRejectsALPNVersionChainAndAmbiguousSAN(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	handler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
			return []byte(`{"accepted":true}`), nil
		},
	}
	server, _, _ := startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
	tests := map[string]func(*tls.Config){
		"wrong ALPN": func(config *tls.Config) {
			config.NextProtos = []string{vnextOwnerTLSALPN}
		},
		"old PREPARE v1 ALPN": func(config *tls.Config) {
			config.NextProtos = []string{"cxld-vnext-reader/" + "1"}
		},
		"noncanonical PREPARE v2 ALPN": func(config *tls.Config) {
			config.NextProtos = []string{"cxld-vnext-reader-prepare/" + "2"}
		},
		"TLS 1.2": func(config *tls.Config) {
			config.MinVersion = tls.VersionTLS12
			config.MaxVersion = tls.VersionTLS12
		},
		"denied exact URI SAN": func(config *tls.Config) {
			certificate, err := tls.LoadX509KeyPair(
				material.deniedCertificatePath, material.deniedPrivateKeyPath)
			if err != nil {
				t.Fatalf("load denied client certificate: %v", err)
			}
			config.Certificates = []tls.Certificate{certificate}
		},
		"multiple URI SANs": func(config *tls.Config) {
			certificate, err := tls.LoadX509KeyPair(
				material.multipleClientCertificatePath,
				material.multipleClientPrivateKeyPath)
			if err != nil {
				t.Fatalf("load multiple-SAN client certificate: %v", err)
			}
			config.Certificates = []tls.Certificate{certificate}
		},
		"missing URI SAN": func(config *tls.Config) {
			certificate, err := tls.LoadX509KeyPair(
				material.noURIClientCertificatePath,
				material.noURIClientPrivateKeyPath)
			if err != nil {
				t.Fatalf("load missing-SAN client certificate: %v", err)
			}
			config.Certificates = []tls.Certificate{certificate}
		},
		"wrong client CA": func(config *tls.Config) {
			certificate, err := tls.LoadX509KeyPair(
				material.wrongCAClientCertificatePath,
				material.wrongCAClientPrivateKeyPath)
			if err != nil {
				t.Fatalf("load wrong-CA client certificate: %v", err)
			}
			config.Certificates = []tls.Certificate{certificate}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := vnextReaderPrepareTLSTestClientConfig(
				t, material, material.clientCertificatePath,
				material.clientPrivateKeyPath)
			mutate(config)
			dialer := &net.Dialer{Timeout: time.Second}
			conn, err := tls.DialWithDialer(
				dialer, "tcp", server.Addr().String(), config)
			if err == nil {
				// With TLS 1.3, a client can finish its side of the handshake
				// before observing the server's certificate-rejection alert.
				// It must still never exchange an authenticated application frame.
				_ = conn.SetDeadline(time.Now().Add(time.Second))
				_ = writeVNextReaderPrepareTLSTestFrame(conn, []byte(`{}`))
				if body, readErr := readVNextReaderPrepareTLSTestFrame(conn); readErr == nil {
					conn.Close()
					t.Fatalf("invalid Reader TLS peer received application body %s", body)
				}
				conn.Close()
			}
		})
	}
	if calls, _, _, _ := handler.snapshot(); calls != 0 {
		t.Fatalf("invalid TLS peers dispatched %d Reader requests", calls)
	}
}

func TestVNextReaderPrepareTLSServerIdentityConfigAndMapAreFailClosed(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	handler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
			return []byte(`{}`), nil
		},
	}
	tests := map[string]func(*vnextReaderPrepareTLSServerConfig){
		"mismatched server URI": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ServerCertificatePath = material.mismatchedServerCertificatePath
			config.ServerPrivateKeyPath = material.mismatchedServerPrivateKeyPath
		},
		"multiple server URI SANs": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ServerCertificatePath = material.multipleServerCertificatePath
			config.ServerPrivateKeyPath = material.multipleServerPrivateKeyPath
		},
		"missing server URI SAN": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ServerCertificatePath = material.noURIServerCertificatePath
			config.ServerPrivateKeyPath = material.noURIServerPrivateKeyPath
		},
		"wrong configured server URI": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ExpectedServerURISAN = "spiffe://test.example/cxld/wrong"
		},
		"relative certificate path": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ServerCertificatePath = "server.pem"
		},
		"empty principal map": func(config *vnextReaderPrepareTLSServerConfig) {
			config.SchedulerByPrincipal = nil
		},
		"zero handshake timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandshakeTimeout = 0
		},
		"zero read timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.RequestReadTimeout = 0
		},
		"zero handler timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandlerTimeout = 0
		},
		"zero write timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ResponseWriteTimeout = 0
		},
		"negative handshake timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandshakeTimeout = -time.Second
		},
		"negative read timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.RequestReadTimeout = -time.Second
		},
		"negative handler timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandlerTimeout = -time.Second
		},
		"negative write timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ResponseWriteTimeout = -time.Second
		},
		"over handshake timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandshakeTimeout =
				vnextReaderPrepareTLSMaxStageTimeout + time.Nanosecond
		},
		"over read timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.RequestReadTimeout =
				vnextReaderPrepareTLSMaxStageTimeout + time.Nanosecond
		},
		"over handler timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.HandlerTimeout =
				vnextReaderPrepareTLSMaxStageTimeout + time.Nanosecond
		},
		"over write timeout": func(config *vnextReaderPrepareTLSServerConfig) {
			config.ResponseWriteTimeout =
				vnextReaderPrepareTLSMaxStageTimeout + time.Nanosecond
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := vnextReaderPrepareTLSTestConfig(material)
			mutate(&config)
			if server, err := startVNextReaderPrepareTLSServer(
				config, handler, make(chan struct{}, 1), make(chan struct{}, 1)); err == nil || server != nil {
				if server != nil {
					server.Close()
				}
				t.Fatalf("invalid Reader PREPARE TLS config = %#v / %v", server, err)
			}
		})
	}
	config := vnextReaderPrepareTLSTestConfig(material)
	tooMany := make(map[string]string, vnextReaderPrepareAuthorityMaxPrincipals+1)
	for index := 0; index <= vnextReaderPrepareAuthorityMaxPrincipals; index++ {
		tooMany[fmt.Sprintf("spiffe://test.example/scheduler/%02d", index)] =
			fmt.Sprintf("scheduler-%02d", index)
	}
	config.SchedulerByPrincipal = tooMany
	if server, err := startVNextReaderPrepareTLSServer(
		config, handler, make(chan struct{}, 1), make(chan struct{}, 1)); err == nil || server != nil {
		t.Fatalf("over-count Reader TLS map = %#v / %v", server, err)
	}
	for name, admissions := range map[string]struct {
		request chan struct{}
		large   chan struct{}
	}{
		"nil request":        {nil, make(chan struct{}, 1)},
		"unbuffered request": {make(chan struct{}), make(chan struct{}, 1)},
		"nil large":          {make(chan struct{}, 1), nil},
		"unbuffered large":   {make(chan struct{}, 1), make(chan struct{})},
	} {
		if server, err := startVNextReaderPrepareTLSServer(
			vnextReaderPrepareTLSTestConfig(material), handler,
			admissions.request, admissions.large); err == nil || server != nil {
			t.Fatalf("%s admission = %#v / %v", name, server, err)
		}
	}

	original := map[string]string{
		vnextReaderPrepareTestPrincipal: "scheduler-a",
	}
	config = vnextReaderPrepareTLSTestConfig(material)
	config.SchedulerByPrincipal = original
	server, err := startVNextReaderPrepareTLSServer(
		config, handler, make(chan struct{}, 2), make(chan struct{}, 1))
	if err != nil {
		t.Fatalf("start cloned-map Reader TLS server: %v", err)
	}
	defer server.Close()
	delete(original, vnextReaderPrepareTestPrincipal)
	original[vnextReaderPrepareTLSTestDeniedURI] = "scheduler-attacker"
	if server.schedulerByPrincipal[vnextReaderPrepareTestPrincipal] != "scheduler-a" {
		t.Fatal("Reader TLS server retained mutable principal map input")
	}
	if _, exists := server.schedulerByPrincipal[vnextReaderPrepareTLSTestDeniedURI]; exists {
		t.Fatal("mutated Reader TLS principal was admitted after construction")
	}
}

func TestVNextReaderPrepareTLSAuthenticatedFrameFailuresPreserveAcceptance(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	clientConfig := func(t *testing.T) *tls.Config {
		return vnextReaderPrepareTLSTestClientConfig(
			t, material, material.clientCertificatePath,
			material.clientPrivateKeyPath)
	}
	t.Run("malformed body", func(t *testing.T) {
		fixture := newVNextReaderPrepareTestFixture(t)
		handler := &vnextReaderPrepareTLSTestHandler{inner: fixture.rpc}
		server, _, _ := startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
		conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig(t))
		defer conn.Close()
		if err := writeVNextReaderPrepareTLSTestFrame(conn, []byte(`{}`)); err != nil {
			t.Fatalf("write malformed Reader request: %v", err)
		}
		failure := readVNextReaderPrepareTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPrepareInvalidRequest ||
			failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("malformed Reader failure = %#v", failure)
		}
	})

	for _, size := range []uint32{0, uint32(vnextReaderPrepareMaxFrameBytes + 1)} {
		t.Run(fmt.Sprintf("frame-size-%d", size), func(t *testing.T) {
			handler := &vnextReaderPrepareTLSTestHandler{
				handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
					return []byte(`{}`), nil
				},
			}
			server, _, large := startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
			conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig(t))
			defer conn.Close()
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], size)
			if _, err := conn.Write(header[:]); err != nil {
				t.Fatalf("write invalid Reader frame header: %v", err)
			}
			failure := readVNextReaderPrepareTLSTestFailure(t, conn)
			if failure.ErrorCode != vnextReaderPrepareInvalidRequest ||
				failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
				t.Fatalf("invalid Reader frame failure = %#v", failure)
			}
			if calls, _, _, _ := handler.snapshot(); calls != 0 || len(large) != 0 {
				t.Fatalf("invalid frame dispatched/allocated: calls=%d large=%d", calls, len(large))
			}
		})
	}

	for name, acceptance := range map[string]vnextReaderPrepareAcceptance{
		"definite": vnextReaderPrepareDefinitelyNotAccepted,
		"unknown":  vnextReaderPrepareAcceptanceUnknown,
	} {
		t.Run(name, func(t *testing.T) {
			handler := &vnextReaderPrepareTLSTestHandler{
				handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
					return nil, vnextReaderPrepareFailure(
						vnextReaderPrepareConflictError, acceptance, errors.New("test failure"))
				},
			}
			server, _, _ := startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
			conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig(t))
			defer conn.Close()
			if err := writeVNextReaderPrepareTLSTestFrame(conn, []byte(`{}`)); err != nil {
				t.Fatalf("write acceptance test frame: %v", err)
			}
			failure := readVNextReaderPrepareTLSTestFailure(t, conn)
			if failure.ErrorCode != vnextReaderPrepareConflictError ||
				failure.Acceptance != acceptance {
				t.Fatalf("Reader failure acceptance changed: %#v", failure)
			}
		})
	}

	t.Run("malformed fake success is unknown", func(t *testing.T) {
		handler := &vnextReaderPrepareTLSTestHandler{
			handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
				return []byte(`{"not":"a-reader-response"}`), nil
			},
		}
		server, _, _ := startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
		conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig(t))
		defer conn.Close()
		if err := writeVNextReaderPrepareTLSTestFrame(conn, []byte(`{}`)); err != nil {
			t.Fatalf("write malformed-success test frame: %v", err)
		}
		failure := readVNextReaderPrepareTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPrepareUnavailable ||
			failure.Acceptance != vnextReaderPrepareAcceptanceUnknown {
			t.Fatalf("malformed handler success failure = %#v", failure)
		}
	})
}

func TestVNextReaderPrepareTLSStrictFailureWireRejectsShapeAndEnums(t *testing.T) {
	valid, err := marshalVNextReaderPrepareTLSFailure(vnextReaderPrepareFailure(
		vnextReaderPrepareConflictError,
		vnextReaderPrepareAcceptanceUnknown,
		errors.New("private cause must not be encoded")))
	if err != nil {
		t.Fatalf("marshal valid Reader TLS failure: %v", err)
	}
	if bytes.Contains(valid, []byte("private cause")) {
		t.Fatalf("Reader TLS failure leaked free-form cause: %s", valid)
	}
	if wire, err := decodeStrictVNextReaderPrepareTLSFailure(valid); err != nil || wire.Acceptance != vnextReaderPrepareAcceptanceUnknown {
		t.Fatalf("decode valid Reader TLS failure = %#v / %v", wire, err)
	}
	mutations := map[string]func([]byte) []byte{
		"unknown field": func(raw []byte) []byte {
			return append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"extra":1}`)...)
		},
		"duplicate field": func(raw []byte) []byte {
			return append([]byte(`{"protocol":"duplicate",`), raw[1:]...)
		},
		"trailing": func(raw []byte) []byte {
			return append(append([]byte(nil), raw...), []byte(`{}`)...)
		},
		"missing": func(raw []byte) []byte {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("decode failure map: %v", err)
			}
			delete(fields, "acceptance")
			mutated, _ := json.Marshal(fields)
			return mutated
		},
		"wrong protocol": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(vnextReaderPrepareProtocol),
				[]byte("wrong.protocol"), 1)
		},
		"wrong operation": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(vnextReaderPrepareOperation),
				[]byte("wrongOperation"), 1)
		},
		"wrong error code": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(vnextReaderPrepareConflictError),
				[]byte("WRONG"), 1)
		},
		"wrong acceptance": func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(vnextReaderPrepareAcceptanceUnknown),
				[]byte("WRONG"), 1)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if wire, err := decodeStrictVNextReaderPrepareTLSFailure(mutate(valid)); err == nil || wire != (vnextReaderPrepareTLSFailureWire{}) {
				t.Fatalf("malformed Reader TLS failure = %#v / %v", wire, err)
			}
		})
	}
}

func TestVNextReaderPrepareTLSFrameBoundsAcceptOneAndSixteenMiB(t *testing.T) {
	for _, size := range []int{1, vnextReaderPrepareMaxFrameBytes} {
		t.Run(fmt.Sprintf("size-%d", size), func(t *testing.T) {
			serverSide, clientSide := net.Pipe()
			defer serverSide.Close()
			defer clientSide.Close()
			body := bytes.Repeat([]byte{'x'}, size)
			writeResult := make(chan error, 1)
			go func() {
				writeResult <- writeVNextReaderPrepareTLSTestFrame(clientSide, body)
			}()
			largeAdmission := make(chan struct{}, 1)
			readBody, release, failure := readVNextReaderPrepareTLSFrame(
				serverSide, largeAdmission, 5*time.Second)
			if failure != nil || !bytes.Equal(readBody, body) {
				t.Fatalf("read valid boundary frame: len=%d failure=%v",
					len(readBody), failure)
			}
			wantLarge := 0
			if size > vnextReaderPrepareTLSLargeFrameThreshold {
				wantLarge = 1
			}
			if len(largeAdmission) != wantLarge {
				t.Fatalf("boundary frame large tokens = %d, want %d",
					len(largeAdmission), wantLarge)
			}
			release()
			if err := <-writeResult; err != nil {
				t.Fatalf("write valid boundary frame: %v", err)
			}
			if len(largeAdmission) != 0 {
				t.Fatal("valid boundary frame leaked large admission")
			}
		})
	}
}

func TestVNextReaderPrepareTLSAdmissionDrainRequiresBothPartiesExactlyOnce(t *testing.T) {
	tests := map[string]struct {
		first  func(*vnextReaderPrepareTLSAdmissionDrain)
		second func(*vnextReaderPrepareTLSAdmissionDrain)
	}{
		"handler then serve": {
			first: func(drain *vnextReaderPrepareTLSAdmissionDrain) {
				drain.markHandlerTerminal()
			},
			second: func(drain *vnextReaderPrepareTLSAdmissionDrain) {
				drain.markServeTerminal()
			},
		},
		"serve then handler": {
			first: func(drain *vnextReaderPrepareTLSAdmissionDrain) {
				drain.markServeTerminal()
			},
			second: func(drain *vnextReaderPrepareTLSAdmissionDrain) {
				drain.markHandlerTerminal()
			},
		},
	}
	for name, order := range tests {
		t.Run(name, func(t *testing.T) {
			requestAdmission := make(chan struct{}, 1)
			largeAdmission := make(chan struct{}, 1)
			requestAdmission <- struct{}{}
			largeAdmission <- struct{}{}
			drain := newVNextReaderPrepareTLSAdmissionDrain(
				func() { <-requestAdmission },
				func() { <-largeAdmission })
			order.first(drain)
			order.first(drain)
			if len(requestAdmission) != 1 || len(largeAdmission) != 1 {
				t.Fatalf("one terminal party released admissions: request=%d large=%d",
					len(requestAdmission), len(largeAdmission))
			}
			order.second(drain)
			if len(requestAdmission) != 0 || len(largeAdmission) != 0 {
				t.Fatalf("both terminal parties did not release: request=%d large=%d",
					len(requestAdmission), len(largeAdmission))
			}
			// Duplicate completion signals must not attempt a second release.
			order.first(drain)
			order.second(drain)
		})
	}
}

func TestVNextReaderPrepareTLSAdmissionsSlowlorisAndLargeFramesAreBounded(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	handler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
			return []byte(`{}`), nil
		},
	}
	t.Run("unauthenticated slowloris", func(t *testing.T) {
		server, requestAdmission, _ := startVNextReaderPrepareTLSTestServer(
			t, material, handler, func(config *vnextReaderPrepareTLSServerConfig) {
				config.HandshakeTimeout = 80 * time.Millisecond
			})
		rawConn, err := net.Dial("tcp", server.Addr().String())
		if err != nil {
			t.Fatalf("dial unauthenticated Reader slowloris: %v", err)
		}
		defer rawConn.Close()
		waitVNextReaderPrepareTLSTestCondition(t, "Reader handshake admission", func() bool {
			return len(server.handshakeAdmission) == 1
		})
		if len(requestAdmission) != 0 {
			t.Fatalf("unauthenticated Reader peer consumed %d request slots",
				len(requestAdmission))
		}
		if err := server.Stop(); err != nil {
			t.Fatalf("stop Reader TLS server: %v", err)
		}
		done := make(chan struct{})
		go func() { server.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Reader TLS Stop/Wait did not drain slow handshake")
		}
		if len(server.handshakeAdmission) != 0 || len(requestAdmission) != 0 {
			t.Fatal("Reader TLS slowloris leaked admission")
		}
	})

	t.Run("authenticated frame slowloris holds shared large budget", func(t *testing.T) {
		server, _, largeAdmission := startVNextReaderPrepareTLSTestServer(
			t, material, handler, func(config *vnextReaderPrepareTLSServerConfig) {
				config.RequestReadTimeout = 100 * time.Millisecond
			})
		clientConfig := vnextReaderPrepareTLSTestClientConfig(
			t, material, material.clientCertificatePath,
			material.clientPrivateKeyPath)
		conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig)
		defer conn.Close()
		var header [4]byte
		binary.BigEndian.PutUint32(
			header[:], uint32(vnextReaderPrepareTLSLargeFrameThreshold+1))
		if _, err := conn.Write(header[:]); err != nil {
			t.Fatalf("write partial large Reader frame: %v", err)
		}
		waitVNextReaderPrepareTLSTestCondition(t, "shared Reader large-frame token", func() bool {
			return len(largeAdmission) == 1
		})
		failure := readVNextReaderPrepareTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPrepareInvalidRequest ||
			failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("large slowloris failure = %#v", failure)
		}
		waitVNextReaderPrepareTLSTestCondition(t, "large token release", func() bool {
			return len(largeAdmission) == 0
		})
	})

	t.Run("shared large budget wait is bounded", func(t *testing.T) {
		config := vnextReaderPrepareTLSTestConfig(material)
		config.RequestReadTimeout = 80 * time.Millisecond
		largeAdmission := make(chan struct{}, 1)
		largeAdmission <- struct{}{}
		server, err := startVNextReaderPrepareTLSServer(
			config, handler, make(chan struct{}, 4), largeAdmission)
		if err != nil {
			t.Fatalf("start prefilled-large Reader server: %v", err)
		}
		defer server.Close()
		clientConfig := vnextReaderPrepareTLSTestClientConfig(
			t, material, material.clientCertificatePath,
			material.clientPrivateKeyPath)
		conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig)
		defer conn.Close()
		var header [4]byte
		binary.BigEndian.PutUint32(
			header[:], uint32(vnextReaderPrepareTLSLargeFrameThreshold+1))
		if _, err := conn.Write(header[:]); err != nil {
			t.Fatalf("write Reader large-budget frame: %v", err)
		}
		failure := readVNextReaderPrepareTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPrepareCapacityError ||
			failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("large-budget timeout failure = %#v", failure)
		}
		<-largeAdmission
	})

	t.Run("request admission rejection is definite", func(t *testing.T) {
		config := vnextReaderPrepareTLSTestConfig(material)
		requestAdmission := make(chan struct{}, 1)
		requestAdmission <- struct{}{}
		server, err := startVNextReaderPrepareTLSServer(
			config, handler, requestAdmission, make(chan struct{}, 1))
		if err != nil {
			t.Fatalf("start full-admission Reader server: %v", err)
		}
		defer server.Close()
		clientConfig := vnextReaderPrepareTLSTestClientConfig(
			t, material, material.clientCertificatePath,
			material.clientPrivateKeyPath)
		conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig)
		defer conn.Close()
		failure := readVNextReaderPrepareTLSTestFailure(t, conn)
		if failure.ErrorCode != vnextReaderPrepareCapacityError ||
			failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("request-admission failure = %#v", failure)
		}
		<-requestAdmission
	})
}

func TestVNextReaderPrepareTLSHandlerTimeoutKeepsTruthfulDrainAndNoLateResponse(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	lateSuccessBody := vnextReaderPrepareTLSTestValidResponseBody(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan struct{})
	handler := &vnextReaderPrepareTLSTestHandler{
		handle: func(ctx context.Context, _ string, _ []byte) (
			[]byte, *vnextReaderPrepareRPCError,
		) {
			close(entered)
			<-release // Deliberately ignore ctx to model an injected hung verifier.
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Errorf("late Reader handler context = %v", ctx.Err())
			}
			close(returned)
			return append([]byte(nil), lateSuccessBody...), nil
		},
	}
	config := vnextReaderPrepareTLSTestConfig(material)
	config.HandlerTimeout = 40 * time.Millisecond
	requestAdmission := make(chan struct{}, 1)
	largeAdmission := make(chan struct{}, 1)
	server, err := startVNextReaderPrepareTLSServer(
		config, handler, requestAdmission, largeAdmission)
	if err != nil {
		t.Fatalf("start hung-handler Reader server: %v", err)
	}
	clientConfig := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath, material.clientPrivateKeyPath)
	conn := dialVNextReaderPrepareTLSTest(t, server.Addr().String(), clientConfig)
	largeBody := bytes.Repeat(
		[]byte{'x'}, vnextReaderPrepareTLSLargeFrameThreshold+1)
	if err := writeVNextReaderPrepareTLSTestFrame(conn, largeBody); err != nil {
		t.Fatalf("write hung-handler Reader frame: %v", err)
	}
	<-entered
	failure := readVNextReaderPrepareTLSTestFailure(t, conn)
	if failure.ErrorCode != vnextReaderPrepareUnavailable ||
		failure.Acceptance != vnextReaderPrepareAcceptanceUnknown {
		t.Fatalf("handler-timeout failure = %#v", failure)
	}
	if len(requestAdmission) != 1 || len(largeAdmission) != 1 {
		t.Fatalf("timed-out handler released live admissions: request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
	var secondHeader [4]byte
	if _, err := io.ReadFull(conn, secondHeader[:]); err == nil {
		t.Fatal("Reader TLS emitted a second response before late handler completion")
	}
	_ = conn.Close()
	secondConfig := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath, material.clientPrivateKeyPath)
	secondConn := dialVNextReaderPrepareTLSTest(
		t, server.Addr().String(), secondConfig)
	secondFailure := readVNextReaderPrepareTLSTestFailure(t, secondConn)
	_ = secondConn.Close()
	if secondFailure.ErrorCode != vnextReaderPrepareCapacityError ||
		secondFailure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("live-handler capacity failure = %#v", secondFailure)
	}
	if calls, _, _, _ := handler.snapshot(); calls != 1 {
		t.Fatalf("capacity-rejected request reached handler; calls=%d", calls)
	}
	if err := server.Stop(); err != nil {
		t.Fatalf("stop hung-handler Reader server: %v", err)
	}
	waitDone := make(chan struct{})
	go func() { server.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
		t.Fatal("Reader server Wait completed before timed-out handler actually returned")
	case <-time.After(60 * time.Millisecond):
	}
	close(release)
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("late Reader handler did not return")
	}
	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("Reader server Wait did not drain returned handler")
	}
	if len(requestAdmission) != 0 || len(largeAdmission) != 0 {
		t.Fatalf("returned Reader handler leaked admissions: request=%d large=%d",
			len(requestAdmission), len(largeAdmission))
	}
}

func TestVNextReaderPrepareTLSConcurrentRequestsAndWriteDeadline(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	validResponseBody := vnextReaderPrepareTLSTestValidResponseBody(t)
	handler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
			return append([]byte(nil), validResponseBody...), nil
		},
	}
	server, requestAdmission, largeAdmission :=
		startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
	baseClientConfig := vnextReaderPrepareTLSTestClientConfig(
		t, material, material.clientCertificatePath, material.clientPrivateKeyPath)
	const callers = 24
	start := make(chan struct{})
	errorsChannel := make(chan error, callers)
	var wait sync.WaitGroup
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			config := baseClientConfig.Clone()
			dialer := &net.Dialer{Timeout: 2 * time.Second}
			conn, err := tls.DialWithDialer(
				dialer, "tcp", server.Addr().String(), config)
			if err != nil {
				errorsChannel <- err
				return
			}
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			if err := writeVNextReaderPrepareTLSTestFrame(conn, []byte(`{}`)); err != nil {
				errorsChannel <- err
				return
			}
			body, err := readVNextReaderPrepareTLSTestFrame(conn)
			if err != nil {
				errorsChannel <- err
				return
			}
			if !bytes.Equal(body, validResponseBody) {
				errorsChannel <- fmt.Errorf("response = %s", body)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent Reader TLS request: %v", err)
		}
	}
	if calls, principals, _, _ := handler.snapshot(); calls != callers {
		t.Fatalf("concurrent Reader calls = %d, want %d", calls, callers)
	} else {
		for _, principal := range principals {
			if principal != vnextReaderPrepareTestPrincipal {
				t.Fatalf("concurrent TLS principal = %q", principal)
			}
		}
	}
	waitVNextReaderPrepareTLSTestCondition(t, "concurrent admission release", func() bool {
		return len(requestAdmission) == 0 && len(largeAdmission) == 0
	})

	t.Run("write deadline", func(t *testing.T) {
		server := &vnextReaderPrepareTLSServer{
			responseWriteTimeout: 30 * time.Millisecond,
		}
		serverSide, clientSide := net.Pipe()
		defer clientSide.Close()
		done := make(chan struct{})
		go func() {
			server.writeBody(serverSide, bytes.Repeat([]byte{'x'}, 2<<20))
			serverSide.Close()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("Reader response write ignored its deadline")
		}
	})
}

func TestVNextReaderPrepareTLSServerHasNoOwnerOrRuntimeAuthority(t *testing.T) {
	material := newVNextReaderPrepareTLSTestMaterial(t)
	handler := &vnextReaderPrepareTLSTestHandler{
		handle: func(context.Context, string, []byte) ([]byte, *vnextReaderPrepareRPCError) {
			return []byte(`{}`), nil
		},
	}
	server, _, _ := startVNextReaderPrepareTLSTestServer(t, material, handler, nil)
	if vnextReaderPrepareALPN == vnextOwnerTLSALPN {
		t.Fatal("Reader PREPARE TLS reused the Owner ALPN")
	}
	for _, value := range []string{
		fmt.Sprintf("%T", server.rpc),
		strings.Join(server.tlsConfig.NextProtos, ","),
	} {
		lower := strings.ToLower(value)
		for _, forbidden := range []string{
			"owner/7", "scheduler role", "producer role", "dax", "criu", "active", "release",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("Reader PREPARE TLS boundary %q contains forbidden %q", value, forbidden)
			}
		}
	}
}
