package main

import (
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
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	vnextReaderPrepareTLSMaxHandshakes       = 32
	vnextReaderPrepareTLSLargeFrameThreshold = 1 << 20
	vnextReaderPrepareTLSMaxStageTimeout     = 30 * time.Second
)

// vnextReaderPrepareTLSServerConfig is deliberately transport-only. It has no
// Owner role, Owner operation, runtime, DAX, CRIU, ACTIVE, or release setting.
// A future runtime builder should clone one URI-SAN-to-Scheduler input into
// this config and the Reader authority verifier. A narrower TLS map remains
// fail-closed, and the shared validator keeps both boundaries' format, count,
// and retained-byte rules identical without coupling this server to a concrete
// verifier type.
type vnextReaderPrepareTLSServerConfig struct {
	ListenAddress         string
	ServerCertificatePath string
	ServerPrivateKeyPath  string
	ClientCAPath          string
	ExpectedServerURISAN  string
	SchedulerByPrincipal  map[string]string
	HandshakeTimeout      time.Duration
	RequestReadTimeout    time.Duration
	HandlerTimeout        time.Duration
	ResponseWriteTimeout  time.Duration
}

// vnextReaderPrepareTransportRPC is the transport-neutral Reader PREPARE
// boundary. Production supplies *vnextReaderPrepareRPC. Keeping the interface
// narrower than the service prevents the TLS listener from gaining any other
// operation or lifecycle authority.
type vnextReaderPrepareTransportRPC interface {
	Handle(
		context.Context,
		string,
		[]byte,
	) ([]byte, *vnextReaderPrepareRPCError)
}

// vnextReaderPrepareTLSFailureWire is the complete failure response. It
// intentionally excludes free-form error text and has no success wrapper.
// Successful responses are the exact body returned by the existing RPC.
type vnextReaderPrepareTLSFailureWire struct {
	Protocol   string                       `json:"protocol"`
	Operation  string                       `json:"operation"`
	ErrorCode  vnextReaderPrepareErrorCode  `json:"errorCode"`
	Acceptance vnextReaderPrepareAcceptance `json:"acceptance"`
}

type vnextReaderPrepareTLSServer struct {
	listener             net.Listener
	tlsConfig            *tls.Config
	rpc                  vnextReaderPrepareTransportRPC
	statusRPC            vnextReaderPreparedStatusTransportRPC
	handshakeAdmission   chan struct{}
	requestAdmission     chan struct{}
	largeFrameAdmission  chan struct{}
	handshakeTimeout     time.Duration
	requestReadTimeout   time.Duration
	handlerTimeout       time.Duration
	responseWriteTimeout time.Duration
	schedulerByPrincipal map[string]string

	stopOnce sync.Once
	wg       sync.WaitGroup
}

type vnextReaderPrepareTLSHandlerResult struct {
	body    []byte
	failure *vnextReaderPrepareRPCError
}

// vnextReaderPrepareTLSAdmissionDrain joins two independently completing
// lifetimes. The request body and response work remain admitted until both the
// actual RPC handler is terminal and the connection's validation/write path
// has returned. Neither side can recycle capacity by completing alone.
type vnextReaderPrepareTLSAdmissionDrain struct {
	mu              sync.Mutex
	handlerTerminal bool
	serveTerminal   bool
	releaseOnce     sync.Once
	release         func()
}

func newVNextReaderPrepareTLSAdmissionDrain(
	releaseRequest func(),
	releaseLarge func(),
) *vnextReaderPrepareTLSAdmissionDrain {
	return &vnextReaderPrepareTLSAdmissionDrain{release: func() {
		releaseLarge()
		releaseRequest()
	}}
}

func (drain *vnextReaderPrepareTLSAdmissionDrain) markHandlerTerminal() {
	drain.markTerminal(true)
}

func (drain *vnextReaderPrepareTLSAdmissionDrain) markServeTerminal() {
	drain.markTerminal(false)
}

func (drain *vnextReaderPrepareTLSAdmissionDrain) markTerminal(handler bool) {
	if drain == nil {
		return
	}
	drain.mu.Lock()
	if handler {
		drain.handlerTerminal = true
	} else {
		drain.serveTerminal = true
	}
	ready := drain.handlerTerminal && drain.serveTerminal
	drain.mu.Unlock()
	if ready {
		drain.releaseOnce.Do(drain.release)
	}
}

func validateVNextReaderPrepareTLSServerConfig(
	config vnextReaderPrepareTLSServerConfig,
	rpc vnextReaderPrepareTransportRPC,
) (map[string]string, error) {
	if rpc == nil {
		return nil, errors.New("VNext Reader PREPARE TLS RPC is unavailable")
	}
	if err := validateVNextReaderPrepareTLSListenAddress(
		config.ListenAddress); err != nil {
		return nil, err
	}
	for role, path := range map[string]string{
		"server certificate": config.ServerCertificatePath,
		"server private key": config.ServerPrivateKeyPath,
		"client CA":          config.ClientCAPath,
	} {
		if err := validateVNextReaderPrepareTLSPath(path, role); err != nil {
			return nil, err
		}
	}
	if err := validateVNextReaderPreparePrincipalURI(
		config.ExpectedServerURISAN); err != nil {
		return nil, fmt.Errorf("validate Reader PREPARE server URI SAN: %w", err)
	}
	bindings, err := cloneVNextReaderPreparePrincipalBindings(
		config.SchedulerByPrincipal)
	if err != nil {
		return nil, fmt.Errorf("validate Reader PREPARE TLS principal bindings: %w", err)
	}
	for name, timeout := range map[string]time.Duration{
		"handshake":      config.HandshakeTimeout,
		"request read":   config.RequestReadTimeout,
		"handler":        config.HandlerTimeout,
		"response write": config.ResponseWriteTimeout,
	} {
		if timeout <= 0 || timeout > vnextReaderPrepareTLSMaxStageTimeout {
			return nil, fmt.Errorf(
				"VNext Reader PREPARE TLS %s timeout %s is outside (0,%s]",
				name, timeout, vnextReaderPrepareTLSMaxStageTimeout)
		}
	}
	return bindings, nil
}

func validateVNextReaderPrepareTLSListenAddress(address string) error {
	if address == "" || strings.TrimSpace(address) != address ||
		strings.IndexFunc(address, unicode.IsControl) >= 0 {
		return errors.New(
			"VNext Reader PREPARE TLS listen address is empty or non-canonical")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf(
			"VNext Reader PREPARE TLS listen address %q is not host:port", address)
	}
	return nil
}

func validateVNextReaderPrepareTLSPath(path string, role string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
		strings.IndexFunc(path, unicode.IsSpace) >= 0 {
		return fmt.Errorf(
			"VNext Reader PREPARE TLS %s path %q is not absolute, clean, and whitespace-free",
			role, path)
	}
	return nil
}

func loadVNextReaderPrepareTLSCertificatePool(
	path string,
) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read VNext Reader PREPARE TLS client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if len(data) == 0 || !pool.AppendCertsFromPEM(data) {
		return nil, errors.New(
			"VNext Reader PREPARE TLS client CA contains no PEM certificates")
	}
	return pool, nil
}

func loadVNextReaderPrepareTLSServerConfig(
	config vnextReaderPrepareTLSServerConfig,
	schedulerByPrincipal map[string]string,
	nextProtos []string,
) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		config.ServerCertificatePath, config.ServerPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf(
			"load VNext Reader PREPARE TLS server certificate/key: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return nil, errors.New(
			"VNext Reader PREPARE TLS server certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf(
			"parse VNext Reader PREPARE TLS server leaf certificate: %w", err)
	}
	if len(leaf.URIs) != 1 {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE TLS server leaf has %d URI SANs; exactly one is required",
			len(leaf.URIs))
	}
	serverIdentity := leaf.URIs[0].String()
	if err := validateVNextReaderPreparePrincipalURI(serverIdentity); err != nil {
		return nil, fmt.Errorf(
			"validate VNext Reader PREPARE TLS server leaf URI SAN: %w", err)
	}
	if serverIdentity != config.ExpectedServerURISAN {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE TLS server leaf URI SAN %q differs from configured %q",
			serverIdentity, config.ExpectedServerURISAN)
	}
	certificate.Leaf = leaf
	clientCAs, err := loadVNextReaderPrepareTLSCertificatePool(config.ClientCAPath)
	if err != nil {
		return nil, err
	}
	bindings := make(map[string]string, len(schedulerByPrincipal))
	for principal, schedulerID := range schedulerByPrincipal {
		bindings[cloneVNextReaderRetainedString(principal)] =
			cloneVNextReaderRetainedString(schedulerID)
	}
	tlsConfig := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		MaxVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{certificate},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              clientCAs,
		NextProtos:             append([]string(nil), nextProtos...),
		SessionTicketsDisabled: true,
	}
	allowedALPNs := make(map[string]struct{}, len(nextProtos))
	for _, protocol := range nextProtos {
		if protocol != vnextReaderPrepareALPN &&
			protocol != vnextReaderPreparedStatusALPN {
			return nil, fmt.Errorf(
				"VNext Reader TLS ALPN %q is not an exact Reader operation", protocol)
		}
		if _, duplicate := allowedALPNs[protocol]; duplicate {
			return nil, fmt.Errorf("VNext Reader TLS ALPN %q is duplicated", protocol)
		}
		allowedALPNs[protocol] = struct{}{}
	}
	if len(allowedALPNs) == 0 {
		return nil, errors.New("VNext Reader TLS has no enabled ALPN")
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		_, err := vnextReaderTLSAuthenticatedPrincipal(
			state, bindings, allowedALPNs)
		return err
	}
	return tlsConfig, nil
}

func vnextReaderPrepareTLSAuthenticatedPrincipal(
	state tls.ConnectionState,
	schedulerByPrincipal map[string]string,
) (string, error) {
	return vnextReaderTLSAuthenticatedPrincipal(
		state,
		schedulerByPrincipal,
		map[string]struct{}{vnextReaderPrepareALPN: {}},
	)
}

func vnextReaderTLSAuthenticatedPrincipal(
	state tls.ConnectionState,
	schedulerByPrincipal map[string]string,
	allowedALPNs map[string]struct{},
) (string, error) {
	if state.Version != tls.VersionTLS13 {
		return "", errors.New(
			"VNext Reader PREPARE TLS peer did not negotiate exact TLS 1.3")
	}
	if _, allowed := allowedALPNs[state.NegotiatedProtocol]; !allowed {
		return "", fmt.Errorf(
			"VNext Reader TLS peer negotiated unsupported ALPN %q",
			state.NegotiatedProtocol)
	}
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 ||
		len(state.PeerCertificates) == 0 {
		return "", errors.New(
			"VNext Reader PREPARE TLS client certificate was not verified")
	}
	identities := state.PeerCertificates[0].URIs
	if len(identities) != 1 {
		return "", fmt.Errorf(
			"VNext Reader PREPARE TLS client leaf has %d URI SANs; exactly one is required",
			len(identities))
	}
	principal := identities[0].String()
	if err := validateVNextReaderPreparePrincipalURI(principal); err != nil {
		return "", fmt.Errorf(
			"validate VNext Reader PREPARE TLS client URI SAN: %w", err)
	}
	if _, allowed := schedulerByPrincipal[principal]; !allowed {
		return "", fmt.Errorf(
			"VNext Reader PREPARE TLS client URI SAN %q is not explicitly allowed",
			principal)
	}
	return cloneVNextReaderRetainedString(principal), nil
}

func startVNextReaderPrepareTLSServer(
	config vnextReaderPrepareTLSServerConfig,
	rpc vnextReaderPrepareTransportRPC,
	requestAdmission chan struct{},
	largeFrameAdmission chan struct{},
) (*vnextReaderPrepareTLSServer, error) {
	return startVNextReaderPrepareTLSServerCommon(
		config, rpc, nil, requestAdmission, largeFrameAdmission)
}

func startVNextReaderPrepareAndStatusTLSServer(
	config vnextReaderPrepareTLSServerConfig,
	prepareRPC vnextReaderPrepareTransportRPC,
	statusRPC vnextReaderPreparedStatusTransportRPC,
	requestAdmission chan struct{},
	largeFrameAdmission chan struct{},
) (*vnextReaderPrepareTLSServer, error) {
	if vnextReaderPreparedStatusNilInterface(statusRPC) {
		return nil, errors.New(
			"VNext Reader STATUS_AND_FENCE TLS RPC is unavailable")
	}
	return startVNextReaderPrepareTLSServerCommon(
		config, prepareRPC, statusRPC, requestAdmission, largeFrameAdmission)
}

func startVNextReaderPrepareTLSServerCommon(
	config vnextReaderPrepareTLSServerConfig,
	rpc vnextReaderPrepareTransportRPC,
	statusRPC vnextReaderPreparedStatusTransportRPC,
	requestAdmission chan struct{},
	largeFrameAdmission chan struct{},
) (*vnextReaderPrepareTLSServer, error) {
	bindings, err := validateVNextReaderPrepareTLSServerConfig(config, rpc)
	if err != nil {
		return nil, err
	}
	if requestAdmission == nil || cap(requestAdmission) == 0 {
		return nil, errors.New(
			"VNext Reader PREPARE TLS request admission is unavailable or unbuffered")
	}
	if largeFrameAdmission == nil || cap(largeFrameAdmission) == 0 {
		return nil, errors.New(
			"VNext Reader PREPARE TLS large-frame admission is unavailable or unbuffered")
	}
	nextProtos := []string{vnextReaderPrepareALPN}
	if !vnextReaderPreparedStatusNilInterface(statusRPC) {
		nextProtos = append(nextProtos, vnextReaderPreparedStatusALPN)
	}
	tlsConfig, err := loadVNextReaderPrepareTLSServerConfig(
		config, bindings, nextProtos)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf(
			"listen for VNext Reader PREPARE mTLS on %q: %w",
			config.ListenAddress, err)
	}
	server := &vnextReaderPrepareTLSServer{
		listener:             listener,
		tlsConfig:            tlsConfig,
		rpc:                  rpc,
		statusRPC:            statusRPC,
		handshakeAdmission:   make(chan struct{}, vnextReaderPrepareTLSMaxHandshakes),
		requestAdmission:     requestAdmission,
		largeFrameAdmission:  largeFrameAdmission,
		handshakeTimeout:     config.HandshakeTimeout,
		requestReadTimeout:   config.RequestReadTimeout,
		handlerTimeout:       config.HandlerTimeout,
		responseWriteTimeout: config.ResponseWriteTimeout,
		schedulerByPrincipal: bindings,
	}
	server.wg.Add(1)
	go server.acceptLoop()
	return server, nil
}

func (server *vnextReaderPrepareTLSServer) Addr() net.Addr {
	if server == nil || server.listener == nil {
		return nil
	}
	return server.listener.Addr()
}

func (server *vnextReaderPrepareTLSServer) Stop() error {
	if server == nil || server.listener == nil {
		return nil
	}
	var closeErr error
	server.stopOnce.Do(func() {
		closeErr = server.listener.Close()
	})
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (server *vnextReaderPrepareTLSServer) Wait() {
	if server != nil {
		server.wg.Wait()
	}
}

func (server *vnextReaderPrepareTLSServer) Close() error {
	if server == nil {
		return nil
	}
	err := server.Stop()
	server.Wait()
	return err
}

func (server *vnextReaderPrepareTLSServer) acceptLoop() {
	defer server.wg.Done()
	var retryDelay time.Duration
	for {
		rawConn, err := server.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if retryDelay == 0 {
				retryDelay = 5 * time.Millisecond
			} else if retryDelay < time.Second {
				retryDelay *= 2
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
			}
			time.Sleep(retryDelay)
			continue
		}
		retryDelay = 0
		// Unauthenticated sockets cannot consume the admission shared by
		// authenticated Reader requests.
		if !tryAcquireDaemonRequestAdmission(server.handshakeAdmission) {
			_ = rawConn.Close()
			continue
		}
		server.wg.Add(1)
		go func(conn net.Conn) {
			defer server.wg.Done()
			server.serveAccepted(conn)
		}(rawConn)
	}
}

func (server *vnextReaderPrepareTLSServer) serveAccepted(rawConn net.Conn) {
	tlsConn := tls.Server(rawConn, server.tlsConfig)
	defer tlsConn.Close()
	handshakeHeld := true
	defer func() {
		if handshakeHeld {
			<-server.handshakeAdmission
		}
	}()
	handshakeCtx, cancel := context.WithTimeout(
		context.Background(), server.handshakeTimeout)
	defer cancel()
	if err := tlsConn.SetDeadline(time.Now().Add(server.handshakeTimeout)); err != nil {
		return
	}
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		return
	}
	allowedALPNs := map[string]struct{}{vnextReaderPrepareALPN: {}}
	if !vnextReaderPreparedStatusNilInterface(server.statusRPC) {
		allowedALPNs[vnextReaderPreparedStatusALPN] = struct{}{}
	}
	state := tlsConn.ConnectionState()
	principal, err := vnextReaderTLSAuthenticatedPrincipal(
		state, server.schedulerByPrincipal, allowedALPNs)
	if err != nil {
		return
	}
	<-server.handshakeAdmission
	handshakeHeld = false
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return
	}
	if !tryAcquireDaemonRequestAdmission(server.requestAdmission) {
		if state.NegotiatedProtocol == vnextReaderPreparedStatusALPN {
			server.writeStatusFailure(tlsConn, vnextReaderPreparedStatusFailure(
				vnextReaderPreparedStatusCapacityError,
				vnextReaderPreparedStatusDefinitelyNotAccepted,
				errors.New(
					"VNext Reader STATUS_AND_FENCE TLS request admission is full")))
		} else {
			server.writeFailure(tlsConn, vnextReaderPrepareFailure(
				vnextReaderPrepareCapacityError,
				vnextReaderPrepareDefinitelyNotAccepted,
				errors.New("VNext Reader PREPARE TLS request admission is full")))
		}
		return
	}
	var releaseRequestOnce sync.Once
	releaseRequest := func() {
		releaseRequestOnce.Do(func() { <-server.requestAdmission })
	}
	server.serveAuthenticated(
		tlsConn, principal, state.NegotiatedProtocol, releaseRequest)
}

func (server *vnextReaderPrepareTLSServer) serveAuthenticated(
	conn net.Conn,
	principal string,
	negotiatedProtocol string,
	releaseRequest func(),
) {
	if negotiatedProtocol == vnextReaderPreparedStatusALPN {
		server.serveAuthenticatedStatus(conn, principal, releaseRequest)
		return
	}
	if negotiatedProtocol != vnextReaderPrepareALPN {
		releaseRequest()
		return
	}
	body, releaseLarge, failure := readVNextReaderPrepareTLSFrame(
		conn, server.largeFrameAdmission, server.requestReadTimeout)
	if failure != nil {
		releaseRequest()
		server.writeFailure(conn, failure)
		return
	}
	// From this point both admissions cover the joined handler/serve lifetime.
	// They remain held until the handler goroutine is terminal and this function
	// has finished strict response validation and its one bounded write attempt.
	drain := newVNextReaderPrepareTLSAdmissionDrain(
		releaseRequest, releaseLarge)
	defer drain.markServeTerminal()
	result := server.runHandler(principal, body, drain.markHandlerTerminal)
	if result.failure != nil {
		server.writeFailure(conn, result.failure)
		return
	}
	if len(result.body) == 0 || len(result.body) > vnextReaderPrepareMaxFrameBytes {
		server.writeFailure(conn, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareAcceptanceUnknown,
			fmt.Errorf("Reader PREPARE handler response has %d bytes", len(result.body))))
		return
	}
	if _, err := decodeVNextReaderPrepareResponse(result.body); err != nil {
		server.writeFailure(conn, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareAcceptanceUnknown,
			fmt.Errorf("strictly validate Reader PREPARE handler response: %v", err)))
		return
	}
	server.writeBody(conn, result.body)
}

func (server *vnextReaderPrepareTLSServer) runHandler(
	principal string,
	body []byte,
	markHandlerTerminal func(),
) vnextReaderPrepareTLSHandlerResult {
	handlerCtx, cancel := context.WithTimeout(
		context.Background(), server.handlerTimeout)
	defer cancel()
	resultChannel := make(chan vnextReaderPrepareTLSHandlerResult, 1)
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		defer markHandlerTerminal()
		result := vnextReaderPrepareTLSHandlerResult{}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					result.failure = vnextReaderPrepareFailure(
						vnextReaderPrepareUnavailable,
						vnextReaderPrepareAcceptanceUnknown,
						fmt.Errorf("VNext Reader PREPARE RPC panic: %v", recovered))
				}
			}()
			result.body, result.failure = server.rpc.Handle(
				handlerCtx, principal, body)
		}()
		resultChannel <- result
	}()
	select {
	case result := <-resultChannel:
		if handlerCtx.Err() != nil {
			return vnextReaderPrepareTLSHandlerTimeout(handlerCtx.Err())
		}
		return result
	case <-handlerCtx.Done():
		return vnextReaderPrepareTLSHandlerTimeout(handlerCtx.Err())
	}
}

func vnextReaderPrepareTLSHandlerTimeout(
	cause error,
) vnextReaderPrepareTLSHandlerResult {
	return vnextReaderPrepareTLSHandlerResult{failure: vnextReaderPrepareFailure(
		vnextReaderPrepareUnavailable,
		// The handler may have committed PREPARED just before the local timer.
		vnextReaderPrepareAcceptanceUnknown,
		fmt.Errorf("VNext Reader PREPARE TLS handler deadline: %v", cause))}
}

func readVNextReaderPrepareTLSFrame(
	conn net.Conn,
	largeFrameAdmission chan struct{},
	readTimeout time.Duration,
) ([]byte, func(), *vnextReaderPrepareRPCError) {
	release := func() {}
	deadline := time.Now().Add(readTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, release, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("set Reader PREPARE frame deadline: %w", err))
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, release, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("read Reader PREPARE frame header: %w", err))
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(vnextReaderPrepareMaxFrameBytes) {
		return nil, release, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("Reader PREPARE frame size %d is outside 1..%d",
				size, vnextReaderPrepareMaxFrameBytes))
	}
	largeHeld := false
	if size > vnextReaderPrepareTLSLargeFrameThreshold {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, release, vnextReaderPrepareFailure(
				vnextReaderPrepareCapacityError,
				vnextReaderPrepareDefinitelyNotAccepted,
				errors.New("Reader PREPARE large-frame admission timed out"))
		}
		timer := time.NewTimer(remaining)
		select {
		case largeFrameAdmission <- struct{}{}:
			largeHeld = true
		case <-timer.C:
			return nil, release, vnextReaderPrepareFailure(
				vnextReaderPrepareCapacityError,
				vnextReaderPrepareDefinitelyNotAccepted,
				errors.New("Reader PREPARE large-frame admission timed out"))
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	if largeHeld {
		var once sync.Once
		release = func() {
			once.Do(func() { <-largeFrameAdmission })
		}
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(conn, body); err != nil {
		release()
		return nil, func() {}, vnextReaderPrepareFailure(
			vnextReaderPrepareInvalidRequest,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("read Reader PREPARE frame body: %w", err))
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		release()
		return nil, func() {}, vnextReaderPrepareFailure(
			vnextReaderPrepareUnavailable,
			vnextReaderPrepareDefinitelyNotAccepted,
			fmt.Errorf("clear Reader PREPARE frame deadline: %w", err))
	}
	return body, release, nil
}

func marshalVNextReaderPrepareTLSFailure(
	failure *vnextReaderPrepareRPCError,
) ([]byte, error) {
	if failure == nil {
		return nil, errors.New("VNext Reader PREPARE TLS failure is nil")
	}
	if !validVNextReaderPrepareTLSErrorCode(failure.Code) {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE TLS error code %q is invalid", failure.Code)
	}
	if !validVNextReaderPrepareTLSAcceptance(failure.Acceptance) {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE TLS acceptance %q is invalid", failure.Acceptance)
	}
	return marshalBoundedVNextReaderPrepareJSON(vnextReaderPrepareTLSFailureWire{
		Protocol:   vnextReaderPrepareProtocol,
		Operation:  vnextReaderPrepareOperation,
		ErrorCode:  failure.Code,
		Acceptance: failure.Acceptance,
	})
}

func decodeStrictVNextReaderPrepareTLSFailure(
	body []byte,
) (vnextReaderPrepareTLSFailureWire, error) {
	var wire vnextReaderPrepareTLSFailureWire
	if err := decodeStrictVNextReaderPrepareJSON(body, &wire); err != nil {
		return vnextReaderPrepareTLSFailureWire{}, err
	}
	if wire.Protocol != vnextReaderPrepareProtocol ||
		wire.Operation != vnextReaderPrepareOperation ||
		!validVNextReaderPrepareTLSErrorCode(wire.ErrorCode) ||
		!validVNextReaderPrepareTLSAcceptance(wire.Acceptance) {
		return vnextReaderPrepareTLSFailureWire{}, errors.New(
			"VNext Reader PREPARE TLS failure identity or enum is invalid")
	}
	return wire, nil
}

func validVNextReaderPrepareTLSErrorCode(code vnextReaderPrepareErrorCode) bool {
	switch code {
	case vnextReaderPrepareInvalidRequest,
		vnextReaderPrepareAuthorityError,
		vnextReaderPrepareIdentityError,
		vnextReaderPrepareConflictError,
		vnextReaderPrepareCapacityError,
		vnextReaderPrepareUnavailable:
		return true
	default:
		return false
	}
}

func validVNextReaderPrepareTLSAcceptance(
	acceptance vnextReaderPrepareAcceptance,
) bool {
	return acceptance == vnextReaderPrepareDefinitelyNotAccepted ||
		acceptance == vnextReaderPrepareAcceptanceUnknown
}

func (server *vnextReaderPrepareTLSServer) writeFailure(
	conn net.Conn,
	failure *vnextReaderPrepareRPCError,
) {
	body, err := marshalVNextReaderPrepareTLSFailure(failure)
	if err != nil {
		body, _ = json.Marshal(vnextReaderPrepareTLSFailureWire{
			Protocol:   vnextReaderPrepareProtocol,
			Operation:  vnextReaderPrepareOperation,
			ErrorCode:  vnextReaderPrepareUnavailable,
			Acceptance: vnextReaderPrepareAcceptanceUnknown,
		})
	}
	server.writeBody(conn, body)
}

// writeBody deliberately does not retry at the protocol level. Any write
// error or EOF remains ambiguous to the client, which must not reinterpret it
// as a definitive PREPARE rejection.
func (server *vnextReaderPrepareTLSServer) writeBody(
	conn net.Conn,
	body []byte,
) {
	if len(body) == 0 || len(body) > vnextReaderPrepareMaxFrameBytes {
		return
	}
	if err := conn.SetWriteDeadline(
		time.Now().Add(server.responseWriteTimeout)); err != nil {
		return
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if err := writeVNextReaderPrepareTLSFull(conn, header[:]); err != nil {
		return
	}
	_ = writeVNextReaderPrepareTLSFull(conn, body)
}

func writeVNextReaderPrepareTLSFull(conn net.Conn, body []byte) error {
	for len(body) != 0 {
		written, err := conn.Write(body)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(body) {
			return io.ErrShortWrite
		}
		body = body[written:]
	}
	return nil
}

var _ vnextReaderPrepareTransportRPC = (*vnextReaderPrepareRPC)(nil)
