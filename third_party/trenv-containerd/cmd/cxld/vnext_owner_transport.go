package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	vnextOwnerTLSALPN             = "cxld-vnext-owner/7"
	vnextOwnerTLSDialTimeout      = 10 * time.Second
	vnextOwnerTLSHandshakeTimeout = 10 * time.Second
	vnextOwnerTLSMaxHandshakes    = 32
)

// vnextOwnerTLSServerConfig is an all-or-nothing, opt-in remote transport.
// It deliberately does not share the legacy metadata HTTP listener. The
// remote listener does not accept a caller-selected role. Mutual TLS binds an
// exact, unambiguous URI SAN to either the Scheduler or Producer operation
// policy before any Owner request is dispatched.
type vnextOwnerTLSServerConfig struct {
	ListenAddress                 string
	ServerCertificatePath         string
	ServerPrivateKeyPath          string
	ClientCAPath                  string
	AllowedSchedulerClientURISANs []string
	AllowedProducerClientURISANs  []string
	HandshakeTimeout              time.Duration
	RequestReadTimeout            time.Duration
	ResponseWriteTimeout          time.Duration
}

type vnextOwnerTLSClientConfig struct {
	Endpoint              string
	ServerName            string
	ClientCertificatePath string
	ClientPrivateKeyPath  string
	ServerCAPath          string
	ExpectedServerURISAN  string
	CallerRole            vnextOwnerCallerRole
	DialTimeout           time.Duration
	HandshakeTimeout      time.Duration
	RequestWriteTimeout   time.Duration
	ResponseReadTimeout   time.Duration
}

// vnextOwnerTLSExecResponse is the exact outer response contract for the
// remote transport. Every field is mandatory, including empty failure fields,
// so the peer can reject missing, null, duplicate, unknown, and trailing JSON
// instead of inheriting the looser legacy daemon response decoder. Per-stage
// timing maps are intentionally not part of this bounded v5 transport.
type vnextOwnerTLSExecResponse struct {
	OK             bool   `json:"ok"`
	Stdout         string `json:"stdout"`
	Stderr         string `json:"stderr"`
	ExitCode       int    `json:"exitCode"`
	Error          string `json:"error"`
	ErrorCode      string `json:"errorCode"`
	Operation      string `json:"operation"`
	DurationMicros int64  `json:"durationMicros"`
}

type vnextOwnerTLSServer struct {
	listener           net.Listener
	tlsConfig          *tls.Config
	rpc                *vnextOwnerRPC
	handshakeAdmission chan struct{}
	requestAdmission   chan struct{}
	largeAdmission     chan struct{}
	handshakeTimeout   time.Duration
	readTimeout        time.Duration
	writeTimeout       time.Duration
	allowedClientRoles map[string]vnextOwnerCallerRole

	stopOnce sync.Once
	wg       sync.WaitGroup
}

type vnextOwnerTLSRoundTripper struct {
	endpoint         string
	tlsConfig        *tls.Config
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	writeTimeout     time.Duration
	readTimeout      time.Duration
	callerRole       vnextOwnerCallerRole
}

func parseVNextOwnerURIAllowlist(value string) ([]string, error) {
	if value == "" {
		return nil, nil
	}
	items := strings.Split(value, ",")
	identities := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for index, item := range items {
		identity := strings.TrimSpace(item)
		if identity == "" {
			return nil, fmt.Errorf("VNext Owner client URI SAN %d is empty", index)
		}
		if identity != item {
			return nil, fmt.Errorf(
				"VNext Owner client URI SAN %q has surrounding whitespace", item)
		}
		if err := validateVNextOwnerTLSURI(identity, "client URI SAN"); err != nil {
			return nil, err
		}
		if _, duplicate := seen[identity]; duplicate {
			return nil, fmt.Errorf(
				"VNext Owner client URI SAN %q is duplicated", identity)
		}
		seen[identity] = struct{}{}
		identities = append(identities, identity)
	}
	return identities, nil
}

func vnextOwnerTLSAllowedClientRoles(
	config vnextOwnerTLSServerConfig,
) (map[string]vnextOwnerCallerRole, error) {
	roles := make(map[string]vnextOwnerCallerRole,
		len(config.AllowedSchedulerClientURISANs)+
			len(config.AllowedProducerClientURISANs))
	add := func(role vnextOwnerCallerRole, identities []string) error {
		for _, identity := range identities {
			if err := validateVNextOwnerTLSURI(
				identity, fmt.Sprintf("%s client URI SAN", role)); err != nil {
				return err
			}
			if existing, duplicate := roles[identity]; duplicate {
				if existing == role {
					return fmt.Errorf(
						"VNext Owner %s client URI SAN %q is duplicated",
						role, identity)
				}
				return fmt.Errorf(
					"VNext Owner client URI SAN %q is assigned to both %s and %s roles",
					identity, existing, role)
			}
			roles[identity] = role
		}
		return nil
	}
	if err := add(vnextOwnerCallerScheduler,
		config.AllowedSchedulerClientURISANs); err != nil {
		return nil, err
	}
	if err := add(vnextOwnerCallerProducer,
		config.AllowedProducerClientURISANs); err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		return nil, errors.New(
			"VNext Owner TLS listener requires at least one Scheduler or Producer client URI SAN")
	}
	return roles, nil
}

func validateVNextOwnerTLSURI(value string, role string) error {
	if value == "" || strings.TrimSpace(value) != value {
		return fmt.Errorf("VNext Owner %s is empty or has surrounding whitespace", role)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("VNext Owner %s contains a control character", role)
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" {
		return fmt.Errorf("VNext Owner %s %q is not an absolute URI", role, value)
	}
	if parsed.String() != value {
		return fmt.Errorf("VNext Owner %s %q is not canonical", role, value)
	}
	return nil
}

func validateVNextOwnerTLSServerConfig(
	config vnextOwnerTLSServerConfig,
	rpc *vnextOwnerRPC,
) (bool, error) {
	configured := 0
	for _, value := range []string{
		config.ListenAddress,
		config.ServerCertificatePath,
		config.ServerPrivateKeyPath,
		config.ClientCAPath,
	} {
		if value != "" {
			configured++
		}
	}
	if len(config.AllowedSchedulerClientURISANs) != 0 ||
		len(config.AllowedProducerClientURISANs) != 0 {
		configured++
	}
	if configured == 0 {
		return false, nil
	}
	if configured != 5 {
		return false, errors.New(
			"VNext Owner TLS listener requires listen address, server certificate, " +
				"server private key, client CA, and non-empty role-specific client URI SAN allowlists together")
	}
	if rpc == nil || rpc.service == nil {
		return false, errors.New(
			"VNext Owner TLS listener requires an active strict VNext Owner runtime")
	}
	if err := validateVNextOwnerTLSListenAddress(config.ListenAddress); err != nil {
		return false, err
	}
	for role, path := range map[string]string{
		"server certificate": config.ServerCertificatePath,
		"server private key": config.ServerPrivateKeyPath,
		"client CA":          config.ClientCAPath,
	} {
		if err := validateVNextOwnerRuntimePath(path, role); err != nil {
			return false, err
		}
	}
	if _, err := vnextOwnerTLSAllowedClientRoles(config); err != nil {
		return false, err
	}
	if config.HandshakeTimeout < 0 || config.RequestReadTimeout < 0 ||
		config.ResponseWriteTimeout < 0 {
		return false, errors.New("VNext Owner TLS server timeouts cannot be negative")
	}
	return true, nil
}

func validateVNextOwnerTLSListenAddress(address string) error {
	if address == "" || strings.TrimSpace(address) != address {
		return errors.New("VNext Owner TLS listen address is empty or has surrounding whitespace")
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return fmt.Errorf("VNext Owner TLS listen address %q is not host:port", address)
	}
	return nil
}

func validateVNextOwnerTLSEndpoint(endpoint string) error {
	if endpoint == "" || strings.TrimSpace(endpoint) != endpoint {
		return errors.New("VNext Owner TLS endpoint is empty or has surrounding whitespace")
	}
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("VNext Owner TLS endpoint %q is not host:port", endpoint)
	}
	return nil
}

func normalizedVNextOwnerTLSServerTimeouts(
	config vnextOwnerTLSServerConfig,
) vnextOwnerTLSServerConfig {
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = vnextOwnerTLSHandshakeTimeout
	}
	if config.RequestReadTimeout == 0 {
		config.RequestReadTimeout = daemonFrameReadTimeout
	}
	if config.ResponseWriteTimeout == 0 {
		config.ResponseWriteTimeout = daemonFrameWriteTimeout
	}
	return config
}

func normalizedVNextOwnerTLSClientTimeouts(
	config vnextOwnerTLSClientConfig,
) vnextOwnerTLSClientConfig {
	if config.DialTimeout == 0 {
		config.DialTimeout = vnextOwnerTLSDialTimeout
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = vnextOwnerTLSHandshakeTimeout
	}
	if config.RequestWriteTimeout == 0 {
		config.RequestWriteTimeout = daemonFrameWriteTimeout
	}
	if config.ResponseReadTimeout == 0 {
		config.ResponseReadTimeout = daemonFrameReadTimeout
	}
	return config
}

func newVNextOwnerTLSServerConfig(
	config vnextOwnerTLSServerConfig,
) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(
		config.ServerCertificatePath, config.ServerPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load VNext Owner TLS server certificate/key: %w", err)
	}
	clientCAs, err := loadVNextOwnerTLSCertificatePool(config.ClientCAPath, "client CA")
	if err != nil {
		return nil, err
	}
	allowedRoles, err := vnextOwnerTLSAllowedClientRoles(config)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    clientCAs,
		NextProtos:   []string{vnextOwnerTLSALPN},
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version < tls.VersionTLS13 {
			return errors.New("VNext Owner TLS peer negotiated a protocol below TLS 1.3")
		}
		if state.NegotiatedProtocol != vnextOwnerTLSALPN {
			return fmt.Errorf(
				"VNext Owner TLS peer did not negotiate ALPN %q", vnextOwnerTLSALPN)
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("VNext Owner TLS client certificate was not verified")
		}
		_, err := vnextOwnerTLSCaller(state, allowedRoles)
		return err
	}
	return tlsConfig, nil
}

func vnextOwnerTLSCallerRole(
	state tls.ConnectionState,
	allowedRoles map[string]vnextOwnerCallerRole,
) (vnextOwnerCallerRole, error) {
	caller, err := vnextOwnerTLSCaller(state, allowedRoles)
	return caller.Role, err
}

func vnextOwnerTLSCaller(
	state tls.ConnectionState,
	allowedRoles map[string]vnextOwnerCallerRole,
) (vnextOwnerCallerContext, error) {
	if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return vnextOwnerCallerContext{},
			errors.New("VNext Owner TLS client certificate was not verified")
	}
	identities := state.PeerCertificates[0].URIs
	if len(identities) != 1 {
		return vnextOwnerCallerContext{}, fmt.Errorf(
			"VNext Owner TLS client certificate has %d URI SANs; exactly one is required",
			len(identities))
	}
	identity := identities[0].String()
	role, permitted := allowedRoles[identity]
	if !permitted {
		return vnextOwnerCallerContext{}, fmt.Errorf(
			"VNext Owner TLS client URI SAN %q is not assigned to an allowed role",
			identity)
	}
	caller := vnextOwnerCallerContext{Role: role, Principal: identity}
	if err := caller.validate(); err != nil {
		return vnextOwnerCallerContext{}, err
	}
	return caller, nil
}

func loadVNextOwnerTLSCertificatePool(path string, role string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read VNext Owner TLS %s: %w", role, err)
	}
	pool := x509.NewCertPool()
	if len(data) == 0 || !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("VNext Owner TLS %s contains no PEM certificates", role)
	}
	return pool, nil
}

func startVNextOwnerTLSServer(
	config vnextOwnerTLSServerConfig,
	rpc *vnextOwnerRPC,
	requestAdmission chan struct{},
	largeAdmission chan struct{},
) (*vnextOwnerTLSServer, error) {
	enabled, err := validateVNextOwnerTLSServerConfig(config, rpc)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	if requestAdmission == nil || largeAdmission == nil {
		return nil, errors.New("VNext Owner TLS admission controls are unavailable")
	}
	config = normalizedVNextOwnerTLSServerTimeouts(config)
	allowedClientRoles, err := vnextOwnerTLSAllowedClientRoles(config)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := newVNextOwnerTLSServerConfig(config)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return nil, fmt.Errorf(
			"listen for VNext Owner mTLS on %q: %w", config.ListenAddress, err)
	}
	server := &vnextOwnerTLSServer{
		listener:           listener,
		tlsConfig:          tlsConfig,
		rpc:                rpc,
		handshakeAdmission: make(chan struct{}, vnextOwnerTLSMaxHandshakes),
		requestAdmission:   requestAdmission,
		largeAdmission:     largeAdmission,
		handshakeTimeout:   config.HandshakeTimeout,
		readTimeout:        config.RequestReadTimeout,
		writeTimeout:       config.ResponseWriteTimeout,
		allowedClientRoles: allowedClientRoles,
	}
	server.wg.Add(1)
	go server.acceptLoop()
	return server, nil
}

func (server *vnextOwnerTLSServer) Addr() net.Addr {
	if server == nil || server.listener == nil {
		return nil
	}
	return server.listener.Addr()
}

func (server *vnextOwnerTLSServer) Stop() error {
	if server == nil {
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

func (server *vnextOwnerTLSServer) Wait() {
	if server != nil {
		server.wg.Wait()
	}
}

func (server *vnextOwnerTLSServer) Close() error {
	err := server.Stop()
	server.Wait()
	return err
}

func (server *vnextOwnerTLSServer) acceptLoop() {
	defer server.wg.Done()
	var retryDelay time.Duration
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if retryDelay == 0 {
				retryDelay = 5 * time.Millisecond
			} else {
				retryDelay *= 2
				if retryDelay > time.Second {
					retryDelay = time.Second
				}
			}
			time.Sleep(retryDelay)
			continue
		}
		retryDelay = 0
		// Unauthenticated peers are bounded separately. They cannot consume the
		// daemon request slots shared with trusted local Unix-socket callers.
		if !tryAcquireDaemonRequestAdmission(server.handshakeAdmission) {
			_ = conn.Close()
			continue
		}
		server.wg.Add(1)
		go func(rawConn net.Conn) {
			defer server.wg.Done()
			server.serveAccepted(rawConn)
		}(conn)
	}
}

func (server *vnextOwnerTLSServer) serveAccepted(rawConn net.Conn) {
	tlsConn := tls.Server(rawConn, server.tlsConfig)
	defer tlsConn.Close()
	handshakeAdmissionHeld := true
	defer func() {
		if handshakeAdmissionHeld {
			<-server.handshakeAdmission
		}
	}()
	handshakeContext, cancel := context.WithTimeout(
		context.Background(), server.handshakeTimeout)
	defer cancel()
	if err := tlsConn.SetDeadline(time.Now().Add(server.handshakeTimeout)); err != nil {
		return
	}
	// Client-chain verification and the exact URI SAN allowlist callback both
	// complete here. No frame header or body is read before this succeeds.
	if err := tlsConn.HandshakeContext(handshakeContext); err != nil {
		return
	}
	caller, err := vnextOwnerTLSCaller(
		tlsConn.ConnectionState(), server.allowedClientRoles)
	if err != nil {
		return
	}
	<-server.handshakeAdmission
	handshakeAdmissionHeld = false
	if !tryAcquireDaemonRequestAdmission(server.requestAdmission) {
		return
	}
	defer func() { <-server.requestAdmission }()
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return
	}
	serveAuthenticatedVNextOwnerTLSConn(
		tlsConn, server.rpc, caller, server.largeAdmission,
		server.readTimeout, server.writeTimeout)
}

func serveAuthenticatedVNextOwnerTLSConn(
	conn net.Conn,
	rpc *vnextOwnerRPC,
	caller vnextOwnerCallerContext,
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	body, releaseLarge, err := readDaemonRequestFrame(conn, largeAdmission, readTimeout)
	if err != nil {
		writeVNextOwnerTLSResponse(conn, execResponse{
			Ok:        false,
			Error:     fmt.Sprintf("invalid request frame: %v", err),
			ErrorCode: string(vnextOwnerServiceInvalidRequest),
		}, writeTimeout)
		return
	}
	defer releaseLarge()

	request, err := decodeVNextOwnerRemoteDaemonRequest(body)
	if err != nil {
		writeVNextOwnerTLSResponse(conn, execResponse{
			Ok:        false,
			Error:     fmt.Sprintf("invalid VNext Owner request: %v", err),
			ErrorCode: string(vnextOwnerServiceInvalidRequest),
		}, writeTimeout)
		return
	}
	writeVNextOwnerTLSResponse(
		conn, runCommandWithVNextOwnerRPCCaller(request, rpc, caller), writeTimeout)
}

func decodeVNextOwnerRemoteDaemonRequest(body []byte) (daemonRequest, error) {
	fields, vnext, object, err := inspectVNextOwnerRPCDaemonEnvelope(body)
	if err != nil {
		return daemonRequest{}, err
	}
	if !object || !vnext {
		return daemonRequest{}, errors.New(
			"remote TLS transport accepts only strict VNext Owner operations")
	}
	request, err := decodeVNextOwnerRPCDaemonEnvelope(fields)
	if err != nil {
		return daemonRequest{}, err
	}
	presentFields := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		presentFields[field.name] = struct{}{}
	}
	for _, name := range []string{"commandLabel", "timeoutMillis", "operation"} {
		if _, present := presentFields[name]; !present {
			return daemonRequest{}, fmt.Errorf(
				"remote VNext Owner request is missing required field %q", name)
		}
	}
	if request.Operation != strings.TrimSpace(request.Operation) {
		return daemonRequest{}, errors.New(
			"remote VNext Owner operation has surrounding whitespace")
	}
	if err := validateVNextOwnerClientText("remote command label", request.CommandLabel); err != nil {
		return daemonRequest{}, err
	}
	if _, err := vnextOwnerRPCPayload(request.Operation, request); err != nil {
		return daemonRequest{}, err
	}
	return request, nil
}

func writeVNextOwnerTLSResponse(
	conn net.Conn,
	response execResponse,
	writeTimeout time.Duration,
) {
	body, err := marshalVNextOwnerTLSExecResponse(response)
	if err != nil {
		body, _ = marshalVNextOwnerTLSExecResponse(execResponse{
			Ok:        false,
			Error:     "VNext Owner TLS response exceeds the bounded transport contract",
			ErrorCode: string(vnextOwnerServiceUnavailable),
		})
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_ = writeFrame(conn, body)
}

func marshalVNextOwnerTLSExecResponse(response execResponse) ([]byte, error) {
	wire := vnextOwnerTLSExecResponse{
		OK:             response.Ok,
		Stdout:         response.Stdout,
		Stderr:         response.Stderr,
		ExitCode:       response.ExitCode,
		Error:          response.Error,
		ErrorCode:      response.ErrorCode,
		Operation:      response.Operation,
		DurationMicros: response.DurationMicros,
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("encode VNext Owner TLS response: %w", err)
	}
	if len(body) == 0 || len(body) > maxDaemonFrameBytes {
		return nil, fmt.Errorf(
			"VNext Owner TLS response is %d bytes, allowed range is 1..%d",
			len(body), maxDaemonFrameBytes)
	}
	return body, nil
}

func decodeStrictVNextOwnerTLSExecResponse(body []byte) (execResponse, error) {
	if len(body) == 0 || len(body) > maxDaemonFrameBytes {
		return execResponse{}, fmt.Errorf(
			"VNext Owner TLS response is %d bytes, allowed range is 1..%d",
			len(body), maxDaemonFrameBytes)
	}
	var wire vnextOwnerTLSExecResponse
	if err := decodeStrictVNextOwnerRPC(body, &wire); err != nil {
		return execResponse{}, fmt.Errorf("decode strict VNext Owner TLS response: %w", err)
	}
	return execResponse{
		Ok:             wire.OK,
		Stdout:         wire.Stdout,
		Stderr:         wire.Stderr,
		ExitCode:       wire.ExitCode,
		Error:          wire.Error,
		ErrorCode:      wire.ErrorCode,
		Operation:      wire.Operation,
		DurationMicros: wire.DurationMicros,
	}, nil
}

func newVNextOwnerTLSRoundTripper(
	config vnextOwnerTLSClientConfig,
) (*vnextOwnerTLSRoundTripper, error) {
	config = normalizedVNextOwnerTLSClientTimeouts(config)
	if err := validateVNextOwnerTLSClientConfig(config); err != nil {
		return nil, err
	}
	certificate, err := tls.LoadX509KeyPair(
		config.ClientCertificatePath, config.ClientPrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load VNext Owner TLS client certificate/key: %w", err)
	}
	serverCAs, err := loadVNextOwnerTLSCertificatePool(config.ServerCAPath, "server CA")
	if err != nil {
		return nil, err
	}
	expectedServerURI := config.ExpectedServerURISAN
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ServerName:   config.ServerName,
		RootCAs:      serverCAs,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{vnextOwnerTLSALPN},
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if state.Version < tls.VersionTLS13 {
			return errors.New("VNext Owner server negotiated a protocol below TLS 1.3")
		}
		if state.NegotiatedProtocol != vnextOwnerTLSALPN {
			return fmt.Errorf(
				"VNext Owner server did not negotiate ALPN %q", vnextOwnerTLSALPN)
		}
		if len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
			return errors.New("VNext Owner TLS server certificate was not verified")
		}
		for _, identity := range state.PeerCertificates[0].URIs {
			if identity.String() == expectedServerURI {
				return nil
			}
		}
		return fmt.Errorf(
			"VNext Owner TLS server URI SAN does not contain %q", expectedServerURI)
	}
	return &vnextOwnerTLSRoundTripper{
		endpoint:         config.Endpoint,
		tlsConfig:        tlsConfig,
		dialTimeout:      config.DialTimeout,
		handshakeTimeout: config.HandshakeTimeout,
		writeTimeout:     config.RequestWriteTimeout,
		readTimeout:      config.ResponseReadTimeout,
		callerRole:       config.CallerRole,
	}, nil
}

func validateVNextOwnerTLSClientConfig(config vnextOwnerTLSClientConfig) error {
	for role, value := range map[string]string{
		"endpoint":           config.Endpoint,
		"server name":        config.ServerName,
		"client certificate": config.ClientCertificatePath,
		"client private key": config.ClientPrivateKeyPath,
		"server CA":          config.ServerCAPath,
		"server URI SAN":     config.ExpectedServerURISAN,
	} {
		if value == "" {
			return fmt.Errorf("VNext Owner TLS client %s is required", role)
		}
	}
	if err := validateVNextOwnerTLSEndpoint(config.Endpoint); err != nil {
		return err
	}
	if strings.TrimSpace(config.ServerName) != config.ServerName ||
		strings.IndexFunc(config.ServerName, unicode.IsControl) >= 0 {
		return errors.New("VNext Owner TLS server name has whitespace or a control character")
	}
	for role, path := range map[string]string{
		"client certificate": config.ClientCertificatePath,
		"client private key": config.ClientPrivateKeyPath,
		"server CA":          config.ServerCAPath,
	} {
		if err := validateVNextOwnerRuntimePath(path, role); err != nil {
			return err
		}
	}
	if err := validateVNextOwnerTLSURI(config.ExpectedServerURISAN, "server URI SAN"); err != nil {
		return err
	}
	if config.DialTimeout <= 0 || config.HandshakeTimeout <= 0 ||
		config.RequestWriteTimeout <= 0 || config.ResponseReadTimeout <= 0 {
		return errors.New("VNext Owner TLS client timeouts must be positive")
	}
	if config.CallerRole != vnextOwnerCallerScheduler &&
		config.CallerRole != vnextOwnerCallerProducer {
		return errors.New(
			"VNext Owner TLS client requires an explicit Scheduler or Producer role")
	}
	return nil
}

func (transport *vnextOwnerTLSRoundTripper) RoundTrip(
	ctx context.Context,
	request daemonRequest,
) (execResponse, error) {
	if transport == nil || transport.tlsConfig == nil {
		return execResponse{}, errors.New("VNext Owner TLS transport is unavailable")
	}
	if ctx == nil {
		return execResponse{}, errors.New("VNext Owner TLS transport context is nil")
	}
	if err := ctx.Err(); err != nil {
		return execResponse{}, err
	}
	if !isVNextOwnerRPCOperation(strings.TrimSpace(request.Operation)) {
		return execResponse{}, errors.New(
			"VNext Owner TLS transport accepts only strict VNext Owner operations")
	}
	if err := authorizeVNextOwnerOperation(
		transport.callerRole, strings.TrimSpace(request.Operation)); err != nil {
		return execResponse{}, err
	}
	if _, err := vnextOwnerRPCPayload(strings.TrimSpace(request.Operation), request); err != nil {
		return execResponse{}, fmt.Errorf("validate VNext Owner TLS request: %w", err)
	}
	if request.Operation != strings.TrimSpace(request.Operation) || request.TimeoutMillis != 0 {
		return execResponse{}, errors.New(
			"VNext Owner TLS request requires an exact operation and zero timeoutMillis")
	}
	if err := validateVNextOwnerClientText("command label", request.CommandLabel); err != nil {
		return execResponse{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return execResponse{}, fmt.Errorf("encode VNext Owner TLS request: %w", err)
	}
	if len(body) == 0 || len(body) > maxDaemonFrameBytes {
		return execResponse{}, fmt.Errorf(
			"VNext Owner TLS request is %d bytes, allowed range is 1..%d",
			len(body), maxDaemonFrameBytes)
	}

	dialer := net.Dialer{Timeout: transport.dialTimeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", transport.endpoint)
	if err != nil {
		if ctx.Err() != nil {
			return execResponse{}, ctx.Err()
		}
		return execResponse{}, fmt.Errorf("dial VNext Owner TLS endpoint: %w", err)
	}
	tlsConn := tls.Client(rawConn, transport.tlsConfig)
	defer tlsConn.Close()
	stopCancellationGuard := guardVNextOwnerTLSConnectionContext(ctx, tlsConn)
	defer stopCancellationGuard()

	handshakeContext, cancel := context.WithTimeout(ctx, transport.handshakeTimeout)
	if err := setVNextOwnerTLSDeadline(tlsConn, handshakeContext, transport.handshakeTimeout); err != nil {
		cancel()
		return execResponse{}, err
	}
	err = tlsConn.HandshakeContext(handshakeContext)
	handshakeContextErr := handshakeContext.Err()
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return execResponse{}, ctx.Err()
		}
		if handshakeContextErr != nil {
			return execResponse{}, handshakeContextErr
		}
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			return execResponse{}, context.DeadlineExceeded
		}
		return execResponse{}, fmt.Errorf("authenticate VNext Owner TLS peer: %w", err)
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		return execResponse{}, fmt.Errorf("clear VNext Owner TLS handshake deadline: %w", err)
	}

	if err := setVNextOwnerTLSWriteDeadline(tlsConn, ctx, transport.writeTimeout); err != nil {
		return execResponse{}, err
	}
	if err := writeFrame(tlsConn, body); err != nil {
		if ctx.Err() != nil {
			return execResponse{}, ctx.Err()
		}
		return execResponse{}, fmt.Errorf("write VNext Owner TLS request: %w", err)
	}
	if err := tlsConn.SetWriteDeadline(time.Time{}); err != nil {
		return execResponse{}, fmt.Errorf("clear VNext Owner TLS write deadline: %w", err)
	}

	if err := setVNextOwnerTLSReadDeadline(tlsConn, ctx, transport.readTimeout); err != nil {
		return execResponse{}, err
	}
	responseBody, err := readFrame(tlsConn)
	if err != nil {
		if ctx.Err() != nil {
			return execResponse{}, ctx.Err()
		}
		return execResponse{}, fmt.Errorf("read VNext Owner TLS response: %w", err)
	}
	response, err := decodeStrictVNextOwnerTLSExecResponse(responseBody)
	if err != nil {
		return execResponse{}, err
	}
	if response.Operation != strings.TrimSpace(request.Operation) {
		return execResponse{}, fmt.Errorf(
			"VNext Owner TLS response operation is %q, expected %q",
			response.Operation, strings.TrimSpace(request.Operation))
	}
	if response.DurationMicros < 0 {
		return execResponse{}, errors.New(
			"VNext Owner TLS response durationMicros cannot be negative")
	}
	if response.Ok {
		if response.Error != "" || response.ErrorCode != "" ||
			response.Stderr != "" || response.ExitCode != 0 || response.Stdout == "" {
			return execResponse{}, errors.New(
				"successful VNext Owner TLS response has inconsistent outer fields")
		}
	} else if response.Error == "" || response.ErrorCode == "" || response.Stdout != "" {
		return execResponse{}, errors.New(
			"failed VNext Owner TLS response has inconsistent outer fields")
	}
	return response, nil
}

func guardVNextOwnerTLSConnectionContext(ctx context.Context, conn net.Conn) func() {
	stopped := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.SetDeadline(time.Now())
		case <-stopped:
		}
	}()
	var once sync.Once
	return func() { once.Do(func() { close(stopped) }) }
}

func setVNextOwnerTLSDeadline(
	conn net.Conn,
	ctx context.Context,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set VNext Owner TLS deadline: %w", err)
	}
	return nil
}

func setVNextOwnerTLSWriteDeadline(
	conn net.Conn,
	ctx context.Context,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return fmt.Errorf("set VNext Owner TLS write deadline: %w", err)
	}
	return nil
}

func setVNextOwnerTLSReadDeadline(
	conn net.Conn,
	ctx context.Context,
	timeout time.Duration,
) error {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return fmt.Errorf("set VNext Owner TLS read deadline: %w", err)
	}
	return nil
}
