package main

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type vnextReaderPrepareRuntimeTestLeaderReader struct{}

func (*vnextReaderPrepareRuntimeTestLeaderReader) LinearizableGetExact(
	context.Context,
	string,
) (vnextOwnerSchedulerLeaderSnapshot, error) {
	return vnextOwnerSchedulerLeaderSnapshot{}, errors.New(
		"runtime test leader reads are not expected during construction")
}

type vnextReaderPrepareRuntimeTestEvents struct {
	mu     sync.Mutex
	values []string
}

func (events *vnextReaderPrepareRuntimeTestEvents) add(value string) {
	events.mu.Lock()
	events.values = append(events.values, value)
	events.mu.Unlock()
}

func (events *vnextReaderPrepareRuntimeTestEvents) snapshot() []string {
	events.mu.Lock()
	defer events.mu.Unlock()
	return append([]string(nil), events.values...)
}

type vnextReaderPrepareRuntimeTestServer struct {
	events      *vnextReaderPrepareRuntimeTestEvents
	stopErr     error
	waitStarted chan struct{}
	waitRelease <-chan struct{}
	startOnce   sync.Once
	stopCalls   int64
	waitCalls   int64
}

func (server *vnextReaderPrepareRuntimeTestServer) Stop() error {
	atomic.AddInt64(&server.stopCalls, 1)
	if server.events != nil {
		server.events.add("listener-stop")
	}
	return server.stopErr
}

func (server *vnextReaderPrepareRuntimeTestServer) Wait() {
	atomic.AddInt64(&server.waitCalls, 1)
	if server.events != nil {
		server.events.add("handler-wait")
	}
	if server.waitStarted != nil {
		server.startOnce.Do(func() { close(server.waitStarted) })
	}
	if server.waitRelease != nil {
		<-server.waitRelease
	}
}

func validVNextReaderPrepareRuntimeInput(
	t *testing.T,
) vnextReaderPrepareRuntimeInput {
	t.Helper()
	material := newVNextReaderPrepareTLSTestMaterial(t)
	return vnextReaderPrepareRuntimeInput{
		Enabled:                     "true",
		LocalExecutorNodeID:         "reader-node-0",
		LocalCxldInstanceID:         "reader-cxld-0",
		StoreMaxEntries:             "8",
		StoreMaxRetainedBytes:       "1048576",
		TLSListenAddress:            "127.0.0.1:0",
		TLSServerCertificatePath:    material.serverCertificatePath,
		TLSServerPrivateKeyPath:     material.serverPrivateKeyPath,
		TLSClientCAPath:             material.caPath,
		TLSExpectedServerURISAN:     vnextReaderPrepareTLSTestServerURI,
		PrincipalBindings:           vnextReaderPrepareTestPrincipal + "=scheduler-a",
		TLSHandshakeTimeoutMillis:   "1000",
		TLSRequestReadTimeoutMillis: "1000",
		TLSHandlerTimeoutMillis:     "1000",
		TLSResponseWriteMillis:      "1000",
		EtcdEndpoints:               "https://etcd.test:2379",
		EtcdLeaderKey:               vnextReaderPrepareCurrentTestLeaderKey,
		EtcdClusterID:               "8000000000000001",
		EtcdCAPath:                  material.caPath,
		EtcdClientCertificatePath:   material.clientCertificatePath,
		EtcdClientPrivateKeyPath:    material.clientPrivateKeyPath,
		EtcdDialTimeoutMillis:       "1000",
		EtcdReadTimeoutMillis:       "1000",
	}
}

func validVNextReaderPrepareRuntimeConfig(
	t *testing.T,
) vnextReaderPrepareRuntimeConfig {
	t.Helper()
	config, err := parseVNextReaderPrepareRuntimeInput(
		validVNextReaderPrepareRuntimeInput(t))
	if err != nil {
		t.Fatalf("parse valid VNext Reader PREPARE runtime input: %v", err)
	}
	return config
}

func vnextReaderPrepareRuntimeTestDependencies(
	events *vnextReaderPrepareRuntimeTestEvents,
	closeErr error,
) (vnextReaderPrepareRuntimeDependencies, *int64) {
	dependencies := defaultVNextReaderPrepareRuntimeDependencies()
	closeCalls := new(int64)
	dependencies.openLeaderReader = func(
		vnextOwnerSchedulerAuthorityConfig,
	) (vnextOwnerSchedulerLeaderReader, func() error, error) {
		return &vnextReaderPrepareRuntimeTestLeaderReader{}, func() error {
			atomic.AddInt64(closeCalls, 1)
			if events != nil {
				events.add("etcd-close")
			}
			return closeErr
		}, nil
	}
	return dependencies, closeCalls
}

func vnextReaderPrepareRuntimeTestAdmissions() (chan struct{}, chan struct{}) {
	return make(chan struct{}, daemonMaxConcurrentRequests),
		make(chan struct{}, daemonMaxConcurrentLargeBody)
}

func openVNextReaderPrepareRuntimeTest(
	config vnextReaderPrepareRuntimeConfig,
	dependencies vnextReaderPrepareRuntimeDependencies,
) (*vnextReaderPrepareRuntime, error) {
	requestAdmission, largeAdmission := vnextReaderPrepareRuntimeTestAdmissions()
	return openVNextReaderPrepareRuntimeWithDependencies(
		config, requestAdmission, largeAdmission, dependencies)
}

func TestVNextReaderPrepareRuntimeDisabledHasZeroSideEffects(t *testing.T) {
	input := vnextReaderPrepareRuntimeInput{
		Enabled:                  "false",
		LocalExecutorNodeID:      " intentionally ignored ",
		TLSServerCertificatePath: "SECRET-CONTENT-IS-NOT-A-PATH",
		EtcdEndpoints:            "not an endpoint",
	}
	config, err := parseVNextReaderPrepareRuntimeInput(input)
	if err != nil {
		t.Fatalf("disabled Reader PREPARE parse: %v", err)
	}
	if !reflect.DeepEqual(config, vnextReaderPrepareRuntimeConfig{}) {
		t.Fatalf("disabled Reader PREPARE retained configuration: %#v", config)
	}

	// Empty dependencies are intentional: the disabled path must return before
	// dependency validation or any constructor can run.
	runtime, err := openVNextReaderPrepareRuntimeWithDependencies(
		config, nil, nil, vnextReaderPrepareRuntimeDependencies{})
	if err != nil {
		t.Fatalf("open disabled Reader PREPARE runtime: %v", err)
	}
	if runtime != nil {
		t.Fatalf("disabled Reader PREPARE runtime = %#v, want nil", runtime)
	}
}

func TestVNextReaderPrepareRuntimeEnabledMissingFieldMatrix(t *testing.T) {
	input := validVNextReaderPrepareRuntimeInput(t)
	typeOfInput := reflect.TypeOf(input)
	for index := 0; index < typeOfInput.NumField(); index++ {
		field := typeOfInput.Field(index)
		if field.Name == "Enabled" {
			continue
		}
		t.Run(field.Name, func(t *testing.T) {
			mutated := input
			reflect.ValueOf(&mutated).Elem().FieldByName(field.Name).SetString("")
			if _, err := parseVNextReaderPrepareRuntimeInput(mutated); err == nil {
				t.Fatalf("enabled Reader PREPARE accepted missing %s", field.Name)
			}
		})
	}

	for _, enabled := range []string{"", "TRUE", " true", "1"} {
		t.Run("enabled-"+strings.ReplaceAll(enabled, " ", "space"), func(t *testing.T) {
			mutated := input
			mutated.Enabled = enabled
			if _, err := parseVNextReaderPrepareRuntimeInput(mutated); err == nil {
				t.Fatalf("Reader PREPARE accepted non-exact enabled value %q", enabled)
			}
		})
	}
}

func TestVNextReaderPrepareRuntimeRejectsNonCanonicalBoundsAndPrincipals(
	t *testing.T,
) {
	input := validVNextReaderPrepareRuntimeInput(t)
	mutations := map[string]func(*vnextReaderPrepareRuntimeInput){
		"leading-zero-store-capacity": func(value *vnextReaderPrepareRuntimeInput) {
			value.StoreMaxEntries = "08"
		},
		"zero-store-byte-budget": func(value *vnextReaderPrepareRuntimeInput) {
			value.StoreMaxRetainedBytes = "0"
		},
		"oversized-timeout": func(value *vnextReaderPrepareRuntimeInput) {
			value.TLSHandlerTimeoutMillis = "30001"
		},
		"duplicate-principal": func(value *vnextReaderPrepareRuntimeInput) {
			value.PrincipalBindings = vnextReaderPrepareTestPrincipal +
				"=scheduler-a," + vnextReaderPrepareTestPrincipal + "=scheduler-b"
		},
		"non-canonical-principal-order": func(value *vnextReaderPrepareRuntimeInput) {
			value.PrincipalBindings = "spiffe://test.example/scheduler/z=scheduler-z," +
				"spiffe://test.example/scheduler/a=scheduler-a"
		},
		"oversized-principal-count": func(value *vnextReaderPrepareRuntimeInput) {
			bindings := make([]string, vnextReaderPrepareAuthorityMaxPrincipals+1)
			for index := range bindings {
				bindings[index] = "spiffe://test.example/scheduler/" +
					strconv.Itoa(index) + "=scheduler-" + strconv.Itoa(index)
			}
			value.PrincipalBindings = strings.Join(bindings, ",")
		},
		"non-canonical-endpoint-list": func(value *vnextReaderPrepareRuntimeInput) {
			value.EtcdEndpoints = "https://etcd.test:2379, https://etcd-2.test:2379"
		},
		"duplicate-endpoint": func(value *vnextReaderPrepareRuntimeInput) {
			value.EtcdEndpoints = "https://etcd.test:2379,https://etcd.test:2379"
		},
		"oversized-endpoint-count": func(value *vnextReaderPrepareRuntimeInput) {
			endpoints := make([]string, vnextReaderPrepareRuntimeMaxEtcdEndpoints+1)
			for index := range endpoints {
				endpoints[index] = "https://etcd-" + strconv.Itoa(index) + ".test:2379"
			}
			value.EtcdEndpoints = strings.Join(endpoints, ",")
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := input
			mutate(&mutated)
			if _, err := parseVNextReaderPrepareRuntimeInput(mutated); err == nil {
				t.Fatalf("Reader PREPARE accepted %s", name)
			}
		})
	}

	ordered := input
	ordered.PrincipalBindings = "spiffe://test.example/scheduler/a=scheduler-a," +
		"spiffe://test.example/scheduler/z=scheduler-z"
	config, err := parseVNextReaderPrepareRuntimeInput(ordered)
	if err != nil || len(config.SchedulerByPrincipal) != 2 {
		t.Fatalf("canonical ordered principal bindings rejected: config=%#v err=%v",
			config.SchedulerByPrincipal, err)
	}
}

func TestVNextReaderPrepareRuntimeLeaderReaderPartialOpenAlwaysCloses(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	openErr := errors.New("test partial independent etcd open failure")
	closeErr := errors.New("test partial independent etcd close failure")
	for _, test := range []struct {
		name      string
		reader    vnextOwnerSchedulerLeaderReader
		openErr   error
		wantOpen  error
		wantClose error
	}{
		{
			name:      "reader-and-close-returned-with-error",
			reader:    &vnextReaderPrepareRuntimeTestLeaderReader{},
			openErr:   openErr,
			wantOpen:  openErr,
			wantClose: closeErr,
		},
		{
			name:      "nil-reader-returned-with-close",
			reader:    nil,
			openErr:   nil,
			wantClose: closeErr,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := defaultVNextReaderPrepareRuntimeDependencies()
			var closeCalls int64
			dependencies.openLeaderReader = func(
				vnextOwnerSchedulerAuthorityConfig,
			) (vnextOwnerSchedulerLeaderReader, func() error, error) {
				return test.reader, func() error {
					atomic.AddInt64(&closeCalls, 1)
					return closeErr
				}, test.openErr
			}
			dependencies.startServer = func(
				vnextReaderPrepareTLSServerConfig,
				vnextReaderPrepareTransportRPC,
				chan struct{},
				chan struct{},
			) (vnextReaderPrepareRuntimeServer, error) {
				t.Fatal("TLS listener opened after partial etcd construction")
				return nil, nil
			}
			runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
			if runtime != nil || err == nil {
				t.Fatalf("partial etcd open returned runtime=%#v err=%v", runtime, err)
			}
			if test.wantOpen != nil && !errors.Is(err, test.wantOpen) {
				t.Fatalf("partial etcd error %v lost open error %v", err, test.wantOpen)
			}
			if !errors.Is(err, test.wantClose) {
				t.Fatalf("partial etcd error %v lost close error %v", err, test.wantClose)
			}
			if got := atomic.LoadInt64(&closeCalls); got != 1 {
				t.Fatalf("partial etcd close calls = %d, want 1", got)
			}
		})
	}
}

func TestVNextReaderPrepareRuntimeValidatesBeforeOpeningResources(t *testing.T) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	config.LocalExecutorNodeID = ""
	var constructorCalls int64
	dependencies := defaultVNextReaderPrepareRuntimeDependencies()
	dependencies.newStore = func(
		vnextReaderAuthorizationStoreConfig,
	) (*vnextReaderAuthorizationStore, error) {
		atomic.AddInt64(&constructorCalls, 1)
		return nil, errors.New("must not be called")
	}
	if runtime, err := openVNextReaderPrepareRuntimeTest(
		config, dependencies); err == nil || runtime != nil {
		t.Fatalf("invalid enabled config returned runtime=%#v err=%v", runtime, err)
	}
	if got := atomic.LoadInt64(&constructorCalls); got != 0 {
		t.Fatalf("constructors called before complete validation: %d", got)
	}
}

func TestVNextReaderPrepareRuntimeRequiresDaemonWideAdmissionsBeforeResources(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	for _, test := range []struct {
		name             string
		requestAdmission chan struct{}
		largeAdmission   chan struct{}
	}{
		{
			name:             "nil-request-admission",
			requestAdmission: nil,
			largeAdmission:   make(chan struct{}, daemonMaxConcurrentLargeBody),
		},
		{
			name:             "different-request-budget",
			requestAdmission: make(chan struct{}, daemonMaxConcurrentRequests-1),
			largeAdmission:   make(chan struct{}, daemonMaxConcurrentLargeBody),
		},
		{
			name:             "nil-large-admission",
			requestAdmission: make(chan struct{}, daemonMaxConcurrentRequests),
			largeAdmission:   nil,
		},
		{
			name:             "different-large-budget",
			requestAdmission: make(chan struct{}, daemonMaxConcurrentRequests),
			largeAdmission:   make(chan struct{}, daemonMaxConcurrentLargeBody+1),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := defaultVNextReaderPrepareRuntimeDependencies()
			var constructorCalls int64
			dependencies.newStore = func(
				vnextReaderAuthorizationStoreConfig,
			) (*vnextReaderAuthorizationStore, error) {
				atomic.AddInt64(&constructorCalls, 1)
				return nil, errors.New("must not be called")
			}
			runtime, err := openVNextReaderPrepareRuntimeWithDependencies(
				config,
				test.requestAdmission,
				test.largeAdmission,
				dependencies)
			if runtime != nil || err == nil {
				t.Fatalf("invalid admission returned runtime=%#v err=%v", runtime, err)
			}
			if got := atomic.LoadInt64(&constructorCalls); got != 0 {
				t.Fatalf("constructors called before admission validation: %d", got)
			}
		})
	}
}

func TestVNextReaderPrepareRuntimeSharesOneCanonicalPrincipalBinding(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	wantBindings := map[string]string{
		vnextReaderPrepareTestPrincipal: "scheduler-a",
	}
	dependencies, _ := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
	defaultNewVerifier := dependencies.newVerifier
	var verifierConfig vnextReaderPrepareCurrentAuthorityConfig
	dependencies.newVerifier = func(
		config vnextReaderPrepareCurrentAuthorityConfig,
		reader vnextOwnerSchedulerLeaderReader,
	) (vnextReaderPrepareAuthorityVerifier, error) {
		verifierConfig = config
		return defaultNewVerifier(config, reader)
	}
	server := &vnextReaderPrepareRuntimeTestServer{}
	var tlsConfig vnextReaderPrepareTLSServerConfig
	dependencies.startServer = func(
		config vnextReaderPrepareTLSServerConfig,
		_ vnextReaderPrepareTransportRPC,
		_ chan struct{},
		_ chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		tlsConfig = config
		return server, nil
	}
	requestAdmission, largeAdmission := vnextReaderPrepareRuntimeTestAdmissions()
	runtime, err := openVNextReaderPrepareRuntimeWithDependencies(
		config, requestAdmission, largeAdmission, dependencies)
	if err != nil {
		t.Fatalf("open Reader PREPARE runtime: %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close() })

	currentVerifier, ok := runtime.verifier.(*vnextReaderPrepareCurrentAuthorityVerifier)
	if !ok {
		t.Fatalf("runtime verifier type = %T", runtime.verifier)
	}
	for name, bindings := range map[string]map[string]string{
		"runtime":           runtime.schedulerByPrincipal,
		"verifier-config":   verifierConfig.SchedulerByPrincipal,
		"verifier-retained": currentVerifier.schedulerByPrincipal,
		"TLS-config":        tlsConfig.SchedulerByPrincipal,
	} {
		if !reflect.DeepEqual(bindings, wantBindings) {
			t.Fatalf("%s principal bindings = %#v, want %#v", name, bindings, wantBindings)
		}
	}
	if runtime.requestAdmission != requestAdmission ||
		runtime.largeFrameAdmission != largeAdmission ||
		cap(runtime.requestAdmission) != daemonMaxConcurrentRequests ||
		cap(runtime.largeFrameAdmission) != daemonMaxConcurrentLargeBody {
		t.Fatalf("runtime did not retain the exact injected daemon admissions")
	}
	if runtime.service.localExecutorNodeID != config.LocalExecutorNodeID ||
		runtime.service.localCxldInstanceID != config.LocalCxldInstanceID ||
		tlsConfig.ExpectedServerURISAN != config.TLS.ExpectedServerURISAN {
		t.Fatal("runtime did not retain the exact trusted local IDs and server URI SAN")
	}

	// The caller cannot mutate either security boundary after construction.
	config.SchedulerByPrincipal[vnextReaderPrepareTestPrincipal] = "scheduler-mutated"
	config.SchedulerAuthority.Endpoints[0] = "https://mutated.test:2379"
	if !reflect.DeepEqual(runtime.schedulerByPrincipal, wantBindings) ||
		!reflect.DeepEqual(currentVerifier.schedulerByPrincipal, wantBindings) {
		t.Fatal("runtime retained aliases into caller-owned principal configuration")
	}
}

func TestVNextReaderPrepareRuntimePartialConstructionCleansUpInReverseOrder(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	startErr := errors.New("test TLS start failure")
	stopErr := errors.New("test partial listener stop failure")
	etcdErr := errors.New("test independent etcd close failure")
	events := &vnextReaderPrepareRuntimeTestEvents{}
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(
		events, etcdErr)
	server := &vnextReaderPrepareRuntimeTestServer{
		events: events, stopErr: stopErr,
	}
	dependencies.startServer = func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		chan struct{},
		chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		return server, startErr
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil {
		t.Fatalf("partial construction returned runtime %#v", runtime)
	}
	for _, target := range []error{startErr, stopErr, etcdErr} {
		if !errors.Is(err, target) {
			t.Fatalf("partial construction error %v lost %v", err, target)
		}
	}
	wantEvents := []string{"listener-stop", "handler-wait", "etcd-close"}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("partial cleanup order = %v, want %v", got, wantEvents)
	}
	if atomic.LoadInt64(&server.stopCalls) != 1 ||
		atomic.LoadInt64(&server.waitCalls) != 1 ||
		atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("partial cleanup calls stop=%d wait=%d etcd=%d, want 1 each",
			atomic.LoadInt64(&server.stopCalls),
			atomic.LoadInt64(&server.waitCalls), atomic.LoadInt64(closeCalls))
	}
}

func TestVNextReaderPrepareRuntimeVerifierFailureClosesOnlyOpenedEtcd(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	events := &vnextReaderPrepareRuntimeTestEvents{}
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(events, nil)
	verifierErr := errors.New("test verifier construction failure")
	dependencies.newVerifier = func(
		vnextReaderPrepareCurrentAuthorityConfig,
		vnextOwnerSchedulerLeaderReader,
	) (vnextReaderPrepareAuthorityVerifier, error) {
		return nil, verifierErr
	}
	dependencies.startServer = func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		chan struct{},
		chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		t.Fatal("TLS server started after verifier construction failed")
		return nil, nil
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil || !errors.Is(err, verifierErr) {
		t.Fatalf("verifier failure returned runtime=%#v err=%v", runtime, err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got, []string{"etcd-close"}) ||
		atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("verifier failure cleanup events=%v closeCalls=%d",
			got, atomic.LoadInt64(closeCalls))
	}
}

func TestVNextReaderPrepareRuntimeShutdownDrainsBeforeEtcdClose(t *testing.T) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	events := &vnextReaderPrepareRuntimeTestEvents{}
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(events, nil)
	waitStarted := make(chan struct{})
	waitRelease := make(chan struct{})
	server := &vnextReaderPrepareRuntimeTestServer{
		events: events, waitStarted: waitStarted, waitRelease: waitRelease,
	}
	dependencies.startServer = func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		chan struct{},
		chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		return server, nil
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if err != nil {
		t.Fatalf("open Reader PREPARE runtime: %v", err)
	}
	if err := runtime.Stop(); err != nil {
		t.Fatalf("stop Reader PREPARE listener: %v", err)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- runtime.Close() }()
	select {
	case <-waitStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime Close did not enter actual handler Wait")
	}
	if atomic.LoadInt64(closeCalls) != 0 {
		t.Fatal("independent etcd reader closed while a handler was draining")
	}
	if got := events.snapshot(); !reflect.DeepEqual(
		got, []string{"listener-stop", "handler-wait"}) {
		t.Fatalf("pre-drain shutdown order = %v", got)
	}
	close(waitRelease)
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("close Reader PREPARE runtime: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime Close did not finish after handler drain")
	}
	wantEvents := []string{"listener-stop", "handler-wait", "etcd-close"}
	if got := events.snapshot(); !reflect.DeepEqual(got, wantEvents) {
		t.Fatalf("shutdown order = %v, want %v", got, wantEvents)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if atomic.LoadInt64(&server.stopCalls) != 1 ||
		atomic.LoadInt64(&server.waitCalls) != 1 ||
		atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("idempotent cleanup calls stop=%d wait=%d etcd=%d",
			atomic.LoadInt64(&server.stopCalls),
			atomic.LoadInt64(&server.waitCalls), atomic.LoadInt64(closeCalls))
	}
}

func TestVNextReaderPrepareRuntimeStartsRealMTLSListener(t *testing.T) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if err != nil {
		t.Fatalf("start production Reader PREPARE mTLS listener: %v", err)
	}
	server, ok := runtime.server.(*vnextReaderPrepareTLSServer)
	if !ok || server.Addr() == nil {
		_ = runtime.Close()
		t.Fatalf("production Reader PREPARE server = %T, addr=%v",
			runtime.server, server)
	}
	if runtime.store == nil || runtime.service == nil || runtime.rpc == nil ||
		runtime.verifier == nil {
		_ = runtime.Close()
		t.Fatal("successful startup omitted a required Reader component")
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close production Reader PREPARE listener: %v", err)
	}
	if atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("successful runtime etcd close calls = %d, want 1",
			atomic.LoadInt64(closeCalls))
	}
}

func TestVNextReaderPrepareRuntimeRejectsCertificateOutsideTrustedServerURI(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	config.TLS.ExpectedServerURISAN = "spiffe://test.example/cxld/different-reader"
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil || err == nil {
		t.Fatalf("server URI mismatch returned runtime=%#v err=%v", runtime, err)
	}
	if !strings.Contains(err.Error(), "differs from configured") {
		t.Fatalf("server URI mismatch error = %v", err)
	}
	if atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("server URI mismatch etcd close calls = %d, want 1",
			atomic.LoadInt64(closeCalls))
	}
}

func TestVNextReaderPrepareRuntimeErrorsDoNotExposeSecretFileContents(t *testing.T) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	secret := "SUPER-SECRET-PRIVATE-MATERIAL"
	invalidCertificatePath := t.TempDir() + "/invalid-server.pem"
	if err := os.WriteFile(invalidCertificatePath, []byte(secret), 0o600); err != nil {
		t.Fatalf("write invalid test certificate: %v", err)
	}
	config.TLS.ServerCertificatePath = invalidCertificatePath
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil || err == nil {
		t.Fatalf("invalid TLS material returned runtime=%#v err=%v", runtime, err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("Reader PREPARE startup error exposed secret file contents: %v", err)
	}
	if atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("TLS material failure etcd close calls = %d, want 1",
			atomic.LoadInt64(closeCalls))
	}
}
