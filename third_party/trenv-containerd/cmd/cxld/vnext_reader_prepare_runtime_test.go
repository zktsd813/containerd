package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
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

type vnextReaderPrepareRuntimeTestIncarnationPublisher struct {
	publish func(string, vnextReaderProcessIncarnation) error
}

type vnextReaderPrepareRuntimeTestIncarnationLock struct {
	remove  func(vnextReaderProcessIncarnation, bool) error
	release func() error
}

func (lock *vnextReaderPrepareRuntimeTestIncarnationLock) RemovePublishedIdentity(
	incarnation vnextReaderProcessIncarnation,
	requireExact bool,
) error {
	if lock.remove != nil {
		return lock.remove(incarnation, requireExact)
	}
	return nil
}

func (lock *vnextReaderPrepareRuntimeTestIncarnationLock) Release() error {
	if lock.release != nil {
		return lock.release()
	}
	return nil
}

type vnextReaderPrepareRuntimeTestIncarnationLocker struct {
	acquire func(string) (vnextReaderProcessIncarnationLock, error)
}

func (locker *vnextReaderPrepareRuntimeTestIncarnationLocker) Acquire(
	path string,
) (vnextReaderProcessIncarnationLock, error) {
	if locker.acquire != nil {
		return locker.acquire(path)
	}
	return &vnextReaderPrepareRuntimeTestIncarnationLock{}, nil
}

func (publisher *vnextReaderPrepareRuntimeTestIncarnationPublisher) Publish(
	path string,
	incarnation vnextReaderProcessIncarnation,
) error {
	if publisher.publish != nil {
		return publisher.publish(path, incarnation)
	}
	return nil
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
		Enabled:                         "true",
		LocalExecutorNodeID:             "reader-node-0",
		LocalCxldLogicalID:              "reader-cxld-0",
		StoreMaxEntries:                 "8",
		StoreMaxRetainedBytes:           "1048576",
		ActivationStoreMaxEntries:       "8",
		ActivationStoreMaxRetainedBytes: "1048576",
		TLSListenAddress:                "127.0.0.1:0",
		TLSServerCertificatePath:        material.serverCertificatePath,
		TLSServerPrivateKeyPath:         material.serverPrivateKeyPath,
		TLSClientCAPath:                 material.caPath,
		TLSExpectedServerURISAN:         vnextReaderPrepareTLSTestServerURI,
		PrincipalBindings:               vnextReaderPrepareTestPrincipal + "=scheduler-a",
		TLSHandshakeTimeoutMillis:       "1000",
		TLSRequestReadTimeoutMillis:     "1000",
		TLSHandlerTimeoutMillis:         "1000",
		TLSResponseWriteMillis:          "1000",
		EtcdEndpoints:                   "https://etcd.test:2379",
		EtcdLeaderKey:                   vnextReaderPrepareCurrentTestLeaderKey,
		EtcdClusterID:                   "8000000000000001",
		EtcdCAPath:                      material.caPath,
		EtcdClientCertificatePath:       material.clientCertificatePath,
		EtcdClientPrivateKeyPath:        material.clientPrivateKeyPath,
		EtcdDialTimeoutMillis:           "1000",
		EtcdReadTimeoutMillis:           "1000",
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
	dependencies.processIncarnationPath = "/test/process-incarnation"
	dependencies.processIncarnationWriter =
		&vnextReaderPrepareRuntimeTestIncarnationPublisher{}
	dependencies.processIncarnationLocker =
		&vnextReaderPrepareRuntimeTestIncarnationLocker{}
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
		Enabled:                         "false",
		LocalExecutorNodeID:             " intentionally ignored ",
		ActivationStoreMaxEntries:       "not-a-number",
		ActivationStoreMaxRetainedBytes: "also-ignored",
		TLSServerCertificatePath:        "SECRET-CONTENT-IS-NOT-A-PATH",
		EtcdEndpoints:                   "not an endpoint",
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

func TestVNextReaderPrepareAndStatusRuntimeDependenciesAreAllOrNothing(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	tests := map[string]func(*vnextReaderPrepareRuntimeDependencies){
		"entropy": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.entropy = nil
		},
		"process-incarnation path": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.processIncarnationPath = ""
		},
		"process-incarnation publisher": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.processIncarnationWriter = nil
		},
		"process-incarnation locker": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.processIncarnationLocker = nil
		},
		"store": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newStore = nil
		},
		"activation store": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newActivationStore = nil
		},
		"leader reader": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.openLeaderReader = nil
		},
		"PREPARE verifier": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newVerifier = nil
		},
		"STATUS verifier": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newStatusVerifier = nil
		},
		"IDENTIFY verifier": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newIdentifyVerifier = nil
		},
		"activation verifier": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newActivationVerifier = nil
		},
		"PREPARE service": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newService = nil
		},
		"STATUS service": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newStatusService = nil
		},
		"IDENTIFY service": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newIdentifyService = nil
		},
		"activation service": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newActivationService = nil
		},
		"PREPARE RPC": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newRPC = nil
		},
		"STATUS RPC": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newStatusRPC = nil
		},
		"IDENTIFY RPC": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newIdentifyRPC = nil
		},
		"activation proposal RPC": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newActivationProposalRPC = nil
		},
		"activation commit RPC": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newActivationCommitRPC = nil
		},
		"activation status RPC": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.newActivationStatusRPC = nil
		},
		"dual listener": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.startServer = nil
		},
		"clock": func(value *vnextReaderPrepareRuntimeDependencies) {
			value.clock = nil
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			dependencies := defaultVNextReaderPrepareRuntimeDependencies()
			mutate(&dependencies)
			requestAdmission, largeAdmission :=
				vnextReaderPrepareRuntimeTestAdmissions()
			runtime, err := openVNextReaderPrepareRuntimeWithDependencies(
				config, requestAdmission, largeAdmission, dependencies)
			if runtime != nil || err == nil ||
				!strings.Contains(err.Error(), "dependencies are incomplete") {
				t.Fatalf("missing %s returned runtime=%#v err=%v",
					name, runtime, err)
			}
		})
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
		"leading-zero-activation-store-capacity": func(value *vnextReaderPrepareRuntimeInput) {
			value.ActivationStoreMaxEntries = "08"
		},
		"zero-activation-store-byte-budget": func(value *vnextReaderPrepareRuntimeInput) {
			value.ActivationStoreMaxRetainedBytes = "0"
		},
		"oversized-activation-store-capacity": func(value *vnextReaderPrepareRuntimeInput) {
			value.ActivationStoreMaxEntries = strconv.FormatUint(
				uint64(vnextReaderActivationStoreMaxEntries)+1, 10)
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
			dependencies.processIncarnationPath = "/test/process-incarnation"
			dependencies.processIncarnationLocker =
				&vnextReaderPrepareRuntimeTestIncarnationLocker{}
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
				vnextReaderPreparedStatusTransportRPC,
				vnextReaderIdentifyTransportRPC,
				vnextReaderActivationTransportRPC,
				vnextReaderActivationTransportRPC,
				vnextReaderActivationTransportRPC,
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

func TestVNextReaderPrepareRuntimeActivationStoreFailurePreventsAuthorityOpen(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	dependencies, _ := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
	storeErr := errors.New("test activation store construction failure")
	dependencies.newActivationStore = func(
		vnextReaderActivationStoreConfig,
		string,
		string,
		vnextReaderProcessIncarnation,
		vnextReaderActivationPreparedStore,
	) (*vnextReaderActivationStore, error) {
		return nil, storeErr
	}
	dependencies.openLeaderReader = func(
		vnextOwnerSchedulerAuthorityConfig,
	) (vnextOwnerSchedulerLeaderReader, func() error, error) {
		t.Fatal("activation store failure reached independent authority open")
		return nil, nil, nil
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil || !errors.Is(err, storeErr) {
		t.Fatalf("activation store failure returned runtime=%#v err=%v",
			runtime, err)
	}
}

func TestVNextReaderPrepareRuntimeEntropyFailureAndZeroOpenNothing(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	for name, entropy := range map[string]io.Reader{
		"failure": vnextReaderProcessIncarnationErrorReader{
			err: errors.New("test runtime entropy failure")},
		"zero": bytes.NewReader(make([]byte,
			vnextReaderProcessIncarnationBytes)),
	} {
		t.Run(name, func(t *testing.T) {
			dependencies, _ := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
			dependencies.entropy = entropy
			var lockAcquireCalls int64
			var lockReleaseCalls int64
			dependencies.processIncarnationLocker =
				&vnextReaderPrepareRuntimeTestIncarnationLocker{
					acquire: func(string) (vnextReaderProcessIncarnationLock, error) {
						atomic.AddInt64(&lockAcquireCalls, 1)
						return &vnextReaderPrepareRuntimeTestIncarnationLock{
							release: func() error {
								atomic.AddInt64(&lockReleaseCalls, 1)
								return nil
							},
						}, nil
					},
				}
			var resourceCalls int64
			dependencies.newStore = func(
				vnextReaderAuthorizationStoreConfig,
			) (*vnextReaderAuthorizationStore, error) {
				atomic.AddInt64(&resourceCalls, 1)
				return nil, errors.New("must not open")
			}
			dependencies.processIncarnationWriter =
				&vnextReaderPrepareRuntimeTestIncarnationPublisher{
					publish: func(string, vnextReaderProcessIncarnation) error {
						atomic.AddInt64(&resourceCalls, 1)
						return nil
					},
				}
			runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
			if runtime != nil || err == nil {
				t.Fatalf("entropy %s returned runtime=%#v err=%v", name, runtime, err)
			}
			if atomic.LoadInt64(&resourceCalls) != 0 {
				t.Fatalf("entropy %s opened %d resources", name, resourceCalls)
			}
			if atomic.LoadInt64(&lockAcquireCalls) != 1 ||
				atomic.LoadInt64(&lockReleaseCalls) != 1 {
				t.Fatalf("entropy %s lock acquire/release=%d/%d, want 1/1",
					name, lockAcquireCalls, lockReleaseCalls)
			}
		})
	}
}

func TestVNextReaderPrepareRuntimePublishesIdentityBeforeListener(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	events := &vnextReaderPrepareRuntimeTestEvents{}
	dependencies, _ := vnextReaderPrepareRuntimeTestDependencies(events, nil)
	want := vnextReaderProcessIncarnationForTest(0x61)
	dependencies.entropy = bytes.NewReader(want[:])
	var published vnextReaderProcessIncarnation
	dependencies.processIncarnationWriter =
		&vnextReaderPrepareRuntimeTestIncarnationPublisher{
			publish: func(path string, incarnation vnextReaderProcessIncarnation) error {
				if path != dependencies.processIncarnationPath {
					t.Fatalf("publish path = %q", path)
				}
				published = incarnation
				events.add("incarnation-publish")
				return nil
			},
		}
	server := &vnextReaderPrepareRuntimeTestServer{events: events}
	dependencies.startServer = func(
		_ vnextReaderPrepareTLSServerConfig,
		_ vnextReaderPrepareTransportRPC,
		_ vnextReaderPreparedStatusTransportRPC,
		identifyRPC vnextReaderIdentifyTransportRPC,
		_ vnextReaderActivationTransportRPC,
		_ vnextReaderActivationTransportRPC,
		_ vnextReaderActivationTransportRPC,
		_ chan struct{},
		_ chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		if got := events.snapshot(); !reflect.DeepEqual(
			got, []string{"incarnation-publish"}) {
			t.Fatalf("listener started before identity publication: %v", got)
		}
		concrete, ok := identifyRPC.(*vnextReaderIdentifyRPC)
		if !ok || concrete.service.processIncarnation != want {
			t.Fatalf("listener IDENTIFY RPC has process incarnation %#v", identifyRPC)
		}
		events.add("listener-open")
		return server, nil
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if err != nil {
		t.Fatalf("open runtime with ordered identity publication: %v", err)
	}
	if published != want || runtime.processIncarnation != want ||
		runtime.identifyService.processIncarnation != want ||
		runtime.service.processIncarnation != want ||
		runtime.statusService.processIncarnation != want {
		_ = runtime.Close()
		t.Fatal("runtime components did not share the one generated incarnation")
	}
	if got := events.snapshot(); !reflect.DeepEqual(
		got, []string{"incarnation-publish", "listener-open"}) {
		_ = runtime.Close()
		t.Fatalf("startup order = %v", got)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}
}

func TestVNextReaderPrepareRuntimePublicationFailureNeverOpensListener(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	events := &vnextReaderPrepareRuntimeTestEvents{}
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(
		events, nil)
	publishErr := errors.New("test process-incarnation publication failure")
	dependencies.processIncarnationWriter =
		&vnextReaderPrepareRuntimeTestIncarnationPublisher{
			publish: func(string, vnextReaderProcessIncarnation) error {
				events.add("incarnation-publish-fail")
				return publishErr
			},
		}
	dependencies.startServer = func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		vnextReaderPreparedStatusTransportRPC,
		vnextReaderIdentifyTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		chan struct{},
		chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		t.Fatal("listener opened after process-incarnation publication failed")
		return nil, nil
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil || !errors.Is(err, publishErr) {
		t.Fatalf("publication failure returned runtime=%#v err=%v", runtime, err)
	}
	if got := events.snapshot(); !reflect.DeepEqual(got,
		[]string{"incarnation-publish-fail", "etcd-close"}) {
		t.Fatalf("publication failure cleanup order = %v", got)
	}
	if atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("publication failure etcd close calls = %d", *closeCalls)
	}
}

func TestVNextReaderPrepareRuntimeListenerFailureRemovesPublishedIdentityAndUnlocks(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	directory := vnextReaderProcessIncarnationSecureTestDir(t)
	path := filepath.Join(directory, "process-incarnation")
	want := vnextReaderProcessIncarnationForTest(0x81)
	dependencies, closeCalls := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
	dependencies.entropy = bytes.NewReader(want[:])
	dependencies.processIncarnationPath = path
	dependencies.processIncarnationWriter =
		&vnextReaderProcessIncarnationFilePublisher{}
	dependencies.processIncarnationLocker =
		&vnextReaderProcessIncarnationFileLockAcquirer{}
	startErr := errors.New("test post-publication listener failure")
	dependencies.startServer = func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		vnextReaderPreparedStatusTransportRPC,
		vnextReaderIdentifyTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		chan struct{},
		chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		assertVNextReaderProcessIncarnationFile(t, path, want)
		return nil, startErr
	}
	runtime, err := openVNextReaderPrepareRuntimeTest(config, dependencies)
	if runtime != nil || !errors.Is(err, startErr) {
		t.Fatalf("listener failure returned runtime=%#v err=%v", runtime, err)
	}
	if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("listener failure left published process incarnation: %v", statErr)
	}
	if atomic.LoadInt64(closeCalls) != 1 {
		t.Fatalf("listener failure etcd close calls = %d", *closeCalls)
	}
	lock, lockErr := (&vnextReaderProcessIncarnationFileLockAcquirer{}).Acquire(path)
	if lockErr != nil {
		t.Fatalf("listener failure left process lock held: %v", lockErr)
	}
	if err := lock.Release(); err != nil {
		t.Fatalf("release post-failure lock: %v", err)
	}
}

func TestVNextReaderPrepareRuntimeLockSerializesStartsThroughGracefulClose(
	t *testing.T,
) {
	config := validVNextReaderPrepareRuntimeConfig(t)
	directory := vnextReaderProcessIncarnationSecureTestDir(t)
	path := filepath.Join(directory, "process-incarnation")
	firstID := vnextReaderProcessIncarnationForTest(0x91)
	secondID := vnextReaderProcessIncarnationForTest(0x92)
	newDependencies := func(
		entropy io.Reader,
	) vnextReaderPrepareRuntimeDependencies {
		dependencies, _ := vnextReaderPrepareRuntimeTestDependencies(nil, nil)
		dependencies.entropy = entropy
		dependencies.processIncarnationPath = path
		dependencies.processIncarnationWriter =
			&vnextReaderProcessIncarnationFilePublisher{}
		dependencies.processIncarnationLocker =
			&vnextReaderProcessIncarnationFileLockAcquirer{}
		dependencies.startServer = func(
			vnextReaderPrepareTLSServerConfig,
			vnextReaderPrepareTransportRPC,
			vnextReaderPreparedStatusTransportRPC,
			vnextReaderIdentifyTransportRPC,
			vnextReaderActivationTransportRPC,
			vnextReaderActivationTransportRPC,
			vnextReaderActivationTransportRPC,
			chan struct{},
			chan struct{},
		) (vnextReaderPrepareRuntimeServer, error) {
			return &vnextReaderPrepareRuntimeTestServer{}, nil
		}
		return dependencies
	}
	first, err := openVNextReaderPrepareRuntimeTest(
		config, newDependencies(bytes.NewReader(firstID[:])))
	if err != nil {
		t.Fatalf("open first locked Reader runtime: %v", err)
	}
	assertVNextReaderProcessIncarnationFile(t, path, firstID)
	blocked, err := openVNextReaderPrepareRuntimeTest(
		config,
		newDependencies(vnextReaderProcessIncarnationErrorReader{
			err: errors.New("entropy must not be read while lock is held")}))
	if blocked != nil ||
		!errors.Is(err, errVNextReaderProcessIncarnationLockHeld) {
		_ = first.Close()
		t.Fatalf("concurrent start returned runtime=%#v err=%v", blocked, err)
	}
	assertVNextReaderProcessIncarnationFile(t, path, firstID)
	if err := first.Close(); err != nil {
		t.Fatalf("close first locked Reader runtime: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("graceful Close left stale process incarnation: %v", err)
	}
	second, err := openVNextReaderPrepareRuntimeTest(
		config, newDependencies(bytes.NewReader(secondID[:])))
	if err != nil {
		t.Fatalf("open Reader runtime after first Close: %v", err)
	}
	assertVNextReaderProcessIncarnationFile(t, path, secondID)
	if err := second.Close(); err != nil {
		t.Fatalf("close second locked Reader runtime: %v", err)
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
	defaultNewActivationStore := dependencies.newActivationStore
	defaultNewVerifier := dependencies.newVerifier
	defaultNewStatusVerifier := dependencies.newStatusVerifier
	defaultNewIdentifyVerifier := dependencies.newIdentifyVerifier
	defaultNewActivationVerifier := dependencies.newActivationVerifier
	var verifierConfig vnextReaderPrepareCurrentAuthorityConfig
	var statusVerifierConfig vnextReaderPreparedStatusCurrentAuthorityConfig
	var identifyVerifierConfig vnextReaderIdentifyCurrentAuthorityConfig
	var activationVerifierConfig vnextReaderActivationCurrentAuthorityConfig
	var activationStoreConfig vnextReaderActivationStoreConfig
	var activationStoreExecutor string
	var activationStoreLogical string
	var activationStoreProcess vnextReaderProcessIncarnation
	var activationPreparedStore vnextReaderActivationPreparedStore
	dependencies.newActivationStore = func(
		config vnextReaderActivationStoreConfig,
		executor string,
		logical string,
		process vnextReaderProcessIncarnation,
		prepared vnextReaderActivationPreparedStore,
	) (*vnextReaderActivationStore, error) {
		activationStoreConfig = config
		activationStoreExecutor = executor
		activationStoreLogical = logical
		activationStoreProcess = process
		activationPreparedStore = prepared
		return defaultNewActivationStore(
			config, executor, logical, process, prepared)
	}
	dependencies.newVerifier = func(
		config vnextReaderPrepareCurrentAuthorityConfig,
		reader vnextOwnerSchedulerLeaderReader,
	) (vnextReaderPrepareAuthorityVerifier, error) {
		verifierConfig = config
		return defaultNewVerifier(config, reader)
	}
	dependencies.newStatusVerifier = func(
		config vnextReaderPreparedStatusCurrentAuthorityConfig,
		reader vnextOwnerSchedulerLeaderReader,
	) (vnextReaderPreparedStatusAuthorityVerifier, error) {
		statusVerifierConfig = config
		return defaultNewStatusVerifier(config, reader)
	}
	dependencies.newIdentifyVerifier = func(
		config vnextReaderIdentifyCurrentAuthorityConfig,
		reader vnextOwnerSchedulerLeaderReader,
	) (vnextReaderIdentifyAuthorityVerifier, error) {
		identifyVerifierConfig = config
		return defaultNewIdentifyVerifier(config, reader)
	}
	dependencies.newActivationVerifier = func(
		config vnextReaderActivationCurrentAuthorityConfig,
		reader vnextOwnerSchedulerLeaderReader,
	) (vnextReaderActivationAuthorityVerifier, error) {
		activationVerifierConfig = config
		return defaultNewActivationVerifier(config, reader)
	}
	server := &vnextReaderPrepareRuntimeTestServer{}
	var tlsConfig vnextReaderPrepareTLSServerConfig
	var passedPrepareRPC vnextReaderPrepareTransportRPC
	var passedStatusRPC vnextReaderPreparedStatusTransportRPC
	var passedIdentifyRPC vnextReaderIdentifyTransportRPC
	var passedActivationProposalRPC vnextReaderActivationTransportRPC
	var passedActivationCommitRPC vnextReaderActivationTransportRPC
	var passedActivationStatusRPC vnextReaderActivationTransportRPC
	dependencies.startServer = func(
		config vnextReaderPrepareTLSServerConfig,
		prepareRPC vnextReaderPrepareTransportRPC,
		statusRPC vnextReaderPreparedStatusTransportRPC,
		identifyRPC vnextReaderIdentifyTransportRPC,
		activationProposalRPC vnextReaderActivationTransportRPC,
		activationCommitRPC vnextReaderActivationTransportRPC,
		activationStatusRPC vnextReaderActivationTransportRPC,
		_ chan struct{},
		_ chan struct{},
	) (vnextReaderPrepareRuntimeServer, error) {
		tlsConfig = config
		passedPrepareRPC = prepareRPC
		passedStatusRPC = statusRPC
		passedIdentifyRPC = identifyRPC
		passedActivationProposalRPC = activationProposalRPC
		passedActivationCommitRPC = activationCommitRPC
		passedActivationStatusRPC = activationStatusRPC
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
	currentStatusVerifier, ok := runtime.statusVerifier.(*vnextReaderPreparedStatusCurrentAuthorityVerifier)
	if !ok {
		t.Fatalf("runtime status verifier type = %T", runtime.statusVerifier)
	}
	currentIdentifyVerifier, ok := runtime.identifyVerifier.(*vnextReaderIdentifyCurrentAuthorityVerifier)
	if !ok {
		t.Fatalf("runtime IDENTIFY verifier type = %T", runtime.identifyVerifier)
	}
	currentActivationVerifier, ok := runtime.activationVerifier.(*vnextReaderActivationCurrentAuthorityVerifier)
	if !ok {
		t.Fatalf("runtime activation verifier type = %T", runtime.activationVerifier)
	}
	for name, bindings := range map[string]map[string]string{
		"runtime":             runtime.schedulerByPrincipal,
		"verifier-config":     verifierConfig.SchedulerByPrincipal,
		"verifier-retained":   currentVerifier.schedulerByPrincipal,
		"status-config":       statusVerifierConfig.SchedulerByPrincipal,
		"status-retained":     currentStatusVerifier.schedulerByPrincipal,
		"identify-config":     identifyVerifierConfig.SchedulerByPrincipal,
		"identify-retained":   currentIdentifyVerifier.schedulerByPrincipal,
		"activation-config":   activationVerifierConfig.SchedulerByPrincipal,
		"activation-retained": currentActivationVerifier.schedulerByPrincipal,
		"TLS-config":          tlsConfig.SchedulerByPrincipal,
	} {
		if !reflect.DeepEqual(bindings, wantBindings) {
			t.Fatalf("%s principal bindings = %#v, want %#v", name, bindings, wantBindings)
		}
	}
	if verifierConfig.LeaderKey != statusVerifierConfig.LeaderKey ||
		verifierConfig.ExpectedCluster != statusVerifierConfig.ExpectedCluster ||
		verifierConfig.ReadTimeout != statusVerifierConfig.ReadTimeout ||
		verifierConfig.LeaderKey != identifyVerifierConfig.LeaderKey ||
		verifierConfig.ExpectedCluster != identifyVerifierConfig.ExpectedCluster ||
		verifierConfig.ReadTimeout != identifyVerifierConfig.ReadTimeout ||
		verifierConfig.LeaderKey != activationVerifierConfig.LeaderKey ||
		verifierConfig.ExpectedCluster != activationVerifierConfig.ExpectedCluster ||
		verifierConfig.ReadTimeout != activationVerifierConfig.ReadTimeout {
		t.Fatalf("Reader authority sources differ: prepare=%#v status=%#v identify=%#v activation=%#v",
			verifierConfig, statusVerifierConfig, identifyVerifierConfig,
			activationVerifierConfig)
	}
	if currentVerifier.reader != currentStatusVerifier.reader ||
		currentVerifier.reader != currentIdentifyVerifier.reader ||
		currentVerifier.reader != currentActivationVerifier.reader {
		t.Fatal("Reader verifiers did not retain the same independent reader")
	}
	if runtime.service.store != runtime.store ||
		runtime.statusService.store != runtime.store ||
		runtime.activationStore.prepared != runtime.store ||
		runtime.activationService.store != runtime.activationStore {
		t.Fatal("Reader services do not share the exact PREPARED and activation stores")
	}
	if activationStoreConfig != config.ActivationStore ||
		activationStoreExecutor != config.LocalExecutorNodeID ||
		activationStoreLogical != config.LocalCxldLogicalID ||
		activationStoreProcess != runtime.processIncarnation ||
		activationPreparedStore != runtime.store {
		t.Fatal("activation store did not receive exact bounded config and process identity")
	}
	if passedPrepareRPC != runtime.rpc || passedStatusRPC != runtime.statusRPC ||
		passedIdentifyRPC != runtime.identifyRPC ||
		passedActivationProposalRPC != runtime.activationProposalRPC ||
		passedActivationCommitRPC != runtime.activationCommitRPC ||
		passedActivationStatusRPC != runtime.activationStatusRPC {
		t.Fatal("listener did not receive the exact six Reader RPCs")
	}
	if runtime.requestAdmission != requestAdmission ||
		runtime.largeFrameAdmission != largeAdmission ||
		cap(runtime.requestAdmission) != daemonMaxConcurrentRequests ||
		cap(runtime.largeFrameAdmission) != daemonMaxConcurrentLargeBody {
		t.Fatalf("runtime did not retain the exact injected daemon admissions")
	}
	if runtime.service.localExecutorNodeID != config.LocalExecutorNodeID ||
		runtime.service.localCxldLogicalID != config.LocalCxldLogicalID ||
		tlsConfig.ExpectedServerURISAN != config.TLS.ExpectedServerURISAN {
		t.Fatal("runtime did not retain the exact trusted local IDs and server URI SAN")
	}

	// The caller cannot mutate either security boundary after construction.
	config.SchedulerByPrincipal[vnextReaderPrepareTestPrincipal] = "scheduler-mutated"
	config.SchedulerAuthority.Endpoints[0] = "https://mutated.test:2379"
	if !reflect.DeepEqual(runtime.schedulerByPrincipal, wantBindings) ||
		!reflect.DeepEqual(currentVerifier.schedulerByPrincipal, wantBindings) ||
		!reflect.DeepEqual(
			currentStatusVerifier.schedulerByPrincipal, wantBindings) ||
		!reflect.DeepEqual(
			currentIdentifyVerifier.schedulerByPrincipal, wantBindings) ||
		!reflect.DeepEqual(
			currentActivationVerifier.schedulerByPrincipal, wantBindings) {
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
		vnextReaderPreparedStatusTransportRPC,
		vnextReaderIdentifyTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
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
		vnextReaderPreparedStatusTransportRPC,
		vnextReaderIdentifyTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
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
	dependencies.processIncarnationLocker =
		&vnextReaderPrepareRuntimeTestIncarnationLocker{
			acquire: func(string) (vnextReaderProcessIncarnationLock, error) {
				return &vnextReaderPrepareRuntimeTestIncarnationLock{
					remove: func(vnextReaderProcessIncarnation, bool) error {
						events.add("incarnation-remove")
						return nil
					},
					release: func() error {
						events.add("incarnation-unlock")
						return nil
					},
				}, nil
			},
		}
	waitStarted := make(chan struct{})
	waitRelease := make(chan struct{})
	server := &vnextReaderPrepareRuntimeTestServer{
		events: events, waitStarted: waitStarted, waitRelease: waitRelease,
	}
	dependencies.startServer = func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		vnextReaderPreparedStatusTransportRPC,
		vnextReaderIdentifyTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
		vnextReaderActivationTransportRPC,
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
	wantEvents := []string{
		"listener-stop", "handler-wait", "etcd-close",
		"incarnation-remove", "incarnation-unlock",
	}
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
		runtime.verifier == nil || runtime.statusVerifier == nil ||
		runtime.statusService == nil || runtime.statusRPC == nil ||
		runtime.identifyVerifier == nil || runtime.identifyService == nil ||
		runtime.identifyRPC == nil || runtime.activationStore == nil ||
		runtime.activationVerifier == nil || runtime.activationService == nil ||
		runtime.activationProposalRPC == nil ||
		runtime.activationCommitRPC == nil || runtime.activationStatusRPC == nil {
		_ = runtime.Close()
		t.Fatal("successful startup omitted a required Reader component")
	}
	if len(server.tlsConfig.NextProtos) != 6 ||
		server.tlsConfig.NextProtos[0] != vnextReaderPrepareALPN ||
		server.tlsConfig.NextProtos[1] != vnextReaderPreparedStatusALPN ||
		server.tlsConfig.NextProtos[2] != vnextReaderIdentifyALPN ||
		server.tlsConfig.NextProtos[3] != vnextReaderActivationProposalALPN ||
		server.tlsConfig.NextProtos[4] != vnextReaderActivationCommitALPN ||
		server.tlsConfig.NextProtos[5] != vnextReaderActivationStatusALPN {
		_ = runtime.Close()
		t.Fatalf("production Reader listener ALPNs = %#v",
			server.tlsConfig.NextProtos)
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
