package main

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

const (
	vnextReaderPrepareRuntimeMaxEtcdEndpoints      = 16
	vnextReaderPrepareRuntimeMaxEndpointInputBytes = 64 << 10
	vnextReaderPrepareRuntimeMaxEtcdTimeout        = 30 * time.Second
)

// vnextReaderPrepareRuntimeInput is the strict textual CLI/environment
// boundary. It contains paths, never file contents. Disabled is checked before
// any other field is parsed so the disabled path opens and allocates no Reader
// resource.
type vnextReaderPrepareRuntimeInput struct {
	Enabled                     string
	LocalExecutorNodeID         string
	LocalCxldInstanceID         string
	StoreMaxEntries             string
	StoreMaxRetainedBytes       string
	TLSListenAddress            string
	TLSServerCertificatePath    string
	TLSServerPrivateKeyPath     string
	TLSClientCAPath             string
	TLSExpectedServerURISAN     string
	PrincipalBindings           string
	TLSHandshakeTimeoutMillis   string
	TLSRequestReadTimeoutMillis string
	TLSHandlerTimeoutMillis     string
	TLSResponseWriteMillis      string
	EtcdEndpoints               string
	EtcdLeaderKey               string
	EtcdClusterID               string
	EtcdCAPath                  string
	EtcdClientCertificatePath   string
	EtcdClientPrivateKeyPath    string
	EtcdDialTimeoutMillis       string
	EtcdReadTimeoutMillis       string
}

type vnextReaderPrepareRuntimeTLSConfig struct {
	ListenAddress         string
	ServerCertificatePath string
	ServerPrivateKeyPath  string
	ClientCAPath          string
	// ExpectedServerURISAN is a mandatory exact trusted route input. This
	// slice has no cross-language ABI for deriving it from the two local IDs;
	// production-derived identity remains a later gate before ACTIVE/mapping.
	ExpectedServerURISAN string
	HandshakeTimeout     time.Duration
	RequestReadTimeout   time.Duration
	HandlerTimeout       time.Duration
	ResponseWriteTimeout time.Duration
}

// vnextReaderPrepareRuntimeConfig is all-or-nothing. Enabled=false is the only
// empty configuration. Enabled=true requires every identity, capacity, TLS,
// principal, and independent etcd field to be present and strict.
type vnextReaderPrepareRuntimeConfig struct {
	Enabled              bool
	LocalExecutorNodeID  string
	LocalCxldInstanceID  string
	Store                vnextReaderAuthorizationStoreConfig
	TLS                  vnextReaderPrepareRuntimeTLSConfig
	SchedulerByPrincipal map[string]string
	SchedulerAuthority   vnextOwnerSchedulerAuthorityConfig
}

type vnextReaderPrepareRuntimeServer interface {
	Stop() error
	Wait()
}

type vnextReaderPrepareRuntimeDependencies struct {
	entropy                  io.Reader
	processIncarnationPath   string
	processIncarnationWriter vnextReaderProcessIncarnationPublisher
	processIncarnationLocker vnextReaderProcessIncarnationLockAcquirer
	newStore                 func(vnextReaderAuthorizationStoreConfig) (
		*vnextReaderAuthorizationStore, error)
	openLeaderReader func(vnextOwnerSchedulerAuthorityConfig) (
		vnextOwnerSchedulerLeaderReader, func() error, error)
	newVerifier func(
		vnextReaderPrepareCurrentAuthorityConfig,
		vnextOwnerSchedulerLeaderReader,
	) (vnextReaderPrepareAuthorityVerifier, error)
	newStatusVerifier func(
		vnextReaderPreparedStatusCurrentAuthorityConfig,
		vnextOwnerSchedulerLeaderReader,
	) (vnextReaderPreparedStatusAuthorityVerifier, error)
	newIdentifyVerifier func(
		vnextReaderIdentifyCurrentAuthorityConfig,
		vnextOwnerSchedulerLeaderReader,
	) (vnextReaderIdentifyAuthorityVerifier, error)
	newService func(
		string,
		string,
		*vnextReaderAuthorizationStore,
		vnextReaderPrepareClock,
		vnextReaderPrepareAuthorityVerifier,
	) (*vnextReaderPrepareService, error)
	newStatusService func(
		string,
		string,
		vnextReaderPreparedStatusStore,
		vnextReaderPreparedStatusAuthorityVerifier,
	) (*vnextReaderPreparedStatusService, error)
	newIdentifyService func(
		string,
		string,
		vnextReaderProcessIncarnation,
		string,
		vnextReaderIdentifyAuthorityVerifier,
	) (*vnextReaderIdentifyService, error)
	newRPC       func(*vnextReaderPrepareService) vnextReaderPrepareTransportRPC
	newStatusRPC func(
		*vnextReaderPreparedStatusService,
	) vnextReaderPreparedStatusTransportRPC
	newIdentifyRPC func(
		*vnextReaderIdentifyService,
	) vnextReaderIdentifyTransportRPC
	startServer func(
		vnextReaderPrepareTLSServerConfig,
		vnextReaderPrepareTransportRPC,
		vnextReaderPreparedStatusTransportRPC,
		vnextReaderIdentifyTransportRPC,
		chan struct{},
		chan struct{},
	) (vnextReaderPrepareRuntimeServer, error)
	clock vnextReaderPrepareClock
}

type vnextReaderPrepareSystemClock struct{}

func (vnextReaderPrepareSystemClock) NowEpochMillis() int64 {
	return time.Now().UnixNano() / int64(time.Millisecond)
}

type vnextReaderPrepareRuntime struct {
	mu sync.Mutex

	store                  *vnextReaderAuthorizationStore
	verifier               vnextReaderPrepareAuthorityVerifier
	service                *vnextReaderPrepareService
	rpc                    vnextReaderPrepareTransportRPC
	statusVerifier         vnextReaderPreparedStatusAuthorityVerifier
	statusService          *vnextReaderPreparedStatusService
	statusRPC              vnextReaderPreparedStatusTransportRPC
	processIncarnation     vnextReaderProcessIncarnation
	processIncarnationLock vnextReaderProcessIncarnationLock
	identifyVerifier       vnextReaderIdentifyAuthorityVerifier
	identifyService        *vnextReaderIdentifyService
	identifyRPC            vnextReaderIdentifyTransportRPC
	server                 vnextReaderPrepareRuntimeServer
	closeLeaderReader      func() error
	requestAdmission       chan struct{}
	largeFrameAdmission    chan struct{}
	schedulerByPrincipal   map[string]string
	stopCalled             bool
	stopErr                error
	closed                 bool
}

type vnextReaderPrepareRuntimeErrors struct {
	failures []error
}

func (failures *vnextReaderPrepareRuntimeErrors) Error() string {
	messages := make([]string, 0, len(failures.failures))
	for _, failure := range failures.failures {
		messages = append(messages, failure.Error())
	}
	return strings.Join(messages, "; ")
}

func (failures *vnextReaderPrepareRuntimeErrors) Is(target error) bool {
	for _, failure := range failures.failures {
		if errors.Is(failure, target) {
			return true
		}
	}
	return false
}

func appendVNextReaderPrepareRuntimeError(existing error, next error) error {
	if next == nil {
		return existing
	}
	if existing == nil {
		return next
	}
	if aggregate, ok := existing.(*vnextReaderPrepareRuntimeErrors); ok {
		aggregate.failures = append(aggregate.failures, next)
		return aggregate
	}
	return &vnextReaderPrepareRuntimeErrors{failures: []error{existing, next}}
}

func parseVNextReaderPrepareRuntimeInput(
	input vnextReaderPrepareRuntimeInput,
) (vnextReaderPrepareRuntimeConfig, error) {
	var config vnextReaderPrepareRuntimeConfig
	switch input.Enabled {
	case "false":
		return config, nil
	case "true":
		config.Enabled = true
	default:
		return config, errors.New(
			"VNext Reader PREPARE enabled must be exactly true or false")
	}
	config.LocalExecutorNodeID = input.LocalExecutorNodeID
	config.LocalCxldInstanceID = input.LocalCxldInstanceID
	storeEntries, err := parseVNextReaderPrepareRuntimePositiveUint(
		"authorization store max entries", input.StoreMaxEntries,
		uint64(vnextReaderAuthorizationStoreMaxEntries))
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	storeBytes, err := parseVNextReaderPrepareRuntimePositiveUint(
		"authorization store retained bytes", input.StoreMaxRetainedBytes,
		vnextReaderAuthorizationStoreMaxRetainedBytes)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.Store = vnextReaderAuthorizationStoreConfig{
		MaxEntries:       int(storeEntries),
		MaxRetainedBytes: storeBytes,
	}
	config.TLS = vnextReaderPrepareRuntimeTLSConfig{
		ListenAddress:         input.TLSListenAddress,
		ServerCertificatePath: input.TLSServerCertificatePath,
		ServerPrivateKeyPath:  input.TLSServerPrivateKeyPath,
		ClientCAPath:          input.TLSClientCAPath,
		ExpectedServerURISAN:  input.TLSExpectedServerURISAN,
	}
	config.TLS.HandshakeTimeout, err = parseVNextReaderPrepareRuntimeMillis(
		"TLS handshake timeout", input.TLSHandshakeTimeoutMillis,
		vnextReaderPrepareTLSMaxStageTimeout)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.TLS.RequestReadTimeout, err = parseVNextReaderPrepareRuntimeMillis(
		"TLS request read timeout", input.TLSRequestReadTimeoutMillis,
		vnextReaderPrepareTLSMaxStageTimeout)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.TLS.HandlerTimeout, err = parseVNextReaderPrepareRuntimeMillis(
		"TLS handler timeout", input.TLSHandlerTimeoutMillis,
		vnextReaderPrepareTLSMaxStageTimeout)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.TLS.ResponseWriteTimeout, err = parseVNextReaderPrepareRuntimeMillis(
		"TLS response write timeout", input.TLSResponseWriteMillis,
		vnextReaderPrepareTLSMaxStageTimeout)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.SchedulerByPrincipal, err =
		parseVNextReaderPreparePrincipalBindings(input.PrincipalBindings)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.SchedulerAuthority, err = parseVNextReaderPrepareSchedulerAuthority(
		input)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	canonical, err := canonicalVNextReaderPrepareRuntimeConfig(config)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	return canonical, nil
}

func parseVNextReaderPrepareRuntimePositiveUint(
	name string,
	value string,
	maximum uint64,
) (uint64, error) {
	if value == "" || strings.TrimSpace(value) != value {
		return 0, fmt.Errorf("VNext Reader PREPARE %s is missing or has whitespace", name)
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == 0 || parsed > maximum ||
		strconv.FormatUint(parsed, 10) != value {
		return 0, fmt.Errorf(
			"VNext Reader PREPARE %s is outside canonical range 1..%d",
			name, maximum)
	}
	return parsed, nil
}

func parseVNextReaderPrepareRuntimeMillis(
	name string,
	value string,
	maximum time.Duration,
) (time.Duration, error) {
	maximumMillis := uint64(maximum / time.Millisecond)
	parsed, err := parseVNextReaderPrepareRuntimePositiveUint(
		name+" milliseconds", value, maximumMillis)
	if err != nil {
		return 0, err
	}
	return time.Duration(parsed) * time.Millisecond, nil
}

func parseVNextReaderPrepareSchedulerAuthority(
	input vnextReaderPrepareRuntimeInput,
) (vnextOwnerSchedulerAuthorityConfig, error) {
	var config vnextOwnerSchedulerAuthorityConfig
	if input.EtcdEndpoints == "" ||
		strings.TrimSpace(input.EtcdEndpoints) != input.EtcdEndpoints ||
		len(input.EtcdEndpoints) > vnextReaderPrepareRuntimeMaxEndpointInputBytes {
		return config, errors.New(
			"VNext Reader PREPARE etcd endpoints are missing, non-canonical, or too long")
	}
	config.Endpoints = strings.Split(input.EtcdEndpoints, ",")
	if len(config.Endpoints) == 0 ||
		len(config.Endpoints) > vnextReaderPrepareRuntimeMaxEtcdEndpoints {
		return vnextOwnerSchedulerAuthorityConfig{}, fmt.Errorf(
			"VNext Reader PREPARE etcd endpoint count is outside 1..%d",
			vnextReaderPrepareRuntimeMaxEtcdEndpoints)
	}
	for index, endpoint := range config.Endpoints {
		if endpoint == "" {
			return vnextOwnerSchedulerAuthorityConfig{}, fmt.Errorf(
				"VNext Reader PREPARE etcd endpoint %d is empty", index)
		}
	}
	config.LeaderKey = input.EtcdLeaderKey
	cluster, err := decodeVNextOwnerSchedulerHexU64(
		"VNext Reader PREPARE expected etcd cluster ID",
		input.EtcdClusterID, false)
	if err != nil {
		return vnextOwnerSchedulerAuthorityConfig{}, err
	}
	config.ExpectedCluster = cluster
	config.CAFile = input.EtcdCAPath
	config.ClientCertFile = input.EtcdClientCertificatePath
	config.ClientKeyFile = input.EtcdClientPrivateKeyPath
	config.DialTimeout, err = parseVNextReaderPrepareRuntimeMillis(
		"etcd dial timeout", input.EtcdDialTimeoutMillis,
		vnextReaderPrepareRuntimeMaxEtcdTimeout)
	if err != nil {
		return vnextOwnerSchedulerAuthorityConfig{}, err
	}
	config.ReadTimeout, err = parseVNextReaderPrepareRuntimeMillis(
		"etcd read timeout", input.EtcdReadTimeoutMillis,
		vnextReaderPrepareAuthorityMaxReadTimeout)
	if err != nil {
		return vnextOwnerSchedulerAuthorityConfig{}, err
	}
	if err := validateVNextOwnerSchedulerAuthorityConfig(config, true); err != nil {
		return vnextOwnerSchedulerAuthorityConfig{}, fmt.Errorf(
			"validate VNext Reader PREPARE independent etcd authority: %w", err)
	}
	return config, nil
}

// parseVNextReaderPreparePrincipalBindings uses the bounded exact grammar
// URI-SAN=Scheduler-ID[,URI-SAN=Scheduler-ID...]. Bindings must be ordered by
// the URI SAN's UTF-8 bytes (Go string order). '=' is reserved as the mapping
// delimiter and therefore rejected inside both identities.
func parseVNextReaderPreparePrincipalBindings(
	value string,
) (map[string]string, error) {
	if value == "" || strings.TrimSpace(value) != value ||
		len(value) > vnextReaderPrepareAuthorityMaxPrincipalRetainedBytes {
		return nil, errors.New(
			"VNext Reader PREPARE principal bindings are missing, non-canonical, or too long")
	}
	items := strings.Split(value, ",")
	if len(items) == 0 || len(items) > vnextReaderPrepareAuthorityMaxPrincipals {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE principal binding count is outside 1..%d",
			vnextReaderPrepareAuthorityMaxPrincipals)
	}
	bindings := make(map[string]string, len(items))
	previousPrincipal := ""
	for index, item := range items {
		if strings.Count(item, "=") != 1 {
			return nil, fmt.Errorf(
				"VNext Reader PREPARE principal binding %d must contain one '=' delimiter",
				index)
		}
		parts := strings.SplitN(item, "=", 2)
		principal, schedulerID := parts[0], parts[1]
		if err := validateVNextReaderPreparePrincipalURI(principal); err != nil {
			return nil, fmt.Errorf(
				"validate VNext Reader PREPARE principal binding %d: %w", index, err)
		}
		if err := validateVNextReaderIdentity(
			"VNext Reader PREPARE bound Scheduler ID", schedulerID); err != nil {
			return nil, err
		}
		if _, duplicate := bindings[principal]; duplicate {
			return nil, fmt.Errorf(
				"VNext Reader PREPARE principal %q is duplicated", principal)
		}
		if index > 0 && principal < previousPrincipal {
			return nil, errors.New(
				"VNext Reader PREPARE principal bindings are not in canonical URI-SAN order")
		}
		bindings[principal] = schedulerID
		previousPrincipal = principal
	}
	cloned, err := cloneVNextReaderPreparePrincipalBindings(bindings)
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

func canonicalVNextReaderPrepareRuntimeConfig(
	config vnextReaderPrepareRuntimeConfig,
) (vnextReaderPrepareRuntimeConfig, error) {
	if !config.Enabled {
		return vnextReaderPrepareRuntimeConfig{}, nil
	}
	if err := validateVNextReaderIdentity(
		"local Reader PREPARE executor node ID", config.LocalExecutorNodeID); err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	if err := validateVNextReaderIdentity(
		"local Reader PREPARE cxld instance ID", config.LocalCxldInstanceID); err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	if config.Store.MaxEntries <= 0 ||
		config.Store.MaxEntries > vnextReaderAuthorizationStoreMaxEntries ||
		config.Store.MaxRetainedBytes == 0 ||
		config.Store.MaxRetainedBytes > vnextReaderAuthorizationStoreMaxRetainedBytes {
		return vnextReaderPrepareRuntimeConfig{}, errors.New(
			"VNext Reader PREPARE store limits are outside bounded ranges")
	}
	if err := validateVNextReaderPrepareTLSListenAddress(
		config.TLS.ListenAddress); err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	for role, path := range map[string]string{
		"server certificate": config.TLS.ServerCertificatePath,
		"server private key": config.TLS.ServerPrivateKeyPath,
		"client CA":          config.TLS.ClientCAPath,
	} {
		if err := validateVNextReaderPrepareTLSPath(path, role); err != nil {
			return vnextReaderPrepareRuntimeConfig{}, err
		}
	}
	if err := validateVNextReaderPreparePrincipalURI(
		config.TLS.ExpectedServerURISAN); err != nil {
		return vnextReaderPrepareRuntimeConfig{}, fmt.Errorf(
			"validate VNext Reader PREPARE server URI SAN: %w", err)
	}
	for name, timeout := range map[string]time.Duration{
		"TLS handshake": config.TLS.HandshakeTimeout,
		"TLS read":      config.TLS.RequestReadTimeout,
		"TLS handler":   config.TLS.HandlerTimeout,
		"TLS write":     config.TLS.ResponseWriteTimeout,
	} {
		if timeout <= 0 || timeout > vnextReaderPrepareTLSMaxStageTimeout {
			return vnextReaderPrepareRuntimeConfig{}, fmt.Errorf(
				"VNext Reader PREPARE %s timeout is outside (0,%s]",
				name, vnextReaderPrepareTLSMaxStageTimeout)
		}
	}
	if err := validateVNextOwnerSchedulerAuthorityConfig(
		config.SchedulerAuthority, true); err != nil {
		return vnextReaderPrepareRuntimeConfig{}, fmt.Errorf(
			"validate VNext Reader PREPARE independent etcd authority: %w", err)
	}
	if config.SchedulerAuthority.DialTimeout > vnextReaderPrepareRuntimeMaxEtcdTimeout ||
		config.SchedulerAuthority.ReadTimeout > vnextReaderPrepareAuthorityMaxReadTimeout {
		return vnextReaderPrepareRuntimeConfig{}, errors.New(
			"VNext Reader PREPARE etcd timeouts exceed bounded maxima")
	}
	if len(config.SchedulerAuthority.Endpoints) >
		vnextReaderPrepareRuntimeMaxEtcdEndpoints {
		return vnextReaderPrepareRuntimeConfig{}, errors.New(
			"VNext Reader PREPARE etcd endpoint count exceeds the bound")
	}
	bindings, err := cloneVNextReaderPreparePrincipalBindings(
		config.SchedulerByPrincipal)
	if err != nil {
		return vnextReaderPrepareRuntimeConfig{}, err
	}
	config.LocalExecutorNodeID = cloneVNextReaderRetainedString(
		config.LocalExecutorNodeID)
	config.LocalCxldInstanceID = cloneVNextReaderRetainedString(
		config.LocalCxldInstanceID)
	config.TLS.ListenAddress = cloneVNextReaderRetainedString(config.TLS.ListenAddress)
	config.TLS.ServerCertificatePath = cloneVNextReaderRetainedString(
		config.TLS.ServerCertificatePath)
	config.TLS.ServerPrivateKeyPath = cloneVNextReaderRetainedString(
		config.TLS.ServerPrivateKeyPath)
	config.TLS.ClientCAPath = cloneVNextReaderRetainedString(config.TLS.ClientCAPath)
	config.TLS.ExpectedServerURISAN = cloneVNextReaderRetainedString(
		config.TLS.ExpectedServerURISAN)
	config.SchedulerByPrincipal = bindings
	endpoints := config.SchedulerAuthority.Endpoints
	config.SchedulerAuthority.Endpoints = make([]string, len(endpoints))
	for index, endpoint := range endpoints {
		config.SchedulerAuthority.Endpoints[index] =
			cloneVNextReaderRetainedString(endpoint)
	}
	config.SchedulerAuthority.LeaderKey = cloneVNextReaderRetainedString(
		config.SchedulerAuthority.LeaderKey)
	config.SchedulerAuthority.CAFile = cloneVNextReaderRetainedString(
		config.SchedulerAuthority.CAFile)
	config.SchedulerAuthority.ClientCertFile = cloneVNextReaderRetainedString(
		config.SchedulerAuthority.ClientCertFile)
	config.SchedulerAuthority.ClientKeyFile = cloneVNextReaderRetainedString(
		config.SchedulerAuthority.ClientKeyFile)
	return config, nil
}

func defaultVNextReaderPrepareRuntimeDependencies() vnextReaderPrepareRuntimeDependencies {
	return vnextReaderPrepareRuntimeDependencies{
		entropy:                  rand.Reader,
		processIncarnationPath:   vnextReaderProcessIncarnationPath,
		processIncarnationWriter: &vnextReaderProcessIncarnationFilePublisher{},
		processIncarnationLocker: &vnextReaderProcessIncarnationFileLockAcquirer{},
		newStore:                 newVNextReaderAuthorizationStore,
		openLeaderReader:         openVNextReaderPrepareIndependentLeaderReader,
		newVerifier: func(
			config vnextReaderPrepareCurrentAuthorityConfig,
			reader vnextOwnerSchedulerLeaderReader,
		) (vnextReaderPrepareAuthorityVerifier, error) {
			return newVNextReaderPrepareCurrentAuthorityVerifier(config, reader)
		},
		newStatusVerifier: func(
			config vnextReaderPreparedStatusCurrentAuthorityConfig,
			reader vnextOwnerSchedulerLeaderReader,
		) (vnextReaderPreparedStatusAuthorityVerifier, error) {
			return newVNextReaderPreparedStatusCurrentAuthorityVerifier(config, reader)
		},
		newIdentifyVerifier: func(
			config vnextReaderIdentifyCurrentAuthorityConfig,
			reader vnextOwnerSchedulerLeaderReader,
		) (vnextReaderIdentifyAuthorityVerifier, error) {
			return newVNextReaderIdentifyCurrentAuthorityVerifier(config, reader)
		},
		newService:         newVNextReaderPrepareService,
		newStatusService:   newVNextReaderPreparedStatusService,
		newIdentifyService: newVNextReaderIdentifyService,
		newRPC: func(service *vnextReaderPrepareService) vnextReaderPrepareTransportRPC {
			return newVNextReaderPrepareRPC(service)
		},
		newStatusRPC: func(
			service *vnextReaderPreparedStatusService,
		) vnextReaderPreparedStatusTransportRPC {
			return newVNextReaderPreparedStatusRPC(service)
		},
		newIdentifyRPC: func(
			service *vnextReaderIdentifyService,
		) vnextReaderIdentifyTransportRPC {
			return newVNextReaderIdentifyRPC(service)
		},
		startServer: func(
			config vnextReaderPrepareTLSServerConfig,
			rpc vnextReaderPrepareTransportRPC,
			statusRPC vnextReaderPreparedStatusTransportRPC,
			identifyRPC vnextReaderIdentifyTransportRPC,
			requestAdmission chan struct{},
			largeAdmission chan struct{},
		) (vnextReaderPrepareRuntimeServer, error) {
			return startVNextReaderPrepareStatusAndIdentifyTLSServer(
				config, rpc, statusRPC, identifyRPC,
				requestAdmission, largeAdmission)
		},
		clock: vnextReaderPrepareSystemClock{},
	}
}

func validateVNextReaderPrepareRuntimeDependencies(
	dependencies vnextReaderPrepareRuntimeDependencies,
) error {
	if vnextReaderPreparedStatusNilInterface(dependencies.entropy) ||
		dependencies.processIncarnationPath == "" ||
		vnextReaderPreparedStatusNilInterface(dependencies.processIncarnationWriter) ||
		vnextReaderPreparedStatusNilInterface(dependencies.processIncarnationLocker) ||
		dependencies.newStore == nil || dependencies.openLeaderReader == nil ||
		dependencies.newVerifier == nil || dependencies.newStatusVerifier == nil ||
		dependencies.newIdentifyVerifier == nil ||
		dependencies.newService == nil || dependencies.newStatusService == nil ||
		dependencies.newIdentifyService == nil ||
		dependencies.newRPC == nil || dependencies.newStatusRPC == nil ||
		dependencies.newIdentifyRPC == nil ||
		dependencies.startServer == nil ||
		dependencies.clock == nil {
		return errors.New(
			"VNext Reader PREPARE runtime dependencies are incomplete")
	}
	return nil
}

func openVNextReaderPrepareRuntime(
	config vnextReaderPrepareRuntimeConfig,
	requestAdmission chan struct{},
	largeAdmission chan struct{},
) (*vnextReaderPrepareRuntime, error) {
	return openVNextReaderPrepareRuntimeWithDependencies(
		config,
		requestAdmission,
		largeAdmission,
		defaultVNextReaderPrepareRuntimeDependencies())
}

func openVNextReaderPrepareRuntimeWithDependencies(
	config vnextReaderPrepareRuntimeConfig,
	requestAdmission chan struct{},
	largeAdmission chan struct{},
	dependencies vnextReaderPrepareRuntimeDependencies,
) (*vnextReaderPrepareRuntime, error) {
	if !config.Enabled {
		return nil, nil
	}
	canonical, err := canonicalVNextReaderPrepareRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	if requestAdmission == nil || cap(requestAdmission) != daemonMaxConcurrentRequests {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE requires the daemon-wide %d-request admission",
			daemonMaxConcurrentRequests)
	}
	if largeAdmission == nil || cap(largeAdmission) != daemonMaxConcurrentLargeBody {
		return nil, fmt.Errorf(
			"VNext Reader PREPARE requires the daemon-wide %d-large-body admission",
			daemonMaxConcurrentLargeBody)
	}
	if err := validateVNextReaderPrepareRuntimeDependencies(dependencies); err != nil {
		return nil, err
	}
	processLock, err := dependencies.processIncarnationLocker.Acquire(
		dependencies.processIncarnationPath)
	if err != nil {
		return nil, fmt.Errorf("acquire VNext Reader process-incarnation lock: %w", err)
	}
	if vnextReaderPreparedStatusNilInterface(processLock) {
		return nil, errors.New(
			"VNext Reader process-incarnation lock acquirer returned nil")
	}
	releaseProcessLock := func(primary error) error {
		if processLock != nil {
			if releaseErr := processLock.Release(); releaseErr != nil {
				primary = appendVNextReaderPrepareRuntimeError(
					primary,
					fmt.Errorf("release VNext Reader process-incarnation lock: %w",
						releaseErr))
			}
			processLock = nil
		}
		return primary
	}
	processIncarnation, err := newVNextReaderProcessIncarnation(
		dependencies.entropy)
	if err != nil {
		return nil, releaseProcessLock(err)
	}
	store, err := dependencies.newStore(canonical.Store)
	if err != nil {
		return nil, releaseProcessLock(fmt.Errorf(
			"open VNext Reader PREPARE store: %w", err))
	}
	if store == nil {
		return nil, releaseProcessLock(errors.New(
			"VNext Reader PREPARE store constructor returned nil"))
	}
	reader, closeReader, err := dependencies.openLeaderReader(
		canonical.SchedulerAuthority)
	if err != nil {
		primary := fmt.Errorf(
			"open VNext Reader PREPARE independent etcd reader: %w", err)
		if closeReader != nil {
			if closeErr := closeReader(); closeErr != nil {
				primary = appendVNextReaderPrepareRuntimeError(
					primary,
					fmt.Errorf("close partial VNext Reader PREPARE etcd reader: %w", closeErr))
			}
		}
		return nil, releaseProcessLock(primary)
	}
	if vnextReaderPreparedStatusNilInterface(reader) || closeReader == nil {
		primary := errors.New(
			"VNext Reader PREPARE etcd reader or close function is unavailable")
		if closeReader != nil {
			if closeErr := closeReader(); closeErr != nil {
				primary = appendVNextReaderPrepareRuntimeError(
					primary,
					fmt.Errorf("close partial VNext Reader PREPARE etcd reader: %w", closeErr))
			}
		}
		return nil, releaseProcessLock(primary)
	}
	cleanupReader := func(primary error) error {
		if closeErr := closeReader(); closeErr != nil {
			primary = appendVNextReaderPrepareRuntimeError(
				primary, fmt.Errorf("close VNext Reader PREPARE etcd reader: %w", closeErr))
		}
		return releaseProcessLock(primary)
	}
	verifierConfig := vnextReaderPrepareCurrentAuthorityConfig{
		LeaderKey:            canonical.SchedulerAuthority.LeaderKey,
		ExpectedCluster:      canonical.SchedulerAuthority.ExpectedCluster,
		ReadTimeout:          canonical.SchedulerAuthority.ReadTimeout,
		SchedulerByPrincipal: canonical.SchedulerByPrincipal,
	}
	verifier, err := dependencies.newVerifier(verifierConfig, reader)
	if err != nil {
		return nil, cleanupReader(fmt.Errorf(
			"construct VNext Reader PREPARE authority verifier: %w", err))
	}
	if verifier == nil {
		return nil, cleanupReader(errors.New(
			"VNext Reader PREPARE authority verifier constructor returned nil"))
	}
	statusVerifierConfig := vnextReaderPreparedStatusCurrentAuthorityConfig{
		LeaderKey:            canonical.SchedulerAuthority.LeaderKey,
		ExpectedCluster:      canonical.SchedulerAuthority.ExpectedCluster,
		ReadTimeout:          canonical.SchedulerAuthority.ReadTimeout,
		SchedulerByPrincipal: canonical.SchedulerByPrincipal,
	}
	statusVerifier, err := dependencies.newStatusVerifier(
		statusVerifierConfig, reader)
	if err != nil {
		return nil, cleanupReader(fmt.Errorf(
			"construct VNext Reader STATUS_AND_FENCE authority verifier: %w", err))
	}
	if vnextReaderPreparedStatusNilInterface(statusVerifier) {
		return nil, cleanupReader(errors.New(
			"VNext Reader STATUS_AND_FENCE authority verifier constructor returned nil"))
	}
	identifyVerifierConfig := vnextReaderIdentifyCurrentAuthorityConfig{
		LeaderKey:            canonical.SchedulerAuthority.LeaderKey,
		ExpectedCluster:      canonical.SchedulerAuthority.ExpectedCluster,
		ReadTimeout:          canonical.SchedulerAuthority.ReadTimeout,
		SchedulerByPrincipal: canonical.SchedulerByPrincipal,
	}
	identifyVerifier, err := dependencies.newIdentifyVerifier(
		identifyVerifierConfig, reader)
	if err != nil {
		return nil, cleanupReader(fmt.Errorf(
			"construct VNext Reader IDENTIFY authority verifier: %w", err))
	}
	if vnextReaderPreparedStatusNilInterface(identifyVerifier) {
		return nil, cleanupReader(errors.New(
			"VNext Reader IDENTIFY authority verifier constructor returned nil"))
	}
	service, err := dependencies.newService(
		canonical.LocalExecutorNodeID,
		canonical.LocalCxldInstanceID,
		store,
		dependencies.clock,
		verifier)
	if err != nil {
		return nil, cleanupReader(fmt.Errorf(
			"construct VNext Reader PREPARE service: %w", err))
	}
	if service == nil {
		return nil, cleanupReader(errors.New(
			"VNext Reader PREPARE service constructor returned nil"))
	}
	statusService, err := dependencies.newStatusService(
		canonical.LocalExecutorNodeID,
		canonical.LocalCxldInstanceID,
		store,
		statusVerifier)
	if err != nil {
		return nil, cleanupReader(fmt.Errorf(
			"construct VNext Reader STATUS_AND_FENCE service: %w", err))
	}
	if statusService == nil {
		return nil, cleanupReader(errors.New(
			"VNext Reader STATUS_AND_FENCE service constructor returned nil"))
	}
	identifyService, err := dependencies.newIdentifyService(
		canonical.LocalExecutorNodeID,
		canonical.LocalCxldInstanceID,
		processIncarnation,
		canonical.TLS.ExpectedServerURISAN,
		identifyVerifier)
	if err != nil {
		return nil, cleanupReader(fmt.Errorf(
			"construct VNext Reader IDENTIFY service: %w", err))
	}
	if identifyService == nil {
		return nil, cleanupReader(errors.New(
			"VNext Reader IDENTIFY service constructor returned nil"))
	}
	rpc := dependencies.newRPC(service)
	if rpc == nil {
		return nil, cleanupReader(errors.New(
			"VNext Reader PREPARE RPC constructor returned nil"))
	}
	statusRPC := dependencies.newStatusRPC(statusService)
	if vnextReaderPreparedStatusNilInterface(statusRPC) {
		return nil, cleanupReader(errors.New(
			"VNext Reader STATUS_AND_FENCE RPC constructor returned nil"))
	}
	identifyRPC := dependencies.newIdentifyRPC(identifyService)
	if vnextReaderPreparedStatusNilInterface(identifyRPC) {
		return nil, cleanupReader(errors.New(
			"VNext Reader IDENTIFY RPC constructor returned nil"))
	}
	tlsConfig := vnextReaderPrepareTLSServerConfig{
		ListenAddress:         canonical.TLS.ListenAddress,
		ServerCertificatePath: canonical.TLS.ServerCertificatePath,
		ServerPrivateKeyPath:  canonical.TLS.ServerPrivateKeyPath,
		ClientCAPath:          canonical.TLS.ClientCAPath,
		ExpectedServerURISAN:  canonical.TLS.ExpectedServerURISAN,
		SchedulerByPrincipal:  canonical.SchedulerByPrincipal,
		HandshakeTimeout:      canonical.TLS.HandshakeTimeout,
		RequestReadTimeout:    canonical.TLS.RequestReadTimeout,
		HandlerTimeout:        canonical.TLS.HandlerTimeout,
		ResponseWriteTimeout:  canonical.TLS.ResponseWriteTimeout,
	}
	if err := dependencies.processIncarnationWriter.Publish(
		dependencies.processIncarnationPath, processIncarnation); err != nil {
		primary := fmt.Errorf(
			"publish VNext Reader process incarnation: %w", err)
		if cleanupErr := processLock.RemovePublishedIdentity(
			processIncarnation, false); cleanupErr != nil {
			primary = appendVNextReaderPrepareRuntimeError(
				primary,
				fmt.Errorf("clean partial VNext Reader process incarnation: %w",
					cleanupErr))
		}
		return nil, cleanupReader(primary)
	}
	server, err := dependencies.startServer(
		tlsConfig, rpc, statusRPC, identifyRPC,
		requestAdmission, largeAdmission)
	if err != nil || server == nil {
		primary := err
		if primary == nil {
			primary = errors.New(
				"VNext Reader PREPARE TLS server constructor returned nil")
		}
		if server != nil {
			if stopErr := server.Stop(); stopErr != nil {
				primary = appendVNextReaderPrepareRuntimeError(
					primary, fmt.Errorf("stop partial Reader PREPARE TLS server: %w", stopErr))
			}
			server.Wait()
		}
		if cleanupErr := processLock.RemovePublishedIdentity(
			processIncarnation, true); cleanupErr != nil {
			primary = appendVNextReaderPrepareRuntimeError(
				primary,
				fmt.Errorf("clean failed VNext Reader process incarnation: %w",
					cleanupErr))
		}
		return nil, cleanupReader(primary)
	}
	return &vnextReaderPrepareRuntime{
		store:                  store,
		verifier:               verifier,
		service:                service,
		rpc:                    rpc,
		statusVerifier:         statusVerifier,
		statusService:          statusService,
		statusRPC:              statusRPC,
		processIncarnation:     processIncarnation,
		processIncarnationLock: processLock,
		identifyVerifier:       identifyVerifier,
		identifyService:        identifyService,
		identifyRPC:            identifyRPC,
		server:                 server,
		closeLeaderReader:      closeReader,
		requestAdmission:       requestAdmission,
		largeFrameAdmission:    largeAdmission,
		schedulerByPrincipal:   canonical.SchedulerByPrincipal,
	}, nil
}

// openVNextReaderPrepareIndependentLeaderReader always creates a dedicated
// etcd client. It reuses only the exact linearizable reader implementation and
// never borrows or aliases the Owner authority client.
func openVNextReaderPrepareIndependentLeaderReader(
	config vnextOwnerSchedulerAuthorityConfig,
) (vnextOwnerSchedulerLeaderReader, func() error, error) {
	if err := validateVNextOwnerSchedulerAuthorityConfig(config, true); err != nil {
		return nil, nil, err
	}
	tlsConfig, err := loadVNextOwnerSchedulerEtcdTLS(config)
	if err != nil {
		return nil, nil, err
	}
	client, err := clientv3.New(clientv3.Config{
		Endpoints:        append([]string(nil), config.Endpoints...),
		DialTimeout:      config.DialTimeout,
		TLS:              tlsConfig,
		RejectOldCluster: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf(
			"open independent VNext Reader PREPARE etcd client: %w", err)
	}
	return &vnextOwnerSchedulerEtcdReader{kv: client}, client.Close, nil
}

// Stop closes only the Reader listener. Close remains responsible for actual
// handler drain followed by the independent etcd client close.
func (runtime *vnextReaderPrepareRuntime) Stop() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed || runtime.stopCalled {
		return runtime.stopErr
	}
	runtime.stopCalled = true
	if runtime.server != nil {
		runtime.stopErr = runtime.server.Stop()
	}
	return runtime.stopErr
}

// Close is terminal and ordered: listener Stop, actual handler Wait, then the
// independent etcd client close. It continues through every stage on error.
func (runtime *vnextReaderPrepareRuntime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if runtime.closed {
		return nil
	}
	if !runtime.stopCalled {
		runtime.stopCalled = true
		if runtime.server != nil {
			runtime.stopErr = runtime.server.Stop()
		}
	}
	closeErr := runtime.stopErr
	if runtime.server != nil {
		runtime.server.Wait()
	}
	if runtime.closeLeaderReader != nil {
		if err := runtime.closeLeaderReader(); err != nil {
			closeErr = appendVNextReaderPrepareRuntimeError(
				closeErr, fmt.Errorf("close VNext Reader PREPARE etcd reader: %w", err))
		}
	}
	if runtime.processIncarnationLock != nil {
		if err := runtime.processIncarnationLock.RemovePublishedIdentity(
			runtime.processIncarnation, true); err != nil {
			closeErr = appendVNextReaderPrepareRuntimeError(
				closeErr,
				fmt.Errorf("remove closed VNext Reader process incarnation: %w", err))
		}
		if err := runtime.processIncarnationLock.Release(); err != nil {
			closeErr = appendVNextReaderPrepareRuntimeError(
				closeErr,
				fmt.Errorf("release VNext Reader process-incarnation lock: %w", err))
		}
	}
	runtime.server = nil
	runtime.closeLeaderReader = nil
	runtime.service = nil
	runtime.rpc = nil
	runtime.verifier = nil
	runtime.statusRPC = nil
	runtime.statusService = nil
	runtime.statusVerifier = nil
	runtime.identifyRPC = nil
	runtime.identifyService = nil
	runtime.identifyVerifier = nil
	runtime.processIncarnation = vnextReaderProcessIncarnation{}
	runtime.processIncarnationLock = nil
	runtime.store = nil
	runtime.closed = true
	return closeErr
}

var _ vnextReaderPrepareClock = vnextReaderPrepareSystemClock{}
var _ vnextReaderPrepareRuntimeServer = (*vnextReaderPrepareTLSServer)(nil)
var _ vnextOwnerSchedulerLeaderReader = (*vnextOwnerSchedulerEtcdReader)(nil)
