package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

const (
	vnextOwnerGatewayProtocol            = "cxld.vnext-owner-gateway.v1"
	vnextOwnerGatewayMaxRouteFileBytes   = 1 << 20
	vnextOwnerGatewayMaxRoutes           = 4096
	vnextOwnerGatewayMaxConcurrentRemote = 32
	// This is only a bounded wait for the authenticated response. Cancellation
	// does not claim to roll back an Owner mutation that already crossed the
	// remote admission boundary; recovery remains driven by durable identity.
	vnextOwnerGatewayRemoteRequestTimeout = 2 * time.Minute
)

var activeVNextOwnerGateway *vnextOwnerGateway

// vnextOwnerGatewayConfig has independent, role-bound outbound identities.
// There is intentionally no shared certificate fallback: a route can be used
// only when the authenticated inbound role has a configured transport for the
// same role.
type vnextOwnerGatewayConfig struct {
	RouteFilePath                  string
	SchedulerClientCertificatePath string
	SchedulerClientPrivateKeyPath  string
	ProducerClientCertificatePath  string
	ProducerClientPrivateKeyPath   string
	ServerCAPath                   string
}

type vnextOwnerGatewayRouteKey struct {
	OwnerID    string
	OwnerEpoch uint64
}

type vnextOwnerGatewayRouteWire struct {
	OwnerID      string `json:"ownerId"`
	OwnerEpoch   uint64 `json:"ownerEpoch"`
	Endpoint     string `json:"endpoint"`
	ServerName   string `json:"serverName"`
	ServerURISAN string `json:"serverUriSan"`
}

type vnextOwnerGatewayRouteWires []vnextOwnerGatewayRouteWire

type vnextOwnerGatewayRouteFile struct {
	Protocol string                      `json:"protocol"`
	Routes   vnextOwnerGatewayRouteWires `json:"routes"`
}

type vnextOwnerGatewayRoute struct {
	transports map[vnextOwnerCallerRole]vnextOwnerClientRoundTripper
}

type vnextOwnerGateway struct {
	mu              sync.RWMutex
	closed          bool
	localRPC        *vnextOwnerRPC
	localKey        *vnextOwnerGatewayRouteKey
	routes          map[vnextOwnerGatewayRouteKey]vnextOwnerGatewayRoute
	remoteAdmission chan struct{}
}

type vnextOwnerGatewayDependencies struct {
	loadRouteFile func(string) ([]byte, error)
	newTransport  func(vnextOwnerTLSClientConfig) (vnextOwnerClientRoundTripper, error)
}

type vnextOwnerGatewayCredential struct {
	certificatePath string
	privateKeyPath  string
}

func vnextOwnerGatewayCredentials(
	config vnextOwnerGatewayConfig,
) (map[vnextOwnerCallerRole]vnextOwnerGatewayCredential, error) {
	credentials := make(map[vnextOwnerCallerRole]vnextOwnerGatewayCredential, 2)
	add := func(
		role vnextOwnerCallerRole,
		certificatePath string,
		privateKeyPath string,
	) error {
		if certificatePath == "" && privateKeyPath == "" {
			return nil
		}
		if certificatePath == "" || privateKeyPath == "" {
			return fmt.Errorf(
				"VNext Owner gateway %s client certificate and private key must be configured together",
				role)
		}
		credentials[role] = vnextOwnerGatewayCredential{
			certificatePath: certificatePath,
			privateKeyPath:  privateKeyPath,
		}
		return nil
	}
	if err := add(
		vnextOwnerCallerScheduler,
		config.SchedulerClientCertificatePath,
		config.SchedulerClientPrivateKeyPath); err != nil {
		return nil, err
	}
	if err := add(
		vnextOwnerCallerProducer,
		config.ProducerClientCertificatePath,
		config.ProducerClientPrivateKeyPath); err != nil {
		return nil, err
	}
	if len(credentials) == 0 {
		return nil, errors.New(
			"VNext Owner gateway requires at least one complete Scheduler or Producer client identity")
	}
	if len(credentials) == 2 {
		scheduler := credentials[vnextOwnerCallerScheduler]
		producer := credentials[vnextOwnerCallerProducer]
		if scheduler.certificatePath == producer.certificatePath ||
			scheduler.privateKeyPath == producer.privateKeyPath {
			return nil, errors.New(
				"VNext Owner gateway Scheduler and Producer client identities must use distinct certificate and key paths")
		}
	}
	return credentials, nil
}

func defaultVNextOwnerGatewayDependencies() vnextOwnerGatewayDependencies {
	return vnextOwnerGatewayDependencies{
		loadRouteFile: readSecureVNextOwnerGatewayRouteFile,
		newTransport: func(config vnextOwnerTLSClientConfig) (vnextOwnerClientRoundTripper, error) {
			return newVNextOwnerTLSRoundTripper(config)
		},
	}
}

func openVNextOwnerGateway(
	config vnextOwnerGatewayConfig,
	localRPC *vnextOwnerRPC,
) (*vnextOwnerGateway, error) {
	return openVNextOwnerGatewayWithDependencies(
		config, localRPC, defaultVNextOwnerGatewayDependencies())
}

func openVNextOwnerGatewayWithDependencies(
	config vnextOwnerGatewayConfig,
	localRPC *vnextOwnerRPC,
	dependencies vnextOwnerGatewayDependencies,
) (*vnextOwnerGateway, error) {
	if config.RouteFilePath == "" && config.ServerCAPath == "" &&
		config.SchedulerClientCertificatePath == "" &&
		config.SchedulerClientPrivateKeyPath == "" &&
		config.ProducerClientCertificatePath == "" &&
		config.ProducerClientPrivateKeyPath == "" {
		return nil, nil
	}
	if config.RouteFilePath == "" || config.ServerCAPath == "" {
		return nil, errors.New(
			"VNext Owner gateway requires route file and server CA together")
	}
	credentials, err := vnextOwnerGatewayCredentials(config)
	if err != nil {
		return nil, err
	}
	for role, path := range map[string]string{
		"gateway route file": config.RouteFilePath,
		"gateway server CA":  config.ServerCAPath,
	} {
		if err := validateVNextOwnerRuntimePath(path, role); err != nil {
			return nil, err
		}
	}
	for role, credential := range credentials {
		for kind, path := range map[string]string{
			"client certificate": credential.certificatePath,
			"client private key": credential.privateKeyPath,
		} {
			if err := validateVNextOwnerRuntimePath(
				path, fmt.Sprintf("gateway %s %s", role, kind)); err != nil {
				return nil, err
			}
		}
	}
	if dependencies.loadRouteFile == nil || dependencies.newTransport == nil {
		return nil, errors.New("VNext Owner gateway dependencies are incomplete")
	}

	raw, err := dependencies.loadRouteFile(config.RouteFilePath)
	if err != nil {
		return nil, err
	}
	var routeFile vnextOwnerGatewayRouteFile
	if err := decodeStrictVNextOwnerRPC(raw, &routeFile); err != nil {
		return nil, fmt.Errorf("decode VNext Owner gateway route file: %w", err)
	}
	if routeFile.Protocol != vnextOwnerGatewayProtocol {
		return nil, fmt.Errorf(
			"VNext Owner gateway protocol is %q, expected %q",
			routeFile.Protocol, vnextOwnerGatewayProtocol)
	}
	if len(routeFile.Routes) == 0 || len(routeFile.Routes) > vnextOwnerGatewayMaxRoutes {
		return nil, fmt.Errorf(
			"VNext Owner gateway route count %d is outside 1..%d",
			len(routeFile.Routes), vnextOwnerGatewayMaxRoutes)
	}

	localKey, err := vnextOwnerGatewayLocalKey(localRPC)
	if err != nil {
		return nil, err
	}
	gateway := &vnextOwnerGateway{
		localRPC:        localRPC,
		localKey:        localKey,
		routes:          make(map[vnextOwnerGatewayRouteKey]vnextOwnerGatewayRoute, len(routeFile.Routes)),
		remoteAdmission: make(chan struct{}, vnextOwnerGatewayMaxConcurrentRemote),
	}
	seenEndpoints := make(map[string]struct{}, len(routeFile.Routes))
	for index, wire := range routeFile.Routes {
		key := vnextOwnerGatewayRouteKey{OwnerID: wire.OwnerID, OwnerEpoch: wire.OwnerEpoch}
		if err := validateVNextOwnerClientText("gateway Owner ID", key.OwnerID); err != nil {
			return nil, fmt.Errorf("gateway route %d: %w", index, err)
		}
		if key.OwnerEpoch == 0 || key.OwnerEpoch > uint64(math.MaxInt64) {
			return nil, fmt.Errorf(
				"gateway route %d Owner epoch is outside the signed ABI", index)
		}
		if err := validateVNextOwnerTLSEndpoint(wire.Endpoint); err != nil {
			return nil, fmt.Errorf("gateway route %d: %w", index, err)
		}
		if wire.ServerName == "" || strings.TrimSpace(wire.ServerName) != wire.ServerName ||
			strings.IndexFunc(wire.ServerName, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("gateway route %d has an invalid server name", index)
		}
		if err := validateVNextOwnerTLSURI(wire.ServerURISAN, "gateway server URI SAN"); err != nil {
			return nil, fmt.Errorf("gateway route %d: %w", index, err)
		}
		if _, duplicate := gateway.routes[key]; duplicate {
			return nil, fmt.Errorf(
				"gateway route %d duplicates Owner incarnation %q/%d",
				index, key.OwnerID, key.OwnerEpoch)
		}
		if localKey != nil && key == *localKey {
			return nil, fmt.Errorf(
				"gateway route %d shadows the local Owner incarnation %q/%d",
				index, key.OwnerID, key.OwnerEpoch)
		}
		if _, duplicate := seenEndpoints[wire.Endpoint]; duplicate {
			return nil, fmt.Errorf(
				"gateway route %d duplicates endpoint %q", index, wire.Endpoint)
		}
		transports := make(map[vnextOwnerCallerRole]vnextOwnerClientRoundTripper, len(credentials))
		for role, credential := range credentials {
			transport, err := dependencies.newTransport(vnextOwnerTLSClientConfig{
				Endpoint:              wire.Endpoint,
				ServerName:            wire.ServerName,
				ClientCertificatePath: credential.certificatePath,
				ClientPrivateKeyPath:  credential.privateKeyPath,
				ServerCAPath:          config.ServerCAPath,
				ExpectedServerURISAN:  wire.ServerURISAN,
				CallerRole:            role,
			})
			if err != nil {
				return nil, fmt.Errorf(
					"initialize gateway route %d %s transport: %w", index, role, err)
			}
			if transport == nil || vnextProducerInterfaceIsNil(transport) {
				return nil, fmt.Errorf(
					"initialize gateway route %d %s transport: transport is unavailable",
					index, role)
			}
			transports[role] = transport
		}
		gateway.routes[key] = vnextOwnerGatewayRoute{transports: transports}
		seenEndpoints[wire.Endpoint] = struct{}{}
	}
	return gateway, nil
}

func readSecureVNextOwnerGatewayRouteFile(path string) ([]byte, error) {
	if err := validateVNextOwnerRuntimePath(path, "gateway route file"); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect VNext Owner gateway route file: %w", err)
	}
	// The route file itself is the trust boundary: it selects the endpoint and
	// TLS identity pins. Parent-directory policy is left to deployment, while
	// this file must be owned by the cxld effective UID and not writable by a
	// different Unix identity.
	if err := validateVNextOwnerGatewayRouteFileMetadata(before, os.Geteuid()); err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open VNext Owner gateway route file: %w", err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat open VNext Owner gateway route file: %w", err)
	}
	if err := validateVNextOwnerGatewayRouteFileMetadata(opened, os.Geteuid()); err != nil {
		return nil, err
	}
	if err := validateVNextOwnerGatewayRouteFileStable(before, opened); err != nil {
		return nil, fmt.Errorf("VNext Owner gateway route file changed while opening: %w", err)
	}
	if opened.Size() <= 0 || opened.Size() > vnextOwnerGatewayMaxRouteFileBytes {
		return nil, fmt.Errorf(
			"VNext Owner gateway route file size %d is outside 1..%d",
			opened.Size(), vnextOwnerGatewayMaxRouteFileBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(file, vnextOwnerGatewayMaxRouteFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read VNext Owner gateway route file: %w", err)
	}
	afterRead, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("re-stat VNext Owner gateway route file after read: %w", err)
	}
	if err := validateVNextOwnerGatewayRouteFileMetadata(afterRead, os.Geteuid()); err != nil {
		return nil, err
	}
	if err := validateVNextOwnerGatewayRouteFileStable(opened, afterRead); err != nil {
		return nil, fmt.Errorf("VNext Owner gateway route file changed while reading: %w", err)
	}
	if len(raw) == 0 || len(raw) > vnextOwnerGatewayMaxRouteFileBytes {
		return nil, fmt.Errorf(
			"VNext Owner gateway route file size %d is outside 1..%d",
			len(raw), vnextOwnerGatewayMaxRouteFileBytes)
	}
	if int64(len(raw)) != opened.Size() {
		return nil, errors.New(
			"VNext Owner gateway route file byte count changed while reading")
	}
	return raw, nil
}

func validateVNextOwnerGatewayRouteFileMetadata(
	info os.FileInfo,
	effectiveUID int,
) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&0o022 != 0 {
		return errors.New(
			"VNext Owner gateway route file must be regular and not group/world writable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return errors.New("VNext Owner gateway route file owner UID is unavailable")
	}
	return validateVNextOwnerGatewayRouteFileOwner(stat.Uid, effectiveUID)
}

func validateVNextOwnerGatewayRouteFileOwner(ownerUID uint32, effectiveUID int) error {
	if effectiveUID < 0 || uint64(ownerUID) != uint64(effectiveUID) {
		return fmt.Errorf(
			"VNext Owner gateway route file owner UID %d does not match effective UID %d",
			ownerUID, effectiveUID)
	}
	return nil
}

func validateVNextOwnerGatewayRouteFileStable(
	before os.FileInfo,
	after os.FileInfo,
) error {
	if before == nil || after == nil || !os.SameFile(before, after) {
		return errors.New("route file identity changed")
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if !beforeOK || !afterOK || beforeStat == nil || afterStat == nil {
		return errors.New("route file Unix metadata is unavailable")
	}
	if before.Size() != after.Size() || before.Mode() != after.Mode() ||
		beforeStat.Uid != afterStat.Uid || !before.ModTime().Equal(after.ModTime()) ||
		beforeStat.Mtim != afterStat.Mtim || beforeStat.Ctim != afterStat.Ctim {
		return errors.New("route file size, mode, owner, or change time changed")
	}
	return nil
}

func vnextOwnerGatewayLocalKey(
	rpc *vnextOwnerRPC,
) (*vnextOwnerGatewayRouteKey, error) {
	if rpc == nil || rpc.service == nil || rpc.service.group == nil {
		return nil, nil
	}
	group := rpc.service.group
	group.mu.Lock()
	defer group.mu.Unlock()
	if err := group.checkUsableLocked(); err != nil {
		return nil, fmt.Errorf("inspect local VNext Owner identity: %w", err)
	}
	if err := validateVNextOwnerClientText("local Owner ID", group.ownerID); err != nil {
		return nil, err
	}
	if group.ownerEpoch == 0 || group.ownerEpoch > uint64(math.MaxInt64) {
		return nil, errors.New("local Owner epoch is outside the signed ABI")
	}
	key := vnextOwnerGatewayRouteKey{OwnerID: group.ownerID, OwnerEpoch: group.ownerEpoch}
	return &key, nil
}

type vnextOwnerGatewayCall struct {
	key    vnextOwnerGatewayRouteKey
	invoke func(context.Context, *vnextOwnerClient) error
}

func decodeVNextOwnerGatewayCall(
	operation string,
	request daemonRequest,
) (vnextOwnerGatewayCall, error) {
	if request.Operation != operation {
		return vnextOwnerGatewayCall{}, errors.New(
			"VNext Owner gateway operation must be exact and have no surrounding whitespace")
	}
	if request.TimeoutMillis != 0 {
		return vnextOwnerGatewayCall{}, errors.New(
			"VNext Owner protocol v5 does not support timeoutMillis; it must be zero")
	}
	raw, err := vnextOwnerRPCPayload(operation, request)
	if err != nil {
		return vnextOwnerGatewayCall{}, err
	}
	switch operation {
	case vnextOwnerRPCOperationAdmissionStatus:
		decoded, err := decodeVNextOwnerRPCAdmissionStatusRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.OwnerID, decoded.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.AdmissionStatus(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationSetAdmission:
		decoded, err := decodeVNextOwnerRPCSetAdmissionRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.OwnerID, decoded.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.SetAdmission(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationInventory:
		decoded, err := decodeVNextOwnerRPCInventoryRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.OwnerID, decoded.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.Inventory(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationReserve:
		decoded, err := decodeVNextOwnerRPCReserveRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.OwnerID, decoded.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.Reserve(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationReservationStatus:
		decoded, err := decodeVNextOwnerRPCReservationStatusRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.OwnerID, decoded.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.ReservationStatus(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationIssueProducerCapability:
		decoded, err := decodeVNextOwnerRPCIssueProducerCapabilityRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.Operation.OwnerID, decoded.Operation.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.IssueProducerCapability(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence:
		decoded, err := decodeVNextOwnerRPCProducerCapabilityIssueStatusAndFenceRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{
				decoded.Operation.OwnerID, decoded.Operation.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.ProducerCapabilityIssueStatusAndFence(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationRevokeProducerCapability:
		decoded, err := decodeVNextOwnerRPCRevokeProducerCapabilityRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.Operation.OwnerID, decoded.Operation.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.RevokeProducerCapability(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationSeal:
		decoded, err := decodeVNextOwnerRPCSealRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{decoded.Operation.OwnerID, decoded.Operation.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				_, err := client.SealVNextCheckpoint(ctx, decoded)
				return err
			},
		}, nil
	case vnextOwnerRPCOperationProducerAbort:
		identity, capability, err := decodeVNextOwnerRPCProducerAbortRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{identity.OwnerID, identity.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				return client.ProducerAbortVNextCheckpoint(ctx, identity, capability)
			},
		}, nil
	case vnextOwnerRPCOperationCommit, vnextOwnerRPCOperationAbort:
		decoded, err := decodeVNextOwnerRPCLifecycleRequest(raw)
		if err != nil {
			return vnextOwnerGatewayCall{}, err
		}
		return vnextOwnerGatewayCall{
			key: vnextOwnerGatewayRouteKey{
				decoded.Operation.OwnerID, decoded.Operation.OwnerEpoch},
			invoke: func(ctx context.Context, client *vnextOwnerClient) error {
				if operation == vnextOwnerRPCOperationCommit {
					return client.CommitVNextCheckpoint(
						ctx, decoded.Operation, decoded.SchedulerAuthority)
				}
				return client.AbortVNextCheckpoint(
					ctx, decoded.Operation, decoded.SchedulerAuthority)
			},
		}, nil
	default:
		return vnextOwnerGatewayCall{}, fmt.Errorf(
			"unsupported VNext Owner gateway operation %q", operation)
	}
}

type vnextOwnerGatewayCaptureTransport struct {
	delegate vnextOwnerClientRoundTripper
	called   bool
	response execResponse
}

func (transport *vnextOwnerGatewayCaptureTransport) RoundTrip(
	ctx context.Context,
	request daemonRequest,
) (execResponse, error) {
	if transport.called {
		return execResponse{}, errors.New("VNext Owner gateway client attempted multiple round trips")
	}
	transport.called = true
	response, err := transport.delegate.RoundTrip(ctx, request)
	if err == nil {
		transport.response = response
	}
	return response, err
}

func (gateway *vnextOwnerGateway) dispatch(
	request daemonRequest,
	callerRole vnextOwnerCallerRole,
) execResponse {
	return gateway.dispatchCaller(request, vnextOwnerInternalCaller(callerRole))
}

func (gateway *vnextOwnerGateway) dispatchCaller(
	request daemonRequest,
	caller vnextOwnerCallerContext,
) execResponse {
	startedAt := time.Now()
	operation := strings.TrimSpace(request.Operation)
	failure := func(code vnextOwnerServiceErrorCode, detail string, cause error) execResponse {
		response := vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
			"gateway", code, detail, cause))
		response.Operation = operation
		response.DurationMicros = elapsedMicros(startedAt)
		return response
	}
	if !isVNextOwnerRPCOperation(operation) {
		return failure(vnextOwnerServiceInvalidRequest,
			"operation is not a strict VNext Owner operation", nil)
	}
	if err := caller.validate(); err != nil {
		return failure(vnextOwnerServicePermissionDenied,
			"caller principal is not authenticated", err)
	}
	if err := authorizeVNextOwnerOperation(caller.Role, operation); err != nil {
		return failure(vnextOwnerServicePermissionDenied,
			"caller is not authorized for this Owner operation", err)
	}
	call, err := decodeVNextOwnerGatewayCall(operation, request)
	if err != nil {
		return failure(vnextOwnerServiceInvalidRequest, "request is invalid", err)
	}

	gateway.mu.RLock()
	if gateway.closed {
		gateway.mu.RUnlock()
		return failure(vnextOwnerServiceUnavailable, "gateway is closed", nil)
	}
	local := gateway.localKey != nil && call.key == *gateway.localKey
	route, routed := gateway.routes[call.key]
	localRPC := gateway.localRPC
	gateway.mu.RUnlock()
	if local {
		// The exact local incarnation is always authoritative in-process. No
		// route-file entry may shadow it, and this branch performs no network I/O.
		response := runCommandWithVNextOwnerRPCCaller(request, localRPC, caller)
		response.Operation = operation
		if response.DurationMicros < 0 {
			response.DurationMicros = 0
		}
		return response
	}
	if !routed {
		return failure(
			vnextOwnerServiceIdentityMismatch,
			fmt.Sprintf("no exact route for Owner incarnation %q/%d", call.key.OwnerID, call.key.OwnerEpoch),
			errVNextAuthority)
	}
	transport, transportConfigured := route.transports[caller.Role]
	if !transportConfigured || transport == nil || vnextProducerInterfaceIsNil(transport) {
		return failure(
			vnextOwnerServicePermissionDenied,
			fmt.Sprintf("no %s gateway identity is configured", caller.Role),
			nil)
	}
	select {
	case gateway.remoteAdmission <- struct{}{}:
		defer func() { <-gateway.remoteAdmission }()
	default:
		return failure(vnextOwnerServiceUnavailable,
			"remote Owner gateway concurrency limit is exhausted", nil)
	}

	capture := &vnextOwnerGatewayCaptureTransport{delegate: transport}
	// A remote hop is a new authenticated principal. In particular, a Producer
	// capability routed remotely must name the URI SAN of this gateway's
	// outbound Producer certificate. This gateway deliberately provides no
	// delegation proof and does not claim to preserve the inbound Unix UID or
	// TLS URI SAN across the hop.
	client, err := newVNextOwnerClient(capture)
	if err != nil {
		return failure(vnextOwnerServiceUnavailable,
			"remote Owner client is unavailable", err)
	}
	ctx, cancel := context.WithTimeout(
		context.Background(), vnextOwnerGatewayRemoteRequestTimeout)
	defer cancel()
	err = call.invoke(ctx, client)
	if err != nil {
		var remoteError *vnextOwnerClientRemoteError
		if errors.As(err, &remoteError) && capture.called &&
			validateVNextOwnerGatewayFailure(capture.response, operation) == nil {
			return capture.response
		}
		return failure(vnextOwnerServiceUnavailable,
			"remote Owner transport or response validation failed", err)
	}
	if !capture.called {
		return failure(vnextOwnerServiceUnavailable,
			"remote Owner client completed without a transport response", nil)
	}
	if err := validateVNextOwnerGatewaySuccess(capture.response, operation); err != nil {
		return failure(vnextOwnerServiceUnavailable,
			"remote Owner response failed outer validation", err)
	}
	// The strict client above has already validated protocol, operation,
	// identity, signed ranges, cardinality, and the operation-specific body.
	// Preserve the authenticated Owner's bounded outer response unchanged.
	return capture.response
}

func runCommandWithVNextOwnerGatewayRole(
	request daemonRequest,
	localRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	callerRole vnextOwnerCallerRole,
) execResponse {
	return runCommandWithVNextOwnerGatewayCaller(
		request, localRPC, gateway, vnextOwnerInternalCaller(callerRole))
}

func runCommandWithVNextOwnerGatewayCaller(
	request daemonRequest,
	localRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	caller vnextOwnerCallerContext,
) execResponse {
	operation := daemonRequestOperation(request)
	if gateway != nil && isVNextOwnerRPCOperation(operation) {
		return gateway.dispatchCaller(request, caller)
	}
	return runCommandWithVNextOwnerBoundaryCaller(
		request, localRPC, localRPC != nil || gateway != nil, caller)
}

func validateVNextOwnerGatewaySuccess(response execResponse, operation string) error {
	if !response.Ok || response.Operation != operation || response.DurationMicros < 0 ||
		response.Error != "" || response.ErrorCode != "" || response.Stderr != "" ||
		response.ExitCode != 0 || response.Stdout == "" || response.TimingsMicros != nil {
		return errors.New("remote VNext Owner success envelope is inconsistent")
	}
	_, err := marshalVNextOwnerTLSExecResponse(response)
	return err
}

func validateVNextOwnerGatewayFailure(response execResponse, operation string) error {
	if response.Ok || response.Operation != operation || response.DurationMicros < 0 ||
		response.Stdout != "" || response.Error == "" || response.ErrorCode == "" ||
		response.TimingsMicros != nil {
		return errors.New("remote VNext Owner failure envelope is inconsistent")
	}
	_, err := marshalVNextOwnerTLSExecResponse(response)
	return err
}

func (gateway *vnextOwnerGateway) Close() error {
	if gateway == nil {
		return nil
	}
	gateway.mu.Lock()
	gateway.closed = true
	gateway.mu.Unlock()
	return nil
}
