package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type vnextOwnerGatewayTestTransport struct {
	roundTrip func(context.Context, daemonRequest) (execResponse, error)
}

func (transport *vnextOwnerGatewayTestTransport) RoundTrip(
	ctx context.Context,
	request daemonRequest,
) (execResponse, error) {
	return transport.roundTrip(ctx, request)
}

func vnextOwnerGatewayTestRouteFile(
	ownerID string,
	ownerEpoch uint64,
	endpoint string,
) []byte {
	return []byte(fmt.Sprintf(
		`{"protocol":%q,"routes":[{"ownerId":%q,"ownerEpoch":%d,"endpoint":%q,"serverName":"owner.test","serverUriSan":"spiffe://trenv.test/owner/owner-0"}]}`,
		vnextOwnerGatewayProtocol, ownerID, ownerEpoch, endpoint))
}

func vnextOwnerGatewayTestConfig(routePath string) vnextOwnerGatewayConfig {
	return vnextOwnerGatewayConfig{
		RouteFilePath:                  routePath,
		SchedulerClientCertificatePath: "/test/scheduler-client.pem",
		SchedulerClientPrivateKeyPath:  "/test/scheduler-client-key.pem",
		ServerCAPath:                   "/test/ca.pem",
	}
}

func openVNextOwnerGatewayForTest(
	t *testing.T,
	raw []byte,
	localRPC *vnextOwnerRPC,
	transport vnextOwnerClientRoundTripper,
) *vnextOwnerGateway {
	t.Helper()
	gateway, err := openVNextOwnerGatewayWithDependencies(
		vnextOwnerGatewayTestConfig("/test/routes.json"),
		localRPC,
		vnextOwnerGatewayDependencies{
			loadRouteFile: func(string) ([]byte, error) {
				return append([]byte(nil), raw...), nil
			},
			newTransport: func(vnextOwnerTLSClientConfig) (vnextOwnerClientRoundTripper, error) {
				return transport, nil
			},
		})
	if err != nil {
		t.Fatalf("open test VNext Owner gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })
	return gateway
}

func vnextOwnerGatewayTestInventoryDaemonRequest(
	t *testing.T,
	ownerID string,
	ownerEpoch uint64,
	requestID string,
) daemonRequest {
	t.Helper()
	raw, err := json.Marshal(vnextOwnerRPCInventoryRequest{
		Protocol:           vnextOwnerRPCProtocol,
		RequestID:          requestID,
		ExpectedOwnerID:    ownerID,
		ExpectedOwnerEpoch: ownerEpoch,
	})
	if err != nil {
		t.Fatalf("marshal inventory request: %v", err)
	}
	return daemonRequest{
		CommandLabel:        "scheduler-gateway-test",
		Operation:           vnextOwnerRPCOperationInventory,
		VNextOwnerInventory: raw,
	}
}

func vnextOwnerGatewayTestReserveDaemonRequest(
	t *testing.T,
	wire vnextOwnerRPCReserveRequest,
) daemonRequest {
	t.Helper()
	raw := marshalVNextOwnerRPCTestPayload(t, wire)
	return daemonRequest{
		CommandLabel:      "scheduler-gateway-test",
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: raw,
	}
}

func vnextOwnerGatewayTestReservationStatusDaemonRequest(
	t *testing.T,
	request vnextOwnerReserveRequest,
) daemonRequest {
	t.Helper()
	_, wire, err := vnextOwnerClientReserveRequestWire(request)
	if err != nil {
		t.Fatalf("validate gateway reservation-status request: %v", err)
	}
	raw, err := json.Marshal(vnextOwnerRPCReservationStatusRequest{
		Protocol: wire.Protocol, RequestID: wire.RequestID,
		CheckpointID: wire.CheckpointID, ProducerID: wire.ProducerID,
		OwnerID: wire.OwnerID, OwnerEpoch: wire.OwnerEpoch,
		Contents: wire.Contents, MaxExtents: wire.MaxExtents,
	})
	if err != nil {
		t.Fatalf("marshal gateway reservation-status request: %v", err)
	}
	return daemonRequest{
		CommandLabel:                "scheduler-gateway-test",
		Operation:                   vnextOwnerRPCOperationReservationStatus,
		VNextOwnerReservationStatus: raw,
	}
}

func vnextOwnerGatewayTestLifecycleDaemonRequest(
	t *testing.T,
	operation string,
) daemonRequest {
	t.Helper()
	identity := vnextOwnerRPCOperationIdentity{
		RequestID:          "gateway-lifecycle-request",
		CheckpointID:       "gateway-lifecycle-checkpoint",
		ProducerID:         "gateway-lifecycle-producer",
		OwnerID:            "owner-0",
		OwnerEpoch:         7,
		AllocationRecordID: 1,
	}
	var body interface{} = vnextOwnerRPCLifecycleRequest{
		Protocol: vnextOwnerRPCProtocol,
		Identity: identity,
	}
	if operation == vnextOwnerRPCOperationProducerAbort {
		body = vnextOwnerRPCProducerAbortRequest{
			Protocol: vnextOwnerRPCProtocol,
			Identity: identity,
			Capability: vnextOwnerRPCProducerCapabilityProof{
				CapabilityID: "00000000000000000000000000000001",
				Token:        bytes.Repeat([]byte{1}, vnextProducerCapabilityTokenBytes),
			},
		}
	} else {
		body = vnextOwnerRPCLifecycleRequest{
			Protocol: vnextOwnerRPCProtocol,
			Identity: identity,
			SchedulerAuthority: vnextOwnerTestSchedulerAuthority(
				operation, identity.internal()),
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := daemonRequest{
		CommandLabel: "gateway-role-test",
		Operation:    operation,
	}
	switch operation {
	case vnextOwnerRPCOperationCommit:
		request.VNextOwnerCommit = raw
	case vnextOwnerRPCOperationAbort:
		request.VNextOwnerAbort = raw
	case vnextOwnerRPCOperationProducerAbort:
		request.VNextOwnerProducerAbort = raw
	default:
		t.Fatalf("unsupported lifecycle test operation %q", operation)
	}
	return request
}

func vnextOwnerGatewayTestInventoryTransport(
	calls *int64,
	entered chan<- struct{},
	release <-chan struct{},
) *vnextOwnerGatewayTestTransport {
	return &vnextOwnerGatewayTestTransport{roundTrip: func(
		ctx context.Context,
		request daemonRequest,
	) (execResponse, error) {
		if calls != nil {
			atomic.AddInt64(calls, 1)
		}
		if entered != nil {
			select {
			case entered <- struct{}{}:
			case <-ctx.Done():
				return execResponse{}, ctx.Err()
			}
		}
		if release != nil {
			select {
			case <-release:
			case <-ctx.Done():
				return execResponse{}, ctx.Err()
			}
		}
		decoded, err := decodeVNextOwnerRPCInventoryRequest(request.VNextOwnerInventory)
		if err != nil {
			return execResponse{}, err
		}
		response := vnextOwnerRPCInventoryResponse{
			Protocol:         vnextOwnerRPCProtocol,
			Operation:        vnextOwnerRPCOperationInventory,
			RequestID:        decoded.RequestID,
			OwnerID:          decoded.OwnerID,
			OwnerEpoch:       decoded.OwnerEpoch,
			SnapshotSequence: 1,
			Devices: vnextOwnerRPCInventoryDevices{{
				DeviceUUID: "gateway-test-device", TotalDataPages: 16, FreeDataPages: 16,
			}},
		}
		outer := marshalVNextOwnerRPCResponse(response)
		outer.Operation = vnextOwnerRPCOperationInventory
		outer.DurationMicros = 1
		return outer, nil
	}}
}

func vnextOwnerGatewayUnixRoundTrip(
	t *testing.T,
	localRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	request daemonRequest,
) execResponse {
	return vnextOwnerGatewayUnixRoundTripAs(
		t, localRPC, gateway, vnextOwnerCallerScheduler, request)
}

func vnextOwnerGatewayUnixRoundTripAs(
	t *testing.T,
	localRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	callerRole vnextOwnerCallerRole,
	request daemonRequest,
) execResponse {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		serveAuthenticatedDaemonConnWithVNextOwnerGatewayRoleLimits(
			server, localRPC, gateway, callerRole,
			make(chan struct{}, 1), time.Second, time.Second)
		close(done)
	}()
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal gateway daemon request: %v", err)
	}
	if err := writeFrame(client, body); err != nil {
		_ = client.Close()
		t.Fatalf("write gateway daemon request: %v", err)
	}
	responseBody, err := readFrame(client)
	if err != nil {
		_ = client.Close()
		t.Fatalf("read gateway daemon response: %v", err)
	}
	_ = client.Close()
	<-done
	var response execResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		t.Fatalf("decode gateway daemon response: %v", err)
	}
	return response
}

func TestVNextOwnerGatewayConfigurationIsAllOrNothing(t *testing.T) {
	if gateway, err := openVNextOwnerGateway(vnextOwnerGatewayConfig{}, nil); err != nil || gateway != nil {
		t.Fatalf("empty gateway config = %#v, %v; want nil, nil", gateway, err)
	}
	_, err := openVNextOwnerGateway(vnextOwnerGatewayConfig{
		RouteFilePath: "/test/routes.json",
	}, nil)
	if err == nil || !strings.Contains(err.Error(), "requires route file") {
		t.Fatalf("partial gateway config error = %v", err)
	}
}

func TestVNextOwnerGatewayRequiresDistinctCompleteRoleCredentials(t *testing.T) {
	partialProducer := vnextOwnerGatewayTestConfig("/test/routes.json")
	partialProducer.ProducerClientCertificatePath = "/test/producer.pem"
	if _, err := openVNextOwnerGatewayWithDependencies(
		partialProducer, nil, vnextOwnerGatewayDependencies{}); err == nil ||
		!strings.Contains(err.Error(), "producer client certificate and private key") {
		t.Fatalf("partial Producer identity error = %v", err)
	}
	shared := vnextOwnerGatewayTestConfig("/test/routes.json")
	shared.ProducerClientCertificatePath = shared.SchedulerClientCertificatePath
	shared.ProducerClientPrivateKeyPath = "/test/producer-key.pem"
	if _, err := openVNextOwnerGatewayWithDependencies(
		shared, nil, vnextOwnerGatewayDependencies{}); err == nil ||
		!strings.Contains(err.Error(), "distinct certificate and key paths") {
		t.Fatalf("shared role identity error = %v", err)
	}
}

func TestVNextOwnerGatewayPreservesRoleAndUsesDistinctCredentials(t *testing.T) {
	config := vnextOwnerGatewayTestConfig("/test/routes.json")
	config.ProducerClientCertificatePath = "/test/producer.pem"
	config.ProducerClientPrivateKeyPath = "/test/producer-key.pem"
	configs := make(map[vnextOwnerCallerRole]vnextOwnerTLSClientConfig)
	calls := make(map[vnextOwnerCallerRole]int)
	gateway, err := openVNextOwnerGatewayWithDependencies(
		config,
		nil,
		vnextOwnerGatewayDependencies{
			loadRouteFile: func(string) ([]byte, error) {
				return vnextOwnerGatewayTestRouteFile("owner-0", 7, "127.0.0.1:1"), nil
			},
			newTransport: func(clientConfig vnextOwnerTLSClientConfig) (
				vnextOwnerClientRoundTripper, error,
			) {
				configs[clientConfig.CallerRole] = clientConfig
				role := clientConfig.CallerRole
				return &vnextOwnerGatewayTestTransport{roundTrip: func(
					_ context.Context,
					request daemonRequest,
				) (execResponse, error) {
					calls[role]++
					var response execResponse
					if request.Operation == vnextOwnerRPCOperationProducerAbort {
						response = marshalVNextOwnerRPCResponse(
							vnextOwnerRPCProducerAbortResponse{
								Protocol: vnextOwnerRPCProtocol, Operation: request.Operation,
								State: "ABORTED",
							})
					} else {
						var lifecycle vnextOwnerRPCLifecycleRequest
						if err := decodeStrictVNextOwnerRPC(
							request.VNextOwnerAbort, &lifecycle); err != nil {
							return execResponse{}, err
						}
						proof := vnextOwnerTestVerifiedAuthority(
							request.Operation, lifecycle.Identity.internal()).proof()
						wireProof, err := vnextOwnerRPCSchedulerProofWire(proof)
						if err != nil {
							return execResponse{}, err
						}
						response = marshalVNextOwnerRPCResponse(
							vnextOwnerRPCLifecycleResponse{
								Protocol: vnextOwnerRPCProtocol, Operation: request.Operation,
								State: "ABORTED", Identity: lifecycle.Identity,
								SchedulerProof: wireProof,
							})
					}
					response.Operation = request.Operation
					response.DurationMicros = 1
					return response, nil
				}}, nil
			},
		})
	if err != nil {
		t.Fatal(err)
	}
	defer gateway.Close()
	if len(configs) != 2 ||
		configs[vnextOwnerCallerScheduler].ClientCertificatePath !=
			config.SchedulerClientCertificatePath ||
		configs[vnextOwnerCallerProducer].ClientCertificatePath !=
			config.ProducerClientCertificatePath {
		t.Fatalf("role transport configs = %#v", configs)
	}
	for _, call := range []struct {
		role      vnextOwnerCallerRole
		operation string
	}{
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationAbort},
		{vnextOwnerCallerProducer, vnextOwnerRPCOperationProducerAbort},
	} {
		request := vnextOwnerGatewayTestLifecycleDaemonRequest(t, call.operation)
		response := gateway.dispatch(request, call.role)
		if !response.Ok {
			t.Fatalf("%s %s response = %#v", call.role, call.operation, response)
		}
	}
	if calls[vnextOwnerCallerScheduler] != 1 ||
		calls[vnextOwnerCallerProducer] != 1 {
		t.Fatalf("role-specific calls = %#v", calls)
	}

	before := calls[vnextOwnerCallerProducer]
	commit := vnextOwnerGatewayTestLifecycleDaemonRequest(
		t, vnextOwnerRPCOperationCommit)
	if response := gateway.dispatch(commit, vnextOwnerCallerProducer); response.Ok ||
		response.ErrorCode != string(vnextOwnerServicePermissionDenied) {
		t.Fatalf("Producer Commit response = %#v", response)
	}
	if calls[vnextOwnerCallerProducer] != before {
		t.Fatal("denied Producer Commit reached its remote transport")
	}

	schedulerCalls := calls[vnextOwnerCallerScheduler]
	if response := gateway.dispatch(daemonRequest{
		Operation: vnextOwnerRPCOperationSeal,
	}, vnextOwnerCallerScheduler); response.Ok ||
		response.ErrorCode != string(vnextOwnerServicePermissionDenied) {
		t.Fatalf("Scheduler Seal response = %#v", response)
	}
	if calls[vnextOwnerCallerScheduler] != schedulerCalls {
		t.Fatal("denied Scheduler Seal reached its remote transport")
	}
}

func TestVNextOwnerGatewayRejectsNonCanonicalRouteFiles(t *testing.T) {
	validRoute := `{"ownerId":"owner-0","ownerEpoch":7,"endpoint":"127.0.0.1:1","serverName":"owner.test","serverUriSan":"spiffe://trenv.test/owner/owner-0"}`
	tests := map[string]string{
		"unknown field":         `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[],"extra":1}`,
		"trailing JSON":         `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[]}{}`,
		"duplicate field":       `{"protocol":"cxld.vnext-owner-gateway.v1","protocol":"cxld.vnext-owner-gateway.v1","routes":[]}`,
		"empty routes":          `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[]}`,
		"signed epoch overflow": `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[{"ownerId":"owner-0","ownerEpoch":9223372036854775808,"endpoint":"127.0.0.1:1","serverName":"owner.test","serverUriSan":"spiffe://trenv.test/owner/owner-0"}]}`,
		"server name control":   `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[{"ownerId":"owner-0","ownerEpoch":7,"endpoint":"127.0.0.1:1","serverName":"owner\u0000.test","serverUriSan":"spiffe://trenv.test/owner/owner-0"}]}`,
		"duplicate incarnation": `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[` + validRoute + `,` + strings.Replace(validRoute, "127.0.0.1:1", "127.0.0.1:2", 1) + `]}`,
		"duplicate route":       `{"protocol":"cxld.vnext-owner-gateway.v1","routes":[` + validRoute + `,` + strings.Replace(validRoute, "owner-0", "owner-1", 1) + `]}`,
	}
	transport := vnextOwnerGatewayTestInventoryTransport(nil, nil, nil)
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := openVNextOwnerGatewayWithDependencies(
				vnextOwnerGatewayTestConfig("/test/routes.json"), nil,
				vnextOwnerGatewayDependencies{
					loadRouteFile: func(string) ([]byte, error) { return []byte(raw), nil },
					newTransport: func(vnextOwnerTLSClientConfig) (vnextOwnerClientRoundTripper, error) {
						return transport, nil
					},
				})
			if err == nil {
				t.Fatal("non-canonical gateway route file was accepted")
			}
		})
	}
}

func TestVNextOwnerGatewayRouteCardinalityIsBoundedDuringStrictDecode(t *testing.T) {
	routes := make([]string, vnextOwnerGatewayMaxRoutes+1)
	for index := range routes {
		routes[index] = fmt.Sprintf(
			`{"ownerId":"owner-%d","ownerEpoch":7,"endpoint":"127.0.0.1:%d","serverName":"owner.test","serverUriSan":"spiffe://trenv.test/owner/%d"}`,
			index, index+1, index)
	}
	raw := []byte(`{"protocol":"cxld.vnext-owner-gateway.v1","routes":[` +
		strings.Join(routes, ",") + `]}`)
	var decoded vnextOwnerGatewayRouteFile
	err := decodeStrictVNextOwnerRPC(raw, &decoded)
	if err == nil || !strings.Contains(err.Error(), "more than 4096") {
		t.Fatalf("oversized route-array error = %v", err)
	}
}

func TestVNextOwnerGatewaySecureRouteFileRejectsUnsafeFiles(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "routes.json")
	if err := os.WriteFile(regular, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "routes-link.json")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	worldWritable := filepath.Join(directory, "routes-world.json")
	if err := os.WriteFile(worldWritable, []byte("{}"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(worldWritable, 0o666); err != nil {
		t.Fatal(err)
	}
	oversized := filepath.Join(directory, "routes-large.json")
	file, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(vnextOwnerGatewayMaxRouteFileBytes + 1); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{directory, symlink, worldWritable, oversized} {
		if _, err := readSecureVNextOwnerGatewayRouteFile(path); err == nil {
			t.Fatalf("unsafe route file %q was accepted", path)
		}
	}
}

func TestVNextOwnerGatewayRouteFileOwnerMustMatchEffectiveUID(t *testing.T) {
	effectiveUID := os.Geteuid()
	if err := validateVNextOwnerGatewayRouteFileOwner(
		uint32(effectiveUID), effectiveUID); err != nil {
		t.Fatalf("matching route-file owner was rejected: %v", err)
	}
	foreignUID := uint32(0)
	if effectiveUID == 0 {
		foreignUID = 1
	}
	if err := validateVNextOwnerGatewayRouteFileOwner(
		foreignUID, effectiveUID); err == nil {
		t.Fatal("foreign route-file owner UID was accepted")
	}
}

func TestVNextOwnerGatewayRouteFileStabilityDetectsInPlaceRewrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "routes.json")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
		t.Fatal(err)
	}
	changedTime := before.ModTime().Add(2 * time.Second)
	if err := os.Chtimes(path, changedTime, changedTime); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() ||
		before.Mode() != after.Mode() {
		t.Fatalf("test setup changed identity, size, or mode: before=%#v after=%#v", before, after)
	}
	if err := validateVNextOwnerGatewayRouteFileStable(before, after); err == nil {
		t.Fatal("same-size in-place route-file rewrite was accepted as stable")
	}
}

func TestVNextOwnerGatewayUnknownAndStaleOwnersFailBeforeNetwork(t *testing.T) {
	var calls int64
	gateway := openVNextOwnerGatewayForTest(
		t, vnextOwnerGatewayTestRouteFile("owner-0", 7, "127.0.0.1:1"), nil,
		vnextOwnerGatewayTestInventoryTransport(&calls, nil, nil))
	for _, request := range []daemonRequest{
		vnextOwnerGatewayTestInventoryDaemonRequest(t, "unknown", 7, "unknown"),
		vnextOwnerGatewayTestInventoryDaemonRequest(t, "owner-0", 6, "stale"),
		vnextOwnerGatewayTestReservationStatusDaemonRequest(
			t, func() vnextOwnerReserveRequest {
				request := vnextOwnerStatusTestRequest("unknown-route", 1)
				request.OwnerID = "unknown"
				return request
			}()),
		vnextOwnerGatewayTestReservationStatusDaemonRequest(
			t, func() vnextOwnerReserveRequest {
				request := vnextOwnerStatusTestRequest("stale-route", 1)
				request.OwnerEpoch = 6
				return request
			}()),
	} {
		response := gateway.dispatch(request, vnextOwnerCallerScheduler)
		if response.Ok || response.ErrorCode != string(vnextOwnerServiceIdentityMismatch) ||
			response.Operation != request.Operation || response.DurationMicros < 0 {
			t.Fatalf("unexpected exact-route rejection: %#v", response)
		}
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("network calls = %d, want 0", got)
	}
}

func TestVNextOwnerGatewayForwardsAuthenticatedBoundedRemoteFailureUnchanged(t *testing.T) {
	want := execResponse{
		Ok:             false,
		Stderr:         "remote diagnostic",
		ExitCode:       23,
		Error:          "remote Owner rejected the exact request",
		ErrorCode:      string(vnextOwnerServiceIdentityMismatch),
		Operation:      vnextOwnerRPCOperationInventory,
		DurationMicros: 987,
	}
	transport := &vnextOwnerGatewayTestTransport{roundTrip: func(
		context.Context,
		daemonRequest,
	) (execResponse, error) {
		return want, nil
	}}
	gateway := openVNextOwnerGatewayForTest(
		t, vnextOwnerGatewayTestRouteFile("owner-0", 7, "127.0.0.1:1"),
		nil, transport)
	got := gateway.dispatch(vnextOwnerGatewayTestInventoryDaemonRequest(
		t, "owner-0", 7, "remote-failure"), vnextOwnerCallerScheduler)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("forwarded remote failure = %#v, want %#v", got, want)
	}
}

func TestVNextOwnerGatewayUsesExactLocalOwnerWithoutNetwork(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "gateway-local-device", Size: 256 << 10,
	}})
	localRPC := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	var calls int64
	gateway := openVNextOwnerGatewayForTest(
		t, vnextOwnerGatewayTestRouteFile("remote-owner", 9, "127.0.0.1:1"),
		localRPC, vnextOwnerGatewayTestInventoryTransport(&calls, nil, nil))
	response := vnextOwnerGatewayUnixRoundTrip(
		t, localRPC, gateway,
		vnextOwnerGatewayTestInventoryDaemonRequest(t, "owner-0", 7, "local"))
	if !response.Ok || response.Operation != vnextOwnerRPCOperationInventory ||
		response.DurationMicros < 0 {
		t.Fatalf("unexpected local gateway response: %#v", response)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("network calls = %d, want 0", got)
	}
}

func TestVNextOwnerGatewayRoutesAdmissionStatusAndTransitionByExactIncarnation(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "gateway-local-admission", Size: 256 << 10,
	}})
	localRPC := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	var calls int64
	gateway := openVNextOwnerGatewayForTest(
		t,
		vnextOwnerGatewayTestRouteFile("remote-owner", 9, "127.0.0.1:1"),
		localRPC,
		vnextOwnerGatewayTestInventoryTransport(&calls, nil, nil))
	setRaw := marshalVNextOwnerRPCTestPayload(t, vnextOwnerRPCSetAdmissionRequest{
		Protocol:                  vnextOwnerRPCProtocol,
		RequestID:                 "gateway-admission-close",
		ExpectedOwnerID:           "owner-0",
		ExpectedOwnerEpoch:        7,
		FromState:                 "ACTIVE",
		TargetState:               "READ_ONLY",
		ExpectedAdmissionSequence: 1,
	})
	set := vnextOwnerGatewayUnixRoundTrip(t, localRPC, gateway, daemonRequest{
		CommandLabel:           "scheduler-gateway-test",
		Operation:              vnextOwnerRPCOperationSetAdmission,
		VNextOwnerSetAdmission: setRaw,
	})
	if !set.Ok || set.Operation != vnextOwnerRPCOperationSetAdmission {
		t.Fatalf("local gateway set admission failed: %#v", set)
	}
	statusRaw, err := json.Marshal(vnextOwnerRPCAdmissionStatusRequest{
		Protocol:           vnextOwnerRPCProtocol,
		RequestID:          "gateway-admission-status",
		ExpectedOwnerID:    "owner-0",
		ExpectedOwnerEpoch: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	status := vnextOwnerGatewayUnixRoundTrip(t, localRPC, gateway, daemonRequest{
		CommandLabel:              "scheduler-gateway-test",
		Operation:                 vnextOwnerRPCOperationAdmissionStatus,
		VNextOwnerAdmissionStatus: statusRaw,
	})
	if !status.Ok || status.Operation != vnextOwnerRPCOperationAdmissionStatus {
		t.Fatalf("local gateway admission status failed: %#v", status)
	}
	var wire vnextOwnerRPCAdmissionStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(status.Stdout), &wire); err != nil {
		t.Fatal(err)
	}
	if wire.State != "READ_ONLY" || wire.AdmissionSequence != 2 {
		t.Fatalf("gateway admission status changed proof: %#v", wire)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("exact local admission route made %d network calls", got)
	}

	unknownRaw, err := json.Marshal(vnextOwnerRPCAdmissionStatusRequest{
		Protocol:           vnextOwnerRPCProtocol,
		RequestID:          "gateway-admission-unknown",
		ExpectedOwnerID:    "unknown-owner",
		ExpectedOwnerEpoch: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := gateway.dispatch(daemonRequest{
		CommandLabel:              "scheduler-gateway-test",
		Operation:                 vnextOwnerRPCOperationAdmissionStatus,
		VNextOwnerAdmissionStatus: unknownRaw,
	}, vnextOwnerCallerScheduler)
	if unknown.Ok || unknown.ErrorCode != string(vnextOwnerServiceIdentityMismatch) {
		t.Fatalf("unknown admission route was not rejected: %#v", unknown)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("unknown admission route made %d network calls", got)
	}
}

func TestRuntimeRoleAdmissionDenialPrecedesLocalMutationAndRemoteForward(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "gateway-denied-admission", Size: 256 << 10,
	}})
	localRPC := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	var calls int64
	gateway := openVNextOwnerGatewayForTest(
		t,
		vnextOwnerGatewayTestRouteFile("remote-owner", 9, "127.0.0.1:1"),
		localRPC,
		vnextOwnerGatewayTestInventoryTransport(&calls, nil, nil))
	raw, err := json.Marshal(vnextOwnerRPCSetAdmissionRequest{
		Protocol:                  vnextOwnerRPCProtocol,
		RequestID:                 "runtime-must-not-close-admission",
		ExpectedOwnerID:           "owner-0",
		ExpectedOwnerEpoch:        7,
		FromState:                 "ACTIVE",
		TargetState:               "READ_ONLY",
		ExpectedAdmissionSequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.group.mu.Lock()
	beforeState := fixture.group.journal.AdmissionState
	beforeAdmissionSequence := fixture.group.journal.AdmissionSequence
	beforeSnapshotSequence := fixture.group.journal.SnapshotSequence
	fixture.group.mu.Unlock()
	response := vnextOwnerGatewayUnixRoundTripAs(t, localRPC, gateway,
		vnextOwnerCallerProducer, daemonRequest{
			CommandLabel:           "forged-runtime-admission",
			Operation:              vnextOwnerRPCOperationSetAdmission,
			VNextOwnerSetAdmission: raw,
		})
	if response.Ok || response.ErrorCode != string(vnextOwnerServicePermissionDenied) {
		t.Fatalf("runtime admission response = %#v", response)
	}
	fixture.group.mu.Lock()
	afterState := fixture.group.journal.AdmissionState
	afterAdmissionSequence := fixture.group.journal.AdmissionSequence
	afterSnapshotSequence := fixture.group.journal.SnapshotSequence
	fixture.group.mu.Unlock()
	if afterState != beforeState || afterAdmissionSequence != beforeAdmissionSequence ||
		afterSnapshotSequence != beforeSnapshotSequence {
		t.Fatalf(
			"denied runtime admission mutated Owner head: %s/%d/%d -> %s/%d/%d",
			beforeState, beforeAdmissionSequence, beforeSnapshotSequence,
			afterState, afterAdmissionSequence, afterSnapshotSequence)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("denied runtime admission made %d remote calls", got)
	}
}

func TestVNextOwnerGatewayRejectsMalformedReserveIdentityBeforeLocalAllocation(t *testing.T) {
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "gateway-local-reserve-device", Size: 256 << 10,
	}})
	localRPC := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))
	var calls int64
	gateway := openVNextOwnerGatewayForTest(
		t, vnextOwnerGatewayTestRouteFile("remote-owner", 9, "127.0.0.1:1"),
		localRPC, vnextOwnerGatewayTestInventoryTransport(&calls, nil, nil))
	tests := map[string]func(*vnextOwnerRPCReserveRequest){
		"request whitespace": func(request *vnextOwnerRPCReserveRequest) {
			request.RequestID = " reserve-request"
		},
		"checkpoint control": func(request *vnextOwnerRPCReserveRequest) {
			request.CheckpointID = "reserve\ncheckpoint"
		},
		"producer whitespace": func(request *vnextOwnerRPCReserveRequest) {
			request.ProducerID = "reserve-producer "
		},
		"Owner whitespace": func(request *vnextOwnerRPCReserveRequest) {
			request.OwnerID = "owner-0 "
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			wire := vnextOwnerRPCTestReserveRequest("owner-0")
			mutate(&wire)
			response := vnextOwnerGatewayUnixRoundTrip(
				t, localRPC, gateway,
				vnextOwnerGatewayTestReserveDaemonRequest(t, wire))
			if response.Ok ||
				response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
				response.Operation != vnextOwnerRPCOperationReserve ||
				response.DurationMicros < 0 {
				t.Fatalf("malformed local Reserve response: %#v", response)
			}
		})
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("local Owner transactions = %d, want 0", count)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("network calls = %d, want 0", got)
	}
}

func TestVNextOwnerGatewayRejectsMalformedReserveIdentityBeforeRemoteNetwork(t *testing.T) {
	var calls int64
	gateway := openVNextOwnerGatewayForTest(
		t, vnextOwnerGatewayTestRouteFile("owner-0", 7, "127.0.0.1:1"), nil,
		vnextOwnerGatewayTestInventoryTransport(&calls, nil, nil))
	wire := vnextOwnerRPCTestReserveRequest("owner-0")
	wire.ProducerID = "remote-producer\x00"
	response := gateway.dispatch(
		vnextOwnerGatewayTestReserveDaemonRequest(t, wire),
		vnextOwnerCallerScheduler)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) {
		t.Fatalf("malformed remote Reserve response: %#v", response)
	}
	validRaw, err := json.Marshal(vnextOwnerRPCTestReserveRequest("owner-0"))
	if err != nil {
		t.Fatal(err)
	}
	invalidRaw := bytes.Replace(
		validRaw, []byte("rpc-reserve-producer"), []byte{0xff}, 1)
	response = gateway.dispatch(daemonRequest{
		CommandLabel:      "scheduler-gateway-test",
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: invalidRaw,
	}, vnextOwnerCallerScheduler)
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) {
		t.Fatalf("invalid-UTF-8 remote Reserve response: %#v", response)
	}
	if got := atomic.LoadInt64(&calls); got != 0 {
		t.Fatalf("network calls = %d, want 0", got)
	}
}

func TestVNextOwnerGatewaySchedulerOnlyInventoryAndReserveUseRealMutualTLS(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
	directory := t.TempDir()
	routePath := filepath.Join(directory, "routes.json")
	if err := os.WriteFile(routePath, vnextOwnerGatewayTestRouteFile(
		"owner-0", 7, server.Addr().String()), 0o600); err != nil {
		t.Fatalf("write gateway route file: %v", err)
	}
	gateway, err := openVNextOwnerGateway(vnextOwnerGatewayConfig{
		RouteFilePath:                  routePath,
		SchedulerClientCertificatePath: material.clientCertificatePath,
		SchedulerClientPrivateKeyPath:  material.clientPrivateKeyPath,
		ServerCAPath:                   material.caPath,
	}, nil)
	if err != nil {
		t.Fatalf("open Scheduler-only VNext Owner gateway: %v", err)
	}
	t.Cleanup(func() { _ = gateway.Close() })

	inventory := vnextOwnerGatewayUnixRoundTrip(
		t, nil, gateway,
		vnextOwnerGatewayTestInventoryDaemonRequest(t, "owner-0", 7, "tls-inventory"))
	if !inventory.Ok || inventory.Operation != vnextOwnerRPCOperationInventory ||
		inventory.DurationMicros < 0 {
		t.Fatalf("gateway Inventory over mTLS failed: %#v", inventory)
	}
	reserve := vnextOwnerGatewayUnixRoundTrip(
		t, nil, gateway, vnextOwnerTLSTestDaemonRequest(t, "gateway"))
	if !reserve.Ok || reserve.Operation != vnextOwnerRPCOperationReserve ||
		reserve.DurationMicros < 0 {
		t.Fatalf("gateway Reserve over mTLS failed: %#v", reserve)
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 1 {
		t.Fatalf("remote Owner transactions = %d, want 1", count)
	}
	status := vnextOwnerGatewayUnixRoundTrip(
		t, nil, gateway,
		vnextOwnerGatewayTestReservationStatusDaemonRequest(
			t, vnextOwnerTLSTestReserveRequest("gateway")))
	if !status.Ok || status.Operation != vnextOwnerRPCOperationReservationStatus ||
		status.DurationMicros < 0 {
		t.Fatalf("gateway ReservationStatus over mTLS failed: %#v", status)
	}
	var statusWire vnextOwnerRPCReservationStatusResponse
	if err := decodeStrictVNextOwnerRPC([]byte(status.Stdout), &statusWire); err != nil {
		t.Fatalf("decode gateway ReservationStatus response: %v", err)
	}
	if statusWire.State != string(vnextOwnerReservationGranted) ||
		!statusWire.HasGrant || statusWire.Identity.AllocationRecordID == 0 ||
		len(statusWire.Extents) == 0 || len(statusWire.Devices) == 0 {
		t.Fatalf("unexpected gateway ReservationStatus response: %#v", statusWire)
	}
}

func TestVNextOwnerRemoteListenerNeverRoutesThroughGateway(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, _, _ := startVNextOwnerTLSTestServer(t, material, nil)
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Inventory(context.Background(), vnextOwnerInventoryRequest{
		RequestID: "wrong-owner", OwnerID: "remote-owner", OwnerEpoch: 9,
	})
	var remoteError *vnextOwnerClientRemoteError
	if !errors.As(err, &remoteError) ||
		remoteError.ErrorCode != string(vnextOwnerServiceIdentityMismatch) {
		t.Fatalf("remote listener wrong-owner error = %v", err)
	}
}

func TestVNextOwnerGatewayRemoteConcurrencyIsBounded(t *testing.T) {
	var calls int64
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	gateway := openVNextOwnerGatewayForTest(
		t, vnextOwnerGatewayTestRouteFile("owner-0", 7, "127.0.0.1:1"), nil,
		vnextOwnerGatewayTestInventoryTransport(&calls, entered, release))
	gateway.remoteAdmission = make(chan struct{}, 2)
	request := vnextOwnerGatewayTestInventoryDaemonRequest(t, "owner-0", 7, "bounded")
	responses := make(chan execResponse, 2)
	var workers sync.WaitGroup
	for index := 0; index < 2; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			responses <- gateway.dispatch(request, vnextOwnerCallerScheduler)
		}()
	}
	for index := 0; index < 2; index++ {
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for admitted remote gateway request")
		}
	}
	overflow := gateway.dispatch(request, vnextOwnerCallerScheduler)
	if overflow.Ok || overflow.ErrorCode != string(vnextOwnerServiceUnavailable) {
		t.Fatalf("unexpected concurrency overflow response: %#v", overflow)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("remote calls after overflow = %d, want 2", got)
	}
	close(release)
	workers.Wait()
	close(responses)
	for response := range responses {
		if !response.Ok {
			t.Fatalf("admitted remote gateway request failed: %#v", response)
		}
	}
}
