package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	testVNextOwnerTLSServerName  = "owner.test"
	testVNextOwnerTLSServerURI   = "spiffe://trenv.test/owner/owner-0"
	testVNextOwnerTLSClientURI   = "spiffe://trenv.test/scheduler/scheduler-0"
	testVNextOwnerTLSProducerURI = "spiffe://trenv.test/producer/producer-0"
	testVNextOwnerTLSDeniedURI   = "spiffe://trenv.test/scheduler/denied"
)

type vnextOwnerTLSTestAuthority struct {
	certificate    *x509.Certificate
	privateKey     *ecdsa.PrivateKey
	certificatePEM []byte
}

type vnextOwnerTLSTestMaterial struct {
	caPath                   string
	wrongCAPath              string
	serverCertificatePath    string
	serverPrivateKeyPath     string
	clientCertificatePath    string
	clientPrivateKeyPath     string
	deniedCertificatePath    string
	deniedPrivateKeyPath     string
	producerCertificatePath  string
	producerPrivateKeyPath   string
	ambiguousCertificatePath string
	ambiguousPrivateKeyPath  string
}

func newVNextOwnerTLSTestAuthority(t *testing.T, commonName string) vnextOwnerTLSTestAuthority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s CA key: %v", commonName, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create %s CA certificate: %v", commonName, err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s CA certificate: %v", commonName, err)
	}
	return vnextOwnerTLSTestAuthority{
		certificate: certificate,
		privateKey:  key,
		certificatePEM: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: der,
		}),
	}
}

func issueVNextOwnerTLSTestCertificate(
	t *testing.T,
	authority vnextOwnerTLSTestAuthority,
	serial int64,
	commonName string,
	dnsNames []string,
	uriSAN string,
	usage x509.ExtKeyUsage,
) ([]byte, []byte) {
	return issueVNextOwnerTLSTestCertificateWithURISANs(
		t, authority, serial, commonName, dnsNames, []string{uriSAN}, usage)
}

func issueVNextOwnerTLSTestCertificateWithURISANs(
	t *testing.T,
	authority vnextOwnerTLSTestAuthority,
	serial int64,
	commonName string,
	dnsNames []string,
	uriSANs []string,
	usage x509.ExtKeyUsage,
) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate %s key: %v", commonName, err)
	}
	identities := make([]*url.URL, len(uriSANs))
	for index, uriSAN := range uriSANs {
		identity, err := url.Parse(uriSAN)
		if err != nil {
			t.Fatalf("parse %s URI SAN %d: %v", commonName, index, err)
		}
		identities[index] = identity
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
		URIs:         identities,
	}
	der, err := x509.CreateCertificate(
		rand.Reader, template, authority.certificate, &key.PublicKey, authority.privateKey)
	if err != nil {
		t.Fatalf("create %s certificate: %v", commonName, err)
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal %s private key: %v", commonName, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey})
}

func writeVNextOwnerTLSTestFile(
	t *testing.T,
	directory string,
	name string,
	contents []byte,
) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("write TLS test file %s: %v", name, err)
	}
	return path
}

func newVNextOwnerTLSTestMaterial(t *testing.T) vnextOwnerTLSTestMaterial {
	t.Helper()
	directory := t.TempDir()
	authority := newVNextOwnerTLSTestAuthority(t, "VNext Owner test CA")
	wrongAuthority := newVNextOwnerTLSTestAuthority(t, "wrong VNext Owner test CA")
	serverCertificate, serverKey := issueVNextOwnerTLSTestCertificate(
		t, authority, 2, testVNextOwnerTLSServerName,
		[]string{testVNextOwnerTLSServerName}, testVNextOwnerTLSServerURI,
		x509.ExtKeyUsageServerAuth)
	clientCertificate, clientKey := issueVNextOwnerTLSTestCertificate(
		t, authority, 3, "scheduler-0", nil, testVNextOwnerTLSClientURI,
		x509.ExtKeyUsageClientAuth)
	deniedCertificate, deniedKey := issueVNextOwnerTLSTestCertificate(
		t, authority, 4, "scheduler-denied", nil, testVNextOwnerTLSDeniedURI,
		x509.ExtKeyUsageClientAuth)
	producerCertificate, producerKey := issueVNextOwnerTLSTestCertificate(
		t, authority, 5, "producer-0", nil, testVNextOwnerTLSProducerURI,
		x509.ExtKeyUsageClientAuth)
	ambiguousCertificate, ambiguousKey := issueVNextOwnerTLSTestCertificateWithURISANs(
		t, authority, 6, "ambiguous-client", nil,
		[]string{testVNextOwnerTLSClientURI, testVNextOwnerTLSProducerURI},
		x509.ExtKeyUsageClientAuth)
	return vnextOwnerTLSTestMaterial{
		caPath: writeVNextOwnerTLSTestFile(
			t, directory, "ca.pem", authority.certificatePEM),
		wrongCAPath: writeVNextOwnerTLSTestFile(
			t, directory, "wrong-ca.pem", wrongAuthority.certificatePEM),
		serverCertificatePath: writeVNextOwnerTLSTestFile(
			t, directory, "server.pem", serverCertificate),
		serverPrivateKeyPath: writeVNextOwnerTLSTestFile(
			t, directory, "server-key.pem", serverKey),
		clientCertificatePath: writeVNextOwnerTLSTestFile(
			t, directory, "client.pem", clientCertificate),
		clientPrivateKeyPath: writeVNextOwnerTLSTestFile(
			t, directory, "client-key.pem", clientKey),
		deniedCertificatePath: writeVNextOwnerTLSTestFile(
			t, directory, "denied.pem", deniedCertificate),
		deniedPrivateKeyPath: writeVNextOwnerTLSTestFile(
			t, directory, "denied-key.pem", deniedKey),
		producerCertificatePath: writeVNextOwnerTLSTestFile(
			t, directory, "producer.pem", producerCertificate),
		producerPrivateKeyPath: writeVNextOwnerTLSTestFile(
			t, directory, "producer-key.pem", producerKey),
		ambiguousCertificatePath: writeVNextOwnerTLSTestFile(
			t, directory, "ambiguous.pem", ambiguousCertificate),
		ambiguousPrivateKeyPath: writeVNextOwnerTLSTestFile(
			t, directory, "ambiguous-key.pem", ambiguousKey),
	}
}

func vnextOwnerTLSTestServerConfig(
	material vnextOwnerTLSTestMaterial,
) vnextOwnerTLSServerConfig {
	return vnextOwnerTLSServerConfig{
		ListenAddress:                 "127.0.0.1:0",
		ServerCertificatePath:         material.serverCertificatePath,
		ServerPrivateKeyPath:          material.serverPrivateKeyPath,
		ClientCAPath:                  material.caPath,
		AllowedSchedulerClientURISANs: []string{testVNextOwnerTLSClientURI},
	}
}

func vnextOwnerTLSTestClientConfig(
	material vnextOwnerTLSTestMaterial,
	endpoint string,
) vnextOwnerTLSClientConfig {
	return vnextOwnerTLSClientConfig{
		Endpoint:              endpoint,
		ServerName:            testVNextOwnerTLSServerName,
		ClientCertificatePath: material.clientCertificatePath,
		ClientPrivateKeyPath:  material.clientPrivateKeyPath,
		ServerCAPath:          material.caPath,
		ExpectedServerURISAN:  testVNextOwnerTLSServerURI,
		CallerRole:            vnextOwnerCallerScheduler,
	}
}

func vnextOwnerTLSProducerTestClientConfig(
	material vnextOwnerTLSTestMaterial,
	endpoint string,
) vnextOwnerTLSClientConfig {
	config := vnextOwnerTLSTestClientConfig(material, endpoint)
	config.ClientCertificatePath = material.producerCertificatePath
	config.ClientPrivateKeyPath = material.producerPrivateKeyPath
	config.CallerRole = vnextOwnerCallerProducer
	return config
}

func startVNextOwnerTLSTestServer(
	t *testing.T,
	material vnextOwnerTLSTestMaterial,
	mutate func(*vnextOwnerTLSServerConfig),
) (*vnextOwnerTLSServer, *vnextOwnerTestFixture, chan struct{}) {
	t.Helper()
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "tls-device", Size: 256 << 10,
	}})
	service := newVNextOwnerServiceForFixture(t, fixture)
	config := vnextOwnerTLSTestServerConfig(material)
	if mutate != nil {
		mutate(&config)
	}
	requestAdmission := make(chan struct{}, 4)
	server, err := startVNextOwnerTLSServer(
		config, newVNextOwnerRPC(service), requestAdmission, make(chan struct{}, 1))
	if err != nil {
		t.Fatalf("start VNext Owner TLS test server: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("close VNext Owner TLS test server: %v", err)
		}
	})
	return server, fixture, requestAdmission
}

func vnextOwnerTLSTestReserveRequest(id string) vnextOwnerReserveRequest {
	return vnextOwnerReserveRequest{
		RequestID:    "tls-request-" + id,
		CheckpointID: "tls-checkpoint-" + id,
		ProducerID:   "tls-producer-" + id,
		OwnerID:      "owner-0",
		OwnerEpoch:   7,
		Contents: []vnextOwnerReserveContent{{
			Kind:          vnextOwnerServiceContentMemory,
			ObjectID:      101,
			ByteLength:    vnextContentPageSize,
			CapacityPages: 1,
		}, {
			Kind:          vnextOwnerServiceContentPublication,
			ObjectID:      102,
			ByteLength:    vnextContentPageSize,
			CapacityPages: 1,
		}},
		MaxExtents: 1,
	}
}

func vnextOwnerTLSTestDaemonRequest(t *testing.T, id string) daemonRequest {
	t.Helper()
	request := vnextOwnerTLSTestReserveRequest(id)
	wire := vnextOwnerRPCReserveRequest{
		Protocol:     vnextOwnerRPCProtocol,
		RequestID:    request.RequestID,
		CheckpointID: request.CheckpointID,
		ProducerID:   request.ProducerID,
		OwnerID:      request.OwnerID,
		OwnerEpoch:   request.OwnerEpoch,
		Contents: vnextOwnerRPCReserveContents{
			{
				Kind: "memory", ObjectID: 101,
				ByteLength: vnextContentPageSize, CapacityPages: 1,
			},
			{
				Kind: "publication", ObjectID: 102,
				ByteLength: vnextContentPageSize, CapacityPages: 1,
			},
		},
		MaxExtents: 1,
	}
	raw := marshalVNextOwnerRPCTestPayload(t, wire)
	return daemonRequest{
		CommandLabel:      "vnext-owner-tls-test",
		TimeoutMillis:     0,
		Operation:         vnextOwnerRPCOperationReserve,
		VNextOwnerReserve: raw,
	}
}

func vnextOwnerTLSTestTransactionCount(fixture *vnextOwnerTestFixture) int {
	fixture.group.mu.Lock()
	defer fixture.group.mu.Unlock()
	return len(fixture.group.journal.Transactions)
}

func waitVNextOwnerTLSTestCondition(
	t *testing.T,
	description string,
	condition func() bool,
) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestVNextOwnerTLSReserveUsesRealMutualTLSFraming(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatalf("create VNext Owner TLS transport: %v", err)
	}
	if transport.tlsConfig.InsecureSkipVerify ||
		transport.tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("client TLS configuration is not fail-closed: %#v", transport.tlsConfig)
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatalf("create strict VNext Owner client: %v", err)
	}
	reserveRequest := vnextOwnerTLSTestReserveRequest("success")
	vnextOwnerTestAuthorizeReserve(&reserveRequest)
	response, err := client.Reserve(context.Background(), reserveRequest)
	if err != nil {
		t.Fatalf("Reserve over real VNext Owner mTLS framing: %v", err)
	}
	if response.Operation.AllocationRecordID != 1 || response.TotalPages != 2 ||
		len(response.Extents) != 1 {
		t.Fatalf("unexpected TLS Reserve response: %#v", response)
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 1 {
		t.Fatalf("Owner transactions = %d, want 1", count)
	}
}

func TestVNextOwnerTLSCapabilityBindsExactProducerURISAN(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material,
		func(config *vnextOwnerTLSServerConfig) {
			config.AllowedProducerClientURISANs = []string{testVNextOwnerTLSProducerURI}
		})
	schedulerTransport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	scheduler, err := newVNextOwnerClient(schedulerTransport)
	if err != nil {
		t.Fatal(err)
	}
	reserveRequest := vnextOwnerTLSTestReserveRequest("capability-uri-san")
	vnextOwnerTestAuthorizeReserve(&reserveRequest)
	reserved, err := scheduler.Reserve(context.Background(), reserveRequest)
	if err != nil {
		t.Fatalf("reserve over Scheduler TLS identity: %v", err)
	}
	issueRequest := vnextOwnerTestCapabilityIssueRequest(
		reserved.Operation, vnextProducerCapabilityAbort)
	issueRequest.ProducerPrincipal = testVNextOwnerTLSProducerURI
	vnextOwnerTestAuthorizeIssue(&issueRequest)
	issued, err := scheduler.IssueProducerCapability(context.Background(), issueRequest)
	if err != nil {
		t.Fatalf("issue exact TLS Producer capability: %v", err)
	}
	producerTransport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSProducerTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := newVNextOwnerClient(producerTransport)
	if err != nil {
		t.Fatal(err)
	}
	if err := producer.ProducerAbortVNextCheckpoint(
		context.Background(), reserved.Operation, issued.Capability); err != nil {
		t.Fatalf("exact Producer URI SAN capability abort: %v", err)
	}
	fixture.group.mu.Lock()
	transaction := fixture.group.journal.Transactions[reserved.Operation.AllocationRecordID]
	state := vnextOwnerTransactionState(0)
	if transaction != nil {
		state = transaction.State
	}
	fixture.group.mu.Unlock()
	if state != vnextOwnerAborted {
		t.Fatalf("TLS Producer abort state=%d, want ABORTED", state)
	}
}

func TestVNextOwnerTLSCallerRetainsExactVerifiedURISAN(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	raw, err := os.ReadFile(material.producerCertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		t.Fatal("Producer test certificate PEM is empty")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := vnextOwnerTLSCaller(tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{certificate},
		VerifiedChains:   [][]*x509.Certificate{{certificate}},
	}, map[string]vnextOwnerCallerRole{
		testVNextOwnerTLSProducerURI: vnextOwnerCallerProducer,
	})
	if err != nil {
		t.Fatal(err)
	}
	if caller.Role != vnextOwnerCallerProducer ||
		caller.Principal != testVNextOwnerTLSProducerURI {
		t.Fatalf("TLS caller lost exact URI SAN: %#v", caller)
	}
}

func TestVNextOwnerTLSInventoryUsesRealMutualTLSFramingWithoutMutation(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatalf("create VNext Owner TLS inventory transport: %v", err)
	}
	client, err := newVNextOwnerClient(transport)
	if err != nil {
		t.Fatalf("create strict VNext Owner inventory client: %v", err)
	}
	fixture.group.mu.Lock()
	wantSequence := fixture.group.journal.SnapshotSequence
	fixture.group.mu.Unlock()
	response, err := client.Inventory(context.Background(), vnextOwnerInventoryRequest{
		RequestID:  "tls-inventory-request",
		OwnerID:    "owner-0",
		OwnerEpoch: 7,
	})
	if err != nil {
		t.Fatalf("Inventory over real VNext Owner mTLS framing: %v", err)
	}
	if response.RequestID != "tls-inventory-request" || response.OwnerID != "owner-0" ||
		response.OwnerEpoch != 7 || response.SnapshotSequence != wantSequence ||
		len(response.Devices) != 1 || response.Devices[0].DeviceUUID != "tls-device" ||
		response.Devices[0].FreeDataPages != response.Devices[0].TotalDataPages {
		t.Fatalf("unexpected TLS Inventory response: %#v", response)
	}
	fixture.group.mu.Lock()
	gotSequence := fixture.group.journal.SnapshotSequence
	transactions := len(fixture.group.journal.Transactions)
	fixture.group.mu.Unlock()
	if gotSequence != wantSequence || transactions != 0 {
		t.Fatalf("TLS inventory mutated Owner state: sequence=%d/%d transactions=%d",
			gotSequence, wantSequence, transactions)
	}
}

func TestVNextOwnerTLSProducerCertificateCannotInvokeSchedulerControl(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material,
		func(config *vnextOwnerTLSServerConfig) {
			config.AllowedProducerClientURISANs = []string{testVNextOwnerTLSProducerURI}
		})
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSProducerTestClientConfig(material, server.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	// Use the authenticated TLS connection directly so this test exercises the
	// server policy rather than the client's identical defense-in-depth check.
	conn, err := tls.Dial("tcp", server.Addr().String(), transport.tlsConfig)
	if err != nil {
		t.Fatalf("dial allowed Producer TLS identity: %v", err)
	}
	defer conn.Close()
	body, err := json.Marshal(vnextOwnerTLSTestDaemonRequest(t, "producer-control-denied"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, body); err != nil {
		t.Fatal(err)
	}
	responseBody, err := readFrame(conn)
	if err != nil {
		t.Fatal(err)
	}
	response, err := decodeStrictVNextOwnerTLSExecResponse(responseBody)
	if err != nil {
		t.Fatal(err)
	}
	if response.Ok || response.ErrorCode != string(vnextOwnerServicePermissionDenied) ||
		response.Operation != vnextOwnerRPCOperationReserve {
		t.Fatalf("Producer control response = %#v", response)
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("denied Producer control call created %d transactions", count)
	}
}

func TestVNextOwnerTLSRejectsAmbiguousMultipleRoleCertificate(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material,
		func(config *vnextOwnerTLSServerConfig) {
			config.AllowedProducerClientURISANs = []string{testVNextOwnerTLSProducerURI}
		})
	config := vnextOwnerTLSTestClientConfig(material, server.Addr().String())
	config.ClientCertificatePath = material.ambiguousCertificatePath
	config.ClientPrivateKeyPath = material.ambiguousPrivateKeyPath
	transport, err := newVNextOwnerTLSRoundTripper(config)
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.RoundTrip(
		context.Background(), vnextOwnerTLSTestDaemonRequest(t, "ambiguous-role"))
	if err == nil {
		t.Fatalf("ambiguous-role certificate error = %v", err)
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("ambiguous TLS identity created %d transactions", count)
	}
}

func TestVNextOwnerTLSRejectsUntrustedOrUnallowlistedPeersBeforeDispatch(t *testing.T) {
	tests := []struct {
		name         string
		mutateClient func(*vnextOwnerTLSClientConfig, vnextOwnerTLSTestMaterial)
	}{
		{
			name: "wrong-server-CA",
			mutateClient: func(config *vnextOwnerTLSClientConfig, material vnextOwnerTLSTestMaterial) {
				config.ServerCAPath = material.wrongCAPath
			},
		},
		{
			name: "client-URI-not-allowlisted",
			mutateClient: func(config *vnextOwnerTLSClientConfig, material vnextOwnerTLSTestMaterial) {
				config.ClientCertificatePath = material.deniedCertificatePath
				config.ClientPrivateKeyPath = material.deniedPrivateKeyPath
			},
		},
		{
			name: "server-URI-mismatch",
			mutateClient: func(config *vnextOwnerTLSClientConfig, _ vnextOwnerTLSTestMaterial) {
				config.ExpectedServerURISAN = "spiffe://trenv.test/owner/different"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			material := newVNextOwnerTLSTestMaterial(t)
			server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
			config := vnextOwnerTLSTestClientConfig(material, server.Addr().String())
			test.mutateClient(&config, material)
			transport, err := newVNextOwnerTLSRoundTripper(config)
			if err != nil {
				t.Fatalf("create VNext Owner TLS transport: %v", err)
			}
			_, err = transport.RoundTrip(
				context.Background(), vnextOwnerTLSTestDaemonRequest(t, test.name))
			if err == nil {
				t.Fatal("unauthorized VNext Owner TLS request succeeded")
			}
			waitVNextOwnerTLSTestCondition(t, "failed TLS handshake cleanup", func() bool {
				return len(server.handshakeAdmission) == 0
			})
			if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
				t.Fatalf("unauthorized peer dispatched %d Owner transactions", count)
			}
		})
	}
}

func TestVNextOwnerTLSRequiresClientCertificateBeforeReadingRequest(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
	roots, err := loadVNextOwnerTLSCertificatePool(material.caPath, "test server CA")
	if err != nil {
		t.Fatalf("load test roots: %v", err)
	}
	conn, err := tls.Dial("tcp", server.Addr().String(), &tls.Config{
		MinVersion: tls.VersionTLS13,
		ServerName: testVNextOwnerTLSServerName,
		RootCAs:    roots,
		NextProtos: []string{vnextOwnerTLSALPN},
	})
	if err == nil {
		body, marshalErr := json.Marshal(vnextOwnerTLSTestDaemonRequest(t, "missing-cert"))
		if marshalErr != nil {
			t.Fatalf("marshal missing-certificate request: %v", marshalErr)
		}
		err = writeFrame(conn, body)
		if err == nil {
			_, err = readFrame(conn)
		}
		_ = conn.Close()
	}
	if err == nil {
		t.Fatal("TLS peer without a client certificate completed an Owner request")
	}
	waitVNextOwnerTLSTestCondition(t, "missing-certificate handshake cleanup", func() bool {
		return len(server.handshakeAdmission) == 0
	})
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("missing-certificate peer dispatched %d Owner transactions", count)
	}
}

func TestVNextOwnerTLSRemotePortRejectsLegacyDaemonOperations(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
	conn := dialVNextOwnerTLSTestConnection(t, material, server.Addr().String())
	defer conn.Close()
	body := []byte(
		`{"commandLabel":"legacy-over-owner-port","timeoutMillis":0,"operation":"metadataResolve"}`)
	if err := writeFrame(conn, body); err != nil {
		t.Fatalf("write legacy operation to Owner port: %v", err)
	}
	responseBody, err := readFrame(conn)
	if err != nil {
		t.Fatalf("read legacy-operation rejection: %v", err)
	}
	response, err := decodeStrictVNextOwnerTLSExecResponse(responseBody)
	if err != nil {
		t.Fatalf("decode legacy-operation rejection: %v", err)
	}
	if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) ||
		!strings.Contains(response.Error, "only strict VNext Owner operations") {
		t.Fatalf("unexpected legacy-operation response: %#v", response)
	}
	if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
		t.Fatalf("legacy remote request dispatched %d Owner transactions", count)
	}
}

func TestVNextOwnerTLSConfigurationIsAllOrNothing(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	complete := vnextOwnerTLSTestServerConfig(material)
	fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
		UUID: "tls-config-device", Size: 256 << 10,
	}})
	rpc := newVNextOwnerRPC(newVNextOwnerServiceForFixture(t, fixture))

	if enabled, err := validateVNextOwnerTLSServerConfig(
		vnextOwnerTLSServerConfig{}, nil); err != nil || enabled {
		t.Fatalf("empty TLS listener config = enabled %v, error %v", enabled, err)
	}
	partial := []vnextOwnerTLSServerConfig{
		{ListenAddress: complete.ListenAddress},
		{
			ListenAddress:         complete.ListenAddress,
			ServerCertificatePath: complete.ServerCertificatePath,
			ServerPrivateKeyPath:  complete.ServerPrivateKeyPath,
			ClientCAPath:          complete.ClientCAPath,
		},
	}
	for index, config := range partial {
		if _, err := validateVNextOwnerTLSServerConfig(config, rpc); err == nil {
			t.Fatalf("partial server config %d was accepted", index)
		}
	}
	if _, err := validateVNextOwnerTLSServerConfig(complete, nil); err == nil ||
		!strings.Contains(err.Error(), "active strict VNext Owner runtime") {
		t.Fatalf("enabled listener without Owner runtime returned %v", err)
	}
	if enabled, err := validateVNextOwnerTLSServerConfig(complete, rpc); err != nil || !enabled {
		t.Fatalf("complete TLS listener config = enabled %v, error %v", enabled, err)
	}
	overlap := complete
	overlap.AllowedProducerClientURISANs = []string{testVNextOwnerTLSClientURI}
	if _, err := validateVNextOwnerTLSServerConfig(overlap, rpc); err == nil ||
		!strings.Contains(err.Error(), "both scheduler and producer") {
		t.Fatalf("overlapping role URI SAN error = %v", err)
	}

	client := vnextOwnerTLSTestClientConfig(material, "127.0.0.1:1")
	client.ClientCertificatePath = ""
	if _, err := newVNextOwnerTLSRoundTripper(client); err == nil {
		t.Fatal("TLS client without an explicit client certificate was accepted")
	}
	client = vnextOwnerTLSTestClientConfig(material, "127.0.0.1:1")
	client.CallerRole = vnextOwnerCallerUnknown
	if _, err := newVNextOwnerTLSRoundTripper(client); err == nil {
		t.Fatal("TLS client without an explicit transport role was accepted")
	}
	if _, err := parseVNextOwnerURIAllowlist(
		testVNextOwnerTLSClientURI + "," + testVNextOwnerTLSClientURI); err == nil {
		t.Fatal("duplicate exact URI SAN allowlist entry was accepted")
	}
}

func dialVNextOwnerTLSTestConnection(
	t *testing.T,
	material vnextOwnerTLSTestMaterial,
	endpoint string,
) *tls.Conn {
	t.Helper()
	transport, err := newVNextOwnerTLSRoundTripper(
		vnextOwnerTLSTestClientConfig(material, endpoint))
	if err != nil {
		t.Fatalf("create raw VNext Owner TLS client config: %v", err)
	}
	conn, err := tls.Dial("tcp", endpoint, transport.tlsConfig)
	if err != nil {
		t.Fatalf("dial raw VNext Owner TLS connection: %v", err)
	}
	return conn
}

func TestVNextOwnerTLSRejectsOversizedAndTruncatedFrames(t *testing.T) {
	t.Run("oversized-request", func(t *testing.T) {
		material := newVNextOwnerTLSTestMaterial(t)
		server, fixture, _ := startVNextOwnerTLSTestServer(t, material, nil)
		conn := dialVNextOwnerTLSTestConnection(t, material, server.Addr().String())
		defer conn.Close()
		header := make([]byte, 4)
		binary.BigEndian.PutUint32(header, uint32(maxDaemonFrameBytes+1))
		if _, err := conn.Write(header); err != nil {
			t.Fatalf("write oversized request header: %v", err)
		}
		body, err := readFrame(conn)
		if err != nil {
			t.Fatalf("read oversized-frame rejection: %v", err)
		}
		response, err := decodeStrictVNextOwnerTLSExecResponse(body)
		if err != nil {
			t.Fatalf("decode oversized-frame rejection: %v", err)
		}
		if response.Ok || response.ErrorCode != string(vnextOwnerServiceInvalidRequest) {
			t.Fatalf("unexpected oversized-frame response: %#v", response)
		}
		if count := vnextOwnerTLSTestTransactionCount(fixture); count != 0 {
			t.Fatalf("oversized frame dispatched %d Owner transactions", count)
		}
	})

	t.Run("truncated-response", func(t *testing.T) {
		material := newVNextOwnerTLSTestMaterial(t)
		config := vnextOwnerTLSTestServerConfig(material)
		tlsConfig, err := newVNextOwnerTLSServerConfig(config)
		if err != nil {
			t.Fatalf("create malicious test server TLS config: %v", err)
		}
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen for truncated response test: %v", err)
		}
		serverDone := make(chan struct{})
		go func() {
			defer close(serverDone)
			rawConn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			conn := tls.Server(rawConn, tlsConfig)
			defer conn.Close()
			if conn.Handshake() != nil {
				return
			}
			if _, readErr := readFrame(conn); readErr != nil {
				return
			}
			header := make([]byte, 4)
			binary.BigEndian.PutUint32(header, 64)
			_, _ = conn.Write(append(header, []byte(`{"ok"`)...))
		}()
		t.Cleanup(func() {
			_ = listener.Close()
			<-serverDone
		})
		transport, err := newVNextOwnerTLSRoundTripper(
			vnextOwnerTLSTestClientConfig(material, listener.Addr().String()))
		if err != nil {
			t.Fatalf("create truncated-response client: %v", err)
		}
		_, err = transport.RoundTrip(
			context.Background(), vnextOwnerTLSTestDaemonRequest(t, "truncated"))
		if err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("truncated response returned %v, want unexpected EOF", err)
		}
	})
}

func TestVNextOwnerTLSStrictOuterResponseRejectsMalformedJSON(t *testing.T) {
	valid, err := marshalVNextOwnerTLSExecResponse(execResponse{
		Ok: true, Stdout: "{}\n", Operation: vnextOwnerRPCOperationReserve,
	})
	if err != nil {
		t.Fatalf("marshal valid outer response: %v", err)
	}
	if _, err := decodeStrictVNextOwnerTLSExecResponse(valid); err != nil {
		t.Fatalf("decode valid outer response: %v", err)
	}
	mutations := map[string]func([]byte) []byte{
		"unknown": func(raw []byte) []byte {
			return append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":1}`)...)
		},
		"duplicate": func(raw []byte) []byte {
			return append([]byte(`{"ok":true,`), raw[1:]...)
		},
		"missing": func(raw []byte) []byte {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("decode response fields: %v", err)
			}
			delete(fields, "stdout")
			mutated, err := json.Marshal(fields)
			if err != nil {
				t.Fatalf("encode response fields: %v", err)
			}
			return mutated
		},
		"null": func(raw []byte) []byte {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(raw, &fields); err != nil {
				t.Fatalf("decode response fields: %v", err)
			}
			fields["stdout"] = json.RawMessage("null")
			mutated, err := json.Marshal(fields)
			if err != nil {
				t.Fatalf("encode response fields: %v", err)
			}
			return mutated
		},
		"trailing": func(raw []byte) []byte {
			return append(append([]byte(nil), raw...), []byte(`{}`)...)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStrictVNextOwnerTLSExecResponse(mutate(valid)); err == nil {
				t.Fatal("malformed outer response was accepted")
			}
		})
	}
}

func TestVNextOwnerTLSContextCancellationAndHandshakeTimeout(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	request := vnextOwnerTLSTestDaemonRequest(t, "context")
	tests := []struct {
		name    string
		timeout time.Duration
		cancel  bool
		want    error
	}{
		{name: "cancellation", timeout: time.Second, cancel: true, want: context.Canceled},
		{name: "timeout", timeout: 40 * time.Millisecond, want: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for stalled handshake: %v", err)
			}
			accepted := make(chan struct{})
			release := make(chan struct{})
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr != nil {
					close(accepted)
					return
				}
				close(accepted)
				<-release
				_ = conn.Close()
			}()
			t.Cleanup(func() {
				_ = listener.Close()
				close(release)
			})
			config := vnextOwnerTLSTestClientConfig(material, listener.Addr().String())
			config.HandshakeTimeout = test.timeout
			transport, err := newVNextOwnerTLSRoundTripper(config)
			if err != nil {
				t.Fatalf("create stalled-handshake client: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				_, roundTripErr := transport.RoundTrip(ctx, request)
				result <- roundTripErr
			}()
			<-accepted
			if test.cancel {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, test.want) {
					t.Fatalf("RoundTrip error = %v, want %v", err, test.want)
				}
			case <-time.After(time.Second):
				t.Fatal("context-aware TLS handshake did not stop")
			}
		})
	}
}

func TestVNextOwnerTLSResponseReadHonorsContextAndDeadline(t *testing.T) {
	material := newVNextOwnerTLSTestMaterial(t)
	tests := []struct {
		name    string
		cancel  bool
		timeout time.Duration
	}{
		{name: "context-cancellation", cancel: true, timeout: time.Second},
		{name: "read-deadline", timeout: 40 * time.Millisecond},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverConfig := vnextOwnerTLSTestServerConfig(material)
			tlsConfig, err := newVNextOwnerTLSServerConfig(serverConfig)
			if err != nil {
				t.Fatalf("create stalled-response server TLS config: %v", err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen for stalled response: %v", err)
			}
			requestRead := make(chan struct{})
			release := make(chan struct{})
			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				rawConn, acceptErr := listener.Accept()
				if acceptErr != nil {
					close(requestRead)
					return
				}
				conn := tls.Server(rawConn, tlsConfig)
				defer conn.Close()
				if conn.Handshake() != nil {
					close(requestRead)
					return
				}
				if _, readErr := readFrame(conn); readErr != nil {
					close(requestRead)
					return
				}
				close(requestRead)
				<-release
			}()
			t.Cleanup(func() {
				_ = listener.Close()
				close(release)
				<-serverDone
			})
			clientConfig := vnextOwnerTLSTestClientConfig(material, listener.Addr().String())
			clientConfig.ResponseReadTimeout = test.timeout
			transport, err := newVNextOwnerTLSRoundTripper(clientConfig)
			if err != nil {
				t.Fatalf("create stalled-response client: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			request := vnextOwnerTLSTestDaemonRequest(t, test.name)
			result := make(chan error, 1)
			go func() {
				_, roundTripErr := transport.RoundTrip(ctx, request)
				result <- roundTripErr
			}()
			<-requestRead
			if test.cancel {
				cancel()
			}
			select {
			case err := <-result:
				if test.cancel {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("response-read cancellation returned %v", err)
					}
				} else {
					var networkError net.Error
					if !errors.As(err, &networkError) || !networkError.Timeout() {
						t.Fatalf("response-read deadline returned %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("stalled response ignored context/deadline")
			}
		})
	}
}

func TestVNextOwnerTLSAdmissionsAndShutdownAreBounded(t *testing.T) {
	t.Run("unauthenticated-peer-does-not-consume-daemon-slot", func(t *testing.T) {
		material := newVNextOwnerTLSTestMaterial(t)
		server, _, requestAdmission := startVNextOwnerTLSTestServer(
			t, material, func(config *vnextOwnerTLSServerConfig) {
				config.HandshakeTimeout = 100 * time.Millisecond
			})
		conn, err := net.Dial("tcp", server.Addr().String())
		if err != nil {
			t.Fatalf("dial unauthenticated stalled peer: %v", err)
		}
		defer conn.Close()
		waitVNextOwnerTLSTestCondition(t, "TLS handshake admission", func() bool {
			return len(server.handshakeAdmission) == 1
		})
		if len(requestAdmission) != 0 {
			t.Fatalf("unauthenticated peer consumed %d daemon request slots", len(requestAdmission))
		}
		if !tryAcquireDaemonRequestAdmission(requestAdmission) {
			t.Fatal("local daemon request admission was unavailable")
		}
		<-requestAdmission
		if err := server.Stop(); err != nil {
			t.Fatalf("stop TLS listener: %v", err)
		}
		waitDone := make(chan struct{})
		go func() { server.Wait(); close(waitDone) }()
		select {
		case <-waitDone:
		case <-time.After(time.Second):
			t.Fatal("stalled unauthenticated handshake exceeded its shutdown timeout")
		}
		if len(server.handshakeAdmission) != 0 || len(requestAdmission) != 0 {
			t.Fatalf("admissions leaked after shutdown: handshake=%d request=%d",
				len(server.handshakeAdmission), len(requestAdmission))
		}
	})

	t.Run("authenticated-idle-peer-holds-only-bounded-request-slot", func(t *testing.T) {
		material := newVNextOwnerTLSTestMaterial(t)
		server, _, requestAdmission := startVNextOwnerTLSTestServer(
			t, material, func(config *vnextOwnerTLSServerConfig) {
				config.RequestReadTimeout = 120 * time.Millisecond
			})
		conn := dialVNextOwnerTLSTestConnection(t, material, server.Addr().String())
		defer conn.Close()
		waitVNextOwnerTLSTestCondition(t, "authenticated request admission", func() bool {
			return len(server.handshakeAdmission) == 0 && len(requestAdmission) == 1
		})
		if err := server.Stop(); err != nil {
			t.Fatalf("stop TLS listener: %v", err)
		}
		waitDone := make(chan struct{})
		go func() { server.Wait(); close(waitDone) }()
		select {
		case <-waitDone:
			t.Fatal("authenticated idle connection bypassed the frame read timeout")
		case <-time.After(20 * time.Millisecond):
		}
		select {
		case <-waitDone:
		case <-time.After(time.Second):
			t.Fatal("authenticated idle connection exceeded the frame read timeout")
		}
		if len(requestAdmission) != 0 {
			t.Fatalf("daemon request admission leaked after shutdown: %d", len(requestAdmission))
		}
	})
}
