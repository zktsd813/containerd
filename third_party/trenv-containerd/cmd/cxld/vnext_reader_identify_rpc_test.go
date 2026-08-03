package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const (
	vnextReaderIdentifyTestNode      = "reader-node-0"
	vnextReaderIdentifyTestLogical   = "reader-cxld-0"
	vnextReaderIdentifyTestPrincipal = vnextReaderPrepareTestPrincipal
	vnextReaderIdentifyTestServerURI = vnextReaderPrepareTLSTestServerURI
)

type vnextReaderIdentifyTestVerifier struct {
	proof vnextReaderIdentifyAuthorityProof
	err   error
	calls int
}

func (verifier *vnextReaderIdentifyTestVerifier) VerifyVNextReaderIdentifyAuthority(
	_ context.Context,
	_ string,
	_ [sha256.Size]byte,
	_ vnextReaderIdentifyAuthorityEnvelope,
) (vnextReaderIdentifyAuthorityProof, error) {
	verifier.calls++
	return verifier.proof, verifier.err
}

type vnextReaderIdentifyTestFixture struct {
	request     vnextReaderIdentifyRequest
	verifier    *vnextReaderIdentifyTestVerifier
	service     *vnextReaderIdentifyService
	rpc         *vnextReaderIdentifyRPC
	incarnation vnextReaderProcessIncarnation
	frame       []byte
}

func newVNextReaderIdentifyTestFixture(
	t *testing.T,
) *vnextReaderIdentifyTestFixture {
	t.Helper()
	incarnation := vnextReaderProcessIncarnationForTest(0x9a)
	request := vnextReaderIdentifyRequest{
		ExpectedExecutorNodeID: vnextReaderIdentifyTestNode,
		ExpectedCxldLogicalID:  vnextReaderIdentifyTestLogical,
		ChallengeNonce: vnextReaderIdentifyNonce(
			sha256.Sum256([]byte("Reader IDENTIFY challenge nonce"))),
		Authority: vnextReaderIdentifyAuthorityEnvelope{
			Domain:                 vnextReaderIdentifyAuthorityDomain,
			ClusterID:              "8000000000000001",
			SchedulerID:            "scheduler-a",
			SchedulerFenceRevision: 101,
			LeaderLeaseID:          202,
			LeaderTermID: sha256.Sum256(
				[]byte("Reader IDENTIFY term")),
			KeyID: sha256.Sum256([]byte("Reader IDENTIFY key")),
		},
	}
	request.Authority.RequestDigest =
		vnextReaderIdentifyCanonicalRequestDigest(request)
	request.Authority.Signature[0] = 1
	receipt, err := vnextReaderIdentifyCanonicalAuthorityReceipt(
		vnextReaderIdentifyTestPrincipal, request.Authority)
	if err != nil {
		t.Fatalf("derive IDENTIFY test authority receipt: %v", err)
	}
	verifier := &vnextReaderIdentifyTestVerifier{
		proof: vnextReaderIdentifyAuthorityProof{
			AuthenticatedSchedulerPrincipal: vnextReaderIdentifyTestPrincipal,
			SchedulerID:                     request.Authority.SchedulerID,
			SchedulerFenceRevision:          request.Authority.SchedulerFenceRevision,
			LeaderLeaseID:                   request.Authority.LeaderLeaseID,
			LeaderTermID:                    request.Authority.LeaderTermID,
			RequestDigest:                   request.Authority.RequestDigest,
			AuthorityReceipt:                receipt,
		},
	}
	service, err := newVNextReaderIdentifyService(
		vnextReaderIdentifyTestNode,
		vnextReaderIdentifyTestLogical,
		incarnation,
		vnextReaderIdentifyTestServerURI,
		verifier)
	if err != nil {
		t.Fatalf("new IDENTIFY test service: %v", err)
	}
	frame, err := marshalVNextReaderIdentifyRequest(request)
	if err != nil {
		t.Fatalf("marshal IDENTIFY test request: %v", err)
	}
	return &vnextReaderIdentifyTestFixture{
		request: request, verifier: verifier, service: service,
		rpc: newVNextReaderIdentifyRPC(service), incarnation: incarnation,
		frame: frame,
	}
}

func TestVNextReaderIdentifyRPCReturnsCanonicalBoundIdentity(t *testing.T) {
	fixture := newVNextReaderIdentifyTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderIdentifyTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("IDENTIFY RPC failed: %v", failure)
	}
	response, err := decodeVNextReaderIdentifyResponse(body)
	if err != nil {
		t.Fatalf("decode IDENTIFY response: %v", err)
	}
	if response.RequestDigest != fixture.request.Authority.RequestDigest ||
		response.LocalExecutorNodeID != vnextReaderIdentifyTestNode ||
		response.LocalCxldLogicalID != vnextReaderIdentifyTestLogical ||
		response.LocalProcessIncarnation != fixture.incarnation ||
		response.ServerURISAN != vnextReaderIdentifyTestServerURI ||
		fixture.verifier.calls != 1 {
		t.Fatalf("IDENTIFY response lost exact identity: %#v calls=%d",
			response, fixture.verifier.calls)
	}
	if err := validateVNextReaderIdentifyCapabilities(
		response.SupportedProtocols); err != nil {
		t.Fatalf("IDENTIFY response capabilities: %v", err)
	}
	if response.CapabilitiesDigest !=
		vnextReaderIdentifyCanonicalCapabilitiesDigest(
			response.SupportedProtocols) ||
		response.Receipt != vnextReaderIdentifyCanonicalReceipt(response) {
		t.Fatal("IDENTIFY response digest or receipt is not canonical")
	}
	if !bytes.Equal(body, mustMarshalVNextReaderIdentifyResponse(t, response)) {
		t.Fatal("IDENTIFY response encoding is not deterministic")
	}
}

func TestVNextReaderIdentifyV1AdvertisesOnlyCanonicalPrepareAndStatusV2(t *testing.T) {
	if vnextReaderIdentifyProtocol != "cxld.vnext-reader-identify.v1" ||
		vnextReaderIdentifyALPN != "cxld-vnext-reader-identify/1" {
		t.Fatalf("IDENTIFY hard-cut identity = %q/%q",
			vnextReaderIdentifyProtocol, vnextReaderIdentifyALPN)
	}
	if vnextReaderPrepareProtocol != "cxld.vnext-reader-prepare.v2" ||
		vnextReaderPrepareALPN != "cxld-vnext-reader/2" ||
		vnextReaderPrepareAuthorityDomain != "cxld-vnext-reader-prepare-authority-v2" ||
		vnextReaderPrepareAuthoritySignatureDomain != "cxld-vnext-reader-prepare-authority-signature-v2" ||
		vnextReaderPrepareAuthorityReceiptDomain != "cxld-vnext-reader-prepare-authority-receipt-v2" ||
		vnextReaderPrepareRequestDigestDomain != "cxld-vnext-reader-prepare-request-digest-v2" ||
		vnextReaderPrepareReceiptDomain != "cxld-vnext-reader-prepare-receipt-v2" {
		t.Fatal("PREPARE v2 protocol, ALPN, or canonical domain drifted")
	}
	if vnextReaderPreparedStatusProtocol !=
		"cxld.vnext-reader-prepared-status-and-fence.v2" ||
		vnextReaderPreparedStatusALPN != "cxld-vnext-reader-prepared-status/2" ||
		vnextReaderPreparedStatusAuthorityDomain !=
			"cxld-vnext-reader-prepared-status-and-fence-authority-v2" ||
		vnextReaderPreparedStatusAuthoritySignatureDomain !=
			"cxld-vnext-reader-prepared-status-and-fence-authority-signature-v2" ||
		vnextReaderPreparedStatusAuthorityReceiptDomain !=
			"cxld-vnext-reader-prepared-status-and-fence-authority-receipt-v2" ||
		vnextReaderPreparedStatusRequestDigestDomain !=
			"cxld-vnext-reader-prepared-status-and-fence-request-digest-v2" ||
		vnextReaderPreparedStatusResponseReceiptDomain !=
			"cxld-vnext-reader-prepared-status-and-fence-response-receipt-v2" {
		t.Fatal("STATUS_AND_FENCE v2 protocol, ALPN, or canonical domain drifted")
	}
	capabilities := vnextReaderIdentifyCurrentCapabilities()
	if err := validateVNextReaderIdentifyCapabilities(capabilities); err != nil {
		t.Fatalf("validate canonical IDENTIFY capabilities: %v", err)
	}
	digest := vnextReaderIdentifyCanonicalCapabilitiesDigest(capabilities)
	const wantDigest = "2ed26b1132cb10ea75c11fd3663a9b837e277451889926231336c2fd2f5193d1"
	if got := fmt.Sprintf("%x", digest); got != wantDigest {
		t.Fatalf("IDENTIFY v1 capabilities digest = %s, want %s", got, wantDigest)
	}
}

func mustMarshalVNextReaderIdentifyResponse(
	t *testing.T,
	response vnextReaderIdentifyResponse,
) []byte {
	t.Helper()
	body, err := marshalVNextReaderIdentifyResponse(response)
	if err != nil {
		t.Fatalf("marshal IDENTIFY response: %v", err)
	}
	return body
}

func TestVNextReaderIdentifyRejectsIdentityNonceAuthorityAndPrincipal(
	t *testing.T,
) {
	for name, mutate := range map[string]func(*vnextReaderIdentifyTestFixture) string{
		"executor": func(fixture *vnextReaderIdentifyTestFixture) string {
			fixture.request.ExpectedExecutorNodeID = "reader-node-other"
			fixture.request.Authority.RequestDigest =
				vnextReaderIdentifyCanonicalRequestDigest(fixture.request)
			return vnextReaderIdentifyTestPrincipal
		},
		"logical": func(fixture *vnextReaderIdentifyTestFixture) string {
			fixture.request.ExpectedCxldLogicalID = "reader-cxld-other"
			fixture.request.Authority.RequestDigest =
				vnextReaderIdentifyCanonicalRequestDigest(fixture.request)
			return vnextReaderIdentifyTestPrincipal
		},
		"zero-nonce": func(fixture *vnextReaderIdentifyTestFixture) string {
			fixture.request.ChallengeNonce = vnextReaderIdentifyNonce{}
			return vnextReaderIdentifyTestPrincipal
		},
		"nonce-substitution": func(fixture *vnextReaderIdentifyTestFixture) string {
			fixture.request.ChallengeNonce[0] ^= 1
			return vnextReaderIdentifyTestPrincipal
		},
		"authority-domain": func(fixture *vnextReaderIdentifyTestFixture) string {
			fixture.request.Authority.Domain = vnextReaderPrepareAuthorityDomain
			return vnextReaderIdentifyTestPrincipal
		},
		"principal": func(*vnextReaderIdentifyTestFixture) string {
			return "scheduler-a"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderIdentifyTestFixture(t)
			principal := mutate(fixture)
			_, failure := fixture.service.Identify(
				context.Background(), principal, fixture.request)
			if failure == nil {
				t.Fatal("invalid IDENTIFY request was accepted")
			}
			if fixture.verifier.calls != 0 {
				t.Fatalf("pre-authority rejection made %d verifier calls",
					fixture.verifier.calls)
			}
		})
	}
}

func TestVNextReaderIdentifyStrictCodecRejectsSubstitutionAndJSONAmbiguity(
	t *testing.T,
) {
	fixture := newVNextReaderIdentifyTestFixture(t)
	valid := string(fixture.frame)
	mutations := map[string][]byte{
		"PREPARE protocol": []byte(strings.Replace(
			valid, vnextReaderIdentifyProtocol, vnextReaderPrepareProtocol, 1)),
		"PREPARE operation": []byte(strings.Replace(
			valid, vnextReaderIdentifyOperation, vnextReaderPrepareOperation, 1)),
		"unknown field": []byte(strings.Replace(
			valid, "{", "{\"unknown\":\"x\",", 1)),
		"duplicate field": []byte(strings.Replace(
			valid, "{", "{\"protocol\":\""+vnextReaderIdentifyProtocol+"\",", 1)),
		"trailing":      append(append([]byte(nil), fixture.frame...), []byte("{}")...),
		"invalid UTF-8": {0xff},
	}
	for name, body := range mutations {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeVNextReaderIdentifyRequest(body); err == nil {
				t.Fatalf("accepted ambiguous/substituted IDENTIFY body: %s", body)
			}
		})
	}
	if _, err := decodeVNextReaderIdentifyRequest(
		bytes.Repeat([]byte{' '}, vnextReaderIdentifyMaxFrameBytes+1)); err == nil {
		t.Fatal("accepted oversized IDENTIFY frame")
	}
}

func TestVNextReaderIdentifyResponseRejectsEveryIdentityAndCapabilityMutation(
	t *testing.T,
) {
	fixture := newVNextReaderIdentifyTestFixture(t)
	response, failure := fixture.service.Identify(
		context.Background(), vnextReaderIdentifyTestPrincipal, fixture.request)
	if failure != nil {
		t.Fatalf("create IDENTIFY response: %v", failure)
	}
	for name, mutate := range map[string]func(*vnextReaderIdentifyResponse){
		"request digest": func(value *vnextReaderIdentifyResponse) {
			value.RequestDigest[0] ^= 1
		},
		"node": func(value *vnextReaderIdentifyResponse) {
			value.LocalExecutorNodeID = "reader-node-other"
		},
		"logical": func(value *vnextReaderIdentifyResponse) {
			value.LocalCxldLogicalID = "reader-cxld-other"
		},
		"incarnation": func(value *vnextReaderIdentifyResponse) {
			value.LocalProcessIncarnation[0] ^= 1
		},
		"URI SAN": func(value *vnextReaderIdentifyResponse) {
			value.ServerURISAN = "spiffe://test.example/cxld/other"
		},
		"capability": func(value *vnextReaderIdentifyResponse) {
			value.SupportedProtocols[0].ALPN = vnextReaderPrepareALPN
		},
		"capability digest": func(value *vnextReaderIdentifyResponse) {
			value.CapabilitiesDigest[0] ^= 1
		},
		"authority proof": func(value *vnextReaderIdentifyResponse) {
			value.AuthorityProof.AuthorityReceipt[0] ^= 1
		},
		"receipt": func(value *vnextReaderIdentifyResponse) {
			value.Receipt[0] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := response
			mutated.SupportedProtocols = cloneVNextReaderIdentifyCapabilities(
				response.SupportedProtocols)
			mutate(&mutated)
			if _, err := marshalVNextReaderIdentifyResponse(mutated); err == nil {
				t.Fatal("marshaled mutated IDENTIFY response")
			}
		})
	}
}

func TestVNextReaderIdentifyResponseWireRejectsWrongCapabilitiesEvenWithRehashedReceipt(
	t *testing.T,
) {
	fixture := newVNextReaderIdentifyTestFixture(t)
	response, failure := fixture.service.Identify(
		context.Background(), vnextReaderIdentifyTestPrincipal, fixture.request)
	if failure != nil {
		t.Fatal(failure)
	}
	body := mustMarshalVNextReaderIdentifyResponse(t, response)
	var wire map[string]interface{}
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	capabilities := wire["supportedProtocols"].([]interface{})
	capabilities[0].(map[string]interface{})["alpn"] = vnextReaderPrepareALPN
	mutated, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeVNextReaderIdentifyResponse(mutated); err == nil {
		t.Fatal("accepted non-canonical IDENTIFY capabilities")
	}
}

func TestVNextReaderIdentifyCurrentVerifierUsesDedicatedSignatureDomain(
	t *testing.T,
) {
	prepareFixture := newVNextReaderPrepareCurrentTestFixture(t)
	request := newVNextReaderIdentifyTestFixture(t).request
	request.Authority.ClusterID = fmt.Sprintf("%016x", prepareFixture.clusterID)
	request.Authority.SchedulerID = vnextReaderPrepareCurrentTestScheduler
	request.Authority.SchedulerFenceRevision = prepareFixture.fence
	request.Authority.LeaderLeaseID = prepareFixture.lease
	request.Authority.LeaderTermID = prepareFixture.request.Authority.LeaderTermID
	request.Authority.KeyID = prepareFixture.leader.KeyID
	request.Authority.RequestDigest =
		vnextReaderIdentifyCanonicalRequestDigest(request)
	preimage, err := vnextReaderIdentifyAuthoritySignaturePreimage(request.Authority)
	if err != nil {
		t.Fatal(err)
	}
	copy(request.Authority.Signature[:],
		ed25519.Sign(prepareFixture.private, preimage))
	verifier, err := newVNextReaderIdentifyCurrentAuthorityVerifier(
		vnextReaderIdentifyCurrentAuthorityConfig{
			LeaderKey:       vnextReaderPrepareCurrentTestLeaderKey,
			ExpectedCluster: prepareFixture.clusterID,
			ReadTimeout:     prepareFixture.config.ReadTimeout,
			SchedulerByPrincipal: map[string]string{
				vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
			},
		},
		prepareFixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := verifier.VerifyVNextReaderIdentifyAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		request.Authority.RequestDigest, request.Authority)
	if err != nil || proof.RequestDigest != request.Authority.RequestDigest ||
		prepareFixture.reader.callCount() != 1 {
		t.Fatalf("verify IDENTIFY current authority proof=%#v err=%v reads=%d",
			proof, err, prepareFixture.reader.callCount())
	}

	// A valid Ed25519 signature under the PREPARE domain cannot be substituted
	// into the IDENTIFY envelope.
	prepareFixture = newVNextReaderPrepareCurrentTestFixture(t)
	request.Authority.Signature = [ed25519.SignatureSize]byte{}
	prepareAuthority := vnextReaderPrepareAuthorityEnvelope{
		Domain:                 vnextReaderPrepareAuthorityDomain,
		ClusterID:              request.Authority.ClusterID,
		SchedulerID:            request.Authority.SchedulerID,
		SchedulerFenceRevision: request.Authority.SchedulerFenceRevision,
		LeaderLeaseID:          request.Authority.LeaderLeaseID,
		LeaderTermID:           request.Authority.LeaderTermID,
		KeyID:                  request.Authority.KeyID,
		RequestDigest:          request.Authority.RequestDigest,
	}
	preparePreimage, err := vnextReaderPrepareAuthoritySignaturePreimage(
		prepareAuthority)
	if err != nil {
		t.Fatal(err)
	}
	copy(request.Authority.Signature[:],
		ed25519.Sign(prepareFixture.private, preparePreimage))
	verifier, err = newVNextReaderIdentifyCurrentAuthorityVerifier(
		vnextReaderIdentifyCurrentAuthorityConfig{
			LeaderKey:       vnextReaderPrepareCurrentTestLeaderKey,
			ExpectedCluster: prepareFixture.clusterID,
			ReadTimeout:     prepareFixture.config.ReadTimeout,
			SchedulerByPrincipal: map[string]string{
				vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
			},
		}, prepareFixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	if proof, err = verifier.VerifyVNextReaderIdentifyAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		request.Authority.RequestDigest, request.Authority); err == nil ||
		proof != (vnextReaderIdentifyAuthorityProof{}) ||
		!errors.Is(err, errVNextReaderIdentifyCurrentAuthority) {
		t.Fatalf("accepted cross-protocol signature proof=%#v err=%v", proof, err)
	}
}

func TestVNextReaderIdentifyCurrentVerifierRejectsStaleLeaderAndUnboundPrincipal(
	t *testing.T,
) {
	prepareFixture := newVNextReaderPrepareCurrentTestFixture(t)
	request := newVNextReaderIdentifyTestFixture(t).request
	request.Authority.ClusterID = fmt.Sprintf("%016x", prepareFixture.clusterID)
	request.Authority.SchedulerID = vnextReaderPrepareCurrentTestScheduler
	request.Authority.SchedulerFenceRevision = prepareFixture.fence
	request.Authority.LeaderLeaseID = prepareFixture.lease
	request.Authority.LeaderTermID = prepareFixture.request.Authority.LeaderTermID
	request.Authority.KeyID = prepareFixture.leader.KeyID
	request.Authority.RequestDigest =
		vnextReaderIdentifyCanonicalRequestDigest(request)
	preimage, err := vnextReaderIdentifyAuthoritySignaturePreimage(request.Authority)
	if err != nil {
		t.Fatal(err)
	}
	copy(request.Authority.Signature[:],
		ed25519.Sign(prepareFixture.private, preimage))
	verifier, err := newVNextReaderIdentifyCurrentAuthorityVerifier(
		vnextReaderIdentifyCurrentAuthorityConfig{
			LeaderKey:       vnextReaderPrepareCurrentTestLeaderKey,
			ExpectedCluster: prepareFixture.clusterID,
			ReadTimeout:     prepareFixture.config.ReadTimeout,
			SchedulerByPrincipal: map[string]string{
				vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
			},
		}, prepareFixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	if proof, err := verifier.VerifyVNextReaderIdentifyAuthority(
		context.Background(), "spiffe://test.example/scheduler/unbound",
		request.Authority.RequestDigest, request.Authority); err == nil ||
		proof != (vnextReaderIdentifyAuthorityProof{}) ||
		prepareFixture.reader.callCount() != 0 {
		t.Fatalf("unbound principal proof=%#v err=%v reads=%d",
			proof, err, prepareFixture.reader.callCount())
	}
	prepareFixture.reader.mu.Lock()
	prepareFixture.reader.snapshot.KVs[0].CreateRevision++
	prepareFixture.reader.snapshot.KVs[0].ModRevision =
		prepareFixture.reader.snapshot.KVs[0].CreateRevision
	prepareFixture.reader.mu.Unlock()
	if proof, err := verifier.VerifyVNextReaderIdentifyAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		request.Authority.RequestDigest, request.Authority); err == nil ||
		proof != (vnextReaderIdentifyAuthorityProof{}) ||
		!errors.Is(err, errVNextReaderIdentifyCurrentAuthority) ||
		prepareFixture.reader.callCount() != 1 {
		t.Fatalf("stale leader proof=%#v err=%v reads=%d",
			proof, err, prepareFixture.reader.callCount())
	}
}
