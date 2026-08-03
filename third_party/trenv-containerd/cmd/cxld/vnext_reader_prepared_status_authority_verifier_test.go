package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderPreparedStatusCurrentTestPrincipal = "spiffe://test.example/scheduler/status-leader"
	vnextReaderPreparedStatusCurrentTestScheduler = "scheduler-status-leader"
	vnextReaderPreparedStatusCurrentTestLeaderKey = "/test-cluster/cxl-checkpoint/global-orchestrator-leader"
)

type vnextReaderPreparedStatusCurrentTestFixture struct {
	clusterID uint64
	fence     uint64
	lease     uint64
	private   ed25519.PrivateKey
	public    ed25519.PublicKey
	request   vnextReaderPreparedStatusRequest
	snapshot  vnextOwnerSchedulerLeaderSnapshot
	reader    *vnextReaderPrepareCurrentTestReader
	config    vnextReaderPreparedStatusCurrentAuthorityConfig
	verifier  *vnextReaderPreparedStatusCurrentAuthorityVerifier
}

func newVNextReaderPreparedStatusCurrentTestFixture(
	t *testing.T,
) *vnextReaderPreparedStatusCurrentTestFixture {
	t.Helper()
	clusterID := uint64(0x8000000000000042)
	fence := uint64(501)
	lease := uint64(777)
	seed := sha256.Sum256([]byte(
		"VNext Reader STATUS_AND_FENCE current authority Ed25519 seed"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := append(ed25519.PublicKey(nil),
		private.Public().(ed25519.PublicKey)...)
	nonce := sha256.Sum256([]byte(
		"VNext Reader STATUS_AND_FENCE current authority term nonce"))
	leaderValue, err := formatVNextOwnerSchedulerLeaderValue(
		vnextReaderPreparedStatusCurrentTestScheduler, lease, nonce, public)
	if err != nil {
		t.Fatalf("format status current leader: %v", err)
	}
	leader, err := parseVNextOwnerSchedulerLeaderValue(leaderValue)
	if err != nil {
		t.Fatalf("parse status current leader: %v", err)
	}
	parsed := vnextOwnerSchedulerParsedAuthority{
		ClusterID:      clusterID,
		CreateRevision: fence,
		ModRevision:    fence,
		LeaseID:        lease,
		LeaderValue:    leaderValue,
		Leader:         leader,
	}
	termID := vnextOwnerSchedulerTermDigest(
		vnextReaderPreparedStatusCurrentTestLeaderKey, parsed)

	acquired := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-status-current-verifier")
	// A deliberately remains from a different historical Scheduler term.
	acquired.SchedulerID = "scheduler-historical"
	acquired.SchedulerFenceRevision = 19
	request := vnextReaderPreparedStatusTestRequest(acquired)
	request.Authority.ClusterID = fmt.Sprintf("%016x", clusterID)
	request.Authority.SchedulerID =
		vnextReaderPreparedStatusCurrentTestScheduler
	request.Authority.SchedulerFenceRevision = fence
	request.Authority.LeaderLeaseID = lease
	request.Authority.LeaderTermID = termID
	request.Authority.KeyID = leader.KeyID
	request.Authority.RequestDigest =
		vnextReaderPreparedStatusCanonicalRequestDigest(acquired)
	preimage, err := vnextReaderPreparedStatusAuthoritySignaturePreimage(
		request.Authority)
	if err != nil {
		t.Fatalf("build status signature preimage: %v", err)
	}
	copy(request.Authority.Signature[:], ed25519.Sign(private, preimage))

	snapshot := vnextOwnerSchedulerLeaderSnapshot{
		HeaderPresent:  true,
		HeaderCluster:  clusterID,
		HeaderRevision: int64(fence + 3),
		Count:          1,
		KVs: []vnextOwnerSchedulerLeaderKV{{
			Key:            []byte(vnextReaderPreparedStatusCurrentTestLeaderKey),
			Value:          []byte(leaderValue),
			CreateRevision: int64(fence),
			ModRevision:    int64(fence),
			Version:        1,
			Lease:          int64(lease),
		}},
	}
	reader := &vnextReaderPrepareCurrentTestReader{snapshot: snapshot}
	config := vnextReaderPreparedStatusCurrentAuthorityConfig{
		LeaderKey:       vnextReaderPreparedStatusCurrentTestLeaderKey,
		ExpectedCluster: clusterID,
		ReadTimeout:     time.Second,
		SchedulerByPrincipal: map[string]string{
			vnextReaderPreparedStatusCurrentTestPrincipal: vnextReaderPreparedStatusCurrentTestScheduler,
		},
	}
	verifier, err := newVNextReaderPreparedStatusCurrentAuthorityVerifier(
		config, reader)
	if err != nil {
		t.Fatalf("new status current authority verifier: %v", err)
	}
	return &vnextReaderPreparedStatusCurrentTestFixture{
		clusterID: clusterID,
		fence:     fence,
		lease:     lease,
		private:   private,
		public:    public,
		request:   request,
		snapshot:  snapshot,
		reader:    reader,
		config:    config,
		verifier:  verifier,
	}
}

func assertVNextReaderPreparedStatusCurrentFailure(
	t *testing.T,
	proof vnextReaderPreparedStatusAuthorityProof,
	err error,
) {
	t.Helper()
	if err == nil ||
		!errors.Is(err, errVNextReaderPreparedStatusCurrentAuthority) {
		t.Fatalf("current status authority error=%v, want typed rejection", err)
	}
	if proof != (vnextReaderPreparedStatusAuthorityProof{}) {
		t.Fatalf("failed verifier returned partial proof: %#v", proof)
	}
}

func TestVNextReaderPreparedStatusCurrentVerifierAcceptsPriorAWithCurrentB(t *testing.T) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	if fixture.request.Acquired.SchedulerID == fixture.request.Authority.SchedulerID ||
		fixture.request.Acquired.SchedulerFenceRevision ==
			fixture.request.Authority.SchedulerFenceRevision {
		t.Fatal("fixture did not separate historical A and current B")
	}
	proof, err := fixture.verifier.VerifyVNextReaderPreparedStatusAuthority(
		context.Background(),
		vnextReaderPreparedStatusCurrentTestPrincipal,
		fixture.request.Authority.RequestDigest,
		fixture.request.Authority)
	if err != nil {
		t.Fatalf("verify status current authority: %v", err)
	}
	wantReceipt, err := vnextReaderPreparedStatusCanonicalAuthorityReceipt(
		vnextReaderPreparedStatusCurrentTestPrincipal,
		fixture.request.Authority)
	if err != nil {
		t.Fatal(err)
	}
	if proof.AuthenticatedSchedulerPrincipal !=
		vnextReaderPreparedStatusCurrentTestPrincipal ||
		proof.SchedulerID != vnextReaderPreparedStatusCurrentTestScheduler ||
		proof.SchedulerFenceRevision != fixture.fence ||
		proof.LeaderLeaseID != fixture.lease ||
		proof.LeaderTermID != fixture.request.Authority.LeaderTermID ||
		proof.RequestDigest != fixture.request.Authority.RequestDigest ||
		proof.AuthorityReceipt != wantReceipt {
		t.Fatalf("status current proof lost B identity: %#v", proof)
	}
	if fixture.reader.callCount() != 1 {
		t.Fatalf("linearizable leader reads=%d, want exactly 1",
			fixture.reader.callCount())
	}
	keys := fixture.reader.recordedKeys()
	if len(keys) != 1 ||
		keys[0] != vnextReaderPreparedStatusCurrentTestLeaderKey {
		t.Fatalf("linearizable reader queried keys %#v", keys)
	}
}

func TestVNextReaderPreparedStatusRealAuthorityServiceCallsReadAndStoreOnce(
	t *testing.T,
) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	inner, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	store := &vnextReaderPreparedStatusTestStore{inner: inner}
	service, err := newVNextReaderPreparedStatusService(
		fixture.request.Acquired.Authorization.ExecutorID,
		fixture.request.Acquired.Authorization.CxldInstanceID,
		store,
		fixture.verifier)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := marshalVNextReaderPreparedStatusRequest(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	body, failure := newVNextReaderPreparedStatusRPC(service).Handle(
		context.Background(),
		vnextReaderPreparedStatusCurrentTestPrincipal,
		frame)
	if failure != nil {
		t.Fatalf("real-authority status service: %v", failure)
	}
	response, err := decodeVNextReaderPreparedStatusResponse(body)
	if err != nil ||
		response.Result.State != vnextReaderPreparedStatusNotPreparedFenced ||
		response.Acquired.SchedulerID != "scheduler-historical" ||
		response.AuthorityProof.SchedulerID !=
			vnextReaderPreparedStatusCurrentTestScheduler {
		t.Fatalf("real-authority response=%#v/%v", response, err)
	}
	if fixture.reader.callCount() != 1 || store.callCount() != 1 ||
		len(inner.byID) != 1 {
		t.Fatalf("real verifier/store/decision=%d/%d/%d, want 1/1/1",
			fixture.reader.callCount(), store.callCount(), len(inner.byID))
	}
}

func TestVNextReaderPreparedStatusCurrentVerifierRejectsPrincipalAndEnvelopeBeforeRead(
	t *testing.T,
) {
	tests := map[string]func(
		*vnextReaderPreparedStatusCurrentTestFixture,
	) (string, [sha256.Size]byte, vnextReaderPreparedStatusAuthorityEnvelope){
		"non-URI principal": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPreparedStatusAuthorityEnvelope) {
			return "scheduler-status-leader",
				fixture.request.Authority.RequestDigest, fixture.request.Authority
		},
		"unbound principal": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPreparedStatusAuthorityEnvelope) {
			return "spiffe://test.example/scheduler/unbound",
				fixture.request.Authority.RequestDigest, fixture.request.Authority
		},
		"request digest argument": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPreparedStatusAuthorityEnvelope) {
			digest := fixture.request.Authority.RequestDigest
			digest[0] ^= 0xff
			return vnextReaderPreparedStatusCurrentTestPrincipal,
				digest, fixture.request.Authority
		},
		"authority domain": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPreparedStatusAuthorityEnvelope) {
			authority := fixture.request.Authority
			authority.Domain = vnextReaderPrepareAuthorityDomain
			return vnextReaderPreparedStatusCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest, authority
		},
		"pinned cluster": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPreparedStatusAuthorityEnvelope) {
			authority := fixture.request.Authority
			authority.ClusterID = "0000000000000001"
			return vnextReaderPreparedStatusCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest, authority
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
			principal, digest, authority := mutate(fixture)
			proof, err := fixture.verifier.
				VerifyVNextReaderPreparedStatusAuthority(
					context.Background(), principal, digest, authority)
			assertVNextReaderPreparedStatusCurrentFailure(t, proof, err)
			if fixture.reader.callCount() != 0 {
				t.Fatalf("pre-read rejection made %d leader reads",
					fixture.reader.callCount())
			}
		})
	}
}

func TestVNextReaderPreparedStatusSignatureCannotReusePrepareDomain(t *testing.T) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	status := fixture.request.Authority
	prepare := vnextReaderPrepareAuthorityEnvelope{
		Domain:                 vnextReaderPrepareAuthorityDomain,
		ClusterID:              status.ClusterID,
		SchedulerID:            status.SchedulerID,
		SchedulerFenceRevision: status.SchedulerFenceRevision,
		LeaderLeaseID:          status.LeaderLeaseID,
		LeaderTermID:           status.LeaderTermID,
		KeyID:                  status.KeyID,
		RequestDigest:          status.RequestDigest,
	}
	preimage, err := vnextReaderPrepareAuthoritySignaturePreimage(prepare)
	if err != nil {
		t.Fatal(err)
	}
	copy(status.Signature[:], ed25519.Sign(fixture.private, preimage))
	proof, err := fixture.verifier.VerifyVNextReaderPreparedStatusAuthority(
		context.Background(),
		vnextReaderPreparedStatusCurrentTestPrincipal,
		status.RequestDigest,
		status)
	assertVNextReaderPreparedStatusCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 1 {
		t.Fatalf("cross-domain signature made %d reads, want one current check",
			fixture.reader.callCount())
	}
}

func TestVNextReaderPreparedStatusSignaturePreimageBindsEveryCurrentBField(
	t *testing.T,
) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	base := fixture.request.Authority
	preimage, err := vnextReaderPreparedStatusAuthoritySignaturePreimage(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*vnextReaderPreparedStatusAuthorityEnvelope){
		"cluster": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.ClusterID = "8000000000000043"
		},
		"Scheduler": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.SchedulerID += "-other"
		},
		"fence": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.SchedulerFenceRevision++
		},
		"lease": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.LeaderLeaseID++
		},
		"term": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.LeaderTermID[0] ^= 0xff
		},
		"key": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.KeyID[0] ^= 0xff
		},
		"request digest": func(value *vnextReaderPreparedStatusAuthorityEnvelope) {
			value.RequestDigest[0] ^= 0xff
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			changed, err :=
				vnextReaderPreparedStatusAuthoritySignaturePreimage(candidate)
			if err != nil || bytes.Equal(changed, preimage) {
				t.Fatalf("B mutation did not change signature preimage: %v", err)
			}
		})
	}
	changedSignature := base
	changedSignature.Signature[0] ^= 0xff
	withoutSignature, err :=
		vnextReaderPreparedStatusAuthoritySignaturePreimage(changedSignature)
	if err != nil || !bytes.Equal(withoutSignature, preimage) {
		t.Fatalf("signature was included in its own preimage: %v", err)
	}
	wrongDomain := base
	wrongDomain.Domain = vnextReaderPrepareAuthorityDomain
	if _, err := vnextReaderPreparedStatusAuthoritySignaturePreimage(
		wrongDomain); err == nil {
		t.Fatal("PREPARE domain produced a status signature preimage")
	}
}

func TestVNextReaderPreparedStatusCurrentSnapshotMustBeExact(t *testing.T) {
	tests := map[string]func(*vnextReaderPreparedStatusCurrentTestFixture){
		"header cluster": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.reader.snapshot.HeaderCluster++
		},
		"count": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.reader.snapshot.Count = 2
		},
		"different key": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Key = []byte("/different")
		},
		"mutable KV": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].ModRevision++
		},
		"fence": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].CreateRevision++
			fixture.reader.snapshot.KVs[0].ModRevision++
		},
		"lease": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Lease++
		},
		"term": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.request.Authority.LeaderTermID[0] ^= 0xff
		},
		"key ID": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.request.Authority.KeyID[0] ^= 0xff
		},
		"signature": func(fixture *vnextReaderPreparedStatusCurrentTestFixture) {
			fixture.request.Authority.Signature[0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
			mutate(fixture)
			proof, err := fixture.verifier.
				VerifyVNextReaderPreparedStatusAuthority(
					context.Background(),
					vnextReaderPreparedStatusCurrentTestPrincipal,
					fixture.request.Authority.RequestDigest,
					fixture.request.Authority)
			assertVNextReaderPreparedStatusCurrentFailure(t, proof, err)
			if fixture.reader.callCount() != 1 {
				t.Fatalf("current snapshot rejection made %d reads, want 1",
					fixture.reader.callCount())
			}
		})
	}
}

func TestVNextReaderPreparedStatusCurrentVerifierHonorsContext(t *testing.T) {
	t.Run("pre-cancelled", func(t *testing.T) {
		fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		proof, err := fixture.verifier.VerifyVNextReaderPreparedStatusAuthority(
			ctx,
			vnextReaderPreparedStatusCurrentTestPrincipal,
			fixture.request.Authority.RequestDigest,
			fixture.request.Authority)
		assertVNextReaderPreparedStatusCurrentFailure(t, proof, err)
		if fixture.reader.callCount() != 0 {
			t.Fatal("pre-cancelled verification read current leader")
		}
	})

	t.Run("cancelled read", func(t *testing.T) {
		fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
		started := make(chan struct{})
		fixture.reader.handler = func(ctx context.Context, _ string) (
			vnextOwnerSchedulerLeaderSnapshot, error) {
			close(started)
			<-ctx.Done()
			return vnextOwnerSchedulerLeaderSnapshot{}, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			<-started
			cancel()
		}()
		proof, err := fixture.verifier.VerifyVNextReaderPreparedStatusAuthority(
			ctx,
			vnextReaderPreparedStatusCurrentTestPrincipal,
			fixture.request.Authority.RequestDigest,
			fixture.request.Authority)
		assertVNextReaderPreparedStatusCurrentFailure(t, proof, err)
		if fixture.reader.callCount() != 1 {
			t.Fatalf("cancelled verification reads=%d, want 1",
				fixture.reader.callCount())
		}
	})
}

func TestVNextReaderPreparedStatusCurrentVerifierConcurrentReadsRemainExact(t *testing.T) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	const callers = 32
	start := make(chan struct{})
	errorsFound := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			<-start
			proof, err := fixture.verifier.
				VerifyVNextReaderPreparedStatusAuthority(
					context.Background(),
					vnextReaderPreparedStatusCurrentTestPrincipal,
					fixture.request.Authority.RequestDigest,
					fixture.request.Authority)
			if err != nil || proof.SchedulerFenceRevision != fixture.fence {
				errorsFound <- fmt.Errorf("concurrent proof=%#v err=%v", proof, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	if fixture.reader.callCount() != callers {
		t.Fatalf("concurrent exact reads=%d, want %d",
			fixture.reader.callCount(), callers)
	}
}

func TestVNextReaderPreparedStatusCurrentVerifierConstructorBoundsAndClones(
	t *testing.T,
) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	valid := fixture.config
	bindings := valid.SchedulerByPrincipal
	verifier, err := newVNextReaderPreparedStatusCurrentAuthorityVerifier(
		valid, fixture.reader)
	if err != nil {
		t.Fatal(err)
	}
	bindings[vnextReaderPreparedStatusCurrentTestPrincipal] = "mutated"
	if verifier.schedulerByPrincipal[vnextReaderPreparedStatusCurrentTestPrincipal] !=
		vnextReaderPreparedStatusCurrentTestScheduler {
		t.Fatal("verifier retained caller principal map")
	}

	tests := map[string]func(*vnextReaderPreparedStatusCurrentAuthorityConfig){
		"empty leader key": func(config *vnextReaderPreparedStatusCurrentAuthorityConfig) {
			config.LeaderKey = ""
		},
		"zero cluster": func(config *vnextReaderPreparedStatusCurrentAuthorityConfig) {
			config.ExpectedCluster = 0
		},
		"zero timeout": func(config *vnextReaderPreparedStatusCurrentAuthorityConfig) {
			config.ReadTimeout = 0
		},
		"long timeout": func(config *vnextReaderPreparedStatusCurrentAuthorityConfig) {
			config.ReadTimeout = vnextReaderPreparedStatusAuthorityMaxReadTimeout +
				time.Nanosecond
		},
		"empty bindings": func(config *vnextReaderPreparedStatusCurrentAuthorityConfig) {
			config.SchedulerByPrincipal = nil
		},
		"non-URI binding": func(config *vnextReaderPreparedStatusCurrentAuthorityConfig) {
			config.SchedulerByPrincipal = map[string]string{"scheduler": "scheduler"}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			config := fixture.config
			config.SchedulerByPrincipal = map[string]string{
				vnextReaderPreparedStatusCurrentTestPrincipal: vnextReaderPreparedStatusCurrentTestScheduler,
			}
			mutate(&config)
			if verifier, err :=
				newVNextReaderPreparedStatusCurrentAuthorityVerifier(
					config, fixture.reader); err == nil || verifier != nil {
				t.Fatalf("invalid constructor=%#v/%v", verifier, err)
			}
		})
	}
	if verifier, err := newVNextReaderPreparedStatusCurrentAuthorityVerifier(
		fixture.config, nil); err == nil || verifier != nil {
		t.Fatalf("nil reader constructor=%#v/%v", verifier, err)
	}
	var typedNilReader *vnextReaderPrepareCurrentTestReader
	if verifier, err := newVNextReaderPreparedStatusCurrentAuthorityVerifier(
		fixture.config, typedNilReader); err == nil || verifier != nil {
		t.Fatalf("typed-nil reader constructor=%#v/%v", verifier, err)
	}

	tooMany := fixture.config
	tooMany.SchedulerByPrincipal = make(map[string]string,
		vnextReaderPreparedStatusAuthorityMaxPrincipals+1)
	for index := 0; index <= vnextReaderPreparedStatusAuthorityMaxPrincipals; index++ {
		tooMany.SchedulerByPrincipal[fmt.Sprintf("spiffe://test.example/scheduler/%02d", index)] =
			fmt.Sprintf("scheduler-%02d", index)
	}
	if verifier, err := newVNextReaderPreparedStatusCurrentAuthorityVerifier(
		tooMany, fixture.reader); err == nil || verifier != nil {
		t.Fatalf("65-principal constructor=%#v/%v", verifier, err)
	}

	overBudget := fixture.config
	overBudget.SchedulerByPrincipal = make(map[string]string,
		vnextReaderPreparedStatusAuthorityMaxPrincipals)
	for index := 0; index < vnextReaderPreparedStatusAuthorityMaxPrincipals; index++ {
		prefix := fmt.Sprintf("spiffe://test.example/status/%02d/", index)
		principal := prefix + strings.Repeat(
			"p", cxlcheckpoint.MaxIdentityBytes-len(prefix))
		suffix := fmt.Sprintf("%02d", index)
		schedulerID := strings.Repeat(
			"s", cxlcheckpoint.MaxIdentityBytes-len(suffix)) + suffix
		overBudget.SchedulerByPrincipal[principal] = schedulerID
	}
	if verifier, err := newVNextReaderPreparedStatusCurrentAuthorityVerifier(
		overBudget, fixture.reader); err == nil || verifier != nil {
		t.Fatalf("over-budget principal constructor=%#v/%v", verifier, err)
	}
}

func TestVNextReaderPreparedStatusStableCrossLanguageFixtureValues(t *testing.T) {
	fixture := newVNextReaderPreparedStatusCurrentTestFixture(t)
	preimage, err := vnextReaderPreparedStatusAuthoritySignaturePreimage(
		fixture.request.Authority)
	if err != nil {
		t.Fatal(err)
	}
	preimageDigest := sha256.Sum256(preimage)
	proof, err := fixture.verifier.VerifyVNextReaderPreparedStatusAuthority(
		context.Background(),
		vnextReaderPreparedStatusCurrentTestPrincipal,
		fixture.request.Authority.RequestDigest,
		fixture.request.Authority)
	if err != nil {
		t.Fatal(err)
	}
	base := vnextReaderPreparedStatusResponse{
		RequestDigest:       fixture.request.Authority.RequestDigest,
		AuthorityProof:      proof,
		LocalExecutorNodeID: fixture.request.Acquired.Authorization.ExecutorID,
		LocalCxldInstanceID: fixture.request.Acquired.Authorization.CxldInstanceID,
		Acquired:            fixture.request.Acquired,
		Result: vnextReaderPreparedStatusAndFenceResult{
			State: vnextReaderPreparedStatusNotPreparedFenced,
		},
	}
	base.Receipt = vnextReaderPreparedStatusCanonicalResponseReceipt(base)
	prepared := base
	prepared.Result = vnextReaderPreparedStatusAndFenceResult{
		State: vnextReaderPreparedStatusExactPrepared,
		Prepared: vnextReaderPreparedAuthorization{
			Acquired:         fixture.request.Acquired,
			PreparationState: vnextReaderPreparationPrepared,
		},
	}
	prepared.Receipt = vnextReaderPreparedStatusCanonicalResponseReceipt(prepared)
	// These hashes are the cross-language ABI fixtures for the distinct status
	// domains and canonical field order. They must be updated only together
	// with every Scheduler signer/verifier implementation.
	want := map[string]string{
		"request digest":            "38a2ae1f2d59b2d23dda37e79b218823ab1788599ce090e385cf264ae2ba8d79",
		"signature preimage":        "324374896e5cc8b45234c7c513ff766e3f12dc47618b576a401b0d1a6649eeb9",
		"authority receipt":         "82d5edfb4b4061eebcedfa44744a43b6f4ec248638cf03cfedc943af62bfd2e2",
		"fenced response receipt":   "a22eaa89a9cebea5a0cd7d702ec1d27e578db401aabdcd5bae96f7306e302b8a",
		"prepared response receipt": "e951b162eb840135fc0b456d4ba091b4ed351ce0fdc0e33660066fcfcaf09a77",
	}
	got := map[string]string{
		"request digest":            fmt.Sprintf("%x", fixture.request.Authority.RequestDigest),
		"signature preimage":        fmt.Sprintf("%x", preimageDigest),
		"authority receipt":         fmt.Sprintf("%x", proof.AuthorityReceipt),
		"fenced response receipt":   fmt.Sprintf("%x", base.Receipt),
		"prepared response receipt": fmt.Sprintf("%x", prepared.Receipt),
	}
	for name, wantHex := range want {
		if got[name] != wantHex {
			t.Fatalf("stable %s=%s, want %s", name, got[name], wantHex)
		}
	}
}
