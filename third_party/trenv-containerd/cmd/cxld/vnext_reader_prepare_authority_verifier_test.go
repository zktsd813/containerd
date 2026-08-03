package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderPrepareCurrentTestPrincipal = "spiffe://test.example/scheduler/scheduler-current"
	vnextReaderPrepareCurrentTestScheduler = "scheduler-current"
	vnextReaderPrepareCurrentTestLeaderKey = "/test-cluster/cxl-checkpoint/global-orchestrator-leader"
)

type vnextReaderPrepareCurrentTestReader struct {
	mu       sync.Mutex
	snapshot vnextOwnerSchedulerLeaderSnapshot
	err      error
	calls    int
	keys     []string
	handler  func(context.Context, string) (vnextOwnerSchedulerLeaderSnapshot, error)
}

func (reader *vnextReaderPrepareCurrentTestReader) LinearizableGetExact(
	ctx context.Context,
	key string,
) (vnextOwnerSchedulerLeaderSnapshot, error) {
	reader.mu.Lock()
	reader.calls++
	reader.keys = append(reader.keys, key)
	handler := reader.handler
	snapshot := cloneVNextReaderPrepareCurrentTestSnapshot(reader.snapshot)
	err := reader.err
	reader.mu.Unlock()
	if handler != nil {
		return handler(ctx, key)
	}
	return snapshot, err
}

func (reader *vnextReaderPrepareCurrentTestReader) callCount() int {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return reader.calls
}

func (reader *vnextReaderPrepareCurrentTestReader) recordedKeys() []string {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	return append([]string(nil), reader.keys...)
}

func cloneVNextReaderPrepareCurrentTestSnapshot(
	snapshot vnextOwnerSchedulerLeaderSnapshot,
) vnextOwnerSchedulerLeaderSnapshot {
	cloned := snapshot
	cloned.KVs = make([]vnextOwnerSchedulerLeaderKV, len(snapshot.KVs))
	for index, kv := range snapshot.KVs {
		cloned.KVs[index] = kv
		cloned.KVs[index].Key = append([]byte(nil), kv.Key...)
		cloned.KVs[index].Value = append([]byte(nil), kv.Value...)
	}
	return cloned
}

func vnextReaderPrepareCurrentTestLeaderValue(
	t *testing.T,
	schedulerID string,
	leaseID uint64,
	publicKey ed25519.PublicKey,
	nonceLabel string,
) []byte {
	t.Helper()
	nonce := sha256.Sum256([]byte(nonceLabel))
	value, err := formatVNextOwnerSchedulerLeaderValue(
		schedulerID, leaseID, nonce, publicKey)
	if err != nil {
		t.Fatalf("format mutated global Scheduler leader value: %v", err)
	}
	return []byte(value)
}

type vnextReaderPrepareCurrentTestFixture struct {
	clusterID uint64
	fence     uint64
	lease     uint64
	private   ed25519.PrivateKey
	public    ed25519.PublicKey
	leader    vnextOwnerSchedulerLeaderTerm
	request   vnextReaderPrepareRequest
	snapshot  vnextOwnerSchedulerLeaderSnapshot
	reader    *vnextReaderPrepareCurrentTestReader
	config    vnextReaderPrepareCurrentAuthorityConfig
	verifier  *vnextReaderPrepareCurrentAuthorityVerifier
}

func newVNextReaderPrepareCurrentTestFixture(
	t *testing.T,
) *vnextReaderPrepareCurrentTestFixture {
	t.Helper()
	clusterID := uint64(0x8000000000000001)
	fence := uint64(101)
	lease := uint64(202)
	seed := sha256.Sum256([]byte("VNext Reader PREPARE current authority Ed25519 seed"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...)
	nonce := sha256.Sum256([]byte("VNext Reader PREPARE current authority term nonce"))
	leaderValue, err := formatVNextOwnerSchedulerLeaderValue(
		vnextReaderPrepareCurrentTestScheduler, lease, nonce, public)
	if err != nil {
		t.Fatalf("format current Scheduler leader value: %v", err)
	}
	leader, err := parseVNextOwnerSchedulerLeaderValue(leaderValue)
	if err != nil {
		t.Fatalf("parse current Scheduler leader value: %v", err)
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
		vnextReaderPrepareCurrentTestLeaderKey, parsed)

	acquired := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-current-authority-a")
	acquired.SchedulerID = vnextReaderPrepareCurrentTestScheduler
	acquired.SchedulerFenceRevision = fence
	request := vnextReaderPrepareTestRequest(acquired)
	request.Authority.ClusterID = fmt.Sprintf("%016x", clusterID)
	request.Authority.SchedulerID = vnextReaderPrepareCurrentTestScheduler
	request.Authority.SchedulerFenceRevision = fence
	request.Authority.LeaderLeaseID = lease
	request.Authority.LeaderTermID = termID
	request.Authority.KeyID = leader.KeyID
	request.Authority.RequestDigest =
		vnextReaderPrepareCanonicalRequestDigest(acquired)
	preimage, err := vnextReaderPrepareAuthoritySignaturePreimage(request.Authority)
	if err != nil {
		t.Fatalf("build Reader authority signature preimage: %v", err)
	}
	copy(request.Authority.Signature[:], ed25519.Sign(private, preimage))

	snapshot := vnextOwnerSchedulerLeaderSnapshot{
		HeaderPresent:  true,
		HeaderCluster:  clusterID,
		HeaderRevision: int64(fence + 7),
		Count:          1,
		KVs: []vnextOwnerSchedulerLeaderKV{{
			Key:            []byte(vnextReaderPrepareCurrentTestLeaderKey),
			Value:          []byte(leaderValue),
			CreateRevision: int64(fence),
			ModRevision:    int64(fence),
			Version:        1,
			Lease:          int64(lease),
		}},
	}
	reader := &vnextReaderPrepareCurrentTestReader{snapshot: snapshot}
	config := vnextReaderPrepareCurrentAuthorityConfig{
		LeaderKey:       vnextReaderPrepareCurrentTestLeaderKey,
		ExpectedCluster: clusterID,
		ReadTimeout:     time.Second,
		SchedulerByPrincipal: map[string]string{
			vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
		},
	}
	verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(config, reader)
	if err != nil {
		t.Fatalf("new current Scheduler authority verifier: %v", err)
	}
	return &vnextReaderPrepareCurrentTestFixture{
		clusterID: clusterID,
		fence:     fence,
		lease:     lease,
		private:   private,
		public:    public,
		leader:    leader,
		request:   request,
		snapshot:  snapshot,
		reader:    reader,
		config:    config,
		verifier:  verifier,
	}
}

func assertVNextReaderPrepareCurrentFailure(
	t *testing.T,
	proof vnextReaderPrepareAuthorityProof,
	err error,
) {
	t.Helper()
	if err == nil {
		t.Fatal("invalid current Scheduler authority was accepted")
	}
	if !errors.Is(err, errVNextReaderPrepareCurrentAuthority) {
		t.Fatalf("current Scheduler authority error = %v, want typed sentinel", err)
	}
	if proof != (vnextReaderPrepareAuthorityProof{}) {
		t.Fatalf("failed current Scheduler authority returned a partial proof: %#v", proof)
	}
}

func TestVNextReaderPrepareCurrentAuthorityVerifierAcceptsRealEd25519Leader(t *testing.T) {
	fixture := newVNextReaderPrepareCurrentTestFixture(t)
	proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
		context.Background(),
		vnextReaderPrepareCurrentTestPrincipal,
		fixture.request.Authority.RequestDigest,
		fixture.request.Authority)
	if err != nil {
		t.Fatalf("verify current Reader authority: %v", err)
	}
	wantReceipt, err := vnextReaderPrepareCanonicalAuthorityReceipt(
		vnextReaderPrepareCurrentTestPrincipal, fixture.request.Authority)
	if err != nil {
		t.Fatalf("derive expected Reader authority receipt: %v", err)
	}
	if proof.AuthenticatedSchedulerPrincipal !=
		vnextReaderPrepareCurrentTestPrincipal ||
		proof.SchedulerID != vnextReaderPrepareCurrentTestScheduler ||
		proof.SchedulerFenceRevision != fixture.fence ||
		proof.LeaderLeaseID != fixture.lease ||
		proof.LeaderTermID != fixture.request.Authority.LeaderTermID ||
		proof.RequestDigest != fixture.request.Authority.RequestDigest ||
		proof.AuthorityReceipt != wantReceipt {
		t.Fatalf("current Reader authority proof lost exact identity: %#v", proof)
	}
	if fixture.reader.callCount() != 1 {
		t.Fatalf("linearizable exact leader reads = %d, want 1",
			fixture.reader.callCount())
	}
	if keys := fixture.reader.recordedKeys(); len(keys) != 1 || keys[0] != vnextReaderPrepareCurrentTestLeaderKey {
		t.Fatalf("linearizable reader keys = %#v, want only the exact leader key", keys)
	}
	const wantGlobalTermHex = "0434666546dcfdf9fafa3abe379056335c040e2ceecc50651aae3246a1db8f4d"
	if got := fmt.Sprintf("%x", proof.LeaderTermID); got != wantGlobalTermHex {
		t.Fatalf("global Scheduler term fixture = %s, want %s",
			got, wantGlobalTermHex)
	}
}

func TestVNextReaderPrepareCurrentAuthorityNilVerifierAndContextFailClosed(t *testing.T) {
	fixture := newVNextReaderPrepareCurrentTestFixture(t)
	var nilVerifier *vnextReaderPrepareCurrentAuthorityVerifier
	proof, err := nilVerifier.VerifyVNextReaderPrepareAuthority(
		context.Background(),
		vnextReaderPrepareCurrentTestPrincipal,
		fixture.request.Authority.RequestDigest,
		fixture.request.Authority)
	assertVNextReaderPrepareCurrentFailure(t, proof, err)

	proof, err = fixture.verifier.VerifyVNextReaderPrepareAuthority(
		nil,
		vnextReaderPrepareCurrentTestPrincipal,
		fixture.request.Authority.RequestDigest,
		fixture.request.Authority)
	assertVNextReaderPrepareCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 0 {
		t.Fatalf("nil verifier/context performed %d leader reads",
			fixture.reader.callCount())
	}
}

func TestVNextReaderPrepareCurrentAuthorityRejectsPrincipalAndEnvelopeBeforeRead(t *testing.T) {
	tests := map[string]func(*vnextReaderPrepareCurrentTestFixture) (
		string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope){
		"unbound principal": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			return "spiffe://test.example/scheduler/unbound",
				fixture.request.Authority.RequestDigest, fixture.request.Authority
		},
		"non-URI principal": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			return "scheduler-current",
				fixture.request.Authority.RequestDigest, fixture.request.Authority
		},
		"request digest argument": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			digest := fixture.request.Authority.RequestDigest
			digest[0] ^= 0xff
			return vnextReaderPrepareCurrentTestPrincipal, digest, fixture.request.Authority
		},
		"pinned cluster": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			authority := fixture.request.Authority
			authority.ClusterID = fmt.Sprintf("%016x", fixture.clusterID+1)
			return vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest, authority
		},
		"principal Scheduler binding": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			authority := fixture.request.Authority
			authority.SchedulerID = "scheduler-other"
			return vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest, authority
		},
		"authority domain": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			authority := fixture.request.Authority
			authority.Domain = "cxld.vnext-owner.v6"
			return vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest, authority
		},
		"zero signature": func(fixture *vnextReaderPrepareCurrentTestFixture) (
			string, [sha256.Size]byte, vnextReaderPrepareAuthorityEnvelope) {
			authority := fixture.request.Authority
			authority.Signature = [ed25519.SignatureSize]byte{}
			return vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest, authority
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareCurrentTestFixture(t)
			principal, digest, authority := prepare(fixture)
			proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
				context.Background(), principal, digest, authority)
			assertVNextReaderPrepareCurrentFailure(t, proof, err)
			if fixture.reader.callCount() != 0 {
				t.Fatalf("pre-read rejection performed %d leader reads",
					fixture.reader.callCount())
			}
		})
	}
}

func TestVNextReaderPrepareCurrentAuthorityRejectsEverySnapshotMismatch(t *testing.T) {
	tests := map[string]func(*vnextReaderPrepareCurrentTestFixture){
		"missing header": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.HeaderPresent = false
		},
		"header cluster": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.HeaderCluster++
		},
		"header revision zero": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.HeaderRevision = 0
		},
		"header behind KV": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.HeaderRevision =
				fixture.reader.snapshot.KVs[0].ModRevision - 1
		},
		"count": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.Count = 2
		},
		"missing KV": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs = nil
		},
		"extra KV": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs = append(
				fixture.reader.snapshot.KVs,
				fixture.reader.snapshot.KVs[0])
		},
		"more": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.More = true
		},
		"key": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Key = []byte("/different")
		},
		"create": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].CreateRevision = 0
		},
		"mod": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].ModRevision++
		},
		"version": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Version = 2
		},
		"lease": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Lease = 0
		},
		"leader value": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Value = []byte("not-a-global-leader")
		},
		"leader Scheduler": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Value =
				vnextReaderPrepareCurrentTestLeaderValue(
					t, "scheduler-other", fixture.lease, fixture.public,
					"mutated Scheduler leader nonce")
		},
		"leader-value lease": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Value =
				vnextReaderPrepareCurrentTestLeaderValue(
					t, vnextReaderPrepareCurrentTestScheduler,
					fixture.lease+1, fixture.public,
					"mutated lease leader nonce")
		},
		"leader nonce global term": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			fixture.reader.snapshot.KVs[0].Value =
				vnextReaderPrepareCurrentTestLeaderValue(
					t, vnextReaderPrepareCurrentTestScheduler,
					fixture.lease, fixture.public,
					"different valid global leader nonce")
		},
		"leader key": func(fixture *vnextReaderPrepareCurrentTestFixture) {
			otherSeed := sha256.Sum256([]byte("different current Scheduler key"))
			otherPrivate := ed25519.NewKeyFromSeed(otherSeed[:])
			otherPublic := otherPrivate.Public().(ed25519.PublicKey)
			fixture.reader.snapshot.KVs[0].Value =
				vnextReaderPrepareCurrentTestLeaderValue(
					t, vnextReaderPrepareCurrentTestScheduler,
					fixture.lease, otherPublic,
					"mutated key leader nonce")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareCurrentTestFixture(t)
			mutate(fixture)
			proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
				context.Background(),
				vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest,
				fixture.request.Authority)
			assertVNextReaderPrepareCurrentFailure(t, proof, err)
			if fixture.reader.callCount() != 1 {
				t.Fatalf("mismatched snapshot reads = %d, want 1",
					fixture.reader.callCount())
			}
		})
	}
}

func TestVNextReaderPrepareCurrentAuthorityRejectsStaleEnvelopeAndSignature(t *testing.T) {
	tests := map[string]func(*vnextReaderPrepareCurrentTestFixture, *vnextReaderPrepareAuthorityEnvelope){
		"fence": func(_ *vnextReaderPrepareCurrentTestFixture, authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.SchedulerFenceRevision++
		},
		"lease": func(_ *vnextReaderPrepareCurrentTestFixture, authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.LeaderLeaseID++
		},
		"key": func(_ *vnextReaderPrepareCurrentTestFixture, authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.KeyID[0] ^= 0xff
		},
		"term": func(_ *vnextReaderPrepareCurrentTestFixture, authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.LeaderTermID[0] ^= 0xff
		},
		"signature": func(_ *vnextReaderPrepareCurrentTestFixture, authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.Signature[0] ^= 0xff
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareCurrentTestFixture(t)
			authority := fixture.request.Authority
			mutate(fixture, &authority)
			proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
				context.Background(),
				vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest,
				authority)
			assertVNextReaderPrepareCurrentFailure(t, proof, err)
			if fixture.reader.callCount() != 1 {
				t.Fatalf("stale envelope reads = %d, want 1",
					fixture.reader.callCount())
			}
		})
	}
}

func TestVNextReaderPrepareCurrentAuthorityRejectsOwnerSignatureDomain(t *testing.T) {
	fixture := newVNextReaderPrepareCurrentTestFixture(t)
	authority := fixture.request.Authority
	ownerPreimage := vnextOwnerSchedulerSignaturePreimage(
		authority.LeaderTermID, authority.RequestDigest)
	copy(authority.Signature[:], ed25519.Sign(fixture.private, ownerPreimage))
	readerPreimage, err := vnextReaderPrepareAuthoritySignaturePreimage(authority)
	if err != nil {
		t.Fatalf("build Reader-domain signature preimage: %v", err)
	}
	if bytes.Equal(ownerPreimage, readerPreimage) ||
		ed25519.Verify(fixture.public, readerPreimage, authority.Signature[:]) {
		t.Fatal("Owner signature was valid in the Reader PREPARE domain")
	}
	proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
		context.Background(),
		vnextReaderPrepareCurrentTestPrincipal,
		authority.RequestDigest,
		authority)
	assertVNextReaderPrepareCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 1 {
		t.Fatalf("Owner-domain signature rejection reads = %d, want 1",
			fixture.reader.callCount())
	}
}

func TestVNextReaderPrepareCurrentAuthorityReadErrorCancellationAndTimeout(t *testing.T) {
	t.Run("read error", func(t *testing.T) {
		fixture := newVNextReaderPrepareCurrentTestFixture(t)
		fixture.reader.err = errors.New("test etcd unavailable")
		proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
			context.Background(),
			vnextReaderPrepareCurrentTestPrincipal,
			fixture.request.Authority.RequestDigest,
			fixture.request.Authority)
		assertVNextReaderPrepareCurrentFailure(t, proof, err)
		if fixture.reader.callCount() != 1 {
			t.Fatalf("read-error calls = %d, want 1", fixture.reader.callCount())
		}
	})

	t.Run("pre-cancelled", func(t *testing.T) {
		fixture := newVNextReaderPrepareCurrentTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
			ctx,
			vnextReaderPrepareCurrentTestPrincipal,
			fixture.request.Authority.RequestDigest,
			fixture.request.Authority)
		assertVNextReaderPrepareCurrentFailure(t, proof, err)
		if fixture.reader.callCount() != 0 {
			t.Fatalf("pre-cancelled calls = %d, want 0", fixture.reader.callCount())
		}
	})

	t.Run("cancelled read", func(t *testing.T) {
		fixture := newVNextReaderPrepareCurrentTestFixture(t)
		entered := make(chan struct{})
		fixture.reader.handler = func(
			ctx context.Context,
			_ string,
		) (vnextOwnerSchedulerLeaderSnapshot, error) {
			close(entered)
			<-ctx.Done()
			return vnextOwnerSchedulerLeaderSnapshot{}, ctx.Err()
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		var proof vnextReaderPrepareAuthorityProof
		var verifyErr error
		go func() {
			proof, verifyErr = fixture.verifier.VerifyVNextReaderPrepareAuthority(
				ctx,
				vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest,
				fixture.request.Authority)
			close(done)
		}()
		<-entered
		cancel()
		<-done
		assertVNextReaderPrepareCurrentFailure(t, proof, verifyErr)
		if fixture.reader.callCount() != 1 {
			t.Fatalf("cancelled read calls = %d, want 1", fixture.reader.callCount())
		}
	})

	t.Run("cancelled as valid snapshot returns", func(t *testing.T) {
		fixture := newVNextReaderPrepareCurrentTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.reader.handler = func(
			_ context.Context,
			_ string,
		) (vnextOwnerSchedulerLeaderSnapshot, error) {
			cancel()
			return cloneVNextReaderPrepareCurrentTestSnapshot(fixture.snapshot), nil
		}
		proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
			ctx,
			vnextReaderPrepareCurrentTestPrincipal,
			fixture.request.Authority.RequestDigest,
			fixture.request.Authority)
		assertVNextReaderPrepareCurrentFailure(t, proof, err)
		if fixture.reader.callCount() != 1 {
			t.Fatalf("return-time cancellation calls = %d, want 1",
				fixture.reader.callCount())
		}
	})

	t.Run("read timeout", func(t *testing.T) {
		fixture := newVNextReaderPrepareCurrentTestFixture(t)
		fixture.verifier.readTimeout = 5 * time.Millisecond
		fixture.reader.handler = func(
			ctx context.Context,
			_ string,
		) (vnextOwnerSchedulerLeaderSnapshot, error) {
			<-ctx.Done()
			return vnextOwnerSchedulerLeaderSnapshot{}, ctx.Err()
		}
		proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
			context.Background(),
			vnextReaderPrepareCurrentTestPrincipal,
			fixture.request.Authority.RequestDigest,
			fixture.request.Authority)
		assertVNextReaderPrepareCurrentFailure(t, proof, err)
		if fixture.reader.callCount() != 1 {
			t.Fatalf("timed-out read calls = %d, want 1", fixture.reader.callCount())
		}
	})
}

func TestVNextReaderPrepareCurrentAuthorityConcurrentVerificationReadsOncePerRequest(t *testing.T) {
	fixture := newVNextReaderPrepareCurrentTestFixture(t)
	const callers = 64
	var failed int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			proof, err := fixture.verifier.VerifyVNextReaderPrepareAuthority(
				context.Background(),
				vnextReaderPrepareCurrentTestPrincipal,
				fixture.request.Authority.RequestDigest,
				fixture.request.Authority)
			if err != nil || proof.LeaderTermID != fixture.request.Authority.LeaderTermID {
				atomic.AddInt64(&failed, 1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if failed != 0 {
		t.Fatalf("concurrent authority verification failures = %d", failed)
	}
	if fixture.reader.callCount() != callers {
		t.Fatalf("concurrent exact leader reads = %d, want %d",
			fixture.reader.callCount(), callers)
	}
}

func TestVNextReaderPrepareCurrentAuthorityConfigBoundsAndDeepClone(t *testing.T) {
	fixture := newVNextReaderPrepareCurrentTestFixture(t)
	valid := fixture.config
	valid.ReadTimeout = vnextReaderPrepareAuthorityMaxReadTimeout
	if verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(
		valid, fixture.reader); err != nil || verifier == nil {
		t.Fatalf("maximum valid read timeout = %#v / %v", verifier, err)
	}

	invalid := map[string]func(*vnextReaderPrepareCurrentAuthorityConfig){
		"leader key": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.LeaderKey = "/wrong"
		},
		"zero cluster": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.ExpectedCluster = 0
		},
		"zero timeout": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.ReadTimeout = 0
		},
		"negative timeout": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.ReadTimeout = -time.Second
		},
		"over timeout": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.ReadTimeout = vnextReaderPrepareAuthorityMaxReadTimeout + time.Nanosecond
		},
		"empty principals": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.SchedulerByPrincipal = nil
		},
		"invalid URI principal": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.SchedulerByPrincipal = map[string]string{
				"scheduler-current": vnextReaderPrepareCurrentTestScheduler,
			}
		},
		"URI query": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.SchedulerByPrincipal = map[string]string{
				"spiffe://test/scheduler?id=1": vnextReaderPrepareCurrentTestScheduler,
			}
		},
		"empty Scheduler": func(config *vnextReaderPrepareCurrentAuthorityConfig) {
			config.SchedulerByPrincipal = map[string]string{
				vnextReaderPrepareCurrentTestPrincipal: "",
			}
		},
	}
	for name, mutate := range invalid {
		t.Run(name, func(t *testing.T) {
			config := fixture.config
			mutate(&config)
			if verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(
				config, fixture.reader); err == nil || verifier != nil {
				t.Fatalf("invalid config = %#v / %v", verifier, err)
			}
		})
	}
	if verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(
		fixture.config, nil); err == nil || verifier != nil {
		t.Fatalf("nil reader config = %#v / %v", verifier, err)
	}

	tooMany := make(map[string]string, vnextReaderPrepareAuthorityMaxPrincipals+1)
	for index := 0; index <= vnextReaderPrepareAuthorityMaxPrincipals; index++ {
		tooMany[fmt.Sprintf("spiffe://test/scheduler/%02d", index)] =
			fmt.Sprintf("scheduler-%02d", index)
	}
	config := fixture.config
	config.SchedulerByPrincipal = tooMany
	if verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(
		config, fixture.reader); err == nil || verifier != nil {
		t.Fatalf("over-count principal map = %#v / %v", verifier, err)
	}

	short64 := make(map[string]string, vnextReaderPrepareAuthorityMaxPrincipals)
	for index := 0; index < vnextReaderPrepareAuthorityMaxPrincipals; index++ {
		short64[fmt.Sprintf("spiffe://test/scheduler/%02d", index)] =
			fmt.Sprintf("scheduler-%02d", index)
	}
	config.SchedulerByPrincipal = short64
	if verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(
		config, fixture.reader); err != nil || verifier == nil {
		t.Fatalf("64 short principal bindings = %#v / %v", verifier, err)
	}

	largeBindings := make(map[string]string)
	for index := 0; index < vnextReaderPrepareAuthorityMaxPrincipals; index++ {
		prefix := fmt.Sprintf("spiffe://test.example/%02d/", index)
		principal := prefix + strings.Repeat(
			"p", cxlcheckpoint.MaxIdentityBytes-len(prefix))
		schedulerPrefix := fmt.Sprintf("scheduler-%02d-", index)
		scheduler := schedulerPrefix + strings.Repeat(
			"s", cxlcheckpoint.MaxIdentityBytes-len(schedulerPrefix))
		largeBindings[principal] = scheduler
	}
	config.SchedulerByPrincipal = largeBindings
	if verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(
		config, fixture.reader); err == nil || verifier != nil {
		t.Fatalf("over-byte principal map = %#v / %v", verifier, err)
	}

	original := map[string]string{
		vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
	}
	config = fixture.config
	config.SchedulerByPrincipal = original
	verifier, err := newVNextReaderPrepareCurrentAuthorityVerifier(config, fixture.reader)
	if err != nil {
		t.Fatalf("new deep-clone verifier: %v", err)
	}
	delete(original, vnextReaderPrepareCurrentTestPrincipal)
	original["spiffe://test.example/scheduler/attacker"] = "scheduler-attacker"
	proof, err := verifier.VerifyVNextReaderPrepareAuthority(
		context.Background(),
		vnextReaderPrepareCurrentTestPrincipal,
		fixture.request.Authority.RequestDigest,
		fixture.request.Authority)
	if err != nil || proof.SchedulerID != vnextReaderPrepareCurrentTestScheduler {
		t.Fatalf("mutated input map changed verifier binding: %#v / %v", proof, err)
	}
	if _, exists := verifier.schedulerByPrincipal["spiffe://test.example/scheduler/attacker"]; exists {
		t.Fatal("verifier retained the caller's principal map")
	}
}

func TestVNextReaderPrepareCurrentAuthorityHasNoRuntimeOrOwnerRightsState(t *testing.T) {
	fixture := newVNextReaderPrepareCurrentTestFixture(t)
	typeOfVerifier := reflect.TypeOf(*fixture.verifier)
	wantFields := map[string]reflect.Type{
		"leaderKey":            reflect.TypeOf(""),
		"expectedCluster":      reflect.TypeOf(uint64(0)),
		"readTimeout":          reflect.TypeOf(time.Duration(0)),
		"schedulerByPrincipal": reflect.TypeOf(map[string]string{}),
		"reader": reflect.TypeOf(
			(*vnextOwnerSchedulerLeaderReader)(nil)).Elem(),
	}
	if typeOfVerifier.NumField() != len(wantFields) {
		t.Fatalf("authority verifier fields = %d, want %d",
			typeOfVerifier.NumField(), len(wantFields))
	}
	for index := 0; index < typeOfVerifier.NumField(); index++ {
		field := typeOfVerifier.Field(index)
		want, exists := wantFields[field.Name]
		if !exists || field.Type != want {
			t.Fatalf("unexpected authority verifier dependency %s %s",
				field.Name, field.Type)
		}
		lower := strings.ToLower(field.Name + " " + field.Type.String())
		for _, forbidden := range []string{
			"dax", "criu", "active", "release", "highwater", "rpc", "role", "alpn",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("authority verifier dependency %s contains forbidden %q",
					field.Name, forbidden)
			}
		}
	}
}
