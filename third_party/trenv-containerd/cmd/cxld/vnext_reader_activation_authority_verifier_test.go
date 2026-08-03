package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

type vnextReaderActivationCurrentTestFixture struct {
	clusterID uint64
	fence     uint64
	lease     uint64
	private   ed25519.PrivateKey
	leader    vnextOwnerSchedulerLeaderTerm
	snapshot  vnextOwnerSchedulerLeaderSnapshot
	reader    *vnextReaderPrepareCurrentTestReader
	config    vnextReaderActivationCurrentAuthorityConfig
	verifier  *vnextReaderActivationCurrentAuthorityVerifier
}

func newVNextReaderActivationCurrentTestFixture(
	t *testing.T,
) *vnextReaderActivationCurrentTestFixture {
	t.Helper()
	clusterID := uint64(0x8000000000000001)
	fence := uint64(101)
	lease := uint64(202)
	seed := sha256.Sum256([]byte(
		"VNext Reader activation current authority Ed25519 seed"))
	private := ed25519.NewKeyFromSeed(seed[:])
	public := append(ed25519.PublicKey(nil),
		private.Public().(ed25519.PublicKey)...)
	nonce := sha256.Sum256([]byte(
		"VNext Reader activation current authority term nonce"))
	leaderValue, err := formatVNextOwnerSchedulerLeaderValue(
		vnextReaderPrepareCurrentTestScheduler, lease, nonce, public)
	if err != nil {
		t.Fatalf("format activation current Scheduler leader: %v", err)
	}
	leader, err := parseVNextOwnerSchedulerLeaderValue(leaderValue)
	if err != nil {
		t.Fatalf("parse activation current Scheduler leader: %v", err)
	}
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
	config := vnextReaderActivationCurrentAuthorityConfig{
		LeaderKey:       vnextReaderPrepareCurrentTestLeaderKey,
		ExpectedCluster: clusterID,
		ReadTimeout:     time.Second,
		SchedulerByPrincipal: map[string]string{
			vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
		},
	}
	verifier, err := newVNextReaderActivationCurrentAuthorityVerifier(
		config, reader)
	if err != nil {
		t.Fatalf("new activation current authority verifier: %v", err)
	}
	fixture := &vnextReaderActivationCurrentTestFixture{
		clusterID: clusterID,
		fence:     fence,
		lease:     lease,
		private:   private,
		leader:    leader,
		snapshot:  snapshot,
		reader:    reader,
		config:    config,
		verifier:  verifier,
	}
	fixture.snapshot.KVs[0].Value = append([]byte(nil), snapshot.KVs[0].Value...)
	return fixture
}

func (fixture *vnextReaderActivationCurrentTestFixture) authority(
	t *testing.T,
	spec vnextReaderActivationOperationSpec,
	digest [sha256.Size]byte,
) vnextReaderActivationAuthorityEnvelope {
	t.Helper()
	leaderValue := string(fixture.snapshot.KVs[0].Value)
	parsed := vnextOwnerSchedulerParsedAuthority{
		ClusterID:      fixture.clusterID,
		CreateRevision: fixture.fence,
		ModRevision:    fixture.fence,
		LeaseID:        fixture.lease,
		LeaderValue:    leaderValue,
		Leader:         fixture.leader,
	}
	authority := vnextReaderActivationAuthorityEnvelope{
		Domain:                 spec.authorityDomain,
		ClusterID:              fmt.Sprintf("%016x", fixture.clusterID),
		SchedulerID:            vnextReaderPrepareCurrentTestScheduler,
		SchedulerFenceRevision: fixture.fence,
		LeaderLeaseID:          fixture.lease,
		LeaderTermID: vnextOwnerSchedulerTermDigest(
			vnextReaderPrepareCurrentTestLeaderKey, parsed),
		KeyID:         fixture.leader.KeyID,
		RequestDigest: digest,
	}
	preimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		spec, authority)
	if err != nil {
		t.Fatalf("build activation authority signature preimage: %v", err)
	}
	copy(authority.Signature[:], ed25519.Sign(fixture.private, preimage))
	return authority
}

func assertVNextReaderActivationCurrentFailure(
	t *testing.T,
	proof vnextReaderActivationAuthorityProof,
	err error,
) {
	t.Helper()
	if err == nil || !errors.Is(err, errVNextReaderActivationCurrentAuthority) {
		t.Fatalf("activation current authority failure = %v", err)
	}
	if proof != (vnextReaderActivationAuthorityProof{}) {
		t.Fatalf("failed activation authority returned partial proof: %#v", proof)
	}
}

func TestVNextReaderActivationCurrentAuthorityAcceptsAllExactOperations(
	t *testing.T,
) {
	fixture := newVNextReaderActivationCurrentTestFixture(t)
	for index, spec := range []vnextReaderActivationOperationSpec{
		vnextReaderActivationProposalSpec,
		vnextReaderActivationCommitSpec,
		vnextReaderActivationStatusSpec,
	} {
		digest := sha256.Sum256([]byte(spec.protocol + "-request"))
		authority := fixture.authority(t, spec, digest)
		proof, err := fixture.verifier.VerifyVNextReaderActivationAuthority(
			context.Background(), vnextReaderPrepareCurrentTestPrincipal,
			spec, digest, authority)
		if err != nil {
			t.Fatalf("verify %s current authority: %v", spec.protocol, err)
		}
		wantReceipt, err := vnextReaderActivationCanonicalAuthorityReceipt(
			spec, vnextReaderPrepareCurrentTestPrincipal, authority)
		if err != nil {
			t.Fatalf("derive %s receipt: %v", spec.protocol, err)
		}
		if proof.AuthenticatedSchedulerPrincipal !=
			vnextReaderPrepareCurrentTestPrincipal ||
			proof.SchedulerID != vnextReaderPrepareCurrentTestScheduler ||
			proof.SchedulerFenceRevision != fixture.fence ||
			proof.LeaderLeaseID != fixture.lease ||
			proof.LeaderTermID != authority.LeaderTermID ||
			proof.RequestDigest != digest ||
			proof.AuthorityReceipt != wantReceipt {
			t.Fatalf("%s proof = %#v", spec.protocol, proof)
		}
		if fixture.reader.callCount() != index+1 {
			t.Fatalf("leader reads after %s = %d, want %d",
				spec.protocol, fixture.reader.callCount(), index+1)
		}
	}
}

func TestVNextReaderActivationCurrentAuthorityRejectsCrossOperationAndStaleTerm(
	t *testing.T,
) {
	fixture := newVNextReaderActivationCurrentTestFixture(t)
	digest := sha256.Sum256([]byte("activation-current-cross-operation"))
	proposal := fixture.authority(
		t, vnextReaderActivationProposalSpec, digest)

	proof, err := fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationCommitSpec, digest, proposal)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 0 {
		t.Fatal("cross-operation domain reached the leader reader")
	}

	proposal.Signature[0] ^= 0xff
	proof, err = fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationProposalSpec, digest, proposal)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 1 {
		t.Fatalf("signature failure leader reads = %d, want 1",
			fixture.reader.callCount())
	}

	stale := fixture.authority(t, vnextReaderActivationProposalSpec, digest)
	stale.SchedulerFenceRevision++
	preimage, preimageErr := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationProposalSpec, stale)
	if preimageErr != nil {
		t.Fatalf("build stale activation preimage: %v", preimageErr)
	}
	copy(stale.Signature[:], ed25519.Sign(fixture.private, preimage))
	proof, err = fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationProposalSpec, digest, stale)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 2 {
		t.Fatalf("stale term leader reads = %d, want 2",
			fixture.reader.callCount())
	}
}

func TestVNextReaderActivationCurrentAuthorityFailsClosedBeforeAndDuringRead(
	t *testing.T,
) {
	fixture := newVNextReaderActivationCurrentTestFixture(t)
	digest := sha256.Sum256([]byte("activation-current-fail-closed"))
	authority := fixture.authority(
		t, vnextReaderActivationStatusSpec, digest)
	proof, err := fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationOperationSpec{}, digest, authority)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 0 {
		t.Fatal("invalid activation operation reached the leader reader")
	}

	wrongDigest := digest
	wrongDigest[0] ^= 1
	proof, err = fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationStatusSpec, wrongDigest, authority)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 0 {
		t.Fatal("activation request-digest mismatch reached the leader reader")
	}

	proof, err = fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), "spiffe://test.example/scheduler/unbound",
		vnextReaderActivationStatusSpec, digest, authority)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 0 {
		t.Fatal("unbound principal reached the leader reader")
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	proof, err = fixture.verifier.VerifyVNextReaderActivationAuthority(
		cancelled, vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationStatusSpec, digest, authority)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 0 {
		t.Fatal("cancelled call reached the leader reader")
	}

	fixture.reader.handler = func(
		ctx context.Context,
		_ string,
	) (vnextOwnerSchedulerLeaderSnapshot, error) {
		<-ctx.Done()
		return vnextOwnerSchedulerLeaderSnapshot{}, ctx.Err()
	}
	fixture.verifier.readTimeout = time.Millisecond
	proof, err = fixture.verifier.VerifyVNextReaderActivationAuthority(
		context.Background(), vnextReaderPrepareCurrentTestPrincipal,
		vnextReaderActivationStatusSpec, digest, authority)
	assertVNextReaderActivationCurrentFailure(t, proof, err)
	if fixture.reader.callCount() != 1 {
		t.Fatalf("timed-out call leader reads = %d, want 1",
			fixture.reader.callCount())
	}
}

func TestVNextReaderActivationCurrentAuthorityRejectsEveryLeaderShapeMismatch(
	t *testing.T,
) {
	mutations := map[string]func(*vnextOwnerSchedulerLeaderSnapshot){
		"header absent": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.HeaderPresent = false
		},
		"wrong cluster": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.HeaderCluster++
		},
		"wrong count": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.Count = 0
		},
		"more": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.More = true
		},
		"wrong key": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.KVs[0].Key = []byte("/wrong")
		},
		"mutable key": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.KVs[0].ModRevision++
		},
		"wrong lease": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.KVs[0].Lease++
		},
		"header before key": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.HeaderRevision = value.KVs[0].ModRevision - 1
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderActivationCurrentTestFixture(t)
			digest := sha256.Sum256([]byte("activation-snapshot-" + name))
			authority := fixture.authority(
				t, vnextReaderActivationCommitSpec, digest)
			mutated := cloneVNextReaderPrepareCurrentTestSnapshot(fixture.snapshot)
			mutate(&mutated)
			fixture.reader.snapshot = mutated
			proof, err := fixture.verifier.VerifyVNextReaderActivationAuthority(
				context.Background(), vnextReaderPrepareCurrentTestPrincipal,
				vnextReaderActivationCommitSpec, digest, authority)
			assertVNextReaderActivationCurrentFailure(t, proof, err)
			if fixture.reader.callCount() != 1 {
				t.Fatalf("leader mismatch reads = %d, want 1",
					fixture.reader.callCount())
			}
		})
	}
}

func TestVNextReaderActivationCurrentAuthorityConfigBoundsAndDeepClone(
	t *testing.T,
) {
	fixture := newVNextReaderActivationCurrentTestFixture(t)
	bindings := map[string]string{
		vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
	}
	config := fixture.config
	config.SchedulerByPrincipal = bindings
	verifier, err := newVNextReaderActivationCurrentAuthorityVerifier(
		config, fixture.reader)
	if err != nil {
		t.Fatalf("construct activation verifier: %v", err)
	}
	bindings[vnextReaderPrepareCurrentTestPrincipal] = "scheduler-mutated"
	config.LeaderKey = "/mutated"
	if !reflect.DeepEqual(verifier.schedulerByPrincipal,
		map[string]string{
			vnextReaderPrepareCurrentTestPrincipal: vnextReaderPrepareCurrentTestScheduler,
		}) || verifier.leaderKey != vnextReaderPrepareCurrentTestLeaderKey {
		t.Fatal("activation verifier retained caller-owned configuration")
	}

	for name, mutate := range map[string]func(*vnextReaderActivationCurrentAuthorityConfig){
		"zero cluster": func(value *vnextReaderActivationCurrentAuthorityConfig) {
			value.ExpectedCluster = 0
		},
		"zero timeout": func(value *vnextReaderActivationCurrentAuthorityConfig) {
			value.ReadTimeout = 0
		},
		"long timeout": func(value *vnextReaderActivationCurrentAuthorityConfig) {
			value.ReadTimeout = vnextReaderPrepareAuthorityMaxReadTimeout + time.Millisecond
		},
		"empty bindings": func(value *vnextReaderActivationCurrentAuthorityConfig) {
			value.SchedulerByPrincipal = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			mutated := fixture.config
			mutate(&mutated)
			if value, err := newVNextReaderActivationCurrentAuthorityVerifier(
				mutated, fixture.reader); err == nil || value != nil {
				t.Fatalf("invalid config returned verifier=%#v err=%v", value, err)
			}
		})
	}
}
