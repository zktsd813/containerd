package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

const vnextOwnerTermFenceTestLeaderKey = "/test/cxl-checkpoint/global-orchestrator-leader"

// vnextOwnerTermFenceTestVerifier exercises the same parse, digest, Ed25519,
// and durable high-water inputs as the production verifier. VerifyCurrent is
// counted in place of its linearizable etcd GET so exact durable replay and
// receipt-conflict tests can prove that neither path consults live authority.
type vnextOwnerTermFenceTestVerifier struct {
	prepareCalls       int
	verifyCurrentCalls int
}

func (verifier *vnextOwnerTermFenceTestVerifier) Prepare(
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerVerifiedAuthority, error) {
	verifier.prepareCalls++
	digest, err := vnextOwnerSchedulerMutationDigest(operation, mutation)
	if err != nil {
		return vnextOwnerSchedulerVerifiedAuthority{}, err
	}
	verified, err := verifyVNextOwnerSchedulerAuthoritySignature(
		vnextOwnerTermFenceTestLeaderKey, authority, digest)
	if err != nil {
		return vnextOwnerSchedulerVerifiedAuthority{}, err
	}
	if verified.Parsed.ClusterID != 1 {
		return vnextOwnerSchedulerVerifiedAuthority{}, errors.New(
			"term-fence test authority changed its pinned cluster")
	}
	verified.HighWater = vnextOwnerSchedulerHighWaterFromVerified(
		verified, vnextOwnerTermFenceTestLeaderKey)
	return verified, nil
}

func (verifier *vnextOwnerTermFenceTestVerifier) VerifyCurrent(
	_ context.Context,
	verified vnextOwnerSchedulerVerifiedAuthority,
) error {
	verifier.verifyCurrentCalls++
	return validateVNextOwnerVerifiedSchedulerAuthority(&verified)
}

func vnextOwnerTermFenceTestAuthority(
	t *testing.T,
	operation string,
	mutation interface{},
	revision uint64,
) (vnextOwnerSchedulerAuthority, vnextOwnerSchedulerVerifiedAuthority) {
	t.Helper()
	seed := sha256.Sum256([]byte(fmt.Sprintf(
		"cxld-vnext-owner-term-fence-key/%d", revision)))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	nonce := sha256.Sum256([]byte(fmt.Sprintf(
		"cxld-vnext-owner-term-fence-nonce/%d", revision)))
	leaseID := uint64(0x1000) + revision
	leaderValue, err := formatVNextOwnerSchedulerLeaderValue(
		"test-scheduler", leaseID, nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	leader, err := parseVNextOwnerSchedulerLeaderValue(leaderValue)
	if err != nil {
		t.Fatal(err)
	}
	parsed := vnextOwnerSchedulerParsedAuthority{
		ClusterID:      1,
		CreateRevision: revision,
		ModRevision:    revision,
		LeaseID:        leaseID,
		LeaderValue:    leaderValue,
		Leader:         leader,
	}
	parsed.TermID = vnextOwnerSchedulerTermDigest(
		vnextOwnerTermFenceTestLeaderKey, parsed)
	digest, err := vnextOwnerSchedulerMutationDigest(operation, mutation)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(
		privateKey,
		vnextOwnerSchedulerSignaturePreimage(parsed.TermID, digest))
	authority := vnextOwnerSchedulerAuthority{
		ClusterID:      fmt.Sprintf("%016x", parsed.ClusterID),
		CreateRevision: parsed.CreateRevision,
		ModRevision:    parsed.ModRevision,
		LeaseID:        fmt.Sprintf("%016x", parsed.LeaseID),
		LeaderValue:    parsed.LeaderValue,
		KeyID:          hex.EncodeToString(parsed.Leader.KeyID[:]),
		TermID:         hex.EncodeToString(parsed.TermID[:]),
		Signature:      base64.RawURLEncoding.EncodeToString(signature),
	}
	verified, err := verifyVNextOwnerSchedulerAuthoritySignature(
		vnextOwnerTermFenceTestLeaderKey, authority, digest)
	if err != nil {
		t.Fatal(err)
	}
	verified.HighWater = vnextOwnerSchedulerHighWaterFromVerified(
		verified, vnextOwnerTermFenceTestLeaderKey)
	if err := validateVNextOwnerVerifiedSchedulerAuthority(&verified); err != nil {
		t.Fatal(err)
	}
	return authority, verified
}

func applyVNextOwnerTermFenceTestMutation(
	service *vnextOwnerService,
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerProof, bool, error) {
	switch operation {
	case vnextOwnerRPCOperationReserve:
		request := mutation.(vnextOwnerReserveRequest)
		request.SchedulerAuthority = authority
		response, err := service.reserveScheduler(request)
		return response.SchedulerProof, response.Replayed, err
	case vnextOwnerRPCOperationSetAdmission:
		request := mutation.(vnextOwnerSetAdmissionRequest)
		request.SchedulerAuthority = authority
		response, err := service.setAdmissionScheduler(request)
		return response.SchedulerProof, response.Replayed, err
	case vnextOwnerRPCOperationIssueProducerCapability:
		request := mutation.(vnextOwnerIssueProducerCapabilityRequest)
		request.SchedulerAuthority = authority
		response, err := service.issueProducerCapabilityScheduler(
			request, vnextOwnerTestSchedulerCaller)
		return response.SchedulerProof, response.Replayed, err
	case vnextOwnerRPCOperationRevokeProducerCapability:
		request := mutation.(vnextOwnerRevokeProducerCapabilityRequest)
		request.SchedulerAuthority = authority
		response, err := service.revokeProducerCapabilityScheduler(
			request, vnextOwnerTestSchedulerCaller)
		return response.SchedulerProof, response.Replayed, err
	case vnextOwnerRPCOperationCommit:
		response, err := service.commitScheduler(vnextOwnerSchedulerLifecycleRequest{
			Operation: mutation.(vnextOwnerOperationIdentity), SchedulerAuthority: authority,
		})
		return response.SchedulerProof, response.Replayed, err
	case vnextOwnerRPCOperationAbort:
		response, err := service.abortScheduler(vnextOwnerSchedulerLifecycleRequest{
			Operation: mutation.(vnextOwnerOperationIdentity), SchedulerAuthority: authority,
		})
		return response.SchedulerProof, response.Replayed, err
	default:
		return vnextOwnerSchedulerProof{}, false, fmt.Errorf(
			"unsupported term-fence test operation %q", operation)
	}
}

func TestVNextOwnerSchedulerExactRetryAndResignedTermConflictAreReadOnly(t *testing.T) {
	tests := []struct {
		name      string
		operation string
		setup     func(*testing.T, *vnextOwnerTestFixture, *vnextOwnerService) interface{}
	}{
		{
			name: "reserve", operation: vnextOwnerRPCOperationReserve,
			setup: func(_ *testing.T, _ *vnextOwnerTestFixture, _ *vnextOwnerService) interface{} {
				return vnextOwnerStatusTestRequest("term-fence-reserve", 2)
			},
		},
		{
			name: "set-admission", operation: vnextOwnerRPCOperationSetAdmission,
			setup: func(_ *testing.T, _ *vnextOwnerTestFixture, _ *vnextOwnerService) interface{} {
				return vnextOwnerSetAdmissionRequest{
					RequestID: "term-fence-admission", OwnerID: "owner-0", OwnerEpoch: 7,
					From: vnextOwnerAdmissionActive, Target: vnextOwnerAdmissionReadOnly,
					ExpectedSequence: 1,
				}
			},
		},
		{
			name: "issue", operation: vnextOwnerRPCOperationIssueProducerCapability,
			setup: func(t *testing.T, _ *vnextOwnerTestFixture, service *vnextOwnerService) interface{} {
				reserved, err := service.reserve(
					vnextOwnerStatusTestRequest("term-fence-issue", 2))
				if err != nil {
					t.Fatal(err)
				}
				return vnextOwnerTestCapabilityIssueRequest(
					reserved.Operation, vnextProducerCapabilityAll)
			},
		},
		{
			name: "revoke", operation: vnextOwnerRPCOperationRevokeProducerCapability,
			setup: func(t *testing.T, _ *vnextOwnerTestFixture, service *vnextOwnerService) interface{} {
				reserved, err := service.reserve(
					vnextOwnerStatusTestRequest("term-fence-revoke", 2))
				if err != nil {
					t.Fatal(err)
				}
				issued, err := service.issueProducerCapability(
					vnextOwnerTestCapabilityIssueRequest(
						reserved.Operation, vnextProducerCapabilityAll),
					vnextOwnerTestSchedulerCaller)
				if err != nil {
					t.Fatal(err)
				}
				return vnextOwnerRevokeProducerCapabilityRequest{
					RequestID:    "term-fence-revoke",
					Operation:    reserved.Operation,
					CapabilityID: issued.Capability.CapabilityID,
				}
			},
		},
		{
			name: "commit", operation: vnextOwnerRPCOperationCommit,
			setup: func(t *testing.T, fixture *vnextOwnerTestFixture, _ *vnextOwnerService) interface{} {
				grant, err := fixture.group.reserve(
					vnextOwnerMemoryRequest("term-fence-commit", 2, 2))
				if err != nil {
					t.Fatal(err)
				}
				writeAllVNextOwnerPages(t, fixture.group, grant, 2)
				return vnextOwnerServiceIdentity(grant)
			},
		},
		{
			name: "abort", operation: vnextOwnerRPCOperationAbort,
			setup: func(t *testing.T, fixture *vnextOwnerTestFixture, _ *vnextOwnerService) interface{} {
				grant, err := fixture.group.reserve(
					vnextOwnerMemoryRequest("term-fence-abort", 2, 2))
				if err != nil {
					t.Fatal(err)
				}
				return vnextOwnerServiceIdentity(grant)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextOwnerTestFixture(t, []vnextOwnerTestDeviceSpec{{
				UUID: "term-fence-" + test.name, Size: 512 << 10,
			}})
			service := newVNextOwnerServiceForFixture(t, fixture)
			mutation := test.setup(t, fixture, service)
			termOne, termOneVerified := vnextOwnerTermFenceTestAuthority(
				t, test.operation, mutation, 2)
			termTwo, termTwoVerified := vnextOwnerTermFenceTestAuthority(
				t, test.operation, mutation, 3)
			if termOneVerified.MutationDigest != termTwoVerified.MutationDigest ||
				termOneVerified.proof() == termTwoVerified.proof() {
				t.Fatal("re-signed test terms do not bind one mutation to distinct proofs")
			}

			verifier := &vnextOwnerTermFenceTestVerifier{}
			service.schedulerAuthority = verifier
			proof, replayed, err := applyVNextOwnerTermFenceTestMutation(
				service, test.operation, mutation, termOne)
			if err != nil || replayed || proof != termOneVerified.proof() {
				t.Fatalf("first signed mutation = proof %#v replayed=%v err=%v",
					proof, replayed, err)
			}
			if verifier.verifyCurrentCalls != 1 {
				t.Fatalf("first mutation live-authority checks=%d, want 1",
					verifier.verifyCurrentCalls)
			}

			stableImage := vnextOwnerStatusTestPersistentImage(t, fixture.group)
			stableSequence := fixture.group.journal.SnapshotSequence
			stableHighWater := fixture.group.journal.SchedulerHighWater
			stableFreePages := vnextOwnerStatusTestFreePages(fixture.group)
			proof, replayed, err = applyVNextOwnerTermFenceTestMutation(
				service, test.operation, mutation, termOne)
			if err != nil || !replayed || proof != termOneVerified.proof() {
				t.Fatalf("exact retry = proof %#v replayed=%v err=%v",
					proof, replayed, err)
			}
			if verifier.verifyCurrentCalls != 1 ||
				fixture.group.journal.SnapshotSequence != stableSequence ||
				fixture.group.journal.SchedulerHighWater != stableHighWater ||
				vnextOwnerStatusTestFreePages(fixture.group) != stableFreePages ||
				!bytes.Equal(vnextOwnerStatusTestPersistentImage(t, fixture.group), stableImage) {
				t.Fatal("exact signed retry performed a live check or mutated durable state")
			}

			fixture.reopen(t)
			restarted := newVNextOwnerServiceForFixture(t, fixture)
			restarted.schedulerAuthority = verifier
			if !bytes.Equal(vnextOwnerStatusTestPersistentImage(t, fixture.group), stableImage) {
				t.Fatal("restart changed the durable mutation image")
			}
			_, _, err = applyVNextOwnerTermFenceTestMutation(
				restarted, test.operation, mutation, termTwo)
			requireVNextOwnerServiceCode(t, err, vnextOwnerServiceConflict)
			if !errors.Is(err, errVNextOwnerSchedulerReceiptConflict) {
				t.Fatalf("re-signed conflict lost its receipt-conflict cause: %v", err)
			}
			if verifier.verifyCurrentCalls != 1 ||
				fixture.group.journal.SnapshotSequence != stableSequence ||
				fixture.group.journal.SchedulerHighWater != stableHighWater ||
				vnextOwnerStatusTestFreePages(fixture.group) != stableFreePages ||
				!bytes.Equal(vnextOwnerStatusTestPersistentImage(t, fixture.group), stableImage) {
				t.Fatal("re-signed conflict performed a live check or mutated durable state")
			}
			if verifier.prepareCalls != 3 {
				t.Fatalf("Scheduler envelope prepare calls=%d, want 3",
					verifier.prepareCalls)
			}
		})
	}
}
