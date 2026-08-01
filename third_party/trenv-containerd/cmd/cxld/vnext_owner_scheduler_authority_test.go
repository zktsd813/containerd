package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
)

const vnextOwnerSchedulerTestLeaderKey = "/trenv/cxl-checkpoint/global-orchestrator-leader"

func vnextOwnerSchedulerTestAuthority(
	t *testing.T,
	operation string,
	mutation interface{},
) (vnextOwnerSchedulerAuthority, vnextOwnerSchedulerVerifiedAuthority) {
	return vnextOwnerSchedulerTestAuthorityWithCluster(
		t, operation, mutation, 0x01abcdef12345678)
}

func vnextOwnerSchedulerTestAuthorityWithCluster(
	t *testing.T,
	operation string,
	mutation interface{},
	clusterID uint64,
) (vnextOwnerSchedulerAuthority, vnextOwnerSchedulerVerifiedAuthority) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	var nonce [vnextOwnerSchedulerNonceBytes]byte
	for index := range nonce {
		nonce[index] = byte(0xa0 + index)
	}
	const leaseID = uint64(0x01a2b3c4d5e6f708)
	leaderValue, err := formatVNextOwnerSchedulerLeaderValue(
		"scheduler/test-a", leaseID, nonce, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	leader, err := parseVNextOwnerSchedulerLeaderValue(leaderValue)
	if err != nil {
		t.Fatal(err)
	}
	parsed := vnextOwnerSchedulerParsedAuthority{
		ClusterID:      clusterID,
		CreateRevision: 41,
		ModRevision:    41,
		LeaseID:        leaseID,
		LeaderValue:    leaderValue,
		Leader:         leader,
	}
	parsed.TermID = vnextOwnerSchedulerTermDigest(vnextOwnerSchedulerTestLeaderKey, parsed)
	mutationDigest, err := vnextOwnerSchedulerMutationDigest(operation, mutation)
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes := ed25519.Sign(
		privateKey,
		vnextOwnerSchedulerSignaturePreimage(parsed.TermID, mutationDigest))
	authority := vnextOwnerSchedulerAuthority{
		ClusterID:      fmt.Sprintf("%016x", clusterID),
		CreateRevision: parsed.CreateRevision,
		ModRevision:    parsed.ModRevision,
		LeaseID:        "01a2b3c4d5e6f708",
		LeaderValue:    leaderValue,
		KeyID:          hex.EncodeToString(leader.KeyID[:]),
		TermID:         hex.EncodeToString(parsed.TermID[:]),
		Signature:      base64.RawURLEncoding.EncodeToString(signatureBytes),
	}
	verified, err := verifyVNextOwnerSchedulerAuthoritySignature(
		vnextOwnerSchedulerTestLeaderKey, authority, mutationDigest)
	if err != nil {
		t.Fatal(err)
	}
	return authority, verified
}

func vnextOwnerSchedulerTestReserveMutation() vnextOwnerReserveRequest {
	return vnextOwnerReserveRequest{
		RequestID:    "reserve-1",
		CheckpointID: "checkpoint-1",
		ProducerID:   "producer-1",
		OwnerID:      "owner-1",
		OwnerEpoch:   7,
		MaxExtents:   13,
		Contents: []vnextOwnerReserveContent{
			{
				Kind:          vnextOwnerServiceContentMemory,
				ObjectID:      1,
				ByteLength:    4095,
				CapacityPages: 1,
			},
			{
				Kind:          vnextOwnerServiceContentArtifact,
				ObjectID:      2,
				ByteLength:    8192,
				CapacityPages: 3,
			},
		},
	}
}

func TestVNextOwnerSchedulerCanonicalGolden(t *testing.T) {
	mutation := vnextOwnerSchedulerTestReserveMutation()
	authority, verified := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, mutation)
	const wantLeaderValue = "cxld-scheduler-leader-v1:c2NoZWR1bGVyL3Rlc3QtYQ:01a2b3c4d5e6f708:oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8:MCowBQYDK2VwAyEAebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ"
	const wantTermID = "f2779101ff9c44c87d5ecb872b01bd48e426c59f109da3e36fa393cb9b70f44b"
	const wantMutationDigest = "83881e322d39fe5af7e182c1f4c874ca8ce144ef63864ae06dbeaa78343ed41b"
	const wantSignature = "CXWLLzwTz5dDrBA3Xrlpw-cpOKupsCEkfwz_h68Yhn3s_Ogbc2TCcrZhWgiTTQegNd8K1DUQy6tZAwo8-J7dBg"
	const wantReceipt = "be4253fc65a4418084664c6c3839ccacacc5d8cc387d0a03fcec0f3037be3e33"
	for name, values := range map[string][2]string{
		"leader value":    {authority.LeaderValue, wantLeaderValue},
		"term ID":         {authority.TermID, wantTermID},
		"mutation digest": {hex.EncodeToString(verified.MutationDigest[:]), wantMutationDigest},
		"signature":       {authority.Signature, wantSignature},
		"receipt":         {hex.EncodeToString(verified.Receipt[:]), wantReceipt},
	} {
		if values[0] != values[1] {
			t.Fatalf("%s = %q, want %q", name, values[0], values[1])
		}
	}
}

func TestVNextOwnerSchedulerLeaderValueStrictCanonical(t *testing.T) {
	authority, _ := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, vnextOwnerSchedulerTestReserveMutation())
	valid := authority.LeaderValue
	fields := strings.Split(valid, ":")
	tests := map[string]string{
		"wrong prefix":        "other" + valid[len(vnextOwnerSchedulerLeaderValuePrefix):],
		"extra field":         valid + ":extra",
		"padded Scheduler ID": strings.Join([]string{fields[0], fields[1] + "=", fields[2], fields[3], fields[4]}, ":"),
		"uppercase lease":     strings.Join([]string{fields[0], fields[1], strings.ToUpper(fields[2]), fields[3], fields[4]}, ":"),
		"padded SPKI":         strings.Join([]string{fields[0], fields[1], fields[2], fields[3], fields[4] + "="}, ":"),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseVNextOwnerSchedulerLeaderValue(value); err == nil {
				t.Fatal("non-canonical leader value was accepted")
			}
		})
	}
}

func TestVNextOwnerSchedulerLeaderKeySchemaIsExact(t *testing.T) {
	valid := []string{
		"/openwhisk/cxl-checkpoint/global-orchestrator-leader",
		"/test-cluster/cxl-checkpoint/global-orchestrator-leader",
	}
	for _, key := range valid {
		if err := validateVNextOwnerSchedulerLeaderKey(key); err != nil {
			t.Fatalf("valid Scheduler leader key %q was rejected: %v", key, err)
		}
	}
	invalid := []string{
		"/openwhisk/cxl-checkpoint/other-leader",
		"/openwhisk/global-orchestrator-leader",
		"//cxl-checkpoint/global-orchestrator-leader",
		"/openwhisk//cxl-checkpoint/global-orchestrator-leader",
		"/parent/openwhisk/cxl-checkpoint/global-orchestrator-leader",
		"openwhisk/cxl-checkpoint/global-orchestrator-leader",
	}
	for _, key := range invalid {
		if err := validateVNextOwnerSchedulerLeaderKey(key); err == nil {
			t.Fatalf("noncanonical Scheduler leader key %q was accepted", key)
		}
	}
}

func TestVNextOwnerSchedulerSignatureBindsEveryReserveField(t *testing.T) {
	mutation := vnextOwnerSchedulerTestReserveMutation()
	authority, verified := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, mutation)
	tampered := []vnextOwnerReserveRequest{
		func() vnextOwnerReserveRequest { value := mutation; value.RequestID += "x"; return value }(),
		func() vnextOwnerReserveRequest { value := mutation; value.CheckpointID += "x"; return value }(),
		func() vnextOwnerReserveRequest { value := mutation; value.ProducerID += "x"; return value }(),
		func() vnextOwnerReserveRequest { value := mutation; value.OwnerID += "x"; return value }(),
		func() vnextOwnerReserveRequest { value := mutation; value.OwnerEpoch++; return value }(),
		func() vnextOwnerReserveRequest { value := mutation; value.MaxExtents++; return value }(),
		func() vnextOwnerReserveRequest {
			value := mutation
			value.Contents = append([]vnextOwnerReserveContent(nil), mutation.Contents...)
			value.Contents[0].Kind++
			return value
		}(),
		func() vnextOwnerReserveRequest {
			value := mutation
			value.Contents = append([]vnextOwnerReserveContent(nil), mutation.Contents...)
			value.Contents[0].ObjectID++
			return value
		}(),
		func() vnextOwnerReserveRequest {
			value := mutation
			value.Contents = append([]vnextOwnerReserveContent(nil), mutation.Contents...)
			value.Contents[0].ByteLength++
			return value
		}(),
		func() vnextOwnerReserveRequest {
			value := mutation
			value.Contents = append([]vnextOwnerReserveContent(nil), mutation.Contents...)
			value.Contents[0].CapacityPages++
			return value
		}(),
		func() vnextOwnerReserveRequest {
			value := mutation
			value.Contents = []vnextOwnerReserveContent{mutation.Contents[1], mutation.Contents[0]}
			return value
		}(),
	}
	for index, changed := range tampered {
		digest, err := vnextOwnerSchedulerMutationDigest(vnextOwnerRPCOperationReserve, changed)
		if err != nil {
			t.Fatal(err)
		}
		if digest == verified.MutationDigest {
			t.Fatalf("tamper %d did not change the mutation digest", index)
		}
		if _, err := verifyVNextOwnerSchedulerAuthoritySignature(
			vnextOwnerSchedulerTestLeaderKey, authority, digest); err == nil {
			t.Fatalf("tamper %d retained a valid signature", index)
		}
	}
}

func TestVNextOwnerSchedulerSignatureRejectsCrossOperationReplay(t *testing.T) {
	identity := vnextOwnerOperationIdentity{
		RequestID:          "reserve-1",
		CheckpointID:       "checkpoint-1",
		ProducerID:         "producer-1",
		OwnerID:            "owner-1",
		OwnerEpoch:         7,
		AllocationRecordID: 11,
	}
	authority, commit := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationCommit, identity)
	abortDigest, err := vnextOwnerSchedulerMutationDigest(vnextOwnerRPCOperationAbort, identity)
	if err != nil {
		t.Fatal(err)
	}
	if abortDigest == commit.MutationDigest {
		t.Fatal("Commit and SchedulerAbort have the same mutation digest")
	}
	if _, err := verifyVNextOwnerSchedulerAuthoritySignature(
		vnextOwnerSchedulerTestLeaderKey, authority, abortDigest); err == nil {
		t.Fatal("Commit signature authorized SchedulerAbort")
	}
}

func TestVNextOwnerSchedulerAllMutationGoldens(t *testing.T) {
	identity := vnextOwnerOperationIdentity{
		RequestID:          "reserve-1",
		CheckpointID:       "checkpoint-1",
		ProducerID:         "producer-1",
		OwnerID:            "owner-1",
		OwnerEpoch:         7,
		AllocationRecordID: 11,
	}
	var issueNonce [vnextProducerCapabilityTokenBytes]byte
	for index := range issueNonce {
		issueNonce[index] = byte(0x40 + index)
	}
	vectors := []struct {
		name          string
		operation     string
		mutation      interface{}
		wantMutation  string
		wantSignature string
		wantReceipt   string
	}{
		{
			name:      "set-admission",
			operation: vnextOwnerRPCOperationSetAdmission,
			mutation: vnextOwnerSetAdmissionRequest{
				RequestID: "admission-1", OwnerID: "owner-1", OwnerEpoch: 7,
				From: vnextOwnerAdmissionActive, Target: vnextOwnerAdmissionReadOnly,
				ExpectedSequence: 1,
			},
			wantMutation:  "3be23b4c74a1dab0e1344232c11e0bc136d989239ca7ff2b327ad4e8440823f3",
			wantSignature: "1knSm8ccExztszT-YpbDLoKpdC3T0XKyMVbozkM7bkQIP6rnkkZrG6phYgBjbZW5flmCJ2-As6HrkEuhDt5GBQ",
			wantReceipt:   "e01aac66ce7f2af0122ce3d30d260d2bed33cb61d01786629fbf18ed19c598e8",
		},
		{
			name:      "reserve-all-content-kinds",
			operation: vnextOwnerRPCOperationReserve,
			mutation: vnextOwnerReserveRequest{
				RequestID: "reserve-all-kinds", CheckpointID: "checkpoint-all-kinds",
				ProducerID: "producer-1", OwnerID: "owner-1", OwnerEpoch: 7,
				MaxExtents: 17,
				Contents: []vnextOwnerReserveContent{
					{Kind: vnextOwnerServiceContentMemory, ObjectID: 1, ByteLength: 4096, CapacityPages: 1},
					{Kind: vnextOwnerServiceContentArtifact, ObjectID: 2, ByteLength: 4097, CapacityPages: 2},
					{Kind: vnextOwnerServiceContentMMTemplate, ObjectID: 3, ByteLength: 17, CapacityPages: 1},
					{Kind: vnextOwnerServiceContentPageMap, ObjectID: 4, ByteLength: 8192, CapacityPages: 2},
					{Kind: vnextOwnerServiceContentRestoreBlob, ObjectID: 5, ByteLength: 1, CapacityPages: 1},
					{Kind: vnextOwnerServiceContentPublication, ObjectID: 6, ByteLength: 4096, CapacityPages: 1},
				},
			},
			wantMutation:  "f4734cdcd32afbd90029e9eb7e4c2e5d4ad1bfef46d66bcc4526875931f8c2df",
			wantSignature: "fy5sZfn8GaLf0tKasUzKs2gTxhntVs8iJmmfAumo0VTH8MfEYQTdCJqprBoAcfLPrk3gafoN_DCH02b-7T6KBA",
			wantReceipt:   "7d973e14322696f1fdea060f3ee127d8e164f25f85267e5b2c5e4e0caf269fa7",
		},
		{
			name:      "issue",
			operation: vnextOwnerRPCOperationIssueProducerCapability,
			mutation: vnextOwnerIssueProducerCapabilityRequest{
				RequestID: "capability-issue-1", Operation: identity,
				ProducerPrincipal:  "spiffe://trenv/producer/test-a",
				AllowedOperations:  vnextProducerCapabilityAll,
				RequestedTTLMillis: 60000, Nonce: issueNonce,
			},
			wantMutation:  "690771483b750759fbe4326a1ef21ae2047faa58475fa283f249bb6758c78a28",
			wantSignature: "jD-ErP6QbzpXyDaiGraZFSFCnPckErKNBMmqPyURryVy6yHbu16cKh3a55SESBd_ffa2FfM4U4G8qwJrqrKoDQ",
			wantReceipt:   "7df4073e4a7332224733ed60c698ef0d0f13db3009a4257e2568d021c8ce5c3d",
		},
		{
			name:      "revoke",
			operation: vnextOwnerRPCOperationRevokeProducerCapability,
			mutation: vnextOwnerRevokeProducerCapabilityRequest{
				RequestID: "capability-revoke-1", Operation: identity,
				CapabilityID: "00112233445566778899aabbccddeeff",
			},
			wantMutation:  "5a545a0cc7b560970910ccc2e8873584c462d6bf932e38d595da9177d52e1de4",
			wantSignature: "iyB2ao1_iF4eeoLAU_GMJd1-RkZ8K8ySho5crq2VTr_ORhIdLTWV0TrpmnHKE9nbOiwvu0VRcadKdrZZiSj8Cg",
			wantReceipt:   "b48dbecad5dd91b69e417ddfcb308a8e5a8ec7363bb9c98ab5c6d56dec98cef4",
		},
		{name: "commit", operation: vnextOwnerRPCOperationCommit, mutation: identity,
			wantMutation:  "9964ae82d2982e079921c72d1fb54ae22dd4d9e1ae6f00025d4263c7503545cc",
			wantSignature: "4jHO5r5kUdT0obnruAOJPXL98ypdr_tFTqEG8A8MhrKlmvxC4zN1rl4j6agGQs0YRcVWl6RMtZS0Ti0jIfvsBw",
			wantReceipt:   "e11fec32ddda622e8fef5063a1dbd44f2fd675169e67c513469dfbe028ce92b7"},
		{name: "abort", operation: vnextOwnerRPCOperationAbort, mutation: identity,
			wantMutation:  "e784f3c6f3f0c14aac5ff03f0474ba20205c1f591b991e7cf08e5ac83407d7e4",
			wantSignature: "bj-927bdF_r2blE_sW1gHaQaugsIbxiol-BMGp9jcx8Z45-Oytxq4ETDgvhlH0DsQMBWbL9uXkEYHuQwNzeDDA",
			wantReceipt:   "2600cbe33d73f4f654be041c0b227a3626e95f5d09c97d6f1e3253e0e1abb43c"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			authority, verified := vnextOwnerSchedulerTestAuthority(
				t, vector.operation, vector.mutation)
			if got := hex.EncodeToString(verified.MutationDigest[:]); got != vector.wantMutation {
				t.Fatalf("mutation digest = %s, want %s", got, vector.wantMutation)
			}
			if authority.Signature != vector.wantSignature {
				t.Fatalf("signature = %s, want %s", authority.Signature, vector.wantSignature)
			}
			if got := hex.EncodeToString(verified.Receipt[:]); got != vector.wantReceipt {
				t.Fatalf("receipt = %s, want %s", got, vector.wantReceipt)
			}
		})
	}
}

func TestVNextOwnerSchedulerHighBitClusterIsCanonicalUnsigned(t *testing.T) {
	const clusterID = uint64(0xfedcba9876543210)
	authority, verified := vnextOwnerSchedulerTestAuthorityWithCluster(
		t, vnextOwnerRPCOperationReserve,
		vnextOwnerSchedulerTestReserveMutation(), clusterID)
	if authority.ClusterID != "fedcba9876543210" || verified.Parsed.ClusterID != clusterID {
		t.Fatalf("high-bit cluster lost unsigned representation: %#v", verified.Parsed)
	}
	if authority.TermID != "7a79ba8fb2b0355e52189d242ac965620c1804996513782ce537f61d40a5acfa" ||
		authority.Signature != "rOwyzw7gAgom9N6sm_6G2TE6nzPk5MUgpEvZ1I3cfyfwUmgzxgHQhCnwLXFWVmivHORIsXHsUZzNuIhlUBwyAA" ||
		hex.EncodeToString(verified.Receipt[:]) != "10687bc1e256d322c08b348bc1a1469bf09773bddbb74909b915d4a9733c9b1d" {
		t.Fatalf("high-bit cluster golden changed: %#v", authority)
	}
}

func TestVNextOwnerSchedulerRejectsSignedHighBitRevisionLeaseAndInvalidUTF8(t *testing.T) {
	mutation := vnextOwnerSchedulerTestReserveMutation()
	authority, _ := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, mutation)
	highCreate := authority
	highCreate.CreateRevision = uint64(math.MaxInt64) + 1
	highCreate.ModRevision = highCreate.CreateRevision
	if _, err := parseVNextOwnerSchedulerAuthority(
		vnextOwnerSchedulerTestLeaderKey, highCreate); err == nil {
		t.Fatal("signed-high-bit revision was accepted")
	}
	highLease := authority
	highLease.LeaseID = "8000000000000000"
	if _, err := parseVNextOwnerSchedulerAuthority(
		vnextOwnerSchedulerTestLeaderKey, highLease); err == nil {
		t.Fatal("signed-high-bit lease was accepted")
	}
	fields := strings.Split(authority.LeaderValue, ":")
	fields[1] = base64.RawURLEncoding.EncodeToString([]byte{0xff, 0xfe})
	if _, err := parseVNextOwnerSchedulerLeaderValue(strings.Join(fields, ":")); err == nil {
		t.Fatal("invalid UTF-8 Scheduler ID was accepted")
	}
	fields = strings.Split(authority.LeaderValue, ":")
	fields[3] = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if _, err := parseVNextOwnerSchedulerLeaderValue(strings.Join(fields, ":")); err == nil {
		t.Fatal("zero Scheduler term nonce was accepted")
	}
}

func TestVNextOwnerSchedulerIdentityUnicodeWhitespaceBoundaryIsPinned(t *testing.T) {
	authority, _ := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, vnextOwnerSchedulerTestReserveMutation())
	for name, character := range map[string]rune{
		"nbsp":         '\u00a0',
		"nel":          '\u0085',
		"figure-space": '\u2007',
		"narrow-nbsp":  '\u202f',
	} {
		for _, schedulerID := range []string{
			string(character) + "scheduler",
			"scheduler" + string(character),
		} {
			fields := strings.Split(authority.LeaderValue, ":")
			fields[1] = base64.RawURLEncoding.EncodeToString([]byte(schedulerID))
			if _, err := parseVNextOwnerSchedulerLeaderValue(
				strings.Join(fields, ":")); err == nil {
				t.Fatalf("%s Scheduler boundary whitespace %q was accepted", name, schedulerID)
			}
		}
	}
	fields := strings.Split(authority.LeaderValue, ":")
	fields[1] = base64.RawURLEncoding.EncodeToString([]byte("scheduler\u00a0part"))
	if _, err := parseVNextOwnerSchedulerLeaderValue(strings.Join(fields, ":")); err != nil {
		t.Fatalf("internal non-control NBSP was rejected: %v", err)
	}
}
