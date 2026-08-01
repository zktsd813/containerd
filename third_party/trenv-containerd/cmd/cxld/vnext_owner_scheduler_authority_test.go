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
	const wantTermID = "fb5b8daad8459394988e90ad1fa291e9d9f2809692a9bcaece4f83de13090a23"
	const wantMutationDigest = "356d18e484d1b1ea755a24c07f94b72de050d1a7be99dbfade743e5f9ffd9a34"
	const wantSignature = "VNxpRP6_s3KntcpdD7S150D6-eqvKKzZO6uLtPAbtxVMoz-e1a9zhJliJjopFOezN-3uYz_7t_0clxyYXrChDA"
	const wantReceipt = "e3af062b83fbca3452c8ebbfca8b793b2a239453d6e155af084e84fa389d4f1d"
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

func TestVNextOwnerSchedulerStatusAndFenceDigestBindsEveryField(t *testing.T) {
	var proof vnextOwnerSchedulerProof
	for index := range proof.TermID {
		proof.TermID[index] = byte(0x10 + index)
		proof.MutationDigest[index] = byte(0x40 + index)
		proof.Receipt[index] = byte(0x70 + index)
	}
	base := vnextOwnerProducerCapabilityIssueStatusAndFenceRequest{
		RequestID: "status-digest-request",
		Operation: vnextOwnerOperationIdentity{
			RequestID: "reserve-request", CheckpointID: "checkpoint",
			ProducerID: "producer", OwnerID: "owner", OwnerEpoch: 7,
			AllocationRecordID: 11,
		},
		ExpectedIssueRequestID:      "issue-request",
		ExpectedIssueSchedulerProof: proof,
		ExpectedIssueCreateRevision: 37,
	}
	want, err := vnextOwnerSchedulerMutationDigest(
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence, base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*vnextOwnerProducerCapabilityIssueStatusAndFenceRequest){
		"request ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) { value.RequestID += "-changed" },
		"allocation request ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.Operation.RequestID += "-changed"
		},
		"checkpoint ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.Operation.CheckpointID += "-changed"
		},
		"producer ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.Operation.ProducerID += "-changed"
		},
		"Owner ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.Operation.OwnerID += "-changed"
		},
		"Owner epoch": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) { value.Operation.OwnerEpoch++ },
		"allocation record ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.Operation.AllocationRecordID++
		},
		"expected Issue request ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.ExpectedIssueRequestID += "-changed"
		},
		"expected term ID": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.ExpectedIssueSchedulerProof.TermID[0]++
		},
		"expected mutation digest": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.ExpectedIssueSchedulerProof.MutationDigest[0]++
		},
		"expected receipt": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.ExpectedIssueSchedulerProof.Receipt[0]++
		},
		"expected create revision": func(value *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest) {
			value.ExpectedIssueCreateRevision++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			got, err := vnextOwnerSchedulerMutationDigest(
				vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence, changed)
			if err != nil {
				t.Fatal(err)
			}
			if got == want {
				t.Fatal("status-and-fence mutation digest ignored changed field")
			}
		})
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
	var expectedIssueProof vnextOwnerSchedulerProof
	for index := 0; index < vnextOwnerSchedulerDigestBytes; index++ {
		expectedIssueProof.TermID[index] = byte(0x10 + index)
		expectedIssueProof.MutationDigest[index] = byte(0x40 + index)
		expectedIssueProof.Receipt[index] = byte(0x70 + index)
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
			wantMutation:  "46fc00d4e99f7c3074f6b7b8e460c0522bc19cb356de1cece0cde5438a137e2a",
			wantSignature: "NMSQp_YtloA5ZlBR3tbM1EgyxnyubmANXPa0uLEle1t1lsU31NNA7w5p9xMRsonZD0YBTGc8eZfbNOETb6rqDA",
			wantReceipt:   "5a289f9fb366eaf46d0eecf4d56e15f815bd3c10447368a30c6861daa2391fa8",
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
			wantMutation:  "8ad5a03cd8dac4fac826cb0a88fcc4bd6b8d53adbdd4b1f0ddfb35c4d7adc1eb",
			wantSignature: "WYbrUpD8bfJniZKUKVPbZlaXK-apOTAuGLAh7WTCVG1JsA0kLiciuLsa3TQaeX2jj7TSGkzLSDlIQUR2JorcDw",
			wantReceipt:   "6b5ddbd9f1293cd265fb9ab57966844dc43f488a350d831cdc2f4a8112042485",
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
			wantMutation:  "6c4ae6ee6e43ef4fa89e19bab364624b0920f1c3dd8f865179a196aefd0e67f9",
			wantSignature: "wdxReHbQYseS4SQlEihR4cobtiin4A6zxkUU7JB04WRnDtrOev-Fu-zFJIfzFwv-D3U-5QcRXxoqdUl1WkTJDA",
			wantReceipt:   "b93f09c9da41e72fd45af7eff131edbf27cd2922f55a2ddc1068bf9fc226e8b8",
		},
		{
			name:      "producer-capability-issue-status-and-fence",
			operation: vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
			mutation: vnextOwnerProducerCapabilityIssueStatusAndFenceRequest{
				RequestID: "capability-status-1", Operation: identity,
				ExpectedIssueRequestID:      "capability-issue-1",
				ExpectedIssueSchedulerProof: expectedIssueProof,
				ExpectedIssueCreateRevision: 37,
			},
			wantMutation:  "df25531cf3c57e0ca95dcf8c74749eca34fba6e59941cd55018d9e935f25e8a6",
			wantSignature: "vIf1Wybp5nH9e943NCUXDzMOL_o-lW_ZYsS4v7K0KAzUtxfDqb_CLBFknqxAEwo02JBZFL7ETyY7cCI0sMgjCA",
			wantReceipt:   "15e4554a18292bbb0e6e63504ea0a7585d30d62de4ef6dd719d5767e4867fd52",
		},
		{
			name:      "revoke",
			operation: vnextOwnerRPCOperationRevokeProducerCapability,
			mutation: vnextOwnerRevokeProducerCapabilityRequest{
				RequestID: "capability-revoke-1", Operation: identity,
				CapabilityID: "00112233445566778899aabbccddeeff",
			},
			wantMutation:  "91c9cd2dd9a1d998b401f8c24aa71facf5a0cf8bab5a3e21a72ae0fbb1d36d1d",
			wantSignature: "pvJJQj9vi7vXB_ipoC834mzgHFrklDFDwnOeGve_hGb9ONUZIEKm3EOU9CREJGHXfUVSPRk21l4SzPG0ZqgFDQ",
			wantReceipt:   "d6d7a18160972d70f5a1c9250cf4f9af924cc40797fefccfd56947e169f7e799",
		},
		{name: "commit", operation: vnextOwnerRPCOperationCommit, mutation: identity,
			wantMutation:  "242aab3a158e7408b2c950495b01209654f75089e56081514aafe687896fd026",
			wantSignature: "QoV6Oo_hPB28iDl94x_4zmJIXTtHpM4TSPnYlxphIvEhF8ZqmE2Q1yORWjR5hCoPL7Kn-6fMqUINYyVwTo-qAg",
			wantReceipt:   "9c3647db0d2e8b8fb7843153f4005e803574bd54100c803887c5b032699a182c"},
		{name: "abort", operation: vnextOwnerRPCOperationAbort, mutation: identity,
			wantMutation:  "7c5ca4c24280f675a223e3f190086ad88d51bd724449164c0949316dde2df104",
			wantSignature: "LK6mXcIbm1T7eKV2u4P6XEiYvW-H6wSY_J6H4is0jCUkzaB3qgVKAG2x6gWICLxGJHkNXWFbWo-g1xUuhNW4Bg",
			wantReceipt:   "afa36a040bac9ab0b034e673a34308f2866345f6aaf00ebc241f7e7b6c2c3c11"},
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
	if authority.TermID != "885654027306807936306b62c6dbd4bb02c3a692277e4b18a322e96d08e7c564" ||
		authority.Signature != "q2REIJAwgy2XwA_Xs9evlm7aSWCpq72-sZwnXeoKBI_SdsHzDrcqSoUUpS8XOgKNGQwTvHabJ14YUY8kgQShAg" ||
		hex.EncodeToString(verified.Receipt[:]) != "5cf8aad626d139c743f8d00498101cf1d83e202d7ff9d2c13d73d29084c290dd" {
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
