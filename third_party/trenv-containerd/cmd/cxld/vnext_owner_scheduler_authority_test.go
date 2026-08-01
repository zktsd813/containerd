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
	const wantTermID = "ba38f636fde761e7ae5464a599cf8724382b0b1e024de34910fa95799ff4bc70"
	const wantMutationDigest = "52df6e9dbef3ef7ab2f1a1f5acdf75b77c7f5fa54e7ffa9ec3aac25c35cee3af"
	const wantSignature = "P7GoUywXygshB-GaRPujODQPFipdyThpdju7MjG0geweRbe6UmO1Wwy-ZRwQpE0VRS0juWPT6Npzk1_fCv4tAQ"
	const wantReceipt = "53ee272bb94c81f40a840153eb3a39225cc5753de63fd3611a64aeafc1c9f6c6"
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
			wantMutation:  "1f32284a798f4654e7555867f469ba1d1ed105899a88e8f8a8fec82274f46e1d",
			wantSignature: "MSUo2iIzx6IVOnaAojIQsmrB5-L3drZGy02montmsiGX_1yhEsU2Ch_Lz4B-npEO_CE4182aiL8WJTCmhi6xDA",
			wantReceipt:   "733872c6b5f55fb96bc7634812d297fe0afc30472d9fa6bd2241d397654948e1",
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
			wantMutation:  "143d83349d3e6d0df901c87fb867a0896321cb694d383f26e760fc98c2332a5f",
			wantSignature: "uLU1Xvtp-l3IllNg91OeUT319HrfPM3CUAdZQG5Ct4xhFI_IaFR4fyOGcHW9fH1iV21HI98EYGsB3YgjScyyCA",
			wantReceipt:   "276882e003461fad9b6d1abc58032352a8a5ceb9e72ac9c03cfb9253ec76486e",
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
			wantMutation:  "a202f0d217e9876535c6a512754f73ce3f41c75a871331dfae7a14b6c473abd8",
			wantSignature: "nMU_FVU5u-rXe2ZDvnQZImxLCl9oXzTWlBrlH3bl9VMLYsudKzyCA2p19Jgl5tjYERhCRqzF6fq3ObOFDe2YBg",
			wantReceipt:   "aac9b2e793bb9f7e9df68f97c94362588df9cd7f6eb4b85b793b32a6e8df27d1",
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
			wantMutation:  "b7de5ff0f799ffa403eef0e3dfde7a694c00ab02fa251f7c27fa78cf2aa3c0a1",
			wantSignature: "JXvhLCN20UF6t5jUxB7WNpzLqcgEtptEgLSFPjUpodRCRBx3p4p2mlvNFvihA7W242Wwf1kuDU6iybE9WAvVDA",
			wantReceipt:   "78d56a30ac075d2d65e34b5bbcfa2e8c6dea4d4f7518708bb5e04b5a18ba6e4a",
		},
		{
			name:      "revoke",
			operation: vnextOwnerRPCOperationRevokeProducerCapability,
			mutation: vnextOwnerRevokeProducerCapabilityRequest{
				RequestID: "capability-revoke-1", Operation: identity,
				CapabilityID: "00112233445566778899aabbccddeeff",
			},
			wantMutation:  "5bffee14ac917792991f8bbaf709223f567ab75ee52f00289915863f83a6b309",
			wantSignature: "TqMvJUk6SABiTjb3kWtPDBQeUrWMkQ214uqo9o-d4wvM7XuVWUzKPHJPYM7VDdAjpo4BBJR5COgEYrtdwG3uDQ",
			wantReceipt:   "f676a3cf3e6e087fbe6e690b089b1208e8224b333fabaa0f1aa91a0c1fc79555",
		},
		{name: "commit", operation: vnextOwnerRPCOperationCommit, mutation: identity,
			wantMutation:  "0c620f5c09a0a23658d907f228c9e014eadc61e8ff31022aadd8267090c7dac0",
			wantSignature: "9akIOy3Dtmw0KLhhbVRG8YYQcKhoVDE0TJ1HibdpPgPz9LF5suEuJa4cvag2tHuTBrW6VfbEah9_C9rLB8vHDw",
			wantReceipt:   "8bb92aea82b4f195ed520bb2f9c81906ac3286c7b443f7a48951659166389df6"},
		{name: "abort", operation: vnextOwnerRPCOperationAbort, mutation: identity,
			wantMutation:  "e822fae38318749e79a38f28d7e6e8918b9133dc6410b15355172a62eaab26eb",
			wantSignature: "Sr16_M4wxIuXroM0vBi2T74Mp5nSOqvPdqco0aN7qvs9nhWDyw4YePzUVeFMRCq3dMvL0stH3MdBUsLUrzzGAQ",
			wantReceipt:   "44b173640b05a4baaefb6873481e1375c777f4344a7a7e1962af41612e36c184"},
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
	if authority.TermID != "61bf312fa1c37b3f3ea77c1fce31a8bfdc9358177564517a7ef4fdcf42282736" ||
		authority.Signature != "qIRa6aA91ibP65WpEo2Lb9haNKo576OyI9FbobiaErcDb5HYcbVjXHvOi_0Fz373X8Z1LbPJ818BEHOMnomfCA" ||
		hex.EncodeToString(verified.Receipt[:]) != "dde3ab28ff4d2c03c98093b889bec7c138a9c40a910cd8d55c995e1a9300cef5" {
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
