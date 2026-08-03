package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	vnextReaderActivationGoldenPrincipal                = "spiffe://test.example/scheduler/activation"
	vnextReaderActivationGoldenProposalRequestDigest    = "db84c097fa72e250d47103b89d05c5759bc5b5af65fe9c701ab2c78551d02a16"
	vnextReaderActivationGoldenProposalPreimageSHA      = "2b34100ccaffb0b61f5d8ecbb36ea63904960dc79204d39b209f24ed669e0a08"
	vnextReaderActivationGoldenProposalAuthorityReceipt = "238d6c2dbe5ef9be1402293d58cb0246bcecd3919a2d3d9327196579f0b9ab9c"
	vnextReaderActivationGoldenProposalRequestJSONSHA   = "87a1fc873cd138c53ed1229a89a40da27faf2dd5dbd83c32755e5e94aec34dcc"
	vnextReaderActivationGoldenStableReceipt            = "a00113cb2573111703761231bf444bc8e0df640356e92bf899c1b49c89890f03"
	vnextReaderActivationGoldenProposalOuterReceipt     = "3923874e573f0f079be946eddd139d8c7990b23c3292a7d4a8e18c3794e73a28"

	vnextReaderActivationGoldenCommitRequestDigest    = "bced0e28d794f9af676ad23a56a0a72ec55e147012e653b16e139df76075f091"
	vnextReaderActivationGoldenCommitPreimageSHA      = "7f4245464248cbabd2f84078d23f8ad52ab8f202935890833f10ff4fb23fedcd"
	vnextReaderActivationGoldenCommitAuthorityReceipt = "d30f0daf3a464649e02a2c8208a67db5fb9c0c8611d6a20f5b545e38a934ff1c"
	vnextReaderActivationGoldenCommitRequestJSONSHA   = "ae949b13f21696c189fb132b60e0d249dea16f1132a0575180dc4e81948dbc80"
	vnextReaderActivationGoldenCommitOuterReceipt     = "4719cdde06c9404c7d3273b4ca70b5d7a3e88efd11c2cca0ae72ff6bae36d16e"

	vnextReaderActivationGoldenStatusRequestDigest       = "2f1fc6dc783bb69dba372106aab1408c6d35673c08f44c6cc62356026ac9451d"
	vnextReaderActivationGoldenStatusPreimageSHA         = "943c4bb7f666d0abcf7c35d2dbb086f58161eb6aab86164e8341f41435dab345"
	vnextReaderActivationGoldenStatusAuthorityReceipt    = "d5bc9cba954d599fc1d2d9b3470114f401548e8d6c88aaa5253b8d1d0dc8cfae"
	vnextReaderActivationGoldenStatusRequestJSONSHA      = "e3dde2caea749c51752ea70704be4858279731d8d2c34c7d4b0777e4c897812a"
	vnextReaderActivationGoldenStatusPendingOuterReceipt = "309a8355152d7d32907766c125254b28f17e636635184d7c1fa1a3ecf50c5cd7"
	vnextReaderActivationGoldenProposalRequestJSON       = `{"protocol":"cxld.vnext-reader-activation-proposal.v1","operation":"vnextReaderProposeActivation","acquired":{"authorization":{"restoreAuthorizationId":"authorization-activation-a","checkpointId":"checkpoint-a","executorNodeId":"executor-a","executorCxldLogicalId":"reader-cxld-a","executorCxldProcessIncarnationId":"58d5ba587f0128968a26f3bd32c69bfbe8a01fdd69738b9137f34ec6343e95c4","readerInitialRegistrationCatalogRevision":47,"targetContainerId":"target-container-a","root":{"rootId":"root-a","rootVersion":7,"mmTemplateId":"mm-template-a","pageMapId":"page-map-a","pageMapVersion":11,"deviceTableDigest":"ce03c6dc31b76bde4e91d53ed53bc4cc5789b25201ca1951e5bcc6296621dd5e","contractId":"publication=TRPUB006/v6/little-endian/trpub006-envelope-little-endian-pages-image-sparse-publication-slot-v1;envelope-header=64;max-payload=67108864;page=4096;fingerprint=crc32c-castagnoli/0x11edc6f41;descriptor=TRCXL006/64/trcxl006-page-descriptor-little-endian-v1","publicationLocator":{"publicationByteLength":4096,"publicationSha256":"fa63a5b64742c4a39fd076c5d94cd3c17054ced0e7dd3c520651bff6db3f5f85","pageRuns":[{"firstPage":{"ownerId":"owner-a","deviceUuid":"device-a","allocationRecordId":13,"dataPageIndex":17},"pageCount":1}]}}},"schedulerId":"scheduler-activation-a","schedulerFenceRevision":41,"issuedAtEpochMillis":100,"expiresAtEpochMillis":200,"catalogState":"ACQUIRED","lastMutationId":"authorization-activation-a"},"activationRequestId":"activation-request-a","authority":{"domain":"cxld-vnext-reader-activation-proposal-authority-v1","clusterId":"0000000000000001","schedulerId":"scheduler-activation-a","schedulerFenceRevision":41,"leaderLeaseId":43,"leaderTermId":"a534945a10776313877572ea96446dbb7c96b55a4a99d32386c4a437ee459b0a","keyId":"fdee0fd2df0d2ae65fcb2b40f58e97bb9924c237681b08fcc08c7978944dcbc0","requestDigest":"db84c097fa72e250d47103b89d05c5759bc5b5af65fe9c701ab2c78551d02a16","signature":"0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40"}}`
)

type vnextReaderActivationGoldenFixture struct {
	request           vnextReaderActivationRequestIdentity
	localProcess      vnextReaderProcessIncarnation
	activation        vnextReaderActivationIntent
	proposalAuthority vnextReaderActivationAuthorityEnvelope
	commitAuthority   vnextReaderActivationAuthorityEnvelope
	statusAuthority   vnextReaderActivationAuthorityEnvelope
}

func vnextReaderActivationGoldenHex32(
	t *testing.T,
	value string,
) [sha256.Size]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != sha256.Size {
		t.Fatalf("decode golden digest %q: len=%d err=%v", value, len(decoded), err)
	}
	var result [sha256.Size]byte
	copy(result[:], decoded)
	return result
}

func vnextReaderActivationGoldenFixtureValue(
	t *testing.T,
) vnextReaderActivationGoldenFixture {
	t.Helper()
	process, err := parseVNextReaderProcessIncarnation(
		"58d5ba587f0128968a26f3bd32c69bfbe8a01fdd69738b9137f34ec6343e95c4")
	if err != nil {
		t.Fatalf("parse golden process incarnation: %v", err)
	}
	acquired := vnextReaderAcquiredAuthorization{
		Authorization: vnextReaderAuthorization{
			RestoreAuthorizationID:                   "authorization-activation-a",
			CheckpointID:                             "checkpoint-a",
			ExecutorID:                               "executor-a",
			CxldLogicalID:                            "reader-cxld-a",
			CxldProcessIncarnationID:                 process,
			ReaderInitialRegistrationCatalogRevision: 47,
			TargetContainerID:                        "target-container-a",
			Root: vnextReaderTrustedRoot{
				RootID:         "root-a",
				RootVersion:    7,
				MMTemplateID:   "mm-template-a",
				PageMapID:      "page-map-a",
				PageMapVersion: 11,
				DeviceTableDigest: vnextReaderActivationGoldenHex32(t,
					"ce03c6dc31b76bde4e91d53ed53bc4cc5789b25201ca1951e5bcc6296621dd5e"),
				ContractID: cxlcheckpoint.V6CompatibilityID,
				PublicationLocator: vnextReaderPublicationLocator{
					PublicationByteLength: 4096,
					PublicationSHA256: vnextReaderActivationGoldenHex32(t,
						"fa63a5b64742c4a39fd076c5d94cd3c17054ced0e7dd3c520651bff6db3f5f85"),
					PageRuns: []cxlcheckpoint.PublicationPageRun{{
						FirstPage: cxlcheckpoint.PageID{
							OwnerID:            "owner-a",
							DeviceUUID:         "device-a",
							AllocationRecordID: 13,
							DataPageIndex:      17,
						},
						PageCount: 1,
					}},
				},
			},
		},
		SchedulerID:            "scheduler-activation-a",
		SchedulerFenceRevision: 41,
		IssuedAtEpochMillis:    100,
		ExpiresAtEpochMillis:   200,
		CatalogState:           vnextReaderCatalogAuthorizationAcquired,
		LastMutationID:         "authorization-activation-a",
	}
	request := vnextReaderActivationRequestIdentity{
		Acquired: acquired, ActivationRequestID: "activation-request-a",
	}
	activation := vnextReaderActivationIntent{
		Request:                request,
		MappingID:              "mapping-a",
		MappingGeneration:      53,
		ActivatedAtEpochMillis: 150,
		State:                  vnextReaderActivationPending,
	}
	activation.CxldReceipt = vnextReaderActivationCanonicalEvidenceReceipt(
		activation, "executor-a", "reader-cxld-a", process)
	proposalDigest := vnextReaderActivationCanonicalProposalRequestDigest(request)
	commitDigest := vnextReaderActivationCanonicalCommitRequestDigest(
		acquired, activation, vnextReaderActivationActiveState{
			CatalogState:   vnextReaderCatalogAuthorizationActive,
			LastMutationID: "activation-request-a",
		})
	statusDigest := vnextReaderActivationCanonicalStatusRequestDigest(request)
	return vnextReaderActivationGoldenFixture{
		request:      request,
		localProcess: process,
		activation:   activation,
		proposalAuthority: vnextReaderActivationGoldenAuthority(
			t, vnextReaderActivationProposalSpec, proposalDigest,
			"scheduler-activation-a", 41, 43,
			"a534945a10776313877572ea96446dbb7c96b55a4a99d32386c4a437ee459b0a",
			"fdee0fd2df0d2ae65fcb2b40f58e97bb9924c237681b08fcc08c7978944dcbc0",
			1),
		commitAuthority: vnextReaderActivationGoldenAuthority(
			t, vnextReaderActivationCommitSpec, commitDigest,
			"scheduler-activation-a", 41, 43,
			"a534945a10776313877572ea96446dbb7c96b55a4a99d32386c4a437ee459b0a",
			"fdee0fd2df0d2ae65fcb2b40f58e97bb9924c237681b08fcc08c7978944dcbc0",
			0x41),
		statusAuthority: vnextReaderActivationGoldenAuthority(
			t, vnextReaderActivationStatusSpec, statusDigest,
			"scheduler-status-b", 59, 61,
			vnextReaderActivationGoldenSHAHex("activation-status-golden-term"),
			vnextReaderActivationGoldenSHAHex("activation-status-golden-key"),
			0x81),
	}
}

func vnextReaderActivationGoldenSHAHex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func vnextReaderActivationGoldenAuthority(
	t *testing.T,
	spec vnextReaderActivationOperationSpec,
	digest [sha256.Size]byte,
	schedulerID string,
	fence uint64,
	lease uint64,
	termHex string,
	keyHex string,
	firstSignatureByte int,
) vnextReaderActivationAuthorityEnvelope {
	t.Helper()
	var signature [ed25519.SignatureSize]byte
	for index := range signature {
		signature[index] = byte(firstSignatureByte + index)
	}
	return vnextReaderActivationAuthorityEnvelope{
		Domain:                 spec.authorityDomain,
		ClusterID:              "0000000000000001",
		SchedulerID:            schedulerID,
		SchedulerFenceRevision: fence,
		LeaderLeaseID:          lease,
		LeaderTermID:           vnextReaderActivationGoldenHex32(t, termHex),
		KeyID:                  vnextReaderActivationGoldenHex32(t, keyHex),
		RequestDigest:          digest,
		Signature:              signature,
	}
}

func vnextReaderActivationGoldenProof(
	t *testing.T,
	spec vnextReaderActivationOperationSpec,
	authority vnextReaderActivationAuthorityEnvelope,
) vnextReaderActivationAuthorityProof {
	t.Helper()
	receipt, err := vnextReaderActivationCanonicalAuthorityReceipt(
		spec, vnextReaderActivationGoldenPrincipal, authority)
	if err != nil {
		t.Fatalf("golden authority receipt: %v", err)
	}
	return vnextReaderActivationAuthorityProof{
		AuthenticatedSchedulerPrincipal: vnextReaderActivationGoldenPrincipal,
		SchedulerID:                     authority.SchedulerID,
		SchedulerFenceRevision:          authority.SchedulerFenceRevision,
		LeaderLeaseID:                   authority.LeaderLeaseID,
		LeaderTermID:                    authority.LeaderTermID,
		RequestDigest:                   authority.RequestDigest,
		AuthorityReceipt:                receipt,
	}
}

func TestVNextReaderActivationCrossLanguageGolden(t *testing.T) {
	fixture := vnextReaderActivationGoldenFixtureValue(t)
	activeState := vnextReaderActivationActiveState{
		CatalogState:   vnextReaderCatalogAuthorizationActive,
		LastMutationID: fixture.request.ActivationRequestID,
	}

	proposalDigest := vnextReaderActivationCanonicalProposalRequestDigest(fixture.request)
	if got := hex.EncodeToString(proposalDigest[:]); got != vnextReaderActivationGoldenProposalRequestDigest {
		t.Fatalf("proposal request digest=%s", got)
	}
	proposalPreimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationProposalSpec, fixture.proposalAuthority)
	if err != nil {
		t.Fatalf("proposal signature preimage: %v", err)
	}
	if got := sha256.Sum256(proposalPreimage); hex.EncodeToString(got[:]) !=
		vnextReaderActivationGoldenProposalPreimageSHA {
		t.Fatalf("proposal preimage SHA=%s", hex.EncodeToString(got[:]))
	}
	proposalProof := vnextReaderActivationGoldenProof(
		t, vnextReaderActivationProposalSpec, fixture.proposalAuthority)
	if got := hex.EncodeToString(proposalProof.AuthorityReceipt[:]); got != vnextReaderActivationGoldenProposalAuthorityReceipt {
		t.Fatalf("proposal authority receipt=%s", got)
	}
	proposalJSON, err := marshalVNextReaderActivationProposalRequest(
		vnextReaderActivationProposalRequest{
			Request: fixture.request, Authority: fixture.proposalAuthority,
		})
	if err != nil {
		t.Fatalf("proposal request JSON: %v", err)
	}
	if got := sha256.Sum256(proposalJSON); hex.EncodeToString(got[:]) !=
		vnextReaderActivationGoldenProposalRequestJSONSHA {
		t.Fatalf("proposal JSON SHA=%s\nJSON=%s", hex.EncodeToString(got[:]), proposalJSON)
	}
	if string(proposalJSON) != vnextReaderActivationGoldenProposalRequestJSON {
		t.Fatalf("proposal JSON differs from shared exact bytes\nwant=%s\ngot =%s",
			vnextReaderActivationGoldenProposalRequestJSON, proposalJSON)
	}
	if got := hex.EncodeToString(fixture.activation.CxldReceipt[:]); got != vnextReaderActivationGoldenStableReceipt {
		t.Fatalf("stable activation receipt=%s", got)
	}
	proposalResponse := vnextReaderActivationProposalResponse{
		RequestDigest:           proposalDigest,
		AuthorityProof:          proposalProof,
		LocalExecutorNodeID:     "executor-a",
		LocalCxldLogicalID:      "reader-cxld-a",
		LocalProcessIncarnation: fixture.localProcess,
		State:                   vnextReaderActivationPending,
		Disposition:             vnextReaderActivationProposalInstalled,
		Acquired:                fixture.request.Acquired,
		Activation:              fixture.activation,
	}
	proposalResponse.Receipt = vnextReaderActivationCanonicalProposalReceipt(proposalResponse)
	if got := hex.EncodeToString(proposalResponse.Receipt[:]); got != vnextReaderActivationGoldenProposalOuterReceipt {
		t.Fatalf("proposal outer receipt=%s", got)
	}

	commitDigest := vnextReaderActivationCanonicalCommitRequestDigest(
		fixture.request.Acquired, fixture.activation, activeState)
	if got := hex.EncodeToString(commitDigest[:]); got != vnextReaderActivationGoldenCommitRequestDigest {
		t.Fatalf("commit request digest=%s", got)
	}
	commitPreimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationCommitSpec, fixture.commitAuthority)
	if err != nil {
		t.Fatalf("commit signature preimage: %v", err)
	}
	if got := sha256.Sum256(commitPreimage); hex.EncodeToString(got[:]) !=
		vnextReaderActivationGoldenCommitPreimageSHA {
		t.Fatalf("commit preimage SHA=%s", hex.EncodeToString(got[:]))
	}
	commitProof := vnextReaderActivationGoldenProof(
		t, vnextReaderActivationCommitSpec, fixture.commitAuthority)
	if got := hex.EncodeToString(commitProof.AuthorityReceipt[:]); got != vnextReaderActivationGoldenCommitAuthorityReceipt {
		t.Fatalf("commit authority receipt=%s", got)
	}
	commitJSON, err := marshalVNextReaderActivationCommitRequest(
		vnextReaderActivationCommitRequest{
			Acquired:    fixture.request.Acquired,
			Activation:  fixture.activation,
			ActiveState: activeState,
			Authority:   fixture.commitAuthority,
		})
	if err != nil {
		t.Fatalf("commit request JSON: %v", err)
	}
	if got := sha256.Sum256(commitJSON); hex.EncodeToString(got[:]) !=
		vnextReaderActivationGoldenCommitRequestJSONSHA {
		t.Fatalf("commit JSON SHA=%s\nJSON=%s", hex.EncodeToString(got[:]), commitJSON)
	}
	commitResponse := vnextReaderActivationCommitResponse{
		RequestDigest:           commitDigest,
		AuthorityProof:          commitProof,
		LocalExecutorNodeID:     "executor-a",
		LocalCxldLogicalID:      "reader-cxld-a",
		LocalProcessIncarnation: fixture.localProcess,
		State:                   vnextReaderActivationActiveArmed,
		Disposition:             vnextReaderActivationCommitArmed,
		Acquired:                fixture.request.Acquired,
		Activation: func() vnextReaderActivationIntent {
			armed := cloneVNextReaderActivationIntent(fixture.activation)
			armed.State = vnextReaderActivationActiveArmed
			return armed
		}(),
		ActiveState: activeState,
	}
	commitResponse.Receipt = vnextReaderActivationCanonicalCommitReceipt(commitResponse)
	if got := hex.EncodeToString(commitResponse.Receipt[:]); got != vnextReaderActivationGoldenCommitOuterReceipt {
		t.Fatalf("commit outer receipt=%s", got)
	}

	statusDigest := vnextReaderActivationCanonicalStatusRequestDigest(fixture.request)
	if got := hex.EncodeToString(statusDigest[:]); got != vnextReaderActivationGoldenStatusRequestDigest {
		t.Fatalf("status request digest=%s", got)
	}
	statusPreimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		vnextReaderActivationStatusSpec, fixture.statusAuthority)
	if err != nil {
		t.Fatalf("status signature preimage: %v", err)
	}
	if got := sha256.Sum256(statusPreimage); hex.EncodeToString(got[:]) !=
		vnextReaderActivationGoldenStatusPreimageSHA {
		t.Fatalf("status preimage SHA=%s", hex.EncodeToString(got[:]))
	}
	statusProof := vnextReaderActivationGoldenProof(
		t, vnextReaderActivationStatusSpec, fixture.statusAuthority)
	if got := hex.EncodeToString(statusProof.AuthorityReceipt[:]); got != vnextReaderActivationGoldenStatusAuthorityReceipt {
		t.Fatalf("status authority receipt=%s", got)
	}
	statusJSON, err := marshalVNextReaderActivationStatusRequest(
		vnextReaderActivationStatusRequest{
			Request: fixture.request, Authority: fixture.statusAuthority,
		})
	if err != nil {
		t.Fatalf("status request JSON: %v", err)
	}
	if got := sha256.Sum256(statusJSON); hex.EncodeToString(got[:]) !=
		vnextReaderActivationGoldenStatusRequestJSONSHA {
		t.Fatalf("status JSON SHA=%s\nJSON=%s", hex.EncodeToString(got[:]), statusJSON)
	}
	statusActivation := cloneVNextReaderActivationIntent(fixture.activation)
	statusResponse := vnextReaderActivationStatusResponse{
		RequestDigest:           statusDigest,
		AuthorityProof:          statusProof,
		LocalExecutorNodeID:     "executor-a",
		LocalCxldLogicalID:      "reader-cxld-a",
		LocalProcessIncarnation: fixture.localProcess,
		State:                   vnextReaderActivationStatusPendingState,
		Acquired:                fixture.request.Acquired,
		Activation:              &statusActivation,
	}
	statusResponse.Receipt = vnextReaderActivationCanonicalStatusReceipt(statusResponse)
	if got := hex.EncodeToString(statusResponse.Receipt[:]); got != vnextReaderActivationGoldenStatusPendingOuterReceipt {
		t.Fatalf("status PENDING outer receipt=%s", got)
	}
}
