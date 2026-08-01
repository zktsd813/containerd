package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// The hard-cut production package has no unsigned Scheduler mutation entry
// points. These test-only shims keep lower-level allocator/lifecycle fixtures
// concise while still persisting structurally complete Scheduler proofs and a
// valid high-water binding.
func vnextOwnerTestVerifiedAuthorityForDigest(
	mutationDigest [vnextOwnerSchedulerDigestBytes]byte,
) *vnextOwnerSchedulerVerifiedAuthority {
	leaderKey := "/test/cxl-checkpoint/global-orchestrator-leader"
	seed := sha256.Sum256([]byte("cxld-vnext-owner-test-ed25519-seed-v1"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	nonce := sha256.Sum256([]byte("cxld-vnext-owner-test-scheduler-nonce-v1"))
	leaderValue, err := formatVNextOwnerSchedulerLeaderValue(
		"test-scheduler", 1, nonce, publicKey)
	if err != nil {
		panic(err)
	}
	leader, err := parseVNextOwnerSchedulerLeaderValue(leaderValue)
	if err != nil {
		panic(err)
	}
	parsed := vnextOwnerSchedulerParsedAuthority{
		ClusterID:      1,
		CreateRevision: 1,
		ModRevision:    1,
		LeaseID:        1,
		LeaderValue:    leaderValue,
		Leader:         leader,
	}
	parsed.TermID = vnextOwnerSchedulerTermDigest(leaderKey, parsed)
	copy(parsed.Signature[:], ed25519.Sign(
		privateKey,
		vnextOwnerSchedulerSignaturePreimage(parsed.TermID, mutationDigest)))
	receipt := vnextOwnerSchedulerReceipt(
		parsed.TermID, mutationDigest, parsed.Signature)
	leaderKeyDigest := sha256.Sum256([]byte(leaderKey))
	leaderValueDigest := sha256.Sum256([]byte(leaderValue))
	return &vnextOwnerSchedulerVerifiedAuthority{
		Parsed:         parsed,
		MutationDigest: mutationDigest,
		Receipt:        receipt,
		HighWater: vnextOwnerSchedulerHighWater{
			Initialized:       true,
			LeaderKeyDigest:   leaderKeyDigest,
			ClusterID:         1,
			CreateRevision:    1,
			ModRevision:       1,
			LeaseID:           1,
			LeaderValueDigest: leaderValueDigest,
			PublicKeyDigest:   leader.KeyID,
			SchedulerTermID:   parsed.TermID,
		},
	}
}

func vnextOwnerTestVerifiedAuthority(
	operation string,
	mutation interface{},
) *vnextOwnerSchedulerVerifiedAuthority {
	digest, err := vnextOwnerSchedulerMutationDigest(operation, mutation)
	if err != nil {
		panic(err)
	}
	return vnextOwnerTestVerifiedAuthorityForDigest(digest)
}

func vnextOwnerTestSchedulerAuthority(
	operation string,
	mutation interface{},
) vnextOwnerSchedulerAuthority {
	verified := vnextOwnerTestVerifiedAuthority(operation, mutation)
	return vnextOwnerSchedulerAuthority{
		ClusterID:      fmt.Sprintf("%016x", verified.Parsed.ClusterID),
		CreateRevision: verified.Parsed.CreateRevision,
		ModRevision:    verified.Parsed.ModRevision,
		LeaseID:        fmt.Sprintf("%016x", verified.Parsed.LeaseID),
		LeaderValue:    verified.Parsed.LeaderValue,
		KeyID:          hex.EncodeToString(verified.Parsed.Leader.KeyID[:]),
		TermID:         hex.EncodeToString(verified.Parsed.TermID[:]),
		Signature: base64.RawURLEncoding.EncodeToString(
			verified.Parsed.Signature[:]),
	}
}

type vnextOwnerTestSchedulerVerifier struct{}

func (vnextOwnerTestSchedulerVerifier) Prepare(
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerVerifiedAuthority, error) {
	expected := vnextOwnerTestSchedulerAuthority(operation, mutation)
	if authority != expected {
		return vnextOwnerSchedulerVerifiedAuthority{}, fmt.Errorf(
			"%w: test Scheduler authority differs from the exact mutation",
			errVNextOwnerSchedulerAuthority)
	}
	return *vnextOwnerTestVerifiedAuthority(operation, mutation), nil
}

func (vnextOwnerTestSchedulerVerifier) VerifyCurrent(
	_ context.Context,
	verified vnextOwnerSchedulerVerifiedAuthority,
) error {
	return validateVNextOwnerVerifiedSchedulerAuthority(&verified)
}

func vnextOwnerTestAuthorizeReserve(request *vnextOwnerReserveRequest) {
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationReserve, *request)
}

func vnextOwnerTestAuthorizeSetAdmission(request *vnextOwnerSetAdmissionRequest) {
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationSetAdmission, *request)
}

func vnextOwnerTestAuthorizeIssue(
	request *vnextOwnerIssueProducerCapabilityRequest,
) {
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationIssueProducerCapability, *request)
}

func vnextOwnerTestAuthorizeProducerCapabilityIssueStatusAndFence(
	request *vnextOwnerProducerCapabilityIssueStatusAndFenceRequest,
) {
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence, *request)
}

func vnextOwnerTestAuthorizeRevoke(
	request *vnextOwnerRevokeProducerCapabilityRequest,
) {
	request.SchedulerAuthority = vnextOwnerTestSchedulerAuthority(
		vnextOwnerRPCOperationRevokeProducerCapability, *request)
}

func (group *vnextOwnerGroup) reserve(
	request vnextCheckpointAllocationRequest,
) (vnextOwnerWriteGrant, error) {
	mutation := vnextOwnerReserveRequest{
		RequestID: request.RequestID, CheckpointID: request.CheckpointID,
		ProducerID: request.ProducerID, OwnerID: request.OwnerID,
		OwnerEpoch: request.OwnerEpoch, MaxExtents: request.MaxExtents,
		Contents: make([]vnextOwnerReserveContent, len(request.Contents)),
	}
	for index, content := range request.Contents {
		kind, ok := vnextOwnerServiceKindFromInternal(content.Kind)
		if !ok {
			kind = vnextOwnerServiceContentKind(content.Kind)
		}
		mutation.Contents[index] = vnextOwnerReserveContent{
			Kind: kind, ObjectID: content.ObjectID,
			ByteLength: content.ByteLength, CapacityPages: content.PageCount,
		}
	}
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationReserve, mutation)
	return group.reserveWithScheduler(request, authority)
}

func (group *vnextOwnerGroup) commit(grant vnextOwnerWriteGrant) error {
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationCommit,
		vnextOwnerOperationIdentity{
			RequestID:          grant.RequestID,
			CheckpointID:       grant.CheckpointID,
			ProducerID:         grant.ProducerID,
			OwnerID:            grant.OwnerID,
			OwnerEpoch:         grant.OwnerEpoch,
			AllocationRecordID: grant.AllocationRecordID,
		})
	return group.commitWithScheduler(grant, authority)
}

func (group *vnextOwnerGroup) abort(grant vnextOwnerWriteGrant) error {
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationAbort,
		vnextOwnerOperationIdentity{
			RequestID:          grant.RequestID,
			CheckpointID:       grant.CheckpointID,
			ProducerID:         grant.ProducerID,
			OwnerID:            grant.OwnerID,
			OwnerEpoch:         grant.OwnerEpoch,
			AllocationRecordID: grant.AllocationRecordID,
		})
	return group.abortWithScheduler(grant, authority)
}

func (group *vnextOwnerGroup) setAdmission(
	request vnextOwnerAdmissionTransitionRequest,
) (vnextOwnerAdmissionTransitionResult, error) {
	mutation := vnextOwnerSetAdmissionRequest{
		RequestID: request.RequestID, OwnerID: request.OwnerID,
		OwnerEpoch: request.OwnerEpoch, From: request.From,
		Target: request.Target, ExpectedSequence: request.ExpectedSequence,
	}
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationSetAdmission, mutation)
	return group.setAdmissionWithScheduler(request, authority)
}

func (service *vnextOwnerService) reserve(
	request vnextOwnerReserveRequest,
) (vnextOwnerReserveResponse, error) {
	const operation = "reserve"
	service.mu.Lock()
	defer service.mu.Unlock()
	internal, err := request.internal()
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceInvalidRequest, err.Error(), err)
	}
	grant, err := service.group.reserve(internal)
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	response, err := service.reserveResponse(internal, grant)
	if err != nil {
		return vnextOwnerReserveResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceUnavailable,
			"reserved placement cannot be represented", err)
	}
	service.group.mu.Lock()
	response.SchedulerProof = service.group.journal.Transactions[response.Operation.AllocationRecordID].SchedulerReserveProof
	service.group.mu.Unlock()
	return response, nil
}

func (service *vnextOwnerService) setAdmission(
	request vnextOwnerSetAdmissionRequest,
) (vnextOwnerSetAdmissionResponse, error) {
	const operation = "set-admission"
	service.mu.Lock()
	defer service.mu.Unlock()
	internal := vnextOwnerAdmissionTransitionRequest{
		RequestID: request.RequestID, OwnerID: request.OwnerID,
		OwnerEpoch: request.OwnerEpoch, From: request.From,
		Target: request.Target, ExpectedSequence: request.ExpectedSequence,
	}
	if err := validateVNextOwnerAdmissionTransitionRequest(internal); err != nil {
		return vnextOwnerSetAdmissionResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServiceInvalidRequest, err.Error(), err)
	}
	result, err := service.group.setAdmission(internal)
	if err != nil {
		return vnextOwnerSetAdmissionResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	record := result.Record
	return vnextOwnerSetAdmissionResponse{
		RequestID: record.RequestID, RequestDigest: record.RequestDigest,
		OwnerID: request.OwnerID, OwnerEpoch: request.OwnerEpoch,
		From: record.From, Target: record.Target,
		ExpectedSequence: record.ExpectedSequence,
		ResultSequence:   record.ResultSequence, Replayed: result.Replayed,
		SchedulerProof: record.SchedulerProof,
	}, nil
}

func (service *vnextOwnerService) issueProducerCapability(
	request vnextOwnerIssueProducerCapabilityRequest,
	caller vnextOwnerCallerContext,
) (vnextOwnerIssueProducerCapabilityResponse, error) {
	const operation = "issue-producer-capability"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerScheduler {
		return vnextOwnerIssueProducerCapabilityResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"only an authenticated Scheduler may issue Producer capabilities", err)
	}
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationIssueProducerCapability, request)
	request.SchedulerReceipt = authority.Receipt
	now, err := service.capabilityNowUnixNano(operation)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, err
	}
	record, replayed, err := service.group.issueProducerCapabilityWithScheduler(
		request, caller.Principal, now, authority)
	if err != nil {
		return vnextOwnerIssueProducerCapabilityResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	return vnextOwnerIssueProducerCapabilityResponse{
		RequestID: request.RequestID,
		Capability: vnextProducerCapabilityProof{
			CapabilityID: record.CapabilityID, Token: request.Nonce,
		},
		Operation: request.Operation, ProducerPrincipal: record.ProducerPrincipal,
		AllowedOperations: record.AllowedOperations,
		IssuedAtUnixNano:  record.IssuedAtUnixNano,
		ExpiresAtUnixNano: record.ExpiresAtUnixNano, Replayed: replayed,
		SchedulerProof: record.IssueSchedulerProof,
	}, nil
}

func (service *vnextOwnerService) revokeProducerCapability(
	request vnextOwnerRevokeProducerCapabilityRequest,
	caller vnextOwnerCallerContext,
) (vnextOwnerRevokeProducerCapabilityResponse, error) {
	const operation = "revoke-producer-capability"
	service.mu.Lock()
	defer service.mu.Unlock()
	if err := caller.validate(); err != nil || caller.Role != vnextOwnerCallerScheduler {
		return vnextOwnerRevokeProducerCapabilityResponse{}, vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"only an authenticated Scheduler may revoke Producer capabilities", err)
	}
	authority := vnextOwnerTestVerifiedAuthority(
		vnextOwnerRPCOperationRevokeProducerCapability, request)
	request.SchedulerReceipt = authority.Receipt
	now, err := service.capabilityNowUnixNano(operation)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, err
	}
	record, replayed, err := service.group.revokeProducerCapabilityWithScheduler(
		request, caller.Principal, now, authority)
	if err != nil {
		return vnextOwnerRevokeProducerCapabilityResponse{}, vnextOwnerServiceWrap(operation, err)
	}
	return vnextOwnerRevokeProducerCapabilityResponse{
		RequestID: request.RequestID, CapabilityID: record.CapabilityID,
		Operation: request.Operation, RevokedAtUnixNano: record.RevokedAtUnixNano,
		Replayed: replayed, SchedulerProof: record.RevokeSchedulerProof,
	}, nil
}

func (service *vnextOwnerService) commit(identity vnextOwnerOperationIdentity) error {
	return service.testSchedulerLifecycle("commit", identity, service.group.commit)
}

func (service *vnextOwnerService) abort(identity vnextOwnerOperationIdentity) error {
	return service.testSchedulerLifecycle("abort", identity, service.group.abort)
}

func (service *vnextOwnerService) testSchedulerLifecycle(
	operation string,
	identity vnextOwnerOperationIdentity,
	apply func(vnextOwnerWriteGrant) error,
) error {
	service.mu.Lock()
	defer service.mu.Unlock()
	terminal := vnextOwnerCommitted
	if operation == "abort" {
		terminal = vnextOwnerAborted
	}
	grant, _, err := service.resolveOperation(
		operation, identity, vnextOwnerGranted, true, terminal)
	if err != nil {
		return err
	}
	if err := apply(grant); err != nil {
		return vnextOwnerServiceWrap(operation, err)
	}
	return nil
}
