package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var errVNextReaderActivationCurrentAuthority = errors.New(
	"VNext Reader activation current Scheduler authority is invalid")

// vnextReaderActivationCurrentAuthorityConfig contains only the independently
// current Scheduler leader source and the exact authenticated URI-SAN
// bindings. It grants no Owner, DAX, runtime, CRIU, or release authority.
type vnextReaderActivationCurrentAuthorityConfig struct {
	LeaderKey            string
	ExpectedCluster      uint64
	ReadTimeout          time.Duration
	SchedulerByPrincipal map[string]string
}

// vnextReaderActivationCurrentAuthorityVerifier is deliberately distinct from
// the PREPARE, PREPARED STATUS, and IDENTIFY verifiers. It shares only their
// independently opened exact linearizable leader reader and the global
// Scheduler leader-record ABI. The supplied activation operation specification
// selects one of three frozen activation-only signature and receipt domains.
type vnextReaderActivationCurrentAuthorityVerifier struct {
	leaderKey            string
	expectedCluster      uint64
	readTimeout          time.Duration
	schedulerByPrincipal map[string]string
	reader               vnextOwnerSchedulerLeaderReader
}

func newVNextReaderActivationCurrentAuthorityVerifier(
	config vnextReaderActivationCurrentAuthorityConfig,
	reader vnextOwnerSchedulerLeaderReader,
) (*vnextReaderActivationCurrentAuthorityVerifier, error) {
	if err := validateVNextOwnerSchedulerLeaderKey(config.LeaderKey); err != nil {
		return nil, fmt.Errorf("validate Reader activation leader key: %w", err)
	}
	if config.ExpectedCluster == 0 {
		return nil, errors.New("Reader activation expected etcd cluster ID is zero")
	}
	if config.ReadTimeout <= 0 ||
		config.ReadTimeout > vnextReaderPrepareAuthorityMaxReadTimeout {
		return nil, fmt.Errorf(
			"Reader activation authority read timeout %s is outside (0,%s]",
			config.ReadTimeout, vnextReaderPrepareAuthorityMaxReadTimeout)
	}
	if vnextReaderPreparedStatusNilInterface(reader) {
		return nil, errors.New(
			"Reader activation exact linearizable leader reader is unavailable")
	}
	bindings, err := cloneVNextReaderPreparePrincipalBindings(
		config.SchedulerByPrincipal)
	if err != nil {
		return nil, err
	}
	return &vnextReaderActivationCurrentAuthorityVerifier{
		leaderKey:            cloneVNextReaderRetainedString(config.LeaderKey),
		expectedCluster:      config.ExpectedCluster,
		readTimeout:          config.ReadTimeout,
		schedulerByPrincipal: bindings,
		reader:               reader,
	}, nil
}

func (verifier *vnextReaderActivationCurrentAuthorityVerifier) VerifyVNextReaderActivationAuthority(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	spec vnextReaderActivationOperationSpec,
	requestDigest [32]byte,
	authority vnextReaderActivationAuthorityEnvelope,
) (vnextReaderActivationAuthorityProof, error) {
	var zero vnextReaderActivationAuthorityProof
	if err := validateVNextReaderActivationOperationSpec(spec); err != nil {
		return zero, fmt.Errorf("%w: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if verifier == nil || vnextReaderPreparedStatusNilInterface(verifier.reader) ||
		len(verifier.schedulerByPrincipal) == 0 {
		return zero, fmt.Errorf("%w: verifier is unavailable",
			errVNextReaderActivationCurrentAuthority)
	}
	if ctx == nil {
		return zero, fmt.Errorf("%w: context is nil",
			errVNextReaderActivationCurrentAuthority)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, fmt.Errorf("%w: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	mappedSchedulerID, bound :=
		verifier.schedulerByPrincipal[authenticatedSchedulerPrincipal]
	if !bound {
		return zero, fmt.Errorf(
			"%w: authenticated URI SAN principal is not explicitly bound",
			errVNextReaderActivationCurrentAuthority)
	}
	if err := validateVNextReaderActivationAuthorityEnvelope(spec, authority); err != nil {
		return zero, fmt.Errorf("%w: validate activation authority envelope: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if allVNextReaderZero(requestDigest[:]) ||
		authority.RequestDigest != requestDigest {
		return zero, fmt.Errorf("%w: request digest differs from the envelope",
			errVNextReaderActivationCurrentAuthority)
	}
	clusterID, err := vnextReaderActivationAuthorityClusterBits(
		authority.ClusterID)
	if err != nil || clusterID != verifier.expectedCluster {
		return zero, fmt.Errorf(
			"%w: envelope cluster differs from the pinned cluster",
			errVNextReaderActivationCurrentAuthority)
	}
	if mappedSchedulerID != authority.SchedulerID {
		return zero, fmt.Errorf(
			"%w: principal binding differs from the envelope Scheduler ID",
			errVNextReaderActivationCurrentAuthority)
	}
	preimage, err := vnextReaderActivationAuthoritySignaturePreimage(
		spec, authority)
	if err != nil {
		return zero, fmt.Errorf("%w: build activation signature preimage: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context before leader read: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}

	readCtx, cancel := context.WithTimeout(ctx, verifier.readTimeout)
	defer cancel()
	snapshot, err := verifier.reader.LinearizableGetExact(
		readCtx, verifier.leaderKey)
	if err != nil {
		return zero, fmt.Errorf(
			"%w: linearizable exact leader read failed: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf(
			"%w: linearizable exact leader read context: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	current, err := verifier.validateCurrentLeaderSnapshot(
		snapshot, mappedSchedulerID, authority)
	if err != nil {
		return zero, err
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf(
			"%w: context before activation signature verification: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if !ed25519.Verify(current.PublicKey, preimage, authority.Signature[:]) {
		return zero, fmt.Errorf(
			"%w: activation Ed25519 signature verification failed",
			errVNextReaderActivationCurrentAuthority)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf(
			"%w: context after activation signature verification: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	receipt, err := vnextReaderActivationCanonicalAuthorityReceipt(
		spec, authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return zero, fmt.Errorf("%w: derive activation authority receipt: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	return vnextReaderActivationAuthorityProof{
		AuthenticatedSchedulerPrincipal: cloneVNextReaderRetainedString(
			authenticatedSchedulerPrincipal),
		SchedulerID:            cloneVNextReaderRetainedString(current.SchedulerID),
		SchedulerFenceRevision: authority.SchedulerFenceRevision,
		LeaderLeaseID:          current.LeaseID,
		LeaderTermID:           authority.LeaderTermID,
		RequestDigest:          requestDigest,
		AuthorityReceipt:       receipt,
	}, nil
}

func vnextReaderActivationAuthorityClusterBits(value string) (uint64, error) {
	if err := validateVNextReaderPrepareClusterID(value); err != nil {
		return 0, err
	}
	clusterID, err := strconv.ParseUint(value, 16, 64)
	if err != nil || clusterID == 0 {
		return 0, errors.New(
			"Reader activation cluster ID is outside the unsigned ABI")
	}
	return clusterID, nil
}

func (verifier *vnextReaderActivationCurrentAuthorityVerifier) validateCurrentLeaderSnapshot(
	snapshot vnextOwnerSchedulerLeaderSnapshot,
	mappedSchedulerID string,
	authority vnextReaderActivationAuthorityEnvelope,
) (vnextOwnerSchedulerLeaderTerm, error) {
	var zero vnextOwnerSchedulerLeaderTerm
	if !snapshot.HeaderPresent ||
		snapshot.HeaderCluster != verifier.expectedCluster ||
		snapshot.HeaderRevision <= 0 {
		return zero, fmt.Errorf(
			"%w: exact leader response header differs from the pinned cluster",
			errVNextReaderActivationCurrentAuthority)
	}
	if snapshot.Count != 1 || len(snapshot.KVs) != 1 || snapshot.More {
		return zero, fmt.Errorf(
			"%w: exact leader read did not return exactly one KV",
			errVNextReaderActivationCurrentAuthority)
	}
	kv := snapshot.KVs[0]
	if string(kv.Key) != verifier.leaderKey {
		return zero, fmt.Errorf(
			"%w: exact leader read returned a different key",
			errVNextReaderActivationCurrentAuthority)
	}
	if kv.CreateRevision <= 0 || kv.ModRevision != kv.CreateRevision ||
		kv.Version != 1 || kv.Lease <= 0 ||
		snapshot.HeaderRevision < kv.ModRevision {
		return zero, fmt.Errorf(
			"%w: leader KV is not one immutable lease-attached current key",
			errVNextReaderActivationCurrentAuthority)
	}
	current, err := parseVNextOwnerSchedulerLeaderValue(string(kv.Value))
	if err != nil {
		return zero, fmt.Errorf(
			"%w: parse current global Scheduler leader value: %v",
			errVNextReaderActivationCurrentAuthority, err)
	}
	if current.SchedulerID != mappedSchedulerID ||
		current.SchedulerID != authority.SchedulerID ||
		current.LeaseID != uint64(kv.Lease) ||
		current.LeaseID != authority.LeaderLeaseID ||
		uint64(kv.CreateRevision) != authority.SchedulerFenceRevision ||
		current.KeyID != authority.KeyID {
		return zero, fmt.Errorf(
			"%w: current Scheduler, fence, lease, or key differs from the envelope",
			errVNextReaderActivationCurrentAuthority)
	}
	parsed := vnextOwnerSchedulerParsedAuthority{
		ClusterID:      verifier.expectedCluster,
		CreateRevision: uint64(kv.CreateRevision),
		ModRevision:    uint64(kv.ModRevision),
		LeaseID:        uint64(kv.Lease),
		LeaderValue:    string(kv.Value),
		Leader:         current,
	}
	termID := vnextOwnerSchedulerTermDigest(verifier.leaderKey, parsed)
	if termID != authority.LeaderTermID {
		return zero, fmt.Errorf(
			"%w: canonical global term differs from the envelope",
			errVNextReaderActivationCurrentAuthority)
	}
	return current, nil
}

var _ vnextReaderActivationAuthorityVerifier = (*vnextReaderActivationCurrentAuthorityVerifier)(nil)
