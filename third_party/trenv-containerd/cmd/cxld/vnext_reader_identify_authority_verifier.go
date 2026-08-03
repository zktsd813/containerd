package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"time"
)

var errVNextReaderIdentifyCurrentAuthority = errors.New(
	"VNext Reader IDENTIFY current Scheduler authority is invalid")

type vnextReaderIdentifyCurrentAuthorityConfig struct {
	LeaderKey            string
	ExpectedCluster      uint64
	ReadTimeout          time.Duration
	SchedulerByPrincipal map[string]string
}

// vnextReaderIdentifyCurrentAuthorityVerifier is intentionally a distinct
// verifier from PREPARE and STATUS. It shares only the independent linearizable
// etcd reader and the global Scheduler leader-record ABI. Its signature and
// receipt domains are IDENTIFY-only.
type vnextReaderIdentifyCurrentAuthorityVerifier struct {
	leaderKey            string
	expectedCluster      uint64
	readTimeout          time.Duration
	schedulerByPrincipal map[string]string
	reader               vnextOwnerSchedulerLeaderReader
}

func newVNextReaderIdentifyCurrentAuthorityVerifier(
	config vnextReaderIdentifyCurrentAuthorityConfig,
	reader vnextOwnerSchedulerLeaderReader,
) (*vnextReaderIdentifyCurrentAuthorityVerifier, error) {
	if err := validateVNextOwnerSchedulerLeaderKey(config.LeaderKey); err != nil {
		return nil, fmt.Errorf("validate Reader IDENTIFY leader key: %w", err)
	}
	if config.ExpectedCluster == 0 {
		return nil, errors.New("Reader IDENTIFY expected etcd cluster ID is zero")
	}
	if config.ReadTimeout <= 0 ||
		config.ReadTimeout > vnextReaderPrepareAuthorityMaxReadTimeout {
		return nil, fmt.Errorf(
			"Reader IDENTIFY authority read timeout %s is outside (0,%s]",
			config.ReadTimeout, vnextReaderPrepareAuthorityMaxReadTimeout)
	}
	if vnextReaderPreparedStatusNilInterface(reader) {
		return nil, errors.New(
			"Reader IDENTIFY exact linearizable leader reader is unavailable")
	}
	bindings, err := cloneVNextReaderPreparePrincipalBindings(
		config.SchedulerByPrincipal)
	if err != nil {
		return nil, err
	}
	return &vnextReaderIdentifyCurrentAuthorityVerifier{
		leaderKey:            cloneVNextReaderRetainedString(config.LeaderKey),
		expectedCluster:      config.ExpectedCluster,
		readTimeout:          config.ReadTimeout,
		schedulerByPrincipal: bindings,
		reader:               reader,
	}, nil
}

func (verifier *vnextReaderIdentifyCurrentAuthorityVerifier) VerifyVNextReaderIdentifyAuthority(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	requestDigest [32]byte,
	authority vnextReaderIdentifyAuthorityEnvelope,
) (vnextReaderIdentifyAuthorityProof, error) {
	var zero vnextReaderIdentifyAuthorityProof
	if verifier == nil || vnextReaderPreparedStatusNilInterface(verifier.reader) ||
		len(verifier.schedulerByPrincipal) == 0 {
		return zero, fmt.Errorf("%w: verifier is unavailable",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if ctx == nil {
		return zero, fmt.Errorf("%w: context is nil",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, fmt.Errorf("%w: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	mappedSchedulerID, bound :=
		verifier.schedulerByPrincipal[authenticatedSchedulerPrincipal]
	if !bound {
		return zero, fmt.Errorf(
			"%w: authenticated URI SAN principal is not explicitly bound",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if err := validateVNextReaderIdentifyAuthorityEnvelope(authority); err != nil {
		return zero, fmt.Errorf("%w: validate IDENTIFY authority envelope: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	if allVNextReaderZero(requestDigest[:]) ||
		authority.RequestDigest != requestDigest {
		return zero, fmt.Errorf("%w: request digest differs from the envelope",
			errVNextReaderIdentifyCurrentAuthority)
	}
	clusterID, err := vnextReaderIdentifyAuthorityClusterBits(authority.ClusterID)
	if err != nil || clusterID != verifier.expectedCluster {
		return zero, fmt.Errorf(
			"%w: envelope cluster differs from the pinned cluster",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if mappedSchedulerID != authority.SchedulerID {
		return zero, fmt.Errorf(
			"%w: principal binding differs from the envelope Scheduler ID",
			errVNextReaderIdentifyCurrentAuthority)
	}
	preimage, err := vnextReaderIdentifyAuthoritySignaturePreimage(authority)
	if err != nil {
		return zero, fmt.Errorf("%w: build IDENTIFY signature preimage: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context before leader read: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	readCtx, cancel := context.WithTimeout(ctx, verifier.readTimeout)
	defer cancel()
	snapshot, err := verifier.reader.LinearizableGetExact(
		readCtx, verifier.leaderKey)
	if err != nil {
		return zero, fmt.Errorf("%w: linearizable exact leader read failed: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf("%w: linearizable exact leader read context: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	current, err := verifier.validateCurrentLeaderSnapshot(
		snapshot, mappedSchedulerID, authority)
	if err != nil {
		return zero, err
	}
	if !ed25519.Verify(current.PublicKey, preimage, authority.Signature[:]) {
		return zero, fmt.Errorf("%w: IDENTIFY Ed25519 signature verification failed",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context after IDENTIFY signature verification: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	receipt, err := vnextReaderIdentifyCanonicalAuthorityReceipt(
		authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return zero, fmt.Errorf("%w: derive IDENTIFY authority receipt: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	return vnextReaderIdentifyAuthorityProof{
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

func vnextReaderIdentifyAuthorityClusterBits(value string) (uint64, error) {
	if err := validateVNextReaderPrepareClusterID(value); err != nil {
		return 0, err
	}
	clusterID, err := strconv.ParseUint(value, 16, 64)
	if err != nil || clusterID == 0 {
		return 0, errors.New("Reader IDENTIFY cluster ID is outside the unsigned ABI")
	}
	return clusterID, nil
}

func (verifier *vnextReaderIdentifyCurrentAuthorityVerifier) validateCurrentLeaderSnapshot(
	snapshot vnextOwnerSchedulerLeaderSnapshot,
	mappedSchedulerID string,
	authority vnextReaderIdentifyAuthorityEnvelope,
) (vnextOwnerSchedulerLeaderTerm, error) {
	var zero vnextOwnerSchedulerLeaderTerm
	if !snapshot.HeaderPresent ||
		snapshot.HeaderCluster != verifier.expectedCluster ||
		snapshot.HeaderRevision <= 0 {
		return zero, fmt.Errorf(
			"%w: exact leader response header differs from the pinned cluster",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if snapshot.Count != 1 || len(snapshot.KVs) != 1 || snapshot.More {
		return zero, fmt.Errorf(
			"%w: exact leader read did not return exactly one KV",
			errVNextReaderIdentifyCurrentAuthority)
	}
	kv := snapshot.KVs[0]
	if string(kv.Key) != verifier.leaderKey {
		return zero, fmt.Errorf("%w: exact leader read returned a different key",
			errVNextReaderIdentifyCurrentAuthority)
	}
	if kv.CreateRevision <= 0 || kv.ModRevision != kv.CreateRevision ||
		kv.Version != 1 || kv.Lease <= 0 ||
		snapshot.HeaderRevision < kv.ModRevision {
		return zero, fmt.Errorf(
			"%w: leader KV is not one immutable lease-attached current key",
			errVNextReaderIdentifyCurrentAuthority)
	}
	current, err := parseVNextOwnerSchedulerLeaderValue(string(kv.Value))
	if err != nil {
		return zero, fmt.Errorf("%w: parse current global Scheduler leader value: %v",
			errVNextReaderIdentifyCurrentAuthority, err)
	}
	if current.SchedulerID != mappedSchedulerID ||
		current.SchedulerID != authority.SchedulerID ||
		current.LeaseID != uint64(kv.Lease) ||
		current.LeaseID != authority.LeaderLeaseID ||
		uint64(kv.CreateRevision) != authority.SchedulerFenceRevision ||
		current.KeyID != authority.KeyID {
		return zero, fmt.Errorf(
			"%w: current Scheduler, fence, lease, or key differs from the envelope",
			errVNextReaderIdentifyCurrentAuthority)
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
			errVNextReaderIdentifyCurrentAuthority)
	}
	return current, nil
}

var _ vnextReaderIdentifyAuthorityVerifier = (*vnextReaderIdentifyCurrentAuthorityVerifier)(nil)
