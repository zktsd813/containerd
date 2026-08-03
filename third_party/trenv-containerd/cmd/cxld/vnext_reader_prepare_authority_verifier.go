package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	vnextReaderPrepareAuthorityMaxPrincipals = 64
	// Charge every retained binding for map buckets, two strings, and allocator
	// overhead in addition to its exact UTF-8 bytes. The byte bound is
	// independent of the entry-count bound and deliberately conservative.
	vnextReaderPrepareAuthorityPrincipalFixedChargeBytes = 4 << 10
	vnextReaderPrepareAuthorityMaxPrincipalRetainedBytes = 512 << 10
	vnextReaderPrepareAuthorityMaxReadTimeout            = 30 * time.Second
)

var errVNextReaderPrepareCurrentAuthority = errors.New(
	"VNext Reader PREPARE current Scheduler authority is invalid")

// vnextReaderPrepareCurrentAuthorityConfig contains no endpoint, TLS, Owner,
// DAX, or runtime configuration. A future main/runtime layer must separately
// construct the already-existing exact linearizable leader reader.
type vnextReaderPrepareCurrentAuthorityConfig struct {
	LeaderKey       string
	ExpectedCluster uint64
	ReadTimeout     time.Duration
	// SchedulerByPrincipal is an exact authenticated URI-SAN allowlist and
	// the security boundary between the transport identity and a Scheduler
	// ID. This verifier does not extract or authenticate a certificate
	// identity itself; a future transport must pass the already-authenticated
	// exact URI SAN.
	SchedulerByPrincipal map[string]string
}

// vnextReaderPrepareCurrentAuthorityVerifier implements only the Reader
// PREPARE authority interface. The reused reader/snapshot and global term ABI
// are low-level Scheduler-leader identities; no Owner RPC role, operation,
// proof, high-water state, ALPN, or mutation permission is accepted here.
type vnextReaderPrepareCurrentAuthorityVerifier struct {
	leaderKey            string
	expectedCluster      uint64
	readTimeout          time.Duration
	schedulerByPrincipal map[string]string
	reader               vnextOwnerSchedulerLeaderReader
}

func newVNextReaderPrepareCurrentAuthorityVerifier(
	config vnextReaderPrepareCurrentAuthorityConfig,
	reader vnextOwnerSchedulerLeaderReader,
) (*vnextReaderPrepareCurrentAuthorityVerifier, error) {
	if err := validateVNextOwnerSchedulerLeaderKey(config.LeaderKey); err != nil {
		return nil, fmt.Errorf("validate Reader PREPARE leader key: %w", err)
	}
	if config.ExpectedCluster == 0 {
		return nil, errors.New("Reader PREPARE expected etcd cluster ID is zero")
	}
	if config.ReadTimeout <= 0 ||
		config.ReadTimeout > vnextReaderPrepareAuthorityMaxReadTimeout {
		return nil, fmt.Errorf(
			"Reader PREPARE authority read timeout %s is outside (0,%s]",
			config.ReadTimeout, vnextReaderPrepareAuthorityMaxReadTimeout)
	}
	if reader == nil {
		return nil, errors.New(
			"Reader PREPARE exact linearizable leader reader is unavailable")
	}
	bindings, err := cloneVNextReaderPreparePrincipalBindings(
		config.SchedulerByPrincipal)
	if err != nil {
		return nil, err
	}
	return &vnextReaderPrepareCurrentAuthorityVerifier{
		leaderKey:            cloneVNextReaderRetainedString(config.LeaderKey),
		expectedCluster:      config.ExpectedCluster,
		readTimeout:          config.ReadTimeout,
		schedulerByPrincipal: bindings,
		reader:               reader,
	}, nil
}

func cloneVNextReaderPreparePrincipalBindings(
	bindings map[string]string,
) (map[string]string, error) {
	if len(bindings) == 0 || len(bindings) > vnextReaderPrepareAuthorityMaxPrincipals {
		return nil, fmt.Errorf(
			"Reader PREPARE principal binding count %d is outside 1..%d",
			len(bindings), vnextReaderPrepareAuthorityMaxPrincipals)
	}
	retainedBytes := uint64(0)
	cloned := make(map[string]string, len(bindings))
	for principal, schedulerID := range bindings {
		if err := validateVNextReaderPreparePrincipalURI(principal); err != nil {
			return nil, err
		}
		if err := validateVNextReaderIdentity(
			"Reader PREPARE principal Scheduler ID", schedulerID); err != nil {
			return nil, err
		}
		charge := uint64(vnextReaderPrepareAuthorityPrincipalFixedChargeBytes) +
			uint64(len(principal)) + uint64(len(schedulerID))
		if retainedBytes > vnextReaderPrepareAuthorityMaxPrincipalRetainedBytes ||
			charge > vnextReaderPrepareAuthorityMaxPrincipalRetainedBytes-retainedBytes {
			return nil, fmt.Errorf(
				"Reader PREPARE principal bindings exceed the %d-byte retained budget",
				vnextReaderPrepareAuthorityMaxPrincipalRetainedBytes)
		}
		retainedBytes += charge
		clonedPrincipal := cloneVNextReaderRetainedString(principal)
		cloned[clonedPrincipal] = cloneVNextReaderRetainedString(schedulerID)
	}
	return cloned, nil
}

func validateVNextReaderPreparePrincipalURI(value string) error {
	if err := validateVNextReaderIdentity(
		"authenticated Reader PREPARE Scheduler URI SAN", value); err != nil {
		return err
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New(
				"authenticated Reader PREPARE Scheduler URI SAN contains a control character")
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != value || strings.TrimSpace(value) != value {
		return fmt.Errorf(
			"authenticated Reader PREPARE Scheduler URI SAN %q is not canonical",
			value)
	}
	return nil
}

func (verifier *vnextReaderPrepareCurrentAuthorityVerifier) VerifyVNextReaderPrepareAuthority(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	requestDigest [32]byte,
	authority vnextReaderPrepareAuthorityEnvelope,
) (vnextReaderPrepareAuthorityProof, error) {
	var zero vnextReaderPrepareAuthorityProof
	if verifier == nil || verifier.reader == nil ||
		len(verifier.schedulerByPrincipal) == 0 {
		return zero, fmt.Errorf("%w: verifier is unavailable",
			errVNextReaderPrepareCurrentAuthority)
	}
	if ctx == nil {
		return zero, fmt.Errorf("%w: context is nil",
			errVNextReaderPrepareCurrentAuthority)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	if err := validateVNextReaderPreparePrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, fmt.Errorf("%w: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	mappedSchedulerID, bound := verifier.schedulerByPrincipal[authenticatedSchedulerPrincipal]
	if !bound {
		return zero, fmt.Errorf(
			"%w: authenticated URI SAN principal is not explicitly bound",
			errVNextReaderPrepareCurrentAuthority)
	}
	if err := validateVNextReaderPrepareAuthorityEnvelope(authority); err != nil {
		return zero, fmt.Errorf("%w: validate Reader authority envelope: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	if allVNextReaderZero(requestDigest[:]) ||
		authority.RequestDigest != requestDigest {
		return zero, fmt.Errorf("%w: request digest differs from the envelope",
			errVNextReaderPrepareCurrentAuthority)
	}
	clusterID, err := vnextReaderPrepareAuthorityClusterBits(authority.ClusterID)
	if err != nil || clusterID != verifier.expectedCluster {
		return zero, fmt.Errorf("%w: envelope cluster differs from the pinned cluster",
			errVNextReaderPrepareCurrentAuthority)
	}
	if mappedSchedulerID != authority.SchedulerID {
		return zero, fmt.Errorf(
			"%w: principal binding differs from the envelope Scheduler ID",
			errVNextReaderPrepareCurrentAuthority)
	}
	preimage, err := vnextReaderPrepareAuthoritySignaturePreimage(authority)
	if err != nil {
		return zero, fmt.Errorf("%w: build Reader signature preimage: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context before leader read: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}

	readCtx, cancel := context.WithTimeout(ctx, verifier.readTimeout)
	defer cancel()
	snapshot, err := verifier.reader.LinearizableGetExact(readCtx, verifier.leaderKey)
	if err != nil {
		return zero, fmt.Errorf("%w: linearizable exact leader read failed: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf("%w: linearizable exact leader read context: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	current, err := verifier.validateCurrentLeaderSnapshot(
		snapshot, mappedSchedulerID, authority)
	if err != nil {
		return zero, err
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context before Reader signature verification: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	if !ed25519.Verify(current.PublicKey, preimage, authority.Signature[:]) {
		return zero, fmt.Errorf("%w: Reader Ed25519 signature verification failed",
			errVNextReaderPrepareCurrentAuthority)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf("%w: context after Reader signature verification: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	receipt, err := vnextReaderPrepareCanonicalAuthorityReceipt(
		authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return zero, fmt.Errorf("%w: derive Reader authority receipt: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	return vnextReaderPrepareAuthorityProof{
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

func vnextReaderPrepareAuthorityClusterBits(value string) (uint64, error) {
	if err := validateVNextReaderPrepareClusterID(value); err != nil {
		return 0, err
	}
	clusterID, err := strconv.ParseUint(value, 16, 64)
	if err != nil || clusterID == 0 {
		return 0, errors.New("Reader PREPARE cluster ID is outside the unsigned ABI")
	}
	return clusterID, nil
}

func (verifier *vnextReaderPrepareCurrentAuthorityVerifier) validateCurrentLeaderSnapshot(
	snapshot vnextOwnerSchedulerLeaderSnapshot,
	mappedSchedulerID string,
	authority vnextReaderPrepareAuthorityEnvelope,
) (vnextOwnerSchedulerLeaderTerm, error) {
	var zero vnextOwnerSchedulerLeaderTerm
	if !snapshot.HeaderPresent ||
		snapshot.HeaderCluster != verifier.expectedCluster ||
		snapshot.HeaderRevision <= 0 {
		return zero, fmt.Errorf(
			"%w: exact leader response header differs from the pinned cluster",
			errVNextReaderPrepareCurrentAuthority)
	}
	if snapshot.Count != 1 || len(snapshot.KVs) != 1 || snapshot.More {
		return zero, fmt.Errorf(
			"%w: exact leader read did not return exactly one KV",
			errVNextReaderPrepareCurrentAuthority)
	}
	kv := snapshot.KVs[0]
	if string(kv.Key) != verifier.leaderKey {
		return zero, fmt.Errorf("%w: exact leader read returned a different key",
			errVNextReaderPrepareCurrentAuthority)
	}
	if kv.CreateRevision <= 0 ||
		kv.ModRevision != kv.CreateRevision || kv.Version != 1 ||
		kv.Lease <= 0 || snapshot.HeaderRevision < kv.ModRevision {
		return zero, fmt.Errorf(
			"%w: leader KV is not one immutable lease-attached current key",
			errVNextReaderPrepareCurrentAuthority)
	}
	current, err := parseVNextOwnerSchedulerLeaderValue(string(kv.Value))
	if err != nil {
		return zero, fmt.Errorf("%w: parse current global Scheduler leader value: %v",
			errVNextReaderPrepareCurrentAuthority, err)
	}
	if current.SchedulerID != mappedSchedulerID ||
		current.SchedulerID != authority.SchedulerID ||
		current.LeaseID != uint64(kv.Lease) ||
		current.LeaseID != authority.LeaderLeaseID ||
		uint64(kv.CreateRevision) != authority.SchedulerFenceRevision ||
		current.KeyID != authority.KeyID {
		return zero, fmt.Errorf(
			"%w: current Scheduler, fence, lease, or key differs from the envelope",
			errVNextReaderPrepareCurrentAuthority)
	}
	// This is the existing global Scheduler term ABI shared with Scala's
	// SchedulerCxlCheckpointAuthority.termDigest. Reusing its identity does not
	// grant any Owner operation or accept an Owner authority envelope.
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
		return zero, fmt.Errorf("%w: canonical global term differs from the envelope",
			errVNextReaderPrepareCurrentAuthority)
	}
	return current, nil
}

var _ vnextReaderPrepareAuthorityVerifier = (*vnextReaderPrepareCurrentAuthorityVerifier)(nil)
