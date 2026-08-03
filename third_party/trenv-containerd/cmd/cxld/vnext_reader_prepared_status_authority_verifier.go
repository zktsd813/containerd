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
	vnextReaderPreparedStatusAuthorityMaxPrincipals             = 64
	vnextReaderPreparedStatusAuthorityPrincipalFixedChargeBytes = 4 << 10
	vnextReaderPreparedStatusAuthorityMaxPrincipalRetainedBytes = 512 << 10
	vnextReaderPreparedStatusAuthorityMaxReadTimeout            = 30 * time.Second
)

var errVNextReaderPreparedStatusCurrentAuthority = errors.New(
	"VNext Reader STATUS_AND_FENCE current Scheduler authority is invalid")

// vnextReaderPreparedStatusCurrentAuthorityConfig contains only the current
// global Scheduler leader source and exact authenticated URI bindings. It has
// no Owner role, DAX, runtime, PREPARE, or lifecycle configuration.
type vnextReaderPreparedStatusCurrentAuthorityConfig struct {
	LeaderKey            string
	ExpectedCluster      uint64
	ReadTimeout          time.Duration
	SchedulerByPrincipal map[string]string
}

type vnextReaderPreparedStatusCurrentAuthorityVerifier struct {
	leaderKey            string
	expectedCluster      uint64
	readTimeout          time.Duration
	schedulerByPrincipal map[string]string
	reader               vnextOwnerSchedulerLeaderReader
}

func newVNextReaderPreparedStatusCurrentAuthorityVerifier(
	config vnextReaderPreparedStatusCurrentAuthorityConfig,
	reader vnextOwnerSchedulerLeaderReader,
) (*vnextReaderPreparedStatusCurrentAuthorityVerifier, error) {
	if err := validateVNextOwnerSchedulerLeaderKey(config.LeaderKey); err != nil {
		return nil, fmt.Errorf("validate STATUS_AND_FENCE leader key: %w", err)
	}
	if config.ExpectedCluster == 0 {
		return nil, errors.New("STATUS_AND_FENCE expected etcd cluster ID is zero")
	}
	if config.ReadTimeout <= 0 ||
		config.ReadTimeout > vnextReaderPreparedStatusAuthorityMaxReadTimeout {
		return nil, fmt.Errorf(
			"STATUS_AND_FENCE authority read timeout %s is outside (0,%s]",
			config.ReadTimeout,
			vnextReaderPreparedStatusAuthorityMaxReadTimeout)
	}
	if vnextReaderPreparedStatusNilInterface(reader) {
		return nil, errors.New(
			"STATUS_AND_FENCE exact linearizable leader reader is unavailable")
	}
	bindings, err := cloneVNextReaderPreparedStatusPrincipalBindings(
		config.SchedulerByPrincipal)
	if err != nil {
		return nil, err
	}
	return &vnextReaderPreparedStatusCurrentAuthorityVerifier{
		leaderKey:            cloneVNextReaderRetainedString(config.LeaderKey),
		expectedCluster:      config.ExpectedCluster,
		readTimeout:          config.ReadTimeout,
		schedulerByPrincipal: bindings,
		reader:               reader,
	}, nil
}

func cloneVNextReaderPreparedStatusPrincipalBindings(
	bindings map[string]string,
) (map[string]string, error) {
	if len(bindings) == 0 ||
		len(bindings) > vnextReaderPreparedStatusAuthorityMaxPrincipals {
		return nil, fmt.Errorf(
			"STATUS_AND_FENCE principal binding count %d is outside 1..%d",
			len(bindings), vnextReaderPreparedStatusAuthorityMaxPrincipals)
	}
	retainedBytes := uint64(0)
	cloned := make(map[string]string, len(bindings))
	for principal, schedulerID := range bindings {
		if err := validateVNextReaderPreparedStatusPrincipalURI(principal); err != nil {
			return nil, err
		}
		if err := validateVNextReaderIdentity(
			"STATUS_AND_FENCE principal Scheduler ID", schedulerID); err != nil {
			return nil, err
		}
		charge := uint64(
			vnextReaderPreparedStatusAuthorityPrincipalFixedChargeBytes) +
			uint64(len(principal)) + uint64(len(schedulerID))
		if retainedBytes >
			vnextReaderPreparedStatusAuthorityMaxPrincipalRetainedBytes ||
			charge >
				vnextReaderPreparedStatusAuthorityMaxPrincipalRetainedBytes-retainedBytes {
			return nil, fmt.Errorf(
				"STATUS_AND_FENCE principal bindings exceed the %d-byte retained budget",
				vnextReaderPreparedStatusAuthorityMaxPrincipalRetainedBytes)
		}
		retainedBytes += charge
		clonedPrincipal := cloneVNextReaderRetainedString(principal)
		cloned[clonedPrincipal] = cloneVNextReaderRetainedString(schedulerID)
	}
	return cloned, nil
}

func validateVNextReaderPreparedStatusPrincipalURI(value string) error {
	if err := validateVNextReaderIdentity(
		"authenticated STATUS_AND_FENCE Scheduler URI SAN", value); err != nil {
		return err
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return errors.New(
				"authenticated STATUS_AND_FENCE Scheduler URI SAN contains a control character")
		}
	}
	parsed, err := url.Parse(value)
	if err != nil || !parsed.IsAbs() || parsed.Scheme == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.String() != value || strings.TrimSpace(value) != value {
		return fmt.Errorf(
			"authenticated STATUS_AND_FENCE Scheduler URI SAN %q is not canonical",
			value)
	}
	return nil
}

func (verifier *vnextReaderPreparedStatusCurrentAuthorityVerifier) VerifyVNextReaderPreparedStatusAuthority(
	ctx context.Context,
	authenticatedSchedulerPrincipal string,
	requestDigest [32]byte,
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) (vnextReaderPreparedStatusAuthorityProof, error) {
	var zero vnextReaderPreparedStatusAuthorityProof
	if verifier == nil || vnextReaderPreparedStatusNilInterface(verifier.reader) ||
		len(verifier.schedulerByPrincipal) == 0 {
		return zero, fmt.Errorf("%w: verifier is unavailable",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if ctx == nil {
		return zero, fmt.Errorf("%w: context is nil",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	if err := validateVNextReaderPreparedStatusPrincipalURI(
		authenticatedSchedulerPrincipal); err != nil {
		return zero, fmt.Errorf("%w: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	mappedSchedulerID, bound :=
		verifier.schedulerByPrincipal[authenticatedSchedulerPrincipal]
	if !bound {
		return zero, fmt.Errorf(
			"%w: authenticated URI SAN principal is not explicitly bound",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if err := validateVNextReaderPreparedStatusAuthorityEnvelope(
		authority); err != nil {
		return zero, fmt.Errorf("%w: validate authority envelope: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	if allVNextReaderZero(requestDigest[:]) ||
		authority.RequestDigest != requestDigest {
		return zero, fmt.Errorf("%w: request digest differs from the envelope",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	clusterID, err := vnextReaderPreparedStatusAuthorityClusterBits(
		authority.ClusterID)
	if err != nil || clusterID != verifier.expectedCluster {
		return zero, fmt.Errorf(
			"%w: envelope cluster differs from the pinned cluster",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if mappedSchedulerID != authority.SchedulerID {
		return zero, fmt.Errorf(
			"%w: principal binding differs from the envelope Scheduler ID",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	preimage, err := vnextReaderPreparedStatusAuthoritySignaturePreimage(authority)
	if err != nil {
		return zero, fmt.Errorf("%w: build signature preimage: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	if err := ctx.Err(); err != nil {
		return zero, fmt.Errorf("%w: caller context before leader read: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}

	readCtx, cancel := context.WithTimeout(ctx, verifier.readTimeout)
	defer cancel()
	snapshot, err := verifier.reader.LinearizableGetExact(
		readCtx, verifier.leaderKey)
	if err != nil {
		return zero, fmt.Errorf(
			"%w: linearizable exact leader read failed: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf(
			"%w: linearizable exact leader read context: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	current, err := verifier.validateCurrentLeaderSnapshot(
		snapshot, mappedSchedulerID, authority)
	if err != nil {
		return zero, err
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf(
			"%w: context before Ed25519 verification: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	if !ed25519.Verify(current.PublicKey, preimage, authority.Signature[:]) {
		return zero, fmt.Errorf("%w: Ed25519 signature verification failed",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if err := readCtx.Err(); err != nil {
		return zero, fmt.Errorf(
			"%w: context after Ed25519 verification: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	receipt, err := vnextReaderPreparedStatusCanonicalAuthorityReceipt(
		authenticatedSchedulerPrincipal, authority)
	if err != nil {
		return zero, fmt.Errorf("%w: derive authority receipt: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	return vnextReaderPreparedStatusAuthorityProof{
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

func vnextReaderPreparedStatusAuthorityClusterBits(value string) (uint64, error) {
	if err := validateVNextReaderPreparedStatusClusterID(value); err != nil {
		return 0, err
	}
	clusterID, err := strconv.ParseUint(value, 16, 64)
	if err != nil || clusterID == 0 {
		return 0, errors.New(
			"STATUS_AND_FENCE cluster ID is outside the unsigned ABI")
	}
	return clusterID, nil
}

func (verifier *vnextReaderPreparedStatusCurrentAuthorityVerifier) validateCurrentLeaderSnapshot(
	snapshot vnextOwnerSchedulerLeaderSnapshot,
	mappedSchedulerID string,
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) (vnextOwnerSchedulerLeaderTerm, error) {
	var zero vnextOwnerSchedulerLeaderTerm
	if !snapshot.HeaderPresent ||
		snapshot.HeaderCluster != verifier.expectedCluster ||
		snapshot.HeaderRevision <= 0 {
		return zero, fmt.Errorf(
			"%w: exact leader response header differs from the pinned cluster",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if snapshot.Count != 1 || len(snapshot.KVs) != 1 || snapshot.More {
		return zero, fmt.Errorf(
			"%w: exact leader read did not return exactly one KV",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	kv := snapshot.KVs[0]
	if string(kv.Key) != verifier.leaderKey {
		return zero, fmt.Errorf("%w: exact leader read returned a different key",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	if kv.CreateRevision <= 0 ||
		kv.ModRevision != kv.CreateRevision || kv.Version != 1 ||
		kv.Lease <= 0 || snapshot.HeaderRevision < kv.ModRevision {
		return zero, fmt.Errorf(
			"%w: leader KV is not one immutable lease-attached current key",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	current, err := parseVNextOwnerSchedulerLeaderValue(string(kv.Value))
	if err != nil {
		return zero, fmt.Errorf("%w: parse current global Scheduler leader: %v",
			errVNextReaderPreparedStatusCurrentAuthority, err)
	}
	if current.SchedulerID != mappedSchedulerID ||
		current.SchedulerID != authority.SchedulerID ||
		current.LeaseID != uint64(kv.Lease) ||
		current.LeaseID != authority.LeaderLeaseID ||
		uint64(kv.CreateRevision) != authority.SchedulerFenceRevision ||
		current.KeyID != authority.KeyID {
		return zero, fmt.Errorf(
			"%w: current Scheduler, fence, lease, or key differs from the envelope",
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	// Only the low-level global Scheduler term identity is reused. No Owner
	// authority envelope, signature domain, operation, or mutation permission
	// is accepted by this status-specific verifier.
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
			errVNextReaderPreparedStatusCurrentAuthority)
	}
	return current, nil
}

var _ vnextReaderPreparedStatusAuthorityVerifier = (*vnextReaderPreparedStatusCurrentAuthorityVerifier)(nil)
