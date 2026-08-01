package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// client/v3 v3.5.7 is the final etcd patch compatible with this module's Go
// 1.17 language floor and the validated Go 1.18 host toolchain. It is not a
// current 2026 security baseline. Production enablement remains CLOSED until
// the toolchain and etcd client are upgraded together and revalidated.
const vnextOwnerSchedulerEtcdCompatibilityVersion = "v3.5.7"

type vnextOwnerSchedulerAuthorityConfig struct {
	Endpoints       []string
	LeaderKey       string
	ExpectedCluster uint64
	CAFile          string
	ClientCertFile  string
	ClientKeyFile   string
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
}

type vnextOwnerSchedulerLeaderKV struct {
	Key            []byte
	Value          []byte
	CreateRevision int64
	ModRevision    int64
	Version        int64
	Lease          int64
}

type vnextOwnerSchedulerLeaderSnapshot struct {
	HeaderPresent  bool
	HeaderCluster  uint64
	HeaderRevision int64
	Count          int64
	More           bool
	KVs            []vnextOwnerSchedulerLeaderKV
}

type vnextOwnerSchedulerLeaderReader interface {
	LinearizableGetExact(
		context.Context,
		string,
	) (vnextOwnerSchedulerLeaderSnapshot, error)
}

type vnextOwnerSchedulerAuthorityVerifier interface {
	Prepare(
		string,
		interface{},
		vnextOwnerSchedulerAuthority,
	) (vnextOwnerSchedulerVerifiedAuthority, error)
	VerifyCurrent(context.Context, vnextOwnerSchedulerVerifiedAuthority) error
}

type vnextOwnerSchedulerVerifier struct {
	leaderKey       string
	expectedCluster uint64
	readTimeout     time.Duration
	reader          vnextOwnerSchedulerLeaderReader
}

func newVNextOwnerSchedulerVerifier(
	config vnextOwnerSchedulerAuthorityConfig,
	reader vnextOwnerSchedulerLeaderReader,
) (*vnextOwnerSchedulerVerifier, error) {
	if err := validateVNextOwnerSchedulerAuthorityConfig(config, false); err != nil {
		return nil, err
	}
	if reader == nil {
		return nil, errors.New("Scheduler authority leader reader is required")
	}
	return &vnextOwnerSchedulerVerifier{
		leaderKey:       config.LeaderKey,
		expectedCluster: config.ExpectedCluster,
		readTimeout:     config.ReadTimeout,
		reader:          reader,
	}, nil
}

func (verifier *vnextOwnerSchedulerVerifier) Prepare(
	operation string,
	mutation interface{},
	authority vnextOwnerSchedulerAuthority,
) (vnextOwnerSchedulerVerifiedAuthority, error) {
	var zero vnextOwnerSchedulerVerifiedAuthority
	if verifier == nil || verifier.reader == nil {
		return zero, fmt.Errorf("%w: verifier is unavailable", errVNextOwnerSchedulerAuthority)
	}
	mutationDigest, err := vnextOwnerSchedulerMutationDigest(operation, mutation)
	if err != nil {
		return zero, fmt.Errorf("%w: %v", errVNextOwnerSchedulerAuthority, err)
	}
	verified, err := verifyVNextOwnerSchedulerAuthoritySignature(
		verifier.leaderKey, authority, mutationDigest)
	if err != nil {
		return zero, err
	}
	if verified.Parsed.ClusterID != verifier.expectedCluster {
		return zero, fmt.Errorf("%w: envelope cluster ID does not match the pinned cluster",
			errVNextOwnerSchedulerAuthority)
	}
	verified.HighWater = vnextOwnerSchedulerHighWaterFromVerified(
		verified, verifier.leaderKey)
	return verified, nil
}

func (verifier *vnextOwnerSchedulerVerifier) VerifyCurrent(
	ctx context.Context,
	verified vnextOwnerSchedulerVerifiedAuthority,
) error {
	if verifier == nil || verifier.reader == nil {
		return fmt.Errorf("%w: verifier is unavailable", errVNextOwnerSchedulerAuthority)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	readCtx, cancel := context.WithTimeout(ctx, verifier.readTimeout)
	defer cancel()
	snapshot, err := verifier.reader.LinearizableGetExact(readCtx, verifier.leaderKey)
	if err != nil {
		return fmt.Errorf("%w: linearizable exact leader read failed: %v",
			errVNextOwnerSchedulerAuthority, err)
	}
	return verifier.validateSnapshot(snapshot, verified)
}

func (verifier *vnextOwnerSchedulerVerifier) validateSnapshot(
	snapshot vnextOwnerSchedulerLeaderSnapshot,
	verified vnextOwnerSchedulerVerifiedAuthority,
) error {
	parsed := verified.Parsed
	if !snapshot.HeaderPresent || snapshot.HeaderCluster != verifier.expectedCluster ||
		snapshot.HeaderCluster != parsed.ClusterID || snapshot.HeaderRevision <= 0 {
		return fmt.Errorf("%w: etcd response header does not match the pinned cluster",
			errVNextOwnerSchedulerAuthority)
	}
	if snapshot.Count != 1 || len(snapshot.KVs) != 1 || snapshot.More {
		return fmt.Errorf("%w: exact leader read did not return exactly one KV",
			errVNextOwnerSchedulerAuthority)
	}
	kv := snapshot.KVs[0]
	if string(kv.Key) != verifier.leaderKey {
		return fmt.Errorf("%w: etcd returned a different leader key",
			errVNextOwnerSchedulerAuthority)
	}
	if kv.CreateRevision <= 0 || kv.ModRevision != kv.CreateRevision || kv.Version != 1 ||
		kv.Lease <= 0 || snapshot.HeaderRevision < kv.ModRevision {
		return fmt.Errorf("%w: leader KV is not one immutable lease-attached key",
			errVNextOwnerSchedulerAuthority)
	}
	if uint64(kv.CreateRevision) != parsed.CreateRevision ||
		uint64(kv.ModRevision) != parsed.ModRevision ||
		uint64(kv.Lease) != parsed.LeaseID || string(kv.Value) != parsed.LeaderValue {
		return fmt.Errorf("%w: leader KV differs from the signed envelope",
			errVNextOwnerSchedulerAuthority)
	}
	return nil
}

type vnextOwnerSchedulerEtcdKV interface {
	Get(context.Context, string, ...clientv3.OpOption) (*clientv3.GetResponse, error)
}

type vnextOwnerSchedulerEtcdReader struct {
	kv vnextOwnerSchedulerEtcdKV
}

func (reader *vnextOwnerSchedulerEtcdReader) LinearizableGetExact(
	ctx context.Context,
	key string,
) (vnextOwnerSchedulerLeaderSnapshot, error) {
	var snapshot vnextOwnerSchedulerLeaderSnapshot
	if reader == nil || reader.kv == nil {
		return snapshot, errors.New("etcd KV client is unavailable")
	}
	// No options are deliberate: etcd Get is linearizable by default. Prefix,
	// range, Serializable, cache, and watch paths are forbidden here.
	response, err := reader.kv.Get(clientv3.WithRequireLeader(ctx), key)
	if err != nil {
		return snapshot, err
	}
	if response == nil {
		return snapshot, errors.New("etcd returned a nil Get response")
	}
	if response.Header != nil {
		snapshot.HeaderPresent = true
		snapshot.HeaderCluster = response.Header.ClusterId
		snapshot.HeaderRevision = response.Header.Revision
	}
	snapshot.Count = response.Count
	snapshot.More = response.More
	snapshot.KVs = make([]vnextOwnerSchedulerLeaderKV, len(response.Kvs))
	for index, kv := range response.Kvs {
		if kv == nil {
			continue
		}
		snapshot.KVs[index] = vnextOwnerSchedulerLeaderKV{
			Key:            append([]byte(nil), kv.Key...),
			Value:          append([]byte(nil), kv.Value...),
			CreateRevision: kv.CreateRevision,
			ModRevision:    kv.ModRevision,
			Version:        kv.Version,
			Lease:          kv.Lease,
		}
	}
	return snapshot, nil
}

func openVNextOwnerSchedulerAuthority(
	config vnextOwnerSchedulerAuthorityConfig,
) (*vnextOwnerSchedulerVerifier, func() error, error) {
	if err := validateVNextOwnerSchedulerAuthorityConfig(config, true); err != nil {
		return nil, nil, err
	}
	tlsConfig, err := loadVNextOwnerSchedulerEtcdTLS(config)
	if err != nil {
		return nil, nil, err
	}
	client, err := clientv3.New(clientv3.Config{
		Endpoints:        append([]string(nil), config.Endpoints...),
		DialTimeout:      config.DialTimeout,
		TLS:              tlsConfig,
		RejectOldCluster: true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("open Scheduler authority etcd client: %w", err)
	}
	verifier, err := newVNextOwnerSchedulerVerifier(
		config, &vnextOwnerSchedulerEtcdReader{kv: client})
	if err != nil {
		_ = client.Close()
		return nil, nil, err
	}
	return verifier, client.Close, nil
}

func validateVNextOwnerSchedulerAuthorityConfig(
	config vnextOwnerSchedulerAuthorityConfig,
	requireTLSFiles bool,
) error {
	if len(config.Endpoints) == 0 {
		return errors.New("Scheduler authority etcd endpoints are required")
	}
	seen := make(map[string]struct{}, len(config.Endpoints))
	for _, endpoint := range config.Endpoints {
		parsed, err := url.Parse(endpoint)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
			parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" ||
			parsed.Fragment != "" || parsed.String() != endpoint ||
			strings.TrimSpace(endpoint) != endpoint {
			return fmt.Errorf("Scheduler authority endpoint %q is not canonical HTTPS", endpoint)
		}
		if _, duplicate := seen[endpoint]; duplicate {
			return fmt.Errorf("Scheduler authority endpoint %q is duplicated", endpoint)
		}
		seen[endpoint] = struct{}{}
	}
	if err := validateVNextOwnerSchedulerLeaderKey(config.LeaderKey); err != nil {
		return err
	}
	if config.ExpectedCluster == 0 {
		return errors.New("Scheduler authority expected cluster ID is zero")
	}
	if config.DialTimeout <= 0 || config.ReadTimeout <= 0 {
		return errors.New("Scheduler authority dial and read timeouts must be positive")
	}
	if requireTLSFiles {
		for name, path := range map[string]string{
			"CA": config.CAFile, "client certificate": config.ClientCertFile,
			"client key": config.ClientKeyFile,
		} {
			if err := validateVNextOwnerRuntimePath(path, "Scheduler authority "+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadVNextOwnerSchedulerEtcdTLS(
	config vnextOwnerSchedulerAuthorityConfig,
) (*tls.Config, error) {
	caPEM, err := os.ReadFile(config.CAFile)
	if err != nil {
		return nil, fmt.Errorf("read Scheduler authority CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("Scheduler authority CA contains no certificate")
	}
	certificate, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load Scheduler authority client certificate: %w", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func vnextOwnerSchedulerHighWaterFromVerified(
	verified vnextOwnerSchedulerVerifiedAuthority,
	leaderKey string,
) vnextOwnerSchedulerHighWater {
	return vnextOwnerSchedulerHighWater{
		Initialized:       true,
		LeaderKeyDigest:   sha256.Sum256([]byte(leaderKey)),
		ClusterID:         verified.Parsed.ClusterID,
		CreateRevision:    verified.Parsed.CreateRevision,
		ModRevision:       verified.Parsed.ModRevision,
		LeaseID:           verified.Parsed.LeaseID,
		LeaderValueDigest: sha256.Sum256([]byte(verified.Parsed.LeaderValue)),
		PublicKeyDigest:   verified.Parsed.Leader.KeyID,
		SchedulerTermID:   verified.Parsed.TermID,
	}
}

func validateVNextOwnerSchedulerHighWaterAdvance(
	current vnextOwnerSchedulerHighWater,
	next vnextOwnerSchedulerHighWater,
) error {
	if err := next.validate(); err != nil {
		return err
	}
	if !current.Initialized {
		return nil
	}
	if err := current.validate(); err != nil {
		return err
	}
	if next.ClusterID != current.ClusterID ||
		next.LeaderKeyDigest != current.LeaderKeyDigest {
		return fmt.Errorf("%w: Scheduler authority cluster/key domain changed",
			errVNextOwnerSchedulerFenced)
	}
	if next.CreateRevision < current.CreateRevision {
		return errVNextOwnerSchedulerFenced
	}
	if next.CreateRevision == current.CreateRevision && next != current {
		return fmt.Errorf("%w: same revision has a different term binding",
			errVNextOwnerSchedulerFenced)
	}
	return nil
}

func (highWater vnextOwnerSchedulerHighWater) validate() error {
	if !highWater.Initialized {
		if highWater != (vnextOwnerSchedulerHighWater{}) {
			return fmt.Errorf("uninitialized Scheduler high-water is non-zero: %w", errVNextCorrupt)
		}
		return nil
	}
	if vnextAllZero(highWater.LeaderKeyDigest[:]) || highWater.ClusterID == 0 ||
		highWater.CreateRevision == 0 || highWater.CreateRevision > uint64(math.MaxInt64) ||
		highWater.ModRevision != highWater.CreateRevision || highWater.LeaseID == 0 ||
		highWater.LeaseID > uint64(math.MaxInt64) ||
		vnextAllZero(highWater.LeaderValueDigest[:]) ||
		vnextAllZero(highWater.PublicKeyDigest[:]) ||
		vnextAllZero(highWater.SchedulerTermID[:]) {
		return fmt.Errorf("Scheduler high-water is invalid: %w", errVNextCorrupt)
	}
	return nil
}
