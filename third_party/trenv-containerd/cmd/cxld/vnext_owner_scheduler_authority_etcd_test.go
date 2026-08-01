package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.etcd.io/etcd/api/v3/etcdserverpb"
	"go.etcd.io/etcd/api/v3/mvccpb"
	"go.etcd.io/etcd/api/v3/v3rpc/rpctypes"
	clientv3 "go.etcd.io/etcd/client/v3"
	"google.golang.org/grpc/metadata"
)

type vnextOwnerSchedulerTestEtcdKV struct {
	t                 *testing.T
	wantKey           string
	requireLeaderSeen bool
	getCalls          int
	response          *clientv3.GetResponse
	err               error
}

func (kv *vnextOwnerSchedulerTestEtcdKV) Get(
	ctx context.Context,
	key string,
	options ...clientv3.OpOption,
) (*clientv3.GetResponse, error) {
	kv.t.Helper()
	kv.getCalls++
	if key != kv.wantKey {
		kv.t.Fatalf("etcd Get key = %q, want %q", key, kv.wantKey)
	}
	operation := clientv3.OpGet(key, options...)
	if operation.IsSerializable() || len(operation.RangeBytes()) != 0 {
		kv.t.Fatalf("etcd Get is serializable or ranged: %#v", operation)
	}
	if len(options) != 0 {
		kv.t.Fatalf("etcd exact Get received %d options", len(options))
	}
	outgoing, ok := metadata.FromOutgoingContext(ctx)
	if ok {
		for _, value := range outgoing.Get(rpctypes.MetadataRequireLeaderKey) {
			if value == rpctypes.MetadataHasLeader {
				kv.requireLeaderSeen = true
			}
		}
	}
	return kv.response, kv.err
}

func TestVNextOwnerSchedulerEtcdReaderUsesLeaderRequiredExactLinearizableGet(t *testing.T) {
	kv := &vnextOwnerSchedulerTestEtcdKV{
		t:       t,
		wantKey: vnextOwnerSchedulerTestLeaderKey,
		response: &clientv3.GetResponse{
			Header: &etcdserverpb.ResponseHeader{
				ClusterId: 1,
				Revision:  2,
			},
			Count: 1,
			Kvs: []*mvccpb.KeyValue{{
				Key:            []byte(vnextOwnerSchedulerTestLeaderKey),
				Value:          []byte("leader"),
				CreateRevision: 2,
				ModRevision:    2,
				Version:        1,
				Lease:          3,
			}},
		},
	}
	reader := &vnextOwnerSchedulerEtcdReader{kv: kv}
	snapshot, err := reader.LinearizableGetExact(
		context.Background(), vnextOwnerSchedulerTestLeaderKey)
	if err != nil {
		t.Fatal(err)
	}
	if !kv.requireLeaderSeen || kv.getCalls != 1 || !snapshot.HeaderPresent ||
		snapshot.Count != 1 || len(snapshot.KVs) != 1 {
		t.Fatalf("exact Get contract was not preserved: %#v / %#v", kv, snapshot)
	}
}

type vnextOwnerSchedulerTestLeaderReader struct {
	snapshot vnextOwnerSchedulerLeaderSnapshot
	err      error
	calls    int
}

func (reader *vnextOwnerSchedulerTestLeaderReader) LinearizableGetExact(
	ctx context.Context,
	key string,
) (vnextOwnerSchedulerLeaderSnapshot, error) {
	reader.calls++
	if reader.err != nil {
		return vnextOwnerSchedulerLeaderSnapshot{}, reader.err
	}
	return reader.snapshot, nil
}

func vnextOwnerSchedulerTestVerifier(
	t *testing.T,
) (*vnextOwnerSchedulerVerifier, *vnextOwnerSchedulerTestLeaderReader,
	vnextOwnerSchedulerAuthority, vnextOwnerSchedulerVerifiedAuthority) {
	t.Helper()
	mutation := vnextOwnerSchedulerTestReserveMutation()
	authority, verified := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, mutation)
	reader := &vnextOwnerSchedulerTestLeaderReader{
		snapshot: vnextOwnerSchedulerLeaderSnapshot{
			HeaderPresent:  true,
			HeaderCluster:  verified.Parsed.ClusterID,
			HeaderRevision: int64(verified.Parsed.ModRevision),
			Count:          1,
			KVs: []vnextOwnerSchedulerLeaderKV{{
				Key:            []byte(vnextOwnerSchedulerTestLeaderKey),
				Value:          []byte(verified.Parsed.LeaderValue),
				CreateRevision: int64(verified.Parsed.CreateRevision),
				ModRevision:    int64(verified.Parsed.ModRevision),
				Version:        1,
				Lease:          int64(verified.Parsed.LeaseID),
			}},
		},
	}
	verifier, err := newVNextOwnerSchedulerVerifier(vnextOwnerSchedulerAuthorityConfig{
		Endpoints:       []string{"https://etcd.test:2379"},
		LeaderKey:       vnextOwnerSchedulerTestLeaderKey,
		ExpectedCluster: verified.Parsed.ClusterID,
		DialTimeout:     time.Second,
		ReadTimeout:     time.Second,
	}, reader)
	if err != nil {
		t.Fatal(err)
	}
	return verifier, reader, authority, verified
}

func TestVNextOwnerSchedulerVerifierReadsEveryUnseenMutation(t *testing.T) {
	verifier, reader, authority, _ := vnextOwnerSchedulerTestVerifier(t)
	for index := 0; index < 2; index++ {
		verified, err := verifier.Prepare(
			vnextOwnerRPCOperationReserve,
			vnextOwnerSchedulerTestReserveMutation(),
			authority)
		if err != nil {
			t.Fatal(err)
		}
		if err := verifier.VerifyCurrent(context.Background(), verified); err != nil {
			t.Fatal(err)
		}
	}
	if reader.calls != 2 {
		t.Fatalf("linearizable Get calls = %d, want 2", reader.calls)
	}
}

func TestVNextOwnerSchedulerVerifierRejectsEveryExactSnapshotMismatch(t *testing.T) {
	verifier, reader, _, verified := vnextOwnerSchedulerTestVerifier(t)
	valid := reader.snapshot
	tests := map[string]func(*vnextOwnerSchedulerLeaderSnapshot){
		"missing header": func(value *vnextOwnerSchedulerLeaderSnapshot) { value.HeaderPresent = false },
		"cluster":        func(value *vnextOwnerSchedulerLeaderSnapshot) { value.HeaderCluster++ },
		"header revision": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.HeaderRevision--
		},
		"count": func(value *vnextOwnerSchedulerLeaderSnapshot) { value.Count = 2 },
		"more":  func(value *vnextOwnerSchedulerLeaderSnapshot) { value.More = true },
		"key": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.KVs[0].Key = []byte("/other")
		},
		"value": func(value *vnextOwnerSchedulerLeaderSnapshot) {
			value.KVs[0].Value = []byte("other")
		},
		"create":  func(value *vnextOwnerSchedulerLeaderSnapshot) { value.KVs[0].CreateRevision++ },
		"mod":     func(value *vnextOwnerSchedulerLeaderSnapshot) { value.KVs[0].ModRevision++ },
		"version": func(value *vnextOwnerSchedulerLeaderSnapshot) { value.KVs[0].Version = 2 },
		"lease":   func(value *vnextOwnerSchedulerLeaderSnapshot) { value.KVs[0].Lease++ },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			changed := valid
			changed.KVs = append([]vnextOwnerSchedulerLeaderKV(nil), valid.KVs...)
			changed.KVs[0].Key = append([]byte(nil), valid.KVs[0].Key...)
			changed.KVs[0].Value = append([]byte(nil), valid.KVs[0].Value...)
			mutate(&changed)
			reader.snapshot = changed
			if err := verifier.VerifyCurrent(context.Background(), verified); err == nil {
				t.Fatal("mismatched exact snapshot was accepted")
			}
		})
	}
}

func TestVNextOwnerSchedulerVerifierFailsClosedOnReadErrorAndTimeout(t *testing.T) {
	verifier, reader, _, verified := vnextOwnerSchedulerTestVerifier(t)
	reader.err = errors.New("etcd unavailable")
	if err := verifier.VerifyCurrent(context.Background(), verified); err == nil {
		t.Fatal("etcd read failure was accepted")
	}

	timeoutReader := vnextOwnerSchedulerBlockingLeaderReader{}
	verifier.reader = timeoutReader
	verifier.readTimeout = time.Millisecond
	if err := verifier.VerifyCurrent(context.Background(), verified); err == nil {
		t.Fatal("etcd read timeout was accepted")
	}
}

func TestVNextOwnerSchedulerHighWaterRejectsAuthorityDomainRebind(t *testing.T) {
	_, verified := vnextOwnerSchedulerTestAuthority(
		t, vnextOwnerRPCOperationReserve, vnextOwnerSchedulerTestReserveMutation())
	current := vnextOwnerSchedulerHighWaterFromVerified(
		verified, vnextOwnerSchedulerTestLeaderKey)

	higher := current
	higher.CreateRevision++
	higher.ModRevision++
	higher.SchedulerTermID[0]++
	if err := validateVNextOwnerSchedulerHighWaterAdvance(current, higher); err != nil {
		t.Fatalf("same authority domain higher term failed: %v", err)
	}

	changedCluster := higher
	changedCluster.ClusterID++
	if err := validateVNextOwnerSchedulerHighWaterAdvance(current, changedCluster); err == nil {
		t.Fatal("higher revision from a different cluster was accepted")
	}
	changedKey := higher
	changedKey.LeaderKeyDigest[0]++
	if err := validateVNextOwnerSchedulerHighWaterAdvance(current, changedKey); err == nil {
		t.Fatal("higher revision from a different leader key was accepted")
	}
}

type vnextOwnerSchedulerBlockingLeaderReader struct{}

func (vnextOwnerSchedulerBlockingLeaderReader) LinearizableGetExact(
	ctx context.Context,
	key string,
) (vnextOwnerSchedulerLeaderSnapshot, error) {
	<-ctx.Done()
	return vnextOwnerSchedulerLeaderSnapshot{}, ctx.Err()
}
