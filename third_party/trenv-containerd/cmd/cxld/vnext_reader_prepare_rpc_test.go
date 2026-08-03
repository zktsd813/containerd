package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const vnextReaderPrepareTestPrincipal = "spiffe://test.example/scheduler/scheduler-a"

type vnextReaderPrepareTestClock struct {
	mu       sync.Mutex
	values   []int64
	position int
}

type vnextReaderPrepareTestStore struct {
	mu    sync.Mutex
	calls int
}

func (store *vnextReaderPrepareTestStore) Prepare(
	vnextReaderAcquiredAuthorization,
	int64,
) (vnextReaderPreparedAuthorization, vnextReaderPreparationDisposition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	return vnextReaderPreparedAuthorization{}, 0,
		errors.New("unexpected PREPARE test-store call")
}

func (store *vnextReaderPrepareTestStore) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

func (clock *vnextReaderPrepareTestClock) NowEpochMillis() int64 {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	if len(clock.values) == 0 {
		return -1
	}
	position := clock.position
	if position >= len(clock.values) {
		position = len(clock.values) - 1
	} else {
		clock.position++
	}
	return clock.values[position]
}

type vnextReaderPrepareTestVerifier struct {
	mu                sync.Mutex
	calls             int
	wantPrincipal     string
	reject            error
	mutateProof       func(*vnextReaderPrepareAuthorityProof)
	beforeReturn      func()
	observedDigests   [][sha256.Size]byte
	observedAuthority []vnextReaderPrepareAuthorityEnvelope
}

func (verifier *vnextReaderPrepareTestVerifier) VerifyVNextReaderPrepareAuthority(
	_ context.Context,
	principal string,
	requestDigest [sha256.Size]byte,
	authority vnextReaderPrepareAuthorityEnvelope,
) (vnextReaderPrepareAuthorityProof, error) {
	verifier.mu.Lock()
	verifier.calls++
	verifier.observedDigests = append(verifier.observedDigests, requestDigest)
	verifier.observedAuthority = append(verifier.observedAuthority, authority)
	wantPrincipal := verifier.wantPrincipal
	reject := verifier.reject
	mutate := verifier.mutateProof
	hook := verifier.beforeReturn
	verifier.mu.Unlock()

	if hook != nil {
		hook()
	}
	if reject != nil {
		return vnextReaderPrepareAuthorityProof{}, reject
	}
	if wantPrincipal != "" && principal != wantPrincipal {
		return vnextReaderPrepareAuthorityProof{}, errors.New(
			"test verifier rejected the authenticated Scheduler principal")
	}
	receipt, err := vnextReaderPrepareCanonicalAuthorityReceipt(principal, authority)
	if err != nil {
		return vnextReaderPrepareAuthorityProof{}, err
	}
	proof := vnextReaderPrepareAuthorityProof{
		AuthenticatedSchedulerPrincipal: principal,
		SchedulerID:                     authority.SchedulerID,
		SchedulerFenceRevision:          authority.SchedulerFenceRevision,
		LeaderLeaseID:                   authority.LeaderLeaseID,
		LeaderTermID:                    authority.LeaderTermID,
		RequestDigest:                   requestDigest,
		AuthorityReceipt:                receipt,
	}
	if mutate != nil {
		mutate(&proof)
	}
	return proof, nil
}

func (verifier *vnextReaderPrepareTestVerifier) callCount() int {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return verifier.calls
}

type vnextReaderPrepareTestFixture struct {
	acquired vnextReaderAcquiredAuthorization
	request  vnextReaderPrepareRequest
	store    *vnextReaderAuthorizationStore
	clock    *vnextReaderPrepareTestClock
	verifier *vnextReaderPrepareTestVerifier
	service  *vnextReaderPrepareService
	rpc      *vnextReaderPrepareRPC
	frame    []byte
}

func newVNextReaderPrepareTestFixture(t *testing.T) *vnextReaderPrepareTestFixture {
	t.Helper()
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(8))
	if err != nil {
		t.Fatalf("new Reader authorization store: %v", err)
	}
	return newVNextReaderPrepareTestFixtureWithStore(t, store)
}

func newVNextReaderPrepareTestFixtureWithStore(
	t *testing.T,
	store *vnextReaderAuthorizationStore,
) *vnextReaderPrepareTestFixture {
	t.Helper()
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-prepare-a")
	clock := &vnextReaderPrepareTestClock{values: []int64{150}}
	verifier := &vnextReaderPrepareTestVerifier{
		wantPrincipal: vnextReaderPrepareTestPrincipal,
	}
	service, err := newVNextReaderPrepareService(
		acquired.Authorization.ExecutorID,
		acquired.Authorization.CxldLogicalID,
		acquired.Authorization.CxldProcessIncarnationID,
		store,
		clock,
		verifier)
	if err != nil {
		t.Fatalf("new Reader PREPARE service: %v", err)
	}
	request := vnextReaderPrepareTestRequest(acquired)
	frame, err := marshalVNextReaderPrepareRequest(request)
	if err != nil {
		t.Fatalf("marshal Reader PREPARE request: %v", err)
	}
	return &vnextReaderPrepareTestFixture{
		acquired: acquired,
		request:  request,
		store:    store,
		clock:    clock,
		verifier: verifier,
		service:  service,
		rpc:      newVNextReaderPrepareRPC(service),
		frame:    frame,
	}
}

func vnextReaderPrepareTestRequest(
	acquired vnextReaderAcquiredAuthorization,
) vnextReaderPrepareRequest {
	digest := vnextReaderPrepareCanonicalRequestDigest(acquired)
	term := sha256.Sum256([]byte("reader-prepare-test-leader-term"))
	key := sha256.Sum256([]byte("reader-prepare-test-key"))
	var signature [64]byte
	for index := range signature {
		signature[index] = byte(index + 1)
	}
	return vnextReaderPrepareRequest{
		Acquired: acquired,
		Authority: vnextReaderPrepareAuthorityEnvelope{
			Domain:                 vnextReaderPrepareAuthorityDomain,
			ClusterID:              "0000000000000001",
			SchedulerID:            acquired.SchedulerID,
			SchedulerFenceRevision: acquired.SchedulerFenceRevision,
			LeaderLeaseID:          23,
			LeaderTermID:           term,
			KeyID:                  key,
			RequestDigest:          digest,
			Signature:              signature,
		},
	}
}

func vnextReaderPrepareTestFrame(
	t *testing.T,
	request vnextReaderPrepareRequest,
) []byte {
	t.Helper()
	request.Authority.SchedulerID = request.Acquired.SchedulerID
	request.Authority.SchedulerFenceRevision = request.Acquired.SchedulerFenceRevision
	request.Authority.RequestDigest = vnextReaderPrepareCanonicalRequestDigest(
		request.Acquired)
	frame, err := marshalVNextReaderPrepareRequest(request)
	if err != nil {
		t.Fatalf("marshal test Reader PREPARE request: %v", err)
	}
	return frame
}

func TestVNextReaderPrepareRPCInstallsAndEchoesExactAuthorization(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)

	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("first Reader PREPARE: %v", failure)
	}
	response, err := decodeVNextReaderPrepareResponse(body)
	if err != nil {
		t.Fatalf("decode first Reader PREPARE response: %v", err)
	}
	if response.Disposition != vnextReaderPreparationInstalled ||
		response.Prepared.PreparationState != vnextReaderPreparationPrepared ||
		response.RequestDigest != fixture.request.Authority.RequestDigest ||
		response.AuthorityProof.RequestDigest != response.RequestDigest ||
		response.AuthorityProof.SchedulerID != fixture.acquired.SchedulerID ||
		response.AuthorityProof.SchedulerFenceRevision !=
			fixture.acquired.SchedulerFenceRevision ||
		response.AuthorityProof.AuthenticatedSchedulerPrincipal !=
			vnextReaderPrepareTestPrincipal ||
		response.LocalExecutorNodeID != fixture.acquired.Authorization.ExecutorID ||
		response.LocalCxldLogicalID != fixture.acquired.Authorization.CxldLogicalID ||
		response.LocalProcessIncarnation !=
			fixture.acquired.Authorization.CxldProcessIncarnationID ||
		!equalVNextReaderAcquiredAuthorization(
			response.Prepared.Acquired, fixture.acquired) {
		t.Fatalf("Reader PREPARE response lost exact identity: %#v", response)
	}
	if response.Receipt != vnextReaderPrepareCanonicalReceipt(response) {
		t.Fatal("Reader PREPARE response receipt is not canonical")
	}

	replayBody, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("exact Reader PREPARE replay: %v", failure)
	}
	replay, err := decodeVNextReaderPrepareResponse(replayBody)
	if err != nil {
		t.Fatalf("decode replay Reader PREPARE response: %v", err)
	}
	if replay.Disposition != vnextReaderPreparationExactReplay ||
		!equalVNextReaderAcquiredAuthorization(
			replay.Prepared.Acquired, fixture.acquired) {
		t.Fatalf("exact replay response = %#v", replay)
	}
	if fixture.verifier.callCount() != 2 {
		t.Fatalf("authority verifier calls = %d, want 2", fixture.verifier.callCount())
	}
}

func TestVNextReaderPrepareStrictRequestCodecRejectsMalformedInput(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	var base map[string]interface{}
	if err := json.Unmarshal(fixture.frame, &base); err != nil {
		t.Fatalf("decode test request map: %v", err)
	}

	cloneMap := func() map[string]interface{} {
		var cloned map[string]interface{}
		body, _ := json.Marshal(base)
		_ = json.Unmarshal(body, &cloned)
		return cloned
	}
	marshalMap := func(value map[string]interface{}) []byte {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("marshal malformed request: %v", err)
		}
		return body
	}

	nullAuthority := cloneMap()
	nullAuthority["authority"] = nil
	missingOperation := cloneMap()
	delete(missingOperation, "operation")
	unknown := cloneMap()
	unknown["ownerOperation"] = "vnextOwnerReserve"
	wrongProtocol := cloneMap()
	wrongProtocol["protocol"] = vnextReaderPrepareProtocol + "-other"
	oldProtocol := cloneMap()
	oldProtocol["protocol"] = "cxld.vnext-reader-prepare." + "v1"
	oldCxldField := cloneMap()
	oldAuthorization := oldCxldField["acquired"].(map[string]interface{})["authorization"].(map[string]interface{})
	oldAuthorization["executorCxld"+"Id"] = oldAuthorization["executorCxldLogicalId"]
	delete(oldAuthorization, "executorCxldLogicalId")
	missingProcess := cloneMap()
	delete(missingProcess["acquired"].(map[string]interface{})["authorization"].(map[string]interface{}),
		"executorCxldProcessIncarnationId")
	zeroBirthRevision := cloneMap()
	zeroBirthRevision["acquired"].(map[string]interface{})["authorization"].(map[string]interface{})["readerInitialRegistrationCatalogRevision"] = float64(0)
	wrongState := cloneMap()
	wrongState["acquired"].(map[string]interface{})["catalogState"] = "active"
	nullRuns := cloneMap()
	nullRuns["acquired"].(map[string]interface{})["authorization"].(map[string]interface{})["root"].(map[string]interface{})["publicationLocator"].(map[string]interface{})["pageRuns"] = nil
	shortCluster := cloneMap()
	shortCluster["authority"].(map[string]interface{})["clusterId"] = "1"
	uppercaseCluster := cloneMap()
	uppercaseCluster["authority"].(map[string]interface{})["clusterId"] =
		"000000000000000A"
	zeroCluster := cloneMap()
	zeroCluster["authority"].(map[string]interface{})["clusterId"] =
		"0000000000000000"
	uppercaseDigest := bytes.Replace(
		fixture.frame,
		[]byte(hex.EncodeToString(fixture.request.Authority.LeaderTermID[:])),
		[]byte(strings.ToUpper(hex.EncodeToString(
			fixture.request.Authority.LeaderTermID[:]))), 1)
	duplicateProtocol := bytes.Replace(
		fixture.frame,
		[]byte(`{"protocol":`),
		[]byte(`{"protocol":"`+vnextReaderPrepareProtocol+`","protocol":`), 1)

	var tooManyRuns vnextReaderPrepareRequestWire
	if err := json.Unmarshal(fixture.frame, &tooManyRuns); err != nil {
		t.Fatalf("decode run-bound fixture: %v", err)
	}
	oneRun := tooManyRuns.Acquired.Authorization.Root.PublicationLocator.PageRuns[0]
	tooManyRuns.Acquired.Authorization.Root.PublicationLocator.PageRuns = make(
		vnextReaderPreparePageRunsWire, vnextReaderMaxLocatorRuns+1)
	for index := range tooManyRuns.Acquired.Authorization.Root.PublicationLocator.PageRuns {
		tooManyRuns.Acquired.Authorization.Root.PublicationLocator.PageRuns[index] = oneRun
	}
	tooManyRunsBody, err := json.Marshal(tooManyRuns)
	if err != nil {
		t.Fatalf("marshal over-bound runs: %v", err)
	}
	// The shape pass runs before json.Decoder.Unmarshal is allowed to populate
	// the target. This proves a 257th run is rejected before allocation of the
	// target PageRuns slice, rather than truncated after allocation.
	sentinel := vnextReaderPrepareRequestWire{Protocol: "sentinel-not-decoded"}
	if err := decodeStrictVNextReaderPrepareJSON(tooManyRunsBody, &sentinel); err == nil {
		t.Fatal("strict shape pass accepted 257 locator runs")
	}
	if sentinel.Protocol != "sentinel-not-decoded" ||
		len(sentinel.Acquired.Authorization.Root.PublicationLocator.PageRuns) != 0 {
		t.Fatalf("over-bound locator populated decoder target before rejection: %#v", sentinel)
	}

	cases := map[string][]byte{
		"empty":               nil,
		"oversize":            bytes.Repeat([]byte{'x'}, vnextReaderPrepareMaxFrameBytes+1),
		"invalid UTF-8":       {0xff},
		"null authority":      marshalMap(nullAuthority),
		"missing operation":   marshalMap(missingOperation),
		"unknown field":       marshalMap(unknown),
		"wrong protocol":      marshalMap(wrongProtocol),
		"old v1 protocol":     marshalMap(oldProtocol),
		"old cxld field":      marshalMap(oldCxldField),
		"missing process":     marshalMap(missingProcess),
		"zero birth revision": marshalMap(zeroBirthRevision),
		"wrong state enum":    marshalMap(wrongState),
		"null page runs":      marshalMap(nullRuns),
		"short cluster":       marshalMap(shortCluster),
		"uppercase cluster":   marshalMap(uppercaseCluster),
		"zero cluster":        marshalMap(zeroCluster),
		"uppercase digest":    uppercaseDigest,
		"duplicate field":     duplicateProtocol,
		"trailing value":      append(append([]byte(nil), fixture.frame...), []byte(` {}`)...),
		"257 page runs":       tooManyRunsBody,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeVNextReaderPrepareRequest(body); err == nil {
				t.Fatal("malformed Reader PREPARE request was accepted")
			}
		})
	}
}

func TestVNextReaderPrepareCanonicalDigestBindsEveryPayloadClass(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	base := fixture.acquired
	want := vnextReaderPrepareCanonicalRequestDigest(base)
	// A stable fixture catches accidental field-order or domain changes across
	// the future Scala/Go transport implementation.
	const wantHex = "d3e66b9433ef007cb9c32be0b82d0363de67a015cb35e355442b63ff7478117d"
	if got := hex.EncodeToString(want[:]); got != wantHex {
		t.Fatalf("canonical Reader PREPARE fixture digest = %s, want %s", got, wantHex)
	}

	mutations := map[string]func(*vnextReaderAcquiredAuthorization){
		"authorization ID": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.RestoreAuthorizationID += "-other"
		},
		"checkpoint ID": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.CheckpointID += "-other"
		},
		"executor": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.ExecutorID += "-other"
		},
		"cxld": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.CxldLogicalID += "-other"
		},
		"process incarnation": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.CxldProcessIncarnationID[0] ^= 0xff
		},
		"initial registration revision": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.ReaderInitialRegistrationCatalogRevision++
		},
		"target": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.TargetContainerID += "-other"
		},
		"root ID": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.RootID += "-other"
		},
		"root version": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.RootVersion++
		},
		"MM template": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.MMTemplateID += "-other"
		},
		"PageMap ID": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PageMapID += "-other"
		},
		"PageMap version": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PageMapVersion++
		},
		"device digest": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.DeviceTableDigest[0] ^= 0xff
		},
		"contract": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.ContractID += "-other"
		},
		"publication length": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PublicationByteLength++
		},
		"publication digest": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PublicationSHA256[0] ^= 0xff
		},
		"run owner": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID += "-other"
		},
		"run device": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID += "-other"
		},
		"run allocation": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.AllocationRecordID++
		},
		"run page": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DataPageIndex++
		},
		"run count": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.PublicationLocator.PageRuns[0].PageCount++
		},
		"Scheduler": func(value *vnextReaderAcquiredAuthorization) {
			value.SchedulerID += "-other"
		},
		"fence": func(value *vnextReaderAcquiredAuthorization) {
			value.SchedulerFenceRevision++
		},
		"issued": func(value *vnextReaderAcquiredAuthorization) {
			value.IssuedAtEpochMillis++
		},
		"expires": func(value *vnextReaderAcquiredAuthorization) {
			value.ExpiresAtEpochMillis++
		},
		"state": func(value *vnextReaderAcquiredAuthorization) {
			value.CatalogState = "OTHER"
		},
		"mutation": func(value *vnextReaderAcquiredAuthorization) {
			value.LastMutationID += "-other"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := cloneVNextReaderAcquiredAuthorization(base)
			mutate(&candidate)
			if got := vnextReaderPrepareCanonicalRequestDigest(candidate); got == want {
				t.Fatal("payload mutation did not change the canonical request digest")
			}
		})
	}
}

func TestVNextReaderPrepareVerifierRunsBeforeStore(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	fixture.verifier.reject = errors.New("test current-leader verification failure")
	fixture.verifier.beforeReturn = func() {
		fixture.store.mu.RLock()
		defer fixture.store.mu.RUnlock()
		if len(fixture.store.byID) != 0 {
			t.Error("PREPARED store mutated before authority verifier returned")
		}
	}

	_, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure == nil || failure.Code != vnextReaderPrepareAuthorityError ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("authority failure = %#v", failure)
	}
	if fixture.verifier.callCount() != 1 {
		t.Fatalf("authority verifier calls = %d, want 1", fixture.verifier.callCount())
	}
	if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
		t.Fatalf("rejected authority store lookup = %v, want not found", err)
	}
}

func TestVNextReaderPrepareRejectsStaleProofPrincipalFenceAndLocalIdentity(t *testing.T) {
	proofCases := map[string]func(*vnextReaderPrepareAuthorityProof){
		"wrong principal": func(proof *vnextReaderPrepareAuthorityProof) {
			proof.AuthenticatedSchedulerPrincipal += "/other"
		},
		"stale Scheduler": func(proof *vnextReaderPrepareAuthorityProof) {
			proof.SchedulerID += "-stale"
		},
		"stale fence": func(proof *vnextReaderPrepareAuthorityProof) {
			proof.SchedulerFenceRevision--
		},
		"wrong leader term": func(proof *vnextReaderPrepareAuthorityProof) {
			proof.LeaderTermID[0] ^= 0xff
		},
		"wrong digest": func(proof *vnextReaderPrepareAuthorityProof) {
			proof.RequestDigest[0] ^= 0xff
		},
		"wrong authority receipt": func(proof *vnextReaderPrepareAuthorityProof) {
			proof.AuthorityReceipt[0] ^= 0xff
		},
	}
	for name, mutate := range proofCases {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareTestFixture(t)
			fixture.verifier.mutateProof = mutate
			_, failure := fixture.rpc.Handle(
				context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
			if failure == nil || failure.Code != vnextReaderPrepareAuthorityError ||
				failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
				t.Fatalf("stale authority failure = %#v", failure)
			}
			if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
				t.Fatalf("stale authority installed PREPARED: %v", err)
			}
		})
	}

	for name, mutate := range map[string]func(*vnextReaderAcquiredAuthorization){
		"wrong executor": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.ExecutorID += "-remote"
		},
		"wrong cxld": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.CxldLogicalID += "-remote"
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareTestFixture(t)
			request := fixture.request
			request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
			mutate(&request.Acquired)
			frame := vnextReaderPrepareTestFrame(t, request)
			_, failure := fixture.rpc.Handle(
				context.Background(), vnextReaderPrepareTestPrincipal, frame)
			if failure == nil || failure.Code != vnextReaderPrepareIdentityError ||
				failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
				t.Fatalf("local identity failure = %#v", failure)
			}
			if fixture.verifier.callCount() != 0 {
				t.Fatalf("local identity mismatch reached verifier %d times",
					fixture.verifier.callCount())
			}
		})
	}
}

func TestVNextReaderPrepareIncarnationMismatchNeverCallsStoreOrVerifier(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	store := &vnextReaderPrepareTestStore{}
	fixture.service.store = store

	acquired := cloneVNextReaderAcquiredAuthorization(fixture.acquired)
	acquired.Authorization.CxldProcessIncarnationID[0] ^= 0xff
	request := vnextReaderPrepareTestRequest(acquired)
	frame := vnextReaderPrepareTestFrame(t, request)
	_, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, frame)
	if failure == nil || failure.Code != vnextReaderPrepareIncarnationMismatch ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("incarnation mismatch failure = %#v", failure)
	}
	if store.callCount() != 0 || fixture.verifier.callCount() != 0 {
		t.Fatalf("incarnation mismatch reached store/verifier: %d/%d",
			store.callCount(), fixture.verifier.callCount())
	}
	fixture.clock.mu.Lock()
	clockCalls := fixture.clock.position
	fixture.clock.mu.Unlock()
	if clockCalls != 0 {
		t.Fatalf("incarnation mismatch reached receiver clock %d times", clockCalls)
	}
}

func TestVNextReaderPrepareRejectsEnvelopeSchedulerAndFenceBeforeVerifier(t *testing.T) {
	mutations := map[string]func(*vnextReaderPrepareAuthorityEnvelope){
		"Scheduler": func(authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.SchedulerID += "-attacker-selected"
		},
		"fence": func(authority *vnextReaderPrepareAuthorityEnvelope) {
			authority.SchedulerFenceRevision++
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareTestFixture(t)
			request := fixture.request
			mutate(&request.Authority)
			frame, err := marshalVNextReaderPrepareRequest(request)
			if err != nil {
				t.Fatalf("marshal mismatched envelope: %v", err)
			}
			_, failure := fixture.rpc.Handle(
				context.Background(), vnextReaderPrepareTestPrincipal, frame)
			if failure == nil || failure.Code != vnextReaderPrepareAuthorityError ||
				failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
				t.Fatalf("mismatched envelope failure = %#v", failure)
			}
			if fixture.verifier.callCount() != 0 {
				t.Fatalf("attacker-selected envelope reached verifier %d times",
					fixture.verifier.callCount())
			}
			if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
				t.Fatalf("mismatched envelope installed PREPARED: %v", err)
			}
		})
	}
}

func TestVNextReaderPrepareServiceRejectsMalformedClusterBeforeVerifier(t *testing.T) {
	for _, clusterID := range []string{
		"cluster-a", "1", "000000000000000A", "0000000000000000",
	} {
		t.Run(clusterID, func(t *testing.T) {
			fixture := newVNextReaderPrepareTestFixture(t)
			request := fixture.request
			request.Authority.ClusterID = clusterID
			_, failure := fixture.service.Prepare(
				context.Background(), vnextReaderPrepareTestPrincipal, request)
			if failure == nil || failure.Code != vnextReaderPrepareAuthorityError ||
				failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
				t.Fatalf("malformed cluster service failure = %#v", failure)
			}
			if fixture.verifier.callCount() != 0 {
				t.Fatalf("malformed cluster reached verifier %d times",
					fixture.verifier.callCount())
			}
			if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
				t.Fatalf("malformed cluster installed PREPARED: %v", err)
			}
		})
	}
}

func TestVNextReaderPrepareCancellationBeforeAndDuringVerifierStoresNothing(t *testing.T) {
	t.Run("cancelled before call", func(t *testing.T) {
		fixture := newVNextReaderPrepareTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, failure := fixture.rpc.Handle(
			ctx, vnextReaderPrepareTestPrincipal, fixture.frame)
		if failure == nil || failure.Acceptance !=
			vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("pre-cancelled failure = %#v", failure)
		}
		if fixture.verifier.callCount() != 0 {
			t.Fatalf("pre-cancelled call reached verifier %d times",
				fixture.verifier.callCount())
		}
		if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
			t.Fatalf("pre-cancelled call stored PREPARED: %v", err)
		}
	})

	t.Run("cancelled by verifier completion", func(t *testing.T) {
		fixture := newVNextReaderPrepareTestFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		fixture.verifier.beforeReturn = cancel
		_, failure := fixture.rpc.Handle(
			ctx, vnextReaderPrepareTestPrincipal, fixture.frame)
		if failure == nil || failure.Acceptance !=
			vnextReaderPrepareDefinitelyNotAccepted {
			t.Fatalf("mid-verifier cancellation failure = %#v", failure)
		}
		if fixture.verifier.callCount() != 1 {
			t.Fatalf("mid-verifier cancellation verifier calls = %d, want 1",
				fixture.verifier.callCount())
		}
		if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
			t.Fatalf("mid-verifier cancellation stored PREPARED: %v", err)
		}
	})
}

func TestVNextReaderPrepareRechecksTimeAndPortableStateBeforeStore(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	fixture.clock.values = []int64{150, fixture.acquired.ExpiresAtEpochMillis}
	_, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure == nil || failure.Code != vnextReaderPrepareInvalidRequest ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("post-verifier expiry failure = %#v", failure)
	}
	if _, err := fixture.store.LookupPreparedExact(fixture.acquired, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
		t.Fatalf("expired authorization was stored: %v", err)
	}

	mutations := map[string]func(*vnextReaderAcquiredAuthorization){
		"future issue": func(value *vnextReaderAcquiredAuthorization) {
			value.IssuedAtEpochMillis = 151
		},
		"wrong state": func(value *vnextReaderAcquiredAuthorization) {
			value.CatalogState = "ACTIVE"
		},
		"wrong last mutation": func(value *vnextReaderAcquiredAuthorization) {
			value.LastMutationID += "-other"
		},
		"zero root digest": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.DeviceTableDigest = [sha256.Size]byte{}
		},
		"invalid root contract": func(value *vnextReaderAcquiredAuthorization) {
			value.Authorization.Root.ContractID += "-other"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPrepareTestFixture(t)
			request := fixture.request
			request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
			mutate(&request.Acquired)
			request.Authority.RequestDigest =
				vnextReaderPrepareCanonicalRequestDigest(request.Acquired)
			// Bypass the client-side encoder because these cases prove the
			// service rejects invalid typed input before verifier/store.
			_, serviceFailure := fixture.service.Prepare(
				context.Background(), vnextReaderPrepareTestPrincipal, request)
			if serviceFailure == nil ||
				serviceFailure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
				t.Fatalf("invalid typed payload failure = %#v", serviceFailure)
			}
			if fixture.verifier.callCount() != 0 {
				t.Fatalf("invalid payload reached verifier %d times",
					fixture.verifier.callCount())
			}
		})
	}
}

func TestVNextReaderPrepareMapsConflictEntryAndByteCapacity(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	if _, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame); failure != nil {
		t.Fatalf("seed Reader PREPARE: %v", failure)
	}
	conflict := fixture.request
	conflict.Acquired = cloneVNextReaderAcquiredAuthorization(conflict.Acquired)
	conflict.Acquired.Authorization.Root.RootID += "-conflict"
	conflictFrame := vnextReaderPrepareTestFrame(t, conflict)
	_, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, conflictFrame)
	if failure == nil || failure.Code != vnextReaderPrepareConflictError ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("conflict mapping = %#v", failure)
	}

	entryStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new entry-bound store: %v", err)
	}
	entryFixture := newVNextReaderPrepareTestFixtureWithStore(t, entryStore)
	if _, failure := entryFixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal,
		entryFixture.frame); failure != nil {
		t.Fatalf("seed entry-bound store: %v", failure)
	}
	second := entryFixture.request
	second.Acquired = cloneVNextReaderAcquiredAuthorization(second.Acquired)
	second.Acquired.Authorization.RestoreAuthorizationID = "authorization-prepare-b"
	second.Acquired.LastMutationID = second.Acquired.Authorization.RestoreAuthorizationID
	secondFrame := vnextReaderPrepareTestFrame(t, second)
	_, failure = entryFixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, secondFrame)
	if failure == nil || failure.Code != vnextReaderPrepareCapacityError ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("entry capacity mapping = %#v", failure)
	}

	charge, err := vnextReaderAuthorizationRetainedCharge(entryFixture.acquired)
	if err != nil {
		t.Fatalf("calculate one authorization charge: %v", err)
	}
	byteStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreConfig{MaxEntries: 2, MaxRetainedBytes: charge})
	if err != nil {
		t.Fatalf("new byte-bound store: %v", err)
	}
	byteFixture := newVNextReaderPrepareTestFixtureWithStore(t, byteStore)
	if _, failure := byteFixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal,
		byteFixture.frame); failure != nil {
		t.Fatalf("seed byte-bound store: %v", failure)
	}
	byteSecond := byteFixture.request
	byteSecond.Acquired = cloneVNextReaderAcquiredAuthorization(byteSecond.Acquired)
	byteSecond.Acquired.Authorization.RestoreAuthorizationID = "authorization-prepare-c"
	byteSecond.Acquired.LastMutationID = byteSecond.Acquired.Authorization.RestoreAuthorizationID
	byteSecondFrame := vnextReaderPrepareTestFrame(t, byteSecond)
	_, failure = byteFixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, byteSecondFrame)
	if failure == nil || failure.Code != vnextReaderPrepareCapacityError ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("byte capacity mapping = %#v", failure)
	}
}

func TestVNextReaderPrepareMapsPermanentFenceToDefinitiveConflict(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	status, err := fixture.store.StatusAndFencePreparedExact(fixture.acquired)
	if err != nil || status.State != vnextReaderPreparedStatusNotPreparedFenced ||
		!reflect.DeepEqual(status.Prepared, vnextReaderPreparedAuthorization{}) {
		t.Fatalf("seed NOT_PREPARED_FENCED status=%#v err=%v", status, err)
	}

	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if len(body) != 0 || failure == nil ||
		failure.Code != vnextReaderPrepareConflictError ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted ||
		!errors.Is(failure, errVNextReaderAuthorizationNotPreparedFenced) {
		t.Fatalf("late fenced PREPARE body=%q failure=%#v", body, failure)
	}
	if fixture.verifier.callCount() != 1 {
		t.Fatalf("late fenced PREPARE verifier calls = %d, want 1",
			fixture.verifier.callCount())
	}
	if _, err := fixture.store.LookupPreparedExact(
		fixture.acquired, 150); !errors.Is(
		err, errVNextReaderAuthorizationNotPreparedFenced) {
		t.Fatalf("late fenced PREPARE installed a receipt: %v", err)
	}
	again, err := fixture.store.StatusAndFencePreparedExact(fixture.acquired)
	if err != nil || again.State != vnextReaderPreparedStatusNotPreparedFenced ||
		!reflect.DeepEqual(again.Prepared, vnextReaderPreparedAuthorization{}) {
		t.Fatalf("late PREPARE changed permanent fence: status=%#v err=%v", again, err)
	}
}

func TestVNextReaderPrepareEncodeFailureAfterStoreIsAmbiguous(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	fixture.rpc.encodeResponse = func(vnextReaderPrepareResponse) ([]byte, error) {
		return nil, errors.New("test response encoder failure")
	}
	_, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure == nil || failure.Code != vnextReaderPrepareUnavailable ||
		failure.Acceptance != vnextReaderPrepareAcceptanceUnknown {
		t.Fatalf("post-store encoder failure = %#v", failure)
	}
	prepared, err := fixture.store.LookupPreparedExact(fixture.acquired, 150)
	if err != nil || prepared.PreparationState != vnextReaderPreparationPrepared {
		t.Fatalf("post-encode-error PREPARED lookup = %#v / %v", prepared, err)
	}
	if failure.Acceptance == vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatal("accepted PREPARED was misreported as a definitive rejection")
	}
}

func TestVNextReaderPrepareResponseEncoderRejectsMalformedAcquiredEcho(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	response, failure := fixture.service.Prepare(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.request)
	if failure != nil {
		t.Fatalf("prepare encoder fixture: %v", failure)
	}
	mutations := map[string]func(*vnextReaderPrepareResponse){
		"wrong preparation state": func(value *vnextReaderPrepareResponse) {
			value.Prepared.PreparationState = "ACTIVE"
		},
		"wrong catalog state": func(value *vnextReaderPrepareResponse) {
			value.Prepared.Acquired.CatalogState = "ACTIVE"
		},
		"wrong last mutation": func(value *vnextReaderPrepareResponse) {
			value.Prepared.Acquired.LastMutationID += "-other"
		},
		"invalid interval": func(value *vnextReaderPrepareResponse) {
			value.Prepared.Acquired.ExpiresAtEpochMillis =
				value.Prepared.Acquired.IssuedAtEpochMillis
		},
		"zero root digest": func(value *vnextReaderPrepareResponse) {
			value.Prepared.Acquired.Authorization.Root.DeviceTableDigest = [sha256.Size]byte{}
		},
		"invalid root": func(value *vnextReaderPrepareResponse) {
			value.Prepared.Acquired.Authorization.Root.ContractID += "-other"
		},
		"wrong request digest": func(value *vnextReaderPrepareResponse) {
			value.RequestDigest[0] ^= 0xff
		},
		"wrong local identity": func(value *vnextReaderPrepareResponse) {
			value.LocalCxldLogicalID += "-other"
		},
		"wrong local process incarnation": func(value *vnextReaderPrepareResponse) {
			value.LocalProcessIncarnation[0] ^= 0xff
		},
		"wrong disposition": func(value *vnextReaderPrepareResponse) {
			value.Disposition = 0
		},
		"wrong receipt": func(value *vnextReaderPrepareResponse) {
			value.Receipt[0] ^= 0xff
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := response
			candidate.Prepared = cloneVNextReaderPreparedAuthorization(response.Prepared)
			mutate(&candidate)
			if _, err := marshalVNextReaderPrepareResponse(candidate); err == nil {
				t.Fatal("malformed accepted response was encoded")
			}
		})
	}
}

func TestVNextReaderPrepareReceiptIsUnkeyedBindingNotCxldSignature(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	response, failure := fixture.service.Prepare(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.request)
	if failure != nil {
		t.Fatalf("prepare receipt fixture: %v", failure)
	}
	want := vnextReaderPrepareCanonicalReceipt(response)
	if want != response.Receipt {
		t.Fatal("service receipt differs from the public canonical hash")
	}

	// Anyone with the response fields can recompute this unkeyed hash. It is
	// deliberately not a cxld signature or MAC. Authenticity must come from the
	// verifier-produced authority receipt and the future authenticated Reader
	// transport; changing that authority receipt changes this binding hash.
	changed := response
	changed.AuthorityProof.AuthorityReceipt[0] ^= 0xff
	if got := vnextReaderPrepareCanonicalReceipt(changed); got == want {
		t.Fatal("authority receipt mutation did not change the canonical binding hash")
	}
}

func TestVNextReaderPrepareAuthoritySignaturePreimageIsStableAndComplete(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	base := fixture.request.Authority
	preimage, err := vnextReaderPrepareAuthoritySignaturePreimage(base)
	if err != nil {
		t.Fatalf("build Reader authority signature preimage: %v", err)
	}
	digest := sha256.Sum256(preimage)
	const wantDigestHex = "034e67ecfec7239efd92ed050ae9edacfd5a9a1f1361f70048580ca36f6b7803"
	if got := hex.EncodeToString(digest[:]); got != wantDigestHex {
		t.Fatalf("Reader authority preimage fixture digest = %s, want %s",
			got, wantDigestHex)
	}

	mutations := map[string]func(*vnextReaderPrepareAuthorityEnvelope){
		"cluster": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.ClusterID = "0000000000000002"
		},
		"Scheduler": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.SchedulerID += "-other"
		},
		"fence": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.SchedulerFenceRevision++
		},
		"lease": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.LeaderLeaseID++
		},
		"term": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.LeaderTermID[0] ^= 0xff
		},
		"key": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.KeyID[0] ^= 0xff
		},
		"request digest": func(value *vnextReaderPrepareAuthorityEnvelope) {
			value.RequestDigest[0] ^= 0xff
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := base
			mutate(&candidate)
			candidatePreimage, err :=
				vnextReaderPrepareAuthoritySignaturePreimage(candidate)
			if err != nil {
				t.Fatalf("build mutated authority preimage: %v", err)
			}
			if bytes.Equal(candidatePreimage, preimage) {
				t.Fatal("authority field mutation did not change signature preimage")
			}
		})
	}

	wrongDomain := base
	wrongDomain.Domain += "-owner"
	if _, err := vnextReaderPrepareAuthoritySignaturePreimage(wrongDomain); err == nil {
		t.Fatal("wrong Reader authority domain produced a signature preimage")
	}
	changedSignature := base
	changedSignature.Signature[0] ^= 0xff
	changedPreimage, err := vnextReaderPrepareAuthoritySignaturePreimage(changedSignature)
	if err != nil || !bytes.Equal(changedPreimage, preimage) {
		t.Fatalf("Signature must be excluded from its own preimage: equal=%v err=%v",
			bytes.Equal(changedPreimage, preimage), err)
	}
	baseReceipt, err := vnextReaderPrepareCanonicalAuthorityReceipt(
		vnextReaderPrepareTestPrincipal, base)
	if err != nil {
		t.Fatalf("derive base authority receipt: %v", err)
	}
	const wantAuthorityReceiptHex = "875e08b5337b025cf8df0ba8908b464b55223f65576708c59812fe8d1efafc55"
	if got := hex.EncodeToString(baseReceipt[:]); got != wantAuthorityReceiptHex {
		t.Fatalf("Reader authority receipt fixture = %s, want %s",
			got, wantAuthorityReceiptHex)
	}
	changedReceipt, err := vnextReaderPrepareCanonicalAuthorityReceipt(
		vnextReaderPrepareTestPrincipal, changedSignature)
	if err != nil {
		t.Fatalf("derive changed-signature authority receipt: %v", err)
	}
	if baseReceipt == changedReceipt {
		t.Fatal("authority receipt did not bind the verified Signature")
	}
}

func TestVNextReaderPrepareMaxEscapedLocatorRoundTripsWithinFrameBound(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreConfig{
			MaxEntries:       1,
			MaxRetainedBytes: vnextReaderAuthorizationStoreMaxRetainedBytes,
		})
	if err != nil {
		t.Fatalf("new maximum escaped locator store: %v", err)
	}
	fixture := newVNextReaderPrepareTestFixtureWithStore(t, store)
	acquired := cloneVNextReaderAcquiredAuthorization(fixture.acquired)
	escapedIdentity := strings.Repeat("<", cxlcheckpoint.MaxIdentityBytes)
	runs := make([]cxlcheckpoint.PublicationPageRun, vnextReaderMaxLocatorRuns)
	for index := range runs {
		runs[index] = cxlcheckpoint.PublicationPageRun{
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            escapedIdentity,
				DeviceUUID:         escapedIdentity,
				AllocationRecordID: uint64(index + 1),
				DataPageIndex:      uint64(index),
			},
			PageCount: 1,
		}
	}
	acquired.Authorization.Root.PublicationLocator.PageRuns = runs
	acquired.Authorization.Root.PublicationLocator.PublicationByteLength =
		uint64(len(runs)) * cxlcheckpoint.PageSize
	request := vnextReaderPrepareTestRequest(acquired)
	frame, err := marshalVNextReaderPrepareRequest(request)
	if err != nil {
		t.Fatalf("marshal maximum escaped locator: %v", err)
	}
	if len(frame) <= 4<<20 || len(frame) > vnextReaderPrepareMaxFrameBytes {
		t.Fatalf("maximum escaped request frame bytes = %d, expected 4 MiB < n <= %d",
			len(frame), vnextReaderPrepareMaxFrameBytes)
	}
	decoded, err := decodeVNextReaderPrepareRequest(frame)
	if err != nil || !equalVNextReaderAcquiredAuthorization(decoded.Acquired, acquired) {
		t.Fatalf("maximum escaped request round trip failed: equal=%v err=%v",
			err == nil && equalVNextReaderAcquiredAuthorization(decoded.Acquired, acquired), err)
	}
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, frame)
	if failure != nil {
		t.Fatalf("prepare maximum escaped locator: %v", failure)
	}
	if len(body) <= 4<<20 || len(body) > vnextReaderPrepareMaxFrameBytes {
		t.Fatalf("maximum escaped response frame bytes = %d, expected 4 MiB < n <= %d",
			len(body), vnextReaderPrepareMaxFrameBytes)
	}
	response, err := decodeVNextReaderPrepareResponse(body)
	if err != nil ||
		!equalVNextReaderAcquiredAuthorization(response.Prepared.Acquired, acquired) {
		t.Fatalf("maximum escaped response round trip failed: equal=%v err=%v",
			err == nil && equalVNextReaderAcquiredAuthorization(
				response.Prepared.Acquired, acquired), err)
	}
}

func TestVNextReaderPrepareStrictResponseCodecRejectsSubstitution(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("prepare response fixture: %v", failure)
	}
	var base map[string]interface{}
	if err := json.Unmarshal(body, &base); err != nil {
		t.Fatalf("decode response map: %v", err)
	}
	clone := func() map[string]interface{} {
		var value map[string]interface{}
		raw, _ := json.Marshal(base)
		_ = json.Unmarshal(raw, &value)
		return value
	}
	mutations := map[string]func(map[string]interface{}){
		"old v1 protocol": func(value map[string]interface{}) {
			value["protocol"] = "cxld.vnext-reader-prepare." + "v1"
		},
		"state": func(value map[string]interface{}) {
			value["state"] = "ACTIVE"
		},
		"disposition": func(value map[string]interface{}) {
			value["disposition"] = "REPLAYED"
		},
		"local executor": func(value map[string]interface{}) {
			value["localExecutorNodeId"] = "executor-other"
		},
		"old local cxld field": func(value map[string]interface{}) {
			value["localCxldInstance"+"Id"] = value["localCxldLogicalId"]
			delete(value, "localCxldLogicalId")
		},
		"missing local process": func(value map[string]interface{}) {
			delete(value, "localProcessIncarnationId")
		},
		"request digest": func(value map[string]interface{}) {
			value["requestDigest"] = strings.ToUpper(value["requestDigest"].(string))
		},
		"proof fence": func(value map[string]interface{}) {
			proof := value["authorityProof"].(map[string]interface{})
			proof["schedulerFenceRevision"] = proof["schedulerFenceRevision"].(float64) + 1
		},
		"authorization target": func(value map[string]interface{}) {
			value["acquired"].(map[string]interface{})["authorization"].(map[string]interface{})["targetContainerId"] = "target-other"
		},
		"receipt": func(value map[string]interface{}) {
			receipt := value["receipt"].(string)
			value["receipt"] = "ff" + receipt[2:]
		},
		"unknown": func(value map[string]interface{}) {
			value["ownerProof"] = map[string]interface{}{}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := clone()
			mutate(value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatalf("marshal substituted response: %v", err)
			}
			if _, err := decodeVNextReaderPrepareResponse(raw); err == nil {
				t.Fatal("substituted Reader PREPARE response was accepted")
			}
		})
	}
}

func TestVNextReaderPrepareConcurrentExactCallsInstallOnce(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new concurrent store: %v", err)
	}
	fixture := newVNextReaderPrepareTestFixtureWithStore(t, store)
	const callers = 64
	var installed int64
	var replayed int64
	var failed int64
	var wait sync.WaitGroup
	start := make(chan struct{})
	for index := 0; index < callers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			body, failure := fixture.rpc.Handle(
				context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
			if failure != nil {
				atomic.AddInt64(&failed, 1)
				return
			}
			response, err := decodeVNextReaderPrepareResponse(body)
			if err != nil {
				atomic.AddInt64(&failed, 1)
				return
			}
			switch response.Disposition {
			case vnextReaderPreparationInstalled:
				atomic.AddInt64(&installed, 1)
			case vnextReaderPreparationExactReplay:
				atomic.AddInt64(&replayed, 1)
			default:
				atomic.AddInt64(&failed, 1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if failed != 0 || installed != 1 || replayed != callers-1 {
		t.Fatalf("concurrent PREPARE installed=%d replayed=%d failed=%d",
			installed, replayed, failed)
	}
	if fixture.verifier.callCount() != callers {
		t.Fatalf("concurrent verifier calls = %d, want %d",
			fixture.verifier.callCount(), callers)
	}
}

func TestVNextReaderPrepareServiceHasZeroDAXOwnerCRIULifecycleDependencies(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	serviceType := reflect.TypeOf(*fixture.service)
	wantFields := map[string]reflect.Type{
		"localExecutorNodeID": reflect.TypeOf(""),
		"localCxldLogicalID":  reflect.TypeOf(""),
		"processIncarnation":  reflect.TypeOf(vnextReaderProcessIncarnation{}),
		"store":               reflect.TypeOf((*vnextReaderPrepareStore)(nil)).Elem(),
		"clock":               reflect.TypeOf((*vnextReaderPrepareClock)(nil)).Elem(),
		"authorityVerifier": reflect.TypeOf(
			(*vnextReaderPrepareAuthorityVerifier)(nil)).Elem(),
	}
	if serviceType.NumField() != len(wantFields) {
		t.Fatalf("Reader PREPARE service has %d dependencies, want only %d",
			serviceType.NumField(), len(wantFields))
	}
	for index := 0; index < serviceType.NumField(); index++ {
		field := serviceType.Field(index)
		want, exists := wantFields[field.Name]
		if !exists || field.Type != want {
			t.Fatalf("unexpected Reader PREPARE dependency %s %s",
				field.Name, field.Type)
		}
		lower := strings.ToLower(field.Name + " " + field.Type.String())
		for _, forbidden := range []string{
			"dax", "owner", "criu", "active", "release", "directory", "source",
		} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("Reader PREPARE dependency %s contains forbidden %q",
					field.Name, forbidden)
			}
		}
	}
	if vnextReaderPrepareProtocol == vnextOwnerRPCProtocol ||
		vnextReaderPrepareALPN == vnextOwnerTLSALPN ||
		strings.Contains(vnextReaderPrepareOperation, "Owner") {
		t.Fatal("Reader PREPARE was mixed into the Owner protocol surface")
	}

	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("zero-DAX Reader PREPARE: %v", failure)
	}
	if _, err := decodeVNextReaderPrepareResponse(body); err != nil {
		t.Fatalf("decode zero-DAX Reader PREPARE response: %v", err)
	}
}

func TestVNextReaderPrepareConstructorFailsClosed(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new constructor test store: %v", err)
	}
	clock := &vnextReaderPrepareTestClock{values: []int64{150}}
	verifier := &vnextReaderPrepareTestVerifier{}
	processIncarnation := vnextReaderAuthorizationStoreTestAcquired(
		"constructor-process").Authorization.CxldProcessIncarnationID
	cases := []struct {
		name     string
		executor string
		cxld     string
		store    *vnextReaderAuthorizationStore
		clock    vnextReaderPrepareClock
		verifier vnextReaderPrepareAuthorityVerifier
	}{
		{"empty executor", "", "cxld-a", store, clock, verifier},
		{"empty cxld", "executor-a", "", store, clock, verifier},
		{"nil store", "executor-a", "cxld-a", nil, clock, verifier},
		{"nil clock", "executor-a", "cxld-a", store, nil, verifier},
		{"nil verifier", "executor-a", "cxld-a", store, clock, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if service, err := newVNextReaderPrepareService(
				test.executor, test.cxld, processIncarnation,
				test.store, test.clock, test.verifier); err == nil || service != nil {
				t.Fatalf("constructor = %#v / %v, want fail closed", service, err)
			}
		})
	}
}

func TestVNextReaderPrepareMalformedFrameIsDefinitivelyRejected(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	_, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPrepareTestPrincipal, []byte(`null`))
	if failure == nil || failure.Code != vnextReaderPrepareInvalidRequest ||
		failure.Acceptance != vnextReaderPrepareDefinitelyNotAccepted {
		t.Fatalf("malformed frame mapping = %#v", failure)
	}
	if fixture.verifier.callCount() != 0 {
		t.Fatalf("malformed frame reached verifier %d times",
			fixture.verifier.callCount())
	}
}

func TestVNextReaderPrepareRequestCodecRoundTrip(t *testing.T) {
	fixture := newVNextReaderPrepareTestFixture(t)
	decoded, err := decodeVNextReaderPrepareRequest(fixture.frame)
	if err != nil {
		t.Fatalf("decode strict Reader PREPARE request: %v", err)
	}
	if !equalVNextReaderAcquiredAuthorization(decoded.Acquired, fixture.acquired) ||
		decoded.Authority != fixture.request.Authority {
		t.Fatalf("strict Reader PREPARE round trip changed request: %#v", decoded)
	}
	canonical, err := marshalVNextReaderPrepareRequest(decoded)
	if err != nil {
		t.Fatalf("re-marshal strict Reader PREPARE request: %v", err)
	}
	if !bytes.Equal(canonical, fixture.frame) {
		t.Fatalf("Reader PREPARE request is not canonical JSON:\n%s\n%s",
			fixture.frame, canonical)
	}
}

func BenchmarkVNextReaderPrepareCanonicalDigest(b *testing.B) {
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-benchmark")
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		if digest := vnextReaderPrepareCanonicalRequestDigest(acquired); digest == [sha256.Size]byte{} {
			b.Fatal("zero digest")
		}
	}
}

func Example_vnextReaderPrepareProtocol() {
	fmt.Printf("%s %s", vnextReaderPrepareProtocol, vnextReaderPrepareOperation)
	// Output: cxld.vnext-reader-prepare.v2 vnextReaderPrepareAuthorization
}
