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
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const vnextReaderPreparedStatusTestPrincipal = "spiffe://test.example/scheduler/status-current"

type vnextReaderPreparedStatusTestVerifier struct {
	mu            sync.Mutex
	calls         int
	wantPrincipal string
	reject        error
	mutateProof   func(*vnextReaderPreparedStatusAuthorityProof)
	beforeReturn  func()
}

func (verifier *vnextReaderPreparedStatusTestVerifier) VerifyVNextReaderPreparedStatusAuthority(
	_ context.Context,
	principal string,
	requestDigest [sha256.Size]byte,
	authority vnextReaderPreparedStatusAuthorityEnvelope,
) (vnextReaderPreparedStatusAuthorityProof, error) {
	verifier.mu.Lock()
	verifier.calls++
	wantPrincipal := verifier.wantPrincipal
	reject := verifier.reject
	mutate := verifier.mutateProof
	hook := verifier.beforeReturn
	verifier.mu.Unlock()
	if hook != nil {
		hook()
	}
	if reject != nil {
		return vnextReaderPreparedStatusAuthorityProof{}, reject
	}
	if wantPrincipal != "" && principal != wantPrincipal {
		return vnextReaderPreparedStatusAuthorityProof{}, errors.New(
			"test verifier rejected principal")
	}
	receipt, err := vnextReaderPreparedStatusCanonicalAuthorityReceipt(
		principal, authority)
	if err != nil {
		return vnextReaderPreparedStatusAuthorityProof{}, err
	}
	proof := vnextReaderPreparedStatusAuthorityProof{
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

func (verifier *vnextReaderPreparedStatusTestVerifier) callCount() int {
	verifier.mu.Lock()
	defer verifier.mu.Unlock()
	return verifier.calls
}

type vnextReaderPreparedStatusTestStore struct {
	mu      sync.Mutex
	calls   int
	inner   *vnextReaderAuthorizationStore
	handler func(vnextReaderAcquiredAuthorization) (
		vnextReaderPreparedStatusAndFenceResult, error)
}

func (store *vnextReaderPreparedStatusTestStore) StatusAndFencePreparedExact(
	acquired vnextReaderAcquiredAuthorization,
) (vnextReaderPreparedStatusAndFenceResult, error) {
	store.mu.Lock()
	store.calls++
	handler := store.handler
	inner := store.inner
	store.mu.Unlock()
	if handler != nil {
		return handler(acquired)
	}
	return inner.StatusAndFencePreparedExact(acquired)
}

func (store *vnextReaderPreparedStatusTestStore) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

type vnextReaderPreparedStatusTestFixture struct {
	acquired vnextReaderAcquiredAuthorization
	request  vnextReaderPreparedStatusRequest
	inner    *vnextReaderAuthorizationStore
	store    *vnextReaderPreparedStatusTestStore
	verifier *vnextReaderPreparedStatusTestVerifier
	service  *vnextReaderPreparedStatusService
	rpc      *vnextReaderPreparedStatusRPC
	frame    []byte
}

func newVNextReaderPreparedStatusTestFixture(
	t *testing.T,
) *vnextReaderPreparedStatusTestFixture {
	t.Helper()
	inner, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(64))
	if err != nil {
		t.Fatalf("new status test store: %v", err)
	}
	return newVNextReaderPreparedStatusTestFixtureWithStore(t, inner)
}

func newVNextReaderPreparedStatusTestFixtureWithStore(
	t *testing.T,
	inner *vnextReaderAuthorizationStore,
) *vnextReaderPreparedStatusTestFixture {
	t.Helper()
	acquired := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-status-rpc-a")
	// The queried record A is historical. Current authority B below uses a
	// different Scheduler and fence; equality between A and B is forbidden.
	acquired.IssuedAtEpochMillis = 1
	acquired.ExpiresAtEpochMillis = 2
	request := vnextReaderPreparedStatusTestRequest(acquired)
	if request.Authority.SchedulerID == acquired.SchedulerID ||
		request.Authority.SchedulerFenceRevision == acquired.SchedulerFenceRevision {
		t.Fatal("test fixture failed to separate historical A from current B")
	}
	store := &vnextReaderPreparedStatusTestStore{inner: inner}
	verifier := &vnextReaderPreparedStatusTestVerifier{
		wantPrincipal: vnextReaderPreparedStatusTestPrincipal,
	}
	service, err := newVNextReaderPreparedStatusService(
		acquired.Authorization.ExecutorID,
		acquired.Authorization.CxldInstanceID,
		store,
		verifier)
	if err != nil {
		t.Fatalf("new STATUS_AND_FENCE service: %v", err)
	}
	frame, err := marshalVNextReaderPreparedStatusRequest(request)
	if err != nil {
		t.Fatalf("marshal STATUS_AND_FENCE request: %v", err)
	}
	return &vnextReaderPreparedStatusTestFixture{
		acquired: acquired,
		request:  request,
		inner:    inner,
		store:    store,
		verifier: verifier,
		service:  service,
		rpc:      newVNextReaderPreparedStatusRPC(service),
		frame:    frame,
	}
}

func vnextReaderPreparedStatusTestRequest(
	acquired vnextReaderAcquiredAuthorization,
) vnextReaderPreparedStatusRequest {
	term := sha256.Sum256([]byte("status-current-leader-term"))
	key := sha256.Sum256([]byte("status-current-leader-key"))
	var signature [64]byte
	for index := range signature {
		signature[index] = byte(255 - index)
	}
	return vnextReaderPreparedStatusRequest{
		Acquired: acquired,
		Authority: vnextReaderPreparedStatusAuthorityEnvelope{
			Domain:                 vnextReaderPreparedStatusAuthorityDomain,
			ClusterID:              "0000000000000001",
			SchedulerID:            "scheduler-status-current",
			SchedulerFenceRevision: acquired.SchedulerFenceRevision + 100,
			LeaderLeaseID:          404,
			LeaderTermID:           term,
			KeyID:                  key,
			RequestDigest: vnextReaderPreparedStatusCanonicalRequestDigest(
				acquired),
			Signature: signature,
		},
	}
}

func TestVNextReaderPreparedStatusPriorTermQueryFencesExactlyOnce(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatalf("historical A/current B STATUS_AND_FENCE: %v", failure)
	}
	if fixture.store.callCount() != 1 || fixture.verifier.callCount() != 1 {
		t.Fatalf("verifier/store calls = %d/%d, want 1/1",
			fixture.verifier.callCount(), fixture.store.callCount())
	}
	response, err := decodeVNextReaderPreparedStatusResponse(body)
	if err != nil {
		t.Fatalf("decode fenced status response: %v", err)
	}
	if response.Result.State != vnextReaderPreparedStatusNotPreparedFenced ||
		!reflect.DeepEqual(
			response.Result.Prepared, vnextReaderPreparedAuthorization{}) ||
		!equalVNextReaderAcquiredAuthorization(response.Acquired, fixture.acquired) ||
		response.AuthorityProof.SchedulerID != fixture.request.Authority.SchedulerID ||
		response.AuthorityProof.SchedulerFenceRevision !=
			fixture.request.Authority.SchedulerFenceRevision {
		t.Fatalf("fenced response lost separated A/B identity: %#v", response)
	}
	if response.AuthorityProof.SchedulerID == response.Acquired.SchedulerID ||
		response.AuthorityProof.SchedulerFenceRevision ==
			response.Acquired.SchedulerFenceRevision {
		t.Fatal("response incorrectly collapsed historical A into current B")
	}

	replay, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.frame)
	if failure != nil || !bytes.Equal(body, replay) {
		t.Fatalf("exact fenced replay changed response: failure=%v", failure)
	}
	if fixture.store.callCount() != 2 {
		t.Fatalf("two authenticated requests made %d store calls, want 2",
			fixture.store.callCount())
	}
}

func TestVNextReaderPreparedStatusReturnsOnlyExactPreparedReceipt(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	prepared, disposition, err := fixture.inner.Prepare(fixture.acquired, 1)
	if err != nil || disposition != vnextReaderPreparationInstalled {
		t.Fatalf("seed historical PREPARED: %#v/%v/%v",
			prepared, disposition, err)
	}
	response, failure := fixture.service.StatusAndFence(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.request)
	if failure != nil {
		t.Fatalf("status exact PREPARED: %v", failure)
	}
	if response.Result.State != vnextReaderPreparedStatusExactPrepared ||
		response.Result.Prepared.PreparationState != vnextReaderPreparationPrepared ||
		!equalVNextReaderAcquiredAuthorization(
			response.Result.Prepared.Acquired, fixture.acquired) ||
		!equalVNextReaderAcquiredAuthorization(response.Acquired, fixture.acquired) {
		t.Fatalf("PREPARED response lost exact receipt: %#v", response)
	}
	body, err := marshalVNextReaderPreparedStatusResponse(response)
	if err != nil {
		t.Fatalf("marshal PREPARED response: %v", err)
	}
	if bytes.Count(body, []byte(`"restoreAuthorizationId"`)) != 1 {
		t.Fatalf("PREPARED wire duplicated full ACQUIRED identity: %s", body)
	}
	decoded, err := decodeVNextReaderPreparedStatusResponse(body)
	if err != nil || !equalVNextReaderAcquiredAuthorization(
		decoded.Result.Prepared.Acquired, fixture.acquired) {
		t.Fatalf("round-trip PREPARED receipt = %#v/%v", decoded, err)
	}

	response.Acquired.Authorization.Root.PublicationLocator.
		PageRuns[0].FirstPage.OwnerID = "mutated-response"
	response.Result.Prepared.Acquired.Authorization.Root.PublicationLocator.
		PageRuns[0].FirstPage.OwnerID = "mutated-prepared"
	again, failure := fixture.service.StatusAndFence(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.request)
	if failure != nil || again.Acquired.Authorization.Root.PublicationLocator.
		PageRuns[0].FirstPage.OwnerID == "mutated-response" ||
		again.Result.Prepared.Acquired.Authorization.Root.PublicationLocator.
			PageRuns[0].FirstPage.OwnerID == "mutated-prepared" {
		t.Fatalf("returned status aliased retained state: %#v/%v", again, failure)
	}
}

func TestVNextReaderPreparedStatusAllPreStoreChecksAreDefinitive(t *testing.T) {
	wantCodes := map[string]vnextReaderPreparedStatusErrorCode{
		"non-URI principal":        vnextReaderPreparedStatusAuthorityError,
		"local target":             vnextReaderPreparedStatusIdentityError,
		"zero device digest":       vnextReaderPreparedStatusInvalidRequest,
		"zero publication digest":  vnextReaderPreparedStatusInvalidRequest,
		"authority request digest": vnextReaderPreparedStatusAuthorityError,
		"verifier rejection":       vnextReaderPreparedStatusAuthorityError,
		"proof substitution":       vnextReaderPreparedStatusAuthorityError,
		"pre-cancelled":            vnextReaderPreparedStatusUnavailable,
		"cancelled after verifier": vnextReaderPreparedStatusUnavailable,
	}
	tests := map[string]func(
		*testing.T,
		*vnextReaderPreparedStatusTestFixture,
	) (context.Context, string, vnextReaderPreparedStatusRequest){
		"non-URI principal": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			return context.Background(), "scheduler-current", fixture.request
		},
		"local target": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			request := fixture.request
			request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
			request.Acquired.Authorization.ExecutorID = "executor-other"
			return context.Background(), vnextReaderPreparedStatusTestPrincipal, request
		},
		"zero device digest": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			request := fixture.request
			request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
			request.Acquired.Authorization.Root.DeviceTableDigest = [sha256.Size]byte{}
			return context.Background(), vnextReaderPreparedStatusTestPrincipal, request
		},
		"zero publication digest": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			request := fixture.request
			request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
			request.Acquired.Authorization.Root.PublicationLocator.PublicationSHA256 =
				[sha256.Size]byte{}
			return context.Background(), vnextReaderPreparedStatusTestPrincipal, request
		},
		"authority request digest": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			request := fixture.request
			request.Authority.RequestDigest[0] ^= 0xff
			return context.Background(), vnextReaderPreparedStatusTestPrincipal, request
		},
		"verifier rejection": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			fixture.verifier.reject = errors.New("test current authority rejection")
			return context.Background(), vnextReaderPreparedStatusTestPrincipal,
				fixture.request
		},
		"proof substitution": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			fixture.verifier.mutateProof = func(
				proof *vnextReaderPreparedStatusAuthorityProof) {
				proof.SchedulerFenceRevision++
			}
			return context.Background(), vnextReaderPreparedStatusTestPrincipal,
				fixture.request
		},
		"pre-cancelled": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, vnextReaderPreparedStatusTestPrincipal, fixture.request
		},
		"cancelled after verifier": func(_ *testing.T, fixture *vnextReaderPreparedStatusTestFixture) (
			context.Context, string, vnextReaderPreparedStatusRequest) {
			ctx, cancel := context.WithCancel(context.Background())
			fixture.verifier.beforeReturn = cancel
			return ctx, vnextReaderPreparedStatusTestPrincipal, fixture.request
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newVNextReaderPreparedStatusTestFixture(t)
			ctx, principal, request := prepare(t, fixture)
			response, failure := fixture.service.StatusAndFence(
				ctx, principal, request)
			if failure == nil ||
				failure.Code != wantCodes[name] ||
				failure.Acceptance !=
					vnextReaderPreparedStatusDefinitelyNotAccepted ||
				!reflect.DeepEqual(response, vnextReaderPreparedStatusResponse{}) {
				t.Fatalf("pre-store failure response=%#v failure=%#v", response, failure)
			}
			if fixture.store.callCount() != 0 || len(fixture.inner.byID) != 0 ||
				fixture.inner.retainedBytes != 0 {
				t.Fatalf("pre-store rejection mutated/called store: calls=%d entries=%d bytes=%d",
					fixture.store.callCount(), len(fixture.inner.byID),
					fixture.inner.retainedBytes)
			}
		})
	}
}

func TestVNextReaderPreparedStatusMalformedSuccessfulStoreResultIsUnknown(
	t *testing.T,
) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	fixture.store.handler = func(vnextReaderAcquiredAuthorization) (
		vnextReaderPreparedStatusAndFenceResult, error) {
		return vnextReaderPreparedStatusAndFenceResult{
			State: "FUTURE_UNDOCUMENTED_STATE",
		}, nil
	}
	response, failure := fixture.service.StatusAndFence(
		context.Background(), vnextReaderPreparedStatusTestPrincipal,
		fixture.request)
	if failure == nil || failure.Code != vnextReaderPreparedStatusUnavailable ||
		failure.Acceptance != vnextReaderPreparedStatusAcceptanceUnknown ||
		!reflect.DeepEqual(response, vnextReaderPreparedStatusResponse{}) ||
		fixture.store.callCount() != 1 {
		t.Fatalf("malformed successful result response=%#v failure=%#v calls=%d",
			response, failure, fixture.store.callCount())
	}
}

func TestVNextReaderPreparedStatusStoreErrorsHaveSafeAcceptance(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		code       vnextReaderPreparedStatusErrorCode
		acceptance vnextReaderPreparedStatusAcceptance
	}{
		{"conflict", errVNextReaderAuthorizationConflict,
			vnextReaderPreparedStatusConflictError,
			vnextReaderPreparedStatusDefinitelyNotAccepted},
		{"entry capacity", errVNextReaderAuthorizationStoreFull,
			vnextReaderPreparedStatusCapacityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted},
		{"byte capacity", errVNextReaderAuthorizationStoreRetainedBytesFull,
			vnextReaderPreparedStatusCapacityError,
			vnextReaderPreparedStatusDefinitelyNotAccepted},
		{"undocumented", errors.New("future ambiguous store failure"),
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusAcceptanceUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextReaderPreparedStatusTestFixture(t)
			fixture.store.handler = func(vnextReaderAcquiredAuthorization) (
				vnextReaderPreparedStatusAndFenceResult, error) {
				return vnextReaderPreparedStatusAndFenceResult{}, test.err
			}
			_, failure := fixture.service.StatusAndFence(
				context.Background(),
				vnextReaderPreparedStatusTestPrincipal,
				fixture.request)
			if failure == nil || failure.Code != test.code ||
				failure.Acceptance != test.acceptance || fixture.store.callCount() != 1 {
				t.Fatalf("store error mapping=%#v calls=%d",
					failure, fixture.store.callCount())
			}
		})
	}
}

func TestVNextReaderPreparedStatusRealCapacityAndConflictAreAtomic(t *testing.T) {
	t.Run("entry capacity", func(t *testing.T) {
		inner, err := newVNextReaderAuthorizationStore(
			vnextReaderAuthorizationStoreTestConfig(1))
		if err != nil {
			t.Fatal(err)
		}
		seed := vnextReaderAuthorizationStoreTestAcquired("status-capacity-seed")
		if _, err := inner.StatusAndFencePreparedExact(seed); err != nil {
			t.Fatalf("seed capacity store: %v", err)
		}
		fixture := newVNextReaderPreparedStatusTestFixtureWithStore(t, inner)
		_, failure := fixture.service.StatusAndFence(
			context.Background(), vnextReaderPreparedStatusTestPrincipal,
			fixture.request)
		if failure == nil ||
			failure.Code != vnextReaderPreparedStatusCapacityError ||
			failure.Acceptance !=
				vnextReaderPreparedStatusDefinitelyNotAccepted ||
			len(inner.byID) != 1 {
			t.Fatalf("real capacity result=%#v entries=%d", failure, len(inner.byID))
		}
	})

	t.Run("identity conflict", func(t *testing.T) {
		fixture := newVNextReaderPreparedStatusTestFixture(t)
		conflict := cloneVNextReaderAcquiredAuthorization(fixture.acquired)
		conflict.Authorization.TargetContainerID = "different-target"
		if _, err := fixture.inner.StatusAndFencePreparedExact(conflict); err != nil {
			t.Fatalf("seed conflict: %v", err)
		}
		_, failure := fixture.service.StatusAndFence(
			context.Background(), vnextReaderPreparedStatusTestPrincipal,
			fixture.request)
		if failure == nil ||
			failure.Code != vnextReaderPreparedStatusConflictError ||
			failure.Acceptance !=
				vnextReaderPreparedStatusDefinitelyNotAccepted ||
			len(fixture.inner.byID) != 1 {
			t.Fatalf("real conflict result=%#v entries=%d",
				failure, len(fixture.inner.byID))
		}
	})
}

func TestVNextReaderPreparedStatusEncodeFailureIsUnknownAfterStore(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	fixture.rpc.encodeResponse = func(vnextReaderPreparedStatusResponse) (
		[]byte, error) {
		return nil, errors.New("test response encoder failure")
	}
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.frame)
	if body != nil || failure == nil ||
		failure.Code != vnextReaderPreparedStatusUnavailable ||
		failure.Acceptance != vnextReaderPreparedStatusAcceptanceUnknown ||
		fixture.store.callCount() != 1 || len(fixture.inner.byID) != 1 {
		t.Fatalf("post-store encode failure body=%q failure=%#v calls=%d entries=%d",
			body, failure, fixture.store.callCount(), len(fixture.inner.byID))
	}
}

func TestVNextReaderPreparedStatusConcurrentExactRequestsRemainOneDecision(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	const callers = 64
	start := make(chan struct{})
	failures := make(chan error, callers)
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			<-start
			body, failure := fixture.rpc.Handle(
				context.Background(),
				vnextReaderPreparedStatusTestPrincipal,
				fixture.frame)
			if failure != nil {
				failures <- failure
				return
			}
			response, err := decodeVNextReaderPreparedStatusResponse(body)
			if err != nil ||
				response.Result.State !=
					vnextReaderPreparedStatusNotPreparedFenced {
				failures <- fmt.Errorf("decode concurrent response: %#v/%v",
					response, err)
			}
		}()
	}
	close(start)
	wait.Wait()
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if fixture.store.callCount() != callers ||
		fixture.verifier.callCount() != callers || len(fixture.inner.byID) != 1 {
		t.Fatalf("concurrent verifier/store/entries=%d/%d/%d, want %d/%d/1",
			fixture.verifier.callCount(), fixture.store.callCount(),
			len(fixture.inner.byID), callers, callers)
	}
}

func TestVNextReaderPreparedStatusCodecIsExactAndBounded(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	decoded, err := decodeVNextReaderPreparedStatusRequest(fixture.frame)
	if err != nil ||
		!equalVNextReaderAcquiredAuthorization(decoded.Acquired, fixture.acquired) ||
		decoded.Authority != fixture.request.Authority {
		t.Fatalf("request round trip=%#v/%v", decoded, err)
	}
	canonical, err := marshalVNextReaderPreparedStatusRequest(decoded)
	if err != nil || !bytes.Equal(canonical, fixture.frame) {
		t.Fatalf("request JSON is not canonical: %v\n%s\n%s",
			err, fixture.frame, canonical)
	}

	var object map[string]json.RawMessage
	if err := json.Unmarshal(fixture.frame, &object); err != nil {
		t.Fatal(err)
	}
	missing := make(map[string]json.RawMessage, len(object)-1)
	for key, value := range object {
		if key != "operation" {
			missing[key] = value
		}
	}
	missingFrame, _ := json.Marshal(missing)
	unknown := append([]byte(nil), fixture.frame[:len(fixture.frame)-1]...)
	unknown = append(unknown, []byte(`,"unknown":1}`)...)
	duplicate := bytes.Replace(
		fixture.frame,
		[]byte(`"protocol":`),
		[]byte(`"protocol":"duplicate","protocol":`),
		1)
	wrongType := bytes.Replace(
		fixture.frame,
		[]byte(`"operation":"`+vnextReaderPreparedStatusOperation+`"`),
		[]byte(`"operation":1`),
		1)
	malformed := map[string][]byte{
		"empty":        nil,
		"null":         []byte(`null`),
		"unknown":      unknown,
		"missing":      missingFrame,
		"duplicate":    duplicate,
		"wrong type":   wrongType,
		"trailing":     append(append([]byte(nil), fixture.frame...), []byte(` {}`)...),
		"invalid utf8": []byte{0xff},
		"oversize":     make([]byte, vnextReaderPreparedStatusMaxFrameBytes+1),
	}
	for name, frame := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeVNextReaderPreparedStatusRequest(frame); err == nil {
				t.Fatal("malformed strict request was accepted")
			}
		})
	}

	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatal(failure)
	}
	if !bytes.Contains(body, []byte(`"prepared":null`)) {
		t.Fatalf("fenced response does not use exact null prepared marker: %s", body)
	}
	invalidFenced := bytes.Replace(body, []byte(`"prepared":null`),
		[]byte(`"prepared":{"preparationState":"PREPARED"}`), 1)
	if _, err := decodeVNextReaderPreparedStatusResponse(invalidFenced); err == nil {
		t.Fatal("fenced response with prepared marker was accepted")
	}
}

func TestVNextReaderPreparedStatusStrictResponseCodecRejectsMalformedShape(
	t *testing.T,
) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatal(failure)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	missing := make(map[string]json.RawMessage, len(object)-1)
	for key, value := range object {
		if key != "prepared" {
			missing[key] = value
		}
	}
	missingBody, _ := json.Marshal(missing)
	unknown := append([]byte(nil), body[:len(body)-1]...)
	unknown = append(unknown, []byte(`,"ownerProof":{}}`)...)
	duplicate := bytes.Replace(
		body,
		[]byte(`"state":`),
		[]byte(`"state":"PREPARED","state":`),
		1)
	wrongType := bytes.Replace(
		body,
		[]byte(`"localExecutorNodeId":"`),
		[]byte(`"localExecutorNodeId":1,"discarded":"`),
		1)
	malformed := map[string][]byte{
		"unknown":      unknown,
		"missing":      missingBody,
		"duplicate":    duplicate,
		"wrong type":   wrongType,
		"trailing":     append(append([]byte(nil), body...), []byte(` {}`)...),
		"invalid utf8": {0xff},
		"oversize":     make([]byte, vnextReaderPreparedStatusMaxFrameBytes+1),
	}
	for name, candidate := range malformed {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeVNextReaderPreparedStatusResponse(candidate); err == nil {
				t.Fatal("malformed strict response was accepted")
			}
		})
	}
}

func TestVNextReaderPreparedStatusIsPortableAndNeverResolvesDevice(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	request := fixture.request
	request.Acquired = cloneVNextReaderAcquiredAuthorization(request.Acquired)
	request.Acquired.Authorization.Root.PublicationLocator.
		PageRuns[0].FirstPage.DeviceUUID = "nonexistent-portable-device"
	request.Authority.RequestDigest =
		vnextReaderPreparedStatusCanonicalRequestDigest(request.Acquired)
	response, failure := fixture.service.StatusAndFence(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, request)
	if failure != nil ||
		response.Result.State != vnextReaderPreparedStatusNotPreparedFenced ||
		fixture.store.callCount() != 1 {
		t.Fatalf("read-free portable status response=%#v failure=%v calls=%d",
			response, failure, fixture.store.callCount())
	}
	serviceType := reflect.TypeOf(vnextReaderPreparedStatusService{})
	for index := 0; index < serviceType.NumField(); index++ {
		field := serviceType.Field(index)
		text := strings.ToLower(field.Name + " " + field.Type.String())
		for _, forbidden := range []string{
			"device", "dax", "mount", "resolver", "criu", "mapping", "active",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("status service field %s has forbidden runtime dependency",
					field.Name)
			}
		}
	}
}

func TestVNextReaderPreparedStatusConstructorFailsClosed(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	var typedNilStore *vnextReaderPreparedStatusTestStore
	var typedNilVerifier *vnextReaderPreparedStatusTestVerifier
	tests := []struct {
		name     string
		executor string
		cxld     string
		store    vnextReaderPreparedStatusStore
		verifier vnextReaderPreparedStatusAuthorityVerifier
	}{
		{"empty executor", "", "cxld-a", fixture.store, fixture.verifier},
		{"empty cxld", "executor-a", "", fixture.store, fixture.verifier},
		{"nil store", "executor-a", "cxld-a", nil, fixture.verifier},
		{"typed nil store", "executor-a", "cxld-a", typedNilStore, fixture.verifier},
		{"nil verifier", "executor-a", "cxld-a", fixture.store, nil},
		{"typed nil verifier", "executor-a", "cxld-a", fixture.store, typedNilVerifier},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, err := newVNextReaderPreparedStatusService(
				test.executor, test.cxld, test.store, test.verifier)
			if err == nil || service != nil {
				t.Fatalf("invalid constructor=%#v/%v", service, err)
			}
		})
	}
}

func vnextReaderPreparedStatusMaxAcquired() vnextReaderAcquiredAuthorization {
	value := strings.Repeat("<", cxlcheckpoint.MaxIdentityBytes)
	acquired := vnextReaderAuthorizationStoreTestAcquired(value)
	acquired.Authorization.CheckpointID = value
	acquired.Authorization.ExecutorID = value
	acquired.Authorization.CxldInstanceID = value
	acquired.Authorization.TargetContainerID = value
	acquired.Authorization.Root.RootID = value
	acquired.Authorization.Root.MMTemplateID = value
	acquired.Authorization.Root.PageMapID = value
	acquired.SchedulerID = value
	acquired.LastMutationID = value
	acquired.IssuedAtEpochMillis = 1
	acquired.ExpiresAtEpochMillis = 2
	runs := make([]cxlcheckpoint.PublicationPageRun, vnextReaderMaxLocatorRuns)
	for index := range runs {
		runs[index] = cxlcheckpoint.PublicationPageRun{
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            value,
				DeviceUUID:         value,
				AllocationRecordID: 1,
				DataPageIndex:      uint64(index * 2),
			},
			PageCount: 1,
		}
	}
	acquired.Authorization.Root.PublicationLocator.PageRuns = runs
	acquired.Authorization.Root.PublicationLocator.PublicationByteLength =
		uint64(len(runs)) * cxlcheckpoint.PageSize
	return acquired
}

func TestVNextReaderPreparedStatusMaximumPortableResponseFitsBound(t *testing.T) {
	acquired := vnextReaderPreparedStatusMaxAcquired()
	request := vnextReaderPreparedStatusTestRequest(acquired)
	request.Authority.SchedulerID = acquired.SchedulerID
	request.Authority.RequestDigest =
		vnextReaderPreparedStatusCanonicalRequestDigest(acquired)
	frame, err := marshalVNextReaderPreparedStatusRequest(request)
	if err != nil || len(frame) > vnextReaderPreparedStatusMaxFrameBytes {
		t.Fatalf("maximum valid request bytes=%d err=%v", len(frame), err)
	}
	decodedRequest, err := decodeVNextReaderPreparedStatusRequest(frame)
	if err != nil || !equalVNextReaderAcquiredAuthorization(
		decodedRequest.Acquired, acquired) ||
		decodedRequest.Authority != request.Authority {
		t.Fatalf("maximum valid request round trip changed identity: %v", err)
	}
	principalPrefix := "spiffe://test.example/status/"
	maxPrincipal := principalPrefix + strings.Repeat(
		"p", cxlcheckpoint.MaxIdentityBytes-len(principalPrefix))
	proofReceipt, err := vnextReaderPreparedStatusCanonicalAuthorityReceipt(
		maxPrincipal, request.Authority)
	if err != nil {
		t.Fatal(err)
	}
	base := vnextReaderPreparedStatusResponse{
		RequestDigest: request.Authority.RequestDigest,
		AuthorityProof: vnextReaderPreparedStatusAuthorityProof{
			AuthenticatedSchedulerPrincipal: maxPrincipal,
			SchedulerID:                     request.Authority.SchedulerID,
			SchedulerFenceRevision:          request.Authority.SchedulerFenceRevision,
			LeaderLeaseID:                   request.Authority.LeaderLeaseID,
			LeaderTermID:                    request.Authority.LeaderTermID,
			RequestDigest:                   request.Authority.RequestDigest,
			AuthorityReceipt:                proofReceipt,
		},
		LocalExecutorNodeID: acquired.Authorization.ExecutorID,
		LocalCxldInstanceID: acquired.Authorization.CxldInstanceID,
		Acquired:            acquired,
	}
	for _, state := range []vnextReaderPreparedStatusAndFenceState{
		vnextReaderPreparedStatusExactPrepared,
		vnextReaderPreparedStatusNotPreparedFenced,
	} {
		response := base
		response.Result.State = state
		if state == vnextReaderPreparedStatusExactPrepared {
			response.Result.Prepared = vnextReaderPreparedAuthorization{
				Acquired: acquired, PreparationState: vnextReaderPreparationPrepared,
			}
		}
		response.Receipt = vnextReaderPreparedStatusCanonicalResponseReceipt(response)
		body, err := marshalVNextReaderPreparedStatusResponse(response)
		if err != nil || len(body) > vnextReaderPreparedStatusMaxFrameBytes {
			t.Fatalf("maximum %s response bytes=%d err=%v", state, len(body), err)
		}
		if bytes.Count(body, []byte(`"restoreAuthorizationId"`)) != 1 {
			t.Fatalf("maximum %s response duplicated queried ACQUIRED", state)
		}
		decoded, err := decodeVNextReaderPreparedStatusResponse(body)
		if err != nil || decoded.Result.State != state ||
			!equalVNextReaderAcquiredAuthorization(decoded.Acquired, acquired) {
			t.Fatalf("maximum %s response round trip failed: %#v/%v",
				state, decoded, err)
		}
		if state == vnextReaderPreparedStatusExactPrepared &&
			!equalVNextReaderAcquiredAuthorization(
				decoded.Result.Prepared.Acquired, acquired) {
			t.Fatal("maximum PREPARED response did not reconstruct exact receipt")
		}
	}

	tooLong := cloneVNextReaderAcquiredAuthorization(acquired)
	tooLong.Authorization.CheckpointID += "x"
	tooLongRequest := vnextReaderPreparedStatusTestRequest(tooLong)
	if _, err := marshalVNextReaderPreparedStatusRequest(tooLongRequest); err == nil {
		t.Fatal("4097-byte identity was accepted")
	}
	tooManyRuns := cloneVNextReaderAcquiredAuthorization(acquired)
	tooManyRuns.Authorization.Root.PublicationLocator.PageRuns = append(
		tooManyRuns.Authorization.Root.PublicationLocator.PageRuns,
		cxlcheckpoint.PublicationPageRun{})
	tooManyRequest := vnextReaderPreparedStatusTestRequest(tooManyRuns)
	if _, err := marshalVNextReaderPreparedStatusRequest(tooManyRequest); err == nil {
		t.Fatal("257 locator runs were accepted")
	}
}

func TestVNextReaderPreparedStatusProtocolAndAPIHaveNoLifecycleAuthority(t *testing.T) {
	values := []string{
		vnextReaderPreparedStatusProtocol,
		vnextReaderPreparedStatusOperation,
		vnextReaderPreparedStatusALPN,
		vnextReaderPreparedStatusAuthorityDomain,
		vnextReaderPreparedStatusAuthoritySignatureDomain,
		vnextReaderPreparedStatusAuthorityReceiptDomain,
		vnextReaderPreparedStatusRequestDigestDomain,
		vnextReaderPreparedStatusResponseReceiptDomain,
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == vnextReaderPrepareProtocol ||
			value == vnextReaderPrepareOperation || value == vnextReaderPrepareALPN ||
			value == vnextReaderPrepareAuthorityDomain ||
			value == vnextReaderPrepareAuthoritySignatureDomain ||
			value == vnextReaderPrepareAuthorityReceiptDomain ||
			value == vnextReaderPrepareRequestDigestDomain ||
			value == vnextReaderPrepareReceiptDomain || value == vnextOwnerRPCProtocol ||
			value == vnextOwnerTLSALPN {
			t.Fatalf("STATUS_AND_FENCE reused PREPARE/Owner identity %q", value)
		}
		if _, duplicate := seen[value]; duplicate {
			t.Fatalf("STATUS_AND_FENCE reused its own domain %q", value)
		}
		seen[value] = struct{}{}
	}
	serviceType := reflect.TypeOf(vnextReaderPreparedStatusService{})
	if _, ok := serviceType.FieldByName("clock"); ok {
		t.Fatal("STATUS_AND_FENCE service unexpectedly has a wall clock")
	}
	for _, value := range []interface{}{
		vnextReaderPreparedStatusResponse{},
		vnextReaderPreparedStatusAndFenceResult{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			field := typeOf.Field(index)
			name := strings.ToLower(field.Name)
			for _, forbidden := range []string{
				"active", "mapping", "release", "reclaim", "readerlease", "criu", "dax",
			} {
				if strings.Contains(name, forbidden) {
					t.Fatalf("status API field %s carries lifecycle authority", field.Name)
				}
			}
		}
	}
}

func TestVNextReaderPreparedStatusConfiguredCxldTargetIsReceiptBound(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	response, failure := fixture.service.StatusAndFence(
		context.Background(), vnextReaderPreparedStatusTestPrincipal,
		fixture.request)
	if failure != nil {
		t.Fatal(failure)
	}
	original := response.Receipt
	response.LocalCxldInstanceID = "cxld-after-restart"
	if vnextReaderPreparedStatusCanonicalResponseReceipt(response) == original {
		t.Fatal("response receipt did not bind the configured cxld target ID")
	}
	if err := validateVNextReaderPreparedStatusResponse(response); err == nil {
		t.Fatal("response with a different configured cxld target was accepted")
	}
	// This deliberately does not claim restart safety. Reusing the same
	// configured ID after restart is not detectable, because this slice has no
	// durable or process-start incarnation field. Therefore no response state
	// can serve as release/reclaim evidence across restart.
}

func TestVNextReaderPreparedStatusResponseWireRejectsReceiptSubstitution(t *testing.T) {
	fixture := newVNextReaderPreparedStatusTestFixture(t)
	body, failure := fixture.rpc.Handle(
		context.Background(), vnextReaderPreparedStatusTestPrincipal, fixture.frame)
	if failure != nil {
		t.Fatal(failure)
	}
	var wire vnextReaderPreparedStatusResponseWire
	if err := json.Unmarshal(body, &wire); err != nil {
		t.Fatal(err)
	}
	receipt, err := hex.DecodeString(wire.Receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt[0] ^= 0xff
	wire.Receipt = hex.EncodeToString(receipt)
	mutated, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeVNextReaderPreparedStatusResponse(mutated); err == nil {
		t.Fatal("response receipt substitution was accepted")
	}
}
