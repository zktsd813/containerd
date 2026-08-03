package main

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func vnextReaderFirstReadEmptyStore(
	t *testing.T,
	request vnextReaderActivatedRestoreRequest,
) *vnextReaderActivationStore {
	t.Helper()
	prepared, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("construct empty first-read PREPARED store: %v", err)
	}
	authorization := request.Activation.Request.Acquired.Authorization
	store, err := newVNextReaderActivationStore(
		vnextReaderActivationStoreTestConfig(2),
		authorization.ExecutorID,
		authorization.CxldLogicalID,
		authorization.CxldProcessIncarnationID,
		prepared)
	if err != nil {
		t.Fatalf("construct empty first-read activation store: %v", err)
	}
	return store
}

func vnextReaderFirstReadPendingStore(
	t *testing.T,
	request vnextReaderActivatedRestoreRequest,
) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
	t.Helper()
	prepared, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("construct PENDING first-read PREPARED store: %v", err)
	}
	acquired := cloneVNextReaderAcquiredAuthorization(
		request.Activation.Request.Acquired)
	if _, _, err := prepared.Prepare(
		acquired, acquired.IssuedAtEpochMillis); err != nil {
		t.Fatalf("prepare PENDING first-read authority: %v", err)
	}
	authorization := acquired.Authorization
	store, err := newVNextReaderActivationStore(
		vnextReaderActivationStoreTestConfig(2),
		authorization.ExecutorID,
		authorization.CxldLogicalID,
		authorization.CxldProcessIncarnationID,
		prepared)
	if err != nil {
		t.Fatalf("construct PENDING first-read activation store: %v", err)
	}
	identity := cloneVNextReaderActivationRequestIdentity(
		request.Activation.Request)
	pending, _, err := store.Propose(
		identity, request.Activation.ActivatedAtEpochMillis)
	if err != nil {
		t.Fatalf("propose PENDING first-read activation: %v", err)
	}
	return store, vnextReaderActivatedRestoreRequest{
		Request:    request.Request,
		Activation: pending,
	}
}

func vnextReaderFirstReadNewReader(
	t *testing.T,
	fixture *vnextReaderTestFixture,
	store *vnextReaderActivationStore,
	source vnextReaderDAXSource,
	runner vnextReaderRunner,
) *vnextAuthorizedReader {
	t.Helper()
	reader, err := newVNextAuthorizedReader(
		fixture.directory, store, source, runner)
	if err != nil {
		t.Fatalf("construct ACTIVE_ARMED first-read reader: %v", err)
	}
	return reader
}

func TestVNextReaderFirstReadRejectsInactiveMissingAndSubstitutedWithoutSourceCall(
	t *testing.T,
) {
	tests := []struct {
		name    string
		arrange func(
			*testing.T,
			*vnextReaderTestFixture,
			*vnextReaderActivationStore,
			vnextReaderActivatedRestoreRequest,
		) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest)
	}{
		{
			name: "PENDING",
			arrange: func(
				t *testing.T,
				_ *vnextReaderTestFixture,
				_ *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				return vnextReaderFirstReadPendingStore(t, request)
			},
		},
		{
			name: "absent",
			arrange: func(
				t *testing.T,
				_ *vnextReaderTestFixture,
				_ *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				return vnextReaderFirstReadEmptyStore(t, request), request
			},
		},
		{
			name: "NOT_FOUND tombstone",
			arrange: func(
				t *testing.T,
				_ *vnextReaderTestFixture,
				_ *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				store := vnextReaderFirstReadEmptyStore(t, request)
				status, err := store.Status(request.Activation.Request)
				if err != nil ||
					status.Disposition != vnextReaderActivationStatusNotFoundFenced {
					t.Fatalf("install first-read NOT_FOUND tombstone: status=%#v err=%v",
						status, err)
				}
				return store, request
			},
		},
		{
			name: "portable target substitution",
			arrange: func(
				_ *testing.T,
				_ *vnextReaderTestFixture,
				store *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				request.Request.TargetContainerID = "substituted-target"
				return store, request
			},
		},
		{
			name: "historical root substitution",
			arrange: func(
				_ *testing.T,
				_ *vnextReaderTestFixture,
				store *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				request.Activation = cloneVNextReaderActivationIntent(request.Activation)
				request.Activation.Request.Acquired.Authorization.Root.RootVersion++
				return store, request
			},
		},
		{
			name: "process incarnation substitution",
			arrange: func(
				_ *testing.T,
				_ *vnextReaderTestFixture,
				store *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				request.Activation = cloneVNextReaderActivationIntent(request.Activation)
				request.Activation.Request.Acquired.Authorization.
					CxldProcessIncarnationID[0] ^= 0xff
				return store, request
			},
		},
		{
			name: "mapping substitution",
			arrange: func(
				_ *testing.T,
				_ *vnextReaderTestFixture,
				store *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				request.Activation = cloneVNextReaderActivationIntent(request.Activation)
				request.Activation.MappingID = "substituted-mapping"
				return store, request
			},
		},
		{
			name: "receipt substitution",
			arrange: func(
				_ *testing.T,
				_ *vnextReaderTestFixture,
				store *vnextReaderActivationStore,
				request vnextReaderActivatedRestoreRequest,
			) (*vnextReaderActivationStore, vnextReaderActivatedRestoreRequest) {
				request.Activation = cloneVNextReaderActivationIntent(request.Activation)
				request.Activation.CxldReceipt[0] ^= 0xff
				return store, request
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVNextReaderTestFixture(t)
			armedStore, activated := vnextReaderArmTestRestore(t, fixture)
			store, request := test.arrange(t, fixture, armedStore, activated)
			source := &vnextReaderCountingSource{
				// The regular-file source is a unit-test adapter only. This
				// test makes no devdax, CRIU, QEMU, or live-CXL claim.
				delegate: vnextRegularFileReaderDAXSource{},
			}
			runner := &vnextReaderTestRunner{}
			reader := vnextReaderFirstReadNewReader(
				t, fixture, store, source, runner)
			if _, err := reader.Restore(context.Background(), request); err == nil {
				t.Fatal("first-read boundary accepted inactive, missing, or substituted evidence")
			}
			descriptors, contents := source.counts()
			if descriptors != 0 || contents != 0 || runner.calls != 0 {
				t.Fatalf(
					"rejected first-read request reached source/runner: descriptor=%d content=%d runner=%d",
					descriptors, contents, runner.calls)
			}
		})
	}
}

func TestVNextReaderFirstReadExactActiveArmedIsOneShot(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	store, request := vnextReaderArmTestRestore(t, fixture)
	source := &vnextReaderCountingSource{delegate: vnextRegularFileReaderDAXSource{}}
	runner := &vnextReaderTestRunner{}
	reader := vnextReaderFirstReadNewReader(t, fixture, store, source, runner)

	if _, err := reader.Restore(context.Background(), request); err != nil {
		t.Fatalf("restore exact ACTIVE_ARMED publication: %v", err)
	}
	descriptors, contents := source.counts()
	if descriptors != 4 || contents != 2 || runner.calls != 1 {
		t.Fatalf("first restore source/runner calls=%d/%d/%d, want 4/2/1",
			descriptors, contents, runner.calls)
	}
	if _, err := reader.Restore(context.Background(), request); !errors.Is(
		err, errVNextReaderFirstReadAlreadyClaimed) {
		t.Fatalf("exact replay error=%v, want one-shot claim rejection", err)
	}
	afterDescriptors, afterContents := source.counts()
	if afterDescriptors != descriptors || afterContents != contents || runner.calls != 1 {
		t.Fatalf("replay added source/runner calls=%d/%d/%d, want %d/%d/1",
			afterDescriptors, afterContents, runner.calls, descriptors, contents)
	}
}

func TestVNextReaderFirstReadConcurrentReplayHasExactlyOneWinner(t *testing.T) {
	const callers = 64
	fixture := newVNextReaderTestFixture(t)
	store, request := vnextReaderArmTestRestore(t, fixture)
	source := &vnextReaderCountingSource{delegate: vnextRegularFileReaderDAXSource{}}
	runner := &vnextReaderTestRunner{}
	reader := vnextReaderFirstReadNewReader(t, fixture, store, source, runner)

	start := make(chan struct{})
	var successes int64
	var claimed int64
	var unexpected int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			<-start
			_, err := reader.Restore(context.Background(), request)
			switch {
			case err == nil:
				atomic.AddInt64(&successes, 1)
			case errors.Is(err, errVNextReaderFirstReadAlreadyClaimed):
				atomic.AddInt64(&claimed, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}()
	}
	close(start)
	wait.Wait()

	if successes != 1 || claimed != callers-1 || unexpected != 0 {
		t.Fatalf("concurrent first-read results success=%d claimed=%d unexpected=%d",
			successes, claimed, unexpected)
	}
	descriptors, contents := source.counts()
	if descriptors != 4 || contents != 2 || runner.calls != 1 {
		t.Fatalf("concurrent replay source/runner calls=%d/%d/%d, want 4/2/1",
			descriptors, contents, runner.calls)
	}
}

type vnextReaderFirstReadDescriptorErrorSource struct {
	err error
}

func (source vnextReaderFirstReadDescriptorErrorSource) ReadVNextDescriptor(
	context.Context,
	vnextLocalDAXBinding,
	uint64,
) (vnextPageDescriptor, error) {
	return vnextPageDescriptor{}, source.err
}

func (vnextReaderFirstReadDescriptorErrorSource) ReadVNextContentPage(
	context.Context,
	vnextLocalDAXBinding,
	uint64,
) ([]byte, error) {
	return nil, errors.New("unexpected content read after descriptor failure")
}

func TestVNextReaderFirstReadClaimSurvivesSourceAndRunnerFailure(t *testing.T) {
	t.Run("source failure", func(t *testing.T) {
		fixture := newVNextReaderTestFixture(t)
		store, request := vnextReaderArmTestRestore(t, fixture)
		failure := errors.New("injected first descriptor failure")
		source := &vnextReaderCountingSource{
			delegate: vnextReaderFirstReadDescriptorErrorSource{err: failure},
		}
		runner := &vnextReaderTestRunner{}
		reader := vnextReaderFirstReadNewReader(t, fixture, store, source, runner)

		if _, err := reader.Restore(context.Background(), request); !errors.Is(err, failure) {
			t.Fatalf("source-failing restore error=%v, want injected failure", err)
		}
		descriptors, contents := source.counts()
		if descriptors != 1 || contents != 0 || runner.calls != 0 {
			t.Fatalf("source failure calls=%d/%d/%d, want 1/0/0",
				descriptors, contents, runner.calls)
		}
		if _, err := reader.Restore(context.Background(), request); !errors.Is(
			err, errVNextReaderFirstReadAlreadyClaimed) {
			t.Fatalf("source-failure replay error=%v, want claimed", err)
		}
		afterDescriptors, afterContents := source.counts()
		if afterDescriptors != descriptors || afterContents != contents || runner.calls != 0 {
			t.Fatalf("source-failure replay added calls=%d/%d/%d",
				afterDescriptors, afterContents, runner.calls)
		}
	})

	t.Run("runner failure", func(t *testing.T) {
		fixture := newVNextReaderTestFixture(t)
		store, request := vnextReaderArmTestRestore(t, fixture)
		source := &vnextReaderCountingSource{delegate: vnextRegularFileReaderDAXSource{}}
		failure := errors.New("injected runner failure")
		runner := &vnextReaderTestRunner{err: failure}
		reader := vnextReaderFirstReadNewReader(t, fixture, store, source, runner)

		if _, err := reader.Restore(context.Background(), request); !errors.Is(err, failure) {
			t.Fatalf("runner-failing restore error=%v, want injected failure", err)
		}
		descriptors, contents := source.counts()
		if descriptors != 4 || contents != 2 || runner.calls != 1 {
			t.Fatalf("runner failure calls=%d/%d/%d, want 4/2/1",
				descriptors, contents, runner.calls)
		}
		if _, err := reader.Restore(context.Background(), request); !errors.Is(
			err, errVNextReaderFirstReadAlreadyClaimed) {
			t.Fatalf("runner-failure replay error=%v, want claimed", err)
		}
		afterDescriptors, afterContents := source.counts()
		if afterDescriptors != descriptors || afterContents != contents || runner.calls != 1 {
			t.Fatalf("runner-failure replay added calls=%d/%d/%d",
				afterDescriptors, afterContents, runner.calls)
		}
	})
}

func TestVNextReaderFirstReadShutdownClosesNewAndPreparedAdmission(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	store, request := vnextReaderArmTestRestore(t, fixture)
	_, permit, err := store.authorizeFirstRead(request)
	if err != nil {
		t.Fatalf("prepare read-free first-read permit before shutdown: %v", err)
	}
	store.CloseFirstReadAdmission()
	store.CloseFirstReadAdmission()
	if err := permit.consume(); !errors.Is(err, errVNextReaderFirstReadAdmissionClosed) {
		t.Fatalf("pre-shutdown permit consume error=%v, want closed admission", err)
	}

	source := &vnextReaderCountingSource{delegate: vnextRegularFileReaderDAXSource{}}
	runner := &vnextReaderTestRunner{}
	reader := vnextReaderFirstReadNewReader(t, fixture, store, source, runner)
	if _, err := reader.Restore(context.Background(), request); !errors.Is(
		err, errVNextReaderFirstReadAdmissionClosed) {
		t.Fatalf("post-shutdown restore error=%v, want closed admission", err)
	}
	descriptors, contents := source.counts()
	if descriptors != 0 || contents != 0 || runner.calls != 0 {
		t.Fatalf("closed admission reached source/runner=%d/%d/%d",
			descriptors, contents, runner.calls)
	}
}

func TestVNextReaderFirstReadPermitRetainsDeepClone(t *testing.T) {
	fixture := newVNextReaderTestFixture(t)
	store, request := vnextReaderArmTestRestore(t, fixture)
	authorization, permit, err := store.authorizeFirstRead(request)
	if err != nil {
		t.Fatalf("authorize read-free first-read permit: %v", err)
	}
	wantOwner := authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID
	wantMapping := request.Activation.MappingID

	request.Activation.Request.Acquired.Authorization.Root.
		PublicationLocator.PageRuns[0].FirstPage.OwnerID = "mutated-caller-owner"
	request.Activation.MappingID = "mutated-caller-mapping"
	authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
		"mutated-returned-authorization"

	if err := permit.consume(); err != nil {
		t.Fatalf("consume permit after caller mutation: %v", err)
	}
	status, err := store.Status(permit.intent.Request)
	if err != nil || status.Intent == nil {
		t.Fatalf("read retained activation after permit consume: status=%#v err=%v",
			status, err)
	}
	if got := status.Intent.Request.Acquired.Authorization.Root.
		PublicationLocator.PageRuns[0].FirstPage.OwnerID; got != wantOwner {
		t.Fatalf("caller mutation changed retained Owner ID %q, want %q", got, wantOwner)
	}
	if status.Intent.MappingID != wantMapping {
		t.Fatalf("caller mutation changed retained mapping ID %q, want %q",
			status.Intent.MappingID, wantMapping)
	}
	if err := permit.consume(); !errors.Is(err, errVNextReaderFirstReadAlreadyClaimed) {
		t.Fatalf("second permit consume error=%v, want claimed", err)
	}
}
