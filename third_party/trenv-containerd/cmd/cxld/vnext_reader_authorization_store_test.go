package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unsafe"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

func vnextReaderAuthorizationStoreTestConfig(
	maxEntries int,
) vnextReaderAuthorizationStoreConfig {
	return vnextReaderAuthorizationStoreConfig{
		MaxEntries:       maxEntries,
		MaxRetainedBytes: vnextReaderAuthorizationStoreMaxRetainedBytes,
	}
}

func vnextReaderAuthorizationStoreTestAcquired(
	authorizationID string,
) vnextReaderAcquiredAuthorization {
	publicationDigest := sha256.Sum256([]byte("authorization-store-publication"))
	deviceDigest := sha256.Sum256([]byte("authorization-store-devices"))
	processIncarnation := vnextReaderProcessIncarnation(
		sha256.Sum256([]byte("authorization-store-process-incarnation")))
	return vnextReaderAcquiredAuthorization{
		Authorization: vnextReaderAuthorization{
			RestoreAuthorizationID:                   authorizationID,
			CheckpointID:                             "checkpoint-a",
			ExecutorID:                               "executor-a",
			CxldLogicalID:                            "reader-cxld-a",
			CxldProcessIncarnationID:                 processIncarnation,
			ReaderInitialRegistrationCatalogRevision: 23,
			TargetContainerID:                        "target-container-a",
			Root: vnextReaderTrustedRoot{
				RootID:            "root-a",
				RootVersion:       7,
				MMTemplateID:      "mm-template-a",
				PageMapID:         "page-map-a",
				PageMapVersion:    11,
				DeviceTableDigest: deviceDigest,
				ContractID:        cxlcheckpoint.V6CompatibilityID,
				PublicationLocator: vnextReaderPublicationLocator{
					PublicationByteLength: cxlcheckpoint.PageSize,
					PublicationSHA256:     publicationDigest,
					PageRuns: []cxlcheckpoint.PublicationPageRun{{
						FirstPage: cxlcheckpoint.PageID{
							OwnerID:            "owner-a",
							DeviceUUID:         "device-a",
							AllocationRecordID: 13,
							DataPageIndex:      17,
						},
						PageCount: 1,
					}},
				},
			},
		},
		SchedulerID:            "scheduler-a",
		SchedulerFenceRevision: 19,
		IssuedAtEpochMillis:    100,
		ExpiresAtEpochMillis:   200,
		CatalogState:           vnextReaderCatalogAuthorizationAcquired,
		LastMutationID:         authorizationID,
	}
}

func TestVNextReaderAuthorizationStoreExactInstallAndReplay(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-a")
	want := cloneVNextReaderAcquiredAuthorization(acquired)

	prepared, disposition, err := store.Prepare(acquired, 150)
	if err != nil || disposition != vnextReaderPreparationInstalled {
		t.Fatalf("first prepare: prepared=%#v disposition=%v err=%v", prepared, disposition, err)
	}
	if prepared.PreparationState != vnextReaderPreparationPrepared ||
		prepared.Acquired.CatalogState != vnextReaderCatalogAuthorizationAcquired ||
		prepared.Acquired.LastMutationID != want.LastMutationID ||
		!equalVNextReaderAcquiredAuthorization(prepared.Acquired, want) {
		t.Fatalf("first prepared receipt lost exact identity: %#v", prepared)
	}

	// Neither an input slice nor a returned receipt may alias the stored root.
	acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID = "mutated-input"
	prepared.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID = "mutated-result"
	lookedUp, err := store.LookupPreparedExact(want, 151)
	if err != nil {
		t.Fatalf("lookup exact prepared receipt: %v", err)
	}
	if !equalVNextReaderAcquiredAuthorization(lookedUp.Acquired, want) {
		t.Fatalf("stored receipt was mutated through an alias: %#v", lookedUp)
	}
	lookedUp.Acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID =
		"mutated-lookup"
	clonedLookup, err := store.LookupPreparedExact(want, 151)
	if err != nil || !equalVNextReaderAcquiredAuthorization(clonedLookup.Acquired, want) {
		t.Fatalf("lookup did not return an isolated clone: %#v / %v", clonedLookup, err)
	}

	second, disposition, err := store.Prepare(want, 152)
	if err != nil || disposition != vnextReaderPreparationExactReplay {
		t.Fatalf("exact replay: prepared=%#v disposition=%v err=%v", second, disposition, err)
	}
	if second.PreparationState != vnextReaderPreparationPrepared ||
		!equalVNextReaderAcquiredAuthorization(second.Acquired, want) {
		t.Fatalf("exact replay changed prepared receipt: %#v", second)
	}
}

func TestVNextReaderAuthorizationStoreRejectsConflictingReplay(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-conflict")
	if _, _, err := store.Prepare(acquired, 150); err != nil {
		t.Fatalf("seed prepared authorization: %v", err)
	}

	conflict := cloneVNextReaderAcquiredAuthorization(acquired)
	conflict.Authorization.TargetContainerID = "different-target"
	if _, _, err := store.Prepare(conflict, 150); !errors.Is(err, errVNextReaderAuthorizationConflict) {
		t.Fatalf("conflicting replay error = %v, want conflict", err)
	}
	lookedUp, err := store.LookupPreparedExact(acquired, 150)
	if err != nil || !equalVNextReaderAcquiredAuthorization(lookedUp.Acquired, acquired) {
		t.Fatalf("conflict changed original receipt: %#v / %v", lookedUp, err)
	}
}

func TestVNextReaderAuthorizationStoreLookupRequiresExactIdentity(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-lookup")
	if _, _, err := store.Prepare(acquired, 150); err != nil {
		t.Fatalf("prepare authorization: %v", err)
	}

	for name, mutate := range map[string]func(*vnextReaderAcquiredAuthorization){
		"scheduler": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.SchedulerID = "different-scheduler"
		},
		"fence": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.SchedulerFenceRevision++
		},
		"executor": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.ExecutorID = "different-executor"
		},
		"reader cxld": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.CxldLogicalID = "different-cxld"
		},
		"reader process incarnation": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.CxldProcessIncarnationID[0] ^= 0xff
		},
		"reader birth revision": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.ReaderInitialRegistrationCatalogRevision++
		},
		"target": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.TargetContainerID = "different-target"
		},
		"root": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.RootVersion++
		},
		"root ID": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.RootID = "different-root"
		},
		"locator": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DataPageIndex++
		},
		"locator hash": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.PublicationLocator.PublicationSHA256[0] ^= 0xff
		},
		"issue time": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.IssuedAtEpochMillis--
		},
		"expiry": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.ExpiresAtEpochMillis++
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneVNextReaderAcquiredAuthorization(acquired)
			mutate(&candidate)
			if _, err := store.LookupPreparedExact(candidate, 150); !errors.Is(err, errVNextReaderAuthorizationIdentityMismatch) {
				t.Fatalf("lookup wrong %s error = %v, want exact-identity rejection", name, err)
			}
		})
	}

	missing := cloneVNextReaderAcquiredAuthorization(acquired)
	missing.Authorization.RestoreAuthorizationID = "authorization-missing"
	missing.LastMutationID = missing.Authorization.RestoreAuthorizationID
	if _, err := store.LookupPreparedExact(missing, 150); !errors.Is(err, errVNextReaderAuthorizationNotFound) {
		t.Fatalf("missing authorization error = %v, want not found", err)
	}
}

func TestVNextReaderAuthorizationStoreValidityIntervalIsHalfOpen(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(3))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	issued := vnextReaderAuthorizationStoreTestAcquired("authorization-issued-boundary")
	if _, _, err := store.Prepare(issued, issued.IssuedAtEpochMillis); err != nil {
		t.Fatalf("issue-time boundary was rejected: %v", err)
	}

	future := vnextReaderAuthorizationStoreTestAcquired("authorization-future")
	if _, _, err := store.Prepare(future, future.IssuedAtEpochMillis-1); err == nil ||
		!strings.Contains(err.Error(), "future") {
		t.Fatalf("future authorization error = %v, want future rejection", err)
	}
	expired := vnextReaderAuthorizationStoreTestAcquired("authorization-expired")
	if _, _, err := store.Prepare(expired, expired.ExpiresAtEpochMillis); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expiry boundary error = %v, want expired rejection", err)
	}
	invalid := vnextReaderAuthorizationStoreTestAcquired("authorization-invalid-time")
	invalid.ExpiresAtEpochMillis = invalid.IssuedAtEpochMillis
	if _, _, err := store.Prepare(invalid, invalid.IssuedAtEpochMillis); err == nil ||
		!strings.Contains(err.Error(), "interval") {
		t.Fatalf("invalid interval error = %v, want interval rejection", err)
	}
}

func TestVNextReaderAuthorizationStoreIdentityAndNumericBounds(t *testing.T) {
	for _, capacity := range []int{1, vnextReaderAuthorizationStoreMaxEntries} {
		if _, err := newVNextReaderAuthorizationStore(
			vnextReaderAuthorizationStoreTestConfig(capacity)); err != nil {
			t.Fatalf("capacity %d was rejected: %v", capacity, err)
		}
	}
	for _, capacity := range []int{0, -1, vnextReaderAuthorizationStoreMaxEntries + 1} {
		if _, err := newVNextReaderAuthorizationStore(
			vnextReaderAuthorizationStoreTestConfig(capacity)); err == nil {
			t.Fatalf("capacity %d was accepted", capacity)
		}
	}
	for _, capacity := range []uint64{1, vnextReaderAuthorizationStoreMaxRetainedBytes} {
		if _, err := newVNextReaderAuthorizationStore(vnextReaderAuthorizationStoreConfig{
			MaxEntries:       1,
			MaxRetainedBytes: capacity,
		}); err != nil {
			t.Fatalf("retained-byte capacity %d was rejected: %v", capacity, err)
		}
	}
	for _, capacity := range []uint64{0, vnextReaderAuthorizationStoreMaxRetainedBytes + 1} {
		if _, err := newVNextReaderAuthorizationStore(vnextReaderAuthorizationStoreConfig{
			MaxEntries:       1,
			MaxRetainedBytes: capacity,
		}); err == nil {
			t.Fatalf("retained-byte capacity %d was accepted", capacity)
		}
	}

	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(4))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	exactIdentity := vnextReaderAuthorizationStoreTestAcquired("authorization-exact-identity")
	exactIdentity.SchedulerID = strings.Repeat("s", cxlcheckpoint.MaxIdentityBytes)
	exactIdentity.SchedulerFenceRevision = cxlcheckpoint.MaxSignedLong
	exactIdentity.Authorization.ReaderInitialRegistrationCatalogRevision =
		cxlcheckpoint.MaxSignedLong
	if _, _, err := store.Prepare(exactIdentity, 150); err != nil {
		t.Fatalf("exact identity/fence bounds were rejected: %v", err)
	}

	tooLong := vnextReaderAuthorizationStoreTestAcquired("authorization-long-identity")
	tooLong.SchedulerID = strings.Repeat("s", cxlcheckpoint.MaxIdentityBytes+1)
	if _, _, err := store.Prepare(tooLong, 150); err == nil {
		t.Fatal("overlong Scheduler identity was accepted")
	}
	tooLargeFence := vnextReaderAuthorizationStoreTestAcquired("authorization-large-fence")
	tooLargeFence.SchedulerFenceRevision = cxlcheckpoint.MaxSignedLong + 1
	if _, _, err := store.Prepare(tooLargeFence, 150); err == nil {
		t.Fatal("Scheduler fence above signed ABI was accepted")
	}
	zeroIncarnation := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-zero-incarnation")
	zeroIncarnation.Authorization.CxldProcessIncarnationID =
		vnextReaderProcessIncarnation{}
	if _, _, err := store.Prepare(zeroIncarnation, 150); err == nil {
		t.Fatal("zero process incarnation was accepted")
	}
	zeroBirthRevision := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-zero-birth-revision")
	zeroBirthRevision.Authorization.ReaderInitialRegistrationCatalogRevision = 0
	if _, _, err := store.Prepare(zeroBirthRevision, 150); err == nil {
		t.Fatal("zero initial registration revision was accepted")
	}
	tooLargeBirthRevision := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-large-birth-revision")
	tooLargeBirthRevision.Authorization.ReaderInitialRegistrationCatalogRevision =
		cxlcheckpoint.MaxSignedLong + 1
	if _, _, err := store.Prepare(tooLargeBirthRevision, 150); err == nil {
		t.Fatal("initial registration revision above signed ABI was accepted")
	}
	missing := vnextReaderAuthorizationStoreTestAcquired("authorization-missing-identity")
	missing.LastMutationID = ""
	if _, _, err := store.Prepare(missing, 150); err == nil {
		t.Fatal("missing last mutation identity was accepted")
	}
	mismatchedMutation := vnextReaderAuthorizationStoreTestAcquired(
		"authorization-mismatched-mutation")
	mismatchedMutation.LastMutationID = "different-authorization-mutation"
	if _, _, err := store.Prepare(mismatchedMutation, 150); err == nil ||
		!strings.Contains(err.Error(), "does not match the authorization ID") {
		t.Fatalf("mismatched last mutation error = %v", err)
	}
	active := vnextReaderAuthorizationStoreTestAcquired("authorization-active")
	active.CatalogState = vnextReaderCatalogAuthorizationState("ACTIVE")
	if _, _, err := store.Prepare(active, 150); err == nil ||
		!strings.Contains(err.Error(), "not ACQUIRED") {
		t.Fatalf("non-ACQUIRED state error = %v", err)
	}
}

func TestVNextReaderAuthorizationStoreLocatorRunBound(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(2))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	accepted := vnextReaderAuthorizationStoreTestWithRuns(
		"authorization-256-runs", vnextReaderMaxLocatorRuns)
	if _, _, err := store.Prepare(accepted, 150); err != nil {
		t.Fatalf("prepare %d locator runs: %v", vnextReaderMaxLocatorRuns, err)
	}
	rejected := vnextReaderAuthorizationStoreTestWithRuns(
		"authorization-257-runs", vnextReaderMaxLocatorRuns+1)
	if _, _, err := store.Prepare(rejected, 150); err == nil ||
		!strings.Contains(err.Error(), "run count") {
		t.Fatalf("prepare %d locator runs error = %v, want run-count rejection",
			vnextReaderMaxLocatorRuns+1, err)
	}
}

func TestVNextReaderAuthorizationStoreRejectsInvalidPortableLocator(t *testing.T) {
	for name, mutate := range map[string]func(*vnextReaderAcquiredAuthorization){
		"path device": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID = "/dev/dax0.0"
		},
		"coverage": func(candidate *vnextReaderAcquiredAuthorization) {
			candidate.Authorization.Root.PublicationLocator.PublicationByteLength++
		},
		"not coalesced": func(candidate *vnextReaderAcquiredAuthorization) {
			first := candidate.Authorization.Root.PublicationLocator.PageRuns[0]
			candidate.Authorization.Root.PublicationLocator.PublicationByteLength = 2 * cxlcheckpoint.PageSize
			candidate.Authorization.Root.PublicationLocator.PageRuns = append(
				candidate.Authorization.Root.PublicationLocator.PageRuns,
				cxlcheckpoint.PublicationPageRun{
					FirstPage: cxlcheckpoint.PageID{
						OwnerID:            first.FirstPage.OwnerID,
						DeviceUUID:         first.FirstPage.DeviceUUID,
						AllocationRecordID: first.FirstPage.AllocationRecordID,
						DataPageIndex:      first.FirstPage.DataPageIndex + 1,
					},
					PageCount: 1,
				})
		},
		"physical overlap": func(candidate *vnextReaderAcquiredAuthorization) {
			first := candidate.Authorization.Root.PublicationLocator.PageRuns[0]
			candidate.Authorization.Root.PublicationLocator.PublicationByteLength = 2 * cxlcheckpoint.PageSize
			candidate.Authorization.Root.PublicationLocator.PageRuns = append(
				candidate.Authorization.Root.PublicationLocator.PageRuns,
				cxlcheckpoint.PublicationPageRun{
					FirstPage: cxlcheckpoint.PageID{
						OwnerID:            first.FirstPage.OwnerID,
						DeviceUUID:         first.FirstPage.DeviceUUID,
						AllocationRecordID: first.FirstPage.AllocationRecordID + 1,
						DataPageIndex:      first.FirstPage.DataPageIndex,
					},
					PageCount: 1,
				})
		},
	} {
		t.Run(name, func(t *testing.T) {
			store, err := newVNextReaderAuthorizationStore(
				vnextReaderAuthorizationStoreTestConfig(1))
			if err != nil {
				t.Fatalf("new store: %v", err)
			}
			candidate := vnextReaderAuthorizationStoreTestAcquired("authorization-invalid-locator")
			mutate(&candidate)
			if _, _, err := store.Prepare(candidate, 150); err == nil {
				t.Fatalf("invalid locator %q was accepted", name)
			}
		})
	}
}

func TestVNextReaderAuthorizationStoreCapacityFailsClosedWithoutEviction(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	first := vnextReaderAuthorizationStoreTestAcquired("authorization-capacity-a")
	if _, disposition, err := store.Prepare(first, 150); err != nil || disposition != vnextReaderPreparationInstalled {
		t.Fatalf("first prepare: disposition=%v err=%v", disposition, err)
	}
	if _, disposition, err := store.Prepare(first, 151); err != nil || disposition != vnextReaderPreparationExactReplay {
		t.Fatalf("exact replay at capacity: disposition=%v err=%v", disposition, err)
	}

	second := vnextReaderAuthorizationStoreTestAcquired("authorization-capacity-b")
	second.IssuedAtEpochMillis = 190
	second.ExpiresAtEpochMillis = 300
	if _, _, err := store.Prepare(second, 200); !errors.Is(err, errVNextReaderAuthorizationStoreFull) {
		t.Fatalf("new authorization after old expiry error = %v, want full", err)
	}
	if _, err := store.LookupPreparedExact(first, first.ExpiresAtEpochMillis); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired exact lookup error = %v, want expired", err)
	}
}

func TestVNextReaderAuthorizationStoreRejectsOneEntryAboveRetainedByteBudget(t *testing.T) {
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-byte-oversized")
	charge, err := vnextReaderAuthorizationRetainedCharge(acquired)
	if err != nil || charge <= 1 {
		t.Fatalf("authorization retained charge = %d / %v", charge, err)
	}
	store, err := newVNextReaderAuthorizationStore(vnextReaderAuthorizationStoreConfig{
		MaxEntries:       2,
		MaxRetainedBytes: charge - 1,
	})
	if err != nil {
		t.Fatalf("new byte-bounded store: %v", err)
	}
	if _, _, err := store.Prepare(acquired, 150); !errors.Is(
		err, errVNextReaderAuthorizationStoreRetainedBytesFull) {
		t.Fatalf("oversized authorization error = %v, want retained-byte full", err)
	}
	if len(store.byID) != 0 || store.retainedBytes != 0 {
		t.Fatalf("rejected authorization consumed store: entries=%d retained=%d",
			len(store.byID), store.retainedBytes)
	}
}

func TestVNextReaderAuthorizationStoreCumulativeRetainedByteBudgetFailsClosed(t *testing.T) {
	first := vnextReaderAuthorizationStoreTestAcquired("authorization-byte-cumulative-a")
	second := vnextReaderAuthorizationStoreTestAcquired("authorization-byte-cumulative-b")
	firstCharge, err := vnextReaderAuthorizationRetainedCharge(first)
	if err != nil {
		t.Fatalf("first retained charge: %v", err)
	}
	secondCharge, err := vnextReaderAuthorizationRetainedCharge(second)
	if err != nil {
		t.Fatalf("second retained charge: %v", err)
	}
	budget := firstCharge + secondCharge - 1
	store, err := newVNextReaderAuthorizationStore(vnextReaderAuthorizationStoreConfig{
		MaxEntries:       3,
		MaxRetainedBytes: budget,
	})
	if err != nil {
		t.Fatalf("new cumulative byte-bounded store: %v", err)
	}
	if _, disposition, err := store.Prepare(first, 150); err != nil ||
		disposition != vnextReaderPreparationInstalled {
		t.Fatalf("install first authorization: disposition=%v err=%v", disposition, err)
	}
	if _, _, err := store.Prepare(second, 150); !errors.Is(
		err, errVNextReaderAuthorizationStoreRetainedBytesFull) {
		t.Fatalf("cumulative byte-budget error = %v, want retained-byte full", err)
	}
	if len(store.byID) != 1 || store.retainedBytes != firstCharge {
		t.Fatalf("cumulative rejection changed store: entries=%d retained=%d, want 1/%d",
			len(store.byID), store.retainedBytes, firstCharge)
	}
}

func TestVNextReaderAuthorizationStoreExactReplaySucceedsAtRetainedByteLimit(t *testing.T) {
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-byte-exact-limit")
	charge, err := vnextReaderAuthorizationRetainedCharge(acquired)
	if err != nil {
		t.Fatalf("authorization retained charge: %v", err)
	}
	store, err := newVNextReaderAuthorizationStore(vnextReaderAuthorizationStoreConfig{
		MaxEntries:       2,
		MaxRetainedBytes: charge,
	})
	if err != nil {
		t.Fatalf("new exact-limit store: %v", err)
	}
	if _, disposition, err := store.Prepare(acquired, 150); err != nil ||
		disposition != vnextReaderPreparationInstalled {
		t.Fatalf("install at exact byte limit: disposition=%v err=%v", disposition, err)
	}
	if _, disposition, err := store.Prepare(acquired, 151); err != nil ||
		disposition != vnextReaderPreparationExactReplay {
		t.Fatalf("replay at exact byte limit: disposition=%v err=%v", disposition, err)
	}
	second := vnextReaderAuthorizationStoreTestAcquired("authorization-byte-other-limit")
	if _, _, err := store.Prepare(second, 150); !errors.Is(
		err, errVNextReaderAuthorizationStoreRetainedBytesFull) {
		t.Fatalf("new authorization at exact byte limit error = %v", err)
	}
	if len(store.byID) != 1 || store.retainedBytes != charge {
		t.Fatalf("exact-limit replay changed charge: entries=%d retained=%d, want 1/%d",
			len(store.byID), store.retainedBytes, charge)
	}
}

func TestVNextReaderAuthorizationStoreClonesRetainedStringsAndRuns(t *testing.T) {
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-cloned-metadata")
	var backingStrings []string
	aliased := func(value string) string {
		prefix := fmt.Sprintf("unretained-prefix-%02d-", len(backingStrings))
		backing := prefix + value + "-unretained-suffix"
		backingStrings = append(backingStrings, backing)
		return backing[len(prefix) : len(prefix)+len(value)]
	}

	acquired.Authorization.RestoreAuthorizationID = aliased(
		acquired.Authorization.RestoreAuthorizationID)
	acquired.Authorization.CheckpointID = aliased(acquired.Authorization.CheckpointID)
	acquired.Authorization.ExecutorID = aliased(acquired.Authorization.ExecutorID)
	acquired.Authorization.CxldLogicalID = aliased(acquired.Authorization.CxldLogicalID)
	acquired.Authorization.TargetContainerID = aliased(acquired.Authorization.TargetContainerID)
	acquired.Authorization.Root.RootID = aliased(acquired.Authorization.Root.RootID)
	acquired.Authorization.Root.MMTemplateID = aliased(acquired.Authorization.Root.MMTemplateID)
	acquired.Authorization.Root.PageMapID = aliased(acquired.Authorization.Root.PageMapID)
	acquired.Authorization.Root.ContractID = aliased(acquired.Authorization.Root.ContractID)
	acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID = aliased(
		acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID)
	acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID = aliased(
		acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID)
	acquired.SchedulerID = aliased(acquired.SchedulerID)
	acquired.CatalogState = vnextReaderCatalogAuthorizationState(
		aliased(string(acquired.CatalogState)))
	acquired.LastMutationID = aliased(acquired.Authorization.RestoreAuthorizationID)

	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new cloning store: %v", err)
	}
	prepared, _, err := store.Prepare(acquired, 150)
	if err != nil {
		t.Fatalf("prepare aliased authorization: %v", err)
	}
	stored := store.byID[acquired.Authorization.RestoreAuthorizationID].acquired
	checks := []struct {
		name   string
		input  string
		stored string
	}{
		{"authorization ID", acquired.Authorization.RestoreAuthorizationID, stored.Authorization.RestoreAuthorizationID},
		{"checkpoint ID", acquired.Authorization.CheckpointID, stored.Authorization.CheckpointID},
		{"executor ID", acquired.Authorization.ExecutorID, stored.Authorization.ExecutorID},
		{"cxld logical ID", acquired.Authorization.CxldLogicalID, stored.Authorization.CxldLogicalID},
		{"target container ID", acquired.Authorization.TargetContainerID, stored.Authorization.TargetContainerID},
		{"root ID", acquired.Authorization.Root.RootID, stored.Authorization.Root.RootID},
		{"MM template ID", acquired.Authorization.Root.MMTemplateID, stored.Authorization.Root.MMTemplateID},
		{"PageMap ID", acquired.Authorization.Root.PageMapID, stored.Authorization.Root.PageMapID},
		{"contract ID", acquired.Authorization.Root.ContractID, stored.Authorization.Root.ContractID},
		{"locator Owner ID", acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID,
			stored.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.OwnerID},
		{"locator device UUID", acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID,
			stored.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID},
		{"Scheduler ID", acquired.SchedulerID, stored.SchedulerID},
		{"catalog state", string(acquired.CatalogState), string(stored.CatalogState)},
		{"last mutation ID", acquired.LastMutationID, stored.LastMutationID},
	}
	for _, check := range checks {
		if check.stored != check.input {
			t.Fatalf("stored %s changed value: %q != %q", check.name, check.stored, check.input)
		}
		if vnextReaderAuthorizationStoreTestStringData(check.stored) ==
			vnextReaderAuthorizationStoreTestStringData(check.input) {
			t.Fatalf("stored %s retained the caller's string backing", check.name)
		}
	}
	if &stored.Authorization.Root.PublicationLocator.PageRuns[0] ==
		&acquired.Authorization.Root.PublicationLocator.PageRuns[0] {
		t.Fatal("stored locator retained the caller's PageRuns backing")
	}
	if &prepared.Acquired.Authorization.Root.PublicationLocator.PageRuns[0] ==
		&stored.Authorization.Root.PublicationLocator.PageRuns[0] {
		t.Fatal("returned receipt aliases the stored PageRuns backing")
	}
	if vnextReaderAuthorizationStoreTestStringData(
		prepared.Acquired.Authorization.RestoreAuthorizationID) ==
		vnextReaderAuthorizationStoreTestStringData(
			stored.Authorization.RestoreAuthorizationID) {
		t.Fatal("returned receipt aliases the stored authorization ID backing")
	}
	for key := range store.byID {
		if vnextReaderAuthorizationStoreTestStringData(key) ==
			vnextReaderAuthorizationStoreTestStringData(
				acquired.Authorization.RestoreAuthorizationID) {
			t.Fatal("map key retained the caller's authorization ID backing")
		}
	}
	if len(backingStrings) != len(checks) {
		t.Fatalf("test retained %d source backings, want %d", len(backingStrings), len(checks))
	}
}

func TestVNextReaderAuthorizationStoreConcurrentRetainedByteBudget(t *testing.T) {
	const (
		callers = 64
		allowed = 8
	)
	template := vnextReaderAuthorizationStoreTestAcquired(
		fmt.Sprintf("authorization-byte-concurrent-%03d", 0))
	charge, err := vnextReaderAuthorizationRetainedCharge(template)
	if err != nil {
		t.Fatalf("concurrent authorization retained charge: %v", err)
	}
	budget := charge * allowed
	store, err := newVNextReaderAuthorizationStore(vnextReaderAuthorizationStoreConfig{
		MaxEntries:       callers,
		MaxRetainedBytes: budget,
	})
	if err != nil {
		t.Fatalf("new concurrent byte-bounded store: %v", err)
	}
	var installed int64
	var full int64
	var unexpected int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		index := index
		go func() {
			defer wait.Done()
			candidate := vnextReaderAuthorizationStoreTestAcquired(
				fmt.Sprintf("authorization-byte-concurrent-%03d", index))
			_, disposition, err := store.Prepare(candidate, 150)
			switch {
			case err == nil && disposition == vnextReaderPreparationInstalled:
				atomic.AddInt64(&installed, 1)
			case errors.Is(err, errVNextReaderAuthorizationStoreRetainedBytesFull):
				atomic.AddInt64(&full, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}()
	}
	wait.Wait()
	if installed != allowed || full != callers-allowed || unexpected != 0 {
		t.Fatalf("concurrent retained-byte budget: installed=%d full=%d unexpected=%d",
			installed, full, unexpected)
	}
	if len(store.byID) != allowed || store.retainedBytes != budget {
		t.Fatalf("concurrent retained-byte store: entries=%d retained=%d, want %d/%d",
			len(store.byID), store.retainedBytes, allowed, budget)
	}
}

func vnextReaderAuthorizationStoreTestStringData(value string) uintptr {
	return *(*uintptr)(unsafe.Pointer(&value))
}

func TestVNextReaderAuthorizationStoreConcurrentExactReplay(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-concurrent-replay")
	const callers = 64
	var first int64
	var replays int64
	var failures int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		go func() {
			defer wait.Done()
			prepared, disposition, err := store.Prepare(acquired, 150)
			if err != nil || prepared.PreparationState != vnextReaderPreparationPrepared ||
				!equalVNextReaderAcquiredAuthorization(prepared.Acquired, acquired) {
				atomic.AddInt64(&failures, 1)
				return
			}
			if disposition == vnextReaderPreparationExactReplay {
				atomic.AddInt64(&replays, 1)
			} else if disposition == vnextReaderPreparationInstalled {
				atomic.AddInt64(&first, 1)
			} else {
				atomic.AddInt64(&failures, 1)
			}
		}()
	}
	wait.Wait()
	if first != 1 || replays != callers-1 || failures != 0 {
		t.Fatalf("concurrent exact replay: first=%d replays=%d failures=%d",
			first, replays, failures)
	}
}

func TestVNextReaderAuthorizationStoreConcurrentConflictAndCapacity(t *testing.T) {
	conflictStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new conflict store: %v", err)
	}
	seed := vnextReaderAuthorizationStoreTestAcquired("authorization-concurrent-conflict")
	if _, _, err := conflictStore.Prepare(seed, 150); err != nil {
		t.Fatalf("seed conflict store: %v", err)
	}
	const callers = 64
	var conflictFailures int64
	var wait sync.WaitGroup
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		index := index
		go func() {
			defer wait.Done()
			candidate := cloneVNextReaderAcquiredAuthorization(seed)
			candidate.Authorization.TargetContainerID = fmt.Sprintf("different-target-%d", index)
			if _, _, err := conflictStore.Prepare(candidate, 150); !errors.Is(err, errVNextReaderAuthorizationConflict) {
				atomic.AddInt64(&conflictFailures, 1)
			}
		}()
	}
	wait.Wait()
	if conflictFailures != 0 {
		t.Fatalf("concurrent conflicting replays had %d unexpected results", conflictFailures)
	}

	const capacity = 8
	capacityStore, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(capacity))
	if err != nil {
		t.Fatalf("new capacity store: %v", err)
	}
	var installed int64
	var full int64
	var unexpected int64
	wait.Add(callers)
	for index := 0; index < callers; index++ {
		index := index
		go func() {
			defer wait.Done()
			candidate := vnextReaderAuthorizationStoreTestAcquired(
				fmt.Sprintf("authorization-capacity-%03d", index))
			_, disposition, err := capacityStore.Prepare(candidate, 150)
			switch {
			case err == nil && disposition == vnextReaderPreparationInstalled:
				atomic.AddInt64(&installed, 1)
			case errors.Is(err, errVNextReaderAuthorizationStoreFull):
				atomic.AddInt64(&full, 1)
			default:
				atomic.AddInt64(&unexpected, 1)
			}
		}()
	}
	wait.Wait()
	if installed != capacity || full != callers-capacity || unexpected != 0 {
		t.Fatalf("concurrent capacity: installed=%d full=%d unexpected=%d",
			installed, full, unexpected)
	}
}

func TestVNextReaderAuthorizationPreparationHasZeroDAXDependency(t *testing.T) {
	store, err := newVNextReaderAuthorizationStore(
		vnextReaderAuthorizationStoreTestConfig(1))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	acquired := vnextReaderAuthorizationStoreTestAcquired("authorization-no-dax")
	// This stable device identity intentionally has no local directory entry,
	// path, file, vnextReaderDAXSource, Owner client, or CRIU runner behind it.
	acquired.Authorization.Root.PublicationLocator.PageRuns[0].FirstPage.DeviceUUID =
		"nonexistent-portable-device"
	prepared, disposition, err := store.Prepare(acquired, 150)
	if err != nil || disposition != vnextReaderPreparationInstalled ||
		prepared.PreparationState != vnextReaderPreparationPrepared {
		t.Fatalf("read-free preparation: prepared=%#v disposition=%v err=%v",
			prepared, disposition, err)
	}
}

func vnextReaderAuthorizationStoreTestWithRuns(
	authorizationID string,
	runCount int,
) vnextReaderAcquiredAuthorization {
	acquired := vnextReaderAuthorizationStoreTestAcquired(authorizationID)
	acquired.Authorization.Root.PublicationLocator.PublicationByteLength =
		uint64(runCount) * cxlcheckpoint.PageSize
	acquired.Authorization.Root.PublicationLocator.PageRuns = make(
		[]cxlcheckpoint.PublicationPageRun, runCount)
	for index := range acquired.Authorization.Root.PublicationLocator.PageRuns {
		acquired.Authorization.Root.PublicationLocator.PageRuns[index] =
			cxlcheckpoint.PublicationPageRun{
				FirstPage: cxlcheckpoint.PageID{
					OwnerID:            "owner-a",
					DeviceUUID:         fmt.Sprintf("device-%03d", index),
					AllocationRecordID: 13,
					DataPageIndex:      17,
				},
				PageCount: 1,
			}
	}
	return acquired
}
