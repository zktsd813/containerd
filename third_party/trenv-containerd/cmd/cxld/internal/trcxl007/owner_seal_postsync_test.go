package trcxl007

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestOwnerSealReadOnlyDescriptorVerifierCommittedReplayHasZeroMutation(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	fixture.resetTracking()
	fixture.lock(t)

	verifier, err := fixture.group.newOwnerSealReadOnlyDescriptorVerifierLocked(
		fixture.plan)
	if err != nil {
		t.Fatalf("new read-only verifier: %v", err)
	}
	for logical, verification := range fixture.verifications {
		if err := verifier.Append(verification); err != nil {
			t.Fatalf("Append(%d): %v", logical, err)
		}
	}
	if err := verifier.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatalf("read-only replay writes/syncs/mutations = %d/%d/%d, want 0/0/0",
			fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("successful COMMITTED read-only verification changed group latch")
	}
	fixture.requireAllExactTargets(t)
}

func TestOwnerSealReadOnlyDescriptorVerifierRejectsPayloadCRCMismatch(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	fixture.resetTracking()
	fixture.lock(t)

	verifier, err := fixture.group.newOwnerSealReadOnlyDescriptorVerifierLocked(
		fixture.plan)
	if err != nil {
		t.Fatalf("new read-only verifier: %v", err)
	}
	wrongCRC := fixture.verifications[0].Descriptor().PaddedPageCRC32C ^ 1
	wrongDescriptor, err := fixture.targets[0].TargetDescriptor(wrongCRC)
	if err != nil {
		t.Fatalf("wrong target descriptor: %v", err)
	}
	fixture.writeTarget(t, 0, wrongDescriptor)
	fixture.resetTracking()

	err = verifier.Append(fixture.verifications[0])
	if !errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) {
		t.Fatalf("CRC mismatch error = %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatalf("CRC mismatch writes/syncs/mutations = %d/%d/%d, want 0/0/0",
			fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("normal read-only mismatch changed group latch")
	}
}

func TestOwnerSealPostSyncRefreshRereadAndFinalLatchGate(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	committing := ownerSealPostSyncTestCommitting(t, fixture)
	ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
	fixture.resetTracking()
	fixture.lock(t)

	oldAnchor := fixture.group.anchor
	fixture.group.executionState.reopenRequired = true
	for index := range fixture.group.devices {
		fixture.group.devices[index].metadata.reopenRequired = true
	}
	verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
		committing,
		fixture.plan)
	if err != nil {
		t.Fatalf("prepare post-Sync verifier: %v", err)
	}
	if fixture.group.anchor == oldAnchor {
		t.Fatal("post-Sync preparation reused stale ANCHOR metadata")
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("post-Sync preparation cleared group latch before pass 3")
	}
	for index := range fixture.group.devices {
		if fixture.group.devices[index].metadata.reopenRequired {
			t.Fatalf("refreshed device %q retained a device-local latch",
				fixture.group.devices[index].deviceUUID)
		}
	}

	fixture.resetTracking()
	for logical, verification := range fixture.verifications {
		if err := verifier.Append(verification); err != nil {
			t.Fatalf("Append(%d): %v", logical, err)
		}
		if !fixture.group.executionState.reopenRequired {
			t.Fatalf("Append(%d) cleared group latch", logical)
		}
	}
	if err := verifier.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("Finish cleared group latch")
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatalf("post-Sync verifier writes/syncs/mutations = %d/%d/%d, want 0/0/0",
			fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
	}
	if err := fixture.group.completeOwnerSealPostSyncVerificationLocked(verifier); err != nil {
		t.Fatalf("complete post-Sync verification: %v", err)
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("successful final gate did not clear group latch")
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatal("final latch gate performed storage mutation")
	}
}

func TestOwnerSealPostSyncMismatchLeavesLatchSet(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	committing := ownerSealPostSyncTestCommitting(t, fixture)
	ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
	fixture.resetTracking()
	fixture.lock(t)

	verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
		committing,
		fixture.plan)
	if err != nil {
		t.Fatalf("prepare post-Sync verifier: %v", err)
	}
	wrongCRC := fixture.verifications[0].Descriptor().PaddedPageCRC32C ^ 1
	wrongDescriptor, err := fixture.targets[0].TargetDescriptor(wrongCRC)
	if err != nil {
		t.Fatalf("wrong target descriptor: %v", err)
	}
	fixture.writeTarget(t, 0, wrongDescriptor)
	fixture.resetTracking()

	err = verifier.Append(fixture.verifications[0])
	if !errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) {
		t.Fatalf("post-Sync CRC mismatch error = %v", err)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("post-Sync CRC mismatch cleared group latch")
	}
	if completeErr := fixture.group.completeOwnerSealPostSyncVerificationLocked(verifier); !errors.Is(completeErr, ErrOwnerSealDescriptorDispositionChanged) {
		t.Fatalf("completion after mismatch error = %v", completeErr)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("failed completion cleared group latch")
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatal("post-Sync mismatch performed storage mutation")
	}
}

func TestOwnerSealPostSyncExpectedOwnerMismatchFailsClosed(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	committing := ownerSealPostSyncTestCommitting(t, fixture)
	ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
	fixture.resetTracking()
	fixture.lock(t)

	wrong := committing.Clone()
	wrong.NextAllocationRecordID++
	verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
		wrong,
		fixture.plan)
	if verifier != nil || !errors.Is(err, ErrOwnerSealPostSyncAuthorityContradiction) {
		t.Fatalf("wrong expected Owner result = verifier=%p error=%v", verifier, err)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("expected Owner mismatch did not retain group latch")
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatal("expected Owner mismatch performed storage mutation")
	}
}

func TestOwnerSealReadOnlyVerifierRejectsCopyAndRetainsCompactState(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	fixture.lock(t)
	verifier, err := fixture.group.newOwnerSealReadOnlyDescriptorVerifierLocked(
		fixture.plan)
	if err != nil {
		t.Fatalf("new read-only verifier: %v", err)
	}
	copied := *verifier
	if err := copied.Append(fixture.verifications[0]); !errors.Is(err, ErrInvalidOwnerSealPostSyncVerification) {
		t.Fatalf("copied verifier error = %v", err)
	}

	verifierType := reflect.TypeOf(ownerSealReadOnlyDescriptorVerifier{})
	for index := 0; index < verifierType.NumField(); index++ {
		field := verifierType.Field(index)
		if field.Type.Kind() == reflect.Map {
			t.Fatalf("verifier retains map field %q", field.Name)
		}
		if field.Type.Kind() == reflect.Slice && field.Name != "devices" {
			t.Fatalf("verifier retains unexpected slice field %q", field.Name)
		}
		lower := strings.ToLower(field.Name)
		if strings.Contains(lower, "crcvector") ||
			strings.Contains(lower, "pagetable") ||
			strings.Contains(lower, "payload") ||
			strings.Contains(lower, "bitmap") {
			t.Fatalf("verifier field %q may retain per-page state", field.Name)
		}
	}
}

func TestOwnerSealPostSyncPrivilegedBoundaryFailureMatrix(t *testing.T) {
	t.Run("normal-constructor-rejects-group-latch", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.seedAllTargets(t)
		fixture.resetTracking()
		fixture.lock(t)
		fixture.group.executionState.reopenRequired = true

		verifier, err := fixture.group.newOwnerSealReadOnlyDescriptorVerifierLocked(
			fixture.plan)
		if verifier != nil || !errors.Is(err, ErrOwnerDeviceGroupReopenRequired) {
			t.Fatalf("normal constructor result = verifier=%p error=%v", verifier, err)
		}
		if fixture.totalReads() != 0 || fixture.totalWrites() != 0 ||
			fixture.totalSyncs() != 0 || fixture.totalMutations() != 0 {
			t.Fatal("normal constructor bypass attempt performed storage I/O")
		}
	})

	t.Run("privileged-prepare-rejects-free-page", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.seedAllTargets(t)
		fixture.resetTracking()
		fixture.lock(t)
		fixture.group.executionState.reopenRequired = true
		target := fixture.targets[0]
		metadata := storageMetadataForUUID(
			t,
			fixture.group,
			target.Device().DeviceUUID)
		metadata.allocator.allocationBitmap[target.DataPageIndex()/8] &^=
			byte(1) << uint(target.DataPageIndex()%8)
		metadata.allocator.AllocatedPageCount--

		_, _, err := fixture.group.prepareOwnerSealDescriptorPostRefreshLocked(
			fixture.plan)
		if !errors.Is(err, ErrOwnerSealDescriptorAllocatorContradiction) {
			t.Fatalf("privileged free-page error = %v", err)
		}
		if !fixture.group.executionState.reopenRequired ||
			fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 {
			t.Fatal("privileged free-page rejection changed latch or storage")
		}
	})

	t.Run("allocator-change-after-construction", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.seedAllTargets(t)
		committing := ownerSealPostSyncTestCommitting(t, fixture)
		ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
		fixture.resetTracking()
		fixture.lock(t)
		verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
			committing,
			fixture.plan)
		if err != nil {
			t.Fatalf("prepare post-Sync verifier: %v", err)
		}
		target := fixture.targets[0]
		metadata := storageMetadataForUUID(
			t,
			fixture.group,
			target.Device().DeviceUUID)
		metadata.allocator.allocationBitmap[target.DataPageIndex()/8] &^=
			byte(1) << uint(target.DataPageIndex()%8)
		metadata.allocator.AllocatedPageCount--
		fixture.resetTracking()

		err = verifier.Append(fixture.verifications[0])
		if !errors.Is(err, ErrOwnerSealDescriptorAllocatorContradiction) {
			t.Fatalf("late allocator contradiction = %v", err)
		}
		if !fixture.group.executionState.reopenRequired ||
			fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 {
			t.Fatal("late allocator contradiction changed latch or storage")
		}
	})

	t.Run("refreshed-member-pointer-replacement", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.seedAllTargets(t)
		committing := ownerSealPostSyncTestCommitting(t, fixture)
		ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
		fixture.lock(t)
		verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
			committing,
			fixture.plan)
		if err != nil {
			t.Fatalf("prepare post-Sync verifier: %v", err)
		}
		for index := range fixture.group.devices {
			device := &fixture.group.devices[index]
			if device.deviceUUID == fixture.group.bootstrap.AnchorDeviceUUID {
				continue
			}
			replacement := *device.metadata
			device.metadata = &replacement
			break
		}

		err = verifier.Append(fixture.verifications[0])
		if !errors.Is(err, ErrOwnerSealPostSyncAuthorityContradiction) {
			t.Fatalf("metadata pointer replacement error = %v", err)
		}
		if !fixture.group.executionState.reopenRequired {
			t.Fatal("metadata pointer replacement cleared group latch")
		}
	})

	t.Run("copied-post-sync-completion-capability", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.seedAllTargets(t)
		committing := ownerSealPostSyncTestCommitting(t, fixture)
		ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
		fixture.lock(t)
		verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
			committing,
			fixture.plan)
		if err != nil {
			t.Fatalf("prepare post-Sync verifier: %v", err)
		}
		for logical, verification := range fixture.verifications {
			if err := verifier.Append(verification); err != nil {
				t.Fatalf("Append(%d): %v", logical, err)
			}
		}
		if err := verifier.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		copied := *verifier
		if err := fixture.group.completeOwnerSealPostSyncVerificationLocked(&copied); !errors.Is(err, ErrInvalidOwnerSealPostSyncVerification) {
			t.Fatalf("copied completion error = %v", err)
		}
		if !fixture.group.executionState.reopenRequired {
			t.Fatal("copied completion capability cleared group latch")
		}
		if err := fixture.group.completeOwnerSealPostSyncVerificationLocked(verifier); err != nil {
			t.Fatalf("original completion capability: %v", err)
		}
	})

	t.Run("expected-owner-envelope-length-is-bound", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.seedAllTargets(t)
		committing := ownerSealPostSyncTestCommitting(t, fixture)
		ownerSealPostSyncTestPersistMetadata(t, fixture, committing)
		fixture.lock(t)
		verifier, err := fixture.group.prepareOwnerSealPostSyncVerifierLocked(
			committing,
			fixture.plan)
		if err != nil {
			t.Fatalf("prepare post-Sync verifier: %v", err)
		}
		for logical, verification := range fixture.verifications {
			if err := verifier.Append(verification); err != nil {
				t.Fatalf("Append(%d): %v", logical, err)
			}
		}
		if err := verifier.Finish(); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		verifier.expectedCommittingLength++
		fixture.resetTracking()

		err = fixture.group.completeOwnerSealPostSyncVerificationLocked(verifier)
		if !errors.Is(err, ErrOwnerSealPostSyncAuthorityContradiction) {
			t.Fatalf("expected Owner length mismatch error = %v", err)
		}
		if !fixture.group.executionState.reopenRequired ||
			fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 {
			t.Fatal("expected Owner length mismatch changed latch or storage")
		}
	})

	t.Run("go-1.17-error-traversal", func(t *testing.T) {
		wrapped := ownerSealPostSyncError(
			ErrInvalidOwnerSealPostSyncVerification,
			"test",
			ErrDeviceMetadataSequence,
			"nested cause")
		if !errors.Is(wrapped, ErrInvalidOwnerSealPostSyncVerification) ||
			!errors.Is(wrapped, ErrDeviceMetadataSequence) {
			t.Fatalf("errors.Is did not expose category and cause: %v", wrapped)
		}
	})
}

func ownerSealPostSyncTestCommitting(
	t *testing.T,
	fixture *ownerSealDescriptorPersistenceTestFixture,
) OwnerStateSnapshot {
	t.Helper()
	transcript, err := NewOwnerSealTranscript(fixture.plan)
	if err != nil {
		t.Fatalf("NewOwnerSealTranscript: %v", err)
	}
	for logical, page := range fixture.pages {
		if _, err := transcript.AppendOwnerRereadPage(
			page,
			ownerSealTranscriptTestCRC32C(page)); err != nil {
			t.Fatalf("AppendOwnerRereadPage(%d): %v", logical, err)
		}
	}
	seal, err := transcript.Finish()
	if err != nil {
		t.Fatalf("transcript Finish: %v", err)
	}
	transitions, err := PlanFreshOwnerSealStateTransitions(
		fixture.owner,
		fixture.plan,
		seal)
	if err != nil {
		t.Fatalf("PlanFreshOwnerSealStateTransitions: %v", err)
	}
	return transitions.Committing()
}

func ownerSealPostSyncTestPersistMetadata(
	t *testing.T,
	fixture *ownerSealDescriptorPersistenceTestFixture,
	committing OwnerStateSnapshot,
) {
	t.Helper()
	for index := range fixture.group.devices {
		opened := &fixture.group.devices[index]
		metadata := opened.metadata
		storage := fixture.storages[opened.deviceUUID]
		allocatorWire, err := CanonicalAllocatorSnapshotBytes(
			metadata.allocator,
			metadata.geometry)
		if err != nil {
			t.Fatalf("CanonicalAllocatorSnapshotBytes(%s): %v", opened.deviceUUID, err)
		}
		allocatorOffset, err := allocatorSnapshotSlotOffset(
			metadata.geometry,
			metadata.superblock.ActiveAllocatorSnapshotSlot)
		if err != nil {
			t.Fatalf("allocatorSnapshotSlotOffset(%s): %v", opened.deviceUUID, err)
		}
		storage.rawWrite(allocatorOffset, allocatorWire)

		superblockWire, err := CanonicalSuperblockBytes(metadata.superblock)
		if err != nil {
			t.Fatalf("CanonicalSuperblockBytes(%s): %v", opened.deviceUUID, err)
		}
		superblockOffset, err := superblockSlotOffset(
			metadata.geometry,
			metadata.superblockSlot)
		if err != nil {
			t.Fatalf("superblockSlotOffset(%s): %v", opened.deviceUUID, err)
		}
		storage.rawWrite(superblockOffset, superblockWire)

		if metadata.superblock.OwnerGroupRole == OwnerGroupRoleAnchor {
			ownerStorage, err := EncodeOwnerStateForStorage(
				committing,
				metadata.geometry)
			if err != nil {
				t.Fatalf("EncodeOwnerStateForStorage: %v", err)
			}
			metadata.ownerStateSlot = OwnerStateSlotA
			metadata.ownerState = committing.Clone()
			metadata.ownerStatePresent = true
			ownerOffset, err := ownerStateSlotOffset(
				metadata.geometry,
				metadata.ownerStateSlot)
			if err != nil {
				t.Fatalf("ownerStateSlotOffset: %v", err)
			}
			storage.rawWrite(ownerOffset, ownerStorage.ExactBytes())
		}
	}
}
