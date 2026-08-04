package trcxl007

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var (
	errOwnerSealDescriptorTestSync        = errors.New("injected Owner seal descriptor Sync failure")
	errOwnerSealDescriptorTestSyncA       = errors.New("injected Owner seal descriptor device-a Sync failure")
	errOwnerSealDescriptorTestSyncB       = errors.New("injected Owner seal descriptor device-b Sync failure")
	errOwnerSealDescriptorTestDML         = errors.New("injected later Owner DML failure")
	errOwnerSealDescriptorTestNoWrite     = errors.New("injected pre-write Owner seal failure")
	errOwnerSealDescriptorTestReplacement = errors.New("replacement failure must not replace primary")
)

type ownerSealDescriptorTestStorage struct {
	*metadataTestStorage
	deviceUUID string
	syncTrace  *[]string
	syncCalls  int
	failSync   error
}

func (storage *ownerSealDescriptorTestStorage) Sync() error {
	storage.syncCalls++
	*storage.syncTrace = append(*storage.syncTrace, storage.deviceUUID)
	if storage.failSync != nil {
		return storage.failSync
	}
	return storage.metadataTestStorage.Sync()
}

type ownerSealDescriptorPersistenceTestFixture struct {
	producer      producerScatterTestFixture
	owner         OwnerStateSnapshot
	plan          OwnerSealPlan
	pages         [][]byte
	targets       []OwnerSealPageTarget
	verifications []OwnerSealPageVerification
	geometry      DeviceGeometry
	group         *OwnerDeviceGroup
	storages      map[string]*ownerSealDescriptorTestStorage
	syncTrace     *[]string
}

func TestOwnerSealDescriptorFreshFragmentedTwoDAX(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)

	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	for logical, verification := range fixture.verifications {
		if err := sink.Append(verification); err != nil {
			t.Fatalf("Append(%d): %v", logical, err)
		}
		if logical == 0 && !fixture.group.executionState.reopenRequired {
			t.Fatal("first attempted write did not latch group reopen-required")
		}
	}
	if err := sink.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if !fixture.group.executionState.reopenRequired {
		t.Fatal("successful write Finish cleared group reopen-required")
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Sync order = %#v, want %#v", got, want)
	}
	var writes int
	for _, storage := range fixture.storages {
		writes += storage.writeCalls
		if !storageMetadataForUUID(t, fixture.group, storage.deviceUUID).reopenRequired {
			t.Fatalf("device %q successful writes did not retain reopen poison", storage.deviceUUID)
		}
	}
	if writes != int(fixture.plan.TotalPages()) {
		t.Fatalf("descriptor writes = %d, want %d", writes, fixture.plan.TotalPages())
	}
	fixture.requireAllExactTargets(t)
}

func TestOwnerSealDescriptorLatePreflightConflictHasZeroMutation(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	last := fixture.plan.TotalPages() - 1
	fixture.writeRawDescriptor(t, last, make([]byte, PageDescriptorBytes))
	fixture.resetTracking()
	fixture.lock(t)

	err := fixture.group.preflightOwnerSealDescriptorsLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) {
		t.Fatalf("late conflict error = %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
		fixture.totalMutations() != 0 {
		t.Fatalf("late conflict writes/syncs/mutations = %d/%d/%d, want 0/0/0",
			fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
	}
	if fixture.totalReads() < int(fixture.plan.TotalPages()) {
		t.Fatalf("late conflict reads = %d, want at least %d",
			fixture.totalReads(), fixture.plan.TotalPages())
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("read-only late conflict poisoned group")
	}
	fixture.requireReserved(t, 0)
}

func TestOwnerSealDescriptorSinkConstructorOwnsExactGlobalPreflight(t *testing.T) {
	constructorType := reflect.TypeOf(
		(*OwnerDeviceGroup).newOwnerSealDescriptorSinkLocked)
	wantConstructorType := reflect.TypeOf((func(
		*OwnerDeviceGroup,
		OwnerSealPlan,
		ownerSealDescriptorMode,
	) (*ownerSealDescriptorSink, error))(nil))
	if constructorType != wantConstructorType {
		t.Fatalf("sink constructor type = %v, want %v",
			constructorType, wantConstructorType)
	}
	sinkType := reflect.TypeOf(ownerSealDescriptorSink{})
	modeField, present := sinkType.FieldByName("mode")
	if !present || modeField.Type != reflect.TypeOf(ownerSealDescriptorMode(0)) {
		t.Fatalf("sink mode field = %#v/%t", modeField, present)
	}

	t.Run("cannot-omit-preflight", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		last := fixture.plan.TotalPages() - 1
		fixture.writeRawDescriptor(t, last, make([]byte, PageDescriptorBytes))
		fixture.resetTracking()
		fixture.lock(t)

		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if sink != nil || !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) {
			t.Fatalf("constructor result = sink=%p error=%v", sink, err)
		}
		if fixture.totalReads() < int(fixture.plan.TotalPages()) {
			t.Fatalf("constructor reads = %d, want at least %d",
				fixture.totalReads(), fixture.plan.TotalPages())
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 {
			t.Fatalf("constructor conflict writes/syncs/mutations = %d/%d/%d",
				fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
		}
		if fixture.group.executionState.reopenRequired {
			t.Fatal("read-only constructor preflight conflict poisoned group")
		}
	})

	t.Run("plan-A-cannot-authorize-plan-B", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		if err := fixture.group.preflightOwnerSealDescriptorsLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly); err != nil {
			t.Fatalf("plan A read-only preflight: %v", err)
		}

		planB := cloneOwnerSealPlan(fixture.plan)
		planB.runs[0].StartDataPageIndex = planB.runs[2].StartDataPageIndex
		planB.integritySHA256 = ownerSealPlanSHA256(planB)
		if err := planB.Validate(); err != nil {
			t.Fatalf("plan B Validate: %v", err)
		}
		// Plan B's first page aliases plan A logical page 5. Corrupt that
		// descriptor after A's barrier so only a fresh B preflight can reject it.
		fixture.writeRawDescriptor(t, 5, make([]byte, PageDescriptorBytes))
		fixture.resetTracking()

		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			planB,
			ownerSealDescriptorFreshReservedOnly)
		if sink != nil || !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) {
			t.Fatalf("plan B constructor result = sink=%p error=%v", sink, err)
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 {
			t.Fatalf("plan B conflict writes/syncs/mutations = %d/%d/%d",
				fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
		}
		if fixture.group.executionState.reopenRequired {
			t.Fatal("plan B constructor conflict poisoned group")
		}
	})

	t.Run("binds-detached-plan-and-mode", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		callerPlan := cloneOwnerSealPlan(fixture.plan)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			callerPlan,
			ownerSealDescriptorFreshReservedOnly)
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		if sink.mode != ownerSealDescriptorFreshReservedOnly {
			t.Fatalf("bound mode = %d", sink.mode)
		}
		if len(callerPlan.runs) == 0 || len(sink.plan.runs) == 0 ||
			&callerPlan.runs[0] == &sink.plan.runs[0] {
			t.Fatal("sink plan is not detached from caller plan")
		}
		callerPlan.runs[0].StartDataPageIndex++
		callerPlan.integritySHA256 = ownerSealPlanSHA256(callerPlan)
		for logical, verification := range fixture.verifications {
			if err := sink.Append(verification); err != nil {
				t.Fatalf("Append(%d) after caller mutation: %v", logical, err)
			}
		}
		if err := sink.Finish(); err != nil {
			t.Fatalf("Finish after caller mutation: %v", err)
		}
		fixture.requireAllExactTargets(t)
	})

	t.Run("invalid-mode-has-no-I-O", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorMode(0))
		if sink != nil || !errors.Is(err, ErrInvalidOwnerSealDescriptorPersistence) {
			t.Fatalf("invalid-mode result = sink=%p error=%v", sink, err)
		}
		if fixture.totalReads() != 0 || fixture.totalWrites() != 0 ||
			fixture.totalSyncs() != 0 || fixture.totalMutations() != 0 {
			t.Fatal("invalid mode performed storage I/O")
		}
	})
}

func TestOwnerSealDescriptorLateClassChangeRespectsBoundMode(t *testing.T) {
	tests := []struct {
		name    string
		mode    ownerSealDescriptorMode
		initial func(*testing.T, *ownerSealDescriptorPersistenceTestFixture)
		late    func(*testing.T, *ownerSealDescriptorPersistenceTestFixture)
	}{
		{
			name:    "fresh-target-must-not-replay",
			mode:    ownerSealDescriptorFreshReservedOnly,
			initial: func(*testing.T, *ownerSealDescriptorPersistenceTestFixture) {},
			late: func(t *testing.T, fixture *ownerSealDescriptorPersistenceTestFixture) {
				fixture.writeTarget(t, 0, fixture.verifications[0].descriptor)
			},
		},
		{
			name: "terminal-RESERVED-must-not-write",
			mode: ownerSealDescriptorTerminalTargetOnly,
			initial: func(t *testing.T, fixture *ownerSealDescriptorPersistenceTestFixture) {
				fixture.seedAllTargets(t)
			},
			late: func(t *testing.T, fixture *ownerSealDescriptorPersistenceTestFixture) {
				fixture.writeReserved(t, 0)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
			test.initial(t, fixture)
			fixture.resetTracking()
			fixture.lock(t)
			sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
				fixture.plan,
				test.mode)
			if err != nil {
				t.Fatalf("new sink: %v", err)
			}

			test.late(t, fixture)
			fixture.resetTracking()
			err = sink.Append(fixture.verifications[0])
			if !errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) {
				t.Fatalf("late class change error = %v", err)
			}
			requireOwnerSealDescriptorOperation(t, err, "append-mode")
			if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
				fixture.totalMutations() != 0 {
				t.Fatalf("late class writes/syncs/mutations = %d/%d/%d, want 0/0/0",
					fixture.totalWrites(), fixture.totalSyncs(), fixture.totalMutations())
			}
			if !fixture.group.executionState.reopenRequired {
				t.Fatal("disposition change did not latch group reopen-required")
			}
			for _, device := range fixture.group.devices {
				if device.metadata.reopenRequired {
					t.Fatalf("no-write disposition change poisoned device %q",
						device.deviceUUID)
				}
			}
			if again := sink.Finish(); again != err {
				t.Fatalf("terminal sink returned %v, want original %v", again, err)
			}
		})
	}

	t.Run("recovery-allows-late-target-replay", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorRecoveryReservedOrTarget)
		if err != nil {
			t.Fatalf("new recovery sink: %v", err)
		}
		fixture.writeTarget(t, 0, fixture.verifications[0].descriptor)
		fixture.resetTracking()
		if err := sink.Append(fixture.verifications[0]); err != nil {
			t.Fatalf("late target replay: %v", err)
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 ||
			fixture.totalMutations() != 0 {
			t.Fatal("late recovery target replay mutated storage")
		}
		if fixture.group.executionState.reopenRequired {
			t.Fatal("late exact recovery replay poisoned group")
		}
	})
}

func TestOwnerSealDescriptorRecoveryMixedPrefixAndContinuedAppend(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	var reserved uint64
	for logical := uint64(0); logical < fixture.plan.TotalPages(); logical++ {
		if logical%2 == 0 {
			fixture.writeTarget(t, logical, fixture.verifications[logical].descriptor)
		} else {
			reserved++
		}
	}
	fixture.resetTracking()
	fixture.lock(t)

	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorRecoveryReservedOrTarget)
	if err != nil {
		t.Fatalf("new recovery sink: %v", err)
	}
	for logical, verification := range fixture.verifications {
		if err := sink.Append(verification); err != nil {
			t.Fatalf("recovery Append(%d): %v", logical, err)
		}
		if logical >= 1 && !fixture.group.executionState.reopenRequired {
			t.Fatal("first recovery write did not latch group")
		}
	}
	if err := sink.Finish(); err != nil {
		t.Fatalf("recovery Finish: %v", err)
	}
	if got := uint64(fixture.totalWrites()); got != reserved {
		t.Fatalf("recovery writes = %d, want %d RESERVED pages", got, reserved)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("recovery Finish cleared required reopen")
	}
	fixture.requireAllExactTargets(t)
}

func TestOwnerSealDescriptorRecoveryWrongStoredCRCAfterTargetPrefix(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.writeTarget(t, 0, fixture.verifications[0].descriptor)
	wrong := fixture.verifications[1].descriptor
	wrong.PaddedPageCRC32C ^= 1
	if wrong.PaddedPageCRC32C == fixture.verifications[1].descriptor.PaddedPageCRC32C {
		t.Fatal("test failed to change CRC32C")
	}
	fixture.writeTarget(t, 1, wrong)
	fixture.resetTracking()
	fixture.lock(t)

	// Raw-CRC structural classification deliberately accepts both canonical
	// targets: the constructor's preflight does not possess the DML
	// transcript's CRC value.
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorRecoveryReservedOrTarget)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Append(fixture.verifications[0]); err != nil {
		t.Fatalf("exact target prefix: %v", err)
	}
	err = sink.Append(fixture.verifications[1])
	if !errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) {
		t.Fatalf("wrong stored CRC Append error = %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
		t.Fatalf("target-prefix CRC mismatch writes/syncs = %d/%d, want 0/0",
			fixture.totalWrites(), fixture.totalSyncs())
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("no-write CRC mismatch did not latch group reopen-required")
	}
}

func TestOwnerSealDescriptorTerminalReplayStillSyncsEveryDAX(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	fixture.resetTracking()
	fixture.lock(t)

	if err := fixture.group.preflightOwnerSealDescriptorsLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly); !errors.Is(
		err, ErrOwnerSealDescriptorMediaConflict) {
		t.Fatalf("fresh preflight over targets = %v", err)
	}
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorTerminalTargetOnly)
	if err != nil {
		t.Fatalf("new terminal sink: %v", err)
	}
	for logical, verification := range fixture.verifications {
		if err := sink.Append(verification); err != nil {
			t.Fatalf("terminal Append(%d): %v", logical, err)
		}
	}
	if err := sink.Finish(); err != nil {
		t.Fatalf("terminal Finish: %v", err)
	}
	if fixture.totalWrites() != 0 || fixture.totalSyncs() != len(fixture.storages) {
		t.Fatalf("terminal writes/syncs = %d/%d, want 0/%d",
			fixture.totalWrites(), fixture.totalSyncs(), len(fixture.storages))
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("successful no-write replay unnecessarily poisoned group")
	}
	for _, device := range fixture.group.devices {
		if device.metadata.reopenRequired {
			t.Fatalf("no-write replay poisoned device %q", device.deviceUUID)
		}
	}
}

func TestOwnerSealDescriptorRejectsCanonicalForeignTargetFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(Descriptor) Descriptor
	}{
		{name: "allocation", mutate: func(value Descriptor) Descriptor {
			value.AllocationRecordID++
			return value
		}},
		{name: "object", mutate: func(value Descriptor) Descriptor {
			value.OriginObjectID++
			return value
		}},
		{name: "reference-count", mutate: func(value Descriptor) Descriptor {
			value.ContentReferenceCount++
			return value
		}},
		{name: "Owner-transaction", mutate: func(value Descriptor) Descriptor {
			value.OwnerTransactionSeq++
			return value
		}},
		{name: "payload-length", mutate: func(value Descriptor) Descriptor {
			value.PayloadLength--
			return value
		}},
		{name: "state", mutate: func(value Descriptor) Descriptor {
			value.State = DescriptorRetiring
			return value
		}},
		{name: "content-kind", mutate: func(value Descriptor) Descriptor {
			value.ContentKind = cxlcheckpoint.ContentRestoreBlobPayloadV7
			return value
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
			fixture.seedAllTargets(t)
			foreign := test.mutate(fixture.verifications[3].descriptor)
			wire, err := foreign.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal foreign descriptor: %v", err)
			}
			fixture.writeRawDescriptor(t, 3, wire)
			fixture.resetTracking()
			fixture.lock(t)

			err = fixture.group.preflightOwnerSealDescriptorsLocked(
				fixture.plan,
				ownerSealDescriptorTerminalTargetOnly)
			if !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) {
				t.Fatalf("foreign %s error = %v", test.name, err)
			}
			if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
				t.Fatalf("foreign %s mutated media", test.name)
			}
		})
	}
}

func TestOwnerSealDescriptorRejectsTornAndNoncanonicalTargetWire(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte)
	}{
		{name: "torn-descriptor-CRC", mutate: func(wire []byte) { wire[4] ^= 1 }},
		{name: "nonzero-reserved-tail", mutate: func(wire []byte) { wire[63] = 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
			fixture.seedAllTargets(t)
			wire, err := fixture.verifications[3].descriptor.MarshalBinary()
			if err != nil {
				t.Fatalf("marshal target: %v", err)
			}
			test.mutate(wire)
			fixture.writeRawDescriptor(t, 3, wire)
			fixture.resetTracking()
			fixture.lock(t)

			err = fixture.group.preflightOwnerSealDescriptorsLocked(
				fixture.plan,
				ownerSealDescriptorTerminalTargetOnly)
			if !errors.Is(err, ErrOwnerSealDescriptorMediaConflict) {
				t.Fatalf("%s error = %v", test.name, err)
			}
		})
	}
}

func TestOwnerSealDescriptorVerificationOrderingAndDuplication(t *testing.T) {
	t.Run("out-of-order-before-I/O", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		err = sink.Append(fixture.verifications[1])
		if !errors.Is(err, ErrInvalidOwnerSealDescriptorPersistence) {
			t.Fatalf("out-of-order error = %v", err)
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
			t.Fatal("out-of-order verification performed mutation")
		}
	})

	t.Run("duplicate-after-prefix", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		if err := sink.Append(fixture.verifications[0]); err != nil {
			t.Fatalf("prefix: %v", err)
		}
		err = sink.Append(fixture.verifications[0])
		if !errors.Is(err, ErrInvalidOwnerSealDescriptorPersistence) {
			t.Fatalf("duplicate error = %v", err)
		}
		if fixture.totalWrites() != 1 || !fixture.group.executionState.reopenRequired {
			t.Fatalf("duplicate prefix writes/poison = %d/%t, want 1/true",
				fixture.totalWrites(), fixture.group.executionState.reopenRequired)
		}
	})

	t.Run("descriptor-substitution-before-I/O", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		verification := fixture.verifications[0]
		verification.descriptor.AllocationRecordID++
		err = sink.Append(verification)
		if !errors.Is(err, ErrInvalidOwnerSealDescriptorPersistence) {
			t.Fatalf("descriptor substitution error = %v", err)
		}
		if fixture.totalWrites() != 0 {
			t.Fatal("descriptor substitution wrote media")
		}
	})
}

func TestOwnerSealDescriptorFailureBarrierSyncsWrittenPrefixOnce(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Append(fixture.verifications[0]); err != nil {
		t.Fatalf("device-a prefix Append: %v", err)
	}
	if !sink.writeAttempted || fixture.totalWrites() != 1 || fixture.totalSyncs() != 0 {
		t.Fatalf("prefix attempted/writes/syncs = %t/%d/%d, want true/1/0",
			sink.writeAttempted, fixture.totalWrites(), fixture.totalSyncs())
	}

	result := sink.FailAndSync(errOwnerSealDescriptorTestDML)
	if result != errOwnerSealDescriptorTestDML ||
		!errors.Is(result, errOwnerSealDescriptorTestDML) {
		t.Fatalf("failure barrier result = %v", result)
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("failure-barrier Sync order = %#v, want %#v", got, want)
	}
	if fixture.totalSyncs() != len(fixture.storages) {
		t.Fatalf("failure-barrier Sync calls = %d, want %d",
			fixture.totalSyncs(), len(fixture.storages))
	}

	firstTrace := append([]string(nil), (*fixture.syncTrace)...)
	firstSyncs := fixture.totalSyncs()
	again := sink.FailAndSync(errOwnerSealDescriptorTestReplacement)
	if again != result || fixture.totalSyncs() != firstSyncs ||
		!reflect.DeepEqual(*fixture.syncTrace, firstTrace) {
		t.Fatalf("repeated barrier result/syncs/trace = %v/%d/%#v, want %v/%d/%#v",
			again, fixture.totalSyncs(), *fixture.syncTrace,
			result, firstSyncs, firstTrace)
	}
	if errors.Is(again, errOwnerSealDescriptorTestReplacement) {
		t.Fatal("repeated barrier replaced the primary failure")
	}
	if appendAgain := sink.Append(fixture.verifications[1]); appendAgain != result {
		t.Fatalf("Append after barrier = %v, want %v", appendAgain, result)
	}
}

func TestOwnerSealDescriptorFailureBarrierAfterAppendFailure(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Append(fixture.verifications[0]); err != nil {
		t.Fatalf("prefix Append: %v", err)
	}
	appendErr := sink.Append(fixture.verifications[0])
	if !errors.Is(appendErr, ErrInvalidOwnerSealDescriptorPersistence) {
		t.Fatalf("injected Append failure = %v", appendErr)
	}
	outer := fmt.Errorf(
		"Owner DML/reread logical page 1 on device-b: %w", appendErr)
	result := sink.FailAndSync(outer)
	if result != outer || !errors.Is(result, appendErr) ||
		!strings.Contains(result.Error(), "logical page 1 on device-b") {
		t.Fatalf("failure barrier = %v, want location-bearing outer %v",
			result, outer)
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Append-failure Sync order = %#v, want %#v", got, want)
	}
}

func TestOwnerSealDescriptorFailureBarrierPreservesUnrelatedOuterAndSinkFailure(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Append(fixture.verifications[0]); err != nil {
		t.Fatalf("prefix Append: %v", err)
	}
	sinkErr := sink.Append(fixture.verifications[0])
	if !errors.Is(sinkErr, ErrInvalidOwnerSealDescriptorPersistence) {
		t.Fatalf("injected sink error = %v", sinkErr)
	}

	result := sink.FailAndSync(errOwnerSealDescriptorTestDML)
	if !errors.Is(result, errOwnerSealDescriptorTestDML) ||
		!errors.Is(result, sinkErr) ||
		!errors.Is(result, ErrInvalidOwnerSealDescriptorPersistence) {
		t.Fatalf("combined unrelated failure = %v", result)
	}
	if !strings.Contains(result.Error(), errOwnerSealDescriptorTestDML.Error()) ||
		!strings.Contains(result.Error(), sinkErr.Error()) {
		t.Fatalf("combined failure lost diagnostics: %v", result)
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("combined-failure Sync order = %#v, want %#v", got, want)
	}
}

func TestOwnerSealDescriptorFailureBarrierPreservesPrimaryAndFirstSyncError(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	if err := sink.Append(fixture.verifications[0]); err != nil {
		t.Fatalf("prefix Append: %v", err)
	}
	fixture.storages["device-a"].failSync = errOwnerSealDescriptorTestSyncA
	fixture.storages["device-b"].failSync = errOwnerSealDescriptorTestSyncB

	result := sink.FailAndSync(errOwnerSealDescriptorTestDML)
	for _, target := range []error{
		errOwnerSealDescriptorTestDML,
		ErrOwnerSealDescriptorSync,
		ErrDeviceMetadataStorage,
		errOwnerSealDescriptorTestSyncA,
	} {
		if !errors.Is(result, target) {
			t.Fatalf("failure barrier %v does not preserve %v", result, target)
		}
	}
	if errors.Is(result, errOwnerSealDescriptorTestSyncB) {
		t.Fatal("failure barrier retained a later Sync error instead of only the first")
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("failed Sync attempts = %#v, want %#v", got, want)
	}
	if fixture.totalSyncs() != len(fixture.storages) {
		t.Fatalf("failed Sync attempts = %d, want %d",
			fixture.totalSyncs(), len(fixture.storages))
	}
	for _, device := range fixture.group.devices {
		if !device.metadata.reopenRequired {
			t.Fatalf("failed failure-barrier Sync did not poison device %q",
				device.deviceUUID)
		}
	}
	if again := sink.FailAndSync(errOwnerSealDescriptorTestReplacement); again != result {
		t.Fatalf("repeated failed barrier = %v, want exact %v", again, result)
	}
	if fixture.totalSyncs() != len(fixture.storages) {
		t.Fatal("repeated failed barrier issued another Sync")
	}
}

func TestOwnerSealDescriptorFailureBarrierWithoutWriteSkipsSyncAndTerminates(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	fixture.resetTracking()

	result := sink.FailAndSync(errOwnerSealDescriptorTestNoWrite)
	if result != errOwnerSealDescriptorTestNoWrite {
		t.Fatalf("no-write barrier = %v", result)
	}
	if sink.writeAttempted || fixture.totalReads() != 0 || fixture.totalWrites() != 0 ||
		fixture.totalSyncs() != 0 || fixture.totalMutations() != 0 {
		t.Fatalf("no-write attempted/reads/writes/syncs/mutations = %t/%d/%d/%d/%d",
			sink.writeAttempted, fixture.totalReads(), fixture.totalWrites(),
			fixture.totalSyncs(), fixture.totalMutations())
	}
	if fixture.group.executionState.reopenRequired {
		t.Fatal("ordinary no-write external failure poisoned group")
	}
	if again := sink.FailAndSync(errOwnerSealDescriptorTestReplacement); again != result {
		t.Fatalf("repeated no-write barrier = %v, want %v", again, result)
	}
	if appendErr := sink.Append(fixture.verifications[0]); appendErr != result {
		t.Fatalf("Append after no-write barrier = %v, want %v", appendErr, result)
	}
	if fixture.totalSyncs() != 0 {
		t.Fatal("repeated no-write barrier issued Sync")
	}
}

func TestOwnerSealDescriptorWriteFailurePoisonsRecoveryPrefix(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorFreshReservedOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	firstDevice := fixture.targets[0].Device().DeviceUUID
	fixture.storages[firstDevice].failMutation = 1
	err = sink.Append(fixture.verifications[0])
	if !errors.Is(err, ErrOwnerSealDescriptorStorage) ||
		!errors.Is(err, ErrDeviceMetadataStorage) ||
		!errors.Is(err, errMetadataTestInjected) {
		t.Fatalf("write failure = %v", err)
	}
	if !fixture.group.executionState.reopenRequired ||
		!storageMetadataForUUID(t, fixture.group, firstDevice).reopenRequired {
		t.Fatal("failed first write did not poison group/device")
	}
	if fixture.totalSyncs() != 0 {
		t.Fatal("failed Append performed Sync")
	}
	again := sink.Append(fixture.verifications[1])
	if again != err {
		t.Fatalf("terminal sink returned %v, want original %v", again, err)
	}
	barrier := sink.FailAndSync(err)
	if barrier != err {
		t.Fatalf("write-failure barrier = %v, want original %v", barrier, err)
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("write-failure Sync order = %#v, want %#v", got, want)
	}
	if repeated := sink.FailAndSync(errOwnerSealDescriptorTestReplacement); repeated != barrier {
		t.Fatalf("repeated write-failure barrier = %v, want %v", repeated, barrier)
	}
	if fixture.totalSyncs() != len(fixture.storages) {
		t.Fatal("repeated write-failure barrier issued another Sync")
	}
}

func TestOwnerSealDescriptorFinishTriesEverySyncAfterFailure(t *testing.T) {
	fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
	fixture.seedAllTargets(t)
	fixture.resetTracking()
	fixture.lock(t)
	sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
		fixture.plan,
		ownerSealDescriptorTerminalTargetOnly)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	for logical, verification := range fixture.verifications {
		if err := sink.Append(verification); err != nil {
			t.Fatalf("Append(%d): %v", logical, err)
		}
	}
	for _, storage := range fixture.storages {
		storage.failSync = errOwnerSealDescriptorTestSync
	}
	err = sink.Finish()
	if !errors.Is(err, ErrOwnerSealDescriptorSync) ||
		!errors.Is(err, ErrDeviceMetadataStorage) ||
		!errors.Is(err, errOwnerSealDescriptorTestSync) {
		t.Fatalf("Finish Sync failure = %v", err)
	}
	if got, want := *fixture.syncTrace, []string{"device-a", "device-b"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Sync attempts = %#v, want %#v", got, want)
	}
	if !fixture.group.executionState.reopenRequired {
		t.Fatal("Sync failure did not poison group")
	}
	for _, device := range fixture.group.devices {
		if !device.metadata.reopenRequired {
			t.Fatalf("failed Sync did not poison device %q", device.deviceUUID)
		}
	}
}

func TestOwnerSealDescriptorAllocatorAndGroupBindingConflicts(t *testing.T) {
	t.Run("allocator-free", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		target := fixture.targets[0]
		metadata := storageMetadataForUUID(t, fixture.group, target.Device().DeviceUUID)
		metadata.allocator.allocationBitmap[target.DataPageIndex()/8] &^=
			byte(1) << uint(target.DataPageIndex()%8)
		fixture.lock(t)
		err := fixture.group.preflightOwnerSealDescriptorsLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if !errors.Is(err, ErrOwnerSealDescriptorAllocatorContradiction) {
			t.Fatalf("allocator-free error = %v", err)
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
			t.Fatal("allocator-free conflict mutated storage")
		}
	})

	t.Run("allocator-free-after-sink-construction", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.lock(t)
		sink, err := fixture.group.newOwnerSealDescriptorSinkLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if err != nil {
			t.Fatalf("new sink: %v", err)
		}
		target := fixture.targets[0]
		metadata := storageMetadataForUUID(t, fixture.group, target.Device().DeviceUUID)
		metadata.allocator.allocationBitmap[target.DataPageIndex()/8] &^=
			byte(1) << uint(target.DataPageIndex()%8)
		err = sink.Append(fixture.verifications[0])
		if !errors.Is(err, ErrOwnerSealDescriptorDispositionChanged) ||
			!errors.Is(err, ErrOwnerSealDescriptorAllocatorContradiction) {
			t.Fatalf("late allocator-free error = %v", err)
		}
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
			t.Fatal("late allocator-free contradiction mutated storage")
		}
		if !fixture.group.executionState.reopenRequired {
			t.Fatal("late allocator-free contradiction did not require group reopen")
		}
	})

	t.Run("foreign-opened-device", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		fixture.group.devices[0].metadata.superblock.DeviceUUID = "foreign-device"
		fixture.lock(t)
		err := fixture.group.preflightOwnerSealDescriptorsLocked(
			fixture.plan,
			ownerSealDescriptorFreshReservedOnly)
		if !errors.Is(err, ErrInvalidOwnerSealDescriptorPersistence) {
			t.Fatalf("foreign device error = %v", err)
		}
		if !errors.Is(err, ErrOwnerDeviceGroupMismatch) {
			t.Fatalf("foreign opened-group error lacks durable mismatch category: %v", err)
		}
		requireOwnerSealDescriptorOperation(t, err, "prepare-opened-binding")
		if fixture.totalWrites() != 0 || fixture.totalSyncs() != 0 {
			t.Fatal("foreign binding mutated storage")
		}
	})

	t.Run("caller-plan-binding", func(t *testing.T) {
		fixture := newOwnerSealDescriptorPersistenceTestFixture(t)
		plan := cloneOwnerSealPlan(fixture.plan)
		plan.devices[0].DeviceBindingSHA256 = sha256.Sum256([]byte("foreign-plan-binding"))
		plan.integritySHA256 = ownerSealPlanSHA256(plan)
		if err := plan.Validate(); err != nil {
			t.Fatalf("mutated compact plan should remain structurally valid: %v", err)
		}
		fixture.lock(t)
		err := fixture.group.preflightOwnerSealDescriptorsLocked(
			plan,
			ownerSealDescriptorFreshReservedOnly)
		if !errors.Is(err, ErrInvalidOwnerSealDescriptorPersistence) ||
			!errors.Is(err, ErrInvalidOwnerSealPlan) {
			t.Fatalf("caller plan binding error = %v", err)
		}
		requireOwnerSealDescriptorOperation(t, err, "prepare-plan-binding")
		if fixture.totalReads() != 0 || fixture.totalWrites() != 0 ||
			fixture.totalSyncs() != 0 {
			t.Fatal("caller plan binding mismatch performed storage I/O")
		}
	})
}

func TestOwnerSealDescriptorPersistenceRetainsOnlyCompactState(t *testing.T) {
	sinkType := reflect.TypeOf(ownerSealDescriptorSink{})
	for index := 0; index < sinkType.NumField(); index++ {
		field := sinkType.Field(index)
		if field.Type.Kind() == reflect.Map {
			t.Fatalf("sink retains map field %q", field.Name)
		}
		if field.Type.Kind() == reflect.Slice && field.Name != "devices" {
			t.Fatalf("sink retains unexpected slice field %q", field.Name)
		}
		lower := strings.ToLower(field.Name)
		if (strings.Contains(lower, "bitmap") || strings.Contains(lower, "crcvector") ||
			strings.Contains(lower, "pagetable")) &&
			(field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.Map) {
			t.Fatalf("sink field %q may retain per-page state", field.Name)
		}
	}
	deviceType := reflect.TypeOf(ownerSealDescriptorDevice{})
	for index := 0; index < deviceType.NumField(); index++ {
		kind := deviceType.Field(index).Type.Kind()
		if kind == reflect.Slice || kind == reflect.Map {
			t.Fatalf("compact device retains %s field %q", kind, deviceType.Field(index).Name)
		}
	}
}

func newOwnerSealDescriptorPersistenceTestFixture(
	t *testing.T,
) *ownerSealDescriptorPersistenceTestFixture {
	t.Helper()
	producer := newProducerScatterTestFixture(t)
	geometry := metadataTestGeometry(t, 142<<12, 16<<10)
	if geometry.DataPageCount != 128 {
		t.Fatalf("test geometry data pages = %d, want 128", geometry.DataPageCount)
	}

	deviceUUIDs := []string{"device-a", "device-b"}
	devices := make([]OwnerStateDevice, len(deviceUUIDs))
	for index, deviceUUID := range deviceUUIDs {
		binding := (DeviceSuperblock{
			ClusterID:              producer.owner.ClusterID,
			DeviceUUID:             deviceUUID,
			StorageCompatibilityID: cxlcheckpoint.V7StorageCompatibilityID,
			Geometry:               geometry,
		}).DeviceBindingSHA256()
		devices[index] = OwnerStateDevice{
			DeviceUUID:          deviceUUID,
			DeviceOwnerEpoch:    producer.owner.OwnerEpoch,
			DataPageCount:       geometry.DataPageCount,
			DeviceBindingSHA256: binding,
		}
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	records := producer.owner.Records()
	owner, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    producer.owner.ClusterID,
		OwnerGroupID:                 producer.owner.OwnerGroupID,
		CurrentOwnerID:               producer.owner.CurrentOwnerID,
		AnchorDeviceUUID:             producer.owner.AnchorDeviceUUID,
		StorageCompatibilityID:       producer.owner.StorageCompatibilityID,
		OwnerEpoch:                   producer.owner.OwnerEpoch,
		GroupConfigurationSequence:   producer.owner.GroupConfigurationSequence,
		MembershipSHA256:             membership,
		SnapshotSequence:             producer.owner.SnapshotSequence,
		NextAllocationRecordID:       producer.owner.NextAllocationRecordID,
		NextOwnerTransactionSequence: producer.owner.NextOwnerTransactionSequence,
		Devices:                      devices,
		Records:                      records,
	})
	if err != nil {
		t.Fatalf("NewOwnerStateSnapshot: %v", err)
	}
	producerPlan, err := BuildProducerScatterPlan(owner, 29, producer.initial)
	if err != nil {
		t.Fatalf("BuildProducerScatterPlan: %v", err)
	}
	producer.owner = owner
	producer.plan = producerPlan
	plan := ownerSealPlanTestBuild(t, producer)
	pages := ownerSealTranscriptTestPages(t, producer, plan)
	targets := ownerSealTranscriptTestTargets(t, plan)
	verifications := ownerSealDescriptorTestVerifications(t, plan, pages)

	bootstrap := OwnerStateBootstrap{
		ClusterID:                  owner.ClusterID,
		OwnerGroupID:               owner.OwnerGroupID,
		CurrentOwnerID:             owner.CurrentOwnerID,
		AnchorDeviceUUID:           owner.AnchorDeviceUUID,
		StorageCompatibilityID:     owner.StorageCompatibilityID,
		OwnerEpoch:                 owner.OwnerEpoch,
		GroupConfigurationSequence: owner.GroupConfigurationSequence,
		MembershipSHA256:           membership,
		Devices:                    devices,
	}
	syncTrace := make([]string, 0, len(devices))
	storages := make(map[string]*ownerSealDescriptorTestStorage, len(devices))
	opened := make([]ownerDeviceGroupOpenedDevice, len(devices))
	var anchor *DeviceMetadata
	for index, member := range devices {
		role := OwnerGroupRoleMember
		if member.DeviceUUID == bootstrap.AnchorDeviceUUID {
			role = OwnerGroupRoleAnchor
		}
		superblock := DeviceSuperblock{
			ClusterID:                       bootstrap.ClusterID,
			DeviceUUID:                      member.DeviceUUID,
			OwnerGroupID:                    bootstrap.OwnerGroupID,
			CurrentOwnerID:                  bootstrap.CurrentOwnerID,
			OwnerGroupAnchorDeviceUUID:      bootstrap.AnchorDeviceUUID,
			StorageCompatibilityID:          bootstrap.StorageCompatibilityID,
			OwnerEpoch:                      bootstrap.OwnerEpoch,
			SuperblockSequence:              3,
			OwnerGroupRole:                  role,
			OwnerGroupConfigurationSequence: bootstrap.GroupConfigurationSequence,
			OwnerGroupMembershipSHA256:      bootstrap.MembershipSHA256,
			Geometry:                        geometry,
			ActiveAllocatorSnapshotSlot:     SuperblockSlotA,
			ActiveAllocatorSnapshotSequence: uint64(7 + index),
		}
		bitmap := make([]byte, (geometry.DataPageCount+7)/8)
		for _, target := range targets {
			if target.Device().DeviceUUID == member.DeviceUUID {
				bitmap[target.DataPageIndex()/8] |=
					byte(1) << uint(target.DataPageIndex()%8)
			}
		}
		allocator, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
			DeviceBindingSHA256:             superblock.DeviceBindingSHA256(),
			OwnerGroupIdentitySHA256:        superblock.OwnerGroupIdentitySHA256(),
			OwnerEpoch:                      superblock.OwnerEpoch,
			SnapshotSequence:                superblock.ActiveAllocatorSnapshotSequence,
			AppliedOwnerTransactionSequence: plan.GrantTransactionSequence(),
			DataPageCount:                   geometry.DataPageCount,
		}, bitmap)
		if err != nil {
			t.Fatalf("NewAllocatorSnapshot(%s): %v", member.DeviceUUID, err)
		}
		allocatorWire, err := CanonicalAllocatorSnapshotBytes(allocator, geometry)
		if err != nil {
			t.Fatalf("CanonicalAllocatorSnapshotBytes(%s): %v", member.DeviceUUID, err)
		}
		superblock.ActiveAllocatorSnapshotLength = uint64(len(allocatorWire))
		superblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(allocatorWire)
		if err := validateSuperblockBootstrap(superblock, bootstrap); err != nil {
			t.Fatalf("validateSuperblockBootstrap(%s): %v", member.DeviceUUID, err)
		}
		storage := &ownerSealDescriptorTestStorage{
			metadataTestStorage: newMetadataTestStorage(geometry.DeviceBytes),
			deviceUUID:          member.DeviceUUID,
			syncTrace:           &syncTrace,
		}
		metadata := &DeviceMetadata{
			storage:                  storage,
			geometry:                 geometry,
			bootstrap:                cloneOwnerStateBootstrap(bootstrap),
			superblockSlot:           SuperblockSlotA,
			superblock:               superblock,
			allocator:                allocator,
			ownerStatePresent:        role == OwnerGroupRoleAnchor,
			ownerState:               owner.Clone(),
			ownerStateReadLimitBytes: geometry.OwnerStateSnapshotSlotBytes,
		}
		opened[index] = ownerDeviceGroupOpenedDevice{
			deviceUUID: member.DeviceUUID,
			geometry:   geometry,
			metadata:   metadata,
		}
		if role == OwnerGroupRoleAnchor {
			anchor = metadata
		}
		storages[member.DeviceUUID] = storage
	}
	group := &OwnerDeviceGroup{
		bootstrap:      cloneOwnerStateBootstrap(bootstrap),
		devices:        opened,
		anchor:         anchor,
		executionState: &ownerDeviceGroupExecutionState{},
	}
	group.self = group
	fixture := &ownerSealDescriptorPersistenceTestFixture{
		producer:      producer,
		owner:         owner,
		plan:          plan,
		pages:         pages,
		targets:       targets,
		verifications: verifications,
		geometry:      geometry,
		group:         group,
		storages:      storages,
		syncTrace:     &syncTrace,
	}
	for logical, target := range targets {
		reserved, err := target.ExpectedReservedDescriptor()
		if err != nil {
			t.Fatalf("ExpectedReservedDescriptor(%d): %v", logical, err)
		}
		wire, err := reserved.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal RESERVED(%d): %v", logical, err)
		}
		fixture.writeRawDescriptor(t, uint64(logical), wire)
	}
	fixture.resetTracking()
	return fixture
}

func ownerSealDescriptorTestVerifications(
	t *testing.T,
	plan OwnerSealPlan,
	pages [][]byte,
) []OwnerSealPageVerification {
	t.Helper()
	transcript, err := NewOwnerSealTranscript(plan)
	if err != nil {
		t.Fatalf("NewOwnerSealTranscript: %v", err)
	}
	result := make([]OwnerSealPageVerification, len(pages))
	for logical, page := range pages {
		verification, err := transcript.AppendOwnerRereadPage(
			page,
			ownerSealTranscriptTestCRC32C(page))
		if err != nil {
			t.Fatalf("AppendOwnerRereadPage(%d): %v", logical, err)
		}
		result[logical] = verification
	}
	if _, err := transcript.Finish(); err != nil {
		t.Fatalf("transcript Finish: %v", err)
	}
	return result
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) lock(t *testing.T) {
	t.Helper()
	fixture.group.executionState.mu.Lock()
	t.Cleanup(func() { fixture.group.executionState.mu.Unlock() })
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) resetTracking() {
	*fixture.syncTrace = nil
	for _, storage := range fixture.storages {
		storage.metadataTestStorage.resetTracking()
		storage.syncCalls = 0
		storage.failSync = nil
	}
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) seedAllTargets(t *testing.T) {
	t.Helper()
	for logical, verification := range fixture.verifications {
		fixture.writeTarget(t, uint64(logical), verification.descriptor)
	}
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) writeTarget(
	t *testing.T,
	logical uint64,
	descriptor Descriptor,
) {
	t.Helper()
	wire, err := descriptor.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal target(%d): %v", logical, err)
	}
	fixture.writeRawDescriptor(t, logical, wire)
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) writeReserved(
	t *testing.T,
	logical uint64,
) {
	t.Helper()
	reserved, err := fixture.targets[logical].ExpectedReservedDescriptor()
	if err != nil {
		t.Fatalf("ExpectedReservedDescriptor(%d): %v", logical, err)
	}
	fixture.writeTarget(t, logical, reserved)
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) writeRawDescriptor(
	t *testing.T,
	logical uint64,
	wire []byte,
) {
	t.Helper()
	if len(wire) != PageDescriptorBytes {
		t.Fatalf("raw descriptor length = %d, want %d", len(wire), PageDescriptorBytes)
	}
	target := fixture.targets[logical]
	offset, err := fixture.geometry.DescriptorOffset(target.DataPageIndex())
	if err != nil {
		t.Fatalf("DescriptorOffset(%d): %v", logical, err)
	}
	fixture.storages[target.Device().DeviceUUID].rawWrite(offset, wire)
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) rawDescriptor(
	t *testing.T,
	logical uint64,
) []byte {
	t.Helper()
	target := fixture.targets[logical]
	offset, err := fixture.geometry.DescriptorOffset(target.DataPageIndex())
	if err != nil {
		t.Fatalf("DescriptorOffset(%d): %v", logical, err)
	}
	return fixture.storages[target.Device().DeviceUUID].rawBytes(offset, PageDescriptorBytes)
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) requireReserved(
	t *testing.T,
	logical uint64,
) {
	t.Helper()
	reserved, err := fixture.targets[logical].ExpectedReservedDescriptor()
	if err != nil {
		t.Fatalf("ExpectedReservedDescriptor(%d): %v", logical, err)
	}
	wire, err := reserved.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal RESERVED(%d): %v", logical, err)
	}
	if got := fixture.rawDescriptor(t, logical); !reflect.DeepEqual(got, wire) {
		t.Fatalf("logical page %d is not exact RESERVED", logical)
	}
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) requireAllExactTargets(t *testing.T) {
	t.Helper()
	for logical, verification := range fixture.verifications {
		wire, err := verification.descriptor.MarshalBinary()
		if err != nil {
			t.Fatalf("marshal target(%d): %v", logical, err)
		}
		if got := fixture.rawDescriptor(t, uint64(logical)); !reflect.DeepEqual(got, wire) {
			t.Fatalf("logical page %d is not exact target", logical)
		}
	}
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) totalWrites() int {
	var total int
	for _, storage := range fixture.storages {
		total += storage.writeCalls
	}
	return total
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) totalReads() int {
	var total int
	for _, storage := range fixture.storages {
		total += storage.readCalls
	}
	return total
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) totalSyncs() int {
	var total int
	for _, storage := range fixture.storages {
		total += storage.syncCalls
	}
	return total
}

func (fixture *ownerSealDescriptorPersistenceTestFixture) totalMutations() int {
	var total int
	for _, storage := range fixture.storages {
		total += storage.mutationCount
	}
	return total
}

func storageMetadataForUUID(
	t *testing.T,
	group *OwnerDeviceGroup,
	deviceUUID string,
) *DeviceMetadata {
	t.Helper()
	for _, device := range group.devices {
		if device.deviceUUID == deviceUUID {
			return device.metadata
		}
	}
	t.Fatalf("device %q not found", deviceUUID)
	return nil
}

func requireOwnerSealDescriptorOperation(t *testing.T, err error, want string) {
	t.Helper()
	var operation interface{ Operation() string }
	if !errors.As(err, &operation) {
		t.Fatalf("error %v has no Operation method", err)
	}
	if got := operation.Operation(); got != want {
		t.Fatalf("error operation = %q, want %q: %v", got, want, err)
	}
}
