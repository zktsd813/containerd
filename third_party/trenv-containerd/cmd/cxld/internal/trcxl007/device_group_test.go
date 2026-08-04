package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

type deviceGroupTestRead struct {
	offset uint64
	length int
}

type deviceGroupTestStorage struct {
	*metadataTestStorage
	deviceUUID    string
	writeOrder    *[]string
	writeObserved bool
	reads         []deviceGroupTestRead
	closeCalls    int
}

func (storage *deviceGroupTestStorage) ReadAt(destination []byte, offset int64) (int, error) {
	if offset >= 0 {
		storage.reads = append(storage.reads, deviceGroupTestRead{
			offset: uint64(offset),
			length: len(destination),
		})
	}
	return storage.metadataTestStorage.ReadAt(destination, offset)
}

func (storage *deviceGroupTestStorage) WriteAt(source []byte, offset int64) (int, error) {
	if !storage.writeObserved {
		storage.writeObserved = true
		*storage.writeOrder = append(*storage.writeOrder, storage.deviceUUID)
	}
	return storage.metadataTestStorage.WriteAt(source, offset)
}

func (storage *deviceGroupTestStorage) Close() error {
	storage.closeCalls++
	return nil
}

func (storage *deviceGroupTestStorage) resetGroupTracking() {
	storage.metadataTestStorage.resetTracking()
	storage.reads = nil
}

type deviceGroupTestFixture struct {
	input      OwnerDeviceGroupInput
	storages   map[string]*deviceGroupTestStorage
	writeOrder *[]string
	payloads   map[string][]byte
	geometry   DeviceGeometry
}

func newDeviceGroupTestFixture(t *testing.T) deviceGroupTestFixture {
	t.Helper()
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	writeOrder := make([]string, 0, 3)
	storages := make(map[string]*deviceGroupTestStorage, 3)
	payloads := make(map[string][]byte, 3)
	deviceUUIDs := []string{"device-a", "device-b", "device-c"}
	devices := make([]OwnerStateDevice, len(deviceUUIDs))
	for index, deviceUUID := range deviceUUIDs {
		binding := (DeviceSuperblock{
			ClusterID:              "cluster-device-group",
			DeviceUUID:             deviceUUID,
			StorageCompatibilityID: cxlcheckpoint.V7StorageCompatibilityID,
			Geometry:               geometry,
		}).DeviceBindingSHA256()
		devices[index] = OwnerStateDevice{
			DeviceUUID:          deviceUUID,
			DeviceOwnerEpoch:    7,
			DataPageCount:       geometry.DataPageCount,
			DeviceBindingSHA256: binding,
		}
		storage := &deviceGroupTestStorage{
			metadataTestStorage: newMetadataTestStorage(geometry.DeviceBytes),
			deviceUUID:          deviceUUID,
			writeOrder:          &writeOrder,
		}
		payload := []byte("preserved-payload-" + deviceUUID)
		storage.rawWrite(geometry.ContentRegionBase, payload)
		storages[deviceUUID] = storage
		payloads[deviceUUID] = payload
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	bootstrap := OwnerStateBootstrap{
		ClusterID:                  "cluster-device-group",
		OwnerGroupID:               "owner-group-device-group",
		CurrentOwnerID:             "owner-node-device-group",
		AnchorDeviceUUID:           "device-b",
		StorageCompatibilityID:     cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch:                 7,
		GroupConfigurationSequence: 3,
		MembershipSHA256:           membership,
		Devices:                    devices,
	}
	// Intentionally neither canonical nor format order.
	entries := []OwnerDeviceGroupDeviceInput{
		{
			ExpectedDeviceUUID:       "device-c",
			Storage:                  storages["device-c"],
			Geometry:                 geometry,
			OwnerStateReadLimitBytes: 4096,
		},
		{
			ExpectedDeviceUUID:       "device-b",
			Storage:                  storages["device-b"],
			Geometry:                 geometry,
			OwnerStateReadLimitBytes: 4096,
		},
		{
			ExpectedDeviceUUID:       "device-a",
			Storage:                  storages["device-a"],
			Geometry:                 geometry,
			OwnerStateReadLimitBytes: 4096,
		},
	}
	return deviceGroupTestFixture{
		input: OwnerDeviceGroupInput{
			Devices:             entries,
			OwnerStateBootstrap: bootstrap,
		},
		storages:   storages,
		writeOrder: &writeOrder,
		payloads:   payloads,
		geometry:   geometry,
	}
}

func deviceGroupTestEntry(
	t *testing.T,
	input *OwnerDeviceGroupInput,
	deviceUUID string,
) *OwnerDeviceGroupDeviceInput {
	t.Helper()
	for index := range input.Devices {
		if input.Devices[index].ExpectedDeviceUUID == deviceUUID {
			return &input.Devices[index]
		}
	}
	t.Fatalf("input has no device %q", deviceUUID)
	return nil
}

func deviceGroupTestResetTracking(fixture deviceGroupTestFixture) {
	for _, storage := range fixture.storages {
		storage.resetGroupTracking()
	}
}

func deviceGroupTestAssertNoMutationOrClose(
	t *testing.T,
	fixture deviceGroupTestFixture,
) {
	t.Helper()
	for deviceUUID, storage := range fixture.storages {
		if storage.mutationCount != 0 || len(storage.events) != 0 {
			t.Fatalf("device %q mutated: count=%d events=%#v",
				deviceUUID, storage.mutationCount, storage.events)
		}
		if storage.closeCalls != 0 {
			t.Fatalf("device %q was closed %d times", deviceUUID, storage.closeCalls)
		}
	}
}

func deviceGroupTestAssertPayloads(t *testing.T, fixture deviceGroupTestFixture) {
	t.Helper()
	for deviceUUID, payload := range fixture.payloads {
		storage := fixture.storages[deviceUUID]
		if got := storage.rawBytes(fixture.geometry.ContentRegionBase, len(payload)); !bytes.Equal(got, payload) {
			t.Fatalf("device %q payload = %x, want %x", deviceUUID, got, payload)
		}
	}
}

func deviceGroupTestRequest(state OwnerStateSnapshot) OwnerReserveRequest {
	return OwnerReserveRequest{
		ClusterID:                  state.ClusterID,
		OwnerGroupID:               state.OwnerGroupID,
		CurrentOwnerID:             state.CurrentOwnerID,
		AnchorDeviceUUID:           state.AnchorDeviceUUID,
		StorageCompatibilityID:     state.StorageCompatibilityID,
		OwnerEpoch:                 state.OwnerEpoch,
		GroupConfigurationSequence: state.GroupConfigurationSequence,
		MembershipSHA256:           state.MembershipSHA256,
		RequestID:                  "request-device-group",
		CheckpointID:               "checkpoint-device-group",
		ProducerID:                 "producer-device-group",
		DedupDomainID:              "dedup-device-group",
		SharingPolicyID:            "sharing-device-group",
		MaxExtents:                 1,
		ContentDemands: []OwnerStateContentDemand{{
			Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
			ObjectID:         1,
			ByteLength:       uint64(ContentPageBytes),
			CapacityPages:    1,
			LogicalPageStart: 0,
		}},
		AuthorityEvidence: OwnerStateAuthorityEvidence{
			SchedulerReserveSHA256:     sha256.Sum256([]byte("scheduler-device-group")),
			ProducerCapabilitySHA256:   sha256.Sum256([]byte("producer-device-group")),
			PublicationAuthoritySHA256: sha256.Sum256([]byte("publication-device-group")),
			ReclaimAuthoritySHA256:     sha256.Sum256([]byte("reclaim-device-group")),
		},
	}
}

func TestOwnerDeviceGroupFormatOpenPlannerAndPayload(t *testing.T) {
	fixture := newDeviceGroupTestFixture(t)
	originalInputOrder := []string{
		fixture.input.Devices[0].ExpectedDeviceUUID,
		fixture.input.Devices[1].ExpectedDeviceUUID,
		fixture.input.Devices[2].ExpectedDeviceUUID,
	}
	if err := FormatOwnerDeviceGroupOffline(fixture.input); err != nil {
		t.Fatalf("FormatOwnerDeviceGroupOffline: %v", err)
	}
	wantWriteOrder := []string{"device-a", "device-c", "device-b"}
	if !reflect.DeepEqual(*fixture.writeOrder, wantWriteOrder) {
		t.Fatalf("write order = %v, want %v", *fixture.writeOrder, wantWriteOrder)
	}
	gotInputOrder := []string{
		fixture.input.Devices[0].ExpectedDeviceUUID,
		fixture.input.Devices[1].ExpectedDeviceUUID,
		fixture.input.Devices[2].ExpectedDeviceUUID,
	}
	if !reflect.DeepEqual(gotInputOrder, originalInputOrder) {
		t.Fatalf("caller input order mutated from %v to %v", originalInputOrder, gotInputOrder)
	}
	deviceGroupTestAssertPayloads(t, fixture)

	deviceGroupTestResetTracking(fixture)
	group, err := OpenOwnerDeviceGroup(fixture.input)
	if err != nil {
		t.Fatalf("OpenOwnerDeviceGroup: %v", err)
	}
	ownerState, plannerInputs := group.PlannerInputs()
	if ownerState.SnapshotSequence != 1 || len(plannerInputs) != 3 {
		t.Fatalf("planner inputs = Owner sequence %d, devices %d",
			ownerState.SnapshotSequence, len(plannerInputs))
	}
	wantPlannerOrder := []string{"device-a", "device-b", "device-c"}
	for index := range plannerInputs {
		if plannerInputs[index].DeviceUUID != wantPlannerOrder[index] ||
			plannerInputs[index].Snapshot.SnapshotSequence != 1 ||
			plannerInputs[index].Snapshot.AppliedOwnerTransactionSequence != 0 {
			t.Fatalf("planner input %d = %#v", index, plannerInputs[index])
		}
	}
	plan, err := PlanOwnerCheckpointReserve(
		ownerState,
		plannerInputs,
		deviceGroupTestRequest(ownerState))
	if err != nil || plan.Outcome != OwnerReservePlanned {
		t.Fatalf("PlanOwnerCheckpointReserve = outcome %d, error %v", plan.Outcome, err)
	}

	readsBeforePlanner := make(map[string]int, len(fixture.storages))
	for deviceUUID, storage := range fixture.storages {
		readsBeforePlanner[deviceUUID] = storage.readCalls
	}
	ownerState.SnapshotSequence = 99
	plannerInputs[0].DeviceUUID = "mutated-device"
	plannerInputs[0].Geometry.DataPageCount++
	plannerInputs[0].Snapshot.SnapshotSequence = 99
	plannerInputs[0].Snapshot.allocationBitmap[0] ^= 1
	fixture.input.Devices[0].ExpectedDeviceUUID = "mutated-input"
	fixture.input.OwnerStateBootstrap.Devices[0].DeviceUUID = "mutated-bootstrap"
	detachedOwner, detachedInputs := group.PlannerInputs()
	if detachedOwner.SnapshotSequence != 1 ||
		detachedInputs[0].DeviceUUID != "device-a" ||
		detachedInputs[0].Snapshot.SnapshotSequence != 1 ||
		detachedInputs[0].Snapshot.allocationBitmap[0] != 0 {
		t.Fatalf("planner result aliases caller/output mutation: %#v %#v",
			detachedOwner, detachedInputs[0])
	}
	bootstrap := group.Bootstrap()
	bootstrap.Devices[0].DeviceUUID = "mutated-returned-bootstrap"
	if group.Bootstrap().Devices[0].DeviceUUID != "device-a" {
		t.Fatal("Bootstrap accessor aliases group state")
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.readCalls != readsBeforePlanner[deviceUUID] {
			t.Fatalf("PlannerInputs reread device %q", deviceUUID)
		}
		if storage.mutationCount != 0 || storage.closeCalls != 0 {
			t.Fatalf("open/planner mutated or closed device %q", deviceUUID)
		}
	}
}

func TestOwnerDeviceGroupInvalidFormatInputWritesNothing(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*deviceGroupTestFixture)
	}{
		{"duplicate-UUID", func(fixture *deviceGroupTestFixture) {
			fixture.input.Devices[0].ExpectedDeviceUUID = "device-a"
		}},
		{"missing-device", func(fixture *deviceGroupTestFixture) {
			fixture.input.Devices = fixture.input.Devices[:2]
		}},
		{"extra-device", func(fixture *deviceGroupTestFixture) {
			fixture.input.Devices = append(fixture.input.Devices, OwnerDeviceGroupDeviceInput{
				ExpectedDeviceUUID:       "device-extra",
				Storage:                  newMetadataTestStorage(8 << 20),
				Geometry:                 fixture.input.Devices[0].Geometry,
				OwnerStateReadLimitBytes: 4096,
			})
		}},
		{"geometry", func(fixture *deviceGroupTestFixture) {
			deviceGroupTestEntry(t, &fixture.input, "device-c").Geometry =
				metadataTestGeometry(t, 9<<20, 4096)
		}},
		{"membership-binding", func(fixture *deviceGroupTestFixture) {
			fixture.input.OwnerStateBootstrap.Devices = append(
				[]OwnerStateDevice(nil), fixture.input.OwnerStateBootstrap.Devices...)
			fixture.input.OwnerStateBootstrap.Devices[0].DeviceBindingSHA256 =
				sha256.Sum256([]byte("wrong binding"))
			fixture.input.OwnerStateBootstrap.MembershipSHA256, _ =
				OwnerGroupMembershipSHA256(fixture.input.OwnerStateBootstrap.Devices)
		}},
		{"member-epoch", func(fixture *deviceGroupTestFixture) {
			fixture.input.OwnerStateBootstrap.Devices = append(
				[]OwnerStateDevice(nil), fixture.input.OwnerStateBootstrap.Devices...)
			fixture.input.OwnerStateBootstrap.Devices[2].DeviceOwnerEpoch++
			fixture.input.OwnerStateBootstrap.MembershipSHA256, _ =
				OwnerGroupMembershipSHA256(fixture.input.OwnerStateBootstrap.Devices)
		}},
		{"anchor-read-limit", func(fixture *deviceGroupTestFixture) {
			deviceGroupTestEntry(t, &fixture.input, "device-b").OwnerStateReadLimitBytes = 64
		}},
		{"aliased-storage", func(fixture *deviceGroupTestFixture) {
			deviceGroupTestEntry(t, &fixture.input, "device-c").Storage =
				deviceGroupTestEntry(t, &fixture.input, "device-a").Storage
		}},
		{"late-size-mismatch", func(fixture *deviceGroupTestFixture) {
			fixture.storages["device-c"].size--
		}},
		{"missing-anchor", func(fixture *deviceGroupTestFixture) {
			fixture.input.OwnerStateBootstrap.AnchorDeviceUUID = "device-missing"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeviceGroupTestFixture(t)
			test.mutate(&fixture)
			if err := FormatOwnerDeviceGroupOffline(fixture.input); err == nil {
				t.Fatal("invalid group formatted successfully")
			}
			deviceGroupTestAssertNoMutationOrClose(t, fixture)
			if len(*fixture.writeOrder) != 0 {
				t.Fatalf("invalid group write order = %v", *fixture.writeOrder)
			}
			deviceGroupTestAssertPayloads(t, fixture)
		})
	}
}

func TestOwnerDeviceGroupPartialFormatFailsClosed(t *testing.T) {
	for _, failureDevice := range []string{"device-c", "device-b"} {
		t.Run(failureDevice, func(t *testing.T) {
			fixture := newDeviceGroupTestFixture(t)
			fixture.storages[failureDevice].failMutation = 1
			err := FormatOwnerDeviceGroupOffline(fixture.input)
			if !errors.Is(err, ErrOwnerDeviceGroupFormatIncomplete) ||
				!errors.Is(err, ErrDeviceMetadataStorage) {
				t.Fatalf("partial-format error = %v", err)
			}
			wantOrder := []string{"device-a", "device-c"}
			if failureDevice == "device-b" {
				wantOrder = []string{"device-a", "device-c", "device-b"}
			}
			if !reflect.DeepEqual(*fixture.writeOrder, wantOrder) {
				t.Fatalf("partial write order = %v, want %v", *fixture.writeOrder, wantOrder)
			}
			if fixture.storages["device-b"].mutationCount != 0 && failureDevice != "device-b" {
				t.Fatal("ANCHOR was touched after MEMBER failure")
			}
			for _, storage := range fixture.storages {
				storage.failMutation = 0
			}
			mutations := make(map[string]int, len(fixture.storages))
			for deviceUUID, storage := range fixture.storages {
				mutations[deviceUUID] = storage.mutationCount
			}
			if _, openErr := OpenOwnerDeviceGroup(fixture.input); openErr == nil {
				t.Fatal("partially formatted fresh group opened successfully")
			}
			for deviceUUID, storage := range fixture.storages {
				if storage.mutationCount != mutations[deviceUUID] {
					t.Fatalf("failed group open wrote device %q", deviceUUID)
				}
				if storage.closeCalls != 0 {
					t.Fatalf("failed format/open closed device %q", deviceUUID)
				}
			}
			deviceGroupTestAssertPayloads(t, fixture)
		})
	}
}

func TestOwnerDeviceGroupOpenRejectsMembershipShapeAndSwappedStorage(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*deviceGroupTestFixture)
		wantNoReads bool
	}{
		{"missing", func(fixture *deviceGroupTestFixture) {
			fixture.input.Devices = fixture.input.Devices[:2]
		}, true},
		{"duplicate", func(fixture *deviceGroupTestFixture) {
			fixture.input.Devices[0].ExpectedDeviceUUID = "device-a"
		}, true},
		{"extra", func(fixture *deviceGroupTestFixture) {
			fixture.input.Devices = append(fixture.input.Devices, fixture.input.Devices[0])
		}, true},
		{"swapped", func(fixture *deviceGroupTestFixture) {
			left := deviceGroupTestEntry(t, &fixture.input, "device-a")
			right := deviceGroupTestEntry(t, &fixture.input, "device-c")
			left.Storage, right.Storage = right.Storage, left.Storage
		}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newDeviceGroupTestFixture(t)
			if err := FormatOwnerDeviceGroupOffline(fixture.input); err != nil {
				t.Fatalf("format baseline: %v", err)
			}
			deviceGroupTestResetTracking(fixture)
			test.mutate(&fixture)
			_, err := OpenOwnerDeviceGroup(fixture.input)
			if err == nil {
				t.Fatal("invalid group opened successfully")
			}
			var totalReads int
			for deviceUUID, storage := range fixture.storages {
				totalReads += storage.readCalls
				if storage.mutationCount != 0 || storage.closeCalls != 0 {
					t.Fatalf("invalid open mutated/closed device %q", deviceUUID)
				}
			}
			if test.wantNoReads && totalReads != 0 {
				t.Fatalf("preflight failure performed %d reads", totalReads)
			}
			if !test.wantNoReads && !errors.Is(err, ErrOwnerDeviceGroupMismatch) {
				t.Fatalf("swapped-storage error = %v", err)
			}
		})
	}
}

func TestOwnerDeviceGroupOpenRejectsMemberAheadOfAnchor(t *testing.T) {
	fixture := newDeviceGroupTestFixture(t)
	if err := FormatOwnerDeviceGroupOffline(fixture.input); err != nil {
		t.Fatalf("format baseline: %v", err)
	}
	prepared, err := prepareOwnerDeviceGroup(fixture.input)
	if err != nil {
		t.Fatalf("prepare fixture: %v", err)
	}
	var memberIndex int
	for index := range prepared.devices {
		if prepared.devices[index].input.ExpectedDeviceUUID == "device-c" {
			memberIndex = index
		}
	}
	genesis, err := buildOwnerDeviceGroupGenesis(prepared, memberIndex)
	if err != nil {
		t.Fatalf("build member genesis: %v", err)
	}
	bitmap := genesis.AllocatorSnapshot.BitmapBytes()
	ahead, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             genesis.AllocatorSnapshot.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        genesis.AllocatorSnapshot.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      genesis.AllocatorSnapshot.OwnerEpoch,
		SnapshotSequence:                2,
		AppliedOwnerTransactionSequence: 1,
		DataPageCount:                   genesis.AllocatorSnapshot.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("ahead allocator: %v", err)
	}
	allocatorWire, err := CanonicalAllocatorSnapshotBytes(ahead, genesis.Superblock.Geometry)
	if err != nil {
		t.Fatalf("encode ahead allocator: %v", err)
	}
	superblock := genesis.Superblock
	superblock.SuperblockSequence = 2
	superblock.ActiveAllocatorSnapshotSlot = SuperblockSlotB
	superblock.ActiveAllocatorSnapshotSequence = 2
	superblock.ActiveAllocatorSnapshotLength = uint64(len(allocatorWire))
	superblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(allocatorWire)
	superblockWire, err := CanonicalSuperblockBytes(superblock)
	if err != nil {
		t.Fatalf("encode ahead superblock: %v", err)
	}
	storage := fixture.storages["device-c"]
	storage.rawWrite(superblock.Geometry.AllocatorSnapshotBOffset, allocatorWire)
	storage.rawWrite(superblock.Geometry.SuperblockBOffset, superblockWire)
	deviceGroupTestResetTracking(fixture)
	_, err = OpenOwnerDeviceGroup(fixture.input)
	if !errors.Is(err, ErrOwnerDeviceGroupMismatch) {
		t.Fatalf("ahead MEMBER error = %v", err)
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.mutationCount != 0 || storage.closeCalls != 0 {
			t.Fatalf("ahead open mutated/closed device %q", deviceUUID)
		}
	}
}

func TestOwnerDeviceGroupOpenAllowsUnequalAppliedTransactionsBelowAnchor(t *testing.T) {
	fixture := newDeviceGroupTestFixture(t)
	if err := FormatOwnerDeviceGroupOffline(fixture.input); err != nil {
		t.Fatalf("format baseline: %v", err)
	}
	group, err := OpenOwnerDeviceGroup(fixture.input)
	if err != nil {
		t.Fatalf("open baseline: %v", err)
	}
	ownerState, allocatorInputs := group.PlannerInputs()
	plan, err := PlanOwnerCheckpointReserve(
		ownerState,
		allocatorInputs,
		deviceGroupTestRequest(ownerState))
	if err != nil || plan.Outcome != OwnerReservePlanned || len(plan.AllocatorUpdates) != 1 {
		t.Fatalf("reserve plan = outcome %d, updates %d, error %v",
			plan.Outcome, len(plan.AllocatorUpdates), err)
	}
	// This persistence-only fixture applies planner metadata without publishing
	// descriptors or content. It tests the group reopen high-water rule, not a
	// complete legal checkpoint execution.
	if err := group.anchor.commitOwnerState(plan.PreparingOwnerState); err != nil {
		t.Fatalf("commit PREPARING Owner state: %v", err)
	}
	update := plan.AllocatorUpdates[0]
	var updatedDevice *DeviceMetadata
	for index := range group.devices {
		if group.devices[index].deviceUUID == update.DeviceUUID {
			updatedDevice = group.devices[index].metadata
			break
		}
	}
	if updatedDevice == nil {
		t.Fatalf("planned update names unknown device %q", update.DeviceUUID)
	}
	if err := updatedDevice.commitAllocatorSnapshot(update.DesiredSnapshot); err != nil {
		t.Fatalf("commit allocator update: %v", err)
	}
	if err := group.anchor.commitOwnerState(plan.GrantedOwnerState); err != nil {
		t.Fatalf("commit GRANTED Owner state: %v", err)
	}

	deviceGroupTestResetTracking(fixture)
	reopened, err := OpenOwnerDeviceGroup(fixture.input)
	if err != nil {
		t.Fatalf("open group with lagging MEMBER allocators: %v", err)
	}
	reopenedOwner, reopenedInputs := reopened.PlannerInputs()
	if reopenedOwner.NextOwnerTransactionSequence != 3 {
		t.Fatalf("next Owner transaction = %d, want 3",
			reopenedOwner.NextOwnerTransactionSequence)
	}
	for _, input := range reopenedInputs {
		wantApplied := uint64(0)
		if input.DeviceUUID == update.DeviceUUID {
			wantApplied = 1
		}
		if input.Snapshot.AppliedOwnerTransactionSequence != wantApplied {
			t.Fatalf("device %q applied transaction = %d, want %d",
				input.DeviceUUID,
				input.Snapshot.AppliedOwnerTransactionSequence,
				wantApplied)
		}
		if input.Snapshot.AppliedOwnerTransactionSequence >=
			reopenedOwner.NextOwnerTransactionSequence {
			t.Fatalf("device %q applied transaction is not strictly below Owner high-water",
				input.DeviceUUID)
		}
	}
	for deviceUUID, storage := range fixture.storages {
		if storage.mutationCount != 0 || storage.closeCalls != 0 {
			t.Fatalf("reopen mutated/closed device %q", deviceUUID)
		}
	}
}

func TestOwnerDeviceGroupBitmapAllocationRejectsHostIntOverflow(t *testing.T) {
	tooLarge := uint64(maxIntValue()) + 1
	if _, err := allocateOwnerDeviceGroupZeroBitmap(tooLarge); err == nil {
		t.Fatalf("allocated host-int-overflowing bitmap of %d bytes", tooLarge)
	}
}

func TestOwnerDeviceGroupReadLimitBlankAndNoIOAmplification(t *testing.T) {
	t.Run("blank-no-autoformat", func(t *testing.T) {
		fixture := newDeviceGroupTestFixture(t)
		if _, err := OpenOwnerDeviceGroup(fixture.input); err == nil {
			t.Fatal("blank group opened successfully")
		}
		deviceGroupTestAssertNoMutationOrClose(t, fixture)
	})

	t.Run("read-limit", func(t *testing.T) {
		fixture := newDeviceGroupTestFixture(t)
		if err := FormatOwnerDeviceGroupOffline(fixture.input); err != nil {
			t.Fatalf("format baseline: %v", err)
		}
		deviceGroupTestResetTracking(fixture)
		deviceGroupTestEntry(t, &fixture.input, "device-b").OwnerStateReadLimitBytes = 64
		_, err := OpenOwnerDeviceGroup(fixture.input)
		if !errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) {
			t.Fatalf("read-limit error = %v", err)
		}
		anchor := fixture.storages["device-b"]
		ownerBody := fixture.input.Devices[0].Geometry.OwnerStateSnapshotAOffset +
			OwnerStateEnvelopeHeaderBytes
		for _, read := range anchor.reads {
			if read.offset == ownerBody {
				t.Fatalf("read-limit open read Owner body: %#v", read)
			}
		}
		for deviceUUID, storage := range fixture.storages {
			if storage.mutationCount != 0 || storage.closeCalls != 0 {
				t.Fatalf("read-limit open mutated/closed %q", deviceUUID)
			}
		}
	})

	t.Run("bounded-success", func(t *testing.T) {
		fixture := newDeviceGroupTestFixture(t)
		if err := FormatOwnerDeviceGroupOffline(fixture.input); err != nil {
			t.Fatalf("format baseline: %v", err)
		}
		deviceGroupTestResetTracking(fixture)
		if _, err := OpenOwnerDeviceGroup(fixture.input); err != nil {
			t.Fatalf("OpenOwnerDeviceGroup: %v", err)
		}
		for deviceUUID, storage := range fixture.storages {
			wantReads := 6
			if deviceUUID == "device-b" {
				wantReads = 7
			}
			if storage.readCalls != wantReads {
				t.Fatalf("device %q read calls = %d, want %d",
					deviceUUID, storage.readCalls, wantReads)
			}
			if storage.maxRead > int(SuperblockSlotBytes) {
				t.Fatalf("device %q max read = %d", deviceUUID, storage.maxRead)
			}
			entry := deviceGroupTestEntry(t, &fixture.input, deviceUUID)
			for _, read := range storage.reads {
				if read.offset >= entry.Geometry.DescriptorRegionBase {
					t.Fatalf("device %q read descriptor/content at %#v", deviceUUID, read)
				}
			}
			if storage.mutationCount != 0 || storage.closeCalls != 0 {
				t.Fatalf("bounded open mutated/closed %q", deviceUUID)
			}
		}
	})
}

func TestOwnerDeviceGroupFormatErrorPreservesCause(t *testing.T) {
	fixture := newDeviceGroupTestFixture(t)
	fixture.storages["device-a"].failMutation = 1
	err := FormatOwnerDeviceGroupOffline(fixture.input)
	if err == nil || !errors.Is(err, ErrOwnerDeviceGroupFormatIncomplete) ||
		!errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("format error = %v", err)
	}
	if got := fmt.Sprint(err); got == "" {
		t.Fatal("format error has an empty message")
	}
}
