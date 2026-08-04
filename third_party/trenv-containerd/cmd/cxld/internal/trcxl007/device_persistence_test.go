package trcxl007

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

var errMetadataTestInjected = errors.New("injected metadata storage failure")

var _ DeviceMetadataStorage = (*metadataTestStorage)(nil)

type metadataTestEvent struct {
	kind   string
	offset uint64
	length int
}

// metadataTestStorage is sparse so a test can expose a 64 MiB Owner-state slot
// without allocating a device-sized byte slice. Only nonzero bytes are kept.
type metadataTestStorage struct {
	size  uint64
	bytes map[uint64]byte

	mutationCount  int
	failMutation   int
	readCalls      int
	writeCalls     int
	shortReadCall  int
	shortWriteCall int
	failReadOffset *uint64

	maxRead  int
	maxWrite int
	events   []metadataTestEvent
}

func newMetadataTestStorage(size uint64) *metadataTestStorage {
	return &metadataTestStorage{size: size, bytes: make(map[uint64]byte)}
}

func (storage *metadataTestStorage) Size() uint64 { return storage.size }

func (storage *metadataTestStorage) ReadAt(destination []byte, offset int64) (int, error) {
	storage.readCalls++
	if len(destination) > storage.maxRead {
		storage.maxRead = len(destination)
	}
	if offset < 0 {
		return 0, fmt.Errorf("negative read offset %d", offset)
	}
	start := uint64(offset)
	if storage.failReadOffset != nil && start == *storage.failReadOffset {
		return 0, errMetadataTestInjected
	}
	if start > storage.size || uint64(len(destination)) > storage.size-start {
		return 0, io.EOF
	}
	length := len(destination)
	short := storage.shortReadCall != 0 && storage.readCalls == storage.shortReadCall
	if short && length > 0 {
		length--
	}
	for index := 0; index < length; index++ {
		destination[index] = storage.bytes[start+uint64(index)]
	}
	if short {
		return length, nil
	}
	return length, nil
}

func (storage *metadataTestStorage) WriteAt(source []byte, offset int64) (int, error) {
	storage.writeCalls++
	if len(source) > storage.maxWrite {
		storage.maxWrite = len(source)
	}
	if err := storage.beforeMutation(); err != nil {
		return 0, err
	}
	if offset < 0 {
		return 0, fmt.Errorf("negative write offset %d", offset)
	}
	start := uint64(offset)
	if start > storage.size || uint64(len(source)) > storage.size-start {
		return 0, io.ErrShortWrite
	}
	length := len(source)
	short := storage.shortWriteCall != 0 && storage.writeCalls == storage.shortWriteCall
	if short && length > 0 {
		length--
	}
	storage.rawWrite(start, source[:length])
	storage.events = append(storage.events, metadataTestEvent{
		kind: "write", offset: start, length: length,
	})
	if short {
		return length, nil
	}
	return length, nil
}

func (storage *metadataTestStorage) Sync() error {
	if err := storage.beforeMutation(); err != nil {
		return err
	}
	storage.events = append(storage.events, metadataTestEvent{kind: "sync"})
	return nil
}

func (storage *metadataTestStorage) beforeMutation() error {
	storage.mutationCount++
	if storage.failMutation != 0 && storage.mutationCount == storage.failMutation {
		return errMetadataTestInjected
	}
	return nil
}

func (storage *metadataTestStorage) rawWrite(offset uint64, source []byte) {
	for index, value := range source {
		position := offset + uint64(index)
		if value == 0 {
			delete(storage.bytes, position)
		} else {
			storage.bytes[position] = value
		}
	}
}

func (storage *metadataTestStorage) rawBytes(offset uint64, length int) []byte {
	result := make([]byte, length)
	for index := range result {
		result[index] = storage.bytes[offset+uint64(index)]
	}
	return result
}

func (storage *metadataTestStorage) clone() *metadataTestStorage {
	clone := newMetadataTestStorage(storage.size)
	for offset, value := range storage.bytes {
		clone.bytes[offset] = value
	}
	return clone
}

func (storage *metadataTestStorage) resetTracking() {
	storage.mutationCount = 0
	storage.failMutation = 0
	storage.readCalls = 0
	storage.writeCalls = 0
	storage.shortReadCall = 0
	storage.shortWriteCall = 0
	storage.failReadOffset = nil
	storage.maxRead = 0
	storage.maxWrite = 0
	storage.events = nil
}

type metadataTestFixture struct {
	input DeviceFormatInput
}

func metadataTestGeometry(t *testing.T, deviceBytes, ownerSlotBytes uint64) DeviceGeometry {
	t.Helper()
	geometry, err := CalculateDeviceGeometry(deviceBytes, 4096, ownerSlotBytes)
	if err != nil {
		t.Fatalf("CalculateDeviceGeometry: %v", err)
	}
	return geometry
}

func metadataTestFixtureForRole(
	t *testing.T,
	geometry DeviceGeometry,
	role OwnerGroupRole,
) metadataTestFixture {
	t.Helper()
	deviceUUID := "device-anchor"
	anchorUUID := deviceUUID
	if role == OwnerGroupRoleMember {
		deviceUUID = "device-member"
	}
	superblock := DeviceSuperblock{
		ClusterID:                       "cluster-test",
		DeviceUUID:                      deviceUUID,
		OwnerGroupID:                    "owner-group-test",
		CurrentOwnerID:                  "owner-node-test",
		OwnerGroupAnchorDeviceUUID:      anchorUUID,
		StorageCompatibilityID:          cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch:                      1,
		SuperblockSequence:              1,
		OwnerGroupRole:                  role,
		OwnerGroupConfigurationSequence: 1,
		Geometry:                        geometry,
		ActiveAllocatorSnapshotSlot:     SuperblockSlotA,
		ActiveAllocatorSnapshotSequence: 1,
	}
	selfBinding := superblock.DeviceBindingSHA256()
	devices := []OwnerStateDevice{{
		DeviceUUID:          deviceUUID,
		DeviceOwnerEpoch:    superblock.OwnerEpoch,
		DataPageCount:       geometry.DataPageCount,
		DeviceBindingSHA256: selfBinding,
	}}
	if role == OwnerGroupRoleMember {
		devices = []OwnerStateDevice{
			{
				DeviceUUID:          anchorUUID,
				DeviceOwnerEpoch:    superblock.OwnerEpoch,
				DataPageCount:       geometry.DataPageCount,
				DeviceBindingSHA256: sha256.Sum256([]byte("anchor binding fixture")),
			},
			devices[0],
		}
	}
	membership, err := OwnerGroupMembershipSHA256(devices)
	if err != nil {
		t.Fatalf("OwnerGroupMembershipSHA256: %v", err)
	}
	superblock.OwnerGroupMembershipSHA256 = membership
	bootstrap := OwnerStateBootstrap{
		ClusterID:                  superblock.ClusterID,
		OwnerGroupID:               superblock.OwnerGroupID,
		CurrentOwnerID:             superblock.CurrentOwnerID,
		AnchorDeviceUUID:           superblock.OwnerGroupAnchorDeviceUUID,
		StorageCompatibilityID:     superblock.StorageCompatibilityID,
		OwnerEpoch:                 superblock.OwnerEpoch,
		GroupConfigurationSequence: superblock.OwnerGroupConfigurationSequence,
		MembershipSHA256:           membership,
		Devices:                    devices,
	}
	bitmap := make([]byte, (geometry.DataPageCount+7)/8)
	allocator, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             selfBinding,
		OwnerGroupIdentitySHA256:        superblock.OwnerGroupIdentitySHA256(),
		OwnerEpoch:                      superblock.OwnerEpoch,
		SnapshotSequence:                1,
		AppliedOwnerTransactionSequence: 0,
		DataPageCount:                   geometry.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("NewAllocatorSnapshot: %v", err)
	}
	allocatorExact, err := CanonicalAllocatorSnapshotBytes(allocator, geometry)
	if err != nil {
		t.Fatalf("CanonicalAllocatorSnapshotBytes: %v", err)
	}
	superblock.ActiveAllocatorSnapshotLength = uint64(len(allocatorExact))
	superblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(allocatorExact)

	var ownerState *OwnerStateSnapshot
	if role == OwnerGroupRoleAnchor {
		value, err := NewOwnerStateSnapshot(OwnerStateConfig{
			ClusterID:                    bootstrap.ClusterID,
			OwnerGroupID:                 bootstrap.OwnerGroupID,
			CurrentOwnerID:               bootstrap.CurrentOwnerID,
			AnchorDeviceUUID:             bootstrap.AnchorDeviceUUID,
			StorageCompatibilityID:       bootstrap.StorageCompatibilityID,
			OwnerEpoch:                   bootstrap.OwnerEpoch,
			GroupConfigurationSequence:   bootstrap.GroupConfigurationSequence,
			MembershipSHA256:             bootstrap.MembershipSHA256,
			SnapshotSequence:             1,
			NextAllocationRecordID:       1,
			NextOwnerTransactionSequence: 1,
			Devices:                      bootstrap.Devices,
		})
		if err != nil {
			t.Fatalf("NewOwnerStateSnapshot: %v", err)
		}
		ownerState = &value
	}
	input := DeviceFormatInput{
		Superblock:          superblock,
		AllocatorSnapshot:   allocator,
		OwnerStateBootstrap: bootstrap,
		OwnerState:          ownerState,
	}
	if _, err := validateDeviceFormatInput(newMetadataTestStorage(geometry.DeviceBytes), input); err != nil {
		t.Fatalf("fixture validation: %v", err)
	}
	return metadataTestFixture{input: input}
}

func metadataTestFormat(t *testing.T, fixture metadataTestFixture) *metadataTestStorage {
	t.Helper()
	storage := newMetadataTestStorage(fixture.input.Superblock.Geometry.DeviceBytes)
	if err := FormatDeviceMetadata(storage, fixture.input); err != nil {
		t.Fatalf("FormatDeviceMetadata: %v", err)
	}
	storage.resetTracking()
	return storage
}

func metadataTestSeedFixture(t *testing.T, storage *metadataTestStorage, fixture metadataTestFixture) {
	t.Helper()
	geometry := fixture.input.Superblock.Geometry
	allocator, err := CanonicalAllocatorSnapshotBytes(fixture.input.AllocatorSnapshot, geometry)
	if err != nil {
		t.Fatalf("encode allocator: %v", err)
	}
	superblock, err := CanonicalSuperblockBytes(fixture.input.Superblock)
	if err != nil {
		t.Fatalf("encode superblock: %v", err)
	}
	storage.rawWrite(geometry.AllocatorSnapshotAOffset, allocator)
	if fixture.input.OwnerState != nil {
		owner, err := CanonicalOwnerStateBytes(*fixture.input.OwnerState, geometry)
		if err != nil {
			t.Fatalf("encode Owner state: %v", err)
		}
		storage.rawWrite(geometry.OwnerStateSnapshotAOffset, owner)
	}
	storage.rawWrite(geometry.SuperblockAOffset, superblock)
}

func metadataTestWriteEmptyPair(
	t *testing.T,
	storage *metadataTestStorage,
	superblock DeviceSuperblock,
	superblockSlot,
	allocatorSlot SuperblockSlot,
	allocatorSequence uint64,
) DeviceSuperblock {
	t.Helper()
	bitmap := make([]byte, (superblock.Geometry.DataPageCount+7)/8)
	allocator, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             superblock.DeviceBindingSHA256(),
		OwnerGroupIdentitySHA256:        superblock.OwnerGroupIdentitySHA256(),
		OwnerEpoch:                      superblock.OwnerEpoch,
		SnapshotSequence:                allocatorSequence,
		AppliedOwnerTransactionSequence: 0,
		DataPageCount:                   superblock.Geometry.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("new candidate allocator: %v", err)
	}
	allocatorWire, err := CanonicalAllocatorSnapshotBytes(allocator, superblock.Geometry)
	if err != nil {
		t.Fatalf("encode candidate allocator: %v", err)
	}
	superblock.ActiveAllocatorSnapshotSlot = allocatorSlot
	superblock.ActiveAllocatorSnapshotSequence = allocatorSequence
	superblock.ActiveAllocatorSnapshotLength = uint64(len(allocatorWire))
	superblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(allocatorWire)
	superblockWire, err := CanonicalSuperblockBytes(superblock)
	if err != nil {
		t.Fatalf("encode candidate superblock: %v", err)
	}
	allocatorOffset, err := allocatorSnapshotSlotOffset(superblock.Geometry, allocatorSlot)
	if err != nil {
		t.Fatalf("candidate allocator offset: %v", err)
	}
	superblockOffset, err := superblockSlotOffset(superblock.Geometry, superblockSlot)
	if err != nil {
		t.Fatalf("candidate superblock offset: %v", err)
	}
	storage.rawWrite(allocatorOffset, allocatorWire)
	storage.rawWrite(superblockOffset, superblockWire)
	return superblock
}

func metadataTestOpen(t *testing.T, storage *metadataTestStorage, fixture metadataTestFixture) *DeviceMetadata {
	t.Helper()
	opened, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
	if err != nil {
		t.Fatalf("OpenDeviceMetadata: %v", err)
	}
	return opened
}

func metadataTestOpenInput(fixture metadataTestFixture) DeviceOpenInput {
	limit := fixture.input.Superblock.Geometry.OwnerStateSnapshotSlotBytes
	if limit > 1<<20 {
		limit = 1 << 20
	}
	return DeviceOpenInput{
		Geometry:                 fixture.input.Superblock.Geometry,
		OwnerStateBootstrap:      fixture.input.OwnerStateBootstrap,
		OwnerStateReadLimitBytes: limit,
	}
}

func metadataTestNextAllocator(
	t *testing.T,
	current AllocatorSnapshot,
	page uint64,
) AllocatorSnapshot {
	t.Helper()
	bitmap := current.BitmapBytes()
	bitmap[page/8] |= byte(1) << uint(page%8)
	next, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                current.SnapshotSequence + 1,
		AppliedOwnerTransactionSequence: current.AppliedOwnerTransactionSequence + 1,
		DataPageCount:                   current.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("next allocator: %v", err)
	}
	return next
}

func metadataTestIssueOwnerTransaction(
	t *testing.T,
	storage *metadataTestStorage,
	fixture metadataTestFixture,
) {
	t.Helper()
	opened := metadataTestOpen(t, storage, fixture)
	_, current, present := opened.ActiveOwnerState()
	if !present {
		t.Fatal("cannot issue Owner transaction on MEMBER")
	}
	next := metadataTestOwnerSnapshot(
		t,
		current,
		current.SnapshotSequence+1,
		current.NextAllocationRecordID,
		current.NextOwnerTransactionSequence+1)
	if err := opened.commitOwnerState(next); err != nil {
		t.Fatalf("issue Owner transaction: %v", err)
	}
	storage.resetTracking()
}

func metadataTestOwnerSnapshot(
	t *testing.T,
	current OwnerStateSnapshot,
	snapshotSequence,
	nextAllocationID,
	nextTransactionSequence uint64,
) OwnerStateSnapshot {
	t.Helper()
	next, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    current.ClusterID,
		OwnerGroupID:                 current.OwnerGroupID,
		CurrentOwnerID:               current.CurrentOwnerID,
		AnchorDeviceUUID:             current.AnchorDeviceUUID,
		StorageCompatibilityID:       current.StorageCompatibilityID,
		OwnerEpoch:                   current.OwnerEpoch,
		GroupConfigurationSequence:   current.GroupConfigurationSequence,
		MembershipSHA256:             current.MembershipSHA256,
		SnapshotSequence:             snapshotSequence,
		NextAllocationRecordID:       nextAllocationID,
		NextOwnerTransactionSequence: nextTransactionSequence,
		Devices:                      current.Devices(),
		Records:                      current.Records(),
	})
	if err != nil {
		t.Fatalf("next Owner state: %v", err)
	}
	return next
}

func TestOpenDeviceMetadataBlankNeverFormats(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := newMetadataTestStorage(geometry.DeviceBytes)
	_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrNoValidSuperblock) {
		t.Fatalf("blank open error = %v", err)
	}
	if storage.mutationCount != 0 || len(storage.events) != 0 {
		t.Fatalf("blank open mutated storage: %#v", storage.events)
	}
}

func TestCommitAllocatorFailurePrefixesPreserveCompletePair(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	baseline := metadataTestFormat(t, fixture)
	metadataTestIssueOwnerTransaction(t, baseline, fixture)
	next := metadataTestNextAllocator(t, fixture.input.AllocatorSnapshot, 0)

	for failure := 1; failure <= 12; failure++ {
		t.Run(fmt.Sprintf("operation-%02d", failure), func(t *testing.T) {
			storage := baseline.clone()
			opened := metadataTestOpen(t, storage, fixture)
			storage.resetTracking()
			storage.failMutation = failure
			if err := opened.commitAllocatorSnapshot(next); !errors.Is(err, ErrDeviceMetadataStorage) {
				t.Fatalf("commit error = %v", err)
			}
			mutationsAfterFailure := storage.mutationCount
			if err := opened.commitAllocatorSnapshot(next); !errors.Is(err, ErrDeviceMetadataReopenRequired) {
				t.Fatalf("poisoned-handle retry error = %v", err)
			}
			if storage.mutationCount != mutationsAfterFailure {
				t.Fatal("poisoned allocator handle performed another mutation")
			}
			storage.failMutation = 0
			reopened := metadataTestOpen(t, storage, fixture)
			_, selected := reopened.ActiveAllocatorSnapshot()
			if selected.SnapshotSequence != 1 && selected.SnapshotSequence != 2 {
				t.Fatalf("selected allocator sequence = %d", selected.SnapshotSequence)
			}
		})
	}

	storage := baseline.clone()
	opened := metadataTestOpen(t, storage, fixture)
	storage.resetTracking()
	if err := opened.commitAllocatorSnapshot(next); err != nil {
		t.Fatalf("successful commit: %v", err)
	}
	reopened := metadataTestOpen(t, storage, fixture)
	superblockSlot, superblock := reopened.ActiveSuperblock()
	allocatorSlot, allocator := reopened.ActiveAllocatorSnapshot()
	if superblockSlot != SuperblockSlotB || allocatorSlot != SuperblockSlotB ||
		superblock.SuperblockSequence != 2 || allocator.SnapshotSequence != 2 {
		t.Fatalf("selected slots/sequences = %s/%d, %s/%d",
			superblockSlot, superblock.SuperblockSequence,
			allocatorSlot, allocator.SnapshotSequence)
	}
}

func TestCommitAllocatorRequiresTransactionAdvanceForBitmapChange(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	opened := metadataTestOpen(t, storage, fixture)
	current := fixture.input.AllocatorSnapshot
	bitmap := current.BitmapBytes()
	bitmap[0] = 1
	changedWithoutTransaction, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                2,
		AppliedOwnerTransactionSequence: 0,
		DataPageCount:                   current.DataPageCount,
	}, bitmap)
	if err != nil {
		t.Fatalf("changed snapshot: %v", err)
	}
	storage.resetTracking()
	if err := opened.commitAllocatorSnapshot(changedWithoutTransaction); !errors.Is(err, ErrDeviceMetadataSequence) {
		t.Fatalf("bitmap-without-transaction error = %v", err)
	}
	if storage.mutationCount != 0 {
		t.Fatal("rejected allocator mutation wrote storage")
	}

	sequenceOnly, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             current.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        current.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      current.OwnerEpoch,
		SnapshotSequence:                2,
		AppliedOwnerTransactionSequence: 0,
		DataPageCount:                   current.DataPageCount,
	}, current.BitmapBytes())
	if err != nil {
		t.Fatalf("sequence-only snapshot: %v", err)
	}
	if err := opened.commitAllocatorSnapshot(sequenceOnly); !errors.Is(err, ErrDeviceMetadataSequence) {
		t.Fatalf("sequence-only error = %v", err)
	}
	unissued := metadataTestNextAllocator(t, current, 0)
	if err := opened.commitAllocatorSnapshot(unissued); !errors.Is(err, ErrDeviceMetadataSequence) {
		t.Fatalf("unissued Owner-transaction error = %v", err)
	}
	if storage.mutationCount != 0 {
		t.Fatal("unissued allocator transaction wrote storage")
	}
	_, owner, present := opened.ActiveOwnerState()
	if !present {
		t.Fatal("ANCHOR has no Owner state")
	}
	issued := metadataTestOwnerSnapshot(t, owner, 2, 1, 2)
	if err := opened.commitOwnerState(issued); err != nil {
		t.Fatalf("preflight-rejected handle could not issue transaction: %v", err)
	}
	if err := opened.commitAllocatorSnapshot(unissued); err != nil {
		t.Fatalf("preflight-rejected handle was not reusable: %v", err)
	}
}

func TestOpenFallsBackFromCorruptNewerAllocator(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	metadataTestIssueOwnerTransaction(t, storage, fixture)
	opened := metadataTestOpen(t, storage, fixture)
	next := metadataTestNextAllocator(t, fixture.input.AllocatorSnapshot, 0)
	if err := opened.commitAllocatorSnapshot(next); err != nil {
		t.Fatalf("CommitAllocatorSnapshot: %v", err)
	}
	position := geometry.AllocatorSnapshotBOffset + AllocatorSnapshotFixedBytes
	storage.bytes[position] ^= 0xff
	reopened := metadataTestOpen(t, storage, fixture)
	slot, allocator := reopened.ActiveAllocatorSnapshot()
	if slot != SuperblockSlotA || allocator.SnapshotSequence != 1 {
		t.Fatalf("fallback selected %s sequence %d", slot, allocator.SnapshotSequence)
	}
}

func TestOpenDoesNotRollBackFromNewerAuthorityOrGeometry(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)

	t.Run("Owner-epoch", func(t *testing.T) {
		storage := metadataTestFormat(t, fixture)
		newer := fixture.input.Superblock
		newer.SuperblockSequence = 2
		newer.OwnerEpoch = 2
		metadataTestWriteEmptyPair(
			t, storage, newer, SuperblockSlotB, SuperblockSlotB, 2)
		_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
		if !errors.Is(err, ErrDeviceMetadataRoleMismatch) {
			t.Fatalf("stale bootstrap selected old pair: %v", err)
		}
	})

	t.Run("geometry", func(t *testing.T) {
		storage := metadataTestFormat(t, fixture)
		newGeometry := metadataTestGeometry(t, 8<<20, 8192)
		newer := fixture.input.Superblock
		newer.SuperblockSequence = 2
		newer.Geometry = newGeometry
		metadataTestWriteEmptyPair(
			t, storage, newer, SuperblockSlotB, SuperblockSlotB, 2)
		_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
		if !errors.Is(err, ErrDeviceMetadataGeometryMismatch) {
			t.Fatalf("stale geometry selected old pair: %v", err)
		}
	})

	t.Run("device-bytes", func(t *testing.T) {
		storage := metadataTestFormat(t, fixture)
		newGeometry := metadataTestGeometry(t, 7<<20, 4096)
		newer := fixture.input.Superblock
		newer.SuperblockSequence = 2
		newer.Geometry = newGeometry
		metadataTestWriteEmptyPair(
			t, storage, newer, SuperblockSlotB, SuperblockSlotB, 2)
		_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
		if !errors.Is(err, ErrDeviceMetadataGeometryMismatch) {
			t.Fatalf("newer DeviceBytes mismatch selected old pair: %v", err)
		}
	})
}

func TestAllocatorDeclaredLengthMismatchDoesNotReadOrAllocateBody(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	headerOffset := geometry.AllocatorSnapshotAOffset
	header := storage.rawBytes(headerOffset, int(AllocatorSnapshotEnvelopeHeaderBytes))
	declared := binary.LittleEndian.Uint64(header[allocatorSnapshotPayloadLengthOffset:])
	binary.LittleEndian.PutUint64(header[allocatorSnapshotPayloadLengthOffset:], declared+1)
	binary.LittleEndian.PutUint32(
		header[allocatorSnapshotHeaderCRCOffset:],
		allocatorSnapshotHeaderCRC32C(header))
	storage.rawWrite(headerOffset, header)
	bodyOffset := headerOffset + AllocatorSnapshotEnvelopeHeaderBytes
	storage.failReadOffset = &bodyOffset
	storage.maxRead = 0
	_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrNoValidSuperblock) {
		t.Fatalf("length-mismatch open error = %v", err)
	}
	if storage.maxRead > int(SuperblockSlotBytes) {
		t.Fatalf("length mismatch requested %d-byte read", storage.maxRead)
	}
}

func TestOwnerStateReadLimitIsExplicitPolicy(t *testing.T) {
	geometry := metadataTestGeometry(t, 140<<20, 64<<20)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := newMetadataTestStorage(geometry.DeviceBytes)
	metadataTestSeedFixture(t, storage, fixture)

	tooSmall := metadataTestOpenInput(fixture)
	tooSmall.OwnerStateReadLimitBytes = OwnerStateEnvelopeHeaderBytes
	bodyOffset := geometry.OwnerStateSnapshotAOffset + OwnerStateEnvelopeHeaderBytes
	storage.failReadOffset = &bodyOffset
	_, err := OpenDeviceMetadata(storage, tooSmall)
	if !errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) {
		t.Fatalf("small Owner-state read limit error = %v", err)
	}
	if storage.maxRead >= 1<<20 {
		t.Fatalf("small policy caused %d-byte read", storage.maxRead)
	}

	storage.resetTracking()
	missing := metadataTestOpenInput(fixture)
	missing.OwnerStateReadLimitBytes = 0
	_, err = OpenDeviceMetadata(storage, missing)
	if !errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) {
		t.Fatalf("missing Owner-state read limit error = %v", err)
	}
	if storage.readCalls != 0 {
		t.Fatalf("invalid read policy performed %d reads", storage.readCalls)
	}
}

func TestAnchorOpenRejectsAllocatorBeyondIssuedOwnerTransaction(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	allocator := metadataTestNextAllocator(t, fixture.input.AllocatorSnapshot, 0)
	allocatorWire, err := CanonicalAllocatorSnapshotBytes(allocator, geometry)
	if err != nil {
		t.Fatalf("encode ahead allocator: %v", err)
	}
	newer := fixture.input.Superblock
	newer.SuperblockSequence = 2
	newer.ActiveAllocatorSnapshotSlot = SuperblockSlotB
	newer.ActiveAllocatorSnapshotSequence = allocator.SnapshotSequence
	newer.ActiveAllocatorSnapshotLength = uint64(len(allocatorWire))
	newer.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(allocatorWire)
	superblockWire, err := CanonicalSuperblockBytes(newer)
	if err != nil {
		t.Fatalf("encode ahead superblock: %v", err)
	}
	storage.rawWrite(geometry.AllocatorSnapshotBOffset, allocatorWire)
	storage.rawWrite(geometry.SuperblockBOffset, superblockWire)
	_, err = OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrDeviceMetadataSequence) {
		t.Fatalf("ahead allocator open error = %v", err)
	}
}

func TestCommitOwnerStateRejectsEnvelopeBeyondOpenedReadPolicy(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	genesisWire, err := CanonicalOwnerStateBytes(*fixture.input.OwnerState, geometry)
	if err != nil {
		t.Fatalf("encode genesis Owner state: %v", err)
	}
	openInput := metadataTestOpenInput(fixture)
	openInput.OwnerStateReadLimitBytes = uint64(len(genesisWire))
	opened, err := OpenDeviceMetadata(storage, openInput)
	if err != nil {
		t.Fatalf("open with exact genesis limit: %v", err)
	}
	currentSlot, current, present := opened.ActiveOwnerState()
	if !present || currentSlot != OwnerStateSlotA {
		t.Fatal("genesis Owner state is absent")
	}
	record := OwnerStateAllocationRecord{
		AllocationRecordID:       1,
		OwnerTransactionSequence: 1,
		State:                    OwnerAllocationRejectedNoSpace,
		RequestID:                "request-read-limit",
		CheckpointID:             "checkpoint-read-limit",
		ProducerID:               "producer-read-limit",
		DedupDomainID:            "dedup-read-limit",
		SharingPolicyID:          "sharing-read-limit",
		RequestSHA256:            sha256.Sum256([]byte("read-limit request")),
		TotalDemandPages:         1,
		MaxExtents:               1,
		ContentDemands: []OwnerStateContentDemand{{
			Kind:             cxlcheckpoint.ContentMemoryPayloadV7,
			ObjectID:         1,
			ByteLength:       uint64(ContentPageBytes),
			CapacityPages:    1,
			LogicalPageStart: 0,
		}},
	}
	large, err := NewOwnerStateSnapshot(OwnerStateConfig{
		ClusterID:                    current.ClusterID,
		OwnerGroupID:                 current.OwnerGroupID,
		CurrentOwnerID:               current.CurrentOwnerID,
		AnchorDeviceUUID:             current.AnchorDeviceUUID,
		StorageCompatibilityID:       current.StorageCompatibilityID,
		OwnerEpoch:                   current.OwnerEpoch,
		GroupConfigurationSequence:   current.GroupConfigurationSequence,
		MembershipSHA256:             current.MembershipSHA256,
		SnapshotSequence:             2,
		NextAllocationRecordID:       2,
		NextOwnerTransactionSequence: 2,
		Devices:                      current.Devices(),
		Records:                      []OwnerStateAllocationRecord{record},
	})
	if err != nil {
		t.Fatalf("large Owner state: %v", err)
	}
	largeWire, err := CanonicalOwnerStateBytes(large, geometry)
	if err != nil {
		t.Fatalf("encode large Owner state: %v", err)
	}
	if uint64(len(largeWire)) <= openInput.OwnerStateReadLimitBytes {
		t.Fatalf("large envelope %d does not exceed policy %d",
			len(largeWire), openInput.OwnerStateReadLimitBytes)
	}
	storage.resetTracking()
	if err := opened.commitOwnerState(large); !errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) {
		t.Fatalf("oversized Owner commit error = %v", err)
	}
	if storage.mutationCount != 0 {
		t.Fatal("oversized Owner commit mutated storage")
	}
	small := metadataTestOwnerSnapshot(t, current, 2, 1, 2)
	if err := opened.commitOwnerState(small); err != nil {
		t.Fatalf("oversized preflight poisoned reusable handle: %v", err)
	}
}

func TestDeviceMetadataDoesNotExportRawCommitMethods(t *testing.T) {
	typeOfDevice := reflect.TypeOf((*DeviceMetadata)(nil))
	for _, name := range []string{"CommitAllocatorSnapshot", "CommitOwnerState"} {
		if _, exists := typeOfDevice.MethodByName(name); exists {
			t.Fatalf("raw persistence bypass %s is exported", name)
		}
	}
}

func TestOwnerStateCommitFallbackSplitBrainAndHighWater(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	opened := metadataTestOpen(t, storage, fixture)
	_, current, ok := opened.ActiveOwnerState()
	if !ok {
		t.Fatal("ANCHOR has no Owner state")
	}
	next := metadataTestOwnerSnapshot(t, current, 2, 2, 2)
	if err := opened.commitOwnerState(next); err != nil {
		t.Fatalf("CommitOwnerState: %v", err)
	}

	regressedID := metadataTestOwnerSnapshot(t, next, 3, 1, 3)
	storage.resetTracking()
	if err := opened.commitOwnerState(regressedID); !errors.Is(err, ErrDeviceMetadataSequence) {
		t.Fatalf("regressed allocation ID error = %v", err)
	}
	nonadvancingTransaction := metadataTestOwnerSnapshot(t, next, 3, 2, 2)
	if err := opened.commitOwnerState(nonadvancingTransaction); !errors.Is(err, ErrDeviceMetadataSequence) {
		t.Fatalf("nonadvancing transaction error = %v", err)
	}
	if storage.mutationCount != 0 {
		t.Fatal("rejected Owner-state mutation wrote storage")
	}

	ownerB, err := CanonicalOwnerStateBytes(next, geometry)
	if err != nil {
		t.Fatalf("encode Owner B: %v", err)
	}
	storage.bytes[geometry.OwnerStateSnapshotBOffset+uint64(len(ownerB))-1] ^= 0xff
	reopened := metadataTestOpen(t, storage, fixture)
	slot, fallback, present := reopened.ActiveOwnerState()
	if !present || slot != OwnerStateSlotA || fallback.SnapshotSequence != 1 {
		t.Fatalf("Owner fallback selected %s sequence %d present=%v",
			slot, fallback.SnapshotSequence, present)
	}

	splitStorage := metadataTestFormat(t, fixture)
	divergent := metadataTestOwnerSnapshot(t, current, 1, 2, 2)
	divergentWire, err := CanonicalOwnerStateBytes(divergent, geometry)
	if err != nil {
		t.Fatalf("encode divergent Owner state: %v", err)
	}
	splitStorage.rawWrite(geometry.OwnerStateSnapshotBOffset, divergentWire)
	_, err = OpenDeviceMetadata(splitStorage, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrOwnerStateSplitBrain) {
		t.Fatalf("split-brain error = %v", err)
	}
}

func TestCommitOwnerStateFailurePrefixesPreserveCompleteSnapshot(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	baseline := metadataTestFormat(t, fixture)
	openedBaseline := metadataTestOpen(t, baseline, fixture)
	_, current, _ := openedBaseline.ActiveOwnerState()
	next := metadataTestOwnerSnapshot(t, current, 2, 2, 2)

	for failure := 1; failure <= 6; failure++ {
		t.Run(fmt.Sprintf("operation-%02d", failure), func(t *testing.T) {
			storage := baseline.clone()
			opened := metadataTestOpen(t, storage, fixture)
			storage.resetTracking()
			storage.failMutation = failure
			if err := opened.commitOwnerState(next); !errors.Is(err, ErrDeviceMetadataStorage) {
				t.Fatalf("commit error = %v", err)
			}
			mutationsAfterFailure := storage.mutationCount
			if err := opened.commitOwnerState(next); !errors.Is(err, ErrDeviceMetadataReopenRequired) {
				t.Fatalf("poisoned-handle retry error = %v", err)
			}
			if storage.mutationCount != mutationsAfterFailure {
				t.Fatal("poisoned Owner-state handle performed another mutation")
			}
			inMemorySlot, inMemory, present := opened.ActiveOwnerState()
			if !present || inMemorySlot != OwnerStateSlotA || inMemory.SnapshotSequence != 1 {
				t.Fatalf("failed commit advanced in-memory state to %s/%d/%v",
					inMemorySlot, inMemory.SnapshotSequence, present)
			}
			storage.failMutation = 0
			reopened := metadataTestOpen(t, storage, fixture)
			_, selected, present := reopened.ActiveOwnerState()
			if !present || (selected.SnapshotSequence != 1 && selected.SnapshotSequence != 2) {
				t.Fatalf("selected Owner-state sequence = %d, present=%v",
					selected.SnapshotSequence, present)
			}
		})
	}

	storage := baseline.clone()
	opened := metadataTestOpen(t, storage, fixture)
	storage.resetTracking()
	if err := opened.commitOwnerState(next); err != nil {
		t.Fatalf("successful commit: %v", err)
	}
	slot, selected, present := opened.ActiveOwnerState()
	if !present || slot != OwnerStateSlotB || selected.SnapshotSequence != 2 {
		t.Fatalf("successful commit selected %s/%d/%v",
			slot, selected.SnapshotSequence, present)
	}
}

func TestOpenOwnerStateBodyIOErrorDoesNotSelectStaleState(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	opened := metadataTestOpen(t, storage, fixture)
	_, current, _ := opened.ActiveOwnerState()
	next := metadataTestOwnerSnapshot(t, current, 2, 2, 2)
	if err := opened.commitOwnerState(next); err != nil {
		t.Fatalf("CommitOwnerState: %v", err)
	}
	bodyOffset := geometry.OwnerStateSnapshotBOffset + OwnerStateEnvelopeHeaderBytes
	storage.failReadOffset = &bodyOffset
	_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("Owner body I/O error = %v", err)
	}
}

func TestOpenAllocatorBodyIOErrorDoesNotSelectStalePair(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	metadataTestIssueOwnerTransaction(t, storage, fixture)
	opened := metadataTestOpen(t, storage, fixture)
	next := metadataTestNextAllocator(t, fixture.input.AllocatorSnapshot, 0)
	if err := opened.commitAllocatorSnapshot(next); err != nil {
		t.Fatalf("CommitAllocatorSnapshot: %v", err)
	}
	bodyOffset := geometry.AllocatorSnapshotBOffset + AllocatorSnapshotEnvelopeHeaderBytes
	storage.failReadOffset = &bodyOffset
	_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("allocator body I/O error fell back to stale pair: %v", err)
	}
}

func TestDeviceMetadataShortIOBoundsAndExactSize(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := metadataTestFormat(t, fixture)
	metadataTestIssueOwnerTransaction(t, storage, fixture)

	shortRead := storage.clone()
	shortRead.shortReadCall = 1
	_, err := OpenDeviceMetadata(shortRead, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("short-read error = %v", err)
	}

	opened := metadataTestOpen(t, storage, fixture)
	next := metadataTestNextAllocator(t, fixture.input.AllocatorSnapshot, 0)
	storage.resetTracking()
	storage.shortWriteCall = 1
	if err := opened.commitAllocatorSnapshot(next); !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("short-write error = %v", err)
	}

	wrongSize := storage.clone()
	wrongSize.size--
	_, err = OpenDeviceMetadata(wrongSize, metadataTestOpenInput(fixture))
	if !errors.Is(err, ErrDeviceMetadataSizeMismatch) {
		t.Fatalf("size-mismatch error = %v", err)
	}
	if err := readMetadataExactAt(storage, geometry.DeviceBytes, make([]byte, 2), geometry.DeviceBytes-1); err == nil {
		t.Fatal("out-of-bounds read succeeded")
	}
	if _, err := metadataIOPosition(geometry.DeviceBytes, ^uint64(0), 2); err == nil {
		t.Fatal("overflowing range succeeded")
	}
}

func TestOpenOwnerStateDoesNotReadFullSixtyFourMiBSlot(t *testing.T) {
	geometry := metadataTestGeometry(t, 140<<20, 64<<20)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := newMetadataTestStorage(geometry.DeviceBytes)
	metadataTestSeedFixture(t, storage, fixture)
	storage.resetTracking()
	opened := metadataTestOpen(t, storage, fixture)
	_, owner, present := opened.ActiveOwnerState()
	if !present || owner.SnapshotSequence != 1 {
		t.Fatalf("Owner state present=%v sequence=%d", present, owner.SnapshotSequence)
	}
	if storage.maxRead >= 1<<20 {
		t.Fatalf("largest read was %d bytes for a %d-byte Owner-state slot",
			storage.maxRead, geometry.OwnerStateSnapshotSlotBytes)
	}
	if geometry.OwnerStateSnapshotSlotBytes != 64<<20 {
		t.Fatalf("fixture Owner-state slot = %d", geometry.OwnerStateSnapshotSlotBytes)
	}
}
