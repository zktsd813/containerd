package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const metadataClearChunkBytes = 64 << 10

var (
	ErrDeviceMetadataStorage             = errors.New("TRCXL007 device metadata storage failure")
	ErrDeviceMetadataSizeMismatch        = errors.New("TRCXL007 device size does not match geometry")
	ErrDeviceMetadataGeometryMismatch    = errors.New("TRCXL007 selected device geometry differs from trusted geometry")
	ErrDeviceMetadataRoleMismatch        = errors.New("TRCXL007 Owner-group role metadata mismatch")
	ErrDeviceMetadataSequence            = errors.New("TRCXL007 metadata sequence is not the next sequence")
	ErrDeviceMetadataOwnerStateReadLimit = errors.New("TRCXL007 Owner-state envelope exceeds configured read limit")
	ErrDeviceMetadataReopenRequired      = errors.New("TRCXL007 device metadata must be reopened after a storage failure")
)

// DeviceMetadataStorage is the complete I/O authority used by the offline
// formatter and the single-Owner metadata writer. It deliberately excludes
// paths, mmap, truncate, allocation, and cache-management policy. Sync is the
// persistence boundary supplied by the concrete device implementation; this
// package does not claim that an arbitrary implementation reaches physical
// non-coherent CXL media.
type DeviceMetadataStorage interface {
	io.ReaderAt
	io.WriterAt
	Sync() error
	Size() uint64
}

// DeviceOpenInput supplies the geometry known by the device binding and the
// independently trusted Owner-group bootstrap. OwnerStateReadLimitBytes is an
// explicit operational allocation/I/O policy, not an on-media ABI limit. A
// caller that accepts every legal snapshot may set it to the configured slot
// size; a bounded service may choose a smaller value and fail closed rather
// than allocate a full maximum slot. OpenDeviceMetadata is read-only and never
// formats, clears, invalidates, or repairs storage.
type DeviceOpenInput struct {
	Geometry                 DeviceGeometry
	OwnerStateBootstrap      OwnerStateBootstrap
	OwnerStateReadLimitBytes uint64
}

// DeviceMetadata is one opened, validated device-metadata view. Mutations are
// deliberately sequential and single-writer; callers must not invoke commit
// methods concurrently or bypass the Owner protocol with direct writes.
type DeviceMetadata struct {
	storage   DeviceMetadataStorage
	geometry  DeviceGeometry
	bootstrap OwnerStateBootstrap

	superblockSlot SuperblockSlot
	superblock     DeviceSuperblock
	allocator      AllocatorSnapshot

	ownerStatePresent        bool
	ownerStateSlot           OwnerStateSlot
	ownerState               OwnerStateSnapshot
	ownerStateReadLimitBytes uint64
	reopenRequired           bool
}

type metadataGeometryFence struct {
	sequence uint64
	err      error
}

// OpenDeviceMetadata selects a complete superblock/allocator pair, validates
// it against expected geometry and Owner-group membership, then independently
// selects TROWN007 on an ANCHOR. A MEMBER must have no committed Owner-state
// header. Blank, unknown, corrupt-without-fallback, and split-brain media fail
// closed without causing any write or Sync.
func OpenDeviceMetadata(
	storage DeviceMetadataStorage,
	input DeviceOpenInput,
) (*DeviceMetadata, error) {
	if err := input.Geometry.Validate(); err != nil {
		return nil, err
	}
	if err := validateMetadataStorageSize(storage, input.Geometry); err != nil {
		return nil, err
	}
	if input.OwnerStateReadLimitBytes < OwnerStateEnvelopeHeaderBytes ||
		input.OwnerStateReadLimitBytes > input.Geometry.OwnerStateSnapshotSlotBytes {
		return nil, fmt.Errorf(
			"%w: limit %d is outside %d..%d",
			ErrDeviceMetadataOwnerStateReadLimit,
			input.OwnerStateReadLimitBytes,
			OwnerStateEnvelopeHeaderBytes,
			input.Geometry.OwnerStateSnapshotSlotBytes)
	}

	superblockA, err := readMetadataBytes(
		storage, input.Geometry.DeviceBytes, input.Geometry.SuperblockAOffset, SuperblockSlotBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: read superblock A: %v", ErrDeviceMetadataStorage, err)
	}
	superblockB, err := readMetadataBytes(
		storage, input.Geometry.DeviceBytes, input.Geometry.SuperblockBOffset, SuperblockSlotBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: read superblock B: %v", ErrDeviceMetadataStorage, err)
	}

	type allocatorCandidate struct {
		snapshot AllocatorSnapshot
		err      error
	}
	allocatorCandidates := make(map[DeviceSuperblock]allocatorCandidate, 2)
	geometryFences := make([]metadataGeometryFence, 0, 2)
	var maximumCompleteCandidateSequence uint64
	for _, wire := range [][]byte{superblockA, superblockB} {
		candidate, parseErr := ParseSuperblock(wire)
		if parseErr != nil {
			continue
		}
		if _, exists := allocatorCandidates[candidate]; exists {
			continue
		}
		if candidate.Geometry.DeviceBytes != storage.Size() {
			fenceErr := fmt.Errorf(
				"%w: canonical sequence %d declares %d bytes, storage has %d",
				ErrDeviceMetadataGeometryMismatch,
				candidate.SuperblockSequence,
				candidate.Geometry.DeviceBytes,
				storage.Size())
			allocatorCandidates[candidate] = allocatorCandidate{err: fenceErr}
			geometryFences = append(geometryFences, metadataGeometryFence{
				sequence: candidate.SuperblockSequence,
				err:      fenceErr,
			})
			continue
		}
		snapshot, _, err := readAllocatorSnapshotForSuperblock(storage, candidate)
		if errors.Is(err, ErrDeviceMetadataStorage) {
			// A storage-access failure is not proof that this otherwise readable
			// candidate is corrupt. Abort instead of silently selecting stale
			// state; successfully read bytes that fail checksums remain ordinary
			// invalid candidates and may fall back below.
			return nil, err
		}
		allocatorCandidates[candidate] = allocatorCandidate{
			snapshot: snapshot,
			err:      err,
		}
		if err == nil && candidate.SuperblockSequence > maximumCompleteCandidateSequence {
			maximumCompleteCandidateSequence = candidate.SuperblockSequence
		}
	}

	validateCandidate := func(candidate DeviceSuperblock) error {
		loaded, exists := allocatorCandidates[candidate]
		if !exists {
			return superblockSnapshotMismatchf("candidate allocator was not loaded")
		}
		return loaded.err
	}

	selectedSlot, selectedSuperblock, err := SelectLatestValidSuperblock(
		superblockA, superblockB, validateCandidate)
	if err != nil {
		if fenceErr := newestGeometryFenceAtOrAbove(
			geometryFences,
			maximumCompleteCandidateSequence); fenceErr != nil {
			return nil, fenceErr
		}
		return nil, err
	}
	if fenceErr := newestGeometryFenceAtOrAbove(
		geometryFences,
		selectedSuperblock.SuperblockSequence); fenceErr != nil {
		return nil, fenceErr
	}
	// Geometry and Owner authority are trusted caller fences, not candidate
	// corruption criteria. Apply them only after selecting the latest complete
	// superblock/allocator pair so a stale bootstrap cannot roll back to an old
	// but matching Owner epoch or group configuration.
	if selectedSuperblock.Geometry != input.Geometry {
		return nil, fmt.Errorf(
			"%w: selected sequence %d carries a different layout",
			ErrDeviceMetadataGeometryMismatch,
			selectedSuperblock.SuperblockSequence)
	}
	if err := validateSuperblockBootstrap(selectedSuperblock, input.OwnerStateBootstrap); err != nil {
		return nil, err
	}
	selectedAllocator, exists := allocatorCandidates[selectedSuperblock]
	if !exists || selectedAllocator.err != nil {
		return nil, superblockSnapshotMismatchf("selected allocator was not loaded")
	}

	opened := &DeviceMetadata{
		storage:                  storage,
		geometry:                 input.Geometry,
		bootstrap:                cloneOwnerStateBootstrap(input.OwnerStateBootstrap),
		superblockSlot:           selectedSlot,
		superblock:               selectedSuperblock,
		allocator:                selectedAllocator.snapshot,
		ownerStateReadLimitBytes: input.OwnerStateReadLimitBytes,
	}
	switch selectedSuperblock.OwnerGroupRole {
	case OwnerGroupRoleAnchor:
		ownerSlotA, err := readOwnerStateSlot(
			storage,
			input.Geometry,
			input.Geometry.OwnerStateSnapshotAOffset,
			input.OwnerStateReadLimitBytes)
		if err != nil {
			if errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: read Owner-state A: %v", ErrDeviceMetadataStorage, err)
		}
		ownerSlotB, err := readOwnerStateSlot(
			storage,
			input.Geometry,
			input.Geometry.OwnerStateSnapshotBOffset,
			input.OwnerStateReadLimitBytes)
		if err != nil {
			if errors.Is(err, ErrDeviceMetadataOwnerStateReadLimit) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: read Owner-state B: %v", ErrDeviceMetadataStorage, err)
		}
		ownerSlot, ownerState, err := SelectLatestValidOwnerState(
			ownerSlotA, ownerSlotB, input.Geometry)
		if err != nil {
			return nil, err
		}
		if err := ownerState.CrossCheckBootstrap(input.OwnerStateBootstrap); err != nil {
			return nil, err
		}
		if selectedAllocator.snapshot.AppliedOwnerTransactionSequence >=
			ownerState.NextOwnerTransactionSequence {
			return nil, fmt.Errorf(
				"%w: allocator applied Owner transaction %d, but Owner next transaction is %d",
				ErrDeviceMetadataSequence,
				selectedAllocator.snapshot.AppliedOwnerTransactionSequence,
				ownerState.NextOwnerTransactionSequence)
		}
		opened.ownerStatePresent = true
		opened.ownerStateSlot = ownerSlot
		opened.ownerState = ownerState
	case OwnerGroupRoleMember:
		if err := requireOwnerStateHeadersBlank(storage, input.Geometry); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf(
			"%w: unsupported role %d",
			ErrDeviceMetadataRoleMismatch,
			selectedSuperblock.OwnerGroupRole)
	}
	return opened, nil
}

func (device *DeviceMetadata) Geometry() DeviceGeometry {
	return device.geometry
}

func (device *DeviceMetadata) ActiveSuperblock() (SuperblockSlot, DeviceSuperblock) {
	return device.superblockSlot, device.superblock
}

func (device *DeviceMetadata) ActiveAllocatorSnapshot() (SuperblockSlot, AllocatorSnapshot) {
	return device.superblock.ActiveAllocatorSnapshotSlot, device.allocator.Clone()
}

func (device *DeviceMetadata) ActiveOwnerState() (OwnerStateSlot, OwnerStateSnapshot, bool) {
	if !device.ownerStatePresent {
		return 0, OwnerStateSnapshot{}, false
	}
	return device.ownerStateSlot, device.ownerState.Clone(), true
}

// commitAllocatorSnapshot writes an exact next per-device bitmap snapshot to
// the inactive allocator slot and only then publishes an inactive superblock
// that selects it. The old superblock and its referenced allocator slot are
// never invalidated, so every failed prefix leaves at least one complete pair.
// It is package-private until the Owner transaction state machine can expose a
// capability-checked public operation rather than a raw persistence bypass.
func (device *DeviceMetadata) commitAllocatorSnapshot(next AllocatorSnapshot) error {
	if device == nil || device.storage == nil {
		return fmt.Errorf("%w: opened device is nil", ErrDeviceMetadataStorage)
	}
	if device.reopenRequired {
		return ErrDeviceMetadataReopenRequired
	}
	if err := validateMetadataStorageSize(device.storage, device.geometry); err != nil {
		return err
	}
	wantSequence, ok := checkedAdd(device.allocator.SnapshotSequence, 1)
	if !ok || wantSequence > cxlcheckpoint.MaxSignedLong || next.SnapshotSequence != wantSequence {
		return fmt.Errorf(
			"%w: allocator snapshot sequence %d, expected %d",
			ErrDeviceMetadataSequence,
			next.SnapshotSequence,
			wantSequence)
	}
	if next.AppliedOwnerTransactionSequence < device.allocator.AppliedOwnerTransactionSequence {
		return fmt.Errorf(
			"%w: applied Owner transaction regresses from %d to %d",
			ErrDeviceMetadataSequence,
			device.allocator.AppliedOwnerTransactionSequence,
			next.AppliedOwnerTransactionSequence)
	}
	bitmapChanged := !bytes.Equal(next.allocationBitmap, device.allocator.allocationBitmap)
	transactionAdvanced := next.AppliedOwnerTransactionSequence >
		device.allocator.AppliedOwnerTransactionSequence
	if bitmapChanged && !transactionAdvanced {
		return fmt.Errorf(
			"%w: allocator bitmap changed without advancing applied Owner transaction %d",
			ErrDeviceMetadataSequence,
			next.AppliedOwnerTransactionSequence)
	}
	if !bitmapChanged && !transactionAdvanced {
		return fmt.Errorf(
			"%w: allocator snapshot is a sequence-only no-op",
			ErrDeviceMetadataSequence)
	}
	if device.ownerStatePresent && next.AppliedOwnerTransactionSequence >=
		device.ownerState.NextOwnerTransactionSequence {
		return fmt.Errorf(
			"%w: applied Owner transaction %d has not been issued below next sequence %d",
			ErrDeviceMetadataSequence,
			next.AppliedOwnerTransactionSequence,
			device.ownerState.NextOwnerTransactionSequence)
	}
	exact, err := CanonicalAllocatorSnapshotBytes(next, device.geometry)
	if err != nil {
		return err
	}
	targetAllocatorSlot := otherSuperblockSlot(device.superblock.ActiveAllocatorSnapshotSlot)
	targetSuperblockSlot := otherSuperblockSlot(device.superblockSlot)
	if !targetAllocatorSlot.valid() || !targetSuperblockSlot.valid() {
		return fmt.Errorf("%w: current slot selection is invalid", ErrDeviceMetadataSequence)
	}

	nextSuperblock := device.superblock
	nextSuperblockSequence, ok := checkedAdd(nextSuperblock.SuperblockSequence, 1)
	if !ok || nextSuperblockSequence > cxlcheckpoint.MaxSignedLong {
		return fmt.Errorf("%w: superblock sequence overflows", ErrDeviceMetadataSequence)
	}
	nextSuperblock.SuperblockSequence = nextSuperblockSequence
	nextSuperblock.ActiveAllocatorSnapshotSlot = targetAllocatorSlot
	nextSuperblock.ActiveAllocatorSnapshotSequence = next.SnapshotSequence
	nextSuperblock.ActiveAllocatorSnapshotLength = uint64(len(exact))
	nextSuperblock.ActiveAllocatorSnapshotSHA256 = sha256.Sum256(exact)
	if err := validateAllocatorSnapshotAgainstSuperblock(nextSuperblock, next, exact); err != nil {
		return err
	}
	superblockWire, err := CanonicalSuperblockBytes(nextSuperblock)
	if err != nil {
		return err
	}

	allocatorOffset, err := allocatorSnapshotSlotOffset(device.geometry, targetAllocatorSlot)
	if err != nil {
		return err
	}
	superblockOffset, err := superblockSlotOffset(device.geometry, targetSuperblockSlot)
	if err != nil {
		return err
	}
	// From the first header-last mutation until complete success, any failure
	// leaves A/B visibility ambiguous to this cached handle. Force a read-only
	// reopen before another commit can reuse a sequence or overwrite a slot.
	device.reopenRequired = true
	if err := writeMetadataEnvelopeHeaderLast(
		device.storage,
		device.geometry.DeviceBytes,
		allocatorOffset,
		device.geometry.AllocatorSnapshotSlotBytes,
		exact,
		AllocatorSnapshotEnvelopeHeaderBytes); err != nil {
		return fmt.Errorf("%w: commit allocator slot %s: %v", ErrDeviceMetadataStorage, targetAllocatorSlot, err)
	}
	if err := writeMetadataEnvelopeHeaderLast(
		device.storage,
		device.geometry.DeviceBytes,
		superblockOffset,
		SuperblockSlotBytes,
		superblockWire,
		SuperblockEnvelopeHeaderBytes); err != nil {
		return fmt.Errorf("%w: commit superblock slot %s: %v", ErrDeviceMetadataStorage, targetSuperblockSlot, err)
	}

	device.superblockSlot = targetSuperblockSlot
	device.superblock = nextSuperblock
	device.allocator = next.Clone()
	device.reopenRequired = false
	return nil
}

// commitOwnerState writes the exact next group-global full snapshot to the
// inactive TROWN007 slot. Owner-state A/B selection is independent of the
// superblock and exists only on the ANCHOR device. It remains package-private
// so callers cannot bypass the future legal record-transition checks.
func (device *DeviceMetadata) commitOwnerState(next OwnerStateSnapshot) error {
	if device == nil || device.storage == nil {
		return fmt.Errorf("%w: opened device is nil", ErrDeviceMetadataStorage)
	}
	if device.reopenRequired {
		return ErrDeviceMetadataReopenRequired
	}
	if device.superblock.OwnerGroupRole != OwnerGroupRoleAnchor || !device.ownerStatePresent {
		return fmt.Errorf("%w: MEMBER cannot commit Owner state", ErrDeviceMetadataRoleMismatch)
	}
	if err := validateMetadataStorageSize(device.storage, device.geometry); err != nil {
		return err
	}
	wantSequence, ok := checkedAdd(device.ownerState.SnapshotSequence, 1)
	if !ok || wantSequence > cxlcheckpoint.MaxSignedLong || next.SnapshotSequence != wantSequence {
		return fmt.Errorf(
			"%w: Owner-state sequence %d, expected %d",
			ErrDeviceMetadataSequence,
			next.SnapshotSequence,
			wantSequence)
	}
	if next.NextAllocationRecordID < device.ownerState.NextAllocationRecordID {
		return fmt.Errorf(
			"%w: next allocation-record ID regresses from %d to %d",
			ErrDeviceMetadataSequence,
			device.ownerState.NextAllocationRecordID,
			next.NextAllocationRecordID)
	}
	if next.NextOwnerTransactionSequence <= device.ownerState.NextOwnerTransactionSequence {
		return fmt.Errorf(
			"%w: next Owner-transaction sequence %d does not advance beyond %d",
			ErrDeviceMetadataSequence,
			next.NextOwnerTransactionSequence,
			device.ownerState.NextOwnerTransactionSequence)
	}
	if err := next.CrossCheckBootstrap(device.bootstrap); err != nil {
		return err
	}
	storage, err := EncodeOwnerStateForStorage(next, device.geometry)
	if err != nil {
		return err
	}
	if storage.ExactLength() > device.ownerStateReadLimitBytes {
		return fmt.Errorf(
			"%w: commit envelope %d exceeds opened policy %d",
			ErrDeviceMetadataOwnerStateReadLimit,
			storage.ExactLength(),
			device.ownerStateReadLimitBytes)
	}
	targetSlot := otherOwnerStateSlot(device.ownerStateSlot)
	offset, err := ownerStateSlotOffset(device.geometry, targetSlot)
	if err != nil {
		return err
	}
	device.reopenRequired = true
	if err := writeMetadataEnvelopeHeaderLast(
		device.storage,
		device.geometry.DeviceBytes,
		offset,
		device.geometry.OwnerStateSnapshotSlotBytes,
		storage.exactBytes,
		OwnerStateEnvelopeHeaderBytes); err != nil {
		return fmt.Errorf("%w: commit Owner-state slot %s: %v", ErrDeviceMetadataStorage, targetSlot, err)
	}
	device.ownerStateSlot = targetSlot
	device.ownerState = next.Clone()
	device.reopenRequired = false
	return nil
}

func validateMetadataStorageSize(storage DeviceMetadataStorage, geometry DeviceGeometry) error {
	if storage == nil {
		return fmt.Errorf("%w: storage is nil", ErrDeviceMetadataStorage)
	}
	size := storage.Size()
	if size != geometry.DeviceBytes {
		return fmt.Errorf(
			"%w: storage has %d bytes, geometry requires %d",
			ErrDeviceMetadataSizeMismatch,
			size,
			geometry.DeviceBytes)
	}
	return nil
}

func validateSuperblockBootstrap(
	superblock DeviceSuperblock,
	bootstrap OwnerStateBootstrap,
) error {
	if err := superblock.Validate(); err != nil {
		return err
	}
	membership, err := OwnerGroupMembershipSHA256(bootstrap.Devices)
	if err != nil {
		return fmt.Errorf("%w: bootstrap device table: %v", ErrDeviceMetadataRoleMismatch, err)
	}
	if bootstrap.MembershipSHA256 != membership {
		return fmt.Errorf(
			"%w: bootstrap membership SHA-256 is not canonical",
			ErrDeviceMetadataRoleMismatch)
	}
	if superblock.ClusterID != bootstrap.ClusterID ||
		superblock.OwnerGroupID != bootstrap.OwnerGroupID ||
		superblock.CurrentOwnerID != bootstrap.CurrentOwnerID ||
		superblock.OwnerGroupAnchorDeviceUUID != bootstrap.AnchorDeviceUUID ||
		superblock.StorageCompatibilityID != bootstrap.StorageCompatibilityID ||
		superblock.OwnerEpoch != bootstrap.OwnerEpoch ||
		superblock.OwnerGroupConfigurationSequence != bootstrap.GroupConfigurationSequence ||
		superblock.OwnerGroupMembershipSHA256 != bootstrap.MembershipSHA256 {
		return fmt.Errorf(
			"%w: superblock static Owner-group fields differ from bootstrap",
			ErrDeviceMetadataRoleMismatch)
	}
	var selfFound, anchorFound bool
	for _, entry := range bootstrap.Devices {
		if entry.DeviceUUID == bootstrap.AnchorDeviceUUID {
			anchorFound = true
		}
		if entry.DeviceUUID != superblock.DeviceUUID {
			continue
		}
		selfFound = true
		if entry.DeviceOwnerEpoch != superblock.OwnerEpoch ||
			entry.DataPageCount != superblock.Geometry.DataPageCount ||
			entry.DeviceBindingSHA256 != superblock.DeviceBindingSHA256() {
			return fmt.Errorf(
				"%w: bootstrap device entry differs from local superblock",
				ErrDeviceMetadataRoleMismatch)
		}
	}
	if !selfFound || !anchorFound {
		return fmt.Errorf(
			"%w: bootstrap is missing local or anchor device entry",
			ErrDeviceMetadataRoleMismatch)
	}
	return nil
}

func validateAllocatorSnapshotAgainstSuperblock(
	superblock DeviceSuperblock,
	snapshot AllocatorSnapshot,
	exact []byte,
) error {
	if err := snapshot.CrossCheck(
		superblock.Geometry,
		superblock.DeviceBindingSHA256(),
		superblock.OwnerGroupIdentitySHA256(),
		superblock.OwnerEpoch); err != nil {
		return superblockSnapshotMismatchf("snapshot binding: %v", err)
	}
	if snapshot.SnapshotSequence != superblock.ActiveAllocatorSnapshotSequence {
		return superblockSnapshotMismatchf(
			"snapshot sequence %d does not equal active sequence %d",
			snapshot.SnapshotSequence,
			superblock.ActiveAllocatorSnapshotSequence)
	}
	return validateAllocatorExact(superblock, exact)
}

func validateAllocatorExact(superblock DeviceSuperblock, exact []byte) error {
	if uint64(len(exact)) != superblock.ActiveAllocatorSnapshotLength {
		return superblockSnapshotMismatchf(
			"snapshot length %d does not equal active length %d",
			len(exact),
			superblock.ActiveAllocatorSnapshotLength)
	}
	if sha256.Sum256(exact) != superblock.ActiveAllocatorSnapshotSHA256 {
		return superblockSnapshotMismatchf("snapshot SHA-256 differs from active digest")
	}
	return nil
}

func readAllocatorSnapshotForSuperblock(
	storage DeviceMetadataStorage,
	superblock DeviceSuperblock,
) (AllocatorSnapshot, []byte, error) {
	offset, err := allocatorSnapshotSlotOffset(
		superblock.Geometry,
		superblock.ActiveAllocatorSnapshotSlot)
	if err != nil {
		return AllocatorSnapshot{}, nil, err
	}
	header, err := readMetadataBytes(
		storage,
		superblock.Geometry.DeviceBytes,
		offset,
		AllocatorSnapshotEnvelopeHeaderBytes)
	if err != nil {
		return AllocatorSnapshot{}, nil, fmt.Errorf(
			"%w: read allocator header: %v", ErrDeviceMetadataStorage, err)
	}
	if err := validateAllocatorHeaderForRead(header, superblock.Geometry); err != nil {
		return AllocatorSnapshot{}, nil, err
	}
	payloadLength := binary.LittleEndian.Uint64(header[allocatorSnapshotPayloadLengthOffset:])
	totalLength, ok := checkedAdd(AllocatorSnapshotEnvelopeHeaderBytes, payloadLength)
	if !ok || totalLength > superblock.Geometry.AllocatorSnapshotSlotBytes ||
		totalLength > uint64(maxIntValue()) {
		return AllocatorSnapshot{}, nil, allocatorSnapshotCorruptf(
			"declared envelope length %d exceeds slot", totalLength)
	}
	if totalLength != superblock.ActiveAllocatorSnapshotLength {
		return AllocatorSnapshot{}, nil, superblockSnapshotMismatchf(
			"header declares allocator length %d, superblock commits to %d",
			totalLength,
			superblock.ActiveAllocatorSnapshotLength)
	}
	exact := make([]byte, int(totalLength))
	copy(exact, header)
	if payloadLength > 0 {
		// A structurally valid, checksummed header commits to this exact body
		// length. An I/O error retrieving that body is a storage-access failure,
		// not evidence that this candidate is merely corrupt. Abort open so a
		// transient/partial read cannot silently select stale state. Successfully
		// read bytes that fail payload checksums still fall back in the selector.
		body, err := readMetadataBytes(
			storage,
			superblock.Geometry.DeviceBytes,
			offset+AllocatorSnapshotEnvelopeHeaderBytes,
			payloadLength)
		if err != nil {
			return AllocatorSnapshot{}, nil, fmt.Errorf(
				"%w: read allocator payload: %v", ErrDeviceMetadataStorage, err)
		}
		copy(exact[AllocatorSnapshotEnvelopeHeaderBytes:], body)
	}
	snapshot, err := ParseAllocatorSnapshot(exact, superblock.Geometry)
	if err != nil {
		return AllocatorSnapshot{}, nil, err
	}
	if err := validateAllocatorSnapshotAgainstSuperblock(superblock, snapshot, exact); err != nil {
		return AllocatorSnapshot{}, nil, err
	}
	return snapshot, exact, nil
}

func validateAllocatorHeaderForRead(header []byte, geometry DeviceGeometry) error {
	if len(header) != int(AllocatorSnapshotEnvelopeHeaderBytes) {
		return allocatorSnapshotCorruptf("header length %d is not 64", len(header))
	}
	if !bytes.Equal(
		header[allocatorSnapshotMagicOffset:allocatorSnapshotVersionOffset],
		allocatorSnapshotMagic[:]) {
		return allocatorSnapshotWrongFormatf("magic is not %q", AllocatorSnapshotMagicString)
	}
	if binary.LittleEndian.Uint32(header[allocatorSnapshotVersionOffset:]) != AllocatorSnapshotVersion ||
		binary.LittleEndian.Uint32(header[allocatorSnapshotHeaderSizeOffset:]) !=
			uint32(AllocatorSnapshotEnvelopeHeaderBytes) ||
		!bytes.Equal(
			header[allocatorSnapshotDomainOffset:allocatorSnapshotPayloadLengthOffset],
			allocatorSnapshotDomain[:]) {
		return allocatorSnapshotWrongFormatf("header contract differs")
	}
	if binary.LittleEndian.Uint32(header[allocatorSnapshotFlagsOffset:]) != 0 ||
		!allocatorSnapshotAllZero(
			header[allocatorSnapshotReservedOffset:AllocatorSnapshotEnvelopeHeaderBytes]) {
		return allocatorSnapshotWrongFormatf("flags or reserved bytes are nonzero")
	}
	wantCRC := binary.LittleEndian.Uint32(header[allocatorSnapshotHeaderCRCOffset:])
	if allocatorSnapshotHeaderCRC32C(header) != wantCRC {
		return allocatorSnapshotCorruptf("header CRC32C differs")
	}
	payloadLength := binary.LittleEndian.Uint64(header[allocatorSnapshotPayloadLengthOffset:])
	if payloadLength < allocatorSnapshotFixedPayloadBytes ||
		payloadLength > geometry.AllocatorSnapshotSlotBytes-AllocatorSnapshotEnvelopeHeaderBytes {
		return allocatorSnapshotCorruptf("payload length %d is outside slot bounds", payloadLength)
	}
	return nil
}

func readOwnerStateSlot(
	storage DeviceMetadataStorage,
	geometry DeviceGeometry,
	offset uint64,
	readLimitBytes uint64,
) ([]byte, error) {
	header, err := readMetadataBytes(
		storage, geometry.DeviceBytes, offset, OwnerStateEnvelopeHeaderBytes)
	if err != nil {
		return nil, err
	}
	if ownerStateAllZero(header) {
		return header, nil
	}
	// Let the pure selector classify incompatible/corrupt headers and fall back
	// to the other slot without trusting an unverified payload length.
	if !ownerStateHeaderValidForRead(header) {
		return header, nil
	}
	payloadLength := binary.LittleEndian.Uint64(header[ownerStatePayloadLengthOffset:])
	totalLength, ok := checkedAdd(OwnerStateEnvelopeHeaderBytes, payloadLength)
	if !ok || totalLength > geometry.OwnerStateSnapshotSlotBytes || totalLength > uint64(maxIntValue()) {
		return header, nil
	}
	if totalLength > readLimitBytes {
		return nil, fmt.Errorf(
			"%w: declared envelope %d exceeds limit %d",
			ErrDeviceMetadataOwnerStateReadLimit,
			totalLength,
			readLimitBytes)
	}
	exact := make([]byte, int(totalLength))
	copy(exact, header)
	if payloadLength > 0 {
		// As with allocator bodies above, a valid header plus an I/O failure is
		// not classified as a corrupt candidate. The caller aborts open rather
		// than falling back to a stale Owner-state snapshot.
		body, err := readMetadataBytes(
			storage,
			geometry.DeviceBytes,
			offset+OwnerStateEnvelopeHeaderBytes,
			payloadLength)
		if err != nil {
			return nil, err
		}
		copy(exact[OwnerStateEnvelopeHeaderBytes:], body)
	}
	return exact, nil
}

func ownerStateHeaderValidForRead(header []byte) bool {
	return len(header) == int(OwnerStateEnvelopeHeaderBytes) &&
		bytes.Equal(header[ownerStateMagicOffset:ownerStateVersionOffset], ownerStateMagic[:]) &&
		binary.LittleEndian.Uint32(header[ownerStateVersionOffset:]) == OwnerStateVersion &&
		binary.LittleEndian.Uint32(header[ownerStateHeaderSizeOffset:]) ==
			uint32(OwnerStateEnvelopeHeaderBytes) &&
		bytes.Equal(
			header[ownerStateDomainOffset:ownerStatePayloadLengthOffset],
			ownerStateDomain[:]) &&
		binary.LittleEndian.Uint32(header[ownerStateHeaderCRCOffset:]) ==
			ownerStateHeaderCRC32C(header)
}

func requireOwnerStateHeadersBlank(
	storage DeviceMetadataStorage,
	geometry DeviceGeometry,
) error {
	for _, entry := range []struct {
		name   string
		offset uint64
	}{
		{"A", geometry.OwnerStateSnapshotAOffset},
		{"B", geometry.OwnerStateSnapshotBOffset},
	} {
		header, err := readMetadataBytes(
			storage, geometry.DeviceBytes, entry.offset, OwnerStateEnvelopeHeaderBytes)
		if err != nil {
			return fmt.Errorf("%w: read MEMBER Owner-state %s header: %v", ErrDeviceMetadataStorage, entry.name, err)
		}
		if !ownerStateAllZero(header) {
			return fmt.Errorf(
				"%w: MEMBER device has a nonblank Owner-state %s header",
				ErrDeviceMetadataRoleMismatch,
				entry.name)
		}
	}
	return nil
}

func readMetadataBytes(
	storage DeviceMetadataStorage,
	deviceBytes uint64,
	offset uint64,
	length uint64,
) ([]byte, error) {
	if length > uint64(maxIntValue()) {
		return nil, fmt.Errorf("read length %d exceeds host int", length)
	}
	buffer := make([]byte, int(length))
	if err := readMetadataExactAt(storage, deviceBytes, buffer, offset); err != nil {
		return nil, err
	}
	return buffer, nil
}

func readMetadataExactAt(
	storage DeviceMetadataStorage,
	deviceBytes uint64,
	destination []byte,
	offset uint64,
) error {
	position, err := metadataIOPosition(deviceBytes, offset, uint64(len(destination)))
	if err != nil {
		return err
	}
	read, readErr := storage.ReadAt(destination, position)
	if readErr != nil {
		return readErr
	}
	if read != len(destination) {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func writeMetadataExactAt(
	storage DeviceMetadataStorage,
	deviceBytes uint64,
	source []byte,
	offset uint64,
) error {
	position, err := metadataIOPosition(deviceBytes, offset, uint64(len(source)))
	if err != nil {
		return err
	}
	written, writeErr := storage.WriteAt(source, position)
	if writeErr != nil {
		return writeErr
	}
	if written != len(source) {
		return io.ErrShortWrite
	}
	return nil
}

func metadataIOPosition(deviceBytes, offset, length uint64) (int64, error) {
	if deviceBytes > cxlcheckpoint.MaxSignedLong ||
		offset > deviceBytes ||
		length > deviceBytes-offset ||
		offset > cxlcheckpoint.MaxSignedLong {
		return 0, fmt.Errorf(
			"metadata range at offset %d with length %d is outside device size %d",
			offset,
			length,
			deviceBytes)
	}
	return int64(offset), nil
}

func writeMetadataEnvelopeHeaderLast(
	storage DeviceMetadataStorage,
	deviceBytes uint64,
	offset uint64,
	slotBytes uint64,
	exact []byte,
	headerBytes uint64,
) error {
	if headerBytes == 0 || uint64(len(exact)) < headerBytes || uint64(len(exact)) > slotBytes {
		return fmt.Errorf(
			"exact envelope length %d/header %d is invalid for slot %d",
			len(exact),
			headerBytes,
			slotBytes)
	}
	if _, err := metadataIOPosition(deviceBytes, offset, slotBytes); err != nil {
		return err
	}
	zeroHeader := make([]byte, int(headerBytes))
	if err := writeMetadataExactAt(storage, deviceBytes, zeroHeader, offset); err != nil {
		return fmt.Errorf("invalidate header: %v", err)
	}
	if err := storage.Sync(); err != nil {
		return fmt.Errorf("sync invalid header: %v", err)
	}
	if err := writeMetadataExactAt(
		storage,
		deviceBytes,
		exact[headerBytes:],
		offset+headerBytes); err != nil {
		return fmt.Errorf("write body: %v", err)
	}
	if err := storage.Sync(); err != nil {
		return fmt.Errorf("sync body: %v", err)
	}
	if err := writeMetadataExactAt(storage, deviceBytes, exact[:headerBytes], offset); err != nil {
		return fmt.Errorf("write final header: %v", err)
	}
	if err := storage.Sync(); err != nil {
		return fmt.Errorf("sync final header: %v", err)
	}
	return nil
}

func allocatorSnapshotSlotOffset(
	geometry DeviceGeometry,
	slot SuperblockSlot,
) (uint64, error) {
	switch slot {
	case SuperblockSlotA:
		return geometry.AllocatorSnapshotAOffset, nil
	case SuperblockSlotB:
		return geometry.AllocatorSnapshotBOffset, nil
	default:
		return 0, fmt.Errorf("invalid allocator slot %d", slot)
	}
}

func superblockSlotOffset(geometry DeviceGeometry, slot SuperblockSlot) (uint64, error) {
	switch slot {
	case SuperblockSlotA:
		return geometry.SuperblockAOffset, nil
	case SuperblockSlotB:
		return geometry.SuperblockBOffset, nil
	default:
		return 0, fmt.Errorf("invalid superblock slot %d", slot)
	}
}

func ownerStateSlotOffset(geometry DeviceGeometry, slot OwnerStateSlot) (uint64, error) {
	switch slot {
	case OwnerStateSlotA:
		return geometry.OwnerStateSnapshotAOffset, nil
	case OwnerStateSlotB:
		return geometry.OwnerStateSnapshotBOffset, nil
	default:
		return 0, fmt.Errorf("invalid Owner-state slot %d", slot)
	}
}

func otherSuperblockSlot(slot SuperblockSlot) SuperblockSlot {
	if slot == SuperblockSlotA {
		return SuperblockSlotB
	}
	if slot == SuperblockSlotB {
		return SuperblockSlotA
	}
	return 0
}

func otherOwnerStateSlot(slot OwnerStateSlot) OwnerStateSlot {
	if slot == OwnerStateSlotA {
		return OwnerStateSlotB
	}
	if slot == OwnerStateSlotB {
		return OwnerStateSlotA
	}
	return 0
}

func cloneOwnerStateBootstrap(source OwnerStateBootstrap) OwnerStateBootstrap {
	source.Devices = append([]OwnerStateDevice(nil), source.Devices...)
	return source
}

func newestGeometryFenceAtOrAbove(
	fences []metadataGeometryFence,
	minimumSequence uint64,
) error {
	var selected *metadataGeometryFence
	for index := range fences {
		candidate := &fences[index]
		if candidate.sequence < minimumSequence ||
			(selected != nil && candidate.sequence <= selected.sequence) {
			continue
		}
		selected = candidate
	}
	if selected == nil {
		return nil
	}
	return selected.err
}
