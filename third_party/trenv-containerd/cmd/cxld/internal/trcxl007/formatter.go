package trcxl007

import (
	"errors"
	"fmt"
)

var ErrDeviceMetadataGenesis = errors.New("invalid TRCXL007 genesis metadata")

// DeviceFormatInput is a complete, caller-constructed genesis. The formatter
// validates these values exactly and never fills defaults, advances sequence
// numbers, sorts membership, or otherwise normalizes mutable state.
type DeviceFormatInput struct {
	Superblock          DeviceSuperblock
	AllocatorSnapshot   AllocatorSnapshot
	OwnerStateBootstrap OwnerStateBootstrap
	OwnerState          *OwnerStateSnapshot
}

// FormatDeviceMetadata destructively replaces only the metadata, descriptor,
// and alignment-prefix bytes [0, ContentRegionBase). ContentRegion and any
// payload sentinel in it are never cleared or written by this function.
//
// Sync is treated as the durability boundary promised by storage. This code
// makes no stronger claim about physical persistence on non-coherent CXL.
func FormatDeviceMetadata(storage DeviceMetadataStorage, input DeviceFormatInput) error {
	prepared, err := validateDeviceFormatInput(storage, input)
	if err != nil {
		return err
	}

	// Invalidate both possible roots before the potentially long descriptor
	// clear. We proceed to bulk clearing only after their invalidation Sync
	// succeeds, so an interrupted clear cannot be opened through an old root.
	zeroHeader := make([]byte, int(SuperblockEnvelopeHeaderBytes))
	for _, entry := range []struct {
		name   string
		offset uint64
	}{
		{"A", prepared.geometry.SuperblockAOffset},
		{"B", prepared.geometry.SuperblockBOffset},
	} {
		if err := writeMetadataExactAt(
			storage,
			prepared.geometry.DeviceBytes,
			zeroHeader,
			entry.offset); err != nil {
			return fmt.Errorf(
				"%w: invalidate old superblock %s header: %v",
				ErrDeviceMetadataStorage,
				entry.name,
				err)
		}
	}
	if err := storage.Sync(); err != nil {
		return fmt.Errorf(
			"%w: sync old-superblock invalidation: %v",
			ErrDeviceMetadataStorage,
			err)
	}

	if err := clearDeviceMetadataPrefix(storage, prepared.geometry); err != nil {
		return err
	}

	if err := writeMetadataEnvelopeHeaderLast(
		storage,
		prepared.geometry.DeviceBytes,
		prepared.geometry.AllocatorSnapshotAOffset,
		prepared.geometry.AllocatorSnapshotSlotBytes,
		prepared.allocatorExact,
		AllocatorSnapshotEnvelopeHeaderBytes); err != nil {
		return fmt.Errorf(
			"%w: publish genesis allocator A: %v",
			ErrDeviceMetadataStorage,
			err)
	}
	if prepared.ownerStateExact != nil {
		if err := writeMetadataEnvelopeHeaderLast(
			storage,
			prepared.geometry.DeviceBytes,
			prepared.geometry.OwnerStateSnapshotAOffset,
			prepared.geometry.OwnerStateSnapshotSlotBytes,
			prepared.ownerStateExact,
			OwnerStateEnvelopeHeaderBytes); err != nil {
			return fmt.Errorf(
				"%w: publish genesis Owner-state A: %v",
				ErrDeviceMetadataStorage,
				err)
		}
	}
	if err := writeMetadataEnvelopeHeaderLast(
		storage,
		prepared.geometry.DeviceBytes,
		prepared.geometry.SuperblockAOffset,
		SuperblockSlotBytes,
		prepared.superblockExact,
		SuperblockEnvelopeHeaderBytes); err != nil {
		return fmt.Errorf(
			"%w: publish genesis superblock A: %v",
			ErrDeviceMetadataStorage,
			err)
	}
	return nil
}

type preparedDeviceFormat struct {
	geometry        DeviceGeometry
	allocatorExact  []byte
	ownerStateExact []byte
	superblockExact []byte
}

func validateDeviceFormatInput(
	storage DeviceMetadataStorage,
	input DeviceFormatInput,
) (preparedDeviceFormat, error) {
	superblock := input.Superblock
	geometry := superblock.Geometry
	if err := geometry.Validate(); err != nil {
		return preparedDeviceFormat{}, err
	}
	if err := validateMetadataStorageSize(storage, geometry); err != nil {
		return preparedDeviceFormat{}, err
	}
	if err := validateSuperblockBootstrap(superblock, input.OwnerStateBootstrap); err != nil {
		return preparedDeviceFormat{}, err
	}
	if superblock.SuperblockSequence != 1 ||
		superblock.ActiveAllocatorSnapshotSlot != SuperblockSlotA ||
		superblock.ActiveAllocatorSnapshotSequence != 1 {
		return preparedDeviceFormat{}, fmt.Errorf(
			"%w: superblock must be sequence 1 and select allocator A sequence 1",
			ErrDeviceMetadataGenesis)
	}

	allocator := input.AllocatorSnapshot
	if allocator.SnapshotSequence != 1 ||
		allocator.AppliedOwnerTransactionSequence != 0 ||
		allocator.AllocatedPageCount != 0 ||
		!allocatorSnapshotAllZero(allocator.allocationBitmap) {
		return preparedDeviceFormat{}, fmt.Errorf(
			"%w: allocator must be empty sequence 1 with applied Owner transaction 0",
			ErrDeviceMetadataGenesis)
	}
	allocatorExact, err := CanonicalAllocatorSnapshotBytes(allocator, geometry)
	if err != nil {
		return preparedDeviceFormat{}, err
	}
	if err := validateAllocatorSnapshotAgainstSuperblock(
		superblock,
		allocator,
		allocatorExact); err != nil {
		return preparedDeviceFormat{}, err
	}

	var ownerStateExact []byte
	switch superblock.OwnerGroupRole {
	case OwnerGroupRoleAnchor:
		if input.OwnerState == nil {
			return preparedDeviceFormat{}, fmt.Errorf(
				"%w: ANCHOR requires a caller-provided genesis Owner state",
				ErrDeviceMetadataGenesis)
		}
		ownerState := *input.OwnerState
		if ownerState.SnapshotSequence != 1 ||
			ownerState.NextAllocationRecordID != 1 ||
			ownerState.NextOwnerTransactionSequence != 1 ||
			len(ownerState.records) != 0 {
			return preparedDeviceFormat{}, fmt.Errorf(
				"%w: ANCHOR Owner state must be empty sequence 1 with both next IDs equal to 1",
				ErrDeviceMetadataGenesis)
		}
		if err := ownerState.CrossCheckBootstrap(input.OwnerStateBootstrap); err != nil {
			return preparedDeviceFormat{}, err
		}
		ownerStorage, err := EncodeOwnerStateForStorage(ownerState, geometry)
		if err != nil {
			return preparedDeviceFormat{}, err
		}
		ownerStateExact = ownerStorage.exactBytes
	case OwnerGroupRoleMember:
		if input.OwnerState != nil {
			return preparedDeviceFormat{}, fmt.Errorf(
				"%w: MEMBER forbids Owner state",
				ErrDeviceMetadataGenesis)
		}
	default:
		return preparedDeviceFormat{}, fmt.Errorf(
			"%w: unsupported role %d",
			ErrDeviceMetadataRoleMismatch,
			superblock.OwnerGroupRole)
	}

	superblockExact, err := CanonicalSuperblockBytes(superblock)
	if err != nil {
		return preparedDeviceFormat{}, err
	}
	return preparedDeviceFormat{
		geometry:        geometry,
		allocatorExact:  allocatorExact,
		ownerStateExact: ownerStateExact,
		superblockExact: superblockExact,
	}, nil
}

func clearDeviceMetadataPrefix(
	storage DeviceMetadataStorage,
	geometry DeviceGeometry,
) error {
	zeroes := make([]byte, metadataClearChunkBytes)
	for offset := uint64(0); offset < geometry.ContentRegionBase; {
		length := geometry.ContentRegionBase - offset
		if length > uint64(len(zeroes)) {
			length = uint64(len(zeroes))
		}
		if err := writeMetadataExactAt(
			storage,
			geometry.DeviceBytes,
			zeroes[:int(length)],
			offset); err != nil {
			return fmt.Errorf(
				"%w: clear metadata at offset %d: %v",
				ErrDeviceMetadataStorage,
				offset,
				err)
		}
		offset += length
	}
	if err := storage.Sync(); err != nil {
		return fmt.Errorf(
			"%w: sync cleared metadata prefix: %v",
			ErrDeviceMetadataStorage,
			err)
	}
	return nil
}
