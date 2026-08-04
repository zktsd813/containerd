package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
)

func TestFormatDeviceMetadataPublishesGenesisAndPreservesContent(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	storage := newMetadataTestStorage(geometry.DeviceBytes)

	poison := bytes.Repeat([]byte{0xa5}, int(geometry.ContentRegionBase))
	storage.rawWrite(0, poison)
	sentinel := []byte("content-payload-must-survive-offline-format")
	storage.rawWrite(geometry.ContentRegionBase, sentinel)
	lastSentinel := []byte{0xde, 0xad, 0xbe, 0xef}
	storage.rawWrite(geometry.DeviceBytes-uint64(len(lastSentinel)), lastSentinel)
	storage.resetTracking()

	if err := FormatDeviceMetadata(storage, fixture.input); err != nil {
		t.Fatalf("FormatDeviceMetadata: %v", err)
	}
	if got := storage.rawBytes(geometry.ContentRegionBase, len(sentinel)); !bytes.Equal(got, sentinel) {
		t.Fatalf("content sentinel = %x, want %x", got, sentinel)
	}
	if got := storage.rawBytes(
		geometry.DeviceBytes-uint64(len(lastSentinel)), len(lastSentinel)); !bytes.Equal(got, lastSentinel) {
		t.Fatalf("last content sentinel = %x, want %x", got, lastSentinel)
	}
	if got := storage.rawBytes(geometry.DescriptorRegionBase, 64); !ownerStateAllZero(got) {
		t.Fatalf("first descriptor was not cleared: %x", got)
	}
	for _, offset := range []uint64{
		geometry.SuperblockBOffset,
		geometry.AllocatorSnapshotBOffset,
		geometry.OwnerStateSnapshotBOffset,
	} {
		if got := storage.rawBytes(offset, 64); !ownerStateAllZero(got) {
			t.Fatalf("inactive slot header at %d is not blank: %x", offset, got)
		}
	}

	opened := metadataTestOpen(t, storage, fixture)
	superblockSlot, superblock := opened.ActiveSuperblock()
	allocatorSlot, allocator := opened.ActiveAllocatorSnapshot()
	ownerSlot, owner, present := opened.ActiveOwnerState()
	if superblockSlot != SuperblockSlotA || superblock.SuperblockSequence != 1 ||
		allocatorSlot != SuperblockSlotA || allocator.SnapshotSequence != 1 ||
		ownerSlot != OwnerStateSlotA || !present || owner.SnapshotSequence != 1 {
		t.Fatalf("genesis selection = super %s/%d allocator %s/%d Owner %s/%d/%v",
			superblockSlot, superblock.SuperblockSequence,
			allocatorSlot, allocator.SnapshotSequence,
			ownerSlot, owner.SnapshotSequence, present)
	}
	if storage.maxWrite > metadataClearChunkBytes {
		t.Fatalf("formatter maximum write = %d, bound = %d", storage.maxWrite, metadataClearChunkBytes)
	}
	if len(storage.events) < 4 {
		t.Fatalf("formatter events = %#v", storage.events)
	}
	first := storage.events[:3]
	if first[0] != (metadataTestEvent{kind: "write", offset: geometry.SuperblockAOffset, length: 64}) ||
		first[1] != (metadataTestEvent{kind: "write", offset: geometry.SuperblockBOffset, length: 64}) ||
		first[2].kind != "sync" {
		t.Fatalf("formatter did not invalidate and sync both roots first: %#v", first)
	}
	last := storage.events[len(storage.events)-2:]
	if last[0] != (metadataTestEvent{kind: "write", offset: geometry.SuperblockAOffset, length: 64}) ||
		last[1].kind != "sync" {
		t.Fatalf("formatter did not publish superblock header last: %#v", last)
	}
}

func TestFormatDeviceMetadataMemberLeavesOwnerStateAbsent(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleMember)
	storage := newMetadataTestStorage(geometry.DeviceBytes)
	if err := FormatDeviceMetadata(storage, fixture.input); err != nil {
		t.Fatalf("FormatDeviceMetadata MEMBER: %v", err)
	}
	opened := metadataTestOpen(t, storage, fixture)
	if _, _, present := opened.ActiveOwnerState(); present {
		t.Fatal("MEMBER exposed Owner state")
	}
	for _, offset := range []uint64{
		geometry.OwnerStateSnapshotAOffset,
		geometry.OwnerStateSnapshotBOffset,
	} {
		if got := storage.rawBytes(offset, 64); !ownerStateAllZero(got) {
			t.Fatalf("MEMBER Owner-state header at %d = %x", offset, got)
		}
	}
}

func TestFormatDeviceMetadataRejectsNonGenesisBeforeWriting(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	anchor := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	member := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleMember)

	ownerSequenceTwo := metadataTestOwnerSnapshot(
		t, *anchor.input.OwnerState, 2, 1, 2)
	ownerNextIDTwo := metadataTestOwnerSnapshot(
		t, *anchor.input.OwnerState, 1, 2, 1)
	mismatchedOwnerConfig := OwnerStateConfig{
		ClusterID:                    anchor.input.OwnerState.ClusterID + "-other",
		OwnerGroupID:                 anchor.input.OwnerState.OwnerGroupID,
		CurrentOwnerID:               anchor.input.OwnerState.CurrentOwnerID,
		AnchorDeviceUUID:             anchor.input.OwnerState.AnchorDeviceUUID,
		StorageCompatibilityID:       anchor.input.OwnerState.StorageCompatibilityID,
		OwnerEpoch:                   anchor.input.OwnerState.OwnerEpoch,
		GroupConfigurationSequence:   anchor.input.OwnerState.GroupConfigurationSequence,
		MembershipSHA256:             anchor.input.OwnerState.MembershipSHA256,
		SnapshotSequence:             1,
		NextAllocationRecordID:       1,
		NextOwnerTransactionSequence: 1,
		Devices:                      anchor.input.OwnerState.Devices(),
	}
	mismatchedOwner, err := NewOwnerStateSnapshot(mismatchedOwnerConfig)
	if err != nil {
		t.Fatalf("mismatched Owner fixture: %v", err)
	}

	allocatedBitmap := anchor.input.AllocatorSnapshot.BitmapBytes()
	allocatedBitmap[0] = 1
	allocated, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             anchor.input.AllocatorSnapshot.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        anchor.input.AllocatorSnapshot.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      anchor.input.AllocatorSnapshot.OwnerEpoch,
		SnapshotSequence:                1,
		AppliedOwnerTransactionSequence: 0,
		DataPageCount:                   anchor.input.AllocatorSnapshot.DataPageCount,
	}, allocatedBitmap)
	if err != nil {
		t.Fatalf("allocated genesis fixture: %v", err)
	}
	applied, err := NewAllocatorSnapshot(AllocatorSnapshotConfig{
		DeviceBindingSHA256:             anchor.input.AllocatorSnapshot.DeviceBindingSHA256,
		OwnerGroupIdentitySHA256:        anchor.input.AllocatorSnapshot.OwnerGroupIdentitySHA256,
		OwnerEpoch:                      anchor.input.AllocatorSnapshot.OwnerEpoch,
		SnapshotSequence:                1,
		AppliedOwnerTransactionSequence: 1,
		DataPageCount:                   anchor.input.AllocatorSnapshot.DataPageCount,
	}, anchor.input.AllocatorSnapshot.BitmapBytes())
	if err != nil {
		t.Fatalf("applied genesis fixture: %v", err)
	}

	tests := []struct {
		name   string
		input  DeviceFormatInput
		mutate func(*DeviceFormatInput)
	}{
		{"superblock-sequence", anchor.input, func(input *DeviceFormatInput) {
			input.Superblock.SuperblockSequence = 2
		}},
		{"allocator-slot-B", anchor.input, func(input *DeviceFormatInput) {
			input.Superblock.ActiveAllocatorSnapshotSlot = SuperblockSlotB
		}},
		{"allocator-applied-transaction", anchor.input, func(input *DeviceFormatInput) {
			input.AllocatorSnapshot = applied
		}},
		{"allocator-nonempty", anchor.input, func(input *DeviceFormatInput) {
			input.AllocatorSnapshot = allocated
		}},
		{"anchor-without-Owner-state", anchor.input, func(input *DeviceFormatInput) {
			input.OwnerState = nil
		}},
		{"Owner-state-sequence", anchor.input, func(input *DeviceFormatInput) {
			input.OwnerState = &ownerSequenceTwo
		}},
		{"Owner-state-next-ID", anchor.input, func(input *DeviceFormatInput) {
			input.OwnerState = &ownerNextIDTwo
		}},
		{"Owner-state-bootstrap-mismatch", anchor.input, func(input *DeviceFormatInput) {
			input.OwnerState = &mismatchedOwner
		}},
		{"member-with-Owner-state", member.input, func(input *DeviceFormatInput) {
			input.OwnerState = anchor.input.OwnerState
		}},
		{"superblock-allocator-digest", anchor.input, func(input *DeviceFormatInput) {
			input.Superblock.ActiveAllocatorSnapshotSHA256[0] ^= 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := test.input
			test.mutate(&input)
			storage := newMetadataTestStorage(geometry.DeviceBytes)
			if err := FormatDeviceMetadata(storage, input); err == nil {
				t.Fatal("invalid genesis formatted successfully")
			}
			if storage.mutationCount != 0 || len(storage.events) != 0 {
				t.Fatalf("validation failure mutated storage: %#v", storage.events)
			}
		})
	}
}

func TestFormatDeviceMetadataFailurePrefixesDoNotExposeOldRootOrTouchContent(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	if geometry.ContentRegionBase <= metadataClearChunkBytes {
		t.Fatalf("fixture prefix %d is too small for a mid-clear failure", geometry.ContentRegionBase)
	}
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	baseline := metadataTestFormat(t, fixture)
	sentinel := []byte("preserve-through-failed-reformat")
	baseline.rawWrite(geometry.ContentRegionBase, sentinel)

	for _, failure := range []int{4, 5} {
		t.Run(fmt.Sprintf("mutation-%d", failure), func(t *testing.T) {
			storage := baseline.clone()
			storage.failMutation = failure
			if err := FormatDeviceMetadata(storage, fixture.input); !errors.Is(err, ErrDeviceMetadataStorage) {
				t.Fatalf("FormatDeviceMetadata error = %v", err)
			}
			storage.failMutation = 0
			_, err := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
			if !errors.Is(err, ErrNoValidSuperblock) {
				t.Fatalf("failed reformat remained openable: %v", err)
			}
			if got := storage.rawBytes(geometry.ContentRegionBase, len(sentinel)); !bytes.Equal(got, sentinel) {
				t.Fatalf("content sentinel = %x, want %x", got, sentinel)
			}
		})
	}
}

func TestFormatDeviceMetadataEveryFailurePrefixPublishesSuperblockLast(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	complete := newMetadataTestStorage(geometry.DeviceBytes)
	if err := FormatDeviceMetadata(complete, fixture.input); err != nil {
		t.Fatalf("baseline format: %v", err)
	}
	operationCount := complete.mutationCount
	if operationCount < 12 {
		t.Fatalf("format mutation count = %d", operationCount)
	}

	for failure := 1; failure <= operationCount; failure++ {
		t.Run(fmt.Sprintf("operation-%02d", failure), func(t *testing.T) {
			storage := newMetadataTestStorage(geometry.DeviceBytes)
			sentinel := []byte{1, 3, 3, 7}
			storage.rawWrite(geometry.ContentRegionBase, sentinel)
			storage.failMutation = failure
			if err := FormatDeviceMetadata(storage, fixture.input); !errors.Is(err, ErrDeviceMetadataStorage) {
				t.Fatalf("failure-prefix error = %v", err)
			}
			storage.failMutation = 0
			_, openErr := OpenDeviceMetadata(storage, metadataTestOpenInput(fixture))
			if failure == operationCount {
				// The last operation is Sync after the final superblock header
				// write. Immediate reads see a complete format, but the failed Sync
				// intentionally carries no physical-durability claim.
				if openErr != nil {
					t.Fatalf("final-Sync prefix is not structurally openable: %v", openErr)
				}
			} else if !errors.Is(openErr, ErrNoValidSuperblock) {
				t.Fatalf("prefix %d exposed a root: %v", failure, openErr)
			}
			if got := storage.rawBytes(geometry.ContentRegionBase, len(sentinel)); !bytes.Equal(got, sentinel) {
				t.Fatalf("content sentinel = %x, want %x", got, sentinel)
			}
		})
	}
}

func TestFormatDeviceMetadataRejectsSizeAndShortIO(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleAnchor)
	wrongSize := newMetadataTestStorage(geometry.DeviceBytes - 1)
	if err := FormatDeviceMetadata(wrongSize, fixture.input); !errors.Is(err, ErrDeviceMetadataSizeMismatch) {
		t.Fatalf("wrong-size error = %v", err)
	}
	if wrongSize.mutationCount != 0 {
		t.Fatal("wrong-size format mutated storage")
	}

	shortWrite := newMetadataTestStorage(geometry.DeviceBytes)
	shortWrite.shortWriteCall = 1
	if err := FormatDeviceMetadata(shortWrite, fixture.input); !errors.Is(err, ErrDeviceMetadataStorage) {
		t.Fatalf("short-write error = %v", err)
	}
}

func TestFormatDeviceMetadataDoesNotNormalizeBootstrap(t *testing.T) {
	geometry := metadataTestGeometry(t, 8<<20, 4096)
	fixture := metadataTestFixtureForRole(t, geometry, OwnerGroupRoleMember)
	input := fixture.input
	input.OwnerStateBootstrap.Devices = append(
		[]OwnerStateDevice(nil), input.OwnerStateBootstrap.Devices...)
	input.OwnerStateBootstrap.Devices[0], input.OwnerStateBootstrap.Devices[1] =
		input.OwnerStateBootstrap.Devices[1], input.OwnerStateBootstrap.Devices[0]
	input.OwnerStateBootstrap.MembershipSHA256 = sha256.Sum256([]byte("not canonical"))
	storage := newMetadataTestStorage(geometry.DeviceBytes)
	if err := FormatDeviceMetadata(storage, input); err == nil {
		t.Fatal("unsorted/noncanonical bootstrap was normalized")
	}
	if storage.mutationCount != 0 {
		t.Fatal("noncanonical bootstrap mutated storage")
	}
}
