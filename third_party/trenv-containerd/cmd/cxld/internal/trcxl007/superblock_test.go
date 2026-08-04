package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	superblockKnownHeaderHex     = "545243584c30303707000000400000006465766963652d7375706572626c6f636b2d76310000000034020000000000000aa0a26e0000000025dc0f4f00000000"
	superblockKnownPayloadHex    = "0a000000636c75737465722dceb10b0000006465766963652d303030310d0000006f776e65722d67726f75702d330c0000006f776e65722d6e6f64652d370b0000006465766963652d30303031f30000007075626c69636174696f6e3d54525055423030372f76372f6c6974746c652d656e6469616e2f696d6d757461626c652d7075626c69636174696f6e2d76313b656e76656c6f70652d6865616465723d36343b6d61782d656e76656c6f70653d383338383630383b706167653d343039363b66696e6765727072696e743d6372633332632d6361737461676e6f6c692f30783131656463366634313b64657363726970746f723d545243584c3030372f36342f747263786c3030372d706167652d64657363726970746f722d6c6974746c652d656e6469616e2d76313b6f776e65722d73746174653d54524f574e3030372f76320b00000000000000110000000000000001000000000000000500000000000000c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf00001000000000000000000000000000001000000000000000200000000000000030000000000000001000000000000000400000000000000050000000000000001000000000000000600000000000000060000000000000803d00000000000000a000000000000000600f0000000000f60000000000000002000000000000000c00000000000000cf000000000000004df6d0c790df97895f9922ccfeb20a6889f17e1c08787c35fdcbf03d87860aad"
	superblockKnownSlotSHA256    = "a27321febb5f9a72e51639949fa7304b9cbfa7d7c0478cdb1ca64715294dc793"
	superblockKnownDeviceSHA     = "9d99de3704ce3f79f1ed6347b0acd3834ed6f0042b705482ecca4919813a3dfc"
	superblockKnownOwnerGroupSHA = "e3d078b2cfd73d02de8eb159ba5ffffc0463fd3c2ef3ebd53be2a160a549bf86"
)

type superblockTestSnapshotPair struct {
	snapshot AllocatorSnapshot
	storage  AllocatorSnapshotStorage
}

func TestSuperblockKnownAnswerSHA256AndOffsets(t *testing.T) {
	superblock, snapshot, storage := superblockKnownFixture(t)
	wire, err := CanonicalSuperblockBytes(superblock)
	if err != nil {
		t.Fatalf("canonical superblock: %v", err)
	}
	if len(wire) != int(SuperblockSlotBytes) {
		t.Fatalf("slot length = %d, expected %d", len(wire), SuperblockSlotBytes)
	}
	payloadLength := binary.LittleEndian.Uint64(wire[superblockPayloadLengthOffset:])
	if payloadLength != 564 {
		t.Fatalf("known payload length = %d, expected 564", payloadLength)
	}
	payloadEnd := int(SuperblockEnvelopeHeaderBytes + payloadLength)
	slotSHA256 := sha256.Sum256(wire)
	deviceSHA256 := superblock.DeviceBindingSHA256()
	ownerGroupSHA256 := superblock.OwnerGroupIdentitySHA256()
	storageSHA256 := storage.SHA256()
	if superblockKnownHeaderHex == "" || superblockKnownPayloadHex == "" ||
		superblockKnownSlotSHA256 == "" || superblockKnownDeviceSHA == "" ||
		superblockKnownOwnerGroupSHA == "" {
		t.Logf("header=%s", hex.EncodeToString(wire[:SuperblockEnvelopeHeaderBytes]))
		t.Logf("payload=%s", hex.EncodeToString(wire[SuperblockEnvelopeHeaderBytes:payloadEnd]))
		t.Logf("slot-sha=%s", hex.EncodeToString(slotSHA256[:]))
		t.Logf("device-sha=%s", hex.EncodeToString(deviceSHA256[:]))
		t.Logf("owner-group-sha=%s", hex.EncodeToString(ownerGroupSHA256[:]))
		t.Fatal("known-answer constants are not populated")
	}
	if got := hex.EncodeToString(wire[:SuperblockEnvelopeHeaderBytes]); got != superblockKnownHeaderHex {
		t.Fatalf("known header = %s", got)
	}
	if got := hex.EncodeToString(wire[SuperblockEnvelopeHeaderBytes:payloadEnd]); got != superblockKnownPayloadHex {
		t.Fatalf("known payload = %s", got)
	}
	if got := hex.EncodeToString(slotSHA256[:]); got != superblockKnownSlotSHA256 {
		t.Fatalf("known slot SHA-256 = %s", got)
	}
	if got := hex.EncodeToString(deviceSHA256[:]); got != superblockKnownDeviceSHA {
		t.Fatalf("known device-binding SHA-256 = %s", got)
	}
	if got := hex.EncodeToString(ownerGroupSHA256[:]); got != superblockKnownOwnerGroupSHA {
		t.Fatalf("known Owner-group-identity SHA-256 = %s", got)
	}

	if string(wire[0:8]) != SuperblockMagicString ||
		binary.LittleEndian.Uint32(wire[8:12]) != SuperblockVersion ||
		binary.LittleEndian.Uint32(wire[12:16]) != uint32(SuperblockEnvelopeHeaderBytes) {
		t.Fatalf("header prefix = %x", wire[:16])
	}
	var wantDomain [superblockDomainFieldBytes]byte
	copy(wantDomain[:], SuperblockDomain)
	if !bytes.Equal(wire[16:40], wantDomain[:]) {
		t.Fatalf("domain field = %x", wire[16:40])
	}
	if binary.LittleEndian.Uint32(wire[superblockFlagsOffset:]) != 0 ||
		!superblockAllZero(wire[superblockHeaderReservedOffset:SuperblockEnvelopeHeaderBytes]) {
		t.Fatalf("flags/reserved = %x", wire[superblockFlagsOffset:SuperblockEnvelopeHeaderBytes])
	}
	if got, want := binary.LittleEndian.Uint32(wire[superblockPayloadCRCOffset:]),
		superblockCRC32C(wire[SuperblockEnvelopeHeaderBytes:payloadEnd]); got != want {
		t.Fatalf("payload CRC32C = %#08x, expected %#08x", got, want)
	}
	if got, want := binary.LittleEndian.Uint32(wire[superblockHeaderCRCOffset:]),
		superblockHeaderCRC32C(wire[:SuperblockEnvelopeHeaderBytes]); got != want {
		t.Fatalf("header CRC32C = %#08x, expected %#08x", got, want)
	}

	// These offsets are intentionally exact known-answer checks, not values
	// rediscovered by the decoder under test.
	if binary.LittleEndian.Uint32(wire[64:68]) != 10 || string(wire[68:78]) != "cluster-α" ||
		binary.LittleEndian.Uint32(wire[78:82]) != 11 || string(wire[82:93]) != "device-0001" ||
		binary.LittleEndian.Uint32(wire[93:97]) != 13 || string(wire[97:110]) != "owner-group-3" ||
		binary.LittleEndian.Uint32(wire[110:114]) != 12 || string(wire[114:126]) != "owner-node-7" ||
		binary.LittleEndian.Uint32(wire[126:130]) != 11 || string(wire[130:141]) != "device-0001" ||
		binary.LittleEndian.Uint32(wire[141:145]) != uint32(len(cxlcheckpoint.V7StorageCompatibilityID)) ||
		string(wire[145:388]) != cxlcheckpoint.V7StorageCompatibilityID {
		t.Fatalf("known length-prefixed identity offsets changed")
	}
	if binary.LittleEndian.Uint64(wire[388:396]) != 11 ||
		binary.LittleEndian.Uint64(wire[396:404]) != 17 ||
		wire[404] != byte(OwnerGroupRoleAnchor) || !superblockAllZero(wire[405:412]) ||
		binary.LittleEndian.Uint64(wire[412:420]) != 5 ||
		!bytes.Equal(wire[420:452], superblock.OwnerGroupMembershipSHA256[:]) ||
		binary.LittleEndian.Uint64(wire[452:460]) != superblock.Geometry.DeviceBytes ||
		binary.LittleEndian.Uint64(wire[564:572]) != superblock.Geometry.DataPageCount ||
		wire[572] != byte(SuperblockSlotB) || !superblockAllZero(wire[573:580]) ||
		binary.LittleEndian.Uint64(wire[580:588]) != snapshot.SnapshotSequence ||
		binary.LittleEndian.Uint64(wire[588:596]) != storage.ExactLength() ||
		!bytes.Equal(wire[596:628], storageSHA256[:]) {
		t.Fatalf("known scalar/geometry/snapshot offsets changed: %x", wire[388:628])
	}
	if !superblockAllZero(wire[payloadEnd:]) {
		t.Fatal("known slot tail is not canonical zero")
	}

	parsed, err := ParseSuperblock(wire)
	if err != nil {
		t.Fatalf("parse known answer: %v", err)
	}
	if !reflect.DeepEqual(parsed, superblock) {
		t.Fatalf("parsed superblock = %#v, expected %#v", parsed, superblock)
	}
	if err := parsed.CrossCheckAllocatorSnapshot(snapshot, storage); err != nil {
		t.Fatalf("cross-check known snapshot: %v", err)
	}
	wire[68] ^= 0xff
	if parsed.ClusterID != superblock.ClusterID {
		t.Fatal("parsed superblock retained input slot alias")
	}
}

func TestSuperblockTwoGiBGeometryAndCanonicalTail(t *testing.T) {
	geometry, err := CalculateDeviceGeometry(2<<30, 128<<10, 128<<10)
	if err != nil {
		t.Fatalf("2 GiB geometry: %v", err)
	}
	superblock := superblockTestSkeleton(geometry)
	pair := superblockTestBuildSnapshot(t, superblock, 73, []uint64{0, 1, 4096, geometry.DataPageCount - 1})
	superblock.ActiveAllocatorSnapshotSlot = SuperblockSlotA
	superblock.ActiveAllocatorSnapshotSequence = pair.snapshot.SnapshotSequence
	superblock.ActiveAllocatorSnapshotLength = pair.storage.ExactLength()
	superblock.ActiveAllocatorSnapshotSHA256 = pair.storage.SHA256()

	if geometry.DataPageCount != 516094 || pair.storage.ExactLength() != 64688 {
		t.Fatalf("2 GiB geometry/snapshot = %d pages/%d bytes", geometry.DataPageCount, pair.storage.ExactLength())
	}
	wire, err := CanonicalSuperblockBytes(superblock)
	if err != nil {
		t.Fatalf("encode 2 GiB superblock: %v", err)
	}
	payloadLength := binary.LittleEndian.Uint64(wire[superblockPayloadLengthOffset:])
	if len(wire) != 4096 || !superblockAllZero(wire[64+payloadLength:]) {
		t.Fatal("2 GiB superblock is not a canonical zero-tailed 4 KiB slot")
	}
	parsed, err := ParseSuperblock(wire)
	if err != nil {
		t.Fatalf("parse 2 GiB superblock: %v", err)
	}
	if !reflect.DeepEqual(parsed.Geometry, geometry) {
		t.Fatalf("parsed geometry = %#v, expected %#v", parsed.Geometry, geometry)
	}
	if err := parsed.CrossCheckAllocatorSnapshot(pair.snapshot, pair.storage); err != nil {
		t.Fatalf("cross-check 2 GiB snapshot: %v", err)
	}
}

func TestSuperblockCrossCheckRejectsSnapshotSubstitution(t *testing.T) {
	superblock, snapshot, storage := superblockKnownFixture(t)
	if err := superblock.CrossCheckAllocatorSnapshot(snapshot, storage); err != nil {
		t.Fatalf("baseline cross-check: %v", err)
	}
	otherGeometry, err := CalculateDeviceGeometry(2<<20, 4096, 4096)
	if err != nil {
		t.Fatalf("other geometry: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*DeviceSuperblock)
	}{
		{"device", func(value *DeviceSuperblock) {
			value.DeviceUUID = "device-0002"
			value.OwnerGroupRole = OwnerGroupRoleMember
		}},
		{"Owner-group", func(value *DeviceSuperblock) { value.OwnerGroupID += "-other" }},
		{"current-Owner", func(value *DeviceSuperblock) { value.CurrentOwnerID += "-other" }},
		{"Owner-epoch", func(value *DeviceSuperblock) { value.OwnerEpoch++ }},
		{"anchor", func(value *DeviceSuperblock) {
			value.OwnerGroupAnchorDeviceUUID = "device-0002"
			value.OwnerGroupRole = OwnerGroupRoleMember
		}},
		{"configuration", func(value *DeviceSuperblock) { value.OwnerGroupConfigurationSequence++ }},
		{"membership", func(value *DeviceSuperblock) { value.OwnerGroupMembershipSHA256[0] ^= 1 }},
		{"geometry", func(value *DeviceSuperblock) { value.Geometry = otherGeometry }},
	} {
		t.Run("superblock-"+test.name, func(t *testing.T) {
			candidate := superblock
			test.mutate(&candidate)
			if err := candidate.CrossCheckAllocatorSnapshot(snapshot, storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
				t.Fatalf("binding substitution error = %v", err)
			}
		})
	}

	wrongSequence := snapshot.Clone()
	wrongSequence.SnapshotSequence++
	if err := superblock.CrossCheckAllocatorSnapshot(wrongSequence, storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("sequence substitution error = %v", err)
	}

	wrongDeviceConfig := superblockTestSnapshotConfig(superblock, snapshot.SnapshotSequence, snapshot.DataPageCount)
	wrongDeviceConfig.DeviceBindingSHA256[0] ^= 0xff
	wrongDevice, err := NewAllocatorSnapshot(wrongDeviceConfig, snapshot.BitmapBytes())
	if err != nil {
		t.Fatalf("wrong-device snapshot: %v", err)
	}
	wrongDeviceStorage, err := EncodeAllocatorSnapshotForStorage(wrongDevice, superblock.Geometry)
	if err != nil {
		t.Fatalf("wrong-device storage: %v", err)
	}
	if err := superblock.CrossCheckAllocatorSnapshot(wrongDevice, wrongDeviceStorage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("device substitution error = %v", err)
	}

	wrongOwnerConfig := superblockTestSnapshotConfig(superblock, snapshot.SnapshotSequence, snapshot.DataPageCount)
	wrongOwnerConfig.OwnerGroupIdentitySHA256[0] ^= 0xff
	wrongOwner, err := NewAllocatorSnapshot(wrongOwnerConfig, snapshot.BitmapBytes())
	if err != nil {
		t.Fatalf("wrong-owner snapshot: %v", err)
	}
	wrongOwnerStorage, err := EncodeAllocatorSnapshotForStorage(wrongOwner, superblock.Geometry)
	if err != nil {
		t.Fatalf("wrong-owner storage: %v", err)
	}
	if err := superblock.CrossCheckAllocatorSnapshot(wrongOwner, wrongOwnerStorage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("Owner substitution error = %v", err)
	}

	wrongEpoch := snapshot.Clone()
	wrongEpoch.OwnerEpoch++
	if err := superblock.CrossCheckAllocatorSnapshot(wrongEpoch, storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("epoch substitution error = %v", err)
	}

	otherPair := superblockTestBuildSnapshot(t, superblock, snapshot.SnapshotSequence, []uint64{2})
	otherStorageSHA256 := otherPair.storage.SHA256()
	storageSHA256 := storage.SHA256()
	if bytes.Equal(otherStorageSHA256[:], storageSHA256[:]) {
		t.Fatal("substitution fixture unexpectedly has equal digest")
	}
	if err := superblock.CrossCheckAllocatorSnapshot(snapshot, otherPair.storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("storage substitution error = %v", err)
	}
	if err := superblock.CrossCheckAllocatorSnapshot(otherPair.snapshot, storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("logical snapshot substitution error = %v", err)
	}

	wrongLength := superblock
	wrongLength.ActiveAllocatorSnapshotLength++
	if err := wrongLength.CrossCheckAllocatorSnapshot(snapshot, storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("active length substitution error = %v", err)
	}
	wrongSHA := superblock
	wrongSHA.ActiveAllocatorSnapshotSHA256[0] ^= 0xff
	if err := wrongSHA.CrossCheckAllocatorSnapshot(snapshot, storage); !errors.Is(err, ErrSuperblockSnapshotMismatch) {
		t.Fatalf("active SHA substitution error = %v", err)
	}
}

func TestSelectLatestValidSuperblockUsesCompleteReferencedSnapshotPair(t *testing.T) {
	base, _, _ := superblockKnownFixture(t)
	left := base
	left.SuperblockSequence = 20
	left.ActiveAllocatorSnapshotSlot = SuperblockSlotA
	leftPair := superblockTestBuildSnapshot(t, left, 30, []uint64{0, 8})
	superblockTestBindSnapshot(&left, leftPair)
	right := base
	right.SuperblockSequence = 21
	right.ActiveAllocatorSnapshotSlot = SuperblockSlotB
	rightPair := superblockTestBuildSnapshot(t, right, 31, []uint64{1, 9})
	superblockTestBindSnapshot(&right, rightPair)
	leftWire := superblockTestEncode(t, left)
	rightWire := superblockTestEncode(t, right)
	pairs := map[SuperblockSlot]superblockTestSnapshotPair{
		SuperblockSlotA: leftPair,
		SuperblockSlotB: rightPair,
	}
	validator := superblockTestSnapshotValidator(pairs)

	selectedSlot, selected, err := SelectLatestValidSuperblock(leftWire, rightWire, validator)
	if err != nil || selectedSlot != SuperblockSlotB || !reflect.DeepEqual(selected, right) {
		t.Fatalf("latest complete pair = %s/%#v/%v", selectedSlot, selected, err)
	}
	blank := make([]byte, SuperblockSlotBytes)
	selectedSlot, _, err = SelectLatestValidSuperblock(leftWire, blank, validator)
	if err != nil || selectedSlot != SuperblockSlotA {
		t.Fatalf("valid/blank selection = %s/%v", selectedSlot, err)
	}

	corruptNewer := append([]byte(nil), rightWire...)
	corruptNewer[superblockPayloadOffset] ^= 0xff
	selectedSlot, selected, err = SelectLatestValidSuperblock(leftWire, corruptNewer, validator)
	if err != nil || selectedSlot != SuperblockSlotA || !reflect.DeepEqual(selected, left) {
		t.Fatalf("corrupt-newer fallback = %s/%#v/%v", selectedSlot, selected, err)
	}

	brokenSnapshotValidator := func(candidate DeviceSuperblock) error {
		if candidate.ActiveAllocatorSnapshotSlot == SuperblockSlotB {
			return errors.New("simulated referenced snapshot corruption")
		}
		return validator(candidate)
	}
	selectedSlot, selected, err = SelectLatestValidSuperblock(leftWire, rightWire, brokenSnapshotValidator)
	if err != nil || selectedSlot != SuperblockSlotA || !reflect.DeepEqual(selected, left) {
		t.Fatalf("corrupt referenced-snapshot fallback = %s/%#v/%v", selectedSlot, selected, err)
	}

	identical := append([]byte(nil), leftWire...)
	selectedSlot, selected, err = SelectLatestValidSuperblock(leftWire, identical, validator)
	if err != nil || selectedSlot != SuperblockSlotA || !reflect.DeepEqual(selected, left) {
		t.Fatalf("identical equal-sequence selection = %s/%#v/%v", selectedSlot, selected, err)
	}

	splitRight := left
	splitRight.CurrentOwnerID = "owner-node-8"
	splitRight.ActiveAllocatorSnapshotSlot = SuperblockSlotB
	splitRightPair := superblockTestBuildSnapshot(t, splitRight, 32, []uint64{2, 10})
	superblockTestBindSnapshot(&splitRight, splitRightPair)
	splitRightWire := superblockTestEncode(t, splitRight)
	splitPairs := map[SuperblockSlot]superblockTestSnapshotPair{
		SuperblockSlotA: leftPair,
		SuperblockSlotB: splitRightPair,
	}
	if _, _, err := SelectLatestValidSuperblock(
		leftWire,
		splitRightWire,
		superblockTestSnapshotValidator(splitPairs)); !errors.Is(err, ErrSuperblockSplitBrain) {
		t.Fatalf("equal-sequence conflict error = %v", err)
	}

	if _, _, err := SelectLatestValidSuperblock(blank, blank, validator); !errors.Is(err, ErrNoValidSuperblock) {
		t.Fatalf("blank/blank error = %v", err)
	}
	if _, _, err := SelectLatestValidSuperblock(leftWire, rightWire, nil); !errors.Is(err, ErrNoValidSuperblock) {
		t.Fatalf("nil snapshot validator error = %v", err)
	}

	leftWire[68] ^= 0xff
	if selected.ClusterID != left.ClusterID {
		t.Fatal("selected model retained superblock slot alias")
	}
}

func TestSuperblockValidationIdentityBoundsSignedRangesAndGeometry(t *testing.T) {
	base, _, _ := superblockKnownFixture(t)
	mutations := []struct {
		name   string
		mutate func(*DeviceSuperblock)
	}{
		{"empty-cluster", func(value *DeviceSuperblock) { value.ClusterID = "" }},
		{"empty-device", func(value *DeviceSuperblock) { value.DeviceUUID = "" }},
		{"empty-owner-group", func(value *DeviceSuperblock) { value.OwnerGroupID = "" }},
		{"empty-current-owner", func(value *DeviceSuperblock) { value.CurrentOwnerID = "" }},
		{"empty-anchor", func(value *DeviceSuperblock) { value.OwnerGroupAnchorDeviceUUID = "" }},
		{"invalid-utf8", func(value *DeviceSuperblock) { value.CurrentOwnerID = string([]byte{0xff}) }},
		{"identity-over-256", func(value *DeviceSuperblock) { value.ClusterID = strings.Repeat("c", 257) }},
		{"surrounding-whitespace", func(value *DeviceSuperblock) { value.CurrentOwnerID = " owner" }},
		{"control-character", func(value *DeviceSuperblock) { value.CurrentOwnerID = "owner\nnode" }},
		{"device-path", func(value *DeviceSuperblock) { value.DeviceUUID = "/dev/dax0.0" }},
		{"device-file-uri", func(value *DeviceSuperblock) { value.DeviceUUID = "FILE:device" }},
		{"anchor-path", func(value *DeviceSuperblock) { value.OwnerGroupAnchorDeviceUUID = "/dev/dax0.0" }},
		{"wrong-compatibility", func(value *DeviceSuperblock) { value.StorageCompatibilityID += ";other" }},
		{"zero-owner-epoch", func(value *DeviceSuperblock) { value.OwnerEpoch = 0 }},
		{"large-owner-epoch", func(value *DeviceSuperblock) { value.OwnerEpoch = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-superblock-sequence", func(value *DeviceSuperblock) { value.SuperblockSequence = 0 }},
		{"large-superblock-sequence", func(value *DeviceSuperblock) { value.SuperblockSequence = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-group-role", func(value *DeviceSuperblock) { value.OwnerGroupRole = 0 }},
		{"self-anchor-as-member", func(value *DeviceSuperblock) { value.OwnerGroupRole = OwnerGroupRoleMember }},
		{"non-anchor-as-anchor", func(value *DeviceSuperblock) { value.DeviceUUID = "device-0002" }},
		{"zero-group-configuration", func(value *DeviceSuperblock) { value.OwnerGroupConfigurationSequence = 0 }},
		{"large-group-configuration", func(value *DeviceSuperblock) { value.OwnerGroupConfigurationSequence = cxlcheckpoint.MaxSignedLong + 1 }},
		{"zero-membership-sha", func(value *DeviceSuperblock) { value.OwnerGroupMembershipSHA256 = [sha256.Size]byte{} }},
		{"invalid-geometry", func(value *DeviceSuperblock) { value.Geometry.OwnerStateSnapshotAOffset++ }},
		{"zero-active-slot", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSlot = 0 }},
		{"large-active-slot", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSlot = 3 }},
		{"zero-active-sequence", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSequence = 0 }},
		{"large-active-sequence", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSequence = cxlcheckpoint.MaxSignedLong + 1 }},
		{"short-active-length", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotLength = AllocatorSnapshotFixedBytes - 1 }},
		{"large-active-length", func(value *DeviceSuperblock) {
			value.ActiveAllocatorSnapshotLength = value.Geometry.AllocatorSnapshotSlotBytes + 1
		}},
		{"zero-active-sha", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSHA256 = [sha256.Size]byte{} }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidSuperblock) {
				t.Fatalf("validation error = %v", err)
			}
			if _, err := CanonicalSuperblockBytes(candidate); !errors.Is(err, ErrInvalidSuperblock) {
				t.Fatalf("encode error = %v", err)
			}
		})
	}

	bounded := base
	bounded.ClusterID = strings.Repeat("c", MaxSuperblockIdentityBytes)
	bounded.DeviceUUID = strings.Repeat("d", MaxSuperblockIdentityBytes)
	bounded.OwnerGroupID = strings.Repeat("g", MaxSuperblockIdentityBytes)
	bounded.CurrentOwnerID = strings.Repeat("o", MaxSuperblockIdentityBytes)
	bounded.OwnerGroupAnchorDeviceUUID = bounded.DeviceUUID
	bounded.OwnerEpoch = cxlcheckpoint.MaxSignedLong
	bounded.SuperblockSequence = cxlcheckpoint.MaxSignedLong
	bounded.OwnerGroupConfigurationSequence = cxlcheckpoint.MaxSignedLong
	bounded.ActiveAllocatorSnapshotSequence = cxlcheckpoint.MaxSignedLong
	bounded.ActiveAllocatorSnapshotLength = bounded.Geometry.AllocatorSnapshotSlotBytes
	if err := bounded.Validate(); err != nil {
		t.Fatalf("inclusive identity/signed/length bounds: %v", err)
	}
	member := base
	member.DeviceUUID = "device-0002"
	member.OwnerGroupRole = OwnerGroupRoleMember
	if err := member.Validate(); err != nil {
		t.Fatalf("valid MEMBER role: %v", err)
	}
}

func TestSuperblockRejectsHeaderPayloadReservedAndTailCorruption(t *testing.T) {
	base, _, _ := superblockKnownFixture(t)
	wire := superblockTestEncode(t, base)

	for _, malformed := range [][]byte{wire[:len(wire)-1], append(append([]byte(nil), wire...), 0)} {
		if _, err := ParseSuperblock(malformed); !errors.Is(err, ErrCorruptSuperblock) {
			t.Fatalf("wrong-length error = %v", err)
		}
	}
	wantWrongFormat := []struct {
		name   string
		mutate func([]byte)
	}{
		{"magic", func(value []byte) { value[superblockMagicOffset] ^= 0xff }},
		{"version", func(value []byte) { binary.LittleEndian.PutUint32(value[superblockVersionOffset:], 6) }},
		{"header-size", func(value []byte) { binary.LittleEndian.PutUint32(value[superblockHeaderSizeOffset:], 63) }},
		{"domain", func(value []byte) { value[superblockDomainOffset] ^= 1 }},
		{"domain-padding", func(value []byte) { value[superblockDomainOffset+len(SuperblockDomain)] = 1 }},
	}
	for _, test := range wantWrongFormat {
		t.Run(test.name, func(t *testing.T) {
			candidate := append([]byte(nil), wire...)
			test.mutate(candidate)
			if _, err := ParseSuperblock(candidate); !errors.Is(err, ErrWrongSuperblockFormat) {
				t.Fatalf("parse error = %v", err)
			}
		})
	}

	wrongFlags := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(wrongFlags[superblockFlagsOffset:], 1)
	superblockTestRechecksum(wrongFlags)
	superblockTestRequireCorrupt(t, wrongFlags, "flags")
	wrongHeaderReserved := append([]byte(nil), wire...)
	wrongHeaderReserved[superblockHeaderReservedOffset] = 1
	superblockTestRechecksum(wrongHeaderReserved)
	superblockTestRequireCorrupt(t, wrongHeaderReserved, "header reserved")
	wrongHeaderCRC := append([]byte(nil), wire...)
	wrongHeaderCRC[superblockHeaderCRCOffset] ^= 1
	superblockTestRequireCorrupt(t, wrongHeaderCRC, "header CRC")
	wrongPayloadCRC := append([]byte(nil), wire...)
	wrongPayloadCRC[superblockPayloadCRCOffset] ^= 1
	// Restore header integrity so the payload CRC is the first failure.
	binary.LittleEndian.PutUint32(
		wrongPayloadCRC[superblockHeaderCRCOffset:],
		superblockHeaderCRC32C(wrongPayloadCRC[:SuperblockEnvelopeHeaderBytes]))
	superblockTestRequireCorrupt(t, wrongPayloadCRC, "payload CRC")
	wrongPayload := append([]byte(nil), wire...)
	wrongPayload[superblockPayloadOffset+4] ^= 1
	superblockTestRequireCorrupt(t, wrongPayload, "payload bytes")
	tail := append([]byte(nil), wire...)
	payloadLength := binary.LittleEndian.Uint64(tail[superblockPayloadLengthOffset:])
	tail[SuperblockEnvelopeHeaderBytes+payloadLength] = 1
	superblockTestRequireCorrupt(t, tail, "tail")

	roleReserved := append([]byte(nil), wire...)
	roleReserved[405] = 1
	superblockTestRechecksum(roleReserved)
	superblockTestRequireCorrupt(t, roleReserved, "Owner-group role reserved")
	activeReserved := append([]byte(nil), wire...)
	activeReserved[573] = 1
	superblockTestRechecksum(activeReserved)
	superblockTestRequireCorrupt(t, activeReserved, "active allocator reserved")
	oversizedIdentity := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint32(oversizedIdentity[superblockPayloadOffset:], MaxSuperblockIdentityBytes+1)
	superblockTestRechecksum(oversizedIdentity)
	superblockTestRequireCorrupt(t, oversizedIdentity, "bounded identity")
	extraPayload := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint64(extraPayload[superblockPayloadLengthOffset:], payloadLength+1)
	superblockTestRechecksum(extraPayload)
	superblockTestRequireCorrupt(t, extraPayload, "payload trailing byte")
	tooShort := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint64(tooShort[superblockPayloadLengthOffset:], superblockMinimumPayloadBytes-1)
	binary.LittleEndian.PutUint32(
		tooShort[superblockHeaderCRCOffset:],
		superblockHeaderCRC32C(tooShort[:SuperblockEnvelopeHeaderBytes]))
	superblockTestRequireCorrupt(t, tooShort, "short payload length")
	tooLong := append([]byte(nil), wire...)
	binary.LittleEndian.PutUint64(
		tooLong[superblockPayloadLengthOffset:],
		SuperblockSlotBytes-SuperblockEnvelopeHeaderBytes+1)
	binary.LittleEndian.PutUint32(
		tooLong[superblockHeaderCRCOffset:],
		superblockHeaderCRC32C(tooLong[:SuperblockEnvelopeHeaderBytes]))
	superblockTestRequireCorrupt(t, tooLong, "large payload length")

	invalidUTF8 := append([]byte(nil), wire...)
	invalidUTF8[68] = 0xff
	superblockTestRechecksum(invalidUTF8)
	if _, err := ParseSuperblock(invalidUTF8); !errors.Is(err, ErrInvalidSuperblock) {
		t.Fatalf("invalid UTF-8 error = %v", err)
	}
	wrongCompatibility := append([]byte(nil), wire...)
	wrongCompatibility[145] ^= 1
	superblockTestRechecksum(wrongCompatibility)
	if _, err := ParseSuperblock(wrongCompatibility); !errors.Is(err, ErrInvalidSuperblock) {
		t.Fatalf("wrong compatibility error = %v", err)
	}
}

func TestSuperblockBindingDigestInclusionAndExclusion(t *testing.T) {
	base, _, _ := superblockKnownFixture(t)
	deviceDigest := base.DeviceBindingSHA256()
	ownerGroupDigest := base.OwnerGroupIdentitySHA256()

	deviceIncluded := []struct {
		name   string
		mutate func(*DeviceSuperblock)
	}{
		{"cluster", func(value *DeviceSuperblock) { value.ClusterID += "-other" }},
		{"device", func(value *DeviceSuperblock) { value.DeviceUUID += "-other" }},
		{"compatibility", func(value *DeviceSuperblock) { value.StorageCompatibilityID += "-other" }},
		{"geometry", func(value *DeviceSuperblock) { value.Geometry.DataPageCount++ }},
		{"Owner-state-A-geometry", func(value *DeviceSuperblock) { value.Geometry.OwnerStateSnapshotAOffset++ }},
		{"Owner-state-B-geometry", func(value *DeviceSuperblock) { value.Geometry.OwnerStateSnapshotBOffset++ }},
		{"Owner-state-slot-geometry", func(value *DeviceSuperblock) { value.Geometry.OwnerStateSnapshotSlotBytes++ }},
	}
	for _, test := range deviceIncluded {
		candidate := base
		test.mutate(&candidate)
		if candidate.DeviceBindingSHA256() == deviceDigest {
			t.Fatalf("device digest excludes %s", test.name)
		}
	}
	deviceExcluded := []struct {
		name   string
		mutate func(*DeviceSuperblock)
	}{
		{"owner-group", func(value *DeviceSuperblock) { value.OwnerGroupID += "-other" }},
		{"current-owner", func(value *DeviceSuperblock) { value.CurrentOwnerID += "-other" }},
		{"owner-epoch", func(value *DeviceSuperblock) { value.OwnerEpoch++ }},
		{"group-role", func(value *DeviceSuperblock) { value.OwnerGroupRole = OwnerGroupRoleMember }},
		{"group-anchor", func(value *DeviceSuperblock) { value.OwnerGroupAnchorDeviceUUID += "-other" }},
		{"group-configuration", func(value *DeviceSuperblock) { value.OwnerGroupConfigurationSequence++ }},
		{"group-membership", func(value *DeviceSuperblock) { value.OwnerGroupMembershipSHA256[0] ^= 1 }},
		{"superblock-sequence", func(value *DeviceSuperblock) { value.SuperblockSequence++ }},
		{"active-slot", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSlot = SuperblockSlotA }},
		{"active-sequence", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSequence++ }},
		{"active-length", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotLength++ }},
		{"active-sha", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSHA256[0] ^= 1 }},
	}
	for _, test := range deviceExcluded {
		candidate := base
		test.mutate(&candidate)
		if candidate.DeviceBindingSHA256() != deviceDigest {
			t.Fatalf("device digest includes mutable %s", test.name)
		}
	}

	ownerGroupIncluded := []struct {
		name   string
		mutate func(*DeviceSuperblock)
	}{
		{"cluster", func(value *DeviceSuperblock) { value.ClusterID += "-other" }},
		{"owner-group", func(value *DeviceSuperblock) { value.OwnerGroupID += "-other" }},
		{"current-owner", func(value *DeviceSuperblock) { value.CurrentOwnerID += "-other" }},
		{"owner-epoch", func(value *DeviceSuperblock) { value.OwnerEpoch++ }},
		{"anchor", func(value *DeviceSuperblock) { value.OwnerGroupAnchorDeviceUUID += "-other" }},
		{"configuration", func(value *DeviceSuperblock) { value.OwnerGroupConfigurationSequence++ }},
		{"membership", func(value *DeviceSuperblock) { value.OwnerGroupMembershipSHA256[0] ^= 1 }},
	}
	for _, test := range ownerGroupIncluded {
		candidate := base
		test.mutate(&candidate)
		if candidate.OwnerGroupIdentitySHA256() == ownerGroupDigest {
			t.Fatalf("Owner-group digest excludes %s", test.name)
		}
	}
	ownerGroupExcluded := []struct {
		name   string
		mutate func(*DeviceSuperblock)
	}{
		{"device", func(value *DeviceSuperblock) { value.DeviceUUID += "-other" }},
		{"group-role", func(value *DeviceSuperblock) { value.OwnerGroupRole = OwnerGroupRoleMember }},
		{"compatibility", func(value *DeviceSuperblock) { value.StorageCompatibilityID += "-other" }},
		{"geometry", func(value *DeviceSuperblock) { value.Geometry.DeviceBytes++ }},
		{"superblock-sequence", func(value *DeviceSuperblock) { value.SuperblockSequence++ }},
		{"active-slot", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSlot = SuperblockSlotA }},
		{"active-sequence", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSequence++ }},
		{"active-length", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotLength++ }},
		{"active-sha", func(value *DeviceSuperblock) { value.ActiveAllocatorSnapshotSHA256[0] ^= 1 }},
	}
	for _, test := range ownerGroupExcluded {
		candidate := base
		test.mutate(&candidate)
		if candidate.OwnerGroupIdentitySHA256() != ownerGroupDigest {
			t.Fatalf("Owner-group digest includes %s", test.name)
		}
	}
}

func TestSuperblockContainsOnlyDeviceSnapshotBindingState(t *testing.T) {
	wantFields := []string{
		"ClusterID",
		"DeviceUUID",
		"OwnerGroupID",
		"CurrentOwnerID",
		"OwnerGroupAnchorDeviceUUID",
		"StorageCompatibilityID",
		"OwnerEpoch",
		"SuperblockSequence",
		"OwnerGroupRole",
		"OwnerGroupConfigurationSequence",
		"OwnerGroupMembershipSHA256",
		"Geometry",
		"ActiveAllocatorSnapshotSlot",
		"ActiveAllocatorSnapshotSequence",
		"ActiveAllocatorSnapshotLength",
		"ActiveAllocatorSnapshotSHA256",
	}
	target := reflect.TypeOf(DeviceSuperblock{})
	if target.NumField() != len(wantFields) {
		t.Fatalf("DeviceSuperblock has %d fields, expected %d", target.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		if got := target.Field(index).Name; got != want {
			t.Fatalf("DeviceSuperblock field %d = %q, expected %q", index, got, want)
		}
	}
	for index := 0; index < target.NumField(); index++ {
		name := strings.ToLower(target.Field(index).Name)
		for _, forbidden := range []string{
			"generation", "path", "mount", "route", "artifact", "checkpoint", "refcount", "runtime",
			"ownerstate", "journalhead", "journalroot",
		} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("DeviceSuperblock contains forbidden field %q", target.Field(index).Name)
			}
		}
	}
	if reflect.TypeOf(SuperblockSlotA).Kind() != reflect.Uint8 ||
		SuperblockSlotA != 1 || SuperblockSlotB != 2 ||
		SuperblockSlotA.String() != "A" || SuperblockSlotB.String() != "B" {
		t.Fatalf("A/B slot ABI = %d/%d", SuperblockSlotA, SuperblockSlotB)
	}
	if reflect.TypeOf(OwnerGroupRoleAnchor).Kind() != reflect.Uint8 ||
		OwnerGroupRoleAnchor != 1 || OwnerGroupRoleMember != 2 ||
		OwnerGroupRoleAnchor.String() != "ANCHOR" || OwnerGroupRoleMember.String() != "MEMBER" {
		t.Fatalf("Owner-group role ABI = %d/%d", OwnerGroupRoleAnchor, OwnerGroupRoleMember)
	}
}

func superblockKnownFixture(
	t *testing.T,
) (DeviceSuperblock, AllocatorSnapshot, AllocatorSnapshotStorage) {
	t.Helper()
	geometry, err := CalculateDeviceGeometry(1<<20, 4096, 4096)
	if err != nil {
		t.Fatalf("known geometry: %v", err)
	}
	superblock := superblockTestSkeleton(geometry)
	superblock.ClusterID = "cluster-α"
	superblock.DeviceUUID = "device-0001"
	superblock.OwnerGroupID = "owner-group-3"
	superblock.CurrentOwnerID = "owner-node-7"
	superblock.OwnerGroupAnchorDeviceUUID = superblock.DeviceUUID
	superblock.OwnerGroupRole = OwnerGroupRoleAnchor
	superblock.OwnerGroupConfigurationSequence = 5
	for index := range superblock.OwnerGroupMembershipSHA256 {
		superblock.OwnerGroupMembershipSHA256[index] = byte(0xc0 + index)
	}
	superblock.OwnerEpoch = 11
	superblock.SuperblockSequence = 17
	superblock.ActiveAllocatorSnapshotSlot = SuperblockSlotB
	if geometry.DataPageCount != 246 {
		t.Fatalf("known data-page count = %d, expected 246", geometry.DataPageCount)
	}
	pair := superblockTestBuildSnapshot(t, superblock, 12, []uint64{0, 1, 7, 8, 63, geometry.DataPageCount - 1})
	superblockTestBindSnapshot(&superblock, pair)
	return superblock, pair.snapshot, pair.storage
}

func superblockTestSkeleton(geometry DeviceGeometry) DeviceSuperblock {
	return DeviceSuperblock{
		ClusterID:                       "cluster-a",
		DeviceUUID:                      "device-a",
		OwnerGroupID:                    "owner-group-a",
		CurrentOwnerID:                  "owner-a",
		OwnerGroupAnchorDeviceUUID:      "device-a",
		StorageCompatibilityID:          cxlcheckpoint.V7StorageCompatibilityID,
		OwnerEpoch:                      11,
		SuperblockSequence:              17,
		OwnerGroupRole:                  OwnerGroupRoleAnchor,
		OwnerGroupConfigurationSequence: 5,
		OwnerGroupMembershipSHA256:      sha256.Sum256([]byte("owner-group-membership-a")),
		Geometry:                        geometry,
	}
}

func superblockTestBuildSnapshot(
	t *testing.T,
	superblock DeviceSuperblock,
	sequence uint64,
	allocatedPages []uint64,
) superblockTestSnapshotPair {
	t.Helper()
	bitmapBytes, err := superblock.Geometry.AllocationBitmapBytes()
	if err != nil {
		t.Fatalf("bitmap length: %v", err)
	}
	bitmap := make([]byte, int(bitmapBytes))
	for _, page := range allocatedPages {
		if page >= superblock.Geometry.DataPageCount {
			t.Fatalf("allocated page %d exceeds geometry", page)
		}
		bitmap[page/8] |= byte(1) << uint(page%8)
	}
	snapshot, err := NewAllocatorSnapshot(
		superblockTestSnapshotConfig(superblock, sequence, superblock.Geometry.DataPageCount),
		bitmap)
	if err != nil {
		t.Fatalf("new allocator snapshot: %v", err)
	}
	storage, err := EncodeAllocatorSnapshotForStorage(snapshot, superblock.Geometry)
	if err != nil {
		t.Fatalf("encode allocator snapshot storage: %v", err)
	}
	return superblockTestSnapshotPair{snapshot: snapshot, storage: storage}
}

func superblockTestSnapshotConfig(
	superblock DeviceSuperblock,
	sequence uint64,
	dataPageCount uint64,
) AllocatorSnapshotConfig {
	return AllocatorSnapshotConfig{
		DeviceBindingSHA256:             superblock.DeviceBindingSHA256(),
		OwnerGroupIdentitySHA256:        superblock.OwnerGroupIdentitySHA256(),
		OwnerEpoch:                      superblock.OwnerEpoch,
		SnapshotSequence:                sequence,
		AppliedOwnerTransactionSequence: 303,
		DataPageCount:                   dataPageCount,
	}
}

func superblockTestBindSnapshot(
	superblock *DeviceSuperblock,
	pair superblockTestSnapshotPair,
) {
	superblock.ActiveAllocatorSnapshotSequence = pair.snapshot.SnapshotSequence
	superblock.ActiveAllocatorSnapshotLength = pair.storage.ExactLength()
	superblock.ActiveAllocatorSnapshotSHA256 = pair.storage.SHA256()
}

func superblockTestSnapshotValidator(
	pairs map[SuperblockSlot]superblockTestSnapshotPair,
) SuperblockSnapshotValidator {
	return func(superblock DeviceSuperblock) error {
		pair, ok := pairs[superblock.ActiveAllocatorSnapshotSlot]
		if !ok {
			return errors.New("referenced allocator-snapshot slot is absent")
		}
		return superblock.CrossCheckAllocatorSnapshot(pair.snapshot, pair.storage)
	}
}

func superblockTestEncode(t *testing.T, superblock DeviceSuperblock) []byte {
	t.Helper()
	wire, err := CanonicalSuperblockBytes(superblock)
	if err != nil {
		t.Fatalf("encode superblock: %v", err)
	}
	return wire
}

func superblockTestRechecksum(wire []byte) {
	payloadLength := binary.LittleEndian.Uint64(wire[superblockPayloadLengthOffset:])
	binary.LittleEndian.PutUint32(
		wire[superblockPayloadCRCOffset:],
		superblockCRC32C(wire[SuperblockEnvelopeHeaderBytes:SuperblockEnvelopeHeaderBytes+payloadLength]))
	binary.LittleEndian.PutUint32(
		wire[superblockHeaderCRCOffset:],
		superblockHeaderCRC32C(wire[:SuperblockEnvelopeHeaderBytes]))
}

func superblockTestRequireCorrupt(t *testing.T, wire []byte, name string) {
	t.Helper()
	if _, err := ParseSuperblock(wire); !errors.Is(err, ErrCorruptSuperblock) {
		t.Fatalf("%s error = %v", name, err)
	}
}
