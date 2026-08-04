package trcxl007

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	// SuperblockMagicString, SuperblockVersion, and SuperblockDomain identify
	// the clean-slate TRCXL007 device-superblock envelope. The format is pure
	// persistent metadata; it does not open, map, write, or flush a DAX device.
	SuperblockMagicString = "TRCXL007"
	SuperblockVersion     = uint32(7)
	SuperblockDomain      = "device-superblock-v1"

	SuperblockEnvelopeHeaderBytes uint64 = 64
	MaxSuperblockIdentityBytes           = 256

	// The digest domains deliberately differ from the envelope domain. A
	// digest is a stable binding key, not authentication and not an encoding
	// of mutable A/B publication state.
	SuperblockDeviceBindingDigestDomain      = "TRCXL007-device-binding-v1"
	SuperblockOwnerGroupIdentityDigestDomain = "TRCXL007-owner-group-identity-v1"
)

var (
	ErrInvalidSuperblock          = errors.New("invalid TRCXL007 device superblock")
	ErrWrongSuperblockFormat      = errors.New("not a TRCXL007 device superblock")
	ErrCorruptSuperblock          = errors.New("corrupt TRCXL007 device superblock")
	ErrSuperblockSnapshotMismatch = errors.New("TRCXL007 allocator snapshot does not match superblock")
	ErrNoValidSuperblock          = errors.New("no valid TRCXL007 device superblock")
	ErrSuperblockSplitBrain       = errors.New("TRCXL007 superblock A/B split brain")
)

// SuperblockSlot is the stable on-media A/B index. The same values identify
// either a superblock copy or the allocator-snapshot copy selected by a
// superblock. Zero is intentionally invalid, so an omitted selection cannot
// silently mean slot A.
type SuperblockSlot uint8

const (
	SuperblockSlotA SuperblockSlot = 1
	SuperblockSlotB SuperblockSlot = 2
)

// OwnerGroupRole is the stable device role within one Owner group. Only the
// device named by OwnerGroupAnchorDeviceUUID may be ANCHOR; every other member
// is MEMBER. Mutable Owner-state A/B selection is deliberately not a role or
// superblock field.
type OwnerGroupRole uint8

const (
	OwnerGroupRoleAnchor OwnerGroupRole = 1
	OwnerGroupRoleMember OwnerGroupRole = 2
)

func (role OwnerGroupRole) valid() bool {
	return role == OwnerGroupRoleAnchor || role == OwnerGroupRoleMember
}

func (role OwnerGroupRole) String() string {
	switch role {
	case OwnerGroupRoleAnchor:
		return "ANCHOR"
	case OwnerGroupRoleMember:
		return "MEMBER"
	default:
		return fmt.Sprintf("OwnerGroupRole(%d)", role)
	}
}

// SuperblockSnapshotValidator validates the complete allocator-snapshot pair
// referenced by one structurally valid superblock candidate. A selector's
// caller can parse the indicated snapshot slot and call
// DeviceSuperblock.CrossCheckAllocatorSnapshot without giving this pure codec
// any device-I/O responsibility.
type SuperblockSnapshotValidator func(DeviceSuperblock) error

func (slot SuperblockSlot) valid() bool {
	return slot == SuperblockSlotA || slot == SuperblockSlotB
}

func (slot SuperblockSlot) String() string {
	switch slot {
	case SuperblockSlotA:
		return "A"
	case SuperblockSlotB:
		return "B"
	default:
		return fmt.Sprintf("SuperblockSlot(%d)", slot)
	}
}

// DeviceSuperblock is the complete logical state of one canonical 4 KiB
// TRCXL007 superblock slot. DeviceUUID is the destructive-format identity: a
// destructive reformat creates a new DeviceUUID. SuperblockSequence only
// orders A/B commits and must never be used as page identity.
//
// Artifact and memory payloads share Geometry.ContentRegion. Checkpoint,
// route, path, mount, per-page generation, reference-count, and runtime state
// intentionally do not belong in this device-level record.
type DeviceSuperblock struct {
	ClusterID                  string
	DeviceUUID                 string
	OwnerGroupID               string
	CurrentOwnerID             string
	OwnerGroupAnchorDeviceUUID string
	StorageCompatibilityID     string

	OwnerEpoch                      uint64
	SuperblockSequence              uint64
	OwnerGroupRole                  OwnerGroupRole
	OwnerGroupConfigurationSequence uint64
	OwnerGroupMembershipSHA256      [sha256.Size]byte
	Geometry                        DeviceGeometry

	ActiveAllocatorSnapshotSlot     SuperblockSlot
	ActiveAllocatorSnapshotSequence uint64
	ActiveAllocatorSnapshotLength   uint64
	ActiveAllocatorSnapshotSHA256   [sha256.Size]byte
}

// Validate checks the complete logical superblock independently of its A/B
// location. It does not inspect or mutate an allocator-snapshot slot.
func (superblock DeviceSuperblock) Validate() error {
	if err := superblockValidateCompiledContract(); err != nil {
		return err
	}
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"cluster ID", superblock.ClusterID},
		{"device UUID", superblock.DeviceUUID},
		{"Owner-group ID", superblock.OwnerGroupID},
		{"current Owner ID", superblock.CurrentOwnerID},
		{"Owner-group anchor device UUID", superblock.OwnerGroupAnchorDeviceUUID},
	} {
		if err := superblockValidateIdentity(identity.name, identity.value); err != nil {
			return err
		}
	}
	if err := superblockValidateDeviceUUID(superblock.DeviceUUID); err != nil {
		return err
	}
	if err := superblockValidateDeviceUUID(superblock.OwnerGroupAnchorDeviceUUID); err != nil {
		return superblockInvalidf("Owner-group anchor: %v", err)
	}
	if superblock.StorageCompatibilityID != cxlcheckpoint.V7StorageCompatibilityID {
		return superblockInvalidf("storage compatibility ID does not equal the compiled V7 target")
	}
	for _, field := range []struct {
		name  string
		value uint64
	}{
		{"Owner epoch", superblock.OwnerEpoch},
		{"superblock sequence", superblock.SuperblockSequence},
		{"Owner-group configuration sequence", superblock.OwnerGroupConfigurationSequence},
		{"active allocator-snapshot sequence", superblock.ActiveAllocatorSnapshotSequence},
	} {
		if field.value == 0 || field.value > cxlcheckpoint.MaxSignedLong {
			return superblockInvalidf(
				"%s %d is outside 1..%d",
				field.name,
				field.value,
				cxlcheckpoint.MaxSignedLong)
		}
	}
	if !superblock.OwnerGroupRole.valid() {
		return superblockInvalidf("Owner-group role %d is neither ANCHOR nor MEMBER", superblock.OwnerGroupRole)
	}
	selfIsAnchor := superblock.DeviceUUID == superblock.OwnerGroupAnchorDeviceUUID
	if (superblock.OwnerGroupRole == OwnerGroupRoleAnchor) != selfIsAnchor {
		return superblockInvalidf(
			"Owner-group role %s disagrees with device/anchor UUID equality",
			superblock.OwnerGroupRole)
	}
	if superblock.OwnerGroupMembershipSHA256 == ([sha256.Size]byte{}) {
		return superblockInvalidf("Owner-group membership SHA-256 is zero")
	}
	if err := superblock.Geometry.Validate(); err != nil {
		return superblockInvalidf("device geometry: %v", err)
	}
	if !superblock.ActiveAllocatorSnapshotSlot.valid() {
		return superblockInvalidf(
			"active allocator-snapshot slot %d is neither A nor B",
			superblock.ActiveAllocatorSnapshotSlot)
	}
	if superblock.ActiveAllocatorSnapshotLength < AllocatorSnapshotFixedBytes ||
		superblock.ActiveAllocatorSnapshotLength > superblock.Geometry.AllocatorSnapshotSlotBytes {
		return superblockInvalidf(
			"active allocator-snapshot length %d is outside %d..%d",
			superblock.ActiveAllocatorSnapshotLength,
			AllocatorSnapshotFixedBytes,
			superblock.Geometry.AllocatorSnapshotSlotBytes)
	}
	if superblock.ActiveAllocatorSnapshotSHA256 == ([sha256.Size]byte{}) {
		return superblockInvalidf("active allocator-snapshot SHA-256 is zero")
	}
	return nil
}

// DeviceBindingSHA256 returns the static device binding copied into every
// allocator snapshot. It includes only the cluster, destructive-format device
// identity, exact compatibility ID, and exact geometry. Owner identity,
// epochs, sequences, and active A/B state are deliberately excluded.
//
// The method is useful while constructing the first allocator snapshot, so it
// does not require the mutable superblock fields to have been populated yet.
func (superblock DeviceSuperblock) DeviceBindingSHA256() [sha256.Size]byte {
	digest := sha256.New()
	superblockDigestString(digest, SuperblockDeviceBindingDigestDomain)
	superblockDigestString(digest, superblock.ClusterID)
	superblockDigestString(digest, superblock.DeviceUUID)
	superblockDigestString(digest, superblock.StorageCompatibilityID)
	superblockDigestGeometry(digest, superblock.Geometry)
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

// OwnerGroupIdentitySHA256 returns the complete Owner-group binding copied
// into every device-local allocator snapshot. The membership digest is an
// already-canonical result produced by the Owner-state contract; this method
// stores it as opaque bytes and does not duplicate that canonical algorithm.
func (superblock DeviceSuperblock) OwnerGroupIdentitySHA256() [sha256.Size]byte {
	digest := sha256.New()
	superblockDigestString(digest, SuperblockOwnerGroupIdentityDigestDomain)
	superblockDigestString(digest, superblock.ClusterID)
	superblockDigestString(digest, superblock.OwnerGroupID)
	superblockDigestString(digest, superblock.CurrentOwnerID)
	superblockDigestUint64(digest, superblock.OwnerEpoch)
	superblockDigestString(digest, superblock.OwnerGroupAnchorDeviceUUID)
	superblockDigestUint64(digest, superblock.OwnerGroupConfigurationSequence)
	_, _ = digest.Write(superblock.OwnerGroupMembershipSHA256[:])
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

// CrossCheckAllocatorSnapshot binds the selected logical snapshot and its
// exact storage envelope to this superblock. All AllocatorSnapshot API contact
// is kept in superblockCrossCheckAllocatorSnapshotStorage so that concurrent
// allocator work can be adapted in one narrow location. No padded slot copy is
// requested or created here.
func (superblock DeviceSuperblock) CrossCheckAllocatorSnapshot(
	snapshot AllocatorSnapshot,
	storage AllocatorSnapshotStorage,
) error {
	if err := superblock.Validate(); err != nil {
		return err
	}
	return superblockCrossCheckAllocatorSnapshotStorage(superblock, snapshot, storage)
}

func superblockCrossCheckAllocatorSnapshotStorage(
	superblock DeviceSuperblock,
	snapshot AllocatorSnapshot,
	storage AllocatorSnapshotStorage,
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

	// Re-encode only the exact meaningful envelope. This ties the logical
	// snapshot to the committed length and digest without allocating or
	// copying the potentially much larger zero-padded slot image.
	exact, err := CanonicalAllocatorSnapshotBytes(snapshot, superblock.Geometry)
	if err != nil {
		return superblockSnapshotMismatchf("canonical snapshot: %v", err)
	}
	exactLength := uint64(len(exact))
	exactSHA256 := sha256.Sum256(exact)
	if exactLength != superblock.ActiveAllocatorSnapshotLength {
		return superblockSnapshotMismatchf(
			"canonical snapshot length %d does not equal active length %d",
			exactLength,
			superblock.ActiveAllocatorSnapshotLength)
	}
	if exactSHA256 != superblock.ActiveAllocatorSnapshotSHA256 {
		return superblockSnapshotMismatchf("canonical snapshot SHA-256 differs from active digest")
	}
	if storage.ExactLength() != exactLength {
		return superblockSnapshotMismatchf(
			"storage exact length %d does not equal canonical length %d",
			storage.ExactLength(),
			exactLength)
	}
	if storage.SlotLength() != superblock.Geometry.AllocatorSnapshotSlotBytes {
		return superblockSnapshotMismatchf(
			"storage slot length %d does not equal geometry slot length %d",
			storage.SlotLength(),
			superblock.Geometry.AllocatorSnapshotSlotBytes)
	}
	if storage.SHA256() != exactSHA256 {
		return superblockSnapshotMismatchf("storage exact SHA-256 differs from canonical digest")
	}
	return nil
}

func superblockValidateCompiledContract() error {
	if SuperblockMagicString != cxlcheckpoint.V7StorageDeviceFormatMagicString ||
		SuperblockVersion != cxlcheckpoint.V7StorageDeviceFormatVersion ||
		SuperblockSlotBytes != cxlcheckpoint.V7StoragePageSize ||
		SuperblockEnvelopeHeaderBytes != 64 ||
		len(SuperblockDomain) > superblockDomainFieldBytes ||
		len(cxlcheckpoint.V7StorageCompatibilityID) > MaxSuperblockIdentityBytes {
		return superblockInvalidf("compiled constants do not name the required TRCXL007 V7 ABI")
	}
	return nil
}

func superblockValidateIdentity(name, value string) error {
	if value == "" {
		return superblockInvalidf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return superblockInvalidf("%s is not valid UTF-8", name)
	}
	if len(value) > MaxSuperblockIdentityBytes {
		return superblockInvalidf(
			"%s is %d UTF-8 bytes, limit is %d",
			name,
			len(value),
			MaxSuperblockIdentityBytes)
	}
	if strings.TrimSpace(value) != value {
		return superblockInvalidf("%s has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return superblockInvalidf("%s contains a control character", name)
		}
	}
	return nil
}

func superblockValidateDeviceUUID(value string) error {
	fileURI := len(value) >= len("file:") && strings.EqualFold(value[:len("file:")], "file:")
	if strings.ContainsAny(value, "/\\") || value == "." || value == ".." || fileURI {
		return superblockInvalidf("device UUID %q looks like a local path", value)
	}
	return nil
}

func superblockDigestString(writer io.Writer, value string) {
	var length [4]byte
	binary.LittleEndian.PutUint32(length[:], uint32(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}

func superblockDigestGeometry(writer io.Writer, geometry DeviceGeometry) {
	var encoded [8]byte
	for _, value := range []uint64{
		geometry.DeviceBytes,
		geometry.SuperblockAOffset,
		geometry.SuperblockBOffset,
		geometry.AllocatorSnapshotAOffset,
		geometry.AllocatorSnapshotBOffset,
		geometry.AllocatorSnapshotSlotBytes,
		geometry.OwnerStateSnapshotAOffset,
		geometry.OwnerStateSnapshotBOffset,
		geometry.OwnerStateSnapshotSlotBytes,
		geometry.ControlRegionBytes,
		geometry.DescriptorRegionBase,
		geometry.DescriptorRegionBytes,
		geometry.ContentRegionBase,
		geometry.ContentRegionBytes,
		geometry.DataPageCount,
	} {
		binary.LittleEndian.PutUint64(encoded[:], value)
		_, _ = writer.Write(encoded[:])
	}
}

func superblockDigestUint64(writer io.Writer, value uint64) {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	_, _ = writer.Write(encoded[:])
}

func superblockInvalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrInvalidSuperblock, fmt.Sprintf(format, arguments...))
}

func superblockCorruptf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCorruptSuperblock, fmt.Sprintf(format, arguments...))
}

func superblockSnapshotMismatchf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrSuperblockSnapshotMismatch, fmt.Sprintf(format, arguments...))
}
