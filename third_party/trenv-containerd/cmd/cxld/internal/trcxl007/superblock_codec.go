package trcxl007

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

const (
	superblockDomainFieldBytes = 24

	superblockMagicOffset          = 0
	superblockVersionOffset        = 8
	superblockHeaderSizeOffset     = 12
	superblockDomainOffset         = 16
	superblockPayloadLengthOffset  = 40
	superblockPayloadCRCOffset     = 48
	superblockFlagsOffset          = 52
	superblockHeaderCRCOffset      = 56
	superblockHeaderReservedOffset = 60

	superblockPayloadOffset = 64

	// The variable prefix is six uint32-length-prefixed UTF-8 strings. The
	// fixed suffix is Owner epoch + superblock sequence + one-byte group role
	// and seven reserved bytes + group configuration sequence + membership
	// SHA-256 + fifteen geometry uint64s + one-byte active allocator slot and
	// seven reserved bytes + active sequence + exact length + SHA-256.
	superblockPayloadStringCount  = 6
	superblockGeometryFieldCount  = 15
	superblockFixedScalarBytes    = 240
	superblockMinimumPayloadBytes = superblockPayloadStringCount*4 + superblockFixedScalarBytes
)

var (
	superblockMagic  = [8]byte{'T', 'R', 'C', 'X', 'L', '0', '0', '7'}
	superblockDomain = func() [superblockDomainFieldBytes]byte {
		var domain [superblockDomainFieldBytes]byte
		copy(domain[:], SuperblockDomain)
		return domain
	}()
	superblockCRC32CTable  = crc32.MakeTable(crc32.Castagnoli)
	superblockZeroCRCField [4]byte
)

// CanonicalSuperblockBytes returns exactly one complete 4 KiB A/B slot image.
// Bytes after the meaningful payload are always zero and are included in the
// canonical representation, but not in the meaningful-payload CRC32C.
func CanonicalSuperblockBytes(superblock DeviceSuperblock) ([]byte, error) {
	if err := superblock.Validate(); err != nil {
		return nil, err
	}
	payload := superblockCanonicalPayload(superblock)
	if len(payload) < superblockMinimumPayloadBytes ||
		uint64(len(payload)) > SuperblockSlotBytes-SuperblockEnvelopeHeaderBytes {
		return nil, superblockInvalidf(
			"payload length %d does not fit one superblock slot",
			len(payload))
	}

	wire := make([]byte, int(SuperblockSlotBytes))
	copy(wire[superblockMagicOffset:superblockVersionOffset], superblockMagic[:])
	binary.LittleEndian.PutUint32(wire[superblockVersionOffset:], SuperblockVersion)
	binary.LittleEndian.PutUint32(
		wire[superblockHeaderSizeOffset:],
		uint32(SuperblockEnvelopeHeaderBytes))
	copy(
		wire[superblockDomainOffset:superblockPayloadLengthOffset],
		superblockDomain[:])
	binary.LittleEndian.PutUint64(wire[superblockPayloadLengthOffset:], uint64(len(payload)))
	binary.LittleEndian.PutUint32(wire[superblockPayloadCRCOffset:], superblockCRC32C(payload))
	copy(wire[superblockPayloadOffset:], payload)
	binary.LittleEndian.PutUint32(
		wire[superblockHeaderCRCOffset:],
		superblockHeaderCRC32C(wire[:SuperblockEnvelopeHeaderBytes]))
	return wire, nil
}

// ParseSuperblock accepts exactly one canonical 4 KiB slot. The fixed header,
// header CRC, and bounded payload length are validated before any payload
// string is converted or any variable-length field is addressed.
func ParseSuperblock(wire []byte) (DeviceSuperblock, error) {
	if err := superblockValidateCompiledContract(); err != nil {
		return DeviceSuperblock{}, err
	}
	if len(wire) != int(SuperblockSlotBytes) {
		return DeviceSuperblock{}, superblockCorruptf(
			"slot length %d does not equal %d",
			len(wire),
			SuperblockSlotBytes)
	}
	if !bytes.Equal(wire[superblockMagicOffset:superblockVersionOffset], superblockMagic[:]) {
		return DeviceSuperblock{}, superblockWrongFormatf("magic is not %q", SuperblockMagicString)
	}
	if binary.LittleEndian.Uint32(wire[superblockVersionOffset:]) != SuperblockVersion {
		return DeviceSuperblock{}, superblockWrongFormatf("version is not %d", SuperblockVersion)
	}
	if binary.LittleEndian.Uint32(wire[superblockHeaderSizeOffset:]) !=
		uint32(SuperblockEnvelopeHeaderBytes) {
		return DeviceSuperblock{}, superblockWrongFormatf(
			"header size is not %d",
			SuperblockEnvelopeHeaderBytes)
	}
	if !bytes.Equal(
		wire[superblockDomainOffset:superblockPayloadLengthOffset],
		superblockDomain[:]) {
		return DeviceSuperblock{}, superblockWrongFormatf("domain is not %q", SuperblockDomain)
	}
	if binary.LittleEndian.Uint32(wire[superblockFlagsOffset:]) != 0 {
		return DeviceSuperblock{}, superblockCorruptf("header flags must be zero")
	}
	if binary.LittleEndian.Uint32(wire[superblockHeaderReservedOffset:]) != 0 {
		return DeviceSuperblock{}, superblockCorruptf("header reserved bytes must be zero")
	}
	storedHeaderCRC32C := binary.LittleEndian.Uint32(wire[superblockHeaderCRCOffset:])
	computedHeaderCRC32C := superblockHeaderCRC32C(wire[:SuperblockEnvelopeHeaderBytes])
	if storedHeaderCRC32C != computedHeaderCRC32C {
		return DeviceSuperblock{}, superblockCorruptf(
			"header CRC32C %#08x does not equal computed CRC32C %#08x",
			storedHeaderCRC32C,
			computedHeaderCRC32C)
	}

	payloadLength := binary.LittleEndian.Uint64(wire[superblockPayloadLengthOffset:])
	if payloadLength < superblockMinimumPayloadBytes ||
		payloadLength > SuperblockSlotBytes-SuperblockEnvelopeHeaderBytes {
		return DeviceSuperblock{}, superblockCorruptf(
			"payload length %d is outside %d..%d",
			payloadLength,
			superblockMinimumPayloadBytes,
			SuperblockSlotBytes-SuperblockEnvelopeHeaderBytes)
	}
	payloadEnd := SuperblockEnvelopeHeaderBytes + payloadLength
	payload := wire[SuperblockEnvelopeHeaderBytes:payloadEnd]
	storedPayloadCRC32C := binary.LittleEndian.Uint32(wire[superblockPayloadCRCOffset:])
	computedPayloadCRC32C := superblockCRC32C(payload)
	if storedPayloadCRC32C != computedPayloadCRC32C {
		return DeviceSuperblock{}, superblockCorruptf(
			"payload CRC32C %#08x does not equal computed CRC32C %#08x",
			storedPayloadCRC32C,
			computedPayloadCRC32C)
	}
	if !superblockAllZero(wire[payloadEnd:]) {
		return DeviceSuperblock{}, superblockCorruptf("slot tail after meaningful payload must be zero")
	}

	decoded, err := superblockParsePayload(payload)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	if err := decoded.Validate(); err != nil {
		return DeviceSuperblock{}, err
	}
	canonical, err := CanonicalSuperblockBytes(decoded)
	if err != nil {
		return DeviceSuperblock{}, superblockCorruptf("canonical re-encode failed: %v", err)
	}
	if !bytes.Equal(canonical, wire) {
		return DeviceSuperblock{}, superblockCorruptf("slot is not canonically encoded")
	}
	return decoded, nil
}

// SelectLatestValidSuperblock performs a read-only latest-valid A/B choice.
// An exactly all-zero 4 KiB slot is absent. A candidate is valid only when its
// superblock is canonical and validateReferencedSnapshot accepts the complete
// referenced allocator-snapshot pair. A corrupt or otherwise invalid newer
// pair may therefore fall back to the older valid pair. Equal valid sequences
// are accepted only when the complete canonical superblock slot images are
// byte-identical; otherwise they are split brain.
func SelectLatestValidSuperblock(
	slotA []byte,
	slotB []byte,
	validateReferencedSnapshot SuperblockSnapshotValidator,
) (SuperblockSlot, DeviceSuperblock, error) {
	parse := func(slot SuperblockSlot, wire []byte) superblockCandidate {
		result := superblockCandidate{slot: slot, wire: wire}
		if len(wire) == int(SuperblockSlotBytes) && superblockAllZero(wire) {
			result.blank = true
			return result
		}
		result.superblock, result.err = ParseSuperblock(wire)
		if result.err == nil {
			if validateReferencedSnapshot == nil {
				result.err = superblockSnapshotMismatchf("referenced-snapshot validator is nil")
			} else if err := validateReferencedSnapshot(result.superblock); err != nil {
				result.err = superblockSnapshotMismatchf("referenced snapshot: %v", err)
			}
		}
		return result
	}

	left := parse(SuperblockSlotA, slotA)
	right := parse(SuperblockSlotB, slotB)
	leftValid := !left.blank && left.err == nil
	rightValid := !right.blank && right.err == nil
	switch {
	case leftValid && !rightValid:
		return left.slot, left.superblock, nil
	case !leftValid && rightValid:
		return right.slot, right.superblock, nil
	case !leftValid && !rightValid:
		return 0, DeviceSuperblock{}, fmt.Errorf(
			"%w: slot A %s; slot B %s",
			ErrNoValidSuperblock,
			superblockCandidateFailure(left),
			superblockCandidateFailure(right))
	}

	if left.superblock.SuperblockSequence > right.superblock.SuperblockSequence {
		return left.slot, left.superblock, nil
	}
	if right.superblock.SuperblockSequence > left.superblock.SuperblockSequence {
		return right.slot, right.superblock, nil
	}
	if !bytes.Equal(left.wire, right.wire) {
		return 0, DeviceSuperblock{}, fmt.Errorf(
			"%w: valid slot A and B both claim sequence %d with different bytes",
			ErrSuperblockSplitBrain,
			left.superblock.SuperblockSequence)
	}
	return left.slot, left.superblock, nil
}

func superblockCanonicalPayload(superblock DeviceSuperblock) []byte {
	payload := make([]byte, 0, 512)
	payload = superblockAppendString(payload, superblock.ClusterID)
	payload = superblockAppendString(payload, superblock.DeviceUUID)
	payload = superblockAppendString(payload, superblock.OwnerGroupID)
	payload = superblockAppendString(payload, superblock.CurrentOwnerID)
	payload = superblockAppendString(payload, superblock.OwnerGroupAnchorDeviceUUID)
	payload = superblockAppendString(payload, superblock.StorageCompatibilityID)
	payload = superblockAppendUint64(payload, superblock.OwnerEpoch)
	payload = superblockAppendUint64(payload, superblock.SuperblockSequence)
	payload = append(payload, byte(superblock.OwnerGroupRole))
	payload = append(payload, make([]byte, 7)...)
	payload = superblockAppendUint64(payload, superblock.OwnerGroupConfigurationSequence)
	payload = append(payload, superblock.OwnerGroupMembershipSHA256[:]...)
	for _, value := range []uint64{
		superblock.Geometry.DeviceBytes,
		superblock.Geometry.SuperblockAOffset,
		superblock.Geometry.SuperblockBOffset,
		superblock.Geometry.AllocatorSnapshotAOffset,
		superblock.Geometry.AllocatorSnapshotBOffset,
		superblock.Geometry.AllocatorSnapshotSlotBytes,
		superblock.Geometry.OwnerStateSnapshotAOffset,
		superblock.Geometry.OwnerStateSnapshotBOffset,
		superblock.Geometry.OwnerStateSnapshotSlotBytes,
		superblock.Geometry.ControlRegionBytes,
		superblock.Geometry.DescriptorRegionBase,
		superblock.Geometry.DescriptorRegionBytes,
		superblock.Geometry.ContentRegionBase,
		superblock.Geometry.ContentRegionBytes,
		superblock.Geometry.DataPageCount,
	} {
		payload = superblockAppendUint64(payload, value)
	}
	payload = append(payload, byte(superblock.ActiveAllocatorSnapshotSlot))
	payload = append(payload, make([]byte, 7)...)
	payload = superblockAppendUint64(payload, superblock.ActiveAllocatorSnapshotSequence)
	payload = superblockAppendUint64(payload, superblock.ActiveAllocatorSnapshotLength)
	payload = append(payload, superblock.ActiveAllocatorSnapshotSHA256[:]...)
	return payload
}

func superblockParsePayload(payload []byte) (DeviceSuperblock, error) {
	decoder := superblockPayloadDecoder{payload: payload}
	clusterID, err := decoder.readString("cluster ID", MaxSuperblockIdentityBytes)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	deviceUUID, err := decoder.readString("device UUID", MaxSuperblockIdentityBytes)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	ownerGroupID, err := decoder.readString("Owner-group ID", MaxSuperblockIdentityBytes)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	currentOwnerID, err := decoder.readString("current Owner ID", MaxSuperblockIdentityBytes)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	ownerGroupAnchorDeviceUUID, err := decoder.readString(
		"Owner-group anchor device UUID",
		MaxSuperblockIdentityBytes)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	compatibilityID, err := decoder.readString(
		"storage compatibility ID",
		len(cxlcheckpoint.V7StorageCompatibilityID))
	if err != nil {
		return DeviceSuperblock{}, err
	}
	ownerEpoch, err := decoder.readUint64("Owner epoch")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	superblockSequence, err := decoder.readUint64("superblock sequence")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	ownerGroupRole, err := decoder.readByte("Owner-group role")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	ownerGroupRoleReserved, err := decoder.readBytes("Owner-group role reserved bytes", 7)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	if !superblockAllZero(ownerGroupRoleReserved) {
		return DeviceSuperblock{}, superblockCorruptf("Owner-group role reserved bytes must be zero")
	}
	ownerGroupConfigurationSequence, err := decoder.readUint64("Owner-group configuration sequence")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	ownerGroupMembershipSHA256Bytes, err := decoder.readBytes("Owner-group membership SHA-256", sha256.Size)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	var ownerGroupMembershipSHA256 [sha256.Size]byte
	copy(ownerGroupMembershipSHA256[:], ownerGroupMembershipSHA256Bytes)
	geometryValues := make([]uint64, superblockGeometryFieldCount)
	for index := range geometryValues {
		geometryValues[index], err = decoder.readUint64(fmt.Sprintf("geometry field %d", index))
		if err != nil {
			return DeviceSuperblock{}, err
		}
	}
	activeSlot, err := decoder.readByte("active allocator-snapshot slot")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	activeSlotReserved, err := decoder.readBytes("active allocator-snapshot reserved bytes", 7)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	if !superblockAllZero(activeSlotReserved) {
		return DeviceSuperblock{}, superblockCorruptf(
			"active allocator-snapshot reserved bytes must be zero")
	}
	activeSequence, err := decoder.readUint64("active allocator-snapshot sequence")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	activeLength, err := decoder.readUint64("active allocator-snapshot length")
	if err != nil {
		return DeviceSuperblock{}, err
	}
	activeSHA256Bytes, err := decoder.readBytes("active allocator-snapshot SHA-256", sha256.Size)
	if err != nil {
		return DeviceSuperblock{}, err
	}
	if decoder.remaining() != 0 {
		return DeviceSuperblock{}, superblockCorruptf(
			"payload has %d trailing bytes",
			decoder.remaining())
	}
	var activeSHA256 [sha256.Size]byte
	copy(activeSHA256[:], activeSHA256Bytes)
	return DeviceSuperblock{
		ClusterID:                       clusterID,
		DeviceUUID:                      deviceUUID,
		OwnerGroupID:                    ownerGroupID,
		CurrentOwnerID:                  currentOwnerID,
		OwnerGroupAnchorDeviceUUID:      ownerGroupAnchorDeviceUUID,
		StorageCompatibilityID:          compatibilityID,
		OwnerEpoch:                      ownerEpoch,
		SuperblockSequence:              superblockSequence,
		OwnerGroupRole:                  OwnerGroupRole(ownerGroupRole),
		OwnerGroupConfigurationSequence: ownerGroupConfigurationSequence,
		OwnerGroupMembershipSHA256:      ownerGroupMembershipSHA256,
		Geometry: DeviceGeometry{
			DeviceBytes:                 geometryValues[0],
			SuperblockAOffset:           geometryValues[1],
			SuperblockBOffset:           geometryValues[2],
			AllocatorSnapshotAOffset:    geometryValues[3],
			AllocatorSnapshotBOffset:    geometryValues[4],
			AllocatorSnapshotSlotBytes:  geometryValues[5],
			OwnerStateSnapshotAOffset:   geometryValues[6],
			OwnerStateSnapshotBOffset:   geometryValues[7],
			OwnerStateSnapshotSlotBytes: geometryValues[8],
			ControlRegionBytes:          geometryValues[9],
			DescriptorRegionBase:        geometryValues[10],
			DescriptorRegionBytes:       geometryValues[11],
			ContentRegionBase:           geometryValues[12],
			ContentRegionBytes:          geometryValues[13],
			DataPageCount:               geometryValues[14],
		},
		ActiveAllocatorSnapshotSlot:     SuperblockSlot(activeSlot),
		ActiveAllocatorSnapshotSequence: activeSequence,
		ActiveAllocatorSnapshotLength:   activeLength,
		ActiveAllocatorSnapshotSHA256:   activeSHA256,
	}, nil
}

type superblockPayloadDecoder struct {
	payload []byte
	offset  int
}

func (decoder *superblockPayloadDecoder) readString(name string, maximumBytes int) (string, error) {
	length, err := decoder.readUint32(name + " length")
	if err != nil {
		return "", err
	}
	if uint64(length) > uint64(maximumBytes) {
		return "", superblockCorruptf(
			"%s length %d exceeds bound %d",
			name,
			length,
			maximumBytes)
	}
	value, err := decoder.readBytes(name, int(length))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func (decoder *superblockPayloadDecoder) readUint32(name string) (uint32, error) {
	value, err := decoder.readBytes(name, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(value), nil
}

func (decoder *superblockPayloadDecoder) readUint64(name string) (uint64, error) {
	value, err := decoder.readBytes(name, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(value), nil
}

func (decoder *superblockPayloadDecoder) readByte(name string) (byte, error) {
	value, err := decoder.readBytes(name, 1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (decoder *superblockPayloadDecoder) readBytes(name string, length int) ([]byte, error) {
	if length < 0 || length > decoder.remaining() {
		return nil, superblockCorruptf(
			"%s needs %d bytes with %d remaining",
			name,
			length,
			decoder.remaining())
	}
	start := decoder.offset
	decoder.offset += length
	return decoder.payload[start:decoder.offset], nil
}

func (decoder *superblockPayloadDecoder) remaining() int {
	return len(decoder.payload) - decoder.offset
}

func superblockAppendString(destination []byte, value string) []byte {
	destination = superblockAppendUint32(destination, uint32(len(value)))
	return append(destination, value...)
}

func superblockAppendUint32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func superblockAppendUint64(destination []byte, value uint64) []byte {
	var encoded [8]byte
	binary.LittleEndian.PutUint64(encoded[:], value)
	return append(destination, encoded[:]...)
}

func superblockCRC32C(value []byte) uint32 {
	return crc32.Checksum(value, superblockCRC32CTable)
}

func superblockHeaderCRC32C(header []byte) uint32 {
	if len(header) != int(SuperblockEnvelopeHeaderBytes) {
		return 0
	}
	checksum := crc32.Update(0, superblockCRC32CTable, header[:superblockHeaderCRCOffset])
	checksum = crc32.Update(checksum, superblockCRC32CTable, superblockZeroCRCField[:])
	return crc32.Update(checksum, superblockCRC32CTable, header[superblockHeaderCRCOffset+4:])
}

func superblockAllZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}

func superblockWrongFormatf(format string, arguments ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrWrongSuperblockFormat, fmt.Sprintf(format, arguments...))
}

type superblockCandidate struct {
	slot       SuperblockSlot
	wire       []byte
	superblock DeviceSuperblock
	err        error
	blank      bool
}

func superblockCandidateFailure(candidate superblockCandidate) string {
	if candidate.blank {
		return "is blank"
	}
	return fmt.Sprintf("is invalid (%v)", candidate.err)
}
