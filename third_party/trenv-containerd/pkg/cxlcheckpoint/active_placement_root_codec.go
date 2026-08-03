package cxlcheckpoint

import (
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	activeContentPlacementRootHeaderSize       uint32 = 64
	activeContentPlacementRootDomainFieldBytes        = 24
	activeContentPlacementRootFieldHeaderBytes        = 8
	activeContentPlacementRootFieldCount       uint32 = 16
	activeContentPlacementRootMaxWireFields    uint32 = 64

	maxActiveContentPlacementRootPayloadBytes = MaxActiveContentPlacementRootBytes - ActiveContentPlacementRootEnvelopeHeaderBytes
)

const (
	activeContentPlacementRootFieldState uint16 = iota + 1
	activeContentPlacementRootFieldRootID
	activeContentPlacementRootFieldRootVersion
	activeContentPlacementRootFieldCheckpointID
	activeContentPlacementRootFieldPublicationLength
	activeContentPlacementRootFieldPublicationSHA256
	activeContentPlacementRootFieldVirtualPageMapID
	activeContentPlacementRootFieldVirtualPageMapVersion
	activeContentPlacementRootFieldVirtualPageMapLength
	activeContentPlacementRootFieldVirtualPageMapSHA256
	activeContentPlacementRootFieldActiveMappingSlot
	activeContentPlacementRootFieldContentPlacementMapID
	activeContentPlacementRootFieldContentPlacementMapVersion
	activeContentPlacementRootFieldContentPlacementMapLength
	activeContentPlacementRootFieldContentPlacementMapSHA256
	activeContentPlacementRootFieldDeviceTableSHA256
)

type activeContentPlacementRootWireType uint8

const (
	activeContentPlacementRootWireU8 activeContentPlacementRootWireType = iota + 1
	activeContentPlacementRootWireU64
	activeContentPlacementRootWireText
	activeContentPlacementRootWireSHA256
)

const activeContentPlacementRootFieldMandatory uint8 = 1

var (
	// These are compile-time wire-layout checks. A changed magic, oversized
	// domain, or changed exported header size must fail the build rather than
	// silently truncate the V7 identity.
	_ [activeContentPlacementRootHeaderSize]byte = [ActiveContentPlacementRootEnvelopeHeaderBytes]byte{}
	_ [8]byte                                    = [len(ActiveContentPlacementRootMagicString)]byte{}
	_ [activeContentPlacementRootDomainFieldBytes - len(ActiveContentPlacementRootDomain)]byte

	activeContentPlacementRootMagic = activeContentPlacementRootFixedMagic(
		ActiveContentPlacementRootMagicString)
	activeContentPlacementRootDomain = activeContentPlacementRootFixedDomain(
		ActiveContentPlacementRootDomain)
)

// CanonicalActiveContentPlacementRootBytes validates root and returns one
// deterministic, domain-separated V7 envelope no larger than 4 KiB.
func CanonicalActiveContentPlacementRootBytes(
	root ActiveContentPlacementRoot,
) ([]byte, error) {
	if err := root.Validate(); err != nil {
		return nil, err
	}
	payload, err := marshalActiveContentPlacementRootPayload(root)
	if err != nil {
		return nil, err
	}
	return marshalActiveContentPlacementRootEnvelope(payload)
}

// CanonicalActiveContentPlacementRootSize returns the complete canonical
// envelope size, including the fixed 64-byte V7 root header.
func CanonicalActiveContentPlacementRootSize(
	root ActiveContentPlacementRoot,
) (uint64, error) {
	encoded, err := CanonicalActiveContentPlacementRootBytes(root)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

// DecodeActiveContentPlacementRoot accepts exactly one complete V7 root,
// checks structural integrity and mandatory fields, and applies Validate.
func DecodeActiveContentPlacementRoot(data []byte) (ActiveContentPlacementRoot, error) {
	payload, err := parseActiveContentPlacementRootEnvelope(data)
	if err != nil {
		return ActiveContentPlacementRoot{}, err
	}
	root, err := unmarshalActiveContentPlacementRootPayload(payload)
	if err != nil {
		return ActiveContentPlacementRoot{}, err
	}
	if err := root.Validate(); err != nil {
		return ActiveContentPlacementRoot{}, err
	}
	return root, nil
}

func marshalActiveContentPlacementRootPayload(
	root ActiveContentPlacementRoot,
) ([]byte, error) {
	payload := make([]byte, 4, 512)
	binary.LittleEndian.PutUint32(payload, activeContentPlacementRootFieldCount)

	var number [8]byte
	var err error
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldState,
		activeContentPlacementRootWireU8,
		[]byte{byte(root.State)},
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldRootID,
		activeContentPlacementRootWireText,
		[]byte(root.RootID),
	)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(number[:], root.RootVersion)
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldRootVersion,
		activeContentPlacementRootWireU64,
		number[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldCheckpointID,
		activeContentPlacementRootWireText,
		[]byte(root.CheckpointID),
	)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(number[:], root.ImmutablePublicationLength)
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldPublicationLength,
		activeContentPlacementRootWireU64,
		number[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldPublicationSHA256,
		activeContentPlacementRootWireSHA256,
		root.ImmutablePublicationSHA256[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldVirtualPageMapID,
		activeContentPlacementRootWireText,
		[]byte(root.VirtualPageMapID),
	)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(number[:], root.VirtualPageMapVersion)
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldVirtualPageMapVersion,
		activeContentPlacementRootWireU64,
		number[:],
	)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(number[:], root.VirtualPageMapLength)
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldVirtualPageMapLength,
		activeContentPlacementRootWireU64,
		number[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldVirtualPageMapSHA256,
		activeContentPlacementRootWireSHA256,
		root.VirtualPageMapSHA256[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldActiveMappingSlot,
		activeContentPlacementRootWireU8,
		[]byte{byte(root.ActiveMappingSlot)},
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldContentPlacementMapID,
		activeContentPlacementRootWireText,
		[]byte(root.ContentPlacementMapID),
	)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(number[:], root.ContentPlacementMapVersion)
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldContentPlacementMapVersion,
		activeContentPlacementRootWireU64,
		number[:],
	)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint64(number[:], root.ContentPlacementMapLength)
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldContentPlacementMapLength,
		activeContentPlacementRootWireU64,
		number[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldContentPlacementMapSHA256,
		activeContentPlacementRootWireSHA256,
		root.ContentPlacementMapSHA256[:],
	)
	if err != nil {
		return nil, err
	}
	payload, err = appendActiveContentPlacementRootField(
		payload,
		activeContentPlacementRootFieldDeviceTableSHA256,
		activeContentPlacementRootWireSHA256,
		root.PlacementDeviceTableSHA256[:],
	)
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func appendActiveContentPlacementRootField(
	payload []byte,
	tag uint16,
	wireType activeContentPlacementRootWireType,
	value []byte,
) ([]byte, error) {
	total := uint64(len(payload)) + activeContentPlacementRootFieldHeaderBytes + uint64(len(value))
	if total > maxActiveContentPlacementRootPayloadBytes {
		return nil, activeContentPlacementRootInvalidf(
			"active root payload would be %d bytes, limit is %d",
			total, maxActiveContentPlacementRootPayloadBytes)
	}
	var header [activeContentPlacementRootFieldHeaderBytes]byte
	binary.LittleEndian.PutUint16(header[0:2], tag)
	header[2] = byte(wireType)
	header[3] = activeContentPlacementRootFieldMandatory
	binary.LittleEndian.PutUint32(header[4:8], uint32(len(value)))
	payload = append(payload, header[:]...)
	payload = append(payload, value...)
	return payload, nil
}

func marshalActiveContentPlacementRootEnvelope(payload []byte) ([]byte, error) {
	if uint64(len(payload)) > maxActiveContentPlacementRootPayloadBytes {
		return nil, activeContentPlacementRootInvalidf(
			"active root payload is %d bytes, limit is %d",
			len(payload), maxActiveContentPlacementRootPayloadBytes)
	}
	total := ActiveContentPlacementRootEnvelopeHeaderBytes + uint64(len(payload))
	if total > MaxActiveContentPlacementRootBytes {
		return nil, activeContentPlacementRootInvalidf(
			"active root envelope is %d bytes, limit is %d",
			total, MaxActiveContentPlacementRootBytes)
	}
	out := make([]byte, int(total))
	copy(out[0:8], activeContentPlacementRootMagic[:])
	binary.LittleEndian.PutUint32(out[8:12], ActiveContentPlacementRootVersion)
	binary.LittleEndian.PutUint32(out[12:16], activeContentPlacementRootHeaderSize)
	copy(out[16:40], activeContentPlacementRootDomain[:])
	binary.LittleEndian.PutUint64(out[40:48], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[48:52], checksumCRC32C(payload))
	// 52:56 is the mandatory feature mask. Zero is the only V7 value.
	// 56:60 is header integrity. 60:64 is reserved and remains zero.
	copy(out[activeContentPlacementRootHeaderSize:], payload)
	binary.LittleEndian.PutUint32(
		out[56:60],
		activeContentPlacementRootHeaderCRC(out[:activeContentPlacementRootHeaderSize]),
	)
	return out, nil
}

func parseActiveContentPlacementRootEnvelope(data []byte) ([]byte, error) {
	if len(data) < int(activeContentPlacementRootHeaderSize) {
		return nil, fmt.Errorf(
			"active root envelope is truncated: %w",
			ErrCorruptActiveContentPlacementRoot)
	}
	var magic [8]byte
	copy(magic[:], data[0:8])
	if magic != activeContentPlacementRootMagic {
		return nil, fmt.Errorf(
			"active root magic %q is not %q: %w",
			magic,
			activeContentPlacementRootMagic,
			ErrWrongActiveContentPlacementRootFormat)
	}
	if version := binary.LittleEndian.Uint32(data[8:12]); version != ActiveContentPlacementRootVersion {
		return nil, fmt.Errorf(
			"active root version %d is not %d: %w",
			version,
			ActiveContentPlacementRootVersion,
			ErrWrongActiveContentPlacementRootFormat)
	}
	if size := binary.LittleEndian.Uint32(data[12:16]); size != activeContentPlacementRootHeaderSize {
		return nil, fmt.Errorf(
			"active root header size %d is not %d: %w",
			size,
			activeContentPlacementRootHeaderSize,
			ErrWrongActiveContentPlacementRootFormat)
	}
	var domain [activeContentPlacementRootDomainFieldBytes]byte
	copy(domain[:], data[16:40])
	if domain != activeContentPlacementRootDomain {
		return nil, fmt.Errorf(
			"active root domain does not match %q: %w",
			ActiveContentPlacementRootDomain,
			ErrWrongActiveContentPlacementRootFormat)
	}
	if flags := binary.LittleEndian.Uint32(data[52:56]); flags != 0 {
		return nil, fmt.Errorf(
			"active root has unknown mandatory flags %#x: %w",
			flags,
			ErrWrongActiveContentPlacementRootFormat)
	}
	if !activeContentPlacementRootAllZero(data[60:activeContentPlacementRootHeaderSize]) {
		return nil, fmt.Errorf(
			"active root reserved header bytes are non-zero: %w",
			ErrWrongActiveContentPlacementRootFormat)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[56:60])
	if got := activeContentPlacementRootHeaderCRC(
		data[:activeContentPlacementRootHeaderSize]); got != wantHeaderCRC {
		return nil, fmt.Errorf(
			"active root header checksum %#x does not match %#x: %w",
			got,
			wantHeaderCRC,
			ErrCorruptActiveContentPlacementRoot)
	}
	payloadLength := binary.LittleEndian.Uint64(data[40:48])
	if payloadLength > maxActiveContentPlacementRootPayloadBytes {
		return nil, fmt.Errorf(
			"active root payload length %d exceeds %d: %w",
			payloadLength,
			maxActiveContentPlacementRootPayloadBytes,
			ErrCorruptActiveContentPlacementRoot)
	}
	total := ActiveContentPlacementRootEnvelopeHeaderBytes + payloadLength
	if total != uint64(len(data)) {
		return nil, fmt.Errorf(
			"active root envelope is %d bytes, header declares %d: %w",
			len(data),
			total,
			ErrCorruptActiveContentPlacementRoot)
	}
	payload := data[activeContentPlacementRootHeaderSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[48:52])
	if got := checksumCRC32C(payload); got != wantPayloadCRC {
		return nil, fmt.Errorf(
			"active root payload checksum %#x does not match %#x: %w",
			got,
			wantPayloadCRC,
			ErrCorruptActiveContentPlacementRoot)
	}
	return append([]byte(nil), payload...), nil
}

func unmarshalActiveContentPlacementRootPayload(
	payload []byte,
) (ActiveContentPlacementRoot, error) {
	if len(payload) < 4 {
		return ActiveContentPlacementRoot{}, fmt.Errorf(
			"active root payload has no field count: %w",
			ErrCorruptActiveContentPlacementRoot)
	}
	fieldCount := binary.LittleEndian.Uint32(payload[0:4])
	if fieldCount == 0 || fieldCount > activeContentPlacementRootMaxWireFields {
		return ActiveContentPlacementRoot{}, fmt.Errorf(
			"active root field count %d is outside 1..%d: %w",
			fieldCount,
			activeContentPlacementRootMaxWireFields,
			ErrCorruptActiveContentPlacementRoot)
	}
	if uint64(fieldCount) >
		uint64(len(payload)-4)/activeContentPlacementRootFieldHeaderBytes {
		return ActiveContentPlacementRoot{}, fmt.Errorf(
			"active root field count %d cannot fit in payload: %w",
			fieldCount,
			ErrCorruptActiveContentPlacementRoot)
	}

	root := ActiveContentPlacementRoot{}
	seen := [activeContentPlacementRootFieldCount + 1]bool{}
	offset := 4
	previousTag := uint16(0)
	for fieldIndex := uint32(0); fieldIndex < fieldCount; fieldIndex++ {
		if len(payload)-offset < activeContentPlacementRootFieldHeaderBytes {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root field %d header is truncated: %w",
				fieldIndex,
				ErrCorruptActiveContentPlacementRoot)
		}
		header := payload[offset : offset+activeContentPlacementRootFieldHeaderBytes]
		offset += activeContentPlacementRootFieldHeaderBytes
		tag := binary.LittleEndian.Uint16(header[0:2])
		wireType := activeContentPlacementRootWireType(header[2])
		flags := header[3]
		length := binary.LittleEndian.Uint32(header[4:8])

		if flags != activeContentPlacementRootFieldMandatory {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root field %d tag %d has unsupported mandatory flags %#x: %w",
				fieldIndex,
				tag,
				flags,
				ErrWrongActiveContentPlacementRootFormat)
		}
		if tag == 0 || tag > activeContentPlacementRootFieldDeviceTableSHA256 {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root has unknown mandatory field tag %d: %w",
				tag,
				ErrWrongActiveContentPlacementRootFormat)
		}
		if seen[tag] {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root duplicates mandatory field tag %d: %w",
				tag,
				ErrCorruptActiveContentPlacementRoot)
		}
		if tag <= previousTag {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root field tag %d is not in canonical order after %d: %w",
				tag,
				previousTag,
				ErrCorruptActiveContentPlacementRoot)
		}
		expectedWire, fixedLength := activeContentPlacementRootExpectedWire(tag)
		if wireType != expectedWire {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root field tag %d wire type %d is not %d: %w",
				tag,
				wireType,
				expectedWire,
				ErrWrongActiveContentPlacementRootFormat)
		}
		if fixedLength != 0 && length != fixedLength {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root field tag %d length %d is not %d: %w",
				tag,
				length,
				fixedLength,
				ErrCorruptActiveContentPlacementRoot)
		}
		if wireType == activeContentPlacementRootWireText &&
			length > MaxActiveContentPlacementRootIdentityBytes {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root text field tag %d length %d exceeds %d: %w",
				tag,
				length,
				MaxActiveContentPlacementRootIdentityBytes,
				ErrCorruptActiveContentPlacementRoot)
		}
		if uint64(length) > uint64(len(payload)-offset) {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root field tag %d needs %d bytes, %d remain: %w",
				tag,
				length,
				len(payload)-offset,
				ErrCorruptActiveContentPlacementRoot)
		}
		value := payload[offset : offset+int(length)]
		offset += int(length)
		if wireType == activeContentPlacementRootWireText && !utf8.Valid(value) {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root text field tag %d is not valid UTF-8: %w",
				tag,
				ErrCorruptActiveContentPlacementRoot)
		}
		if err := assignActiveContentPlacementRootField(&root, tag, value); err != nil {
			return ActiveContentPlacementRoot{}, err
		}
		seen[tag] = true
		previousTag = tag
	}
	if offset != len(payload) {
		return ActiveContentPlacementRoot{}, fmt.Errorf(
			"active root payload has %d trailing bytes: %w",
			len(payload)-offset,
			ErrCorruptActiveContentPlacementRoot)
	}
	for tag := uint16(1); tag <= activeContentPlacementRootFieldDeviceTableSHA256; tag++ {
		if !seen[tag] {
			return ActiveContentPlacementRoot{}, fmt.Errorf(
				"active root is missing mandatory field tag %d: %w",
				tag,
				ErrCorruptActiveContentPlacementRoot)
		}
	}
	return root, nil
}

func activeContentPlacementRootExpectedWire(
	tag uint16,
) (activeContentPlacementRootWireType, uint32) {
	switch tag {
	case activeContentPlacementRootFieldState,
		activeContentPlacementRootFieldActiveMappingSlot:
		return activeContentPlacementRootWireU8, 1
	case activeContentPlacementRootFieldRootVersion,
		activeContentPlacementRootFieldPublicationLength,
		activeContentPlacementRootFieldVirtualPageMapVersion,
		activeContentPlacementRootFieldVirtualPageMapLength,
		activeContentPlacementRootFieldContentPlacementMapVersion,
		activeContentPlacementRootFieldContentPlacementMapLength:
		return activeContentPlacementRootWireU64, 8
	case activeContentPlacementRootFieldRootID,
		activeContentPlacementRootFieldCheckpointID,
		activeContentPlacementRootFieldVirtualPageMapID,
		activeContentPlacementRootFieldContentPlacementMapID:
		return activeContentPlacementRootWireText, 0
	case activeContentPlacementRootFieldPublicationSHA256,
		activeContentPlacementRootFieldVirtualPageMapSHA256,
		activeContentPlacementRootFieldContentPlacementMapSHA256,
		activeContentPlacementRootFieldDeviceTableSHA256:
		return activeContentPlacementRootWireSHA256, 32
	default:
		return 0, 0
	}
}

func assignActiveContentPlacementRootField(
	root *ActiveContentPlacementRoot,
	tag uint16,
	value []byte,
) error {
	switch tag {
	case activeContentPlacementRootFieldState:
		root.State = ActiveContentPlacementRootState(value[0])
	case activeContentPlacementRootFieldRootID:
		root.RootID = string(value)
	case activeContentPlacementRootFieldRootVersion:
		root.RootVersion = binary.LittleEndian.Uint64(value)
	case activeContentPlacementRootFieldCheckpointID:
		root.CheckpointID = string(value)
	case activeContentPlacementRootFieldPublicationLength:
		root.ImmutablePublicationLength = binary.LittleEndian.Uint64(value)
	case activeContentPlacementRootFieldPublicationSHA256:
		copy(root.ImmutablePublicationSHA256[:], value)
	case activeContentPlacementRootFieldVirtualPageMapID:
		root.VirtualPageMapID = string(value)
	case activeContentPlacementRootFieldVirtualPageMapVersion:
		root.VirtualPageMapVersion = binary.LittleEndian.Uint64(value)
	case activeContentPlacementRootFieldVirtualPageMapLength:
		root.VirtualPageMapLength = binary.LittleEndian.Uint64(value)
	case activeContentPlacementRootFieldVirtualPageMapSHA256:
		copy(root.VirtualPageMapSHA256[:], value)
	case activeContentPlacementRootFieldActiveMappingSlot:
		root.ActiveMappingSlot = MappingSlotName(value[0])
	case activeContentPlacementRootFieldContentPlacementMapID:
		root.ContentPlacementMapID = string(value)
	case activeContentPlacementRootFieldContentPlacementMapVersion:
		root.ContentPlacementMapVersion = binary.LittleEndian.Uint64(value)
	case activeContentPlacementRootFieldContentPlacementMapLength:
		root.ContentPlacementMapLength = binary.LittleEndian.Uint64(value)
	case activeContentPlacementRootFieldContentPlacementMapSHA256:
		copy(root.ContentPlacementMapSHA256[:], value)
	case activeContentPlacementRootFieldDeviceTableSHA256:
		copy(root.PlacementDeviceTableSHA256[:], value)
	default:
		return fmt.Errorf(
			"active root has unknown mandatory field tag %d: %w",
			tag,
			ErrWrongActiveContentPlacementRootFormat)
	}
	return nil
}

func activeContentPlacementRootHeaderCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= int(activeContentPlacementRootHeaderSize) {
		for index := 56; index < 60; index++ {
			copyForCRC[index] = 0
		}
	}
	return checksumCRC32C(copyForCRC)
}

func activeContentPlacementRootFixedMagic(value string) [8]byte {
	var result [8]byte
	copy(result[:], []byte(value))
	return result
}

func activeContentPlacementRootFixedDomain(
	value string,
) [activeContentPlacementRootDomainFieldBytes]byte {
	var result [activeContentPlacementRootDomainFieldBytes]byte
	copy(result[:], []byte(value))
	return result
}

func activeContentPlacementRootAllZero(value []byte) bool {
	for _, current := range value {
		if current != 0 {
			return false
		}
	}
	return true
}
