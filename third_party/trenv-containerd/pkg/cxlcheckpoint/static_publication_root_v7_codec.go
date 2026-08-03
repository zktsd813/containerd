package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	staticPublicationRootV7HeaderSize       uint32 = 64
	staticPublicationRootV7DomainFieldBytes        = 24
	maxStaticPublicationRootV7PayloadBytes         = MaxStaticPublicationRootV7Bytes -
		StaticPublicationRootV7EnvelopeHeaderBytes
)

var (
	_ [staticPublicationRootV7HeaderSize]byte = [StaticPublicationRootV7EnvelopeHeaderBytes]byte{}
	_ [8]byte                                 = [len(StaticPublicationRootV7MagicString)]byte{}
	_ [staticPublicationRootV7DomainFieldBytes - len(StaticPublicationRootV7Domain)]byte

	staticPublicationRootV7Magic  = staticPublicationRootV7FixedMagic(StaticPublicationRootV7MagicString)
	staticPublicationRootV7Domain = staticPublicationRootV7FixedDomain(StaticPublicationRootV7Domain)
)

// CanonicalStaticPublicationRootV7Bytes validates and deterministically
// encodes one complete immutable TRPSR007 bootstrap root.
func CanonicalStaticPublicationRootV7Bytes(
	root StaticPublicationRootV7,
) ([]byte, error) {
	if err := root.Validate(); err != nil {
		return nil, err
	}
	return canonicalStaticPublicationRootV7BytesValidated(root)
}

func canonicalStaticPublicationRootV7BytesValidated(
	root StaticPublicationRootV7,
) ([]byte, error) {
	payload, err := marshalStaticPublicationRootV7Payload(root)
	if err != nil {
		return nil, err
	}
	return marshalStaticPublicationRootV7Envelope(payload)
}

// CanonicalStaticPublicationRootV7Size includes the fixed 64-byte integrity
// header and the complete canonical payload.
func CanonicalStaticPublicationRootV7Size(root StaticPublicationRootV7) (uint64, error) {
	encoded, err := CanonicalStaticPublicationRootV7Bytes(root)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

// DecodeStaticPublicationRootV7 accepts exactly one complete canonical
// TRPSR007 envelope. All text and collection bounds are checked before any
// value-dependent allocation.
func DecodeStaticPublicationRootV7(data []byte) (StaticPublicationRootV7, error) {
	payload, err := parseStaticPublicationRootV7Envelope(data)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	root, err := unmarshalStaticPublicationRootV7Payload(payload)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	if err := root.Validate(); err != nil {
		return StaticPublicationRootV7{}, err
	}
	canonical, err := canonicalStaticPublicationRootV7BytesValidated(root)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	if !bytes.Equal(canonical, data) {
		return StaticPublicationRootV7{}, fmt.Errorf(
			"static publication root is not canonically encoded: %w",
			ErrCorruptStaticPublicationRootV7)
	}
	return root, nil
}

func marshalStaticPublicationRootV7Payload(root StaticPublicationRootV7) ([]byte, error) {
	encoder := newStaticPublicationRootV7Encoder()
	encoder.u8(uint8(root.State))
	encoder.text(root.CheckpointID)
	encoder.text(root.StorageCompatibilityID)
	encoder.u64(root.PublicationObjectID)
	encoder.text(root.OwnerID)
	encoder.u64(root.OwnerEpoch)
	encoder.u64(root.AllocationRecordID)
	encoder.u64(root.PublicationLength)
	encoder.fixed(root.PublicationSHA256[:])
	encoder.count(len(root.Devices))
	for _, device := range root.Devices {
		encoder.text(device.DeviceUUID)
		encoder.u64(device.DataPageCount)
	}
	encoder.count(len(root.Runs))
	for _, run := range root.Runs {
		encoder.u64(run.ObjectPageStart)
		encoder.u32(run.DeviceIndex)
		encoder.u64(run.DataPageIndex)
		encoder.u64(run.PageCount)
	}
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalStaticPublicationRootV7Payload(
	payload []byte,
) (StaticPublicationRootV7, error) {
	decoder := newStaticPublicationRootV7Decoder(payload)
	root := StaticPublicationRootV7{}
	state, err := decoder.u8()
	if err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError("state", err)
	}
	root.State = StaticPublicationRootV7State(state)
	if root.CheckpointID, err = decoder.text(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"checkpoint ID", err)
	}
	if root.StorageCompatibilityID, err = decoder.text(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"storage compatibility ID", err)
	}
	if root.PublicationObjectID, err = decoder.u64(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"publication object ID", err)
	}
	if root.OwnerID, err = decoder.text(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError("Owner ID", err)
	}
	if root.OwnerEpoch, err = decoder.u64(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"Owner epoch", err)
	}
	if root.AllocationRecordID, err = decoder.u64(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"allocation record ID", err)
	}
	if root.PublicationLength, err = decoder.u64(); err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"publication length", err)
	}
	digest, err := decoder.fixed(sha256.Size)
	if err != nil {
		return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
			"publication SHA-256", err)
	}
	copy(root.PublicationSHA256[:], digest)

	deviceCount, err := decoder.count(
		"devices", 4+8, MaxStaticPublicationRootV7Devices)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	root.Devices = make([]StaticPublicationRootV7Device, deviceCount)
	for index := range root.Devices {
		if root.Devices[index].DeviceUUID, err = decoder.text(); err != nil {
			return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
				"device UUID", err)
		}
		if root.Devices[index].DataPageCount, err = decoder.u64(); err != nil {
			return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
				"device data page count", err)
		}
	}

	runCount, err := decoder.count("runs", 8+4+8+8, MaxStaticPublicationRootV7Runs)
	if err != nil {
		return StaticPublicationRootV7{}, err
	}
	root.Runs = make([]StaticPublicationRootV7Run, runCount)
	for index := range root.Runs {
		if root.Runs[index].ObjectPageStart, err = decoder.u64(); err != nil {
			return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
				"run object page start", err)
		}
		if root.Runs[index].DeviceIndex, err = decoder.u32(); err != nil {
			return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
				"run device index", err)
		}
		if root.Runs[index].DataPageIndex, err = decoder.u64(); err != nil {
			return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
				"run data page index", err)
		}
		if root.Runs[index].PageCount, err = decoder.u64(); err != nil {
			return StaticPublicationRootV7{}, staticPublicationRootV7DecodeError(
				"run page count", err)
		}
	}
	if err := decoder.done(); err != nil {
		return StaticPublicationRootV7{}, err
	}
	return root, nil
}

func marshalStaticPublicationRootV7Envelope(payload []byte) ([]byte, error) {
	if uint64(len(payload)) > maxStaticPublicationRootV7PayloadBytes {
		return nil, staticPublicationRootV7Invalidf(
			"static publication root payload is %d bytes, limit is %d",
			len(payload), maxStaticPublicationRootV7PayloadBytes)
	}
	total := StaticPublicationRootV7EnvelopeHeaderBytes + uint64(len(payload))
	out := make([]byte, int(total))
	copy(out[0:8], staticPublicationRootV7Magic[:])
	binary.LittleEndian.PutUint32(out[8:12], StaticPublicationRootV7Version)
	binary.LittleEndian.PutUint32(out[12:16], staticPublicationRootV7HeaderSize)
	copy(out[16:40], staticPublicationRootV7Domain[:])
	binary.LittleEndian.PutUint64(out[40:48], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[48:52], checksumCRC32C(payload))
	// 52:56 mandatory flags and 60:64 reserved are zero in V7.
	copy(out[staticPublicationRootV7HeaderSize:], payload)
	binary.LittleEndian.PutUint32(
		out[56:60], staticPublicationRootV7HeaderCRC(out[:staticPublicationRootV7HeaderSize]))
	return out, nil
}

func parseStaticPublicationRootV7Envelope(data []byte) ([]byte, error) {
	if len(data) < int(staticPublicationRootV7HeaderSize) {
		return nil, fmt.Errorf(
			"static publication root envelope is truncated: %w",
			ErrCorruptStaticPublicationRootV7)
	}
	if uint64(len(data)) > MaxStaticPublicationRootV7Bytes {
		return nil, fmt.Errorf(
			"static publication root envelope is %d bytes, limit is %d: %w",
			len(data), MaxStaticPublicationRootV7Bytes, ErrCorruptStaticPublicationRootV7)
	}
	var magic [8]byte
	copy(magic[:], data[0:8])
	if magic != staticPublicationRootV7Magic {
		return nil, fmt.Errorf(
			"static publication root magic %q is not %q: %w",
			magic, staticPublicationRootV7Magic, ErrWrongStaticPublicationRootV7Format)
	}
	if version := binary.LittleEndian.Uint32(data[8:12]); version != StaticPublicationRootV7Version {
		return nil, fmt.Errorf(
			"static publication root version %d is not %d: %w",
			version, StaticPublicationRootV7Version, ErrWrongStaticPublicationRootV7Format)
	}
	if size := binary.LittleEndian.Uint32(data[12:16]); size != staticPublicationRootV7HeaderSize {
		return nil, fmt.Errorf(
			"static publication root header size %d is not %d: %w",
			size, staticPublicationRootV7HeaderSize, ErrWrongStaticPublicationRootV7Format)
	}
	var domain [staticPublicationRootV7DomainFieldBytes]byte
	copy(domain[:], data[16:40])
	if domain != staticPublicationRootV7Domain {
		return nil, fmt.Errorf(
			"static publication root domain does not match %q: %w",
			StaticPublicationRootV7Domain, ErrWrongStaticPublicationRootV7Format)
	}
	if flags := binary.LittleEndian.Uint32(data[52:56]); flags != 0 {
		return nil, fmt.Errorf(
			"static publication root has unknown mandatory flags %#x: %w",
			flags, ErrWrongStaticPublicationRootV7Format)
	}
	if !staticPublicationRootV7AllZero(data[60:staticPublicationRootV7HeaderSize]) {
		return nil, fmt.Errorf(
			"static publication root reserved header bytes are non-zero: %w",
			ErrWrongStaticPublicationRootV7Format)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[56:60])
	if got := staticPublicationRootV7HeaderCRC(data[:staticPublicationRootV7HeaderSize]); got != wantHeaderCRC {
		return nil, fmt.Errorf(
			"static publication root header checksum %#x does not match %#x: %w",
			got, wantHeaderCRC, ErrCorruptStaticPublicationRootV7)
	}
	payloadLength := binary.LittleEndian.Uint64(data[40:48])
	if payloadLength > maxStaticPublicationRootV7PayloadBytes {
		return nil, fmt.Errorf(
			"static publication root payload length %d exceeds %d: %w",
			payloadLength, maxStaticPublicationRootV7PayloadBytes,
			ErrCorruptStaticPublicationRootV7)
	}
	total := StaticPublicationRootV7EnvelopeHeaderBytes + payloadLength
	if total != uint64(len(data)) {
		return nil, fmt.Errorf(
			"static publication root envelope is %d bytes, header declares %d: %w",
			len(data), total, ErrCorruptStaticPublicationRootV7)
	}
	payload := data[staticPublicationRootV7HeaderSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[48:52])
	if got := checksumCRC32C(payload); got != wantPayloadCRC {
		return nil, fmt.Errorf(
			"static publication root payload checksum %#x does not match %#x: %w",
			got, wantPayloadCRC, ErrCorruptStaticPublicationRootV7)
	}
	return append([]byte(nil), payload...), nil
}

func staticPublicationRootV7HeaderCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= int(staticPublicationRootV7HeaderSize) {
		for index := 56; index < 60; index++ {
			copyForCRC[index] = 0
		}
	}
	return checksumCRC32C(copyForCRC)
}

func staticPublicationRootV7FixedMagic(value string) [8]byte {
	var result [8]byte
	copy(result[:], value)
	return result
}

func staticPublicationRootV7FixedDomain(
	value string,
) [staticPublicationRootV7DomainFieldBytes]byte {
	var result [staticPublicationRootV7DomainFieldBytes]byte
	copy(result[:], value)
	return result
}

func staticPublicationRootV7AllZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

type staticPublicationRootV7Encoder struct {
	buffer bytes.Buffer
	err    error
}

func newStaticPublicationRootV7Encoder() *staticPublicationRootV7Encoder {
	return &staticPublicationRootV7Encoder{}
}

func (encoder *staticPublicationRootV7Encoder) bytes() []byte {
	return append([]byte(nil), encoder.buffer.Bytes()...)
}

func (encoder *staticPublicationRootV7Encoder) fixed(value []byte) {
	if encoder.err != nil {
		return
	}
	if uint64(len(value)) >
		maxStaticPublicationRootV7PayloadBytes-uint64(encoder.buffer.Len()) {
		encoder.err = staticPublicationRootV7Invalidf(
			"static publication root payload exceeds %d bytes",
			maxStaticPublicationRootV7PayloadBytes)
		return
	}
	_, encoder.err = encoder.buffer.Write(value)
}

func (encoder *staticPublicationRootV7Encoder) u8(value uint8) {
	encoder.fixed([]byte{value})
}

func (encoder *staticPublicationRootV7Encoder) u32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	encoder.fixed(data[:])
}

func (encoder *staticPublicationRootV7Encoder) u64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	encoder.fixed(data[:])
}

func (encoder *staticPublicationRootV7Encoder) count(value int) {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		encoder.err = staticPublicationRootV7Invalidf(
			"collection count %d cannot be encoded", value)
		return
	}
	encoder.u32(uint32(value))
}

func (encoder *staticPublicationRootV7Encoder) text(value string) {
	if !utf8.ValidString(value) || uint64(len(value)) > uint64(^uint32(0)) {
		encoder.err = staticPublicationRootV7Invalidf("text cannot be encoded")
		return
	}
	encoder.u32(uint32(len(value)))
	encoder.fixed([]byte(value))
}

type staticPublicationRootV7Decoder struct {
	payload []byte
	offset  int
}

func newStaticPublicationRootV7Decoder(payload []byte) *staticPublicationRootV7Decoder {
	return &staticPublicationRootV7Decoder{payload: payload}
}

func (decoder *staticPublicationRootV7Decoder) fixed(size int) ([]byte, error) {
	if size < 0 || decoder.offset > len(decoder.payload) ||
		size > len(decoder.payload)-decoder.offset {
		return nil, fmt.Errorf(
			"static publication root payload is truncated: %w",
			ErrCorruptStaticPublicationRootV7)
	}
	value := decoder.payload[decoder.offset : decoder.offset+size]
	decoder.offset += size
	return value, nil
}

func (decoder *staticPublicationRootV7Decoder) u8() (uint8, error) {
	data, err := decoder.fixed(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func (decoder *staticPublicationRootV7Decoder) u32() (uint32, error) {
	data, err := decoder.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (decoder *staticPublicationRootV7Decoder) u64() (uint64, error) {
	data, err := decoder.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (decoder *staticPublicationRootV7Decoder) count(
	name string,
	minimumBytes int,
	maximum int,
) (int, error) {
	value, err := decoder.u32()
	if err != nil {
		return 0, staticPublicationRootV7DecodeError(name+" count", err)
	}
	if uint64(value) > uint64(maximum) {
		return 0, fmt.Errorf(
			"%s count %d exceeds %d before allocation: %w",
			name, value, maximum, ErrCorruptStaticPublicationRootV7)
	}
	remaining := len(decoder.payload) - decoder.offset
	if minimumBytes < 1 || uint64(value) > uint64(remaining/minimumBytes) {
		return 0, fmt.Errorf(
			"%s count %d cannot fit remaining payload before allocation: %w",
			name, value, ErrCorruptStaticPublicationRootV7)
	}
	return int(value), nil
}

func (decoder *staticPublicationRootV7Decoder) text() (string, error) {
	length, err := decoder.u32()
	if err != nil {
		return "", err
	}
	if uint64(length) > MaxStaticPublicationRootV7IdentityBytes {
		return "", fmt.Errorf(
			"text length %d exceeds identity limit %d before allocation: %w",
			length, MaxStaticPublicationRootV7IdentityBytes,
			ErrCorruptStaticPublicationRootV7)
	}
	if uint64(length) > uint64(len(decoder.payload)-decoder.offset) {
		return "", fmt.Errorf(
			"text length exceeds remaining payload before allocation: %w",
			ErrCorruptStaticPublicationRootV7)
	}
	data, err := decoder.fixed(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf(
			"text is not valid UTF-8: %w", ErrCorruptStaticPublicationRootV7)
	}
	return string(data), nil
}

func (decoder *staticPublicationRootV7Decoder) done() error {
	if decoder.offset != len(decoder.payload) {
		return fmt.Errorf(
			"static publication root payload has %d trailing bytes: %w",
			len(decoder.payload)-decoder.offset, ErrCorruptStaticPublicationRootV7)
	}
	return nil
}

func staticPublicationRootV7DecodeError(field string, err error) error {
	return fmt.Errorf("decode %s: %w", field, err)
}
