package cxlcheckpoint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	metadataV7HeaderSize       uint32 = 64
	metadataV7DomainFieldBytes        = 24
	maxMetadataV7PayloadBytes         = MaxMetadataV7Bytes - MetadataV7EnvelopeHeaderBytes
)

type metadataV7EnvelopeSpec struct {
	name   string
	magic  [8]byte
	domain [metadataV7DomainFieldBytes]byte
}

var (
	_ [metadataV7HeaderSize]byte = [MetadataV7EnvelopeHeaderBytes]byte{}
	_ [8]byte                    = [len(MMTemplateV7MagicString)]byte{}
	_ [8]byte                    = [len(ArtifactManifestV7MagicString)]byte{}
	_ [metadataV7DomainFieldBytes - len(MMTemplateV7Domain)]byte
	_ [metadataV7DomainFieldBytes - len(ArtifactManifestV7Domain)]byte

	mmTemplateV7EnvelopeSpec = metadataV7EnvelopeSpec{
		name:   "MMTemplateV7",
		magic:  metadataV7FixedMagic(MMTemplateV7MagicString),
		domain: metadataV7FixedDomain(MMTemplateV7Domain),
	}
	artifactManifestV7EnvelopeSpec = metadataV7EnvelopeSpec{
		name:   "ArtifactManifestV7",
		magic:  metadataV7FixedMagic(ArtifactManifestV7MagicString),
		domain: metadataV7FixedDomain(ArtifactManifestV7Domain),
	}
)

func CanonicalMMTemplateV7Bytes(template MMTemplateV7) ([]byte, error) {
	if err := template.Validate(); err != nil {
		return nil, err
	}
	payload, err := marshalMMTemplateV7Payload(template)
	if err != nil {
		return nil, err
	}
	return marshalMetadataV7Envelope(mmTemplateV7EnvelopeSpec, payload)
}

func CanonicalMMTemplateV7Size(template MMTemplateV7) (uint64, error) {
	encoded, err := CanonicalMMTemplateV7Bytes(template)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

func DecodeMMTemplateV7(data []byte) (MMTemplateV7, error) {
	payload, err := parseMetadataV7Envelope(mmTemplateV7EnvelopeSpec, data)
	if err != nil {
		return MMTemplateV7{}, err
	}
	template, err := unmarshalMMTemplateV7Payload(payload)
	if err != nil {
		return MMTemplateV7{}, err
	}
	if err := template.Validate(); err != nil {
		return MMTemplateV7{}, err
	}
	return template, nil
}

func CanonicalArtifactManifestV7Bytes(
	manifest ArtifactManifestV7,
) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	payload, err := marshalArtifactManifestV7Payload(manifest)
	if err != nil {
		return nil, err
	}
	return marshalMetadataV7Envelope(artifactManifestV7EnvelopeSpec, payload)
}

func CanonicalArtifactManifestV7Size(
	manifest ArtifactManifestV7,
) (uint64, error) {
	encoded, err := CanonicalArtifactManifestV7Bytes(manifest)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

func DecodeArtifactManifestV7(data []byte) (ArtifactManifestV7, error) {
	payload, err := parseMetadataV7Envelope(artifactManifestV7EnvelopeSpec, data)
	if err != nil {
		return ArtifactManifestV7{}, err
	}
	manifest, err := unmarshalArtifactManifestV7Payload(payload)
	if err != nil {
		return ArtifactManifestV7{}, err
	}
	if err := manifest.Validate(); err != nil {
		return ArtifactManifestV7{}, err
	}
	return manifest, nil
}

func marshalMMTemplateV7Payload(template MMTemplateV7) ([]byte, error) {
	encoder := newMetadataV7Encoder()
	encoder.text(template.MMTemplateID)
	encoder.u64(template.Version)
	encoder.text(template.RuntimeCompatibilityID)
	encoder.u64(template.PageSize)
	encoder.count(len(template.VMAs))
	for _, vma := range template.VMAs {
		encoder.u32(vma.PagesImageID)
		encoder.u64(vma.StartVAddr)
		encoder.u64(vma.EndVAddr)
		encoder.u64(vma.ProtectionFlags)
		encoder.u64(vma.MappingFlags)
		encoder.u8(uint8(vma.BackingKind))
		encoder.u64(vma.VirtualPageMapRunStart)
		encoder.u64(vma.VirtualPageMapRunCount)
	}
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalMMTemplateV7Payload(payload []byte) (MMTemplateV7, error) {
	decoder := newMetadataV7Decoder(payload)
	template := MMTemplateV7{}
	var err error
	if template.MMTemplateID, err = decoder.text(); err != nil {
		return MMTemplateV7{}, metadataV7DecodeError("MMTemplate ID", err)
	}
	if template.Version, err = decoder.u64(); err != nil {
		return MMTemplateV7{}, metadataV7DecodeError("MMTemplate version", err)
	}
	if template.RuntimeCompatibilityID, err = decoder.text(); err != nil {
		return MMTemplateV7{}, metadataV7DecodeError("runtime compatibility ID", err)
	}
	if template.PageSize, err = decoder.u64(); err != nil {
		return MMTemplateV7{}, metadataV7DecodeError("MMTemplate page size", err)
	}
	count, err := decoder.count("VMAs", 53, MaxMetadataV7Entries)
	if err != nil {
		return MMTemplateV7{}, err
	}
	template.VMAs = make([]VMAV7, count)
	for index := range template.VMAs {
		vma := &template.VMAs[index]
		if vma.PagesImageID, err = decoder.u32(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA pages image ID", err)
		}
		if vma.StartVAddr, err = decoder.u64(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA start address", err)
		}
		if vma.EndVAddr, err = decoder.u64(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA end address", err)
		}
		if vma.ProtectionFlags, err = decoder.u64(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA protection flags", err)
		}
		if vma.MappingFlags, err = decoder.u64(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA mapping flags", err)
		}
		backing, err := decoder.u8()
		if err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA backing kind", err)
		}
		vma.BackingKind = BackingKind(backing)
		if vma.VirtualPageMapRunStart, err = decoder.u64(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA VirtualPageMap run start", err)
		}
		if vma.VirtualPageMapRunCount, err = decoder.u64(); err != nil {
			return MMTemplateV7{}, metadataV7DecodeError("VMA VirtualPageMap run count", err)
		}
	}
	if err := decoder.done(); err != nil {
		return MMTemplateV7{}, err
	}
	return template, nil
}

func marshalArtifactManifestV7Payload(manifest ArtifactManifestV7) ([]byte, error) {
	encoder := newMetadataV7Encoder()
	encoder.text(manifest.ArtifactManifestID)
	encoder.u64(manifest.Version)
	encoder.count(len(manifest.Entries))
	for _, entry := range manifest.Entries {
		encoder.text(entry.Path)
		encoder.u8(uint8(entry.Type))
		encoder.u64(entry.Mode)
		encoder.u64(entry.UID)
		encoder.u64(entry.GID)
		encoder.u64(entry.ByteLength)
		encoder.u64(entry.ContentObjectID)
		encoder.u64(entry.ContentOffset)
		encoder.text(entry.LinkTarget)
	}
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalArtifactManifestV7Payload(payload []byte) (ArtifactManifestV7, error) {
	decoder := newMetadataV7Decoder(payload)
	manifest := ArtifactManifestV7{}
	var err error
	if manifest.ArtifactManifestID, err = decoder.text(); err != nil {
		return ArtifactManifestV7{}, metadataV7DecodeError("ArtifactManifest ID", err)
	}
	if manifest.Version, err = decoder.u64(); err != nil {
		return ArtifactManifestV7{}, metadataV7DecodeError("ArtifactManifest version", err)
	}
	count, err := decoder.count("artifact entries", 57, MaxMetadataV7Entries)
	if err != nil {
		return ArtifactManifestV7{}, err
	}
	manifest.Entries = make([]ArtifactEntryV7, count)
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if entry.Path, err = decoder.text(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact path", err)
		}
		entryType, err := decoder.u8()
		if err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact type", err)
		}
		entry.Type = ArtifactType(entryType)
		if entry.Mode, err = decoder.u64(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact mode", err)
		}
		if entry.UID, err = decoder.u64(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact UID", err)
		}
		if entry.GID, err = decoder.u64(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact GID", err)
		}
		if entry.ByteLength, err = decoder.u64(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact byte length", err)
		}
		if entry.ContentObjectID, err = decoder.u64(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact content object ID", err)
		}
		if entry.ContentOffset, err = decoder.u64(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact content offset", err)
		}
		if entry.LinkTarget, err = decoder.text(); err != nil {
			return ArtifactManifestV7{}, metadataV7DecodeError("artifact link target", err)
		}
	}
	if err := decoder.done(); err != nil {
		return ArtifactManifestV7{}, err
	}
	return manifest, nil
}

func marshalMetadataV7Envelope(
	spec metadataV7EnvelopeSpec,
	payload []byte,
) ([]byte, error) {
	if uint64(len(payload)) > maxMetadataV7PayloadBytes {
		return nil, metadataV7Invalidf(
			"%s payload is %d bytes, limit is %d",
			spec.name, len(payload), maxMetadataV7PayloadBytes)
	}
	total := MetadataV7EnvelopeHeaderBytes + uint64(len(payload))
	out := make([]byte, int(total))
	copy(out[0:8], spec.magic[:])
	binary.LittleEndian.PutUint32(out[8:12], MetadataV7Version)
	binary.LittleEndian.PutUint32(out[12:16], metadataV7HeaderSize)
	copy(out[16:40], spec.domain[:])
	binary.LittleEndian.PutUint64(out[40:48], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[48:52], checksumCRC32C(payload))
	// 52:56 mandatory flags and 60:64 reserved are zero in V7.
	copy(out[metadataV7HeaderSize:], payload)
	binary.LittleEndian.PutUint32(
		out[56:60], metadataV7HeaderCRC(out[:metadataV7HeaderSize]))
	return out, nil
}

func parseMetadataV7Envelope(
	spec metadataV7EnvelopeSpec,
	data []byte,
) ([]byte, error) {
	if len(data) < int(metadataV7HeaderSize) {
		return nil, fmt.Errorf("%s envelope is truncated: %w", spec.name, ErrCorruptMetadataV7)
	}
	if uint64(len(data)) > MaxMetadataV7Bytes {
		return nil, fmt.Errorf(
			"%s envelope is %d bytes, limit is %d: %w",
			spec.name, len(data), MaxMetadataV7Bytes, ErrCorruptMetadataV7)
	}
	var magic [8]byte
	copy(magic[:], data[0:8])
	if magic != spec.magic {
		return nil, fmt.Errorf(
			"%s magic %q does not match: %w", spec.name, magic, ErrWrongMetadataV7Format)
	}
	if version := binary.LittleEndian.Uint32(data[8:12]); version != MetadataV7Version {
		return nil, fmt.Errorf(
			"%s version %d is not %d: %w",
			spec.name, version, MetadataV7Version, ErrWrongMetadataV7Format)
	}
	if size := binary.LittleEndian.Uint32(data[12:16]); size != metadataV7HeaderSize {
		return nil, fmt.Errorf(
			"%s header size %d is not %d: %w",
			spec.name, size, metadataV7HeaderSize, ErrWrongMetadataV7Format)
	}
	var domain [metadataV7DomainFieldBytes]byte
	copy(domain[:], data[16:40])
	if domain != spec.domain {
		return nil, fmt.Errorf("%s domain does not match: %w", spec.name, ErrWrongMetadataV7Format)
	}
	if flags := binary.LittleEndian.Uint32(data[52:56]); flags != 0 {
		return nil, fmt.Errorf(
			"%s has unknown mandatory flags %#x: %w",
			spec.name, flags, ErrWrongMetadataV7Format)
	}
	if !metadataV7AllZero(data[60:metadataV7HeaderSize]) {
		return nil, fmt.Errorf(
			"%s reserved header bytes are non-zero: %w",
			spec.name, ErrWrongMetadataV7Format)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[56:60])
	if got := metadataV7HeaderCRC(data[:metadataV7HeaderSize]); got != wantHeaderCRC {
		return nil, fmt.Errorf(
			"%s header checksum %#x does not match %#x: %w",
			spec.name, got, wantHeaderCRC, ErrCorruptMetadataV7)
	}
	payloadLength := binary.LittleEndian.Uint64(data[40:48])
	if payloadLength > maxMetadataV7PayloadBytes {
		return nil, fmt.Errorf(
			"%s payload length %d exceeds %d: %w",
			spec.name, payloadLength, maxMetadataV7PayloadBytes, ErrCorruptMetadataV7)
	}
	total := MetadataV7EnvelopeHeaderBytes + payloadLength
	if total != uint64(len(data)) {
		return nil, fmt.Errorf(
			"%s envelope is %d bytes, header declares %d: %w",
			spec.name, len(data), total, ErrCorruptMetadataV7)
	}
	payload := data[metadataV7HeaderSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[48:52])
	if got := checksumCRC32C(payload); got != wantPayloadCRC {
		return nil, fmt.Errorf(
			"%s payload checksum %#x does not match %#x: %w",
			spec.name, got, wantPayloadCRC, ErrCorruptMetadataV7)
	}
	return append([]byte(nil), payload...), nil
}

func metadataV7HeaderCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= int(metadataV7HeaderSize) {
		for index := 56; index < 60; index++ {
			copyForCRC[index] = 0
		}
	}
	return checksumCRC32C(copyForCRC)
}

func metadataV7FixedMagic(value string) [8]byte {
	var result [8]byte
	copy(result[:], value)
	return result
}

func metadataV7FixedDomain(value string) [metadataV7DomainFieldBytes]byte {
	var result [metadataV7DomainFieldBytes]byte
	copy(result[:], value)
	return result
}

func metadataV7AllZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

type metadataV7Encoder struct {
	buffer bytes.Buffer
	err    error
}

func newMetadataV7Encoder() *metadataV7Encoder {
	return &metadataV7Encoder{}
}

func (encoder *metadataV7Encoder) bytes() []byte {
	return append([]byte(nil), encoder.buffer.Bytes()...)
}

func (encoder *metadataV7Encoder) fixed(value []byte) {
	if encoder.err != nil {
		return
	}
	if uint64(len(value)) > maxMetadataV7PayloadBytes-uint64(encoder.buffer.Len()) {
		encoder.err = metadataV7Invalidf(
			"metadata payload exceeds %d bytes", maxMetadataV7PayloadBytes)
		return
	}
	_, encoder.err = encoder.buffer.Write(value)
}

func (encoder *metadataV7Encoder) u8(value uint8) {
	encoder.fixed([]byte{value})
}

func (encoder *metadataV7Encoder) u32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	encoder.fixed(data[:])
}

func (encoder *metadataV7Encoder) u64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	encoder.fixed(data[:])
}

func (encoder *metadataV7Encoder) count(value int) {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		encoder.err = metadataV7Invalidf("collection count %d cannot be encoded", value)
		return
	}
	encoder.u32(uint32(value))
}

func (encoder *metadataV7Encoder) text(value string) {
	if !utf8.ValidString(value) || uint64(len(value)) > uint64(^uint32(0)) {
		encoder.err = metadataV7Invalidf("text cannot be encoded")
		return
	}
	encoder.u32(uint32(len(value)))
	encoder.fixed([]byte(value))
}

type metadataV7Decoder struct {
	payload []byte
	offset  int
}

func newMetadataV7Decoder(payload []byte) *metadataV7Decoder {
	return &metadataV7Decoder{payload: payload}
}

func (decoder *metadataV7Decoder) fixed(size int) ([]byte, error) {
	if size < 0 || decoder.offset > len(decoder.payload) ||
		size > len(decoder.payload)-decoder.offset {
		return nil, fmt.Errorf("metadata payload is truncated: %w", ErrCorruptMetadataV7)
	}
	value := decoder.payload[decoder.offset : decoder.offset+size]
	decoder.offset += size
	return value, nil
}

func (decoder *metadataV7Decoder) u8() (uint8, error) {
	data, err := decoder.fixed(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func (decoder *metadataV7Decoder) u32() (uint32, error) {
	data, err := decoder.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (decoder *metadataV7Decoder) u64() (uint64, error) {
	data, err := decoder.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (decoder *metadataV7Decoder) count(
	name string,
	minimumBytes int,
	maximum int,
) (int, error) {
	value, err := decoder.u32()
	if err != nil {
		return 0, metadataV7DecodeError(name+" count", err)
	}
	if uint64(value) > uint64(maximum) {
		return 0, fmt.Errorf(
			"%s count %d exceeds %d: %w",
			name, value, maximum, ErrCorruptMetadataV7)
	}
	remaining := len(decoder.payload) - decoder.offset
	if minimumBytes < 1 || uint64(value) > uint64(remaining/minimumBytes) {
		return 0, fmt.Errorf(
			"%s count %d cannot fit remaining payload: %w",
			name, value, ErrCorruptMetadataV7)
	}
	return int(value), nil
}

func (decoder *metadataV7Decoder) text() (string, error) {
	length, err := decoder.u32()
	if err != nil {
		return "", err
	}
	if uint64(length) > MaxPublicationV7IdentityBytes {
		return "", fmt.Errorf(
			"text length %d exceeds identity limit %d before allocation: %w",
			length, MaxPublicationV7IdentityBytes, ErrCorruptMetadataV7)
	}
	if uint64(length) > uint64(len(decoder.payload)-decoder.offset) {
		return "", fmt.Errorf("text length exceeds remaining payload: %w", ErrCorruptMetadataV7)
	}
	data, err := decoder.fixed(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("text is not valid UTF-8: %w", ErrCorruptMetadataV7)
	}
	return string(data), nil
}

func (decoder *metadataV7Decoder) done() error {
	if decoder.offset != len(decoder.payload) {
		return fmt.Errorf(
			"metadata payload has %d trailing bytes: %w",
			len(decoder.payload)-decoder.offset, ErrCorruptMetadataV7)
	}
	return nil
}

func metadataV7DecodeError(field string, err error) error {
	return fmt.Errorf("decode %s: %w", field, err)
}
