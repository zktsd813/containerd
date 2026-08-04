package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unicode/utf8"
)

const (
	publicationV7HeaderSize       uint32 = 64
	publicationV7DomainFieldBytes        = 24
	maxPublicationV7PayloadBytes         = MaxPublicationV7Bytes - PublicationV7EnvelopeHeaderBytes
)

var (
	_ [publicationV7HeaderSize]byte = [PublicationV7EnvelopeHeaderBytes]byte{}
	_ [8]byte                       = [len(PublicationV7MagicString)]byte{}
	_ [publicationV7DomainFieldBytes - len(PublicationV7Domain)]byte

	publicationV7Magic  = publicationV7FixedMagic(PublicationV7MagicString)
	publicationV7Domain = publicationV7FixedDomain(PublicationV7Domain)
)

// CanonicalPublicationV7Bytes validates and deterministically encodes one
// complete TRPUB007 immutable graph.
func CanonicalPublicationV7Bytes(publication PublicationV7) ([]byte, error) {
	if err := publication.Validate(); err != nil {
		return nil, err
	}
	return canonicalPublicationV7BytesValidated(publication)
}

func canonicalPublicationV7BytesValidated(publication PublicationV7) ([]byte, error) {
	payload, err := marshalPublicationV7Payload(publication)
	if err != nil {
		return nil, err
	}
	return marshalPublicationV7Envelope(payload)
}

// CanonicalPublicationV7Size returns the complete envelope size, including
// the fixed 64-byte integrity header.
func CanonicalPublicationV7Size(publication PublicationV7) (uint64, error) {
	encoded, err := CanonicalPublicationV7Bytes(publication)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

// DecodePublicationV7 accepts exactly one complete TRPUB007 envelope.
func DecodePublicationV7(data []byte) (PublicationV7, error) {
	payload, err := parsePublicationV7Envelope(data)
	if err != nil {
		return PublicationV7{}, err
	}
	publication, err := unmarshalPublicationV7Payload(payload)
	if err != nil {
		return PublicationV7{}, err
	}
	if err := publication.Validate(); err != nil {
		return PublicationV7{}, err
	}
	return publication, nil
}

// PublicationV7EnvelopeExactLengthFromHeader validates exactly one fixed
// TRPUB007 envelope header and returns the complete envelope length declared
// by that header. capacityBytes is the non-zero size of the storage object
// from which recovery will read the envelope.
//
// This function validates only header integrity and bounds. It cannot validate
// the declared payload CRC-32C without the payload; after reading exactly the
// returned length, callers must pass the complete envelope to
// DecodePublicationV7.
func PublicationV7EnvelopeExactLengthFromHeader(
	header []byte,
	capacityBytes uint64,
) (uint64, error) {
	if uint64(len(header)) != PublicationV7EnvelopeHeaderBytes {
		return 0, fmt.Errorf(
			"publication header is %d bytes, want exactly %d: %w",
			len(header), PublicationV7EnvelopeHeaderBytes, ErrCorruptPublicationV7)
	}
	var magic [8]byte
	copy(magic[:], header[0:8])
	if magic != publicationV7Magic {
		return 0, fmt.Errorf(
			"publication magic %q is not %q: %w",
			magic, publicationV7Magic, ErrWrongPublicationV7Format)
	}
	if version := binary.LittleEndian.Uint32(header[8:12]); version != PublicationV7Version {
		return 0, fmt.Errorf(
			"publication version %d is not %d: %w",
			version, PublicationV7Version, ErrWrongPublicationV7Format)
	}
	if size := binary.LittleEndian.Uint32(header[12:16]); size != publicationV7HeaderSize {
		return 0, fmt.Errorf(
			"publication header size %d is not %d: %w",
			size, publicationV7HeaderSize, ErrWrongPublicationV7Format)
	}
	var domain [publicationV7DomainFieldBytes]byte
	copy(domain[:], header[16:40])
	if domain != publicationV7Domain {
		return 0, fmt.Errorf(
			"publication domain does not match %q: %w",
			PublicationV7Domain, ErrWrongPublicationV7Format)
	}
	if flags := binary.LittleEndian.Uint32(header[52:56]); flags != 0 {
		return 0, fmt.Errorf(
			"publication has unknown mandatory flags %#x: %w",
			flags, ErrWrongPublicationV7Format)
	}
	if !publicationV7AllZero(header[60:publicationV7HeaderSize]) {
		return 0, fmt.Errorf(
			"publication reserved header bytes are non-zero: %w",
			ErrWrongPublicationV7Format)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(header[56:60])
	if got := publicationV7HeaderCRC(header); got != wantHeaderCRC {
		return 0, fmt.Errorf(
			"publication header checksum %#x does not match %#x: %w",
			got, wantHeaderCRC, ErrCorruptPublicationV7)
	}
	payloadLength := binary.LittleEndian.Uint64(header[40:48])
	if payloadLength > ^uint64(0)-PublicationV7EnvelopeHeaderBytes {
		return 0, fmt.Errorf(
			"publication envelope length overflows for payload %d: %w",
			payloadLength, ErrCorruptPublicationV7)
	}
	total := PublicationV7EnvelopeHeaderBytes + payloadLength
	if payloadLength > maxPublicationV7PayloadBytes || total > MaxPublicationV7Bytes {
		return 0, fmt.Errorf(
			"publication payload length %d exceeds %d: %w",
			payloadLength, maxPublicationV7PayloadBytes, ErrCorruptPublicationV7)
	}
	if capacityBytes == 0 {
		return 0, fmt.Errorf(
			"publication storage capacity is zero: %w", ErrCorruptPublicationV7)
	}
	if total > capacityBytes {
		return 0, fmt.Errorf(
			"publication envelope length %d exceeds storage capacity %d: %w",
			total, capacityBytes, ErrCorruptPublicationV7)
	}
	return total, nil
}

// EncodePublicationV7ForStorage prepares the exact immutable bytes, zero-only
// slot padding, digest, and external bootstrap PageID runs. The graph itself
// never embeds these runs, avoiding a self-locator cycle.
func EncodePublicationV7ForStorage(
	publication PublicationV7,
) (PublicationStorageV7, error) {
	if err := publication.Validate(); err != nil {
		return PublicationStorageV7{}, err
	}
	exact, err := canonicalPublicationV7BytesValidated(publication)
	if err != nil {
		return PublicationStorageV7{}, err
	}
	var slot ContentObjectV7
	found := false
	for _, object := range publication.Objects {
		if object.Kind == ContentPublicationV7 {
			slot = object
			found = true
			break
		}
	}
	if !found {
		return PublicationStorageV7{}, publicationV7Invalidf(
			"immutable publication has no publication slot")
	}
	runs, err := publication.controlObjectPageRunsValidated(
		slot, uint64(len(exact)), uint64(len(exact)))
	if err != nil {
		return PublicationStorageV7{}, err
	}
	paddedWriteRuns, err := publication.allocationPageRuns(
		slot.LogicalPageStart, slot.CapacityPages, slot.LogicalPageStart)
	if err != nil {
		return PublicationStorageV7{}, err
	}
	capacityBytes, ok := mulLong(slot.CapacityPages, PublicationV7PageSize)
	if !ok || capacityBytes > MaxPublicationV7Bytes || uint64(len(exact)) > capacityBytes {
		return PublicationStorageV7{}, publicationV7Invalidf(
			"publication slot capacity %d cannot safely contain %d exact bytes",
			capacityBytes, len(exact))
	}
	padded := make([]byte, int(capacityBytes))
	copy(padded, exact)
	return PublicationStorageV7{
		ContentObjectID:  slot.ObjectID,
		LogicalPageStart: slot.LogicalPageStart,
		CapacityPages:    slot.CapacityPages,
		ExactBytes:       append([]byte(nil), exact...),
		PaddedBytes:      padded,
		SHA256:           sha256.Sum256(exact),
		PageRuns:         append([]AllocationPageRunV7(nil), runs...),
		PaddedWriteRuns:  append([]AllocationPageRunV7(nil), paddedWriteRuns...),
	}, nil
}

func marshalPublicationV7Payload(publication PublicationV7) ([]byte, error) {
	encoder := newPublicationV7Encoder()
	encoder.text(publication.CheckpointID)
	encoder.text(publication.ImmutableGraphID)
	encoder.text(publication.DedupDomainID)
	encoder.text(publication.SharingPolicyID)
	encodeInitialAllocationV7(encoder, publication.InitialAllocation)
	encodeContentObjectsV7(encoder, publication.Objects)
	encodeMMTemplateRefV7(encoder, publication.MMTemplate)
	encodeVirtualPageMapRefV7(encoder, publication.VirtualPageMap)
	encodeArtifactManifestRefV7(encoder, publication.ArtifactManifest)
	encoder.u64(publication.PlacementSlots.AObjectID)
	encoder.u64(publication.PlacementSlots.BObjectID)
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalPublicationV7Payload(payload []byte) (PublicationV7, error) {
	decoder := newPublicationV7Decoder(payload)
	publication := PublicationV7{}
	var err error
	if publication.CheckpointID, err = decoder.text(); err != nil {
		return PublicationV7{}, publicationV7DecodeError("checkpoint ID", err)
	}
	if publication.ImmutableGraphID, err = decoder.text(); err != nil {
		return PublicationV7{}, publicationV7DecodeError("immutable graph ID", err)
	}
	if publication.DedupDomainID, err = decoder.text(); err != nil {
		return PublicationV7{}, publicationV7DecodeError("dedup domain ID", err)
	}
	if publication.SharingPolicyID, err = decoder.text(); err != nil {
		return PublicationV7{}, publicationV7DecodeError("sharing policy ID", err)
	}
	if publication.InitialAllocation, err = decodeInitialAllocationV7(decoder); err != nil {
		return PublicationV7{}, err
	}
	if publication.Objects, err = decodeContentObjectsV7(decoder); err != nil {
		return PublicationV7{}, err
	}
	if publication.MMTemplate, err = decodeMMTemplateRefV7(decoder); err != nil {
		return PublicationV7{}, err
	}
	if publication.VirtualPageMap, err = decodeVirtualPageMapRefV7(decoder); err != nil {
		return PublicationV7{}, err
	}
	if publication.ArtifactManifest, err = decodeArtifactManifestRefV7(decoder); err != nil {
		return PublicationV7{}, err
	}
	if publication.PlacementSlots.AObjectID, err = decoder.u64(); err != nil {
		return PublicationV7{}, publicationV7DecodeError("placement slot A object ID", err)
	}
	if publication.PlacementSlots.BObjectID, err = decoder.u64(); err != nil {
		return PublicationV7{}, publicationV7DecodeError("placement slot B object ID", err)
	}
	if err := decoder.done(); err != nil {
		return PublicationV7{}, err
	}
	return publication, nil
}

func encodeInitialAllocationV7(encoder *publicationV7Encoder, allocation InitialAllocationV7) {
	encoder.text(allocation.OwnerID)
	encoder.u64(allocation.OwnerEpoch)
	encoder.u64(allocation.AllocationRecordID)
	encoder.u64(allocation.TotalPages)
	encoder.count(len(allocation.Devices))
	for _, device := range allocation.Devices {
		encoder.text(device.DeviceUUID)
		encoder.u64(device.DataPageCount)
	}
	encoder.count(len(allocation.Extents))
	for _, extent := range allocation.Extents {
		encoder.u32(extent.DeviceIndex)
		encoder.u64(extent.StartDataPageIndex)
		encoder.u64(extent.PageCount)
		encoder.u64(extent.LogicalPageStart)
	}
}

func decodeInitialAllocationV7(decoder *publicationV7Decoder) (InitialAllocationV7, error) {
	allocation := InitialAllocationV7{}
	var err error
	if allocation.OwnerID, err = decoder.text(); err != nil {
		return InitialAllocationV7{}, publicationV7DecodeError("allocation Owner ID", err)
	}
	if allocation.OwnerEpoch, err = decoder.u64(); err != nil {
		return InitialAllocationV7{}, publicationV7DecodeError("allocation Owner epoch", err)
	}
	if allocation.AllocationRecordID, err = decoder.u64(); err != nil {
		return InitialAllocationV7{}, publicationV7DecodeError("allocation record ID", err)
	}
	if allocation.TotalPages, err = decoder.u64(); err != nil {
		return InitialAllocationV7{}, publicationV7DecodeError("allocation total pages", err)
	}
	deviceCount, err := decoder.count("allocation devices", 12, MaxPublicationV7Devices)
	if err != nil {
		return InitialAllocationV7{}, err
	}
	allocation.Devices = make([]AllocationDeviceV7, deviceCount)
	for index := range allocation.Devices {
		if allocation.Devices[index].DeviceUUID, err = decoder.text(); err != nil {
			return InitialAllocationV7{}, publicationV7DecodeError("allocation device UUID", err)
		}
		if allocation.Devices[index].DataPageCount, err = decoder.u64(); err != nil {
			return InitialAllocationV7{}, publicationV7DecodeError("allocation device capacity", err)
		}
	}
	extentCount, err := decoder.count("allocation extents", 28, MaxPublicationV7Extents)
	if err != nil {
		return InitialAllocationV7{}, err
	}
	allocation.Extents = make([]AllocationExtentV7, extentCount)
	for index := range allocation.Extents {
		if allocation.Extents[index].DeviceIndex, err = decoder.u32(); err != nil {
			return InitialAllocationV7{}, publicationV7DecodeError("extent device index", err)
		}
		if allocation.Extents[index].StartDataPageIndex, err = decoder.u64(); err != nil {
			return InitialAllocationV7{}, publicationV7DecodeError("extent data page start", err)
		}
		if allocation.Extents[index].PageCount, err = decoder.u64(); err != nil {
			return InitialAllocationV7{}, publicationV7DecodeError("extent page count", err)
		}
		if allocation.Extents[index].LogicalPageStart, err = decoder.u64(); err != nil {
			return InitialAllocationV7{}, publicationV7DecodeError("extent logical page start", err)
		}
	}
	return allocation, nil
}

func encodeContentObjectsV7(encoder *publicationV7Encoder, objects []ContentObjectV7) {
	encoder.count(len(objects))
	for _, object := range objects {
		encoder.u64(object.ObjectID)
		encoder.u8(uint8(object.Kind))
		encoder.u64(object.ImmutableByteLength)
		encoder.u64(object.LogicalPageStart)
		encoder.u64(object.CapacityPages)
	}
}

func decodeContentObjectsV7(decoder *publicationV7Decoder) ([]ContentObjectV7, error) {
	count, err := decoder.count("content objects", 33, MaxPublicationV7Objects)
	if err != nil {
		return nil, err
	}
	objects := make([]ContentObjectV7, count)
	for index := range objects {
		if objects[index].ObjectID, err = decoder.u64(); err != nil {
			return nil, publicationV7DecodeError("content object ID", err)
		}
		kind, err := decoder.u8()
		if err != nil {
			return nil, publicationV7DecodeError("content object kind", err)
		}
		objects[index].Kind = ContentKindV7(kind)
		if objects[index].ImmutableByteLength, err = decoder.u64(); err != nil {
			return nil, publicationV7DecodeError("content immutable byte length", err)
		}
		if objects[index].LogicalPageStart, err = decoder.u64(); err != nil {
			return nil, publicationV7DecodeError("content logical page start", err)
		}
		if objects[index].CapacityPages, err = decoder.u64(); err != nil {
			return nil, publicationV7DecodeError("content capacity pages", err)
		}
	}
	return objects, nil
}

func encodeMMTemplateRefV7(encoder *publicationV7Encoder, reference MMTemplateRefV7) {
	encoder.u64(reference.ObjectID)
	encoder.text(reference.MMTemplateID)
	encoder.u64(reference.Version)
	encoder.fixed(reference.SHA256[:])
}

func decodeMMTemplateRefV7(decoder *publicationV7Decoder) (MMTemplateRefV7, error) {
	reference := MMTemplateRefV7{}
	var err error
	if reference.ObjectID, err = decoder.u64(); err != nil {
		return MMTemplateRefV7{}, publicationV7DecodeError("MMTemplate object ID", err)
	}
	if reference.MMTemplateID, err = decoder.text(); err != nil {
		return MMTemplateRefV7{}, publicationV7DecodeError("MMTemplate ID", err)
	}
	if reference.Version, err = decoder.u64(); err != nil {
		return MMTemplateRefV7{}, publicationV7DecodeError("MMTemplate version", err)
	}
	digest, err := decoder.fixed(sha256.Size)
	if err != nil {
		return MMTemplateRefV7{}, publicationV7DecodeError("MMTemplate SHA-256", err)
	}
	copy(reference.SHA256[:], digest)
	return reference, nil
}

func encodeVirtualPageMapRefV7(encoder *publicationV7Encoder, reference VirtualPageMapRefV7) {
	encoder.u64(reference.ObjectID)
	encoder.text(reference.VirtualPageMapID)
	encoder.u64(reference.Version)
	encoder.fixed(reference.SHA256[:])
}

func decodeVirtualPageMapRefV7(decoder *publicationV7Decoder) (VirtualPageMapRefV7, error) {
	reference := VirtualPageMapRefV7{}
	var err error
	if reference.ObjectID, err = decoder.u64(); err != nil {
		return VirtualPageMapRefV7{}, publicationV7DecodeError("VirtualPageMap object ID", err)
	}
	if reference.VirtualPageMapID, err = decoder.text(); err != nil {
		return VirtualPageMapRefV7{}, publicationV7DecodeError("VirtualPageMap ID", err)
	}
	if reference.Version, err = decoder.u64(); err != nil {
		return VirtualPageMapRefV7{}, publicationV7DecodeError("VirtualPageMap version", err)
	}
	digest, err := decoder.fixed(sha256.Size)
	if err != nil {
		return VirtualPageMapRefV7{}, publicationV7DecodeError("VirtualPageMap SHA-256", err)
	}
	copy(reference.SHA256[:], digest)
	return reference, nil
}

func encodeArtifactManifestRefV7(
	encoder *publicationV7Encoder,
	reference ArtifactManifestRefV7,
) {
	encoder.u64(reference.ObjectID)
	encoder.text(reference.ArtifactManifestID)
	encoder.u64(reference.Version)
	encoder.fixed(reference.SHA256[:])
}

func decodeArtifactManifestRefV7(
	decoder *publicationV7Decoder,
) (ArtifactManifestRefV7, error) {
	reference := ArtifactManifestRefV7{}
	var err error
	if reference.ObjectID, err = decoder.u64(); err != nil {
		return ArtifactManifestRefV7{}, publicationV7DecodeError("ArtifactManifest object ID", err)
	}
	if reference.ArtifactManifestID, err = decoder.text(); err != nil {
		return ArtifactManifestRefV7{}, publicationV7DecodeError("ArtifactManifest ID", err)
	}
	if reference.Version, err = decoder.u64(); err != nil {
		return ArtifactManifestRefV7{}, publicationV7DecodeError("ArtifactManifest version", err)
	}
	digest, err := decoder.fixed(sha256.Size)
	if err != nil {
		return ArtifactManifestRefV7{}, publicationV7DecodeError("ArtifactManifest SHA-256", err)
	}
	copy(reference.SHA256[:], digest)
	return reference, nil
}

func marshalPublicationV7Envelope(payload []byte) ([]byte, error) {
	if uint64(len(payload)) > maxPublicationV7PayloadBytes {
		return nil, publicationV7Invalidf(
			"publication payload is %d bytes, limit is %d",
			len(payload), maxPublicationV7PayloadBytes)
	}
	total := PublicationV7EnvelopeHeaderBytes + uint64(len(payload))
	out := make([]byte, int(total))
	copy(out[0:8], publicationV7Magic[:])
	binary.LittleEndian.PutUint32(out[8:12], PublicationV7Version)
	binary.LittleEndian.PutUint32(out[12:16], publicationV7HeaderSize)
	copy(out[16:40], publicationV7Domain[:])
	binary.LittleEndian.PutUint64(out[40:48], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[48:52], checksumCRC32C(payload))
	// 52:56 mandatory flags and 60:64 reserved are zero in V7.
	copy(out[publicationV7HeaderSize:], payload)
	binary.LittleEndian.PutUint32(
		out[56:60], publicationV7HeaderCRC(out[:publicationV7HeaderSize]))
	return out, nil
}

func parsePublicationV7Envelope(data []byte) ([]byte, error) {
	if len(data) < int(publicationV7HeaderSize) {
		return nil, fmt.Errorf("publication envelope is truncated: %w", ErrCorruptPublicationV7)
	}
	if uint64(len(data)) > MaxPublicationV7Bytes {
		return nil, fmt.Errorf(
			"publication envelope is %d bytes, limit is %d: %w",
			len(data), MaxPublicationV7Bytes, ErrCorruptPublicationV7)
	}
	total, err := PublicationV7EnvelopeExactLengthFromHeader(
		data[:publicationV7HeaderSize], MaxPublicationV7Bytes)
	if err != nil {
		return nil, err
	}
	if total != uint64(len(data)) {
		return nil, fmt.Errorf(
			"publication envelope is %d bytes, header declares %d: %w",
			len(data), total, ErrCorruptPublicationV7)
	}
	payload := data[publicationV7HeaderSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[48:52])
	if got := checksumCRC32C(payload); got != wantPayloadCRC {
		return nil, fmt.Errorf(
			"publication payload checksum %#x does not match %#x: %w",
			got, wantPayloadCRC, ErrCorruptPublicationV7)
	}
	return append([]byte(nil), payload...), nil
}

func publicationV7HeaderCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= int(publicationV7HeaderSize) {
		for index := 56; index < 60; index++ {
			copyForCRC[index] = 0
		}
	}
	return checksumCRC32C(copyForCRC)
}

func publicationV7FixedMagic(value string) [8]byte {
	var result [8]byte
	copy(result[:], value)
	return result
}

func publicationV7FixedDomain(value string) [publicationV7DomainFieldBytes]byte {
	var result [publicationV7DomainFieldBytes]byte
	copy(result[:], value)
	return result
}

func publicationV7AllZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

type publicationV7Encoder struct {
	buffer bytes.Buffer
	err    error
}

func newPublicationV7Encoder() *publicationV7Encoder {
	return &publicationV7Encoder{}
}

func (encoder *publicationV7Encoder) bytes() []byte {
	return append([]byte(nil), encoder.buffer.Bytes()...)
}

func (encoder *publicationV7Encoder) fixed(value []byte) {
	if encoder.err != nil {
		return
	}
	if uint64(len(value)) > maxPublicationV7PayloadBytes-uint64(encoder.buffer.Len()) {
		encoder.err = publicationV7Invalidf(
			"publication payload exceeds %d bytes", maxPublicationV7PayloadBytes)
		return
	}
	_, encoder.err = encoder.buffer.Write(value)
}

func (encoder *publicationV7Encoder) u8(value uint8) {
	encoder.fixed([]byte{value})
}

func (encoder *publicationV7Encoder) u32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	encoder.fixed(data[:])
}

func (encoder *publicationV7Encoder) u64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	encoder.fixed(data[:])
}

func (encoder *publicationV7Encoder) count(value int) {
	if value < 0 || uint64(value) > uint64(^uint32(0)) {
		encoder.err = publicationV7Invalidf("collection count %d cannot be encoded", value)
		return
	}
	encoder.u32(uint32(value))
}

func (encoder *publicationV7Encoder) text(value string) {
	if !utf8.ValidString(value) || uint64(len(value)) > uint64(^uint32(0)) {
		encoder.err = publicationV7Invalidf("text cannot be encoded")
		return
	}
	encoder.u32(uint32(len(value)))
	encoder.fixed([]byte(value))
}

type publicationV7Decoder struct {
	payload []byte
	offset  int
}

func newPublicationV7Decoder(payload []byte) *publicationV7Decoder {
	return &publicationV7Decoder{payload: payload}
}

func (decoder *publicationV7Decoder) fixed(size int) ([]byte, error) {
	if size < 0 || decoder.offset > len(decoder.payload) ||
		size > len(decoder.payload)-decoder.offset {
		return nil, fmt.Errorf("publication payload is truncated: %w", ErrCorruptPublicationV7)
	}
	value := decoder.payload[decoder.offset : decoder.offset+size]
	decoder.offset += size
	return value, nil
}

func (decoder *publicationV7Decoder) u8() (uint8, error) {
	data, err := decoder.fixed(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

func (decoder *publicationV7Decoder) u32() (uint32, error) {
	data, err := decoder.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (decoder *publicationV7Decoder) u64() (uint64, error) {
	data, err := decoder.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (decoder *publicationV7Decoder) count(
	name string,
	minimumBytes int,
	maximum int,
) (int, error) {
	value, err := decoder.u32()
	if err != nil {
		return 0, publicationV7DecodeError(name+" count", err)
	}
	if uint64(value) > uint64(maximum) {
		return 0, fmt.Errorf(
			"%s count %d exceeds %d: %w",
			name, value, maximum, ErrCorruptPublicationV7)
	}
	remaining := len(decoder.payload) - decoder.offset
	if minimumBytes < 1 || uint64(value) > uint64(remaining/minimumBytes) {
		return 0, fmt.Errorf(
			"%s count %d cannot fit remaining payload: %w",
			name, value, ErrCorruptPublicationV7)
	}
	return int(value), nil
}

func (decoder *publicationV7Decoder) text() (string, error) {
	length, err := decoder.u32()
	if err != nil {
		return "", err
	}
	if uint64(length) > MaxPublicationV7IdentityBytes {
		return "", fmt.Errorf(
			"text length %d exceeds identity limit %d before allocation: %w",
			length, MaxPublicationV7IdentityBytes, ErrCorruptPublicationV7)
	}
	if uint64(length) > uint64(len(decoder.payload)-decoder.offset) {
		return "", fmt.Errorf("text length exceeds remaining payload: %w", ErrCorruptPublicationV7)
	}
	data, err := decoder.fixed(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("text is not valid UTF-8: %w", ErrCorruptPublicationV7)
	}
	return string(data), nil
}

func (decoder *publicationV7Decoder) done() error {
	if decoder.offset != len(decoder.payload) {
		return fmt.Errorf(
			"publication payload has %d trailing bytes: %w",
			len(decoder.payload)-decoder.offset, ErrCorruptPublicationV7)
	}
	return nil
}

func publicationV7DecodeError(field string, err error) error {
	return fmt.Errorf("decode %s: %w", field, err)
}
