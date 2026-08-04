package cxlcheckpoint

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	contentMappingHeaderSize       uint32 = 64
	contentMappingDomainFieldBytes        = 24
	maxContentMappingPayloadBytes         = MaxContentMappingBytes - ContentMappingEnvelopeHeaderBytes
)

type contentMappingEnvelopeSpec struct {
	name   string
	magic  [8]byte
	domain [contentMappingDomainFieldBytes]byte
}

var (
	// These assignments are compile-time invariants: changing the exported
	// header size, either eight-byte magic, or growing a domain past its fixed
	// field fails the build instead of silently changing/truncating the wire
	// identity.
	_ [contentMappingHeaderSize]byte = [ContentMappingEnvelopeHeaderBytes]byte{}
	_ [8]byte                        = [len(VirtualPageMapMagicString)]byte{}
	_ [8]byte                        = [len(ContentPlacementMapMagicString)]byte{}
	_ [contentMappingDomainFieldBytes - len(VirtualPageMapDomain)]byte
	_ [contentMappingDomainFieldBytes - len(ContentPlacementMapDomain)]byte

	virtualPageMapEnvelopeSpec = contentMappingEnvelopeSpec{
		name:   "VirtualPageMap",
		magic:  contentMappingMagic(VirtualPageMapMagicString),
		domain: contentMappingDomain(VirtualPageMapDomain),
	}
	contentPlacementMapEnvelopeSpec = contentMappingEnvelopeSpec{
		name:   "ContentPlacementMap",
		magic:  contentMappingMagic(ContentPlacementMapMagicString),
		domain: contentMappingDomain(ContentPlacementMapDomain),
	}
)

// CanonicalVirtualPageMapBytes validates and returns the exact deterministic
// V7 VirtualPageMap envelope. A later V7 Scheduler root is expected to bind
// this complete byte slice by exact length and SHA-256; this foundation does
// not change the active TRPUB006 root.
func CanonicalVirtualPageMapBytes(
	mapping VirtualPageMap,
	contentObjects []ContentObject,
) ([]byte, error) {
	if err := mapping.Validate(contentObjects); err != nil {
		return nil, err
	}
	payload, err := marshalVirtualPageMapPayload(mapping)
	if err != nil {
		return nil, err
	}
	return marshalContentMappingEnvelope(virtualPageMapEnvelopeSpec, payload)
}

// CanonicalVirtualPageMapSize returns the complete canonical envelope length,
// including the fixed 64-byte V7 mapping header.
func CanonicalVirtualPageMapSize(
	mapping VirtualPageMap,
	contentObjects []ContentObject,
) (uint64, error) {
	encoded, err := CanonicalVirtualPageMapBytes(mapping, contentObjects)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

// DecodeVirtualPageMap accepts exactly one complete V7 VirtualPageMap
// envelope, applies structural integrity checks, and validates every logical
// content reference against contentObjects.
func DecodeVirtualPageMap(
	data []byte,
	contentObjects []ContentObject,
) (VirtualPageMap, error) {
	payload, err := parseContentMappingEnvelope(virtualPageMapEnvelopeSpec, data)
	if err != nil {
		return VirtualPageMap{}, err
	}
	mapping, err := unmarshalVirtualPageMapPayload(payload)
	if err != nil {
		return VirtualPageMap{}, err
	}
	if err := mapping.Validate(contentObjects); err != nil {
		return VirtualPageMap{}, err
	}
	return mapping, nil
}

// CanonicalContentPlacementMapBytes validates and returns the exact
// deterministic V7 ContentPlacementMap envelope. A later V7 active root is
// expected to bind its exact length and SHA-256 after writing an inactive A/B
// slot; this function does not publish or select either slot.
func CanonicalContentPlacementMapBytes(
	mapping ContentPlacementMap,
	contentObjects []ContentObject,
) ([]byte, error) {
	if err := mapping.Validate(contentObjects); err != nil {
		return nil, err
	}
	payload, err := marshalContentPlacementMapPayload(mapping)
	if err != nil {
		return nil, err
	}
	return marshalContentMappingEnvelope(contentPlacementMapEnvelopeSpec, payload)
}

// CanonicalContentPlacementMapSize returns the complete canonical envelope
// length, including the fixed 64-byte V7 mapping header.
func CanonicalContentPlacementMapSize(
	mapping ContentPlacementMap,
	contentObjects []ContentObject,
) (uint64, error) {
	encoded, err := CanonicalContentPlacementMapBytes(mapping, contentObjects)
	if err != nil {
		return 0, err
	}
	return uint64(len(encoded)), nil
}

// DecodeContentPlacementMap accepts exactly one complete V7 placement-map
// envelope and validates exact coverage of all eligible content-object pages.
func DecodeContentPlacementMap(
	data []byte,
	contentObjects []ContentObject,
) (ContentPlacementMap, error) {
	payload, err := parseContentMappingEnvelope(contentPlacementMapEnvelopeSpec, data)
	if err != nil {
		return ContentPlacementMap{}, err
	}
	mapping, err := unmarshalContentPlacementMapPayload(payload)
	if err != nil {
		return ContentPlacementMap{}, err
	}
	if err := mapping.Validate(contentObjects); err != nil {
		return ContentPlacementMap{}, err
	}
	return mapping, nil
}

// ContentPlacementMapEnvelopeExactLengthFromHeader validates exactly one
// fixed TRCPM007 envelope header and returns the complete envelope length
// declared by that header. capacityBytes is the non-zero size of the storage
// object from which recovery will read the envelope.
//
// This function validates only header integrity and bounds. It cannot validate
// the declared payload CRC-32C without the payload; after reading exactly the
// returned length, callers must pass the complete envelope to
// DecodeContentPlacementMap.
func ContentPlacementMapEnvelopeExactLengthFromHeader(
	header []byte,
	capacityBytes uint64,
) (uint64, error) {
	return contentMappingEnvelopeExactLengthFromHeader(
		contentPlacementMapEnvelopeSpec, header, capacityBytes)
}

func marshalVirtualPageMapPayload(mapping VirtualPageMap) ([]byte, error) {
	encoder := newContentMappingEncoder()
	encoder.text(mapping.VirtualPageMapID)
	encoder.u64(mapping.Version)
	encoder.u64(mapping.PageSize)
	encoder.count(len(mapping.Runs))
	for _, run := range mapping.Runs {
		encoder.u32(run.PagesImageID)
		encoder.u64(run.StartVAddr)
		encoder.u64(run.PageCount)
		encoder.u64(run.ContentObjectID)
		encoder.u64(run.ObjectPageIndex)
	}
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalVirtualPageMapPayload(payload []byte) (VirtualPageMap, error) {
	decoder := newContentMappingDecoder(payload)
	mapping := VirtualPageMap{}
	var err error
	if mapping.VirtualPageMapID, err = decoder.text(); err != nil {
		return VirtualPageMap{}, contentMappingDecodeError("VirtualPageMap ID", err)
	}
	if mapping.Version, err = decoder.u64(); err != nil {
		return VirtualPageMap{}, contentMappingDecodeError("VirtualPageMap version", err)
	}
	if mapping.PageSize, err = decoder.u64(); err != nil {
		return VirtualPageMap{}, contentMappingDecodeError("VirtualPageMap page size", err)
	}
	count, err := decoder.count("VirtualPageMap runs", 36)
	if err != nil {
		return VirtualPageMap{}, err
	}
	mapping.Runs = make([]VirtualPageMapRun, count)
	for index := range mapping.Runs {
		run := &mapping.Runs[index]
		if run.PagesImageID, err = decoder.u32(); err != nil {
			return VirtualPageMap{}, contentMappingDecodeError("pages image ID", err)
		}
		if run.StartVAddr, err = decoder.u64(); err != nil {
			return VirtualPageMap{}, contentMappingDecodeError("virtual address", err)
		}
		if run.PageCount, err = decoder.u64(); err != nil {
			return VirtualPageMap{}, contentMappingDecodeError("virtual page count", err)
		}
		if run.ContentObjectID, err = decoder.u64(); err != nil {
			return VirtualPageMap{}, contentMappingDecodeError("content object ID", err)
		}
		if run.ObjectPageIndex, err = decoder.u64(); err != nil {
			return VirtualPageMap{}, contentMappingDecodeError("object page index", err)
		}
	}
	if err := decoder.done(); err != nil {
		return VirtualPageMap{}, err
	}
	return mapping, nil
}

func marshalContentPlacementMapPayload(mapping ContentPlacementMap) ([]byte, error) {
	encoder := newContentMappingEncoder()
	encoder.text(mapping.ContentPlacementMapID)
	encoder.u64(mapping.Version)
	encoder.u64(mapping.PageSize)
	encoder.count(len(mapping.Devices))
	for _, device := range mapping.Devices {
		encoder.text(device.DeviceUUID)
		encoder.text(device.OwnerID)
		encoder.u64(device.OwnerEpoch)
		encoder.u64(device.DataPageCount)
	}
	encoder.count(len(mapping.Runs))
	for _, run := range mapping.Runs {
		encoder.u64(run.ContentObjectID)
		encoder.u64(run.ObjectPageIndex)
		encoder.u64(run.PageCount)
		encoder.u32(run.DeviceIndex)
		encoder.u64(run.AllocationRecordID)
		encoder.u64(run.DataPageIndex)
	}
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalContentPlacementMapPayload(payload []byte) (ContentPlacementMap, error) {
	decoder := newContentMappingDecoder(payload)
	mapping := ContentPlacementMap{}
	var err error
	if mapping.ContentPlacementMapID, err = decoder.text(); err != nil {
		return ContentPlacementMap{}, contentMappingDecodeError("ContentPlacementMap ID", err)
	}
	if mapping.Version, err = decoder.u64(); err != nil {
		return ContentPlacementMap{}, contentMappingDecodeError("ContentPlacementMap version", err)
	}
	if mapping.PageSize, err = decoder.u64(); err != nil {
		return ContentPlacementMap{}, contentMappingDecodeError("ContentPlacementMap page size", err)
	}
	deviceCount, err := decoder.count("ContentPlacementMap devices", 24)
	if err != nil {
		return ContentPlacementMap{}, err
	}
	mapping.Devices = make([]Device, deviceCount)
	for index := range mapping.Devices {
		device := &mapping.Devices[index]
		if device.DeviceUUID, err = decoder.text(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("device UUID", err)
		}
		if device.OwnerID, err = decoder.text(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("device Owner ID", err)
		}
		if device.OwnerEpoch, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("device Owner epoch", err)
		}
		if device.DataPageCount, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("device page count", err)
		}
	}
	runCount, err := decoder.count("ContentPlacementMap runs", 44)
	if err != nil {
		return ContentPlacementMap{}, err
	}
	mapping.Runs = make([]ContentPlacementRun, runCount)
	for index := range mapping.Runs {
		run := &mapping.Runs[index]
		if run.ContentObjectID, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("content object ID", err)
		}
		if run.ObjectPageIndex, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("object page index", err)
		}
		if run.PageCount, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("placement page count", err)
		}
		if run.DeviceIndex, err = decoder.u32(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("device index", err)
		}
		if run.AllocationRecordID, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("allocation record ID", err)
		}
		if run.DataPageIndex, err = decoder.u64(); err != nil {
			return ContentPlacementMap{}, contentMappingDecodeError("data page index", err)
		}
	}
	if err := decoder.done(); err != nil {
		return ContentPlacementMap{}, err
	}
	return mapping, nil
}

func marshalContentMappingEnvelope(
	spec contentMappingEnvelopeSpec,
	payload []byte,
) ([]byte, error) {
	if uint64(len(payload)) > maxContentMappingPayloadBytes {
		return nil, contentMappingInvalidf(
			"%s payload is %d bytes, limit is %d",
			spec.name, len(payload), maxContentMappingPayloadBytes)
	}
	total := ContentMappingEnvelopeHeaderBytes + uint64(len(payload))
	if total > MaxContentMappingBytes {
		return nil, contentMappingInvalidf(
			"%s envelope is %d bytes, limit is %d",
			spec.name, total, MaxContentMappingBytes)
	}
	out := make([]byte, int(total))
	copy(out[0:8], spec.magic[:])
	binary.LittleEndian.PutUint32(out[8:12], ContentMappingVersion)
	binary.LittleEndian.PutUint32(out[12:16], contentMappingHeaderSize)
	copy(out[16:40], spec.domain[:])
	binary.LittleEndian.PutUint64(out[40:48], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[48:52], checksumCRC32C(payload))
	// 52:56 is the mandatory feature mask. Zero is the only V7 value.
	// 56:60 is header integrity. 60:64 is reserved and remains zero.
	copy(out[contentMappingHeaderSize:], payload)
	binary.LittleEndian.PutUint32(
		out[56:60], contentMappingHeaderCRC(out[:contentMappingHeaderSize]))
	return out, nil
}

func parseContentMappingEnvelope(
	spec contentMappingEnvelopeSpec,
	data []byte,
) ([]byte, error) {
	if len(data) < int(contentMappingHeaderSize) {
		return nil, fmt.Errorf(
			"%s envelope is truncated: %w", spec.name, ErrCorruptContentMapping)
	}
	total, err := contentMappingEnvelopeExactLengthFromHeader(
		spec, data[:contentMappingHeaderSize], MaxContentMappingBytes)
	if err != nil {
		return nil, err
	}
	if total != uint64(len(data)) {
		return nil, fmt.Errorf(
			"%s envelope is %d bytes, header declares %d: %w",
			spec.name, len(data), total, ErrCorruptContentMapping)
	}
	payload := data[contentMappingHeaderSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[48:52])
	if got := checksumCRC32C(payload); got != wantPayloadCRC {
		return nil, fmt.Errorf(
			"%s payload checksum %#x does not match %#x: %w",
			spec.name, got, wantPayloadCRC, ErrCorruptContentMapping)
	}
	return append([]byte(nil), payload...), nil
}

func contentMappingEnvelopeExactLengthFromHeader(
	spec contentMappingEnvelopeSpec,
	header []byte,
	capacityBytes uint64,
) (uint64, error) {
	if uint64(len(header)) != ContentMappingEnvelopeHeaderBytes {
		return 0, fmt.Errorf(
			"%s header is %d bytes, want exactly %d: %w",
			spec.name, len(header), ContentMappingEnvelopeHeaderBytes,
			ErrCorruptContentMapping)
	}
	var magic [8]byte
	copy(magic[:], header[0:8])
	if magic != spec.magic {
		return 0, fmt.Errorf(
			"%s magic %q is not %q: %w",
			spec.name, magic, spec.magic, ErrWrongContentMappingFormat)
	}
	if version := binary.LittleEndian.Uint32(header[8:12]); version != ContentMappingVersion {
		return 0, fmt.Errorf(
			"%s version %d is not %d: %w",
			spec.name, version, ContentMappingVersion, ErrWrongContentMappingFormat)
	}
	if size := binary.LittleEndian.Uint32(header[12:16]); size != contentMappingHeaderSize {
		return 0, fmt.Errorf(
			"%s header size %d is not %d: %w",
			spec.name, size, contentMappingHeaderSize, ErrWrongContentMappingFormat)
	}
	var domain [contentMappingDomainFieldBytes]byte
	copy(domain[:], header[16:40])
	if domain != spec.domain {
		return 0, fmt.Errorf(
			"%s domain does not match %q: %w",
			spec.name, contentMappingDomainString(spec.domain), ErrWrongContentMappingFormat)
	}
	if flags := binary.LittleEndian.Uint32(header[52:56]); flags != 0 {
		return 0, fmt.Errorf(
			"%s has unknown mandatory flags %#x: %w",
			spec.name, flags, ErrWrongContentMappingFormat)
	}
	if !allZero(header[60:contentMappingHeaderSize]) {
		return 0, fmt.Errorf(
			"%s reserved header bytes are non-zero: %w",
			spec.name, ErrWrongContentMappingFormat)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(header[56:60])
	if got := contentMappingHeaderCRC(header); got != wantHeaderCRC {
		return 0, fmt.Errorf(
			"%s header checksum %#x does not match %#x: %w",
			spec.name, got, wantHeaderCRC, ErrCorruptContentMapping)
	}
	payloadLength := binary.LittleEndian.Uint64(header[40:48])
	if payloadLength > ^uint64(0)-ContentMappingEnvelopeHeaderBytes {
		return 0, fmt.Errorf(
			"%s envelope length overflows for payload %d: %w",
			spec.name, payloadLength, ErrCorruptContentMapping)
	}
	total := ContentMappingEnvelopeHeaderBytes + payloadLength
	if payloadLength > maxContentMappingPayloadBytes || total > MaxContentMappingBytes {
		return 0, fmt.Errorf(
			"%s payload length %d exceeds %d: %w",
			spec.name, payloadLength, maxContentMappingPayloadBytes,
			ErrCorruptContentMapping)
	}
	if capacityBytes == 0 {
		return 0, fmt.Errorf(
			"%s storage capacity is zero: %w", spec.name, ErrCorruptContentMapping)
	}
	if total > capacityBytes {
		return 0, fmt.Errorf(
			"%s envelope length %d exceeds storage capacity %d: %w",
			spec.name, total, capacityBytes, ErrCorruptContentMapping)
	}
	return total, nil
}

func contentMappingHeaderCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= int(contentMappingHeaderSize) {
		for index := 56; index < 60; index++ {
			copyForCRC[index] = 0
		}
	}
	return checksumCRC32C(copyForCRC)
}

func contentMappingMagic(value string) [8]byte {
	var result [8]byte
	copy(result[:], []byte(value))
	return result
}

func contentMappingDomain(value string) [contentMappingDomainFieldBytes]byte {
	var result [contentMappingDomainFieldBytes]byte
	copy(result[:], []byte(value))
	return result
}

func contentMappingDomainString(value [contentMappingDomainFieldBytes]byte) string {
	length := bytes.IndexByte(value[:], 0)
	if length < 0 {
		length = len(value)
	}
	return string(value[:length])
}

type contentMappingEncoder struct {
	buffer bytes.Buffer
	err    error
}

func newContentMappingEncoder() *contentMappingEncoder {
	return &contentMappingEncoder{}
}

func (e *contentMappingEncoder) bytes() []byte {
	return append([]byte(nil), e.buffer.Bytes()...)
}

func (e *contentMappingEncoder) fixed(value []byte) {
	if e.err != nil {
		return
	}
	if uint64(len(value)) > maxContentMappingPayloadBytes-uint64(e.buffer.Len()) {
		e.err = contentMappingInvalidf(
			"content mapping payload exceeds %d bytes", maxContentMappingPayloadBytes)
		return
	}
	_, e.err = e.buffer.Write(value)
}

func (e *contentMappingEncoder) u32(value uint32) {
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	e.fixed(data[:])
}

func (e *contentMappingEncoder) u64(value uint64) {
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	e.fixed(data[:])
}

func (e *contentMappingEncoder) count(value int) {
	if value < 0 || value > maxCollectionElements {
		if e.err == nil {
			e.err = contentMappingInvalidf(
				"content mapping collection count %d exceeds %d",
				value, maxCollectionElements)
		}
		return
	}
	e.u32(uint32(value))
}

func (e *contentMappingEncoder) text(value string) {
	if len(value) > MaxIdentityBytes {
		if e.err == nil {
			e.err = contentMappingInvalidf(
				"content mapping text is %d bytes, limit is %d",
				len(value), MaxIdentityBytes)
		}
		return
	}
	e.u32(uint32(len(value)))
	e.fixed([]byte(value))
}

type contentMappingDecoder struct {
	reader *bytes.Reader
}

func newContentMappingDecoder(payload []byte) *contentMappingDecoder {
	return &contentMappingDecoder{reader: bytes.NewReader(payload)}
}

func (d *contentMappingDecoder) fixed(size int) ([]byte, error) {
	if size < 0 || int64(size) > int64(d.reader.Len()) {
		return nil, fmt.Errorf(
			"content mapping field needs %d bytes, %d remain: %w",
			size, d.reader.Len(), ErrCorruptContentMapping)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(d.reader, data); err != nil {
		return nil, fmt.Errorf(
			"read content mapping payload: %v: %w", err, ErrCorruptContentMapping)
	}
	return data, nil
}

func (d *contentMappingDecoder) u32() (uint32, error) {
	data, err := d.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (d *contentMappingDecoder) u64() (uint64, error) {
	data, err := d.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (d *contentMappingDecoder) count(name string, minimumBytes int) (int, error) {
	value, err := d.u32()
	if err != nil {
		return 0, contentMappingDecodeError(name+" count", err)
	}
	if value > maxCollectionElements {
		return 0, fmt.Errorf(
			"%s count %d exceeds %d: %w",
			name, value, maxCollectionElements, ErrCorruptContentMapping)
	}
	if minimumBytes > 0 && uint64(value) > uint64(d.reader.Len())/uint64(minimumBytes) {
		return 0, fmt.Errorf(
			"%s count %d cannot fit in remaining payload: %w",
			name, value, ErrCorruptContentMapping)
	}
	return int(value), nil
}

func (d *contentMappingDecoder) text() (string, error) {
	length, err := d.u32()
	if err != nil {
		return "", err
	}
	if length > MaxIdentityBytes {
		return "", fmt.Errorf(
			"content mapping text length %d exceeds %d: %w",
			length, MaxIdentityBytes, ErrCorruptContentMapping)
	}
	data, err := d.fixed(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf(
			"content mapping text is not valid UTF-8: %w",
			ErrCorruptContentMapping)
	}
	return string(data), nil
}

func (d *contentMappingDecoder) done() error {
	if d.reader.Len() != 0 {
		return fmt.Errorf(
			"content mapping payload has %d trailing bytes: %w",
			d.reader.Len(), ErrCorruptContentMapping)
	}
	return nil
}

func contentMappingDecodeError(field string, err error) error {
	return fmt.Errorf("decode content mapping %s: %w", field, err)
}
