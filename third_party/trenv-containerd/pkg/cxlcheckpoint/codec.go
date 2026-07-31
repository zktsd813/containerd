package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"unicode/utf8"
)

// TRPUB006 uses CRC-32C/Castagnoli to detect corruption of its envelope header
// and payload. The same polynomial is used by the immutable 4 KiB content
// fingerprint contract for Intel DML COPY_CRC, but the values and protected
// byte ranges are separate. Neither CRC provides authenticity. The committed
// root's SHA-256 device-table digest is another, separately scoped value.
const (
	envelopeHeaderSize uint32 = 64
)

var crc32cTable = crc32.MakeTable(crc32.Castagnoli)

// Encode validates and deterministically encodes one strict TRPUB006
// publication. Slice order is canonical and therefore part of the contract.
func Encode(publication Publication) ([]byte, error) {
	if err := publication.Validate(); err != nil {
		return nil, err
	}
	payload, err := marshalPayload(publication)
	if err != nil {
		return nil, err
	}
	encoded, err := marshalEnvelope(payload)
	if err != nil {
		return nil, err
	}
	if err := validatePublicationEnvelopeCapacity(publication, uint64(len(encoded))); err != nil {
		return nil, err
	}
	return encoded, nil
}

// EncodeForStorage returns both the exact Scheduler-addressed TRPUB006 bytes
// and the zero-padded bytes that the producer writes to the complete reserved
// publication slot. The PageID runs cover only the exact envelope pages, so a
// larger capacity reservation never broadens the discoverable root.
func EncodeForStorage(publication Publication) (PublicationStorage, error) {
	encoded, err := Encode(publication)
	if err != nil {
		return PublicationStorage{}, err
	}
	slot, err := publication.publicationContentSlot()
	if err != nil {
		return PublicationStorage{}, err
	}
	capacity, ok := mulLong(slot.PageCount, PageSize)
	if !ok || capacity > uint64(math.MaxInt) {
		return PublicationStorage{}, invalidf("publication slot exceeds host address space")
	}
	requiredPages := (uint64(len(encoded)) + PageSize - 1) / PageSize
	runs, err := publication.publicationPageRuns(slot, requiredPages)
	if err != nil {
		return PublicationStorage{}, err
	}
	padded := make([]byte, int(capacity))
	copy(padded, encoded)
	return PublicationStorage{
		ContentObjectID:  slot.ObjectID,
		LogicalPageStart: slot.LogicalPageStart,
		CapacityPages:    slot.PageCount,
		ExactBytes:       append([]byte(nil), encoded...),
		PaddedBytes:      padded,
		SHA256:           sha256.Sum256(encoded),
		PageRuns:         runs,
	}, nil
}

// Decode accepts only a complete, checksummed TRPUB006 envelope. Legacy
// publications, unknown mandatory flags, non-zero reserved bytes, and trailing
// bytes are rejected rather than treated as an optional extension.
func Decode(data []byte) (Publication, error) {
	payload, err := parseEnvelope(data)
	if err != nil {
		return Publication{}, err
	}
	publication, err := unmarshalPayload(payload)
	if err != nil {
		return Publication{}, err
	}
	if err := publication.Validate(); err != nil {
		return Publication{}, err
	}
	if err := validatePublicationEnvelopeCapacity(publication, uint64(len(data))); err != nil {
		return Publication{}, err
	}
	return publication, nil
}

func validatePublicationEnvelopeCapacity(publication Publication, encodedBytes uint64) error {
	slot, err := publication.publicationContentSlot()
	if err != nil {
		return err
	}
	capacity, ok := mulLong(slot.PageCount, PageSize)
	if !ok || encodedBytes == 0 || encodedBytes > capacity {
		return invalidf(
			"encoded publication is %d bytes, publication slot capacity is %d",
			encodedBytes, capacity)
	}
	return nil
}

func marshalEnvelope(payload []byte) ([]byte, error) {
	if len(payload) > MaxPayloadBytes {
		return nil, invalidf("publication payload is %d bytes, limit is %d", len(payload), MaxPayloadBytes)
	}
	if uint64(len(payload)) > MaxSignedLong {
		return nil, invalidf("publication payload exceeds signed-Long ABI")
	}
	total := uint64(envelopeHeaderSize) + uint64(len(payload))
	if total > uint64(math.MaxInt) {
		return nil, invalidf("publication envelope exceeds host address space")
	}
	out := make([]byte, int(total))
	copy(out[0:8], publicationMagic[:])
	binary.LittleEndian.PutUint32(out[8:12], Version)
	binary.LittleEndian.PutUint32(out[12:16], envelopeHeaderSize)
	binary.LittleEndian.PutUint64(out[16:24], uint64(len(payload)))
	binary.LittleEndian.PutUint32(out[24:28], checksumCRC32C(payload))
	// 28:32 is the mandatory feature mask. Zero is the only V6 value.
	// 32:36 is header integrity. 36:64 is reserved and remains zero.
	copy(out[envelopeHeaderSize:], payload)
	binary.LittleEndian.PutUint32(out[32:36], headerCRC(out[:envelopeHeaderSize]))
	return out, nil
}

func parseEnvelope(data []byte) ([]byte, error) {
	if len(data) < int(envelopeHeaderSize) {
		return nil, fmt.Errorf("publication envelope is truncated: %w", ErrCorrupt)
	}
	var magic [8]byte
	copy(magic[:], data[:8])
	if magic != publicationMagic {
		return nil, fmt.Errorf("publication magic %q is not %q: %w", magic, publicationMagic, ErrWrongFormat)
	}
	if version := binary.LittleEndian.Uint32(data[8:12]); version != Version {
		return nil, fmt.Errorf("publication version %d is not %d: %w", version, Version, ErrWrongFormat)
	}
	if size := binary.LittleEndian.Uint32(data[12:16]); size != envelopeHeaderSize {
		return nil, fmt.Errorf("publication header size %d is not %d: %w", size, envelopeHeaderSize, ErrWrongFormat)
	}
	if flags := binary.LittleEndian.Uint32(data[28:32]); flags != 0 {
		return nil, fmt.Errorf("unknown mandatory publication flags %#x: %w", flags, ErrWrongFormat)
	}
	if !allZero(data[36:envelopeHeaderSize]) {
		return nil, fmt.Errorf("publication reserved header bytes are non-zero: %w", ErrWrongFormat)
	}
	wantHeaderCRC := binary.LittleEndian.Uint32(data[32:36])
	if got := headerCRC(data[:envelopeHeaderSize]); got != wantHeaderCRC {
		return nil, fmt.Errorf("publication header checksum %#x does not match %#x: %w", got, wantHeaderCRC, ErrCorrupt)
	}
	payloadLength := binary.LittleEndian.Uint64(data[16:24])
	if payloadLength > MaxSignedLong || payloadLength > MaxPayloadBytes {
		return nil, fmt.Errorf("publication payload length %d exceeds its limit: %w", payloadLength, ErrCorrupt)
	}
	total := uint64(envelopeHeaderSize) + payloadLength
	if total != uint64(len(data)) {
		return nil, fmt.Errorf("publication is %d bytes, header declares %d: %w", len(data), total, ErrCorrupt)
	}
	payload := data[envelopeHeaderSize:]
	wantPayloadCRC := binary.LittleEndian.Uint32(data[24:28])
	if got := checksumCRC32C(payload); got != wantPayloadCRC {
		return nil, fmt.Errorf("publication payload checksum %#x does not match %#x: %w", got, wantPayloadCRC, ErrCorrupt)
	}
	return append([]byte(nil), payload...), nil
}

func headerCRC(header []byte) uint32 {
	copyForCRC := append([]byte(nil), header...)
	if len(copyForCRC) >= 36 {
		for index := 32; index < 36; index++ {
			copyForCRC[index] = 0
		}
	}
	return checksumCRC32C(copyForCRC)
}

func checksumCRC32C(data []byte) uint32 {
	return crc32.Checksum(data, crc32cTable)
}

func marshalPayload(publication Publication) ([]byte, error) {
	encoder := newPayloadEncoder()
	encoder.text(publication.CheckpointID)
	encodeDevices(encoder, publication.Devices)
	encodeContentObjects(encoder, publication.ContentObjects)
	encodeAllocation(encoder, publication.Allocation)
	encodeMMTemplate(encoder, publication.MMTemplate)
	encodePageMap(encoder, publication.PageMap)
	encodeArtifacts(encoder, publication.Artifacts)
	encodeMappingSlots(encoder, publication.MappingSlots)
	encodeRoot(encoder, publication.Root)
	if encoder.err != nil {
		return nil, encoder.err
	}
	return encoder.bytes(), nil
}

func unmarshalPayload(payload []byte) (Publication, error) {
	decoder := newPayloadDecoder(payload)
	publication := Publication{}
	var err error
	if publication.CheckpointID, err = decoder.text(); err != nil {
		return Publication{}, decodeError("checkpoint ID", err)
	}
	if publication.Devices, err = decodeDevices(decoder); err != nil {
		return Publication{}, err
	}
	if publication.ContentObjects, err = decodeContentObjects(decoder); err != nil {
		return Publication{}, err
	}
	if publication.Allocation, err = decodeAllocation(decoder); err != nil {
		return Publication{}, err
	}
	if publication.MMTemplate, err = decodeMMTemplate(decoder); err != nil {
		return Publication{}, err
	}
	if publication.PageMap, err = decodePageMap(decoder); err != nil {
		return Publication{}, err
	}
	if publication.Artifacts, err = decodeArtifacts(decoder); err != nil {
		return Publication{}, err
	}
	if publication.MappingSlots, err = decodeMappingSlots(decoder); err != nil {
		return Publication{}, err
	}
	if publication.Root, err = decodeRoot(decoder); err != nil {
		return Publication{}, err
	}
	if err := decoder.done(); err != nil {
		return Publication{}, err
	}
	return publication, nil
}

func encodeDevices(encoder *payloadEncoder, devices []Device) {
	encoder.count(len(devices))
	for _, device := range devices {
		encoder.text(device.DeviceUUID)
		encoder.text(device.OwnerID)
		encoder.u64(device.OwnerEpoch)
		encoder.u64(device.DataPageCount)
	}
}

func decodeDevices(decoder *payloadDecoder) ([]Device, error) {
	count, err := decoder.count("devices", 24)
	if err != nil {
		return nil, err
	}
	devices := make([]Device, count)
	for index := range devices {
		if devices[index].DeviceUUID, err = decoder.text(); err != nil {
			return nil, decodeError("device UUID", err)
		}
		if devices[index].OwnerID, err = decoder.text(); err != nil {
			return nil, decodeError("device Owner ID", err)
		}
		if devices[index].OwnerEpoch, err = decoder.u64(); err != nil {
			return nil, err
		}
		if devices[index].DataPageCount, err = decoder.u64(); err != nil {
			return nil, err
		}
	}
	return devices, nil
}

func encodeContentObjects(encoder *payloadEncoder, objects []ContentObject) {
	encoder.count(len(objects))
	for _, object := range objects {
		encoder.u64(object.ObjectID)
		encoder.u8(uint8(object.Kind))
		encoder.u64(object.ByteLength)
		encoder.u64(object.LogicalPageStart)
		encoder.u64(object.PageCount)
	}
}

func decodeContentObjects(decoder *payloadDecoder) ([]ContentObject, error) {
	count, err := decoder.count("content objects", 33)
	if err != nil {
		return nil, err
	}
	objects := make([]ContentObject, count)
	for index := range objects {
		if objects[index].ObjectID, err = decoder.u64(); err != nil {
			return nil, err
		}
		kind, err := decoder.u8()
		if err != nil {
			return nil, err
		}
		objects[index].Kind = ContentKind(kind)
		if objects[index].ByteLength, err = decoder.u64(); err != nil {
			return nil, err
		}
		if objects[index].LogicalPageStart, err = decoder.u64(); err != nil {
			return nil, err
		}
		if objects[index].PageCount, err = decoder.u64(); err != nil {
			return nil, err
		}
	}
	return objects, nil
}

func encodeAllocation(encoder *payloadEncoder, allocation InitialAllocation) {
	encoder.text(allocation.OwnerID)
	encoder.u64(allocation.OwnerEpoch)
	encoder.u64(allocation.AllocationRecordID)
	encoder.u64(allocation.TotalPages)
	encoder.count(len(allocation.Extents))
	for _, extent := range allocation.Extents {
		encoder.text(extent.DeviceUUID)
		encoder.u64(extent.StartDataPageIndex)
		encoder.u64(extent.PageCount)
		encoder.u64(extent.LogicalPageStart)
	}
}

func decodeAllocation(decoder *payloadDecoder) (InitialAllocation, error) {
	allocation := InitialAllocation{}
	var err error
	if allocation.OwnerID, err = decoder.text(); err != nil {
		return InitialAllocation{}, decodeError("allocation Owner ID", err)
	}
	if allocation.OwnerEpoch, err = decoder.u64(); err != nil {
		return InitialAllocation{}, err
	}
	if allocation.AllocationRecordID, err = decoder.u64(); err != nil {
		return InitialAllocation{}, err
	}
	if allocation.TotalPages, err = decoder.u64(); err != nil {
		return InitialAllocation{}, err
	}
	count, err := decoder.count("allocation extents", 28)
	if err != nil {
		return InitialAllocation{}, err
	}
	allocation.Extents = make([]AllocationExtent, count)
	for index := range allocation.Extents {
		if allocation.Extents[index].DeviceUUID, err = decoder.text(); err != nil {
			return InitialAllocation{}, decodeError("extent device UUID", err)
		}
		if allocation.Extents[index].StartDataPageIndex, err = decoder.u64(); err != nil {
			return InitialAllocation{}, err
		}
		if allocation.Extents[index].PageCount, err = decoder.u64(); err != nil {
			return InitialAllocation{}, err
		}
		if allocation.Extents[index].LogicalPageStart, err = decoder.u64(); err != nil {
			return InitialAllocation{}, err
		}
	}
	return allocation, nil
}

func encodeMMTemplate(encoder *payloadEncoder, template MMTemplate) {
	encoder.text(template.TemplateID)
	encoder.u64(template.ContentObjectID)
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
		encoder.u64(vma.PageMapRunStart)
		encoder.u64(vma.PageMapRunCount)
	}
}

func decodeMMTemplate(decoder *payloadDecoder) (MMTemplate, error) {
	template := MMTemplate{}
	var err error
	if template.TemplateID, err = decoder.text(); err != nil {
		return MMTemplate{}, decodeError("MM template ID", err)
	}
	if template.ContentObjectID, err = decoder.u64(); err != nil {
		return MMTemplate{}, err
	}
	if template.RuntimeCompatibilityID, err = decoder.text(); err != nil {
		return MMTemplate{}, decodeError("runtime compatibility ID", err)
	}
	if template.PageSize, err = decoder.u64(); err != nil {
		return MMTemplate{}, err
	}
	// A VMA is one uint32 pages-image identity, six uint64 values, and one
	// uint8 backing kind.
	count, err := decoder.count("VMAs", 53)
	if err != nil {
		return MMTemplate{}, err
	}
	template.VMAs = make([]VMA, count)
	for index := range template.VMAs {
		vma := &template.VMAs[index]
		if vma.PagesImageID, err = decoder.u32(); err != nil {
			return MMTemplate{}, err
		}
		if vma.StartVAddr, err = decoder.u64(); err != nil {
			return MMTemplate{}, err
		}
		if vma.EndVAddr, err = decoder.u64(); err != nil {
			return MMTemplate{}, err
		}
		if vma.ProtectionFlags, err = decoder.u64(); err != nil {
			return MMTemplate{}, err
		}
		if vma.MappingFlags, err = decoder.u64(); err != nil {
			return MMTemplate{}, err
		}
		backing, err := decoder.u8()
		if err != nil {
			return MMTemplate{}, err
		}
		vma.BackingKind = BackingKind(backing)
		if vma.PageMapRunStart, err = decoder.u64(); err != nil {
			return MMTemplate{}, err
		}
		if vma.PageMapRunCount, err = decoder.u64(); err != nil {
			return MMTemplate{}, err
		}
	}
	return template, nil
}

func encodePageMap(encoder *payloadEncoder, pageMap PageMap) {
	encoder.text(pageMap.PageMapID)
	encoder.u64(pageMap.Version)
	encoder.u64(pageMap.ContentObjectID)
	encoder.u64(pageMap.PageSize)
	encoder.count(len(pageMap.Runs))
	for _, run := range pageMap.Runs {
		encoder.u32(run.PagesImageID)
		encoder.u64(run.StartVAddr)
		encoder.u64(run.PageCount)
		encoder.text(run.FirstPage.OwnerID)
		encoder.text(run.FirstPage.DeviceUUID)
		encoder.u64(run.FirstPage.AllocationRecordID)
		encoder.u64(run.FirstPage.DataPageIndex)
	}
}

func decodePageMap(decoder *payloadDecoder) (PageMap, error) {
	pageMap := PageMap{}
	var err error
	if pageMap.PageMapID, err = decoder.text(); err != nil {
		return PageMap{}, decodeError("PageMap ID", err)
	}
	if pageMap.Version, err = decoder.u64(); err != nil {
		return PageMap{}, err
	}
	if pageMap.ContentObjectID, err = decoder.u64(); err != nil {
		return PageMap{}, err
	}
	if pageMap.PageSize, err = decoder.u64(); err != nil {
		return PageMap{}, err
	}
	count, err := decoder.count("PageMap runs", 44)
	if err != nil {
		return PageMap{}, err
	}
	pageMap.Runs = make([]PageMapRun, count)
	for index := range pageMap.Runs {
		run := &pageMap.Runs[index]
		if run.PagesImageID, err = decoder.u32(); err != nil {
			return PageMap{}, err
		}
		if run.StartVAddr, err = decoder.u64(); err != nil {
			return PageMap{}, err
		}
		if run.PageCount, err = decoder.u64(); err != nil {
			return PageMap{}, err
		}
		if run.FirstPage.OwnerID, err = decoder.text(); err != nil {
			return PageMap{}, decodeError("PageID Owner ID", err)
		}
		if run.FirstPage.DeviceUUID, err = decoder.text(); err != nil {
			return PageMap{}, decodeError("PageID device UUID", err)
		}
		if run.FirstPage.AllocationRecordID, err = decoder.u64(); err != nil {
			return PageMap{}, err
		}
		if run.FirstPage.DataPageIndex, err = decoder.u64(); err != nil {
			return PageMap{}, err
		}
	}
	return pageMap, nil
}

func encodeArtifacts(encoder *payloadEncoder, manifest ArtifactManifest) {
	encoder.text(manifest.ManifestID)
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
}

func decodeArtifacts(decoder *payloadDecoder) (ArtifactManifest, error) {
	manifest := ArtifactManifest{}
	var err error
	if manifest.ManifestID, err = decoder.text(); err != nil {
		return ArtifactManifest{}, decodeError("artifact manifest ID", err)
	}
	// An entry has two length prefixes, one uint8 kind, and six uint64
	// values. The variable-length path and target may both be empty at this
	// structural decoding stage; semantic validation rejects an empty path.
	count, err := decoder.count("artifact entries", 57)
	if err != nil {
		return ArtifactManifest{}, err
	}
	manifest.Entries = make([]ArtifactEntry, count)
	for index := range manifest.Entries {
		entry := &manifest.Entries[index]
		if entry.Path, err = decoder.text(); err != nil {
			return ArtifactManifest{}, decodeError("artifact path", err)
		}
		kind, err := decoder.u8()
		if err != nil {
			return ArtifactManifest{}, err
		}
		entry.Type = ArtifactType(kind)
		if entry.Mode, err = decoder.u64(); err != nil {
			return ArtifactManifest{}, err
		}
		if entry.UID, err = decoder.u64(); err != nil {
			return ArtifactManifest{}, err
		}
		if entry.GID, err = decoder.u64(); err != nil {
			return ArtifactManifest{}, err
		}
		if entry.ByteLength, err = decoder.u64(); err != nil {
			return ArtifactManifest{}, err
		}
		if entry.ContentObjectID, err = decoder.u64(); err != nil {
			return ArtifactManifest{}, err
		}
		if entry.ContentOffset, err = decoder.u64(); err != nil {
			return ArtifactManifest{}, err
		}
		if entry.LinkTarget, err = decoder.text(); err != nil {
			return ArtifactManifest{}, decodeError("artifact link target", err)
		}
	}
	return manifest, nil
}

func encodeMappingSlots(encoder *payloadEncoder, slots MappingSlots) {
	for _, slot := range []MappingSlot{slots.A, slots.B} {
		encoder.u8(uint8(slot.Name))
		encoder.u64(slot.ContentObjectID)
		encoder.u64(slot.CapacityPages)
	}
}

func decodeMappingSlots(decoder *payloadDecoder) (MappingSlots, error) {
	slots := MappingSlots{}
	for _, slot := range []*MappingSlot{&slots.A, &slots.B} {
		name, err := decoder.u8()
		if err != nil {
			return MappingSlots{}, err
		}
		slot.Name = MappingSlotName(name)
		if slot.ContentObjectID, err = decoder.u64(); err != nil {
			return MappingSlots{}, err
		}
		if slot.CapacityPages, err = decoder.u64(); err != nil {
			return MappingSlots{}, err
		}
	}
	return slots, nil
}

func encodeRoot(encoder *payloadEncoder, root CommittedRoot) {
	encoder.u8(uint8(root.State))
	encoder.text(root.RootID)
	encoder.text(root.CheckpointID)
	encoder.text(root.OwnerID)
	encoder.u64(root.AllocationRecordID)
	encoder.text(root.MMTemplateID)
	encoder.text(root.PageMapID)
	encoder.u64(root.PageMapVersion)
	encoder.text(root.ArtifactManifestID)
	encoder.u8(uint8(root.ActiveMappingSlot))
	encoder.fixed(root.DeviceTableDigest[:])
	encoder.u64(root.PublicationSequence)
}

func decodeRoot(decoder *payloadDecoder) (CommittedRoot, error) {
	root := CommittedRoot{}
	state, err := decoder.u8()
	if err != nil {
		return CommittedRoot{}, err
	}
	root.State = RootState(state)
	if root.RootID, err = decoder.text(); err != nil {
		return CommittedRoot{}, decodeError("root ID", err)
	}
	if root.CheckpointID, err = decoder.text(); err != nil {
		return CommittedRoot{}, decodeError("root checkpoint ID", err)
	}
	if root.OwnerID, err = decoder.text(); err != nil {
		return CommittedRoot{}, decodeError("root Owner ID", err)
	}
	if root.AllocationRecordID, err = decoder.u64(); err != nil {
		return CommittedRoot{}, err
	}
	if root.MMTemplateID, err = decoder.text(); err != nil {
		return CommittedRoot{}, decodeError("root MM template ID", err)
	}
	if root.PageMapID, err = decoder.text(); err != nil {
		return CommittedRoot{}, decodeError("root PageMap ID", err)
	}
	if root.PageMapVersion, err = decoder.u64(); err != nil {
		return CommittedRoot{}, err
	}
	if root.ArtifactManifestID, err = decoder.text(); err != nil {
		return CommittedRoot{}, decodeError("root artifact manifest ID", err)
	}
	active, err := decoder.u8()
	if err != nil {
		return CommittedRoot{}, err
	}
	root.ActiveMappingSlot = MappingSlotName(active)
	digest, err := decoder.fixed(len(root.DeviceTableDigest))
	if err != nil {
		return CommittedRoot{}, err
	}
	copy(root.DeviceTableDigest[:], digest)
	if root.PublicationSequence, err = decoder.u64(); err != nil {
		return CommittedRoot{}, err
	}
	return root, nil
}

type payloadEncoder struct {
	buffer bytes.Buffer
	err    error
}

func newPayloadEncoder() *payloadEncoder {
	return &payloadEncoder{}
}

func (e *payloadEncoder) bytes() []byte {
	return append([]byte(nil), e.buffer.Bytes()...)
}

func (e *payloadEncoder) fixed(value []byte) {
	if e.err != nil {
		return
	}
	if len(value) > MaxPayloadBytes-e.buffer.Len() {
		e.err = invalidf("publication payload exceeds %d bytes", MaxPayloadBytes)
		return
	}
	_, e.err = e.buffer.Write(value)
}

func (e *payloadEncoder) u8(value uint8) {
	e.fixed([]byte{value})
}

func (e *payloadEncoder) u32(value uint32) {
	if e.err != nil {
		return
	}
	var data [4]byte
	binary.LittleEndian.PutUint32(data[:], value)
	e.fixed(data[:])
}

func (e *payloadEncoder) u64(value uint64) {
	if e.err != nil {
		return
	}
	var data [8]byte
	binary.LittleEndian.PutUint64(data[:], value)
	e.fixed(data[:])
}

func (e *payloadEncoder) count(value int) {
	if value < 0 || value > maxCollectionElements || uint64(value) > math.MaxUint32 {
		if e.err == nil {
			e.err = invalidf("collection count %d exceeds its encoding limit", value)
		}
		return
	}
	e.u32(uint32(value))
}

func (e *payloadEncoder) text(value string) {
	if len(value) > MaxIdentityBytes || len(value) > math.MaxUint32 {
		if e.err == nil {
			e.err = invalidf("text is %d bytes, limit is %d", len(value), MaxIdentityBytes)
		}
		return
	}
	e.u32(uint32(len(value)))
	e.fixed([]byte(value))
}

type payloadDecoder struct {
	reader *bytes.Reader
}

func newPayloadDecoder(payload []byte) *payloadDecoder {
	return &payloadDecoder{reader: bytes.NewReader(payload)}
}

func (d *payloadDecoder) fixed(size int) ([]byte, error) {
	if size < 0 || int64(size) > int64(d.reader.Len()) {
		return nil, fmt.Errorf("payload field needs %d bytes, %d remain: %w", size, d.reader.Len(), ErrCorrupt)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(d.reader, data); err != nil {
		return nil, fmt.Errorf("read publication payload: %w: %v", ErrCorrupt, err)
	}
	return data, nil
}

func (d *payloadDecoder) u8() (uint8, error) {
	value, err := d.reader.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read uint8: %w: %v", ErrCorrupt, err)
	}
	return value, nil
}

func (d *payloadDecoder) u32() (uint32, error) {
	data, err := d.fixed(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

func (d *payloadDecoder) u64() (uint64, error) {
	data, err := d.fixed(8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(data), nil
}

func (d *payloadDecoder) count(name string, minimumBytes int) (int, error) {
	value, err := d.u32()
	if err != nil {
		return 0, decodeError(name+" count", err)
	}
	if value > maxCollectionElements {
		return 0, fmt.Errorf("%s count %d exceeds %d: %w", name, value, maxCollectionElements, ErrCorrupt)
	}
	if minimumBytes > 0 && uint64(value) > uint64(d.reader.Len())/uint64(minimumBytes) {
		return 0, fmt.Errorf("%s count %d cannot fit in remaining payload: %w", name, value, ErrCorrupt)
	}
	return int(value), nil
}

func (d *payloadDecoder) text() (string, error) {
	length, err := d.u32()
	if err != nil {
		return "", err
	}
	if length > MaxIdentityBytes {
		return "", fmt.Errorf("text length %d exceeds %d: %w", length, MaxIdentityBytes, ErrCorrupt)
	}
	data, err := d.fixed(int(length))
	if err != nil {
		return "", err
	}
	if !utf8.Valid(data) {
		return "", fmt.Errorf("text is not valid UTF-8: %w", ErrCorrupt)
	}
	return string(data), nil
}

func (d *payloadDecoder) done() error {
	if d.reader.Len() != 0 {
		return fmt.Errorf("publication payload has %d trailing bytes: %w", d.reader.Len(), ErrCorrupt)
	}
	return nil
}

func decodeError(field string, err error) error {
	return fmt.Errorf("decode %s: %w", field, err)
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
