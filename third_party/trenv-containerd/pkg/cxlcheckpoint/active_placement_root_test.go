package cxlcheckpoint

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func validActiveContentPlacementRootFixture(t *testing.T) (
	[]ContentObject,
	[]byte,
	VirtualPageMap,
	ContentPlacementMap,
	ActiveContentPlacementRoot,
) {
	t.Helper()
	objects, virtualPageMap, contentPlacementMap := validContentMappingFixture()
	// This deliberately contains values that must remain opaque to the root.
	// Only its exact length and digest may appear in the root envelope.
	immutablePublication := []byte(
		"opaque immutable publication with /dev/dax9.9 and complete page metadata")
	virtualBytes, err := CanonicalVirtualPageMapBytes(virtualPageMap, objects)
	if err != nil {
		t.Fatalf("CanonicalVirtualPageMapBytes(): %v", err)
	}
	placementBytes, err := CanonicalContentPlacementMapBytes(contentPlacementMap, objects)
	if err != nil {
		t.Fatalf("CanonicalContentPlacementMapBytes(): %v", err)
	}
	deviceDigest, err := DeviceTableDigest(contentPlacementMap.Devices)
	if err != nil {
		t.Fatalf("DeviceTableDigest(): %v", err)
	}
	root := ActiveContentPlacementRoot{
		State:                      ActiveContentPlacementRootCommitted,
		RootID:                     "active-root-12",
		RootVersion:                12,
		CheckpointID:               "checkpoint-42",
		ImmutablePublicationLength: uint64(len(immutablePublication)),
		ImmutablePublicationSHA256: sha256.Sum256(immutablePublication),
		VirtualPageMapID:           virtualPageMap.VirtualPageMapID,
		VirtualPageMapVersion:      virtualPageMap.Version,
		VirtualPageMapLength:       uint64(len(virtualBytes)),
		VirtualPageMapSHA256:       sha256.Sum256(virtualBytes),
		ActiveMappingSlot:          MappingSlotB,
		ContentPlacementMapID:      contentPlacementMap.ContentPlacementMapID,
		ContentPlacementMapVersion: contentPlacementMap.Version,
		ContentPlacementMapLength:  uint64(len(placementBytes)),
		ContentPlacementMapSHA256:  sha256.Sum256(placementBytes),
		PlacementDeviceTableSHA256: deviceDigest,
	}
	return objects, immutablePublication, virtualPageMap, contentPlacementMap, root
}

func TestActiveContentPlacementRootCanonicalRoundTripIsCompactAndSeparated(t *testing.T) {
	objects, publication, virtualPageMap, contentPlacementMap, root :=
		validActiveContentPlacementRootFixture(t)
	if err := root.Validate(); err != nil {
		t.Fatalf("Validate(): %v", err)
	}
	if err := root.CrossCheck(
		objects, publication, virtualPageMap, contentPlacementMap); err != nil {
		t.Fatalf("CrossCheck(): %v", err)
	}

	first, err := CanonicalActiveContentPlacementRootBytes(root)
	if err != nil {
		t.Fatalf("CanonicalActiveContentPlacementRootBytes(first): %v", err)
	}
	second, err := CanonicalActiveContentPlacementRootBytes(root)
	if err != nil {
		t.Fatalf("CanonicalActiveContentPlacementRootBytes(second): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical active root encoding is not deterministic")
	}
	if got, want := string(first[0:8]), ActiveContentPlacementRootMagicString; got != want {
		t.Fatalf("magic = %q, want %q", got, want)
	}
	if got, want := string(first[16:40]), ActiveContentPlacementRootDomain; got != want {
		t.Fatalf("domain = %q, want %q", got, want)
	}
	if got := binary.LittleEndian.Uint32(first[12:16]); got != uint32(ActiveContentPlacementRootEnvelopeHeaderBytes) {
		t.Fatalf("header size = %d", got)
	}
	if len(first) > int(MaxActiveContentPlacementRootBytes) {
		t.Fatalf("active root is %d bytes, page limit is %d", len(first), PageSize)
	}
	if len(first) >= int(PageSize/4) {
		t.Fatalf("fixture active root is not far below one page: %d bytes", len(first))
	}
	size, err := CanonicalActiveContentPlacementRootSize(root)
	if err != nil || size != uint64(len(first)) {
		t.Fatalf("CanonicalActiveContentPlacementRootSize() = %d, %v", size, err)
	}

	decoded, err := DecodeActiveContentPlacementRoot(first)
	if err != nil {
		t.Fatalf("DecodeActiveContentPlacementRoot(): %v", err)
	}
	if !reflect.DeepEqual(decoded, root) {
		t.Fatalf("decoded root differs:\n got %#v\nwant %#v", decoded, root)
	}
	reencoded, err := CanonicalActiveContentPlacementRootBytes(decoded)
	if err != nil {
		t.Fatalf("canonical re-encode: %v", err)
	}
	if !bytes.Equal(reencoded, first) {
		t.Fatal("decode/canonical re-encode changed exact root bytes")
	}

	virtualBytes, err := CanonicalVirtualPageMapBytes(virtualPageMap, objects)
	if err != nil {
		t.Fatal(err)
	}
	placementBytes, err := CanonicalContentPlacementMapBytes(contentPlacementMap, objects)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		publication,
		virtualBytes,
		placementBytes,
		[]byte("/dev/dax9.9"),
		[]byte("device-a"),
		[]byte("device-b"),
		[]byte("owner-a"),
		[]byte("owner-b"),
	} {
		if bytes.Contains(first, forbidden) {
			t.Fatalf("compact root leaks payload/map/route bytes %q", forbidden)
		}
	}
	rootType := reflect.TypeOf(root)
	for index := 0; index < rootType.NumField(); index++ {
		field := rootType.Field(index)
		switch field.Type.Kind() {
		case reflect.Slice, reflect.Map, reflect.Ptr, reflect.Interface:
			t.Fatalf("root field %s can retain a full object", field.Name)
		}
		lower := strings.ToLower(field.Name)
		for _, forbidden := range []string{"path", "owner", "route", "lease", "refcount", "payload", "runs", "devices"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("root has forbidden authority field %s", field.Name)
			}
		}
	}

	if _, err := DecodeVirtualPageMap(first, objects); !errors.Is(err, ErrWrongContentMappingFormat) {
		t.Fatalf("VirtualPageMap decoder accepted active root: %v", err)
	}
	if _, err := DecodeContentPlacementMap(first, objects); !errors.Is(err, ErrWrongContentMappingFormat) {
		t.Fatalf("ContentPlacementMap decoder accepted active root: %v", err)
	}
	if _, err := DecodeActiveContentPlacementRoot(virtualBytes); !errors.Is(err, ErrWrongActiveContentPlacementRootFormat) {
		t.Fatalf("active root decoder accepted VirtualPageMap: %v", err)
	}
	if ActiveContentPlacementRootMagicString == MagicString ||
		ActiveContentPlacementRootMagicString == VirtualPageMapMagicString ||
		ActiveContentPlacementRootMagicString == ContentPlacementMapMagicString {
		t.Fatal("active root magic is not domain-separated")
	}
}

func TestActiveContentPlacementRootValidationIsStrict(t *testing.T) {
	_, _, _, _, valid := validActiveContentPlacementRootFixture(t)
	one := sha256.Sum256([]byte("nonzero"))
	tests := []struct {
		name   string
		mutate func(*ActiveContentPlacementRoot)
	}{
		{"state-zero", func(root *ActiveContentPlacementRoot) { root.State = 0 }},
		{"state-prepared", func(root *ActiveContentPlacementRoot) { root.State = 2 }},
		{"root-id-empty", func(root *ActiveContentPlacementRoot) { root.RootID = "" }},
		{"root-id-invalid-utf8", func(root *ActiveContentPlacementRoot) { root.RootID = string([]byte{0xff}) }},
		{"root-id-leading-space", func(root *ActiveContentPlacementRoot) { root.RootID = " root" }},
		{"root-id-control", func(root *ActiveContentPlacementRoot) { root.RootID = "root\n" }},
		{"root-id-too-long", func(root *ActiveContentPlacementRoot) {
			root.RootID = strings.Repeat("r", MaxActiveContentPlacementRootIdentityBytes+1)
		}},
		{"root-version-zero", func(root *ActiveContentPlacementRoot) { root.RootVersion = 0 }},
		{"root-version-too-large", func(root *ActiveContentPlacementRoot) {
			root.RootVersion = MaxSignedLong + 1
		}},
		{"checkpoint-empty", func(root *ActiveContentPlacementRoot) { root.CheckpointID = "" }},
		{"publication-length-zero", func(root *ActiveContentPlacementRoot) {
			root.ImmutablePublicationLength = 0
		}},
		{"publication-length-too-large", func(root *ActiveContentPlacementRoot) {
			root.ImmutablePublicationLength = MaxActiveContentPlacementPublicationBytes + 1
		}},
		{"publication-digest-zero", func(root *ActiveContentPlacementRoot) {
			root.ImmutablePublicationSHA256 = [sha256.Size]byte{}
		}},
		{"virtual-id-empty", func(root *ActiveContentPlacementRoot) { root.VirtualPageMapID = "" }},
		{"virtual-version-zero", func(root *ActiveContentPlacementRoot) { root.VirtualPageMapVersion = 0 }},
		{"virtual-version-too-large", func(root *ActiveContentPlacementRoot) {
			root.VirtualPageMapVersion = MaxSignedLong + 1
		}},
		{"virtual-length-zero", func(root *ActiveContentPlacementRoot) { root.VirtualPageMapLength = 0 }},
		{"virtual-length-header-only", func(root *ActiveContentPlacementRoot) {
			root.VirtualPageMapLength = ContentMappingEnvelopeHeaderBytes
		}},
		{"virtual-length-too-large", func(root *ActiveContentPlacementRoot) {
			root.VirtualPageMapLength = MaxActiveContentPlacementMapBytes + 1
		}},
		{"virtual-digest-zero", func(root *ActiveContentPlacementRoot) {
			root.VirtualPageMapSHA256 = [sha256.Size]byte{}
		}},
		{"slot-zero", func(root *ActiveContentPlacementRoot) { root.ActiveMappingSlot = 0 }},
		{"slot-unknown", func(root *ActiveContentPlacementRoot) { root.ActiveMappingSlot = 3 }},
		{"placement-id-empty", func(root *ActiveContentPlacementRoot) { root.ContentPlacementMapID = "" }},
		{"placement-version-zero", func(root *ActiveContentPlacementRoot) {
			root.ContentPlacementMapVersion = 0
		}},
		{"placement-version-too-large", func(root *ActiveContentPlacementRoot) {
			root.ContentPlacementMapVersion = MaxSignedLong + 1
		}},
		{"placement-length-zero", func(root *ActiveContentPlacementRoot) {
			root.ContentPlacementMapLength = 0
		}},
		{"placement-length-header-only", func(root *ActiveContentPlacementRoot) {
			root.ContentPlacementMapLength = ContentMappingEnvelopeHeaderBytes
		}},
		{"placement-length-too-large", func(root *ActiveContentPlacementRoot) {
			root.ContentPlacementMapLength = MaxActiveContentPlacementMapBytes + 1
		}},
		{"placement-digest-zero", func(root *ActiveContentPlacementRoot) {
			root.ContentPlacementMapSHA256 = [sha256.Size]byte{}
		}},
		{"device-table-digest-zero", func(root *ActiveContentPlacementRoot) {
			root.PlacementDeviceTableSHA256 = [sha256.Size]byte{}
		}},
		{"all-digests-zero", func(root *ActiveContentPlacementRoot) {
			root.ImmutablePublicationSHA256 = [sha256.Size]byte{}
			root.VirtualPageMapSHA256 = [sha256.Size]byte{}
			root.ContentPlacementMapSHA256 = [sha256.Size]byte{}
			root.PlacementDeviceTableSHA256 = [sha256.Size]byte{}
		}},
		{"sanity-nonzero-digest-does-not-repair-zero-length", func(root *ActiveContentPlacementRoot) {
			root.ImmutablePublicationLength = 0
			root.ImmutablePublicationSHA256 = one
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidActiveContentPlacementRoot) {
				t.Fatalf("Validate() error = %v", err)
			}
			if _, err := CanonicalActiveContentPlacementRootBytes(candidate); !errors.Is(err, ErrInvalidActiveContentPlacementRoot) {
				t.Fatalf("canonical encoder error = %v", err)
			}
		})
	}

	for _, slot := range []MappingSlotName{MappingSlotA, MappingSlotB} {
		candidate := valid
		candidate.ActiveMappingSlot = slot
		if err := candidate.Validate(); err != nil {
			t.Fatalf("slot %d rejected: %v", slot, err)
		}
	}
	// Identifier values are opaque portable identities. Path-looking syntax is
	// accepted because no root code interprets an identity as a local path.
	opaque := valid
	opaque.RootID = "tenant/root:id"
	opaque.CheckpointID = `checkpoint\with/path`
	opaque.VirtualPageMapID = "file:virtual-map-id"
	opaque.ContentPlacementMapID = "placement/map/id"
	if err := opaque.Validate(); err != nil {
		t.Fatalf("opaque identifier syntax rejected: %v", err)
	}
	if MaxActiveContentPlacementPublicationBytes != 64<<20 {
		t.Fatalf("V7 publication limit = %d", MaxActiveContentPlacementPublicationBytes)
	}
}

func TestActiveContentPlacementRootCrossCheckRejectsEverySubstitutionWithoutMutation(t *testing.T) {
	objects, publication, virtualPageMap, contentPlacementMap, root :=
		validActiveContentPlacementRootFixture(t)
	originalObjects := cloneActiveRootContentObjects(objects)
	originalPublication := append([]byte(nil), publication...)
	originalVirtual := cloneActiveRootVirtualPageMap(virtualPageMap)
	originalPlacement := cloneActiveRootContentPlacementMap(contentPlacementMap)
	if err := root.CrossCheck(
		objects, publication, virtualPageMap, contentPlacementMap); err != nil {
		t.Fatalf("exact CrossCheck(): %v", err)
	}
	if !reflect.DeepEqual(objects, originalObjects) ||
		!bytes.Equal(publication, originalPublication) ||
		!reflect.DeepEqual(virtualPageMap, originalVirtual) ||
		!reflect.DeepEqual(contentPlacementMap, originalPlacement) {
		t.Fatal("CrossCheck mutated an input")
	}

	tests := []struct {
		name   string
		mutate func(*ActiveContentPlacementRoot, *[]byte, *VirtualPageMap, *ContentPlacementMap)
	}{
		{"publication-length-binding", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.ImmutablePublicationLength++
		}},
		{"publication-bytes", func(_ *ActiveContentPlacementRoot, publication *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			(*publication)[0] ^= 0x40
		}},
		{"virtual-root-id", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.VirtualPageMapID = "substituted-virtual-root-id"
		}},
		{"virtual-map-id", func(_ *ActiveContentPlacementRoot, _ *[]byte, virtual *VirtualPageMap, _ *ContentPlacementMap) {
			virtual.VirtualPageMapID = "substituted-virtual-map-id"
		}},
		{"virtual-map-version", func(_ *ActiveContentPlacementRoot, _ *[]byte, virtual *VirtualPageMap, _ *ContentPlacementMap) {
			virtual.Version++
		}},
		{"virtual-map-bytes", func(_ *ActiveContentPlacementRoot, _ *[]byte, virtual *VirtualPageMap, _ *ContentPlacementMap) {
			virtual.Runs[1].StartVAddr += PageSize
		}},
		{"virtual-map-length", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.VirtualPageMapLength++
		}},
		{"virtual-map-digest", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.VirtualPageMapSHA256[0] ^= 1
		}},
		{"placement-root-id", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.ContentPlacementMapID = "substituted-placement-root-id"
		}},
		{"placement-map-id", func(_ *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, placement *ContentPlacementMap) {
			placement.ContentPlacementMapID = "substituted-placement-map-id"
		}},
		{"placement-map-version", func(_ *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, placement *ContentPlacementMap) {
			placement.Version++
		}},
		{"placement-map-bytes", func(_ *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, placement *ContentPlacementMap) {
			placement.Runs[len(placement.Runs)-1].DataPageIndex++
		}},
		{"placement-map-length", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.ContentPlacementMapLength++
		}},
		{"placement-map-digest", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.ContentPlacementMapSHA256[0] ^= 1
		}},
		{"placement-devices", func(_ *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, placement *ContentPlacementMap) {
			placement.Devices[0].OwnerEpoch++
		}},
		{"device-table-digest", func(root *ActiveContentPlacementRoot, _ *[]byte, _ *VirtualPageMap, _ *ContentPlacementMap) {
			root.PlacementDeviceTableSHA256[0] ^= 1
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateRoot := root
			candidatePublication := append([]byte(nil), publication...)
			candidateVirtual := cloneActiveRootVirtualPageMap(virtualPageMap)
			candidatePlacement := cloneActiveRootContentPlacementMap(contentPlacementMap)
			test.mutate(
				&candidateRoot,
				&candidatePublication,
				&candidateVirtual,
				&candidatePlacement,
			)
			beforeObjects := cloneActiveRootContentObjects(objects)
			beforePublication := append([]byte(nil), candidatePublication...)
			beforeVirtual := cloneActiveRootVirtualPageMap(candidateVirtual)
			beforePlacement := cloneActiveRootContentPlacementMap(candidatePlacement)
			err := candidateRoot.CrossCheck(
				objects,
				candidatePublication,
				candidateVirtual,
				candidatePlacement,
			)
			if !errors.Is(err, ErrInvalidActiveContentPlacementRoot) {
				t.Fatalf("CrossCheck() error = %v", err)
			}
			if !reflect.DeepEqual(objects, beforeObjects) ||
				!bytes.Equal(candidatePublication, beforePublication) ||
				!reflect.DeepEqual(candidateVirtual, beforeVirtual) ||
				!reflect.DeepEqual(candidatePlacement, beforePlacement) {
				t.Fatal("failed CrossCheck mutated an input")
			}
		})
	}
}

func TestActiveContentPlacementRootDecoderRejectsMalformedWire(t *testing.T) {
	_, _, _, _, root := validActiveContentPlacementRootFixture(t)
	encoded, err := CanonicalActiveContentPlacementRootBytes(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), encoded[activeContentPlacementRootHeaderSize:]...)
	records := splitActiveRootTestRecords(t, payload)

	corruptPayload := append([]byte(nil), encoded...)
	corruptPayload[len(corruptPayload)-1] ^= 0x80
	corruptHeader := append([]byte(nil), encoded...)
	corruptHeader[56] ^= 0x80
	trailingEnvelope := append(append([]byte(nil), encoded...), 0)
	truncatedEnvelope := append([]byte(nil), encoded[:len(encoded)-1]...)
	badMagic := append([]byte(nil), encoded...)
	badMagic[0] ^= 1
	badVersion := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(badVersion[8:12], ActiveContentPlacementRootVersion+1)
	badDomain := append([]byte(nil), encoded...)
	badDomain[16] ^= 1
	badHeaderSize := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(badHeaderSize[12:16], activeContentPlacementRootHeaderSize+1)
	badFlags := append([]byte(nil), encoded...)
	binary.LittleEndian.PutUint32(badFlags[52:56], 1)
	badReserved := append([]byte(nil), encoded...)
	badReserved[60] = 1

	duplicateRecords := cloneActiveRootTestRecords(records)
	duplicateRecords[1] = append([]byte(nil), duplicateRecords[0]...)
	duplicate := activeRootTestEnvelope(t, joinActiveRootTestRecords(duplicateRecords))
	unknownRecords := cloneActiveRootTestRecords(records)
	binary.LittleEndian.PutUint16(unknownRecords[1][0:2], ^uint16(0))
	unknown := activeRootTestEnvelope(t, joinActiveRootTestRecords(unknownRecords))
	unknownFlagsRecords := cloneActiveRootTestRecords(records)
	unknownFlagsRecords[1][3] = 0x80
	unknownFlags := activeRootTestEnvelope(t, joinActiveRootTestRecords(unknownFlagsRecords))
	wrongWireRecords := cloneActiveRootTestRecords(records)
	wrongWireRecords[1][2] = byte(activeContentPlacementRootWireU64)
	wrongWire := activeRootTestEnvelope(t, joinActiveRootTestRecords(wrongWireRecords))
	outOfOrderRecords := cloneActiveRootTestRecords(records)
	outOfOrderRecords[1], outOfOrderRecords[2] = outOfOrderRecords[2], outOfOrderRecords[1]
	outOfOrder := activeRootTestEnvelope(t, joinActiveRootTestRecords(outOfOrderRecords))
	missingRecords := cloneActiveRootTestRecords(records[:len(records)-1])
	missing := activeRootTestEnvelope(t, joinActiveRootTestRecords(missingRecords))
	invalidUTF8Records := cloneActiveRootTestRecords(records)
	invalidUTF8Records[1][activeContentPlacementRootFieldHeaderBytes] = 0xff
	invalidUTF8 := activeRootTestEnvelope(t, joinActiveRootTestRecords(invalidUTF8Records))
	overlongTextRecords := cloneActiveRootTestRecords(records)
	binary.LittleEndian.PutUint32(
		overlongTextRecords[1][4:8],
		MaxActiveContentPlacementRootIdentityBytes+1,
	)
	overlongText := activeRootTestEnvelope(t, joinActiveRootTestRecords(overlongTextRecords))
	badFieldLengthRecords := cloneActiveRootTestRecords(records)
	binary.LittleEndian.PutUint32(badFieldLengthRecords[0][4:8], 2)
	badFieldLength := activeRootTestEnvelope(t, joinActiveRootTestRecords(badFieldLengthRecords))
	uncommittedRecords := cloneActiveRootTestRecords(records)
	uncommittedRecords[0][activeContentPlacementRootFieldHeaderBytes] = 2
	uncommitted := activeRootTestEnvelope(t, joinActiveRootTestRecords(uncommittedRecords))
	invalidSlotRecords := cloneActiveRootTestRecords(records)
	invalidSlotRecords[10][activeContentPlacementRootFieldHeaderBytes] = 3
	invalidSlot := activeRootTestEnvelope(t, joinActiveRootTestRecords(invalidSlotRecords))
	zeroDigestRecords := cloneActiveRootTestRecords(records)
	for index := activeContentPlacementRootFieldHeaderBytes; index < len(zeroDigestRecords[5]); index++ {
		zeroDigestRecords[5][index] = 0
	}
	zeroDigest := activeRootTestEnvelope(t, joinActiveRootTestRecords(zeroDigestRecords))
	countAttackPayload := append([]byte(nil), payload...)
	binary.LittleEndian.PutUint32(countAttackPayload[0:4], ^uint32(0))
	countAttack := activeRootTestEnvelope(t, countAttackPayload)
	payloadTrailing := append(append([]byte(nil), payload...), 0)
	payloadTrailingEnvelope := activeRootTestEnvelope(t, payloadTrailing)

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"wrong-magic", badMagic, ErrWrongActiveContentPlacementRootFormat},
		{"wrong-version", badVersion, ErrWrongActiveContentPlacementRootFormat},
		{"wrong-domain", badDomain, ErrWrongActiveContentPlacementRootFormat},
		{"wrong-header-size", badHeaderSize, ErrWrongActiveContentPlacementRootFormat},
		{"unknown-header-flags", badFlags, ErrWrongActiveContentPlacementRootFormat},
		{"reserved-header", badReserved, ErrWrongActiveContentPlacementRootFormat},
		{"header-crc", corruptHeader, ErrCorruptActiveContentPlacementRoot},
		{"payload-crc", corruptPayload, ErrCorruptActiveContentPlacementRoot},
		{"trailing-envelope", trailingEnvelope, ErrCorruptActiveContentPlacementRoot},
		{"truncated-envelope", truncatedEnvelope, ErrCorruptActiveContentPlacementRoot},
		{"duplicate-field", duplicate, ErrCorruptActiveContentPlacementRoot},
		{"unknown-mandatory-tag", unknown, ErrWrongActiveContentPlacementRootFormat},
		{"unknown-field-flags", unknownFlags, ErrWrongActiveContentPlacementRootFormat},
		{"wrong-wire-type", wrongWire, ErrWrongActiveContentPlacementRootFormat},
		{"out-of-order", outOfOrder, ErrCorruptActiveContentPlacementRoot},
		{"missing-field", missing, ErrCorruptActiveContentPlacementRoot},
		{"invalid-utf8", invalidUTF8, ErrCorruptActiveContentPlacementRoot},
		{"text-over-256", overlongText, ErrCorruptActiveContentPlacementRoot},
		{"bad-fixed-field-length", badFieldLength, ErrCorruptActiveContentPlacementRoot},
		{"decoded-uncommitted-state", uncommitted, ErrInvalidActiveContentPlacementRoot},
		{"decoded-invalid-slot", invalidSlot, ErrInvalidActiveContentPlacementRoot},
		{"decoded-zero-digest", zeroDigest, ErrInvalidActiveContentPlacementRoot},
		{"field-count-attack", countAttack, ErrCorruptActiveContentPlacementRoot},
		{"payload-trailing", payloadTrailingEnvelope, ErrCorruptActiveContentPlacementRoot},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeActiveContentPlacementRoot(test.data); !errors.Is(err, test.want) {
				t.Fatalf("DecodeActiveContentPlacementRoot() error = %v, want %v", err, test.want)
			}
		})
	}

	tooLargePayload := make([]byte, maxActiveContentPlacementRootPayloadBytes+1)
	if _, err := marshalActiveContentPlacementRootEnvelope(tooLargePayload); !errors.Is(err, ErrInvalidActiveContentPlacementRoot) {
		t.Fatalf("4097-byte envelope error = %v", err)
	}
	if got := ActiveContentPlacementRootEnvelopeHeaderBytes + uint64(len(tooLargePayload)); got != MaxActiveContentPlacementRootBytes+1 {
		t.Fatalf("oversize test constructed %d bytes, want %d", got, MaxActiveContentPlacementRootBytes+1)
	}
}

func TestActiveContentPlacementRootWorstCaseIdentitiesStayWithinOnePage(t *testing.T) {
	_, _, _, _, root := validActiveContentPlacementRootFixture(t)
	root.RootID = strings.Repeat("r", MaxActiveContentPlacementRootIdentityBytes)
	root.CheckpointID = strings.Repeat("c", MaxActiveContentPlacementRootIdentityBytes)
	root.VirtualPageMapID = strings.Repeat("v", MaxActiveContentPlacementRootIdentityBytes)
	root.ContentPlacementMapID = strings.Repeat("p", MaxActiveContentPlacementRootIdentityBytes)
	encoded, err := CanonicalActiveContentPlacementRootBytes(root)
	if err != nil {
		t.Fatalf("worst-case identities: %v", err)
	}
	if len(encoded) > int(MaxActiveContentPlacementRootBytes) {
		t.Fatalf("worst-case root is %d bytes, limit is %d", len(encoded), MaxActiveContentPlacementRootBytes)
	}
	if len(encoded) >= int(MaxActiveContentPlacementRootBytes/2) {
		t.Fatalf("worst-case root is not compact: %d bytes", len(encoded))
	}
}

func cloneActiveRootContentObjects(objects []ContentObject) []ContentObject {
	return append([]ContentObject(nil), objects...)
}

func cloneActiveRootVirtualPageMap(mapping VirtualPageMap) VirtualPageMap {
	clone := mapping
	clone.Runs = append([]VirtualPageMapRun(nil), mapping.Runs...)
	return clone
}

func cloneActiveRootContentPlacementMap(mapping ContentPlacementMap) ContentPlacementMap {
	clone := mapping
	clone.Devices = append([]Device(nil), mapping.Devices...)
	clone.Runs = append([]ContentPlacementRun(nil), mapping.Runs...)
	return clone
}

func splitActiveRootTestRecords(t *testing.T, payload []byte) [][]byte {
	t.Helper()
	if len(payload) < 4 {
		t.Fatal("fixture payload is truncated")
	}
	count := binary.LittleEndian.Uint32(payload[0:4])
	offset := 4
	records := make([][]byte, 0, count)
	for index := uint32(0); index < count; index++ {
		if len(payload)-offset < activeContentPlacementRootFieldHeaderBytes {
			t.Fatalf("fixture field %d header is truncated", index)
		}
		length := binary.LittleEndian.Uint32(payload[offset+4 : offset+8])
		end := offset + activeContentPlacementRootFieldHeaderBytes + int(length)
		if end > len(payload) {
			t.Fatalf("fixture field %d value is truncated", index)
		}
		records = append(records, append([]byte(nil), payload[offset:end]...))
		offset = end
	}
	if offset != len(payload) {
		t.Fatalf("fixture payload has %d trailing bytes", len(payload)-offset)
	}
	return records
}

func cloneActiveRootTestRecords(records [][]byte) [][]byte {
	clone := make([][]byte, len(records))
	for index := range records {
		clone[index] = append([]byte(nil), records[index]...)
	}
	return clone
}

func joinActiveRootTestRecords(records [][]byte) []byte {
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint32(payload, uint32(len(records)))
	for _, record := range records {
		payload = append(payload, record...)
	}
	return payload
}

func activeRootTestEnvelope(t *testing.T, payload []byte) []byte {
	t.Helper()
	encoded, err := marshalActiveContentPlacementRootEnvelope(payload)
	if err != nil {
		t.Fatalf("marshal malformed test envelope: %v", err)
	}
	return encoded
}
