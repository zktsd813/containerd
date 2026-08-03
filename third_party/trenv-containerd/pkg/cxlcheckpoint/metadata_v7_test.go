package cxlcheckpoint

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestMetadataV7CanonicalRoundTripsAndDomainsAreSeparate(t *testing.T) {
	fixture := validPublicationV7Fixture(t)
	templateBytes, err := CanonicalMMTemplateV7Bytes(fixture.template)
	if err != nil {
		t.Fatalf("CanonicalMMTemplateV7Bytes(): %v", err)
	}
	templateAgain, err := CanonicalMMTemplateV7Bytes(fixture.template)
	if err != nil || !bytes.Equal(templateBytes, templateAgain) {
		t.Fatalf("MMTemplate encoding is nondeterministic: %v", err)
	}
	if got := string(templateBytes[0:8]); got != MMTemplateV7MagicString {
		t.Fatalf("MMTemplate magic = %q", got)
	}
	if got := string(bytes.TrimRight(templateBytes[16:40], "\x00")); got != MMTemplateV7Domain {
		t.Fatalf("MMTemplate domain = %q", got)
	}
	decodedTemplate, err := DecodeMMTemplateV7(templateBytes)
	if err != nil {
		t.Fatalf("DecodeMMTemplateV7(): %v", err)
	}
	if !reflect.DeepEqual(decodedTemplate, fixture.template) {
		t.Fatalf("MMTemplate round trip differs:\n got %#v\nwant %#v", decodedTemplate, fixture.template)
	}
	templateSize, err := CanonicalMMTemplateV7Size(fixture.template)
	if err != nil || templateSize != uint64(len(templateBytes)) {
		t.Fatalf("CanonicalMMTemplateV7Size() = %d, %v", templateSize, err)
	}

	manifestBytes, err := CanonicalArtifactManifestV7Bytes(fixture.manifest)
	if err != nil {
		t.Fatalf("CanonicalArtifactManifestV7Bytes(): %v", err)
	}
	manifestAgain, err := CanonicalArtifactManifestV7Bytes(fixture.manifest)
	if err != nil || !bytes.Equal(manifestBytes, manifestAgain) {
		t.Fatalf("ArtifactManifest encoding is nondeterministic: %v", err)
	}
	if got := string(manifestBytes[0:8]); got != ArtifactManifestV7MagicString {
		t.Fatalf("ArtifactManifest magic = %q", got)
	}
	if got := string(bytes.TrimRight(manifestBytes[16:40], "\x00")); got != ArtifactManifestV7Domain {
		t.Fatalf("ArtifactManifest domain = %q", got)
	}
	decodedManifest, err := DecodeArtifactManifestV7(manifestBytes)
	if err != nil {
		t.Fatalf("DecodeArtifactManifestV7(): %v", err)
	}
	if !reflect.DeepEqual(decodedManifest, fixture.manifest) {
		t.Fatalf("ArtifactManifest round trip differs:\n got %#v\nwant %#v", decodedManifest, fixture.manifest)
	}
	manifestSize, err := CanonicalArtifactManifestV7Size(fixture.manifest)
	if err != nil || manifestSize != uint64(len(manifestBytes)) {
		t.Fatalf("CanonicalArtifactManifestV7Size() = %d, %v", manifestSize, err)
	}

	if _, err := DecodeArtifactManifestV7(templateBytes); !errors.Is(err, ErrWrongMetadataV7Format) {
		t.Fatalf("ArtifactManifest decoder accepted MMTemplate: %v", err)
	}
	if _, err := DecodeMMTemplateV7(manifestBytes); !errors.Is(err, ErrWrongMetadataV7Format) {
		t.Fatalf("MMTemplate decoder accepted ArtifactManifest: %v", err)
	}
	if _, err := DecodePublicationV7(templateBytes); !errors.Is(err, ErrWrongPublicationV7Format) {
		t.Fatalf("TRPUB007 decoder accepted MMTemplate: %v", err)
	}
	for _, forbidden := range [][]byte{
		[]byte("unique-artifact-file-content-not-metadata"),
		[]byte("/dev/dax0.0"),
	} {
		if bytes.Contains(templateBytes, forbidden) || bytes.Contains(manifestBytes, forbidden) {
			t.Fatalf("metadata embeds content or a local path %q", forbidden)
		}
	}
}

func TestMMTemplateV7LocalValidationIsStrictAndUsesVirtualTerminology(t *testing.T) {
	base := validPublicationV7Fixture(t).template
	tests := []struct {
		name   string
		mutate func(*MMTemplateV7)
	}{
		{"ID-empty", func(m *MMTemplateV7) { m.MMTemplateID = "" }},
		{"ID-invalid-UTF8", func(m *MMTemplateV7) { m.MMTemplateID = string([]byte{0xff}) }},
		{"ID-surrounding-space", func(m *MMTemplateV7) { m.MMTemplateID = " mm" }},
		{"version-zero", func(m *MMTemplateV7) { m.Version = 0 }},
		{"runtime-ID-control", func(m *MMTemplateV7) { m.RuntimeCompatibilityID = "runtime\n" }},
		{"page-size", func(m *MMTemplateV7) { m.PageSize = 8192 }},
		{"no-VMAs", func(m *MMTemplateV7) { m.VMAs = nil }},
		{"zero-pages-image", func(m *MMTemplateV7) { m.VMAs[0].PagesImageID = 0 }},
		{"unaligned-start", func(m *MMTemplateV7) { m.VMAs[0].StartVAddr++ }},
		{"empty-range", func(m *MMTemplateV7) { m.VMAs[0].EndVAddr = m.VMAs[0].StartVAddr }},
		{"unknown-protection", func(m *MMTemplateV7) { m.VMAs[0].ProtectionFlags = 1 << 8 }},
		{"unknown-mapping", func(m *MMTemplateV7) { m.VMAs[0].MappingFlags = 1 << 20 }},
		{"privacy-both", func(m *MMTemplateV7) { m.VMAs[0].MappingFlags |= MappingShared }},
		{"unknown-backing", func(m *MMTemplateV7) { m.VMAs[0].BackingKind = 99 }},
		{"anonymous-flag-missing", func(m *MMTemplateV7) { m.VMAs[0].MappingFlags = MappingPrivate }},
		{"file-marked-anonymous", func(m *MMTemplateV7) { m.VMAs[0].BackingKind = BackingArtifact }},
		{"run-slice-gap", func(m *MMTemplateV7) { m.VMAs[0].VirtualPageMapRunStart = 1 }},
		{"run-count-overflow", func(m *MMTemplateV7) { m.VMAs[0].VirtualPageMapRunCount = MaxSignedLong + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			candidate.VMAs = append([]VMAV7(nil), base.VMAs...)
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidMetadataV7) {
				t.Fatalf("Validate() error = %v", err)
			}
			if _, err := CanonicalMMTemplateV7Bytes(candidate); !errors.Is(err, ErrInvalidMetadataV7) {
				t.Fatalf("encoder error = %v", err)
			}
		})
	}
	vmaType := reflect.TypeOf(VMAV7{})
	if _, exists := vmaType.FieldByName("VirtualPageMapRunStart"); !exists {
		t.Fatal("VMAV7 lacks VirtualPageMapRunStart")
	}
	if _, exists := vmaType.FieldByName("VirtualPageMapRunCount"); !exists {
		t.Fatal("VMAV7 lacks VirtualPageMapRunCount")
	}
	if _, exists := vmaType.FieldByName("PageMapRunStart"); exists {
		t.Fatal("VMAV7 retained physical PageMapRunStart terminology")
	}
	if _, exists := vmaType.FieldByName("PageMapRunCount"); exists {
		t.Fatal("VMAV7 retained physical PageMapRunCount terminology")
	}
}

func TestMMTemplateV7CrossCheckBindsExactVirtualPageMapSemanticIdentity(t *testing.T) {
	base := validPublicationV7Fixture(t)
	if err := base.template.CrossCheckVirtualPageMap(base.publication, base.virtual); err != nil {
		t.Fatalf("CrossCheckVirtualPageMap(): %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*publicationV7Fixture)
	}{
		{"VPM-ID", func(f *publicationV7Fixture) { f.virtual.VirtualPageMapID = "substituted-map" }},
		{"VPM-version", func(f *publicationV7Fixture) { f.virtual.Version++ }},
		{"template-ID", func(f *publicationV7Fixture) { f.template.MMTemplateID = "substituted-template" }},
		{"slice-too-short", func(f *publicationV7Fixture) { f.template.VMAs[0].VirtualPageMapRunCount = 1 }},
		{"run-outside-VMA", func(f *publicationV7Fixture) { f.template.VMAs[0].EndVAddr = 0x5000 }},
		{"run-pages-image", func(f *publicationV7Fixture) { f.virtual.Runs[1].PagesImageID = 2 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := clonePublicationV7Fixture(base)
			test.mutate(&candidate)
			if err := candidate.template.CrossCheckVirtualPageMap(
				candidate.publication, candidate.virtual); !errors.Is(err, ErrInvalidMetadataV7) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestArtifactManifestV7ValidationAndExactPayloadCoverage(t *testing.T) {
	base := validPublicationV7Fixture(t)
	if err := base.manifest.CrossCheckPublication(base.publication); err != nil {
		t.Fatalf("CrossCheckPublication(): %v", err)
	}
	validationTests := []struct {
		name   string
		mutate func(*ArtifactManifestV7)
	}{
		{"ID-empty", func(m *ArtifactManifestV7) { m.ArtifactManifestID = "" }},
		{"version-zero", func(m *ArtifactManifestV7) { m.Version = 0 }},
		{"exact-dotdot", func(m *ArtifactManifestV7) { m.Entries[0].Path = ".." }},
		{"absolute-path", func(m *ArtifactManifestV7) { m.Entries[0].Path = "/tmp/a" }},
		{"traversal-path", func(m *ArtifactManifestV7) { m.Entries[0].Path = "../a" }},
		{"unclean-path", func(m *ArtifactManifestV7) { m.Entries[0].Path = "a/../b" }},
		{"duplicate-path", func(m *ArtifactManifestV7) { m.Entries[1].Path = m.Entries[0].Path }},
		{"unknown-type", func(m *ArtifactManifestV7) { m.Entries[0].Type = 99 }},
		{"regular-link-target", func(m *ArtifactManifestV7) { m.Entries[0].LinkTarget = "target" }},
		{"nonempty-no-object", func(m *ArtifactManifestV7) { m.Entries[0].ContentObjectID = 0 }},
		{"directory-content", func(m *ArtifactManifestV7) { m.Entries[2].ByteLength = 1 }},
		{"symlink-content", func(m *ArtifactManifestV7) { m.Entries[3].ContentObjectID = 2 }},
		{"symlink-control", func(m *ArtifactManifestV7) { m.Entries[3].LinkTarget = "bad\nlink" }},
	}
	for _, test := range validationTests {
		t.Run("validation-"+test.name, func(t *testing.T) {
			candidate := base.manifest
			candidate.Entries = append([]ArtifactEntryV7(nil), base.manifest.Entries...)
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidMetadataV7) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	coverageTests := []struct {
		name   string
		mutate func(*ArtifactManifestV7)
	}{
		{"gap", func(m *ArtifactManifestV7) { m.Entries[1].ContentOffset = 2001 }},
		{"overlap", func(m *ArtifactManifestV7) { m.Entries[1].ContentOffset = 1999 }},
		{"short-tail", func(m *ArtifactManifestV7) { m.Entries[1].ByteLength = 2999 }},
		{"range-beyond", func(m *ArtifactManifestV7) { m.Entries[1].ByteLength = 3001 }},
		{"wrong-kind", func(m *ArtifactManifestV7) { m.Entries[0].ContentObjectID = 3 }},
		{"unreferenced-payload", func(m *ArtifactManifestV7) { m.Entries = append([]ArtifactEntryV7(nil), m.Entries[2:]...) }},
	}
	for _, test := range coverageTests {
		t.Run("coverage-"+test.name, func(t *testing.T) {
			candidate := base.manifest
			candidate.Entries = append([]ArtifactEntryV7(nil), base.manifest.Entries...)
			test.mutate(&candidate)
			if err := candidate.CrossCheckPublication(base.publication); !errors.Is(err, ErrInvalidMetadataV7) {
				t.Fatalf("CrossCheckPublication() error = %v", err)
			}
		})
	}
	absoluteLink := base.manifest
	absoluteLink.Entries = append([]ArtifactEntryV7(nil), base.manifest.Entries...)
	absoluteLink.Entries[3].LinkTarget = "/absolute/portable/link-target"
	if err := absoluteLink.Validate(); err != nil {
		t.Fatalf("portable absolute symlink target was rejected: %v", err)
	}
}

func TestMetadataV7EnvelopesRejectCorruptionCountsAndOversizedIdentityEarly(t *testing.T) {
	fixture := validPublicationV7Fixture(t)
	templateBytes, err := CanonicalMMTemplateV7Bytes(fixture.template)
	if err != nil {
		t.Fatal(err)
	}
	manifestBytes, err := CanonicalArtifactManifestV7Bytes(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"template": templateBytes,
		"manifest": manifestBytes,
	} {
		t.Run(name, func(t *testing.T) {
			decode := func(data []byte) error {
				if name == "template" {
					_, err := DecodeMMTemplateV7(data)
					return err
				}
				_, err := DecodeArtifactManifestV7(data)
				return err
			}
			mutations := []struct {
				name  string
				wrong bool
				apply func([]byte) []byte
			}{
				{"magic", true, func(data []byte) []byte { data[0] ^= 1; return data }},
				{"version", true, func(data []byte) []byte {
					binary.LittleEndian.PutUint32(data[8:12], 8)
					repairMetadataV7Header(data)
					return data
				}},
				{"header-size", true, func(data []byte) []byte {
					binary.LittleEndian.PutUint32(data[12:16], 65)
					repairMetadataV7Header(data)
					return data
				}},
				{"domain", true, func(data []byte) []byte { data[16] ^= 1; repairMetadataV7Header(data); return data }},
				{"flags", true, func(data []byte) []byte {
					binary.LittleEndian.PutUint32(data[52:56], 1)
					repairMetadataV7Header(data)
					return data
				}},
				{"reserved", true, func(data []byte) []byte { data[60] = 1; repairMetadataV7Header(data); return data }},
				{"header-crc", false, func(data []byte) []byte { data[56] ^= 1; return data }},
				{"payload-crc", false, func(data []byte) []byte { data[len(data)-1] ^= 1; return data }},
				{"truncated", false, func(data []byte) []byte { return data[:len(data)-1] }},
				{"trailing", false, func(data []byte) []byte { return append(data, 0) }},
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					candidate := mutation.apply(append([]byte(nil), encoded...))
					err := decode(candidate)
					want := ErrCorruptMetadataV7
					if mutation.wrong {
						want = ErrWrongMetadataV7Format
					}
					if !errors.Is(err, want) {
						t.Fatalf("decode error = %v, want %v", err, want)
					}
				})
			}
			for length := 0; length < len(encoded); length++ {
				if err := decode(encoded[:length]); err == nil {
					t.Fatalf("truncated prefix %d unexpectedly decoded", length)
				}
			}
		})
	}

	countAttacks := []struct {
		name    string
		encoded []byte
		offset  func([]byte) int
		decode  func([]byte) error
	}{
		{
			name: "VMA", encoded: templateBytes,
			offset: func(data []byte) int {
				offset := skipMetadataV7Text(t, data, int(metadataV7HeaderSize))
				offset += 8
				offset = skipMetadataV7Text(t, data, offset)
				return offset + 8
			},
			decode: func(data []byte) error { _, err := DecodeMMTemplateV7(data); return err },
		},
		{
			name: "artifact", encoded: manifestBytes,
			offset: func(data []byte) int {
				return skipMetadataV7Text(t, data, int(metadataV7HeaderSize)) + 8
			},
			decode: func(data []byte) error { _, err := DecodeArtifactManifestV7(data); return err },
		},
	}
	for _, attack := range countAttacks {
		candidate := append([]byte(nil), attack.encoded...)
		offset := attack.offset(candidate)
		binary.LittleEndian.PutUint32(candidate[offset:offset+4], MaxMetadataV7Entries+1)
		repairMetadataV7Checksums(candidate)
		if err := attack.decode(candidate); !errors.Is(err, ErrCorruptMetadataV7) {
			t.Fatalf("%s oversized count error = %v", attack.name, err)
		}
	}

	// A valid envelope can declare and carry a 4097-byte first identity, but
	// both decoders reject the length before slicing/copying it into a Go string.
	oversizedIdentityPayload := make([]byte, 4+MaxPublicationV7IdentityBytes+1)
	binary.LittleEndian.PutUint32(
		oversizedIdentityPayload[0:4], MaxPublicationV7IdentityBytes+1)
	for index := 4; index < len(oversizedIdentityPayload); index++ {
		oversizedIdentityPayload[index] = 'x'
	}
	for _, spec := range []metadataV7EnvelopeSpec{
		mmTemplateV7EnvelopeSpec,
		artifactManifestV7EnvelopeSpec,
	} {
		encoded, err := marshalMetadataV7Envelope(spec, oversizedIdentityPayload)
		if err != nil {
			t.Fatal(err)
		}
		var decodeErr error
		if spec == mmTemplateV7EnvelopeSpec {
			_, decodeErr = DecodeMMTemplateV7(encoded)
		} else {
			_, decodeErr = DecodeArtifactManifestV7(encoded)
		}
		if !errors.Is(decodeErr, ErrCorruptMetadataV7) {
			t.Fatalf("oversized identity for %s error = %v", spec.name, decodeErr)
		}
	}

	declaredTooLarge := append([]byte(nil), templateBytes[:metadataV7HeaderSize]...)
	binary.LittleEndian.PutUint64(declaredTooLarge[40:48], maxMetadataV7PayloadBytes+1)
	repairMetadataV7Header(declaredTooLarge)
	if _, err := DecodeMMTemplateV7(declaredTooLarge); !errors.Is(err, ErrCorruptMetadataV7) {
		t.Fatalf("oversized declared metadata payload error = %v", err)
	}
}

func TestMetadataV7WireBoundsAreExact(t *testing.T) {
	if len(MMTemplateV7MagicString) != 8 || len(ArtifactManifestV7MagicString) != 8 {
		t.Fatal("metadata magic is not exactly eight bytes")
	}
	if len(MMTemplateV7Domain) > metadataV7DomainFieldBytes ||
		len(ArtifactManifestV7Domain) > metadataV7DomainFieldBytes {
		t.Fatal("metadata domain exceeds 24-byte field")
	}
	if MetadataV7EnvelopeHeaderBytes != 64 || MaxMetadataV7Bytes != 64<<20 {
		t.Fatalf("metadata bounds are header=%d max=%d",
			MetadataV7EnvelopeHeaderBytes, MaxMetadataV7Bytes)
	}
	identities := []string{
		MMTemplateV7MagicString,
		ArtifactManifestV7MagicString,
		PublicationV7MagicString,
		VirtualPageMapMagicString,
		ContentPlacementMapMagicString,
	}
	for left := range identities {
		for right := left + 1; right < len(identities); right++ {
			if identities[left] == identities[right] {
				t.Fatalf("wire identities %q are not separated", identities[left])
			}
		}
	}
	if strings.Contains(reflect.TypeOf(MMTemplateV7{}).String(), "PageMap") {
		t.Fatal("MMTemplateV7 type name unexpectedly contains physical PageMap")
	}
}

func skipMetadataV7Text(t *testing.T, data []byte, offset int) int {
	t.Helper()
	if offset+4 > len(data) {
		t.Fatal("test text offset is truncated")
	}
	length := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
	offset += 4 + length
	if offset > len(data) {
		t.Fatal("test text exceeds data")
	}
	return offset
}

func repairMetadataV7Checksums(data []byte) {
	payload := data[metadataV7HeaderSize:]
	binary.LittleEndian.PutUint32(data[48:52], checksumCRC32C(payload))
	repairMetadataV7Header(data)
}

func repairMetadataV7Header(data []byte) {
	if len(data) >= int(metadataV7HeaderSize) {
		binary.LittleEndian.PutUint32(
			data[56:60], metadataV7HeaderCRC(data[:metadataV7HeaderSize]))
	}
}
