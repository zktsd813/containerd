package cxlcheckpoint

import (
	"errors"
	"fmt"
	pathpkg "path"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MetadataV7Version uint32 = 7

	MMTemplateV7MagicString       = "TRMMT007"
	MMTemplateV7Domain            = "mm-template-v1"
	ArtifactManifestV7MagicString = "TRAMF007"
	ArtifactManifestV7Domain      = "artifact-manifest-v1"

	MetadataV7EnvelopeHeaderBytes uint64 = 64
	MaxMetadataV7Bytes            uint64 = 64 << 20
	MaxMetadataV7Entries                 = 1 << 20
)

var (
	// ErrWrongMetadataV7Format identifies the wrong metadata magic, version,
	// domain, mandatory flags, or reserved header bytes.
	ErrWrongMetadataV7Format = errors.New("not a V7 immutable metadata envelope")
	// ErrCorruptMetadataV7 identifies truncated, trailing, checksummed, or
	// structurally impossible metadata bytes.
	ErrCorruptMetadataV7 = errors.New("corrupt V7 immutable metadata envelope")
	// ErrInvalidMetadataV7 identifies locally invalid MMTemplate or artifact
	// metadata, including an invalid explicit graph cross-check.
	ErrInvalidMetadataV7 = errors.New("invalid V7 immutable metadata")
)

// VMAV7 is a portable virtual-memory range. VirtualPageMapRunStart and
// VirtualPageMapRunCount index immutable logical V7 VirtualPageMap runs; no
// physical PageMap, PageID, pseudo-mm pointer, or local descriptor is stored.
type VMAV7 struct {
	PagesImageID           uint32
	StartVAddr             uint64
	EndVAddr               uint64
	ProtectionFlags        uint64
	MappingFlags           uint64
	BackingKind            BackingKind
	VirtualPageMapRunStart uint64
	VirtualPageMapRunCount uint64
}

// MMTemplateV7 contains portable VMA shape only. Version is the semantic
// template version bound by MMTemplateRefV7, independent of envelope version.
type MMTemplateV7 struct {
	MMTemplateID           string
	Version                uint64
	RuntimeCompatibilityID string
	PageSize               uint64
	VMAs                   []VMAV7
}

// ArtifactEntryV7 preserves portable filesystem metadata and a logical byte
// range. It does not embed file data or a physical locator.
type ArtifactEntryV7 struct {
	Path            string
	Type            ArtifactType
	Mode            uint64
	UID             uint64
	GID             uint64
	ByteLength      uint64
	ContentObjectID uint64
	ContentOffset   uint64
	LinkTarget      string
}

// ArtifactManifestV7 is an independently encoded immutable catalog. Version
// is its semantic version bound by ArtifactManifestRefV7.
type ArtifactManifestV7 struct {
	ArtifactManifestID string
	Version            uint64
	Entries            []ArtifactEntryV7
}

// Validate checks all MMTemplate properties that do not require dereferencing
// a VirtualPageMap. Sparse VMAs may own zero runs, but their run-table slices
// must form one canonical, gap-free index sequence.
func (template MMTemplateV7) Validate() error {
	if err := validateMetadataV7Identity("MMTemplate ID", template.MMTemplateID); err != nil {
		return err
	}
	if err := metadataV7PositiveLong("MMTemplate version", template.Version); err != nil {
		return err
	}
	if err := validateMetadataV7Identity(
		"runtime compatibility ID", template.RuntimeCompatibilityID); err != nil {
		return err
	}
	if template.PageSize != PublicationV7PageSize {
		return metadataV7Invalidf(
			"MMTemplate page size is %d, expected %d", template.PageSize, PublicationV7PageSize)
	}
	if len(template.VMAs) == 0 || len(template.VMAs) > MaxMetadataV7Entries {
		return metadataV7Invalidf(
			"VMA count %d is outside 1..%d", len(template.VMAs), MaxMetadataV7Entries)
	}

	expectedRunStart := uint64(0)
	previousPagesImageID := uint32(0)
	previousEnd := uint64(0)
	for index, vma := range template.VMAs {
		if vma.PagesImageID == 0 {
			return metadataV7Invalidf("VMA %d has a zero CRIU pages image ID", index)
		}
		if err := metadataV7AlignedRange("VMA", vma.StartVAddr, vma.EndVAddr); err != nil {
			return metadataV7FieldInvalid(fmt.Sprintf("VMA %d", index), err)
		}
		if index > 0 && (vma.PagesImageID < previousPagesImageID ||
			(vma.PagesImageID == previousPagesImageID && vma.StartVAddr < previousEnd)) {
			return metadataV7Invalidf(
				"VMAs overlap or are not ordered by pages image/address at index %d", index)
		}
		if vma.ProtectionFlags&^knownProtectionFlags != 0 {
			return metadataV7Invalidf(
				"VMA %d has unknown protection flags %#x", index, vma.ProtectionFlags)
		}
		if vma.MappingFlags&^knownMappingFlags != 0 {
			return metadataV7Invalidf(
				"VMA %d has unknown mapping flags %#x", index, vma.MappingFlags)
		}
		privacy := vma.MappingFlags & (MappingPrivate | MappingShared)
		if privacy != MappingPrivate && privacy != MappingShared {
			return metadataV7Invalidf(
				"VMA %d must select exactly one of PRIVATE or SHARED", index)
		}
		if !vma.BackingKind.valid() {
			return metadataV7Invalidf(
				"VMA %d has unknown backing kind %d", index, vma.BackingKind)
		}
		anonymous := vma.MappingFlags&MappingAnonymous != 0
		switch vma.BackingKind {
		case BackingAnonymous, BackingZero:
			if !anonymous {
				return metadataV7Invalidf(
					"VMA %d anonymous/zero backing lacks the ANONYMOUS mapping flag", index)
			}
		case BackingArtifact, BackingRestoreBlob:
			if anonymous {
				return metadataV7Invalidf(
					"VMA %d file/blob backing has the ANONYMOUS mapping flag", index)
			}
		}
		if vma.VirtualPageMapRunStart != expectedRunStart {
			return metadataV7Invalidf(
				"VMA %d VirtualPageMap slice has a gap, overlap, or noncanonical start", index)
		}
		if err := metadataV7NonNegativeLong(
			"VirtualPageMap run count", vma.VirtualPageMapRunCount); err != nil {
			return metadataV7FieldInvalid(fmt.Sprintf("VMA %d", index), err)
		}
		runEnd, ok := addLong(vma.VirtualPageMapRunStart, vma.VirtualPageMapRunCount)
		if !ok {
			return metadataV7Invalidf("VMA %d VirtualPageMap slice overflows", index)
		}
		expectedRunStart = runEnd
		previousPagesImageID = vma.PagesImageID
		previousEnd = vma.EndVAddr
	}
	return nil
}

// CrossCheckVirtualPageMap proves that every VirtualPageMap run belongs to
// exactly one VMA slice and stays inside that VMA. The publication supplies
// only payload objects to the V7 mapping validator, so metadata/control pages
// cannot be smuggled into this relationship.
func (template MMTemplateV7) CrossCheckVirtualPageMap(
	publication PublicationV7,
	virtualPageMap VirtualPageMap,
) error {
	if err := publication.Validate(); err != nil {
		return metadataV7FieldInvalid("immutable publication", err)
	}
	if err := template.Validate(); err != nil {
		return err
	}
	contentObjects := publication.mappingContentObjectsValidated()
	return template.crossCheckVirtualPageMapValidated(
		publication, virtualPageMap, contentObjects)
}

func (template MMTemplateV7) crossCheckVirtualPageMapValidated(
	publication PublicationV7,
	virtualPageMap VirtualPageMap,
	contentObjects []ContentObject,
) error {
	if template.MMTemplateID != publication.MMTemplate.MMTemplateID ||
		template.Version != publication.MMTemplate.Version {
		return metadataV7Invalidf(
			"MMTemplate semantic identity/version does not match its publication reference")
	}
	if virtualPageMap.VirtualPageMapID != publication.VirtualPageMap.VirtualPageMapID ||
		virtualPageMap.Version != publication.VirtualPageMap.Version {
		return metadataV7Invalidf(
			"VirtualPageMap semantic identity/version does not match its publication reference")
	}
	if err := virtualPageMap.Validate(contentObjects); err != nil {
		return metadataV7FieldInvalid("VirtualPageMap", err)
	}

	expectedRun := uint64(0)
	for vmaIndex, vma := range template.VMAs {
		runEnd, ok := addLong(vma.VirtualPageMapRunStart, vma.VirtualPageMapRunCount)
		if !ok || runEnd > uint64(len(virtualPageMap.Runs)) {
			return metadataV7Invalidf(
				"VMA %d VirtualPageMap slice exceeds the run table", vmaIndex)
		}
		if vma.VirtualPageMapRunStart != expectedRun {
			return metadataV7Invalidf(
				"VMA %d VirtualPageMap slice does not begin at run %d",
				vmaIndex, expectedRun)
		}
		previousRunEnd := vma.StartVAddr
		for runIndex := vma.VirtualPageMapRunStart; runIndex < runEnd; runIndex++ {
			run := virtualPageMap.Runs[runIndex]
			if run.PagesImageID != vma.PagesImageID {
				return metadataV7Invalidf(
					"VMA %d VirtualPageMap run %d names pages image %d, expected %d",
					vmaIndex, runIndex, run.PagesImageID, vma.PagesImageID)
			}
			if run.StartVAddr < previousRunEnd || run.StartVAddr < vma.StartVAddr {
				return metadataV7Invalidf(
					"VMA %d VirtualPageMap runs overlap or are not ordered", vmaIndex)
			}
			bytes, ok := mulLong(run.PageCount, PublicationV7PageSize)
			if !ok {
				return metadataV7Invalidf(
					"VMA %d VirtualPageMap run %d byte range overflows", vmaIndex, runIndex)
			}
			previousRunEnd, ok = addLong(run.StartVAddr, bytes)
			if !ok || previousRunEnd > vma.EndVAddr {
				return metadataV7Invalidf(
					"VMA %d VirtualPageMap run %d extends beyond the VMA", vmaIndex, runIndex)
			}
		}
		expectedRun = runEnd
	}
	if expectedRun != uint64(len(virtualPageMap.Runs)) {
		return metadataV7Invalidf(
			"MMTemplate consumes %d of %d VirtualPageMap runs",
			expectedRun, len(virtualPageMap.Runs))
	}
	return nil
}

// Validate checks the portable artifact namespace without dereferencing a
// publication. CrossCheckPublication performs the payload-kind/range proof.
func (manifest ArtifactManifestV7) Validate() error {
	if err := validateMetadataV7Identity(
		"ArtifactManifest ID", manifest.ArtifactManifestID); err != nil {
		return err
	}
	if err := metadataV7PositiveLong("ArtifactManifest version", manifest.Version); err != nil {
		return err
	}
	if len(manifest.Entries) > MaxMetadataV7Entries {
		return metadataV7Invalidf(
			"artifact entry count %d exceeds %d",
			len(manifest.Entries), MaxMetadataV7Entries)
	}
	previousPath := ""
	for index, entry := range manifest.Entries {
		if err := validateMetadataV7ArtifactPath(entry.Path); err != nil {
			return metadataV7FieldInvalid(fmt.Sprintf("artifact entry %d", index), err)
		}
		if index > 0 && previousPath >= entry.Path {
			return metadataV7Invalidf(
				"artifact entries are duplicate or not strictly ordered by path")
		}
		previousPath = entry.Path
		if !entry.Type.valid() {
			return metadataV7Invalidf(
				"artifact entry %q has unknown type %d", entry.Path, entry.Type)
		}
		for _, field := range []struct {
			name  string
			value uint64
		}{
			{name: "mode", value: entry.Mode},
			{name: "UID", value: entry.UID},
			{name: "GID", value: entry.GID},
			{name: "byte length", value: entry.ByteLength},
			{name: "content object ID", value: entry.ContentObjectID},
			{name: "content offset", value: entry.ContentOffset},
		} {
			if err := metadataV7NonNegativeLong("artifact "+field.name, field.value); err != nil {
				return metadataV7FieldInvalid(fmt.Sprintf("artifact entry %q", entry.Path), err)
			}
		}
		switch entry.Type {
		case ArtifactRegular:
			if entry.LinkTarget != "" {
				return metadataV7Invalidf("regular artifact %q has a link target", entry.Path)
			}
			if entry.ByteLength == 0 {
				if entry.ContentObjectID != 0 || entry.ContentOffset != 0 {
					return metadataV7Invalidf(
						"empty artifact %q has a content reference", entry.Path)
				}
			} else if entry.ContentObjectID == 0 {
				return metadataV7Invalidf(
					"non-empty artifact %q has no content object", entry.Path)
			}
		case ArtifactDirectory:
			if entry.ByteLength != 0 || entry.ContentObjectID != 0 ||
				entry.ContentOffset != 0 || entry.LinkTarget != "" {
				return metadataV7Invalidf(
					"directory artifact %q carries file content", entry.Path)
			}
		case ArtifactSymlink:
			if err := validateMetadataV7Text(
				"artifact link target", entry.LinkTarget, false); err != nil {
				return metadataV7FieldInvalid(fmt.Sprintf("artifact entry %q", entry.Path), err)
			}
			if entry.ByteLength != 0 || entry.ContentObjectID != 0 || entry.ContentOffset != 0 {
				return metadataV7Invalidf(
					"symlink artifact %q carries file content", entry.Path)
			}
		}
	}
	return nil
}

// CrossCheckPublication verifies every non-empty regular-file range against
// an ArtifactPayload object in the immutable publication. Restore blobs,
// memory payload, metadata, slots, and publication bytes are never accepted as
// artifact file data.
func (manifest ArtifactManifestV7) CrossCheckPublication(
	publication PublicationV7,
) error {
	if err := publication.Validate(); err != nil {
		return metadataV7FieldInvalid("immutable publication", err)
	}
	if err := manifest.Validate(); err != nil {
		return err
	}
	return manifest.crossCheckPublicationValidated(publication)
}

type artifactPayloadRangeV7 struct {
	start uint64
	end   uint64
}

func (manifest ArtifactManifestV7) crossCheckPublicationValidated(
	publication PublicationV7,
) error {
	if manifest.ArtifactManifestID != publication.ArtifactManifest.ArtifactManifestID ||
		manifest.Version != publication.ArtifactManifest.Version {
		return metadataV7Invalidf(
			"ArtifactManifest semantic identity/version does not match its publication reference")
	}
	payloadRanges := make(map[uint64][]artifactPayloadRangeV7)
	for _, entry := range manifest.Entries {
		if entry.Type != ArtifactRegular || entry.ByteLength == 0 {
			continue
		}
		object, exists := publication.objectByID(entry.ContentObjectID)
		if !exists || object.Kind != ContentArtifactPayloadV7 {
			return metadataV7Invalidf(
				"artifact %q content object %d is missing or is not ArtifactPayload",
				entry.Path, entry.ContentObjectID)
		}
		end, ok := addLong(entry.ContentOffset, entry.ByteLength)
		if !ok || end > object.ImmutableByteLength {
			return metadataV7Invalidf(
				"artifact %q byte range exceeds ArtifactPayload object %d",
				entry.Path, entry.ContentObjectID)
		}
		payloadRanges[entry.ContentObjectID] = append(
			payloadRanges[entry.ContentObjectID],
			artifactPayloadRangeV7{start: entry.ContentOffset, end: end})
	}
	for _, object := range publication.Objects {
		if object.Kind != ContentArtifactPayloadV7 {
			continue
		}
		ranges := payloadRanges[object.ObjectID]
		sort.Slice(ranges, func(left, right int) bool {
			if ranges[left].start != ranges[right].start {
				return ranges[left].start < ranges[right].start
			}
			return ranges[left].end < ranges[right].end
		})
		expectedOffset := uint64(0)
		for rangeIndex, contentRange := range ranges {
			if contentRange.start != expectedOffset {
				return metadataV7Invalidf(
					"ArtifactPayload object %d range %d begins at %d, expected %d",
					object.ObjectID, rangeIndex, contentRange.start, expectedOffset)
			}
			expectedOffset = contentRange.end
		}
		if expectedOffset != object.ImmutableByteLength {
			return metadataV7Invalidf(
				"ArtifactPayload object %d is covered through byte %d, expected exact length %d",
				object.ObjectID, expectedOffset, object.ImmutableByteLength)
		}
	}
	return nil
}

func validateMetadataV7Identity(name, value string) error {
	if err := validateMetadataV7Text(name, value, true); err != nil {
		return err
	}
	return nil
}

func validateMetadataV7Text(name, value string, trim bool) error {
	if value == "" {
		return metadataV7Invalidf("%s is empty", name)
	}
	if !utf8.ValidString(value) {
		return metadataV7Invalidf("%s is not valid UTF-8", name)
	}
	if len(value) > MaxPublicationV7IdentityBytes {
		return metadataV7Invalidf(
			"%s is %d UTF-8 bytes, limit is %d",
			name, len(value), MaxPublicationV7IdentityBytes)
	}
	if trim && strings.TrimSpace(value) != value {
		return metadataV7Invalidf("%s has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return metadataV7Invalidf("%s contains a control character", name)
		}
	}
	return nil
}

func validateMetadataV7ArtifactPath(value string) error {
	if err := validateMetadataV7Text("artifact path", value, false); err != nil {
		return err
	}
	if pathpkg.IsAbs(value) || value == "." || value == ".." || pathpkg.Clean(value) != value ||
		strings.HasPrefix(value, "../") {
		return metadataV7Invalidf("artifact path %q is not a clean relative path", value)
	}
	return nil
}

func metadataV7AlignedRange(name string, start, end uint64) error {
	if err := metadataV7NonNegativeLong(name+" start", start); err != nil {
		return err
	}
	if err := metadataV7NonNegativeLong(name+" end", end); err != nil {
		return err
	}
	if start%PublicationV7PageSize != 0 || end%PublicationV7PageSize != 0 {
		return metadataV7Invalidf("%s range [%#x,%#x) is not 4 KiB aligned", name, start, end)
	}
	if start >= end {
		return metadataV7Invalidf("%s start %#x is not below end %#x", name, start, end)
	}
	return nil
}

func metadataV7PositiveLong(name string, value uint64) error {
	if value == 0 || value > MaxSignedLong {
		return metadataV7Invalidf(
			"%s %d is outside 1..%d", name, value, MaxSignedLong)
	}
	return nil
}

func metadataV7NonNegativeLong(name string, value uint64) error {
	if value > MaxSignedLong {
		return metadataV7Invalidf("%s %d exceeds %d", name, value, MaxSignedLong)
	}
	return nil
}

func metadataV7FieldInvalid(context string, err error) error {
	return fmt.Errorf("%s: %v: %w", context, err, ErrInvalidMetadataV7)
}

func metadataV7Invalidf(format string, arguments ...interface{}) error {
	return fmt.Errorf(format+": %w", append(arguments, ErrInvalidMetadataV7)...)
}
