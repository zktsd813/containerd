package trenvpub

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	Version          uint32 = 5
	ContentType             = "application/vnd.trenv.publication.v5"
	ManifestSchema          = "trenv.artifact/v5"
	DedupApplySchema        = "trenv.dedup/base-restore-map-v1"
	Extension               = ".trpub"

	DedupRestoreCOWPhase  = "dedup-restore-cow"
	restoreExtentPageSize = 4096

	RestoreExtentTypeSharedReadonly uint32 = 0
	RestoreExtentFlagCOW            uint32 = 1
)

var magicV5 = [8]byte{'T', 'R', 'P', 'U', 'B', '0', '0', '5'}

type SectionType uint32

const (
	SectionIdentity SectionType = 1
	SectionArtifact SectionType = 2
	SectionShards   SectionType = 3
	SectionBaseMap  SectionType = 4
	// Section type 5 was the V4 DedupDelta section. V5 deliberately leaves
	// the value unused and rejects it when decoding.
	SectionStats   SectionType = 6
	SectionStorage SectionType = 7
	SectionFiles   SectionType = 8
)

type ActionIdentity struct {
	Namespace          string
	FullyQualifiedName string
	Revision           string
}

type Publication struct {
	Version                    uint32
	ManifestSchema             string
	DedupApplySchema           string
	ArtifactID                 string
	CheckpointID               string
	Generation                 uint64
	WriterEpoch                uint64
	State                      string
	CheckpointPhase            string
	Fingerprint                string
	SnapshotStartMode          string
	RuntimeKind                string
	RuntimeFamily              string
	ActionIdentity             *ActionIdentity
	CheckpointPath             string
	MetadataBundlePath         string
	PlacementPath              string
	CheckpointActionExportRoot string
	MetadataBundleSize         int64
	PageExtent                 StorageExtent
	ArtifactExtent             StorageExtent
	Files                      []ArtifactFile
	Shards                     []Shard
	BaseRestoreMap             []RestoreExtent
	Stats                      Stats
	CreatedAt                  time.Time
}

type Shard struct {
	WriterID       string
	ShardID        string
	DaxDevice      string
	DaxStartPage   int64
	DaxLengthPages int64
	PageCount      int64
	PageSize       int64
	Layout         string
}

type StorageExtent struct {
	Role           string `json:"role"`
	DeviceIdentity string `json:"device_identity"`
	ShardID        string `json:"shard_id"`
	OffsetBytes    int64  `json:"offset_bytes"`
	LengthBytes    int64  `json:"length_bytes"`
	PayloadBytes   int64  `json:"payload_bytes"`
	PageSize       int64  `json:"page_size"`
	Layout         string `json:"layout"`
}

type ArtifactFile struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid,omitempty"`
	GID        uint32 `json:"gid,omitempty"`
	Offset     int64  `json:"offset,omitempty"`
	Length     int64  `json:"length,omitempty"`
	LinkTarget string `json:"link_target,omitempty"`
}

type RestoreExtent struct {
	Vaddr      uint64
	NrPages    uint64
	Pgoff      uint64
	ShardIndex uint32
	Type       uint32
	Flags      uint32
}

type Stats struct {
	RestoreMapExtentCount uint64
	DedupAppliedPages     uint64
	SkippedWritablePages  uint64
}

type sectionHeader struct {
	typ    SectionType
	flags  uint32
	offset uint64
	size   uint64
}

func NormalizePath(path string) string {
	if filepath.Ext(path) == ".json" {
		return path[:len(path)-len(".json")] + Extension
	}
	return path
}

func ReadFile(path string) (Publication, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Publication{}, err
	}
	pub, err := Decode(data)
	if err != nil {
		return Publication{}, fmt.Errorf("decode binary publication %q: %w", path, err)
	}
	return pub, nil
}

func WriteFileNoReplace(path string, pub Publication) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := Encode(pub)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("publication metadata already exists at %q", path)
		}
		return err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func DerivedDedupArtifactID(base Publication, createdAt time.Time) string {
	artifactID := base.ArtifactID
	if artifactID == "" {
		artifactID = base.CheckpointID
	}
	if artifactID == "" {
		artifactID = "checkpoint"
	}
	return fmt.Sprintf("%s-dedup-%s", artifactID, createdAt.UTC().Format("20060102T150405.000000000Z"))
}

func CoalesceRestoreExtents(extents []RestoreExtent) []RestoreExtent {
	if len(extents) == 0 {
		return nil
	}
	out := append([]RestoreExtent(nil), extents...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vaddr != out[j].Vaddr {
			return out[i].Vaddr < out[j].Vaddr
		}
		if out[i].ShardIndex != out[j].ShardIndex {
			return out[i].ShardIndex < out[j].ShardIndex
		}
		return out[i].Pgoff < out[j].Pgoff
	})
	write := 0
	for _, extent := range out {
		if extent.NrPages == 0 {
			continue
		}
		if write > 0 {
			prev := &out[write-1]
			nextVaddr := prev.Vaddr + prev.NrPages*restoreExtentPageSize
			nextPgoff := prev.Pgoff + prev.NrPages
			if prev.ShardIndex == extent.ShardIndex && prev.Type == extent.Type && prev.Flags == extent.Flags &&
				nextVaddr == extent.Vaddr && nextPgoff == extent.Pgoff {
				prev.NrPages += extent.NrPages
				continue
			}
		}
		out[write] = extent
		write++
	}
	return out[:write]
}

// ValidatePublication validates the complete fresh-reset V5 publication
// contract. It is intentionally suitable for callers that decode a portable
// publication and need to reject malformed restore maps before discovery or
// restore.
func ValidatePublication(pub Publication) error {
	if pub.Version != Version {
		return fmt.Errorf("publication version is %d, expected %d", pub.Version, Version)
	}
	if pub.ManifestSchema != ManifestSchema {
		return fmt.Errorf("manifest schema is %q, expected %q", pub.ManifestSchema, ManifestSchema)
	}
	if pub.DedupApplySchema != DedupApplySchema {
		return fmt.Errorf("dedup apply schema is %q, expected %q", pub.DedupApplySchema, DedupApplySchema)
	}
	if strings.TrimSpace(pub.ArtifactID) == "" || strings.TrimSpace(pub.CheckpointID) == "" {
		return errors.New("publication artifact or checkpoint identity is empty")
	}
	if pub.State != "COMMITTED" {
		return fmt.Errorf("publication state is %q, expected COMMITTED", pub.State)
	}
	if strings.TrimSpace(pub.CheckpointPhase) == "" ||
		strings.TrimSpace(pub.Fingerprint) == "" ||
		strings.TrimSpace(pub.SnapshotStartMode) == "" ||
		strings.TrimSpace(pub.RuntimeKind) == "" ||
		strings.TrimSpace(pub.RuntimeFamily) == "" {
		return errors.New("publication runtime identity is incomplete")
	}
	if pub.Generation == 0 || pub.WriterEpoch == 0 {
		return errors.New("publication generation or writer epoch is zero")
	}
	if pub.CreatedAt.IsZero() {
		return errors.New("publication created_at is zero")
	}
	if pub.MetadataBundleSize < 0 {
		return errors.New("publication metadata bundle size is negative")
	}
	if pub.ActionIdentity != nil &&
		(strings.TrimSpace(pub.ActionIdentity.Namespace) == "" ||
			strings.TrimSpace(pub.ActionIdentity.FullyQualifiedName) == "" ||
			strings.TrimSpace(pub.ActionIdentity.Revision) == "") {
		return errors.New("publication action identity is incomplete")
	}
	if err := validateShards(pub.Shards); err != nil {
		return err
	}
	if err := validateStorageExtent(pub.PageExtent, "criu-pages"); err != nil {
		return fmt.Errorf("page extent: %w", err)
	}
	if err := validateStorageExtent(pub.ArtifactExtent, "restore-artifact"); err != nil {
		return fmt.Errorf("artifact extent: %w", err)
	}
	if pub.PageExtent.ShardID == pub.ArtifactExtent.ShardID {
		pageEnd, err := checkedInt64End(pub.PageExtent.OffsetBytes, pub.PageExtent.LengthBytes)
		if err != nil {
			return fmt.Errorf("page extent: %w", err)
		}
		artifactEnd, err := checkedInt64End(pub.ArtifactExtent.OffsetBytes, pub.ArtifactExtent.LengthBytes)
		if err != nil {
			return fmt.Errorf("artifact extent: %w", err)
		}
		if pub.PageExtent.OffsetBytes < artifactEnd && pub.ArtifactExtent.OffsetBytes < pageEnd {
			return errors.New("page and artifact extents overlap")
		}
	}
	if err := validatePageExtentShard(pub.PageExtent, pub.Shards); err != nil {
		return err
	}
	if err := validateArtifactFiles(pub.ArtifactExtent, pub.Files); err != nil {
		return err
	}
	if err := validateRestoreMap(pub); err != nil {
		return err
	}
	return nil
}

func validateShards(shards []Shard) error {
	if len(shards) == 0 {
		return errors.New("publication shard table is empty")
	}
	seen := make(map[string]struct{}, len(shards))
	for index, shard := range shards {
		if strings.TrimSpace(shard.WriterID) == "" ||
			strings.TrimSpace(shard.ShardID) == "" ||
			strings.TrimSpace(shard.Layout) == "" {
			return fmt.Errorf("shard %d identity is incomplete", index)
		}
		if _, ok := seen[shard.ShardID]; ok {
			return fmt.Errorf("duplicate shard id %q", shard.ShardID)
		}
		seen[shard.ShardID] = struct{}{}
		if shard.DaxStartPage < 0 || shard.DaxLengthPages <= 0 || shard.PageCount < 0 ||
			shard.PageCount > shard.DaxLengthPages || shard.PageSize <= 0 {
			return fmt.Errorf("shard %d geometry is invalid", index)
		}
		if shard.DaxStartPage > math.MaxInt64-shard.DaxLengthPages ||
			shard.DaxStartPage > math.MaxInt64/shard.PageSize ||
			shard.DaxLengthPages > math.MaxInt64/shard.PageSize ||
			shard.PageCount > math.MaxInt64/shard.PageSize {
			return fmt.Errorf("shard %d geometry overflows int64", index)
		}
	}
	return nil
}

func validateStorageExtent(extent StorageExtent, role string) error {
	if extent.Role != role {
		return fmt.Errorf("role is %q, expected %q", extent.Role, role)
	}
	if strings.TrimSpace(extent.DeviceIdentity) == "" ||
		strings.TrimSpace(extent.ShardID) == "" ||
		extent.DeviceIdentity != extent.ShardID ||
		strings.TrimSpace(extent.Layout) == "" {
		return errors.New("stable shard identity is incomplete")
	}
	if extent.OffsetBytes < 0 || extent.LengthBytes <= 0 || extent.PayloadBytes <= 0 ||
		extent.PayloadBytes > extent.LengthBytes || extent.PageSize <= 0 {
		return errors.New("range is invalid")
	}
	if extent.OffsetBytes%extent.PageSize != 0 || extent.LengthBytes%extent.PageSize != 0 {
		return errors.New("range is not page aligned")
	}
	if _, err := checkedInt64End(extent.OffsetBytes, extent.LengthBytes); err != nil {
		return err
	}
	return nil
}

func validatePageExtentShard(extent StorageExtent, shards []Shard) error {
	for _, shard := range shards {
		if shard.ShardID != extent.ShardID {
			continue
		}
		if shard.PageSize != extent.PageSize ||
			shard.DaxStartPage*shard.PageSize != extent.OffsetBytes ||
			shard.DaxLengthPages*shard.PageSize != extent.LengthBytes ||
			shard.PageCount*shard.PageSize != extent.PayloadBytes ||
			shard.Layout != extent.Layout {
			return errors.New("page extent does not match its shard geometry")
		}
		return nil
	}
	return fmt.Errorf("page extent references unknown shard %q", extent.ShardID)
}

func validateArtifactFiles(extent StorageExtent, files []ArtifactFile) error {
	if len(files) == 0 {
		return errors.New("artifact file table is empty")
	}
	seen := make(map[string]struct{}, len(files))
	regular := make([]ArtifactFile, 0, len(files))
	previousPath := ""
	for _, file := range files {
		if file.Path == "" || strings.Contains(file.Path, "\\") || path.IsAbs(file.Path) ||
			path.Clean(file.Path) != file.Path || file.Path == "." || strings.HasPrefix(file.Path, "../") {
			return fmt.Errorf("unsafe artifact path %q", file.Path)
		}
		if _, ok := seen[file.Path]; ok {
			return fmt.Errorf("duplicate artifact path %q", file.Path)
		}
		if previousPath != "" && file.Path < previousPath {
			return errors.New("artifact file table is not path sorted")
		}
		previousPath = file.Path
		seen[file.Path] = struct{}{}
		switch file.Type {
		case "regular":
			if file.Offset < 0 || file.Length < 0 || file.Offset%extent.PageSize != 0 || file.LinkTarget != "" {
				return fmt.Errorf("regular artifact file %q has invalid metadata", file.Path)
			}
			end, err := checkedInt64End(file.Offset, file.Length)
			if err != nil || end > extent.PayloadBytes {
				return fmt.Errorf("regular artifact file %q is outside its extent", file.Path)
			}
			if file.Length > 0 {
				regular = append(regular, file)
			}
		case "directory":
			if file.Offset != 0 || file.Length != 0 || file.LinkTarget != "" {
				return fmt.Errorf("directory %q has payload metadata", file.Path)
			}
		case "symlink":
			if file.Offset != 0 || file.Length != 0 || !safeArtifactSymlink(file.Path, file.LinkTarget) {
				return fmt.Errorf("symlink %q has unsafe metadata", file.Path)
			}
		default:
			return fmt.Errorf("artifact file %q has unsupported type %q", file.Path, file.Type)
		}
	}
	sort.Slice(regular, func(i, j int) bool { return regular[i].Offset < regular[j].Offset })
	for i := 1; i < len(regular); i++ {
		previousEnd, _ := checkedInt64End(regular[i-1].Offset, regular[i-1].Length)
		if regular[i].Offset < previousEnd {
			return fmt.Errorf("artifact files %q and %q overlap", regular[i-1].Path, regular[i].Path)
		}
	}
	return nil
}

func safeArtifactSymlink(_ string, target string) bool {
	// The artifact path itself is constrained to the projection root above,
	// but link targets must retain the action filesystem's original semantics.
	// Python virtualenvs commonly contain absolute links into the runtime image
	// and relative links that leave the exported action directory. The reader
	// creates the link verbatim and never follows it while materializing files.
	return target != "" && !strings.ContainsRune(target, '\x00')
}

func validateRestoreMap(pub Publication) error {
	if len(pub.BaseRestoreMap) == 0 {
		if pub.CheckpointPhase == DedupRestoreCOWPhase ||
			pub.Stats.RestoreMapExtentCount != 0 ||
			pub.Stats.DedupAppliedPages != 0 ||
			pub.Stats.SkippedWritablePages != 0 {
			return errors.New("publication without a restore map has dedup phase or stats")
		}
		return nil
	}
	if pub.CheckpointPhase != DedupRestoreCOWPhase {
		return errors.New("materialized restore map requires the dedup restore phase")
	}
	if pub.Stats.RestoreMapExtentCount != uint64(len(pub.BaseRestoreMap)) {
		return errors.New("restore map extent count does not match stats")
	}
	var appliedPages uint64
	var previousEnd uint64
	for index, extent := range pub.BaseRestoreMap {
		if extent.NrPages == 0 || extent.Vaddr == 0 || extent.Vaddr%restoreExtentPageSize != 0 {
			return fmt.Errorf("restore extent %d target geometry is invalid", index)
		}
		if extent.Type != RestoreExtentTypeSharedReadonly || extent.Flags != RestoreExtentFlagCOW {
			return fmt.Errorf("restore extent %d type or flags are invalid", index)
		}
		if int(extent.ShardIndex) >= len(pub.Shards) {
			return fmt.Errorf("restore extent %d references missing shard %d", index, extent.ShardIndex)
		}
		if extent.NrPages > (math.MaxUint64-extent.Vaddr)/restoreExtentPageSize {
			return fmt.Errorf("restore extent %d target range overflows", index)
		}
		targetEnd := extent.Vaddr + extent.NrPages*restoreExtentPageSize
		if index > 0 && extent.Vaddr < previousEnd {
			return errors.New("restore map target ranges overlap or are not sorted")
		}
		previousEnd = targetEnd
		if extent.Pgoff > math.MaxUint64-extent.NrPages {
			return fmt.Errorf("restore extent %d page offset overflows", index)
		}
		shard := pub.Shards[extent.ShardIndex]
		shardStart := uint64(shard.DaxStartPage)
		shardEnd := shardStart + uint64(shard.DaxLengthPages)
		if extent.Pgoff < shardStart || extent.Pgoff+extent.NrPages > shardEnd {
			return fmt.Errorf("restore extent %d is outside shard %d", index, extent.ShardIndex)
		}
		if math.MaxUint64-appliedPages < extent.NrPages {
			return errors.New("dedup applied page count overflows uint64")
		}
		appliedPages += extent.NrPages
	}
	if pub.Stats.DedupAppliedPages != appliedPages {
		return errors.New("dedup applied page count does not match restore map")
	}
	return nil
}

func checkedInt64End(offset, length int64) (int64, error) {
	if offset < 0 || length < 0 || offset > math.MaxInt64-length {
		return 0, errors.New("range overflows int64")
	}
	return offset + length, nil
}

func DeriveDedupPublication(base Publication, restoreMap []RestoreExtent, stats Stats, createdAt time.Time) (Publication, error) {
	if err := ValidatePublication(base); err != nil {
		return Publication{}, fmt.Errorf("validate base publication: %w", err)
	}
	if len(base.BaseRestoreMap) != 0 {
		return Publication{}, errors.New("base publication already has a materialized restore map")
	}
	materialized := CoalesceRestoreExtents(restoreMap)
	if len(materialized) == 0 {
		return Publication{}, errors.New("materialized base restore map is empty")
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	derived := base
	derived.ArtifactID = DerivedDedupArtifactID(base, createdAt)
	if derived.CheckpointID == "" {
		derived.CheckpointID = base.ArtifactID
	}
	derived.State = "COMMITTED"
	derived.CheckpointPhase = DedupRestoreCOWPhase
	derived.BaseRestoreMap = materialized
	derived.CreatedAt = createdAt.UTC()
	derived.Shards = append([]Shard(nil), base.Shards...)
	derived.Files = append([]ArtifactFile(nil), base.Files...)
	stats.RestoreMapExtentCount = uint64(len(materialized))
	stats.DedupAppliedPages = 0
	for _, extent := range materialized {
		if math.MaxUint64-stats.DedupAppliedPages < extent.NrPages {
			return Publication{}, errors.New("dedup applied page count overflows uint64")
		}
		stats.DedupAppliedPages += extent.NrPages
	}
	derived.Stats = stats
	if err := ValidatePublication(derived); err != nil {
		return Publication{}, fmt.Errorf("validate derived publication: %w", err)
	}
	return derived, nil
}

func WriteDerivedDedupPublication(basePath, outputPath string, restoreMap []RestoreExtent, stats Stats, createdAt time.Time) (Publication, error) {
	base, err := ReadFile(basePath)
	if err != nil {
		return Publication{}, err
	}
	derived, err := DeriveDedupPublication(base, restoreMap, stats, createdAt)
	if err != nil {
		return Publication{}, err
	}
	if err := WriteFileNoReplace(outputPath, derived); err != nil {
		return Publication{}, err
	}
	return derived, nil
}

func Encode(pub Publication) ([]byte, error) {
	if pub.Version == 0 {
		pub.Version = Version
	}
	if pub.ManifestSchema == "" {
		pub.ManifestSchema = ManifestSchema
	}
	if pub.DedupApplySchema == "" {
		pub.DedupApplySchema = DedupApplySchema
	}
	if err := ValidatePublication(pub); err != nil {
		return nil, err
	}

	sections := []sectionHeader{}
	payloads := [][]byte{}
	addSection := func(typ SectionType, payload []byte) {
		header := sectionHeader{typ: typ, size: uint64(len(payload))}
		sections = append(sections, header)
		payloads = append(payloads, payload)
	}

	identity, err := encodeIdentity(pub)
	if err != nil {
		return nil, err
	}
	artifact, err := encodeArtifact(pub)
	if err != nil {
		return nil, err
	}
	shards, err := encodeShards(pub.Shards)
	if err != nil {
		return nil, err
	}
	baseMap, err := encodeExtents(pub.BaseRestoreMap)
	if err != nil {
		return nil, err
	}
	stats, err := encodeStats(pub.Stats)
	if err != nil {
		return nil, err
	}
	storage, err := encodeStorage(pub.PageExtent, pub.ArtifactExtent)
	if err != nil {
		return nil, err
	}
	files, err := encodeFiles(pub.Files)
	if err != nil {
		return nil, err
	}

	addSection(SectionIdentity, identity)
	addSection(SectionArtifact, artifact)
	addSection(SectionShards, shards)
	addSection(SectionBaseMap, baseMap)
	addSection(SectionStats, stats)
	addSection(SectionStorage, storage)
	addSection(SectionFiles, files)

	const fileHeaderSize = 24
	const sectionHeaderSize = 24
	offset := uint64(fileHeaderSize + len(sections)*sectionHeaderSize)
	for i := range sections {
		sections[i].offset = offset
		offset += sections[i].size
	}

	var out bytes.Buffer
	out.Write(magicV5[:])
	writeU32(&out, Version)
	writeU32(&out, 0)
	writeU32(&out, uint32(len(sections)))
	writeU32(&out, 0)
	for _, section := range sections {
		writeU32(&out, uint32(section.typ))
		writeU32(&out, section.flags)
		writeU64(&out, section.offset)
		writeU64(&out, section.size)
	}
	for _, payload := range payloads {
		out.Write(payload)
	}
	return out.Bytes(), nil
}

func Decode(data []byte) (Publication, error) {
	reader := bytes.NewReader(data)
	var gotMagic [8]byte
	if _, err := io.ReadFull(reader, gotMagic[:]); err != nil {
		return Publication{}, err
	}
	if gotMagic != magicV5 {
		return Publication{}, errors.New("invalid V5 magic")
	}
	version, err := readU32(reader)
	if err != nil {
		return Publication{}, err
	}
	if version != Version {
		return Publication{}, fmt.Errorf("unsupported version %d", version)
	}
	headerFlags, err := readU32(reader)
	if err != nil {
		return Publication{}, err
	}
	if headerFlags != 0 {
		return Publication{}, fmt.Errorf("unsupported V5 header flags %#x", headerFlags)
	}
	sectionCount, err := readU32(reader)
	if err != nil {
		return Publication{}, err
	}
	reserved, err := readU32(reader)
	if err != nil {
		return Publication{}, err
	}
	if reserved != 0 {
		return Publication{}, errors.New("V5 header reserved field is non-zero")
	}

	requiredSections := [...]SectionType{
		SectionIdentity,
		SectionArtifact,
		SectionShards,
		SectionBaseMap,
		SectionStats,
		SectionStorage,
		SectionFiles,
	}
	if sectionCount != uint32(len(requiredSections)) {
		return Publication{}, fmt.Errorf("invalid V5 section count %d", sectionCount)
	}
	sections := make([]sectionHeader, sectionCount)
	for i := range sections {
		typ, err := readU32(reader)
		if err != nil {
			return Publication{}, err
		}
		flags, err := readU32(reader)
		if err != nil {
			return Publication{}, err
		}
		offset, err := readU64(reader)
		if err != nil {
			return Publication{}, err
		}
		size, err := readU64(reader)
		if err != nil {
			return Publication{}, err
		}
		if SectionType(typ) != requiredSections[i] {
			return Publication{}, fmt.Errorf("unexpected V5 section %d at index %d", typ, i)
		}
		if flags != 0 {
			return Publication{}, fmt.Errorf("unsupported flags %#x for section %d", flags, typ)
		}
		sections[i].typ = SectionType(typ)
		sections[i].flags = flags
		sections[i].offset = offset
		sections[i].size = size
	}

	expectedOffset := uint64(24 + len(requiredSections)*24)
	for _, section := range sections {
		if section.offset != expectedOffset {
			return Publication{}, fmt.Errorf("section %d has non-contiguous offset %d, expected %d", section.typ, section.offset, expectedOffset)
		}
		if expectedOffset > uint64(len(data)) {
			return Publication{}, fmt.Errorf("section %d starts out of bounds", section.typ)
		}
		if section.size > uint64(len(data))-expectedOffset {
			return Publication{}, fmt.Errorf("section %d is out of bounds", section.typ)
		}
		expectedOffset += section.size
	}
	if expectedOffset != uint64(len(data)) {
		return Publication{}, fmt.Errorf("V5 publication has %d trailing bytes", uint64(len(data))-expectedOffset)
	}

	pub := Publication{Version: version}
	for _, section := range sections {
		payload := data[section.offset : section.offset+section.size]
		switch section.typ {
		case SectionIdentity:
			if err := decodeIdentity(payload, &pub); err != nil {
				return Publication{}, err
			}
		case SectionArtifact:
			if err := decodeArtifact(payload, &pub); err != nil {
				return Publication{}, err
			}
		case SectionShards:
			shards, err := decodeShards(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.Shards = shards
		case SectionBaseMap:
			extents, err := decodeExtents(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.BaseRestoreMap = extents
		case SectionStats:
			stats, err := decodeStats(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.Stats = stats
		case SectionStorage:
			pageExtent, artifactExtent, err := decodeStorage(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.PageExtent = pageExtent
			pub.ArtifactExtent = artifactExtent
		case SectionFiles:
			files, err := decodeFiles(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.Files = files
		default:
			return Publication{}, fmt.Errorf("unknown section %d", section.typ)
		}
	}
	if err := ValidatePublication(pub); err != nil {
		return Publication{}, err
	}
	return pub, nil
}

func encodeIdentity(pub Publication) ([]byte, error) {
	var out bytes.Buffer
	writeString(&out, pub.ManifestSchema)
	writeString(&out, pub.DedupApplySchema)
	writeString(&out, pub.ArtifactID)
	writeString(&out, pub.CheckpointID)
	writeString(&out, pub.State)
	writeString(&out, pub.CheckpointPhase)
	writeString(&out, pub.Fingerprint)
	writeString(&out, pub.SnapshotStartMode)
	writeString(&out, pub.RuntimeKind)
	writeString(&out, pub.RuntimeFamily)
	if pub.ActionIdentity == nil {
		writeU32(&out, 0)
	} else {
		writeU32(&out, 1)
		writeString(&out, pub.ActionIdentity.Namespace)
		writeString(&out, pub.ActionIdentity.FullyQualifiedName)
		writeString(&out, pub.ActionIdentity.Revision)
	}
	writeI64(&out, pub.CreatedAt.UnixNano())
	writeU64(&out, pub.Generation)
	writeU64(&out, pub.WriterEpoch)
	return out.Bytes(), nil
}

func decodeIdentity(data []byte, pub *Publication) error {
	reader := bytes.NewReader(data)
	var err error
	if pub.ManifestSchema, err = readString(reader); err != nil {
		return err
	}
	if pub.DedupApplySchema, err = readString(reader); err != nil {
		return err
	}
	if pub.ArtifactID, err = readString(reader); err != nil {
		return err
	}
	if pub.CheckpointID, err = readString(reader); err != nil {
		return err
	}
	if pub.State, err = readString(reader); err != nil {
		return err
	}
	if pub.CheckpointPhase, err = readString(reader); err != nil {
		return err
	}
	if pub.Fingerprint, err = readString(reader); err != nil {
		return err
	}
	if pub.SnapshotStartMode, err = readString(reader); err != nil {
		return err
	}
	if pub.RuntimeKind, err = readString(reader); err != nil {
		return err
	}
	if pub.RuntimeFamily, err = readString(reader); err != nil {
		return err
	}
	hasIdentity, err := readU32(reader)
	if err != nil {
		return err
	}
	if hasIdentity != 0 {
		identity := &ActionIdentity{}
		if identity.Namespace, err = readString(reader); err != nil {
			return err
		}
		if identity.FullyQualifiedName, err = readString(reader); err != nil {
			return err
		}
		if identity.Revision, err = readString(reader); err != nil {
			return err
		}
		pub.ActionIdentity = identity
	}
	nanos, err := readI64(reader)
	if err != nil {
		return err
	}
	pub.CreatedAt = time.Unix(0, nanos).UTC()
	if pub.Generation, err = readU64(reader); err != nil {
		return err
	}
	if pub.WriterEpoch, err = readU64(reader); err != nil {
		return err
	}
	return ensureEOF(reader)
}

func encodeArtifact(pub Publication) ([]byte, error) {
	var out bytes.Buffer
	writeString(&out, pub.CheckpointPath)
	writeString(&out, pub.MetadataBundlePath)
	writeString(&out, pub.PlacementPath)
	writeString(&out, pub.CheckpointActionExportRoot)
	writeI64(&out, pub.MetadataBundleSize)
	return out.Bytes(), nil
}

func decodeArtifact(data []byte, pub *Publication) error {
	reader := bytes.NewReader(data)
	var err error
	if pub.CheckpointPath, err = readString(reader); err != nil {
		return err
	}
	if pub.MetadataBundlePath, err = readString(reader); err != nil {
		return err
	}
	if pub.PlacementPath, err = readString(reader); err != nil {
		return err
	}
	if pub.CheckpointActionExportRoot, err = readString(reader); err != nil {
		return err
	}
	if pub.MetadataBundleSize, err = readI64(reader); err != nil {
		return err
	}
	return ensureEOF(reader)
}

func encodeShards(shards []Shard) ([]byte, error) {
	var out bytes.Buffer
	if len(shards) > int(^uint32(0)) {
		return nil, errors.New("too many shards")
	}
	writeU32(&out, uint32(len(shards)))
	for _, shard := range shards {
		writeString(&out, shard.WriterID)
		writeString(&out, shard.ShardID)
		writeString(&out, shard.DaxDevice)
		writeI64(&out, shard.DaxStartPage)
		writeI64(&out, shard.DaxLengthPages)
		writeI64(&out, shard.PageCount)
		writeI64(&out, shard.PageSize)
		writeString(&out, shard.Layout)
	}
	return out.Bytes(), nil
}

func decodeShards(data []byte) ([]Shard, error) {
	reader := bytes.NewReader(data)
	count, err := readU32(reader)
	if err != nil {
		return nil, err
	}
	if count > 1024 {
		return nil, fmt.Errorf("too many shards: %d", count)
	}
	shards := make([]Shard, count)
	for i := range shards {
		if shards[i].WriterID, err = readString(reader); err != nil {
			return nil, err
		}
		if shards[i].ShardID, err = readString(reader); err != nil {
			return nil, err
		}
		if shards[i].DaxDevice, err = readString(reader); err != nil {
			return nil, err
		}
		if shards[i].DaxStartPage, err = readI64(reader); err != nil {
			return nil, err
		}
		if shards[i].DaxLengthPages, err = readI64(reader); err != nil {
			return nil, err
		}
		if shards[i].PageCount, err = readI64(reader); err != nil {
			return nil, err
		}
		if shards[i].PageSize, err = readI64(reader); err != nil {
			return nil, err
		}
		if shards[i].Layout, err = readString(reader); err != nil {
			return nil, err
		}
	}
	return shards, ensureEOF(reader)
}

func encodeExtents(extents []RestoreExtent) ([]byte, error) {
	var out bytes.Buffer
	if len(extents) > int(^uint32(0)) {
		return nil, errors.New("too many restore extents")
	}
	writeU32(&out, uint32(len(extents)))
	for _, extent := range extents {
		writeU64(&out, extent.Vaddr)
		writeU64(&out, extent.NrPages)
		writeU64(&out, extent.Pgoff)
		writeU32(&out, extent.ShardIndex)
		writeU32(&out, extent.Type)
		writeU32(&out, extent.Flags)
		writeU32(&out, 0)
	}
	return out.Bytes(), nil
}

func decodeExtents(data []byte) ([]RestoreExtent, error) {
	reader := bytes.NewReader(data)
	count, err := readU32(reader)
	if err != nil {
		return nil, err
	}
	if count > 1<<24 {
		return nil, fmt.Errorf("too many restore extents: %d", count)
	}
	extents := make([]RestoreExtent, count)
	for i := range extents {
		if extents[i].Vaddr, err = readU64(reader); err != nil {
			return nil, err
		}
		if extents[i].NrPages, err = readU64(reader); err != nil {
			return nil, err
		}
		if extents[i].Pgoff, err = readU64(reader); err != nil {
			return nil, err
		}
		if extents[i].ShardIndex, err = readU32(reader); err != nil {
			return nil, err
		}
		if extents[i].Type, err = readU32(reader); err != nil {
			return nil, err
		}
		if extents[i].Flags, err = readU32(reader); err != nil {
			return nil, err
		}
		if _, err := readU32(reader); err != nil {
			return nil, err
		}
	}
	return extents, ensureEOF(reader)
}

func encodeStats(stats Stats) ([]byte, error) {
	var out bytes.Buffer
	writeU64(&out, stats.RestoreMapExtentCount)
	writeU64(&out, stats.DedupAppliedPages)
	writeU64(&out, stats.SkippedWritablePages)
	return out.Bytes(), nil
}

func decodeStats(data []byte) (Stats, error) {
	reader := bytes.NewReader(data)
	var stats Stats
	var err error
	if stats.RestoreMapExtentCount, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	if stats.DedupAppliedPages, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	if stats.SkippedWritablePages, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	return stats, ensureEOF(reader)
}

func encodeStorage(pageExtent, artifactExtent StorageExtent) ([]byte, error) {
	var out bytes.Buffer
	for _, extent := range []StorageExtent{pageExtent, artifactExtent} {
		writeString(&out, extent.Role)
		writeString(&out, extent.DeviceIdentity)
		writeString(&out, extent.ShardID)
		writeI64(&out, extent.OffsetBytes)
		writeI64(&out, extent.LengthBytes)
		writeI64(&out, extent.PayloadBytes)
		writeI64(&out, extent.PageSize)
		writeString(&out, extent.Layout)
	}
	return out.Bytes(), nil
}

func decodeStorage(data []byte) (StorageExtent, StorageExtent, error) {
	reader := bytes.NewReader(data)
	extents := make([]StorageExtent, 2)
	for i := range extents {
		var err error
		if extents[i].Role, err = readString(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].DeviceIdentity, err = readString(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].ShardID, err = readString(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].OffsetBytes, err = readI64(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].LengthBytes, err = readI64(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].PayloadBytes, err = readI64(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].PageSize, err = readI64(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
		if extents[i].Layout, err = readString(reader); err != nil {
			return StorageExtent{}, StorageExtent{}, err
		}
	}
	if err := ensureEOF(reader); err != nil {
		return StorageExtent{}, StorageExtent{}, err
	}
	return extents[0], extents[1], nil
}

func encodeFiles(files []ArtifactFile) ([]byte, error) {
	if len(files) > int(^uint32(0)) {
		return nil, errors.New("too many artifact files")
	}
	var out bytes.Buffer
	writeU32(&out, uint32(len(files)))
	for _, file := range files {
		writeString(&out, file.Path)
		writeString(&out, file.Type)
		writeU32(&out, file.Mode)
		writeU32(&out, file.UID)
		writeU32(&out, file.GID)
		writeI64(&out, file.Offset)
		writeI64(&out, file.Length)
		writeString(&out, file.LinkTarget)
	}
	return out.Bytes(), nil
}

func decodeFiles(data []byte) ([]ArtifactFile, error) {
	reader := bytes.NewReader(data)
	count, err := readU32(reader)
	if err != nil {
		return nil, err
	}
	if count > 1<<20 {
		return nil, fmt.Errorf("too many artifact files: %d", count)
	}
	files := make([]ArtifactFile, count)
	for i := range files {
		if files[i].Path, err = readString(reader); err != nil {
			return nil, err
		}
		if files[i].Type, err = readString(reader); err != nil {
			return nil, err
		}
		if files[i].Mode, err = readU32(reader); err != nil {
			return nil, err
		}
		if files[i].UID, err = readU32(reader); err != nil {
			return nil, err
		}
		if files[i].GID, err = readU32(reader); err != nil {
			return nil, err
		}
		if files[i].Offset, err = readI64(reader); err != nil {
			return nil, err
		}
		if files[i].Length, err = readI64(reader); err != nil {
			return nil, err
		}
		if files[i].LinkTarget, err = readString(reader); err != nil {
			return nil, err
		}
	}
	return files, ensureEOF(reader)
}

func writeString(out *bytes.Buffer, value string) {
	writeU32(out, uint32(len(value)))
	out.WriteString(value)
}

func readString(reader *bytes.Reader) (string, error) {
	size, err := readU32(reader)
	if err != nil {
		return "", err
	}
	if size > uint32(reader.Len()) {
		return "", io.ErrUnexpectedEOF
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	return string(data), nil
}

func writeU32(out *bytes.Buffer, value uint32) {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], value)
	out.Write(buf[:])
}

func writeU64(out *bytes.Buffer, value uint64) {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], value)
	out.Write(buf[:])
}

func writeI64(out *bytes.Buffer, value int64) {
	writeU64(out, uint64(value))
}

func readU32(reader *bytes.Reader) (uint32, error) {
	var buf [4]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(buf[:]), nil
}

func readU64(reader *bytes.Reader) (uint64, error) {
	var buf [8]byte
	if _, err := io.ReadFull(reader, buf[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

func readI64(reader *bytes.Reader) (int64, error) {
	value, err := readU64(reader)
	return int64(value), err
}

func ensureEOF(reader *bytes.Reader) error {
	if reader.Len() != 0 {
		return fmt.Errorf("section has %d trailing bytes", reader.Len())
	}
	return nil
}
