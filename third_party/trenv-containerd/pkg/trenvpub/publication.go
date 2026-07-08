package trenvpub

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

const (
	Version     uint32 = 2
	ContentType        = "application/vnd.trenv.publication.v2"
	Extension          = ".trpub"

	DedupRestoreCOWPhase  = "dedup-restore-cow"
	restoreExtentPageSize = 4096
)

var magic = [8]byte{'T', 'R', 'P', 'U', 'B', '0', '0', '2'}

type SectionType uint32

const (
	SectionIdentity SectionType = 1
	SectionArtifact SectionType = 2
	SectionShards   SectionType = 3
	SectionBaseMap  SectionType = 4
	SectionDedupMap SectionType = 5
	SectionStats    SectionType = 6
)

type ActionIdentity struct {
	Namespace          string
	FullyQualifiedName string
	Revision           string
}

type Publication struct {
	ArtifactID                 string
	CheckpointID               string
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
	MetadataBundleSHA256       string
	Shards                     []Shard
	BaseRestoreMap             []RestoreExtent
	DedupDelta                 []RestoreExtent
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

type RestoreExtent struct {
	Vaddr      uint64
	NrPages    uint64
	Pgoff      uint64
	ShardIndex uint32
	Type       uint32
	Flags      uint32
}

type Stats struct {
	BaseExtentCount     uint64
	DedupDeltaCount     uint64
	DedupAppliedCount   uint64
	SkippedWritablePage uint64
}

type sectionHeader struct {
	typ    SectionType
	flags  uint32
	offset uint64
	size   uint64
	sum    [32]byte
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
	return file.Close()
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

func DeriveDedupPublication(base Publication, dedup []RestoreExtent, stats Stats, createdAt time.Time) Publication {
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
	derived.DedupDelta = append([]RestoreExtent(nil), dedup...)
	derived.Stats = stats
	if derived.Stats.DedupDeltaCount == 0 {
		derived.Stats.DedupDeltaCount = uint64(len(dedup))
	}
	if derived.Stats.DedupAppliedCount == 0 {
		derived.Stats.DedupAppliedCount = uint64(len(dedup))
	}
	derived.CreatedAt = createdAt.UTC()
	derived.Shards = append([]Shard(nil), base.Shards...)
	if len(base.BaseRestoreMap) == 0 {
		derived.BaseRestoreMap = CoalesceRestoreExtents(dedup)
	} else {
		derived.BaseRestoreMap = append([]RestoreExtent(nil), base.BaseRestoreMap...)
	}
	if derived.Stats.BaseExtentCount == 0 {
		derived.Stats.BaseExtentCount = uint64(len(derived.BaseRestoreMap))
	}
	return derived
}

func WriteDerivedDedupPublication(basePath, outputPath string, dedup []RestoreExtent, stats Stats, createdAt time.Time) (Publication, error) {
	base, err := ReadFile(basePath)
	if err != nil {
		return Publication{}, err
	}
	derived := DeriveDedupPublication(base, dedup, stats, createdAt)
	if err := WriteFileNoReplace(outputPath, derived); err != nil {
		return Publication{}, err
	}
	return derived, nil
}

func Encode(pub Publication) ([]byte, error) {
	sections := []sectionHeader{}
	payloads := [][]byte{}
	addSection := func(typ SectionType, payload []byte) {
		header := sectionHeader{typ: typ, size: uint64(len(payload)), sum: sha256.Sum256(payload)}
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
	dedupMap, err := encodeExtents(pub.DedupDelta)
	if err != nil {
		return nil, err
	}
	stats, err := encodeStats(pub.Stats)
	if err != nil {
		return nil, err
	}

	addSection(SectionIdentity, identity)
	addSection(SectionArtifact, artifact)
	addSection(SectionShards, shards)
	addSection(SectionBaseMap, baseMap)
	addSection(SectionDedupMap, dedupMap)
	addSection(SectionStats, stats)

	const fileHeaderSize = 24
	const sectionHeaderSize = 56
	offset := uint64(fileHeaderSize + len(sections)*sectionHeaderSize)
	for i := range sections {
		sections[i].offset = offset
		offset += sections[i].size
	}

	var out bytes.Buffer
	out.Write(magic[:])
	writeU32(&out, Version)
	writeU32(&out, 0)
	writeU32(&out, uint32(len(sections)))
	writeU32(&out, 0)
	for _, section := range sections {
		writeU32(&out, uint32(section.typ))
		writeU32(&out, section.flags)
		writeU64(&out, section.offset)
		writeU64(&out, section.size)
		out.Write(section.sum[:])
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
	if gotMagic != magic {
		return Publication{}, errors.New("invalid magic")
	}
	version, err := readU32(reader)
	if err != nil {
		return Publication{}, err
	}
	if version != Version {
		return Publication{}, fmt.Errorf("unsupported version %d", version)
	}
	if _, err := readU32(reader); err != nil {
		return Publication{}, err
	}
	sectionCount, err := readU32(reader)
	if err != nil {
		return Publication{}, err
	}
	if _, err := readU32(reader); err != nil {
		return Publication{}, err
	}
	if sectionCount == 0 || sectionCount > 64 {
		return Publication{}, fmt.Errorf("invalid section count %d", sectionCount)
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
		if _, err := io.ReadFull(reader, sections[i].sum[:]); err != nil {
			return Publication{}, err
		}
		sections[i].typ = SectionType(typ)
		sections[i].flags = flags
		sections[i].offset = offset
		sections[i].size = size
	}

	var pub Publication
	for _, section := range sections {
		if section.offset > uint64(len(data)) || section.size > uint64(len(data))-section.offset {
			return Publication{}, fmt.Errorf("section %d is out of bounds", section.typ)
		}
		payload := data[section.offset : section.offset+section.size]
		if sha256.Sum256(payload) != section.sum {
			return Publication{}, fmt.Errorf("section %d checksum mismatch", section.typ)
		}
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
		case SectionDedupMap:
			extents, err := decodeExtents(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.DedupDelta = extents
		case SectionStats:
			stats, err := decodeStats(payload)
			if err != nil {
				return Publication{}, err
			}
			pub.Stats = stats
		default:
			return Publication{}, fmt.Errorf("unknown section %d", section.typ)
		}
	}
	return pub, nil
}

func encodeIdentity(pub Publication) ([]byte, error) {
	var out bytes.Buffer
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
	return out.Bytes(), nil
}

func decodeIdentity(data []byte, pub *Publication) error {
	reader := bytes.NewReader(data)
	var err error
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
	return ensureEOF(reader)
}

func encodeArtifact(pub Publication) ([]byte, error) {
	var out bytes.Buffer
	writeString(&out, pub.CheckpointPath)
	writeString(&out, pub.MetadataBundlePath)
	writeString(&out, pub.PlacementPath)
	writeString(&out, pub.CheckpointActionExportRoot)
	writeI64(&out, pub.MetadataBundleSize)
	writeString(&out, pub.MetadataBundleSHA256)
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
	if pub.MetadataBundleSHA256, err = readString(reader); err != nil {
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
	writeU64(&out, stats.BaseExtentCount)
	writeU64(&out, stats.DedupDeltaCount)
	writeU64(&out, stats.DedupAppliedCount)
	writeU64(&out, stats.SkippedWritablePage)
	return out.Bytes(), nil
}

func decodeStats(data []byte) (Stats, error) {
	reader := bytes.NewReader(data)
	var stats Stats
	var err error
	if stats.BaseExtentCount, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	if stats.DedupDeltaCount, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	if stats.DedupAppliedCount, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	if stats.SkippedWritablePage, err = readU64(reader); err != nil {
		return Stats{}, err
	}
	return stats, ensureEOF(reader)
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

func DecodeHexSHA256(value string) ([32]byte, error) {
	var out [32]byte
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	if len(decoded) != len(out) {
		return out, fmt.Errorf("sha256 digest has %d bytes", len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}
