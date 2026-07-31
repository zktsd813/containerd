package trenvpub

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"
)

func validBasePublication() Publication {
	return Publication{
		Version:           Version,
		ManifestSchema:    ManifestSchema,
		DedupApplySchema:  DedupApplySchema,
		ArtifactID:        "ckpt-a",
		CheckpointID:      "ckpt-a",
		Generation:        9,
		WriterEpoch:       4,
		State:             "COMMITTED",
		CheckpointPhase:   "post-first-run",
		Fingerprint:       "fp-a",
		SnapshotStartMode: "switch",
		RuntimeKind:       "nodejs:20_hybrid",
		RuntimeFamily:     "nodejs",
		ActionIdentity: &ActionIdentity{
			Namespace:          "guest",
			FullyQualifiedName: "/guest/hello",
			Revision:           "rev-1",
		},
		CheckpointPath:             "/tmp/checkpoints/ckpt-a/image",
		MetadataBundlePath:         "/tmp/checkpoints/ckpt-a/work/metadata-bundle",
		PlacementPath:              "/tmp/checkpoints/ckpt-a/work/metadata-bundle/placement.json",
		CheckpointActionExportRoot: "/tmp/checkpoints/ckpt-a/work/action-root",
		MetadataBundleSize:         128,
		PageExtent: StorageExtent{
			Role:           "criu-pages",
			DeviceIdentity: "page-shard",
			ShardID:        "page-shard",
			OffsetBytes:    16 * 4096,
			LengthBytes:    32 * 4096,
			PayloadBytes:   12 * 4096,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		},
		ArtifactExtent: StorageExtent{
			Role:           "restore-artifact",
			DeviceIdentity: "artifact-shard",
			ShardID:        "artifact-shard",
			OffsetBytes:    64 * 4096,
			LengthBytes:    8 * 4096,
			PayloadBytes:   4096,
			PageSize:       4096,
			Layout:         "immutable-packed-files-v1",
		},
		Files: []ArtifactFile{{
			Path:   "metadata-bundle/image/inventory.img",
			Type:   "regular",
			Mode:   0o644,
			Length: 10,
		}},
		Shards: []Shard{{
			WriterID:       "writer0",
			ShardID:        "page-shard",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   16,
			DaxLengthPages: 32,
			PageCount:      12,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		}},
		CreatedAt: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
}

func validDerivedPublication() Publication {
	pub := validBasePublication()
	pub.ArtifactID = "ckpt-a-dedup"
	pub.CheckpointPhase = DedupRestoreCOWPhase
	pub.BaseRestoreMap = []RestoreExtent{{
		Vaddr:      0x400000,
		NrPages:    2,
		Pgoff:      16,
		ShardIndex: 0,
		Type:       RestoreExtentTypeSharedReadonly,
		Flags:      RestoreExtentFlagCOW,
	}}
	pub.Stats = Stats{
		RestoreMapExtentCount: 1,
		DedupAppliedPages:     2,
		SkippedWritablePages:  3,
	}
	return pub
}

func TestV5EncodeDecodeRoundTrip(t *testing.T) {
	pub := validDerivedPublication()
	data, err := Encode(pub)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !bytes.Equal(data[:8], []byte("TRPUB005")) {
		t.Fatalf("unexpected magic %q", data[:8])
	}
	if ContentType != "application/vnd.trenv.publication.v5" ||
		ManifestSchema != "trenv.artifact/v5" ||
		DedupApplySchema != "trenv.dedup/base-restore-map-v1" {
		t.Fatalf("unexpected V5 constants")
	}

	got, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != Version || got.ManifestSchema != ManifestSchema || got.DedupApplySchema != DedupApplySchema {
		t.Fatalf("unexpected decoded schemas: %#v", got)
	}
	if got.CheckpointID != pub.CheckpointID || got.ArtifactID != pub.ArtifactID ||
		got.Generation != pub.Generation || got.WriterEpoch != pub.WriterEpoch ||
		!got.CreatedAt.Equal(pub.CreatedAt) {
		t.Fatalf("unexpected decoded identity: %#v", got)
	}
	if len(got.BaseRestoreMap) != 1 || got.BaseRestoreMap[0].Pgoff != 16 {
		t.Fatalf("unexpected base restore map: %#v", got.BaseRestoreMap)
	}
	if got.Stats.RestoreMapExtentCount != 1 || got.Stats.DedupAppliedPages != 2 ||
		got.Stats.SkippedWritablePages != 3 {
		t.Fatalf("unexpected stats: %#v", got.Stats)
	}
}

func TestV5EncodesExactSectionsWithoutDedupDelta(t *testing.T) {
	data, err := Encode(validBasePublication())
	if err != nil {
		t.Fatal(err)
	}
	count := binary.LittleEndian.Uint32(data[16:20])
	if count != 7 {
		t.Fatalf("unexpected section count %d", count)
	}
	want := []SectionType{
		SectionIdentity,
		SectionArtifact,
		SectionShards,
		SectionBaseMap,
		SectionStats,
		SectionStorage,
		SectionFiles,
	}
	for i, sectionType := range want {
		offset := 24 + i*24
		got := SectionType(binary.LittleEndian.Uint32(data[offset : offset+4]))
		if got != sectionType {
			t.Fatalf("section %d: got %d, want %d", i, got, sectionType)
		}
		if got == 5 {
			t.Fatal("V5 encoded the removed DedupDelta section")
		}
	}
}

func TestDecodeRejectsLegacyMagicAndDedupDeltaSection(t *testing.T) {
	data, err := Encode(validBasePublication())
	if err != nil {
		t.Fatal(err)
	}

	legacy := append([]byte(nil), data...)
	copy(legacy[:8], []byte("TRPUB004"))
	binary.LittleEndian.PutUint32(legacy[8:12], 4)
	if _, err := Decode(legacy); err == nil {
		t.Fatal("V5 decoder accepted V4 publication")
	}

	withDedupDelta := append([]byte(nil), data...)
	const baseMapSectionIndex = 3
	offset := 24 + baseMapSectionIndex*24
	binary.LittleEndian.PutUint32(withDedupDelta[offset:offset+4], 5)
	if _, err := Decode(withDedupDelta); err == nil || !strings.Contains(err.Error(), "unexpected V5 section") {
		t.Fatalf("V5 decoder accepted old DedupDelta section: %v", err)
	}
}

func TestDecodeRemainsChecksumFreeButValidatesStructure(t *testing.T) {
	data, err := Encode(validBasePublication())
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), data...)
	index := bytes.Index(tampered, []byte("ckpt-a"))
	if index < 0 {
		t.Fatal("artifact id was not found in encoded publication")
	}
	tampered[index] = 'd'
	got, err := Decode(tampered)
	if err != nil {
		t.Fatalf("checksum-free V5 rejected an in-bounds valid mutation: %v", err)
	}
	if got.ArtifactID != "dkpt-a" {
		t.Fatalf("unexpected mutated artifact id %q", got.ArtifactID)
	}

	withTrailingByte := append(append([]byte(nil), data...), 0)
	if _, err := Decode(withTrailingByte); err == nil {
		t.Fatal("strict V5 decoder accepted a trailing byte")
	}
}

func TestValidatePublicationPreservesRuntimeSymlinkTargets(t *testing.T) {
	for _, target := range []string{
		"/usr/lib/python3.5/LICENSE.txt",
		"../../base-runtime-file",
	} {
		pub := validBasePublication()
		pub.Files = []ArtifactFile{{
			Path:       "action-root/home/app/virtualenv/LICENSE.txt",
			Type:       "symlink",
			Mode:       0o777,
			LinkTarget: target,
		}}
		if err := ValidatePublication(pub); err != nil {
			t.Fatalf("runtime symlink target %q was rejected: %v", target, err)
		}
	}

	for _, target := range []string{"", "bad\x00target"} {
		pub := validBasePublication()
		pub.Files = []ArtifactFile{{
			Path:       "action-root/link",
			Type:       "symlink",
			Mode:       0o777,
			LinkTarget: target,
		}}
		if err := ValidatePublication(pub); err == nil {
			t.Fatalf("invalid symlink target %q was accepted", target)
		}
	}
}

func TestValidatePublicationRejectsInvalidRestoreMaps(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Publication)
	}{
		{
			name: "dedup phase without map",
			mutate: func(pub *Publication) {
				pub.CheckpointPhase = DedupRestoreCOWPhase
				pub.BaseRestoreMap = nil
				pub.Stats = Stats{}
			},
		},
		{
			name: "stats mismatch",
			mutate: func(pub *Publication) {
				pub.Stats.DedupAppliedPages = 1
			},
		},
		{
			name: "missing shard",
			mutate: func(pub *Publication) {
				pub.BaseRestoreMap[0].ShardIndex = 1
			},
		},
		{
			name: "outside shard",
			mutate: func(pub *Publication) {
				pub.BaseRestoreMap[0].Pgoff = 48
			},
		},
		{
			name: "invalid flags",
			mutate: func(pub *Publication) {
				pub.BaseRestoreMap[0].Flags = 0
			},
		},
		{
			name: "overlapping targets",
			mutate: func(pub *Publication) {
				pub.BaseRestoreMap = append(pub.BaseRestoreMap, RestoreExtent{
					Vaddr:      0x401000,
					NrPages:    1,
					Pgoff:      18,
					ShardIndex: 0,
					Type:       RestoreExtentTypeSharedReadonly,
					Flags:      RestoreExtentFlagCOW,
				})
				pub.Stats.RestoreMapExtentCount = 2
				pub.Stats.DedupAppliedPages = 3
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pub := validDerivedPublication()
			test.mutate(&pub)
			if err := ValidatePublication(pub); err == nil {
				t.Fatalf("invalid publication was accepted: %#v", pub)
			}
		})
	}
}

func TestDeriveDedupPublicationMaterializesNonemptyMap(t *testing.T) {
	base := validBasePublication()
	createdAt := time.Date(2026, 7, 29, 4, 5, 6, 7, time.UTC)
	restoreMap := []RestoreExtent{{
		Vaddr:      0x402000,
		NrPages:    1,
		Pgoff:      18,
		ShardIndex: 0,
		Type:       RestoreExtentTypeSharedReadonly,
		Flags:      RestoreExtentFlagCOW,
	}, {
		Vaddr:      0x400000,
		NrPages:    2,
		Pgoff:      16,
		ShardIndex: 0,
		Type:       RestoreExtentTypeSharedReadonly,
		Flags:      RestoreExtentFlagCOW,
	}}

	derived, err := DeriveDedupPublication(base, restoreMap, Stats{SkippedWritablePages: 5}, createdAt)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if derived.CheckpointID != base.CheckpointID || derived.ArtifactID == base.ArtifactID {
		t.Fatalf("derived identity is invalid: %#v", derived)
	}
	if derived.CheckpointPhase != DedupRestoreCOWPhase || len(derived.BaseRestoreMap) != 1 {
		t.Fatalf("restore map was not materialized: %#v", derived.BaseRestoreMap)
	}
	if derived.BaseRestoreMap[0].NrPages != 3 ||
		derived.Stats.RestoreMapExtentCount != 1 ||
		derived.Stats.DedupAppliedPages != 3 ||
		derived.Stats.SkippedWritablePages != 5 {
		t.Fatalf("unexpected derived map or stats: %#v %#v", derived.BaseRestoreMap, derived.Stats)
	}
	if !derived.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected created_at %s", derived.CreatedAt)
	}
	if err := ValidatePublication(derived); err != nil {
		t.Fatalf("derived publication does not validate: %v", err)
	}
}

func TestDeriveDedupPublicationRejectsEmptyMap(t *testing.T) {
	if _, err := DeriveDedupPublication(validBasePublication(), nil, Stats{}, time.Now()); err == nil {
		t.Fatal("empty materialized restore map was accepted")
	}
}

func TestEncodeSuppliesFixedV5Schemas(t *testing.T) {
	pub := validBasePublication()
	pub.Version = 0
	pub.ManifestSchema = ""
	pub.DedupApplySchema = ""
	data, err := Encode(pub)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != Version || got.ManifestSchema != ManifestSchema || got.DedupApplySchema != DedupApplySchema {
		t.Fatalf("fixed V5 schemas were not supplied: %#v", got)
	}
}

func TestNormalizePathReplacesJSONExtension(t *testing.T) {
	if got := NormalizePath("/tmp/ckpt.json"); got != "/tmp/ckpt"+Extension {
		t.Fatalf("unexpected normalized path %q", got)
	}
	if got := NormalizePath("/tmp/ckpt" + Extension); !bytes.HasSuffix([]byte(got), []byte(Extension)) {
		t.Fatalf("unexpected normalized path %q", got)
	}
}
