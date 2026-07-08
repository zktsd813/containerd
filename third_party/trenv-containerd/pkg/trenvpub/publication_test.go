package trenvpub

import (
	"bytes"
	"testing"
	"time"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 1, 2, 3, 4, time.UTC)
	pub := Publication{
		ArtifactID:        "ckpt-a",
		CheckpointID:      "ckpt-a",
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
		MetadataBundleSHA256:       "unit",
		Shards: []Shard{{
			WriterID:       "writer0",
			ShardID:        "dax0.0",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   16,
			DaxLengthPages: 32,
			PageCount:      12,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		}},
		BaseRestoreMap: []RestoreExtent{{
			Vaddr:      0x400000,
			NrPages:    2,
			Pgoff:      16,
			ShardIndex: 0,
		}},
		DedupDelta: []RestoreExtent{{
			Vaddr:      0x402000,
			NrPages:    1,
			Pgoff:      4096,
			ShardIndex: 0,
			Flags:      1,
		}},
		Stats: Stats{
			BaseExtentCount:     1,
			DedupDeltaCount:     1,
			DedupAppliedCount:   1,
			SkippedWritablePage: 3,
		},
		CreatedAt: createdAt,
	}

	data, err := Encode(pub)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.CheckpointID != pub.CheckpointID || got.Fingerprint != pub.Fingerprint || !got.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected decoded publication: %#v", got)
	}
	if len(got.Shards) != 1 || got.Shards[0].DaxStartPage != 16 {
		t.Fatalf("unexpected decoded shards: %#v", got.Shards)
	}
	if len(got.BaseRestoreMap) != 1 || got.BaseRestoreMap[0].Vaddr != 0x400000 {
		t.Fatalf("unexpected decoded base map: %#v", got.BaseRestoreMap)
	}
	if len(got.DedupDelta) != 1 || got.DedupDelta[0].Pgoff != 4096 {
		t.Fatalf("unexpected decoded dedup map: %#v", got.DedupDelta)
	}
	if got.Stats.SkippedWritablePage != 3 {
		t.Fatalf("unexpected decoded stats: %#v", got.Stats)
	}
}

func TestDecodeRejectsChecksumMismatch(t *testing.T) {
	data, err := Encode(Publication{ArtifactID: "a", CheckpointID: "a", State: "COMMITTED", CreatedAt: time.Unix(0, 0)})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 0x7f
	if _, err := Decode(tampered); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestDeriveDedupPublicationPreservesCheckpointIdentity(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 4, 5, 6, 7, time.UTC)
	base := Publication{
		ArtifactID:        "ckpt-a",
		CheckpointID:      "ckpt-a",
		State:             "COMMITTED",
		CheckpointPhase:   "post-first-run",
		Fingerprint:       "fp-a",
		SnapshotStartMode: "restore",
		Shards: []Shard{{
			ShardID:        "dax0.0",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   16,
			DaxLengthPages: 32,
		}},
	}
	dedup := []RestoreExtent{{
		Vaddr:      0x400000,
		NrPages:    2,
		Pgoff:      128,
		ShardIndex: 0,
	}}

	derived := DeriveDedupPublication(base, dedup, Stats{}, createdAt)
	if derived.CheckpointID != base.CheckpointID {
		t.Fatalf("checkpoint identity changed: %#v", derived)
	}
	if derived.ArtifactID == base.ArtifactID || derived.ArtifactID == "" {
		t.Fatalf("expected unique derived artifact id, got %q", derived.ArtifactID)
	}
	if derived.CheckpointPhase != DedupRestoreCOWPhase {
		t.Fatalf("unexpected checkpoint phase %q", derived.CheckpointPhase)
	}
	if len(derived.DedupDelta) != 1 || derived.DedupDelta[0].Pgoff != 128 {
		t.Fatalf("unexpected dedup delta: %#v", derived.DedupDelta)
	}
	if len(derived.BaseRestoreMap) != 1 || derived.BaseRestoreMap[0].Pgoff != 128 {
		t.Fatalf("expected materialized restore map, got %#v", derived.BaseRestoreMap)
	}
	if derived.Stats.DedupDeltaCount != 1 || derived.Stats.DedupAppliedCount != 1 {
		t.Fatalf("unexpected derived stats: %#v", derived.Stats)
	}
	if !derived.CreatedAt.Equal(createdAt) {
		t.Fatalf("unexpected created_at: %s", derived.CreatedAt)
	}
}

func TestCoalesceRestoreExtents(t *testing.T) {
	extents := []RestoreExtent{{
		Vaddr:      0x402000,
		NrPages:    1,
		Pgoff:      130,
		ShardIndex: 0,
		Flags:      1,
	}, {
		Vaddr:      0x400000,
		NrPages:    2,
		Pgoff:      128,
		ShardIndex: 0,
		Flags:      1,
	}, {
		Vaddr:      0x500000,
		NrPages:    1,
		Pgoff:      2048,
		ShardIndex: 1,
		Flags:      1,
	}}

	got := CoalesceRestoreExtents(extents)
	if len(got) != 2 {
		t.Fatalf("expected two coalesced extents, got %#v", got)
	}
	if got[0].Vaddr != 0x400000 || got[0].NrPages != 3 || got[0].Pgoff != 128 {
		t.Fatalf("unexpected first extent: %#v", got[0])
	}
	if got[1].ShardIndex != 1 || got[1].Pgoff != 2048 {
		t.Fatalf("unexpected second extent: %#v", got[1])
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
