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

func TestNormalizePathReplacesJSONExtension(t *testing.T) {
	if got := NormalizePath("/tmp/ckpt.json"); got != "/tmp/ckpt"+Extension {
		t.Fatalf("unexpected normalized path %q", got)
	}
	if got := NormalizePath("/tmp/ckpt" + Extension); !bytes.HasSuffix([]byte(got), []byte(Extension)) {
		t.Fatalf("unexpected normalized path %q", got)
	}
}
