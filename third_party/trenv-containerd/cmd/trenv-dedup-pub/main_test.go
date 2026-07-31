package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

func validBasePublication() trenvpub.Publication {
	return trenvpub.Publication{
		Version:           trenvpub.Version,
		ManifestSchema:    trenvpub.ManifestSchema,
		DedupApplySchema:  trenvpub.DedupApplySchema,
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
		PageExtent: trenvpub.StorageExtent{
			Role:           "criu-pages",
			DeviceIdentity: "page-shard",
			ShardID:        "page-shard",
			OffsetBytes:    128 * 4096,
			LengthBytes:    512 * 4096,
			PayloadBytes:   256 * 4096,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		},
		ArtifactExtent: trenvpub.StorageExtent{
			Role:           "restore-artifact",
			DeviceIdentity: "artifact-shard",
			ShardID:        "artifact-shard",
			OffsetBytes:    8 * 4096,
			LengthBytes:    8 * 4096,
			PayloadBytes:   4096,
			PageSize:       4096,
			Layout:         "immutable-packed-files-v1",
		},
		Files: []trenvpub.ArtifactFile{{
			Path:   "metadata-bundle/image/inventory.img",
			Type:   "regular",
			Mode:   0o644,
			Length: 32,
		}},
		Shards: []trenvpub.Shard{{
			WriterID:       "writer0",
			ShardID:        "page-shard",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   128,
			DaxLengthPages: 512,
			PageCount:      256,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		}},
		CreatedAt: time.Date(2026, 7, 29, 1, 2, 3, 4, time.UTC),
	}
}

func TestCurrentAdvisoryMockPlanMaterializesOnlyCompleteRequiresCOW(t *testing.T) {
	cowTargetVaddr := uint64(0x400000)
	cowCanonicalPgoff := uint64(128)
	pseudoTargetVaddr := uint64(0x402000)
	pseudoCanonicalPgoff := uint64(256)
	plan := applyPlan{
		Mode:              "checkpoint-apply-plan",
		PageSize:          4096,
		PlanScope:         "advisory-precheck",
		KernelRequestMode: "mock-transcript-only",
		Items: []applyPlanItem{{
			Action:       "share-readonly-alias",
			Status:       "requires_cow",
			AdvisoryOnly: true,
			Execution: applyPlanExecution{
				TargetVaddr:    &cowTargetVaddr,
				TargetSize:     8192,
				CanonicalPgoff: &cowCanonicalPgoff,
				RequestOpcode:  "pseudo-mm-share-range-dry-run",
			},
		}, {
			Action:       "share-readonly-alias",
			Status:       "requires_pseudo_mm",
			AdvisoryOnly: true,
			Execution: applyPlanExecution{
				TargetVaddr:    &pseudoTargetVaddr,
				TargetSize:     4096,
				CanonicalPgoff: &pseudoCanonicalPgoff,
			},
		}, {
			Action:       "share-readonly-alias",
			Status:       "requires_cow",
			AdvisoryOnly: true,
			Execution: applyPlanExecution{
				TargetSize:    4096,
				TargetVaddr:   &pseudoTargetVaddr,
				RequestOpcode: "pseudo-mm-share-range-dry-run",
			},
		}},
	}

	root := t.TempDir()
	basePath := filepath.Join(root, "base.trpub")
	outputPath := filepath.Join(root, "derived.trpub")
	if err := trenvpub.WriteFileNoReplace(basePath, validBasePublication()); err != nil {
		t.Fatalf("write base: %v", err)
	}
	derived, err := writeDerivedFromPlan(
		basePath,
		outputPath,
		plan,
		0,
		1,
		time.Date(2026, 7, 29, 4, 5, 6, 7, time.UTC),
	)
	if err != nil {
		t.Fatalf("materialize current plan: %v", err)
	}
	if derived.Version != trenvpub.Version ||
		derived.ManifestSchema != trenvpub.ManifestSchema ||
		derived.DedupApplySchema != trenvpub.DedupApplySchema {
		t.Fatalf("unexpected V5 schemas: %#v", derived)
	}
	if len(derived.BaseRestoreMap) != 1 {
		t.Fatalf("expected only the complete requires_cow extent, got %#v", derived.BaseRestoreMap)
	}
	extent := derived.BaseRestoreMap[0]
	if extent.Vaddr != cowTargetVaddr || extent.NrPages != 2 || extent.Pgoff != cowCanonicalPgoff ||
		extent.ShardIndex != 0 || extent.Type != trenvpub.RestoreExtentTypeSharedReadonly ||
		extent.Flags != trenvpub.RestoreExtentFlagCOW {
		t.Fatalf("unexpected materialized extent: %#v", extent)
	}
	if derived.Stats.RestoreMapExtentCount != 1 || derived.Stats.DedupAppliedPages != 2 {
		t.Fatalf("unexpected V5 stats: %#v", derived.Stats)
	}
	decoded, err := trenvpub.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read derived: %v", err)
	}
	if err := trenvpub.ValidatePublication(decoded); err != nil {
		t.Fatalf("derived publication does not validate: %v", err)
	}
}

func TestNonMaterializablePlanProducesNoPublication(t *testing.T) {
	targetVaddr := uint64(0x400000)
	canonicalPgoff := uint64(128)
	plan := applyPlan{
		Mode:              "checkpoint-apply-plan",
		PageSize:          4096,
		PlanScope:         "advisory-precheck",
		KernelRequestMode: "mock-transcript-only",
		Items: []applyPlanItem{{
			Action:       "share-readonly-alias",
			Status:       "requires_pseudo_mm",
			AdvisoryOnly: true,
			Execution: applyPlanExecution{
				TargetVaddr:    &targetVaddr,
				TargetSize:     4096,
				CanonicalPgoff: &canonicalPgoff,
			},
		}, {
			Action:       "share-readonly-alias",
			Status:       "requires_cow",
			AdvisoryOnly: true,
			Execution: applyPlanExecution{
				TargetVaddr: &targetVaddr,
				TargetSize:  4096,
			},
		}},
	}

	root := t.TempDir()
	basePath := filepath.Join(root, "base.trpub")
	outputPath := filepath.Join(root, "derived.trpub")
	if err := trenvpub.WriteFileNoReplace(basePath, validBasePublication()); err != nil {
		t.Fatalf("write base: %v", err)
	}
	if _, err := writeDerivedFromPlan(basePath, outputPath, plan, 0, 1, time.Now()); err == nil ||
		!strings.Contains(err.Error(), "no publishable requires_cow") {
		t.Fatalf("unexpected non-materializable plan result: %v", err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("non-materializable plan created output: %v", err)
	}
}

func TestExtentsFromPlanRejectsInvalidRequiresCOWGeometry(t *testing.T) {
	targetVaddr := uint64(0x400000)
	canonicalPgoff := uint64(128)
	plan := applyPlan{
		Mode:     "checkpoint-apply-plan",
		PageSize: 4096,
		Items: []applyPlanItem{{
			Action: "share-readonly-alias",
			Status: "requires_cow",
			Execution: applyPlanExecution{
				TargetVaddr:    &targetVaddr,
				TargetSize:     4097,
				CanonicalPgoff: &canonicalPgoff,
			},
		}},
	}
	if _, _, err := extentsFromPlan(plan, 0, 1); err == nil {
		t.Fatal("invalid requires_cow target geometry was accepted")
	}
}
