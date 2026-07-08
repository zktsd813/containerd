package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

type applyPlan struct {
	Mode     string          `json:"mode"`
	PageSize uint64          `json:"page_size"`
	Items    []applyPlanItem `json:"items"`
}

type applyPlanItem struct {
	Action    string             `json:"action"`
	Status    string             `json:"status"`
	Execution applyPlanExecution `json:"execution"`
}

type applyPlanExecution struct {
	TargetVaddr             *uint64 `json:"target_vaddr"`
	TargetSize              uint64  `json:"target_size"`
	CanonicalPgoff          *uint64 `json:"canonical_pgoff"`
	CanonicalPlacementIndex *uint64 `json:"canonical_placement_index"`
	DuplicatePlacementIndex *uint64 `json:"duplicate_placement_index"`
	CanonicalBackendKind    string  `json:"canonical_backend_kind"`
	RequestOpcode           string  `json:"request_opcode"`
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: trenv-dedup-pub --base BASE.trpub --plan checkpoint-apply-plan.json --output DERIVED.trpub [--canonical-shard-index N]\n")
}

func planStatusAllowed(status string) bool {
	return status == "eligible" || status == "requires_pseudo_mm" || status == "requires_cow"
}

func extentsFromPlan(plan applyPlan, shardIndex uint, minPages uint64) ([]trenvpub.RestoreExtent, uint64, error) {
	if plan.Mode != "checkpoint-apply-plan" {
		return nil, 0, fmt.Errorf("unsupported plan mode %q", plan.Mode)
	}
	if plan.PageSize == 0 {
		return nil, 0, fmt.Errorf("plan page_size is empty")
	}
	var extents []trenvpub.RestoreExtent
	var appliedPages uint64
	for _, item := range plan.Items {
		if item.Action != "share-readonly-alias" || !planStatusAllowed(item.Status) {
			continue
		}
		if item.Execution.TargetVaddr == nil || item.Execution.CanonicalPgoff == nil {
			continue
		}
		if item.Execution.TargetSize == 0 || item.Execution.TargetSize%plan.PageSize != 0 {
			return nil, 0, fmt.Errorf("invalid target_size %d for page_size %d", item.Execution.TargetSize, plan.PageSize)
		}
		nrPages := item.Execution.TargetSize / plan.PageSize
		if nrPages < minPages {
			continue
		}
		extents = append(extents, trenvpub.RestoreExtent{
			Vaddr:      *item.Execution.TargetVaddr,
			NrPages:    nrPages,
			Pgoff:      *item.Execution.CanonicalPgoff,
			ShardIndex: uint32(shardIndex),
			Type:       0,
			Flags:      1,
		})
		appliedPages += nrPages
	}
	return extents, appliedPages, nil
}

func main() {
	basePath := flag.String("base", "", "base publication path")
	planPath := flag.String("plan", "", "dedupd checkpoint-apply-plan JSON path")
	outputPath := flag.String("output", "", "derived dedup publication output path")
	createdAtText := flag.String("created-at", "", "optional RFC3339Nano created_at for deterministic tests")
	shardIndex := flag.Uint("canonical-shard-index", 0, "publication shard index used by canonical_pgoff values")
	minPages := flag.Uint64("min-pages", 1, "minimum extent size to publish")
	flag.Usage = usage
	flag.Parse()

	if *basePath == "" || *planPath == "" || *outputPath == "" {
		usage()
		os.Exit(2)
	}

	planData, err := os.ReadFile(*planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read plan: %v\n", err)
		os.Exit(1)
	}
	var plan applyPlan
	if err := json.Unmarshal(planData, &plan); err != nil {
		fmt.Fprintf(os.Stderr, "parse plan: %v\n", err)
		os.Exit(1)
	}
	createdAt := time.Now().UTC()
	if *createdAtText != "" {
		createdAt, err = time.Parse(time.RFC3339Nano, *createdAtText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse created-at: %v\n", err)
			os.Exit(2)
		}
	}
	extents, appliedPages, err := extentsFromPlan(plan, *shardIndex, *minPages)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build dedup extents: %v\n", err)
		os.Exit(1)
	}
	if len(extents) == 0 {
		fmt.Fprintf(os.Stderr, "plan has no publishable dedup extents\n")
		os.Exit(1)
	}
	stats := trenvpub.Stats{
		DedupDeltaCount:   uint64(len(extents)),
		DedupAppliedCount: appliedPages,
	}
	pub, err := trenvpub.WriteDerivedDedupPublication(*basePath, *outputPath, extents, stats, createdAt)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write derived publication: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("derived_publication=%s checkpoint=%s artifact=%s dedup_extents=%d dedup_pages=%d\n",
		*outputPath, pub.CheckpointID, pub.ArtifactID, len(pub.DedupDelta), appliedPages)
}
