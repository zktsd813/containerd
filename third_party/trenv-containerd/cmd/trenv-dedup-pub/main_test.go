package main

import "testing"

func TestExtentsFromPlanPublishesExecutableAliasItems(t *testing.T) {
	targetVaddr := uint64(0x400000)
	cowTargetVaddr := uint64(0x402000)
	canonicalPgoff := uint64(128)
	cowCanonicalPgoff := uint64(256)
	plan := applyPlan{
		Mode:     "checkpoint-apply-plan",
		PageSize: 4096,
		Items: []applyPlanItem{{
			Action: "share-readonly-alias",
			Status: "requires_pseudo_mm",
			Execution: applyPlanExecution{
				TargetVaddr:    &targetVaddr,
				TargetSize:     8192,
				CanonicalPgoff: &canonicalPgoff,
				RequestOpcode:  "pseudo-mm-share-range-dry-run",
			},
		}, {
			Action: "share-readonly-alias",
			Status: "requires_cow",
			Execution: applyPlanExecution{
				TargetVaddr:    &cowTargetVaddr,
				TargetSize:     4096,
				CanonicalPgoff: &cowCanonicalPgoff,
				RequestOpcode:  "pseudo-mm-share-range-dry-run",
			},
		}, {
			Action: "share-readonly-alias",
			Status: "blocked",
			Execution: applyPlanExecution{
				TargetVaddr:    &targetVaddr,
				TargetSize:     4096,
				CanonicalPgoff: &canonicalPgoff,
			},
		}},
	}

	extents, appliedPages, err := extentsFromPlan(plan, 2, 1)
	if err != nil {
		t.Fatalf("extentsFromPlan returned error: %v", err)
	}
	if len(extents) != 2 {
		t.Fatalf("expected two extents, got %#v", extents)
	}
	if extents[0].Vaddr != targetVaddr || extents[0].NrPages != 2 || extents[0].Pgoff != canonicalPgoff || extents[0].ShardIndex != 2 {
		t.Fatalf("unexpected extent: %#v", extents[0])
	}
	if extents[1].Vaddr != cowTargetVaddr || extents[1].NrPages != 1 || extents[1].Pgoff != cowCanonicalPgoff || extents[1].ShardIndex != 2 {
		t.Fatalf("unexpected CoW extent: %#v", extents[1])
	}
	if appliedPages != 3 {
		t.Fatalf("unexpected applied pages %d", appliedPages)
	}
}
