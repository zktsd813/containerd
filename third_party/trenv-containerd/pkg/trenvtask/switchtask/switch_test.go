package switchtask

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBuildRebindPlanUsesSourceAndTargetRootfs(t *testing.T) {
	stateRoot := t.TempDir()
	sourceRoot := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "source"), "app", "action")
	targetRoot := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "target"), "action")

	if err := os.MkdirAll(sourceRoot, 0o755); err != nil {
		t.Fatalf("mkdir source root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "payload.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	plan, err := buildRebindPlan(stateRoot, "openwhisk", "source", "target", []actionRebind{
		{sourceRoot: "/app/action", targetRoot: "/action"},
	})
	if err != nil {
		t.Fatalf("buildRebindPlan returned error: %v", err)
	}
	if len(plan) != 1 {
		t.Fatalf("expected one staged path, got %d", len(plan))
	}
	if plan[0].source != sourceRoot {
		t.Fatalf("unexpected source path %q", plan[0].source)
	}
	if plan[0].target != targetRoot {
		t.Fatalf("unexpected target path %q", plan[0].target)
	}
	if _, err := os.Stat(targetRoot); err != nil {
		t.Fatalf("expected target path to be prepared: %v", err)
	}
}

func TestBuildRebindPlanSupportsMultipleTargetsFromSameSource(t *testing.T) {
	stateRoot := t.TempDir()
	sourceRoot := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "source"), "app", "action")
	targetActionRoot := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "target"), "action")
	targetAppActionRoot := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "target"), "app", "action")

	if err := os.MkdirAll(sourceRoot, 0o755); err != nil {
		t.Fatalf("mkdir source root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "payload.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	plan, err := buildRebindPlan(stateRoot, "openwhisk", "source", "target", []actionRebind{
		{sourceRoot: "/app/action", targetRoot: "/action"},
		{sourceRoot: "/app/action", targetRoot: "/app/action"},
	})
	if err != nil {
		t.Fatalf("buildRebindPlan returned error: %v", err)
	}
	if len(plan) != 2 {
		t.Fatalf("expected two staged paths, got %d", len(plan))
	}
	if plan[0].source != sourceRoot || plan[1].source != sourceRoot {
		t.Fatalf("unexpected source paths: %#v", plan)
	}
	if plan[0].target != targetActionRoot {
		t.Fatalf("unexpected first target path %q", plan[0].target)
	}
	if plan[1].target != targetAppActionRoot {
		t.Fatalf("unexpected second target path %q", plan[1].target)
	}
	if _, err := os.Stat(targetActionRoot); err != nil {
		t.Fatalf("expected /action target path to be prepared: %v", err)
	}
	if _, err := os.Stat(targetAppActionRoot); err != nil {
		t.Fatalf("expected /app/action target path to be prepared: %v", err)
	}
}

func TestBuildRebindPlanFromExplicitSourceRootfs(t *testing.T) {
	sourceRootfs := t.TempDir()
	targetRootfs := t.TempDir()
	sourceRoot := filepath.Join(sourceRootfs, "home", "app")
	targetRoot := filepath.Join(targetRootfs, "home", "app")

	if err := os.MkdirAll(sourceRoot, 0o755); err != nil {
		t.Fatalf("mkdir source root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "payload.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	plan, err := buildRebindPlanFromRootfs(sourceRootfs, targetRootfs, []actionRebind{
		{sourceRoot: "/home/app", targetRoot: "/home/app"},
	})
	if err != nil {
		t.Fatalf("buildRebindPlanFromRootfs returned error: %v", err)
	}
	if len(plan) != 1 {
		t.Fatalf("expected one staged path, got %d", len(plan))
	}
	if plan[0].source != sourceRoot {
		t.Fatalf("unexpected source path %q", plan[0].source)
	}
	if plan[0].target != targetRoot {
		t.Fatalf("unexpected target path %q", plan[0].target)
	}
}

func TestStableOverlayRebindSelectsHybridStableRoot(t *testing.T) {
	stateRoot := t.TempDir()
	overlayRoot := t.TempDir()
	t.Setenv("TRENV_ACTION_OVERLAY_ROOT", overlayRoot)
	sourceRootfs := t.TempDir()
	sourceAppRoot := filepath.Join(sourceRootfs, "home", "app")
	if err := os.MkdirAll(sourceAppRoot, 0o755); err != nil {
		t.Fatalf("mkdir source app root: %v", err)
	}

	plan, ok, err := stableOverlayRebind(
		stateRoot,
		"openwhisk",
		"target",
		sourceRootfs,
		"/home/app",
		[]actionRebind{{sourceRoot: "/home/app", targetRoot: "/home/app"}},
	)
	if err != nil {
		t.Fatalf("stableOverlayRebind returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected stable overlay rebind to be selected")
	}
	if plan.source != sourceAppRoot {
		t.Fatalf("unexpected overlay source %q", plan.source)
	}
	expectedTarget := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "target"), "home", "app")
	if plan.target != expectedTarget {
		t.Fatalf("unexpected overlay target %q", plan.target)
	}
	expectedBase := filepath.Join(overlayRoot, "openwhisk", "target")
	if plan.upper != filepath.Join(expectedBase, "upper") {
		t.Fatalf("unexpected overlay upper %q", plan.upper)
	}
	if plan.work != filepath.Join(expectedBase, "work") {
		t.Fatalf("unexpected overlay work %q", plan.work)
	}
	if plan.merged != expectedTarget {
		t.Fatalf("unexpected overlay merged %q", plan.merged)
	}
}

func TestStableOverlayRebindFallsBackForNonStableLayout(t *testing.T) {
	stateRoot := t.TempDir()
	sourceRootfs := t.TempDir()
	sourceActionRoot := filepath.Join(sourceRootfs, "app", "action")
	if err := os.MkdirAll(sourceActionRoot, 0o755); err != nil {
		t.Fatalf("mkdir source action root: %v", err)
	}

	plan, ok, err := stableOverlayRebind(
		stateRoot,
		"openwhisk",
		"target",
		sourceRootfs,
		"/app/action",
		[]actionRebind{
			{sourceRoot: "/app/action", targetRoot: "/action"},
			{sourceRoot: "/app/action", targetRoot: "/app/action"},
		},
	)
	if err != nil {
		t.Fatalf("stableOverlayRebind returned error: %v", err)
	}
	if ok {
		t.Fatalf("expected fallback to regular rebind plan, got %#v", plan)
	}
}

func TestBuildRebindPlanFailsWhenHintsMatchNoRoots(t *testing.T) {
	stateRoot := t.TempDir()
	_, err := buildRebindPlan(stateRoot, "openwhisk", "source", "target", []actionRebind{
		{sourceRoot: "/app/action", targetRoot: "/action"},
	})
	if err == nil {
		t.Fatal("expected an error when no hinted action roots exist")
	}
}

func TestBuildRebindPlanRejectsTraversal(t *testing.T) {
	stateRoot := t.TempDir()
	_, err := buildRebindPlan(stateRoot, "openwhisk", "source", "target", []actionRebind{
		{sourceRoot: "/app/../../etc", targetRoot: "/action"},
	})
	if err == nil {
		t.Fatal("expected an error for a traversal action root")
	}
}

func TestBuildRebindPlanRejectsTargetTraversal(t *testing.T) {
	stateRoot := t.TempDir()
	_, err := buildRebindPlan(stateRoot, "openwhisk", "source", "target", []actionRebind{
		{sourceRoot: "/app/action", targetRoot: "/../../action"},
	})
	if err == nil {
		t.Fatal("expected an error for a traversal target root")
	}
}

func TestResolvePseudoMMImportPlanUsesReaderPublication(t *testing.T) {
	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(restoreRoot, "publication.reader.json"), []byte(`{
  "checkpoint_id": "ckpt-a",
  "dax_device": "/dev/dax-writer",
  "dax_start_page": 65536,
  "dax_length_pages": 65536
}`), 0o644); err != nil {
		t.Fatalf("write reader publication: %v", err)
	}

	plan, ok, err := resolvePseudoMMImportPlan(imagePath, "/dev/dax-reader", nil, "")
	if err != nil {
		t.Fatalf("resolvePseudoMMImportPlan returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected reader pseudo_mm import plan")
	}
	if plan.checkpointID != "ckpt-a" {
		t.Fatalf("unexpected checkpoint id %q", plan.checkpointID)
	}
	if plan.daxDevice != "/dev/dax-reader" {
		t.Fatalf("expected local DAX override, got %q", plan.daxDevice)
	}
	if plan.daxStartPage != 65536 || plan.daxLengthPages != 65536 {
		t.Fatalf("unexpected DAX placement: start=%d length=%d", plan.daxStartPage, plan.daxLengthPages)
	}
	if plan.workPath != filepath.Join(restoreRoot, "pseudo-mm-import-work") {
		t.Fatalf("unexpected import work path %q", plan.workPath)
	}
}

func TestResolvePseudoMMImportPlanUsesReaderShardMap(t *testing.T) {
	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(restoreRoot, "publication.reader.json"), []byte(`{
  "checkpoint_id": "ckpt-a",
  "shard_id": "dax7.0",
  "dax_device": "/dev/dax-writer",
  "dax_start_page": 65536,
  "dax_length_pages": 65536
}`), 0o644); err != nil {
		t.Fatalf("write reader publication: %v", err)
	}

	plan, ok, err := resolvePseudoMMImportPlan(imagePath, "", []daxShardOption{
		{shardID: "dax7.0", daxDevice: "/dev/dax-reader"},
	}, "/dev/dax-fallback")
	if err != nil {
		t.Fatalf("resolvePseudoMMImportPlan returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected reader pseudo_mm import plan")
	}
	if plan.daxDevice != "/dev/dax-reader" {
		t.Fatalf("expected reader-local DAX mapping, got %q", plan.daxDevice)
	}
}

func TestResolvePseudoMMImportPlanUsesPublicationBeforeFallback(t *testing.T) {
	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(restoreRoot, "publication.reader.json"), []byte(`{
  "checkpoint_id": "ckpt-a",
  "shard_id": "dax7.0",
  "dax_device": "/dev/dax-publication",
  "dax_start_page": 65536,
  "dax_length_pages": 65536
}`), 0o644); err != nil {
		t.Fatalf("write reader publication: %v", err)
	}

	plan, ok, err := resolvePseudoMMImportPlan(imagePath, "", nil, "/dev/dax-fallback")
	if err != nil {
		t.Fatalf("resolvePseudoMMImportPlan returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected reader pseudo_mm import plan")
	}
	if plan.daxDevice != "/dev/dax-publication" {
		t.Fatalf("expected publication DAX before fallback, got %q", plan.daxDevice)
	}
}

func TestResolvePseudoMMImportPlanSkipsWithoutReaderPublication(t *testing.T) {
	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image path: %v", err)
	}

	plan, ok, err := resolvePseudoMMImportPlan(imagePath, "/dev/dax-reader", nil, "")
	if err != nil {
		t.Fatalf("resolvePseudoMMImportPlan returned error: %v", err)
	}
	if ok || plan != nil {
		t.Fatalf("expected no import plan, got ok=%v plan=%#v", ok, plan)
	}
}

func TestBuildRebindPlanSkipsSelfSwitch(t *testing.T) {
	stateRoot := t.TempDir()
	plan, err := buildRebindPlan(stateRoot, "openwhisk", "same", "same", []actionRebind{
		{sourceRoot: "/app/action", targetRoot: "/action"},
	})
	if err != nil {
		t.Fatalf("buildRebindPlan returned error: %v", err)
	}
	if len(plan) != 0 {
		t.Fatalf("expected empty plan for self-switch, got %d entries", len(plan))
	}
}

func TestReplaceTargetPathRecreatesFileOverDirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "action")

	if err := os.MkdirAll(filepath.Join(target, "nested"), 0o755); err != nil {
		t.Fatalf("mkdir target dir: %v", err)
	}

	sourceFile := filepath.Join(root, "payload.txt")
	if err := os.WriteFile(sourceFile, []byte("ok"), 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}

	sourceInfo, err := os.Stat(sourceFile)
	if err != nil {
		t.Fatalf("stat source file: %v", err)
	}
	if err := replaceTargetPath(target, sourceInfo); err != nil {
		t.Fatalf("replaceTargetPath returned error: %v", err)
	}

	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat target file: %v", err)
	}
	if targetInfo.IsDir() {
		t.Fatal("expected target to be recreated as a file")
	}
}

func TestApplyRebindPlanUsesBindMountForDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("bind mount test requires root")
	}

	sourceRoot := t.TempDir()
	targetRoot := t.TempDir()
	sourceAction := filepath.Join(sourceRoot, "action")
	targetAction := filepath.Join(targetRoot, "action")

	if err := os.MkdirAll(sourceAction, 0o755); err != nil {
		t.Fatalf("mkdir source action: %v", err)
	}
	if err := os.MkdirAll(targetAction, 0o755); err != nil {
		t.Fatalf("mkdir target action: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceAction, "payload.txt"), []byte("source"), 0o644); err != nil {
		t.Fatalf("write source payload: %v", err)
	}
	if err := os.WriteFile(filepath.Join(targetAction, "payload.txt"), []byte("target"), 0o644); err != nil {
		t.Fatalf("write target payload: %v", err)
	}

	if err := applyRebindPlan([]stagedPath{{source: sourceAction, target: targetAction}}); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bind mount not permitted in this environment: %v", err)
		}
		t.Fatalf("applyRebindPlan returned error: %v", err)
	}
	defer func() {
		if err := detachTargetMount(targetAction); err != nil {
			t.Fatalf("detach target mount: %v", err)
		}
	}()

	payload, err := os.ReadFile(filepath.Join(targetAction, "payload.txt"))
	if err != nil {
		t.Fatalf("read rebound payload: %v", err)
	}
	if string(payload) != "source" {
		t.Fatalf("expected target payload to come from source bind mount, got %q", string(payload))
	}
}
