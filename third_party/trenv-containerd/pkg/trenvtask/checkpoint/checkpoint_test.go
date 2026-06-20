package checkpoint

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	"github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestFindAvailableStartPageUsesPreferredGap(t *testing.T) {
	records := []daxAllocationRecord{
		{ImagePath: "a", StartPage: 0, LengthPages: 8},
		{ImagePath: "b", StartPage: 24, LengthPages: 8},
	}

	start, ok := findAvailableStartPage(records, 64, 4, 8, 8)
	if !ok {
		t.Fatalf("expected to find a free range")
	}
	if start != 8 {
		t.Fatalf("expected preferred free start 8, got %d", start)
	}
}

func TestFindAvailableStartPageWrapsAround(t *testing.T) {
	records := []daxAllocationRecord{
		{ImagePath: "a", StartPage: 8, LengthPages: 24},
		{ImagePath: "b", StartPage: 32, LengthPages: 8},
	}

	start, ok := findAvailableStartPage(records, 40, 4, 8, 8)
	if !ok {
		t.Fatalf("expected to find a free range")
	}
	if start != 0 {
		t.Fatalf("expected wrapped start 0, got %d", start)
	}
}

func TestOverlapsExisting(t *testing.T) {
	records := []daxAllocationRecord{{ImagePath: "a", StartPage: 16, LengthPages: 16}}

	if !overlapsExisting(records, 24, 8) {
		t.Fatalf("expected overlap")
	}
	if overlapsExisting(records, 32, 8) {
		t.Fatalf("did not expect overlap at boundary")
	}
}

func TestExportActionRootsCopiesRequestedTree(t *testing.T) {
	stateRoot := t.TempDir()
	workPath := t.TempDir()
	sourceRoot := filepath.Join(taskRootfsPath(stateRoot, "openwhisk", "source"), "home", "app", "1", "bin")

	if err := os.MkdirAll(sourceRoot, 0o755); err != nil {
		t.Fatalf("mkdir source root: %v", err)
	}
	if err := os.WriteFile(filepath.Join(sourceRoot, "exec"), []byte("ok"), 0o755); err != nil {
		t.Fatalf("write source payload: %v", err)
	}

	if err := exportActionRoots(stateRoot, "openwhisk", "source", workPath, []string{"/home/app"}); err != nil {
		t.Fatalf("exportActionRoots returned error: %v", err)
	}

	exportedPath := filepath.Join(workPath, "action-root", "home", "app", "1", "bin", "exec")
	if _, err := os.Stat(exportedPath); err != nil {
		t.Fatalf("expected exported payload at %q: %v", exportedPath, err)
	}
}

func TestCheckpointOptionsEnableFileLocksForRuncV2(t *testing.T) {
	info := &containerd.CheckpointTaskInfo{Options: &options.CheckpointOptions{}}
	if err := checkpointOptions(plugin.RuntimeRuncV2, "/image", "/work", true, false)(info); err != nil {
		t.Fatalf("checkpointOptions returned error: %v", err)
	}

	opts, ok := info.Options.(*options.CheckpointOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", info.Options)
	}
	if !opts.FileLocks {
		t.Fatal("expected file locks to be enabled")
	}
	if !opts.OpenTcp {
		t.Fatal("expected open tcp to be enabled")
	}
	if opts.Terminal {
		t.Fatal("did not expect shell-job/terminal mode by default")
	}
}

func TestCheckpointOptionsEnableFileLocksForLegacyRunc(t *testing.T) {
	info := &containerd.CheckpointTaskInfo{Options: &runctypes.CheckpointOptions{}}
	if err := checkpointOptions("legacy", "/image", "/work", true, false)(info); err != nil {
		t.Fatalf("checkpointOptions returned error: %v", err)
	}

	opts, ok := info.Options.(*runctypes.CheckpointOptions)
	if !ok {
		t.Fatalf("unexpected options type %T", info.Options)
	}
	if !opts.FileLocks {
		t.Fatal("expected file locks to be enabled")
	}
	if !opts.OpenTcp {
		t.Fatal("expected open tcp to be enabled")
	}
	if opts.Terminal {
		t.Fatal("did not expect shell-job/terminal mode by default")
	}
}

func TestCheckpointNeedsShellJobForJavaFamily(t *testing.T) {
	spec := &specs.Spec{
		Process: &specs.Process{
			Env: []string{
				"FOO=bar",
				activeRuntimeFamilyEnv + "=java",
			},
		},
	}

	if !checkpointNeedsShellJob(spec) {
		t.Fatal("expected java family to require shell-job checkpointing")
	}
}

func TestCheckpointNeedsShellJobDisabledForNonJava(t *testing.T) {
	spec := &specs.Spec{
		Process: &specs.Process{
			Env: []string{
				activeRuntimeFamilyEnv + "=python",
			},
		},
	}

	if checkpointNeedsShellJob(spec) {
		t.Fatal("did not expect non-java family to require shell-job checkpointing")
	}
}

func TestAllocateWriterShardDaxPagesIsAppendOnly(t *testing.T) {
	root := t.TempDir()

	first, err := allocateWriterShardDaxPages(root, "host/a", "dax0.0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	if first != 0 {
		t.Fatalf("expected first allocation at page 0, got %d", first)
	}

	second, err := allocateWriterShardDaxPages(root, "host/a", "dax0.0", "ckpt-b", "/checkpoints/ckpt-b/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}
	if second != 12 {
		t.Fatalf("expected second allocation to advance to aligned page 12, got %d", second)
	}

	stateDir := writerShardAllocatorDir(root, "host/a", "dax0.0")
	if err := os.Remove(writerShardExtentPath(stateDir, "ckpt-a")); err != nil {
		t.Fatalf("remove first extent record: %v", err)
	}

	third, err := allocateWriterShardDaxPages(root, "host/a", "dax0.0", "ckpt-c", "/checkpoints/ckpt-c/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("third allocation failed: %v", err)
	}
	if third != 24 {
		t.Fatalf("expected append-only allocation to avoid the freed gap and use page 24, got %d", third)
	}
}

func TestAllocateWriterShardDaxPagesIsIdempotent(t *testing.T) {
	root := t.TempDir()

	first, err := allocateWriterShardDaxPages(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 8)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	second, err := allocateWriterShardDaxPages(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 8)
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}
	if second != first {
		t.Fatalf("expected idempotent allocation to return %d, got %d", first, second)
	}
}

func TestAllocateWriterShardDaxPagesReturnsExhaustion(t *testing.T) {
	root := t.TempDir()

	if _, err := allocateWriterShardDaxPages(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 16, 4, 10); err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	if _, err := allocateWriterShardDaxPages(root, "writer0", "shard0", "ckpt-b", "/checkpoints/ckpt-b/image", 16, 4, 10); err == nil {
		t.Fatal("expected second allocation to fail because append-only state is exhausted")
	}
}

func TestParseDaxShardOptionSupportsExplicitAndBareDevice(t *testing.T) {
	explicit, err := parseDaxShardOption("dax7.0=/dev/dax7.0")
	if err != nil {
		t.Fatalf("parse explicit shard: %v", err)
	}
	if explicit.ShardID != "dax7.0" || explicit.DaxDevice != "/dev/dax7.0" {
		t.Fatalf("unexpected explicit shard: %#v", explicit)
	}

	bare, err := parseDaxShardOption("/dev/dax8.0")
	if err != nil {
		t.Fatalf("parse bare shard: %v", err)
	}
	if bare.ShardID != "dax8.0" || bare.DaxDevice != "/dev/dax8.0" {
		t.Fatalf("unexpected bare shard: %#v", bare)
	}
}

func TestAllocateDaxPlacementInOrderFallsBackWhenShardIsFull(t *testing.T) {
	root := t.TempDir()
	candidates := []daxPlacementCandidate{
		{
			shard:       daxShardOption{ShardID: "dax0.0", DaxDevice: "/dev/dax0.0"},
			devicePages: 16,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
		{
			shard:       daxShardOption{ShardID: "dax1.0", DaxDevice: "/dev/dax1.0"},
			devicePages: 64,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
	}

	if _, err := allocateDaxPlacementInOrder(root, "writer0", "ckpt-a", "/checkpoints/ckpt-a/image", candidates[:1], 0); err != nil {
		t.Fatalf("seed allocation failed: %v", err)
	}
	placement, err := allocateDaxPlacementInOrder(root, "writer0", "ckpt-b", "/checkpoints/ckpt-b/image", candidates, 0)
	if err != nil {
		t.Fatalf("fallback allocation failed: %v", err)
	}
	if placement.ShardID != "dax1.0" || placement.DaxDevice != "/dev/dax1.0" {
		t.Fatalf("expected fallback to second shard, got %#v", placement)
	}
}

func TestRoundRobinDaxPlacementAdvancesSelector(t *testing.T) {
	root := t.TempDir()
	candidates := []daxPlacementCandidate{
		{
			shard:       daxShardOption{ShardID: "dax0.0", DaxDevice: "/dev/dax0.0"},
			devicePages: 64,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
		{
			shard:       daxShardOption{ShardID: "dax1.0", DaxDevice: "/dev/dax1.0"},
			devicePages: 64,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
	}

	first, err := resolveRoundRobinDaxPlacement(root, "writer0", "ckpt-a", "/checkpoints/ckpt-a/image", candidates, 0)
	if err != nil {
		t.Fatalf("first round-robin allocation failed: %v", err)
	}
	second, err := resolveRoundRobinDaxPlacement(root, "writer0", "ckpt-b", "/checkpoints/ckpt-b/image", candidates, 0)
	if err != nil {
		t.Fatalf("second round-robin allocation failed: %v", err)
	}
	if first.ShardID != "dax0.0" || second.ShardID != "dax1.0" {
		t.Fatalf("expected round-robin shard order dax0.0 then dax1.0, got %q then %q", first.ShardID, second.ShardID)
	}
}

func TestWriteMetadataBundleExcludesPagePayloadButKeepsRestoreMetadata(t *testing.T) {
	imagePath := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "bundle")
	files := map[string]string{
		"inventory.img":     "inventory",
		"cgroup.img":        "writer cgroup",
		"mm-1.img":          "mm",
		"pagemap-1.img":     "pagemap",
		"pages-1.img":       "pages",
		"pseudo_mm_id-1":    "local pseudo mm",
		"convert-pgnum.img": "123",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(imagePath, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write image file %s: %v", name, err)
		}
	}

	placement := daxPlacement{
		CheckpointID:   "ckpt-a",
		WriterID:       "writer0",
		ShardID:        "shard0",
		DaxDevice:      "/dev/dax0.0",
		DaxStartPage:   16,
		DaxLengthPages: 32,
		PageCount:      12,
		PageSize:       4096,
		Layout:         "contiguous-criu-page-stream",
		State:          "COMMITTED",
		UpdatedAt:      time.Now().UTC(),
	}

	if err := writeMetadataBundle(imagePath, bundlePath, placement); err != nil {
		t.Fatalf("writeMetadataBundle failed: %v", err)
	}

	for _, name := range []string{"inventory.img", "mm-1.img", "pagemap-1.img", "pseudo_mm_id-1", "convert-pgnum.img"} {
		if _, err := os.Stat(filepath.Join(bundlePath, "image", name)); err != nil {
			t.Fatalf("expected bundled metadata file %s: %v", name, err)
		}
	}
	for _, name := range []string{"pages-1.img", "cgroup.img"} {
		if _, err := os.Stat(filepath.Join(bundlePath, "image", name)); !os.IsNotExist(err) {
			t.Fatalf("expected %s to be excluded from metadata bundle, stat err=%v", name, err)
		}
	}

	var manifest metadataBundleManifest
	manifestData, err := os.ReadFile(filepath.Join(bundlePath, "bundle.json"))
	if err != nil {
		t.Fatalf("read bundle manifest: %v", err)
	}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("unmarshal bundle manifest: %v", err)
	}
	if manifest.CheckpointID != "ckpt-a" {
		t.Fatalf("unexpected checkpoint id in bundle manifest: %s", manifest.CheckpointID)
	}
	if len(manifest.Files) != 5 {
		t.Fatalf("expected 5 metadata files in bundle manifest, got %d", len(manifest.Files))
	}

	var actualPlacement daxPlacement
	placementData, err := os.ReadFile(filepath.Join(bundlePath, "placement.json"))
	if err != nil {
		t.Fatalf("read placement: %v", err)
	}
	if err := json.Unmarshal(placementData, &actualPlacement); err != nil {
		t.Fatalf("unmarshal placement: %v", err)
	}
	if actualPlacement.PageCount != 12 {
		t.Fatalf("expected page_count=12, got %d", actualPlacement.PageCount)
	}
}

func TestDefaultPublicationPathUsesOpenWhiskPublicationRoot(t *testing.T) {
	got := defaultPublicationPath("/tmp/openwhisk-trenv/checkpoints/unit-123/image")
	want := "/tmp/openwhisk-trenv/checkpoints/publication/unit-123" + trenvpub.Extension
	if got != want {
		t.Fatalf("unexpected publication path: want %q, got %q", want, got)
	}
}

func TestWritePublicationMetadataWritesBinaryRecord(t *testing.T) {
	imagePath := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "metadata-bundle")
	publicationPath := filepath.Join(t.TempDir(), "publication", "ckpt-a"+trenvpub.Extension)

	if err := os.WriteFile(filepath.Join(imagePath, "inventory.img"), []byte("inventory"), 0o644); err != nil {
		t.Fatalf("write image metadata: %v", err)
	}
	placement := daxPlacement{
		CheckpointID:   "ckpt-a",
		WriterID:       "writer0",
		ShardID:        "shard0",
		DaxDevice:      "/dev/dax0.0",
		DaxStartPage:   16,
		DaxLengthPages: 32,
		PageCount:      12,
		PageSize:       4096,
		Layout:         "contiguous-criu-page-stream",
		State:          "COMMITTED",
		UpdatedAt:      time.Now().UTC(),
	}
	if err := writeMetadataBundle(imagePath, bundlePath, placement); err != nil {
		t.Fatalf("writeMetadataBundle failed: %v", err)
	}

	context := checkpointPublicationContext{
		RuntimeKind:       "nodejs:20_hybrid",
		RuntimeFamily:     "nodejs",
		ActionNamespace:   "guest",
		ActionName:        "/guest/hello",
		ActionRevision:    "rev-1",
		Fingerprint:       "fp-1",
		SnapshotStartMode: "switch",
	}
	if err := writePublicationMetadata(imagePath, bundlePath, publicationPath, placement, context); err != nil {
		t.Fatalf("writePublicationMetadata failed: %v", err)
	}

	publication, err := trenvpub.ReadFile(publicationPath)
	if err != nil {
		t.Fatalf("read binary publication: %v", err)
	}
	if publication.State != "COMMITTED" || publication.Fingerprint != "fp-1" {
		t.Fatalf("unexpected binary publication: %#v", publication)
	}
	if len(publication.Shards) != 1 || publication.Shards[0].DaxStartPage != 16 {
		t.Fatalf("unexpected binary shard placement: %#v", publication.Shards)
	}
	if publication.ActionIdentity == nil || publication.ActionIdentity.FullyQualifiedName != "/guest/hello" {
		t.Fatalf("unexpected action identity: %#v", publication.ActionIdentity)
	}
}

func TestWritePublicationMetadataWritesCommittedRecord(t *testing.T) {
	imagePath := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "metadata-bundle")
	publicationPath := filepath.Join(t.TempDir(), "publication", "ckpt-a.json")

	if err := os.WriteFile(filepath.Join(imagePath, "inventory.img"), []byte("inventory"), 0o644); err != nil {
		t.Fatalf("write image metadata: %v", err)
	}
	placement := daxPlacement{
		CheckpointID:     "ckpt-a",
		WriterID:         "writer0",
		ShardID:          "shard0",
		DaxDevice:        "/dev/dax0.0",
		DaxStartPage:     16,
		DaxLengthPages:   32,
		PageCount:        12,
		ConvertPageCount: 12,
		PageSize:         4096,
		Layout:           "contiguous-criu-page-stream",
		State:            "COMMITTED",
		UpdatedAt:        time.Now().UTC(),
	}
	if err := writeMetadataBundle(imagePath, bundlePath, placement); err != nil {
		t.Fatalf("writeMetadataBundle failed: %v", err)
	}

	context := checkpointPublicationContext{
		RuntimeKind:                "nodejs:20",
		RuntimeFamily:              "nodejs",
		ActionNamespace:            "guest",
		ActionName:                 "/guest/hello",
		ActionRevision:             "rev-1",
		CheckpointPhase:            "post-first-run",
		Fingerprint:                "fp-1",
		SnapshotStartMode:          "switch",
		CheckpointActionExportRoot: filepath.Join(bundlePath, "..", "action-root"),
	}
	if err := writePublicationMetadata(imagePath, bundlePath, publicationPath, placement, context); err != nil {
		t.Fatalf("writePublicationMetadata failed: %v", err)
	}

	var publication checkpointPublicationMetadata
	data, err := os.ReadFile(publicationPath)
	if err != nil {
		t.Fatalf("read publication: %v", err)
	}
	if err := json.Unmarshal(data, &publication); err != nil {
		t.Fatalf("unmarshal publication: %v", err)
	}
	if publication.State != "COMMITTED" {
		t.Fatalf("expected COMMITTED publication, got %q", publication.State)
	}
	if publication.MetadataBundleSize <= 0 {
		t.Fatalf("expected positive bundle size, got %d", publication.MetadataBundleSize)
	}
	if publication.MetadataBundleSHA256 == "" {
		t.Fatal("expected bundle digest")
	}
	if publication.ActionIdentity == nil || publication.ActionIdentity.FullyQualifiedName != "/guest/hello" {
		t.Fatalf("unexpected action identity: %#v", publication.ActionIdentity)
	}
	if publication.Fingerprint != "fp-1" || publication.SnapshotStartMode != "switch" {
		t.Fatalf("unexpected publication identity fields: %#v", publication)
	}
	if publication.CheckpointActionExportRoot == "" {
		t.Fatalf("expected checkpoint_action_export_root in publication: %#v", publication)
	}
	if publication.DaxStartPage != 16 || publication.DaxLengthPages != 32 || publication.PageCount != 12 {
		t.Fatalf("unexpected placement in publication: %#v", publication)
	}
}

func TestWritePublicationMetadataRejectsExistingRecord(t *testing.T) {
	imagePath := t.TempDir()
	bundlePath := filepath.Join(t.TempDir(), "metadata-bundle")
	publicationPath := filepath.Join(t.TempDir(), "publication", "ckpt-a.json")
	placement := daxPlacement{
		CheckpointID:   "ckpt-a",
		WriterID:       "writer0",
		ShardID:        "shard0",
		DaxDevice:      "/dev/dax0.0",
		DaxStartPage:   0,
		DaxLengthPages: 8,
		PageSize:       4096,
		Layout:         "contiguous-criu-page-stream",
		State:          "COMMITTED",
	}
	if err := os.WriteFile(filepath.Join(imagePath, "inventory.img"), []byte("inventory"), 0o644); err != nil {
		t.Fatalf("write image metadata: %v", err)
	}
	if err := writeMetadataBundle(imagePath, bundlePath, placement); err != nil {
		t.Fatalf("writeMetadataBundle failed: %v", err)
	}
	if err := writePublicationMetadata(imagePath, bundlePath, publicationPath, placement, checkpointPublicationContext{}); err != nil {
		t.Fatalf("first publication failed: %v", err)
	}
	err := writePublicationMetadata(imagePath, bundlePath, publicationPath, placement, checkpointPublicationContext{})
	if err == nil {
		t.Fatal("expected existing publication to be rejected")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWritePublicationMetadataRequiresReadyBundle(t *testing.T) {
	placement := daxPlacement{
		CheckpointID:   "ckpt-a",
		WriterID:       "writer0",
		ShardID:        "shard0",
		DaxDevice:      "/dev/dax0.0",
		DaxStartPage:   0,
		DaxLengthPages: 8,
		PageSize:       4096,
		Layout:         "contiguous-criu-page-stream",
		State:          "COMMITTED",
	}
	err := writePublicationMetadata(t.TempDir(), filepath.Join(t.TempDir(), "missing-bundle"), filepath.Join(t.TempDir(), "pub.json"), placement, checkpointPublicationContext{})
	if err == nil {
		t.Fatal("expected missing metadata bundle to be rejected")
	}
	if !strings.Contains(err.Error(), "metadata bundle manifest is not ready") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDigestDirectoryIsDeterministicAndContentSensitive(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "b.img"), []byte("b"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a.img"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}

	sizeA, digestA, err := digestDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	sizeB, digestB, err := digestDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if sizeA != sizeB || digestA != digestB {
		t.Fatalf("expected deterministic digest, got (%d, %s) and (%d, %s)", sizeA, digestA, sizeB, digestB)
	}

	if err := os.WriteFile(filepath.Join(root, "a.img"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	sizeC, digestC, err := digestDirectory(root)
	if err != nil {
		t.Fatal(err)
	}
	if sizeC == sizeA && digestC == digestA {
		t.Fatal("expected digest to change after file content changed")
	}
}
