package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPrepareOverlayDirectories(t *testing.T) {
	root := t.TempDir()
	upper := filepath.Join(root, "state", "upper")
	work := filepath.Join(root, "state", "work")
	merged := filepath.Join(root, "restore", "metadata-bundle")

	if err := prepareOverlayDirectories(upper, work, merged); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{upper, work, merged} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatalf("stat %s: %v", directory, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", directory)
		}
	}
}

func TestResolveRootfsCacheUsesSanitizedImageDirectory(t *testing.T) {
	root := t.TempDir()
	image := "trenv-experimental/openwhisk-hybrid-shell:latest"
	cacheDir := filepath.Join(root, sanitizePathPart(image))
	if err := os.MkdirAll(filepath.Join(cacheDir, "rootfs"), 0o755); err != nil {
		t.Fatalf("mkdir rootfs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "config.json"), []byte(`{"ociVersion":"1.0.2"}`), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	entry, err := resolveRootfsCache(root, image)
	if err != nil {
		t.Fatalf("resolveRootfsCache returned error: %v", err)
	}
	if entry.Rootfs != filepath.Join(cacheDir, "rootfs") {
		t.Fatalf("unexpected rootfs path: %s", entry.Rootfs)
	}
}

func TestResolveRootfsCacheFailsHardOnCacheMiss(t *testing.T) {
	if _, err := resolveRootfsCache(t.TempDir(), "missing/image:latest"); err == nil {
		t.Fatal("expected cache miss to fail")
	}
}

func TestContainerStateRegistryRoundTrip(t *testing.T) {
	config := daemonConfig{WorkingDirectory: t.TempDir()}
	state := trenvContainerState{
		ContainerID: "wsk-direct-a",
		LogicalName: "wsk-direct-a",
		Image:       "unit/test:latest",
		Rootfs:      "/tmp/rootfs",
		Bundle:      "/tmp/bundle",
		PID:         1234,
		Host:        "10.0.0.2",
		Port:        8080,
		CgroupPath:  "openwhisk-trenv/wsk-direct-a",
		RuncRoot:    "/tmp/runc",
		RuncBinary:  "/usr/local/bin/runc",
		CriuBinary:  "/usr/local/bin/criu",
		State:       "running",
		CreatedAt:   time.Unix(1, 0).UTC(),
		UpdatedAt:   time.Unix(2, 0).UTC(),
	}
	if err := saveContainerState(config, state); err != nil {
		t.Fatalf("saveContainerState returned error: %v", err)
	}
	got, err := loadContainerState(config, state.ContainerID)
	if err != nil {
		t.Fatalf("loadContainerState returned error: %v", err)
	}
	if got.ContainerID != state.ContainerID || got.PID != state.PID || got.Host != state.Host {
		t.Fatalf("unexpected loaded state: %#v", got)
	}
	ids, err := listContainerStateIDs(config)
	if err != nil {
		t.Fatalf("listContainerStateIDs returned error: %v", err)
	}
	if len(ids) != 1 || ids[0] != state.ContainerID {
		t.Fatalf("unexpected ids: %#v", ids)
	}
}

func TestCxldIdentityDefaults(t *testing.T) {
	if defaultSocketPath != "/run/cxld/cxld.sock" {
		t.Fatalf("default socket path = %q", defaultSocketPath)
	}
	workDir := t.TempDir()
	got := stateRoot(daemonConfig{WorkingDirectory: workDir})
	want := filepath.Join(workDir, "cxld-state", "containers")
	if got != want {
		t.Fatalf("state root = %q, want %q", got, want)
	}
}

func TestDirectContainerCgroupPathUsesStoredPathWithLivePID(t *testing.T) {
	state := trenvContainerState{
		ContainerID: "wsk-direct-a",
		PID:         1234,
		CgroupPath:  "openwhisk-trenv/wsk-direct-a",
	}

	got, err := directContainerCgroupPath(state)
	if err != nil {
		t.Fatalf("directContainerCgroupPath returned error: %v", err)
	}
	if got != "openwhisk-trenv/wsk-direct-a" {
		t.Fatalf("unexpected cgroup path: %s", got)
	}
}

func TestCollectDirectProcessTree(t *testing.T) {
	children := map[int][]int{
		10: {11, 12},
		11: {13},
	}
	processes, err := collectDirectProcessTree(10, func(pid int) ([]int, error) {
		return children[pid], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []int{10, 11, 12, 13}
	if len(processes) != len(want) {
		t.Fatalf("processes=%v want=%v", processes, want)
	}
	for index := range want {
		if processes[index] != want[index] {
			t.Fatalf("processes=%v want=%v", processes, want)
		}
	}
}

func TestDirectContainerCgroupPathFallsBackToStoredPath(t *testing.T) {
	state := trenvContainerState{
		ContainerID: "wsk-direct-a",
		CgroupPath:  "/openwhisk-trenv/wsk-direct-a",
	}

	got, err := directContainerCgroupPath(state)
	if err != nil {
		t.Fatalf("directContainerCgroupPath returned error: %v", err)
	}
	if got != "openwhisk-trenv/wsk-direct-a" {
		t.Fatalf("unexpected cgroup path: %s", got)
	}
}

func TestDirectContainerCgroupPathRejectsServiceCgroup(t *testing.T) {
	state := trenvContainerState{
		ContainerID: "wsk-direct-a",
		PID:         1234,
		CgroupPath:  "/system.slice/cxld.service",
	}

	if _, err := directContainerCgroupPath(state); err == nil {
		t.Fatal("expected service cgroup path to be rejected")
	}
}

func TestWriteBundleConfigDisablesTerminalForDetachedRuncCreate(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.json")
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(source, []byte(`{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": true,
    "args": ["/bin/proxy"],
    "cwd": "/app"
  }
}`), 0o644); err != nil {
		t.Fatalf("write source config: %v", err)
	}

	if err := writeBundleConfig(source, target, "/tmp/rootfs", "openwhisk-trenv/unit-a", createContainerRequest{}); err != nil {
		t.Fatalf("writeBundleConfig returned error: %v", err)
	}

	var got struct {
		Process struct {
			Terminal bool     `json:"terminal"`
			Args     []string `json:"args"`
		} `json:"process"`
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target config: %v", err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("parse target config: %v", err)
	}
	if got.Process.Terminal {
		t.Fatal("expected process.terminal to be false for detached runc create")
	}
	if len(got.Process.Args) != 1 || got.Process.Args[0] != "/bin/proxy" {
		t.Fatalf("unexpected process args: %#v", got.Process.Args)
	}
}

func TestDirectCheckpointPlacementRejectsDisabledWriter(t *testing.T) {
	_, err := directCheckpointPlacement(checkpointRequest{
		ImagePath: filepath.Join(t.TempDir(), "checkpoints", "unit-a", "image"),
		Publication: &checkpointPublicationRequest{
			PublicationPath: filepath.Join(t.TempDir(), "unit-a"+trenvpubExtensionForTest()),
		},
	}, daemonConfig{CheckpointWriterDisabled: true})
	if err == nil {
		t.Fatal("expected disabled checkpoint writer to be rejected")
	}
}

func TestDirectDefaultWriterStateRootUsesOpenWhiskRoot(t *testing.T) {
	got := directDefaultWriterStateRoot("/tmp/openwhisk-trenv/checkpoints/unit-abcd/image")
	want := "/tmp/openwhisk-trenv/writers"
	if got != want {
		t.Fatalf("unexpected default writer state root: want %q, got %q", want, got)
	}
}

func TestAllocateDirectWriterShardDaxPagesAppendOnly(t *testing.T) {
	root := t.TempDir()

	first, err := allocateDirectWriterShardDaxPages(root, "host/a", "dax0.0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	if first != 0 {
		t.Fatalf("expected first allocation at page 0, got %d", first)
	}

	second, err := allocateDirectWriterShardDaxPages(root, "host/a", "dax0.0", "ckpt-b", "/checkpoints/ckpt-b/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}
	if second != 12 {
		t.Fatalf("expected second allocation to advance to aligned page 12, got %d", second)
	}

	stateDir := directWriterShardAllocatorDir(root, "host/a", "dax0.0")
	if err := os.Remove(directWriterShardExtentPath(stateDir, "ckpt-a")); err != nil {
		t.Fatalf("remove first extent record: %v", err)
	}
	third, err := allocateDirectWriterShardDaxPages(root, "host/a", "dax0.0", "ckpt-c", "/checkpoints/ckpt-c/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("third allocation failed: %v", err)
	}
	if third != 24 {
		t.Fatalf("expected append-only allocation to avoid the freed gap and use page 24, got %d", third)
	}
}

func TestAllocateDirectWriterShardDaxPagesIsIdempotent(t *testing.T) {
	root := t.TempDir()

	first, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 8)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	second, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 8)
	if err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}
	if second != first {
		t.Fatalf("expected idempotent allocation to return %d, got %d", first, second)
	}
}

func TestAllocateDirectWriterShardDaxPagesReturnsExhaustion(t *testing.T) {
	root := t.TempDir()

	if _, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 16, 4, 10); err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	if _, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-b", "/checkpoints/ckpt-b/image", 16, 4, 10); err == nil {
		t.Fatal("expected second allocation to fail because append-only state is exhausted")
	}
}

func TestRollbackDirectDaxPlacementReservationRewindsTail(t *testing.T) {
	root := t.TempDir()

	start, existed, err := allocateDirectWriterShardDaxPagesWithResult(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("allocation failed: %v", err)
	}
	if existed {
		t.Fatal("expected first allocation to be new")
	}
	placement := directDaxPlacement{
		CheckpointID:    "ckpt-a",
		WriterID:        "writer0",
		ShardID:         "shard0",
		DaxStartPage:    start,
		DaxLengthPages:  10,
		NewReservation:  true,
		WriterStateRoot: root,
	}
	if err := rollbackDirectDaxPlacementReservationErr(placement); err != nil {
		t.Fatalf("rollback failed: %v", err)
	}

	next, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-b", "/checkpoints/ckpt-b/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("next allocation failed: %v", err)
	}
	if next != 0 {
		t.Fatalf("expected rollback to rewind tail to page 0, got %d", next)
	}
}

func TestRollbackDirectDaxPlacementReservationRefusesNonTail(t *testing.T) {
	root := t.TempDir()

	start, existed, err := allocateDirectWriterShardDaxPagesWithResult(root, "writer0", "shard0", "ckpt-a", "/checkpoints/ckpt-a/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("first allocation failed: %v", err)
	}
	if existed {
		t.Fatal("expected first allocation to be new")
	}
	if _, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-b", "/checkpoints/ckpt-b/image", 64, 4, 10); err != nil {
		t.Fatalf("second allocation failed: %v", err)
	}

	err = rollbackDirectDaxPlacementReservationErr(directDaxPlacement{
		CheckpointID:    "ckpt-a",
		WriterID:        "writer0",
		ShardID:         "shard0",
		DaxStartPage:    start,
		DaxLengthPages:  10,
		NewReservation:  true,
		WriterStateRoot: root,
	})
	if err == nil {
		t.Fatal("expected non-tail rollback to be refused")
	}

	third, err := allocateDirectWriterShardDaxPages(root, "writer0", "shard0", "ckpt-c", "/checkpoints/ckpt-c/image", 64, 4, 10)
	if err != nil {
		t.Fatalf("third allocation failed: %v", err)
	}
	if third != 24 {
		t.Fatalf("expected non-tail rollback refusal to preserve allocator tail, got page %d", third)
	}
}

func TestAllocateDirectDaxPlacementInOrderFallsBackWhenShardIsFull(t *testing.T) {
	root := t.TempDir()
	candidates := []directDaxPlacementCandidate{
		{
			shard:       daxShardConfig{ShardID: "dax0.0", DaxDevice: "/dev/dax0.0"},
			devicePages: 16,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
		{
			shard:       daxShardConfig{ShardID: "dax1.0", DaxDevice: "/dev/dax1.0"},
			devicePages: 64,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
	}

	if _, err := allocateDirectDaxPlacementInOrder(root, "writer0", "ckpt-a", "/checkpoints/ckpt-a/image", candidates[:1]); err != nil {
		t.Fatalf("seed allocation failed: %v", err)
	}
	placement, err := allocateDirectDaxPlacementInOrder(root, "writer0", "ckpt-b", "/checkpoints/ckpt-b/image", candidates)
	if err != nil {
		t.Fatalf("fallback allocation failed: %v", err)
	}
	if placement.ShardID != "dax1.0" || placement.DaxDevice != "/dev/dax1.0" {
		t.Fatalf("expected fallback to second shard, got %#v", placement)
	}
}

func TestDirectRoundRobinDaxPlacementAdvancesSelector(t *testing.T) {
	root := t.TempDir()
	candidates := []directDaxPlacementCandidate{
		{
			shard:       daxShardConfig{ShardID: "dax0.0", DaxDevice: "/dev/dax0.0"},
			devicePages: 64,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
		{
			shard:       daxShardConfig{ShardID: "dax1.0", DaxDevice: "/dev/dax1.0"},
			devicePages: 64,
			alignPages:  4,
			lengthPages: 10,
			pageSize:    4096,
		},
	}

	first, err := resolveDirectRoundRobinDaxPlacement(root, "writer0", "ckpt-a", "/checkpoints/ckpt-a/image", candidates)
	if err != nil {
		t.Fatalf("first round-robin allocation failed: %v", err)
	}
	second, err := resolveDirectRoundRobinDaxPlacement(root, "writer0", "ckpt-b", "/checkpoints/ckpt-b/image", candidates)
	if err != nil {
		t.Fatalf("second round-robin allocation failed: %v", err)
	}
	if first.ShardID != "dax0.0" || second.ShardID != "dax1.0" {
		t.Fatalf("expected round-robin shard order dax0.0 then dax1.0, got %q then %q", first.ShardID, second.ShardID)
	}
}

func TestNormalizeDirectDaxPlacementPolicyRejectsUnsupported(t *testing.T) {
	if _, err := normalizeDirectDaxPlacementPolicy("spread"); err == nil {
		t.Fatal("expected unsupported DAX placement policy to fail")
	}
}

func TestDirectCheckpointPagePayloadIncludesLegacyPagesImage(t *testing.T) {
	imagePath := t.TempDir()
	files := map[string]int{
		"pages-1.img": 4096,
		"pages.img":   8192,
		"pagemap.img": 4096,
	}
	for name, size := range files {
		if err := os.WriteFile(filepath.Join(imagePath, name), make([]byte, size), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	bytes, pages := directCheckpointPagePayload(imagePath, 4096)
	if bytes != 12288 || pages != 3 {
		t.Fatalf("expected pages payload 12288 bytes / 3 pages, got %d bytes / %d pages", bytes, pages)
	}
}

func TestWriteDirectMetadataBundleExcludesPagePayload(t *testing.T) {
	root := t.TempDir()
	imagePath := filepath.Join(root, "image")
	bundlePath := filepath.Join(root, "metadata-bundle")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image: %v", err)
	}
	files := map[string]string{
		"inventory.img":    "inventory",
		"descriptors.json": `[]`,
		"pages-1.img":      "page payload",
		"pages.img":        "legacy page payload",
		"cgroup.img":       "cgroup payload",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(imagePath, name), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	placement := directDaxPlacement{
		CheckpointID:   "unit-a",
		WriterID:       "writer-a",
		ShardID:        "dax0.0",
		DaxDevice:      "/dev/dax0.0",
		DaxLengthPages: 1,
		PageSize:       4096,
		Layout:         "direct-runc-criu-page-files",
		State:          "COMMITTED",
	}
	if err := writeDirectMetadataBundle(imagePath, bundlePath, placement); err != nil {
		t.Fatalf("writeDirectMetadataBundle returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "image", "inventory.img")); err != nil {
		t.Fatalf("expected inventory in metadata bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "image", "descriptors.json")); err != nil {
		t.Fatalf("expected descriptors in metadata bundle: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "image", "pages-1.img")); !os.IsNotExist(err) {
		t.Fatalf("page payload should not be copied, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "image", "pages.img")); !os.IsNotExist(err) {
		t.Fatalf("legacy page payload should not be copied, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(bundlePath, "image", "cgroup.img")); !os.IsNotExist(err) {
		t.Fatalf("cgroup payload should not be copied, stat err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(bundlePath, "bundle.json"))
	if err != nil {
		t.Fatalf("read bundle manifest: %v", err)
	}
	var manifest directMetadataBundleManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse bundle manifest: %v", err)
	}
	if len(manifest.Files) != 2 {
		t.Fatalf("expected two reader metadata files, got %#v", manifest.Files)
	}
}

func trenvpubExtensionForTest() string {
	return ".trenvpub"
}
