package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

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
