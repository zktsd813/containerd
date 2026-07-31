package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

func TestResolveDirectPseudoMMImportPlanUsesStableReaderShard(t *testing.T) {
	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatal(err)
	}
	publication := metadataPublicationRecord{
		Version:      int(trenvpub.Version),
		ArtifactID:   "artifact-a",
		CheckpointID: "checkpoint-a",
		Generation:   7,
		WriterEpoch:  3,
		State:        "COMMITTED",
		PageExtent: trenvpub.StorageExtent{
			Role:           directPageExtentRole,
			DeviceIdentity: "shared-page-shard",
			ShardID:        "shared-page-shard",
			OffsetBytes:    32 * 4096,
			LengthBytes:    64 * 4096,
			PayloadBytes:   4 * 4096,
			PageSize:       4096,
		},
	}
	if err := writeJSONFile(filepath.Join(restoreRoot, "publication.reader.json"), publication); err != nil {
		t.Fatal(err)
	}
	config := daemonConfig{
		WorkingDirectory:            filepath.Join(restoreRoot, "work"),
		PseudoMMMaterializationRoot: filepath.Join(restoreRoot, "pseudo"),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   "shared-page-shard",
			DaxDevice: "/dev/dax-reader-local",
		}},
	}
	plan, ok, err := resolveDirectPseudoMMImportPlan(switchRequest{
		CheckpointPath: imagePath,
		ContainerID:    "reader-container",
	}, config)
	if err != nil {
		t.Fatalf("resolve import plan: %v", err)
	}
	if !ok {
		t.Fatal("expected reader pseudo_mm import plan")
	}
	if plan.daxDevice != "/dev/dax-reader-local" || plan.daxStartPage != 32 {
		t.Fatalf("unexpected reader DAX binding: %#v", plan)
	}
	wantWork := filepath.Join(config.PseudoMMMaterializationRoot, sanitizePathPart("artifact-a"), sanitizePathPart("reader-container"))
	if plan.workPath != wantWork {
		t.Fatalf("unexpected materialization work path: want %q got %q", wantWork, plan.workPath)
	}
	wantArgs := []string{"--dax-device", "/dev/dax-reader-local", "--dax-pgoff", "32", "--import-existing-dax"}
	args := buildDirectPseudoMMImportArgs(plan)
	for _, value := range wantArgs {
		if !containsDirectImportArg(args, value) {
			t.Fatalf("import args missing %q: %#v", value, args)
		}
	}
}

func TestResolveDirectPseudoMMImportPlanSkipsLocalCheckpoint(t *testing.T) {
	plan, ok, err := resolveDirectPseudoMMImportPlan(switchRequest{
		CheckpointPath: filepath.Join(t.TempDir(), "raw-image"),
	}, daemonConfig{})
	if err != nil || ok || !reflect.DeepEqual(plan, directPseudoMMImportPlan{}) {
		t.Fatalf("expected local checkpoint to skip reader import: plan=%#v ok=%v err=%v", plan, ok, err)
	}
}

func TestRemoveDirectReaderPseudoMMIDs(t *testing.T) {
	imagePath := t.TempDir()
	for _, name := range []string{"pseudo_mm_id-1", "pseudo_mm_id-2", "inventory.img"} {
		if err := os.WriteFile(filepath.Join(imagePath, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeDirectReaderPseudoMMIDs(imagePath); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(imagePath, "inventory.img")); err != nil {
		t.Fatal("non-pseudo_mm file was removed")
	}
	if matches, _ := filepath.Glob(filepath.Join(imagePath, "pseudo_mm_id-*")); len(matches) != 0 {
		t.Fatalf("stale pseudo_mm ids remain: %#v", matches)
	}
}

func TestPrepareDirectReaderPseudoMMImportsOncePerKernelBoot(t *testing.T) {
	originalInvalidate := directDaxInvalidateHook
	directDaxInvalidateHook = func([]byte) error { return nil }
	t.Cleanup(func() { directDaxInvalidateHook = originalInvalidate })

	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatal(err)
	}
	pageData := []byte(strings.Repeat("p", 4096))
	device := filepath.Join(restoreRoot, "shared-dax.bin")
	if err := os.WriteFile(device, pageData, 0o600); err != nil {
		t.Fatal(err)
	}
	publication := metadataPublicationRecord{
		Version:      int(trenvpub.Version),
		ArtifactID:   "artifact-import",
		CheckpointID: "checkpoint-import",
		Generation:   1,
		WriterEpoch:  1,
		State:        "COMMITTED",
		PageExtent: trenvpub.StorageExtent{
			Role:           directPageExtentRole,
			DeviceIdentity: "shared-page-shard",
			ShardID:        "shared-page-shard",
			LengthBytes:    4096,
			PayloadBytes:   4096,
			PageSize:       4096,
		},
	}
	if err := writeJSONFile(filepath.Join(restoreRoot, "publication.reader.json"), publication); err != nil {
		t.Fatal(err)
	}

	pseudoDevice := filepath.Join(restoreRoot, "pseudo-mm")
	if err := os.WriteFile(pseudoDevice, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPseudoMMPath := directReaderPseudoMMPath
	directReaderPseudoMMPath = pseudoDevice
	t.Cleanup(func() { directReaderPseudoMMPath = originalPseudoMMPath })
	logPath := filepath.Join(restoreRoot, "imports.log")
	t.Setenv("TRENV_READER_IMPORT_LOG", logPath)
	fakeCRIU := filepath.Join(restoreRoot, "fake-criu")
	script := "#!/bin/sh\n" +
		"echo import >> \"$TRENV_READER_IMPORT_LOG\"\n" +
		"image=\n" +
		"while [ $# -gt 0 ]; do if [ \"$1\" = -D ]; then shift; image=$1; fi; shift; done\n" +
		"printf 7 > \"$image/pseudo_mm_id-1\"\n"
	if err := os.WriteFile(fakeCRIU, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	config := daemonConfig{
		WorkingDirectory:            filepath.Join(restoreRoot, "work"),
		PseudoMMMaterializationRoot: filepath.Join(restoreRoot, "pseudo-cache"),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   "shared-page-shard",
			DaxDevice: device,
		}},
	}
	req := switchRequest{CheckpointPath: imagePath, ContainerID: "reader-container"}
	state := trenvContainerState{PID: os.Getpid(), CriuBinary: fakeCRIU}
	plan, ok, err := resolveDirectPseudoMMImportPlan(req, config)
	if err != nil {
		t.Fatalf("resolve reader import: %v", err)
	}
	if !ok {
		t.Fatal("expected reader import plan")
	}
	if err := prepareDirectReaderPseudoMM(context.Background(), plan, state, config); err != nil {
		t.Fatalf("first reader import: %v", err)
	}
	if err := os.Remove(filepath.Join(imagePath, "pseudo_mm_id-1")); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirectReaderPseudoMM(context.Background(), plan, state, config); err != nil {
		t.Fatalf("reuse reader import: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(data), "import") != 1 {
		t.Fatalf("expected one CRIU import, got %q", data)
	}
	if got, err := os.ReadFile(filepath.Join(imagePath, "pseudo_mm_id-1")); err != nil || string(got) != "7" {
		t.Fatalf("expected cached reader pseudo_mm id, got %q err=%v", got, err)
	}
}

func containsDirectImportArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}
