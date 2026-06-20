package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

func TestRunCommandDispatchesLegacyCheckpointRequest(t *testing.T) {
	resp := runCommand(daemonRequest{
		Command:       []string{"/usr/local/bin/trenv-checkpoint-task"},
		TimeoutMillis: 1500,
	})

	if resp.Ok {
		t.Fatalf("expected checkpoint request to fail on helper usage validation")
	}
	if resp.ExitCode != 2 {
		t.Fatalf("expected helper usage exit code 2, got %d", resp.ExitCode)
	}
	if !strings.Contains(resp.Stderr, "image path must be provided") {
		t.Fatalf("expected checkpoint helper stderr, got %q", resp.Stderr)
	}
}

func TestRunCommandDispatchesExplicitSwitchRequest(t *testing.T) {
	resp := runCommand(daemonRequest{
		Operation:     "switch",
		Command:       []string{"/usr/local/bin/trenv-switch-task"},
		TimeoutMillis: 1500,
	})

	if resp.Ok {
		t.Fatalf("expected switch request to fail on helper usage validation")
	}
	if resp.ExitCode != 2 {
		t.Fatalf("expected helper usage exit code 2, got %d", resp.ExitCode)
	}
	if !strings.Contains(resp.Stderr, "checkpoint path must be provided") {
		t.Fatalf("expected switch helper stderr, got %q", resp.Stderr)
	}
}

func TestRunCommandRejectsHelperAsExternalExec(t *testing.T) {
	resp := runCommand(daemonRequest{
		Operation:     "exec",
		Command:       []string{"/usr/local/bin/trenv-switch-task"},
		TimeoutMillis: 1500,
	})

	if resp.Ok {
		t.Fatalf("expected external helper exec to be rejected")
	}
	if !strings.Contains(resp.Error, "not allowed") {
		t.Fatalf("expected not-allowed error, got %q", resp.Error)
	}
}

func TestStructuredCheckpointRequestBuildsHelperArgs(t *testing.T) {
	got := checkpointArgs(checkpointRequest{
		Address:            "/run/containerd/containerd.sock",
		Namespace:          "openwhisk",
		ImagePath:          "/tmp/image",
		WorkPath:           "/tmp/work",
		MetadataBundlePath: "/tmp/work/metadata-bundle",
		ActionExportRoots:  []string{"/home/app"},
		Publication: &checkpointPublicationRequest{
			PublicationPath:            "/tmp/checkpoints/publication/ckpt.json",
			RuntimeKind:                "nodejs:20",
			RuntimeFamily:              "nodejs",
			ActionNamespace:            "guest",
			ActionName:                 "/guest/hello",
			ActionRevision:             "rev-1",
			CheckpointPhase:            "post-first-run",
			Fingerprint:                "fp-1",
			SnapshotStartMode:          "switch",
			CheckpointActionExportRoot: "/tmp/work/action-root",
		},
		ContainerID: "source",
	}, 2500, checkpointWriterPlacement{
		DaxDevice:       "/dev/dax0.0",
		WriterID:        "writer0",
		ShardID:         "dax0.0",
		WriterStateRoot: "/tmp/openwhisk-trenv/writers",
	})
	want := []string{
		"--timeout", "2500ms",
		"--address", "/run/containerd/containerd.sock",
		"--namespace", "openwhisk",
		"--image-path", "/tmp/image",
		"--work-path", "/tmp/work",
		"--metadata-bundle-path", "/tmp/work/metadata-bundle",
		"--dax-device", "/dev/dax0.0",
		"--shard-id", "dax0.0",
		"--writer-id", "writer0",
		"--writer-state-root", "/tmp/openwhisk-trenv/writers",
		"--publication-path", "/tmp/checkpoints/publication/ckpt.json",
		"--runtime-kind", "nodejs:20",
		"--runtime-family", "nodejs",
		"--action-namespace", "guest",
		"--action-name", "/guest/hello",
		"--action-revision", "rev-1",
		"--checkpoint-phase", "post-first-run",
		"--fingerprint", "fp-1",
		"--snapshot-start-mode", "switch",
		"--checkpoint-action-export-root", "/tmp/work/action-root",
		"--action-export-root", "/home/app",
		"source",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args:\nwant: %#v\n got: %#v", want, got)
	}
}

func TestStructuredCheckpointRequestOmitsEmptyPublicationArgs(t *testing.T) {
	got := checkpointArgs(checkpointRequest{
		Address:            "/run/containerd/containerd.sock",
		Namespace:          "openwhisk",
		ImagePath:          "/tmp/image",
		WorkPath:           "/tmp/work",
		MetadataBundlePath: "/tmp/work/metadata-bundle",
		Publication:        &checkpointPublicationRequest{},
		ContainerID:        "source",
	}, 0, checkpointWriterPlacement{
		DaxDevice:       "/dev/dax0.0",
		WriterID:        "writer0",
		ShardID:         "dax0.0",
		WriterStateRoot: "/tmp/openwhisk-trenv/writers",
	})

	for _, forbidden := range []string{"--publication-path", "--runtime-kind", "--runtime-family", "--action-namespace", "--action-name", "--action-revision", "--checkpoint-phase", "--fingerprint", "--snapshot-start-mode", "--checkpoint-action-export-root"} {
		for _, arg := range got {
			if arg == forbidden {
				t.Fatalf("did not expect empty publication arg %s in %#v", forbidden, got)
			}
		}
	}
}

func TestStructuredCheckpointRequestDoesNotPreallocateDaxOffset(t *testing.T) {
	got := checkpointArgs(checkpointRequest{
		Address:            "/run/containerd/containerd.sock",
		Namespace:          "openwhisk",
		ImagePath:          "/tmp/image",
		WorkPath:           "/tmp/work",
		MetadataBundlePath: "/tmp/work/metadata-bundle",
		ContainerID:        "source",
	}, 0, checkpointWriterPlacement{
		DaxDevice:       "/dev/dax0.0",
		WriterID:        "writer0",
		ShardID:         "dax0.0",
		WriterStateRoot: "/tmp/openwhisk-trenv/writers",
	})

	for _, arg := range got {
		if arg == "--dax-pgoff" {
			t.Fatalf("trenvd must not preallocate dax pgoff before checkpoint succeeds: %#v", got)
		}
	}
}

func TestStructuredCheckpointRequestBuildsMultiDaxArgs(t *testing.T) {
	got := checkpointArgs(checkpointRequest{
		Address:            "/run/containerd/containerd.sock",
		Namespace:          "openwhisk",
		ImagePath:          "/tmp/image",
		WorkPath:           "/tmp/work",
		MetadataBundlePath: "/tmp/work/metadata-bundle",
		ContainerID:        "source",
	}, 0, checkpointWriterPlacement{
		WriterID: "writer0",
		DaxShards: []daxShardConfig{
			{ShardID: "dax7.0", DaxDevice: "/dev/dax7.0"},
			{ShardID: "dax8.0", DaxDevice: "/dev/dax8.0"},
		},
		DaxPlacementPolicy: "round-robin",
		WriterStateRoot:    "/tmp/openwhisk-trenv/writers",
	})

	for _, want := range []string{"--dax-shard", "dax7.0=/dev/dax7.0", "dax8.0=/dev/dax8.0", "--dax-placement-policy", "round-robin"} {
		if !containsArg(got, want) {
			t.Fatalf("expected %q in args: %#v", want, got)
		}
	}
	if containsArg(got, "--dax-device") || containsArg(got, "--shard-id") {
		t.Fatalf("multi-DAX args should not include legacy single-DAX flags: %#v", got)
	}
}

func TestParseDaxShardConfigList(t *testing.T) {
	got, err := parseDaxShardConfigList("dax7.0=/dev/dax7.0,/dev/dax8.0")
	if err != nil {
		t.Fatalf("parseDaxShardConfigList returned error: %v", err)
	}
	want := []daxShardConfig{
		{ShardID: "dax7.0", DaxDevice: "/dev/dax7.0"},
		{ShardID: "dax8.0", DaxDevice: "/dev/dax8.0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected shards:\nwant: %#v\n got: %#v", want, got)
	}
	if _, err := parseDaxShardConfigList("dup=/dev/dax7.0,dup=/dev/dax8.0"); err == nil {
		t.Fatal("expected duplicate shard id to be rejected")
	}
}

func TestStructuredSwitchRequestBuildsHelperArgs(t *testing.T) {
	got := switchArgs(switchRequest{
		Address:             "/run/containerd/containerd.sock",
		Namespace:           "openwhisk",
		CheckpointPath:      "/tmp/image",
		SourceContainer:     "source",
		ActionSourceRootfs:  "/tmp/action-root",
		ShellID:             "node-shell",
		CompatibilityClass:  "nodejs",
		ActiveRuntimeKind:   "nodejs:20_hybrid",
		ActiveRuntimeFamily: "nodejs",
		StableActionRoot:    "/home/app",
		ActionRebinds:       []actionRebind{{SourceRoot: "/home/app", TargetRoot: "/home/app"}},
		NullIO:              true,
		PidFile:             "/tmp/pid",
		ContainerID:         "candidate",
	}, 2500)
	want := []string{
		"--timeout", "2500ms",
		"--address", "/run/containerd/containerd.sock",
		"--namespace", "openwhisk",
		"--checkpoint-path", "/tmp/image",
		"--null-io",
		"--pid-file", "/tmp/pid",
		"--shell-id", "node-shell",
		"--compatibility-class", "nodejs",
		"--active-runtime-kind", "nodejs:20_hybrid",
		"--active-runtime-family", "nodejs",
		"--stable-action-root", "/home/app",
		"--action-source-rootfs", "/tmp/action-root",
		"--source-container", "source",
		"--action-rebind", "/home/app:/home/app",
		"candidate",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args:\nwant: %#v\n got: %#v", want, got)
	}
}

func TestSwitchRequestWithRuntimeConfigUsesReaderDaxShardMap(t *testing.T) {
	req := switchRequest{
		Address:        "/run/containerd/containerd.sock",
		Namespace:      "openwhisk",
		CheckpointPath: "/tmp/image",
		ContainerID:    "candidate",
	}
	withConfig := switchRequestWithRuntimeConfig(req, daemonConfig{
		DaxDevice: "/dev/dax-legacy",
		ReaderDaxShards: []daxShardConfig{
			{ShardID: "dax7.0", DaxDevice: "/dev/dax7.0"},
		},
	})
	got := switchArgs(withConfig, 0)
	if !containsArg(got, "--reader-dax-shard") || !containsArg(got, "dax7.0=/dev/dax7.0") {
		t.Fatalf("expected reader DAX shard mapping in args: %#v", got)
	}
	if containsArg(got, "--dax-device") || containsArg(got, "/dev/dax-legacy") {
		t.Fatalf("reader shard mapping should prevent legacy override injection: %#v", got)
	}
}

func TestStructuredSwitchPhaseArgsSplitPrepareAndRestore(t *testing.T) {
	req := switchRequest{
		Address:        "/run/containerd/containerd.sock",
		Namespace:      "openwhisk",
		CheckpointPath: "/tmp/image",
		ActionRebinds:  []actionRebind{{SourceRoot: "/home/app", TargetRoot: "/home/app"}},
		ContainerID:    "candidate",
	}

	prepare := switchArgsForPhase(req, 0, true, false)
	if !containsArg(prepare, "--prepare-only") {
		t.Fatalf("prepare args should include --prepare-only: %#v", prepare)
	}
	if containsArg(prepare, "--skip-action-rebind") {
		t.Fatalf("prepare args should not skip action rebind: %#v", prepare)
	}

	restore := switchArgsForPhase(req, 0, false, true)
	if !containsArg(restore, "--skip-action-rebind") {
		t.Fatalf("restore args should include --skip-action-rebind: %#v", restore)
	}
	if containsArg(restore, "--prepare-only") {
		t.Fatalf("restore args should not include --prepare-only: %#v", restore)
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

func TestIntegratedTaskArgsInjectsDaemonTimeout(t *testing.T) {
	got := integratedTaskArgs([]string{"--checkpoint-path", "/tmp/image", "candidate"}, 2500)
	want := []string{"--timeout", "2500ms", "--checkpoint-path", "/tmp/image", "candidate"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected args:\nwant: %#v\n got: %#v", want, got)
	}
}

func TestIntegratedTaskArgsKeepsExplicitTimeout(t *testing.T) {
	args := []string{"--timeout", "7s", "--checkpoint-path", "/tmp/image", "candidate"}
	got := integratedTaskArgs(args, 2500)
	if !reflect.DeepEqual(got, args) {
		t.Fatalf("unexpected args:\nwant: %#v\n got: %#v", args, got)
	}

	args = []string{"--timeout=7s", "--checkpoint-path", "/tmp/image", "candidate"}
	got = integratedTaskArgs(args, 2500)
	if !reflect.DeepEqual(got, args) {
		t.Fatalf("unexpected args:\nwant: %#v\n got: %#v", args, got)
	}
}

func TestDefaultWriterStateRootUsesOpenWhiskRoot(t *testing.T) {
	got := defaultWriterStateRoot("/tmp/openwhisk-trenv/checkpoints/unit-abcd/image")
	want := "/tmp/openwhisk-trenv/writers"
	if got != want {
		t.Fatalf("unexpected default writer state root: want %q, got %q", want, got)
	}
}

func TestResolveCheckpointWriterPlacementRejectsDisabledWriter(t *testing.T) {
	_, err := resolveCheckpointWriterPlacement(checkpointRequest{
		ImagePath: "/tmp/openwhisk-trenv/checkpoints/unit-abcd/image",
	}, daemonConfig{CheckpointWriterDisabled: true})
	if err == nil {
		t.Fatal("expected disabled checkpoint writer to be rejected")
	}
	if !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func writeTestPublication(t *testing.T, workDir, checkpointID, fingerprint, createdAt string) metadataPublicationRecord {
	t.Helper()
	bundlePath := filepath.Join(workDir, "checkpoints", checkpointID, "work", "metadata-bundle")
	imagePath := filepath.Join(bundlePath, "image")
	actionRoot := filepath.Join(workDir, "checkpoints", checkpointID, "work", "action-root")
	publicationPath := filepath.Join(workDir, "checkpoints", "publication", checkpointID+".json")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image: %v", err)
	}
	if err := os.MkdirAll(actionRoot, 0o755); err != nil {
		t.Fatalf("mkdir action root: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(publicationPath), 0o755); err != nil {
		t.Fatalf("mkdir publication: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imagePath, "inventory.img"), []byte("inventory\n"), 0o644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "placement.json"), []byte(`{"checkpoint_id":"`+checkpointID+`","state":"COMMITTED"}`+"\n"), 0o644); err != nil {
		t.Fatalf("write placement: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "bundle.json"), []byte(`{"checkpoint_id":"`+checkpointID+`","image_path":"image","placement":"placement.json","files":[]}`+"\n"), 0o644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(actionRoot, "index.js"), []byte("module.exports = {}\n"), 0o644); err != nil {
		t.Fatalf("write action root: %v", err)
	}
	virtualenvBin := filepath.Join(actionRoot, "1", "bin", "virtualenv", "bin")
	if err := os.MkdirAll(virtualenvBin, 0o755); err != nil {
		t.Fatalf("mkdir virtualenv bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(virtualenvBin, "python3.10"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write virtualenv python target: %v", err)
	}
	if err := os.Symlink("python3.10", filepath.Join(virtualenvBin, "python3")); err != nil {
		t.Fatalf("write virtualenv python symlink: %v", err)
	}
	bundleSize, bundleDigest, err := digestDirectory(bundlePath)
	if err != nil {
		t.Fatalf("digest bundle: %v", err)
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t.Fatalf("parse created_at: %v", err)
	}
	record := metadataPublicationRecord{
		Version:                    1,
		ArtifactID:                 checkpointID,
		CheckpointID:               checkpointID,
		State:                      "COMMITTED",
		Fingerprint:                fingerprint,
		SnapshotStartMode:          "restore",
		RuntimeKind:                "nodejs:20_hybrid",
		RuntimeFamily:              "nodejs",
		CheckpointPath:             filepath.Join(workDir, "checkpoints", checkpointID, "image"),
		MetadataBundlePath:         bundlePath,
		PlacementPath:              filepath.Join(bundlePath, "placement.json"),
		CheckpointActionExportRoot: actionRoot,
		MetadataBundleSize:         bundleSize,
		MetadataBundleSHA256:       bundleDigest,
		WriterID:                   "writer0",
		ShardID:                    "dax0.0",
		DaxDevice:                  "/dev/dax0.0",
		DaxStartPage:               0,
		DaxLengthPages:             16,
		PageCount:                  4,
		PageSize:                   4096,
		Layout:                     "contiguous-criu-page-stream",
		CreatedAt:                  parsedCreatedAt,
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal publication: %v", err)
	}
	if err := os.WriteFile(publicationPath, data, 0o644); err != nil {
		t.Fatalf("write publication: %v", err)
	}
	record.PublicationPath = publicationPath
	return record
}

func TestListCommittedPublicationsFiltersByFingerprint(t *testing.T) {
	workDir := t.TempDir()
	config := daemonConfig{WorkingDirectory: workDir}
	writeTestPublication(t, workDir, "ckpt-a", "fp-a", "2026-05-18T00:00:00Z")
	writeTestPublication(t, workDir, "ckpt-b", "fp-b", "2026-05-18T00:01:00Z")

	got, err := listCommittedPublications(config, "fp-a")
	if err != nil {
		t.Fatalf("list publications: %v", err)
	}
	if len(got) != 1 || got[0].CheckpointID != "ckpt-a" {
		t.Fatalf("unexpected publications: %#v", got)
	}
}

func TestArtifactTarContainsReaderMetadataAndActionRoot(t *testing.T) {
	workDir := t.TempDir()
	record := writeTestPublication(t, workDir, "ckpt-a", "fp-a", "2026-05-18T00:00:00Z")

	var buf bytes.Buffer
	if err := writeArtifactTar(&buf, record); err != nil {
		t.Fatalf("write artifact tar: %v", err)
	}
	tr := tar.NewReader(&buf)
	seen := map[string]bool{}
	symlinks := map[string]string{}
	for {
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("read tar: %v", err)
		}
		seen[header.Name] = true
		if header.Typeflag == tar.TypeSymlink {
			symlinks[header.Name] = header.Linkname
		}
	}
	for _, name := range []string{"metadata-bundle/bundle.json", "metadata-bundle/placement.json", "metadata-bundle/image/inventory.img", "action-root/index.js", "publication.original.json"} {
		if !seen[name] {
			t.Fatalf("expected tar entry %q, saw %#v", name, seen)
		}
	}
	if got := symlinks["action-root/1/bin/virtualenv/bin/python3"]; got != "python3.10" {
		t.Fatalf("expected action-root symlink target python3.10, got %q in %#v", got, symlinks)
	}
}

func TestMetadataResolveMaterializesPeerArtifact(t *testing.T) {
	writerWorkDir := t.TempDir()
	readerWorkDir := t.TempDir()
	record := writeTestPublication(t, writerWorkDir, "ckpt-a", "fp-a", "2026-05-18T00:00:00Z")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/publications":
			if r.URL.Query().Get("fingerprint") != "fp-a" {
				t.Fatalf("unexpected fingerprint query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode([]metadataPublicationRecord{record})
		case r.URL.Path == "/v1/artifacts/ckpt-a.tar":
			if err := writeArtifactTar(w, record); err != nil {
				t.Fatalf("write artifact: %v", err)
			}
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()

	response, err := resolveMetadata(contextWithTimeout(t), metadataResolveRequest{
		Fingerprint:     "fp-a",
		ReaderContainer: "reader-container",
	}, daemonConfig{
		WorkingDirectory: readerWorkDir,
		MetadataPeers:    []string{server.URL},
	})
	if err != nil {
		t.Fatalf("resolve metadata: %v", err)
	}
	if !response.Found || response.CheckpointID != "ckpt-a" || response.Source != "publication-reader-network" {
		t.Fatalf("unexpected metadata response: %#v", response)
	}
	if _, err := os.Stat(response.CheckpointPath); err != nil {
		t.Fatalf("expected reader checkpoint path: %v", err)
	}
	if _, err := os.Stat(response.CheckpointActionExportRoot); err != nil {
		t.Fatalf("expected reader action root: %v", err)
	}
	readerSymlink := filepath.Join(response.CheckpointActionExportRoot, "1", "bin", "virtualenv", "bin", "python3")
	if got, err := os.Readlink(readerSymlink); err != nil || got != "python3.10" {
		t.Fatalf("expected reader action-root symlink target python3.10, got %q err=%v", got, err)
	}
	cachePublication, err := readPublicationRecord(filepath.Join(readerWorkDir, "reader-cache", "ckpt-a", "publication.reader"+trenvpub.Extension))
	if err != nil {
		t.Fatalf("read cache publication: %v", err)
	}
	wantCacheCheckpointPath := filepath.Join(readerWorkDir, "reader-cache", "ckpt-a", "metadata-bundle", "image")
	if cachePublication.CheckpointPath != wantCacheCheckpointPath {
		t.Fatalf("cache publication checkpoint path should use final cache root: want %q, got %q", wantCacheCheckpointPath, cachePublication.CheckpointPath)
	}
	if strings.Contains(cachePublication.CheckpointPath, ".tmp.") {
		t.Fatalf("cache publication should not contain staging path: %q", cachePublication.CheckpointPath)
	}
}

func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
