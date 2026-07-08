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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

func TestPublicationRecordBinaryRoundTripPreservesDedupDelta(t *testing.T) {
	pub := trenvpub.Publication{
		ArtifactID:        "ckpt-a-dedup",
		CheckpointID:      "ckpt-a",
		State:             "COMMITTED",
		Fingerprint:       "fp-a",
		SnapshotStartMode: "restore",
		Shards: []trenvpub.Shard{{
			ShardID:        "base",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   100,
			DaxLengthPages: 50,
		}, {
			ShardID:        "canon",
			DaxDevice:      "/dev/dax1.0",
			DaxStartPage:   900,
			DaxLengthPages: 50,
		}},
		DedupDelta: []trenvpub.RestoreExtent{{
			Vaddr:      0x400000,
			NrPages:    2,
			Pgoff:      904,
			ShardIndex: 1,
		}},
		Stats: trenvpub.Stats{
			DedupDeltaCount:   1,
			DedupAppliedCount: 1,
		},
		CreatedAt: time.Unix(0, 1).UTC(),
	}

	record := publicationRecordFromBinary(pub)
	got := publicationRecordToBinary(record)
	if got.CheckpointID != "ckpt-a" || got.ArtifactID != "ckpt-a-dedup" {
		t.Fatalf("unexpected identity after round trip: %#v", got)
	}
	if len(got.Shards) != 2 || got.Shards[1].ShardID != "canon" {
		t.Fatalf("dedup shards were not preserved: %#v", got.Shards)
	}
	if len(got.DedupDelta) != 1 || got.DedupDelta[0].Pgoff != 904 || got.DedupDelta[0].ShardIndex != 1 {
		t.Fatalf("dedup delta was not preserved: %#v", got.DedupDelta)
	}
	if got.Stats.DedupDeltaCount != 1 || got.Stats.DedupAppliedCount != 1 {
		t.Fatalf("dedup stats were not preserved: %#v", got.Stats)
	}
}

func TestRunCommandAnnotatesOperationTiming(t *testing.T) {
	resp := runCommand(daemonRequest{
		Operation: "unknown-operation",
	})

	if resp.Operation != "unknown-operation" {
		t.Fatalf("expected response operation annotation, got %q", resp.Operation)
	}
	if resp.DurationMicros < 0 {
		t.Fatalf("expected non-negative duration, got %d", resp.DurationMicros)
	}
}

func TestRunCommandRejectsRemovedExecOperation(t *testing.T) {
	resp := runCommand(daemonRequest{Operation: "exec"})
	if resp.Ok {
		t.Fatal("expected removed exec operation to fail")
	}
	if !strings.Contains(resp.Error, "unsupported operation") {
		t.Fatalf("expected unsupported operation error, got %q", resp.Error)
	}
}

func TestRunCommandRejectsRemovedLegacySwitchOperation(t *testing.T) {
	resp := runCommand(daemonRequest{Operation: "switch"})
	if resp.Ok {
		t.Fatal("expected removed switch operation to fail")
	}
	if !strings.Contains(resp.Error, "unsupported operation") {
		t.Fatalf("expected unsupported operation error, got %q", resp.Error)
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

func writeTestPublication(t *testing.T, workDir, checkpointID, fingerprint, createdAt string) metadataPublicationRecord {
	t.Helper()
	bundlePath := filepath.Join(workDir, "checkpoints", checkpointID, "work", "metadata-bundle")
	imagePath := filepath.Join(bundlePath, "image")
	checkpointPath := filepath.Join(workDir, "checkpoints", checkpointID, "image")
	actionRoot := filepath.Join(workDir, "checkpoints", checkpointID, "work", "action-root")
	publicationPath := filepath.Join(workDir, "checkpoints", "publication", checkpointID+".json")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatalf("mkdir image: %v", err)
	}
	if err := os.MkdirAll(checkpointPath, 0o755); err != nil {
		t.Fatalf("mkdir checkpoint path: %v", err)
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
	if err := os.WriteFile(filepath.Join(checkpointPath, "pages-1.img"), []byte("pages\n"), 0o644); err != nil {
		t.Fatalf("write checkpoint pages: %v", err)
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
		CheckpointPath:             checkpointPath,
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

func TestPublicationPreferencePrefersDedupOverNewerBase(t *testing.T) {
	base := metadataPublicationRecord{
		ArtifactID:   "ckpt-a",
		CheckpointID: "ckpt-a",
		State:        "COMMITTED",
		CreatedAt:    time.Date(2026, 5, 18, 0, 1, 0, 0, time.UTC),
	}
	dedup := metadataPublicationRecord{
		ArtifactID:      "ckpt-a-dedup",
		CheckpointID:    "ckpt-a",
		State:           "COMMITTED",
		CheckpointPhase: trenvpub.DedupRestoreCOWPhase,
		Stats:           trenvpub.Stats{DedupDeltaCount: 1, DedupAppliedCount: 4},
		CreatedAt:       time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC),
	}
	publications := []metadataPublicationRecord{base, dedup}
	sort.Slice(publications, func(i, j int) bool {
		return publicationLess(publications[i], publications[j])
	})
	if publications[len(publications)-1].ArtifactID != "ckpt-a-dedup" {
		t.Fatalf("dedup publication should win over newer base: %#v", publications)
	}
}

func TestFindPublicationByCheckpointIDPrefersDerivedDedupPublication(t *testing.T) {
	workDir := t.TempDir()
	config := daemonConfig{WorkingDirectory: workDir}
	base := writeTestPublication(t, workDir, "ckpt-a", "fp-a", "2026-05-18T00:01:00Z")
	baseBinaryPath := filepath.Join(workDir, "checkpoints", "publication", "ckpt-a"+trenvpub.Extension)
	if err := trenvpub.WriteFileNoReplace(baseBinaryPath, publicationRecordToBinary(base)); err != nil {
		t.Fatalf("write base binary publication: %v", err)
	}
	dedup := base
	dedup.ArtifactID = "ckpt-a-dedup"
	dedup.CheckpointPhase = trenvpub.DedupRestoreCOWPhase
	dedup.DedupDelta = []trenvpub.RestoreExtent{{Vaddr: 0x400000, NrPages: 1, Pgoff: 64}}
	dedup.Stats = trenvpub.Stats{DedupDeltaCount: 1, DedupAppliedCount: 1}
	dedup.CreatedAt = base.CreatedAt.Add(-time.Minute)
	dedupPath := filepath.Join(workDir, "checkpoints", "publication", "ckpt-a.dedup"+trenvpub.Extension)
	if err := trenvpub.WriteFileNoReplace(dedupPath, publicationRecordToBinary(dedup)); err != nil {
		t.Fatalf("write derived binary publication: %v", err)
	}

	got, err := findPublicationByCheckpointID(config, "ckpt-a")
	if err != nil {
		t.Fatalf("find publication: %v", err)
	}
	if got.ArtifactID != "ckpt-a-dedup" || got.PublicationPath != dedupPath {
		t.Fatalf("expected derived dedup publication, got %#v", got)
	}
}

func TestListDedupCandidatesSkipsCheckpointWithExistingDerivedPublication(t *testing.T) {
	workDir := t.TempDir()
	config := normalizeDedupConfig(daemonConfig{WorkingDirectory: workDir})
	base := writeTestPublication(t, workDir, "ckpt-a", "fp-a", "2026-05-18T00:01:00Z")
	baseBinaryPath := filepath.Join(workDir, "checkpoints", "publication", "ckpt-a"+trenvpub.Extension)
	if err := trenvpub.WriteFileNoReplace(baseBinaryPath, publicationRecordToBinary(base)); err != nil {
		t.Fatalf("write base binary publication: %v", err)
	}
	candidates, err := listDedupCandidates(config)
	if err != nil {
		t.Fatalf("list candidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].CheckpointID != "ckpt-a" {
		t.Fatalf("expected base candidate before derived publication, got %#v", candidates)
	}

	dedup := base
	dedup.ArtifactID = "ckpt-a-dedup"
	dedup.CheckpointPhase = trenvpub.DedupRestoreCOWPhase
	dedup.DedupDelta = []trenvpub.RestoreExtent{{Vaddr: 0x400000, NrPages: 1, Pgoff: 64}}
	dedup.Stats = trenvpub.Stats{DedupDeltaCount: 1, DedupAppliedCount: 1}
	dedup.CreatedAt = base.CreatedAt.Add(time.Minute)
	dedupPath := filepath.Join(workDir, "checkpoints", "publication", "ckpt-a.dedup"+trenvpub.Extension)
	if err := trenvpub.WriteFileNoReplace(dedupPath, publicationRecordToBinary(dedup)); err != nil {
		t.Fatalf("write derived binary publication: %v", err)
	}

	candidates, err = listDedupCandidates(config)
	if err != nil {
		t.Fatalf("list candidates after derived publication: %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("expected checkpoint with derived publication to be skipped, got %#v", candidates)
	}
}

func TestRunDedupPublicationPassesDaxDeviceToLedger(t *testing.T) {
	workDir := t.TempDir()
	logPath := filepath.Join(workDir, "dedup-args.log")
	dedupdPath := filepath.Join(workDir, "fake-dedupd")
	pubPath := filepath.Join(workDir, "fake-trenv-dedup-pub")
	fakeDedupd := "#!/bin/sh\n" +
		"echo dedupd \"$@\" >> \"$TRENV_TEST_ARG_LOG\"\n" +
		"if [ \"$1\" = checkpoint-ledger ]; then\n" +
		"  while [ $# -gt 0 ]; do if [ \"$1\" = --output ]; then shift; touch \"$1\"; break; fi; shift; done\n" +
		"  echo '{\"mode\":\"checkpoint-candidate-ledger\"}'\n" +
		"  exit 0\n" +
		"fi\n" +
		"if [ \"$1\" = checkpoint-apply-plan ]; then echo '{\"mode\":\"checkpoint-apply-plan\",\"page_size\":4096,\"items\":[]}'; exit 0; fi\n" +
		"exit 1\n"
	fakePub := "#!/bin/sh\n" +
		"echo trenv-dedup-pub \"$@\" >> \"$TRENV_TEST_ARG_LOG\"\n" +
		"exit 0\n"
	if err := os.WriteFile(dedupdPath, []byte(fakeDedupd), 0o755); err != nil {
		t.Fatalf("write fake dedupd: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(fakePub), 0o755); err != nil {
		t.Fatalf("write fake trenv-dedup-pub: %v", err)
	}
	t.Setenv("TRENV_TEST_ARG_LOG", logPath)

	checkpointPath := filepath.Join(workDir, "checkpoints", "ckpt-a", "image")
	if err := os.MkdirAll(checkpointPath, 0o755); err != nil {
		t.Fatalf("mkdir checkpoint: %v", err)
	}
	config := normalizeDedupConfig(daemonConfig{
		WorkingDirectory:       workDir,
		DedupDedupdBinary:      dedupdPath,
		DedupPublicationBinary: pubPath,
		DedupExecution:         "cpu",
		DedupOutputDirectory:   filepath.Join(workDir, "dedup"),
		DedupMinPages:          1,
	})
	publication := metadataPublicationRecord{
		ArtifactID:      "ckpt-a",
		CheckpointID:    "ckpt-a",
		State:           "COMMITTED",
		CheckpointPath:  checkpointPath,
		PublicationPath: filepath.Join(workDir, "checkpoints", "publication", "ckpt-a"+trenvpub.Extension),
		DaxDevice:       "/dev/dax0.0",
	}
	if err := runDedupPublication(context.Background(), config, publication, "unit-test"); err != nil {
		t.Fatalf("runDedupPublication: %v", err)
	}
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read arg log: %v", err)
	}
	if !strings.Contains(string(data), "checkpoint-ledger") ||
		!strings.Contains(string(data), "--dax-device /dev/dax0.0") {
		t.Fatalf("expected ledger args to include dax device, got:\n%s", data)
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
