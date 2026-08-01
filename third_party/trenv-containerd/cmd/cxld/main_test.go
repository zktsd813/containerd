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

func TestPublicationRecordBinaryRoundTripPreservesBaseRestoreMap(t *testing.T) {
	pub := trenvpub.Publication{
		Version:           trenvpub.Version,
		ManifestSchema:    trenvpub.ManifestSchema,
		DedupApplySchema:  trenvpub.DedupApplySchema,
		ArtifactID:        "ckpt-a-dedup",
		CheckpointID:      "ckpt-a",
		State:             "COMMITTED",
		CheckpointPhase:   trenvpub.DedupRestoreCOWPhase,
		Fingerprint:       "fp-a",
		SnapshotStartMode: "restore",
		Shards: []trenvpub.Shard{{
			WriterID:       "writer0",
			ShardID:        "base",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   100,
			DaxLengthPages: 50,
			PageCount:      50,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		}},
		BaseRestoreMap: []trenvpub.RestoreExtent{{
			Vaddr:      0x400000,
			NrPages:    2,
			Pgoff:      104,
			ShardIndex: 0,
			Type:       trenvpub.RestoreExtentTypeSharedReadonly,
			Flags:      trenvpub.RestoreExtentFlagCOW,
		}},
		Stats: trenvpub.Stats{
			RestoreMapExtentCount: 1,
			DedupAppliedPages:     2,
		},
		CreatedAt: time.Unix(0, 1).UTC(),
	}

	record := publicationRecordFromBinary(pub)
	got := publicationRecordToBinary(record)
	if got.CheckpointID != "ckpt-a" || got.ArtifactID != "ckpt-a-dedup" {
		t.Fatalf("unexpected identity after round trip: %#v", got)
	}
	if len(got.Shards) != 1 || got.Shards[0].ShardID != "base" {
		t.Fatalf("dedup shards were not preserved: %#v", got.Shards)
	}
	if len(got.BaseRestoreMap) != 1 || got.BaseRestoreMap[0].Pgoff != 104 || got.BaseRestoreMap[0].ShardIndex != 0 {
		t.Fatalf("base restore map was not preserved: %#v", got.BaseRestoreMap)
	}
	if got.Stats.RestoreMapExtentCount != 1 || got.Stats.DedupAppliedPages != 2 {
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
	bundleSize, err := directoryRegularFileSize(bundlePath)
	if err != nil {
		t.Fatalf("measure bundle: %v", err)
	}
	parsedCreatedAt, err := time.Parse(time.RFC3339, createdAt)
	if err != nil {
		t.Fatalf("parse created_at: %v", err)
	}
	record := metadataPublicationRecord{
		Version:                    int(trenvpub.Version),
		ArtifactID:                 checkpointID,
		CheckpointID:               checkpointID,
		ManifestSchema:             trenvpub.ManifestSchema,
		DedupApplySchema:           trenvpub.DedupApplySchema,
		Generation:                 uint64(parsedCreatedAt.UnixNano()),
		WriterEpoch:                1,
		State:                      "COMMITTED",
		CheckpointPhase:            "cold",
		Fingerprint:                fingerprint,
		SnapshotStartMode:          "restore",
		RuntimeKind:                "nodejs:20_hybrid",
		RuntimeFamily:              "nodejs",
		CheckpointPath:             checkpointPath,
		MetadataBundlePath:         bundlePath,
		PlacementPath:              filepath.Join(bundlePath, "placement.json"),
		CheckpointActionExportRoot: actionRoot,
		MetadataBundleSize:         bundleSize,
		WriterID:                   "writer0",
		ShardID:                    "dax0.0",
		DaxDevice:                  "/dev/dax0.0",
		DaxStartPage:               0,
		DaxLengthPages:             16,
		PageCount:                  4,
		PageSize:                   4096,
		Layout:                     "contiguous-criu-page-stream",
		PageExtent: trenvpub.StorageExtent{
			Role:           directPageExtentRole,
			DeviceIdentity: "dax0.0",
			ShardID:        "dax0.0",
			OffsetBytes:    0,
			LengthBytes:    16 * 4096,
			PayloadBytes:   4 * 4096,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		},
		ArtifactExtent: trenvpub.StorageExtent{
			Role:           directArtifactExtentRole,
			DeviceIdentity: "artifact0",
			ShardID:        "artifact0",
			OffsetBytes:    0,
			LengthBytes:    4096,
			PayloadBytes:   4096,
			PageSize:       4096,
			Layout:         directArtifactExtentLayout,
		},
		Files: []trenvpub.ArtifactFile{{
			Path:   "metadata/inventory.img",
			Type:   "regular",
			Mode:   0o644,
			Offset: 0,
			Length: 10,
		}},
		Shards: []trenvpub.Shard{{
			WriterID:       "writer0",
			ShardID:        "dax0.0",
			DaxDevice:      "/dev/dax0.0",
			DaxStartPage:   0,
			DaxLengthPages: 16,
			PageCount:      4,
			PageSize:       4096,
			Layout:         "contiguous-criu-page-stream",
		}},
		CreatedAt: parsedCreatedAt,
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

func TestHandlePublicationsLatestReturnsOnePublication(t *testing.T) {
	workDir := t.TempDir()
	config := daemonConfig{WorkingDirectory: workDir}
	writeTestPublication(t, workDir, "ckpt-a", "fp-a", "2026-05-18T00:00:00Z")
	writeTestPublication(t, workDir, "ckpt-b", "fp-b", "2026-05-18T00:01:00Z")

	request := httptest.NewRequest(http.MethodGet, "/v1/publications?latest=1", nil)
	recorder := httptest.NewRecorder()
	handlePublications(config).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	var got []metadataPublicationRecord
	if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(got) != 1 || got[0].CheckpointID != "ckpt-b" {
		t.Fatalf("unexpected latest publications: %#v", got)
	}
}

func TestHandlePublicationsRejectsInvalidLatestValue(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/v1/publications?latest=yes", nil)
	recorder := httptest.NewRecorder()
	handlePublications(daemonConfig{WorkingDirectory: t.TempDir()}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
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
		BaseRestoreMap: []trenvpub.RestoreExtent{{
			Vaddr: 0x400000, NrPages: 4, Pgoff: 0, Type: 0, Flags: 1,
		}},
		Stats:     trenvpub.Stats{RestoreMapExtentCount: 1, DedupAppliedPages: 4},
		CreatedAt: time.Date(2026, 5, 18, 0, 0, 0, 0, time.UTC),
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
	dedup.BaseRestoreMap = []trenvpub.RestoreExtent{{
		Vaddr: 0x400000, NrPages: 1, Pgoff: 0, Type: 0, Flags: 1,
	}}
	dedup.Stats = trenvpub.Stats{RestoreMapExtentCount: 1, DedupAppliedPages: 1}
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
		"if [ \"$1\" = checkpoint-apply-verify ]; then echo '{\"mode\":\"checkpoint-apply-verify\"}'; exit 0; fi\n" +
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
	derivedPath := filepath.Join(workDir, "checkpoints", "publication", "ckpt-a"+trenvpub.Extension)
	if err := runDedupPublication(context.Background(), config, publication, "unit-test", derivedPath); err == nil {
		t.Fatal("expected empty fake publication output to be rejected")
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

func TestRunDedupPublicationPublishesValidatedV5Atomically(t *testing.T) {
	workDir := t.TempDir()
	baseRecord := writeTestPublication(t, workDir, "ckpt-sync", "fp-sync", "2026-07-28T00:00:00Z")
	basePath := filepath.Join(workDir, "dedup-base"+trenvpub.Extension)
	baseRecord.PublicationPath = basePath
	basePublication := publicationRecordToBinary(baseRecord)
	if err := trenvpub.WriteFileNoReplace(basePath, basePublication); err != nil {
		t.Fatalf("write base publication: %v", err)
	}
	derived, err := trenvpub.DeriveDedupPublication(
		basePublication,
		[]trenvpub.RestoreExtent{{
			Vaddr:      0x400000,
			NrPages:    2,
			Pgoff:      0,
			ShardIndex: 0,
			Type:       trenvpub.RestoreExtentTypeSharedReadonly,
			Flags:      trenvpub.RestoreExtentFlagCOW,
		}},
		trenvpub.Stats{},
		time.Date(2026, 7, 28, 0, 1, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("derive fixture publication: %v", err)
	}
	templatePath := filepath.Join(workDir, "derived-template"+trenvpub.Extension)
	if err := trenvpub.WriteFileNoReplace(templatePath, derived); err != nil {
		t.Fatalf("write derived fixture: %v", err)
	}

	dedupdPath := filepath.Join(workDir, "fake-dedupd")
	fakeDedupd := "#!/bin/sh\n" +
		"if [ \"$1\" = checkpoint-ledger ]; then\n" +
		"  while [ $# -gt 0 ]; do if [ \"$1\" = --output ]; then shift; touch \"$1\"; break; fi; shift; done\n" +
		"fi\n" +
		"echo '{}'\n"
	if err := os.WriteFile(dedupdPath, []byte(fakeDedupd), 0o755); err != nil {
		t.Fatalf("write fake dedupd: %v", err)
	}
	publisherPath := filepath.Join(workDir, "fake-trenv-dedup-pub")
	fakePublisher := "#!/bin/sh\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  if [ \"$1\" = --output ]; then shift; cp \"$TRENV_TEST_DERIVED\" \"$1\"; exit $?; fi\n" +
		"  shift\n" +
		"done\n" +
		"exit 1\n"
	if err := os.WriteFile(publisherPath, []byte(fakePublisher), 0o755); err != nil {
		t.Fatalf("write fake publisher: %v", err)
	}
	t.Setenv("TRENV_TEST_DERIVED", templatePath)

	config := normalizeDedupConfig(daemonConfig{
		WorkingDirectory:       workDir,
		DedupDedupdBinary:      dedupdPath,
		DedupPublicationBinary: publisherPath,
		DedupOutputDirectory:   filepath.Join(workDir, "dedup"),
	})
	finalPath := filepath.Join(workDir, "checkpoints", "publication", "ckpt-sync"+trenvpub.Extension)
	if err := runDedupPublication(
		context.Background(),
		config,
		baseRecord,
		"unit-sync-required",
		finalPath); err != nil {
		t.Fatalf("publish required dedup: %v", err)
	}
	published, err := trenvpub.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read final publication: %v", err)
	}
	if err := trenvpub.ValidatePublication(published); err != nil {
		t.Fatalf("validate final publication: %v", err)
	}
	if len(published.BaseRestoreMap) != 1 || published.Stats.DedupAppliedPages != 2 {
		t.Fatalf("unexpected final restore map: %#v stats=%#v", published.BaseRestoreMap, published.Stats)
	}
	statusData, err := os.ReadFile(dedupStatusPath(config, baseRecord))
	if err != nil {
		t.Fatalf("read dedup outcome: %v", err)
	}
	var status dedupRunStatus
	if err := json.Unmarshal(statusData, &status); err != nil {
		t.Fatalf("decode dedup outcome: %v", err)
	}
	if status.State != "PUBLISHED" || status.DerivedPublication != finalPath {
		t.Fatalf("unexpected dedup outcome: %#v", status)
	}
	staging, err := filepath.Glob(finalPath + ".staging-*")
	if err != nil || len(staging) != 0 {
		t.Fatalf("staging publication leaked: paths=%v err=%v", staging, err)
	}
}

func TestEnvExactDefaultPreservesSchedulerAuthorityWhitespaceForRejection(t *testing.T) {
	const name = "CXLD_TEST_EXACT_AUTHORITY_VALUE"
	t.Setenv(name, " https://etcd.test:2379 ")
	if got := envExactDefault(name, "fallback"); got != " https://etcd.test:2379 " {
		t.Fatalf("exact environment boundary changed %q", got)
	}
}

func TestVNextOwnerStartupExclusivityRejectsAuthorityOnGatewayOnlyDaemon(t *testing.T) {
	authority := vnextOwnerTestSchedulerAuthorityConfig()
	gateway := vnextOwnerGatewayConfig{
		RouteFilePath: "/etc/cxld/vnext-owner-routes.json",
	}
	if err := validateVNextOwnerStartupExclusivity(
		daemonConfig{DedupCheckpointMode: "off"},
		vnextOwnerRuntimeConfig{SchedulerAuthority: authority},
		gateway,
	); err == nil || !strings.Contains(err.Error(), "gateway-only") {
		t.Fatalf("gateway-only Scheduler authority configuration was accepted: %v", err)
	}
	if err := validateVNextOwnerStartupExclusivity(
		daemonConfig{DedupCheckpointMode: "off"},
		vnextOwnerRuntimeConfig{},
		gateway,
	); err != nil {
		t.Fatalf("gateway-only daemon with no local etcd authority was rejected: %v", err)
	}
	if err := validateVNextOwnerStartupExclusivity(
		daemonConfig{DedupCheckpointMode: "off"},
		vnextOwnerRuntimeConfig{
			ControlFilePath:    "/var/lib/cxld/owner-control",
			ControlSlotBytes:   4096,
			DAXDeviceList:      "/dev/dax0.0",
			SchedulerAuthority: authority,
		},
		vnextOwnerGatewayConfig{},
	); err != nil {
		t.Fatalf("complete local Owner Scheduler authority was rejected: %v", err)
	}
}

func TestResolveMetadataPropagatesPersistentDedupRejection(t *testing.T) {
	outcome := dedupRunStatus{
		CheckpointID: "ckpt-rejected",
		ArtifactID:   "ckpt-rejected",
		Fingerprint:  "fp-rejected",
		Generation:   42,
		WriterID:     "writer-current",
		WriterEpoch:  7,
		State:        "REJECTED",
		ErrorCode:    "dedup_no_extents",
		Error:        "no publishable dedup extents",
		FinishedAt:   time.Now().UTC(),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/publications":
			_ = json.NewEncoder(writer).Encode([]metadataPublicationRecord{})
		case "/v1/dedup-outcomes":
			_ = json.NewEncoder(writer).Encode([]dedupRunStatus{outcome})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	response := runMetadataResolveRequest(metadataResolveRequest{
		Fingerprint:     outcome.Fingerprint,
		ReaderContainer: "reader-rejected",
	}, 1000, daemonConfig{MetadataPeers: []string{server.URL}})
	if response.Ok || response.ErrorCode != outcome.ErrorCode {
		t.Fatalf("expected typed persistent dedup rejection, got %#v", response)
	}
	outcome.State = "RUNNING"
	response = runMetadataResolveRequest(metadataResolveRequest{
		Fingerprint:     outcome.Fingerprint,
		ReaderContainer: "reader-pending",
	}, 1000, daemonConfig{MetadataPeers: []string{server.URL}})
	if response.Ok || response.ErrorCode != "dedup_publication_pending" {
		t.Fatalf("expected typed pending dedup rejection, got %#v", response)
	}
	outcome.State = "PUBLISHED"
	response = runMetadataResolveRequest(metadataResolveRequest{
		Fingerprint:     outcome.Fingerprint,
		ReaderContainer: "reader-missing",
	}, 1000, daemonConfig{MetadataPeers: []string{server.URL}})
	if response.Ok || response.ErrorCode != "dedup_publication_missing" {
		t.Fatalf("expected typed missing dedup publication rejection, got %#v", response)
	}
}

func TestDedupOutcomeMatchesDerivedPublicationByCheckpointLineage(t *testing.T) {
	outcome := dedupRunStatus{
		CheckpointID: "ckpt-current",
		ArtifactID:   "ckpt-current",
		Fingerprint:  "fp-current",
		Generation:   9,
		WriterID:     "writer-current",
		WriterEpoch:  2,
		State:        "PUBLISHED",
	}
	derived := metadataPublicationRecord{
		Version:          int(trenvpub.Version),
		CheckpointID:     outcome.CheckpointID,
		ArtifactID:       outcome.ArtifactID + "-dedup-20260728T081816Z",
		Fingerprint:      outcome.Fingerprint,
		Generation:       outcome.Generation,
		WriterID:         outcome.WriterID,
		WriterEpoch:      outcome.WriterEpoch,
		CheckpointPhase:  trenvpub.DedupRestoreCOWPhase,
		DedupApplySchema: trenvpub.DedupApplySchema,
		BaseRestoreMap: []trenvpub.RestoreExtent{{
			Vaddr:      0x1000,
			NrPages:    1,
			ShardIndex: 0,
			Type:       trenvpub.RestoreExtentTypeSharedReadonly,
			Flags:      trenvpub.RestoreExtentFlagCOW,
		}},
		Stats: trenvpub.Stats{
			RestoreMapExtentCount: 1,
			DedupAppliedPages:     1,
		},
	}
	if !dedupOutcomeHasPublication(outcome, []metadataPublicationRecord{derived}) {
		t.Fatal("derived artifact ID must not break checkpoint-lineage matching")
	}
	derived.CheckpointID = "different-checkpoint"
	if dedupOutcomeHasPublication(outcome, []metadataPublicationRecord{derived}) {
		t.Fatal("publication from a different checkpoint lineage matched")
	}
}

func TestResolveMetadataDoesNotUseOlderPublicationForCurrentDedupOutcome(t *testing.T) {
	now := time.Now().UTC()
	outcome := dedupRunStatus{
		CheckpointID: "ckpt-current",
		ArtifactID:   "artifact-current",
		Fingerprint:  "fp-current",
		Generation:   9,
		WriterID:     "writer-current",
		WriterEpoch:  2,
		State:        "PUBLISHED",
		StartedAt:    now,
		FinishedAt:   now.Add(time.Second),
	}
	oldPublication := metadataPublicationRecord{
		Version:          int(trenvpub.Version),
		State:            "COMMITTED",
		CheckpointID:     "ckpt-old",
		ArtifactID:       "artifact-old",
		Fingerprint:      outcome.Fingerprint,
		Generation:       8,
		WriterID:         "writer-old",
		WriterEpoch:      1,
		CheckpointPhase:  trenvpub.DedupRestoreCOWPhase,
		DedupApplySchema: trenvpub.DedupApplySchema,
		BaseRestoreMap: []trenvpub.RestoreExtent{{
			Vaddr:      0x1000,
			NrPages:    1,
			ShardIndex: 0,
			Type:       trenvpub.RestoreExtentTypeSharedReadonly,
			Flags:      trenvpub.RestoreExtentFlagCOW,
		}},
		Stats: trenvpub.Stats{
			RestoreMapExtentCount: 1,
			DedupAppliedPages:     1,
		},
		CreatedAt: now.Add(-time.Minute),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/v1/publications":
			_ = json.NewEncoder(writer).Encode([]metadataPublicationRecord{oldPublication})
		case "/v1/dedup-outcomes":
			_ = json.NewEncoder(writer).Encode([]dedupRunStatus{outcome})
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	response := runMetadataResolveRequest(metadataResolveRequest{
		Fingerprint:     outcome.Fingerprint,
		ReaderContainer: "reader-current",
	}, 1000, daemonConfig{MetadataPeers: []string{server.URL}})
	if response.Ok || response.ErrorCode != "dedup_publication_missing" {
		t.Fatalf("expected current missing publication to reject older fallback, got %#v", response)
	}

	outcome.State = "RUNNING"
	outcome.FinishedAt = time.Time{}
	response = runMetadataResolveRequest(metadataResolveRequest{
		Fingerprint:     outcome.Fingerprint,
		ReaderContainer: "reader-running",
	}, 1000, daemonConfig{MetadataPeers: []string{server.URL}})
	if response.Ok || response.ErrorCode != "dedup_publication_pending" {
		t.Fatalf("expected current cross-writer RUNNING outcome to reject older fallback, got %#v", response)
	}
}

func TestResolveMetadataPropagatesInvalidV5Publication(t *testing.T) {
	workDir := t.TempDir()
	publicationDirectory := filepath.Join(workDir, "checkpoints", "publication")
	if err := os.MkdirAll(publicationDirectory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(publicationDirectory, "corrupt"+trenvpub.Extension),
		[]byte("not-a-v5-publication"),
		0o644); err != nil {
		t.Fatal(err)
	}
	writerConfig := daemonConfig{WorkingDirectory: workDir}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/publications", handlePublications(writerConfig))
	mux.HandleFunc("/v1/dedup-outcomes", handleDedupOutcomes(writerConfig))
	server := httptest.NewServer(mux)
	defer server.Close()

	response := runMetadataResolveRequest(metadataResolveRequest{
		Fingerprint:     "fp-corrupt",
		ReaderContainer: "reader-corrupt",
	}, 1000, daemonConfig{MetadataPeers: []string{server.URL}})
	if response.Ok || response.ErrorCode != "dedup_publication_invalid" {
		t.Fatalf("expected typed invalid-publication rejection, got %#v", response)
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

func TestArtifactHandlerV3DaxManifestFailsClosed(t *testing.T) {
	workDir := t.TempDir()
	record := writeTestV3TarPublication(t, workDir, "ckpt-v3-dax-manifest")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/artifacts/"+record.CheckpointID+".tar", nil)

	handleArtifact(daemonConfig{
		WorkingDirectory:  workDir,
		ArtifactTransport: "dax-manifest",
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusGone {
		t.Fatalf("expected v3 dax-manifest tar rejection, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
}

func TestArtifactHandlerV3LegacyTarAllowsMetadataAndActionRoot(t *testing.T) {
	workDir := t.TempDir()
	record := writeTestV3TarPublication(t, workDir, "ckpt-v3-legacy-tar")
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/v1/artifacts/"+record.CheckpointID+".tar", nil)

	handleArtifact(daemonConfig{
		WorkingDirectory:  workDir,
		ArtifactTransport: "legacy-tar",
	}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected explicit legacy-tar mode to serve v3 artifact, got status=%d body=%q", recorder.Code, recorder.Body.String())
	}
	if got := recorder.Header().Get("Content-Type"); got != "application/x-tar" {
		t.Fatalf("unexpected content type %q", got)
	}
	entries := map[string]bool{}
	reader := tar.NewReader(recorder.Body)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read v3 legacy tar: %v", err)
		}
		entries[header.Name] = true
	}
	for _, name := range []string{
		"metadata-bundle/bundle.json",
		"metadata-bundle/placement.json",
		"metadata-bundle/image/inventory.img",
		"action-root/index.js",
		"publication.original" + trenvpub.Extension,
	} {
		if !entries[name] {
			t.Fatalf("expected v3 legacy tar entry %q, saw %#v", name, entries)
		}
	}
}

func writeTestV3TarPublication(t *testing.T, workDir, checkpointID string) metadataPublicationRecord {
	t.Helper()
	record := writeTestPublication(t, workDir, checkpointID, "fp-v3", "2026-07-20T00:00:00Z")
	if err := os.Remove(record.PublicationPath); err != nil {
		t.Fatalf("remove legacy test publication: %v", err)
	}
	record.Version = int(trenvpub.Version)
	record.Generation = 1
	record.WriterEpoch = 1
	publicationPath := filepath.Join(workDir, "checkpoints", "publication", checkpointID+trenvpub.Extension)
	if err := trenvpub.WriteFileNoReplace(publicationPath, publicationRecordToBinary(record)); err != nil {
		t.Fatalf("write v3 test publication: %v", err)
	}
	record.PublicationPath = publicationPath
	return record
}

func TestMetadataResolveMaterializesPeerArtifact(t *testing.T) {
	writerWorkDir := t.TempDir()
	readerWorkDir := t.TempDir()
	record := writeTestPublication(t, writerWorkDir, "ckpt-a", "fp-a", "2026-05-18T00:00:00Z")
	record.Version = 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/publications":
			if r.URL.Query().Get("fingerprint") != "fp-a" {
				t.Fatalf("unexpected fingerprint query: %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode([]metadataPublicationRecord{record})
		case r.URL.Path == "/v1/dedup-outcomes":
			_ = json.NewEncoder(w).Encode([]dedupRunStatus{})
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
