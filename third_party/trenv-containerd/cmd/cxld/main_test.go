package main

import (
	"context"
	"encoding/json"
	"errors"
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
	publicationPath := filepath.Join(workDir, "checkpoints", "publication", checkpointID+trenvpub.Extension)
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
	if err := trenvpub.WriteFileNoReplace(publicationPath, publicationRecordToBinary(record)); err != nil {
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
	if err := os.Remove(baseRecord.PublicationPath); err != nil {
		t.Fatalf("remove initial base publication: %v", err)
	}
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
	oldPublication := writeTestPublication(
		t,
		t.TempDir(),
		"ckpt-old",
		outcome.Fingerprint,
		"2026-07-28T00:00:00Z")
	oldPublication.ArtifactID = "artifact-old"
	oldPublication.Generation = 8
	oldPublication.WriterID = "writer-old"
	oldPublication.WriterEpoch = 1
	oldPublication.CheckpointPhase = trenvpub.DedupRestoreCOWPhase
	oldPublication.BaseRestoreMap = []trenvpub.RestoreExtent{{
		Vaddr:      0x1000,
		NrPages:    1,
		ShardIndex: 0,
		Type:       trenvpub.RestoreExtentTypeSharedReadonly,
		Flags:      trenvpub.RestoreExtentFlagCOW,
	}}
	oldPublication.Stats = trenvpub.Stats{
		RestoreMapExtentCount: 1,
		DedupAppliedPages:     1,
	}
	oldPublication.CreatedAt = now.Add(-time.Minute)
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

func TestReadPublicationRecordRejectsLegacyJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"state":"COMMITTED"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicationRecord(path); err == nil || !strings.Contains(err.Error(), "only strict V5") {
		t.Fatalf("expected strict V5 rejection, got %v", err)
	}
}

func TestFetchPeerPublicationsRejectsNonV5Schema(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*metadataPublicationRecord)
	}{
		{
			name: "legacy version",
			mutate: func(record *metadataPublicationRecord) {
				record.Version = 1
			},
		},
		{
			name: "legacy manifest schema",
			mutate: func(record *metadataPublicationRecord) {
				record.ManifestSchema = "trenv-publication-v4"
			},
		},
		{
			name: "legacy dedup apply schema",
			mutate: func(record *metadataPublicationRecord) {
				record.DedupApplySchema = "trenv-dedup-apply-v4"
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writerWorkDir := t.TempDir()
			record := writeTestPublication(t, writerWorkDir, "ckpt-a", "fp-a", "2026-05-18T00:00:00Z")
			test.mutate(&record)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/publications" {
					t.Fatalf("unexpected path: %s", r.URL.Path)
				}
				if r.URL.Query().Get("fingerprint") != "fp-a" {
					t.Fatalf("unexpected fingerprint query: %s", r.URL.RawQuery)
				}
				_ = json.NewEncoder(w).Encode([]metadataPublicationRecord{record})
			}))
			defer server.Close()

			_, err := fetchPeerPublications(contextWithTimeout(t), []string{server.URL}, "fp-a")
			var rejection *dedupMetadataRejectionError
			if !errors.As(err, &rejection) || rejection.Code != "dedup_publication_invalid" {
				t.Fatalf("expected typed non-V5 publication rejection, got %v", err)
			}
		})
	}
}

func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}
