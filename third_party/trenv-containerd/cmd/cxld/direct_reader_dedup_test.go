package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

func validDirectV5DedupPublication() metadataPublicationRecord {
	return metadataPublicationRecord{
		Version:          directDedupPublicationVersion,
		ArtifactID:       "artifact-v5-dedup",
		CheckpointID:     "checkpoint-v5",
		ManifestSchema:   trenvpub.ManifestSchema,
		DedupApplySchema: trenvpub.DedupApplySchema,
		Generation:       9,
		WriterEpoch:      4,
		State:            "COMMITTED",
		CheckpointPhase:  trenvpub.DedupRestoreCOWPhase,
		WriterID:         "writer-a",
		ShardID:          "shared-page-shard",
		PageExtent: trenvpub.StorageExtent{
			Role:           directPageExtentRole,
			DeviceIdentity: "shared-page-shard",
			ShardID:        "shared-page-shard",
			OffsetBytes:    32 * 4096,
			LengthBytes:    16 * 4096,
			PayloadBytes:   8 * 4096,
			PageSize:       4096,
		},
		BaseRestoreMap: []trenvpub.RestoreExtent{
			{
				Vaddr:      0x400000,
				NrPages:    2,
				Pgoff:      32,
				ShardIndex: 0,
				Type:       trenvpub.RestoreExtentTypeSharedReadonly,
				Flags:      trenvpub.RestoreExtentFlagCOW,
			},
			{
				Vaddr:      0x500000,
				NrPages:    1,
				Pgoff:      34,
				ShardIndex: 0,
				Type:       trenvpub.RestoreExtentTypeSharedReadonly,
				Flags:      trenvpub.RestoreExtentFlagCOW,
			},
		},
		Stats: trenvpub.Stats{
			RestoreMapExtentCount: 2,
			DedupAppliedPages:     3,
		},
	}
}

func TestDedupRestoreErrorCodeSurvivesWrapping(t *testing.T) {
	inner := newDedupRestoreError(dedupRestoreCodeStats, errors.New("bad stats"))
	wrapped := errors.New("outer: " + inner.Error())
	if code := dedupRestoreErrorCode(wrapped); code != "" {
		t.Fatalf("plain rendered error unexpectedly retained typed code %q", code)
	}
	wrapped = &testWrappedError{err: inner}
	if code := dedupRestoreErrorCode(wrapped); code != dedupRestoreCodeStats {
		t.Fatalf("unexpected typed error code %q", code)
	}
}

type testWrappedError struct {
	err error
}

func (e *testWrappedError) Error() string { return "wrapped: " + e.err.Error() }
func (e *testWrappedError) Unwrap() error { return e.err }

func TestBuildDirectV5RestoreMapUsesBaseMapAndLocalDevice(t *testing.T) {
	publication := validDirectV5DedupPublication()
	data, digest, pages, err := buildDirectV5RestoreMap(publication, "/dev/dax-reader-local")
	if err != nil {
		t.Fatal(err)
	}
	want := "0x400000 2 32 /dev/dax-reader-local\n0x500000 1 34 /dev/dax-reader-local\n"
	if string(data) != want {
		t.Fatalf("unexpected remap:\nwant: %q\n got: %q", want, string(data))
	}
	if len(digest) != 64 {
		t.Fatalf("unexpected restore map digest %q", digest)
	}
	if pages != 3 {
		t.Fatalf("unexpected restore map page count %d", pages)
	}
}

func TestBuildDirectV5RestoreMapRejectsInvalidBaseMap(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*metadataPublicationRecord)
		code   string
	}{
		{
			name: "empty",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap = nil
				publication.Stats = trenvpub.Stats{}
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "shard index",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[0].ShardIndex = 1
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "unaligned vaddr",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[0].Vaddr++
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "zero pages",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[0].NrPages = 0
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "target overlap",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[1].Vaddr = publication.BaseRestoreMap[0].Vaddr + 4096
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "pgoff outside payload",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[0].Pgoff = 40
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "unsupported type",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[0].Type = 7
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "unsupported flags",
			mutate: func(publication *metadataPublicationRecord) {
				publication.BaseRestoreMap[0].Flags = 2
			},
			code: dedupRestoreCodeBaseMap,
		},
		{
			name: "extent stats mismatch",
			mutate: func(publication *metadataPublicationRecord) {
				publication.Stats.RestoreMapExtentCount = 1
			},
			code: dedupRestoreCodeStats,
		},
		{
			name: "page stats mismatch",
			mutate: func(publication *metadataPublicationRecord) {
				publication.Stats.DedupAppliedPages = 4
			},
			code: dedupRestoreCodeStats,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			publication := validDirectV5DedupPublication()
			test.mutate(&publication)
			_, _, _, err := buildDirectV5RestoreMap(publication, "/dev/dax-reader-local")
			if err == nil {
				t.Fatal("expected invalid BaseRestoreMap to fail")
			}
			if code := dedupRestoreErrorCode(err); code != test.code {
				t.Fatalf("unexpected error code %q for %v", code, err)
			}
		})
	}
}

func TestDirectV5DedupPublicationRequiresV5Phase(t *testing.T) {
	publication := validDirectV5DedupPublication()
	if ok, err := directV5DedupPublication(publication); err != nil || !ok {
		t.Fatalf("expected V5 derived publication, ok=%v err=%v", ok, err)
	}
	publication.Version = directDedupPublicationVersion - 1
	if _, err := directV5DedupPublication(publication); dedupRestoreErrorCode(err) != dedupRestoreCodePublication {
		t.Fatalf("expected old dedup publication rejection, got %v", err)
	}
	publication = validDirectV5DedupPublication()
	publication.CheckpointPhase = ""
	if _, err := directV5DedupPublication(publication); dedupRestoreErrorCode(err) != dedupRestoreCodePublication {
		t.Fatalf("expected missing phase rejection, got %v", err)
	}
}

func TestResolveDirectPseudoMMImportPlanBuildsV5RestoreMap(t *testing.T) {
	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatal(err)
	}
	publication := validDirectV5DedupPublication()
	publication.ArtifactID = strings.Repeat("artifact-", 64)
	publication.CheckpointPath = imagePath
	publication.DaxDevice = "/dev/dax-writer-must-not-leak"
	writeStrictReaderPublication(t, restoreRoot, publication)
	localDevice := filepath.Join(restoreRoot, "reader-dax")
	config := daemonConfig{
		WorkingDirectory: filepath.Join(restoreRoot, "work"),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   publication.PageExtent.ShardID,
			DaxDevice: localDevice,
		}},
	}
	plan, ok, err := resolveDirectPseudoMMImportPlan(switchRequest{
		CheckpointPath: imagePath,
		ContainerID:    "reader-container",
	}, config)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected V5 reader import plan")
	}
	if plan.daxDevice != localDevice ||
		plan.restoreMapExtentCount != uint64(len(publication.BaseRestoreMap)) ||
		plan.restoreMapPageCount != publication.Stats.DedupAppliedPages ||
		len(plan.restoreMapSHA256) != 64 {
		t.Fatalf("incomplete V5 reader import plan: %#v", plan)
	}
	if strings.Contains(string(plan.restoreMap), publication.DaxDevice) ||
		!strings.Contains(string(plan.restoreMap), localDevice) {
		t.Fatalf("restore map did not bind exclusively to reader-local device: %q", plan.restoreMap)
	}
}

func TestWriteDirectReaderDaxRemapFileIsAtomicPrivateAndCleaned(t *testing.T) {
	workPath := t.TempDir()
	data := []byte("0x400000 1 32 /dev/dax-reader-local\n")
	path, cleanup, err := writeDirectReaderDaxRemapFile(workPath, data)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != "dax-remap.txt" {
		t.Fatalf("unexpected remap path %q", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("unexpected remap mode %#o", info.Mode().Perm())
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != string(data) {
		t.Fatalf("unexpected remap contents %q err=%v", got, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(workPath, ".dax-remap.txt.tmp.*")); len(matches) != 0 {
		t.Fatalf("remap temp files remain: %#v", matches)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("remap file was not cleaned up: %v", err)
	}
}

func TestDirectReaderCriuImportArgsForceRemapWithExistingDax(t *testing.T) {
	args := directReaderCriuImportArgs("/image", "/work", "/dev/dax-reader", 32, "/work/dax-remap.txt")
	remapIndex := indexDirectReaderArg(args, "--dax-remap-file")
	importIndex := indexDirectReaderArg(args, "--import-existing-dax")
	if remapIndex < 0 || remapIndex+1 >= len(args) || args[remapIndex+1] != "/work/dax-remap.txt" {
		t.Fatalf("missing DAX remap args: %#v", args)
	}
	if importIndex < 0 || remapIndex > importIndex {
		t.Fatalf("remap file must be supplied with import-existing-dax: %#v", args)
	}
}

func TestPrepareDirectReaderPseudoMMV5UsesAndCachesRestoreMap(t *testing.T) {
	originalInvalidate := directDaxInvalidateHook
	directDaxInvalidateHook = func([]byte) error { return nil }
	t.Cleanup(func() { directDaxInvalidateHook = originalInvalidate })

	restoreRoot := t.TempDir()
	imagePath := filepath.Join(restoreRoot, "metadata-bundle", "image")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(restoreRoot, "shared-dax.bin")
	if err := os.WriteFile(device, make([]byte, 48*4096), 0o600); err != nil {
		t.Fatal(err)
	}
	publication := validDirectV5DedupPublication()
	publication.CheckpointPath = imagePath
	remap, digest, pages, err := buildDirectV5RestoreMap(publication, device)
	if err != nil {
		t.Fatal(err)
	}
	plan := directPseudoMMImportPlan{
		checkpointPath:        imagePath,
		publication:           publication,
		daxDevice:             device,
		daxStartPage:          32,
		restoreMap:            remap,
		restoreMapSHA256:      digest,
		restoreMapExtentCount: uint64(len(publication.BaseRestoreMap)),
		restoreMapPageCount:   pages,
	}

	pseudoDevice := filepath.Join(restoreRoot, "pseudo-mm")
	if err := os.WriteFile(pseudoDevice, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPseudoMMPath := directReaderPseudoMMPath
	directReaderPseudoMMPath = pseudoDevice
	t.Cleanup(func() { directReaderPseudoMMPath = originalPseudoMMPath })

	importLog := filepath.Join(restoreRoot, "imports.log")
	remapCapture := filepath.Join(restoreRoot, "remap.capture")
	modeCapture := filepath.Join(restoreRoot, "remap.mode")
	t.Setenv("TRENV_READER_IMPORT_LOG", importLog)
	t.Setenv("TRENV_REMAP_CAPTURE", remapCapture)
	t.Setenv("TRENV_REMAP_MODE", modeCapture)
	fakeCRIU := filepath.Join(restoreRoot, "fake-criu")
	script := "#!/bin/sh\n" +
		"echo import >> \"$TRENV_READER_IMPORT_LOG\"\n" +
		"image=\nremap=\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  if [ \"$1\" = -D ]; then shift; image=$1\n" +
		"  elif [ \"$1\" = --dax-remap-file ]; then shift; remap=$1\n" +
		"  fi\n" +
		"  shift\n" +
		"done\n" +
		"cp \"$remap\" \"$TRENV_REMAP_CAPTURE\"\n" +
		"stat -c %a \"$remap\" > \"$TRENV_REMAP_MODE\"\n" +
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
	state := trenvContainerState{PID: os.Getpid(), CriuBinary: fakeCRIU}
	if err := prepareDirectReaderPseudoMM(context.Background(), plan, state, config); err != nil {
		t.Fatalf("first dedup reader import: %v", err)
	}
	if err := os.Remove(filepath.Join(imagePath, "pseudo_mm_id-1")); err != nil {
		t.Fatal(err)
	}
	if err := prepareDirectReaderPseudoMM(context.Background(), plan, state, config); err != nil {
		t.Fatalf("cached dedup reader import: %v", err)
	}
	if got, err := os.ReadFile(importLog); err != nil || strings.Count(string(got), "import") != 1 {
		t.Fatalf("expected one CRIU import, got %q err=%v", got, err)
	}
	if got, err := os.ReadFile(remapCapture); err != nil || string(got) != string(remap) {
		t.Fatalf("unexpected captured remap %q err=%v", got, err)
	}
	if got, err := os.ReadFile(modeCapture); err != nil || strings.TrimSpace(string(got)) != "600" {
		t.Fatalf("unexpected remap mode %q err=%v", got, err)
	}
	if matches, _ := filepath.Glob(filepath.Join(config.PseudoMMMaterializationRoot, "*", "*", "work", "dax-remap.txt")); len(matches) != 0 {
		t.Fatalf("persistent remap files remain: %#v", matches)
	}
	manifestMatches, err := filepath.Glob(filepath.Join(config.PseudoMMMaterializationRoot, "*", "*", "manifest.json"))
	if err != nil || len(manifestMatches) != 1 {
		t.Fatalf("unexpected materialization manifests %#v err=%v", manifestMatches, err)
	}
	data, err := os.ReadFile(manifestMatches[0])
	if err != nil {
		t.Fatal(err)
	}
	var manifest directReaderPseudoMMManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.RestoreMapSHA256 != digest ||
		manifest.RestoreMapExtentCount != uint64(len(publication.BaseRestoreMap)) ||
		manifest.RestoreMapPageCount != pages ||
		manifest.RestoreMapDevice != device {
		t.Fatalf("restore map cache identity is incomplete: %#v", manifest)
	}
}

func TestRunDirectReaderCriuImportCleansRemapAfterFailure(t *testing.T) {
	root := t.TempDir()
	imagePath := filepath.Join(root, "image")
	workPath := filepath.Join(root, "work")
	if err := os.MkdirAll(imagePath, 0o755); err != nil {
		t.Fatal(err)
	}
	pseudoDevice := filepath.Join(root, "pseudo-mm")
	if err := os.WriteFile(pseudoDevice, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	originalPseudoMMPath := directReaderPseudoMMPath
	directReaderPseudoMMPath = pseudoDevice
	t.Cleanup(func() { directReaderPseudoMMPath = originalPseudoMMPath })
	fakeCRIU := filepath.Join(root, "fake-criu")
	if err := os.WriteFile(fakeCRIU, []byte("#!/bin/sh\nexit 9\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	plan := directPseudoMMImportPlan{
		checkpointPath: imagePath,
		daxDevice:      "/dev/dax-reader-local",
		daxStartPage:   32,
		restoreMap:     []byte("0x400000 1 32 /dev/dax-reader-local\n"),
	}
	err := runDirectReaderCriuImport(
		context.Background(),
		workPath,
		trenvContainerState{PID: os.Getpid(), CriuBinary: fakeCRIU},
		plan)
	if err == nil {
		t.Fatal("expected fake CRIU failure")
	}
	if code := dedupRestoreErrorCode(err); code != dedupRestoreCodeRemapFile {
		t.Fatalf("unexpected error code %q for %v", code, err)
	}
	if _, err := os.Stat(filepath.Join(workPath, "dax-remap.txt")); !os.IsNotExist(err) {
		t.Fatalf("remap file remains after failed CRIU import: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(workPath, ".dax-remap.txt.tmp.*")); len(matches) != 0 {
		t.Fatalf("remap temp files remain after failed import: %#v", matches)
	}
}

func indexDirectReaderArg(args []string, value string) int {
	for index, arg := range args {
		if arg == value {
			return index
		}
	}
	return -1
}
