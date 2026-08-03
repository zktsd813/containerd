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
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	"golang.org/x/sys/unix"
)

func TestBuildDirectArtifactPlanIsDeterministic(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "metadata-bundle")
	action := filepath.Join(root, "action-root")
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "image", "inventory.img"), "inventory", 0o644)
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "placement.json"), "{}", 0o644)
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "bundle.json"), "{}", 0o644)
	writeDirectArtifactTestFile(t, filepath.Join(action, "index.js"), "module.exports = {}", 0o644)
	if err := os.Symlink("index.js", filepath.Join(action, "main.js")); err != nil {
		t.Fatal(err)
	}
	req := checkpointRequest{
		MetadataBundlePath: bundle,
		Publication: &checkpointPublicationRequest{
			CheckpointActionExportRoot: action,
		},
	}

	first, firstBytes, err := buildDirectArtifactPlan(req, 4096)
	if err != nil {
		t.Fatalf("build first artifact plan: %v", err)
	}
	second, secondBytes, err := buildDirectArtifactPlan(req, 4096)
	if err != nil {
		t.Fatalf("build second artifact plan: %v", err)
	}
	if !reflect.DeepEqual(first, second) || firstBytes != secondBytes {
		t.Fatalf("artifact plan is not deterministic:\nfirst=%#v\nsecond=%#v", first, second)
	}
	previous := ""
	for _, entry := range first {
		if entry.File.Path < previous {
			t.Fatalf("artifact paths are not sorted: %q before %q", previous, entry.File.Path)
		}
		previous = entry.File.Path
		if entry.File.Type == "regular" && entry.File.Offset%4096 != 0 {
			t.Fatalf("file %q offset %d is not page aligned", entry.File.Path, entry.File.Offset)
		}
	}
}

func TestBuildDirectArtifactPlanPreservesAbsoluteSymlink(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "metadata-bundle")
	action := filepath.Join(root, "action-root")
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "image", "inventory.img"), "inventory", 0o644)
	linkPath := filepath.Join(action, "home", "app", "virtualenv", "LICENSE.txt")
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	const linkTarget = "/usr/lib/python3.5/LICENSE.txt"
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}

	entries, _, err := buildDirectArtifactPlan(checkpointRequest{
		MetadataBundlePath: bundle,
		Publication: &checkpointPublicationRequest{
			CheckpointActionExportRoot: action,
		},
	}, 4096)
	if err != nil {
		t.Fatalf("build artifact plan with absolute symlink: %v", err)
	}
	for _, entry := range entries {
		if entry.File.Path == "action-root/home/app/virtualenv/LICENSE.txt" {
			if entry.File.Type != "symlink" || entry.File.LinkTarget != linkTarget {
				t.Fatalf("unexpected symlink entry: %#v", entry.File)
			}
			return
		}
	}
	t.Fatal("absolute symlink was not included in artifact plan")
}

func TestValidateDirectArtifactSymlinkRejectsInvalidTarget(t *testing.T) {
	for _, target := range []string{"", "bad\x00target"} {
		if err := validateDirectArtifactSymlink("action-root/link", target); err == nil {
			t.Fatalf("expected target %q to be rejected", target)
		}
	}
	for _, target := range []string{"/usr/lib/python3.5/LICENSE.txt", "../../base-runtime-file"} {
		if err := validateDirectArtifactSymlink("action-root/link", target); err != nil {
			t.Fatalf("expected target %q to be preserved: %v", target, err)
		}
	}
}

func TestPersistDirectArtifactPlanFailsClosedOnFlushError(t *testing.T) {
	root := t.TempDir()
	bundle := filepath.Join(root, "metadata-bundle")
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "image", "inventory.img"), "inventory", 0o644)
	entries, payloadBytes, err := buildDirectArtifactPlan(checkpointRequest{MetadataBundlePath: bundle}, 4096)
	if err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(root, "shared-dax.bin")
	if err := os.WriteFile(device, make([]byte, 16*4096), 0o600); err != nil {
		t.Fatal(err)
	}
	original := directDaxFlushHook
	directDaxFlushHook = func(*os.File, []byte) error { return errors.New("flush unavailable") }
	t.Cleanup(func() { directDaxFlushHook = original })

	_, _, err = persistDirectArtifactPlan(directDaxPlacement{
		ShardID:        "shared-dax",
		DaxDevice:      device,
		DaxLengthPages: 16,
		PageSize:       4096,
	}, entries, payloadBytes)
	if err == nil || !strings.Contains(err.Error(), "flush") {
		t.Fatalf("expected flush failure to reject publication, got %v", err)
	}
}

func TestIgnorableDirectDaxSyncErrorIsLimitedToCharacterDevices(t *testing.T) {
	for _, err := range []error{unix.EINVAL, unix.ENOTSUP, unix.ENOTTY} {
		if !ignorableDirectDaxSyncError(os.ModeDevice|os.ModeCharDevice, err) {
			t.Fatalf("expected character-device sync error %v to be ignored", err)
		}
		if ignorableDirectDaxSyncError(0, err) {
			t.Fatalf("regular-file sync error %v must not be ignored", err)
		}
	}
	if ignorableDirectDaxSyncError(os.ModeDevice|os.ModeCharDevice, unix.EIO) {
		t.Fatal("character-device I/O failure must not be ignored")
	}
}

func TestWriteDirectDaxArtifactUsesNonOverlappingTypedExtent(t *testing.T) {
	root := t.TempDir()
	device := filepath.Join(root, "shared-dax.bin")
	if err := os.WriteFile(device, make([]byte, 32*4096), 0o600); err != nil {
		t.Fatal(err)
	}
	shard := daxShardConfig{ShardID: "shared-dax", DaxDevice: device}
	writerRoot := filepath.Join(root, "writers")
	pagePlacement, err := resolveDirectDaxPlacement(writerRoot, "writer-a", "checkpoint-a", "image", []daxShardConfig{shard}, 4096, directDaxPlacementPolicyFirstFit)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "metadata-bundle")
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "image", "inventory.img"), "inventory", 0o644)
	artifactExtent, _, _, err := writeDirectDaxArtifact(checkpointRequest{MetadataBundlePath: bundle}, pagePlacement, daemonConfig{
		DaxShards:          []daxShardConfig{shard},
		DaxPlacementPolicy: directDaxPlacementPolicyFirstFit,
	})
	if err != nil {
		t.Fatal(err)
	}
	pageEnd := (pagePlacement.DaxStartPage + pagePlacement.DaxLengthPages) * pagePlacement.PageSize
	if artifactExtent.OffsetBytes < pageEnd {
		t.Fatalf("artifact extent overlaps page extent: pageEnd=%d artifact=%#v", pageEnd, artifactExtent)
	}
	stateDir := directWriterShardAllocatorDir(writerRoot, "writer-a", "shared-dax")
	pageRecord, err := loadDirectWriterShardExtent(directWriterShardExtentPath(stateDir, "checkpoint-a"))
	if err != nil {
		t.Fatal(err)
	}
	artifactRecord, err := loadDirectWriterShardExtent(directWriterShardExtentPath(stateDir, "checkpoint-a"+directArtifactAllocationID))
	if err != nil {
		t.Fatal(err)
	}
	if pageRecord.ExtentType != "page" || artifactRecord.ExtentType != "artifact" {
		t.Fatalf("unexpected typed extents: page=%#v artifact=%#v", pageRecord, artifactRecord)
	}
}

func TestWriteDirectDaxArtifactUsesDedicatedArtifactShard(t *testing.T) {
	root := t.TempDir()
	pageDevice := filepath.Join(root, "page-dax.bin")
	artifactDevice := filepath.Join(root, "artifact-dax.bin")
	for _, device := range []string{pageDevice, artifactDevice} {
		if err := os.WriteFile(device, make([]byte, 32*4096), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pagePlacement, err := resolveDirectDaxPlacement(filepath.Join(root, "writers"), "writer-a", "checkpoint-a", "image", []daxShardConfig{{ShardID: "page-0", DaxDevice: pageDevice}}, 4096, directDaxPlacementPolicyFirstFit)
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(root, "metadata-bundle")
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "image", "inventory.img"), "inventory", 0o644)
	extent, _, placement, err := writeDirectDaxArtifact(checkpointRequest{MetadataBundlePath: bundle}, pagePlacement, daemonConfig{
		ArtifactDaxShards:  []daxShardConfig{{ShardID: "artifact-0", DaxDevice: artifactDevice}},
		DaxPlacementPolicy: directDaxPlacementPolicyFirstFit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if extent.ShardID != "artifact-0" || placement.DaxDevice != artifactDevice {
		t.Fatalf("artifact placement=%#v extent=%#v", placement, extent)
	}
}

func TestMaterializeDaxArtifactUsesStableShardManifest(t *testing.T) {
	installDirectDaxProjectionTestHook(t)
	fixture := newDirectDaxArtifactFixture(t)
	readerWork := t.TempDir()
	root, err := materializeDaxArtifact(fixture.publication, "reader-a", daemonConfig{
		WorkingDirectory: readerWork,
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.ArtifactExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err != nil {
		t.Fatalf("materialize DAX artifact: %v", err)
	}
	t.Cleanup(func() { _ = makeDirectProjectedTreeRemovable(root) })
	data, err := os.ReadFile(filepath.Join(root, "metadata-bundle", "image", "inventory.img"))
	if err != nil {
		t.Fatalf("read projected inventory: %v", err)
	}
	if string(data) != "inventory" {
		t.Fatalf("unexpected projected inventory %q", data)
	}
	info, err := os.Stat(filepath.Join(root, "metadata-bundle", "image", "inventory.img"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Fatalf("projected artifact file is writable: %v", info.Mode())
	}
	if got, err := os.Readlink(filepath.Join(root, "action-root", "main.js")); err != nil || got != "index.js" {
		t.Fatalf("unexpected projected symlink target %q err=%v", got, err)
	}
	if _, err := readPublicationRecord(filepath.Join(root, "publication.reader"+trenvpub.Extension)); err != nil {
		t.Fatalf("read reader publication: %v", err)
	}
}

func TestResolveMetadataV5DoesNotFetchArtifactTar(t *testing.T) {
	installDirectDaxProjectionTestHook(t)
	fixture := newDirectDaxArtifactFixture(t)
	requests := make(chan string, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests <- request.URL.Path
		if request.URL.Path == "/v1/dedup-outcomes" {
			_ = json.NewEncoder(writer).Encode([]dedupRunStatus{})
			return
		}
		if request.URL.Path != "/v1/publications" {
			http.Error(writer, "unexpected payload request", http.StatusGone)
			return
		}
		_ = json.NewEncoder(writer).Encode([]metadataPublicationRecord{compactNetworkPublication(fixture.publication)})
	}))
	defer server.Close()

	response, err := resolveMetadata(context.Background(), metadataResolveRequest{
		Fingerprint:     fixture.publication.Fingerprint,
		ReaderContainer: "reader-network",
	}, daemonConfig{
		WorkingDirectory: t.TempDir(),
		MetadataPeers:    []string{server.URL},
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.ArtifactExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err != nil {
		t.Fatalf("resolve v5 metadata: %v", err)
	}
	if response.Source != "publication-reader-dax-manifest" || !response.Found {
		t.Fatalf("unexpected resolve response: %#v", response)
	}
	if response.ArtifactTransport != "dax-manifest" || response.PublicationID != fixture.publication.CheckpointID ||
		response.ArtifactID != fixture.publication.ArtifactID || response.ManifestSchema != directDaxManifestSchema ||
		response.Generation != fixture.publication.Generation ||
		response.WriterID != fixture.publication.WriterID || response.WriterEpoch != fixture.publication.WriterEpoch {
		t.Fatalf("incomplete v5 resolve identity: %#v", response)
	}
	t.Cleanup(func() { _ = makeDirectProjectedTreeRemovable(filepath.Dir(filepath.Dir(response.CheckpointPath))) })
	close(requests)
	for requestPath := range requests {
		if strings.HasPrefix(requestPath, "/v1/artifacts/") {
			t.Fatalf("v5 resolve fetched network artifact payload: %s", requestPath)
		}
	}
}

func TestCompactNetworkPublicationOmitsWriterLocalPaths(t *testing.T) {
	fixture := newDirectDaxArtifactFixture(t)
	publication := fixture.publication
	publication.CheckpointPath = "/writer/checkpoint/image"
	publication.MetadataBundlePath = "/writer/checkpoint/metadata-bundle"
	publication.PlacementPath = "/writer/checkpoint/placement.json"
	publication.CheckpointActionExportRoot = "/writer/checkpoint/action-root"
	publication.DaxDevice = "/dev/dax-writer.0"
	publication.Shards = []trenvpub.Shard{{ShardID: "shared-dax-a", DaxDevice: "/dev/dax-writer.0"}}
	data, err := json.Marshal(compactNetworkPublication(publication))
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range []string{"/writer/checkpoint", "/dev/dax-writer.0"} {
		if strings.Contains(string(data), local) {
			t.Fatalf("compact manifest leaked writer-local value %q: %s", local, data)
		}
	}
	if !strings.Contains(string(data), "shared-dax-a") || !strings.Contains(string(data), "offset_bytes") {
		t.Fatalf("compact manifest lost stable DAX placement: %s", data)
	}
}

func TestValidateDaxPublicationRejectsOverlapAndTraversal(t *testing.T) {
	fixture := newDirectDaxArtifactFixture(t)
	zeroLength := fixture.publication
	zeroLength.Files = append(append([]trenvpub.ArtifactFile(nil), zeroLength.Files...), trenvpub.ArtifactFile{
		Path:   "zz-zero-length",
		Type:   "regular",
		Mode:   0o444,
		Offset: zeroLength.Files[1].Offset,
	})
	if err := validateDaxPublication(zeroLength); err != nil {
		t.Fatalf("zero-length artifact file must not overlap: %v", err)
	}
	overlap := fixture.publication
	overlap.ArtifactExtent.OffsetBytes = overlap.PageExtent.OffsetBytes
	if err := validateDaxPublication(overlap); err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("expected overlap rejection, got %v", err)
	}
	traversal := fixture.publication
	traversal.Files = append([]trenvpub.ArtifactFile(nil), traversal.Files...)
	traversal.Files[0].Path = "../escape"
	if err := validateDaxPublication(traversal); err == nil || !strings.Contains(err.Error(), "unsafe artifact path") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
	unfenced := fixture.publication
	unfenced.WriterEpoch = 0
	if err := validateDaxPublication(unfenced); err == nil || !strings.Contains(err.Error(), "writer-fenced") {
		t.Fatalf("expected writer fence rejection, got %v", err)
	}
}

func TestMaterializeDaxArtifactDoesNotScanPayload(t *testing.T) {
	installDirectDaxProjectionTestHook(t)
	fixture := newDirectDaxArtifactFixture(t)
	file, err := os.OpenFile(fixture.device, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte("X"), fixture.publication.ArtifactExtent.OffsetBytes); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := materializeDaxArtifact(fixture.publication, "reader-no-scan", daemonConfig{
		WorkingDirectory: t.TempDir(),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.ArtifactExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err != nil {
		t.Fatalf("checksum-free materialization rejected structurally valid payload: %v", err)
	}
	t.Cleanup(func() { _ = makeDirectProjectedTreeRemovable(root) })
}

func TestMaterializeDaxArtifactInvalidatesBothExtents(t *testing.T) {
	installDirectDaxProjectionTestHook(t)
	fixture := newDirectDaxArtifactFixture(t)

	original := directDaxInvalidateHook
	invalidateCalls := 0
	directDaxInvalidateHook = func([]byte) error {
		invalidateCalls++
		return nil
	}
	t.Cleanup(func() { directDaxInvalidateHook = original })

	root, err := materializeDaxArtifact(fixture.publication, "reader-invalidation", daemonConfig{
		WorkingDirectory: t.TempDir(),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.ArtifactExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err != nil {
		t.Fatalf("materialize checksum-free publication: %v", err)
	}
	t.Cleanup(func() { _ = makeDirectProjectedTreeRemovable(root) })
	if invalidateCalls != 2 {
		t.Fatalf("DAX invalidation calls=%d want=2", invalidateCalls)
	}
}

func TestValidateReaderPageExtentInvalidatesWithoutScanning(t *testing.T) {
	fixture := newDirectDaxArtifactFixture(t)
	publication := fixture.publication
	config := daemonConfig{
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   publication.PageExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	}

	original := directDaxInvalidateHook
	invalidateCalls := 0
	directDaxInvalidateHook = func([]byte) error {
		invalidateCalls++
		return nil
	}
	t.Cleanup(func() { directDaxInvalidateHook = original })

	if err := validateReaderPageExtent(publication, config); err != nil {
		t.Fatalf("checksum-free page validation rejected structurally valid extent: %v", err)
	}
	if invalidateCalls != 1 {
		t.Fatalf("DAX invalidation calls=%d want=1", invalidateCalls)
	}
}

func TestMaterializeDaxArtifactFailsClosedOnInvalidateError(t *testing.T) {
	fixture := newDirectDaxArtifactFixture(t)
	original := directDaxInvalidateHook
	directDaxInvalidateHook = func([]byte) error { return errors.New("invalidate unavailable") }
	t.Cleanup(func() { directDaxInvalidateHook = original })

	_, err := materializeDaxArtifact(fixture.publication, "reader-invalidate-failure", daemonConfig{
		WorkingDirectory: t.TempDir(),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.ArtifactExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalidate") {
		t.Fatalf("expected invalidate failure to reject restore, got %v", err)
	}
}

func TestMaterializeDaxArtifactFailsClosedOnInvalidateHook(t *testing.T) {
	fixture := newDirectDaxArtifactFixture(t)
	original := directDaxInvalidateHook
	directDaxInvalidateHook = func([]byte) error { return os.ErrInvalid }
	t.Cleanup(func() { directDaxInvalidateHook = original })
	_, err := materializeDaxArtifact(fixture.publication, "reader-invalidate", daemonConfig{
		WorkingDirectory: t.TempDir(),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.ArtifactExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "invalidate") {
		t.Fatalf("expected invalidate hook failure to fail closed, got %v", err)
	}
}

func TestResolveReaderDaxDeviceRequiresStableMapping(t *testing.T) {
	_, err := resolveReaderDaxDevice(trenvpub.StorageExtent{ShardID: "shared-artifact"}, daemonConfig{
		DaxDevice: "/dev/dax-writer-local",
		ShardID:   "different-shard",
	})
	if err == nil {
		t.Fatal("expected missing stable reader shard mapping to fail")
	}
}

func TestResolveReaderDaxDeviceUsesDedicatedArtifactMapping(t *testing.T) {
	device, err := resolveReaderDaxDevice(trenvpub.StorageExtent{Role: directArtifactExtentRole, ShardID: "artifact-0"}, daemonConfig{
		ReaderDaxShards:         []daxShardConfig{{ShardID: "page-0", DaxDevice: "/dev/dax0.0"}},
		ReaderArtifactDaxShards: []daxShardConfig{{ShardID: "artifact-0", DaxDevice: "/dev/dax1.0"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if device != "/dev/dax1.0" {
		t.Fatalf("artifact device=%q want=/dev/dax1.0", device)
	}
}

type directDaxArtifactFixture struct {
	device      string
	publication metadataPublicationRecord
}

func installDirectDaxProjectionTestHook(t *testing.T) {
	t.Helper()
	original := directDaxProjectionMountHook
	directDaxProjectionMountHook = func(source *directDaxArtifactSource, publication metadataPublicationRecord, restoreRoot string) (*directDaxProjection, error) {
		if err := projectDirectDaxArtifactSource(source, publication, restoreRoot); err != nil {
			return nil, err
		}
		return &directDaxProjection{restoreRoot: restoreRoot, source: source}, nil
	}
	t.Cleanup(func() { directDaxProjectionMountHook = original })
}

func TestRemoveDirectProjectedTreesForContainer(t *testing.T) {
	config := daemonConfig{WorkingDirectory: t.TempDir()}
	containerID := "reader/container"
	containerRoot := filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(containerID))
	projectionRoots := []string{
		filepath.Join(containerRoot, "checkpoint-a"),
		filepath.Join(containerRoot, "checkpoint-b"),
	}

	directDaxProjectionMu.Lock()
	for _, root := range projectionRoots {
		projection := &directDaxProjection{
			restoreRoot: root,
			lowerRoot:   root + ".dax-lower",
			stateRoot:   root + ".dax-state",
		}
		for _, directory := range []string{projection.restoreRoot, projection.lowerRoot, projection.stateRoot} {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				directDaxProjectionMu.Unlock()
				t.Fatal(err)
			}
		}
		directDaxProjections[root] = projection
	}
	directDaxProjectionMu.Unlock()

	if err := removeDirectProjectedTreesForContainer(containerID, config); err != nil {
		t.Fatal(err)
	}
	directDaxProjectionMu.Lock()
	defer directDaxProjectionMu.Unlock()
	for _, root := range projectionRoots {
		if directDaxProjections[root] != nil {
			t.Fatalf("projection %s was not removed", root)
		}
	}
	if _, err := os.Stat(containerRoot); !os.IsNotExist(err) {
		t.Fatalf("container projection root still exists: %v", err)
	}
}

func TestRemoveDirectProjectedTreesForContainerRecoversUntrackedTree(t *testing.T) {
	config := daemonConfig{WorkingDirectory: t.TempDir()}
	containerID := "reader-container"
	root := filepath.Join(config.WorkingDirectory, "restore", containerID, "checkpoint-a")
	for _, directory := range []string{root, root + ".dax-lower", root + ".dax-state"} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if err := removeDirectProjectedTreesForContainer(containerID, config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(root)); !os.IsNotExist(err) {
		t.Fatalf("untracked projection tree still exists: %v", err)
	}
}

func TestRemoveDirectProjectedContainersByPrefixRecoversStateLessTree(t *testing.T) {
	config := daemonConfig{WorkingDirectory: t.TempDir()}
	matchingRoot := filepath.Join(config.WorkingDirectory, "restore", "wsk-reader-a", "checkpoint-a")
	otherRoot := filepath.Join(config.WorkingDirectory, "restore", "other-reader", "checkpoint-b")
	for _, root := range []string{matchingRoot, otherRoot} {
		for _, directory := range []string{root, root + ".dax-lower", root + ".dax-state"} {
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := removeDirectProjectedContainersByPrefix("wsk", config); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(matchingRoot)); !os.IsNotExist(err) {
		t.Fatalf("matching stateless projection tree still exists: %v", err)
	}
	if _, err := os.Stat(otherRoot); err != nil {
		t.Fatalf("nonmatching projection tree was removed: %v", err)
	}
}

func newDirectDaxArtifactFixture(t *testing.T) directDaxArtifactFixture {
	t.Helper()
	root := t.TempDir()
	bundle := filepath.Join(root, "metadata-bundle")
	action := filepath.Join(root, "action-root")
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "image", "inventory.img"), "inventory", 0o644)
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "placement.json"), "{}", 0o644)
	writeDirectArtifactTestFile(t, filepath.Join(bundle, "bundle.json"), "{}", 0o644)
	writeDirectArtifactTestFile(t, filepath.Join(action, "index.js"), "module.exports = {}", 0o644)
	if err := os.Symlink("index.js", filepath.Join(action, "main.js")); err != nil {
		t.Fatal(err)
	}
	req := checkpointRequest{
		MetadataBundlePath: bundle,
		Publication: &checkpointPublicationRequest{
			CheckpointActionExportRoot: action,
		},
	}
	entries, payloadBytes, err := buildDirectArtifactPlan(req, 4096)
	if err != nil {
		t.Fatal(err)
	}
	device := filepath.Join(root, "shared-dax.bin")
	if err := os.WriteFile(device, make([]byte, 128*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	pageData := []byte(strings.Repeat("p", 4096))
	deviceFile, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deviceFile.WriteAt(pageData, 0); err != nil {
		deviceFile.Close()
		t.Fatal(err)
	}
	if err := deviceFile.Close(); err != nil {
		t.Fatal(err)
	}
	artifactPlacement := directDaxPlacement{
		CheckpointID:   "ckpt-v5.artifact",
		WriterID:       "writer-a",
		ShardID:        "shared-dax-a",
		DaxDevice:      device,
		DaxStartPage:   4,
		DaxLengthPages: 16,
		PageSize:       4096,
		Layout:         directArtifactExtentLayout,
	}
	artifactExtent, files, err := persistDirectArtifactPlan(artifactPlacement, entries, payloadBytes)
	if err != nil {
		t.Fatalf("persist test DAX artifact: %v", err)
	}
	publication := metadataPublicationRecord{
		Version:           int(trenvpub.Version),
		ArtifactID:        "ckpt-v5",
		CheckpointID:      "ckpt-v5",
		ManifestSchema:    trenvpub.ManifestSchema,
		DedupApplySchema:  trenvpub.DedupApplySchema,
		Generation:        1,
		WriterEpoch:       1,
		WriterID:          "writer-a",
		State:             "COMMITTED",
		CheckpointPhase:   "cold",
		Fingerprint:       "fp-v5",
		SnapshotStartMode: "restore",
		RuntimeKind:       "nodejs:20_hybrid",
		RuntimeFamily:     "nodejs",
		PageExtent: trenvpub.StorageExtent{
			Role:           directPageExtentRole,
			DeviceIdentity: "shared-dax-a",
			ShardID:        "shared-dax-a",
			OffsetBytes:    0,
			LengthBytes:    4096,
			PayloadBytes:   4096,
			PageSize:       4096,
			Layout:         directDaxPlacementLayoutContiguous,
		},
		ArtifactExtent: artifactExtent,
		Files:          files,
		Shards: []trenvpub.Shard{{
			WriterID:       "writer-a",
			ShardID:        "shared-dax-a",
			DaxDevice:      device,
			DaxStartPage:   0,
			DaxLengthPages: 1,
			PageCount:      1,
			PageSize:       4096,
			Layout:         directDaxPlacementLayoutContiguous,
		}},
		CreatedAt: time.Now().UTC(),
	}
	return directDaxArtifactFixture{device: device, publication: publication}
}

func writeDirectArtifactTestFile(t *testing.T, path, contents string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), mode); err != nil {
		t.Fatal(err)
	}
}
