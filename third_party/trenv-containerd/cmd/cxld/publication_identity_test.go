package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSwitchPublicationIdentityMatchesReaderManifest(t *testing.T) {
	installDirectDaxProjectionTestHook(t)
	fixture := newDirectDaxArtifactFixture(t)
	root, err := materializeDaxArtifact(fixture.publication, "reader-identity", daemonConfig{
		WorkingDirectory: t.TempDir(),
		ReaderDaxShards: []daxShardConfig{{
			ShardID:   fixture.publication.PageExtent.ShardID,
			DaxDevice: fixture.device,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = removeDirectProjectedTree(root) })
	request := switchRequest{
		CheckpointPath: filepath.Join(root, "metadata-bundle", "image"),
		PublicationIdentity: &publicationIdentityRequest{
			PublicationID:     fixture.publication.CheckpointID,
			ArtifactID:        fixture.publication.ArtifactID,
			Generation:        fixture.publication.Generation,
			WriterID:          fixture.publication.WriterID,
			WriterEpoch:       fixture.publication.WriterEpoch,
			ArtifactTransport: "dax-manifest",
			ManifestSchema:    directDaxManifestSchema,
		},
	}
	if err := validateSwitchPublicationIdentity(request); err != nil {
		t.Fatalf("validate matching identity: %v", err)
	}
	request.PublicationIdentity.Generation++
	if err := validateSwitchPublicationIdentity(request); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected stale generation rejection, got %v", err)
	}
}

func TestResolveMetadataRejectsTransportMismatch(t *testing.T) {
	_, err := resolveMetadata(context.Background(), metadataResolveRequest{
		Fingerprint:       "fingerprint",
		ReaderContainer:   "reader-a",
		ArtifactTransport: "legacy-tar",
	}, daemonConfig{ArtifactTransport: "dax-manifest"})
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected transport mismatch, got %v", err)
	}
}
