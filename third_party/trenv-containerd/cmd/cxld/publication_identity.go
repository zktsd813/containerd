package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

func validateSwitchPublicationIdentity(request switchRequest) error {
	identity := request.PublicationIdentity
	if identity == nil {
		return nil
	}
	if identity.ArtifactTransport != "dax-manifest" || identity.ManifestSchema != directDaxManifestSchema {
		return errors.New("switch publication identity does not select the shared-DAX v5 manifest contract")
	}
	if identity.PublicationID == "" || identity.ArtifactID == "" || identity.Generation == 0 || identity.WriterID == "" || identity.WriterEpoch == 0 {
		return errors.New("switch publication identity is incomplete")
	}
	checkpointPath := filepath.Clean(strings.TrimSpace(request.CheckpointPath))
	if checkpointPath == "." || filepath.Base(checkpointPath) != "image" {
		return errors.New("switch publication identity requires a reader-local image path")
	}
	restoreRoot := filepath.Dir(filepath.Dir(checkpointPath))
	publicationPath := filepath.Join(restoreRoot, "publication.reader"+trenvpub.Extension)
	publication, err := readPublicationRecord(publicationPath)
	if err != nil {
		return fmt.Errorf("read switch publication identity: %w", err)
	}
	if err := validateDaxPublication(publication); err != nil {
		return fmt.Errorf("validate switch publication identity: %w", err)
	}
	if filepath.Clean(publication.CheckpointPath) != checkpointPath {
		return errors.New("switch checkpoint path does not match reader publication")
	}
	if identity.PublicationID != publication.CheckpointID ||
		identity.ArtifactID != publication.ArtifactID ||
		identity.Generation != publication.Generation ||
		identity.WriterID != publication.WriterID ||
		identity.WriterEpoch != publication.WriterEpoch {
		return errors.New("switch publication identity does not match reader publication")
	}
	return nil
}
