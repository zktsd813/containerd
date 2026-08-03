package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const vnextReaderInvocationWorkspacePrefix = "vnext-reader-restore-"

type vnextReaderInvocationWorkspace struct {
	path string
}

// createVNextReaderInvocationWorkspace creates one private directory for one
// authorized invocation. The target contributes only a SHA-256 name prefix;
// neither that name nor the random suffix is an authorization credential.
func createVNextReaderInvocationWorkspace(
	root string,
	target vnextReaderExecutionTarget,
) (vnextReaderInvocationWorkspace, error) {
	if err := validateVNextReaderIdentity(
		"VNext reader execution target", target.TargetContainerID()); err != nil {
		return vnextReaderInvocationWorkspace{}, err
	}
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return vnextReaderInvocationWorkspace{}, errors.New(
			"VNext Reader invocation workspace root must be absolute and clean")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return vnextReaderInvocationWorkspace{}, fmt.Errorf(
			"create VNext Reader invocation workspace root: %w", err)
	}
	digest := sha256.Sum256([]byte(target.TargetContainerID()))
	prefix := vnextReaderInvocationWorkspacePrefix +
		hex.EncodeToString(digest[:]) + "-"
	path, err := os.MkdirTemp(root, prefix)
	if err != nil {
		return vnextReaderInvocationWorkspace{}, fmt.Errorf(
			"create private VNext Reader invocation workspace: %w", err)
	}
	return vnextReaderInvocationWorkspace{path: path}, nil
}

func (workspace vnextReaderInvocationWorkspace) cleanup() error {
	if workspace.path == "" {
		return nil
	}
	if err := os.Remove(workspace.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove VNext Reader invocation workspace: %w", err)
	}
	return nil
}

type vnextReaderInvocationCleanupError struct {
	primary error
	cleanup error
}

func (failure *vnextReaderInvocationCleanupError) Error() string {
	return fmt.Sprintf("%v; %v", failure.primary, failure.cleanup)
}

func (failure *vnextReaderInvocationCleanupError) Is(target error) bool {
	return errors.Is(failure.primary, target) || errors.Is(failure.cleanup, target)
}

func appendVNextReaderInvocationCleanupError(
	primary error,
	cleanup error,
) error {
	if cleanup == nil {
		return primary
	}
	if primary == nil {
		return cleanup
	}
	return &vnextReaderInvocationCleanupError{
		primary: primary,
		cleanup: cleanup,
	}
}
