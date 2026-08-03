package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type vnextReaderWorkspaceTestContextKey struct{}

type vnextReaderWorkspaceTestInvocation struct {
	id   string
	path string
}

type vnextReaderWorkspaceTestResult struct {
	id  string
	err error
}

func vnextReaderWorkspaceTestVerified(
	fixture *vnextReaderTestFixture,
) vnextReaderVerifiedPublication {
	return vnextReaderVerifiedPublication{
		Publication: fixture.publication,
		ExactBytes:  append([]byte(nil), fixture.storage.ExactBytes...),
	}
}

func TestVNextReaderCRIUWorkspaceIsolatesConcurrentSameTargetInvocations(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	root := filepath.Join(t.TempDir(), "reader-workspaces")
	target := vnextReaderExecutionTarget{
		targetContainerID: "same-target/../../must-not-appear",
	}
	verified := vnextReaderWorkspaceTestVerified(fixture)
	releases := map[string]chan struct{}{
		"first":  make(chan struct{}),
		"second": make(chan struct{}),
	}
	defer func() {
		for _, release := range releases {
			select {
			case <-release:
			default:
				close(release)
			}
		}
	}()
	invocations := make(chan vnextReaderWorkspaceTestInvocation, 2)
	results := make(chan vnextReaderWorkspaceTestResult, 2)
	runner := vnextReaderCRIURemapRunner{
		WorkDirectory: root,
		Invoke: func(
			ctx context.Context,
			gotTarget vnextReaderExecutionTarget,
			path string,
			gotVerified vnextReaderVerifiedPublication,
		) error {
			id, _ := ctx.Value(vnextReaderWorkspaceTestContextKey{}).(string)
			if id == "" || gotTarget != target ||
				!bytes.Equal(gotVerified.ExactBytes, verified.ExactBytes) {
				return errors.New("concurrent invocation lost its exact handoff")
			}
			if _, err := os.Stat(path); err != nil {
				return err
			}
			invocations <- vnextReaderWorkspaceTestInvocation{id: id, path: path}
			<-releases[id]
			return nil
		},
	}
	for _, id := range []string{"first", "second"} {
		id := id
		go func() {
			ctx := context.WithValue(
				context.Background(), vnextReaderWorkspaceTestContextKey{}, id)
			results <- vnextReaderWorkspaceTestResult{
				id: id,
				err: runner.RunAuthorizedVNextPublication(
					ctx, target, fixture.directory, verified),
			}
		}()
	}

	seen := make(map[string]string, 2)
	for len(seen) < 2 {
		select {
		case invocation := <-invocations:
			seen[invocation.id] = invocation.path
		case result := <-results:
			t.Fatalf("invocation %q returned before both entered: %v",
				result.id, result.err)
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent invocations did not both reach Invoke")
		}
	}
	if seen["first"] == seen["second"] ||
		filepath.Dir(seen["first"]) == filepath.Dir(seen["second"]) {
		t.Fatalf("same-target invocations shared remap/workspace: %#v", seen)
	}
	digest := sha256.Sum256([]byte(target.TargetContainerID()))
	wantPrefix := vnextReaderInvocationWorkspacePrefix +
		hex.EncodeToString(digest[:]) + "-"
	for id, path := range seen {
		workspace := filepath.Dir(path)
		if filepath.Dir(workspace) != root ||
			!strings.HasPrefix(filepath.Base(workspace), wantPrefix) ||
			strings.Contains(filepath.Base(workspace), "same-target") ||
			filepath.Base(path) != vnextCRIURemapFilename {
			t.Fatalf("invocation %q has unsafe workspace/remap path %q", id, path)
		}
		workspaceInfo, err := os.Stat(workspace)
		if err != nil || workspaceInfo.Mode().Perm() != 0o700 {
			t.Fatalf("invocation %q workspace mode=%v err=%v",
				id, workspaceInfo, err)
		}
		remapInfo, err := os.Stat(path)
		if err != nil || remapInfo.Mode().Perm() != 0o600 {
			t.Fatalf("invocation %q remap mode=%v err=%v", id, remapInfo, err)
		}
	}

	close(releases["first"])
	first := <-results
	if first.id != "first" || first.err != nil {
		t.Fatalf("first invocation result=%#v", first)
	}
	if _, err := os.Stat(seen["first"]); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first remap survived cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(seen["first"])); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first workspace survived cleanup: %v", err)
	}
	if _, err := os.Stat(seen["second"]); err != nil {
		t.Fatalf("first cleanup removed second remap: %v", err)
	}

	close(releases["second"])
	second := <-results
	if second.id != "second" || second.err != nil {
		t.Fatalf("second invocation result=%#v", second)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("completed invocation workspaces remain: entries=%v err=%v",
			entries, err)
	}
}

func TestVNextReaderCRIUWorkspaceRejectsInvalidTargetBeforeFilesystemMutation(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	verified := vnextReaderWorkspaceTestVerified(fixture)
	for _, test := range []struct {
		name   string
		target vnextReaderExecutionTarget
	}{
		{name: "zero"},
		{name: "invalid", target: vnextReaderExecutionTarget{
			targetContainerID: " invalid-target",
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "must-not-exist")
			var calls int32
			runner := vnextReaderCRIURemapRunner{
				WorkDirectory: root,
				Invoke: func(
					context.Context,
					vnextReaderExecutionTarget,
					string,
					vnextReaderVerifiedPublication,
				) error {
					atomic.AddInt32(&calls, 1)
					return nil
				},
			}
			if err := runner.RunAuthorizedVNextPublication(
				context.Background(), test.target,
				fixture.directory, verified); err == nil {
				t.Fatal("runner accepted an invalid execution target")
			}
			if atomic.LoadInt32(&calls) != 0 {
				t.Fatal("invalid execution target reached Invoke")
			}
			if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid target mutated workspace root: %v", err)
			}
		})
	}
}

func TestVNextReaderCRIUWorkspaceRejectsUncleanAbsoluteRootBeforeFilesystemMutation(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	parent := t.TempDir()
	intermediate := filepath.Join(parent, "must-not-create")
	cleanRoot := filepath.Join(parent, "cleaned-workspace")
	uncleanRoot := intermediate + string(os.PathSeparator) + ".." +
		string(os.PathSeparator) + "cleaned-workspace"
	if !filepath.IsAbs(uncleanRoot) || uncleanRoot == cleanRoot ||
		filepath.Clean(uncleanRoot) != cleanRoot {
		t.Fatalf("test root is not an unclean absolute alias: %q", uncleanRoot)
	}
	var calls int32
	runner := vnextReaderCRIURemapRunner{
		WorkDirectory: uncleanRoot,
		Invoke: func(
			context.Context,
			vnextReaderExecutionTarget,
			string,
			vnextReaderVerifiedPublication,
		) error {
			atomic.AddInt32(&calls, 1)
			return nil
		},
	}
	err := runner.RunAuthorizedVNextPublication(
		context.Background(),
		vnextReaderExecutionTarget{targetContainerID: "clean-root-target"},
		fixture.directory, vnextReaderWorkspaceTestVerified(fixture))
	if err == nil || !strings.Contains(err.Error(), "absolute and clean") {
		t.Fatalf("unclean absolute root error=%v", err)
	}
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("unclean absolute root reached Invoke")
	}
	for _, path := range []string{intermediate, cleanRoot} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unclean root mutated filesystem at %q: %v", path, err)
		}
	}
}

func TestVNextReaderCRIUWorkspaceCleansInvocationAndMaterializationFailures(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	target := vnextReaderExecutionTarget{targetContainerID: "cleanup-target"}

	t.Run("Invoke-error", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "workspaces")
		invokeErr := errors.New("test CRIU invocation failure")
		var remapPath string
		runner := vnextReaderCRIURemapRunner{
			WorkDirectory: root,
			Invoke: func(
				_ context.Context,
				_ vnextReaderExecutionTarget,
				path string,
				_ vnextReaderVerifiedPublication,
			) error {
				remapPath = path
				return invokeErr
			},
		}
		err := runner.RunAuthorizedVNextPublication(
			context.Background(), target, fixture.directory,
			vnextReaderWorkspaceTestVerified(fixture))
		if !errors.Is(err, invokeErr) {
			t.Fatalf("Invoke failure error=%v", err)
		}
		if remapPath == "" {
			t.Fatal("Invoke failure did not reach Invoke")
		}
		if _, err := os.Stat(remapPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Invoke failure left remap: %v", err)
		}
		if _, err := os.Stat(filepath.Dir(remapPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Invoke failure left workspace: %v", err)
		}
	})

	t.Run("materialization-error", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "workspaces")
		var calls int32
		runner := vnextReaderCRIURemapRunner{
			WorkDirectory: root,
			Invoke: func(
				context.Context,
				vnextReaderExecutionTarget,
				string,
				vnextReaderVerifiedPublication,
			) error {
				atomic.AddInt32(&calls, 1)
				return nil
			},
		}
		err := runner.RunAuthorizedVNextPublication(
			context.Background(), target, fixture.directory,
			vnextReaderVerifiedPublication{})
		if err == nil || atomic.LoadInt32(&calls) != 0 {
			t.Fatalf("invalid publication error/calls=%v/%d",
				err, atomic.LoadInt32(&calls))
		}
		if entries, readErr := os.ReadDir(root); readErr != nil || len(entries) != 0 {
			t.Fatalf("materialization failure left workspace: entries=%v err=%v",
				entries, readErr)
		}
	})
}

func TestVNextReaderCRIUWorkspaceCleanupRemovesRemapBeforeEmptyDirectory(
	t *testing.T,
) {
	fixture := newVNextReaderTestFixture(t)
	root := filepath.Join(t.TempDir(), "workspaces")
	target := vnextReaderExecutionTarget{targetContainerID: "cleanup-order-target"}
	var remapPath string
	var unexpectedPath string
	runner := vnextReaderCRIURemapRunner{
		WorkDirectory: root,
		Invoke: func(
			_ context.Context,
			_ vnextReaderExecutionTarget,
			path string,
			_ vnextReaderVerifiedPublication,
		) error {
			remapPath = path
			unexpectedPath = filepath.Join(filepath.Dir(path), "unexpected")
			return os.WriteFile(unexpectedPath, []byte("retain"), 0o600)
		},
	}
	err := runner.RunAuthorizedVNextPublication(
		context.Background(), target, fixture.directory,
		vnextReaderWorkspaceTestVerified(fixture))
	if err == nil || !strings.Contains(
		err.Error(), "remove VNext Reader invocation workspace") {
		t.Fatalf("non-empty workspace cleanup error=%v", err)
	}
	if _, err := os.Stat(remapPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup did not remove remap first: %v", err)
	}
	if data, err := os.ReadFile(unexpectedPath); err != nil || string(data) != "retain" {
		t.Fatalf("cleanup recursively removed unrelated invocation file: %q/%v",
			data, err)
	}
	if err := os.Remove(unexpectedPath); err != nil {
		t.Fatalf("remove test unexpected file: %v", err)
	}
	if err := os.Remove(filepath.Dir(remapPath)); err != nil {
		t.Fatalf("remove retained test workspace: %v", err)
	}
}
