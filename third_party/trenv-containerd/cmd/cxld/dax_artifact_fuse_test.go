package main

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	"github.com/hanwen/go-fuse/v2/fuse"
)

func TestBuildDirectDaxFuseTreeAndReadMappedFile(t *testing.T) {
	mapped := []byte("prefixpayloadsuffix")
	tree, err := buildDirectDaxFuseTree([]trenvpub.ArtifactFile{
		{Path: "metadata-bundle", Type: "directory", Mode: 0o755},
		{Path: "metadata-bundle/image", Type: "directory", Mode: 0o755},
		{Path: "metadata-bundle/image/inventory.img", Type: "regular", Mode: 0o755, Offset: 6, Length: 7},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry := tree.children["metadata-bundle"].children["image"].children["inventory.img"]
	createdAt := time.Date(2026, 7, 19, 7, 0, 0, 0, time.UTC)
	node := &directDaxFuseNode{tree: entry, mapped: mapped, timestamp: directDaxFuseTimestamp(createdAt)}
	handle, _, errno := node.Open(context.Background(), syscall.O_RDONLY)
	if errno != 0 {
		t.Fatalf("open projected file: %v", errno)
	}
	result, errno := handle.(*directDaxFuseFile).Read(context.Background(), make([]byte, 32), 0)
	if errno != 0 {
		t.Fatalf("read projected file: %v", errno)
	}
	data, status := result.Bytes(make([]byte, 32))
	if status != 0 {
		t.Fatalf("read result status: %v", status)
	}
	if string(data) != "payload" {
		t.Fatalf("projected data=%q want=%q", data, "payload")
	}
	var attributes fuse.AttrOut
	if errno := node.Getattr(context.Background(), nil, &attributes); errno != 0 {
		t.Fatalf("getattr projected file: %v", errno)
	}
	if attributes.Mode != fuse.S_IFREG|0o755 {
		t.Fatalf("projected mode=%#o want=%#o", attributes.Mode, fuse.S_IFREG|0o755)
	}
	if attributes.Mtime != uint64(createdAt.Unix()) {
		t.Fatalf("projected mtime=%d want=%d", attributes.Mtime, createdAt.Unix())
	}
	if _, _, errno := node.Open(context.Background(), syscall.O_RDWR); errno != syscall.EROFS {
		t.Fatalf("write open errno=%v want=%v", errno, syscall.EROFS)
	}
}

func TestDirectDaxFuseTimestampClampsToZipEpoch(t *testing.T) {
	const zipEpoch = uint64(315532800)
	if got := directDaxFuseTimestamp(time.Time{}); got != zipEpoch {
		t.Fatalf("zero timestamp=%d want=%d", got, zipEpoch)
	}
	if got := directDaxFuseTimestamp(time.Unix(1, 0)); got != zipEpoch {
		t.Fatalf("pre-1980 timestamp=%d want=%d", got, zipEpoch)
	}
}

func TestBuildDirectDaxFuseTreeRejectsDuplicatePath(t *testing.T) {
	_, err := buildDirectDaxFuseTree([]trenvpub.ArtifactFile{
		{Path: "metadata-bundle", Type: "directory"},
		{Path: "metadata-bundle", Type: "directory"},
	})
	if err == nil {
		t.Fatal("expected duplicate projection path rejection")
	}
}

func TestBuildDirectDaxFuseTreeRejectsNonDirectoryParent(t *testing.T) {
	_, err := buildDirectDaxFuseTree([]trenvpub.ArtifactFile{
		{Path: "metadata-bundle", Type: "regular"},
		{Path: "metadata-bundle/image", Type: "directory"},
	})
	if err == nil {
		t.Fatal("expected non-directory parent rejection")
	}
}
