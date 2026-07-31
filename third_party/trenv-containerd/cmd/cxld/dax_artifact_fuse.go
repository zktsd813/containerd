package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/sys/unix"
)

type directDaxArtifactSource struct {
	mapped []byte
	file   *os.File
}

func (source *directDaxArtifactSource) close() error {
	if source == nil {
		return nil
	}
	var errs []string
	if source.mapped != nil {
		if err := unix.Munmap(source.mapped); err != nil {
			errs = append(errs, err.Error())
		}
		source.mapped = nil
	}
	if source.file != nil {
		if err := source.file.Close(); err != nil {
			errs = append(errs, err.Error())
		}
		source.file = nil
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

type directDaxFuseTree struct {
	entry    *trenvpub.ArtifactFile
	children map[string]*directDaxFuseTree
}

type directDaxFuseNode struct {
	fs.Inode
	tree      *directDaxFuseTree
	mapped    []byte
	timestamp uint64
}

func (node *directDaxFuseNode) OnAdd(ctx context.Context) {
	names := make([]string, 0, len(node.tree.children))
	for name := range node.tree.children {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		childTree := node.tree.children[name]
		childNode := &directDaxFuseNode{tree: childTree, mapped: node.mapped, timestamp: node.timestamp}
		mode := uint32(fuse.S_IFDIR)
		if childTree.entry != nil {
			switch childTree.entry.Type {
			case "regular":
				mode = fuse.S_IFREG
			case "symlink":
				mode = fuse.S_IFLNK
			}
		}
		inode := node.NewPersistentInode(ctx, childNode, fs.StableAttr{Mode: mode})
		node.AddChild(name, inode, true)
	}
}

func (node *directDaxFuseNode) Getattr(_ context.Context, _ fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	out.Attr.Mode = fuse.S_IFDIR | 0o555
	out.Attr.Nlink = 2
	out.Attr.Blksize = uint32(os.Getpagesize())
	out.Attr.Atime = node.timestamp
	out.Attr.Mtime = node.timestamp
	out.Attr.Ctime = node.timestamp
	if node.tree.entry == nil {
		return 0
	}
	entry := node.tree.entry
	out.Attr.Uid = entry.UID
	out.Attr.Gid = entry.GID
	permissions := entry.Mode & 0o7777
	if permissions == 0 {
		permissions = 0o444
	}
	switch entry.Type {
	case "directory":
		out.Attr.Mode = fuse.S_IFDIR | permissions
		out.Attr.Nlink = 2
	case "regular":
		out.Attr.Mode = fuse.S_IFREG | permissions
		out.Attr.Nlink = 1
		out.Attr.Size = uint64(entry.Length)
		out.Attr.Blocks = uint64((entry.Length + 511) / 512)
	case "symlink":
		out.Attr.Mode = fuse.S_IFLNK | 0o777
		out.Attr.Nlink = 1
		out.Attr.Size = uint64(len(entry.LinkTarget))
	default:
		return syscall.EIO
	}
	return 0
}

func directDaxFuseTimestamp(createdAt time.Time) uint64 {
	const zipEpoch = int64(315532800)
	seconds := createdAt.Unix()
	if seconds < zipEpoch {
		seconds = zipEpoch
	}
	return uint64(seconds)
}

func (node *directDaxFuseNode) Access(_ context.Context, mask uint32) syscall.Errno {
	if mask&unix.W_OK != 0 {
		return syscall.EROFS
	}
	return 0
}

func (node *directDaxFuseNode) Open(_ context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	entry := node.tree.entry
	if entry == nil || entry.Type != "regular" {
		return nil, 0, syscall.EISDIR
	}
	if flags&syscall.O_ACCMODE != syscall.O_RDONLY || flags&(syscall.O_TRUNC|syscall.O_APPEND|syscall.O_CREAT) != 0 {
		return nil, 0, syscall.EROFS
	}
	end, err := checkedDirectExtentEnd(entry.Offset, entry.Length, int64(len(node.mapped)))
	if err != nil {
		return nil, 0, syscall.EIO
	}
	return &directDaxFuseFile{data: node.mapped[int(entry.Offset):int(end)]}, fuse.FOPEN_KEEP_CACHE, 0
}

func (node *directDaxFuseNode) Readlink(_ context.Context) ([]byte, syscall.Errno) {
	if node.tree.entry == nil || node.tree.entry.Type != "symlink" {
		return nil, syscall.EINVAL
	}
	return []byte(node.tree.entry.LinkTarget), 0
}

type directDaxFuseFile struct {
	data []byte
}

func (file *directDaxFuseFile) Read(_ context.Context, buffer []byte, offset int64) (fuse.ReadResult, syscall.Errno) {
	if offset < 0 {
		return nil, syscall.EINVAL
	}
	if offset >= int64(len(file.data)) {
		return fuse.ReadResultData(nil), 0
	}
	end := offset + int64(len(buffer))
	if end > int64(len(file.data)) {
		end = int64(len(file.data))
	}
	return fuse.ReadResultData(file.data[offset:end]), 0
}

type directDaxProjection struct {
	restoreRoot     string
	lowerRoot       string
	stateRoot       string
	metadataMounted bool
	actionMounted   bool
	server          *fuse.Server
	source          *directDaxArtifactSource
}

var (
	directDaxProjectionMu        sync.Mutex
	directDaxProjections         = make(map[string]*directDaxProjection)
	directDaxProjectionMountHook = mountDirectDaxProjection
)

func buildDirectDaxFuseTree(files []trenvpub.ArtifactFile) (*directDaxFuseTree, error) {
	root := &directDaxFuseTree{children: make(map[string]*directDaxFuseTree)}
	for i := range files {
		entry := files[i]
		if err := validateDirectArtifactPath(entry.Path); err != nil {
			return nil, err
		}
		parts := strings.Split(entry.Path, "/")
		current := root
		for _, part := range parts {
			if current.entry != nil && current.entry.Type != "directory" {
				return nil, fmt.Errorf("DAX projection path %q descends through non-directory %q", entry.Path, current.entry.Path)
			}
			child := current.children[part]
			if child == nil {
				child = &directDaxFuseTree{children: make(map[string]*directDaxFuseTree)}
				current.children[part] = child
			}
			current = child
		}
		if current.entry != nil {
			return nil, fmt.Errorf("duplicate DAX projection path %q", entry.Path)
		}
		if entry.Type != "directory" && len(current.children) > 0 {
			return nil, fmt.Errorf("non-directory DAX projection path %q has children", entry.Path)
		}
		entryCopy := entry
		current.entry = &entryCopy
	}
	return root, nil
}

func mountDirectDaxProjection(source *directDaxArtifactSource, publication metadataPublicationRecord, restoreRoot string) (*directDaxProjection, error) {
	tree, err := buildDirectDaxFuseTree(publication.Files)
	if err != nil {
		return nil, err
	}
	projection := &directDaxProjection{
		restoreRoot: restoreRoot,
		lowerRoot:   restoreRoot + ".dax-lower",
		stateRoot:   restoreRoot + ".dax-state",
		source:      source,
	}
	if err := os.MkdirAll(projection.lowerRoot, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(projection.restoreRoot, 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(projection.stateRoot, 0o700); err != nil {
		return nil, err
	}
	hour := time.Hour
	root := &directDaxFuseNode{
		tree:      tree,
		mapped:    source.mapped,
		timestamp: directDaxFuseTimestamp(publication.CreatedAt),
	}
	server, err := fs.Mount(projection.lowerRoot, root, &fs.Options{
		MountOptions: fuse.MountOptions{
			FsName:        daemonName + "-dax-" + sanitizePathPart(publication.ArtifactID),
			Name:          daemonName + "-dax",
			Options:       []string{"ro", "default_permissions"},
			DisableXAttrs: true,
		},
		EntryTimeout: &hour,
		AttrTimeout:  &hour,
	})
	if err != nil {
		return nil, fmt.Errorf("mount DAX artifact projection: %w", err)
	}
	projection.server = server
	metadataLower := filepath.Join(projection.lowerRoot, "metadata-bundle")
	if !isDirectory(metadataLower) {
		projection.close()
		return nil, errors.New("DAX artifact projection is missing metadata-bundle")
	}
	metadataUpper := filepath.Join(projection.stateRoot, "metadata-upper")
	metadataWork := filepath.Join(projection.stateRoot, "metadata-work")
	metadataMerged := filepath.Join(projection.restoreRoot, "metadata-bundle")
	if err := mountOverlay(metadataLower, metadataUpper, metadataWork, metadataMerged); err != nil {
		projection.close()
		return nil, fmt.Errorf("mount reader metadata overlay: %w", err)
	}
	projection.metadataMounted = true
	actionLower := filepath.Join(projection.lowerRoot, "action-root")
	if isDirectory(actionLower) {
		actionTarget := filepath.Join(projection.restoreRoot, "action-root")
		if err := os.MkdirAll(actionTarget, 0o555); err != nil {
			projection.close()
			return nil, err
		}
		if err := unix.Mount(actionLower, actionTarget, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
			projection.close()
			return nil, fmt.Errorf("bind DAX action-root projection: %w", err)
		}
		if err := unix.Mount("", actionTarget, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			unix.Unmount(actionTarget, unix.MNT_DETACH)
			projection.close()
			return nil, fmt.Errorf("make DAX action-root projection read-only: %w", err)
		}
		projection.actionMounted = true
	}
	return projection, nil
}

func (projection *directDaxProjection) close() error {
	if projection == nil {
		return nil
	}
	var errs []string
	if projection.actionMounted {
		if err := unix.Unmount(filepath.Join(projection.restoreRoot, "action-root"), unix.MNT_DETACH); err != nil && err != syscall.EINVAL && err != syscall.ENOENT {
			errs = append(errs, err.Error())
		}
		projection.actionMounted = false
	}
	if projection.metadataMounted {
		if err := unix.Unmount(filepath.Join(projection.restoreRoot, "metadata-bundle"), unix.MNT_DETACH); err != nil && err != syscall.EINVAL && err != syscall.ENOENT {
			errs = append(errs, err.Error())
		}
		projection.metadataMounted = false
	}
	if projection.server != nil {
		if err := unix.Unmount(projection.lowerRoot, unix.MNT_DETACH); err != nil && err != syscall.EINVAL && err != syscall.ENOENT {
			errs = append(errs, err.Error())
		}
		projection.server = nil
	}
	if err := projection.source.close(); err != nil {
		errs = append(errs, err.Error())
	}
	if err := makeDirectProjectedTreeRemovable(projection.restoreRoot); err != nil && !os.IsNotExist(err) {
		errs = append(errs, err.Error())
	}
	if err := os.RemoveAll(projection.restoreRoot); err != nil {
		errs = append(errs, err.Error())
	}
	if err := os.RemoveAll(projection.lowerRoot); err != nil {
		errs = append(errs, err.Error())
	}
	if err := os.RemoveAll(projection.stateRoot); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}
