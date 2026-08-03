package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
	"golang.org/x/sys/unix"
)

const (
	directPageExtentRole       = "criu-pages"
	directArtifactExtentRole   = "restore-artifact"
	directArtifactExtentLayout = "immutable-packed-files-v1"
	directArtifactAllocationID = ".artifact"
	directDaxManifestSchema    = "trenv.artifact/v5"
)

type directArtifactPlanEntry struct {
	File       trenvpub.ArtifactFile
	SourcePath string
}

var (
	directDaxFlushHook = func(file *os.File, mapped []byte) error {
		if err := directWritebackDaxCache(mapped); err != nil {
			return err
		}
		return syncDirectDaxMapping(file, mapped)
	}
	directDaxInvalidateHook = func(mapped []byte) error {
		if err := directInvalidateDaxCache(mapped); err != nil {
			return err
		}
		return unix.Madvise(mapped, unix.MADV_DONTNEED)
	}
)

func syncDirectDaxMapping(file *os.File, mapped []byte) error {
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat DAX mapping: %w", err)
	}
	if err := unix.Msync(mapped, unix.MS_SYNC); err != nil && !ignorableDirectDaxSyncError(info.Mode(), err) {
		return fmt.Errorf("msync DAX mapping: %w", err)
	}
	if err := file.Sync(); err != nil && !ignorableDirectDaxSyncError(info.Mode(), err) {
		return fmt.Errorf("fsync DAX device: %w", err)
	}
	return nil
}

func ignorableDirectDaxSyncError(mode os.FileMode, err error) bool {
	if mode&os.ModeCharDevice == 0 {
		return false
	}
	return errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOTTY)
}

func writeDirectDaxArtifact(req checkpointRequest, pagePlacement directDaxPlacement, config daemonConfig) (trenvpub.StorageExtent, []trenvpub.ArtifactFile, directDaxPlacement, error) {
	pageSize := pagePlacement.PageSize
	if pageSize <= 0 {
		pageSize = int64(os.Getpagesize())
	}
	entries, payloadBytes, err := buildDirectArtifactPlan(req, pageSize)
	if err != nil {
		return trenvpub.StorageExtent{}, nil, directDaxPlacement{}, err
	}
	shards, err := directArtifactDaxShards(config)
	if err != nil {
		return trenvpub.StorageExtent{}, nil, directDaxPlacement{}, err
	}
	allocationID := pagePlacement.CheckpointID + directArtifactAllocationID
	placement, err := resolveDirectDaxPlacement(
		pagePlacement.WriterStateRoot,
		pagePlacement.WriterID,
		allocationID,
		"artifact:"+pagePlacement.CheckpointID,
		shards,
		payloadBytes,
		config.DaxPlacementPolicy)
	if err != nil {
		return trenvpub.StorageExtent{}, nil, directDaxPlacement{}, err
	}
	placement.WriterStateRoot = pagePlacement.WriterStateRoot
	placement.Layout = directArtifactExtentLayout
	if !placement.NewReservation {
		return trenvpub.StorageExtent{}, nil, directDaxPlacement{}, fmt.Errorf("immutable artifact DAX extent %q already exists", allocationID)
	}

	extent, files, err := persistDirectArtifactPlan(placement, entries, payloadBytes)
	if err != nil {
		rollbackDirectDaxPlacementReservation(placement)
		return trenvpub.StorageExtent{}, nil, directDaxPlacement{}, err
	}
	return extent, files, placement, nil
}

func buildDirectArtifactPlan(req checkpointRequest, pageSize int64) ([]directArtifactPlanEntry, int64, error) {
	if pageSize <= 0 {
		return nil, 0, fmt.Errorf("invalid artifact page size %d", pageSize)
	}
	sources := []struct {
		path string
		name string
	}{{path: strings.TrimSpace(req.MetadataBundlePath), name: "metadata-bundle"}}
	if actionRoot := directCheckpointActionExportRoot(req); isDirectory(actionRoot) {
		sources = append(sources, struct {
			path string
			name string
		}{path: actionRoot, name: "action-root"})
	}

	var entries []directArtifactPlanEntry
	for _, source := range sources {
		if !isDirectory(source.path) {
			return nil, 0, fmt.Errorf("artifact source %q is not a directory", source.path)
		}
		rootEntries, err := walkDirectArtifactSource(source.path, source.name)
		if err != nil {
			return nil, 0, err
		}
		entries = append(entries, rootEntries...)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].File.Path < entries[j].File.Path })

	var nextOffset int64
	for i := range entries {
		if entries[i].File.Type != "regular" {
			continue
		}
		nextOffset = roundUpInt64(nextOffset, pageSize)
		entries[i].File.Offset = nextOffset
		nextOffset += entries[i].File.Length
	}
	payloadBytes := roundUpInt64(nextOffset, pageSize)
	if payloadBytes == 0 {
		payloadBytes = pageSize
	}
	return entries, payloadBytes, nil
}

func walkDirectArtifactSource(sourceRoot, artifactRoot string) ([]directArtifactPlanEntry, error) {
	var entries []directArtifactPlanEntry
	err := filepath.Walk(sourceRoot, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil {
			return nil
		}
		relative, err := filepath.Rel(sourceRoot, path)
		if err != nil {
			return err
		}
		artifactPath := artifactRoot
		if relative != "." {
			artifactPath = filepath.ToSlash(filepath.Join(artifactRoot, relative))
		}
		if err := validateDirectArtifactPath(artifactPath); err != nil {
			return err
		}

		entry := directArtifactPlanEntry{SourcePath: path}
		entry.File.Path = artifactPath
		entry.File.Mode = uint32(info.Mode().Perm())
		if stat, ok := info.Sys().(*syscall.Stat_t); ok {
			entry.File.UID = stat.Uid
			entry.File.GID = stat.Gid
		}
		switch {
		case info.IsDir():
			entry.File.Type = "directory"
		case info.Mode().IsRegular():
			entry.File.Type = "regular"
			entry.File.Length = info.Size()
		case info.Mode()&os.ModeSymlink != 0:
			entry.File.Type = "symlink"
			entry.File.LinkTarget, err = os.Readlink(path)
			if err != nil {
				return err
			}
			if err := validateDirectArtifactSymlink(artifactPath, entry.File.LinkTarget); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported artifact node %q with mode %v", path, info.Mode())
		}
		entries = append(entries, entry)
		return nil
	})
	return entries, err
}

func validateDirectArtifactPath(path string) error {
	if path == "" || path != filepath.ToSlash(path) || strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("invalid artifact path %q", path)
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(path)))
	if clean != path || clean == "." || strings.HasPrefix(clean, "../") || filepath.IsAbs(filepath.FromSlash(path)) {
		return fmt.Errorf("unsafe artifact path %q", path)
	}
	return nil
}

func validateDirectArtifactSymlink(path, target string) error {
	if target == "" || strings.ContainsRune(target, '\x00') {
		return fmt.Errorf("unsafe artifact symlink %q -> %q", path, target)
	}
	return nil
}

func persistDirectArtifactPlan(placement directDaxPlacement, entries []directArtifactPlanEntry, payloadBytes int64) (trenvpub.StorageExtent, []trenvpub.ArtifactFile, error) {
	offsetBytes := placement.DaxStartPage * placement.PageSize
	lengthBytes := placement.DaxLengthPages * placement.PageSize
	if offsetBytes < 0 || payloadBytes <= 0 || lengthBytes < payloadBytes {
		return trenvpub.StorageExtent{}, nil, errors.New("invalid artifact DAX extent")
	}
	mapped, file, err := mapDirectDaxRange(placement.DaxDevice, offsetBytes, lengthBytes, true)
	if err != nil {
		return trenvpub.StorageExtent{}, nil, err
	}
	defer file.Close()
	defer unix.Munmap(mapped) //nolint:errcheck
	for i := range mapped {
		mapped[i] = 0
	}

	files := make([]trenvpub.ArtifactFile, len(entries))
	for i := range entries {
		files[i] = entries[i].File
		if files[i].Type != "regular" {
			continue
		}
		end, err := checkedDirectExtentEnd(files[i].Offset, files[i].Length, payloadBytes)
		if err != nil {
			return trenvpub.StorageExtent{}, nil, fmt.Errorf("artifact file %q: %w", files[i].Path, err)
		}
		source, err := os.Open(entries[i].SourcePath)
		if err != nil {
			return trenvpub.StorageExtent{}, nil, err
		}
		_, copyErr := io.ReadFull(source, mapped[int(files[i].Offset):int(end)])
		closeErr := source.Close()
		if copyErr != nil {
			return trenvpub.StorageExtent{}, nil, fmt.Errorf("pack artifact file %q: %w", files[i].Path, copyErr)
		}
		if closeErr != nil {
			return trenvpub.StorageExtent{}, nil, closeErr
		}
	}
	if err := directDaxFlushHook(file, mapped); err != nil {
		return trenvpub.StorageExtent{}, nil, fmt.Errorf("flush artifact DAX extent: %w", err)
	}
	return trenvpub.StorageExtent{
		Role:           directArtifactExtentRole,
		DeviceIdentity: placement.ShardID,
		ShardID:        placement.ShardID,
		OffsetBytes:    offsetBytes,
		LengthBytes:    lengthBytes,
		PayloadBytes:   payloadBytes,
		PageSize:       placement.PageSize,
		Layout:         directArtifactExtentLayout,
	}, files, nil
}

func directPageStorageExtent(placement directDaxPlacement) (trenvpub.StorageExtent, error) {
	payloadBytes := placement.PageCount * placement.PageSize
	lengthBytes := placement.DaxLengthPages * placement.PageSize
	if payloadBytes <= 0 || payloadBytes > lengthBytes {
		return trenvpub.StorageExtent{}, fmt.Errorf("invalid page payload %d bytes for extent %d bytes", payloadBytes, lengthBytes)
	}
	offsetBytes := placement.DaxStartPage * placement.PageSize
	if err := flushDirectDaxRange(placement.DaxDevice, offsetBytes, lengthBytes, payloadBytes); err != nil {
		return trenvpub.StorageExtent{}, err
	}
	return trenvpub.StorageExtent{
		Role:           directPageExtentRole,
		DeviceIdentity: placement.ShardID,
		ShardID:        placement.ShardID,
		OffsetBytes:    offsetBytes,
		LengthBytes:    lengthBytes,
		PayloadBytes:   payloadBytes,
		PageSize:       placement.PageSize,
		Layout:         placement.Layout,
	}, nil
}

func flushDirectDaxRange(device string, offsetBytes, lengthBytes, payloadBytes int64) error {
	mapped, file, err := mapDirectDaxRange(device, offsetBytes, lengthBytes, true)
	if err != nil {
		return err
	}
	defer file.Close()
	defer unix.Munmap(mapped) //nolint:errcheck
	if payloadBytes <= 0 || payloadBytes > int64(len(mapped)) {
		return errors.New("invalid DAX payload length")
	}
	if err := directDaxFlushHook(file, mapped); err != nil {
		return fmt.Errorf("flush page DAX extent: %w", err)
	}
	return nil
}

func mapDirectDaxRange(device string, offsetBytes, lengthBytes int64, writable bool) ([]byte, *os.File, error) {
	if offsetBytes < 0 || lengthBytes <= 0 || offsetBytes%int64(os.Getpagesize()) != 0 || lengthBytes > int64(^uint(0)>>1) {
		return nil, nil, fmt.Errorf("invalid DAX mapping offset=%d length=%d", offsetBytes, lengthBytes)
	}
	flags := os.O_RDONLY
	protection := unix.PROT_READ
	if writable {
		flags = os.O_RDWR
		protection |= unix.PROT_WRITE
	}
	file, err := os.OpenFile(device, flags, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := validateDirectDaxFileRange(file, device, offsetBytes, lengthBytes); err != nil {
		file.Close()
		return nil, nil, err
	}
	mapped, err := unix.Mmap(int(file.Fd()), offsetBytes, int(lengthBytes), protection, unix.MAP_SHARED)
	if err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("mmap DAX range %s[%d:%d]: %w", device, offsetBytes, offsetBytes+lengthBytes, err)
	}
	return mapped, file, nil
}

func validateDirectDaxFileRange(file *os.File, device string, offsetBytes, lengthBytes int64) error {
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if info.Mode().IsRegular() && (offsetBytes > info.Size() || lengthBytes > info.Size()-offsetBytes) {
		return fmt.Errorf("DAX range exceeds %q size %d", device, info.Size())
	}
	return nil
}

func flushDirectDaxMapping(file *os.File, mapped []byte) error {
	if len(mapped) == 0 {
		return errors.New("cannot flush empty DAX mapping")
	}
	return directDaxFlushHook(file, mapped)
}

func invalidateDirectDaxMapping(mapped []byte) error {
	if len(mapped) == 0 {
		return errors.New("cannot invalidate empty DAX mapping")
	}
	return directDaxInvalidateHook(mapped)
}

func materializeDaxArtifact(publication metadataPublicationRecord, readerContainer string, config daemonConfig) (string, error) {
	if err := validateDaxPublication(publication); err != nil {
		return "", err
	}
	artifactDevice, err := resolveReaderDaxDevice(publication.ArtifactExtent, config)
	if err != nil {
		return "", err
	}
	if err := validateReaderPageExtent(publication, config); err != nil {
		return "", err
	}

	restoreRoot := filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(publication.CheckpointID))
	if err := os.MkdirAll(filepath.Dir(restoreRoot), 0o755); err != nil {
		return "", err
	}
	directDaxProjectionMu.Lock()
	defer directDaxProjectionMu.Unlock()
	if err := removeDirectProjectedTreeLocked(restoreRoot); err != nil {
		return "", err
	}
	source, err := openDirectDaxArtifactSource(artifactDevice, publication)
	if err != nil {
		return "", err
	}
	projection, err := directDaxProjectionMountHook(source, publication, restoreRoot)
	if err != nil {
		source.close()
		return "", err
	}
	directDaxProjections[restoreRoot] = projection
	if err := writeReaderPublication(restoreRoot, publication); err != nil {
		delete(directDaxProjections, restoreRoot)
		projection.close()
		return "", err
	}
	return restoreRoot, nil
}

func removeDirectProjectedTree(root string) error {
	directDaxProjectionMu.Lock()
	projection := directDaxProjections[root]
	delete(directDaxProjections, root)
	directDaxProjectionMu.Unlock()
	if projection != nil {
		return projection.close()
	}
	return removeDirectProjectedTreeFiles(root)
}

func removeDirectProjectedTreesForContainer(readerContainer string, config daemonConfig) error {
	containerRoot := filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer))
	directDaxProjectionMu.Lock()
	projections := make(map[string]*directDaxProjection)
	for root, projection := range directDaxProjections {
		if filepath.Dir(root) == containerRoot {
			projections[root] = projection
			delete(directDaxProjections, root)
		}
	}
	directDaxProjectionMu.Unlock()

	entries, err := os.ReadDir(containerRoot)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.TrimSuffix(strings.TrimSuffix(entry.Name(), ".dax-lower"), ".dax-state")
		root := filepath.Join(containerRoot, name)
		if _, exists := projections[root]; !exists {
			projections[root] = nil
		}
	}

	roots := make([]string, 0, len(projections))
	for root := range projections {
		roots = append(roots, root)
	}
	sort.Strings(roots)
	var cleanupErrors []string
	for _, root := range roots {
		projection := projections[root]
		var err error
		if projection != nil {
			err = projection.close()
		} else {
			err = removeDirectProjectedTreeFiles(root)
		}
		if err != nil {
			cleanupErrors = append(cleanupErrors, err.Error())
		}
	}
	if err := os.RemoveAll(containerRoot); err != nil {
		cleanupErrors = append(cleanupErrors, err.Error())
	}
	if len(cleanupErrors) > 0 {
		return errors.New(strings.Join(cleanupErrors, "; "))
	}
	return nil
}

func removeDirectProjectedContainersByPrefix(containerPrefix string, config daemonConfig) error {
	restoreRoot := filepath.Join(config.WorkingDirectory, "restore")
	entries, err := os.ReadDir(restoreRoot)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	prefix := sanitizePathPart(containerPrefix)
	var cleanupErrors []string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix) {
			continue
		}
		if err := removeDirectProjectedTreesForContainer(entry.Name(), config); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Sprintf("%s: %v", entry.Name(), err))
		}
	}
	if len(cleanupErrors) > 0 {
		return errors.New(strings.Join(cleanupErrors, "; "))
	}
	return nil
}

func removeDirectProjectedTreeLocked(root string) error {
	if projection := directDaxProjections[root]; projection != nil {
		delete(directDaxProjections, root)
		return projection.close()
	}
	return removeDirectProjectedTreeFiles(root)
}

func removeDirectProjectedTreeFiles(root string) error {
	mountpoints, err := readDirectMountpoints()
	if err != nil {
		return err
	}
	for _, mountpoint := range []string{
		filepath.Join(root, "action-root"),
		filepath.Join(root, "metadata-bundle"),
		root + ".dax-lower",
	} {
		if !mountpoints[filepath.Clean(mountpoint)] {
			continue
		}
		if err := unix.Unmount(mountpoint, unix.MNT_DETACH); err != nil && err != syscall.EINVAL && err != syscall.ENOENT {
			return err
		}
	}
	if err := makeDirectProjectedTreeRemovable(root); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.RemoveAll(root); err != nil {
		return err
	}
	if err := os.RemoveAll(root + ".dax-lower"); err != nil {
		return err
	}
	return os.RemoveAll(root + ".dax-state")
}

func readDirectMountpoints() (map[string]bool, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	mountpoints := make(map[string]bool)
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mountpoints[filepath.Clean(replacer.Replace(fields[4]))] = true
	}
	return mountpoints, nil
}

func makeDirectProjectedTreeRemovable(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info != nil && info.IsDir() {
			if err := os.Chmod(path, info.Mode().Perm()|0o700); err != nil {
				return err
			}
		}
		return nil
	})
}

func openDirectDaxArtifactSource(device string, publication metadataPublicationRecord) (*directDaxArtifactSource, error) {
	extent := publication.ArtifactExtent
	mapped, file, err := mapDirectDaxRange(device, extent.OffsetBytes, extent.LengthBytes, false)
	if err != nil {
		return nil, err
	}
	if err := directDaxInvalidateHook(mapped); err != nil {
		unix.Munmap(mapped)
		file.Close()
		return nil, fmt.Errorf("invalidate artifact DAX extent: %w", err)
	}
	if extent.PayloadBytes <= 0 || extent.PayloadBytes > int64(len(mapped)) {
		unix.Munmap(mapped)
		file.Close()
		return nil, errors.New("artifact payload is outside mapped DAX extent")
	}
	return &directDaxArtifactSource{mapped: mapped, file: file}, nil
}

func projectDirectDaxArtifact(device string, publication metadataPublicationRecord, targetRoot string) error {
	source, err := openDirectDaxArtifactSource(device, publication)
	if err != nil {
		return err
	}
	defer source.close()
	return projectDirectDaxArtifactSource(source, publication, targetRoot)
}

func projectDirectDaxArtifactSource(source *directDaxArtifactSource, publication metadataPublicationRecord, targetRoot string) error {
	extent := publication.ArtifactExtent
	mapped := source.mapped

	var directories []trenvpub.ArtifactFile
	for _, artifactFile := range publication.Files {
		target, err := safeJoin(targetRoot, filepath.FromSlash(artifactFile.Path))
		if err != nil {
			return err
		}
		switch artifactFile.Type {
		case "directory":
			if err := ensureArchivePathHasNoSymlink(targetRoot, target); err != nil {
				return err
			}
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			if err := applyDirectArtifactOwnership(target, artifactFile); err != nil {
				return err
			}
			directories = append(directories, artifactFile)
		case "regular":
			end, err := checkedDirectExtentEnd(artifactFile.Offset, artifactFile.Length, extent.PayloadBytes)
			if err != nil {
				return fmt.Errorf("artifact file %q: %w", artifactFile.Path, err)
			}
			data := mapped[int(artifactFile.Offset):int(end)]
			if err := ensureArchivePathHasNoSymlink(targetRoot, filepath.Dir(target)); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			mode := os.FileMode(artifactFile.Mode) & 0o555
			if err := os.WriteFile(target, data, mode); err != nil {
				return err
			}
			if err := applyDirectArtifactOwnership(target, artifactFile); err != nil {
				return err
			}
		case "symlink":
			if err := validateDirectArtifactSymlink(artifactFile.Path, artifactFile.LinkTarget); err != nil {
				return err
			}
			if err := ensureArchivePathHasNoSymlink(targetRoot, filepath.Dir(target)); err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(artifactFile.LinkTarget, target); err != nil {
				return err
			}
			if err := applyDirectArtifactOwnership(target, artifactFile); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported artifact file type %q", artifactFile.Type)
		}
	}
	for i := len(directories) - 1; i >= 0; i-- {
		target, err := safeJoin(targetRoot, filepath.FromSlash(directories[i].Path))
		if err != nil {
			return err
		}
		mode := os.FileMode(directories[i].Mode) & 0o555
		if mode == 0 {
			mode = 0o555
		}
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
	}
	return nil
}

func applyDirectArtifactOwnership(path string, artifactFile trenvpub.ArtifactFile) error {
	uid := int(artifactFile.UID)
	gid := int(artifactFile.GID)
	if uid == os.Getuid() && gid == os.Getgid() {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("cannot preserve ownership %d:%d for %q without root", uid, gid, artifactFile.Path)
	}
	if err := os.Lchown(path, uid, gid); err != nil {
		return fmt.Errorf("preserve ownership for %q: %w", artifactFile.Path, err)
	}
	return nil
}

func validateDaxPublication(publication metadataPublicationRecord) error {
	if publication.Version != int(trenvpub.Version) {
		return fmt.Errorf("publication version is %d, expected %d", publication.Version, trenvpub.Version)
	}
	if publication.State != "COMMITTED" {
		return fmt.Errorf("publication state %q is not COMMITTED", publication.State)
	}
	if publication.ManifestSchema != trenvpub.ManifestSchema {
		return fmt.Errorf(
			"publication manifest schema %q does not match %q",
			publication.ManifestSchema,
			trenvpub.ManifestSchema)
	}
	if publication.DedupApplySchema != trenvpub.DedupApplySchema {
		return fmt.Errorf(
			"publication dedup apply schema %q does not match %q",
			publication.DedupApplySchema,
			trenvpub.DedupApplySchema)
	}
	if publication.Generation == 0 || publication.WriterEpoch == 0 {
		return errors.New("publication generation is not writer-fenced")
	}
	if publication.CheckpointID == "" || publication.ArtifactID == "" || publication.WriterID == "" || len(publication.Files) == 0 {
		return errors.New("DAX publication identity or file table is incomplete")
	}
	if err := validateDirectStorageExtent(publication.PageExtent, directPageExtentRole); err != nil {
		return fmt.Errorf("page extent: %w", err)
	}
	if err := validateDirectStorageExtent(publication.ArtifactExtent, directArtifactExtentRole); err != nil {
		return fmt.Errorf("artifact extent: %w", err)
	}
	if publication.PageExtent.ShardID == publication.ArtifactExtent.ShardID {
		pageEnd, err := checkedDirectExtentEnd(publication.PageExtent.OffsetBytes, publication.PageExtent.LengthBytes, int64(^uint64(0)>>1))
		if err != nil {
			return err
		}
		artifactEnd, err := checkedDirectExtentEnd(publication.ArtifactExtent.OffsetBytes, publication.ArtifactExtent.LengthBytes, int64(^uint64(0)>>1))
		if err != nil {
			return err
		}
		if publication.PageExtent.OffsetBytes < artifactEnd && publication.ArtifactExtent.OffsetBytes < pageEnd {
			return errors.New("page and artifact DAX extents overlap")
		}
	}
	seen := make(map[string]struct{}, len(publication.Files))
	var regularFiles []trenvpub.ArtifactFile
	previousPath := ""
	for _, file := range publication.Files {
		if err := validateDirectArtifactPath(file.Path); err != nil {
			return err
		}
		if _, ok := seen[file.Path]; ok {
			return fmt.Errorf("duplicate artifact path %q", file.Path)
		}
		if previousPath != "" && file.Path < previousPath {
			return errors.New("artifact file table is not path sorted")
		}
		previousPath = file.Path
		seen[file.Path] = struct{}{}
		switch file.Type {
		case "directory":
			if file.Offset != 0 || file.Length != 0 || file.LinkTarget != "" {
				return fmt.Errorf("directory %q has payload metadata", file.Path)
			}
		case "regular":
			if file.Offset%publication.ArtifactExtent.PageSize != 0 {
				return fmt.Errorf("artifact file %q offset is not page aligned", file.Path)
			}
			if _, err := checkedDirectExtentEnd(file.Offset, file.Length, publication.ArtifactExtent.PayloadBytes); err != nil {
				return fmt.Errorf("artifact file %q: %w", file.Path, err)
			}
			if file.LinkTarget != "" {
				return fmt.Errorf("regular artifact file %q has a link target", file.Path)
			}
			if file.Length > 0 {
				regularFiles = append(regularFiles, file)
			}
		case "symlink":
			if file.Offset != 0 || file.Length != 0 {
				return fmt.Errorf("symlink %q has payload metadata", file.Path)
			}
			if err := validateDirectArtifactSymlink(file.Path, file.LinkTarget); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported artifact file type %q", file.Type)
		}
	}
	sort.Slice(regularFiles, func(i, j int) bool { return regularFiles[i].Offset < regularFiles[j].Offset })
	for i := 1; i < len(regularFiles); i++ {
		previousEnd, err := checkedDirectExtentEnd(regularFiles[i-1].Offset, regularFiles[i-1].Length, publication.ArtifactExtent.PayloadBytes)
		if err != nil {
			return err
		}
		if regularFiles[i].Offset < previousEnd {
			return fmt.Errorf("artifact files %q and %q overlap", regularFiles[i-1].Path, regularFiles[i].Path)
		}
	}
	return nil
}

func validateDirectStorageExtent(extent trenvpub.StorageExtent, role string) error {
	if extent.Role != role || extent.DeviceIdentity == "" || extent.ShardID == "" || extent.DeviceIdentity != extent.ShardID {
		return errors.New("stable shard identity is incomplete")
	}
	if extent.OffsetBytes < 0 || extent.LengthBytes <= 0 || extent.PayloadBytes <= 0 || extent.PayloadBytes > extent.LengthBytes {
		return errors.New("range is invalid")
	}
	if extent.PageSize <= 0 || extent.OffsetBytes%extent.PageSize != 0 || extent.LengthBytes%extent.PageSize != 0 {
		return errors.New("range is not page aligned")
	}
	return nil
}

func validateReaderPageExtent(publication metadataPublicationRecord, config daemonConfig) error {
	device, err := resolveReaderDaxDevice(publication.PageExtent, config)
	if err != nil {
		return err
	}
	extent := publication.PageExtent
	mapped, file, err := mapDirectDaxRange(device, extent.OffsetBytes, extent.LengthBytes, false)
	if err != nil {
		return err
	}
	defer file.Close()
	defer unix.Munmap(mapped) //nolint:errcheck
	if err := directDaxInvalidateHook(mapped); err != nil {
		return fmt.Errorf("invalidate page DAX extent: %w", err)
	}
	return nil
}

func resolveReaderDaxDevice(extent trenvpub.StorageExtent, config daemonConfig) (string, error) {
	shards := config.ReaderDaxShards
	if extent.Role == directArtifactExtentRole && len(config.ReaderArtifactDaxShards) > 0 {
		shards = config.ReaderArtifactDaxShards
	}
	if len(shards) == 0 {
		shards = config.DaxShards
	}
	for _, shard := range shards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return "", err
		}
		if normalized.ShardID == extent.ShardID {
			return normalized.DaxDevice, nil
		}
	}
	if len(shards) == 0 && strings.TrimSpace(config.DaxDevice) != "" && (strings.TrimSpace(config.ShardID) == "" || strings.TrimSpace(config.ShardID) == extent.ShardID) {
		return strings.TrimSpace(config.DaxDevice), nil
	}
	return "", fmt.Errorf("no reader-local DAX mapping for stable shard %q", extent.ShardID)
}

func validateDisjointDaxShardSets(pageShards, artifactShards []daxShardConfig) error {
	if len(pageShards) == 0 || len(artifactShards) == 0 {
		return nil
	}
	pageIDs := make(map[string]struct{}, len(pageShards))
	pageDevices := make(map[string]struct{}, len(pageShards))
	for _, shard := range pageShards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return err
		}
		pageIDs[normalized.ShardID] = struct{}{}
		pageDevices[normalized.DaxDevice] = struct{}{}
	}
	for _, shard := range artifactShards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return err
		}
		if _, ok := pageIDs[normalized.ShardID]; ok {
			return fmt.Errorf("page and artifact shard id %q overlap", normalized.ShardID)
		}
		if _, ok := pageDevices[normalized.DaxDevice]; ok {
			return fmt.Errorf("page and artifact shard device %q overlap", normalized.DaxDevice)
		}
	}
	return nil
}

func checkedDirectExtentEnd(offset, length, limit int64) (int64, error) {
	if offset < 0 || length < 0 || offset > limit || length > limit-offset {
		return 0, fmt.Errorf("range offset=%d length=%d exceeds limit=%d", offset, length, limit)
	}
	return offset + length, nil
}
