package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

const directRootfsStateDirectoryName = "rootfs-state"

type directDaxPlacement struct {
	CheckpointID     string    `json:"checkpoint_id"`
	WriterID         string    `json:"writer_id"`
	ShardID          string    `json:"shard_id"`
	DaxDevice        string    `json:"dax_device"`
	DaxStartPage     int64     `json:"dax_start_page"`
	DaxLengthPages   int64     `json:"dax_length_pages"`
	PageCount        int64     `json:"page_count"`
	ConvertPageCount int64     `json:"convert_page_count"`
	PageSize         int64     `json:"page_size"`
	Layout           string    `json:"layout"`
	State            string    `json:"state"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type directMetadataBundleFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type directMetadataBundleManifest struct {
	CheckpointID string                     `json:"checkpoint_id"`
	ImagePath    string                     `json:"image_path"`
	Placement    string                     `json:"placement"`
	Files        []directMetadataBundleFile `json:"files"`
	CreatedAt    time.Time                  `json:"created_at"`
}

func finalizeDirectCheckpoint(ctx context.Context, req checkpointRequest, state trenvContainerState, config daemonConfig) error {
	if req.Publication == nil && strings.TrimSpace(req.MetadataBundlePath) == "" && len(req.ActionExportRoots) == 0 {
		return nil
	}
	placement, err := directCheckpointPlacement(req, config)
	if err != nil {
		return err
	}
	if strings.TrimSpace(req.MetadataBundlePath) != "" {
		if err := writeDirectMetadataBundle(req.ImagePath, req.MetadataBundlePath, placement); err != nil {
			return fmt.Errorf("write metadata bundle: %w", err)
		}
		if err := exportDirectRuntimeRootfsState(state.Rootfs, req.WorkPath, req.MetadataBundlePath); err != nil {
			return fmt.Errorf("export runtime rootfs state: %w", err)
		}
	}
	if len(req.ActionExportRoots) > 0 {
		exportRoot := directCheckpointActionExportRoot(req)
		if exportRoot == "" {
			return errors.New("checkpoint action export root is empty")
		}
		if err := exportDirectActionRoots(state.Rootfs, exportRoot, req.ActionExportRoots); err != nil {
			return fmt.Errorf("export packaged action roots: %w", err)
		}
	}
	if req.Publication != nil {
		if err := writeDirectPublication(ctx, req, placement); err != nil {
			return fmt.Errorf("write publication metadata: %w", err)
		}
	}
	return nil
}

func directCheckpointActionExportRoot(req checkpointRequest) string {
	if req.Publication != nil && strings.TrimSpace(req.Publication.CheckpointActionExportRoot) != "" {
		return strings.TrimSpace(req.Publication.CheckpointActionExportRoot)
	}
	if strings.TrimSpace(req.WorkPath) != "" {
		return filepath.Join(req.WorkPath, "action-root")
	}
	return ""
}

func directCheckpointPlacement(req checkpointRequest, config daemonConfig) (directDaxPlacement, error) {
	if req.Publication != nil && config.CheckpointWriterDisabled {
		return directDaxPlacement{}, errors.New("checkpoint writer is disabled")
	}
	writerID := strings.TrimSpace(config.WriterID)
	if writerID == "" {
		writerID = defaultWriterID()
	}
	daxDevice := strings.TrimSpace(config.DaxDevice)
	shardID := strings.TrimSpace(config.ShardID)
	if len(config.DaxShards) > 0 {
		shard := config.DaxShards[0]
		daxDevice = strings.TrimSpace(shard.DaxDevice)
		shardID = strings.TrimSpace(shard.ShardID)
	}
	if daxDevice == "" {
		var err error
		daxDevice, err = detectDaxDevice()
		if err != nil {
			return directDaxPlacement{}, err
		}
	}
	if shardID == "" {
		shardID = filepath.Base(daxDevice)
	}
	pageSize := int64(os.Getpagesize())
	pageBytes, pageCount := directCheckpointPagePayload(req.ImagePath, pageSize)
	reservationBytes := req.ReservationBytes
	if reservationBytes < pageBytes {
		reservationBytes = pageBytes
	}
	lengthPages := roundUpInt64(reservationBytes, pageSize) / pageSize
	if lengthPages <= 0 {
		lengthPages = 1
	}
	return directDaxPlacement{
		CheckpointID:     checkpointID(req.ImagePath),
		WriterID:         writerID,
		ShardID:          shardID,
		DaxDevice:        daxDevice,
		DaxStartPage:     0,
		DaxLengthPages:   lengthPages,
		PageCount:        pageCount,
		ConvertPageCount: pageCount,
		PageSize:         pageSize,
		Layout:           "direct-runc-criu-page-files",
		State:            "COMMITTED",
		UpdatedAt:        time.Now().UTC(),
	}, nil
}

func directCheckpointPagePayload(imagePath string, pageSize int64) (int64, int64) {
	matches, err := filepath.Glob(filepath.Join(imagePath, "pages-*.img"))
	if err != nil {
		return 0, 0
	}
	var total int64
	for _, match := range matches {
		info, err := os.Stat(match)
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	if pageSize <= 0 {
		pageSize = int64(os.Getpagesize())
	}
	return total, roundUpInt64(total, pageSize) / pageSize
}

func roundUpInt64(value, align int64) int64 {
	if align <= 0 || value <= 0 {
		return value
	}
	remainder := value % align
	if remainder == 0 {
		return value
	}
	return value + align - remainder
}

func writeDirectMetadataBundle(imagePath, bundlePath string, placement directDaxPlacement) error {
	if err := os.RemoveAll(bundlePath); err != nil {
		return err
	}
	imageBundlePath := filepath.Join(bundlePath, "image")
	if err := os.MkdirAll(imageBundlePath, 0o755); err != nil {
		return err
	}
	var files []directMetadataBundleFile
	err := filepath.Walk(imagePath, func(sourcePath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		relative, err := filepath.Rel(imagePath, sourcePath)
		if err != nil {
			return err
		}
		if !isDirectReaderMetadataFile(relative) {
			return nil
		}
		targetPath := filepath.Join(imageBundlePath, relative)
		if err := copyFile(sourcePath, targetPath, info.Mode().Perm()); err != nil {
			return err
		}
		sum, err := fileSHA256(targetPath)
		if err != nil {
			return err
		}
		files = append(files, directMetadataBundleFile{
			Path:   filepath.ToSlash(filepath.Join("image", relative)),
			Size:   info.Size(),
			SHA256: sum,
		})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	if err := writeJSONFile(filepath.Join(bundlePath, "placement.json"), placement); err != nil {
		return err
	}
	return writeJSONFile(filepath.Join(bundlePath, "bundle.json"), directMetadataBundleManifest{
		CheckpointID: placement.CheckpointID,
		ImagePath:    "image",
		Placement:    "placement.json",
		Files:        files,
		CreatedAt:    time.Now().UTC(),
	})
}

func isDirectReaderMetadataFile(relativePath string) bool {
	base := filepath.Base(relativePath)
	if matched, _ := filepath.Match("pages-*.img", base); matched {
		return false
	}
	return base != "cgroup.img"
}

func exportDirectActionRoots(rootfs, exportRoot string, roots []string) error {
	if len(roots) == 0 {
		return nil
	}
	for _, root := range roots {
		relative, err := directContainerSubpath(root)
		if err != nil {
			return err
		}
		sourcePath := filepath.Join(rootfs, relative)
		if _, err := os.Stat(sourcePath); err != nil {
			return fmt.Errorf("stat action export root %q: %w", sourcePath, err)
		}
		targetPath := filepath.Join(exportRoot, relative)
		if err := os.RemoveAll(targetPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := copyTree(sourcePath, targetPath); err != nil {
			return fmt.Errorf("export %q -> %q: %w", sourcePath, targetPath, err)
		}
	}
	return nil
}

func exportDirectRuntimeRootfsState(rootfs, workPath, metadataBundlePath string) error {
	if strings.TrimSpace(workPath) == "" || strings.TrimSpace(metadataBundlePath) == "" {
		return nil
	}
	paths, err := directRuntimeRootfsStatePaths(filepath.Join(workPath, "dump.log"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	exportRoot := filepath.Join(metadataBundlePath, directRootfsStateDirectoryName)
	if err := os.RemoveAll(exportRoot); err != nil {
		return err
	}
	for _, guestPath := range paths {
		relative, err := directContainerSubpath(guestPath)
		if err != nil {
			return err
		}
		sourcePath := filepath.Join(rootfs, relative)
		info, err := os.Stat(sourcePath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat runtime rootfs state %q: %w", sourcePath, err)
		}
		if !info.Mode().IsRegular() {
			continue
		}
		targetPath := filepath.Join(exportRoot, relative)
		if err := copyFile(sourcePath, targetPath, info.Mode().Perm()); err != nil {
			return fmt.Errorf("export runtime rootfs state %q -> %q: %w", sourcePath, targetPath, err)
		}
	}
	return nil
}

func directRuntimeRootfsStatePaths(dumpLogPath string) ([]string, error) {
	data, err := os.ReadFile(dumpLogPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]struct{}{}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		fd, guestPath, ok := parseDirectDumpedRegularPath(line)
		if !ok || fd < 0 || !shouldExportDirectRuntimeRootfsPath(guestPath) {
			continue
		}
		if _, exists := seen[guestPath]; exists {
			continue
		}
		seen[guestPath] = struct{}{}
		paths = append(paths, guestPath)
	}
	sort.Strings(paths)
	return paths, nil
}

func parseDirectDumpedRegularPath(line string) (int, string, bool) {
	const marker = "Dumping path for "
	idx := strings.Index(line, marker)
	if idx < 0 {
		return 0, "", false
	}
	rest := line[idx+len(marker):]
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return 0, "", false
	}
	fd, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, "", false
	}
	start := strings.LastIndex(line, "[/")
	end := strings.LastIndex(line, "]")
	if start < 0 || end <= start {
		return 0, "", false
	}
	return fd, line[start+1 : end], true
}

func shouldExportDirectRuntimeRootfsPath(path string) bool {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(os.PathSeparator) {
		return false
	}
	staticPrefixes := []string{"/bin", "/boot", "/dev", "/etc", "/home/app", "/lib", "/lib64", "/opt", "/proc", "/run", "/sbin", "/sys", "/usr"}
	for _, prefix := range staticPrefixes {
		if clean == prefix || strings.HasPrefix(clean, prefix+"/") {
			return false
		}
	}
	return true
}

func writeDirectPublication(_ context.Context, req checkpointRequest, placement directDaxPlacement) error {
	publication := req.Publication
	if publication == nil {
		return nil
	}
	publicationPath := trenvpub.NormalizePath(strings.TrimSpace(publication.PublicationPath))
	if publicationPath == "" {
		return errors.New("publication path is empty")
	}
	bundleSize, bundleSHA256, err := digestDirectory(req.MetadataBundlePath)
	if err != nil {
		return err
	}
	record := metadataPublicationRecord{
		Version:                    int(trenvpub.Version),
		ArtifactID:                 placement.CheckpointID,
		CheckpointID:               placement.CheckpointID,
		State:                      "COMMITTED",
		CheckpointPhase:            strings.TrimSpace(publication.CheckpointPhase),
		Fingerprint:                strings.TrimSpace(publication.Fingerprint),
		SnapshotStartMode:          strings.TrimSpace(publication.SnapshotStartMode),
		RuntimeKind:                strings.TrimSpace(publication.RuntimeKind),
		RuntimeFamily:              strings.TrimSpace(publication.RuntimeFamily),
		CheckpointPath:             req.ImagePath,
		MetadataBundlePath:         req.MetadataBundlePath,
		PlacementPath:              filepath.Join(req.MetadataBundlePath, "placement.json"),
		CheckpointActionExportRoot: strings.TrimSpace(publication.CheckpointActionExportRoot),
		MetadataBundleSize:         bundleSize,
		MetadataBundleSHA256:       bundleSHA256,
		WriterID:                   placement.WriterID,
		ShardID:                    placement.ShardID,
		DaxDevice:                  placement.DaxDevice,
		DaxStartPage:               placement.DaxStartPage,
		DaxLengthPages:             placement.DaxLengthPages,
		PageCount:                  placement.PageCount,
		PageSize:                   placement.PageSize,
		Layout:                     placement.Layout,
		Shards: []trenvpub.Shard{{
			WriterID:       placement.WriterID,
			ShardID:        placement.ShardID,
			DaxDevice:      placement.DaxDevice,
			DaxStartPage:   placement.DaxStartPage,
			DaxLengthPages: placement.DaxLengthPages,
			PageCount:      placement.PageCount,
			PageSize:       placement.PageSize,
			Layout:         placement.Layout,
		}},
		CreatedAt: time.Now().UTC(),
	}
	if publication.ActionNamespace != "" || publication.ActionName != "" || publication.ActionRevision != "" {
		record.ActionIdentity = &metadataPublicationActionIdentity{
			Namespace:          strings.TrimSpace(publication.ActionNamespace),
			FullyQualifiedName: strings.TrimSpace(publication.ActionName),
			Revision:           strings.TrimSpace(publication.ActionRevision),
		}
	}
	if filepath.Ext(publicationPath) == trenvpub.Extension {
		return trenvpub.WriteFileNoReplace(publicationPath, publicationRecordToBinary(record))
	}
	return writeDirectJSONFileNoReplace(publicationPath, record)
}

func writeDirectJSONFileNoReplace(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if pathExists(path) {
		return fmt.Errorf("publication metadata already exists at %q", path)
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("publication metadata already exists at %q", path)
		}
		return err
	}
	return nil
}

func directContainerSubpath(root string) (string, error) {
	clean := filepath.Clean(root)
	relative := strings.TrimPrefix(clean, string(os.PathSeparator))
	if relative == "" || relative == "." {
		return "", fmt.Errorf("invalid container path %q", root)
	}
	for _, segment := range strings.Split(relative, string(os.PathSeparator)) {
		if segment == ".." {
			return "", fmt.Errorf("invalid container path %q", root)
		}
	}
	return relative, nil
}
