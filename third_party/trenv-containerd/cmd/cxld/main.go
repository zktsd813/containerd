package main

import (
	"archive/tar"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/trenvpub"
)

const (
	daemonName                        = "cxld"
	defaultSocketPath                 = "/run/" + daemonName + "/" + daemonName + ".sock"
	defaultSchedulerControlSocketPath = "/run/" + daemonName + "-control/" + daemonName + ".sock"
	daemonStateDirectory              = daemonName + "-state"
	// The Unix socket remains a bounded control plane. Larger publication or
	// CRC payloads require a future streaming or SCM_RIGHTS transport rather
	// than increasing one JSON/base64 allocation without bound.
	maxDaemonFrameBytes          = 32 << 20
	daemonLargeFrameThreshold    = 1 << 20
	daemonMaxConcurrentRequests  = 32
	daemonMaxConcurrentLargeBody = 1
	daemonFrameReadTimeout       = 30 * time.Second
	daemonFrameWriteTimeout      = 30 * time.Second
)

var (
	daemonRequestAdmission = make(chan struct{}, daemonMaxConcurrentRequests)
	daemonLargeAdmission   = make(chan struct{}, daemonMaxConcurrentLargeBody)
)

type daemonRequest struct {
	CommandLabel                         string                    `json:"commandLabel"`
	TimeoutMillis                        int64                     `json:"timeoutMillis"`
	Operation                            string                    `json:"operation"`
	CreateContainer                      *createContainerRequest   `json:"createContainer,omitempty"`
	Checkpoint                           *checkpointRequest        `json:"checkpointContainer,omitempty"`
	Restore                              *switchRequest            `json:"restoreIntoContainer,omitempty"`
	Switch                               *switchRequest            `json:"switchIntoCandidate,omitempty"`
	Container                            *containerRequest         `json:"container,omitempty"`
	Cleanup                              *cleanupContainersRequest `json:"cleanupContainers,omitempty"`
	MetadataResolve                      *metadataResolveRequest   `json:"metadataResolve,omitempty"`
	VNextOwnerReserve                    json.RawMessage           `json:"vnextOwnerReserve,omitempty"`
	VNextOwnerIssueProducerCapability    json.RawMessage           `json:"vnextOwnerIssueProducerCapability,omitempty"`
	VNextOwnerCapabilityIssueStatusFence json.RawMessage           `json:"vnextOwnerProducerCapabilityIssueStatusAndFence,omitempty"`
	VNextOwnerRevokeProducerCapability   json.RawMessage           `json:"vnextOwnerRevokeProducerCapability,omitempty"`
	VNextOwnerSeal                       json.RawMessage           `json:"vnextOwnerSeal,omitempty"`
	VNextOwnerProducerAbort              json.RawMessage           `json:"vnextOwnerProducerAbort,omitempty"`
	VNextOwnerCommit                     json.RawMessage           `json:"vnextOwnerCommit,omitempty"`
	VNextOwnerAbort                      json.RawMessage           `json:"vnextOwnerAbort,omitempty"`
	VNextOwnerReclaim                    json.RawMessage           `json:"vnextOwnerReclaim,omitempty"`
	VNextOwnerReclaimStatusAndFence      json.RawMessage           `json:"vnextOwnerReclaimStatusAndFence,omitempty"`
	VNextOwnerInventory                  json.RawMessage           `json:"vnextOwnerInventory,omitempty"`
	VNextOwnerReservationStatus          json.RawMessage           `json:"vnextOwnerReservationStatus,omitempty"`
	VNextOwnerSetAdmission               json.RawMessage           `json:"vnextOwnerSetAdmission,omitempty"`
	VNextOwnerAdmissionStatus            json.RawMessage           `json:"vnextOwnerAdmissionStatus,omitempty"`
}

// A structured checkpoint request is preferred over allowing the invoker to
// execute helper binaries. cxld owns DAX placement, publication commit, and
// action-root export so those host-side decisions stay outside the invoker
// container.
type checkpointRequest struct {
	ImagePath          string                        `json:"imagePath"`
	WorkPath           string                        `json:"workPath"`
	MetadataBundlePath string                        `json:"metadataBundlePath"`
	ActionExportRoots  []string                      `json:"actionExportRoots"`
	ReservationBytes   int64                         `json:"reservationBytes"`
	Publication        *checkpointPublicationRequest `json:"publication,omitempty"`
	ContainerID        string                        `json:"containerId"`
}

type checkpointPublicationRequest struct {
	PublicationPath            string `json:"publicationPath"`
	RuntimeKind                string `json:"runtimeKind,omitempty"`
	RuntimeFamily              string `json:"runtimeFamily,omitempty"`
	ActionNamespace            string `json:"actionNamespace,omitempty"`
	ActionName                 string `json:"actionName,omitempty"`
	ActionRevision             string `json:"actionRevision,omitempty"`
	CheckpointPhase            string `json:"checkpointPhase,omitempty"`
	Fingerprint                string `json:"fingerprint,omitempty"`
	SnapshotStartMode          string `json:"snapshotStartMode,omitempty"`
	CheckpointActionExportRoot string `json:"checkpointActionExportRoot,omitempty"`
}

type switchRequest struct {
	CheckpointPath              string                      `json:"checkpointPath"`
	DaxDevice                   string                      `json:"daxDevice,omitempty"`
	DaxDeviceFallback           string                      `json:"-"`
	ReaderDaxShards             []daxShardConfig            `json:"-"`
	SourceContainer             string                      `json:"sourceContainer,omitempty"`
	ActionSourceRootfs          string                      `json:"actionSourceRootfs,omitempty"`
	ShellID                     string                      `json:"shellId,omitempty"`
	CompatibilityClass          string                      `json:"compatibilityClass,omitempty"`
	ActiveRuntimeKind           string                      `json:"activeRuntimeKind,omitempty"`
	ActiveRuntimeFamily         string                      `json:"activeRuntimeFamily,omitempty"`
	StableActionRoot            string                      `json:"stableActionRoot,omitempty"`
	PseudoMMMaterializationRoot string                      `json:"-"`
	ActionRebinds               []actionRebind              `json:"actionRebinds"`
	NullIO                      bool                        `json:"nullIO"`
	PidFile                     string                      `json:"pidFile,omitempty"`
	ContainerID                 string                      `json:"containerId"`
	PublicationIdentity         *publicationIdentityRequest `json:"publicationIdentity,omitempty"`
}

type publicationIdentityRequest struct {
	PublicationID     string `json:"publicationId"`
	ArtifactID        string `json:"artifactId"`
	Generation        uint64 `json:"generation"`
	WriterID          string `json:"writerId"`
	WriterEpoch       uint64 `json:"writerEpoch"`
	ArtifactTransport string `json:"artifactTransport"`
	ManifestSchema    string `json:"manifestSchema"`
}

type actionRebind struct {
	SourceRoot string `json:"sourceRoot"`
	TargetRoot string `json:"targetRoot"`
}

type execResponse struct {
	Ok             bool             `json:"ok"`
	Stdout         string           `json:"stdout"`
	Stderr         string           `json:"stderr"`
	ExitCode       int              `json:"exitCode"`
	Error          string           `json:"error"`
	ErrorCode      string           `json:"errorCode,omitempty"`
	Operation      string           `json:"operation,omitempty"`
	DurationMicros int64            `json:"durationMicros,omitempty"`
	TimingsMicros  map[string]int64 `json:"timingsMicros,omitempty"`
}

type metadataResolveRequest struct {
	Fingerprint       string `json:"fingerprint"`
	RuntimeKind       string `json:"runtimeKind,omitempty"`
	RuntimeFamily     string `json:"runtimeFamily,omitempty"`
	ActionNamespace   string `json:"actionNamespace,omitempty"`
	ActionName        string `json:"actionName,omitempty"`
	ActionRevision    string `json:"actionRevision,omitempty"`
	ReaderContainer   string `json:"readerContainer"`
	ArtifactTransport string `json:"artifactTransport,omitempty"`
}

type metadataResolveResponse struct {
	Found                      bool   `json:"found"`
	CheckpointID               string `json:"checkpoint_id,omitempty"`
	SnapshotStartMode          string `json:"snapshot_start_mode,omitempty"`
	CheckpointPath             string `json:"checkpoint_path,omitempty"`
	MetadataBundlePath         string `json:"metadata_bundle_path,omitempty"`
	PlacementPath              string `json:"placement_path,omitempty"`
	CheckpointActionExportRoot string `json:"checkpoint_action_export_root,omitempty"`
	PublicationPath            string `json:"publication_path,omitempty"`
	Fingerprint                string `json:"fingerprint,omitempty"`
	Source                     string `json:"source,omitempty"`
	CreatedAt                  string `json:"created_at,omitempty"`
	ArtifactTransport          string `json:"artifact_transport,omitempty"`
	PublicationID              string `json:"publication_id,omitempty"`
	ArtifactID                 string `json:"artifact_id,omitempty"`
	ManifestSchema             string `json:"manifest_schema,omitempty"`
	Generation                 uint64 `json:"generation,omitempty"`
	WriterID                   string `json:"writer_id,omitempty"`
	WriterEpoch                uint64 `json:"writer_epoch,omitempty"`
}

type metadataPublicationActionIdentity struct {
	Namespace          string `json:"namespace"`
	FullyQualifiedName string `json:"fully_qualified_name"`
	Revision           string `json:"revision"`
}

type metadataPublicationRecord struct {
	Version                    int                                `json:"version"`
	ArtifactID                 string                             `json:"artifact_id"`
	CheckpointID               string                             `json:"checkpoint_id"`
	ManifestSchema             string                             `json:"manifest_schema,omitempty"`
	DedupApplySchema           string                             `json:"dedup_apply_schema,omitempty"`
	Generation                 uint64                             `json:"generation,omitempty"`
	WriterEpoch                uint64                             `json:"writer_epoch,omitempty"`
	State                      string                             `json:"state"`
	CheckpointPhase            string                             `json:"checkpoint_phase,omitempty"`
	Fingerprint                string                             `json:"fingerprint,omitempty"`
	SnapshotStartMode          string                             `json:"snapshot_start_mode,omitempty"`
	RuntimeKind                string                             `json:"runtime_kind,omitempty"`
	RuntimeFamily              string                             `json:"runtime_family,omitempty"`
	ActionIdentity             *metadataPublicationActionIdentity `json:"action_identity,omitempty"`
	CheckpointPath             string                             `json:"checkpoint_path,omitempty"`
	MetadataBundlePath         string                             `json:"metadata_bundle_path,omitempty"`
	PlacementPath              string                             `json:"placement_path,omitempty"`
	CheckpointActionExportRoot string                             `json:"checkpoint_action_export_root,omitempty"`
	MetadataBundleSize         int64                              `json:"metadata_bundle_size"`
	WriterID                   string                             `json:"writer_id"`
	ShardID                    string                             `json:"shard_id"`
	DaxDevice                  string                             `json:"dax_device,omitempty"`
	DaxStartPage               int64                              `json:"dax_start_page"`
	DaxLengthPages             int64                              `json:"dax_length_pages"`
	PageCount                  int64                              `json:"page_count"`
	PageSize                   int64                              `json:"page_size"`
	Layout                     string                             `json:"layout"`
	PageExtent                 trenvpub.StorageExtent             `json:"page_extent,omitempty"`
	ArtifactExtent             trenvpub.StorageExtent             `json:"artifact_extent,omitempty"`
	Files                      []trenvpub.ArtifactFile            `json:"files,omitempty"`
	Shards                     []trenvpub.Shard                   `json:"shards,omitempty"`
	BaseRestoreMap             []trenvpub.RestoreExtent           `json:"base_restore_map,omitempty"`
	Stats                      trenvpub.Stats                     `json:"stats,omitempty"`
	CreatedAt                  time.Time                          `json:"created_at"`
	PublicationPath            string                             `json:"-"`
	PeerURL                    string                             `json:"-"`
}

type daemonConfig struct {
	WriterID                    string
	WriterEpoch                 uint64
	WriterStateRoot             string
	DaxDevice                   string
	ShardID                     string
	DaxShards                   []daxShardConfig
	ArtifactDaxShards           []daxShardConfig
	ReaderDaxShards             []daxShardConfig
	ReaderArtifactDaxShards     []daxShardConfig
	DaxPlacementPolicy          string
	ArtifactTransport           string
	CheckpointWriterDisabled    bool
	WorkingDirectory            string
	MetadataListen              string
	MetadataPeers               []string
	PseudoMMMaterializationRoot string
	DedupCheckpointMode         string
	DedupTimeout                time.Duration
	DedupDedupdBinary           string
	DedupPublicationBinary      string
	DedupExecution              string
	DedupOutputDirectory        string
	DedupMinPages               uint64
}

type daxShardConfig struct {
	ShardID   string
	DaxDevice string
}

func (d daxShardConfig) String() string {
	if d.ShardID == "" {
		return d.DaxDevice
	}
	return d.ShardID + "=" + d.DaxDevice
}

var activeConfig daemonConfig

func writeFrame(conn net.Conn, payload []byte) error {
	if len(payload) > maxDaemonFrameBytes {
		return fmt.Errorf(
			"frame is %d bytes, maximum is %d", len(payload), maxDaemonFrameBytes)
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))
	if err := writeConnFull(conn, header); err != nil {
		return err
	}
	return writeConnFull(conn, payload)
}

func writeConnFull(conn net.Conn, payload []byte) error {
	for len(payload) != 0 {
		written, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(payload) {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header)
	if size > maxDaemonFrameBytes {
		return nil, fmt.Errorf(
			"request frame is %d bytes, maximum is %d", size, maxDaemonFrameBytes)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// readDaemonRequestFrame acquires the single large-frame budget before it
// allocates the request body. The returned release function must remain held
// through JSON decoding and dispatch because those phases retain the body and
// decoded base64 byte slices at the same time.
func readDaemonRequestFrame(
	conn net.Conn,
	largeAdmission chan struct{},
	readTimeout time.Duration,
) ([]byte, func(), error) {
	release := func() {}
	if readTimeout <= 0 {
		return nil, release, errors.New("daemon request read timeout must be positive")
	}
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, release, fmt.Errorf("set request read deadline: %w", err)
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, release, err
	}
	size := binary.BigEndian.Uint32(header)
	if size > maxDaemonFrameBytes {
		return nil, release, fmt.Errorf(
			"request frame is %d bytes, maximum is %d", size, maxDaemonFrameBytes)
	}
	acquiredLarge := false
	if size > daemonLargeFrameThreshold {
		timer := time.NewTimer(readTimeout)
		defer timer.Stop()
		select {
		case largeAdmission <- struct{}{}:
			acquiredLarge = true
		case <-timer.C:
			return nil, release, errors.New("timed out waiting for the large-request memory budget")
		}
	}
	if acquiredLarge {
		release = func() { <-largeAdmission }
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(conn, body); err != nil {
		release()
		return nil, func() {}, err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		release()
		return nil, func() {}, fmt.Errorf("clear request read deadline: %w", err)
	}
	return body, release, nil
}

func writeDaemonResponse(conn net.Conn, payload []byte) {
	if len(payload) > maxDaemonFrameBytes {
		payload, _ = json.Marshal(execResponse{
			Ok:        false,
			Error:     "daemon response exceeds the bounded control-frame contract",
			ErrorCode: string(vnextOwnerServiceUnavailable),
		})
	}
	_ = writeFrame(conn, payload)
}

func runCommand(req daemonRequest) execResponse {
	return runCommandWithVNextOwnerGatewayCaller(
		req, activeVNextOwnerRPC, activeVNextOwnerGateway,
		vnextOwnerInternalCaller(vnextOwnerCallerProducer))
}

func runCommandWithVNextOwnerRPCRole(
	req daemonRequest,
	vnextOwnerRPC *vnextOwnerRPC,
	callerRole vnextOwnerCallerRole,
) (resp execResponse) {
	return runCommandWithVNextOwnerRPCCaller(
		req, vnextOwnerRPC, vnextOwnerInternalCaller(callerRole))
}

func runCommandWithVNextOwnerRPCCaller(
	req daemonRequest,
	vnextOwnerRPC *vnextOwnerRPC,
	caller vnextOwnerCallerContext,
) execResponse {
	return runCommandWithVNextOwnerBoundaryCaller(
		req, vnextOwnerRPC, vnextOwnerRPC != nil, caller)
}

func runCommandWithVNextOwnerBoundaryCaller(
	req daemonRequest,
	vnextOwnerRPC *vnextOwnerRPC,
	vnextOwnerActive bool,
	caller vnextOwnerCallerContext,
) (resp execResponse) {
	startedAt := time.Now()
	operation := daemonRequestOperation(req)
	defer func() {
		resp.Operation = operation
		resp.DurationMicros = elapsedMicros(startedAt)
	}()
	if err := caller.validate(); err != nil {
		return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
			operation, vnextOwnerServicePermissionDenied,
			"daemon caller principal is not authenticated", err))
	}
	if err := authorizeDaemonOperation(caller.Role, operation); err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	if vnextOwnerActive && vnextOwnerRejectsLegacyDAXOperation(operation) {
		return execResponse{
			Ok: false,
			Error: fmt.Sprintf(
				"legacy operation %q is disabled while the strict VNext Owner is active",
				operation),
			ErrorCode: string(vnextOwnerServicePublicationIncompatible),
		}
	}

	switch operation {
	case "createContainer":
		if req.CreateContainer == nil {
			return execResponse{Ok: false, Error: "createContainer operation requires createContainer request"}
		}
		return runCreateContainerRequest(*req.CreateContainer, req.TimeoutMillis, activeConfig)
	case "checkpointContainer":
		if req.Checkpoint != nil {
			return runDirectCheckpointRequest(*req.Checkpoint, req.TimeoutMillis, activeConfig)
		}
		return execResponse{Ok: false, Error: "checkpointContainer operation requires checkpointContainer request"}
	case "restoreIntoContainer":
		if req.Restore == nil {
			return execResponse{Ok: false, Error: "restoreIntoContainer operation requires restoreIntoContainer request"}
		}
		return runDirectRestoreRequest(*req.Restore, req.TimeoutMillis, activeConfig)
	case "switchIntoCandidate":
		if req.Switch == nil {
			return execResponse{Ok: false, Error: "switchIntoCandidate operation requires switchIntoCandidate request"}
		}
		return runDirectSwitchRequest(*req.Switch, req.TimeoutMillis, activeConfig)
	case "pauseContainer", "resumeContainer", "removeContainer":
		if req.Container == nil {
			return execResponse{Ok: false, Error: fmt.Sprintf("%s operation requires container request", operation)}
		}
		return runContainerLifecycleRequest(operation, *req.Container, req.TimeoutMillis, activeConfig)
	case "cleanupContainers":
		if req.Cleanup == nil {
			return execResponse{Ok: false, Error: "cleanupContainers operation requires cleanupContainers request"}
		}
		return runCleanupContainersRequest(*req.Cleanup, req.TimeoutMillis, activeConfig)
	case "metadataResolve":
		if req.MetadataResolve == nil {
			return execResponse{Ok: false, Error: "metadataResolve operation requires metadataResolve request"}
		}
		return runMetadataResolveRequest(*req.MetadataResolve, req.TimeoutMillis, activeConfig)
	case vnextOwnerRPCOperationReserve,
		vnextOwnerRPCOperationIssueProducerCapability,
		vnextOwnerRPCOperationProducerCapabilityIssueStatusAndFence,
		vnextOwnerRPCOperationRevokeProducerCapability,
		vnextOwnerRPCOperationSeal,
		vnextOwnerRPCOperationProducerAbort,
		vnextOwnerRPCOperationCommit,
		vnextOwnerRPCOperationAbort,
		vnextOwnerRPCOperationReclaim,
		vnextOwnerRPCOperationReclaimStatusAndFence,
		vnextOwnerRPCOperationInventory,
		vnextOwnerRPCOperationReservationStatus,
		vnextOwnerRPCOperationSetAdmission,
		vnextOwnerRPCOperationAdmissionStatus:
		return runVNextOwnerRPC(operation, req, vnextOwnerRPC, caller)
	case "":
		return execResponse{Ok: false, Error: "operation is empty"}
	default:
		return execResponse{Ok: false, Error: fmt.Sprintf("unsupported operation %q", operation)}
	}
}

func daemonRequestOperation(req daemonRequest) string {
	operation := strings.TrimSpace(req.Operation)
	if operation == "" && req.CreateContainer != nil {
		operation = "createContainer"
	}
	if operation == "" && req.Checkpoint != nil {
		operation = "checkpointContainer"
	}
	if operation == "" && req.Restore != nil {
		operation = "restoreIntoContainer"
	}
	if operation == "" && req.Switch != nil {
		operation = "switchIntoCandidate"
	}
	if operation == "" && req.Container != nil {
		operation = "container"
	}
	if operation == "" && req.Cleanup != nil {
		operation = "cleanupContainers"
	}
	return operation
}

func vnextOwnerRejectsLegacyDAXOperation(operation string) bool {
	switch operation {
	case "checkpointContainer",
		"restoreIntoContainer",
		"switchIntoCandidate",
		"metadataResolve":
		return true
	default:
		return false
	}
}

func runMetadataResolveRequest(req metadataResolveRequest, timeoutMillis int64, config daemonConfig) execResponse {
	timeout := time.Duration(timeoutMillis) * time.Millisecond
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	result, err := resolveMetadata(ctx, req, config)
	if err != nil {
		response := execResponse{Ok: false, Error: err.Error()}
		var rejection *dedupMetadataRejectionError
		if errors.As(err, &rejection) {
			response.ErrorCode = rejection.Code
		}
		return response
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return execResponse{Ok: false, Error: err.Error()}
	}
	return execResponse{Ok: true, Stdout: string(payload) + "\n"}
}

func resolveMetadata(ctx context.Context, req metadataResolveRequest, config daemonConfig) (metadataResolveResponse, error) {
	fingerprint := strings.TrimSpace(req.Fingerprint)
	if fingerprint == "" {
		return metadataResolveResponse{}, errors.New("metadata resolve fingerprint is empty")
	}
	readerContainer := strings.TrimSpace(req.ReaderContainer)
	if readerContainer == "" {
		return metadataResolveResponse{}, errors.New("metadata resolve reader container is empty")
	}
	transport := strings.TrimSpace(config.ArtifactTransport)
	requestedTransport := strings.TrimSpace(req.ArtifactTransport)
	if requestedTransport != "" {
		if transport != "" && requestedTransport != transport {
			return metadataResolveResponse{}, fmt.Errorf("requested artifact transport %q does not match daemon transport %q", requestedTransport, transport)
		}
		transport = requestedTransport
	}

	publications, err := fetchPeerPublications(ctx, config.MetadataPeers, fingerprint)
	if err != nil {
		return metadataResolveResponse{}, err
	}
	outcomes, err := fetchPeerDedupOutcomes(ctx, config.MetadataPeers, fingerprint)
	if err != nil {
		return metadataResolveResponse{}, err
	}
	sort.Slice(publications, func(i, j int) bool {
		return publicationLess(publications[i], publications[j])
	})
	sort.Slice(outcomes, func(i, j int) bool {
		return dedupOutcomeLess(outcomes[i], outcomes[j])
	})
	if len(outcomes) > 0 {
		latestOutcome := outcomes[len(outcomes)-1]
		outcomeIsCurrent :=
			len(publications) == 0 || !dedupOutcomeOlderThanPublication(latestOutcome, publications[len(publications)-1])
		code := ""
		message := ""
		if outcomeIsCurrent {
			switch latestOutcome.State {
			case "REJECTED":
				code = nonEmptyOrDefault(latestOutcome.ErrorCode, "dedup_publication_rejected")
				message = nonEmptyOrDefault(latestOutcome.Error, latestOutcome.Reason)
			case "RUNNING":
				code = "dedup_publication_pending"
				message = "required checkpoint dedup has not reached a terminal publication"
			case "PUBLISHED":
				if !dedupOutcomeHasPublication(latestOutcome, publications) {
					code = "dedup_publication_missing"
					message = "durable outcome is PUBLISHED but the derived publication is missing"
				}
			}
		}
		if code != "" {
			return metadataResolveResponse{}, &dedupMetadataRejectionError{
				Code: code,
				Message: fmt.Sprintf(
					"required dedup publication unavailable for checkpoint %q: %s",
					latestOutcome.CheckpointID,
					message),
			}
		}
	}
	if len(publications) == 0 {
		return metadataResolveResponse{Found: false}, nil
	}
	selected := publications[len(publications)-1]
	readerRoot := ""
	source := "publication-reader-network"
	if transport == "" {
		if selected.Version >= int(trenvpub.Version) {
			transport = "dax-manifest"
		} else {
			transport = "legacy-tar"
		}
	}
	if transport == "dax-manifest" {
		if selected.Version < int(trenvpub.Version) {
			return metadataResolveResponse{}, fmt.Errorf("publication version %d cannot use dax-manifest transport", selected.Version)
		}
		readerRoot, err = materializeDaxArtifact(selected, readerContainer, config)
		source = "publication-reader-dax-manifest"
	} else if transport == "legacy-tar" {
		readerRoot, err = materializePeerArtifact(ctx, selected, readerContainer, config)
	} else {
		return metadataResolveResponse{}, fmt.Errorf("unsupported artifact transport %q", transport)
	}
	if err != nil {
		return metadataResolveResponse{}, err
	}

	metadataBundlePath := filepath.Join(readerRoot, "metadata-bundle")
	checkpointPath := filepath.Join(metadataBundlePath, "image")
	placementPath := filepath.Join(metadataBundlePath, "placement.json")
	actionRoot := filepath.Join(readerRoot, "action-root")
	if !isDirectory(actionRoot) {
		actionRoot = ""
	}
	publicationPath := filepath.Join(readerRoot, "publication.reader"+trenvpub.Extension)
	manifestSchema := ""
	if transport == "dax-manifest" {
		manifestSchema = directDaxManifestSchema
	}

	return metadataResolveResponse{
		Found:                      true,
		CheckpointID:               selected.CheckpointID,
		SnapshotStartMode:          nonEmptyOrDefault(selected.SnapshotStartMode, "restore"),
		CheckpointPath:             checkpointPath,
		MetadataBundlePath:         metadataBundlePath,
		PlacementPath:              placementPath,
		CheckpointActionExportRoot: actionRoot,
		PublicationPath:            publicationPath,
		Fingerprint:                selected.Fingerprint,
		Source:                     source,
		CreatedAt:                  selected.CreatedAt.Format(time.RFC3339Nano),
		ArtifactTransport:          transport,
		PublicationID:              selected.CheckpointID,
		ArtifactID:                 selected.ArtifactID,
		ManifestSchema:             manifestSchema,
		Generation:                 selected.Generation,
		WriterID:                   selected.WriterID,
		WriterEpoch:                selected.WriterEpoch,
	}, nil
}

func fetchPeerPublications(ctx context.Context, peers []string, fingerprint string) ([]metadataPublicationRecord, error) {
	normalizedPeers := normalizePeerURLs(peers)
	if len(normalizedPeers) == 0 {
		return nil, nil
	}
	var results []metadataPublicationRecord
	var failures []string
	client := &http.Client{}
	for _, peer := range normalizedPeers {
		endpoint := peer + "/v1/publications?fingerprint=" + url.QueryEscape(fingerprint)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", peer, err))
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				if code := strings.TrimSpace(resp.Header.Get("X-Cxld-Error-Code")); strings.HasPrefix(code, "dedup_") {
					failures = append(failures, fmt.Sprintf("%s: %s", peer, code))
					return
				}
				failures = append(failures, fmt.Sprintf("%s: status %s", peer, resp.Status))
				return
			}
			var publications []metadataPublicationRecord
			if err := json.NewDecoder(resp.Body).Decode(&publications); err != nil {
				failures = append(failures, fmt.Sprintf("%s: dedup_publication_invalid: decode publications: %v", peer, err))
				return
			}
			for _, publication := range publications {
				if publication.State == "COMMITTED" && publication.Fingerprint == fingerprint {
					publication.PeerURL = peer
					results = append(results, publication)
				}
			}
		}()
	}
	if len(failures) > 0 {
		message := fmt.Sprintf("metadata publication fetch failed: %s", strings.Join(failures, "; "))
		for _, failure := range failures {
			if strings.Contains(failure, "dedup_publication_invalid") {
				return nil, &dedupMetadataRejectionError{
					Code:    "dedup_publication_invalid",
					Message: message,
				}
			}
		}
		if len(results) == 0 {
			return nil, errors.New(message)
		}
	}
	return results, nil
}

func fetchPeerDedupOutcomes(ctx context.Context, peers []string, fingerprint string) ([]dedupRunStatus, error) {
	normalizedPeers := normalizePeerURLs(peers)
	if len(normalizedPeers) == 0 {
		return nil, nil
	}
	var results []dedupRunStatus
	var failures []string
	client := &http.Client{}
	for _, peer := range normalizedPeers {
		endpoint := peer + "/v1/dedup-outcomes?fingerprint=" + url.QueryEscape(fingerprint)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", peer, err))
			continue
		}
		func() {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
				return
			}
			if resp.StatusCode != http.StatusOK {
				failures = append(failures, fmt.Sprintf("%s: status %s", peer, resp.Status))
				return
			}
			var outcomes []dedupRunStatus
			if err := json.NewDecoder(resp.Body).Decode(&outcomes); err != nil {
				failures = append(failures, fmt.Sprintf("%s: decode dedup outcomes: %v", peer, err))
				return
			}
			for _, outcome := range outcomes {
				if outcome.Fingerprint == fingerprint {
					results = append(results, outcome)
				}
			}
		}()
	}
	if len(results) == 0 && len(failures) > 0 {
		return nil, fmt.Errorf("metadata dedup outcome fetch failed: %s", strings.Join(failures, "; "))
	}
	return results, nil
}

func dedupOutcomeLess(a, b dedupRunStatus) bool {
	if a.WriterID != b.WriterID {
		return dedupOutcomeEventTime(a).Before(dedupOutcomeEventTime(b))
	}
	if a.WriterEpoch != b.WriterEpoch {
		return a.WriterEpoch < b.WriterEpoch
	}
	if a.Generation != b.Generation {
		return a.Generation < b.Generation
	}
	return a.FinishedAt.Before(b.FinishedAt)
}

func dedupOutcomeOlderThanPublication(outcome dedupRunStatus, publication metadataPublicationRecord) bool {
	if outcome.WriterID != publication.WriterID {
		return dedupOutcomeEventTime(outcome).Before(publication.CreatedAt)
	}
	if outcome.WriterEpoch != publication.WriterEpoch {
		return outcome.WriterEpoch < publication.WriterEpoch
	}
	if outcome.Generation != publication.Generation {
		return outcome.Generation < publication.Generation
	}
	return dedupOutcomeEventTime(outcome).Before(publication.CreatedAt)
}

func dedupOutcomeEventTime(outcome dedupRunStatus) time.Time {
	if !outcome.FinishedAt.IsZero() {
		return outcome.FinishedAt
	}
	return outcome.StartedAt
}

func dedupOutcomeHasPublication(outcome dedupRunStatus, publications []metadataPublicationRecord) bool {
	for _, publication := range publications {
		if publication.CheckpointID == outcome.CheckpointID &&
			publication.Fingerprint == outcome.Fingerprint &&
			publication.Generation == outcome.Generation &&
			publication.WriterID == outcome.WriterID &&
			publication.WriterEpoch == outcome.WriterEpoch &&
			publicationHasDedup(publication) {
			return true
		}
	}
	return false
}

func materializePeerArtifact(ctx context.Context, publication metadataPublicationRecord, readerContainer string, config daemonConfig) (string, error) {
	if strings.TrimSpace(publication.PeerURL) == "" {
		return "", errors.New("selected publication is missing peer URL")
	}
	checkpointID := strings.TrimSpace(publication.CheckpointID)
	if checkpointID == "" {
		return "", errors.New("selected publication is missing checkpoint id")
	}
	cacheRoot := filepath.Join(config.WorkingDirectory, "reader-cache", publicationCacheKey(publication))
	cacheCommitted := filepath.Join(cacheRoot, "COMMITTED")
	if isRegularFile(cacheCommitted) {
		if err := materializeRestoreState(cacheRoot, checkpointID, readerContainer, publication, config); err != nil {
			return "", err
		}
		return filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(checkpointID)), nil
	}

	if err := os.MkdirAll(filepath.Join(config.WorkingDirectory, "reader-cache"), 0o755); err != nil {
		return "", err
	}
	stageRoot, err := os.MkdirTemp(filepath.Join(config.WorkingDirectory, "reader-cache"), publicationCacheKey(publication)+".tmp.")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(stageRoot)

	if err := fetchArtifactTar(ctx, publication, stageRoot); err != nil {
		return "", err
	}
	if err := validateMaterializedArtifact(stageRoot, publication); err != nil {
		return "", err
	}
	// Commit by rename after validation so readers never observe a partially
	// extracted metadata bundle or action-root.
	if err := os.RemoveAll(cacheRoot); err != nil {
		return "", err
	}
	if err := os.Rename(stageRoot, cacheRoot); err != nil {
		return "", err
	}
	if err := writeReaderPublication(cacheRoot, publication); err != nil {
		return "", err
	}
	if err := os.WriteFile(filepath.Join(cacheRoot, "COMMITTED"), []byte(time.Now().UTC().Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
		return "", err
	}
	if err := materializeRestoreState(cacheRoot, checkpointID, readerContainer, publication, config); err != nil {
		return "", err
	}
	return filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(checkpointID)), nil
}

func publicationCacheKey(publication metadataPublicationRecord) string {
	key := strings.TrimSpace(publication.ArtifactID)
	if key == "" {
		key = strings.TrimSpace(publication.CheckpointID)
	}
	return sanitizePathPart(key)
}

func fetchArtifactTar(ctx context.Context, publication metadataPublicationRecord, target string) error {
	artifactID := strings.TrimSpace(publication.CheckpointID)
	if artifactID == "" {
		return errors.New("publication checkpoint id is empty")
	}
	endpoint := publication.PeerURL + "/v1/artifacts/" + url.PathEscape(artifactID) + ".tar"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch artifact %q failed: status %s", artifactID, resp.Status)
	}
	return extractTar(resp.Body, target)
}

func validateMaterializedArtifact(root string, publication metadataPublicationRecord) error {
	bundlePath := filepath.Join(root, "metadata-bundle")
	if !isDirectory(filepath.Join(bundlePath, "image")) {
		return errors.New("metadata bundle image directory is missing")
	}
	if !isRegularFile(filepath.Join(bundlePath, "bundle.json")) {
		return errors.New("metadata bundle manifest is missing")
	}
	if !isRegularFile(filepath.Join(bundlePath, "placement.json")) {
		return errors.New("metadata bundle placement is missing")
	}
	return nil
}

func materializeRestoreState(cacheRoot, checkpointID, readerContainer string, publication metadataPublicationRecord, config daemonConfig) error {
	restoreRoot := filepath.Join(config.WorkingDirectory, "restore", sanitizePathPart(readerContainer), sanitizePathPart(checkpointID))
	if err := os.RemoveAll(restoreRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(restoreRoot, 0o755); err != nil {
		return err
	}
	if err := copyTree(filepath.Join(cacheRoot, "metadata-bundle"), filepath.Join(restoreRoot, "metadata-bundle")); err != nil {
		return err
	}
	actionRoot := filepath.Join(cacheRoot, "action-root")
	if isDirectory(actionRoot) {
		// The restore workdir is target-private. Metadata and action-root are
		// copied out of the immutable cache so CRIU logs and action writes do
		// not mutate the cached publication artifact.
		if err := copyTree(actionRoot, filepath.Join(restoreRoot, "action-root")); err != nil {
			return err
		}
	}
	return writeReaderPublication(restoreRoot, publication)
}

func writeReaderPublication(root string, publication metadataPublicationRecord) error {
	record := publication
	record.CheckpointPath = filepath.Join(root, "metadata-bundle", "image")
	record.MetadataBundlePath = filepath.Join(root, "metadata-bundle")
	record.PlacementPath = filepath.Join(root, "metadata-bundle", "placement.json")
	actionRoot := filepath.Join(root, "action-root")
	if isDirectory(actionRoot) {
		record.CheckpointActionExportRoot = actionRoot
	} else {
		record.CheckpointActionExportRoot = ""
	}
	return trenvpub.WriteFileNoReplace(filepath.Join(root, "publication.reader"+trenvpub.Extension), publicationRecordToBinary(record))
}

func elapsedMicros(startedAt time.Time) int64 {
	elapsed := time.Since(startedAt).Microseconds()
	if elapsed < 0 {
		return 0
	}
	return elapsed
}

func defaultWriterID() string {
	if hostname, err := os.Hostname(); err == nil && strings.TrimSpace(hostname) != "" {
		return hostname
	}
	return "unknown-writer"
}

func checkpointID(imagePath string) string {
	return filepath.Base(filepath.Dir(filepath.Clean(imagePath)))
}

func detectDaxDevice() (string, error) {
	matches, err := filepath.Glob("/dev/dax*.0")
	if err != nil {
		return "", err
	}
	sort.Strings(matches)
	for _, match := range matches {
		if stat, err := os.Stat(match); err == nil && stat.Mode()&os.ModeDevice != 0 {
			return match, nil
		}
	}
	return "", errors.New("no usable /dev/dax*.0 device found")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func isDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func nonEmptyOrDefault(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func sanitizePathPart(value string) string {
	var builder strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	if builder.Len() == 0 {
		return "unknown"
	}
	return builder.String()
}

func normalizePeerURLs(peers []string) []string {
	var normalized []string
	seen := map[string]bool{}
	for _, peer := range peers {
		trimmed := strings.TrimRight(strings.TrimSpace(peer), "/")
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
			trimmed = "http://" + trimmed
		}
		if !seen[trimmed] {
			seen[trimmed] = true
			normalized = append(normalized, trimmed)
		}
	}
	return normalized
}

func splitCommaList(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func parseDaxShardConfig(value string) (daxShardConfig, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return daxShardConfig{}, errors.New("empty DAX shard")
	}
	shardID, daxDevice, ok := strings.Cut(trimmed, "=")
	if !ok {
		daxDevice = trimmed
		shardID = filepath.Base(daxDevice)
	}
	return normalizeDaxShardConfig(daxShardConfig{
		ShardID:   shardID,
		DaxDevice: daxDevice,
	})
}

func parseDaxShardConfigList(value string) ([]daxShardConfig, error) {
	var shards []daxShardConfig
	for _, item := range splitCommaList(value) {
		shard, err := parseDaxShardConfig(item)
		if err != nil {
			return nil, err
		}
		shards = append(shards, shard)
	}
	if err := rejectDuplicateDaxShardConfig(shards); err != nil {
		return nil, err
	}
	return shards, nil
}

func normalizeDaxShardConfig(shard daxShardConfig) (daxShardConfig, error) {
	shardID := strings.TrimSpace(shard.ShardID)
	daxDevice := strings.TrimSpace(shard.DaxDevice)
	if daxDevice == "" {
		return daxShardConfig{}, errors.New("DAX shard device is empty")
	}
	if shardID == "" {
		shardID = filepath.Base(daxDevice)
	}
	if shardID == "." || shardID == string(os.PathSeparator) {
		return daxShardConfig{}, fmt.Errorf("invalid DAX shard id %q", shardID)
	}
	return daxShardConfig{ShardID: shardID, DaxDevice: daxDevice}, nil
}

func rejectDuplicateDaxShardConfig(shards []daxShardConfig) error {
	seenShardIDs := map[string]bool{}
	seenDevices := map[string]bool{}
	for _, shard := range shards {
		normalized, err := normalizeDaxShardConfig(shard)
		if err != nil {
			return err
		}
		if seenShardIDs[normalized.ShardID] {
			return fmt.Errorf("duplicate DAX shard id %q", normalized.ShardID)
		}
		if seenDevices[normalized.DaxDevice] {
			return fmt.Errorf("duplicate DAX device %q", normalized.DaxDevice)
		}
		seenShardIDs[normalized.ShardID] = true
		seenDevices[normalized.DaxDevice] = true
	}
	return nil
}

func envDefault(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envExactDefault(name, fallback string) string {
	if value, configured := os.LookupEnv(name); configured {
		return value
	}
	return fallback
}

func envDefaultBool(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid boolean %s=%q, using %v\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func envDefaultDuration(name string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid duration %s=%q, using %s\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func envDefaultUint64(name string, fallback uint64) uint64 {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid uint64 %s=%q, using %d\n", name, value, fallback)
		return fallback
	}
	return parsed
}

func envStrictInt64(name string, fallback int64) (int64, error) {
	value, configured := os.LookupEnv(name)
	if !configured {
		return fallback, nil
	}
	if value == "" || strings.TrimSpace(value) != value {
		return 0, fmt.Errorf("%s is empty or has surrounding whitespace", name)
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s=%q as int64: %w", name, value, err)
	}
	return parsed, nil
}

func safeJoin(root, name string) (string, error) {
	separator := string(os.PathSeparator)
	cleanName := filepath.Clean(strings.TrimPrefix(name, separator))
	if cleanName == "." || strings.HasPrefix(cleanName, ".."+separator) || cleanName == ".." || filepath.IsAbs(cleanName) {
		return "", fmt.Errorf("unsafe archive path %q", name)
	}
	target := filepath.Join(root, cleanName)
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	cleanTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if cleanTarget != cleanRoot && !strings.HasPrefix(cleanTarget, cleanRoot+separator) {
		return "", fmt.Errorf("archive path escapes target root: %q", name)
	}
	return target, nil
}

func copyFile(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyTree(source, target string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		linkTarget, err := os.Readlink(source)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return os.Symlink(linkTarget, target)
	}
	if !info.IsDir() {
		return copyFile(source, target, info.Mode().Perm())
	}
	return filepath.Walk(source, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		targetPath := target
		if relative != "." {
			targetPath = filepath.Join(target, relative)
		}
		if info.IsDir() {
			return os.MkdirAll(targetPath, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return err
			}
			// Preserve action-root symlinks, especially Python virtualenv links.
			// Dereferencing them would copy host/runtime targets into the
			// publication and change action filesystem semantics.
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
				return err
			}
			if _, err := os.Lstat(targetPath); err == nil {
				return fmt.Errorf("copy target already exists: %s", targetPath)
			} else if !os.IsNotExist(err) {
				return err
			}
			return os.Symlink(linkTarget, targetPath)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, targetPath, info.Mode().Perm())
	})
}

func directoryRegularFileSize(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info == nil || info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return total, nil
}

func writeJSONFile(path string, value interface{}) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o644); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

type dedupRunStatus struct {
	CheckpointID       string    `json:"checkpoint_id"`
	ArtifactID         string    `json:"artifact_id"`
	Fingerprint        string    `json:"fingerprint"`
	Generation         uint64    `json:"generation"`
	WriterID           string    `json:"writer_id"`
	WriterEpoch        uint64    `json:"writer_epoch"`
	BasePublication    string    `json:"base_publication"`
	DerivedPublication string    `json:"derived_publication,omitempty"`
	CheckpointPath     string    `json:"checkpoint_path"`
	State              string    `json:"state"`
	Reason             string    `json:"reason,omitempty"`
	ErrorCode          string    `json:"error_code,omitempty"`
	Error              string    `json:"error,omitempty"`
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
}

type dedupMetadataRejectionError struct {
	Code    string
	Message string
}

func (e *dedupMetadataRejectionError) Error() string {
	return e.Message
}

func normalizeDedupConfig(config daemonConfig) daemonConfig {
	config.DedupCheckpointMode = strings.ToLower(strings.TrimSpace(config.DedupCheckpointMode))
	if config.DedupCheckpointMode == "" {
		config.DedupCheckpointMode = "off"
	}
	if strings.TrimSpace(config.DedupDedupdBinary) == "" {
		config.DedupDedupdBinary = "dedupd"
	}
	if strings.TrimSpace(config.DedupPublicationBinary) == "" {
		config.DedupPublicationBinary = "trenv-dedup-pub"
	}
	if strings.TrimSpace(config.DedupExecution) == "" {
		config.DedupExecution = "cpu"
	}
	if strings.TrimSpace(config.DedupOutputDirectory) == "" {
		config.DedupOutputDirectory = filepath.Join(config.WorkingDirectory, "dedup")
	}
	if config.DedupTimeout <= 0 {
		config.DedupTimeout = 15 * time.Minute
	}
	if config.DedupMinPages == 0 {
		config.DedupMinPages = 1
	}
	return config
}

func runDedupPublication(
	ctx context.Context,
	config daemonConfig,
	publication metadataPublicationRecord,
	reason string,
	derivedPath string,
) error {
	startedAt := time.Now().UTC()
	reject := func(code, message string) error {
		statusErr := writeDedupStatus(config, publication, dedupRunStatus{
			State:              "REJECTED",
			Reason:             reason,
			ErrorCode:          code,
			Error:              message,
			CheckpointPath:     publication.CheckpointPath,
			DerivedPublication: derivedPath,
			StartedAt:          startedAt,
			FinishedAt:         time.Now().UTC(),
		})
		if statusErr != nil {
			return fmt.Errorf("%s: %s (write rejection status: %v)", code, message, statusErr)
		}
		return fmt.Errorf("%s: %s", code, message)
	}
	workRoot := filepath.Join(dedupWorkDirectory(config), sanitizePathPart(publication.ArtifactID))
	if err := os.RemoveAll(workRoot); err != nil {
		return reject("dedup_workdir_failed", err.Error())
	}
	if err := os.MkdirAll(workRoot, 0o755); err != nil {
		return reject("dedup_workdir_failed", err.Error())
	}

	ledgerPath := filepath.Join(workRoot, "checkpoint-ledger.bin")
	summaryPath := filepath.Join(workRoot, "checkpoint-ledger-summary.json")
	planPath := filepath.Join(workRoot, "checkpoint-apply-plan.json")
	verifyPath := filepath.Join(workRoot, "checkpoint-apply-verify.json")
	if err := writeDedupStatus(config, publication, dedupRunStatus{
		State:          "RUNNING",
		Reason:         reason,
		CheckpointPath: publication.CheckpointPath,
		StartedAt:      startedAt,
	}); err != nil {
		return err
	}

	ledgerArgs := []string{
		"checkpoint-ledger",
		"--source", publication.CheckpointPath,
		"--page-size", "4096",
		"--execution", config.DedupExecution,
		"--output", ledgerPath,
	}
	if strings.TrimSpace(publication.DaxDevice) != "" {
		ledgerArgs = append(ledgerArgs, "--dax-device", publication.DaxDevice)
	}
	if _, stderr, err := runDedupCommand(ctx, config.DedupDedupdBinary, ledgerArgs, summaryPath); err != nil {
		return reject("dedup_ledger_failed", commandErrorString(err, stderr))
	}

	if _, stderr, err := runDedupCommand(ctx, config.DedupDedupdBinary, []string{
		"checkpoint-apply-plan",
		"--source", publication.CheckpointPath,
		"--page-size", "4096",
		"--ledger", ledgerPath,
	}, planPath); err != nil {
		return reject("dedup_apply_plan_failed", commandErrorString(err, stderr))
	}

	if _, stderr, err := runDedupCommand(ctx, config.DedupDedupdBinary, []string{
		"checkpoint-apply-verify",
		"--source", publication.CheckpointPath,
		"--page-size", "4096",
		"--ledger", ledgerPath,
		"--plan", planPath,
	}, verifyPath); err != nil {
		return reject("dedup_apply_verify_failed", commandErrorString(err, stderr))
	}

	createdAt := time.Now().UTC()
	if strings.TrimSpace(derivedPath) == "" {
		return reject("dedup_publication_path_missing", "derived publication path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(derivedPath), 0o755); err != nil {
		return reject("dedup_publication_stage_failed", err.Error())
	}
	derivedStagePath := fmt.Sprintf("%s.staging-%d", derivedPath, createdAt.UnixNano())
	defer os.Remove(derivedStagePath)
	_, stderr, err := runDedupCommand(ctx, config.DedupPublicationBinary, []string{
		"--base", publication.PublicationPath,
		"--plan", planPath,
		"--output", derivedStagePath,
		"--created-at", createdAt.Format(time.RFC3339Nano),
		"--min-pages", strconv.FormatUint(config.DedupMinPages, 10),
	}, "")
	if err != nil {
		code := "dedup_publication_failed"
		if strings.Contains(stderr, "no publishable") {
			code = "dedup_no_extents"
		}
		return reject(code, commandErrorString(err, stderr))
	}
	derived, err := trenvpub.ReadFile(derivedStagePath)
	if err != nil {
		return reject("dedup_publication_invalid", err.Error())
	}
	if err := trenvpub.ValidatePublication(derived); err != nil {
		return reject("dedup_publication_invalid", err.Error())
	}
	if derived.CheckpointID != publication.CheckpointID ||
		derived.Generation != publication.Generation ||
		derived.WriterEpoch != publication.WriterEpoch ||
		derived.Fingerprint != publication.Fingerprint {
		return reject("dedup_publication_identity_mismatch", "derived publication does not preserve the base checkpoint identity")
	}
	if derived.CheckpointPhase != trenvpub.DedupRestoreCOWPhase ||
		len(derived.BaseRestoreMap) == 0 ||
		derived.Stats.RestoreMapExtentCount == 0 ||
		derived.Stats.DedupAppliedPages == 0 {
		return reject("dedup_base_restore_map_missing", "derived publication has no materialized BaseRestoreMap")
	}
	file, err := os.OpenFile(derivedStagePath, os.O_RDONLY, 0)
	if err != nil {
		return reject("dedup_publication_stage_failed", err.Error())
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return reject("dedup_publication_stage_failed", err.Error())
	}
	if err := file.Close(); err != nil {
		return reject("dedup_publication_stage_failed", err.Error())
	}
	if pathExists(derivedPath) {
		return reject("dedup_publication_exists", fmt.Sprintf("immutable publication already exists at %q", derivedPath))
	}
	if err := os.Rename(derivedStagePath, derivedPath); err != nil {
		return reject("dedup_publication_commit_failed", err.Error())
	}
	if err := syncDirectory(filepath.Dir(derivedPath)); err != nil {
		return reject("dedup_publication_commit_failed", err.Error())
	}

	if err := writeDedupStatus(config, publication, dedupRunStatus{
		State:              "PUBLISHED",
		Reason:             reason,
		CheckpointPath:     publication.CheckpointPath,
		DerivedPublication: derivedPath,
		StartedAt:          startedAt,
		FinishedAt:         time.Now().UTC(),
	}); err != nil {
		_ = os.Remove(derivedPath)
		_ = syncDirectory(filepath.Dir(derivedPath))
		return err
	}
	fmt.Fprintf(os.Stderr, "%s dedup published checkpoint=%s base=%s derived=%s\n", daemonName, publication.CheckpointID, publication.PublicationPath, derivedPath)
	return nil
}

func runDedupCommand(ctx context.Context, binary string, args []string, stdoutPath string) (string, string, error) {
	cmd := exec.CommandContext(ctx, binary, args...)
	var stdoutBuilder strings.Builder
	var stderrBuilder strings.Builder
	var stdoutFile *os.File
	var stdoutTemp string
	if strings.TrimSpace(stdoutPath) != "" {
		if err := os.MkdirAll(filepath.Dir(stdoutPath), 0o755); err != nil {
			return "", "", err
		}
		file, err := os.CreateTemp(filepath.Dir(stdoutPath), filepath.Base(stdoutPath)+".tmp.")
		if err != nil {
			return "", "", err
		}
		stdoutFile = file
		stdoutTemp = file.Name()
		cmd.Stdout = stdoutFile
	} else {
		cmd.Stdout = &stdoutBuilder
	}
	cmd.Stderr = &stderrBuilder

	err := cmd.Run()
	if stdoutFile != nil {
		if closeErr := stdoutFile.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(stdoutTemp, stdoutPath)
		}
		if err != nil {
			_ = os.Remove(stdoutTemp)
		}
	}
	return stdoutBuilder.String(), stderrBuilder.String(), err
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func commandErrorString(err error, stderr string) string {
	message := strings.TrimSpace(stderr)
	if message == "" && err != nil {
		message = err.Error()
	}
	if message == "" {
		message = "unknown error"
	}
	return message
}

func dedupWorkDirectory(config daemonConfig) string {
	if strings.TrimSpace(config.DedupOutputDirectory) != "" {
		return config.DedupOutputDirectory
	}
	return filepath.Join(config.WorkingDirectory, "dedup")
}

func dedupStatusPath(config daemonConfig, publication metadataPublicationRecord) string {
	key := strings.TrimSpace(publication.ArtifactID)
	if key == "" {
		key = publication.CheckpointID
	}
	return filepath.Join(dedupWorkDirectory(config), "status", sanitizePathPart(key)+".json")
}

func writeDedupStatus(config daemonConfig, publication metadataPublicationRecord, status dedupRunStatus) error {
	status.CheckpointID = publication.CheckpointID
	status.ArtifactID = publication.ArtifactID
	status.Fingerprint = publication.Fingerprint
	status.Generation = publication.Generation
	status.WriterID = publication.WriterID
	status.WriterEpoch = publication.WriterEpoch
	status.BasePublication = publication.PublicationPath
	if status.CheckpointPath == "" {
		status.CheckpointPath = publication.CheckpointPath
	}
	if status.StartedAt.IsZero() {
		status.StartedAt = time.Now().UTC()
	}
	if status.FinishedAt.IsZero() {
		status.FinishedAt = time.Now().UTC()
	}
	return writeJSONFile(dedupStatusPath(config, publication), status)
}

func publicationDirectory(config daemonConfig) string {
	return filepath.Join(config.WorkingDirectory, "checkpoints", "publication")
}

func publicationHasDedup(record metadataPublicationRecord) bool {
	return record.CheckpointPhase == trenvpub.DedupRestoreCOWPhase &&
		len(record.BaseRestoreMap) > 0 &&
		record.Stats.RestoreMapExtentCount > 0 &&
		record.Stats.DedupAppliedPages > 0
}

func publicationPriority(record metadataPublicationRecord) int {
	if publicationHasDedup(record) {
		return 1
	}
	return 0
}

func publicationLess(a, b metadataPublicationRecord) bool {
	if publicationPriority(a) != publicationPriority(b) {
		return publicationPriority(a) < publicationPriority(b)
	}
	if a.WriterEpoch != b.WriterEpoch {
		return a.WriterEpoch < b.WriterEpoch
	}
	if a.Generation != b.Generation {
		return a.Generation < b.Generation
	}
	if !a.CreatedAt.Equal(b.CreatedAt) {
		return a.CreatedAt.Before(b.CreatedAt)
	}
	if a.CheckpointID != b.CheckpointID {
		return a.CheckpointID < b.CheckpointID
	}
	return a.ArtifactID < b.ArtifactID
}

func listCommittedPublications(config daemonConfig, fingerprint string) ([]metadataPublicationRecord, error) {
	dir := publicationDirectory(config)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var publications []metadataPublicationRecord
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), trenvpub.Extension) && !strings.HasSuffix(entry.Name(), ".json")) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		record, err := readPublicationRecord(path)
		if err != nil {
			return nil, fmt.Errorf("read publication %q: %w", path, err)
		}
		if record.State != "COMMITTED" {
			continue
		}
		if strings.TrimSpace(fingerprint) != "" && record.Fingerprint != fingerprint {
			continue
		}
		record.PublicationPath = path
		publications = append(publications, record)
	}
	sort.Slice(publications, func(i, j int) bool {
		return publicationLess(publications[i], publications[j])
	})
	return publications, nil
}

func readPublicationRecord(path string) (metadataPublicationRecord, error) {
	if filepath.Ext(path) == trenvpub.Extension {
		pub, err := trenvpub.ReadFile(path)
		if err != nil {
			return metadataPublicationRecord{}, err
		}
		record := publicationRecordFromBinary(pub)
		record.PublicationPath = path
		return record, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return metadataPublicationRecord{}, err
	}
	var record metadataPublicationRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return metadataPublicationRecord{}, err
	}
	if record.CheckpointID == "" {
		record.CheckpointID = record.ArtifactID
	}
	record.PublicationPath = path
	return record, nil
}

func publicationRecordFromBinary(pub trenvpub.Publication) metadataPublicationRecord {
	version := pub.Version
	if version == 0 {
		version = trenvpub.Version
	}
	record := metadataPublicationRecord{
		Version:                    int(version),
		ArtifactID:                 pub.ArtifactID,
		CheckpointID:               pub.CheckpointID,
		ManifestSchema:             pub.ManifestSchema,
		DedupApplySchema:           pub.DedupApplySchema,
		Generation:                 pub.Generation,
		WriterEpoch:                pub.WriterEpoch,
		State:                      pub.State,
		CheckpointPhase:            pub.CheckpointPhase,
		Fingerprint:                pub.Fingerprint,
		SnapshotStartMode:          pub.SnapshotStartMode,
		RuntimeKind:                pub.RuntimeKind,
		RuntimeFamily:              pub.RuntimeFamily,
		CheckpointPath:             pub.CheckpointPath,
		MetadataBundlePath:         pub.MetadataBundlePath,
		PlacementPath:              pub.PlacementPath,
		CheckpointActionExportRoot: pub.CheckpointActionExportRoot,
		MetadataBundleSize:         pub.MetadataBundleSize,
		PageExtent:                 pub.PageExtent,
		ArtifactExtent:             pub.ArtifactExtent,
		Files:                      append([]trenvpub.ArtifactFile(nil), pub.Files...),
		CreatedAt:                  pub.CreatedAt,
	}
	if record.CheckpointID == "" {
		record.CheckpointID = record.ArtifactID
	}
	if pub.ActionIdentity != nil {
		record.ActionIdentity = &metadataPublicationActionIdentity{
			Namespace:          pub.ActionIdentity.Namespace,
			FullyQualifiedName: pub.ActionIdentity.FullyQualifiedName,
			Revision:           pub.ActionIdentity.Revision,
		}
	}
	if len(pub.Shards) > 0 {
		shard := pub.Shards[0]
		record.WriterID = shard.WriterID
		record.ShardID = shard.ShardID
		record.DaxDevice = shard.DaxDevice
		record.DaxStartPage = shard.DaxStartPage
		record.DaxLengthPages = shard.DaxLengthPages
		record.PageCount = shard.PageCount
		record.PageSize = shard.PageSize
		record.Layout = shard.Layout
	}
	record.Shards = append([]trenvpub.Shard(nil), pub.Shards...)
	record.BaseRestoreMap = append([]trenvpub.RestoreExtent(nil), pub.BaseRestoreMap...)
	record.Stats = pub.Stats
	return record
}

func publicationRecordToBinary(record metadataPublicationRecord) trenvpub.Publication {
	var identity *trenvpub.ActionIdentity
	if record.ActionIdentity != nil {
		identity = &trenvpub.ActionIdentity{
			Namespace:          record.ActionIdentity.Namespace,
			FullyQualifiedName: record.ActionIdentity.FullyQualifiedName,
			Revision:           record.ActionIdentity.Revision,
		}
	}
	shards := append([]trenvpub.Shard(nil), record.Shards...)
	if len(shards) == 0 {
		shards = []trenvpub.Shard{{
			WriterID:       record.WriterID,
			ShardID:        record.ShardID,
			DaxDevice:      record.DaxDevice,
			DaxStartPage:   record.DaxStartPage,
			DaxLengthPages: record.DaxLengthPages,
			PageCount:      record.PageCount,
			PageSize:       record.PageSize,
			Layout:         record.Layout,
		}}
	}
	return trenvpub.Publication{
		Version:                    trenvpub.Version,
		ArtifactID:                 record.ArtifactID,
		CheckpointID:               record.CheckpointID,
		ManifestSchema:             record.ManifestSchema,
		DedupApplySchema:           record.DedupApplySchema,
		Generation:                 record.Generation,
		WriterEpoch:                record.WriterEpoch,
		State:                      record.State,
		CheckpointPhase:            record.CheckpointPhase,
		Fingerprint:                record.Fingerprint,
		SnapshotStartMode:          record.SnapshotStartMode,
		RuntimeKind:                record.RuntimeKind,
		RuntimeFamily:              record.RuntimeFamily,
		ActionIdentity:             identity,
		CheckpointPath:             record.CheckpointPath,
		MetadataBundlePath:         record.MetadataBundlePath,
		PlacementPath:              record.PlacementPath,
		CheckpointActionExportRoot: record.CheckpointActionExportRoot,
		MetadataBundleSize:         record.MetadataBundleSize,
		PageExtent:                 record.PageExtent,
		ArtifactExtent:             record.ArtifactExtent,
		Files:                      append([]trenvpub.ArtifactFile(nil), record.Files...),
		Shards:                     shards,
		BaseRestoreMap:             append([]trenvpub.RestoreExtent(nil), record.BaseRestoreMap...),
		Stats:                      record.Stats,
		CreatedAt:                  record.CreatedAt,
	}
}

func findPublicationByCheckpointID(config daemonConfig, checkpointID string) (metadataPublicationRecord, error) {
	if strings.TrimSpace(checkpointID) == "" {
		return metadataPublicationRecord{}, errors.New("checkpoint id is empty")
	}
	publications, err := listCommittedPublications(config, "")
	if err != nil {
		return metadataPublicationRecord{}, err
	}
	for i := len(publications) - 1; i >= 0; i-- {
		record := publications[i]
		if record.CheckpointID == checkpointID || record.ArtifactID == checkpointID {
			return record, nil
		}
	}
	return metadataPublicationRecord{}, fmt.Errorf("publication %q was not found", checkpointID)
}

func handlePublications(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		publications, err := listCommittedPublications(config, r.URL.Query().Get("fingerprint"))
		if err != nil {
			w.Header().Set("X-Cxld-Error-Code", "dedup_publication_invalid")
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		latest := strings.TrimSpace(r.URL.Query().Get("latest"))
		if latest != "" && latest != "0" && latest != "1" {
			http.Error(w, "latest must be 0 or 1", http.StatusBadRequest)
			return
		}
		if latest == "1" && len(publications) > 1 {
			publications = publications[len(publications)-1:]
		}
		portable := make([]metadataPublicationRecord, 0, len(publications))
		for _, publication := range publications {
			if publication.Version >= int(trenvpub.Version) {
				if err := validateDaxPublication(publication); err != nil {
					w.Header().Set("X-Cxld-Error-Code", "dedup_publication_invalid")
					http.Error(
						w,
						fmt.Sprintf("invalid committed publication %q: %v", publication.ArtifactID, err),
						http.StatusUnprocessableEntity)
					return
				}
				publication = compactNetworkPublication(publication)
			}
			portable = append(portable, publication)
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(portable); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func compactNetworkPublication(publication metadataPublicationRecord) metadataPublicationRecord {
	publication.CheckpointPath = ""
	publication.MetadataBundlePath = ""
	publication.PlacementPath = ""
	publication.CheckpointActionExportRoot = ""
	publication.DaxDevice = ""
	publication.PublicationPath = ""
	publication.PeerURL = ""
	publication.Shards = append([]trenvpub.Shard(nil), publication.Shards...)
	for index := range publication.Shards {
		publication.Shards[index].DaxDevice = ""
	}
	return publication
}

func handleDedupOutcomes(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		fingerprint := strings.TrimSpace(r.URL.Query().Get("fingerprint"))
		statusDirectory := filepath.Join(dedupWorkDirectory(config), "status")
		entries, err := os.ReadDir(statusDirectory)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		outcomes := make([]dedupRunStatus, 0)
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(statusDirectory, entry.Name()))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var outcome dedupRunStatus
			if err := json.Unmarshal(data, &outcome); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if fingerprint == "" || outcome.Fingerprint == fingerprint {
				outcome.BasePublication = ""
				outcome.DerivedPublication = ""
				outcome.CheckpointPath = ""
				outcomes = append(outcomes, outcome)
			}
		}
		sort.Slice(outcomes, func(i, j int) bool {
			return dedupOutcomeLess(outcomes[i], outcomes[j])
		})
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(outcomes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

func handleArtifact(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/artifacts/")
		name = strings.TrimSuffix(name, ".tar")
		checkpointID, err := url.PathUnescape(name)
		if err != nil || checkpointID == "" || strings.Contains(checkpointID, "/") || strings.Contains(checkpointID, "..") {
			http.Error(w, "invalid checkpoint id", http.StatusBadRequest)
			return
		}
		publication, err := findPublicationByCheckpointID(config, checkpointID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		if publication.Version >= int(trenvpub.Version) && strings.TrimSpace(config.ArtifactTransport) != "legacy-tar" {
			http.Error(w, "v5 publications use manifest-only shared-DAX transport", http.StatusGone)
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		if err := writeArtifactTar(w, publication); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func handleBinaryPublication(config daemonConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/v5/publications/")
		name = strings.TrimSuffix(name, trenvpub.Extension)
		checkpointID, err := url.PathUnescape(name)
		if err != nil || checkpointID == "" || strings.Contains(checkpointID, "/") || strings.Contains(checkpointID, "..") {
			http.Error(w, "invalid checkpoint id", http.StatusBadRequest)
			return
		}
		publication, err := findPublicationByCheckpointID(config, checkpointID)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", trenvpub.ContentType)
		http.ServeFile(w, r, publication.PublicationPath)
	}
}

func writeArtifactTar(writer io.Writer, publication metadataPublicationRecord) error {
	tw := tar.NewWriter(writer)
	defer tw.Close()
	// Artifact tar deliberately contains metadata/action-root only. DAX page
	// payload remains in the shared DAX publication and is referenced by
	// placement.json.
	if err := addDirectoryToTar(tw, publication.MetadataBundlePath, "metadata-bundle"); err != nil {
		return err
	}
	if strings.TrimSpace(publication.CheckpointActionExportRoot) != "" && isDirectory(publication.CheckpointActionExportRoot) {
		if err := addDirectoryToTar(tw, publication.CheckpointActionExportRoot, "action-root"); err != nil {
			return err
		}
	}
	archiveName := "publication.original" + filepath.Ext(publication.PublicationPath)
	if archiveName == "publication.original" {
		archiveName = "publication.original"
	}
	return addFileToTar(tw, publication.PublicationPath, archiveName)
}

func addDirectoryToTar(tw *tar.Writer, sourceRoot, archiveRoot string) error {
	sourceRoot = filepath.Clean(sourceRoot)
	return filepath.Walk(sourceRoot, func(path string, info os.FileInfo, walkErr error) error {
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
		name := archiveRoot
		if relative != "." {
			name = filepath.ToSlash(filepath.Join(archiveRoot, relative))
		}
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return err
		}
		header.Name = name
		if info.IsDir() {
			header.Name = strings.TrimSuffix(header.Name, "/") + "/"
		}
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tw, file)
		return err
	})
}

func addFileToTar(tw *tar.Writer, sourcePath, archivePath string) error {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("artifact source is not a regular file: %s", sourcePath)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = archivePath
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	file, err := os.Open(sourcePath)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(tw, file)
	return err
}

func extractTar(reader io.Reader, target string) error {
	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		targetPath, err := safeJoin(target, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := ensureArchivePathHasNoSymlink(target, targetPath); err != nil {
				return err
			}
			if err := os.MkdirAll(targetPath, os.FileMode(header.Mode).Perm()); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			parent := filepath.Dir(targetPath)
			// Reject writes through symlink parents before creating files. This
			// keeps a malicious or malformed artifact from escaping target root.
			if err := ensureArchivePathHasNoSymlink(target, parent); err != nil {
				return err
			}
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return err
			}
			if err := ensureArchivePathHasNoSymlink(target, targetPath); err != nil {
				return err
			}
			file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(header.Mode).Perm())
			if err != nil {
				return err
			}
			if _, err := io.Copy(file, tr); err != nil {
				file.Close()
				return err
			}
			if err := file.Close(); err != nil {
				return err
			}
		case tar.TypeSymlink:
			if header.Linkname == "" {
				return fmt.Errorf("archive symlink %q has empty target", header.Name)
			}
			parent := filepath.Dir(targetPath)
			// Symlinks are allowed as entries, but not as traversal components
			// leading to later entries.
			if err := ensureArchivePathHasNoSymlink(target, parent); err != nil {
				return err
			}
			if err := os.MkdirAll(parent, 0o755); err != nil {
				return err
			}
			if err := ensureArchivePathHasNoSymlink(target, parent); err != nil {
				return err
			}
			if _, err := os.Lstat(targetPath); err == nil {
				return fmt.Errorf("archive symlink target already exists: %q", header.Name)
			} else if !os.IsNotExist(err) {
				return err
			}
			if err := os.Symlink(header.Linkname, targetPath); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry type for %q", header.Name)
		}
	}
}

func ensureArchivePathHasNoSymlink(root, path string) error {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return err
	}
	if relative == "." {
		return nil
	}
	if strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || relative == ".." || filepath.IsAbs(relative) {
		return fmt.Errorf("archive path escapes target root: %q", path)
	}
	current := cleanRoot
	for _, part := range strings.Split(relative, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("archive path traverses symlink: %q", path)
		}
	}
	return nil
}

func startMetadataServer(config daemonConfig) (*http.Server, net.Listener, error) {
	if strings.TrimSpace(config.MetadataListen) == "" {
		return nil, nil, nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/publications", handlePublications(config))
	mux.HandleFunc("/v1/dedup-outcomes", handleDedupOutcomes(config))
	mux.HandleFunc("/v1/artifacts/", handleArtifact(config))
	mux.HandleFunc("/v5/publications/", handleBinaryPublication(config))
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	listener, err := net.Listen("tcp", config.MetadataListen)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "%s metadata server failed: %v\n", daemonName, err)
		}
	}()
	return server, listener, nil
}

func validateVNextOwnerExclusiveLegacyConfig(config daemonConfig) error {
	var conflicts []string
	if strings.TrimSpace(config.DaxDevice) != "" {
		conflicts = append(conflicts, "dax-device")
	}
	if len(config.DaxShards) != 0 {
		conflicts = append(conflicts, "dax-shards")
	}
	if len(config.ArtifactDaxShards) != 0 {
		conflicts = append(conflicts, "artifact-dax-shards")
	}
	if len(config.ReaderDaxShards) != 0 {
		conflicts = append(conflicts, "reader-dax-shards")
	}
	if len(config.ReaderArtifactDaxShards) != 0 {
		conflicts = append(conflicts, "reader-artifact-dax-shards")
	}
	if strings.TrimSpace(config.MetadataListen) != "" {
		conflicts = append(conflicts, "metadata-listen")
	}
	if len(config.MetadataPeers) != 0 {
		conflicts = append(conflicts, "metadata-peers")
	}
	if config.DedupCheckpointMode != "" && config.DedupCheckpointMode != "off" {
		conflicts = append(conflicts, "dedup-checkpoint-mode")
	}
	if len(conflicts) != 0 {
		return fmt.Errorf(
			"strict VNext Owner mode cannot share legacy DAX/metadata configuration: %s",
			strings.Join(conflicts, ", "))
	}
	return nil
}

func validateVNextOwnerStartupExclusivity(
	legacy daemonConfig,
	runtime vnextOwnerRuntimeConfig,
	gateway vnextOwnerGatewayConfig,
) error {
	runtimeStorageConfigured := strings.TrimSpace(runtime.ControlFilePath) != "" ||
		runtime.ControlSlotBytes != 0 || strings.TrimSpace(runtime.DAXDeviceList) != ""
	authorityConfigured :=
		vnextOwnerSchedulerAuthorityConfiguredFields(runtime.SchedulerAuthority) != 0
	if !runtimeStorageConfigured && authorityConfigured {
		return errors.New(
			"Scheduler-authority etcd settings require a local VNext Owner; " +
				"a gateway-only daemon must configure none")
	}
	runtimeConfigured := runtimeStorageConfigured || authorityConfigured
	gatewayConfigured := strings.TrimSpace(gateway.RouteFilePath) != "" ||
		strings.TrimSpace(gateway.SchedulerClientCertificatePath) != "" ||
		strings.TrimSpace(gateway.SchedulerClientPrivateKeyPath) != "" ||
		strings.TrimSpace(gateway.ProducerClientCertificatePath) != "" ||
		strings.TrimSpace(gateway.ProducerClientPrivateKeyPath) != "" ||
		strings.TrimSpace(gateway.ServerCAPath) != ""
	if !runtimeConfigured && !gatewayConfigured {
		return nil
	}
	return validateVNextOwnerExclusiveLegacyConfig(legacy)
}

func serveConn(conn net.Conn) {
	serveConnWithVNextOwnerGateway(
		conn, activeVNextOwnerRPC, activeVNextOwnerGateway)
}

func serveConnWithVNextOwnerGateway(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
) {
	serveConnWithVNextOwnerGatewayLimits(
		conn,
		vnextOwnerRPC,
		gateway,
		daemonRequestAdmission,
		daemonLargeAdmission,
		daemonFrameReadTimeout,
		daemonFrameWriteTimeout)
}

func serveConnWithVNextOwnerRPC(conn net.Conn, vnextOwnerRPC *vnextOwnerRPC) {
	serveConnWithVNextOwnerRPCLimits(
		conn,
		vnextOwnerRPC,
		daemonRequestAdmission,
		daemonLargeAdmission,
		daemonFrameReadTimeout,
		daemonFrameWriteTimeout)
}

func serveConnWithVNextOwnerRPCLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	requestAdmission chan struct{},
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	serveConnWithVNextOwnerGatewayLimits(
		conn, vnextOwnerRPC, nil, requestAdmission, largeAdmission,
		readTimeout, writeTimeout)
}

func serveConnWithVNextOwnerGatewayLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	requestAdmission chan struct{},
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	serveConnWithVNextOwnerGatewayPolicyLimits(
		conn, vnextOwnerRPC, gateway, vnextOwnerRuntimeUnixPolicy,
		requestAdmission, largeAdmission, readTimeout, writeTimeout)
}

func serveConnWithVNextOwnerGatewayPolicyLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	unixPolicy vnextOwnerUnixListenerPolicy,
	requestAdmission chan struct{},
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	if tryAcquireDaemonRequestAdmission(requestAdmission) {
		defer func() { <-requestAdmission }()
	} else {
		// Do not wait while writing a rejection to a peer that may never read
		// it. Closing immediately is what keeps excess connections from
		// retaining goroutines and file descriptors for the write timeout.
		_ = conn.Close()
		return
	}
	serveAdmittedConnWithVNextOwnerGatewayPolicyLimits(
		conn, vnextOwnerRPC, gateway, unixPolicy, largeAdmission,
		readTimeout, writeTimeout)
}

func serveAdmittedConnWithVNextOwnerRPCLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	serveAdmittedConnWithVNextOwnerGatewayLimits(
		conn, vnextOwnerRPC, nil, largeAdmission, readTimeout, writeTimeout)
}

func serveAdmittedConnWithVNextOwnerGatewayLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	serveAdmittedConnWithVNextOwnerGatewayPolicyLimits(
		conn, vnextOwnerRPC, gateway, vnextOwnerRuntimeUnixPolicy,
		largeAdmission, readTimeout, writeTimeout)
}

func serveAdmittedConnWithVNextOwnerGatewayPolicyLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	unixPolicy vnextOwnerUnixListenerPolicy,
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	caller, err := unixPolicy.authenticateCaller(conn)
	if err != nil {
		defer conn.Close()
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		resp := vnextOwnerRPCErrorResponse(err)
		resp.Operation = "unix-authentication"
		respBody, _ := json.Marshal(resp)
		writeDaemonResponse(conn, respBody)
		return
	}
	serveAuthenticatedDaemonConnWithVNextOwnerGatewayCallerLimits(
		conn, vnextOwnerRPC, gateway, caller, largeAdmission,
		readTimeout, writeTimeout)
}

func serveAuthenticatedDaemonConnWithVNextOwnerGatewayRoleLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	callerRole vnextOwnerCallerRole,
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	serveAuthenticatedDaemonConnWithVNextOwnerGatewayCallerLimits(
		conn, vnextOwnerRPC, gateway, vnextOwnerInternalCaller(callerRole),
		largeAdmission, readTimeout, writeTimeout)
}

func serveAuthenticatedDaemonConnWithVNextOwnerGatewayCallerLimits(
	conn net.Conn,
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	caller vnextOwnerCallerContext,
	largeAdmission chan struct{},
	readTimeout time.Duration,
	writeTimeout time.Duration,
) {
	defer conn.Close()
	body, releaseLarge, err := readDaemonRequestFrame(conn, largeAdmission, readTimeout)
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		resp, _ := json.Marshal(execResponse{
			Ok:        false,
			Error:     fmt.Sprintf("invalid request frame: %v", err),
			ErrorCode: string(vnextOwnerServiceInvalidRequest),
		})
		writeDaemonResponse(conn, resp)
		return
	}
	defer releaseLarge()

	req, err := decodeDaemonRequest(body)
	if err != nil {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		resp, _ := json.Marshal(execResponse{
			Ok:        false,
			Error:     fmt.Sprintf("invalid request: %v", err),
			ErrorCode: string(vnextOwnerServiceInvalidRequest),
		})
		writeDaemonResponse(conn, resp)
		return
	}

	respBody, _ := json.Marshal(runCommandWithVNextOwnerGatewayCaller(
		req, vnextOwnerRPC, gateway, caller))
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	writeDaemonResponse(conn, respBody)
}

type daemonUnixServer struct {
	listener       net.Listener
	socketPath     string
	socketIdentity os.FileInfo
	policy         vnextOwnerUnixListenerPolicy
}

func openDaemonUnixServer(
	socketPath string,
	directoryMode os.FileMode,
	requireSetgidDirectory bool,
	policy vnextOwnerUnixListenerPolicy,
) (*daemonUnixServer, error) {
	if socketPath == "" || strings.TrimSpace(socketPath) != socketPath {
		return nil, errors.New("daemon Unix socket path is empty or has surrounding whitespace")
	}
	directoryPath := filepath.Dir(socketPath)
	if requireSetgidDirectory {
		directoryInfo, err := os.Lstat(directoryPath)
		if err != nil {
			return nil, fmt.Errorf("inspect pre-created control socket directory: %w", err)
		}
		if !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New(
				"control socket parent must be a real pre-created directory")
		}
		if directoryInfo.Mode()&os.ModeSetgid == 0 {
			return nil, errors.New(
				"control socket directory must have the setgid bit")
		}
		if directoryInfo.Mode().Perm()&0o022 != 0 {
			return nil, errors.New(
				"control socket directory must not be group or world writable")
		}
		directoryStat, ok := directoryInfo.Sys().(*syscall.Stat_t)
		if !ok || directoryStat.Uid != uint32(os.Geteuid()) {
			return nil, errors.New(
				"control socket directory must be owned by the cxld effective UID")
		}
	} else if err := os.MkdirAll(directoryPath, directoryMode); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := removeStaleDaemonUnixSocket(socketPath); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	unixListener, ok := listener.(*net.UnixListener)
	if !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("listener for %s is not a Unix listener", socketPath)
	}
	// Go's default UnixListener close path unlinks by pathname. Disable it so
	// cleanup can verify the inode before removing anything a caller may have
	// replaced after startup.
	unixListener.SetUnlinkOnClose(false)
	socketIdentity, err := os.Lstat(socketPath)
	if err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("inspect newly created Unix socket: %w", err)
	}
	if socketIdentity.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		return nil, errors.New("new Unix listener path is not a socket")
	}
	if err := os.Chmod(socketPath, 0o660); err != nil {
		_ = listener.Close()
		_ = removeDaemonUnixSocketIfSame(socketPath, socketIdentity)
		return nil, fmt.Errorf("chmod socket: %w", err)
	}
	if requireSetgidDirectory {
		if err := verifyDaemonUnixSocketInheritedGroup(directoryPath, socketPath); err != nil {
			_ = listener.Close()
			_ = removeDaemonUnixSocketIfSame(socketPath, socketIdentity)
			return nil, err
		}
	}
	return &daemonUnixServer{
		listener:       listener,
		socketPath:     socketPath,
		socketIdentity: socketIdentity,
		policy:         policy,
	}, nil
}

func removeStaleDaemonUnixSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect stale socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf(
			"refuse to replace non-socket path %q with mode %s", socketPath, info.Mode())
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

func removeDaemonUnixSocketIfSame(socketPath string, expected os.FileInfo) error {
	if expected == nil || expected.Mode()&os.ModeSocket == 0 {
		return errors.New("expected Unix socket identity is unavailable")
	}
	current, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned Unix socket during cleanup: %w", err)
	}
	if current.Mode()&os.ModeSocket == 0 || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(expected, current) {
		return fmt.Errorf("refuse to remove replaced Unix socket path %q", socketPath)
	}
	if err := os.Remove(socketPath); err != nil {
		return fmt.Errorf("remove owned Unix socket: %w", err)
	}
	return nil
}

func verifyDaemonUnixSocketInheritedGroup(directoryPath string, socketPath string) error {
	directoryInfo, err := os.Lstat(directoryPath)
	if err != nil {
		return fmt.Errorf("inspect control socket directory group: %w", err)
	}
	socketInfo, err := os.Lstat(socketPath)
	if err != nil {
		return fmt.Errorf("inspect control socket group: %w", err)
	}
	directoryStat, directoryOK := directoryInfo.Sys().(*syscall.Stat_t)
	socketStat, socketOK := socketInfo.Sys().(*syscall.Stat_t)
	if !directoryOK || !socketOK {
		return errors.New("control socket group metadata is unavailable")
	}
	if directoryStat.Gid != socketStat.Gid {
		return fmt.Errorf(
			"control socket GID %d did not inherit directory GID %d",
			socketStat.Gid, directoryStat.Gid)
	}
	return nil
}

func (server *daemonUnixServer) close() {
	if server == nil {
		return
	}
	if server.listener != nil {
		_ = server.listener.Close()
	}
	_ = removeDaemonUnixSocketIfSame(server.socketPath, server.socketIdentity)
}

func (server *daemonUnixServer) acceptLoop(
	vnextOwnerRPC *vnextOwnerRPC,
	gateway *vnextOwnerGateway,
	requestWG *sync.WaitGroup,
) {
	var acceptRetryDelay time.Duration
	for {
		conn, err := server.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if acceptRetryDelay == 0 {
				acceptRetryDelay = 5 * time.Millisecond
			} else {
				acceptRetryDelay *= 2
				if acceptRetryDelay > time.Second {
					acceptRetryDelay = time.Second
				}
			}
			time.Sleep(acceptRetryDelay)
			continue
		}
		acceptRetryDelay = 0
		if !tryAcquireDaemonRequestAdmission(daemonRequestAdmission) {
			_ = conn.Close()
			continue
		}
		requestWG.Add(1)
		go func(admittedConn net.Conn) {
			defer requestWG.Done()
			defer func() { <-daemonRequestAdmission }()
			serveAdmittedConnWithVNextOwnerGatewayPolicyLimits(
				admittedConn,
				vnextOwnerRPC,
				gateway,
				server.policy,
				daemonLargeAdmission,
				daemonFrameReadTimeout,
				daemonFrameWriteTimeout)
		}(conn)
	}
}

func main() {
	schedulerControlUIDDefault, err := envStrictInt64(
		"CXLD_SCHEDULER_CONTROL_UID", vnextOwnerSchedulerUIDUnconfigured)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid Scheduler control UID environment: %v\n", err)
		os.Exit(1)
	}
	vnextOwnerSchedulerEtcdDialTimeoutMillisDefault, err := envStrictInt64(
		"CXLD_VNEXT_OWNER_SCHEDULER_ETCD_DIAL_TIMEOUT_MILLIS", 0)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"invalid VNext Owner Scheduler etcd dial timeout environment: %v\n", err)
		os.Exit(1)
	}
	vnextOwnerSchedulerEtcdReadTimeoutMillisDefault, err := envStrictInt64(
		"CXLD_VNEXT_OWNER_SCHEDULER_ETCD_READ_TIMEOUT_MILLIS", 0)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"invalid VNext Owner Scheduler etcd read timeout environment: %v\n", err)
		os.Exit(1)
	}
	socketPath := flag.String("socket-path", envDefault("CXLD_SOCKET_PATH", defaultSocketPath), "Unix socket path")
	schedulerControlSocketPath := flag.String(
		"scheduler-control-socket-path",
		envDefault("CXLD_SCHEDULER_CONTROL_SOCKET_PATH", defaultSchedulerControlSocketPath),
		"Scheduler-only Unix control socket path; enabled only with scheduler-control-uid")
	schedulerControlUID := flag.Int64(
		"scheduler-control-uid",
		schedulerControlUIDDefault,
		"exact host UID allowed on the Scheduler control socket; -1 disables the socket")
	writerID := flag.String("writer-id", envDefault("CXLD_WRITER_ID", ""), "checkpoint writer identity; defaults to host name")
	writerEpoch := flag.Uint64("writer-epoch", envDefaultUint64("CXLD_WRITER_EPOCH", uint64(time.Now().UTC().UnixNano())), "monotonic writer incarnation used to fence stale publications")
	writerStateRoot := flag.String("writer-state-root", envDefault("CXLD_WRITER_STATE_ROOT", ""), "writer-owned allocator state root; defaults beside the OpenWhisk checkpoint root")
	daxDevice := flag.String("dax-device", envDefault("CXLD_DAX_DEVICE", ""), "DAX device path for checkpoint conversion; autodetects first /dev/dax*.0 when empty")
	shardID := flag.String("shard-id", envDefault("CXLD_SHARD_ID", ""), "writer-owned DAX shard identity; defaults to DAX device basename")
	daxShards := flag.String("dax-shards", envDefault("CXLD_DAX_SHARDS", ""), "comma-separated DAX shard mappings as shard-id=/dev/daxN.0")
	artifactDaxShards := flag.String("artifact-dax-shards", envDefault("CXLD_ARTIFACT_DAX_SHARDS", ""), "comma-separated writer artifact DAX shard mappings as shard-id=/dev/daxN.0")
	readerDaxShards := flag.String("reader-dax-shards", envDefault("CXLD_READER_DAX_SHARDS", ""), "comma-separated reader-local DAX shard mappings as shard-id=/dev/daxN.0")
	readerArtifactDaxShards := flag.String("reader-artifact-dax-shards", envDefault("CXLD_READER_ARTIFACT_DAX_SHARDS", ""), "comma-separated reader-local artifact DAX shard mappings as shard-id=/dev/daxN.0")
	daxPlacementPolicy := flag.String("dax-placement-policy", envDefault("CXLD_DAX_PLACEMENT_POLICY", "first-fit"), "DAX placement policy for checkpoint writers: first-fit or round-robin")
	artifactTransport := flag.String("artifact-transport", envDefault("CXLD_ARTIFACT_TRANSPORT", "dax-manifest"), "artifact transport: dax-manifest or legacy-tar")
	publicationSchemaVersion := flag.Uint64(
		"publication-schema-version",
		envDefaultUint64("CXLD_PUBLICATION_SCHEMA_VERSION", uint64(trenvpub.Version)),
		"fixed binary publication schema version; only 5 is supported")
	checkpointWriterEnabled := flag.Bool("checkpoint-writer-enabled", envDefaultBool("CXLD_CHECKPOINT_WRITER_ENABLED", true), "allow this cxld to create checkpoint publications")
	workingDirectory := flag.String("working-directory", envDefault("CXLD_WORKING_DIRECTORY", "/tmp/openwhisk-trenv"), "OpenWhisk TrEnv working directory")
	metadataListen := flag.String("metadata-listen", envDefault("CXLD_METADATA_LISTEN", ""), "optional TCP listen address for metadata HTTP, for example 127.0.0.1:18080")
	metadataPeers := flag.String("metadata-peers", envDefault("CXLD_METADATA_PEERS", ""), "comma-separated metadata peer HTTP URLs")
	pseudoMMMaterializationRoot := flag.String("pseudo-mm-materialization-root", envDefault("CXLD_PSEUDO_MM_MATERIALIZATION_ROOT", ""), "host-local root for reusable reader pseudo_mm materializations")
	dedupCheckpointMode := flag.String("dedup-checkpoint-mode", envDefault("CXLD_DEDUP_CHECKPOINT_MODE", "off"), "checkpoint dedup mode: off or sync-required")
	dedupTimeout := flag.Duration("dedup-timeout", envDefaultDuration("CXLD_DEDUP_TIMEOUT", 15*time.Minute), "timeout for synchronous checkpoint dedup")
	dedupDedupdBinary := flag.String("dedup-dedupd-binary", envDefault("CXLD_DEDUP_DEDUPD_BINARY", "dedupd"), "dedupd binary used by synchronous checkpoint dedup")
	dedupPublicationBinary := flag.String("dedup-publication-binary", envDefault("CXLD_DEDUP_PUBLICATION_BINARY", "trenv-dedup-pub"), "trenv-dedup-pub binary used to write derived dedup publications")
	dedupExecution := flag.String("dedup-execution", envDefault("CXLD_DEDUP_EXECUTION", "cpu"), "dedupd fingerprint execution backend: cpu, sw, or hw")
	dedupOutputDirectory := flag.String("dedup-output-directory", envDefault("CXLD_DEDUP_OUTPUT_DIRECTORY", ""), "directory for automatic dedup ledgers, plans, and status files")
	dedupMinPages := flag.Uint64("dedup-min-pages", envDefaultUint64("CXLD_DEDUP_MIN_PAGES", 1), "minimum dedup extent size to publish")
	vnextOwnerControlFile := flag.String(
		"vnext-owner-control-file",
		envDefault("CXLD_VNEXT_OWNER_CONTROL_FILE", ""),
		"existing VNext Owner A/B control file; never created or formatted by cxld startup")
	vnextOwnerControlSlotBytes := flag.Uint64(
		"vnext-owner-control-slot-bytes",
		envDefaultUint64("CXLD_VNEXT_OWNER_CONTROL_SLOT_BYTES", 0),
		"exact byte capacity of one existing VNext Owner control slot")
	vnextOwnerDAXDevices := flag.String(
		"vnext-owner-dax-devices",
		envDefault("CXLD_VNEXT_OWNER_DAX_DEVICES", ""),
		"comma-separated existing TRCXL006 devdax paths owned by this cxld")
	vnextOwnerSchedulerEtcdEndpoints := flag.String(
		"vnext-owner-scheduler-etcd-endpoints",
		envExactDefault("CXLD_VNEXT_OWNER_SCHEDULER_ETCD_ENDPOINTS", ""),
		"comma-separated canonical HTTPS etcd endpoints for local Owner Scheduler fencing")
	vnextOwnerSchedulerLeaderKey := flag.String(
		"vnext-owner-scheduler-leader-key",
		envExactDefault("CXLD_VNEXT_OWNER_SCHEDULER_LEADER_KEY", ""),
		"exact immutable-lease Scheduler leader key read by the local Owner")
	vnextOwnerSchedulerEtcdClusterID := flag.String(
		"vnext-owner-scheduler-etcd-cluster-id",
		envExactDefault("CXLD_VNEXT_OWNER_SCHEDULER_ETCD_CLUSTER_ID", ""),
		"exact nonzero etcd cluster ID as 16 lower-case hexadecimal digits")
	vnextOwnerSchedulerEtcdCA := flag.String(
		"vnext-owner-scheduler-etcd-ca",
		envExactDefault("CXLD_VNEXT_OWNER_SCHEDULER_ETCD_CA", ""),
		"PEM CA used by the local Owner to authenticate Scheduler-authority etcd")
	vnextOwnerSchedulerEtcdClientCertificate := flag.String(
		"vnext-owner-scheduler-etcd-client-cert",
		envExactDefault("CXLD_VNEXT_OWNER_SCHEDULER_ETCD_CLIENT_CERT", ""),
		"PEM client certificate used by the local Owner for Scheduler-authority etcd")
	vnextOwnerSchedulerEtcdClientPrivateKey := flag.String(
		"vnext-owner-scheduler-etcd-client-key",
		envExactDefault("CXLD_VNEXT_OWNER_SCHEDULER_ETCD_CLIENT_KEY", ""),
		"PEM client private key used by the local Owner for Scheduler-authority etcd")
	vnextOwnerSchedulerEtcdDialTimeoutMillis := flag.Int64(
		"vnext-owner-scheduler-etcd-dial-timeout-millis",
		vnextOwnerSchedulerEtcdDialTimeoutMillisDefault,
		"positive etcd dial timeout in milliseconds for local Owner Scheduler fencing")
	vnextOwnerSchedulerEtcdReadTimeoutMillis := flag.Int64(
		"vnext-owner-scheduler-etcd-read-timeout-millis",
		vnextOwnerSchedulerEtcdReadTimeoutMillisDefault,
		"positive exact leader-read timeout in milliseconds for local Owner Scheduler fencing")
	vnextOwnerTLSListen := flag.String(
		"vnext-owner-tls-listen",
		envDefault("CXLD_VNEXT_OWNER_TLS_LISTEN", ""),
		"optional strict VNext Owner mTLS listen address; requires the complete TLS configuration")
	vnextOwnerTLSServerCertificate := flag.String(
		"vnext-owner-tls-server-cert",
		envDefault("CXLD_VNEXT_OWNER_TLS_SERVER_CERT", ""),
		"PEM server certificate for the strict VNext Owner mTLS listener")
	vnextOwnerTLSServerPrivateKey := flag.String(
		"vnext-owner-tls-server-key",
		envDefault("CXLD_VNEXT_OWNER_TLS_SERVER_KEY", ""),
		"PEM server private key for the strict VNext Owner mTLS listener")
	vnextOwnerTLSClientCA := flag.String(
		"vnext-owner-tls-client-ca",
		envDefault("CXLD_VNEXT_OWNER_TLS_CLIENT_CA", ""),
		"PEM CA used to authenticate strict VNext Owner mTLS clients")
	vnextOwnerTLSAllowedSchedulerClientURISANs := flag.String(
		"vnext-owner-tls-allowed-scheduler-client-uri-sans",
		envDefault("CXLD_VNEXT_OWNER_TLS_ALLOWED_SCHEDULER_CLIENT_URI_SANS", ""),
		"comma-separated exact Scheduler client URI SAN identities")
	vnextOwnerTLSAllowedProducerClientURISANs := flag.String(
		"vnext-owner-tls-allowed-producer-client-uri-sans",
		envDefault("CXLD_VNEXT_OWNER_TLS_ALLOWED_PRODUCER_CLIENT_URI_SANS", ""),
		"comma-separated exact Producer client URI SAN identities")
	vnextOwnerGatewayRoutes := flag.String(
		"vnext-owner-gateway-routes",
		envDefault("CXLD_VNEXT_OWNER_GATEWAY_ROUTES", ""),
		"strict bounded VNext Owner gateway route-file v1")
	vnextOwnerGatewaySchedulerClientCertificate := flag.String(
		"vnext-owner-gateway-scheduler-client-cert",
		envDefault("CXLD_VNEXT_OWNER_GATEWAY_SCHEDULER_CLIENT_CERT", ""),
		"Scheduler PEM client certificate for outbound VNext Owner gateway mTLS")
	vnextOwnerGatewaySchedulerClientPrivateKey := flag.String(
		"vnext-owner-gateway-scheduler-client-key",
		envDefault("CXLD_VNEXT_OWNER_GATEWAY_SCHEDULER_CLIENT_KEY", ""),
		"Scheduler PEM client private key for outbound VNext Owner gateway mTLS")
	vnextOwnerGatewayProducerClientCertificate := flag.String(
		"vnext-owner-gateway-producer-client-cert",
		envDefault("CXLD_VNEXT_OWNER_GATEWAY_PRODUCER_CLIENT_CERT", ""),
		"Producer PEM client certificate for outbound VNext Owner gateway mTLS")
	vnextOwnerGatewayProducerClientPrivateKey := flag.String(
		"vnext-owner-gateway-producer-client-key",
		envDefault("CXLD_VNEXT_OWNER_GATEWAY_PRODUCER_CLIENT_KEY", ""),
		"Producer PEM client private key for outbound VNext Owner gateway mTLS")
	vnextOwnerGatewayServerCA := flag.String(
		"vnext-owner-gateway-server-ca",
		envDefault("CXLD_VNEXT_OWNER_GATEWAY_SERVER_CA", ""),
		"PEM CA used to authenticate outbound VNext Owner gateway servers")
	flag.Parse()
	vnextSchedulerAuthorityConfig, err := parseVNextOwnerSchedulerAuthorityInput(
		vnextOwnerSchedulerAuthorityInput{
			Endpoints:         *vnextOwnerSchedulerEtcdEndpoints,
			LeaderKey:         *vnextOwnerSchedulerLeaderKey,
			ExpectedCluster:   *vnextOwnerSchedulerEtcdClusterID,
			CAFile:            *vnextOwnerSchedulerEtcdCA,
			ClientCertFile:    *vnextOwnerSchedulerEtcdClientCertificate,
			ClientKeyFile:     *vnextOwnerSchedulerEtcdClientPrivateKey,
			DialTimeoutMillis: *vnextOwnerSchedulerEtcdDialTimeoutMillis,
			ReadTimeoutMillis: *vnextOwnerSchedulerEtcdReadTimeoutMillis,
		})
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid VNext Owner Scheduler authority: %v\n", err)
		os.Exit(1)
	}
	if *publicationSchemaVersion != uint64(trenvpub.Version) {
		fmt.Fprintf(
			os.Stderr,
			"invalid --publication-schema-version %d; only %d is supported after the V5 fresh reset\n",
			*publicationSchemaVersion,
			trenvpub.Version)
		os.Exit(1)
	}

	parsedDaxShards, err := parseDaxShardConfigList(*daxShards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --dax-shards: %v\n", err)
		os.Exit(1)
	}
	parsedArtifactDaxShards, err := parseDaxShardConfigList(*artifactDaxShards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --artifact-dax-shards: %v\n", err)
		os.Exit(1)
	}
	parsedReaderDaxShards, err := parseDaxShardConfigList(*readerDaxShards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --reader-dax-shards: %v\n", err)
		os.Exit(1)
	}
	parsedReaderArtifactDaxShards, err := parseDaxShardConfigList(*readerArtifactDaxShards)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --reader-artifact-dax-shards: %v\n", err)
		os.Exit(1)
	}
	if err := validateDisjointDaxShardSets(parsedDaxShards, parsedArtifactDaxShards); err != nil {
		fmt.Fprintf(os.Stderr, "invalid page/artifact DAX shard configuration: %v\n", err)
		os.Exit(1)
	}

	activeConfig = daemonConfig{
		WriterID:                    *writerID,
		WriterEpoch:                 *writerEpoch,
		WriterStateRoot:             *writerStateRoot,
		DaxDevice:                   *daxDevice,
		ShardID:                     *shardID,
		DaxShards:                   parsedDaxShards,
		ArtifactDaxShards:           parsedArtifactDaxShards,
		ReaderDaxShards:             parsedReaderDaxShards,
		ReaderArtifactDaxShards:     parsedReaderArtifactDaxShards,
		DaxPlacementPolicy:          *daxPlacementPolicy,
		ArtifactTransport:           strings.TrimSpace(*artifactTransport),
		CheckpointWriterDisabled:    !*checkpointWriterEnabled,
		WorkingDirectory:            *workingDirectory,
		MetadataListen:              *metadataListen,
		MetadataPeers:               splitCommaList(*metadataPeers),
		PseudoMMMaterializationRoot: *pseudoMMMaterializationRoot,
		DedupCheckpointMode:         *dedupCheckpointMode,
		DedupTimeout:                *dedupTimeout,
		DedupDedupdBinary:           *dedupDedupdBinary,
		DedupPublicationBinary:      *dedupPublicationBinary,
		DedupExecution:              *dedupExecution,
		DedupOutputDirectory:        *dedupOutputDirectory,
		DedupMinPages:               *dedupMinPages,
	}

	if activeConfig.WorkingDirectory == "" {
		activeConfig.WorkingDirectory = "/tmp/openwhisk-trenv"
	}
	if strings.TrimSpace(activeConfig.PseudoMMMaterializationRoot) == "" {
		activeConfig.PseudoMMMaterializationRoot = filepath.Join(activeConfig.WorkingDirectory, "pseudo-mm-materialized")
	}
	activeConfig = normalizeDedupConfig(activeConfig)
	switch activeConfig.ArtifactTransport {
	case "dax-manifest", "legacy-tar":
	default:
		fmt.Fprintf(os.Stderr, "invalid --artifact-transport %q; expected dax-manifest or legacy-tar\n", activeConfig.ArtifactTransport)
		os.Exit(1)
	}
	switch activeConfig.DedupExecution {
	case "cpu", "sw", "hw":
	default:
		fmt.Fprintf(os.Stderr, "invalid --dedup-execution %q; expected cpu, sw, or hw\n", activeConfig.DedupExecution)
		os.Exit(1)
	}
	switch activeConfig.DedupCheckpointMode {
	case "off", "sync-required":
	default:
		fmt.Fprintf(
			os.Stderr,
			"invalid --dedup-checkpoint-mode %q; expected off or sync-required\n",
			activeConfig.DedupCheckpointMode)
		os.Exit(1)
	}
	if err := os.MkdirAll(activeConfig.WorkingDirectory, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create working directory: %v\n", err)
		os.Exit(1)
	}

	vnextRuntimeConfig := vnextOwnerRuntimeConfig{
		ControlFilePath:    *vnextOwnerControlFile,
		ControlSlotBytes:   *vnextOwnerControlSlotBytes,
		DAXDeviceList:      *vnextOwnerDAXDevices,
		SchedulerAuthority: vnextSchedulerAuthorityConfig,
	}
	vnextGatewayConfig := vnextOwnerGatewayConfig{
		RouteFilePath:                  *vnextOwnerGatewayRoutes,
		SchedulerClientCertificatePath: *vnextOwnerGatewaySchedulerClientCertificate,
		SchedulerClientPrivateKeyPath:  *vnextOwnerGatewaySchedulerClientPrivateKey,
		ProducerClientCertificatePath:  *vnextOwnerGatewayProducerClientCertificate,
		ProducerClientPrivateKeyPath:   *vnextOwnerGatewayProducerClientPrivateKey,
		ServerCAPath:                   *vnextOwnerGatewayServerCA,
	}
	if err := validateVNextOwnerStartupExclusivity(
		activeConfig, vnextRuntimeConfig, vnextGatewayConfig); err != nil {
		fmt.Fprintf(os.Stderr, "invalid VNext Owner configuration: %v\n", err)
		os.Exit(1)
	}

	vnextOwnerRuntime, err := openVNextOwnerRuntime(vnextRuntimeConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open VNext Owner runtime: %v\n", err)
		os.Exit(1)
	}
	if vnextOwnerRuntime != nil {
		defer func() {
			if err := closeVNextOwnerRuntimeWithRetry(vnextOwnerRuntime, 3); err != nil {
				fmt.Fprintf(os.Stderr, "failed to close VNext Owner runtime: %v\n", err)
			}
		}()
		activeVNextOwnerRPC = newVNextOwnerRPC(vnextOwnerRuntime.service)
	}
	activeVNextOwnerGateway, err = openVNextOwnerGateway(
		vnextGatewayConfig, activeVNextOwnerRPC)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open VNext Owner gateway: %v\n", err)
		os.Exit(1)
	}
	if activeVNextOwnerGateway != nil {
		defer activeVNextOwnerGateway.Close()
	}
	allowedVNextOwnerSchedulerClientURISANs, err := parseVNextOwnerURIAllowlist(
		*vnextOwnerTLSAllowedSchedulerClientURISANs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid VNext Owner TLS Scheduler client URI SAN allowlist: %v\n", err)
		os.Exit(1)
	}
	allowedVNextOwnerProducerClientURISANs, err := parseVNextOwnerURIAllowlist(
		*vnextOwnerTLSAllowedProducerClientURISANs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid VNext Owner TLS Producer client URI SAN allowlist: %v\n", err)
		os.Exit(1)
	}
	vnextOwnerTLSServer, err := startVNextOwnerTLSServer(
		vnextOwnerTLSServerConfig{
			ListenAddress:                 *vnextOwnerTLSListen,
			ServerCertificatePath:         *vnextOwnerTLSServerCertificate,
			ServerPrivateKeyPath:          *vnextOwnerTLSServerPrivateKey,
			ClientCAPath:                  *vnextOwnerTLSClientCA,
			AllowedSchedulerClientURISANs: allowedVNextOwnerSchedulerClientURISANs,
			AllowedProducerClientURISANs:  allowedVNextOwnerProducerClientURISANs,
		},
		activeVNextOwnerRPC,
		daemonRequestAdmission,
		daemonLargeAdmission)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start VNext Owner TLS listener: %v\n", err)
		os.Exit(1)
	}
	if vnextOwnerTLSServer != nil {
		defer vnextOwnerTLSServer.Close()
	}

	metadataServer, metadataListener, err := startMetadataServer(activeConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to start metadata server: %v\n", err)
		os.Exit(1)
	}
	if metadataListener != nil {
		defer metadataListener.Close()
	}

	if err := validateVNextOwnerSchedulerControlUID(*schedulerControlUID); err != nil {
		fmt.Fprintf(os.Stderr, "invalid --scheduler-control-uid: %v\n", err)
		os.Exit(1)
	}
	runtimeUnixServer, err := openDaemonUnixServer(
		*socketPath, 0o755, false, vnextOwnerRuntimeUnixPolicy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open runtime Unix socket: %v\n", err)
		os.Exit(1)
	}
	unixServers := []*daemonUnixServer{runtimeUnixServer}
	if *schedulerControlUID >= 0 {
		if activeVNextOwnerRPC == nil && activeVNextOwnerGateway == nil {
			runtimeUnixServer.close()
			fmt.Fprintln(os.Stderr,
				"Scheduler control socket requires an active local Owner or Owner gateway")
			os.Exit(1)
		}
		if filepath.Clean(filepath.Dir(*schedulerControlSocketPath)) ==
			filepath.Clean(filepath.Dir(*socketPath)) {
			runtimeUnixServer.close()
			fmt.Fprintln(os.Stderr,
				"Scheduler control socket must use a directory separate from the runtime socket")
			os.Exit(1)
		}
		controlUnixServer, err := openDaemonUnixServer(
			*schedulerControlSocketPath,
			0o750,
			true,
			vnextOwnerUnixListenerPolicy{
				Role:                 vnextOwnerCallerScheduler,
				RequiredSchedulerUID: *schedulerControlUID,
			})
		if err != nil {
			runtimeUnixServer.close()
			fmt.Fprintf(os.Stderr, "failed to open Scheduler control Unix socket: %v\n", err)
			os.Exit(1)
		}
		unixServers = append(unixServers, controlUnixServer)
	}
	defer func() {
		for _, server := range unixServers {
			server.close()
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	var requestWG sync.WaitGroup
	var acceptWG sync.WaitGroup
	for _, server := range unixServers {
		acceptWG.Add(1)
		go func(unixServer *daemonUnixServer) {
			defer acceptWG.Done()
			unixServer.acceptLoop(
				activeVNextOwnerRPC, activeVNextOwnerGateway, &requestWG)
		}(server)
	}
	<-sigCh
	if vnextOwnerTLSServer != nil {
		_ = vnextOwnerTLSServer.Stop()
	}
	if metadataServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = metadataServer.Shutdown(ctx)
		cancel()
	}
	for _, server := range unixServers {
		server.close()
	}
	acceptWG.Wait()
	requestWG.Wait()
	if vnextOwnerTLSServer != nil {
		vnextOwnerTLSServer.Wait()
	}
}

func tryAcquireDaemonRequestAdmission(admission chan struct{}) bool {
	select {
	case admission <- struct{}{}:
		return true
	default:
		return false
	}
}
