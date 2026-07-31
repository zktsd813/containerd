package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/containerd/containerd/third_party/trenv-containerd/pkg/cxlcheckpoint"
)

// vnextOwnerClientRoundTripper is the transport-neutral boundary below the
// strict Owner client. A Unix-socket length-prefixed JSON adapter can
// implement this contract, as can an in-process test adapter. This interface
// does not provide dialing, TLS, peer authentication, authorization, or
// distributed fencing by itself.
//
// The transport is responsible for encoding daemonRequest into the bounded
// daemon frame and decoding its outer execResponse. This client owns the
// cxld.vnext-owner.v1 operation payload and response contracts inside those
// envelopes.
type vnextOwnerClientRoundTripper interface {
	RoundTrip(context.Context, daemonRequest) (execResponse, error)
}

type vnextOwnerClient struct {
	transport vnextOwnerClientRoundTripper
}

func newVNextOwnerClient(
	transport vnextOwnerClientRoundTripper,
) (*vnextOwnerClient, error) {
	if transport == nil || vnextProducerInterfaceIsNil(transport) {
		return nil, errors.New("VNext Owner client transport is unavailable")
	}
	return &vnextOwnerClient{transport: transport}, nil
}

// vnextOwnerClientRemoteError retains the stable ErrorCode returned in the
// daemon execResponse. Callers can use errors.As and make policy decisions
// without parsing an error string.
type vnextOwnerClientRemoteError struct {
	Operation string
	ErrorCode string
	Message   string
	Stderr    string
	ExitCode  int
}

func (err *vnextOwnerClientRemoteError) Error() string {
	if err == nil {
		return "<nil>"
	}
	message := err.Message
	if message == "" {
		message = "remote VNext Owner operation failed"
	}
	if err.ErrorCode == "" {
		return fmt.Sprintf("VNext Owner %s: %s", err.Operation, message)
	}
	return fmt.Sprintf(
		"VNext Owner %s failed (%s): %s", err.Operation, err.ErrorCode, message)
}

// Reserve is intentionally separate from vnextProducerOwnerClient. Scheduler
// placement code can use it before constructing a location-specific
// publication, while the Producer interface remains limited to the lifecycle
// of an already selected reserve.
func (client *vnextOwnerClient) Reserve(
	ctx context.Context,
	request vnextOwnerReserveRequest,
) (vnextOwnerReserveResponse, error) {
	if client == nil || client.transport == nil {
		return vnextOwnerReserveResponse{}, errors.New("VNext Owner client is unavailable")
	}
	for name, value := range map[string]string{
		"request ID": request.RequestID, "checkpoint ID": request.CheckpointID,
		"producer ID": request.ProducerID, "Owner ID": request.OwnerID,
	} {
		if err := validateVNextOwnerClientText(name, value); err != nil {
			return vnextOwnerReserveResponse{}, err
		}
	}
	internal, err := request.internal()
	if err != nil {
		return vnextOwnerReserveResponse{}, fmt.Errorf("validate VNext reserve request: %w", err)
	}
	wire := vnextOwnerRPCReserveRequest{
		Protocol:     vnextOwnerRPCProtocol,
		RequestID:    request.RequestID,
		CheckpointID: request.CheckpointID,
		ProducerID:   request.ProducerID,
		OwnerID:      request.OwnerID,
		OwnerEpoch:   request.OwnerEpoch,
		Contents:     make(vnextOwnerRPCReserveContents, len(request.Contents)),
		MaxExtents:   request.MaxExtents,
	}
	var externalPages uint64
	for index, content := range request.Contents {
		name, ok := vnextOwnerRPCContentKindName(content.Kind)
		if !ok {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"reserve content %d has unsupported kind %d", index, content.Kind)
		}
		wire.Contents[index] = vnextOwnerRPCReserveContent{
			Kind:          name,
			ObjectID:      content.ObjectID,
			ByteLength:    content.ByteLength,
			CapacityPages: content.CapacityPages,
		}
		if content.Kind != vnextOwnerServiceContentMemory &&
			content.Kind != vnextOwnerServiceContentPublication {
			if content.CapacityPages >
				uint64(vnextOwnerRPCMaxExternalContentPageCRCs)-externalPages {
				return vnextOwnerReserveResponse{}, fmt.Errorf(
					"producer-written non-memory reserve exceeds the RPC seal limit of %d pages",
					vnextOwnerRPCMaxExternalContentPageCRCs)
			}
			externalPages += content.CapacityPages
		}
	}
	raw, err := marshalVNextOwnerClientPayload(wire)
	if err != nil {
		return vnextOwnerReserveResponse{}, err
	}
	response, err := client.roundTrip(
		ctx,
		vnextOwnerRPCOperationReserve,
		daemonRequest{VNextOwnerReserve: raw},
	)
	if err != nil {
		return vnextOwnerReserveResponse{}, err
	}
	var decoded vnextOwnerRPCReserveResponse
	if err := decodeVNextOwnerClientSuccess(
		response, vnextOwnerRPCOperationReserve, &decoded); err != nil {
		return vnextOwnerReserveResponse{}, err
	}
	return convertVNextOwnerClientReserveResponse(request, internal, decoded)
}

func (client *vnextOwnerClient) SealVNextCheckpoint(
	ctx context.Context,
	request vnextOwnerExternalSealRequest,
) (vnextOwnerSealResponse, error) {
	if client == nil || client.transport == nil {
		return vnextOwnerSealResponse{}, errors.New("VNext Owner client is unavailable")
	}
	if err := validateVNextOwnerClientOperationIdentity(request.Operation); err != nil {
		return vnextOwnerSealResponse{}, err
	}
	if len(request.PublicationEnvelope) == 0 ||
		len(request.PublicationEnvelope) > vnextOwnerRPCMaxPublicationBytes {
		return vnextOwnerSealResponse{}, fmt.Errorf(
			"publication envelope is %d bytes, allowed range is 1..%d",
			len(request.PublicationEnvelope), vnextOwnerRPCMaxPublicationBytes)
	}
	if len(request.CRCPageSidecars) > vnextOwnerRPCMaxSidecars {
		return vnextOwnerSealResponse{}, fmt.Errorf(
			"CRC sidecar count %d exceeds %d",
			len(request.CRCPageSidecars), vnextOwnerRPCMaxSidecars)
	}
	pagesImageIDs := make([]uint32, 0, len(request.CRCPageSidecars))
	var sidecarBytes int
	for pagesImageID, data := range request.CRCPageSidecars {
		if pagesImageID == 0 || len(data) == 0 {
			return vnextOwnerSealResponse{}, errors.New(
				"CRC sidecar has a zero pages-image ID or empty bytes")
		}
		if len(data) > vnextOwnerRPCMaxSidecarBytes-sidecarBytes {
			return vnextOwnerSealResponse{}, fmt.Errorf(
				"CRC sidecar bytes exceed transport limit %d", vnextOwnerRPCMaxSidecarBytes)
		}
		sidecarBytes += len(data)
		pagesImageIDs = append(pagesImageIDs, pagesImageID)
	}
	sort.Slice(pagesImageIDs, func(i, j int) bool {
		return pagesImageIDs[i] < pagesImageIDs[j]
	})
	sidecars := make(vnextOwnerRPCSidecars, 0, len(pagesImageIDs))
	for _, pagesImageID := range pagesImageIDs {
		sidecars = append(sidecars, vnextOwnerRPCSidecar{
			PagesImageID: pagesImageID,
			Bytes:        append([]byte(nil), request.CRCPageSidecars[pagesImageID]...),
		})
	}
	if len(request.ExternalContentPageCRCs) > vnextOwnerRPCMaxExternalContentPageCRCs {
		return vnextOwnerSealResponse{}, fmt.Errorf(
			"external content CRC count %d exceeds %d",
			len(request.ExternalContentPageCRCs),
			vnextOwnerRPCMaxExternalContentPageCRCs)
	}
	external := make(
		vnextOwnerRPCExternalContentPageCRCs,
		len(request.ExternalContentPageCRCs))
	seenLogicalPages := make(map[uint64]struct{}, len(request.ExternalContentPageCRCs))
	for index, record := range request.ExternalContentPageCRCs {
		if record.LogicalPage > uint64(math.MaxInt64) || !record.CopyEngine.valid() {
			return vnextOwnerSealResponse{}, fmt.Errorf(
				"external content CRC %d has invalid logical page or copy engine", index)
		}
		if _, duplicate := seenLogicalPages[record.LogicalPage]; duplicate {
			return vnextOwnerSealResponse{}, fmt.Errorf(
				"external content logical page %d is duplicated", record.LogicalPage)
		}
		seenLogicalPages[record.LogicalPage] = struct{}{}
		external[index] = vnextOwnerRPCExternalContentPageCRC{
			LogicalPage:   record.LogicalPage,
			ContentCRC32C: record.ContentCRC32C,
			CopyEngine:    uint32(record.CopyEngine),
		}
	}
	sort.Slice(external, func(i, j int) bool {
		return external[i].LogicalPage < external[j].LogicalPage
	})
	wire := vnextOwnerRPCSealRequest{
		Protocol:                vnextOwnerRPCProtocol,
		Identity:                vnextOwnerRPCIdentityFromInternal(request.Operation),
		PublicationEnvelope:     append([]byte(nil), request.PublicationEnvelope...),
		CRCPageSidecars:         sidecars,
		ExternalContentPageCRCs: external,
	}
	raw, err := marshalVNextOwnerClientPayload(wire)
	if err != nil {
		return vnextOwnerSealResponse{}, err
	}
	response, err := client.roundTrip(
		ctx,
		vnextOwnerRPCOperationSeal,
		daemonRequest{VNextOwnerSeal: raw},
	)
	if err != nil {
		return vnextOwnerSealResponse{}, err
	}
	var decoded vnextOwnerRPCSealResponse
	if err := decodeVNextOwnerClientSuccess(
		response, vnextOwnerRPCOperationSeal, &decoded); err != nil {
		return vnextOwnerSealResponse{}, err
	}
	return convertVNextOwnerClientSealResponse(request.Operation, decoded)
}

func (client *vnextOwnerClient) CommitVNextCheckpoint(
	ctx context.Context,
	identity vnextOwnerOperationIdentity,
) error {
	return client.lifecycle(ctx, vnextOwnerRPCOperationCommit, "COMMITTED", identity)
}

func (client *vnextOwnerClient) AbortVNextCheckpoint(
	ctx context.Context,
	identity vnextOwnerOperationIdentity,
) error {
	return client.lifecycle(ctx, vnextOwnerRPCOperationAbort, "ABORTED", identity)
}

func (client *vnextOwnerClient) lifecycle(
	ctx context.Context,
	operation string,
	expectedState string,
	identity vnextOwnerOperationIdentity,
) error {
	if client == nil || client.transport == nil {
		return errors.New("VNext Owner client is unavailable")
	}
	if err := validateVNextOwnerClientOperationIdentity(identity); err != nil {
		return err
	}
	wire := vnextOwnerRPCLifecycleRequest{
		Protocol: vnextOwnerRPCProtocol,
		Identity: vnextOwnerRPCIdentityFromInternal(identity),
	}
	raw, err := marshalVNextOwnerClientPayload(wire)
	if err != nil {
		return err
	}
	request := daemonRequest{}
	switch operation {
	case vnextOwnerRPCOperationCommit:
		request.VNextOwnerCommit = raw
	case vnextOwnerRPCOperationAbort:
		request.VNextOwnerAbort = raw
	default:
		return fmt.Errorf("unsupported VNext Owner lifecycle operation %q", operation)
	}
	response, err := client.roundTrip(ctx, operation, request)
	if err != nil {
		return err
	}
	var decoded vnextOwnerRPCLifecycleResponse
	if err := decodeVNextOwnerClientSuccess(response, operation, &decoded); err != nil {
		return err
	}
	if decoded.Protocol != vnextOwnerRPCProtocol ||
		decoded.Operation != operation || decoded.State != expectedState {
		return fmt.Errorf(
			"VNext Owner %s response has protocol/operation/state %q/%q/%q",
			operation, decoded.Protocol, decoded.Operation, decoded.State)
	}
	return nil
}

func (client *vnextOwnerClient) roundTrip(
	ctx context.Context,
	operation string,
	request daemonRequest,
) (execResponse, error) {
	if err := ctx.Err(); err != nil {
		return execResponse{}, err
	}
	request.CommandLabel = "vnext-owner-client"
	request.TimeoutMillis = 0
	request.Operation = operation
	encodedEnvelope, err := json.Marshal(request)
	if err != nil {
		return execResponse{}, fmt.Errorf(
			"encode VNext Owner %s daemon envelope: %w", operation, err)
	}
	if len(encodedEnvelope) == 0 || len(encodedEnvelope) > maxDaemonFrameBytes {
		return execResponse{}, fmt.Errorf(
			"encoded VNext Owner %s daemon frame is %d bytes, allowed range is 1..%d",
			operation, len(encodedEnvelope), maxDaemonFrameBytes)
	}
	response, err := client.transport.RoundTrip(ctx, request)
	if err != nil {
		return execResponse{}, fmt.Errorf("VNext Owner %s transport: %w", operation, err)
	}
	if err := ctx.Err(); err != nil {
		return execResponse{}, err
	}
	if !response.Ok {
		return execResponse{}, &vnextOwnerClientRemoteError{
			Operation: operation,
			ErrorCode: response.ErrorCode,
			Message:   response.Error,
			Stderr:    response.Stderr,
			ExitCode:  response.ExitCode,
		}
	}
	return response, nil
}

func marshalVNextOwnerClientPayload(value interface{}) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode %s request: %w", vnextOwnerRPCProtocol, err)
	}
	if len(raw) == 0 || len(raw) > maxDaemonFrameBytes {
		return nil, fmt.Errorf(
			"encoded %s payload is %d bytes, allowed range is 1..%d",
			vnextOwnerRPCProtocol, len(raw), maxDaemonFrameBytes)
	}
	return json.RawMessage(raw), nil
}

func decodeVNextOwnerClientSuccess(
	response execResponse,
	operation string,
	target interface{},
) error {
	if !response.Ok {
		return errors.New("VNext Owner success decoder received a failed response")
	}
	if response.Operation != operation {
		return fmt.Errorf(
			"VNext Owner outer response operation is %q, expected %q",
			response.Operation, operation)
	}
	if response.Error != "" || response.ErrorCode != "" || response.Stderr != "" ||
		response.ExitCode != 0 {
		return errors.New("VNext Owner successful outer response contains failure fields")
	}
	if response.Stdout == "" || len(response.Stdout) > maxDaemonFrameBytes {
		return fmt.Errorf(
			"VNext Owner response payload is %d bytes, allowed range is 1..%d",
			len(response.Stdout), maxDaemonFrameBytes)
	}
	if err := decodeStrictVNextOwnerRPC([]byte(response.Stdout), target); err != nil {
		return fmt.Errorf("decode strict VNext Owner %s response: %w", operation, err)
	}
	return nil
}

func convertVNextOwnerClientReserveResponse(
	request vnextOwnerReserveRequest,
	internal vnextCheckpointAllocationRequest,
	wire vnextOwnerRPCReserveResponse,
) (vnextOwnerReserveResponse, error) {
	if wire.Protocol != vnextOwnerRPCProtocol ||
		wire.Operation != vnextOwnerRPCOperationReserve {
		return vnextOwnerReserveResponse{}, fmt.Errorf(
			"reserve response has protocol/operation %q/%q", wire.Protocol, wire.Operation)
	}
	identity := wire.Identity.internal()
	if identity.RequestID != request.RequestID ||
		identity.CheckpointID != request.CheckpointID ||
		identity.ProducerID != request.ProducerID ||
		identity.OwnerID != request.OwnerID ||
		identity.OwnerEpoch != request.OwnerEpoch ||
		identity.AllocationRecordID == 0 ||
		identity.AllocationRecordID > uint64(math.MaxInt64) {
		return vnextOwnerReserveResponse{}, errors.New(
			"reserve response identity differs from the request")
	}
	if len(wire.Contents) != len(request.Contents) || len(wire.Contents) == 0 {
		return vnextOwnerReserveResponse{}, errors.New(
			"reserve response content count differs from the request")
	}
	response := vnextOwnerReserveResponse{
		Operation:  identity,
		TotalPages: wire.TotalPages,
		Contents:   make([]vnextOwnerPortableContentSegment, len(wire.Contents)),
		Extents:    make([]vnextOwnerPortableExtent, len(wire.Extents)),
		Devices:    make([]vnextOwnerPortableDevice, len(wire.Devices)),
	}
	var totalPages uint64
	for index, content := range wire.Contents {
		kind, ok := vnextOwnerRPCContentKind(content.Kind)
		requested := request.Contents[index]
		if !ok || kind != requested.Kind || content.ObjectID != requested.ObjectID ||
			content.ByteLength != requested.ByteLength ||
			content.PageCount != requested.CapacityPages ||
			content.LogicalPageStart != totalPages {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"reserve response content %d differs from the request", index)
		}
		response.Contents[index] = vnextOwnerPortableContentSegment{
			Kind:             kind,
			ObjectID:         content.ObjectID,
			ByteLength:       content.ByteLength,
			LogicalPageStart: content.LogicalPageStart,
			PageCount:        content.PageCount,
		}
		var added bool
		totalPages, added = vnextAdd(totalPages, content.PageCount)
		if !added || totalPages > uint64(math.MaxInt64) {
			return vnextOwnerReserveResponse{}, errors.New(
				"reserve response content coverage overflows")
		}
	}
	if wire.TotalPages != totalPages || wire.TotalPages == 0 ||
		wire.TotalPages != vnextOwnerClientRequestPages(internal) {
		return vnextOwnerReserveResponse{}, errors.New(
			"reserve response total pages differ from requested content")
	}
	if len(wire.Extents) == 0 || len(wire.Extents) > int(request.MaxExtents) ||
		len(wire.Extents) > vnextOwnerRPCMaxExtents || len(wire.Devices) == 0 {
		return vnextOwnerReserveResponse{}, errors.New(
			"reserve response has an invalid extent or device count")
	}
	devices := make(map[string]vnextOwnerRPCPortableDevice, len(wire.Devices))
	previousUUID := ""
	for index, device := range wire.Devices {
		if err := validateVNextOwnerClientDeviceID(device.DeviceUUID); err != nil {
			return vnextOwnerReserveResponse{}, err
		}
		if index > 0 && previousUUID >= device.DeviceUUID {
			return vnextOwnerReserveResponse{}, errors.New(
				"reserve response device table is not strictly UUID ordered")
		}
		if device.DataPageCount == 0 || device.DataPageCount > uint64(math.MaxInt64) ||
			device.ContentRegionBase == 0 ||
			device.ContentRegionBase%cxlcheckpoint.PageSize != 0 ||
			device.ContentRegionBase > uint64(math.MaxInt64) {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"reserve response device %q has invalid geometry", device.DeviceUUID)
		}
		contentBytes, ok := vnextMul(device.DataPageCount, cxlcheckpoint.PageSize)
		contentEnd, endOK := vnextAdd(device.ContentRegionBase, contentBytes)
		if !ok || !endOK || contentEnd > uint64(math.MaxInt64) {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"reserve response device %q content region overflows", device.DeviceUUID)
		}
		devices[device.DeviceUUID] = device
		response.Devices[index] = vnextOwnerPortableDevice(device)
		previousUUID = device.DeviceUUID
	}
	var logicalPage uint64
	usedDevices := make(map[string]struct{})
	physical := make(map[string][]vnextOwnerRPCPortableExtent)
	for index, extent := range wire.Extents {
		device, exists := devices[extent.DeviceUUID]
		end, ok := vnextAdd(extent.StartDataPageIndex, extent.PageCount)
		if !exists || extent.PageCount == 0 ||
			extent.LogicalPageStart != logicalPage || !ok || end > device.DataPageCount {
			return vnextOwnerReserveResponse{}, fmt.Errorf(
				"reserve response extent %d has invalid coverage or geometry", index)
		}
		response.Extents[index] = vnextOwnerPortableExtent(extent)
		logicalPage, ok = vnextAdd(logicalPage, extent.PageCount)
		if !ok {
			return vnextOwnerReserveResponse{}, errors.New(
				"reserve response extent coverage overflows")
		}
		usedDevices[extent.DeviceUUID] = struct{}{}
		physical[extent.DeviceUUID] = append(physical[extent.DeviceUUID], extent)
	}
	if logicalPage != wire.TotalPages || len(usedDevices) != len(devices) {
		return vnextOwnerReserveResponse{}, errors.New(
			"reserve response extents do not exactly cover pages/devices")
	}
	for deviceUUID, extents := range physical {
		sort.Slice(extents, func(i, j int) bool {
			return extents[i].StartDataPageIndex < extents[j].StartDataPageIndex
		})
		for index := 1; index < len(extents); index++ {
			previousEnd, _ := vnextAdd(
				extents[index-1].StartDataPageIndex, extents[index-1].PageCount)
			if previousEnd >= extents[index].StartDataPageIndex {
				return vnextOwnerReserveResponse{}, fmt.Errorf(
					"reserve response extents overlap or are not coalesced on device %q",
					deviceUUID)
			}
		}
	}
	return response, nil
}

func convertVNextOwnerClientSealResponse(
	identity vnextOwnerOperationIdentity,
	wire vnextOwnerRPCSealResponse,
) (vnextOwnerSealResponse, error) {
	if wire.Protocol != vnextOwnerRPCProtocol || wire.Operation != vnextOwnerRPCOperationSeal {
		return vnextOwnerSealResponse{}, fmt.Errorf(
			"seal response has protocol/operation %q/%q", wire.Protocol, wire.Operation)
	}
	root := wire.Root
	for name, value := range map[string]string{
		"root ID": root.RootID, "MMTemplate ID": root.MMTemplateID,
		"PageMap ID": root.PageMapID,
	} {
		if err := validateVNextOwnerClientText(name, value); err != nil {
			return vnextOwnerSealResponse{}, err
		}
	}
	if root.RootVersion == 0 || root.RootVersion > uint64(math.MaxInt64) ||
		root.PageMapVersion == 0 || root.PageMapVersion > uint64(math.MaxInt64) ||
		root.ContractID != cxlcheckpoint.V6CompatibilityID {
		return vnextOwnerSealResponse{}, errors.New(
			"seal response has invalid root versions or compatibility contract")
	}
	deviceDigest, err := decodeCanonicalVNextOwnerClientDigest(
		"device-table digest", root.DeviceTableDigest)
	if err != nil {
		return vnextOwnerSealResponse{}, err
	}
	publicationSHA, err := decodeCanonicalVNextOwnerClientDigest(
		"publication SHA-256", root.Locator.PublicationSHA256)
	if err != nil {
		return vnextOwnerSealResponse{}, err
	}
	if root.Locator.PublicationByteLength == 0 ||
		root.Locator.PublicationByteLength > vnextOwnerRPCMaxPublicationBytes ||
		len(root.Locator.PageRuns) == 0 ||
		len(root.Locator.PageRuns) > vnextOwnerRPCMaxExtents {
		return vnextOwnerSealResponse{}, errors.New(
			"seal response publication locator has invalid length or run count")
	}
	wantPages := (root.Locator.PublicationByteLength + cxlcheckpoint.PageSize - 1) /
		cxlcheckpoint.PageSize
	runs := make([]vnextOwnerPublicationPageRun, len(root.Locator.PageRuns))
	var covered uint64
	physical := make(map[string][]vnextOwnerRPCPublicationPageRun)
	for index, run := range root.Locator.PageRuns {
		if err := validateVNextOwnerClientDeviceID(run.FirstPage.DeviceID); err != nil {
			return vnextOwnerSealResponse{}, err
		}
		if run.FirstPage.OwnerID != identity.OwnerID ||
			run.FirstPage.AllocationRecordID != identity.AllocationRecordID ||
			run.FirstPage.DataPageIndex > uint64(math.MaxInt64) ||
			run.PageCount == 0 || run.PageCount > uint64(math.MaxInt64) {
			return vnextOwnerSealResponse{}, fmt.Errorf(
				"seal response publication run %d has invalid authority or range", index)
		}
		end, ok := vnextAdd(run.FirstPage.DataPageIndex, run.PageCount)
		if !ok || end > uint64(math.MaxInt64) {
			return vnextOwnerSealResponse{}, fmt.Errorf(
				"seal response publication run %d overflows", index)
		}
		if index > 0 {
			previous := root.Locator.PageRuns[index-1]
			previousEnd := previous.FirstPage.DataPageIndex + previous.PageCount
			if previous.FirstPage.OwnerID == run.FirstPage.OwnerID &&
				previous.FirstPage.DeviceID == run.FirstPage.DeviceID &&
				previous.FirstPage.AllocationRecordID == run.FirstPage.AllocationRecordID &&
				previousEnd == run.FirstPage.DataPageIndex {
				return vnextOwnerSealResponse{}, fmt.Errorf(
					"seal response publication runs %d and %d are not canonically coalesced",
					index-1, index)
			}
		}
		covered, ok = vnextAdd(covered, run.PageCount)
		if !ok || covered > wantPages {
			return vnextOwnerSealResponse{}, errors.New(
				"seal response publication locator page coverage overflows")
		}
		runs[index] = vnextOwnerPublicationPageRun{
			FirstPage: cxlcheckpoint.PageID{
				OwnerID:            run.FirstPage.OwnerID,
				DeviceUUID:         run.FirstPage.DeviceID,
				DataPageIndex:      run.FirstPage.DataPageIndex,
				AllocationRecordID: run.FirstPage.AllocationRecordID,
			},
			PageCount: run.PageCount,
		}
		physical[run.FirstPage.DeviceID] = append(
			physical[run.FirstPage.DeviceID], run)
	}
	if covered != wantPages {
		return vnextOwnerSealResponse{}, fmt.Errorf(
			"seal response locator covers %d pages, expected %d", covered, wantPages)
	}
	for deviceID, deviceRuns := range physical {
		sort.Slice(deviceRuns, func(i, j int) bool {
			return deviceRuns[i].FirstPage.DataPageIndex <
				deviceRuns[j].FirstPage.DataPageIndex
		})
		for index := 1; index < len(deviceRuns); index++ {
			previousEnd := deviceRuns[index-1].FirstPage.DataPageIndex +
				deviceRuns[index-1].PageCount
			if previousEnd > deviceRuns[index].FirstPage.DataPageIndex {
				return vnextOwnerSealResponse{}, fmt.Errorf(
					"seal response publication runs overlap on device %q", deviceID)
			}
		}
	}
	return vnextOwnerSealResponse{Root: vnextOwnerCheckpointRoot{
		RootID:            root.RootID,
		RootVersion:       root.RootVersion,
		MMTemplateID:      root.MMTemplateID,
		PageMapID:         root.PageMapID,
		PageMapVersion:    root.PageMapVersion,
		DeviceTableDigest: deviceDigest,
		ContractID:        root.ContractID,
		Locator: vnextOwnerCheckpointRootLocator{
			PublicationByteLength: root.Locator.PublicationByteLength,
			PublicationSHA256:     publicationSHA,
			PageRuns:              runs,
		},
	}}, nil
}

func decodeCanonicalVNextOwnerClientDigest(
	name string,
	encoded string,
) ([32]byte, error) {
	var digest [32]byte
	if len(encoded) != hex.EncodedLen(len(digest)) || encoded != strings.ToLower(encoded) {
		return digest, fmt.Errorf("%s is not canonical 64-character lowercase hex", name)
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(digest) {
		return digest, fmt.Errorf("decode %s: %w", name, err)
	}
	copy(digest[:], decoded)
	return digest, nil
}

func validateVNextOwnerClientText(name, value string) error {
	if value == "" || !utf8.ValidString(value) ||
		len([]byte(value)) > cxlcheckpoint.MaxIdentityBytes ||
		strings.TrimSpace(value) != value {
		return fmt.Errorf("%s is empty, invalid UTF-8, too long, or has surrounding whitespace", name)
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return fmt.Errorf("%s contains a control character", name)
		}
	}
	return nil
}

func validateVNextOwnerClientOperationIdentity(
	identity vnextOwnerOperationIdentity,
) error {
	if err := validateVNextProducerOperationIdentity(identity); err != nil {
		return err
	}
	for name, value := range map[string]string{
		"request ID": identity.RequestID, "checkpoint ID": identity.CheckpointID,
		"producer ID": identity.ProducerID, "Owner ID": identity.OwnerID,
	} {
		if err := validateVNextOwnerClientText(name, value); err != nil {
			return err
		}
	}
	return nil
}

func validateVNextOwnerClientDeviceID(value string) error {
	if err := validateVNextOwnerClientText("device UUID", value); err != nil {
		return err
	}
	fileURI := len(value) >= len("file:") && strings.EqualFold(value[:len("file:")], "file:")
	if value == "." || value == ".." || strings.ContainsAny(value, "/\\") || fileURI {
		return fmt.Errorf("device UUID %q is a local path or URI", value)
	}
	return nil
}

func vnextOwnerClientRequestPages(request vnextCheckpointAllocationRequest) uint64 {
	var total uint64
	for _, content := range request.Contents {
		total += content.PageCount
	}
	return total
}
