package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"unicode/utf8"
)

const (
	vnextOwnerRPCProtocol = "cxld.vnext-owner.v1"

	vnextOwnerRPCOperationReserve   = "vnextOwnerReserve"
	vnextOwnerRPCOperationSeal      = "vnextOwnerSeal"
	vnextOwnerRPCOperationCommit    = "vnextOwnerCommit"
	vnextOwnerRPCOperationAbort     = "vnextOwnerAbort"
	vnextOwnerRPCOperationInventory = "vnextOwnerInventory"

	// JSON/base64 is intentionally limited below the 64 MiB publication codec
	// ceiling. At 40 bytes per record, eight MiB of TRCRC006 describes roughly
	// 0.8 GiB of 4 KiB pages. Larger metadata requires a future streaming or
	// SCM_RIGHTS protocol, not a larger single allocation in this v1 adapter.
	vnextOwnerRPCMaxPublicationBytes = 8 << 20
	vnextOwnerRPCMaxSidecarBytes     = 8 << 20
	vnextOwnerRPCMaxSidecars         = 4096
	// One record is emitted for every producer-written non-memory,
	// non-publication content page. This bound keeps the worst-case compact
	// JSON array near 9.8 MiB, leaving enough of the 32 MiB control frame for
	// base64 expansion of both decoded eight-MiB bulk fields and bounded object
	// overhead. Larger checkpoints require a future streaming or SCM_RIGHTS
	// protocol.
	vnextOwnerRPCMaxExternalContentPageCRCs = 1 << 17
	vnextOwnerRPCMaxContents                = 4096
	vnextOwnerRPCMaxExtents                 = 256
	// A device UUID can use the complete 4 KiB identity limit. Even if every
	// byte needs HTML-safe JSON escaping, this count keeps both the inner
	// inventory JSON and its escaped outer execResponse below 32 MiB.
	vnextOwnerRPCMaxInventoryDevices = 1024
	// The complete daemon envelope currently defines fifteen fields. Keep a
	// little legacy headroom, but reject an attacker-controlled number of
	// unknown or duplicate members before retaining RawMessage entries.
	vnextOwnerRPCMaxDaemonFields = 32
)

var activeVNextOwnerRPC *vnextOwnerRPC

// vnextOwnerRPC is only a transport adapter. Durable authority and lifecycle
// validation remain in vnextOwnerService.
type vnextOwnerRPC struct {
	service *vnextOwnerService
}

func newVNextOwnerRPC(service *vnextOwnerService) *vnextOwnerRPC {
	if service == nil {
		return nil
	}
	return &vnextOwnerRPC{service: service}
}

type vnextOwnerRPCOperationIdentity struct {
	RequestID          string `json:"requestId"`
	CheckpointID       string `json:"checkpointId"`
	ProducerID         string `json:"producerId"`
	OwnerID            string `json:"ownerId"`
	OwnerEpoch         uint64 `json:"ownerEpoch"`
	AllocationRecordID uint64 `json:"allocationRecordId"`
}

type vnextOwnerRPCReserveContent struct {
	Kind          string `json:"kind"`
	ObjectID      uint64 `json:"objectId"`
	ByteLength    uint64 `json:"byteLength"`
	CapacityPages uint64 `json:"capacityPages"`
}

type vnextOwnerRPCReserveContents []vnextOwnerRPCReserveContent

type vnextOwnerRPCReserveRequest struct {
	Protocol     string                       `json:"protocol"`
	RequestID    string                       `json:"requestId"`
	CheckpointID string                       `json:"checkpointId"`
	ProducerID   string                       `json:"producerId"`
	OwnerID      string                       `json:"ownerId"`
	OwnerEpoch   uint64                       `json:"ownerEpoch"`
	Contents     vnextOwnerRPCReserveContents `json:"contents"`
	MaxExtents   uint32                       `json:"maxExtents"`
}

type vnextOwnerRPCPortableContent struct {
	Kind             string `json:"kind"`
	ObjectID         uint64 `json:"objectId"`
	ByteLength       uint64 `json:"byteLength"`
	LogicalPageStart uint64 `json:"logicalPageStart"`
	PageCount        uint64 `json:"pageCount"`
}

type vnextOwnerRPCPortableExtent struct {
	DeviceUUID         string `json:"deviceUuid"`
	StartDataPageIndex uint64 `json:"startDataPageIndex"`
	PageCount          uint64 `json:"pageCount"`
	LogicalPageStart   uint64 `json:"logicalPageStart"`
}

type vnextOwnerRPCPortableDevice struct {
	DeviceUUID        string `json:"deviceUuid"`
	DataPageCount     uint64 `json:"dataPageCount"`
	ContentRegionBase uint64 `json:"contentRegionBase"`
}

type vnextOwnerRPCReserveResponse struct {
	Protocol   string                         `json:"protocol"`
	Operation  string                         `json:"operation"`
	Identity   vnextOwnerRPCOperationIdentity `json:"identity"`
	TotalPages uint64                         `json:"totalPages"`
	Contents   []vnextOwnerRPCPortableContent `json:"contents"`
	Extents    []vnextOwnerRPCPortableExtent  `json:"extents"`
	Devices    []vnextOwnerRPCPortableDevice  `json:"devices"`
}

type vnextOwnerRPCSidecar struct {
	PagesImageID uint32 `json:"pagesImageId"`
	Bytes        []byte `json:"bytes"`
}

type vnextOwnerRPCSidecars []vnextOwnerRPCSidecar

type vnextOwnerRPCExternalContentPageCRC struct {
	LogicalPage   uint64 `json:"logicalPage"`
	ContentCRC32C uint32 `json:"contentCrc32c"`
	CopyEngine    uint32 `json:"copyEngine"`
}

type vnextOwnerRPCExternalContentPageCRCs []vnextOwnerRPCExternalContentPageCRC

type vnextOwnerRPCSealRequest struct {
	Protocol                string                               `json:"protocol"`
	Identity                vnextOwnerRPCOperationIdentity       `json:"identity"`
	PublicationEnvelope     []byte                               `json:"publicationEnvelope"`
	CRCPageSidecars         vnextOwnerRPCSidecars                `json:"crcPageSidecars"`
	ExternalContentPageCRCs vnextOwnerRPCExternalContentPageCRCs `json:"externalContentPageCRCs"`
}

type vnextOwnerRPCPageID struct {
	OwnerID            string `json:"ownerId"`
	DeviceID           string `json:"deviceId"`
	DataPageIndex      uint64 `json:"dataPageIndex"`
	AllocationRecordID uint64 `json:"allocationRecordId"`
}

type vnextOwnerRPCPublicationPageRun struct {
	FirstPage vnextOwnerRPCPageID `json:"firstPage"`
	PageCount uint64              `json:"pageCount"`
}

type vnextOwnerRPCRootLocator struct {
	PublicationByteLength uint64                            `json:"publicationByteLength"`
	PublicationSHA256     string                            `json:"publicationSha256"`
	PageRuns              []vnextOwnerRPCPublicationPageRun `json:"pageRuns"`
}

type vnextOwnerRPCCheckpointRoot struct {
	RootID            string                   `json:"rootId"`
	RootVersion       uint64                   `json:"rootVersion"`
	MMTemplateID      string                   `json:"mmTemplateId"`
	PageMapID         string                   `json:"pageMapId"`
	PageMapVersion    uint64                   `json:"pageMapVersion"`
	DeviceTableDigest string                   `json:"deviceTableDigest"`
	ContractID        string                   `json:"contractId"`
	Locator           vnextOwnerRPCRootLocator `json:"locator"`
}

type vnextOwnerRPCSealResponse struct {
	Protocol  string                      `json:"protocol"`
	Operation string                      `json:"operation"`
	Root      vnextOwnerRPCCheckpointRoot `json:"root"`
}

type vnextOwnerRPCLifecycleRequest struct {
	Protocol string                         `json:"protocol"`
	Identity vnextOwnerRPCOperationIdentity `json:"identity"`
}

type vnextOwnerRPCLifecycleResponse struct {
	Protocol  string `json:"protocol"`
	Operation string `json:"operation"`
	State     string `json:"state"`
}

type vnextOwnerRPCInventoryRequest struct {
	Protocol           string `json:"protocol"`
	RequestID          string `json:"requestId"`
	ExpectedOwnerID    string `json:"expectedOwnerId"`
	ExpectedOwnerEpoch uint64 `json:"expectedOwnerEpoch"`
}

type vnextOwnerRPCInventoryDevice struct {
	DeviceUUID     string `json:"deviceUuid"`
	TotalDataPages uint64 `json:"totalDataPages"`
	FreeDataPages  uint64 `json:"freeDataPages"`
}

type vnextOwnerRPCInventoryDevices []vnextOwnerRPCInventoryDevice

type vnextOwnerRPCInventoryResponse struct {
	Protocol         string                        `json:"protocol"`
	Operation        string                        `json:"operation"`
	RequestID        string                        `json:"requestId"`
	OwnerID          string                        `json:"ownerId"`
	OwnerEpoch       uint64                        `json:"ownerEpoch"`
	SnapshotSequence uint64                        `json:"snapshotSequence"`
	Devices          vnextOwnerRPCInventoryDevices `json:"devices"`
}

func (contents *vnextOwnerRPCReserveContents) UnmarshalJSON(raw []byte) error {
	decoder, err := newVNextOwnerRPCBoundedArrayDecoder(raw, "contents")
	if err != nil {
		return err
	}
	decoded := make(vnextOwnerRPCReserveContents, 0)
	for decoder.More() {
		if len(decoded) >= vnextOwnerRPCMaxContents {
			return fmt.Errorf(
				"VNext Owner contents contain more than %d elements",
				vnextOwnerRPCMaxContents)
		}
		var content vnextOwnerRPCReserveContent
		if err := decoder.Decode(&content); err != nil {
			return fmt.Errorf("decode VNext Owner content %d: %w", len(decoded), err)
		}
		decoded = append(decoded, content)
	}
	if err := finishVNextOwnerRPCBoundedArray(decoder, "contents"); err != nil {
		return err
	}
	*contents = decoded
	return nil
}

func (sidecars *vnextOwnerRPCSidecars) UnmarshalJSON(raw []byte) error {
	decoder, err := newVNextOwnerRPCBoundedArrayDecoder(raw, "crcPageSidecars")
	if err != nil {
		return err
	}
	decoded := make(vnextOwnerRPCSidecars, 0)
	for decoder.More() {
		if len(decoded) >= vnextOwnerRPCMaxSidecars {
			return fmt.Errorf(
				"VNext Owner CRC sidecars contain more than %d elements",
				vnextOwnerRPCMaxSidecars)
		}
		var sidecar vnextOwnerRPCSidecar
		if err := decoder.Decode(&sidecar); err != nil {
			return fmt.Errorf("decode VNext Owner CRC sidecar %d: %w", len(decoded), err)
		}
		decoded = append(decoded, sidecar)
	}
	if err := finishVNextOwnerRPCBoundedArray(decoder, "crcPageSidecars"); err != nil {
		return err
	}
	*sidecars = decoded
	return nil
}

func (records *vnextOwnerRPCExternalContentPageCRCs) UnmarshalJSON(raw []byte) error {
	decoder, err := newVNextOwnerRPCBoundedArrayDecoder(raw, "externalContentPageCRCs")
	if err != nil {
		return err
	}
	decoded := make(vnextOwnerRPCExternalContentPageCRCs, 0)
	for decoder.More() {
		if len(decoded) >= vnextOwnerRPCMaxExternalContentPageCRCs {
			return fmt.Errorf(
				"VNext Owner external content CRCs contain more than %d elements",
				vnextOwnerRPCMaxExternalContentPageCRCs)
		}
		var record vnextOwnerRPCExternalContentPageCRC
		if err := decoder.Decode(&record); err != nil {
			return fmt.Errorf(
				"decode VNext Owner external content CRC %d: %w", len(decoded), err)
		}
		decoded = append(decoded, record)
	}
	if err := finishVNextOwnerRPCBoundedArray(
		decoder, "externalContentPageCRCs"); err != nil {
		return err
	}
	*records = decoded
	return nil
}

func newVNextOwnerRPCBoundedArrayDecoder(
	raw []byte,
	field string,
) (*json.Decoder, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, fmt.Errorf("VNext Owner %s must be a JSON array", field)
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("decode VNext Owner %s array: %w", field, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '[' {
		return nil, fmt.Errorf("VNext Owner %s must begin with a JSON array", field)
	}
	return decoder, nil
}

func finishVNextOwnerRPCBoundedArray(decoder *json.Decoder, field string) error {
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("decode VNext Owner %s closing token: %w", field, err)
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return fmt.Errorf("VNext Owner %s has an invalid closing token", field)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("VNext Owner %s has trailing JSON", field)
		}
		return fmt.Errorf("decode VNext Owner %s trailer: %w", field, err)
	}
	return nil
}

func runVNextOwnerRPC(
	operation string,
	request daemonRequest,
	rpc *vnextOwnerRPC,
) execResponse {
	// VNext Owner mutations include persistence barriers that must not be
	// cancelled halfway through. The v1 transport therefore does not pretend
	// that the legacy command timeout applies to these operations. A future
	// protocol may add a deadline for admission before a mutation starts.
	if request.TimeoutMillis != 0 {
		return vnextOwnerRPCErrorResponse(errors.New(
			"VNext Owner protocol v1 does not support timeoutMillis; it must be zero"))
	}
	raw, err := vnextOwnerRPCPayload(operation, request)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	if rpc == nil || rpc.service == nil {
		return execResponse{
			Ok:        false,
			Error:     "VNext Owner RPC is not configured on this cxld",
			ErrorCode: string(vnextOwnerServiceUnavailable),
		}
	}

	switch operation {
	case vnextOwnerRPCOperationReserve:
		return rpc.reserve(raw)
	case vnextOwnerRPCOperationSeal:
		return rpc.seal(raw)
	case vnextOwnerRPCOperationCommit:
		return rpc.commit(raw)
	case vnextOwnerRPCOperationAbort:
		return rpc.abort(raw)
	case vnextOwnerRPCOperationInventory:
		return rpc.inventory(raw)
	default:
		return vnextOwnerRPCErrorResponse(fmt.Errorf("unsupported VNext Owner operation %q", operation))
	}
}

func isVNextOwnerRPCOperation(operation string) bool {
	switch operation {
	case vnextOwnerRPCOperationReserve,
		vnextOwnerRPCOperationSeal,
		vnextOwnerRPCOperationCommit,
		vnextOwnerRPCOperationAbort,
		vnextOwnerRPCOperationInventory:
		return true
	default:
		return false
	}
}

type vnextOwnerRPCRawField struct {
	name string
	raw  json.RawMessage
}

var vnextOwnerRPCDaemonFields = map[string]struct{}{
	"commandLabel":         {},
	"timeoutMillis":        {},
	"operation":            {},
	"createContainer":      {},
	"checkpointContainer":  {},
	"restoreIntoContainer": {},
	"switchIntoCandidate":  {},
	"container":            {},
	"cleanupContainers":    {},
	"metadataResolve":      {},
	"vnextOwnerReserve":    {},
	"vnextOwnerSeal":       {},
	"vnextOwnerCommit":     {},
	"vnextOwnerAbort":      {},
	"vnextOwnerInventory":  {},
}

var vnextOwnerRPCLegacyPayloadFields = map[string]struct{}{
	"createContainer":      {},
	"checkpointContainer":  {},
	"restoreIntoContainer": {},
	"switchIntoCandidate":  {},
	"container":            {},
	"cleanupContainers":    {},
	"metadataResolve":      {},
}

// decodeDaemonRequest preserves json.Unmarshal for legacy operations. It
// first scans only the bounded top-level JSON values as RawMessage, however,
// so a VNext request cannot force a legacy payload's nested arrays or maps to
// be materialized before the mixed-protocol request is rejected.
func decodeDaemonRequest(body []byte) (daemonRequest, error) {
	fields, vnext, object, err := inspectVNextOwnerRPCDaemonEnvelope(body)
	if err != nil {
		return daemonRequest{}, err
	}
	if !object || !vnext {
		var request daemonRequest
		if err := json.Unmarshal(body, &request); err != nil {
			return daemonRequest{}, err
		}
		return request, nil
	}
	return decodeVNextOwnerRPCDaemonEnvelope(fields)
}

func inspectVNextOwnerRPCDaemonEnvelope(
	body []byte,
) ([]vnextOwnerRPCRawField, bool, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return nil, false, false, err
	}
	delimiter, object := token.(json.Delim)
	if !object || delimiter != '{' {
		return nil, false, false, nil
	}
	fields := make([]vnextOwnerRPCRawField, 0, 8)
	vnext := false
	for decoder.More() {
		if len(fields) >= vnextOwnerRPCMaxDaemonFields {
			return nil, false, true, fmt.Errorf(
				"daemon request contains more than %d top-level fields",
				vnextOwnerRPCMaxDaemonFields)
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, false, true, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, false, true, errors.New("daemon request field name is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, false, true, fmt.Errorf("decode daemon request field %q: %w", name, err)
		}
		fields = append(fields, vnextOwnerRPCRawField{name: name, raw: raw})
		if strings.EqualFold(name, "operation") {
			var operation string
			if err := json.Unmarshal(raw, &operation); err == nil &&
				isVNextOwnerRPCOperation(strings.TrimSpace(operation)) {
				vnext = true
			}
		}
	}
	token, err = decoder.Token()
	if err != nil {
		return nil, false, true, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, false, true, errors.New("daemon request has an invalid object terminator")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, false, true, errors.New("daemon request has trailing JSON")
		}
		return nil, false, true, fmt.Errorf("decode daemon request trailer: %w", err)
	}
	return fields, vnext, true, nil
}

func decodeVNextOwnerRPCDaemonEnvelope(
	fields []vnextOwnerRPCRawField,
) (daemonRequest, error) {
	var request daemonRequest
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		if _, allowed := vnextOwnerRPCDaemonFields[field.name]; !allowed {
			return daemonRequest{}, fmt.Errorf(
				"decode %s request: unknown field %q",
				vnextOwnerRPCProtocol, field.name)
		}
		if _, duplicate := seen[field.name]; duplicate {
			return daemonRequest{}, fmt.Errorf(
				"decode %s request: duplicate field %q",
				vnextOwnerRPCProtocol, field.name)
		}
		seen[field.name] = struct{}{}
		if _, legacy := vnextOwnerRPCLegacyPayloadFields[field.name]; legacy {
			return daemonRequest{}, errors.New(
				"VNext Owner request cannot contain a legacy operation payload")
		}
		switch field.name {
		case "commandLabel":
			if err := decodeVNextOwnerRPCDaemonScalar(
				field.raw, &request.CommandLabel, field.name); err != nil {
				return daemonRequest{}, fmt.Errorf("decode VNext commandLabel: %w", err)
			}
		case "timeoutMillis":
			if err := decodeVNextOwnerRPCDaemonScalar(
				field.raw, &request.TimeoutMillis, field.name); err != nil {
				return daemonRequest{}, fmt.Errorf("decode VNext timeoutMillis: %w", err)
			}
		case "operation":
			if err := decodeVNextOwnerRPCDaemonScalar(
				field.raw, &request.Operation, field.name); err != nil {
				return daemonRequest{}, fmt.Errorf("decode VNext operation: %w", err)
			}
		case "vnextOwnerReserve":
			request.VNextOwnerReserve = append(json.RawMessage(nil), field.raw...)
		case "vnextOwnerSeal":
			request.VNextOwnerSeal = append(json.RawMessage(nil), field.raw...)
		case "vnextOwnerCommit":
			request.VNextOwnerCommit = append(json.RawMessage(nil), field.raw...)
		case "vnextOwnerAbort":
			request.VNextOwnerAbort = append(json.RawMessage(nil), field.raw...)
		case "vnextOwnerInventory":
			request.VNextOwnerInventory = append(json.RawMessage(nil), field.raw...)
		}
	}
	if !isVNextOwnerRPCOperation(strings.TrimSpace(request.Operation)) {
		return daemonRequest{}, fmt.Errorf(
			"VNext Owner envelope has unsupported operation %q", request.Operation)
	}
	return request, nil
}

func decodeVNextOwnerRPCDaemonScalar(
	raw json.RawMessage,
	target interface{},
	field string,
) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return fmt.Errorf("%s cannot be null", field)
	}
	return json.Unmarshal(trimmed, target)
}

func vnextOwnerRPCPayload(operation string, request daemonRequest) (json.RawMessage, error) {
	if request.CreateContainer != nil || request.Checkpoint != nil ||
		request.Restore != nil || request.Switch != nil || request.Container != nil ||
		request.Cleanup != nil || request.MetadataResolve != nil {
		return nil, errors.New(
			"VNext Owner request cannot contain a legacy operation payload")
	}
	payloads := []struct {
		operation string
		payload   json.RawMessage
	}{
		{vnextOwnerRPCOperationReserve, request.VNextOwnerReserve},
		{vnextOwnerRPCOperationSeal, request.VNextOwnerSeal},
		{vnextOwnerRPCOperationCommit, request.VNextOwnerCommit},
		{vnextOwnerRPCOperationAbort, request.VNextOwnerAbort},
		{vnextOwnerRPCOperationInventory, request.VNextOwnerInventory},
	}
	present := 0
	var selected json.RawMessage
	for _, candidate := range payloads {
		if len(candidate.payload) == 0 {
			continue
		}
		present++
		if candidate.operation == operation {
			selected = candidate.payload
		}
	}
	if present != 1 {
		return nil, fmt.Errorf(
			"VNext Owner request must contain exactly one operation payload, found %d", present)
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("%s operation is missing its matching payload", operation)
	}
	return selected, nil
}

func (rpc *vnextOwnerRPC) inventory(raw json.RawMessage) execResponse {
	request, err := decodeVNextOwnerRPCInventoryRequest(raw)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}

	response, err := rpc.service.inventory(request)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	if response.RequestID != request.RequestID ||
		response.OwnerID != request.OwnerID ||
		response.OwnerEpoch != request.OwnerEpoch ||
		response.SnapshotSequence == 0 ||
		response.SnapshotSequence > uint64(math.MaxInt64) ||
		len(response.Devices) == 0 ||
		len(response.Devices) > vnextOwnerRPCMaxInventoryDevices {
		return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
			"inventory",
			vnextOwnerServiceUnavailable,
			"Owner inventory cannot be represented by the bounded signed RPC contract",
			nil))
	}

	wireResponse := vnextOwnerRPCInventoryResponse{
		Protocol:         vnextOwnerRPCProtocol,
		Operation:        vnextOwnerRPCOperationInventory,
		RequestID:        response.RequestID,
		OwnerID:          response.OwnerID,
		OwnerEpoch:       response.OwnerEpoch,
		SnapshotSequence: response.SnapshotSequence,
		Devices: make(
			vnextOwnerRPCInventoryDevices, len(response.Devices)),
	}
	previousUUID := ""
	for index, device := range response.Devices {
		if err := validateVNextOwnerClientDeviceID(device.DeviceUUID); err != nil {
			return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
				"inventory",
				vnextOwnerServiceUnavailable,
				"Owner inventory contains an invalid device UUID",
				err))
		}
		if index > 0 && previousUUID >= device.DeviceUUID {
			return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
				"inventory",
				vnextOwnerServiceUnavailable,
				"Owner inventory is not strictly UUID-sorted",
				errVNextCorrupt))
		}
		if device.TotalDataPages == 0 ||
			device.TotalDataPages > uint64(math.MaxInt64) ||
			device.FreeDataPages > device.TotalDataPages ||
			device.FreeDataPages > uint64(math.MaxInt64) {
			return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
				"inventory",
				vnextOwnerServiceUnavailable,
				"Owner inventory contains capacity outside the signed ABI",
				errVNextCorrupt))
		}
		wireResponse.Devices[index] = vnextOwnerRPCInventoryDevice{
			DeviceUUID:     device.DeviceUUID,
			TotalDataPages: device.TotalDataPages,
			FreeDataPages:  device.FreeDataPages,
		}
		previousUUID = device.DeviceUUID
	}
	return marshalVNextOwnerRPCResponse(wireResponse)
}

func decodeVNextOwnerRPCInventoryRequest(
	raw json.RawMessage,
) (vnextOwnerInventoryRequest, error) {
	var wire vnextOwnerRPCInventoryRequest
	if err := decodeStrictVNextOwnerRPC(raw, &wire); err != nil {
		return vnextOwnerInventoryRequest{}, err
	}
	if err := requireVNextOwnerRPCProtocol(wire.Protocol); err != nil {
		return vnextOwnerInventoryRequest{}, err
	}
	if err := validateVNextOwnerClientText("inventory request ID", wire.RequestID); err != nil {
		return vnextOwnerInventoryRequest{}, err
	}
	if err := validateVNextOwnerClientText(
		"expected Owner ID", wire.ExpectedOwnerID); err != nil {
		return vnextOwnerInventoryRequest{}, err
	}
	if wire.ExpectedOwnerEpoch == 0 ||
		wire.ExpectedOwnerEpoch > uint64(math.MaxInt64) {
		return vnextOwnerInventoryRequest{}, errors.New(
			"expected Owner epoch is outside the signed ABI")
	}
	return vnextOwnerInventoryRequest{
		RequestID:  wire.RequestID,
		OwnerID:    wire.ExpectedOwnerID,
		OwnerEpoch: wire.ExpectedOwnerEpoch,
	}, nil
}

func (rpc *vnextOwnerRPC) reserve(raw json.RawMessage) execResponse {
	request, err := decodeVNextOwnerRPCReserveRequest(raw)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	response, err := rpc.service.reserve(request)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	wireResponse := vnextOwnerRPCReserveResponse{
		Protocol:   vnextOwnerRPCProtocol,
		Operation:  vnextOwnerRPCOperationReserve,
		Identity:   vnextOwnerRPCIdentityFromInternal(response.Operation),
		TotalPages: response.TotalPages,
		Contents:   make([]vnextOwnerRPCPortableContent, len(response.Contents)),
		Extents:    make([]vnextOwnerRPCPortableExtent, len(response.Extents)),
		Devices:    make([]vnextOwnerRPCPortableDevice, len(response.Devices)),
	}
	for index, content := range response.Contents {
		kind, ok := vnextOwnerRPCContentKindName(content.Kind)
		if !ok {
			return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
				"reserve",
				vnextOwnerServiceUnavailable,
				"Owner response contains an unknown content kind",
				nil))
		}
		wireResponse.Contents[index] = vnextOwnerRPCPortableContent{
			Kind:             kind,
			ObjectID:         content.ObjectID,
			ByteLength:       content.ByteLength,
			LogicalPageStart: content.LogicalPageStart,
			PageCount:        content.PageCount,
		}
	}
	for index, extent := range response.Extents {
		wireResponse.Extents[index] = vnextOwnerRPCPortableExtent{
			DeviceUUID:         extent.DeviceUUID,
			StartDataPageIndex: extent.StartDataPageIndex,
			PageCount:          extent.PageCount,
			LogicalPageStart:   extent.LogicalPageStart,
		}
	}
	for index, device := range response.Devices {
		wireResponse.Devices[index] = vnextOwnerRPCPortableDevice{
			DeviceUUID:        device.DeviceUUID,
			DataPageCount:     device.DataPageCount,
			ContentRegionBase: device.ContentRegionBase,
		}
	}
	return marshalVNextOwnerRPCResponse(wireResponse)
}

func decodeVNextOwnerRPCReserveRequest(
	raw json.RawMessage,
) (vnextOwnerReserveRequest, error) {
	var wire vnextOwnerRPCReserveRequest
	if err := decodeStrictVNextOwnerRPC(raw, &wire); err != nil {
		return vnextOwnerReserveRequest{}, err
	}
	if err := requireVNextOwnerRPCProtocol(wire.Protocol); err != nil {
		return vnextOwnerReserveRequest{}, err
	}
	if wire.MaxExtents == 0 || wire.MaxExtents > vnextOwnerRPCMaxExtents {
		return vnextOwnerReserveRequest{}, fmt.Errorf(
			"maxExtents %d is outside the RPC response-safe range 1..%d",
			wire.MaxExtents, vnextOwnerRPCMaxExtents)
	}
	request := vnextOwnerReserveRequest{
		RequestID:    wire.RequestID,
		CheckpointID: wire.CheckpointID,
		ProducerID:   wire.ProducerID,
		OwnerID:      wire.OwnerID,
		OwnerEpoch:   wire.OwnerEpoch,
		Contents:     make([]vnextOwnerReserveContent, len(wire.Contents)),
		MaxExtents:   wire.MaxExtents,
	}
	var externalContentPages uint64
	for index, content := range wire.Contents {
		kind, ok := vnextOwnerRPCContentKind(content.Kind)
		if !ok {
			return vnextOwnerReserveRequest{}, fmt.Errorf(
				"content %d has unsupported kind %q", index, content.Kind)
		}
		request.Contents[index] = vnextOwnerReserveContent{
			Kind:          kind,
			ObjectID:      content.ObjectID,
			ByteLength:    content.ByteLength,
			CapacityPages: content.CapacityPages,
		}
		if kind != vnextOwnerServiceContentMemory &&
			kind != vnextOwnerServiceContentPublication {
			if content.CapacityPages >
				uint64(vnextOwnerRPCMaxExternalContentPageCRCs)-externalContentPages {
				return vnextOwnerReserveRequest{}, fmt.Errorf(
					"producer-written non-memory content exceeds the RPC seal limit of %d pages",
					vnextOwnerRPCMaxExternalContentPageCRCs)
			}
			externalContentPages += content.CapacityPages
		}
	}
	for _, identity := range []struct {
		name  string
		value string
	}{
		{"request ID", wire.RequestID},
		{"checkpoint ID", wire.CheckpointID},
		{"producer ID", wire.ProducerID},
		{"Owner ID", wire.OwnerID},
	} {
		if err := validateVNextOwnerClientText(identity.name, identity.value); err != nil {
			return vnextOwnerReserveRequest{}, err
		}
	}
	if _, err := request.internal(); err != nil {
		return vnextOwnerReserveRequest{}, fmt.Errorf(
			"validate VNext reserve request: %w", err)
	}
	return request, nil
}

func (rpc *vnextOwnerRPC) seal(raw json.RawMessage) execResponse {
	request, err := decodeVNextOwnerRPCSealRequest(raw)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	response, err := rpc.service.sealExternal(request)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	wireResponse := vnextOwnerRPCSealResponse{
		Protocol:  vnextOwnerRPCProtocol,
		Operation: vnextOwnerRPCOperationSeal,
		Root: vnextOwnerRPCCheckpointRoot{
			RootID:            response.Root.RootID,
			RootVersion:       response.Root.RootVersion,
			MMTemplateID:      response.Root.MMTemplateID,
			PageMapID:         response.Root.PageMapID,
			PageMapVersion:    response.Root.PageMapVersion,
			DeviceTableDigest: hex.EncodeToString(response.Root.DeviceTableDigest[:]),
			ContractID:        response.Root.ContractID,
			Locator: vnextOwnerRPCRootLocator{
				PublicationByteLength: response.Root.Locator.PublicationByteLength,
				PublicationSHA256: hex.EncodeToString(
					response.Root.Locator.PublicationSHA256[:]),
				PageRuns: make(
					[]vnextOwnerRPCPublicationPageRun,
					len(response.Root.Locator.PageRuns)),
			},
		},
	}
	for index, run := range response.Root.Locator.PageRuns {
		wireResponse.Root.Locator.PageRuns[index] = vnextOwnerRPCPublicationPageRun{
			FirstPage: vnextOwnerRPCPageID{
				OwnerID:            run.FirstPage.OwnerID,
				DeviceID:           run.FirstPage.DeviceUUID,
				DataPageIndex:      run.FirstPage.DataPageIndex,
				AllocationRecordID: run.FirstPage.AllocationRecordID,
			},
			PageCount: run.PageCount,
		}
	}
	return marshalVNextOwnerRPCResponse(wireResponse)
}

func decodeVNextOwnerRPCSealRequest(
	raw json.RawMessage,
) (vnextOwnerExternalSealRequest, error) {
	var wire vnextOwnerRPCSealRequest
	if err := decodeStrictVNextOwnerRPC(raw, &wire); err != nil {
		return vnextOwnerExternalSealRequest{}, err
	}
	if err := requireVNextOwnerRPCProtocol(wire.Protocol); err != nil {
		return vnextOwnerExternalSealRequest{}, err
	}
	if len(wire.PublicationEnvelope) == 0 ||
		len(wire.PublicationEnvelope) > vnextOwnerRPCMaxPublicationBytes {
		return vnextOwnerExternalSealRequest{}, fmt.Errorf(
			"publication envelope is %d bytes, allowed range is 1..%d",
			len(wire.PublicationEnvelope), vnextOwnerRPCMaxPublicationBytes)
	}
	if len(wire.CRCPageSidecars) > vnextOwnerRPCMaxSidecars {
		return vnextOwnerExternalSealRequest{}, fmt.Errorf(
			"CRC sidecar count %d exceeds %d",
			len(wire.CRCPageSidecars), vnextOwnerRPCMaxSidecars)
	}
	sidecars := make(map[uint32][]byte, len(wire.CRCPageSidecars))
	totalSidecarBytes := 0
	for index, sidecar := range wire.CRCPageSidecars {
		if sidecar.PagesImageID == 0 || len(sidecar.Bytes) == 0 {
			return vnextOwnerExternalSealRequest{}, fmt.Errorf(
				"CRC sidecar %d has a zero pages-image ID or empty bytes", index)
		}
		if _, duplicate := sidecars[sidecar.PagesImageID]; duplicate {
			return vnextOwnerExternalSealRequest{}, fmt.Errorf(
				"CRC sidecar pages-image ID %d is duplicated", sidecar.PagesImageID)
		}
		if len(sidecar.Bytes) > vnextOwnerRPCMaxSidecarBytes-totalSidecarBytes {
			return vnextOwnerExternalSealRequest{}, fmt.Errorf(
				"CRC sidecar bytes exceed transport limit %d", vnextOwnerRPCMaxSidecarBytes)
		}
		totalSidecarBytes += len(sidecar.Bytes)
		sidecars[sidecar.PagesImageID] = sidecar.Bytes
	}
	if len(wire.ExternalContentPageCRCs) > vnextOwnerRPCMaxExternalContentPageCRCs {
		return vnextOwnerExternalSealRequest{}, fmt.Errorf(
			"external content CRC count %d exceeds %d",
			len(wire.ExternalContentPageCRCs),
			vnextOwnerRPCMaxExternalContentPageCRCs)
	}
	externalContentPageCRCs := make(
		[]vnextExternalContentPageCRC, len(wire.ExternalContentPageCRCs))
	seenLogicalPages := make(map[uint64]struct{}, len(wire.ExternalContentPageCRCs))
	for index, record := range wire.ExternalContentPageCRCs {
		if record.LogicalPage > uint64(math.MaxInt64) {
			return vnextOwnerExternalSealRequest{}, fmt.Errorf(
				"external content CRC %d logical page %d exceeds the signed ABI",
				index, record.LogicalPage)
		}
		engine := vnextCRCCopyEngine(record.CopyEngine)
		if !engine.valid() {
			return vnextOwnerExternalSealRequest{}, fmt.Errorf(
				"external content CRC %d has unsupported copy engine %d",
				index, record.CopyEngine)
		}
		if _, duplicate := seenLogicalPages[record.LogicalPage]; duplicate {
			return vnextOwnerExternalSealRequest{}, fmt.Errorf(
				"external content logical page %d is duplicated",
				record.LogicalPage)
		}
		seenLogicalPages[record.LogicalPage] = struct{}{}
		externalContentPageCRCs[index] = vnextExternalContentPageCRC{
			LogicalPage:   record.LogicalPage,
			ContentCRC32C: record.ContentCRC32C,
			CopyEngine:    engine,
		}
	}
	request := vnextOwnerExternalSealRequest{
		Operation:               wire.Identity.internal(),
		PublicationEnvelope:     wire.PublicationEnvelope,
		CRCPageSidecars:         sidecars,
		ExternalContentPageCRCs: externalContentPageCRCs,
	}
	if err := validateVNextOwnerClientOperationIdentity(request.Operation); err != nil {
		return vnextOwnerExternalSealRequest{}, err
	}
	return request, nil
}

func (rpc *vnextOwnerRPC) commit(raw json.RawMessage) execResponse {
	return rpc.lifecycle(raw, vnextOwnerRPCOperationCommit, "COMMITTED", rpc.service.commit)
}

func (rpc *vnextOwnerRPC) abort(raw json.RawMessage) execResponse {
	return rpc.lifecycle(raw, vnextOwnerRPCOperationAbort, "ABORTED", rpc.service.abort)
}

func (rpc *vnextOwnerRPC) lifecycle(
	raw json.RawMessage,
	operation string,
	state string,
	apply func(vnextOwnerOperationIdentity) error,
) execResponse {
	identity, err := decodeVNextOwnerRPCLifecycleRequest(raw)
	if err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	if err := apply(identity); err != nil {
		return vnextOwnerRPCErrorResponse(err)
	}
	return marshalVNextOwnerRPCResponse(vnextOwnerRPCLifecycleResponse{
		Protocol:  vnextOwnerRPCProtocol,
		Operation: operation,
		State:     state,
	})
}

func decodeVNextOwnerRPCLifecycleRequest(
	raw json.RawMessage,
) (vnextOwnerOperationIdentity, error) {
	var wire vnextOwnerRPCLifecycleRequest
	if err := decodeStrictVNextOwnerRPC(raw, &wire); err != nil {
		return vnextOwnerOperationIdentity{}, err
	}
	if err := requireVNextOwnerRPCProtocol(wire.Protocol); err != nil {
		return vnextOwnerOperationIdentity{}, err
	}
	identity := wire.Identity.internal()
	if err := validateVNextOwnerClientOperationIdentity(identity); err != nil {
		return vnextOwnerOperationIdentity{}, err
	}
	return identity, nil
}

func decodeStrictVNextOwnerRPC(raw []byte, target interface{}) error {
	if !utf8.Valid(raw) {
		return fmt.Errorf("decode %s request: JSON is not valid UTF-8", vnextOwnerRPCProtocol)
	}
	if err := validateVNextOwnerRPCJSONShape(raw, target); err != nil {
		return fmt.Errorf("decode %s request: %w", vnextOwnerRPCProtocol, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s request: %w", vnextOwnerRPCProtocol, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s request: trailing JSON value", vnextOwnerRPCProtocol)
		}
		return fmt.Errorf("decode %s request trailer: %w", vnextOwnerRPCProtocol, err)
	}
	return nil
}

func validateVNextOwnerRPCJSONShape(raw []byte, target interface{}) error {
	targetType := reflect.TypeOf(target)
	if targetType == nil || targetType.Kind() != reflect.Ptr ||
		targetType.Elem().Kind() != reflect.Struct {
		return errors.New("strict VNext decoder target must be a pointer to a struct")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := validateVNextOwnerRPCJSONValue(
		decoder, targetType.Elem(), "request"); err != nil {
		return err
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return fmt.Errorf("decode JSON trailer: %w", err)
	}
	return nil
}

func validateVNextOwnerRPCJSONValue(
	decoder *json.Decoder,
	valueType reflect.Type,
	path string,
) error {
	for valueType.Kind() == reflect.Ptr {
		valueType = valueType.Elem()
	}
	switch valueType.Kind() {
	case reflect.Struct:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '{' {
			return fmt.Errorf("%s must be a JSON object", path)
		}
		fields := make(map[string]reflect.Type, valueType.NumField())
		fieldOrder := make([]string, 0, valueType.NumField())
		for index := 0; index < valueType.NumField(); index++ {
			field := valueType.Field(index)
			if field.PkgPath != "" {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" {
				name = field.Name
			}
			if name != "-" {
				fields[name] = field.Type
				fieldOrder = append(fieldOrder, name)
			}
		}
		seen := make(map[string]struct{}, len(fields))
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%s field: %w", path, err)
			}
			name, ok := token.(string)
			if !ok {
				return fmt.Errorf("%s field name is not a string", path)
			}
			fieldType, allowed := fields[name]
			if !allowed {
				return fmt.Errorf("%s has unknown field %q", path, name)
			}
			if _, duplicate := seen[name]; duplicate {
				return fmt.Errorf("%s has duplicate field %q", path, name)
			}
			seen[name] = struct{}{}
			if err := validateVNextOwnerRPCJSONValue(
				decoder, fieldType, path+"."+name); err != nil {
				return err
			}
		}
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%s closing token: %w", path, err)
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
			return fmt.Errorf("%s has an invalid object terminator", path)
		}
		for _, name := range fieldOrder {
			if _, present := seen[name]; !present {
				return fmt.Errorf("%s is missing required field %q", path, name)
			}
		}
		return nil
	case reflect.Slice:
		if valueType.Elem().Kind() == reflect.Uint8 {
			token, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}
			if _, ok := token.(string); !ok {
				return fmt.Errorf("%s must be a base64 JSON string", path)
			}
			return nil
		}
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		delimiter, ok := token.(json.Delim)
		if !ok || delimiter != '[' {
			return fmt.Errorf("%s must be a JSON array", path)
		}
		limit := 0
		switch valueType {
		case reflect.TypeOf(vnextOwnerRPCReserveContents{}):
			limit = vnextOwnerRPCMaxContents
		case reflect.TypeOf(vnextOwnerRPCSidecars{}):
			limit = vnextOwnerRPCMaxSidecars
		case reflect.TypeOf(vnextOwnerRPCExternalContentPageCRCs{}):
			limit = vnextOwnerRPCMaxExternalContentPageCRCs
		case reflect.TypeOf(vnextOwnerRPCInventoryDevices{}):
			limit = vnextOwnerRPCMaxInventoryDevices
		case reflect.TypeOf(vnextOwnerGatewayRouteWires{}):
			limit = vnextOwnerGatewayMaxRoutes
		}
		count := 0
		for decoder.More() {
			if limit != 0 && count >= limit {
				return fmt.Errorf("%s contains more than %d elements", path, limit)
			}
			if err := validateVNextOwnerRPCJSONValue(
				decoder, valueType.Elem(), fmt.Sprintf("%s[%d]", path, count)); err != nil {
				return err
			}
			count++
		}
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("%s closing token: %w", path, err)
		}
		if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
			return fmt.Errorf("%s has an invalid array terminator", path)
		}
		return nil
	case reflect.String:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := token.(string); !ok {
			return fmt.Errorf("%s must be a JSON string", path)
		}
		return nil
	case reflect.Bool:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := token.(bool); !ok {
			return fmt.Errorf("%s must be a JSON boolean", path)
		}
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if _, ok := token.(json.Number); !ok {
			return fmt.Errorf("%s must be a JSON number", path)
		}
		return nil
	default:
		return fmt.Errorf("%s has unsupported JSON target type %s", path, valueType)
	}
}

func requireVNextOwnerRPCProtocol(protocol string) error {
	if protocol != vnextOwnerRPCProtocol {
		return fmt.Errorf("VNext Owner protocol is %q, expected %q", protocol, vnextOwnerRPCProtocol)
	}
	return nil
}

func (identity vnextOwnerRPCOperationIdentity) internal() vnextOwnerOperationIdentity {
	return vnextOwnerOperationIdentity{
		RequestID:          identity.RequestID,
		CheckpointID:       identity.CheckpointID,
		ProducerID:         identity.ProducerID,
		OwnerID:            identity.OwnerID,
		OwnerEpoch:         identity.OwnerEpoch,
		AllocationRecordID: identity.AllocationRecordID,
	}
}

func vnextOwnerRPCIdentityFromInternal(
	identity vnextOwnerOperationIdentity,
) vnextOwnerRPCOperationIdentity {
	return vnextOwnerRPCOperationIdentity{
		RequestID:          identity.RequestID,
		CheckpointID:       identity.CheckpointID,
		ProducerID:         identity.ProducerID,
		OwnerID:            identity.OwnerID,
		OwnerEpoch:         identity.OwnerEpoch,
		AllocationRecordID: identity.AllocationRecordID,
	}
}

func vnextOwnerRPCContentKind(name string) (vnextOwnerServiceContentKind, bool) {
	switch name {
	case "memory":
		return vnextOwnerServiceContentMemory, true
	case "artifact":
		return vnextOwnerServiceContentArtifact, true
	case "mm_template":
		return vnextOwnerServiceContentMMTemplate, true
	case "page_map":
		return vnextOwnerServiceContentPageMap, true
	case "restore_blob":
		return vnextOwnerServiceContentRestoreBlob, true
	case "publication":
		return vnextOwnerServiceContentPublication, true
	default:
		return 0, false
	}
}

func vnextOwnerRPCContentKindName(kind vnextOwnerServiceContentKind) (string, bool) {
	switch kind {
	case vnextOwnerServiceContentMemory:
		return "memory", true
	case vnextOwnerServiceContentArtifact:
		return "artifact", true
	case vnextOwnerServiceContentMMTemplate:
		return "mm_template", true
	case vnextOwnerServiceContentPageMap:
		return "page_map", true
	case vnextOwnerServiceContentRestoreBlob:
		return "restore_blob", true
	case vnextOwnerServiceContentPublication:
		return "publication", true
	default:
		return "", false
	}
}

func marshalVNextOwnerRPCResponse(value interface{}) execResponse {
	payload, err := json.Marshal(value)
	if err != nil {
		return vnextOwnerRPCErrorResponse(vnextOwnerServiceFailure(
			"encode",
			vnextOwnerServiceUnavailable,
			"VNext Owner response cannot be encoded",
			err))
	}
	return execResponse{Ok: true, Stdout: string(payload) + "\n"}
}

func vnextOwnerRPCErrorResponse(err error) execResponse {
	code := vnextOwnerServiceInvalidRequest
	var serviceError *vnextOwnerServiceError
	if errors.As(err, &serviceError) {
		code = serviceError.Code
	}
	return execResponse{
		Ok:        false,
		Error:     err.Error(),
		ErrorCode: string(code),
	}
}
