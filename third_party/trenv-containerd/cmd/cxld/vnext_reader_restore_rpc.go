package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	vnextReaderRestoreProtocol  = "cxld.vnext-reader-restore.v1"
	vnextReaderRestoreOperation = "vnextReaderRestore"

	// Restore is the latency-sensitive path and main waits for every admitted
	// runtime request before closing Reader resources. Keeping both values at
	// the daemon's 30-second frame-stage bound prevents a caller from extending
	// shutdown drain with a multi-hour restore deadline.
	vnextReaderRestoreDefaultTimeout = 30 * time.Second
	vnextReaderRestoreMaxTimeout     = 30 * time.Second
)

type vnextReaderRestoreErrorCode string

const (
	vnextReaderRestoreInvalidRequest     vnextReaderRestoreErrorCode = "INVALID_REQUEST"
	vnextReaderRestoreUnavailable        vnextReaderRestoreErrorCode = "UNAVAILABLE"
	vnextReaderRestoreActivationRejected vnextReaderRestoreErrorCode = "ACTIVATION_REJECTED"
	vnextReaderRestoreFailed             vnextReaderRestoreErrorCode = "RESTORE_FAILED"
)

var vnextReaderRestoreSpec = vnextReaderActivationOperationSpec{
	protocol:  vnextReaderRestoreProtocol,
	operation: vnextReaderRestoreOperation,
}

// vnextReaderRestoreIdentityWire is deliberately portable. A local DAX path,
// file descriptor, mapping offset, or checkpoint directory is never accepted
// from the runtime caller.
type vnextReaderRestoreIdentityWire struct {
	RestoreAuthorizationID string `json:"restoreAuthorizationId"`
	CheckpointID           string `json:"checkpointId"`
	ExecutorNodeID         string `json:"executorNodeId"`
	ExecutorCxldLogicalID  string `json:"executorCxldLogicalId"`
	TargetContainerID      string `json:"targetContainerId"`
}

// vnextReaderRestoreRequestWire carries the complete historical ACQUIRED
// authorization and the complete stable activation evidence. An
// authorization ID by itself is intentionally not a data-plane credential.
type vnextReaderRestoreRequestWire struct {
	Protocol   string                            `json:"protocol"`
	Operation  string                            `json:"operation"`
	Request    vnextReaderRestoreIdentityWire    `json:"request"`
	Acquired   vnextReaderPrepareAcquiredWire    `json:"acquired"`
	Activation vnextReaderActivationEvidenceWire `json:"activation"`
	State      vnextReaderActivationState        `json:"state"`
}

// vnextReaderRestoreDaemonRequestWire is the exact local Unix envelope. Its
// strict decoder rejects duplicate, unknown, missing, mixed legacy, and mixed
// Owner fields before daemonRequest is constructed.
type vnextReaderRestoreDaemonRequestWire struct {
	CommandLabel       string                        `json:"commandLabel"`
	TimeoutMillis      int64                         `json:"timeoutMillis"`
	Operation          string                        `json:"operation"`
	VNextReaderRestore vnextReaderRestoreRequestWire `json:"vnextReaderRestore"`
}

// vnextReaderRestoreSuccessWire contains only bounded identity metadata. It
// never returns publication bytes, a local path, a file descriptor, or a DAX
// offset through the control socket.
type vnextReaderRestoreSuccessWire struct {
	Protocol               string `json:"protocol"`
	Operation              string `json:"operation"`
	RestoreAuthorizationID string `json:"restoreAuthorizationId"`
	CheckpointID           string `json:"checkpointId"`
	TargetContainerID      string `json:"targetContainerId"`
	RootID                 string `json:"rootId"`
	RootVersion            uint64 `json:"rootVersion"`
	MappingID              string `json:"mappingId"`
	MappingGeneration      uint64 `json:"mappingGeneration"`
}

// vnextReaderRestoreRPC is an optional local adapter. Production construction
// deliberately leaves it nil until a separately reviewed read-only devdax
// source and VNext CRIU runner are supplied; no dummy implementation is
// installed because a failed first source call permanently consumes the
// one-shot activation claim.
type vnextReaderRestoreRPC struct {
	reader *vnextAuthorizedReader
}

func newVNextReaderRestoreRPC(
	reader *vnextAuthorizedReader,
) (*vnextReaderRestoreRPC, error) {
	if reader == nil || reader.directory == nil || reader.activationStore == nil ||
		reader.source == nil || reader.runner == nil {
		return nil, errors.New("VNext Reader restore implementation is incomplete")
	}
	return &vnextReaderRestoreRPC{reader: reader}, nil
}

func decodeVNextReaderRestoreRequest(
	raw []byte,
) (vnextReaderActivatedRestoreRequest, error) {
	var wire vnextReaderRestoreRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderRestoreSpec, raw, &wire); err != nil {
		return vnextReaderActivatedRestoreRequest{}, err
	}
	if wire.Protocol != vnextReaderRestoreProtocol ||
		wire.Operation != vnextReaderRestoreOperation ||
		wire.State != vnextReaderActivationActiveArmed {
		return vnextReaderActivatedRestoreRequest{}, errors.New(
			"VNext Reader restore protocol, operation, or state is invalid")
	}
	acquired, err := wire.Acquired.internal()
	if err != nil {
		return vnextReaderActivatedRestoreRequest{}, err
	}
	identity := vnextReaderActivationRequestIdentity{
		Acquired:            acquired,
		ActivationRequestID: wire.Activation.ActivationRequestID,
	}
	if err := validateVNextReaderActivationRequestIdentity(identity); err != nil {
		return vnextReaderActivatedRestoreRequest{}, err
	}
	activation, err := wire.Activation.internal(
		identity, vnextReaderActivationActiveArmed)
	if err != nil {
		return vnextReaderActivatedRestoreRequest{}, err
	}
	request := vnextReaderRequest{
		RestoreAuthorizationID: wire.Request.RestoreAuthorizationID,
		CheckpointID:           wire.Request.CheckpointID,
		ExecutorID:             wire.Request.ExecutorNodeID,
		CxldLogicalID:          wire.Request.ExecutorCxldLogicalID,
		TargetContainerID:      wire.Request.TargetContainerID,
	}
	if err := validateVNextReaderRequest(request); err != nil {
		return vnextReaderActivatedRestoreRequest{}, err
	}
	if err := validateVNextReaderActivationRestoreIdentity(
		request, acquired.Authorization); err != nil {
		return vnextReaderActivatedRestoreRequest{}, err
	}
	return vnextReaderActivatedRestoreRequest{
		Request: request, Activation: activation,
	}, nil
}

func marshalVNextReaderRestoreRequest(
	request vnextReaderActivatedRestoreRequest,
) ([]byte, error) {
	if err := validateVNextReaderRequest(request.Request); err != nil {
		return nil, err
	}
	if request.Activation.State != vnextReaderActivationActiveArmed {
		return nil, errVNextReaderActivationNotActiveArmed
	}
	if err := validateVNextReaderActivationEvidence(
		request.Activation, request.Activation.Request); err != nil {
		return nil, err
	}
	if err := validateVNextReaderActivationRestoreIdentity(
		request.Request,
		request.Activation.Request.Acquired.Authorization); err != nil {
		return nil, err
	}
	wire := vnextReaderRestoreRequestWire{
		Protocol:  vnextReaderRestoreProtocol,
		Operation: vnextReaderRestoreOperation,
		Request: vnextReaderRestoreIdentityWire{
			RestoreAuthorizationID: request.Request.RestoreAuthorizationID,
			CheckpointID:           request.Request.CheckpointID,
			ExecutorNodeID:         request.Request.ExecutorID,
			ExecutorCxldLogicalID:  request.Request.CxldLogicalID,
			TargetContainerID:      request.Request.TargetContainerID,
		},
		Acquired: vnextReaderPrepareAcquiredWireFromInternal(
			request.Activation.Request.Acquired),
		Activation: vnextReaderActivationEvidenceWireFromInternal(
			request.Activation),
		State: request.Activation.State,
	}
	return marshalBoundedVNextReaderActivationJSON(vnextReaderRestoreSpec, wire)
}

func decodeDaemonRequestWithVNextReaderRestore(
	body []byte,
) (daemonRequest, error) {
	selected, err := containsVNextReaderRestoreEnvelope(body)
	if err != nil {
		return daemonRequest{}, err
	}
	if !selected {
		return decodeDaemonRequest(body)
	}
	var wire vnextReaderRestoreDaemonRequestWire
	if err := decodeStrictVNextReaderActivationJSON(
		vnextReaderRestoreSpec, body, &wire); err != nil {
		return daemonRequest{}, err
	}
	if wire.Operation != vnextReaderRestoreOperation ||
		wire.VNextReaderRestore.Protocol != vnextReaderRestoreProtocol ||
		wire.VNextReaderRestore.Operation != vnextReaderRestoreOperation {
		return daemonRequest{}, errors.New(
			"VNext Reader restore daemon operation does not match its payload")
	}
	raw, err := marshalBoundedVNextReaderActivationJSON(
		vnextReaderRestoreSpec, wire.VNextReaderRestore)
	if err != nil {
		return daemonRequest{}, err
	}
	return daemonRequest{
		CommandLabel:       wire.CommandLabel,
		TimeoutMillis:      wire.TimeoutMillis,
		Operation:          wire.Operation,
		VNextReaderRestore: append(json.RawMessage(nil), raw...),
	}, nil
}

// containsVNextReaderRestoreEnvelope selects the strict decoder when either
// the operation or its payload field is present. Consequently an Owner or
// legacy operation cannot smuggle a Reader payload that another decoder would
// otherwise ignore.
func containsVNextReaderRestoreEnvelope(body []byte) (bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delimiter, object := token.(json.Delim)
	if !object || delimiter != '{' {
		return false, nil
	}
	selected := false
	fields := 0
	for decoder.More() {
		if fields >= vnextOwnerRPCMaxDaemonFields {
			return false, fmt.Errorf(
				"daemon request contains more than %d top-level fields",
				vnextOwnerRPCMaxDaemonFields)
		}
		fieldToken, err := decoder.Token()
		if err != nil {
			return false, err
		}
		name, ok := fieldToken.(string)
		if !ok {
			return false, errors.New("daemon request field name is not a string")
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return false, fmt.Errorf("decode daemon request field %q: %w", name, err)
		}
		if strings.EqualFold(name, "vnextReaderRestore") {
			selected = true
		}
		if strings.EqualFold(name, "operation") {
			var operation string
			if json.Unmarshal(raw, &operation) == nil &&
				strings.TrimSpace(operation) == vnextReaderRestoreOperation {
				selected = true
			}
		}
		fields++
	}
	closing, err := decoder.Token()
	if err != nil {
		return false, err
	}
	if delimiter, ok := closing.(json.Delim); !ok || delimiter != '}' {
		return false, errors.New("daemon request has an invalid object terminator")
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return false, errors.New("daemon request has trailing JSON")
		}
		return false, fmt.Errorf("decode daemon request trailer: %w", err)
	}
	return selected, nil
}

func runVNextReaderRestoreRPC(
	raw json.RawMessage,
	timeoutMillis int64,
	rpc *vnextReaderRestoreRPC,
) execResponse {
	request, err := decodeVNextReaderRestoreRequest(raw)
	if err != nil {
		return vnextReaderRestoreErrorResponse(vnextReaderRestoreInvalidRequest)
	}
	timeout, err := vnextReaderRestoreTimeout(timeoutMillis)
	if err != nil {
		return vnextReaderRestoreErrorResponse(vnextReaderRestoreInvalidRequest)
	}
	if rpc == nil || rpc.reader == nil {
		return vnextReaderRestoreErrorResponse(vnextReaderRestoreUnavailable)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := rpc.reader.Restore(ctx, request); err != nil {
		return vnextReaderRestoreErrorResponse(vnextReaderRestoreFailureCode(err))
	}
	root := request.Activation.Request.Acquired.Authorization.Root
	response := vnextReaderRestoreSuccessWire{
		Protocol:               vnextReaderRestoreProtocol,
		Operation:              vnextReaderRestoreOperation,
		RestoreAuthorizationID: request.Request.RestoreAuthorizationID,
		CheckpointID:           request.Request.CheckpointID,
		TargetContainerID:      request.Request.TargetContainerID,
		RootID:                 root.RootID,
		RootVersion:            root.RootVersion,
		MappingID:              request.Activation.MappingID,
		MappingGeneration:      request.Activation.MappingGeneration,
	}
	body, err := marshalBoundedVNextReaderActivationJSON(
		vnextReaderRestoreSpec, response)
	if err != nil {
		return vnextReaderRestoreErrorResponse(vnextReaderRestoreUnavailable)
	}
	return execResponse{Ok: true, Stdout: string(body) + "\n"}
}

func vnextReaderRestoreTimeout(timeoutMillis int64) (time.Duration, error) {
	if timeoutMillis == 0 {
		return vnextReaderRestoreDefaultTimeout, nil
	}
	if timeoutMillis < 0 || timeoutMillis >
		int64(vnextReaderRestoreMaxTimeout/time.Millisecond) {
		return 0, fmt.Errorf(
			"VNext Reader restore timeoutMillis is outside 0..%d",
			vnextReaderRestoreMaxTimeout/time.Millisecond)
	}
	return time.Duration(timeoutMillis) * time.Millisecond, nil
}

func vnextReaderRestoreFailureCode(err error) vnextReaderRestoreErrorCode {
	for _, activationError := range []error{
		errVNextReaderActivationIncarnationMismatch,
		errVNextReaderActivationConflict,
		errVNextReaderActivationNotFoundFenced,
		errVNextReaderActivationNotPending,
		errVNextReaderActivationNotActiveArmed,
		errVNextReaderFirstReadAlreadyClaimed,
		errVNextReaderFirstReadAdmissionClosed,
	} {
		if errors.Is(err, activationError) {
			return vnextReaderRestoreActivationRejected
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return vnextReaderRestoreUnavailable
	}
	return vnextReaderRestoreFailed
}

// vnextReaderRestoreErrorResponse never serializes an internal cause. DAX
// source and CRIU adapter errors may contain host-local paths, file details,
// or other implementation data that the runtime caller must not observe.
func vnextReaderRestoreErrorResponse(
	code vnextReaderRestoreErrorCode,
) execResponse {
	message := "VNext Reader restore failed"
	switch code {
	case vnextReaderRestoreInvalidRequest:
		message = "VNext Reader restore request is invalid"
	case vnextReaderRestoreUnavailable:
		message = "VNext Reader restore is unavailable"
	case vnextReaderRestoreActivationRejected:
		message = "VNext Reader restore activation was rejected"
	case vnextReaderRestoreFailed:
		message = "VNext Reader restore failed"
	}
	return execResponse{Ok: false, Error: message, ErrorCode: string(code)}
}
