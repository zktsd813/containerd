package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// vnextReaderActivationTransportRPC is narrower than the activation service.
// The listener selects one concrete instance by exact ALPN before the RPC sees
// any JSON. The route's frozen operation specification remains separate so a
// structurally compatible RPC cannot change operation identity silently.
type vnextReaderActivationTransportRPC interface {
	Handle(context.Context, string, []byte) ([]byte, *vnextReaderActivationRPCError)
}

type vnextReaderActivationTLSFailureWire struct {
	Protocol   string                          `json:"protocol"`
	Operation  string                          `json:"operation"`
	ErrorCode  vnextReaderActivationErrorCode  `json:"errorCode"`
	Acceptance vnextReaderActivationAcceptance `json:"acceptance"`
}

type vnextReaderActivationTLSHandlerResult struct {
	body    []byte
	failure *vnextReaderActivationRPCError
}

// startVNextReaderPrepareStatusIdentifyAndActivationTLSServer is the only
// production constructor that advertises activation. All three activation
// routes are mandatory and share the existing Reader listener, authentication,
// process-wide admission, and drain lifetime.
func startVNextReaderPrepareStatusIdentifyAndActivationTLSServer(
	config vnextReaderPrepareTLSServerConfig,
	prepareRPC vnextReaderPrepareTransportRPC,
	statusRPC vnextReaderPreparedStatusTransportRPC,
	identifyRPC vnextReaderIdentifyTransportRPC,
	activationProposalRPC vnextReaderActivationTransportRPC,
	activationCommitRPC vnextReaderActivationTransportRPC,
	activationStatusRPC vnextReaderActivationTransportRPC,
	requestAdmission chan struct{},
	largeFrameAdmission chan struct{},
) (*vnextReaderPrepareTLSServer, error) {
	if vnextReaderPreparedStatusNilInterface(statusRPC) {
		return nil, errors.New(
			"VNext Reader STATUS_AND_FENCE TLS RPC is unavailable")
	}
	if vnextReaderPreparedStatusNilInterface(identifyRPC) {
		return nil, errors.New("VNext Reader IDENTIFY TLS RPC is unavailable")
	}
	for name, rpc := range map[string]vnextReaderActivationTransportRPC{
		"proposal": activationProposalRPC,
		"commit":   activationCommitRPC,
		"status":   activationStatusRPC,
	} {
		if vnextReaderPreparedStatusNilInterface(rpc) {
			return nil, fmt.Errorf(
				"VNext Reader activation %s TLS RPC is unavailable", name)
		}
	}
	return startVNextReaderPrepareTLSServerCommon(
		config, prepareRPC, statusRPC, identifyRPC,
		activationProposalRPC, activationCommitRPC, activationStatusRPC,
		requestAdmission, largeFrameAdmission)
}

func (server *vnextReaderPrepareTLSServer) hasAllVNextReaderActivationTLSRoutes() bool {
	return server != nil &&
		!vnextReaderPreparedStatusNilInterface(server.activationProposalRPC) &&
		!vnextReaderPreparedStatusNilInterface(server.activationCommitRPC) &&
		!vnextReaderPreparedStatusNilInterface(server.activationStatusRPC)
}

func (server *vnextReaderPrepareTLSServer) vnextReaderActivationTLSRoute(
	alpn string,
) (vnextReaderActivationOperationSpec, vnextReaderActivationTransportRPC, bool) {
	if !server.hasAllVNextReaderActivationTLSRoutes() {
		return vnextReaderActivationOperationSpec{}, nil, false
	}
	switch alpn {
	case vnextReaderActivationProposalALPN:
		return vnextReaderActivationProposalSpec,
			server.activationProposalRPC, true
	case vnextReaderActivationCommitALPN:
		return vnextReaderActivationCommitSpec,
			server.activationCommitRPC, true
	case vnextReaderActivationStatusALPN:
		return vnextReaderActivationStatusSpec,
			server.activationStatusRPC, true
	default:
		return vnextReaderActivationOperationSpec{}, nil, false
	}
}

func (server *vnextReaderPrepareTLSServer) serveAuthenticatedActivation(
	conn net.Conn,
	principal string,
	spec vnextReaderActivationOperationSpec,
	rpc vnextReaderActivationTransportRPC,
	releaseRequest func(),
) {
	body, releaseLarge, failure := readVNextReaderActivationTLSFrame(
		conn, server.largeFrameAdmission, server.requestReadTimeout, spec)
	if failure != nil {
		releaseRequest()
		server.writeActivationFailure(conn, spec, failure)
		return
	}
	// PROPOSE, COMMIT, and STATUS may install retained process-local state. The
	// request and large-frame permits therefore remain held until both the
	// actual handler and the response-side validation/write path are terminal.
	drain := newVNextReaderPrepareTLSAdmissionDrain(releaseRequest, releaseLarge)
	defer drain.markServeTerminal()
	result := server.runActivationHandler(
		principal, spec, rpc, body, drain.markHandlerTerminal)
	if result.failure != nil {
		if result.failure.Protocol != spec.protocol {
			result.failure = vnextReaderActivationFailure(
				spec, vnextReaderActivationUnavailable,
				vnextReaderActivationAcceptanceUnknown,
				errors.New(
					"activation handler failure protocol differs from negotiated ALPN"))
		}
		server.writeActivationFailure(conn, spec, result.failure)
		return
	}
	if len(result.body) == 0 || len(result.body) > vnextReaderActivationMaxFrameBytes {
		server.writeActivationFailure(conn, spec,
			vnextReaderActivationFailure(
				spec, vnextReaderActivationUnavailable,
				vnextReaderActivationAcceptanceUnknown,
				fmt.Errorf("Reader activation %s handler response has %d bytes",
					spec.operation, len(result.body))))
		return
	}
	if err := validateVNextReaderActivationTLSSuccess(spec, result.body); err != nil {
		server.writeActivationFailure(conn, spec,
			vnextReaderActivationFailure(
				spec, vnextReaderActivationUnavailable,
				vnextReaderActivationAcceptanceUnknown,
				fmt.Errorf("strictly validate Reader activation response: %v", err)))
		return
	}
	server.writeBody(conn, result.body)
}

func (server *vnextReaderPrepareTLSServer) runActivationHandler(
	principal string,
	spec vnextReaderActivationOperationSpec,
	rpc vnextReaderActivationTransportRPC,
	body []byte,
	markHandlerTerminal func(),
) vnextReaderActivationTLSHandlerResult {
	handlerCtx, cancel := context.WithTimeout(
		context.Background(), server.handlerTimeout)
	defer cancel()
	resultChannel := make(chan vnextReaderActivationTLSHandlerResult, 1)
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		defer markHandlerTerminal()
		result := vnextReaderActivationTLSHandlerResult{}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					result.failure = vnextReaderActivationFailure(
						spec, vnextReaderActivationUnavailable,
						vnextReaderActivationAcceptanceUnknown,
						fmt.Errorf("VNext Reader activation RPC panic: %v", recovered))
				}
			}()
			result.body, result.failure = rpc.Handle(
				handlerCtx, principal, body)
		}()
		resultChannel <- result
	}()
	select {
	case result := <-resultChannel:
		if handlerCtx.Err() != nil {
			return vnextReaderActivationTLSHandlerTimeout(spec, handlerCtx.Err())
		}
		return result
	case <-handlerCtx.Done():
		return vnextReaderActivationTLSHandlerTimeout(spec, handlerCtx.Err())
	}
}

func vnextReaderActivationTLSHandlerTimeout(
	spec vnextReaderActivationOperationSpec,
	cause error,
) vnextReaderActivationTLSHandlerResult {
	return vnextReaderActivationTLSHandlerResult{
		failure: vnextReaderActivationFailure(
			spec, vnextReaderActivationUnavailable,
			// The handler may have installed PENDING, a permanent tombstone,
			// or ACTIVE_ARMED before the local timer won.
			vnextReaderActivationAcceptanceUnknown,
			fmt.Errorf("VNext Reader activation TLS handler deadline: %v", cause)),
	}
}

func readVNextReaderActivationTLSFrame(
	conn net.Conn,
	largeFrameAdmission chan struct{},
	readTimeout time.Duration,
	spec vnextReaderActivationOperationSpec,
) ([]byte, func(), *vnextReaderActivationRPCError) {
	release := func() {}
	if err := validateVNextReaderActivationOperationSpec(spec); err != nil {
		return nil, release, vnextReaderActivationFailure(
			vnextReaderActivationProposalSpec,
			vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted, err)
	}
	deadline := time.Now().Add(readTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, release, vnextReaderActivationFailure(
			spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted,
			fmt.Errorf("set Reader activation frame deadline: %w", err))
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, release, vnextReaderActivationFailure(
			spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted,
			fmt.Errorf("read Reader activation frame header: %w", err))
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(vnextReaderActivationMaxFrameBytes) {
		return nil, release, vnextReaderActivationFailure(
			spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted,
			fmt.Errorf("Reader activation frame size %d is outside 1..%d",
				size, vnextReaderActivationMaxFrameBytes))
	}
	largeHeld := false
	if size > vnextReaderPrepareTLSLargeFrameThreshold {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, release, vnextReaderActivationFailure(
				spec, vnextReaderActivationCapacityError,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New("Reader activation large-frame admission timed out"))
		}
		timer := time.NewTimer(remaining)
		select {
		case largeFrameAdmission <- struct{}{}:
			largeHeld = true
		case <-timer.C:
			return nil, release, vnextReaderActivationFailure(
				spec, vnextReaderActivationCapacityError,
				vnextReaderActivationDefinitelyNotAccepted,
				errors.New("Reader activation large-frame admission timed out"))
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	if largeHeld {
		var once sync.Once
		release = func() {
			once.Do(func() { <-largeFrameAdmission })
		}
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(conn, body); err != nil {
		release()
		return nil, func() {}, vnextReaderActivationFailure(
			spec, vnextReaderActivationInvalidRequest,
			vnextReaderActivationDefinitelyNotAccepted,
			fmt.Errorf("read Reader activation frame body: %w", err))
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		release()
		return nil, func() {}, vnextReaderActivationFailure(
			spec, vnextReaderActivationUnavailable,
			vnextReaderActivationDefinitelyNotAccepted,
			fmt.Errorf("clear Reader activation frame deadline: %w", err))
	}
	return body, release, nil
}

func validateVNextReaderActivationTLSSuccess(
	spec vnextReaderActivationOperationSpec,
	body []byte,
) error {
	switch spec {
	case vnextReaderActivationProposalSpec:
		_, err := decodeVNextReaderActivationProposalResponse(body)
		return err
	case vnextReaderActivationCommitSpec:
		_, err := decodeVNextReaderActivationCommitResponse(body)
		return err
	case vnextReaderActivationStatusSpec:
		_, err := decodeVNextReaderActivationStatusResponse(body)
		return err
	default:
		return errors.New("Reader activation TLS success has an invalid operation")
	}
}

func marshalVNextReaderActivationTLSFailure(
	spec vnextReaderActivationOperationSpec,
	failure *vnextReaderActivationRPCError,
) ([]byte, error) {
	if err := validateVNextReaderActivationOperationSpec(spec); err != nil {
		return nil, err
	}
	if failure == nil || failure.Protocol != spec.protocol {
		return nil, errors.New(
			"VNext Reader activation TLS failure has the wrong protocol")
	}
	if !validVNextReaderActivationTLSErrorCode(failure.Code) {
		return nil, fmt.Errorf(
			"VNext Reader activation TLS error code %q is invalid", failure.Code)
	}
	if !validVNextReaderActivationTLSAcceptance(failure.Acceptance) {
		return nil, fmt.Errorf(
			"VNext Reader activation TLS acceptance %q is invalid",
			failure.Acceptance)
	}
	return marshalBoundedVNextReaderActivationJSON(
		spec,
		vnextReaderActivationTLSFailureWire{
			Protocol:   spec.protocol,
			Operation:  spec.operation,
			ErrorCode:  failure.Code,
			Acceptance: failure.Acceptance,
		})
}

func decodeStrictVNextReaderActivationTLSFailure(
	spec vnextReaderActivationOperationSpec,
	body []byte,
) (vnextReaderActivationTLSFailureWire, error) {
	var wire vnextReaderActivationTLSFailureWire
	if err := validateVNextReaderActivationOperationSpec(spec); err != nil {
		return wire, err
	}
	if err := decodeStrictVNextReaderActivationJSON(spec, body, &wire); err != nil {
		return vnextReaderActivationTLSFailureWire{}, err
	}
	if wire.Protocol != spec.protocol || wire.Operation != spec.operation ||
		!validVNextReaderActivationTLSErrorCode(wire.ErrorCode) ||
		!validVNextReaderActivationTLSAcceptance(wire.Acceptance) {
		return vnextReaderActivationTLSFailureWire{}, errors.New(
			"VNext Reader activation TLS failure identity or enum is invalid")
	}
	return wire, nil
}

func validVNextReaderActivationTLSErrorCode(
	code vnextReaderActivationErrorCode,
) bool {
	switch code {
	case vnextReaderActivationInvalidRequest,
		vnextReaderActivationAuthorityError,
		vnextReaderActivationIdentityError,
		vnextReaderActivationIncarnation,
		vnextReaderActivationConflictError,
		vnextReaderActivationNotFound,
		vnextReaderActivationCapacityError,
		vnextReaderActivationUnavailable:
		return true
	default:
		return false
	}
}

func validVNextReaderActivationTLSAcceptance(
	acceptance vnextReaderActivationAcceptance,
) bool {
	return acceptance == vnextReaderActivationDefinitelyNotAccepted ||
		acceptance == vnextReaderActivationAcceptanceUnknown
}

func (server *vnextReaderPrepareTLSServer) writeActivationFailure(
	conn net.Conn,
	spec vnextReaderActivationOperationSpec,
	failure *vnextReaderActivationRPCError,
) {
	body, err := marshalVNextReaderActivationTLSFailure(spec, failure)
	if err != nil {
		body, _ = json.Marshal(vnextReaderActivationTLSFailureWire{
			Protocol:   spec.protocol,
			Operation:  spec.operation,
			ErrorCode:  vnextReaderActivationUnavailable,
			Acceptance: vnextReaderActivationAcceptanceUnknown,
		})
	}
	server.writeBody(conn, body)
}

var _ vnextReaderActivationTransportRPC = (*vnextReaderActivationProposalRPC)(nil)
var _ vnextReaderActivationTransportRPC = (*vnextReaderActivationCommitRPC)(nil)
var _ vnextReaderActivationTransportRPC = (*vnextReaderActivationStatusRPC)(nil)
