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

// vnextReaderPreparedStatusTransportRPC is intentionally narrower than the
// status service. TLS dispatch reaches it only after the exact status ALPN was
// negotiated; request JSON is never inspected to choose an operation.
type vnextReaderPreparedStatusTransportRPC interface {
	Handle(
		context.Context,
		string,
		[]byte,
	) ([]byte, *vnextReaderPreparedStatusRPCError)
}

type vnextReaderPreparedStatusTLSFailureWire struct {
	Protocol   string                              `json:"protocol"`
	Operation  string                              `json:"operation"`
	ErrorCode  vnextReaderPreparedStatusErrorCode  `json:"errorCode"`
	Acceptance vnextReaderPreparedStatusAcceptance `json:"acceptance"`
}

type vnextReaderPreparedStatusTLSHandlerResult struct {
	body    []byte
	failure *vnextReaderPreparedStatusRPCError
}

func (server *vnextReaderPrepareTLSServer) serveAuthenticatedStatus(
	conn net.Conn,
	principal string,
	releaseRequest func(),
) {
	body, releaseLarge, failure := readVNextReaderPreparedStatusTLSFrame(
		conn, server.largeFrameAdmission, server.requestReadTimeout)
	if failure != nil {
		releaseRequest()
		server.writeStatusFailure(conn, failure)
		return
	}
	// Admission remains held across both the actual handler lifetime and this
	// validation/write path. A local timeout cannot release capacity while a
	// status call may still be installing a process-local tombstone.
	drain := newVNextReaderPrepareTLSAdmissionDrain(
		releaseRequest, releaseLarge)
	defer drain.markServeTerminal()
	result := server.runStatusHandler(
		principal, body, drain.markHandlerTerminal)
	if result.failure != nil {
		server.writeStatusFailure(conn, result.failure)
		return
	}
	if len(result.body) == 0 ||
		len(result.body) > vnextReaderPreparedStatusMaxFrameBytes {
		server.writeStatusFailure(conn, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusAcceptanceUnknown,
			fmt.Errorf(
				"Reader STATUS_AND_FENCE handler response has %d bytes",
				len(result.body))))
		return
	}
	if _, err := decodeVNextReaderPreparedStatusResponse(result.body); err != nil {
		server.writeStatusFailure(conn, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusAcceptanceUnknown,
			fmt.Errorf(
				"strictly validate Reader STATUS_AND_FENCE handler response: %v",
				err)))
		return
	}
	server.writeBody(conn, result.body)
}

func (server *vnextReaderPrepareTLSServer) runStatusHandler(
	principal string,
	body []byte,
	markHandlerTerminal func(),
) vnextReaderPreparedStatusTLSHandlerResult {
	handlerCtx, cancel := context.WithTimeout(
		context.Background(), server.handlerTimeout)
	defer cancel()
	resultChannel := make(chan vnextReaderPreparedStatusTLSHandlerResult, 1)
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		defer markHandlerTerminal()
		result := vnextReaderPreparedStatusTLSHandlerResult{}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					result.failure = vnextReaderPreparedStatusFailure(
						vnextReaderPreparedStatusUnavailable,
						vnextReaderPreparedStatusAcceptanceUnknown,
						fmt.Errorf(
							"VNext Reader STATUS_AND_FENCE RPC panic: %v",
							recovered))
				}
			}()
			result.body, result.failure = server.statusRPC.Handle(
				handlerCtx, principal, body)
		}()
		resultChannel <- result
	}()
	select {
	case result := <-resultChannel:
		if handlerCtx.Err() != nil {
			return vnextReaderPreparedStatusTLSHandlerTimeout(handlerCtx.Err())
		}
		return result
	case <-handlerCtx.Done():
		return vnextReaderPreparedStatusTLSHandlerTimeout(handlerCtx.Err())
	}
}

func vnextReaderPreparedStatusTLSHandlerTimeout(
	cause error,
) vnextReaderPreparedStatusTLSHandlerResult {
	return vnextReaderPreparedStatusTLSHandlerResult{
		failure: vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			// The handler may have installed PREPARED or a permanent process-
			// local NOT_PREPARED_FENCED tombstone before this local timer won.
			vnextReaderPreparedStatusAcceptanceUnknown,
			fmt.Errorf(
				"VNext Reader STATUS_AND_FENCE TLS handler deadline: %v", cause)),
	}
}

func readVNextReaderPreparedStatusTLSFrame(
	conn net.Conn,
	largeFrameAdmission chan struct{},
	readTimeout time.Duration,
) ([]byte, func(), *vnextReaderPreparedStatusRPCError) {
	release := func() {}
	deadline := time.Now().Add(readTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, release, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf("set Reader STATUS_AND_FENCE frame deadline: %w", err))
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, release, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusInvalidRequest,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf("read Reader STATUS_AND_FENCE frame header: %w", err))
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(vnextReaderPreparedStatusMaxFrameBytes) {
		return nil, release, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusInvalidRequest,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf("Reader STATUS_AND_FENCE frame size %d is outside 1..%d",
				size, vnextReaderPreparedStatusMaxFrameBytes))
	}
	largeHeld := false
	if size > vnextReaderPrepareTLSLargeFrameThreshold {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, release, vnextReaderPreparedStatusFailure(
				vnextReaderPreparedStatusCapacityError,
				vnextReaderPreparedStatusDefinitelyNotAccepted,
				errors.New(
					"Reader STATUS_AND_FENCE large-frame admission timed out"))
		}
		timer := time.NewTimer(remaining)
		select {
		case largeFrameAdmission <- struct{}{}:
			largeHeld = true
		case <-timer.C:
			return nil, release, vnextReaderPreparedStatusFailure(
				vnextReaderPreparedStatusCapacityError,
				vnextReaderPreparedStatusDefinitelyNotAccepted,
				errors.New(
					"Reader STATUS_AND_FENCE large-frame admission timed out"))
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
		return nil, func() {}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusInvalidRequest,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf("read Reader STATUS_AND_FENCE frame body: %w", err))
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		release()
		return nil, func() {}, vnextReaderPreparedStatusFailure(
			vnextReaderPreparedStatusUnavailable,
			vnextReaderPreparedStatusDefinitelyNotAccepted,
			fmt.Errorf("clear Reader STATUS_AND_FENCE frame deadline: %w", err))
	}
	return body, release, nil
}

func marshalVNextReaderPreparedStatusTLSFailure(
	failure *vnextReaderPreparedStatusRPCError,
) ([]byte, error) {
	if failure == nil {
		return nil, errors.New("VNext Reader STATUS_AND_FENCE TLS failure is nil")
	}
	if !validVNextReaderPreparedStatusTLSErrorCode(failure.Code) {
		return nil, fmt.Errorf(
			"VNext Reader STATUS_AND_FENCE TLS error code %q is invalid",
			failure.Code)
	}
	if !validVNextReaderPreparedStatusTLSAcceptance(failure.Acceptance) {
		return nil, fmt.Errorf(
			"VNext Reader STATUS_AND_FENCE TLS acceptance %q is invalid",
			failure.Acceptance)
	}
	return marshalBoundedVNextReaderPreparedStatusJSON(
		vnextReaderPreparedStatusTLSFailureWire{
			Protocol:   vnextReaderPreparedStatusProtocol,
			Operation:  vnextReaderPreparedStatusOperation,
			ErrorCode:  failure.Code,
			Acceptance: failure.Acceptance,
		})
}

func decodeStrictVNextReaderPreparedStatusTLSFailure(
	body []byte,
) (vnextReaderPreparedStatusTLSFailureWire, error) {
	var wire vnextReaderPreparedStatusTLSFailureWire
	if err := decodeStrictVNextReaderPreparedStatusJSON(body, &wire); err != nil {
		return vnextReaderPreparedStatusTLSFailureWire{}, err
	}
	if wire.Protocol != vnextReaderPreparedStatusProtocol ||
		wire.Operation != vnextReaderPreparedStatusOperation ||
		!validVNextReaderPreparedStatusTLSErrorCode(wire.ErrorCode) ||
		!validVNextReaderPreparedStatusTLSAcceptance(wire.Acceptance) {
		return vnextReaderPreparedStatusTLSFailureWire{}, errors.New(
			"VNext Reader STATUS_AND_FENCE TLS failure identity or enum is invalid")
	}
	return wire, nil
}

func validVNextReaderPreparedStatusTLSErrorCode(
	code vnextReaderPreparedStatusErrorCode,
) bool {
	switch code {
	case vnextReaderPreparedStatusInvalidRequest,
		vnextReaderPreparedStatusAuthorityError,
		vnextReaderPreparedStatusIdentityError,
		vnextReaderPreparedStatusConflictError,
		vnextReaderPreparedStatusCapacityError,
		vnextReaderPreparedStatusUnavailable:
		return true
	default:
		return false
	}
}

func validVNextReaderPreparedStatusTLSAcceptance(
	acceptance vnextReaderPreparedStatusAcceptance,
) bool {
	return acceptance == vnextReaderPreparedStatusDefinitelyNotAccepted ||
		acceptance == vnextReaderPreparedStatusAcceptanceUnknown
}

func (server *vnextReaderPrepareTLSServer) writeStatusFailure(
	conn net.Conn,
	failure *vnextReaderPreparedStatusRPCError,
) {
	body, err := marshalVNextReaderPreparedStatusTLSFailure(failure)
	if err != nil {
		body, _ = json.Marshal(vnextReaderPreparedStatusTLSFailureWire{
			Protocol:   vnextReaderPreparedStatusProtocol,
			Operation:  vnextReaderPreparedStatusOperation,
			ErrorCode:  vnextReaderPreparedStatusUnavailable,
			Acceptance: vnextReaderPreparedStatusAcceptanceUnknown,
		})
	}
	server.writeBody(conn, body)
}

var _ vnextReaderPreparedStatusTransportRPC = (*vnextReaderPreparedStatusRPC)(nil)
