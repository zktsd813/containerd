package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

type vnextReaderIdentifyTransportRPC interface {
	Handle(context.Context, string, []byte) ([]byte, *vnextReaderIdentifyRPCError)
}

type vnextReaderIdentifyTLSFailureWire struct {
	Protocol  string                       `json:"protocol"`
	Operation string                       `json:"operation"`
	ErrorCode vnextReaderIdentifyErrorCode `json:"errorCode"`
}

type vnextReaderIdentifyTLSHandlerResult struct {
	body    []byte
	failure *vnextReaderIdentifyRPCError
}

func (server *vnextReaderPrepareTLSServer) serveAuthenticatedIdentify(
	conn net.Conn,
	principal string,
	releaseRequest func(),
) {
	body, failure := readVNextReaderIdentifyTLSFrame(
		conn, server.requestReadTimeout)
	if failure != nil {
		defer releaseRequest()
		server.writeIdentifyFailure(conn, failure)
		return
	}
	// IDENTIFY is bounded below the large-frame threshold. It still uses the
	// same joined drain so request admission is held until both the actual
	// handler and validation/write side have terminated.
	drain := newVNextReaderPrepareTLSAdmissionDrain(releaseRequest, func() {})
	defer drain.markServeTerminal()
	result := server.runIdentifyHandler(
		principal, body, drain.markHandlerTerminal)
	if result.failure != nil {
		server.writeIdentifyFailure(conn, result.failure)
		return
	}
	if len(result.body) == 0 || len(result.body) > vnextReaderIdentifyMaxFrameBytes {
		server.writeIdentifyFailure(conn, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			fmt.Errorf("Reader IDENTIFY handler response has %d bytes", len(result.body))))
		return
	}
	if _, err := decodeVNextReaderIdentifyResponse(result.body); err != nil {
		server.writeIdentifyFailure(conn, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			fmt.Errorf("strictly validate Reader IDENTIFY handler response: %v", err)))
		return
	}
	server.writeBody(conn, result.body)
}

func (server *vnextReaderPrepareTLSServer) runIdentifyHandler(
	principal string,
	body []byte,
	markHandlerTerminal func(),
) vnextReaderIdentifyTLSHandlerResult {
	handlerCtx, cancel := context.WithTimeout(
		context.Background(), server.handlerTimeout)
	defer cancel()
	resultChannel := make(chan vnextReaderIdentifyTLSHandlerResult, 1)
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		defer markHandlerTerminal()
		result := vnextReaderIdentifyTLSHandlerResult{}
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					result.failure = vnextReaderIdentifyFailure(
						vnextReaderIdentifyUnavailable,
						fmt.Errorf("VNext Reader IDENTIFY RPC panic: %v", recovered))
				}
			}()
			result.body, result.failure = server.identifyRPC.Handle(
				handlerCtx, principal, body)
		}()
		resultChannel <- result
	}()
	select {
	case result := <-resultChannel:
		if handlerCtx.Err() != nil {
			return vnextReaderIdentifyTLSHandlerTimeout(handlerCtx.Err())
		}
		return result
	case <-handlerCtx.Done():
		return vnextReaderIdentifyTLSHandlerTimeout(handlerCtx.Err())
	}
}

func vnextReaderIdentifyTLSHandlerTimeout(
	cause error,
) vnextReaderIdentifyTLSHandlerResult {
	return vnextReaderIdentifyTLSHandlerResult{failure: vnextReaderIdentifyFailure(
		vnextReaderIdentifyUnavailable,
		fmt.Errorf("VNext Reader IDENTIFY TLS handler deadline: %v", cause))}
}

func readVNextReaderIdentifyTLSFrame(
	conn net.Conn,
	readTimeout time.Duration,
) ([]byte, *vnextReaderIdentifyRPCError) {
	if err := conn.SetReadDeadline(time.Now().Add(readTimeout)); err != nil {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			fmt.Errorf("set Reader IDENTIFY frame deadline: %w", err))
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyInvalidRequest,
			fmt.Errorf("read Reader IDENTIFY frame header: %w", err))
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || uint64(size) > uint64(vnextReaderIdentifyMaxFrameBytes) {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyInvalidRequest,
			fmt.Errorf("Reader IDENTIFY frame size %d is outside 1..%d",
				size, vnextReaderIdentifyMaxFrameBytes))
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyInvalidRequest,
			fmt.Errorf("read Reader IDENTIFY frame body: %w", err))
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		return nil, vnextReaderIdentifyFailure(
			vnextReaderIdentifyUnavailable,
			fmt.Errorf("clear Reader IDENTIFY frame deadline: %w", err))
	}
	return body, nil
}

func marshalVNextReaderIdentifyTLSFailure(
	failure *vnextReaderIdentifyRPCError,
) ([]byte, error) {
	if failure == nil || !validVNextReaderIdentifyTLSErrorCode(failure.Code) {
		return nil, errors.New("VNext Reader IDENTIFY TLS failure is invalid")
	}
	return marshalBoundedVNextReaderIdentifyJSON(vnextReaderIdentifyTLSFailureWire{
		Protocol:  vnextReaderIdentifyProtocol,
		Operation: vnextReaderIdentifyOperation,
		ErrorCode: failure.Code,
	})
}

func decodeStrictVNextReaderIdentifyTLSFailure(
	body []byte,
) (vnextReaderIdentifyTLSFailureWire, error) {
	var wire vnextReaderIdentifyTLSFailureWire
	if err := decodeStrictVNextReaderIdentifyJSON(body, &wire); err != nil {
		return vnextReaderIdentifyTLSFailureWire{}, err
	}
	if wire.Protocol != vnextReaderIdentifyProtocol ||
		wire.Operation != vnextReaderIdentifyOperation ||
		!validVNextReaderIdentifyTLSErrorCode(wire.ErrorCode) {
		return vnextReaderIdentifyTLSFailureWire{}, errors.New(
			"VNext Reader IDENTIFY TLS failure identity or code is invalid")
	}
	return wire, nil
}

func validVNextReaderIdentifyTLSErrorCode(
	code vnextReaderIdentifyErrorCode,
) bool {
	switch code {
	case vnextReaderIdentifyInvalidRequest,
		vnextReaderIdentifyAuthorityError,
		vnextReaderIdentifyIdentityError,
		vnextReaderIdentifyCapacityError,
		vnextReaderIdentifyUnavailable:
		return true
	default:
		return false
	}
}

func (server *vnextReaderPrepareTLSServer) writeIdentifyFailure(
	conn net.Conn,
	failure *vnextReaderIdentifyRPCError,
) {
	body, err := marshalVNextReaderIdentifyTLSFailure(failure)
	if err != nil {
		body, _ = json.Marshal(vnextReaderIdentifyTLSFailureWire{
			Protocol:  vnextReaderIdentifyProtocol,
			Operation: vnextReaderIdentifyOperation,
			ErrorCode: vnextReaderIdentifyUnavailable,
		})
	}
	server.writeBody(conn, body)
}

var _ vnextReaderIdentifyTransportRPC = (*vnextReaderIdentifyRPC)(nil)
