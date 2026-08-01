package main

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

const vnextOwnerSchedulerUIDUnconfigured int64 = -1

func validateVNextOwnerSchedulerControlUID(uid int64) error {
	if uid < vnextOwnerSchedulerUIDUnconfigured || uid > int64(^uint32(0)) {
		return fmt.Errorf("expected -1 or a uint32 UID, got %d", uid)
	}
	return nil
}

type vnextOwnerUnixListenerPolicy struct {
	Role                 vnextOwnerCallerRole
	RequiredSchedulerUID int64
}

var (
	vnextOwnerRuntimeUnixPolicy = vnextOwnerUnixListenerPolicy{
		Role:                 vnextOwnerCallerProducer,
		RequiredSchedulerUID: vnextOwnerSchedulerUIDUnconfigured,
	}
)

func (policy vnextOwnerUnixListenerPolicy) authenticate(conn net.Conn) error {
	_, err := policy.authenticateCaller(conn)
	return err
}

func (policy vnextOwnerUnixListenerPolicy) authenticateCaller(
	conn net.Conn,
) (vnextOwnerCallerContext, error) {
	switch policy.Role {
	case vnextOwnerCallerProducer:
		uid, err := vnextOwnerUnixPeerUID(conn)
		if err != nil {
			return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
				"unix-authentication",
				vnextOwnerServicePermissionDenied,
				"Producer runtime peer credentials are unavailable",
				err)
		}
		principal, err := vnextOwnerUnixPrincipal(policy.Role, uid)
		if err != nil {
			return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
				"unix-authentication",
				vnextOwnerServicePermissionDenied,
				"Producer runtime peer principal is invalid",
				err)
		}
		return vnextOwnerCallerContext{Role: policy.Role, Principal: principal}, nil
	case vnextOwnerCallerScheduler:
		if policy.RequiredSchedulerUID < 0 {
			return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
				"unix-authentication",
				vnextOwnerServicePermissionDenied,
				"Scheduler control UID is not configured",
				nil)
		}
		uid, err := vnextOwnerUnixPeerUID(conn)
		if err != nil {
			return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
				"unix-authentication",
				vnextOwnerServicePermissionDenied,
				"Scheduler control peer credentials are unavailable",
				err)
		}
		if int64(uid) != policy.RequiredSchedulerUID {
			return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
				"unix-authentication",
				vnextOwnerServicePermissionDenied,
				fmt.Sprintf(
					"Scheduler control peer UID %d does not match required UID %d",
					uid, policy.RequiredSchedulerUID),
				nil)
		}
		principal, err := vnextOwnerUnixPrincipal(policy.Role, uid)
		if err != nil {
			return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
				"unix-authentication",
				vnextOwnerServicePermissionDenied,
				"Scheduler control peer principal is invalid",
				err)
		}
		return vnextOwnerCallerContext{Role: policy.Role, Principal: principal}, nil
	default:
		return vnextOwnerCallerContext{}, vnextOwnerServiceFailure(
			"unix-authentication",
			vnextOwnerServicePermissionDenied,
			"Unix listener has no authorized role",
			nil)
	}
}

func vnextOwnerUnixPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, fmt.Errorf("connection type %T is not a Unix connection", conn)
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("access Unix connection descriptor: %w", err)
	}
	var (
		credential *syscall.Ucred
		controlErr error
	)
	if err := rawConn.Control(func(fd uintptr) {
		credential, controlErr = syscall.GetsockoptUcred(
			int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, fmt.Errorf("inspect Unix peer credentials: %w", err)
	}
	if controlErr != nil {
		return 0, fmt.Errorf("read Unix peer credentials: %w", controlErr)
	}
	if credential == nil {
		return 0, errors.New("Unix peer credentials are empty")
	}
	return credential.Uid, nil
}
