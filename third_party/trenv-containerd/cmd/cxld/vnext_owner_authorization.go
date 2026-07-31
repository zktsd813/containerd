package main

import (
	"fmt"
)

// vnextOwnerCallerRole is assigned by a trusted transport boundary. It is
// never decoded from a daemon request. Keeping the role outside the wire body
// prevents commandLabel or another caller-controlled field from becoming an
// authorization credential.
type vnextOwnerCallerRole uint8

const (
	vnextOwnerCallerUnknown vnextOwnerCallerRole = iota
	vnextOwnerCallerScheduler
	vnextOwnerCallerProducer
	vnextOwnerCallerReader
)

func (role vnextOwnerCallerRole) String() string {
	switch role {
	case vnextOwnerCallerScheduler:
		return "scheduler"
	case vnextOwnerCallerProducer:
		return "producer"
	case vnextOwnerCallerReader:
		return "reader"
	default:
		return "unknown"
	}
}

// authorizeVNextOwnerOperation is the single strict Owner operation policy.
// Callers must apply it before selecting a local Owner or a remote gateway so
// a denied request can neither mutate durable state nor consume a privileged
// outbound client identity.
func authorizeVNextOwnerOperation(
	role vnextOwnerCallerRole,
	operation string,
) error {
	allowed := false
	switch role {
	case vnextOwnerCallerScheduler:
		switch operation {
		case vnextOwnerRPCOperationReserve,
			vnextOwnerRPCOperationCommit,
			vnextOwnerRPCOperationAbort,
			vnextOwnerRPCOperationInventory,
			vnextOwnerRPCOperationReservationStatus,
			vnextOwnerRPCOperationSetAdmission,
			vnextOwnerRPCOperationAdmissionStatus:
			allowed = true
		}
	case vnextOwnerCallerProducer:
		switch operation {
		case vnextOwnerRPCOperationSeal, vnextOwnerRPCOperationAbort:
			allowed = true
		}
	case vnextOwnerCallerReader, vnextOwnerCallerUnknown:
		// Readers have no strict Owner RPC operations. An unknown transport
		// role is deliberately equivalent to no authority.
	}
	if allowed {
		return nil
	}
	return vnextOwnerServiceFailure(
		operation,
		vnextOwnerServicePermissionDenied,
		fmt.Sprintf("%s caller is not authorized for operation %q", role, operation),
		nil)
}

// authorizeDaemonOperation also isolates the Scheduler control listener from
// legacy runtime operations. The producer listener remains the existing local
// runtime boundary and therefore continues to serve checkpoint/restore/read
// operations in addition to its narrowly authorized strict Owner operations.
func authorizeDaemonOperation(role vnextOwnerCallerRole, operation string) error {
	if isVNextOwnerRPCOperation(operation) {
		return authorizeVNextOwnerOperation(role, operation)
	}
	if role == vnextOwnerCallerProducer {
		return nil
	}
	return vnextOwnerServiceFailure(
		operation,
		vnextOwnerServicePermissionDenied,
		fmt.Sprintf("%s caller is not authorized for runtime operation %q", role, operation),
		nil)
}
