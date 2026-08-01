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

// vnextOwnerCallerContext is created only by a trusted Unix or TLS transport
// boundary. Principal is the exact authenticated peer identity: a canonical
// URI SAN for TLS, or a canonical SO_PEERCRED-derived Unix UID URI. Neither
// field is decoded from the request body.
type vnextOwnerCallerContext struct {
	Role      vnextOwnerCallerRole
	Principal string
}

// vnextOwnerInternalCaller labels direct in-process dispatch used by command
// mode and unit-test adapters. Unix and TLS listeners must never use it: they
// derive the exact peer principal from SO_PEERCRED or the verified URI SAN.
func vnextOwnerInternalCaller(role vnextOwnerCallerRole) vnextOwnerCallerContext {
	return vnextOwnerCallerContext{
		Role:      role,
		Principal: "internal://cxld/" + role.String(),
	}
}

func (caller vnextOwnerCallerContext) validate() error {
	if caller.Role != vnextOwnerCallerScheduler && caller.Role != vnextOwnerCallerProducer {
		return fmt.Errorf("caller role %s has no strict Owner authority", caller.Role)
	}
	return validateVNextOwnerPrincipal(caller.Principal)
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
			vnextOwnerRPCOperationIssueProducerCapability,
			vnextOwnerRPCOperationRevokeProducerCapability,
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
		case vnextOwnerRPCOperationSeal, vnextOwnerRPCOperationProducerAbort:
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
