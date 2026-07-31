package main

import "testing"

// vnextOwnerAuthorizedTestRole is used only by pre-authorization protocol
// tests. Production paths never derive authority from an operation string.
func vnextOwnerAuthorizedTestRole(operation string) vnextOwnerCallerRole {
	switch operation {
	case vnextOwnerRPCOperationSeal:
		return vnextOwnerCallerProducer
	case vnextOwnerRPCOperationAbort:
		return vnextOwnerCallerProducer
	case vnextOwnerRPCOperationReserve,
		vnextOwnerRPCOperationCommit,
		vnextOwnerRPCOperationInventory,
		vnextOwnerRPCOperationReservationStatus,
		vnextOwnerRPCOperationSetAdmission,
		vnextOwnerRPCOperationAdmissionStatus:
		return vnextOwnerCallerScheduler
	default:
		return vnextOwnerCallerProducer
	}
}

func runCommandWithVNextOwnerRPCTestRole(
	request daemonRequest,
	rpc *vnextOwnerRPC,
) execResponse {
	return runCommandWithVNextOwnerRPCRole(
		request, rpc, vnextOwnerAuthorizedTestRole(request.Operation))
}

func TestVNextOwnerAuthorizationPolicyIsFailClosed(t *testing.T) {
	tests := []struct {
		role      vnextOwnerCallerRole
		operation string
		allowed   bool
	}{
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationReserve, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationInventory, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationReservationStatus, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationAdmissionStatus, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationSetAdmission, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationCommit, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationAbort, true},
		{vnextOwnerCallerScheduler, vnextOwnerRPCOperationSeal, false},
		{vnextOwnerCallerProducer, vnextOwnerRPCOperationSeal, true},
		{vnextOwnerCallerProducer, vnextOwnerRPCOperationAbort, true},
		{vnextOwnerCallerProducer, vnextOwnerRPCOperationCommit, false},
		{vnextOwnerCallerProducer, vnextOwnerRPCOperationReserve, false},
		{vnextOwnerCallerReader, vnextOwnerRPCOperationSeal, false},
		{vnextOwnerCallerReader, vnextOwnerRPCOperationInventory, false},
		{vnextOwnerCallerUnknown, vnextOwnerRPCOperationAbort, false},
	}
	for _, test := range tests {
		t.Run(test.role.String()+"/"+test.operation, func(t *testing.T) {
			err := authorizeVNextOwnerOperation(test.role, test.operation)
			if (err == nil) != test.allowed {
				t.Fatalf("authorization error = %v, allowed = %v", err, test.allowed)
			}
		})
	}
}
