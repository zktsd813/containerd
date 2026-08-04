//go:build trenv_v7_dml_hw && (!linux || !amd64 || !cgo)
// +build trenv_v7_dml_hw
// +build !linux !amd64 !cgo

package trcxl007dml

// Selecting trenv_v7_dml_hw is an explicit request for the real hardware
// implementation. Make unsupported targets fail compilation instead of
// silently falling back to the default stub.
var _ = trenvV7DMLHardwareRequiresLinuxAMD64AndCGO
