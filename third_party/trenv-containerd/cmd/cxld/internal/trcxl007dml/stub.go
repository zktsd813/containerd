//go:build !trenv_v7_dml_hw
// +build !trenv_v7_dml_hw

package trcxl007dml

// OpenHardware fails closed unless the custom trenv_v7_dml_hw build tag is
// explicitly selected. No default-build CPU or software implementation exists.
func OpenHardware() (Copier, error) {
	return nil, ErrHardwareBackendNotBuilt
}
