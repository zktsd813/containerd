//go:build !amd64
// +build !amd64

package main

import "errors"

func directWritebackDaxCache([]byte) error {
	return errors.New("direct DAX cache writeback is only supported on amd64")
}

func directInvalidateDaxCache([]byte) error {
	return errors.New("direct DAX cache invalidation is only supported on amd64")
}
