//go:build !amd64
// +build !amd64

package main

import "errors"

func newVNextReaderDAXCacheInvalidator() (
	vnextReaderDAXCacheInvalidator,
	error,
) {
	return nil, errors.New(
		"VNext Reader devdax cache invalidation is supported only on amd64")
}
