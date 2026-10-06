//go:build !goexperiment.simd

package simdcheck

import "simd"

// VectorBitSize is never called: importing simd without GOEXPERIMENT=simd fails
// to build, which turns a stock `go build ./...` or `go test ./...` from a
// silent skip of every gated package into an explicit error.
var _ = simd.VectorBitSize
