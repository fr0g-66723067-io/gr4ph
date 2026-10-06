//go:build goexperiment.simd

// Package simdcheck is a compile-time tripwire for the experiment-gated build:
// see stock.go, which is the only buildable file on a stock toolchain and
// deliberately fails to compile there.
package simdcheck
