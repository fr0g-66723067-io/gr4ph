//go:build goexperiment.simd

package gr4ph

import "simd"

// wordsPerVector is the number of uint64 words in one SIMD vector. The width is
// fixed for the life of the process (the simd package reads its GODEBUG setting
// once), so caching it here keeps the hot path free of the accessor call.
var wordsPerVector = simd.VectorBitSize() / 64

// Vectorised row arithmetic. This is the only file in the module that imports
// the experimental simd package; everything else goes through these three
// kernels, so a portable scalar fallback would be a drop-in replacement
// (see README "Build requirement").
//
// All three kernels require len(dst) == len(src) and operate on whole rows.
// Rows are exact-length (stride words, no padding), so the loops below are
// uniform for every row length: whole vectors go through LoadUint64s/Store and
// the tail (up to wordsPerVector-1 words) is handled scalar.
//
// The partial helpers LoadUint64sPart/StorePart are deliberately not used. The
// count LoadUint64sPart reports differs between implementations —
// min(wordsPerVector, len(s)) on hardware, len(s) under GODEBUG=simd=0 — so
// advancing by it silently skips the tail of every row that is not a whole
// number of vectors. `make test` runs the whole suite under GODEBUG=simd=0
// precisely so the emulated implementation keeps checking that.

// orRowInto computes dst[i] |= src[i] for every i.
func orRowInto(dst, src []uint64) {
	pos := 0
	for ; pos+wordsPerVector <= len(dst); pos += wordsPerVector {
		a := simd.LoadUint64s(dst[pos:])
		b := simd.LoadUint64s(src[pos:])
		a.Or(b).Store(dst[pos:])
	}
	for ; pos < len(dst); pos++ {
		dst[pos] |= src[pos]
	}
}

// andRowInto computes dst[i] &= src[i] for every i.
func andRowInto(dst, src []uint64) {
	pos := 0
	for ; pos+wordsPerVector <= len(dst); pos += wordsPerVector {
		a := simd.LoadUint64s(dst[pos:])
		b := simd.LoadUint64s(src[pos:])
		a.And(b).Store(dst[pos:])
	}
	for ; pos < len(dst); pos++ {
		dst[pos] &= src[pos]
	}
}

// copyRow copies src into dst.
func copyRow(dst, src []uint64) {
	pos := 0
	for ; pos+wordsPerVector <= len(dst); pos += wordsPerVector {
		simd.LoadUint64s(src[pos:]).Store(dst[pos:])
	}
	for ; pos < len(dst); pos++ {
		dst[pos] = src[pos]
	}
}
