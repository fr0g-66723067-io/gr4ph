//go:build goexperiment.simd

package gr4ph

import "simd"

// Vectorised row arithmetic. This is the only file in the module that imports
// the experimental simd package; everything else goes through these three
// kernels, so a portable scalar fallback would be a drop-in replacement
// (see README "Portability").
//
// All three kernels require len(dst) == len(src) and operate on whole rows.
// Rows are exact-length (stride words, no padding), so the loop below is
// uniform for every row length: LoadUint64sPart/StorePart clamp themselves to
// the vector width, which makes them valid for short rows (below one vector)
// as well as for the full-vector case.
//
// Semantics, from GOROOT src/simd (verified against src/simd/archsimd/
// slice_gen_amd64.go for Uint64x4 and by kernel_test.go for this build):
//
//   - LoadUint64sPart(s) returns (vector, n) with n = min(lanes, len(s)) and
//     zero-fills the lanes beyond n.
//   - StorePart(s) writes min(len(s), lanes) elements, using a masked store
//     when the slice is shorter than one vector, so it never overruns s.

// orRowInto computes dst[i] |= src[i] for every i.
func orRowInto(dst, src []uint64) {
	for pos := 0; pos < len(dst); {
		a, _ := simd.LoadUint64sPart(dst[pos:])
		b, n := simd.LoadUint64sPart(src[pos:])
		a.Or(b).StorePart(dst[pos:])
		pos += n
	}
}

// andRowInto computes dst[i] &= src[i] for every i.
func andRowInto(dst, src []uint64) {
	for pos := 0; pos < len(dst); {
		a, _ := simd.LoadUint64sPart(dst[pos:])
		b, n := simd.LoadUint64sPart(src[pos:])
		a.And(b).StorePart(dst[pos:])
		pos += n
	}
}

// copyRow copies src into dst.
func copyRow(dst, src []uint64) {
	for pos := 0; pos < len(dst); {
		b, n := simd.LoadUint64sPart(src[pos:])
		b.StorePart(dst[pos:])
		pos += n
	}
}
