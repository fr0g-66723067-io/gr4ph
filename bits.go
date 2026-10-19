//go:build goexperiment.simd

package gr4ph

import "math/bits"

// Bit helpers over a single bitmatrix row ([]uint64, LSB-first within each
// word: bit i lives in word i>>6, mask 1<<(i&63)).
//
// For the pinned tables the matrix rows are a handful of words wide (the
// data-component rows are the narrowest, the weakness and product rows over the
// entries the widest; the tactic and platform masks are one word each), so bit
// *scanning* is scalar: there is no SIMD instruction that enumerates set-bit
// indices, and math/bits compiles to single tzcnt/popcnt instructions. Only the
// bulk row arithmetic (OR/AND/COPY) is vectorised, in kernel_simd.go. The
// engine itself admits up to 1024-word rows at MaxNodes.

// setBit sets bit i of row.
func setBit(row []uint64, i int) {
	row[i>>6] |= 1 << uint(i&63)
}

// testBit reports whether bit i of row is set.
func testBit(row []uint64, i int) bool {
	return row[i>>6]&(1<<uint(i&63)) != 0
}

// eachBit calls f with the index of every set bit of row, in ascending order,
// stopping early (returning) as soon as f returns false.
func eachBit(row []uint64, f func(i int) bool) {
	for w, word := range row {
		for word != 0 {
			i := w<<6 + bits.TrailingZeros64(word)
			if !f(i) {
				return
			}
			word &= word - 1
		}
	}
}

// maskTail clears the bits at and beyond n in the last word of row, which is
// where a row sized for n can hold them. A selection may be wider than the live
// range (checkSelection only sets a lower bound), and an out-of-range bit must
// select nothing rather than enumerate a phantom id.
func maskTail(row []uint64, n int) {
	if rem := n & 63; rem != 0 && len(row) > 0 {
		row[len(row)-1] &= 1<<uint(rem) - 1
	}
}

// popcountRow returns the number of set bits in row.
func popcountRow(row []uint64) int {
	n := 0
	for _, w := range row {
		n += bits.OnesCount64(w)
	}
	return n
}
