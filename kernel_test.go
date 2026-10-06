//go:build goexperiment.simd

package gr4ph

import (
	"math/rand/v2"
	"simd"
	"testing"
)

// TestKernelEquivalence checks the vector kernels against a scalar reference
// over every row length from 1 to 40 words (spanning below-one-vector rows, the
// 256-bit case of 4 words, and multi-vector rows).
func TestKernelEquivalence(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x6772_3470, 0x5349_4d44))
	for words := 1; words <= 40; words++ {
		for range 200 {
			src := make([]uint64, words)
			for i := range src {
				src[i] = rng.Uint64()
			}

			// orRowInto
			dst := make([]uint64, words)
			for i := range dst {
				dst[i] = rng.Uint64()
			}
			want := make([]uint64, words)
			for i := range want {
				want[i] = dst[i] | src[i]
			}
			orRowInto(dst, src)
			if !equalRows(dst, want) {
				t.Fatalf("orRowInto words=%d: got %x want %x", words, dst, want)
			}

			// andRowInto
			dst = make([]uint64, words)
			for i := range dst {
				dst[i] = rng.Uint64()
			}
			for i := range want {
				want[i] = dst[i] & src[i]
			}
			andRowInto(dst, src)
			if !equalRows(dst, want) {
				t.Fatalf("andRowInto words=%d: got %x want %x", words, dst, want)
			}

			// copyRow
			dst = make([]uint64, words)
			for i := range dst {
				dst[i] = rng.Uint64()
			}
			copyRow(dst, src)
			if !equalRows(dst, src) {
				t.Fatalf("copyRow words=%d: got %x want %x", words, dst, src)
			}
		}
	}
}

// TestKernelShortRows pins the sub-vector behaviour explicitly: a 1-word and a
// 2-word row must be handled without touching memory beyond the row.
func TestKernelShortRows(t *testing.T) {
	for _, words := range []int{1, 2, 3} {
		src := make([]uint64, words)
		for i := range src {
			src[i] = ^uint64(0)
		}
		dst := make([]uint64, words)
		orRowInto(dst, src)
		for i := range dst {
			if dst[i] != ^uint64(0) {
				t.Fatalf("orRowInto words=%d: dst[%d]=%x want all ones", words, i, dst[i])
			}
		}
	}
}

// TestKernelPartContract documents the simd Part semantics this module relies
// on: n = min(lanes, len(s)) and a masked store that writes exactly n elements.
func TestKernelPartContract(t *testing.T) {
	lanes := simd.VectorBitSize() / 64
	t.Logf("simd.VectorBitSize()=%d lanes=%d emulated=%v", simd.VectorBitSize(), lanes, simd.Emulated())

	for n := 1; n <= lanes*2+1; n++ {
		s := make([]uint64, n)
		for i := range s {
			s[i] = uint64(i + 1)
		}
		_, got := simd.LoadUint64sPart(s)
		want := n
		if want > lanes {
			want = lanes
		}
		if got != want {
			t.Fatalf("LoadUint64sPart(len=%d) returned n=%d want %d", n, got, want)
		}

		out := make([]uint64, n)
		for i := range out {
			out[i] = ^uint64(0)
		}
		simd.BroadcastUint64s(0).StorePart(out)
		for i := range want {
			if out[i] != 0 {
				t.Fatalf("StorePart(len=%d) left out[%d]=%x, want 0", n, i, out[i])
			}
		}
		for i := want; i < n; i++ {
			if out[i] != ^uint64(0) {
				t.Fatalf("StorePart(len=%d) wrote past the vector: out[%d]=%x", n, i, out[i])
			}
		}
	}
}

func equalRows(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
