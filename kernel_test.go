//go:build goexperiment.simd

package gr4ph

import (
	"math/rand/v2"
	"simd"
	"testing"
)

// TestKernelEquivalence checks the vector kernels against a scalar reference
// over every row length from 0 to 40 words (spanning the empty row,
// below-one-vector rows, the 256-bit case of 4 words, and multi-vector rows).
//
// It is also the regression test for the row-tail bug: under GODEBUG=simd=0 the
// count LoadUint64sPart reports is len(s) rather than min(lanes, len(s)), so a
// kernel that advances by that count skips the tail of every row that is not a
// whole number of vectors.
func TestKernelEquivalence(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x6772_3470, 0x5349_4d44))
	for words := 0; words <= 40; words++ {
		for range 200 {
			// Rows are carved out of one-word-padded buffers whose outer words
			// hold a sentinel, so a kernel that writes outside the row is
			// observed rather than assumed away.
			srcBuf := make([]uint64, words+2)
			for i := range srcBuf {
				srcBuf[i] = rng.Uint64()
			}
			dstBuf := make([]uint64, words+2)
			for i := range dstBuf {
				dstBuf[i] = rng.Uint64()
			}
			src, dst := rowOf(srcBuf, words), rowOf(dstBuf, words)
			want := make([]uint64, words)
			for i := range want {
				want[i] = dst[i] | src[i]
			}

			orRowInto(dst, src)
			if !equalRows(dst, want) {
				t.Fatalf("orRowInto words=%d: got %x want %x", words, dst, want)
			}
			checkCanaries(t, "orRowInto", words, srcBuf, dstBuf)

			// andRowInto
			dstBuf = make([]uint64, words+2)
			for i := range dstBuf {
				dstBuf[i] = rng.Uint64()
			}
			dst = rowOf(dstBuf, words)
			for i := range want {
				want[i] = dst[i] & src[i]
			}
			andRowInto(dst, src)
			if !equalRows(dst, want) {
				t.Fatalf("andRowInto words=%d: got %x want %x", words, dst, want)
			}
			checkCanaries(t, "andRowInto", words, srcBuf, dstBuf)

			// copyRow
			dstBuf = make([]uint64, words+2)
			for i := range dstBuf {
				dstBuf[i] = rng.Uint64()
			}
			dst = rowOf(dstBuf, words)
			copyRow(dst, src)
			if !equalRows(dst, src) {
				t.Fatalf("copyRow words=%d: got %x want %x", words, dst, src)
			}
			checkCanaries(t, "copyRow", words, srcBuf, dstBuf)
		}
	}
}

// canary is the sentinel parked in the words on either side of a row.
const canary = ^uint64(0)

// rowOf parks the sentinel outside the row and returns the row itself.
func rowOf(buf []uint64, words int) []uint64 {
	buf[0], buf[words+1] = canary, canary
	return buf[1 : 1+words]
}

// checkCanaries fails when a kernel wrote outside its row.
func checkCanaries(t *testing.T, name string, words int, bufs ...[]uint64) {
	t.Helper()
	for _, buf := range bufs {
		if buf[0] != canary || buf[words+1] != canary {
			t.Fatalf("%s words=%d: kernel touched memory outside the row: %x %x",
				name, words, buf[0], buf[words+1])
		}
	}
}

// TestKernelShortRows pins the short-row behaviour explicitly: rows below one
// vector, and one whole vector plus a one-word tail, must be handled without
// touching memory beyond the row.
func TestKernelShortRows(t *testing.T) {
	lanes := simd.VectorBitSize() / 64
	for _, words := range []int{1, 2, 3, lanes + 1} {
		srcBuf := make([]uint64, words+2)
		for i := range srcBuf {
			srcBuf[i] = ^uint64(0)
		}
		src := rowOf(srcBuf, words)

		dstBuf := make([]uint64, words+2)
		dst := rowOf(dstBuf, words)
		orRowInto(dst, src)
		for i := range dst {
			if dst[i] != ^uint64(0) {
				t.Fatalf("orRowInto words=%d: dst[%d]=%x want all ones", words, i, dst[i])
			}
		}
		checkCanaries(t, "orRowInto", words, srcBuf, dstBuf)

		dstBuf = make([]uint64, words+2)
		dst = rowOf(dstBuf, words)
		andRowInto(dst, src)
		checkCanaries(t, "andRowInto", words, srcBuf, dstBuf)

		dstBuf = make([]uint64, words+2)
		dst = rowOf(dstBuf, words)
		copyRow(dst, src)
		if !equalRows(dst, src) {
			t.Fatalf("copyRow words=%d: got %x want %x", words, dst, src)
		}
		checkCanaries(t, "copyRow", words, srcBuf, dstBuf)
	}
}

// TestKernelPartContract pins what the kernels may assume about the simd partial
// helpers, and what they must not.
//
// The count LoadUint64sPart reports is implementation-dependent: min(lanes,
// len(s)) on hardware, but len(s) under GODEBUG=simd=0, where the emulated
// vector holds two words yet reports the whole slice. The kernels therefore
// never advance by it; TestKernelEquivalence is the contract that matters, and
// `make test` runs the suite under both implementations because only the
// emulated one can expose a stride that trusts the reported count.
func TestKernelPartContract(t *testing.T) {
	lanes := simd.VectorBitSize() / 64
	if wordsPerVector != lanes {
		t.Fatalf("wordsPerVector = %d, want simd.VectorBitSize()/64 = %d", wordsPerVector, lanes)
	}
	if wordsPerVector < 1 {
		t.Fatalf("wordsPerVector = %d, want >= 1", wordsPerVector)
	}
	t.Logf("simd.VectorBitSize()=%d lanes=%d emulated=%v", simd.VectorBitSize(), lanes, simd.Emulated())

	for n := 1; n <= lanes*2+1; n++ {
		s := make([]uint64, n)
		for i := range s {
			s[i] = uint64(i + 1)
		}
		// The reported count stays within the slice on every implementation;
		// its exact value is not a contract (see the doc comment).
		if _, got := simd.LoadUint64sPart(s); got < 1 || got > n {
			t.Fatalf("LoadUint64sPart(len=%d) returned n=%d, want 1 <= n <= %d", n, got, n)
		}

		// StorePart writes exactly min(len(s), lanes) elements and never
		// overruns the slice.
		out := make([]uint64, n)
		for i := range out {
			out[i] = ^uint64(0)
		}
		want := min(n, lanes)
		if written := simd.BroadcastUint64s(0).StorePart(out); written != want {
			t.Fatalf("StorePart(len=%d) returned %d, want %d", n, written, want)
		}
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
