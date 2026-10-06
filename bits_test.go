//go:build goexperiment.simd

package gr4ph

import "testing"

func TestBitsSetTest(t *testing.T) {
	row := make([]uint64, 3)
	for _, i := range []int{0, 63, 64, 65, 127, 191} {
		setBit(row, i)
	}
	for _, i := range []int{0, 63, 64, 65, 127, 191} {
		if !testBit(row, i) {
			t.Fatalf("testBit(%d) = false after setBit", i)
		}
	}
	for _, i := range []int{1, 62, 66, 126, 128, 190} {
		if testBit(row, i) {
			t.Fatalf("testBit(%d) = true, want false", i)
		}
	}
	if got := popcountRow(row); got != 6 {
		t.Fatalf("popcountRow = %d, want 6", got)
	}
	// The clear() builtin is what the engine uses to reset a scratch row.
	clear(row[:1])
	if got := popcountRow(row); got != 4 {
		t.Fatalf("popcountRow after clear(row[:1]) = %d, want 4 (bits 64, 65, 127, 191 survive)", got)
	}
	if !testBit(row, 64) || !testBit(row, 65) || !testBit(row, 127) {
		t.Fatal("clear(row[:1]) must not touch the other words")
	}
}

func TestBitsEachBit(t *testing.T) {
	row := make([]uint64, 2)
	want := []int{3, 64, 70, 127}
	for _, i := range want {
		setBit(row, i)
	}

	var got []int
	eachBit(row, func(i int) bool {
		got = append(got, i)
		return true
	})
	if len(got) != len(want) {
		t.Fatalf("eachBit visited %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("eachBit visited %v, want %v (ascending order)", got, want)
		}
	}

	// Early exit: stop after the second hit.
	count := 0
	eachBit(row, func(int) bool {
		count++
		return count < 2
	})
	if count != 2 {
		t.Fatalf("eachBit visited %d bits after early exit, want 2", count)
	}

	// Empty rows are a no-op, including the zero-length row of an empty engine.
	eachBit(nil, func(int) bool { t.Fatal("eachBit visited a bit in an empty row"); return true })
	if got := popcountRow(nil); got != 0 {
		t.Fatalf("popcountRow(nil) = %d, want 0", got)
	}
}
