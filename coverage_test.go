//go:build goexperiment.simd

package gr4ph

import (
	"strconv"
	"testing"
)

// The mask-driven coverage overlay on the synthetic fixture: cm0 defends
// T1003.001 (1) and T1059.001 (4), cm1 defends T1003 (0) and T1003.002 (2), so
// the mapped range is {0,1,2,4}, {3,5} is unmapped and TTP 3 is unmapped while
// its child TTP 4 is defended.

// selOf builds a selection of words words with bits set.
func selOf(words int, bits ...int) Selection {
	s := make(Selection, words)
	for _, b := range bits {
		setBit(s, b)
	}
	return s
}

func TestCoverageMapped(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	dstT := make([]TTP, e.TTPCount())

	n := e.TTPsMapped(scratchT, dstT)
	if n != 4 {
		t.Fatalf("TTPsMapped = %d, want 4", n)
	}
	if !equalIDs(dstT[:n], []TTP{0, 1, 2, 4}) {
		t.Fatalf("TTPsMapped ids = %v, want [0 1 2 4]", dstT[:n])
	}
}

func TestCoverageSelection(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	dstT := make([]TTP, e.TTPCount())

	for _, c := range []struct {
		name string
		sel  Selection
		want []TTP
	}{
		{"cm0", selOf(1, 0), []TTP{1, 4}},
		{"cm1", selOf(1, 1), []TTP{0, 2}},
		{"both", selOf(1, 0, 1), []TTP{0, 1, 2, 4}},
		{"empty", selOf(1), nil},
	} {
		n := e.TTPsCovered(c.sel, scratchT, dstT)
		if n != len(c.want) {
			t.Errorf("TTPsCovered %s = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstT[:n], c.want) {
			t.Errorf("TTPsCovered %s ids = %v, want %v", c.name, dstT[:n], c.want)
		}
	}
}

func TestCoverageBlind(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	dstT := make([]TTP, e.TTPCount())
	all := selOf(1, 0, 1, 2, 3, 4, 5)

	for _, c := range []struct {
		name   string
		active Selection
		sel    Selection
		want   []TTP
	}{
		{"all active, cm0", all, selOf(1, 0), []TTP{0, 2, 3, 5}},
		{"{0,2} active, cm1", selOf(1, 0, 2), selOf(1, 1), nil},
	} {
		n := e.TTPsBlind(c.active, c.sel, scratchT, dstT)
		if n != len(c.want) {
			t.Errorf("TTPsBlind %s = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstT[:n], c.want) {
			t.Errorf("TTPsBlind %s ids = %v, want %v", c.name, dstT[:n], c.want)
		}
	}
}

func TestCoverageGain(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	empty := selOf(1)
	cm0 := selOf(1, 0)
	cm1 := selOf(1, 1)

	for _, c := range []struct {
		name string
		cm   Countermeasure
		sel  Selection
		want int
	}{
		{"cm1 over cm0", 1, cm0, 2},
		{"cm0 over cm1", 0, cm1, 2},
		{"cm0 over cm0", 0, cm0, 0},
		{"cm0 over nothing", 0, empty, 2},
		{"out of range cm", Countermeasure(9), empty, 0},
	} {
		if got := e.CoverageGain(c.cm, c.sel, scratchT); got != c.want {
			t.Errorf("CoverageGain %s = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestCountermeasuresForObserved(t *testing.T) {
	e := buildSynthetic(t)
	scratchC := make([]uint64, e.WordsPerRow(KindCountermeasure))
	dstC := make([]Countermeasure, e.CountermeasureCount())

	for _, c := range []struct {
		name     string
		observed Selection
		want     []Countermeasure
	}{
		{"{1,4}", selOf(1, 1, 4), []Countermeasure{0}},
		{"{0,2}", selOf(1, 0, 2), []Countermeasure{1}},
		{"{0,1}", selOf(1, 0, 1), []Countermeasure{0, 1}},
		{"empty", selOf(1), nil},
	} {
		n := e.CountermeasuresForObserved(c.observed, scratchC, dstC)
		if n != len(c.want) {
			t.Errorf("CountermeasuresForObserved %s = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstC[:n], c.want) {
			t.Errorf("CountermeasuresForObserved %s ids = %v, want %v", c.name, dstC[:n], c.want)
		}
	}
}

// TestCoverageTotality pins that a selection bit past the live range selects no
// row (so a stale inventory cannot fail) and that the empty engine answers every
// overlay query with 0 instead of panicking.
func TestCoverageTotality(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	scratchC := make([]uint64, e.WordsPerRow(KindCountermeasure))
	dstT := make([]TTP, e.TTPCount())
	dstC := make([]Countermeasure, e.CountermeasureCount())

	// Bit 40 is past the two live countermeasures: the result equals the
	// selection without it.
	if n := e.TTPsCovered(selOf(1, 0, 40), scratchT, dstT); n != 2 || !equalIDs(dstT[:n], []TTP{1, 4}) {
		t.Errorf("TTPsCovered with bit 40 = %d %v, want 2 [1 4]", n, dstT[:n])
	}
	// The same for an observed set with a bit past the technique range.
	if n := e.CountermeasuresForObserved(selOf(1, 1, 40), scratchC, dstC); n != 1 || !equalIDs(dstC[:n], []Countermeasure{0}) {
		t.Errorf("CountermeasuresForObserved with bit 40 = %d %v, want 1 [0]", n, dstC[:n])
	}
	if got := e.CoverageGain(0, selOf(1, 40), scratchT); got != 2 {
		t.Errorf("CoverageGain over a selection with bit 40 = %d, want 2", got)
	}
	// The active side of TTPsBlind is the caller's technique selection, so the
	// same rule holds there: bit 40 selects no technique.
	if n := e.TTPsBlind(selOf(1, 0, 40), selOf(1, 0), scratchT, dstT); n != 1 || !equalIDs(dstT[:n], []TTP{0}) {
		t.Errorf("TTPsBlind with an active bit past the range = %d %v, want 1 [0]", n, dstT[:n])
	}

	empty, err := NewBuilder().Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if n := empty.TTPsMapped(nil, nil); n != 0 {
		t.Errorf("empty TTPsMapped = %d, want 0", n)
	}
	if n := empty.TTPsCovered(nil, nil, nil); n != 0 {
		t.Errorf("empty TTPsCovered = %d, want 0", n)
	}
	if n := empty.TTPsBlind(nil, nil, nil, nil); n != 0 {
		t.Errorf("empty TTPsBlind = %d, want 0", n)
	}
	if n := empty.CoverageGain(0, nil, nil); n != 0 {
		t.Errorf("empty CoverageGain = %d, want 0", n)
	}
	if n := empty.CountermeasuresForObserved(nil, nil, nil); n != 0 {
		t.Errorf("empty CountermeasuresForObserved = %d, want 0", n)
	}
}

// TestCoverageTruncation pins the result contract on the overlay queries: dst is
// truncated at len(dst) and the return value is the total.
func TestCoverageTruncation(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	one := make([]TTP, 1)

	n := e.TTPsBlind(selOf(1, 0, 1, 2, 3, 4, 5), selOf(1, 0), scratchT, one)
	if n != 4 {
		t.Fatalf("TTPsBlind truncated = %d, want 4", n)
	}
	if one[0] != 0 {
		t.Fatalf("TTPsBlind truncated wrote dst[0] = %d, want 0", one[0])
	}
}

// TestCoverageGainsMatchesGain pins the bulk primitive against the
// single-candidate one it was extracted from: a ranking walks the table
// CoverageGains writes, so any disagreement would change what `gain` prints.
func TestCoverageGainsMatchesGain(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	gains := make([]int, e.CountermeasureCount())

	for _, sel := range []Selection{selOf(1), selOf(1, 0), selOf(1, 1), selOf(1, 0, 1)} {
		n := e.CoverageGains(sel, scratchT, gains)
		positive := 0
		for cm := range e.CountermeasureCount() {
			want := e.CoverageGain(Countermeasure(cm), sel, scratchT)
			if gains[cm] != want {
				t.Errorf("CoverageGains[%d] over %v = %d, CoverageGain = %d", cm, sel, gains[cm], want)
			}
			if want > 0 {
				positive++
			}
		}
		if n != positive {
			t.Errorf("CoverageGains over %v reported %d positive gains, want %d", sel, n, positive)
		}
	}

	// A dst shorter than the partition counts every gain but writes only the
	// entries it has room for.
	short := []int{-1}
	if n := e.CoverageGains(selOf(1), scratchT, short); n != 2 || short[0] != 2 {
		t.Errorf("CoverageGains with a one-entry dst = %d %v, want 2 [2]", n, short)
	}
}

func TestCoverageGuards(t *testing.T) {
	e := buildSynthetic(t)
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	scratchC := make([]uint64, e.WordsPerRow(KindCountermeasure))
	dstT := make([]TTP, e.TTPCount())
	dstC := make([]Countermeasure, e.CountermeasureCount())

	mustPanic(t, "TTPsMapped nil scratch", "gr4ph: scratch too small", func() {
		e.TTPsMapped(nil, dstT)
	})
	mustPanic(t, "TTPsCovered nil selection", "gr4ph: selection too small", func() {
		e.TTPsCovered(nil, scratchT, dstT)
	})
	mustPanic(t, "TTPsBlind nil active", "gr4ph: selection too small", func() {
		e.TTPsBlind(nil, selOf(1, 0), scratchT, dstT)
	})
	mustPanic(t, "TTPsBlind nil selection", "gr4ph: selection too small", func() {
		e.TTPsBlind(selOf(1, 0), nil, scratchT, dstT)
	})
	mustPanic(t, "CoverageGain nil selection", "gr4ph: selection too small", func() {
		e.CoverageGain(0, nil, scratchT)
	})
	mustPanic(t, "CountermeasuresForObserved nil observed", "gr4ph: selection too small", func() {
		e.CountermeasuresForObserved(nil, scratchC, dstC)
	})
	mustPanic(t, "TTPsCovered short scratch", "gr4ph: scratch too small", func() {
		e.TTPsCovered(selOf(1, 0), scratchT[:0], dstT)
	})
}

// TestCoverageMaskTailFullWord pins maskTail's no-op: with exactly 64
// techniques the single word of a KindTTP row is full, so rem is 0, there is no
// tail to clear and bit 63 must survive. Every other fixture has nTTP ≡ 6, 48
// or 34 (mod 64) — 6 synthetic, 1200 bench, 1186 real — so this is the only
// case that reaches rem == 0, and a maskTail that masked unconditionally (or
// dropped the rem != 0 clause, which is the same thing at a full word) would
// wipe the whole row: the case reads 0 ids where it must read 2.
func TestCoverageMaskTailFullWord(t *testing.T) {
	b := NewBuilder()
	for i := range 64 {
		if _, err := b.AddTTP("T"+strconv.Itoa(i), "t"+strconv.Itoa(i), DomainEnterprise, NoParent, false); err != nil {
			t.Fatalf("AddTTP #%d: %v", i, err)
		}
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := e.WordsPerRow(KindTTP); got != 1 {
		t.Fatalf("WordsPerRow(TTP) = %d, want 1 for 64 techniques", got)
	}
	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	dstT := make([]TTP, e.TTPCount())

	// Nothing deployed: the blind set is the active set, and bit 63 is both the
	// last live technique and the last bit of the row's only word.
	if n := e.TTPsBlind(selOf(2, 0, 63), selOf(1), scratchT, dstT); n != 2 || !equalIDs(dstT[:n], []TTP{0, 63}) {
		t.Errorf("TTPsBlind over a full word = %d %v, want 2 [0 63]", n, dstT[:n])
	}
	// Bits at and past the live range select nothing, even though the caller's
	// selection is wide enough to hold them.
	if n := e.TTPsBlind(selOf(2, 0, 63, 64, 70), selOf(1), scratchT, dstT); n != 2 || !equalIDs(dstT[:n], []TTP{0, 63}) {
		t.Errorf("TTPsBlind with bits past the live range = %d %v, want 2 [0 63]", n, dstT[:n])
	}
}
