//go:build goexperiment.simd

package gr4ph

import "testing"

// The KEV partition on the synthetic fixture (engine_test.go): entry 0
// (CVE-2099-0001) names CWE-20 and CWE-502 and is about Avendor/Alpha, entry 1
// (CVE-2099-0002) names CWE-502 only and is about Bvendor/Beta. Every direction
// of both families is therefore non-empty, and the two CVEs are the CVE of the
// file, not of the plan.

func TestKEVWeaknesses(t *testing.T) {
	e := buildSynthetic(t)
	dstCWE := make([]CWE, e.CWECount())

	if got := e.KEVCWEDegree(KEV(0)); got != 2 {
		t.Errorf("KEVCWEDegree(entry 0) = %d, want 2", got)
	}
	if got := e.KEVCWEDegree(KEV(1)); got != 1 {
		t.Errorf("KEVCWEDegree(entry 1) = %d, want 1", got)
	}
	if got := e.KEVCWEDegree(KEV(9)); got != 0 {
		t.Errorf("KEVCWEDegree(out of range) = %d, want 0", got)
	}

	for _, c := range []struct {
		name  string
		entry KEV
		want  []CWE
	}{
		{"entry 0", 0, []CWE{0, 1}},
		{"entry 1", 1, []CWE{1}},
	} {
		n := e.CWEsForKEV(c.entry, dstCWE)
		if n != len(c.want) {
			t.Errorf("CWEsForKEV(%s) = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstCWE[:n], c.want) {
			t.Errorf("CWEsForKEV(%s) = %v, want %v", c.name, dstCWE[:n], c.want)
		}
	}

	// The transpose: weakness 0 is named by entry 0 only, weakness 1 by both.
	dstK := make([]KEV, e.KEVCount())
	for _, c := range []struct {
		name string
		cwe  CWE
		want []KEV
	}{
		{"CWE-20", 0, []KEV{0}},
		{"CWE-502", 1, []KEV{0, 1}},
	} {
		n := e.KEVsForCWE(c.cwe, dstK)
		if n != len(c.want) {
			t.Errorf("KEVsForCWE(%s) = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstK[:n], c.want) {
			t.Errorf("KEVsForCWE(%s) = %v, want %v", c.name, dstK[:n], c.want)
		}
	}
}

func TestKEVProducts(t *testing.T) {
	e := buildSynthetic(t)
	dstP := make([]Product, e.ProductCount())
	dstK := make([]KEV, e.KEVCount())
	scratch := make([]uint64, e.WordsPerRow(KindKEV))

	if n := e.ProductsForKEV(KEV(0), dstP); n != 1 || dstP[0] != 0 {
		t.Errorf("ProductsForKEV(entry 0) = %d %v, want 1 [0]", n, dstP[:n])
	}
	if n := e.ProductsForKEV(KEV(1), dstP); n != 1 || dstP[0] != 1 {
		t.Errorf("ProductsForKEV(entry 1) = %d %v, want 1 [1]", n, dstP[:n])
	}
	if n := e.ProductsForKEV(KEV(9), dstP); n != 0 {
		t.Errorf("ProductsForKEV(out of range) = %d, want 0", n)
	}

	sel := make([]uint64, e.WordsPerRow(KindProduct))
	for _, c := range []struct {
		name string
		bits []int
		want []KEV
	}{
		{"one product", []int{0}, []KEV{0}},
		{"both products", []int{0, 1}, []KEV{0, 1}},
		{"no product", nil, nil},
	} {
		for i := range sel {
			sel[i] = 0
		}
		for _, b := range c.bits {
			setBit(sel, b)
		}
		n := e.KEVsForProducts(sel, scratch, dstK)
		if n != len(c.want) {
			t.Errorf("KEVsForProducts(%s) = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstK[:n], c.want) {
			t.Errorf("KEVsForProducts(%s) = %v, want %v", c.name, dstK[:n], c.want)
		}
	}
}

// TestKEVsForCWEs pins the union over a weakness selection, including that two
// selected classes naming the same entry yield it once.
func TestKEVsForCWEs(t *testing.T) {
	e := buildSynthetic(t)
	dstK := make([]KEV, e.KEVCount())
	scratch := make([]uint64, e.WordsPerRow(KindKEV))
	sel := make([]uint64, e.WordsPerRow(KindCWE))

	for _, c := range []struct {
		name string
		bits []int
		want []KEV
	}{
		{"CWE-20", []int{0}, []KEV{0}},
		{"CWE-502", []int{1}, []KEV{0, 1}},
		{"both, entry 0 counted once", []int{0, 1}, []KEV{0, 1}},
		{"none", nil, nil},
	} {
		for i := range sel {
			sel[i] = 0
		}
		for _, b := range c.bits {
			setBit(sel, b)
		}
		n := e.KEVsForCWEs(sel, scratch, dstK)
		if n != len(c.want) {
			t.Errorf("KEVsForCWEs(%s) = %d, want %d", c.name, n, len(c.want))
			continue
		}
		if !equalIDs(dstK[:n], c.want) {
			t.Errorf("KEVsForCWEs(%s) = %v, want %v", c.name, dstK[:n], c.want)
		}
	}
}

// TestKEVLayout pins the four blocks word by word, so a transposed offset
// formula or a wrong stride cannot pass unnoticed.
func TestKEVLayout(t *testing.T) {
	e := buildSynthetic(t)

	if got := e.WordsPerRow(KindKEV); got != 1 {
		t.Fatalf("WordsPerRow(KEV) = %d, want 1", got)
	}
	if got := e.WordsPerRow(KindCWE); got != 1 {
		t.Fatalf("WordsPerRow(CWE) = %d, want 1", got)
	}
	if got := e.WordsPerRow(KindProduct); got != 1 {
		t.Fatalf("WordsPerRow(Product) = %d, want 1", got)
	}
	for _, c := range []struct {
		name  string
		block []uint64
		want  []uint64
	}{
		{"kevCWE", e.kevCWE, []uint64{0b11, 0b10}},
		{"cweKEV", e.cweKEV, []uint64{0b01, 0b11}},
		{"kevProduct", e.kevProduct, []uint64{0b01, 0b10}},
		{"productKEV", e.productKEV, []uint64{0b01, 0b10}},
	} {
		if !equalRows(c.block, c.want) {
			t.Errorf("%s = %v, want %v", c.name, c.block, c.want)
		}
	}
}

// TestKEVColdPath pins the resolvers and the accessors, including that every
// key is matched trimmed and case-insensitively.
func TestKEVColdPath(t *testing.T) {
	e := buildSynthetic(t)

	for _, c := range []struct {
		query string
		want  KEV
	}{
		{"CVE-2099-0001", 0},
		{"cve-2099-0001", 0},
		{" CVE-2099-0002 ", 1},
	} {
		got, ok := e.KEV(c.query)
		if !ok || got != c.want {
			t.Errorf("KEV(%q) = %d,%v, want %d,true", c.query, got, ok, c.want)
		}
	}
	if _, ok := e.KEV("CVE-2099-9999"); ok {
		t.Error("unknown CVE id resolved")
	}
	if _, ok := e.KEV("Alpha Flaw"); ok {
		t.Error("a vulnerability name must not resolve: the CVE id is the only key")
	}

	if got, ok := e.CWE("cwe-502"); !ok || got != 1 {
		t.Errorf("CWE(cwe-502) = %d,%v, want 1,true", got, ok)
	}
	if got, ok := e.Product("avendor", "alpha"); !ok || got != 0 {
		t.Errorf("Product(avendor, alpha) = %d,%v, want 0,true", got, ok)
	}
	if _, ok := e.Product("Avendor", "Nope"); ok {
		t.Error("an unknown product pair resolved")
	}

	for _, c := range []struct {
		name string
		got  string
		want string
	}{
		{"KEVID", e.KEVID(0), "CVE-2099-0001"},
		{"KEVName", e.KEVName(1), "Beta Flaw"},
		{"KEVAdded", e.KEVAdded(0), "2099-01-01"},
		{"CWEID", e.CWEID(1), "CWE-502"},
		{"KEVProductVendor", e.KEVProductVendor(1), "Bvendor"},
		{"KEVProductName", e.KEVProductName(0), "Alpha"},
		{"KEVVendor", e.KEVVendor(1), "Bvendor"},
		{"KEVProduct", e.KEVProduct(0), "Alpha"},
	} {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
	if !e.KEVRansomware(0) || e.KEVRansomware(1) {
		t.Errorf("KEVRansomware = %v/%v, want true/false", e.KEVRansomware(0), e.KEVRansomware(1))
	}
}

// TestKEVTotality pins that an out-of-range id and a selection bit past the live
// range are ignored rather than fatal.
func TestKEVTotality(t *testing.T) {
	e := buildSynthetic(t)
	scratch := make([]uint64, e.WordsPerRow(KindKEV))
	dstK := make([]KEV, e.KEVCount())
	dstCWE := make([]CWE, e.CWECount())
	dstP := make([]Product, e.ProductCount())
	sel := make([]uint64, e.WordsPerRow(KindCWE))
	setBit(sel, 1)
	setBit(sel, 40) // past the two live weaknesses

	if n := e.KEVsForCWEs(sel, scratch, dstK); n != 2 || !equalIDs(dstK[:n], []KEV{0, 1}) {
		t.Errorf("KEVsForCWEs with a stale bit = %d %v, want 2 [0 1]", n, dstK[:n])
	}
	if n := e.CWEsForKEV(KEV(99), dstCWE); n != 0 {
		t.Errorf("CWEsForKEV(out of range) = %d, want 0", n)
	}
	if n := e.KEVsForCWE(CWE(99), dstK); n != 0 {
		t.Errorf("KEVsForCWE(out of range) = %d, want 0", n)
	}
	if n := e.ProductsForKEV(KEV(99), dstP); n != 0 {
		t.Errorf("ProductsForKEV(out of range) = %d, want 0", n)
	}
	if n := e.KEVCWEDegree(KEV(99)); n != 0 {
		t.Errorf("KEVCWEDegree(out of range) = %d, want 0", n)
	}
}

// TestKEVTruncation pins the result contract: dst is truncated at len(dst) and
// the return value is the total.
func TestKEVTruncation(t *testing.T) {
	e := buildSynthetic(t)
	scratch := make([]uint64, e.WordsPerRow(KindKEV))
	sel := make([]uint64, e.WordsPerRow(KindCWE))
	setBit(sel, 1)
	one := make([]KEV, 1)

	if n := e.KEVsForCWEs(sel, scratch, one); n != 2 {
		t.Fatalf("KEVsForCWEs truncated = %d, want 2", n)
	}
	if one[0] != 0 {
		t.Fatalf("KEVsForCWEs wrote dst[0] = %d, want 0", one[0])
	}
}

func TestKEVGuards(t *testing.T) {
	e := buildSynthetic(t)
	scratch := make([]uint64, e.WordsPerRow(KindKEV))
	dstK := make([]KEV, e.KEVCount())

	mustPanic(t, "KEVsForProducts nil selection", "gr4ph: selection too small", func() {
		e.KEVsForProducts(nil, scratch, dstK)
	})
	mustPanic(t, "KEVsForCWEs nil selection", "gr4ph: selection too small", func() {
		e.KEVsForCWEs(nil, scratch, dstK)
	})
	mustPanic(t, "KEVsForProducts short scratch", "gr4ph: scratch too small", func() {
		e.KEVsForProducts(make([]uint64, 1), nil, dstK)
	})
	mustPanic(t, "KEVsForCWEs short scratch", "gr4ph: scratch too small", func() {
		e.KEVsForCWEs(make([]uint64, 1), nil, dstK)
	})
	mustPanic(t, "KEVID out of range", "gr4ph: kev out of range", func() {
		e.KEVID(KEV(99))
	})
	mustPanic(t, "CWEID out of range", "gr4ph: cwe out of range", func() {
		e.CWEID(CWE(99))
	})
	mustPanic(t, "KEVProductVendor out of range", "gr4ph: product out of range", func() {
		e.KEVProductVendor(Product(99))
	})
	mustPanic(t, "KEVVendor out of range", "gr4ph: kev out of range", func() {
		e.KEVVendor(KEV(99))
	})
}
