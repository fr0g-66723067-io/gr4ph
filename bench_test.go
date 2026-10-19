//go:build goexperiment.simd

package gr4ph

import (
	"math/rand/v2"
	"strconv"
	"testing"
)

// generatedEngine builds a deterministic large graph with the same strides as
// the ontology dataset (19-word TTP rows, 4-word artifact rows, 3-word
// countermeasure rows) without depending on it: 1200 techniques, 250
// artifacts, 160 countermeasures, 40 offensive and 37 defensive relations.
//
// Nodes are registered in ascending id order and every tenth node is a parent
// of the nine that follow it, so the contiguous-child invariant holds and
// roll-up has real children to walk.
func generatedEngine(tb testing.TB, nTTP, nArt, nCM, nEdges int) *Engine {
	tb.Helper()
	b := NewBuilder()
	rng := rand.New(rand.NewPCG(0x9e37_79b9, 0x7f4a_7c15))

	for i := range nTTP {
		parent := NoParent
		if k := i % 10; k != 0 {
			parent = TTP(i - k)
		}
		id := "T" + strconv.Itoa(i)
		if _, err := b.AddTTP(id, "Technique "+id, DomainEnterprise, parent, false); err != nil {
			tb.Fatalf("AddTTP: %v", err)
		}
	}
	for i := range nArt {
		name := "A" + strconv.Itoa(i)
		if _, err := b.AddArtifact(name, "Artifact "+name); err != nil {
			tb.Fatalf("AddArtifact: %v", err)
		}
	}
	for i := range nCM {
		id := "CM" + strconv.Itoa(i)
		if _, err := b.AddCountermeasure(id, "Countermeasure "+id); err != nil {
			tb.Fatalf("AddCountermeasure: %v", err)
		}
	}

	rels := make([]Rel, 0, 40)
	for i := range 40 {
		r, err := b.AddRel("rel" + strconv.Itoa(i))
		if err != nil {
			tb.Fatalf("AddRel: %v", err)
		}
		rels = append(rels, r)
	}
	defRels := make([]DefRel, 0, 37)
	for i := range 37 {
		dr, err := b.AddDefRel("defrel" + strconv.Itoa(i))
		if err != nil {
			tb.Fatalf("AddDefRel: %v", err)
		}
		defRels = append(defRels, dr)
	}

	for range nEdges {
		if err := b.AddEdge(TTP(rng.IntN(nTTP)), Artifact(rng.IntN(nArt)), rels[rng.IntN(len(rels))]); err != nil {
			tb.Fatalf("AddEdge: %v", err)
		}
	}
	for range nEdges / 4 {
		if err := b.AddDefEdge(Countermeasure(rng.IntN(nCM)), Artifact(rng.IntN(nArt)), defRels[rng.IntN(len(defRels))]); err != nil {
			tb.Fatalf("AddDefEdge: %v", err)
		}
	}
	for range nEdges / 2 {
		if err := b.AddDefendsEdge(Countermeasure(rng.IntN(nCM)), TTP(rng.IntN(nTTP))); err != nil {
			tb.Fatalf("AddDefendsEdge: %v", err)
		}
	}

	e, err := b.Build()
	if err != nil {
		tb.Fatalf("Build: %v", err)
	}
	return e
}

func benchEngine(tb testing.TB) *Engine {
	tb.Helper()
	e := generatedEngine(tb, 1200, 250, 160, 700)
	if got := e.WordsPerRow(KindTTP); got != 19 {
		tb.Fatalf("WordsPerRow(TTP) = %d, want 19", got)
	}
	if got := e.WordsPerRow(KindArtifact); got != 4 {
		tb.Fatalf("WordsPerRow(Artifact) = %d, want 4", got)
	}
	if got := e.WordsPerRow(KindCountermeasure); got != 3 {
		tb.Fatalf("WordsPerRow(Countermeasure) = %d, want 3", got)
	}
	return e
}

func BenchmarkAdjacentRel(b *testing.B) {
	e := benchEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		if e.AdjacentRel(TTP(i%1200), Artifact(i%250), Rel(1+i%40)) {
			sink++
		}
	}
}

func BenchmarkArtifacts(b *testing.B) {
	e := benchEngine(b)
	dst := make([]Artifact, e.ArtifactCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.Artifacts(TTP(i%1200), dst)
	}
}

func BenchmarkTTPsRel(b *testing.B) {
	e := benchEngine(b)
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.TTPsRel(Artifact(i%250), Rel(1+i%40), dst)
	}
}

func BenchmarkArtifactsRollup(b *testing.B) {
	e := benchEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindArtifact))
	dst := make([]Artifact, e.ArtifactCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.ArtifactsRollup(TTP(i%1200), scratch, dst)
	}
}

func BenchmarkTTPsRollup(b *testing.B) {
	e := benchEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.TTPsRollup(Artifact(i%250), scratch, dst)
	}
}

func BenchmarkTTPsAnyProcessFile(b *testing.B) {
	e := benchEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]TTP, e.TTPCount())
	arts := []Artifact{1, 2}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.TTPsAny(RelAny, scratch, dst, arts)
	}
}

func BenchmarkCountermeasuresForArtifactViaTTPs(b *testing.B) {
	e := benchEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindCountermeasure))
	dst := make([]Countermeasure, e.CountermeasureCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.CountermeasuresForArtifactViaTTPs(Artifact(i%250), scratch, dst)
	}
}

func BenchmarkCountermeasuresForTTPRollup(b *testing.B) {
	e := benchEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindCountermeasure))
	dst := make([]Countermeasure, e.CountermeasureCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.CountermeasuresForTTPRollup(TTP(i%1200), scratch, dst)
	}
}

// BenchmarkTTPsCovered is the union of the selected countermeasure rows over
// the widest overlay surface the fixture offers: every row of the block is
// examined, 20 of the 160 are ORed in.
func BenchmarkTTPsCovered(b *testing.B) {
	e := benchEngine(b)
	sel := make([]uint64, e.WordsPerRow(KindCountermeasure))
	for i := range 20 {
		setBit(sel, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.TTPsCovered(sel, scratch, dst)
	}
}

// BenchmarkTTPsBlind is the blind-spot difference: a fully active technique
// selection minus the same 20-countermeasure deployment.
func BenchmarkTTPsBlind(b *testing.B) {
	e := benchEngine(b)
	sel := make([]uint64, e.WordsPerRow(KindCountermeasure))
	active := make([]uint64, e.WordsPerRow(KindTTP))
	for i := range 20 {
		setBit(sel, i)
	}
	for i := range e.TTPCount() {
		setBit(active, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.TTPsBlind(active, sel, scratch, dst)
	}
}

// BenchmarkCoverageGain is the marginal-gain probe a procurement ranking runs
// per candidate: one selected-row union plus a masked popcount.
func BenchmarkCoverageGain(b *testing.B) {
	e := benchEngine(b)
	sel := make([]uint64, e.WordsPerRow(KindCountermeasure))
	for i := range 20 {
		setBit(sel, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.CoverageGain(Countermeasure(0), sel, scratch)
	}
}

// BenchmarkCoverageGains is the whole ranking: one selected-row union plus a
// masked popcount per countermeasure, i.e. the scan `gain` runs once instead of
// one CoverageGain call per candidate.
func BenchmarkCoverageGains(b *testing.B) {
	e := benchEngine(b)
	sel := make([]uint64, e.WordsPerRow(KindCountermeasure))
	for i := range 20 {
		setBit(sel, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]int, e.CountermeasureCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.CoverageGains(sel, scratch, dst)
	}
}

// BenchmarkCountermeasuresForObserved is the containment query: the union of
// the transposed rows of a 50-technique observed set.
func BenchmarkCountermeasuresForObserved(b *testing.B) {
	e := benchEngine(b)
	observed := make([]uint64, e.WordsPerRow(KindTTP))
	for i := range 50 {
		setBit(observed, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindCountermeasure))
	dst := make([]Countermeasure, e.CountermeasureCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.CountermeasuresForObserved(observed, scratch, dst)
	}
}

// BenchmarkTTPsMapped is the mapping range every coverage state is measured
// against: the union of all 160 countermeasure rows, computed per call. There is
// no input selection, so the cost is the whole block.
func BenchmarkTTPsMapped(b *testing.B) {
	e := benchEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.TTPsMapped(scratch, dst)
	}
}

// kevEngine is a standalone KEV fixture, kept separate from the ATT&CK
// fixtures so their stride contracts stay untouched. It registers fixKEV
// entries, fixCWE weaknesses and fixProduct products with fixKEVEdges distinct
// weakness edges and one product edge per entry: a fixture sized to exercise
// the 28/3/12-word rows, not a copy of any catalog release, so a re-pin never
// edits this file.
// fixKEVEdges is the fixture's own weakness-edge count: enough distinct pairs
// to populate the rows without pinning a catalog release's shape.
const fixKEVEdges = 1689

func kevEngine(tb testing.TB) *Engine {
	tb.Helper()
	b := NewBuilder()
	rng := rand.New(rand.NewPCG(0xfeed_face, 0xdead_beef))

	for i := range fixCWE {
		id := "CWE-" + strconv.Itoa(i)
		if _, err := b.AddCWE(id, id); err != nil {
			tb.Fatalf("AddCWE: %v", err)
		}
	}
	for i := range fixProduct {
		if _, err := b.AddProduct("Vendor"+strconv.Itoa(i%97), "Product "+strconv.Itoa(i)); err != nil {
			tb.Fatalf("AddProduct: %v", err)
		}
	}
	for i := range fixKEV {
		id := "CVE-2000-" + strconv.Itoa(10000+i)
		if _, err := b.AddKEV(id, "Entry "+strconv.Itoa(i), "2000-01-01", i%5 == 0); err != nil {
			tb.Fatalf("AddKEV: %v", err)
		}
	}
	// The fixKEVEdges weakness references are distinct pairs: a draw that
	// repeats one would leave the matrix short of the shape this fixture
	// documents, silently changing what the KEV row widths cost.
	seen := make(map[[2]uint16]struct{}, fixKEVEdges)
	for len(seen) < fixKEVEdges {
		k, c := uint16(rng.IntN(fixKEV)), uint16(rng.IntN(fixCWE))
		if _, dup := seen[[2]uint16{k, c}]; dup {
			continue
		}
		seen[[2]uint16{k, c}] = struct{}{}
		if err := b.AddKEVWeaknessEdge(KEV(k), CWE(c)); err != nil {
			tb.Fatalf("AddKEVWeaknessEdge: %v", err)
		}
	}
	for i := range fixKEV {
		if err := b.AddKEVProductEdge(KEV(i), Product(rng.IntN(fixProduct))); err != nil {
			tb.Fatalf("AddKEVProductEdge: %v", err)
		}
	}

	e, err := b.Build()
	if err != nil {
		tb.Fatalf("Build: %v", err)
	}
	if got := e.WordsPerRow(KindKEV); got != 28 {
		tb.Fatalf("WordsPerRow(KEV) = %d, want 28", got)
	}
	if got := e.WordsPerRow(KindCWE); got != 3 {
		tb.Fatalf("WordsPerRow(CWE) = %d, want 3", got)
	}
	if got := e.WordsPerRow(KindProduct); got != 12 {
		tb.Fatalf("WordsPerRow(Product) = %d, want 12", got)
	}
	edges := 0
	for i := range fixKEV {
		edges += e.KEVCWEDegree(KEV(i))
	}
	if edges != fixKEVEdges {
		tb.Fatalf("the fixture's KEVCWEDegree sums to %d, want its own %d edges", edges, fixKEVEdges)
	}
	return e
}

// BenchmarkKEVsForProducts is the asset-inventory query: the union of 50 of the
// ProductCount productKEV rows, one kevCWE row per entry named.
func BenchmarkKEVsForProducts(b *testing.B) {
	e := kevEngine(b)
	sel := make([]uint64, e.WordsPerRow(KindProduct))
	for i := range 50 {
		setBit(sel, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindKEV))
	dst := make([]KEV, e.KEVCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.KEVsForProducts(sel, scratch, dst)
	}
}

// BenchmarkKEVsForCWEs is the weakness-class query over the whole vocabulary:
// the union of every cweKEV row.
func BenchmarkKEVsForCWEs(b *testing.B) {
	e := kevEngine(b)
	sel := make([]uint64, e.WordsPerRow(KindCWE))
	for i := range e.CWECount() {
		setBit(sel, i)
	}
	scratch := make([]uint64, e.WordsPerRow(KindKEV))
	dst := make([]KEV, e.KEVCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.KEVsForCWEs(sel, scratch, dst)
	}
}

// BenchmarkCWEsForKEV is the single-entry read: one 3-word kevCWE row.
func BenchmarkCWEsForKEV(b *testing.B) {
	e := kevEngine(b)
	dst := make([]CWE, e.CWECount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.CWEsForKEV(KEV(i%fixKEV), dst)
	}
}

// BenchmarkKEVCWEDegree is the degree of one entry: a popcount over its 3-word
// kevCWE row, with no destination to write.
func BenchmarkKEVCWEDegree(b *testing.B) {
	e := kevEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.KEVCWEDegree(KEV(i % fixKEV))
	}
}

// BenchmarkKEVsForCWE is the single-class read: the entries of one weakness,
// i.e. one 28-word cweKEV row enumerated. It is the sibling of CWEsForKEV.
func BenchmarkKEVsForCWE(b *testing.B) {
	e := kevEngine(b)
	dst := make([]KEV, e.KEVCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.KEVsForCWE(CWE(i%fixCWE), dst)
	}
}

// BenchmarkProductsForKEV is the product read of one entry: one 12-word
// kevProduct row enumerated.
func BenchmarkProductsForKEV(b *testing.B) {
	e := kevEngine(b)
	dst := make([]Product, e.ProductCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.ProductsForKEV(KEV(i%fixKEV), dst)
	}
}

// attributedEngine is a standalone attributed fixture, kept separate from
// generatedEngine so that fixture's stride contract (and therefore every
// existing benchmark) stays untouched. It registers 1200 techniques with the
// same i%10 parent rule, 41 tactics, 15 platforms, 212 tactic edges, 212
// platform edges, 1212 grouping nodes and 18885 group-uses edges — and no
// artifacts, countermeasures, relations, offensive/defensive/defends edges or
// data components, so DataComponentCount() is 0 here: a benchmark for a
// data-component traversal needs a fixture that registers some.
// The tactic row holds 212 techniques, the widest row of the pinned release.
func attributedEngine(tb testing.TB) *Engine {
	tb.Helper()
	b := NewBuilder()
	rng := rand.New(rand.NewPCG(0x1234_5678, 0x9abc_def0))

	for i := range 1200 {
		parent := NoParent
		if k := i % 10; k != 0 {
			parent = TTP(i - k)
		}
		id := "T" + strconv.Itoa(i)
		if _, err := b.AddTTP(id, "Technique "+id, DomainEnterprise, parent, false); err != nil {
			tb.Fatalf("AddTTP: %v", err)
		}
	}
	var tactics []Tactic
	for i := range 41 {
		ta, err := b.AddTactic("TA"+strconv.Itoa(1000+i), "Tactic "+strconv.Itoa(i))
		if err != nil {
			tb.Fatalf("AddTactic: %v", err)
		}
		tactics = append(tactics, ta)
	}
	for i := range 15 {
		if _, err := b.AddPlatform("P" + strconv.Itoa(i)); err != nil {
			tb.Fatalf("AddPlatform: %v", err)
		}
	}
	var groups []Group
	for i := range 1212 {
		kind := GroupActor
		id := "G" + strconv.Itoa(i)
		if i%3 == 1 {
			kind, id = GroupSoftware, "S"+strconv.Itoa(i)
		} else if i%3 == 2 {
			kind, id = GroupCampaign, "C"+strconv.Itoa(i)
		}
		g, err := b.AddGroup(id, "Group "+id, kind, false)
		if err != nil {
			tb.Fatalf("AddGroup: %v", err)
		}
		groups = append(groups, g)
	}
	for i := range 212 {
		if err := b.AddTacticEdge(TTP(i), tactics[0]); err != nil {
			tb.Fatalf("AddTacticEdge: %v", err)
		}
		if err := b.AddPlatformEdge(TTP(i), Platform(0)); err != nil {
			tb.Fatalf("AddPlatformEdge: %v", err)
		}
	}
	for range 18885 {
		if err := b.AddGroupUsesEdge(groups[rng.IntN(len(groups))], TTP(rng.IntN(1200))); err != nil {
			tb.Fatalf("AddGroupUsesEdge: %v", err)
		}
	}

	e, err := b.Build()
	if err != nil {
		tb.Fatalf("Build: %v", err)
	}
	return e
}

// BenchmarkTTPTactics is the attribute-mask read: one load, no traversal.
func BenchmarkTTPTactics(b *testing.B) {
	e := attributedEngine(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += int(e.TTPTactics(TTP(i % 212)))
	}
}

// BenchmarkTTPsForTactic is the widest attribute row of the pinned release: the
// 212-technique row of Tactic 0.
func BenchmarkTTPsForTactic(b *testing.B) {
	e := attributedEngine(b)
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		sink += e.TTPsForTactic(Tactic(0), dst)
	}
}

// BenchmarkTTPsForGroupRollup is the grouping roll-up: a group row scan with the
// parent substitution of every sub-technique.
func BenchmarkTTPsForGroupRollup(b *testing.B) {
	e := attributedEngine(b)
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	dst := make([]TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for i := range b.N {
		sink += e.TTPsForGroupRollup(Group(i%1212), scratch, dst)
	}
}
