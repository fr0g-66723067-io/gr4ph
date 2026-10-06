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
		if _, err := b.AddTTP(id, "Technique "+id, DomainEnterprise, parent); err != nil {
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
