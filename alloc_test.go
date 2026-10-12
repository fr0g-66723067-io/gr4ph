//go:build goexperiment.simd

package gr4ph

import (
	"slices"
	"testing"

	"github.com/fr0g-66723067-io/gr4ph/internal/hotmethods"
)

// sink defeats dead-code elimination without allocating.
var sink int

// TestZeroAllocSynthetic pins the allocation contract on the hot path: every
// traversal, set operation, roll-up and countermeasure query must run without
// touching the heap. Callers own dst and scratch, so nothing is allocated
// per call.
func TestZeroAllocSynthetic(t *testing.T) {
	e := buildSynthetic(t)

	scratchT := make([]uint64, e.WordsPerRow(KindTTP))
	scratchA := make([]uint64, e.WordsPerRow(KindArtifact))
	scratchC := make([]uint64, e.WordsPerRow(KindCountermeasure))
	scratchD := make([]uint64, e.WordsPerRow(KindDataComponent))
	dstT := make([]TTP, e.TTPCount())
	dstA := make([]Artifact, e.ArtifactCount())
	dstC := make([]Countermeasure, e.CountermeasureCount())
	dstD := make([]DataComponent, e.DataComponentCount())
	dstG := make([]Group, e.GroupCount())
	arts := []Artifact{0, 1, 2, 3}
	ttps := []TTP{0, 1, 2, 3, 4, 5}
	selC := make([]uint64, e.WordsPerRow(KindCountermeasure))
	setBit(selC, 0)
	selT := make([]uint64, e.WordsPerRow(KindTTP))
	setBit(selT, 1)
	dstK := make([]KEV, e.KEVCount())
	dstCWE := make([]CWE, e.CWECount())
	dstP := make([]Product, e.ProductCount())
	scrK := make([]uint64, e.WordsPerRow(KindKEV))
	selP := make([]uint64, e.WordsPerRow(KindProduct))
	setBit(selP, 0)
	selCWE := make([]uint64, e.WordsPerRow(KindCWE))
	setBit(selCWE, 1)

	cases := []struct {
		name string
		fn   func()
	}{
		{"Adjacent", func() {
			if e.Adjacent(1, 0) {
				sink++
			}
		}},
		{"AdjacentRel", func() {
			if e.AdjacentRel(1, 0, Rel(1)) {
				sink++
			}
		}},
		{"Artifacts", func() { sink += e.Artifacts(1, dstA) }},
		{"ArtifactsRel", func() { sink += e.ArtifactsRel(1, Rel(1), dstA) }},
		{"TTPs", func() { sink += e.TTPs(0, dstT) }},
		{"TTPsRel", func() { sink += e.TTPsRel(0, Rel(2), dstT) }},
		{"Degree", func() { sink += e.Degree(1, RelAny) }},
		{"ArtifactDegree", func() { sink += e.ArtifactDegree(0, RelAny) }},
		{"ArtifactsRollup", func() { sink += e.ArtifactsRollup(0, scratchA, dstA) }},
		{"ArtifactsRollupRel", func() { sink += e.ArtifactsRollupRel(0, Rel(1), scratchA, dstA) }},
		{"TTPsRollup", func() { sink += e.TTPsRollup(1, scratchT, dstT) }},
		{"TTPsRollupRel", func() { sink += e.TTPsRollupRel(0, Rel(1), scratchT, dstT) }},
		{"TTPsAny", func() { sink += e.TTPsAny(RelAny, scratchT, dstT, arts) }},
		{"TTPsAll", func() { sink += e.TTPsAll(RelAny, scratchT, dstT, arts) }},
		{"ArtifactsAny", func() { sink += e.ArtifactsAny(RelAny, scratchA, dstA, ttps) }},
		{"ArtifactsAll", func() { sink += e.ArtifactsAll(RelAny, scratchA, dstA, ttps) }},
		{"Defends", func() {
			if e.Defends(0, 1) {
				sink++
			}
		}},
		{"CountermeasuresForTTP", func() { sink += e.CountermeasuresForTTP(1, dstC) }},
		{"CountermeasuresForTTPRollup", func() {
			sink += e.CountermeasuresForTTPRollup(0, scratchC, dstC)
		}},
		{"CountermeasuresForArtifact", func() { sink += e.CountermeasuresForArtifact(0, DefRelAny, dstC) }},
		{"CountermeasuresForArtifactViaTTPs", func() {
			sink += e.CountermeasuresForArtifactViaTTPs(0, scratchC, dstC)
		}},
		{"ArtifactsForCountermeasure", func() { sink += e.ArtifactsForCountermeasure(0, DefRelAny, dstA) }},
		{"TTPsForCountermeasure", func() { sink += e.TTPsForCountermeasure(0, dstT) }},
		{"TTPsForCountermeasureRollup", func() {
			sink += e.TTPsForCountermeasureRollup(0, scratchT, dstT)
		}},
		{"CountermeasureDegree", func() { sink += e.CountermeasureDegree(0) }},
		{"TTPsMapped", func() { sink += e.TTPsMapped(scratchT, dstT) }},
		{"TTPsCovered", func() { sink += e.TTPsCovered(selC, scratchT, dstT) }},
		{"TTPsBlind", func() { sink += e.TTPsBlind(selT, selC, scratchT, dstT) }},
		{"CoverageGain", func() { sink += e.CoverageGain(0, selC, scratchT) }},
		{"CountermeasuresForObserved", func() { sink += e.CountermeasuresForObserved(selT, scratchC, dstC) }},
		{"KEVCWEDegree", func() { sink += e.KEVCWEDegree(0) }},
		{"CWEsForKEV", func() { sink += e.CWEsForKEV(0, dstCWE) }},
		{"KEVsForCWE", func() { sink += e.KEVsForCWE(0, dstK) }},
		{"ProductsForKEV", func() { sink += e.ProductsForKEV(0, dstP) }},
		{"KEVsForProducts", func() { sink += e.KEVsForProducts(selP, scrK, dstK) }},
		{"KEVsForCWEs", func() { sink += e.KEVsForCWEs(selCWE, scrK, dstK) }},
		{"TTPTactics", func() { sink += int(e.TTPTactics(1)) }},
		{"TTPPlatforms", func() { sink += int(e.TTPPlatforms(1)) }},
		{"TTPFlags", func() { sink += int(e.TTPFlags(1)) }},
		{"TTPSubTechnique", func() {
			if e.TTPSubTechnique(1) {
				sink++
			}
		}},
		{"TTPsForTactic", func() { sink += e.TTPsForTactic(0, dstT) }},
		{"TTPsForPlatform", func() { sink += e.TTPsForPlatform(0, dstT) }},
		{"TTPsForDataComponent", func() { sink += e.TTPsForDataComponent(0, dstT) }},
		{"DataComponentsForTTP", func() { sink += e.DataComponentsForTTP(1, dstD) }},
		{"DataComponentsForTTPRollup", func() {
			sink += e.DataComponentsForTTPRollup(0, scratchD, dstD)
		}},
		{"DataComponentDegree", func() { sink += e.DataComponentDegree(0) }},
		{"TTPsForGroup", func() { sink += e.TTPsForGroup(0, dstT) }},
		{"TTPsForGroupRollup", func() { sink += e.TTPsForGroupRollup(0, scratchT, dstT) }},
		{"GroupsForTTP", func() { sink += e.GroupsForTTP(0, dstG) }},
		{"SoftwareForGroup", func() { sink += e.SoftwareForGroup(0, dstG) }},
		{"GroupsForSoftware", func() { sink += e.GroupsForSoftware(1, dstG) }},
		{"SoftwareDegree", func() { sink += e.SoftwareDegree(0) }},
		{"TTPParent", func() {
			if _, ok := e.TTPParent(1); ok {
				sink++
			}
		}},
		{"TTPChildCount", func() { sink += e.TTPChildCount(0) }},
		{"TTPChildren", func() { sink += e.TTPChildren(0, dstT) }},
		{"RelName", func() {
			if e.RelName(RelAny) != "" {
				sink++
			}
		}},
		{"DefRelName", func() {
			if e.DefRelName(DefRelAny) != "" {
				sink++
			}
		}},
	}

	names := make([]string, len(cases))
	for i, c := range cases {
		names[i] = c.name
	}
	if !slices.Equal(names, hotmethods.Names) {
		t.Fatalf("hot-method cases = %v, want %v (internal/hotmethods)", names, hotmethods.Names)
	}
	for _, c := range cases {
		if n := testing.AllocsPerRun(200, c.fn); n != 0 {
			t.Errorf("%s: %v allocs/op, want 0", c.name, n)
		}
	}
}
