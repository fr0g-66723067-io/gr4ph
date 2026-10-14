//go:build goexperiment.simd

package gr4ph

import (
	"slices"
	"sync"
	"testing"
)

// TestConcurrentQueries checks the documented concurrency contract: an Engine
// built once may be queried by any number of goroutines as long as each owns its
// dst and scratch. Every goroutine's results are compared against a
// single-threaded reference, so a shared-state bug shows up as a wrong value as
// well as (under -race) a reported race. `make test` runs the suite with -race.
func TestConcurrentQueries(t *testing.T) {
	e := buildSynthetic(t)

	// run executes the whole query set into buffers it allocates itself, so
	// concurrent callers share nothing but the engine.
	run := func() results {
		ttps := make([]TTP, e.TTPCount())
		rolled := make([]TTP, e.TTPCount())
		arts := make([]Artifact, e.ArtifactCount())
		cms := make([]Countermeasure, e.CountermeasureCount())
		scratchT := make([]uint64, e.WordsPerRow(KindTTP))
		scratchA := make([]uint64, e.WordsPerRow(KindArtifact))
		scratchC := make([]uint64, e.WordsPerRow(KindCountermeasure))
		scratchD := make([]uint64, e.WordsPerRow(KindDataComponent))
		dcs := make([]DataComponent, e.DataComponentCount())
		groups := make([]Group, e.GroupCount())
		strs := make([]string, e.TTPCount())
		// The overlay selections: every live countermeasure bit on one side, and
		// every live technique bit on the other, so the blind set below is not
		// empty (the non-vacuity guard requires a non-empty result).
		selC := make([]uint64, e.WordsPerRow(KindCountermeasure))
		selT := make([]uint64, e.WordsPerRow(KindTTP))
		for i := range e.CountermeasureCount() {
			setBit(selC, i)
		}
		for i := range e.TTPCount() {
			setBit(selT, i)
		}
		// The KEV selections: one weakness (all of a weakness class's entries)
		// and one product.
		bufK := make([]KEV, e.KEVCount())
		bufCWE := make([]CWE, e.CWECount())
		bufP := make([]Product, e.ProductCount())
		scrK := make([]uint64, e.WordsPerRow(KindKEV))
		selKEV := make([]uint64, e.WordsPerRow(KindCWE))
		setBit(selKEV, 1)
		selProd := make([]uint64, e.WordsPerRow(KindProduct))
		setBit(selProd, 0)

		var r results
		r.adjacent = e.AdjacentRel(TTP(0), Artifact(0), RelAny)
		r.degree = e.Degree(TTP(1), RelAny)
		r.artifactDegree = e.ArtifactDegree(Artifact(1), RelAny)
		r.cmDegree = e.CountermeasureDegree(Countermeasure(0))
		r.defends = e.Defends(Countermeasure(0), TTP(0))

		r.artifactsRel = append(r.artifactsRel, arts[:e.ArtifactsRel(TTP(1), RelAny, arts)]...)
		r.ttpsRel = append(r.ttpsRel, ttps[:e.TTPsRel(Artifact(0), RelAny, ttps)]...)
		r.ttpsAny = append(r.ttpsAny, ttps[:e.TTPsAny(RelAny, scratchT, ttps, []Artifact{0, 1})]...)
		r.ttpsAll = append(r.ttpsAll, ttps[:e.TTPsAll(RelAny, scratchT, ttps, []Artifact{0, 1})]...)
		r.artRollup = append(r.artRollup, arts[:e.ArtifactsRollup(TTP(0), scratchA, arts)]...)
		r.ttpRollup = append(r.ttpRollup, ttps[:e.TTPsRollup(Artifact(0), scratchT, ttps)]...)
		r.cmTTPRollup = append(r.cmTTPRollup, cms[:e.CountermeasuresForTTPRollup(TTP(0), scratchC, cms)]...)
		r.cmViaTTPs = append(r.cmViaTTPs, cms[:e.CountermeasuresForArtifactViaTTPs(Artifact(0), scratchC, cms)]...)
		r.cmForTTP = append(r.cmForTTP, cms[:e.CountermeasuresForTTP(TTP(1), cms)]...)
		r.mapped = append(r.mapped, ttps[:e.TTPsMapped(scratchT, ttps)]...)
		r.covered = append(r.covered, ttps[:e.TTPsCovered(selC, scratchT, ttps)]...)
		r.blind = append(r.blind, ttps[:e.TTPsBlind(selT, selC, scratchT, ttps)]...)
		r.gain = e.CoverageGain(Countermeasure(0), selC, scratchT)
		r.observed = append(r.observed, cms[:e.CountermeasuresForObserved(selT, scratchC, cms)]...)
		r.kevDegree = e.KEVCWEDegree(KEV(0))
		r.cweEntries = append(r.cweEntries, bufCWE[:e.CWEsForKEV(KEV(0), bufCWE)]...)
		r.kevEntries = append(r.kevEntries, bufK[:e.KEVsForCWE(CWE(1), bufK)]...)
		r.productEntries = append(r.productEntries, bufP[:e.ProductsForKEV(KEV(0), bufP)]...)
		r.kevEntries = append(r.kevEntries, bufK[:e.KEVsForProducts(selProd, scrK, bufK)]...)
		r.kevEntries = append(r.kevEntries, bufK[:e.KEVsForCWEs(selKEV, scrK, bufK)]...)
		r.ttpForCM = append(r.ttpForCM, rolled[:e.TTPsForCountermeasureRollup(Countermeasure(0), scratchT, rolled)]...)
		r.children = append(r.children, ttps[:e.TTPChildren(TTP(0), ttps)]...)
		r.tacticMask = e.TTPTactics(TTP(0))
		r.platformMask = e.TTPPlatforms(TTP(0))
		r.subTechnique = e.TTPSubTechnique(TTP(1))
		r.ttpForTactic = append(r.ttpForTactic, ttps[:e.TTPsForTactic(Tactic(0), ttps)]...)
		r.ttpForPlatform = append(r.ttpForPlatform, ttps[:e.TTPsForPlatform(Platform(0), ttps)]...)
		r.ttpForDC = append(r.ttpForDC, ttps[:e.TTPsForDataComponent(DataComponent(0), ttps)]...)
		r.dcsExact = append(r.dcsExact, dcs[:e.DataComponentsForTTP(TTP(1), dcs)]...)
		r.dcsRollup = append(r.dcsRollup, dcs[:e.DataComponentsForTTPRollup(TTP(0), scratchD, dcs)]...)
		r.grpRollup = append(r.grpRollup, ttps[:e.TTPsForGroupRollup(Group(0), scratchT, ttps)]...)
		r.groupsForTTP = append(r.groupsForTTP, groups[:e.GroupsForTTP(TTP(0), groups)]...)
		r.softwareForGroup = append(r.softwareForGroup, groups[:e.SoftwareForGroup(Group(0), groups)]...)
		r.groupsForSoftware = append(r.groupsForSoftware, groups[:e.GroupsForSoftware(Group(1), groups)]...)
		r.response = append(r.response, strs[:e.Response(strs, []TTP{0, 1, 5})]...)
		return r
	}

	want := run()
	// A vacuous check (every query empty) would pass without touching the
	// matrices; these fields are non-empty on the synthetic engine. (ttpsAll is
	// legitimately empty: artifacts 0 and 1 share no technique.)
	if len(want.artifactsRel) == 0 || len(want.children) == 0 || len(want.ttpsAny) == 0 ||
		len(want.cmViaTTPs) == 0 || len(want.response) == 0 || len(want.cmTTPRollup) == 0 ||
		len(want.dcsExact) == 0 || len(want.dcsRollup) == 0 || len(want.ttpForTactic) == 0 ||
		len(want.ttpForPlatform) == 0 || len(want.ttpForDC) == 0 ||
		len(want.groupsForTTP) == 0 || len(want.softwareForGroup) == 0 ||
		len(want.grpRollup) == 0 || len(want.groupsForSoftware) == 0 ||
		len(want.mapped) == 0 || len(want.covered) == 0 || len(want.blind) == 0 ||
		len(want.observed) == 0 || len(want.kevEntries) == 0 || len(want.cweEntries) == 0 ||
		len(want.productEntries) == 0 {
		t.Fatalf("query set produced empty results, so the comparison is vacuous: %+v", want)
	}
	const goroutines, iterations = 8, 200

	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if got := run(); !got.equal(want) {
					// t.Errorf is goroutine-safe; t.Fatal is not.
					t.Errorf("goroutine %d, iteration %d: results differ from the single-threaded reference", g, i)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}

// results is one full pass of the query set above.
type results struct {
	adjacent, defends, subTechnique  bool
	degree, artifactDegree, cmDegree int
	gain                             int
	tacticMask, platformMask         uint64
	artifactsRel                     []Artifact
	ttpsRel, ttpsAny, ttpsAll        []TTP
	artRollup                        []Artifact
	ttpRollup, ttpForCM, children    []TTP
	ttpForTactic, grpRollup          []TTP
	ttpForPlatform, ttpForDC         []TTP
	cmTTPRollup, cmViaTTPs, cmForTTP []Countermeasure
	mapped, covered, blind           []TTP
	observed                         []Countermeasure
	kevDegree                        int
	kevEntries                       []KEV
	cweEntries                       []CWE
	productEntries                   []Product
	dcsExact, dcsRollup              []DataComponent
	groupsForTTP, softwareForGroup   []Group
	groupsForSoftware                []Group
	response                         []string
}

// equal reports whether two passes agree in every field.
func (r results) equal(o results) bool {
	return r.adjacent == o.adjacent &&
		r.defends == o.defends &&
		r.degree == o.degree &&
		r.artifactDegree == o.artifactDegree &&
		r.cmDegree == o.cmDegree &&
		slices.Equal(r.artifactsRel, o.artifactsRel) &&
		slices.Equal(r.ttpsRel, o.ttpsRel) &&
		slices.Equal(r.ttpsAny, o.ttpsAny) &&
		slices.Equal(r.ttpsAll, o.ttpsAll) &&
		slices.Equal(r.artRollup, o.artRollup) &&
		slices.Equal(r.ttpRollup, o.ttpRollup) &&
		slices.Equal(r.ttpForCM, o.ttpForCM) &&
		slices.Equal(r.children, o.children) &&
		slices.Equal(r.cmTTPRollup, o.cmTTPRollup) &&
		slices.Equal(r.cmViaTTPs, o.cmViaTTPs) &&
		slices.Equal(r.cmForTTP, o.cmForTTP) &&
		slices.Equal(r.mapped, o.mapped) &&
		slices.Equal(r.covered, o.covered) &&
		slices.Equal(r.blind, o.blind) &&
		slices.Equal(r.observed, o.observed) &&
		slices.Equal(r.kevEntries, o.kevEntries) &&
		slices.Equal(r.cweEntries, o.cweEntries) &&
		slices.Equal(r.productEntries, o.productEntries) &&
		r.kevDegree == o.kevDegree &&
		r.gain == o.gain &&
		slices.Equal(r.ttpForTactic, o.ttpForTactic) &&
		slices.Equal(r.ttpForPlatform, o.ttpForPlatform) &&
		slices.Equal(r.ttpForDC, o.ttpForDC) &&
		slices.Equal(r.grpRollup, o.grpRollup) &&
		slices.Equal(r.dcsExact, o.dcsExact) &&
		slices.Equal(r.dcsRollup, o.dcsRollup) &&
		slices.Equal(r.groupsForTTP, o.groupsForTTP) &&
		slices.Equal(r.softwareForGroup, o.softwareForGroup) &&
		slices.Equal(r.groupsForSoftware, o.groupsForSoftware) &&
		r.tacticMask == o.tacticMask &&
		r.platformMask == o.platformMask &&
		r.subTechnique == o.subTechnique &&
		slices.Equal(r.response, o.response)
}
