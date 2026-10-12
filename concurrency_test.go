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
		len(want.observed) == 0 {
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
		equalIDs(r.artifactsRel, o.artifactsRel) &&
		equalIDs(r.ttpsRel, o.ttpsRel) &&
		equalIDs(r.ttpsAny, o.ttpsAny) &&
		equalIDs(r.ttpsAll, o.ttpsAll) &&
		equalIDs(r.artRollup, o.artRollup) &&
		equalIDs(r.ttpRollup, o.ttpRollup) &&
		equalIDs(r.ttpForCM, o.ttpForCM) &&
		equalIDs(r.children, o.children) &&
		equalIDs(r.cmTTPRollup, o.cmTTPRollup) &&
		equalIDs(r.cmViaTTPs, o.cmViaTTPs) &&
		equalIDs(r.cmForTTP, o.cmForTTP) &&
		equalIDs(r.mapped, o.mapped) &&
		equalIDs(r.covered, o.covered) &&
		equalIDs(r.blind, o.blind) &&
		equalIDs(r.observed, o.observed) &&
		r.gain == o.gain &&
		equalIDs(r.ttpForTactic, o.ttpForTactic) &&
		equalIDs(r.ttpForPlatform, o.ttpForPlatform) &&
		equalIDs(r.ttpForDC, o.ttpForDC) &&
		equalIDs(r.grpRollup, o.grpRollup) &&
		equalIDs(r.dcsExact, o.dcsExact) &&
		equalIDs(r.dcsRollup, o.dcsRollup) &&
		equalIDs(r.groupsForTTP, o.groupsForTTP) &&
		equalIDs(r.softwareForGroup, o.softwareForGroup) &&
		equalIDs(r.groupsForSoftware, o.groupsForSoftware) &&
		r.tacticMask == o.tacticMask &&
		r.platformMask == o.platformMask &&
		r.subTechnique == o.subTechnique &&
		slices.Equal(r.response, o.response)
}

// equalIDs compares two id slices element-wise. The root package has no such
// helper (equalRows in kernel_test.go compares []uint64 rows).
func equalIDs[T ~uint16](a, b []T) bool {
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
