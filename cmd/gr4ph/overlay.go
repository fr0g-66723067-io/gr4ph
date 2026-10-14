//go:build goexperiment.simd

package main

import (
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/fr0g-66723067-io/gr4ph"
)

// runCoverage answers `coverage <cm>...`: the resolved countermeasures are the
// deployed set, and every technique is classified as defended (covered by the
// deployment), undefended (inside the D3FEND mapping but uncovered) or unmapped
// (outside the mapping, so no countermeasure can cover it). One result per
// invocation, not per query: the three sets describe the deployment as a whole.
func runCoverage(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	// No query is a valid invocation here: the empty deployment is a real
	// question ("what does nothing cover?"), and its answer is the state of an
	// organisation that has bought no countermeasure yet.
	buf := newBuffers(e)
	failures := make([]string, 0)
	deployed := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	seen := make(map[gr4ph.Countermeasure]bool)
	for _, q := range queries {
		cm, ok := e.Countermeasure(q)
		if !ok {
			failures = append(failures, "gr4ph: no such countermeasure: "+q)
			continue
		}
		if seen[cm] {
			continue
		}
		seen[cm] = true
		setBit(deployed, int(cm))
	}

	// The three states, each computed by one overlay query. The mapped range
	// doubles as the active set of the undefended set, so no state is derived
	// from another state's output.
	defendedN := e.TTPsCovered(deployed, buf.scrT, buf.ttps)
	defendedLive, retiredDefended := splitRetired(e, buf.ttps, defendedN)
	defended := set{Dir: "in", Name: "defended", Count: len(defendedLive), Nodes: ttpNodes(e, defendedLive, len(defendedLive))}
	mappedN := e.TTPsMapped(buf.scrT, buf.ttps)
	mapped := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	for _, t := range buf.ttps[:mappedN] {
		setBit(mapped, int(t))
	}
	undefendedN := e.TTPsBlind(mapped, deployed, buf.scrT, buf.ttps)
	undefendedLive, retiredUndefended := splitRetired(e, buf.ttps, undefendedN)
	undefended := set{Dir: "in", Name: "undefended", Count: len(undefendedLive), Nodes: ttpNodes(e, undefendedLive, len(undefendedLive))}
	allTTP, allCM := allSelections(e)
	unmappedN := e.TTPsBlind(allTTP, allCM, buf.scrT, buf.ttps)
	unmappedLive, retiredUnmapped := splitRetired(e, buf.ttps, unmappedN)
	unmapped := set{Dir: "in", Name: "unmapped", Count: len(unmappedLive), Nodes: ttpNodes(e, unmappedLive, len(unmappedLive))}

	// The retired state: every flagged technique, wherever it sat. The three
	// sets above are disjoint and cover the whole partition, so this union is
	// too, and it is sorted because the three parts are.
	retiredIDs := slices.Concat(retiredDefended, retiredUndefended, retiredUnmapped)
	slices.Sort(retiredIDs)
	retired := set{Dir: "in", Name: "retired", Count: len(retiredIDs), Nodes: ttpNodes(e, retiredIDs, len(retiredIDs))}

	res := result{
		Query:    strings.Join(queries, " "),
		Kind:     "coverage",
		Deployed: new(len(seen)),
		Mapped:   new(mappedN),
		Retired:  new(len(retiredIDs)),
		// The order is the classification's: what is defended, what is not, what
		// is retired, and what D3FEND never mapped.
		Sets: []set{defended, undefended, retired, unmapped},
	}
	return finish(stdout, stderr, []result{res}, failures, *jsonOut)
}

// splitRetired partitions a result set into its live and retired members, in
// that order and keeping the ascending id order of the input: a flagged
// technique is not a purchase target, so coverage reports it as its own state
// instead of mixing it into the set a deployment would act on.
func splitRetired(e *gr4ph.Engine, ids []gr4ph.TTP, n int) (live, retired []gr4ph.TTP) {
	for _, t := range ids[:n] {
		if e.TTPRevoked(t) {
			retired = append(retired, t)
			continue
		}
		live = append(live, t)
	}
	return live, retired
}

// runGain answers `gain <cm>...`: the resolved countermeasures are the deployed
// set, and every candidate is ranked by the techniques it would newly cover on
// top of it. -greedy replaces the ranking with the successive maximum-gain
// sequence, which is the order a procurement plan would buy in.
func runGain(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	top := fs.Int("top", 10, "")
	all := fs.Bool("all", false, "")
	greedy := fs.Bool("greedy", false, "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	// -top carries a default, so only an explicitly set one conflicts with
	// -greedy (fs.Visit reports the flags the caller actually passed).
	explicit := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if *greedy && (explicit["top"] || *all) {
		fmt.Fprintln(stderr, "gr4ph: -greedy cannot be combined with -top or -all")
		return 2
	}
	if *top < 0 {
		fmt.Fprintln(stderr, "gr4ph: -top must not be negative")
		return 2
	}
	// No query is a valid invocation here either: ranking every countermeasure
	// against an empty deployment is the "what should we buy first?" question.

	buf := newBuffers(e)
	failures := make([]string, 0)
	deployed := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	seen := make(map[gr4ph.Countermeasure]bool)
	for _, q := range queries {
		cm, ok := e.Countermeasure(q)
		if !ok {
			failures = append(failures, "gr4ph: no such countermeasure: "+q)
			continue
		}
		if seen[cm] {
			continue
		}
		seen[cm] = true
		setBit(deployed, int(cm))
	}

	res := result{
		Query:    strings.Join(queries, " "),
		Kind:     "gain",
		Deployed: new(len(seen)),
	}
	if *greedy {
		var rounds int
		res.Gains, rounds = greedyGain(e, deployed, buf.scrT)
		res.Greedy = &rounds
		return finish(stdout, stderr, []result{res}, failures, *jsonOut)
	}

	// One union for the whole scan: the covered set of the deployment is the
	// same for every candidate, so ranking walks the gains table instead of
	// re-deriving the union 157 times.
	candidates := make([]gain, 0, e.CountermeasureCount())
	n := e.CoverageGains(deployed, buf.scrT, buf.gains)
	for cm := range e.CountermeasureCount() {
		g := buf.gains[cm]
		if g <= 0 {
			continue
		}
		name := e.CountermeasureName(gr4ph.Countermeasure(cm))
		candidates = append(candidates, gain{
			ID:    cm,
			Name:  name,
			Label: collapseLabel(name, e.CountermeasureLabel(gr4ph.Countermeasure(cm))),
			Gain:  g,
		})
	}
	// A total order: gain descending, then the byte-smallest countermeasure
	// name, then the byte-smallest id, so the output is deterministic whatever
	// the dense ids are. The name keys are unique, so the second key alone is
	// already total; the id keeps it total even if a table repeats a name.
	slices.SortFunc(candidates, func(a, b gain) int {
		if a.Gain != b.Gain {
			return b.Gain - a.Gain
		}
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return a.ID - b.ID
	})
	shown := candidates
	if !*all && *top < len(shown) {
		shown = shown[:*top]
	}
	res.Candidates = new(n)
	res.Gains = shown
	return finish(stdout, stderr, []result{res}, failures, *jsonOut)
}

// greedyGain is the successive maximum-gain sequence over the accumulated
// selection: each round buys the candidate that covers the most still-uncovered
// techniques, ties broken by the byte-smallest countermeasure name and then by
// the byte-smallest id (the ascending scan keeps the first of a repeated name),
// and the walk stops as soon as no candidate gains anything. It returns the
// rows and the number of rounds. Policy lives here, not in the engine, so the
// engine keeps only the primitive.
func greedyGain(e *gr4ph.Engine, deployed []uint64, scratch []uint64) ([]gain, int) {
	sel := make([]uint64, len(deployed))
	copy(sel, deployed)
	gains := make([]int, e.CountermeasureCount())
	var rows []gain
	for {
		// One union per round, not one per candidate: every candidate is
		// ranked against the same accumulated selection.
		e.CoverageGains(sel, scratch, gains)
		best := -1
		bestGain := 0
		bestName := ""
		for cm := range e.CountermeasureCount() {
			g := gains[cm]
			if g <= 0 {
				continue
			}
			name := e.CountermeasureName(gr4ph.Countermeasure(cm))
			if g > bestGain || (g == bestGain && strings.Compare(name, bestName) < 0) {
				best, bestGain, bestName = cm, g, name
			}
		}
		if best < 0 {
			return rows, len(rows)
		}
		cm := gr4ph.Countermeasure(best)
		rows = append(rows, gain{
			ID:    best,
			Name:  bestName,
			Label: collapseLabel(bestName, e.CountermeasureLabel(cm)),
			Gain:  bestGain,
		})
		setBit(sel, best)
	}
}

// runContain answers `contain <ttp>...`: the resolved techniques are the observed
// set, and the answer is every countermeasure that touches any of them — the
// mitigation set for the current state of an intrusion.
func runContain(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("contain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if !requireQueries(stderr, queries) {
		return 2
	}

	buf := newBuffers(e)
	failures := make([]string, 0)
	observed := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	seen := make(map[gr4ph.TTP]bool)
	for _, q := range queries {
		t, ok := e.Incident(q)
		if !ok {
			failures = append(failures, "gr4ph: no such technique: "+q)
			continue
		}
		if seen[t] {
			continue
		}
		seen[t] = true
		setBit(observed, int(t))
	}

	n := e.CountermeasuresForObserved(observed, buf.scrC, buf.cms)
	res := result{
		Query:    strings.Join(queries, " "),
		Kind:     "contain",
		Observed: new(len(seen)),
		Sets: []set{
			{Dir: "out", Name: "countermeasures", Count: n, Nodes: cmNodes(e, buf.cms, n)},
		},
	}
	return finish(stdout, stderr, []result{res}, failures, *jsonOut)
}

// setBit sets bit i of sel. The library's own helper is unexported, and the CLI
// owns its selections: the engine never retains one.
func setBit(sel []uint64, i int) { sel[i>>6] |= 1 << uint(i&63) }

// allSelections returns a selection with every live technique bit and every live
// countermeasure bit set: the active set of "everything that could be observed"
// and the deployment of "every countermeasure there is".
func allSelections(e *gr4ph.Engine) (ttps, cms []uint64) {
	ttps = make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	for i := range e.TTPCount() {
		setBit(ttps, i)
	}
	cms = make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	for i := range e.CountermeasureCount() {
		setBit(cms, i)
	}
	return ttps, cms
}

// scanOffensive counts the distinct (technique, artifact) pairs of plane r and
// the techniques that have at least one. It allocates nothing: buf is the
// caller's full-size artifact buffer.
func scanOffensive(e *gr4ph.Engine, r gr4ph.Rel, buf []gr4ph.Artifact) (edges, sources int) {
	for t := range e.TTPCount() {
		if n := e.ArtifactsRel(gr4ph.TTP(t), r, buf); n > 0 {
			edges += n
			sources++
		}
	}
	return edges, sources
}

// scanDefensive counts the distinct (countermeasure, artifact) pairs of plane
// dr and the countermeasures that have at least one.
func scanDefensive(e *gr4ph.Engine, dr gr4ph.DefRel, buf []gr4ph.Artifact) (edges, sources int) {
	for cm := range e.CountermeasureCount() {
		if n := e.ArtifactsForCountermeasure(gr4ph.Countermeasure(cm), dr, buf); n > 0 {
			edges += n
			sources++
		}
	}
	return edges, sources
}
