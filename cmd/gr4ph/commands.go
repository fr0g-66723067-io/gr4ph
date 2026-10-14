//go:build goexperiment.simd

package main

import (
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/gr4ph"
)

// runTTP answers `ttp <query>...`.
func runTTP(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ttp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	relName := fs.String("rel", "any", "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if !requireQueries(stderr, queries) {
		return 2
	}
	r, ok := e.Rel(*relName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such offensive relation: %s\n", *relName)
		return 1
	}

	buf := newBuffers(e)
	suffix := relSuffix(r, *relName)
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		t, ok := e.Incident(q)
		if !ok {
			failures = append(failures, "gr4ph: no such technique: "+q)
			continue
		}
		name, label := e.TTPName(t), e.TTPLabel(t)
		res := result{
			Query: q, Kind: "ttp",
			ID:       new(int(t)),
			Name:     name,
			Label:    collapseLabel(name, label),
			Domain:   e.TTPDomain(t).String(),
			Children: new(e.TTPChildCount(t)),
			Revoked:  e.TTPRevoked(t),

			Tactics:      tacticIDs(e, e.TTPTactics(t)),
			Platforms:    platformNames(e, e.TTPPlatforms(t)),
			SubTechnique: e.TTPSubTechnique(t),
		}
		if p, ok := e.TTPParent(t); ok {
			res.Parent = e.TTPName(p)
		}
		n := e.ArtifactsRel(t, r, buf.arts)
		arts := set{Dir: "out", Name: "artifacts" + suffix, Count: n, Nodes: artNodes(e, buf.arts, n)}
		n = e.ArtifactsRollupRel(t, r, buf.scrA, buf.arts)
		rollupArts := set{Dir: "out", Name: "artifacts rollup" + suffix, Count: n, Nodes: artNodes(e, buf.arts, n)}
		n = e.CountermeasuresForTTP(t, buf.cms)
		cms := set{Dir: "in", Name: "countermeasures", Count: n, Nodes: cmNodes(e, buf.cms, n)}
		n = e.CountermeasuresForTTPRollup(t, buf.scrC, buf.cms)
		rollupCMs := set{Dir: "in", Name: "countermeasures rollup", Count: n, Nodes: cmNodes(e, buf.cms, n)}
		n = e.DataComponentsForTTP(t, buf.dcs)
		dcs := set{Dir: "in", Name: "data components", Count: n, Nodes: dcNodes(e, buf.dcs, n)}
		n = e.DataComponentsForTTPRollup(t, buf.scrD, buf.dcs)
		rollupDCs := set{Dir: "in", Name: "data components rollup", Count: n, Nodes: dcNodes(e, buf.dcs, n)}
		n = e.GroupsForTTP(t, buf.gs)
		groups := set{Dir: "in", Name: "groups", Count: n, Nodes: groupNodes(e, buf.gs, n)}
		res.Sets = []set{arts, rollupArts, cms, rollupCMs, dcs, rollupDCs, groups}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runArtifact answers `artifact <query>...`.
func runArtifact(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("artifact", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	relName := fs.String("rel", "any", "")
	defRelName := fs.String("defrel", "any", "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if !requireQueries(stderr, queries) {
		return 2
	}
	r, ok := e.Rel(*relName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such offensive relation: %s\n", *relName)
		return 1
	}
	dr, ok := e.DefRel(*defRelName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such defensive relation: %s\n", *defRelName)
		return 1
	}

	buf := newBuffers(e)
	relSuffixStr := relSuffix(r, *relName)
	defSuffix := defRelSuffix(dr, *defRelName)
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		a, ok := e.Artifact(q)
		if !ok {
			failures = append(failures, "gr4ph: no such artifact: "+q)
			continue
		}
		name, label := e.ArtifactName(a), e.ArtifactLabel(a)
		res := result{
			Query: q, Kind: "artifact",
			ID:    new(int(a)),
			Name:  name,
			Label: collapseLabel(name, label),
		}
		n := e.TTPsRel(a, r, buf.ttps)
		ttps := set{Dir: "in", Name: "techniques" + relSuffixStr, Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.TTPsRollupRel(a, r, buf.scrT, buf.ttps)
		rollupTTPs := set{Dir: "in", Name: "techniques rollup" + relSuffixStr, Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.CountermeasuresForArtifact(a, dr, buf.cms)
		cms := set{Dir: "in", Name: "countermeasures" + defSuffix, Count: n, Nodes: cmNodes(e, buf.cms, n)}
		// The viaTTPs surface is the direct links unioned with the links of the
		// techniques touching a, with no relation filter, so it has no suffix.
		n = e.CountermeasuresForArtifactViaTTPs(a, buf.scrC, buf.cms)
		viaTTPs := set{Dir: "in", Name: "countermeasures viaTTPs", Count: n, Nodes: cmNodes(e, buf.cms, n)}
		res.Sets = []set{ttps, rollupTTPs, cms, viaTTPs}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runCM answers `cm <query>...`.
func runCM(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	defRelName := fs.String("defrel", "any", "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if !requireQueries(stderr, queries) {
		return 2
	}
	dr, ok := e.DefRel(*defRelName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such defensive relation: %s\n", *defRelName)
		return 1
	}

	buf := newBuffers(e)
	defSuffix := defRelSuffix(dr, *defRelName)
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		cm, ok := e.Countermeasure(q)
		if !ok {
			failures = append(failures, "gr4ph: no such countermeasure: "+q)
			continue
		}
		name, label := e.CountermeasureName(cm), e.CountermeasureLabel(cm)
		res := result{
			Query: q, Kind: "cm",
			ID:    new(int(cm)),
			Name:  name,
			Label: collapseLabel(name, label),
		}
		n := e.ArtifactsForCountermeasure(cm, dr, buf.arts)
		arts := set{Dir: "out", Name: "artifacts" + defSuffix, Count: n, Nodes: artNodes(e, buf.arts, n)}
		n = e.TTPsForCountermeasure(cm, buf.ttps)
		ttps := set{Dir: "out", Name: "techniques", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.TTPsForCountermeasureRollup(cm, buf.scrT, buf.ttps)
		rollupTTPs := set{Dir: "out", Name: "techniques rollup", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		res.Sets = []set{arts, ttps, rollupTTPs}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runDC answers `dc <query>...`.
func runDC(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("dc", flag.ContinueOnError)
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
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		dc, ok := e.DataComponent(q)
		if !ok {
			failures = append(failures, "gr4ph: no such data component: "+q)
			continue
		}
		name, label := e.DataComponentID(dc), e.DataComponentLabel(dc)
		res := result{
			Query: q, Kind: "dc",
			ID:    new(int(dc)),
			Name:  name,
			Label: collapseLabel(name, label),
		}
		n := e.TTPsForDataComponent(dc, buf.ttps)
		res.Sets = []set{{Dir: "out", Name: "techniques", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runGroup answers `group <query>...`: one partition holds actors, software and
// campaigns, so the kind is part of the header.
func runGroup(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("group", flag.ContinueOnError)
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
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		g, ok := e.Group(q)
		if !ok {
			failures = append(failures, "gr4ph: no such group: "+q)
			continue
		}
		name, label := e.GroupID(g), e.GroupLabel(g)
		res := result{
			Query: q, Kind: "group",
			ID:        new(int(g)),
			Name:      name,
			Label:     collapseLabel(name, label),
			GroupKind: e.GroupKind(g).String(),
			Revoked:   e.GroupRevoked(g),
		}
		n := e.TTPsForGroup(g, buf.ttps)
		ttps := set{Dir: "out", Name: "techniques", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.SoftwareForGroup(g, buf.gs)
		software := set{Dir: "out", Name: "software", Count: n, Nodes: groupNodes(e, buf.gs, n)}
		n = e.GroupsForSoftware(g, buf.gs)
		groups := set{Dir: "in", Name: "groups", Count: n, Nodes: groupNodes(e, buf.gs, n)}
		res.Sets = []set{ttps, software, groups}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runTactic answers `tactic <ta-id>...`. The query is a TA id, not a label:
// tactic labels repeat across the three ATT&CK domains.
func runTactic(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("tactic", flag.ContinueOnError)
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
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		ta, ok := e.Tactic(q)
		if !ok {
			failures = append(failures, "gr4ph: no such tactic: "+q)
			continue
		}
		name, label := e.TacticID(ta), e.TacticLabel(ta)
		res := result{
			Query: q, Kind: "tactic",
			ID:    new(int(ta)),
			Name:  name,
			Label: collapseLabel(name, label),
		}
		n := e.TTPsForTactic(ta, buf.ttps)
		res.Sets = []set{{Dir: "out", Name: "techniques", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runPlatform answers `platform <name>...`.
func runPlatform(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("platform", flag.ContinueOnError)
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
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		p, ok := e.Platform(q)
		if !ok {
			failures = append(failures, "gr4ph: no such platform: "+q)
			continue
		}
		name := e.PlatformName(p)
		res := result{
			Query: q, Kind: "platform",
			ID:   new(int(p)),
			Name: name,
		}
		n := e.TTPsForPlatform(p, buf.ttps)
		res.Sets = []set{{Dir: "out", Name: "techniques", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runKEV answers `kev <query>...`: each query resolves a CVE id and reports the
// catalog's own columns for that entry plus the weakness classes it is filed
// under.
func runKEV(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kev", flag.ContinueOnError)
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
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		k, ok := e.KEV(q)
		if !ok {
			failures = append(failures, "gr4ph: no such KEV entry: "+q)
			continue
		}
		name := e.KEVID(k)
		res := result{
			Query: q, Kind: "kev",
			ID:         new(int(k)),
			Name:       name,
			Label:      collapseLabel(name, e.KEVName(k)),
			Added:      e.KEVAdded(k),
			Ransomware: e.KEVRansomware(k),
			Vendor:     e.KEVVendor(k),
			Product:    e.KEVProduct(k),
		}
		n := e.CWEsForKEV(k, buf.cwes)
		res.Sets = []set{{Dir: "out", Name: "weaknesses", Count: n, Nodes: cweNodes(e, buf.cwes, n)}}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runCWE answers `cwe <query>...`: each query resolves a weakness id and lists
// the KEV entries filed under that class.
func runCWE(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cwe", flag.ContinueOnError)
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
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		c, ok := e.CWE(q)
		if !ok {
			failures = append(failures, "gr4ph: no such cwe: "+q)
			continue
		}
		res := result{
			Query: q, Kind: "cwe",
			ID:   new(int(c)),
			Name: e.CWEID(c),
		}
		n := e.KEVsForCWE(c, buf.kevs)
		res.Sets = []set{{Dir: "in", Name: "entries", Count: n, Nodes: kevNodes(e, buf.kevs, n)}}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runProduct answers `product <vendor>/<name>...`. Unlike kev and cwe this is a
// selection verb, like coverage and gain: every query contributes one product
// to a single selection, and the answer is the union of the entries filed under
// any of them — the asset-inventory question ("which exploited vulnerabilities
// are in the software we run?"). A run in which no query resolved prints no
// block at all, only the failures.
func runProduct(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("product", flag.ContinueOnError)
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
	sel := make([]uint64, e.WordsPerRow(gr4ph.KindProduct))
	seen := make(map[gr4ph.Product]bool)
	keys := make([]string, 0, len(queries))
	for _, q := range queries {
		vendor, name, ok := strings.Cut(q, "/")
		if !ok {
			failures = append(failures, "gr4ph: product query must be Vendor/Product: "+q)
			continue
		}
		p, ok := e.Product(vendor, name)
		if !ok {
			failures = append(failures, "gr4ph: no such product: "+q)
			continue
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		setBit(sel, int(p))
		keys = append(keys, e.KEVProductVendor(p)+"/"+e.KEVProductName(p))
	}
	if len(keys) == 0 {
		return finish(stdout, stderr, nil, failures, *jsonOut)
	}

	n := e.KEVsForProducts(sel, buf.scrK, buf.kevs)
	res := result{
		Query: strings.Join(queries, " "),
		Kind:  "product",
		Name:  strings.Join(keys, " "),
		Sets:  []set{{Dir: "out", Name: "entries", Count: n, Nodes: kevNodes(e, buf.kevs, n)}},
	}
	return finish(stdout, stderr, []result{res}, failures, *jsonOut)
}

// runRel answers `rel <name>...`.
func runRel(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	family := fs.String("family", "", "")
	jsonOut := fs.Bool("json", false, "")
	flags, names := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	switch *family {
	case "", "off", "def":
	default:
		fmt.Fprintf(stderr, "gr4ph: -family must be off or def, got %s\n", *family)
		return 2
	}
	if len(names) == 0 {
		fmt.Fprintln(stderr, "gr4ph: missing relation name")
		return 2
	}

	buf := newBuffers(e)
	results := make([]result, 0, len(names))
	failures := make([]string, 0)
	for _, name := range names {
		r, offOK := e.Rel(name)
		dr, defOK := e.DefRel(name)
		// A relation name may exist in one family, the other, or both. Only the
		// requested families are reported, and only a requested family that does
		// not resolve is an error.
		switch {
		case *family == "off" && !offOK:
			failures = append(failures, "gr4ph: no such offensive relation: "+name)
			continue
		case *family == "def" && !defOK:
			failures = append(failures, "gr4ph: no such defensive relation: "+name)
			continue
		case *family == "" && !offOK && !defOK:
			failures = append(failures, "gr4ph: no such relation: "+name)
			continue
		}
		res := result{Query: name, Kind: "rel", Name: name}
		if *family != "def" && offOK {
			edges, sources := scanOffensive(e, r, buf.arts)
			res.Planes = append(res.Planes, plane{
				Family: "offensive", ID: int(r), Count: e.RelCount(), Edges: edges, Sources: sources,
			})
		}
		if *family != "off" && defOK {
			edges, sources := scanDefensive(e, dr, buf.arts)
			res.Planes = append(res.Planes, plane{
				Family: "defensive", ID: int(dr), Count: e.DefRelCount(), Edges: edges, Sources: sources,
			})
		}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}
