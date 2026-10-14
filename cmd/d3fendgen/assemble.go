// assemble.go: the graph assembly, the model statistics and the pinned-shape
// check. It is untagged, like the rest of cmd/d3fendgen, so the generator
// rebuilds on a stock toolchain.
package main

import (
	"fmt"
	"sort"
	"strings"
)

// --- assembly ---

type model struct {
	ttpIDs        []string
	ttpLabels     []string
	ttpAliases    [][]string
	ttpDomains    []domain
	ttpParents    []int // -1 == no parent
	ttpChildCount []int
	ttpRevoked    []bool

	// Attribute vocabularies and their rows: tacticTTP[i] holds the indices of
	// the techniques of tacticIDs[i], ascending.
	tacticIDs     []string
	tacticLabels  []string
	tacticTTP     [][]int
	platformNames []string
	platformTTP   [][]int

	dcIDs    []string
	dcLabels []string
	// detects pairs, parallel and sorted by (dc, ttp).
	detectsDC  []int
	detectsTTP []int

	groupIDs     []string
	groupLabels  []string
	groupKinds   []groupKind
	groupRevoked []bool
	// uses pairs, parallel and sorted by (group, technique), and software-use
	// pairs sorted by (group, software).
	usesGroup         []int
	usesTTP           []int
	softwareUseGroup  []int
	softwareUseTarget []int

	artNames  []string
	artLabels []string

	cmIDs    []string
	cmLabels []string

	offRelNames []string
	defRelNames []string

	offT, offA, offR   []int // parallel
	defC, defA, defR   []int
	defendsC, defendsT []int
}

// sumRows returns the total length of a slice of rows.
func sumRows(rows [][]int) int {
	n := 0
	for _, r := range rows {
		n += len(r)
	}
	return n
}

// kindHistogram counts grouping nodes by kind.
func (m *model) kindHistogram() (actor, software, campaign int) {
	for _, k := range m.groupKinds {
		switch k {
		case kindActor:
			actor++
		case kindSoftware:
			software++
		default:
			campaign++
		}
	}
	return actor, software, campaign
}

func (m *model) topLevel() int {
	n := 0
	for _, p := range m.ttpParents {
		if p < 0 {
			n++
		}
	}
	return n
}

func (m *model) parentCount() int {
	n := 0
	for _, c := range m.ttpChildCount {
		if c > 0 {
			n++
		}
	}
	return n
}

func (m *model) revokedCount() int {
	n := 0
	for _, r := range m.ttpRevoked {
		if r {
			n++
		}
	}
	return n
}

func (m *model) maxChildren() int {
	best := 0
	for _, c := range m.ttpChildCount {
		if c > best {
			best = c
		}
	}
	return best
}

func (m *model) domainHistogram() string {
	var e, i, mo, sp int
	for _, d := range m.ttpDomains {
		switch d {
		case domEnterprise:
			e++
		case domICS:
			i++
		case domMobile:
			mo++
		default:
			sp++
		}
	}
	return fmt.Sprintf("%d enterprise, %d mobile, %d ics, %d sparta", e, mo, i, sp)
}

func assemble(stix map[string]*ttpInfo, g *attackGraph, d3 *d3fendData) (*model, error) {
	offIDs := sortedKeys(d3.ttpLabel)

	// Synthesised parents: the prefix of a sub-technique that exists in no
	// ATT&CK domain (and is not itself a referenced technique). These are the
	// SPARTA parents D3FEND names only through off_tech_parent.
	synth := map[string]string{}
	for _, id := range offIDs {
		if !strings.Contains(id, ".") {
			continue
		}
		if strings.Count(id, ".") > 1 {
			return nil, fmt.Errorf("technique %s is deeper than two levels", id)
		}
		prefix := id[:strings.LastIndexByte(id, '.')]
		if _, inSTIX := stix[prefix]; inSTIX {
			// The prefix is a node, so it is the parent and off_tech_parent is
			// ignored: D3FEND's mapping may differ from ATT&CK's hierarchy
			// (T1499.002 carries off_tech_parent T1498 in 1.6.0, while ATT&CK
			// makes it a child of T1499).
			continue
		}
		if _, inOff := d3.ttpLabel[prefix]; inOff {
			continue
		}
		// Only here is off_tech_parent load-bearing, because it is the sole
		// source of the parent: every spelling it gives must agree with the id
		// prefix.
		for _, parent := range sortedKeys(d3.parentOf[id]) {
			if parent != prefix {
				return nil, fmt.Errorf("sub-technique %s: off_tech_parent %q disagrees with its id prefix %q", id, parent, prefix)
			}
		}
		label := d3.parentLabel[prefix]
		if label == "" {
			return nil, fmt.Errorf("sub-technique %s: no off_tech_parent_label for synthesised parent %s", id, prefix)
		}
		synth[prefix] = label
	}

	all := make(map[string]bool, len(stix)+len(offIDs)+len(synth))
	for id := range stix {
		all[id] = true
	}
	for _, id := range offIDs {
		all[id] = true
	}
	for id := range synth {
		all[id] = true
	}
	ids := sortedKeys(all)

	m := &model{
		ttpIDs:        ids,
		ttpParents:    make([]int, len(ids)),
		ttpChildCount: make([]int, len(ids)),
	}
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		index[id] = i
	}

	// Attribute rows, collected in index order so every row is ascending.
	tacticOf := map[string][]int{}
	platformOf := map[string][]int{}

	for i, id := range ids {
		info := stix[id]
		var label string
		switch {
		case info != nil:
			label = info.label
			m.ttpDomains = append(m.ttpDomains, info.domain)
		case synth[id] != "":
			label = synth[id]
			m.ttpDomains = append(m.ttpDomains, domSPARTA)
		default:
			// No ATT&CK object: the byte-smallest D3FEND spelling is the name
			// (ttpLabels is sorted), and any other spelling becomes an alias.
			label = d3.ttpLabels(id)[0]
			m.ttpDomains = append(m.ttpDomains, domSPARTA)
		}
		if label == "" {
			return nil, fmt.Errorf("technique %s has no label", id)
		}
		m.ttpLabels = append(m.ttpLabels, label)

		// Aliases: every D3FEND spelling that differs from the chosen label,
		// whatever the node's provenance, so a second spelling is never dropped.
		var aliases []string
		for _, variant := range d3.ttpLabels(id) {
			if variant != label {
				aliases = append(aliases, variant)
			}
		}
		m.ttpAliases = append(m.ttpAliases, aliases)

		// Attribute rows: the technique's tactics and platforms. Only the 1140
		// STIX-sourced nodes have them; the D3FEND-named nodes contribute to no
		// row, and a platform name that occurs on no technique is dropped.
		if info != nil {
			for _, ta := range info.tactics {
				tacticOf[ta] = append(tacticOf[ta], i)
			}
			for _, p := range info.platforms {
				platformOf[p] = append(platformOf[p], i)
			}
		}

		// Parent: the id prefix, when that prefix is a node. The id prefix is
		// authoritative (it agrees with x_mitre_is_subtechnique on every node
		// of 19.2).
		parent := -1
		dot := strings.LastIndexByte(id, '.')
		if dot >= 0 {
			if p, ok := index[id[:dot]]; ok {
				parent = p
			}
		}
		m.ttpParents[i] = parent
		m.ttpRevoked = append(m.ttpRevoked, info != nil && info.bad)

		// The prefix rule must agree with the STIX flag (measured: 1140/1140
		// attack-patterns in 19.2), the tree may only be two levels deep, and no
		// dotted id may be left without a parent node. Depth is reported first:
		// a three-level id is a depth error whichever node is missing, which is
		// the more specific diagnostic.
		if strings.Count(id, ".") > 1 {
			return nil, fmt.Errorf("technique %s is deeper than two levels", id)
		}
		if info := stix[id]; info != nil && info.sub != (dot >= 0) {
			return nil, fmt.Errorf("technique %s: x_mitre_is_subtechnique=%v disagrees with its id prefix", id, info.sub)
		}
		if dot >= 0 && parent < 0 {
			return nil, fmt.Errorf("technique %s: sub-technique has no parent node (orphan)", id)
		}
	}
	for _, p := range m.ttpParents {
		if p >= 0 {
			m.ttpChildCount[p]++
		}
	}

	// Attribute vocabularies: sorted ids and names, with the label of each
	// tactic taken from the bundle that defined it (labels repeat across
	// domains, so the id is the key). Both rows are non-empty by construction:
	// a tactic id or platform name enters a vocabulary only by being referenced
	// by a technique. The checks below record that, so a later change to the
	// collection cannot quietly emit an empty row.
	m.tacticIDs = sortedKeys(tacticOf)
	for _, ta := range m.tacticIDs {
		label, ok := g.tactics[ta]
		if !ok || label == "" {
			return nil, fmt.Errorf("tactic %s has no label", ta)
		}
		m.tacticLabels = append(m.tacticLabels, label)
		m.tacticTTP = append(m.tacticTTP, tacticOf[ta])
	}
	m.platformNames = sortedKeys(platformOf)
	for _, p := range m.platformNames {
		m.platformTTP = append(m.platformTTP, platformOf[p])
	}
	for i, ta := range m.tacticIDs {
		if len(m.tacticTTP[i]) == 0 {
			return nil, fmt.Errorf("tactic %s has no technique", ta)
		}
	}
	for i, name := range m.platformNames {
		if len(m.platformTTP[i]) == 0 {
			return nil, fmt.Errorf("platform %s has no technique", name)
		}
	}

	// Contiguous child blocks: the children of p must be exactly the indices
	// p+1 .. p+count[p], which is what makes the O(1) child range valid.
	filled := make([]int, len(ids))
	for i, p := range m.ttpParents {
		if p < 0 {
			continue
		}
		if want := p + 1 + filled[p]; i != want {
			return nil, fmt.Errorf("technique %s at index %d does not extend its parent's child block (want index %d)", ids[i], i, want)
		}
		filled[p]++
	}

	// Artifacts: name + label (offensive label preferred).
	artSet := map[string]bool{}
	for _, art := range sortedKeys(d3.artLabel) {
		artSet[art] = true
	}
	for _, art := range sortedKeys(d3.artOff) {
		artSet[art] = true
	}
	for _, art := range sortedKeys(d3.artDef) {
		artSet[art] = true
	}
	m.artNames = sortedKeys(artSet)
	for _, art := range m.artNames {
		label := d3.artLabel[art]
		if label == "" {
			label = art
		}
		m.artLabels = append(m.artLabels, label)
	}

	m.cmIDs = sortedKeys(d3.cmLabel)
	for _, cm := range m.cmIDs {
		m.cmLabels = append(m.cmLabels, d3.cmLabel[cm])
	}

	m.offRelNames = sortedKeys(d3.offRel)
	m.defRelNames = sortedKeys(d3.defRel)

	artIndex := make(map[string]int, len(m.artNames))
	for i, a := range m.artNames {
		artIndex[a] = i
	}
	cmIndex := make(map[string]int, len(m.cmIDs))
	for i, cm := range m.cmIDs {
		cmIndex[cm] = i
	}
	offRelIndex := make(map[string]int, len(m.offRelNames))
	for i, r := range m.offRelNames {
		offRelIndex[r] = i + 1 // plane 0 is RelAny
	}
	defRelIndex := make(map[string]int, len(m.defRelNames))
	for i, r := range m.defRelNames {
		defRelIndex[r] = i + 1
	}

	offTriples := sortedTriples(d3.offEdge)
	for _, t := range offTriples {
		ti, ok := index[t[0]]
		if !ok {
			return nil, fmt.Errorf("offensive edge references unknown technique %s", t[0])
		}
		ai, ok := artIndex[t[1]]
		if !ok {
			return nil, fmt.Errorf("offensive edge references unknown artifact %s", t[1])
		}
		m.offT = append(m.offT, ti)
		m.offA = append(m.offA, ai)
		m.offR = append(m.offR, offRelIndex[t[2]])
	}

	defTriples := sortedTriples(d3.defEdge)
	for _, t := range defTriples {
		ci, ok := cmIndex[t[0]]
		if !ok {
			return nil, fmt.Errorf("defensive edge references unknown countermeasure %s", t[0])
		}
		ai, ok := artIndex[t[1]]
		if !ok {
			return nil, fmt.Errorf("defensive edge references unknown artifact %s", t[1])
		}
		m.defC = append(m.defC, ci)
		m.defA = append(m.defA, ai)
		m.defR = append(m.defR, defRelIndex[t[2]])
	}

	pairs := sortedPairs(d3.defends)
	for _, p := range pairs {
		ci, ok := cmIndex[p[0]]
		if !ok {
			return nil, fmt.Errorf("defends-against references unknown countermeasure %s", p[0])
		}
		ti, ok := index[p[1]]
		if !ok {
			return nil, fmt.Errorf("defends-against references unknown technique %s", p[1])
		}
		m.defendsC = append(m.defendsC, ci)
		m.defendsT = append(m.defendsT, ti)
	}

	// Data components: the detects relation is folded from the detection
	// strategies, so a data component is a node whether or not it detects
	// anything.
	m.dcIDs = sortedKeys(g.dcNodes)
	for _, dc := range m.dcIDs {
		label := g.dcNodes[dc].label
		if label == "" {
			// An empty label is a dead key: the builder's index map skips it
			// (claim), so DataComponent(label) could never resolve the node.
			return nil, fmt.Errorf("data component %s has no label", dc)
		}
		m.dcLabels = append(m.dcLabels, label)
	}
	dcIndex := make(map[string]int, len(m.dcIDs))
	for i, dc := range m.dcIDs {
		dcIndex[dc] = i
	}
	for _, p := range sortedPairs(g.detects) {
		di, ok := dcIndex[p[0]]
		if !ok {
			return nil, fmt.Errorf("detects references unknown data component %s", p[0])
		}
		ti, ok := index[p[1]]
		if !ok {
			return nil, fmt.Errorf("detects references unknown technique %s", p[1])
		}
		m.detectsDC = append(m.detectsDC, di)
		m.detectsTTP = append(m.detectsTTP, ti)
	}

	// Grouping nodes: actors, software and campaigns share one partition, and
	// their uses edges split into the technique family and the software family.
	m.groupIDs = sortedKeys(g.nodes)
	for _, id := range m.groupIDs {
		label := g.nodes[id].label
		if label == "" {
			// Same dead-key rule as the data components above.
			return nil, fmt.Errorf("group %s has no label", id)
		}
		m.groupLabels = append(m.groupLabels, label)
		m.groupKinds = append(m.groupKinds, g.nodes[id].kind)
		m.groupRevoked = append(m.groupRevoked, g.nodes[id].bad)
	}
	groupIndex := make(map[string]int, len(m.groupIDs))
	for i, id := range m.groupIDs {
		groupIndex[id] = i
	}
	for _, p := range sortedPairs(g.uses) {
		gi, ok := groupIndex[p[0]]
		if !ok {
			return nil, fmt.Errorf("uses references unknown group %s", p[0])
		}
		ti, ok := index[p[1]]
		if !ok {
			return nil, fmt.Errorf("uses references unknown technique %s", p[1])
		}
		m.usesGroup = append(m.usesGroup, gi)
		m.usesTTP = append(m.usesTTP, ti)
	}
	for _, p := range sortedPairs(g.software) {
		gi, ok := groupIndex[p[0]]
		if !ok {
			return nil, fmt.Errorf("uses references unknown group %s", p[0])
		}
		si, ok := groupIndex[p[1]]
		if !ok {
			return nil, fmt.Errorf("uses references unknown software %s", p[1])
		}
		m.softwareUseGroup = append(m.softwareUseGroup, gi)
		m.softwareUseTarget = append(m.softwareUseTarget, si)
	}

	return m, nil
}

// sortedPairs returns the pairs of a set in (first, second) order.
func sortedPairs(m map[[2]string]bool) [][2]string {
	out := make([][2]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// checkShape compares the assembled graph against want and fails on any drift:
// node/edge/relation counts, the offensive union-plane cardinality, the domain
// histogram and the technique-hierarchy counts.
func (m *model) checkShape(want shape) error {
	// Caps first: a graph the tables cannot represent must never reach emit.
	if len(m.offRelNames) > maxPlanes || len(m.defRelNames) > maxPlanes {
		return fmt.Errorf("shape drift: %d/%d relation planes exceed the %d-plane space",
			len(m.offRelNames), len(m.defRelNames), maxPlanes)
	}
	if len(m.ttpIDs) > maxNodes || len(m.artNames) > maxNodes || len(m.cmIDs) > maxNodes ||
		len(m.dcIDs) > maxNodes || len(m.groupIDs) > maxNodes {
		return fmt.Errorf("shape drift: node count exceeds %d (techniques %d, artifacts %d, countermeasures %d, data components %d, groups %d)",
			maxNodes, len(m.ttpIDs), len(m.artNames), len(m.cmIDs), len(m.dcIDs), len(m.groupIDs))
	}
	if len(m.tacticIDs) > 64 || len(m.platformNames) > 64 {
		return fmt.Errorf("shape drift: attribute vocabulary exceeds the 64-bit mask (tactics %d, platforms %d)",
			len(m.tacticIDs), len(m.platformNames))
	}

	counts := []struct {
		name string
		got  int
		want int
	}{
		{"techniques", len(m.ttpIDs), want.ttps},
		{"artifacts", len(m.artNames), want.artifacts},
		{"countermeasures", len(m.cmIDs), want.cms},
		{"offensive relations", len(m.offRelNames), want.offRels},
		{"defensive relations", len(m.defRelNames), want.defRels},
		{"offensive edges", len(m.offT), want.offEdges},
		{"defensive edges", len(m.defC), want.defEdges},
		{"defends-against pairs", len(m.defendsC), want.defends},
		{"tactics", len(m.tacticIDs), want.tactics},
		{"platforms", len(m.platformNames), want.platforms},
		{"tactic assignments", sumRows(m.tacticTTP), want.tacticAssignments},
		{"platform assignments", sumRows(m.platformTTP), want.platformAssignments},
		{"data components", len(m.dcIDs), want.dataComponents},
		{"detects pairs", len(m.detectsDC), want.detectsPairs},
		{"groups", len(m.groupIDs), want.groups},
		{"uses pairs", len(m.usesGroup), want.groupUses},
		{"software-use pairs", len(m.softwareUseGroup), want.softwareUses},
	}
	for _, c := range counts {
		if c.got != c.want {
			return fmt.Errorf("shape drift: %d %s, want %d (upstream release changed; re-pin the sources and re-derive the expectations)", c.got, c.name, c.want)
		}
	}

	// Distinct (technique, artifact) pairs: the union-plane cardinality of the
	// offensive blocks. The edge slices are sorted by (ttp, artifact, rel), so
	// equal pairs are adjacent.
	pairs := 0
	for i := range m.offT {
		if i == 0 || m.offT[i] != m.offT[i-1] || m.offA[i] != m.offA[i-1] {
			pairs++
		}
	}
	if pairs != want.offPairs {
		return fmt.Errorf("shape drift: %d distinct technique/artifact pairs, want %d (upstream release changed; re-pin the sources and re-derive the expectations)", pairs, want.offPairs)
	}

	var e, i, mo, sp int
	for _, d := range m.ttpDomains {
		switch d {
		case domEnterprise:
			e++
		case domICS:
			i++
		case domMobile:
			mo++
		default:
			sp++
		}
	}
	if e != want.enterprise || mo != want.mobile || i != want.ics || sp != want.sparta {
		return fmt.Errorf("shape drift: domain histogram %d/%d/%d/%d (enterprise/mobile/ics/sparta), want %d/%d/%d/%d",
			e, mo, i, sp, want.enterprise, want.mobile, want.ics, want.sparta)
	}

	// The grouping partition's own histogram: a kind mapped to the wrong node
	// would leave the total right and the split wrong.
	actor, software, campaign := m.kindHistogram()
	if actor != want.actors || software != want.software || campaign != want.campaigns {
		return fmt.Errorf("shape drift: group histogram %d/%d/%d (actors/software/campaigns), want %d/%d/%d",
			actor, software, campaign, want.actors, want.software, want.campaigns)
	}

	// The hierarchy counts are part of the shape the report prints, and the
	// emitted TTPParents is written from the same data: drift here must fail the
	// gate instead of only showing up as a diff in the report.
	topLevel, subs := m.topLevel(), len(m.ttpIDs)-m.topLevel()
	if parents, maxChildren := m.parentCount(), m.maxChildren(); topLevel != want.topLevel || subs != want.subs ||
		parents != want.parents || maxChildren != want.maxChildren {
		return fmt.Errorf("shape drift: hierarchy %d top-level / %d sub-techniques / %d parents / max %d children, want %d/%d/%d/%d (upstream release changed; re-pin the sources and re-derive the expectations)",
			topLevel, subs, parents, maxChildren, want.topLevel, want.subs, want.parents, want.maxChildren)
	}
	return nil
}

func sortedKeys[M ~map[string]V, V any](m M) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedTriples(m map[[3]string]bool) [][3]string {
	out := make([][3]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		for k := range 3 {
			if out[i][k] != out[j][k] {
				return out[i][k] < out[j][k]
			}
		}
		return false
	})
	return out
}
