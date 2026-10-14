// parse.go: ATT&CK STIX, D3FEND CSV and graph-assembly parsing.
package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// --- ATT&CK STIX ---

type ttpInfo struct {
	label  string
	domain domain
	// sub is x_mitre_is_subtechnique, checked against the id prefix in assemble.
	sub bool
	// bad marks a revoked or deprecated object, which is kept (D3FEND still
	// references it) but loses its name to a live object with the same id.
	bad bool
	// tactics holds the technique's ATT&CK tactic ids (TA ids) from its
	// kill_chain_phases, sorted; platforms holds x_mitre_platforms. Both come
	// from the object that won the id, so a duplicate id never mixes two
	// objects' attributes.
	tactics   []string
	platforms []string
}

type stixBundle struct {
	Objects []stixObject `json:"objects"`
}

type stixObject struct {
	UUID               string               `json:"id"`
	Type               string               `json:"type"`
	Name               string               `json:"name"`
	Revoked            bool                 `json:"revoked"`
	Deprecated         bool                 `json:"x_mitre_deprecated"`
	Subtechnique       bool                 `json:"x_mitre_is_subtechnique"`
	Shortname          string               `json:"x_mitre_shortname"`
	Platforms          []string             `json:"x_mitre_platforms"`
	KillChainPhases    []stixKillChainPhase `json:"kill_chain_phases"`
	AnalyticRefs       []string             `json:"x_mitre_analytic_refs"`
	LogSourceRefs      []stixLogSourceRef   `json:"x_mitre_log_source_references"`
	RelationshipType   string               `json:"relationship_type"`
	SourceRef          string               `json:"source_ref"`
	TargetRef          string               `json:"target_ref"`
	ExternalReferences []stixExternalRef    `json:"external_references"`
}

type stixKillChainPhase struct {
	ChainName string `json:"kill_chain_name"`
	PhaseName string `json:"phase_name"`
}

type stixLogSourceRef struct {
	DataComponentRef string `json:"x_mitre_data_component_ref"`
}

type stixExternalRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
}

// attackID returns the id of the object's mitre-attack reference, or "" when it
// has none. It is the single rule that decides which ATT&CK objects this
// generator sees.
func attackID(obj stixObject) string {
	for _, ref := range obj.ExternalReferences {
		if ref.SourceName == "mitre-attack" {
			return ref.ExternalID
		}
	}
	return ""
}

// parseAttack adds every attack-pattern in data to out, keyed by ATT&CK id.
// Ids are deduplicated: the first non-revoked, non-deprecated name wins, else
// the first in file order (ICS and mobile repeat ids across objects).
//
// The bundle's own tactics resolve each technique's kill_chain_phases, so the 11
// shortnames that appear in more than one domain (with a different TA id each)
// can never mis-tag a technique: the phase's bundle decides.
func parseAttack(data []byte, dom domain, out map[string]*ttpInfo) error {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse STIX: %w", err)
	}
	tac := map[string]string{}
	for _, obj := range bundle.Objects {
		if obj.Type != "x-mitre-tactic" {
			continue
		}
		id := attackID(obj)
		if id == "" {
			return fmt.Errorf("tactic %s has no mitre-attack external id", obj.Shortname)
		}
		tac[obj.Shortname] = id
	}
	for _, obj := range bundle.Objects {
		if obj.Type != "attack-pattern" {
			continue
		}
		id := attackID(obj)
		if id == "" {
			// Not a node: an attack-pattern with no mitre-attack external id
			// has no key to be looked up by, so the whole object is invisible
			// here. A relationship that names it fails loudly in
			// parseAttackGraph instead.
			continue
		}
		bad := obj.Revoked || obj.Deprecated
		prev, ok := out[id]
		if !ok {
			info := &ttpInfo{label: obj.Name, domain: dom, sub: obj.Subtechnique, bad: bad}
			if err := info.setAttributes(obj, tac, id); err != nil {
				return err
			}
			out[id] = info
			continue
		}
		if prev.bad && !bad {
			// The whole record comes from the live twin: name, flag, domain and
			// attributes.
			prev.label = obj.Name
			prev.domain = dom
			prev.sub = obj.Subtechnique
			prev.bad = false
			if err := prev.setAttributes(obj, tac, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// setAttributes records the technique's tactic ids and platforms from one STIX
// object. A phase name the bundle's tactics do not define is an error: it would
// silently drop a bit.
func (t *ttpInfo) setAttributes(obj stixObject, tac map[string]string, id string) error {
	tactics := map[string]bool{}
	for _, p := range obj.KillChainPhases {
		ta, ok := tac[p.PhaseName]
		if !ok {
			return fmt.Errorf("technique %s: kill chain phase %q matches no tactic", id, p.PhaseName)
		}
		tactics[ta] = true
	}
	t.tactics = sortedKeys(tactics)
	platforms := map[string]bool{}
	for _, p := range obj.Platforms {
		platforms[p] = true
	}
	t.platforms = sortedKeys(platforms)
	return nil
}

// --- ATT&CK graph: data components and grouping nodes ---

// attackGraph is the non-technique ATT&CK data: the folded detects relation, the
// grouping nodes and their uses edges, all keyed by ATT&CK external id. It is
// filled one bundle at a time and assembled with the technique table.
type attackGraph struct {
	stub     map[string]string    // STIX uuid -> attack-pattern external id
	dcUUID   map[string]string    // STIX uuid -> data-component external id
	dcNodes  map[string]dcNode    // data-component external id -> label
	anRefs   map[string][]string  // detection-strategy uuid -> analytic uuids
	dcRefs   map[string][]string  // analytic uuid -> data-component uuids
	detects  map[[2]string]bool   // (data component, technique)
	grpUUID  map[string]string    // STIX uuid -> grouping-node external id
	nodes    map[string]groupNode // grouping-node external id -> label + kind
	uses     map[[2]string]bool   // (group, technique)
	software map[[2]string]bool   // (group, software node)
	tactics  map[string]string    // tactic id (TA id) -> label
}

func newAttackGraph() *attackGraph {
	return &attackGraph{
		stub:     map[string]string{},
		dcUUID:   map[string]string{},
		dcNodes:  map[string]dcNode{},
		anRefs:   map[string][]string{},
		dcRefs:   map[string][]string{},
		detects:  map[[2]string]bool{},
		grpUUID:  map[string]string{},
		nodes:    map[string]groupNode{},
		uses:     map[[2]string]bool{},
		software: map[[2]string]bool{},
		tactics:  map[string]string{},
	}
}

// dcNode is one data component: the label plus the flag that decides which of two
// duplicate records wins.
type dcNode struct {
	label string
	bad   bool
}

// groupNode is one grouping node: an ATT&CK intrusion set, malware, tool or
// campaign.
type groupNode struct {
	label string
	kind  groupKind
	bad   bool
}

// groupKind mirrors gr4ph.GroupKind, kept local so this package stays
// dependency-free.
type groupKind uint8

const (
	kindActor groupKind = iota
	kindSoftware
	kindCampaign
)

// groupKindOf maps a STIX object type to its grouping kind, and reports whether
// the type is a grouping node at all.
func groupKindOf(typ string) (groupKind, bool) {
	switch typ {
	case "intrusion-set":
		return kindActor, true
	case "malware", "tool":
		return kindSoftware, true
	case "campaign":
		return kindCampaign, true
	}
	return 0, false
}

// idPrefix is the ATT&CK external-id prefix each grouping kind uses.
func (k groupKind) idPrefix() string {
	switch k {
	case kindActor:
		return "G"
	case kindSoftware:
		return "S"
	}
	return "C"
}

func (k groupKind) constName() string {
	switch k {
	case kindActor:
		return "gr4ph.GroupActor"
	case kindSoftware:
		return "gr4ph.GroupSoftware"
	}
	return "gr4ph.GroupCampaign"
}

// parseAttackGraph folds one bundle into g. The detects relation has no direct
// edge in the pinned bundles: a detection strategy detects a technique and names
// analytics, which name log source references, which name data components, so the
// fold is technique <-detects- strategy ->analytics-> log sources -> data
// component.
//
// Every reference that resolves to nothing is an error, not a silent drop: the
// pinned 19.2 bundles resolve completely (measured), so a drop would be upstream
// drift this generator must report.
func parseAttackGraph(data []byte, g *attackGraph) error {
	var bundle stixBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse STIX: %w", err)
	}
	for _, obj := range bundle.Objects {
		id := attackID(obj)
		switch obj.Type {
		case "attack-pattern":
			if id != "" {
				g.stub[obj.UUID] = id
			}
		case "x-mitre-data-component":
			if id == "" {
				continue
			}
			g.dcUUID[obj.UUID] = id
			live := !obj.Revoked && !obj.Deprecated
			if prev, ok := g.dcNodes[id]; !ok || (prev.bad && live) {
				g.dcNodes[id] = dcNode{label: obj.Name, bad: !live}
			}
		case "x-mitre-detection-strategy":
			g.anRefs[obj.UUID] = obj.AnalyticRefs
		case "x-mitre-tactic":
			if id != "" {
				// Last registration wins, which is safe on the pinned data: no
				// TA id is defined by two bundles (measured: 41 ids, 0
				// redefinitions, and no x_mitre_shortname repeats within a
				// bundle). A future release that redefines one takes the
				// last-parsed bundle's label.
				g.tactics[id] = obj.Name
			}
		case "x-mitre-analytic":
			for _, ls := range obj.LogSourceRefs {
				if ls.DataComponentRef != "" {
					g.dcRefs[obj.UUID] = append(g.dcRefs[obj.UUID], ls.DataComponentRef)
				}
			}
		default:
			kind, isGroup := groupKindOf(obj.Type)
			if !isGroup || id == "" {
				// Not a node: a grouping object with no mitre-attack external
				// id has no key (7 malware objects in 19.2). A uses
				// relationship that names one fails loudly below instead.
				continue
			}
			if !strings.HasPrefix(id, kind.idPrefix()) {
				return fmt.Errorf("group %s: id does not match the %s object", id, obj.Type)
			}
			g.grpUUID[obj.UUID] = id
			live := !obj.Revoked && !obj.Deprecated
			if prev, ok := g.nodes[id]; !ok || (prev.bad && live) {
				g.nodes[id] = groupNode{label: obj.Name, kind: kind, bad: !live}
			}
		}
	}

	for _, obj := range bundle.Objects {
		if obj.Type != "relationship" {
			continue
		}
		switch obj.RelationshipType {
		case "detects":
			ttp, ok := g.stub[obj.TargetRef]
			if !ok {
				return fmt.Errorf("detects references technique %s with no external id", obj.TargetRef)
			}
			dcs, err := g.detectedComponents(obj.SourceRef)
			if err != nil {
				return err
			}
			for _, dc := range dcs {
				g.detects[[2]string{dc, ttp}] = true
			}
		case "uses":
			from, ok := g.grpUUID[obj.SourceRef]
			if !ok {
				return fmt.Errorf("uses references %s with no external id", obj.SourceRef)
			}
			if to, ok := g.stub[obj.TargetRef]; ok {
				g.uses[[2]string{from, to}] = true
				continue
			}
			to, ok := g.grpUUID[obj.TargetRef]
			if !ok || g.nodes[to].kind != kindSoftware {
				return fmt.Errorf("uses references unknown target %s", obj.TargetRef)
			}
			g.software[[2]string{from, to}] = true
		}
	}
	return nil
}

// detectedComponents resolves the data components of one detection strategy:
// strategy -> analytics -> log source references -> data components.
//
// A strategy that names no analytic is an error. An analytic that names no data
// component is not: it detects nothing through one, so it contributes no pair.
// That is the common case in 19.2, where 69 of the 2066 analytics carry no
// x_mitre_log_source_references entry, and all of the 62 strategies whose
// analytics lack one resolve to no data component. The other direction is an
// error: a log source reference whose component has no x-mitre-data-component
// object would silently drop a pair.
func (g *attackGraph) detectedComponents(det string) ([]string, error) {
	analytics := g.anRefs[det]
	if len(analytics) == 0 {
		return nil, fmt.Errorf("detection strategy %s has no analytic", det)
	}
	var out []string
	for _, an := range analytics {
		for _, ref := range g.dcRefs[an] {
			dc, ok := g.dcUUID[ref]
			if !ok {
				return nil, fmt.Errorf("analytic %s references unknown data component %s", an, ref)
			}
			out = append(out, dc)
		}
	}
	return out, nil
}

// --- D3FEND CSV ---

type d3fendData struct {
	// ttpLabel maps an off_tech id to the set of labels D3FEND gives it. It is
	// a set because T0821 is spelled two ways in 1.6.0 ("Modify Controller
	// Tasking" and "Modify controller Tasking"), and the alias table must be
	// independent of row order.
	ttpLabel map[string]map[string]bool
	// artOffLabels/artDefLabels, cmLabels and parentLabels are per-key label
	// sets, resolved into the single-valued artLabel, cmLabel and parentLabel
	// maps once the CSV has been read: last-write-wins would make the output
	// depend on row order. Artifact labels prefer the offensive spelling.
	artOffLabels map[string]map[string]bool
	artDefLabels map[string]map[string]bool
	cmLabels     map[string]map[string]bool
	parentLabels map[string]map[string]bool

	artLabel    map[string]string // artifact -> label (offensive label preferred)
	cmLabel     map[string]string // def_tech id -> label
	parentLabel map[string]string // synthesised parent id -> label

	artOff  map[string]bool // artifact appears on the offensive side
	artDef  map[string]bool // artifact appears on the defensive side
	offRel  map[string]bool
	defRel  map[string]bool
	offEdge map[[3]string]bool // (ttp, artifact, rel)
	defEdge map[[3]string]bool // (cm, artifact, defrel)
	defends map[[2]string]bool // (cm, ttp)
	// parentOf maps a sub-technique id to the set of off_tech_parent local
	// names D3FEND gives it, used to synthesise parents that exist in no
	// ATT&CK domain. A set keeps the diagnostic independent of row order.
	parentOf map[string]map[string]bool
}

// Column names of d3fend-full-mappings.csv@1.6.0 (SPARQL 1.1 CSV; every value
// used here is an IRI whose fragment is the local name).
const (
	colOffTech        = "off_tech"
	colOffArtifact    = "off_artifact"
	colOffArtifactRel = "off_artifact_rel"
	colOffTechLabel   = "off_tech_label"
	colOffArtifactLbl = "off_artifact_label"
	colDefTech        = "def_tech"
	colDefArtifact    = "def_artifact"
	colDefArtifactRel = "def_artifact_rel"
	colDefTechLabel   = "def_tech_label"
	colDefArtifactLbl = "def_artifact_label"
	colOffTechParent  = "off_tech_parent"
	colOffTechParLbl  = "off_tech_parent_label"
)

func parseD3FEND(data []byte) (*d3fendData, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = -1 // tolerate ragged rows; missing columns read as ""
	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read CSV header: %w", err)
	}
	col := make(map[string]int, len(header))
	for i, name := range header {
		col[name] = i
	}
	for _, want := range []string{
		colOffTech, colOffArtifact, colOffArtifactRel, colOffTechLabel, colOffArtifactLbl,
		colDefTech, colDefArtifact, colDefArtifactRel, colDefTechLabel, colDefArtifactLbl,
		colOffTechParent, colOffTechParLbl,
	} {
		if _, ok := col[want]; !ok {
			return nil, fmt.Errorf("CSV is missing column %q", want)
		}
	}

	d := &d3fendData{
		ttpLabel:     map[string]map[string]bool{},
		artOffLabels: map[string]map[string]bool{},
		artDefLabels: map[string]map[string]bool{},
		cmLabels:     map[string]map[string]bool{},
		parentLabels: map[string]map[string]bool{},
		artOff:       map[string]bool{},
		artDef:       map[string]bool{},
		offRel:       map[string]bool{},
		defRel:       map[string]bool{},
		offEdge:      map[[3]string]bool{},
		defEdge:      map[[3]string]bool{},
		defends:      map[[2]string]bool{},
		parentOf:     map[string]map[string]bool{},
	}
	get := func(rec []string, name string) string {
		i := col[name]
		if i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read CSV row %d: %w", r.InputOffset(), err)
		}
		offTech := localName(get(rec, colOffTech))
		offArt := localName(get(rec, colOffArtifact))
		defTech := localName(get(rec, colDefTech))
		defArt := localName(get(rec, colDefArtifact))

		// Every row of 1.6.0 populates all four, but stay defensive: an empty
		// side simply contributes nothing.
		if offTech != "" && offArt != "" {
			rel := localName(get(rec, colOffArtifactRel))
			lbl := get(rec, colOffTechLabel)
			if lbl == "" {
				// An endpoint with no label cell of its own still becomes a
				// node: the id stands in for the name, as it does for artifacts.
				lbl = offTech
			}
			addLabel(d.ttpLabel, offTech, lbl)
			d.artOff[offArt] = true
			if lbl := get(rec, colOffArtifactLbl); lbl != "" {
				addLabel(d.artOffLabels, offArt, lbl)
			}
			d.offRel[rel] = true
			d.offEdge[[3]string{offTech, offArt, rel}] = true

			if parent := localName(get(rec, colOffTechParent)); parent != "" {
				addLabel(d.parentOf, offTech, parent)
				if lbl := get(rec, colOffTechParLbl); lbl != "" {
					addLabel(d.parentLabels, parent, lbl)
				}
			}
		}
		if defTech != "" && defArt != "" {
			dr := localName(get(rec, colDefArtifactRel))
			lbl := get(rec, colDefTechLabel)
			if lbl == "" {
				lbl = defTech
			}
			addLabel(d.cmLabels, defTech, lbl)
			d.artDef[defArt] = true
			if lbl := get(rec, colDefArtifactLbl); lbl != "" {
				addLabel(d.artDefLabels, defArt, lbl)
			}
			d.defRel[dr] = true
			d.defEdge[[3]string{defTech, defArt, dr}] = true
			if offTech != "" {
				d.defends[[2]string{defTech, offTech}] = true
			}
		}
	}
	d.artLabel = make(map[string]string, len(d.artOffLabels))
	for art, set := range d.artOffLabels {
		d.artLabel[art] = pickLabel(set)
	}
	for art, set := range d.artDefLabels {
		if _, ok := d.artLabel[art]; ok {
			continue
		}
		d.artLabel[art] = pickLabel(set)
	}
	d.cmLabel = pickAll(d.cmLabels)
	d.parentLabel = pickAll(d.parentLabels)
	return d, nil
}

// addLabel records one spelling of key in a label set.
func addLabel(sets map[string]map[string]bool, key, label string) {
	set := sets[key]
	if set == nil {
		set = map[string]bool{}
		sets[key] = set
	}
	set[label] = true
}

// pickLabel returns the byte-smallest spelling in a set, or "" when it is empty.
// Choosing from a set keeps the result independent of CSV row order.
func pickLabel(set map[string]bool) string {
	best := ""
	for label := range set {
		if best == "" || label < best {
			best = label
		}
	}
	return best
}

// pickAll resolves every spelling set of a map to one label.
func pickAll(sets map[string]map[string]bool) map[string]string {
	out := make(map[string]string, len(sets))
	for key, set := range sets {
		out[key] = pickLabel(set)
	}
	return out
}

// ttpLabels returns the distinct D3FEND labels for an off_tech id, sorted so
// the result never depends on CSV row order.
func (d *d3fendData) ttpLabels(id string) []string {
	set := d.ttpLabel[id]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for lbl := range set {
		out = append(out, lbl)
	}
	sort.Strings(out)
	return out
}

// localName returns the fragment after the last '#' of an IRI, which is the
// ATT&CK external id for techniques and the ontology local name otherwise.
func localName(iri string) string {
	if i := strings.LastIndexByte(iri, '#'); i >= 0 {
		return iri[i+1:]
	}
	return iri
}

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
