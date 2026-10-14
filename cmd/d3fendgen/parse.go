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
