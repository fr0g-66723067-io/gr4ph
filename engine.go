//go:build goexperiment.simd

package gr4ph

import (
	"math/bits"
	"strconv"
)

// Engine is the frozen graph: four multi-plane bitmatrix blocks, sixteen
// single-plane blocks, the per-technique attribute columns and the
// cold-path tables. It is immutable after Build, so any number of goroutines
// may query it concurrently as long as each supplies its own dst and scratch
// slices.
//
// # Result contract
//
// Every method that writes ids into dst truncates at len(dst) and returns the
// total number of matches, which may exceed len(dst); a nil dst therefore
// still yields the count. Ids come out in ascending index order and are
// duplicate-free, because they are the set bits of one row.
//
// # Error contract
//
// Hot-path queries are total over the id space: an id outside its partition
// yields no matches (0/false) rather than panicking, so a stale or foreign id
// set can never crash a traversal. Misuse of the *engine*'s own dimensions
// still panics, because it is a programming error with no sensible fallback:
// a relation id >= RelCount()+1 (or a defensive relation id >=
// DefRelCount()+1), a Kind that is not one of the seven partitions with a row
// stride (WordsPerRow panics "gr4ph: unknown kind"), or a scratch row shorter than
// WordsPerRow(returned partition). The scratch check runs before the id bounds
// check, so an undersized scratch panics even when the id is out of range.
//
// The overlay queries take a caller-owned Selection and never retain it; a
// selection shorter than WordsPerRow of the partition it selects panics
// "gr4ph: selection too small", the same class of engine misuse as an
// undersized scratch row.
//
// The cold string accessors (TTPName, TTPLabel, TTPDomain, ArtifactName, ...)
// panic on an out-of-range id; Response and CountermeasureResponse are the
// total boundary formatters that render "<invalid ...>" instead.
//
// The zero Engine is not a usable graph: it has no nodes and no planes, so its
// counts are 0, every id is out of range, and a relation-taking query panics
// because there is no plane 0. Obtain an Engine from Builder.Build.
type Engine struct {
	nTTP, nArt, nCM int // partition sizes
	nDC, nGrp       int
	nKEV            int // KEV entries
	nCWE, nProduct  int // the weakness and product vocabularies the KEV catalog names
	nRel, nDefRel   int // planes per family, including the union plane 0
	nTactic         int // tactic vocabulary size (TA ids)
	nPlatform       int // platform vocabulary size

	wTTP, wArt, wCM int // words per row for each partition
	wDC, wGrp       int
	wKEV            int // words per row over KEV entries (cweKEV, productKEV rows)
	wCWE, wProduct  int // words per row over the two KEV vocabularies
	wTactic         int // one word per technique (the tactic mask)
	wPlatform       int // one word per technique (the platform mask)

	// Six matrix blocks. Every row is exactly one stride long (no padding),
	// and every directed relation is materialised in both directions.
	ttpArt []uint64 // [nRel][nTTP][wArt]    technique-major over artifacts
	artTTP []uint64 // [nRel][nArt][wTTP]    artifact-major transpose
	cmArt  []uint64 // [nDefRel][nCM][wArt]  countermeasure-major over artifacts
	artCM  []uint64 // [nDefRel][nArt][wCM]  artifact-major transpose
	cmTTP  []uint64 // [nCM][wTTP]           countermeasure-major over techniques
	ttpCM  []uint64 // [nTTP][wCM]           technique-major transpose

	// The attribute columns and their transposes, the data-component partition
	// and the grouping partition. Each family has one inferred predicate, so
	// these blocks have no planes dimension.
	tacticTTP   []uint64 // [nTactic][wTTP]   tactic -> techniques
	ttpTactic   []uint64 // [nTTP][wTactic]   the per-technique tactic mask
	platformTTP []uint64 // [nPlatform][wTTP] platform -> techniques
	ttpPlatform []uint64 // [nTTP][wPlatform] the per-technique platform mask
	ttpFlags    []uint64 // [nTTP]            per-technique flags (derived)
	dcTTP       []uint64 // [nDC][wTTP]       data component -> techniques
	ttpDC       []uint64 // [nTTP][wDC]       technique -> data components
	grpTTP      []uint64 // [nGrp][wTTP]      group -> techniques
	ttpGrp      []uint64 // [nTTP][wGrp]      technique -> groups
	grpSoftware []uint64 // [nGrp][wGrp]      group -> software
	softwareGrp []uint64 // [nGrp][wGrp]      software -> groups

	// The KEV catalog: the entry partition, the weakness vocabulary it names
	// and the product vocabulary it is about. Both families are materialised in
	// both directions, and every row is exactly one stride long.
	kevCWE     []uint64 // [nKEV][wCWE]      entry -> weakness
	cweKEV     []uint64 // [nCWE][wKEV]      weakness -> entry (transpose)
	kevProduct []uint64 // [nKEV][wProduct]  entry -> product
	productKEV []uint64 // [nProduct][wKEV]  product -> entry (transpose)

	ttpIDs        []string // index-parallel cold tables
	ttpLabels     []string
	ttpDomains    []Domain
	ttpParents    []uint16 // parent index or NoParent
	ttpChildCount []uint16 // children occupy indices t+1 .. t+count
	ttpRevoked    []bool   // ATT&CK revoked or deprecated, index-parallel

	tacticIDs     []string // index-parallel vocabulary tables
	tacticLabels  []string
	platformNames []string

	dcIDs    []string
	dcLabels []string

	groupIDs    []string
	groupLabels []string
	groupKinds  []GroupKind

	artNames  []string
	artLabels []string

	cmIDs    []string
	cmLabels []string

	kevIDs         []string // KEV entries (CVE ids), index-parallel
	kevNames       []string
	kevAdded       []string
	kevRansomware  []bool
	cweIDs         []string // weakness vocabulary, index-parallel
	productVendors []string // product vocabulary, index-parallel
	productNames   []string

	relNames    []string // index 0 is "any"
	defRelNames []string // index 0 is "any"

	ttpIndex      map[string]uint16
	artIndex      map[string]uint16
	cmIndex       map[string]uint16
	dcIndex       map[string]uint16
	groupIndex    map[string]uint16
	tacticIndex   map[string]uint16
	platformIndex map[string]uint16
	relIndex      map[string]Rel
	defRelIndex   map[string]DefRel
	kevIndex      map[string]uint16
	cweIndex      map[string]uint16
	productIndex  map[[2]string]uint16
}

// --- row offsets (one formula per block row) ---

func (e *Engine) ttpArtOff(r Rel, t TTP) int { return (int(r)*e.nTTP + int(t)) * e.wArt }

func (e *Engine) artTTPOff(r Rel, a Artifact) int {
	return (int(r)*e.nArt + int(a)) * e.wTTP
}

func (e *Engine) cmArtOff(dr DefRel, cm Countermeasure) int {
	return (int(dr)*e.nCM + int(cm)) * e.wArt
}

func (e *Engine) artCMOff(dr DefRel, a Artifact) int {
	return (int(dr)*e.nArt + int(a)) * e.wCM
}
func (e *Engine) cmTTPOff(cm Countermeasure) int { return int(cm) * e.wTTP }
func (e *Engine) ttpCMOff(t TTP) int             { return int(t) * e.wCM }

func (e *Engine) tacticTTPOff(ta Tactic) int    { return int(ta) * e.wTTP }
func (e *Engine) ttpTacticOff(t TTP) int        { return int(t) * e.wTactic }
func (e *Engine) platformTTPOff(p Platform) int { return int(p) * e.wTTP }
func (e *Engine) ttpPlatformOff(t TTP) int      { return int(t) * e.wPlatform }
func (e *Engine) ttpFlagsOff(t TTP) int         { return int(t) }
func (e *Engine) dcTTPOff(dc DataComponent) int { return int(dc) * e.wTTP }
func (e *Engine) ttpDCOff(t TTP) int            { return int(t) * e.wDC }
func (e *Engine) grpTTPOff(g Group) int         { return int(g) * e.wTTP }
func (e *Engine) ttpGrpOff(t TTP) int           { return int(t) * e.wGrp }
func (e *Engine) grpSoftwareOff(g Group) int    { return int(g) * e.wGrp }
func (e *Engine) softwareGrpOff(g Group) int    { return int(g) * e.wGrp }

// The KEV rows: kevCWE is entry-major over the weakness vocabulary, so a kevCWE
// row is wCWE words, and cweKEV is its transpose with a wKEV-word row per
// weakness. The product pair is laid out the same way.
func (e *Engine) kevCWEOff(k KEV) int         { return int(k) * e.wCWE }
func (e *Engine) cweKEVOff(c CWE) int         { return int(c) * e.wKEV }
func (e *Engine) kevProductOff(k KEV) int     { return int(k) * e.wProduct }
func (e *Engine) productKEVOff(p Product) int { return int(p) * e.wKEV }

// row slices one block row. off must come from the matching offset helper and
// the id must have passed its bounds predicate.
func (e *Engine) row(block []uint64, off, stride int) []uint64 {
	return block[off : off+stride]
}

// --- bounds predicates (hot path) and panic guards (engine misuse) ---

func (e *Engine) okTTP(t TTP) bool            { return int(t) < e.nTTP }
func (e *Engine) okArt(a Artifact) bool       { return int(a) < e.nArt }
func (e *Engine) okCM(cm Countermeasure) bool { return int(cm) < e.nCM }
func (e *Engine) okDC(dc DataComponent) bool  { return int(dc) < e.nDC }
func (e *Engine) okGroup(g Group) bool        { return int(g) < e.nGrp }
func (e *Engine) okKEV(k KEV) bool            { return int(k) < e.nKEV }
func (e *Engine) okCWE(c CWE) bool            { return int(c) < e.nCWE }
func (e *Engine) okProduct(p Product) bool    { return int(p) < e.nProduct }

func (e *Engine) mustTTP(t TTP) {
	if int(t) >= e.nTTP {
		panic("gr4ph: ttp out of range")
	}
}

func (e *Engine) mustArt(a Artifact) {
	if int(a) >= e.nArt {
		panic("gr4ph: artifact out of range")
	}
}

func (e *Engine) mustCM(cm Countermeasure) {
	if int(cm) >= e.nCM {
		panic("gr4ph: countermeasure out of range")
	}
}

func (e *Engine) mustDC(dc DataComponent) {
	if int(dc) >= e.nDC {
		panic("gr4ph: data component out of range")
	}
}

func (e *Engine) mustGroup(g Group) {
	if int(g) >= e.nGrp {
		panic("gr4ph: group out of range")
	}
}

func (e *Engine) mustKEV(k KEV) {
	if int(k) >= e.nKEV {
		panic("gr4ph: kev out of range")
	}
}

func (e *Engine) mustCWE(c CWE) {
	if int(c) >= e.nCWE {
		panic("gr4ph: cwe out of range")
	}
}

func (e *Engine) mustProduct(p Product) {
	if int(p) >= e.nProduct {
		panic("gr4ph: product out of range")
	}
}

func (e *Engine) mustTactic(ta Tactic) {
	if int(ta) >= e.nTactic {
		panic("gr4ph: tactic out of range")
	}
}

func (e *Engine) mustPlatform(p Platform) {
	if int(p) >= e.nPlatform {
		panic("gr4ph: platform out of range")
	}
}

func (e *Engine) checkRel(r Rel) {
	if int(r) >= e.nRel {
		panic("gr4ph: relation out of range")
	}
}

func (e *Engine) checkDefRel(dr DefRel) {
	if int(dr) >= e.nDefRel {
		panic("gr4ph: defensive relation out of range")
	}
}

// checkScratch enforces the scratch sizing rule: len(scratch) must be at least
// WordsPerRow of the partition being returned.
func (e *Engine) checkScratch(scratch []uint64, cols Kind) {
	if len(scratch) < e.WordsPerRow(cols) {
		panic("gr4ph: scratch too small")
	}
}

// checkSelection enforces the selection sizing rule: len(sel) must be at least
// WordsPerRow of the partition it selects. An undersized selection is the same
// class of engine misuse as an undersized scratch row.
func (e *Engine) checkSelection(sel []uint64, cols Kind) {
	if len(sel) < e.WordsPerRow(cols) {
		panic("gr4ph: selection too small")
	}
}

// --- sizes ---

// TTPCount returns the number of techniques (including sub-techniques).
func (e *Engine) TTPCount() int { return e.nTTP }

// ArtifactCount returns the number of artifacts.
func (e *Engine) ArtifactCount() int { return e.nArt }

// CountermeasureCount returns the number of countermeasures.
func (e *Engine) CountermeasureCount() int { return e.nCM }

// DataComponentCount returns the number of data components.
func (e *Engine) DataComponentCount() int { return e.nDC }

// GroupCount returns the number of grouping nodes: actors, software and
// campaigns share one partition.
func (e *Engine) GroupCount() int { return e.nGrp }

// KEVCount returns the number of KEV entries (CVE ids).
func (e *Engine) KEVCount() int { return e.nKEV }

// CWECount returns the size of the weakness vocabulary the KEV catalog names.
func (e *Engine) CWECount() int { return e.nCWE }

// ProductCount returns the size of the KEV product vocabulary.
func (e *Engine) ProductCount() int { return e.nProduct }

// TacticCount returns the size of the tactic vocabulary (ATT&CK TA ids).
func (e *Engine) TacticCount() int { return e.nTactic }

// PlatformCount returns the size of the platform vocabulary.
func (e *Engine) PlatformCount() int { return e.nPlatform }

// RelCount returns the number of offensive relation predicates (excluding
// RelAny); it is 0 for the zero Engine, which has no planes.
func (e *Engine) RelCount() int { return max(e.nRel-1, 0) }

// DefRelCount returns the number of defensive relation predicates (excluding
// DefRelAny); it is 0 for the zero Engine, which has no planes.
func (e *Engine) DefRelCount() int { return max(e.nDefRel-1, 0) }

// WordsPerRow returns the number of uint64 words in one row over cols:
// ceil(count(cols)/64), i.e. the minimum scratch length for a query returning
// ids of that partition. KindDataComponent is the scratch kind of
// DataComponentsForTTPRollup; KindKEV, KindCWE and KindProduct are the scratch
// kinds of the KEV queries and the partition kinds their selections index. A
// Kind outside these partitions panics.
func (e *Engine) WordsPerRow(cols Kind) int {
	switch cols {
	case KindTTP:
		return e.wTTP
	case KindArtifact:
		return e.wArt
	case KindCountermeasure:
		return e.wCM
	case KindDataComponent:
		return e.wDC
	case KindKEV:
		return e.wKEV
	case KindCWE:
		return e.wCWE
	case KindProduct:
		return e.wProduct
	}
	panic("gr4ph: unknown kind")
}

// --- cold path: strings <-> ids ---

// Incident resolves an alert string (technique id, label or alias, trimmed and
// case-insensitively) to a technique id.
//
// Technique labels are not unique keys: the pinned tables keep ATT&CK's revoked
// techniques, whose live successors reuse their labels, so a shared label
// resolves to its live carrier and, when every carrier is revoked, to the
// lowest-index one. Ids are unambiguous (TTPName round-trips through Incident,
// and no label or alias key takes an id key), and no artifact or countermeasure
// key names two nodes. TTPRevoked reports the flag the resolver uses.
func (e *Engine) Incident(alert string) (TTP, bool) {
	i, ok := e.ttpIndex[normalize(alert)]
	return TTP(i), ok
}

// Artifact resolves an artifact name or label to an artifact id.
func (e *Engine) Artifact(s string) (Artifact, bool) {
	i, ok := e.artIndex[normalize(s)]
	return Artifact(i), ok
}

// Countermeasure resolves a countermeasure local name or label to an id.
func (e *Engine) Countermeasure(s string) (Countermeasure, bool) {
	i, ok := e.cmIndex[normalize(s)]
	return Countermeasure(i), ok
}

// DataComponent resolves a data component id ("DC0084") or label to an id.
func (e *Engine) DataComponent(s string) (DataComponent, bool) {
	i, ok := e.dcIndex[normalize(s)]
	return DataComponent(i), ok
}

// Group resolves a grouping-node id ("G0007", "S0002", "C0001") or label to an
// id. Labels are unique within a kind but not across kinds ("Frankenstein" is
// both C0001 and G0101), so the earliest registration keeps a shared label.
func (e *Engine) Group(s string) (Group, bool) {
	i, ok := e.groupIndex[normalize(s)]
	return Group(i), ok
}

// Tactic resolves an ATT&CK tactic id ("TA0005") to its dense index (the bit
// position in TTPTactics). Only the TA id is a key: tactic labels repeat across
// domains, so 11 of them name two or three tactics.
func (e *Engine) Tactic(id string) (Tactic, bool) {
	i, ok := e.tacticIndex[normalize(id)]
	return Tactic(i), ok
}

// Platform resolves an ATT&CK platform name ("Windows") to its dense index (the
// bit position in TTPPlatforms).
func (e *Engine) Platform(name string) (Platform, bool) {
	i, ok := e.platformIndex[normalize(name)]
	return Platform(i), ok
}

// KEV resolves a CVE id ("CVE-2021-44228") to its dense index. The CVE id is
// the only key: vulnerability names repeat across entries, so a name key would
// be ambiguous.
func (e *Engine) KEV(id string) (KEV, bool) {
	i, ok := e.kevIndex[normalize(id)]
	return KEV(i), ok
}

// CWE resolves a weakness id ("CWE-78") or its registered label to a dense
// index. The KEV catalog carries no CWE name, so the two are the same string
// for every table this module ships.
func (e *Engine) CWE(s string) (CWE, bool) {
	i, ok := e.cweIndex[normalize(s)]
	return CWE(i), ok
}

// Product resolves a (vendor, product) pair ("Apache", "Log4j2") to its dense
// index. Both halves must be non-empty; the pair is matched trimmed and
// case-insensitively, like every other key.
func (e *Engine) Product(vendor, name string) (Product, bool) {
	p, ok := e.productIndex[[2]string{normalize(vendor), normalize(name)}]
	return Product(p), ok
}

// TacticID returns the tactic id string, e.g. "TA0005".
func (e *Engine) TacticID(ta Tactic) string {
	e.mustTactic(ta)
	return e.tacticIDs[ta]
}

// TacticLabel returns the tactic label, e.g. "Stealth". Labels repeat across
// domains: TacticID is the unambiguous key.
func (e *Engine) TacticLabel(ta Tactic) string {
	e.mustTactic(ta)
	return e.tacticLabels[ta]
}

// PlatformName returns the platform name, e.g. "Windows".
func (e *Engine) PlatformName(p Platform) string {
	e.mustPlatform(p)
	return e.platformNames[p]
}

// DataComponentID returns the data component id string, e.g. "DC0084".
func (e *Engine) DataComponentID(dc DataComponent) string {
	e.mustDC(dc)
	return e.dcIDs[dc]
}

// DataComponentLabel returns the data component label, e.g. "Active Directory
// Credential Request".
func (e *Engine) DataComponentLabel(dc DataComponent) string {
	e.mustDC(dc)
	return e.dcLabels[dc]
}

// GroupID returns the grouping-node id string, e.g. "G0007".
func (e *Engine) GroupID(g Group) string {
	e.mustGroup(g)
	return e.groupIDs[g]
}

// GroupLabel returns the grouping-node label, e.g. "APT28".
func (e *Engine) GroupLabel(g Group) string {
	e.mustGroup(g)
	return e.groupLabels[g]
}

// GroupKind returns the ATT&CK object type of g: GroupActor, GroupSoftware or
// GroupCampaign.
func (e *Engine) GroupKind(g Group) GroupKind {
	e.mustGroup(g)
	return e.groupKinds[g]
}

// TTPName returns the technique id string, e.g. "T1003.001".
func (e *Engine) TTPName(t TTP) string {
	e.mustTTP(t)
	return e.ttpIDs[t]
}

// TTPLabel returns the technique label, e.g. "LSASS Memory".
func (e *Engine) TTPLabel(t TTP) string {
	e.mustTTP(t)
	return e.ttpLabels[t]
}

// ArtifactName returns the artifact name, e.g. "CreateProcess".
func (e *Engine) ArtifactName(a Artifact) string {
	e.mustArt(a)
	return e.artNames[a]
}

// ArtifactLabel returns the artifact label, e.g. "Create Process".
func (e *Engine) ArtifactLabel(a Artifact) string {
	e.mustArt(a)
	return e.artLabels[a]
}

// CountermeasureName returns the countermeasure local name.
func (e *Engine) CountermeasureName(cm Countermeasure) string {
	e.mustCM(cm)
	return e.cmIDs[cm]
}

// CountermeasureLabel returns the countermeasure label.
func (e *Engine) CountermeasureLabel(cm Countermeasure) string {
	e.mustCM(cm)
	return e.cmLabels[cm]
}

// KEVID returns the CVE id of a KEV entry, e.g. "CVE-2021-44228".
func (e *Engine) KEVID(k KEV) string {
	e.mustKEV(k)
	return e.kevIDs[k]
}

// KEVName returns the vulnerability name of a KEV entry.
func (e *Engine) KEVName(k KEV) string {
	e.mustKEV(k)
	return e.kevNames[k]
}

// KEVAdded returns the date the entry was added to the catalog, e.g.
// "2021-12-10".
func (e *Engine) KEVAdded(k KEV) string {
	e.mustKEV(k)
	return e.kevAdded[k]
}

// KEVRansomware reports whether CISA links the entry to a known ransomware
// campaign.
func (e *Engine) KEVRansomware(k KEV) bool {
	e.mustKEV(k)
	return e.kevRansomware[k]
}

// CWEID returns the weakness id of a CWE, e.g. "CWE-78".
func (e *Engine) CWEID(c CWE) string {
	e.mustCWE(c)
	return e.cweIDs[c]
}

// KEVProductVendor returns the vendor of a product, e.g. "Apache".
func (e *Engine) KEVProductVendor(p Product) string {
	e.mustProduct(p)
	return e.productVendors[p]
}

// KEVProductName returns the product name of a product, e.g. "Log4j2".
func (e *Engine) KEVProductName(p Product) string {
	e.mustProduct(p)
	return e.productNames[p]
}

// KEVVendor returns the vendor of the product entry k is about.
func (e *Engine) KEVVendor(k KEV) string {
	e.mustKEV(k)
	return e.productVendors[e.kevProductID(k)]
}

// KEVProduct returns the product name entry k is about, e.g. "Log4j2".
func (e *Engine) KEVProduct(k KEV) string {
	e.mustKEV(k)
	return e.productNames[e.kevProductID(k)]
}

// kevProductID returns the product id of entry k, which Build guarantees to
// exist: every entry names exactly one product (ErrKEVWithoutProduct), so the
// row holds exactly one set bit.
func (e *Engine) kevProductID(k KEV) Product {
	p := Product(0)
	eachBit(e.row(e.kevProduct, e.kevProductOff(k), e.wProduct), func(i int) bool {
		p = Product(i)
		return false
	})
	return p
}

// TTPDomain returns the ATT&CK domain a technique came from.
func (e *Engine) TTPDomain(t TTP) Domain {
	e.mustTTP(t)
	return e.ttpDomains[t]
}

// Rel resolves an offensive relation name to its plane id. RelName(RelAny) is
// "any", and Rel("any") resolves back to RelAny, so every plane round-trips
// through name and id.
func (e *Engine) Rel(name string) (Rel, bool) {
	r, ok := e.relIndex[normalize(name)]
	return r, ok
}

// RelName returns the name of an offensive relation plane (RelAny -> "any").
func (e *Engine) RelName(r Rel) string {
	e.checkRel(r)
	return e.relNames[r]
}

// DefRel resolves a defensive relation name to its plane id. DefRelName(DefRelAny)
// is "any", and DefRel("any") resolves back to DefRelAny.
func (e *Engine) DefRel(name string) (DefRel, bool) {
	dr, ok := e.defRelIndex[normalize(name)]
	return dr, ok
}

// DefRelName returns the name of a defensive relation plane.
func (e *Engine) DefRelName(dr DefRel) string {
	e.checkDefRel(dr)
	return e.defRelNames[dr]
}

// Response formats technique ids as "<id> <label>" log lines, writing
// "<invalid ttp N>" for out-of-range ids. It returns the number of ids
// processed, which may exceed len(dst) when dst is too short.
func (e *Engine) Response(dst []string, ids []TTP) int {
	n := 0
	for _, id := range ids {
		if n < len(dst) {
			if int(id) >= e.nTTP {
				dst[n] = "<invalid ttp " + strconv.Itoa(int(id)) + ">"
			} else {
				dst[n] = e.ttpIDs[id] + " " + e.ttpLabels[id]
			}
		}
		n++
	}
	return n
}

// CountermeasureResponse formats countermeasure ids as "<id> <label>" log
// lines, writing "<invalid cm N>" for out-of-range ids. It returns the number
// of ids processed, which may exceed len(dst) when dst is too short.
func (e *Engine) CountermeasureResponse(dst []string, ids []Countermeasure) int {
	n := 0
	for _, id := range ids {
		if n < len(dst) {
			if int(id) >= e.nCM {
				dst[n] = "<invalid cm " + strconv.Itoa(int(id)) + ">"
			} else {
				dst[n] = e.cmIDs[id] + " " + e.cmLabels[id]
			}
		}
		n++
	}
	return n
}

// --- hierarchy ---

// TTPParent returns the parent of a sub-technique. A top-level technique (or
// an out-of-range id) returns (0, false).
func (e *Engine) TTPParent(t TTP) (TTP, bool) {
	if !e.okTTP(t) {
		return 0, false
	}
	p := e.ttpParents[t]
	if p == uint16(NoParent) {
		return 0, false
	}
	return TTP(p), true
}

// TTPChildCount returns the number of direct sub-techniques of t (0 for leaves
// and out-of-range ids).
func (e *Engine) TTPChildCount(t TTP) int {
	if !e.okTTP(t) {
		return 0
	}
	return int(e.ttpChildCount[t])
}

// TTPRevoked reports whether ATT&CK revoked (or deprecated) the technique, which
// is the flag Incident's label resolution prefers the live twin by.
func (e *Engine) TTPRevoked(t TTP) bool {
	e.mustTTP(t)
	return e.ttpRevoked[t]
}

// TTPChildren writes the direct sub-technique ids of t into dst (truncated to
// len(dst)) and returns the total number of children.
func (e *Engine) TTPChildren(t TTP, dst []TTP) int {
	n := e.TTPChildCount(t)
	for i := range n {
		if i < len(dst) {
			dst[i] = TTP(int(t) + 1 + i)
		}
	}
	return n
}

// --- hot path: offensive traversals ---

// Adjacent reports whether technique t is linked to artifact a under any
// relation.
func (e *Engine) Adjacent(t TTP, a Artifact) bool { return e.AdjacentRel(t, a, RelAny) }

// AdjacentRel reports whether t -> a holds under relation r (RelAny for the
// union plane).
func (e *Engine) AdjacentRel(t TTP, a Artifact, r Rel) bool {
	e.checkRel(r)
	if !e.okTTP(t) || !e.okArt(a) {
		return false
	}
	return testBit(e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt), int(a))
}

// Artifacts writes the artifacts linked to t under any relation into dst,
// truncated to len(dst), and returns the total number of matches.
func (e *Engine) Artifacts(t TTP, dst []Artifact) int { return e.ArtifactsRel(t, RelAny, dst) }

// ArtifactsRel is Artifacts restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsRel(t TTP, r Rel, dst []Artifact) int {
	e.checkRel(r)
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt), dst)
}

// TTPs writes the techniques linked to a under any relation into dst,
// truncated to len(dst), and returns the total number of matches.
func (e *Engine) TTPs(a Artifact, dst []TTP) int { return e.TTPsRel(a, RelAny, dst) }

// TTPsRel is TTPs restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsRel(a Artifact, r Rel, dst []TTP) int {
	e.checkRel(r)
	if !e.okArt(a) {
		return 0
	}
	return enumerate(e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP), dst)
}

// Degree returns the number of artifacts linked from t under r.
func (e *Engine) Degree(t TTP, r Rel) int {
	e.checkRel(r)
	if !e.okTTP(t) {
		return 0
	}
	return popcountRow(e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
}

// ArtifactDegree returns the number of techniques linked to a under r.
func (e *Engine) ArtifactDegree(a Artifact, r Rel) int {
	e.checkRel(r)
	if !e.okArt(a) {
		return 0
	}
	return popcountRow(e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
}

// --- hot path: set operations over artifact / technique slices ---

// TTPsAny writes the union of the technique rows of arts under r. Ids outside
// the artifact partition are ignored; an empty (or all-invalid) input yields 0.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsAny(r Rel, scratch []uint64, dst []TTP, arts []Artifact) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	for _, a := range arts {
		if !e.okArt(a) {
			continue
		}
		orRowInto(row, e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
	}
	return enumerate(row, dst)
}

// TTPsAll writes the intersection of the technique rows of arts under r.
// Invalid ids are ignored; if none remain the result is empty.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsAll(r Rel, scratch []uint64, dst []TTP, arts []Artifact) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	first := true
	for _, a := range arts {
		if !e.okArt(a) {
			continue
		}
		if first {
			copyRow(row, e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
			first = false
			continue
		}
		andRowInto(row, e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP))
	}
	return enumerate(row, dst)
}

// ArtifactsAny writes the union of the artifact rows of ttps under r.
// Ids outside the technique partition are ignored; an empty (or all-invalid)
// input yields 0.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsAny(r Rel, scratch []uint64, dst []Artifact, ttps []TTP) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindArtifact)
	row := scratch[:e.wArt]
	clear(row)
	for _, t := range ttps {
		if !e.okTTP(t) {
			continue
		}
		orRowInto(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
	}
	return enumerate(row, dst)
}

// ArtifactsAll writes the intersection of the artifact rows of ttps under r.
// Ids outside the technique partition are ignored; an empty (or all-invalid)
// input yields 0.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsAll(r Rel, scratch []uint64, dst []Artifact, ttps []TTP) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindArtifact)
	row := scratch[:e.wArt]
	clear(row)
	first := true
	for _, t := range ttps {
		if !e.okTTP(t) {
			continue
		}
		if first {
			copyRow(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
			first = false
			continue
		}
		andRowInto(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
	}
	return enumerate(row, dst)
}

// --- hot path: roll-up over the technique hierarchy ---

// ArtifactsRollup writes the union of the artifact rows of t and all its
// direct sub-techniques under any relation. For a sub-technique this is
// exactly its own row (the hierarchy is two levels deep).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsRollup(t TTP, scratch []uint64, dst []Artifact) int {
	return e.ArtifactsRollupRel(t, RelAny, scratch, dst)
}

// ArtifactsRollupRel is ArtifactsRollup restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsRollupRel(t TTP, r Rel, scratch []uint64, dst []Artifact) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindArtifact)
	if !e.okTTP(t) {
		return 0
	}
	row := scratch[:e.wArt]
	copyRow(row, e.row(e.ttpArt, e.ttpArtOff(r, t), e.wArt))
	for c := int(t) + 1; c <= int(t)+int(e.ttpChildCount[t]); c++ {
		orRowInto(row, e.row(e.ttpArt, e.ttpArtOff(r, TTP(c)), e.wArt))
	}
	return enumerate(row, dst)
}

// TTPsRollup writes the techniques linked to a under any relation, with every
// sub-technique collapsed onto its parent.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsRollup(a Artifact, scratch []uint64, dst []TTP) int {
	return e.TTPsRollupRel(a, RelAny, scratch, dst)
}

// TTPsRollupRel is TTPsRollup restricted to relation r.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsRollupRel(a Artifact, r Rel, scratch []uint64, dst []TTP) int {
	e.checkRel(r)
	e.checkScratch(scratch, KindTTP)
	if !e.okArt(a) {
		return 0
	}
	row := scratch[:e.wTTP]
	clear(row)
	eachBit(e.row(e.artTTP, e.artTTPOff(r, a), e.wTTP), func(x int) bool {
		if p := e.ttpParents[x]; p != uint16(NoParent) {
			setBit(row, int(p))
		} else {
			setBit(row, x)
		}
		return true
	})
	return enumerate(row, dst)
}

// --- hot path: countermeasure queries ---

// Defends reports whether countermeasure cm defends technique t.
func (e *Engine) Defends(cm Countermeasure, t TTP) bool {
	if !e.okCM(cm) || !e.okTTP(t) {
		return false
	}
	return testBit(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP), int(t))
}

// CountermeasuresForTTP writes the countermeasures defending exactly t.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CountermeasuresForTTP(t TTP, dst []Countermeasure) int {
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpCM, e.ttpCMOff(t), e.wCM), dst)
}

// CountermeasuresForTTPRollup writes the union of the countermeasures
// defending t and all its direct sub-techniques.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CountermeasuresForTTPRollup(t TTP, scratch []uint64, dst []Countermeasure) int {
	e.checkScratch(scratch, KindCountermeasure)
	if !e.okTTP(t) {
		return 0
	}
	row := scratch[:e.wCM]
	copyRow(row, e.row(e.ttpCM, e.ttpCMOff(t), e.wCM))
	for c := int(t) + 1; c <= int(t)+int(e.ttpChildCount[t]); c++ {
		orRowInto(row, e.row(e.ttpCM, e.ttpCMOff(TTP(c)), e.wCM))
	}
	return enumerate(row, dst)
}

// CountermeasuresForArtifact writes the countermeasures directly linked to a
// under defensive relation dr (DefRelAny for the union plane).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CountermeasuresForArtifact(a Artifact, dr DefRel, dst []Countermeasure) int {
	e.checkDefRel(dr)
	if !e.okArt(a) {
		return 0
	}
	return enumerate(e.row(e.artCM, e.artCMOff(dr, a), e.wCM), dst)
}

// CountermeasuresForArtifactViaTTPs writes the countermeasure surface of a:
// the countermeasures directly linked to a, unioned with the countermeasures
// defending every technique that touches a. Techniques are used exactly as
// linked (no hierarchy roll-up) — see the package documentation.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CountermeasuresForArtifactViaTTPs(a Artifact, scratch []uint64, dst []Countermeasure) int {
	e.checkScratch(scratch, KindCountermeasure)
	if !e.okArt(a) {
		return 0
	}
	row := scratch[:e.wCM]
	clear(row)
	eachBit(e.row(e.artTTP, e.artTTPOff(RelAny, a), e.wTTP), func(t int) bool {
		orRowInto(row, e.row(e.ttpCM, e.ttpCMOff(TTP(t)), e.wCM))
		return true
	})
	eachBit(e.row(e.artCM, e.artCMOff(DefRelAny, a), e.wCM), func(cm int) bool {
		setBit(row, cm)
		return true
	})
	return enumerate(row, dst)
}

// ArtifactsForCountermeasure writes the artifacts linked from cm under
// defensive relation dr (DefRelAny for the union plane).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ArtifactsForCountermeasure(cm Countermeasure, dr DefRel, dst []Artifact) int {
	e.checkDefRel(dr)
	if !e.okCM(cm) {
		return 0
	}
	return enumerate(e.row(e.cmArt, e.cmArtOff(dr, cm), e.wArt), dst)
}

// TTPsForCountermeasure writes the techniques defended by cm, exactly as
// linked (sub-technique ids included).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForCountermeasure(cm Countermeasure, dst []TTP) int {
	if !e.okCM(cm) {
		return 0
	}
	return enumerate(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP), dst)
}

// TTPsForCountermeasureRollup is TTPsForCountermeasure with every
// sub-technique collapsed onto its parent.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForCountermeasureRollup(cm Countermeasure, scratch []uint64, dst []TTP) int {
	e.checkScratch(scratch, KindTTP)
	if !e.okCM(cm) {
		return 0
	}
	row := scratch[:e.wTTP]
	clear(row)
	eachBit(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP), func(t int) bool {
		if p := e.ttpParents[t]; p != uint16(NoParent) {
			setBit(row, int(p))
		} else {
			setBit(row, t)
		}
		return true
	})
	return enumerate(row, dst)
}

// CountermeasureDegree returns the number of techniques defended by cm.
func (e *Engine) CountermeasureDegree(cm Countermeasure) int {
	if !e.okCM(cm) {
		return 0
	}
	return popcountRow(e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP))
}

// --- hot path: coverage overlay (mask-driven) ---

// TTPsMapped writes the techniques with at least one defends-against edge — the
// range of the D3FEND mapping, i.e. the set the coverage states are measured
// against — and returns the total. It is the union of every cmTTP row, computed
// per call rather than stored: the union is derivable and the engine keeps no
// duplicate of a derivable row.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsMapped(scratch []uint64, dst []TTP) int {
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	for cm := range e.nCM {
		orRowInto(row, e.row(e.cmTTP, e.cmTTPOff(Countermeasure(cm)), e.wTTP))
	}
	return enumerate(row, dst)
}

// TTPsCovered writes the techniques defended by any countermeasure the
// selection names: the union of the selected cmTTP rows. A selection bit past
// the live countermeasure range selects no row, so a stale inventory cannot
// fail.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsCovered(sel Selection, scratch []uint64, dst []TTP) int {
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	return enumerate(row, dst)
}

// TTPsBlind writes the techniques that are active and not covered: active &^
// covered, i.e. the blind spots of a deployed set. Both selections are
// caller-owned; active is over techniques, sel over countermeasures. active is
// a selection like any other, so a bit past the technique range selects nothing
// rather than inventing an id.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsBlind(active Selection, sel Selection, scratch []uint64, dst []TTP) int {
	e.checkSelection(active, KindTTP)
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	// row is now the covered set; mask it out of the active set. A row kernel
	// cannot do this in place — the operation reads two different slices — so
	// the loop is the whole computation.
	for i := range row {
		row[i] = active[i] &^ row[i]
	}
	// The active side is the only direct-enumeration path in the overlay, so it
	// is the one that must mask its own tail: the covered side is a selection
	// walked through orSelectedRowsInto, which ignores a row past the block.
	maskTail(row, e.nTTP)
	return enumerate(row, dst)
}

// CoverageGain returns how many techniques cm would newly cover on top of the
// deployed selection: popcount(cmTTP[cm] &^ covered(sel)). It is the marginal
// value of adding one countermeasure, the number a procurement ranking sorts
// by. An out-of-range cm yields 0.
func (e *Engine) CoverageGain(cm Countermeasure, sel Selection, scratch []uint64) int {
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	if !e.okCM(cm) {
		return 0
	}
	n := 0
	for i, w := range e.row(e.cmTTP, e.cmTTPOff(cm), e.wTTP) {
		n += bits.OnesCount64(w &^ row[i])
	}
	return n
}

// CoverageGains writes the marginal gain of every countermeasure against one
// deployment: dst[cm] is what cm would newly cover on top of covered(sel), the
// number CoverageGain returns for a single candidate. The covered union is
// computed once for the whole scan, so ranking every countermeasure costs one
// selected-row union instead of one union per candidate. Countermeasures at and
// beyond len(dst) are counted but not written; the return value is the number of
// countermeasures with a positive gain.
func (e *Engine) CoverageGains(sel Selection, scratch []uint64, dst []int) int {
	e.checkSelection(sel, KindCountermeasure)
	e.checkScratch(scratch, KindTTP)
	row := scratch[:e.wTTP]
	clear(row)
	orSelectedRowsInto(row, sel, e.cmTTP, e.wTTP)
	n := 0
	for cm := range e.nCM {
		g := 0
		for i, w := range e.row(e.cmTTP, e.cmTTPOff(Countermeasure(cm)), e.wTTP) {
			g += bits.OnesCount64(w &^ row[i])
		}
		if g > 0 {
			n++
		}
		if cm < len(dst) {
			dst[cm] = g
		}
	}
	return n
}

// CountermeasuresForObserved writes the countermeasures of any observed
// technique: the union of the selected ttpCM rows, i.e. the mitigation set for
// the current state of an intrusion. observed is over techniques.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CountermeasuresForObserved(observed Selection, scratch []uint64, dst []Countermeasure) int {
	e.checkSelection(observed, KindTTP)
	e.checkScratch(scratch, KindCountermeasure)
	row := scratch[:e.wCM]
	clear(row)
	orSelectedRowsInto(row, observed, e.ttpCM, e.wCM)
	return enumerate(row, dst)
}

// --- hot path: attributes, data components and groups ---

// TTPTactics returns the tactic mask of t: bit i is TacticID(i). It is 0 for a
// technique with no ATT&CK tactic (the D3FEND-named nodes), for an
// out-of-range id, and on an engine that registered no tactics (the row would
// have no words). One word per technique, so the read is a single load.
func (e *Engine) TTPTactics(t TTP) uint64 {
	if !e.okTTP(t) || e.nTactic == 0 {
		return 0
	}
	return e.ttpTactic[e.ttpTacticOff(t)]
}

// TTPPlatforms returns the platform mask of t: bit i is PlatformName(i). It is 0
// for an out-of-range id and on an engine that registered no platforms.
func (e *Engine) TTPPlatforms(t TTP) uint64 {
	if !e.okTTP(t) || e.nPlatform == 0 {
		return 0
	}
	return e.ttpPlatform[e.ttpPlatformOff(t)]
}

// TTPFlags returns the attribute flags of t: FlagSubTechnique for a
// sub-technique, 0 for a top-level technique or an out-of-range id. Build
// derives the bit from the hierarchy.
func (e *Engine) TTPFlags(t TTP) uint64 {
	if !e.okTTP(t) {
		return 0
	}
	return e.ttpFlags[e.ttpFlagsOff(t)]
}

// TTPSubTechnique reports whether t is a sub-technique (TTPFlags bit
// FlagSubTechnique).
func (e *Engine) TTPSubTechnique(t TTP) bool {
	return e.TTPFlags(t)&FlagSubTechnique != 0
}

// TTPsForTactic writes the techniques of tactic ta.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForTactic(ta Tactic, dst []TTP) int {
	if int(ta) >= e.nTactic {
		return 0
	}
	return enumerate(e.row(e.tacticTTP, e.tacticTTPOff(ta), e.wTTP), dst)
}

// TTPsForPlatform writes the techniques that run on platform p.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForPlatform(p Platform, dst []TTP) int {
	if int(p) >= e.nPlatform {
		return 0
	}
	return enumerate(e.row(e.platformTTP, e.platformTTPOff(p), e.wTTP), dst)
}

// TTPsForDataComponent writes the techniques dc's log sources can detect.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForDataComponent(dc DataComponent, dst []TTP) int {
	if !e.okDC(dc) {
		return 0
	}
	return enumerate(e.row(e.dcTTP, e.dcTTPOff(dc), e.wTTP), dst)
}

// DataComponentsForTTP writes the data components that detect exactly t.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) DataComponentsForTTP(t TTP, dst []DataComponent) int {
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpDC, e.ttpDCOff(t), e.wDC), dst)
}

// DataComponentsForTTPRollup writes the union of the data components detecting
// t and all its direct sub-techniques: the ATT&CK detections hang off the
// sub-technique, so a parent's own row is usually empty.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) DataComponentsForTTPRollup(t TTP, scratch []uint64, dst []DataComponent) int {
	e.checkScratch(scratch, KindDataComponent)
	if !e.okTTP(t) {
		return 0
	}
	row := scratch[:e.wDC]
	copyRow(row, e.row(e.ttpDC, e.ttpDCOff(t), e.wDC))
	for c := int(t) + 1; c <= int(t)+int(e.ttpChildCount[t]); c++ {
		orRowInto(row, e.row(e.ttpDC, e.ttpDCOff(TTP(c)), e.wDC))
	}
	return enumerate(row, dst)
}

// DataComponentDegree returns the number of techniques dc can detect.
func (e *Engine) DataComponentDegree(dc DataComponent) int {
	if !e.okDC(dc) {
		return 0
	}
	return popcountRow(e.row(e.dcTTP, e.dcTTPOff(dc), e.wTTP))
}

// TTPsForGroup writes the techniques g is recorded as using, exactly as linked
// (sub-techniques stay sub-techniques).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForGroup(g Group, dst []TTP) int {
	if !e.okGroup(g) {
		return 0
	}
	return enumerate(e.row(e.grpTTP, e.grpTTPOff(g), e.wTTP), dst)
}

// TTPsForGroupRollup is TTPsForGroup with every sub-technique collapsed onto
// its parent.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) TTPsForGroupRollup(g Group, scratch []uint64, dst []TTP) int {
	e.checkScratch(scratch, KindTTP)
	if !e.okGroup(g) {
		return 0
	}
	row := scratch[:e.wTTP]
	clear(row)
	eachBit(e.row(e.grpTTP, e.grpTTPOff(g), e.wTTP), func(t int) bool {
		if p := e.ttpParents[t]; p != uint16(NoParent) {
			setBit(row, int(p))
		} else {
			setBit(row, t)
		}
		return true
	})
	return enumerate(row, dst)
}

// GroupsForTTP writes every grouping node — actor, software or campaign — that
// uses t. Filter with GroupKind on the results for one kind.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) GroupsForTTP(t TTP, dst []Group) int {
	if !e.okTTP(t) {
		return 0
	}
	return enumerate(e.row(e.ttpGrp, e.ttpGrpOff(t), e.wGrp), dst)
}

// SoftwareForGroup writes the software g uses (empty for a software node).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) SoftwareForGroup(g Group, dst []Group) int {
	if !e.okGroup(g) {
		return 0
	}
	return enumerate(e.row(e.grpSoftware, e.grpSoftwareOff(g), e.wGrp), dst)
}

// GroupsForSoftware writes the actors and campaigns recorded as using software
// node g (empty for an actor or campaign).
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) GroupsForSoftware(g Group, dst []Group) int {
	if !e.okGroup(g) {
		return 0
	}
	return enumerate(e.row(e.softwareGrp, e.softwareGrpOff(g), e.wGrp), dst)
}

// SoftwareDegree returns the number of software nodes g uses.
func (e *Engine) SoftwareDegree(g Group) int {
	if !e.okGroup(g) {
		return 0
	}
	return popcountRow(e.row(e.grpSoftware, e.grpSoftwareOff(g), e.wGrp))
}

// --- hot path: KEV, weakness and product queries ---

// KEVCWEDegree returns the number of weaknesses entry k names (0 for an
// out-of-range id).
func (e *Engine) KEVCWEDegree(k KEV) int {
	if !e.okKEV(k) {
		return 0
	}
	return popcountRow(e.row(e.kevCWE, e.kevCWEOff(k), e.wCWE))
}

// CWEsForKEV writes the weaknesses entry k names.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) CWEsForKEV(k KEV, dst []CWE) int {
	if !e.okKEV(k) {
		return 0
	}
	return enumerate(e.row(e.kevCWE, e.kevCWEOff(k), e.wCWE), dst)
}

// KEVsForCWE writes the entries naming weakness c.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) KEVsForCWE(c CWE, dst []KEV) int {
	if !e.okCWE(c) {
		return 0
	}
	return enumerate(e.row(e.cweKEV, e.cweKEVOff(c), e.wKEV), dst)
}

// ProductsForKEV writes the product of entry k: exactly one id for a catalog
// entry, none for an out-of-range id.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) ProductsForKEV(k KEV, dst []Product) int {
	if !e.okKEV(k) {
		return 0
	}
	return enumerate(e.row(e.kevProduct, e.kevProductOff(k), e.wProduct), dst)
}

// KEVsForProducts writes the union of the selected productKEV rows: the entries
// that apply to any of the products an asset inventory names. sel is over
// products; a bit past the live range selects no row.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) KEVsForProducts(sel Selection, scratch []uint64, dst []KEV) int {
	e.checkSelection(sel, KindProduct)
	e.checkScratch(scratch, KindKEV)
	row := scratch[:e.wKEV]
	clear(row)
	orSelectedRowsInto(row, sel, e.productKEV, e.wKEV)
	return enumerate(row, dst)
}

// KEVsForCWEs writes the union of the selected cweKEV rows: the entries in any
// of the named weakness classes. sel is over weaknesses.
// Results are truncated to len(dst) and the return value is the total number
// of matches.
func (e *Engine) KEVsForCWEs(sel Selection, scratch []uint64, dst []KEV) int {
	e.checkSelection(sel, KindCWE)
	e.checkScratch(scratch, KindKEV)
	row := scratch[:e.wKEV]
	clear(row)
	orSelectedRowsInto(row, sel, e.cweKEV, e.wKEV)
	return enumerate(row, dst)
}

// enumerate writes the set bits of row into dst as ascending ids of type T
// (truncated to len(dst)) and returns the total number of set bits.
func enumerate[T ~uint16](row []uint64, dst []T) int {
	n := 0
	eachBit(row, func(i int) bool {
		if n < len(dst) {
			dst[n] = T(i)
		}
		n++
		return true
	})
	return n
}
