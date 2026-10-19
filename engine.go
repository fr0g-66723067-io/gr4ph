//go:build goexperiment.simd

package gr4ph

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
// DefRelCount()+1), a Kind that WordsPerRow does not map (the engine has eight
// row-strided partitions but only seven Kinds: grouping rows are always read
// into a caller-sized dst, never through the scratch/selection protocol, so no
// Kind names them; WordsPerRow panics "gr4ph: unknown kind"), or a scratch row
// shorter than WordsPerRow(returned partition). The scratch check runs before
// the id bounds check, so an undersized scratch panics even when the id is out
// of range.
//
// The overlay queries take a caller-owned Selection and never retain it; a
// selection shorter than WordsPerRow of the partition it selects panics
// "gr4ph: selection too small", the same class of engine misuse as an
// undersized scratch row.
//
// The cold accessors that take a dense id panic on an out-of-range id: the id
// and label getters (TTPName, TTPLabel, TTPDomain, KEVID, KEVName, KEVAdded,
// CWEID, KEVProductVendor, KEVProductName, KEVVendor, KEVProduct, ...), the
// flag getters (TTPRevoked, GroupKind, GroupRevoked, KEVRansomware), and the
// relation-name getters (RelName, DefRelName). Response and
// CountermeasureResponse are the total boundary formatters that render
// "<invalid ...>" instead.
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
	// and every directed relation is materialized in both directions.
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

	// The revoked-or-deprecated flag as a row. The coverage overlay masks it out
	// of a marginal gain, so a retired technique is never a purchase target; the
	// cold ttpRevoked list below cannot serve a row scan.
	ttpRevokedRow []uint64 // [nTTP]

	dcTTP       []uint64 // [nDC][wTTP]       data component -> techniques
	ttpDC       []uint64 // [nTTP][wDC]       technique -> data components
	grpTTP      []uint64 // [nGrp][wTTP]      group -> techniques
	ttpGrp      []uint64 // [nTTP][wGrp]      technique -> groups
	grpSoftware []uint64 // [nGrp][wGrp]      group -> software
	softwareGrp []uint64 // [nGrp][wGrp]      software -> groups

	// The KEV catalog: the entry partition, the weakness vocabulary it names
	// and the product vocabulary it is about. Both families are materialized in
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

	groupIDs     []string
	groupLabels  []string
	groupKinds   []GroupKind
	groupRevoked []bool

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
func (e *Engine) okTactic(ta Tactic) bool     { return int(ta) < e.nTactic }
func (e *Engine) okPlatform(p Platform) bool  { return int(p) < e.nPlatform }

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
// kinds of the KEV queries and the partition kinds their selections index.
// It panics if cols is not one of the seven Kinds it maps.
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
