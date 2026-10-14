//go:build goexperiment.simd

package gr4ph

import "strconv"

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
// id. Labels are unique within a kind up to case folding, with one exception on
// the pinned tables: two software nodes pair up under the key "ngrok" (S0508 and
// S9000) and two under "triton" (S0609 and S1009). Across kinds a shared label
// is normal ("Frankenstein" is both C0001 and G0101), and a shared label
// resolves to its live carrier, or to the lowest-index holder when every carrier
// is revoked — the rule GroupRevoked reports the flag for.
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
// It panics if ta is out of range.
func (e *Engine) TacticID(ta Tactic) string {
	e.mustTactic(ta)
	return e.tacticIDs[ta]
}

// TacticLabel returns the tactic label, e.g. "Stealth". Labels repeat across
// domains: TacticID is the unambiguous key.
// It panics if ta is out of range.
func (e *Engine) TacticLabel(ta Tactic) string {
	e.mustTactic(ta)
	return e.tacticLabels[ta]
}

// PlatformName returns the platform name, e.g. "Windows".
// It panics if p is out of range.
func (e *Engine) PlatformName(p Platform) string {
	e.mustPlatform(p)
	return e.platformNames[p]
}

// DataComponentID returns the data component id string, e.g. "DC0084".
// It panics if dc is out of range.
func (e *Engine) DataComponentID(dc DataComponent) string {
	e.mustDC(dc)
	return e.dcIDs[dc]
}

// DataComponentLabel returns the data component label, e.g. "Active Directory
// Credential Request".
// It panics if dc is out of range.
func (e *Engine) DataComponentLabel(dc DataComponent) string {
	e.mustDC(dc)
	return e.dcLabels[dc]
}

// GroupID returns the grouping-node id string, e.g. "G0007".
// It panics if g is out of range.
func (e *Engine) GroupID(g Group) string {
	e.mustGroup(g)
	return e.groupIDs[g]
}

// GroupLabel returns the grouping-node label, e.g. "APT28".
// It panics if g is out of range.
func (e *Engine) GroupLabel(g Group) string {
	e.mustGroup(g)
	return e.groupLabels[g]
}

// GroupKind returns the ATT&CK object type of g: GroupActor, GroupSoftware or
// GroupCampaign.
// It panics if g is out of range.
func (e *Engine) GroupKind(g Group) GroupKind {
	e.mustGroup(g)
	return e.groupKinds[g]
}

// GroupRevoked reports whether ATT&CK revoked (or deprecated) the grouping
// node, which is the flag the label resolution prefers the live twin by.
// It panics if g is out of range.
func (e *Engine) GroupRevoked(g Group) bool {
	e.mustGroup(g)
	return e.groupRevoked[g]
}

// TTPName returns the technique id string, e.g. "T1003.001".
// It panics if t is out of range.
func (e *Engine) TTPName(t TTP) string {
	e.mustTTP(t)
	return e.ttpIDs[t]
}

// TTPLabel returns the technique label, e.g. "LSASS Memory".
// It panics if t is out of range.
func (e *Engine) TTPLabel(t TTP) string {
	e.mustTTP(t)
	return e.ttpLabels[t]
}

// ArtifactName returns the artifact name, e.g. "CreateProcess".
// It panics if a is out of range.
func (e *Engine) ArtifactName(a Artifact) string {
	e.mustArt(a)
	return e.artNames[a]
}

// ArtifactLabel returns the artifact label, e.g. "Create Process".
// It panics if a is out of range.
func (e *Engine) ArtifactLabel(a Artifact) string {
	e.mustArt(a)
	return e.artLabels[a]
}

// CountermeasureName returns the countermeasure local name.
// It panics if cm is out of range.
func (e *Engine) CountermeasureName(cm Countermeasure) string {
	e.mustCM(cm)
	return e.cmIDs[cm]
}

// CountermeasureLabel returns the countermeasure label.
// It panics if cm is out of range.
func (e *Engine) CountermeasureLabel(cm Countermeasure) string {
	e.mustCM(cm)
	return e.cmLabels[cm]
}

// KEVID returns the CVE id of a KEV entry, e.g. "CVE-2021-44228".
// It panics if k is out of range.
func (e *Engine) KEVID(k KEV) string {
	e.mustKEV(k)
	return e.kevIDs[k]
}

// KEVName returns the vulnerability name of a KEV entry.
// It panics if k is out of range.
func (e *Engine) KEVName(k KEV) string {
	e.mustKEV(k)
	return e.kevNames[k]
}

// KEVAdded returns the date the entry was added to the catalog, e.g.
// "2021-12-10".
// It panics if k is out of range.
func (e *Engine) KEVAdded(k KEV) string {
	e.mustKEV(k)
	return e.kevAdded[k]
}

// KEVRansomware reports whether CISA links the entry to a known ransomware
// campaign.
// It panics if k is out of range.
func (e *Engine) KEVRansomware(k KEV) bool {
	e.mustKEV(k)
	return e.kevRansomware[k]
}

// CWEID returns the weakness id of a CWE, e.g. "CWE-78".
// It panics if c is out of range.
func (e *Engine) CWEID(c CWE) string {
	e.mustCWE(c)
	return e.cweIDs[c]
}

// KEVProductVendor returns the vendor of a product, e.g. "Apache".
// It panics if p is out of range.
func (e *Engine) KEVProductVendor(p Product) string {
	e.mustProduct(p)
	return e.productVendors[p]
}

// KEVProductName returns the product name of a product, e.g. "Log4j2".
// It panics if p is out of range.
func (e *Engine) KEVProductName(p Product) string {
	e.mustProduct(p)
	return e.productNames[p]
}

// KEVVendor returns the vendor of the product entry k is about.
// It panics if k is out of range.
func (e *Engine) KEVVendor(k KEV) string {
	e.mustKEV(k)
	return e.productVendors[e.kevProductID(k)]
}

// KEVProduct returns the product name entry k is about, e.g. "Log4j2".
// It panics if k is out of range.
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
// It panics if t is out of range.
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
// It panics if r is out of range.
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
// It panics if dr is out of range.
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
// It panics if t is out of range.
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
