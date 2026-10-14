//go:build goexperiment.simd

package gr4ph

import "strings"

// --- registration: relation planes, vocabularies, nodes and edges ---
//
// The relation, vocabulary and node registrations are idempotent on the
// normalised key, seed the zero value first, and reject a used Builder with
// ErrBuilderUsed. The edge registrations append to their index lists instead,
// where a duplicate is harmless (each edge method says so).

// AddRel registers an offensive relation predicate and returns its plane id
// (1..255). Idempotent on the normalised name. The name "any" is reserved for the
// union plane (RelAny) and returns ErrReservedName.
func (b *Builder) AddRel(name string) (Rel, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(name)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if key == reservedRelName {
		return 0, ErrReservedName
	}
	if r, ok := b.relIndex[key]; ok {
		return r, nil
	}
	if len(b.relNames) >= 256 {
		return 0, ErrTooManyRels
	}
	r := Rel(len(b.relNames))
	b.relNames = append(b.relNames, strings.TrimSpace(name))
	b.relIndex[key] = r
	return r, nil
}

// AddDefRel registers a defensive relation predicate and returns its plane id
// (1..255). Idempotent on the normalised name. The name "any" is reserved for the
// union plane (DefRelAny) and returns ErrReservedName.
func (b *Builder) AddDefRel(name string) (DefRel, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(name)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if key == reservedRelName {
		return 0, ErrReservedName
	}
	if dr, ok := b.defRelIndex[key]; ok {
		return dr, nil
	}
	if len(b.defRelNames) >= 256 {
		return 0, ErrTooManyRels
	}
	dr := DefRel(len(b.defRelNames))
	b.defRelNames = append(b.defRelNames, strings.TrimSpace(name))
	b.defRelIndex[key] = dr
	return dr, nil
}

// AddTactic registers an ATT&CK tactic and returns its dense id (0..63). It is
// idempotent on the normalised TA id. The TA id is the only lookup key: tactic
// labels repeat across domains ("Impact" is TA0040, TA0105 and TA0034), so a
// label key would be ambiguous.
//
// The space is 64 because a technique's tactic mask is one uint64 (bit i is
// TacticID(i)): 64 entries keep every stride at one word, so no bit a tactic edge
// writes can fall outside the word TTPTactics reads.
func (b *Builder) AddTactic(id, label string) (Tactic, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if ta, ok := b.tacticIndex[key]; ok {
		return Tactic(ta), nil
	}
	if len(b.tacticIDs) >= 64 {
		return 0, ErrTooManyTactics
	}
	ta := Tactic(len(b.tacticIDs))
	b.tacticIDs = append(b.tacticIDs, strings.TrimSpace(id))
	b.tacticLabels = append(b.tacticLabels, strings.TrimSpace(label))
	b.tacticIndex[key] = uint16(ta)
	return ta, nil
}

// AddPlatform registers a platform and returns its dense id (0..63). It is
// idempotent on the normalised name. The space is 64 for the same reason
// AddTactic's is: a technique's platform mask is one uint64.
func (b *Builder) AddPlatform(name string) (Platform, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(name)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if p, ok := b.platformIndex[key]; ok {
		return Platform(p), nil
	}
	if len(b.platformNames) >= 64 {
		return 0, ErrTooManyPlatforms
	}
	p := Platform(len(b.platformNames))
	b.platformNames = append(b.platformNames, strings.TrimSpace(name))
	b.platformIndex[key] = uint16(p)
	return p, nil
}

// AddDataComponent registers a data component and returns its dense id.
// Idempotent on the normalised id; the label is a lookup key too. Ids and labels
// share one key map, so a key that normalises to an existing one returns that
// node as well: first registration wins.
func (b *Builder) AddDataComponent(id, label string) (DataComponent, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if dc, ok := b.dcIndex[key]; ok {
		return DataComponent(dc), nil
	}
	if len(b.dcIDs) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.dcIDs)
	b.dcIDs = append(b.dcIDs, strings.TrimSpace(id))
	b.dcLabels = append(b.dcLabels, strings.TrimSpace(label))
	claim(b.dcIndex, key, uint16(idx))
	claim(b.dcIndex, normalize(label), uint16(idx))
	return DataComponent(idx), nil
}

// AddGroup registers a grouping node — an actor, a piece of software or a
// campaign — and returns its dense id. Idempotent on the normalised id; the label
// is a lookup key too, resolved live-first as a technique's label is: a live node
// takes a shared label from a revoked holder, and the earliest registration keeps
// it between holders of the same standing. kind must be one of the three
// GroupKind constants. revoked marks an ATT&CK object that has been revoked or
// deprecated; it only decides who wins a shared label.
func (b *Builder) AddGroup(id, label string, kind GroupKind, revoked bool) (Group, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if g, ok := b.groupIndex[key]; ok {
		return Group(g), nil
	}
	if kind > GroupCampaign {
		return 0, ErrUnknownGroupKind
	}
	if len(b.groupIDs) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.groupIDs)
	b.groupIDs = append(b.groupIDs, strings.TrimSpace(id))
	b.groupLabels = append(b.groupLabels, strings.TrimSpace(label))
	b.groupKinds = append(b.groupKinds, kind)
	b.groupRevoked = append(b.groupRevoked, revoked)
	claim(b.groupIndex, key, uint16(idx))
	b.claimGroup(normalize(label), idx)
	return Group(idx), nil
}

// AddTTP registers a technique and returns its dense id. Idempotent on the
// normalised id: a second call with the same id returns the stored id and
// ignores its other arguments (label, domain, parent, revoked, aliases). Labels
// and aliases are lookup keys too, so an id that normalises to an existing label
// or alias returns that node as well: first registration wins, except that a
// live technique takes a label or alias from a revoked holder — see claimTTP.
// revoked marks an ATT&CK technique that has been revoked or deprecated; it only
// decides who wins a shared label or alias. parent must be
// NoParent or an already-registered top-level technique whose child block the
// new node extends contiguously. An id that normalises to the empty string
// returns ErrEmptyKey; a dom other than the four Domain constants returns
// ErrUnknownDomain.
func (b *Builder) AddTTP(id, label string, dom Domain, parent TTP, revoked bool, aliases ...string) (TTP, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if t, ok := b.ttpIndex[key]; ok {
		return TTP(t), nil
	}
	if dom > DomainSPARTA {
		return 0, ErrUnknownDomain
	}
	if len(b.ttpIDs) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.ttpIDs)
	if parent != NoParent {
		p := int(parent)
		// p >= idx: not registered yet (forward reference).
		if p >= idx {
			return 0, ErrUnknownParent
		}
		if uint16(b.ttpParents[p]) != uint16(NoParent) {
			return 0, ErrDepthExceeded
		}
		if idx != p+1+int(b.ttpChildCount[p]) {
			return 0, ErrNonContiguousChild
		}
	}

	b.ttpIDs = append(b.ttpIDs, strings.TrimSpace(id))
	b.ttpLabels = append(b.ttpLabels, strings.TrimSpace(label))
	b.ttpDomains = append(b.ttpDomains, dom)
	b.ttpParents = append(b.ttpParents, uint16(parent))
	b.ttpChildCount = append(b.ttpChildCount, 0)
	b.ttpRevoked = append(b.ttpRevoked, revoked)
	if parent != NoParent {
		b.ttpChildCount[int(parent)]++
	}

	claim(b.ttpIndex, key, uint16(idx))
	b.claimTTP(normalize(label), idx)
	for _, a := range aliases {
		b.claimTTP(normalize(a), idx)
	}
	return TTP(idx), nil
}

// AddArtifact registers an artifact and returns its dense id. Idempotent on the
// normalised name; the label is registered as a lookup key too. It takes no
// aliases: artifacts are looked up by name or label only. Names and labels share
// one key map, so a name that normalises to an existing label returns that node
// as well: first registration wins.
func (b *Builder) AddArtifact(name, label string) (Artifact, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(name)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if a, ok := b.artIndex[key]; ok {
		return Artifact(a), nil
	}
	if len(b.artNames) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.artNames)
	b.artNames = append(b.artNames, strings.TrimSpace(name))
	b.artLabels = append(b.artLabels, strings.TrimSpace(label))
	claim(b.artIndex, key, uint16(idx))
	claim(b.artIndex, normalize(label), uint16(idx))
	return Artifact(idx), nil
}

// AddCountermeasure registers a countermeasure and returns its dense id.
// Idempotent on the normalised id; label and aliases are lookup keys. Ids,
// labels and aliases share one key map, so a key that normalises to an existing
// one returns that node as well: first registration wins.
func (b *Builder) AddCountermeasure(id, label string, aliases ...string) (Countermeasure, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if cm, ok := b.cmIndex[key]; ok {
		return Countermeasure(cm), nil
	}
	if len(b.cmIDs) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.cmIDs)
	b.cmIDs = append(b.cmIDs, strings.TrimSpace(id))
	b.cmLabels = append(b.cmLabels, strings.TrimSpace(label))
	claim(b.cmIndex, key, uint16(idx))
	claim(b.cmIndex, normalize(label), uint16(idx))
	for _, a := range aliases {
		claim(b.cmIndex, normalize(a), uint16(idx))
	}
	return Countermeasure(idx), nil
}

// --- edges: ORed into the plane blocks by Build ---

// AddEdge records technique -> artifact under relation r. r must be a
// registered predicate (not RelAny). Duplicate edges are harmless.
func (b *Builder) AddEdge(t TTP, a Artifact, r Rel) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(t) >= len(b.ttpIDs) {
		return ErrUnknownTTP
	}
	if int(a) >= len(b.artNames) {
		return ErrUnknownArtifact
	}
	if r == RelAny || int(r) >= len(b.relNames) {
		return ErrUnknownRel
	}
	b.edgeT = append(b.edgeT, uint16(t))
	b.edgeA = append(b.edgeA, uint16(a))
	b.edgeR = append(b.edgeR, uint8(r))
	return nil
}

// AddDefEdge records countermeasure -> artifact under defensive relation dr.
// dr must be a registered predicate (not DefRelAny).
func (b *Builder) AddDefEdge(cm Countermeasure, a Artifact, dr DefRel) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(cm) >= len(b.cmIDs) {
		return ErrUnknownCountermeasure
	}
	if int(a) >= len(b.artNames) {
		return ErrUnknownArtifact
	}
	if dr == DefRelAny || int(dr) >= len(b.defRelNames) {
		return ErrUnknownDefRel
	}
	b.defEdgeC = append(b.defEdgeC, uint16(cm))
	b.defEdgeA = append(b.defEdgeA, uint16(a))
	b.defEdgeR = append(b.defEdgeR, uint8(dr))
	return nil
}

// AddDefendsEdge records countermeasure -> technique (defends-against). The
// family has a single inferred predicate, so no relation id is taken.
func (b *Builder) AddDefendsEdge(cm Countermeasure, t TTP) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(cm) >= len(b.cmIDs) {
		return ErrUnknownCountermeasure
	}
	if int(t) >= len(b.ttpIDs) {
		return ErrUnknownTTP
	}
	b.defendsC = append(b.defendsC, uint16(cm))
	b.defendsT = append(b.defendsT, uint16(t))
	return nil
}

// AddTacticEdge records technique -> tactic. ta must be a registered tactic.
func (b *Builder) AddTacticEdge(t TTP, ta Tactic) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(t) >= len(b.ttpIDs) {
		return ErrUnknownTTP
	}
	if int(ta) >= len(b.tacticIDs) {
		return ErrUnknownTactic
	}
	b.tacticT = append(b.tacticT, uint16(t))
	b.tacticTA = append(b.tacticTA, uint16(ta))
	return nil
}

// AddPlatformEdge records technique -> platform. p must be a registered platform.
func (b *Builder) AddPlatformEdge(t TTP, p Platform) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(t) >= len(b.ttpIDs) {
		return ErrUnknownTTP
	}
	if int(p) >= len(b.platformNames) {
		return ErrUnknownPlatform
	}
	b.platformT = append(b.platformT, uint16(t))
	b.platformP = append(b.platformP, uint16(p))
	return nil
}

// AddDetectsEdge records data component -> technique: the component's log
// sources can detect the technique. The family has a single inferred predicate.
func (b *Builder) AddDetectsEdge(dc DataComponent, t TTP) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(dc) >= len(b.dcIDs) {
		return ErrUnknownDataComponent
	}
	if int(t) >= len(b.ttpIDs) {
		return ErrUnknownTTP
	}
	b.detectsDC = append(b.detectsDC, uint16(dc))
	b.detectsTTP = append(b.detectsTTP, uint16(t))
	return nil
}

// AddGroupUsesEdge records group -> technique: an actor or campaign uses the
// technique, or a piece of software implements it. The family has a single
// inferred predicate.
func (b *Builder) AddGroupUsesEdge(g Group, t TTP) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(g) >= len(b.groupIDs) {
		return ErrUnknownGroup
	}
	if int(t) >= len(b.ttpIDs) {
		return ErrUnknownTTP
	}
	b.usesGroup = append(b.usesGroup, uint16(g))
	b.usesTTP = append(b.usesTTP, uint16(t))
	return nil
}

// AddGroupSoftwareEdge records group -> software: an actor or campaign uses a
// piece of software. to must be a registered grouping node too.
func (b *Builder) AddGroupSoftwareEdge(from, to Group) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(from) >= len(b.groupIDs) || int(to) >= len(b.groupIDs) {
		return ErrUnknownGroup
	}
	b.softwareFrom = append(b.softwareFrom, uint16(from))
	b.softwareTo = append(b.softwareTo, uint16(to))
	return nil
}

// AddCWE registers a weakness id and returns its dense id. The KEV catalog
// carries no CWE name, so the caller passes the id as its own label:
// AddCWE("CWE-78", "CWE-78"). Ids and labels share one key map, so a key that
// normalises to an existing one returns that node as well: first registration
// wins.
func (b *Builder) AddCWE(id, label string) (CWE, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if c, ok := b.cweIndex[key]; ok {
		return CWE(c), nil
	}
	if len(b.cweIDs) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.cweIDs)
	b.cweIDs = append(b.cweIDs, strings.TrimSpace(id))
	b.cweLabels = append(b.cweLabels, strings.TrimSpace(label))
	claim(b.cweIndex, key, uint16(idx))
	claim(b.cweIndex, normalize(label), uint16(idx))
	return CWE(idx), nil
}

// AddProduct registers one (vendor, product) pair as the asset-side node of the
// KEV partition and returns its dense id. The pair is the key and there is no
// separate vendor id space, because no query intersects vendor bits. Idempotent
// on the normalised pair: a pair already registered returns its node, so a
// product is one node however many entries name it. An empty vendor or product
// returns ErrEmptyKey.
func (b *Builder) AddProduct(vendor, name string) (Product, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	v, n := normalize(vendor), normalize(name)
	if v == "" || n == "" {
		return 0, ErrEmptyKey
	}
	key := [2]string{v, n}
	if p, ok := b.productIndex[key]; ok {
		return Product(p), nil
	}
	if len(b.productVendors) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.productVendors)
	b.productVendors = append(b.productVendors, strings.TrimSpace(vendor))
	b.productNames = append(b.productNames, strings.TrimSpace(name))
	b.productIndex[key] = uint16(idx)
	return Product(idx), nil
}

// AddKEV registers one Known Exploited Vulnerabilities entry: its CVE id, the
// vulnerability name, the date it was added to the catalog and whether CISA
// links it to a known ransomware campaign. Idempotent on the normalised CVE id:
// a second call with the same id returns the stored id and ignores its other
// arguments. The CVE id is the only key — vulnerability names repeat across
// entries, so a name key would be ambiguous.
func (b *Builder) AddKEV(id, name, added string, ransomware bool) (KEV, error) {
	if b.Built() {
		return 0, ErrBuilderUsed
	}
	b.seed()
	key := normalize(id)
	if key == "" {
		return 0, ErrEmptyKey
	}
	if k, ok := b.kevIndex[key]; ok {
		return KEV(k), nil
	}
	if len(b.kevIDs) >= MaxNodes {
		return 0, ErrTooManyNodes
	}
	idx := len(b.kevIDs)
	b.kevIDs = append(b.kevIDs, strings.TrimSpace(id))
	b.kevNames = append(b.kevNames, strings.TrimSpace(name))
	b.kevAdded = append(b.kevAdded, strings.TrimSpace(added))
	b.kevRansomware = append(b.kevRansomware, ransomware)
	b.kevIndex[key] = uint16(idx)
	return KEV(idx), nil
}

// AddKEVWeaknessEdge records KEV entry -> weakness: the entry names that
// weakness class. Both ids must be registered. Duplicate edges are harmless.
func (b *Builder) AddKEVWeaknessEdge(k KEV, c CWE) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(k) >= len(b.kevIDs) {
		return ErrUnknownKEV
	}
	if int(c) >= len(b.cweIDs) {
		return ErrUnknownCWE
	}
	b.kevWeaknessKEV = append(b.kevWeaknessKEV, uint16(k))
	b.kevWeaknessCWE = append(b.kevWeaknessCWE, uint16(c))
	return nil
}

// AddKEVProductEdge records KEV entry -> product: the entry is about that
// product. Both ids must be registered.
func (b *Builder) AddKEVProductEdge(k KEV, p Product) error {
	if b.Built() {
		return ErrBuilderUsed
	}
	if int(k) >= len(b.kevIDs) {
		return ErrUnknownKEV
	}
	if int(p) >= len(b.productVendors) {
		return ErrUnknownProduct
	}
	b.kevProductKEV = append(b.kevProductKEV, uint16(k))
	b.kevProduct = append(b.kevProduct, uint16(p))
	return nil
}
