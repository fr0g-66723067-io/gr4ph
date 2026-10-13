//go:build goexperiment.simd

package gr4ph

import (
	"errors"
	"strings"
)

// TTP is a technique id: a dense index into the technique partition, assigned
// in registration order. 0 is a valid id; NoParent marks "no parent".
type TTP uint16

// Artifact is a dense index into the artifact partition.
type Artifact uint16

// Countermeasure is a dense index into the countermeasure partition.
type Countermeasure uint16

// Rel is an offensive (technique -> artifact) relation plane: 0 is RelAny
// (the union of all predicates), 1..255 are the registered predicates.
type Rel uint8

// DefRel is a defensive (countermeasure -> artifact) relation plane: 0 is
// DefRelAny, 1..255 are the registered predicates.
type DefRel uint8

// Domain tags a technique with the ATT&CK domain it came from.
type Domain uint8

// Tactic is a dense index into the tactic vocabulary (ATT&CK TA ids), assigned in
// registration order. A technique's tactic mask is a uint64 whose bit i is
// TacticID(i).
type Tactic uint8

// Platform is a dense index into the platform vocabulary, assigned in
// registration order. A technique's platform mask is a uint64 whose bit i is
// PlatformName(i).
type Platform uint8

// DataComponent is a dense index into the data-component partition (ATT&CK DC
// ids), the log-source layer that detects techniques.
type DataComponent uint16

// Group is a dense index into the grouping partition: ATT&CK actors (intrusion
// sets), software (malware and tools) and campaigns share one id space.
type Group uint16

// Selection is a caller-owned bitset over one partition's dense ids: bit i of
// word i>>6 selects id i. The engine reads it and never retains it, so a caller
// may flip bits between calls — a SIEM alert stream, a deployed-tool
// inventory. len(sel) must be at least WordsPerRow of the partition it selects.
type Selection []uint64

// GroupKind tags a grouping node with the ATT&CK object type it came from.
type GroupKind uint8

// KEV is a dense index into the KEV partition: one CISA Known Exploited
// Vulnerabilities entry (a CVE id).
type KEV uint16

// CWE is a dense index into the weakness vocabulary the KEV catalog names.
type CWE uint16

// Product is a dense index into the KEV product vocabulary, one distinct
// (vendorProject, product) pair. It is the asset side: every KEV entry names
// exactly one product.
type Product uint16

// Kind selects a node partition for WordsPerRow.
type Kind uint8

const (
	// DomainEnterprise is the ATT&CK Enterprise domain.
	DomainEnterprise Domain = 0
	// DomainICS is the ATT&CK ICS domain.
	DomainICS Domain = 1
	// DomainMobile is the ATT&CK Mobile domain.
	DomainMobile Domain = 2
	// DomainSPARTA tags a node D3FEND names that exists in no ATT&CK domain.
	DomainSPARTA Domain = 3
)

const (
	// KindTTP selects the technique partition.
	KindTTP Kind = 0
	// KindArtifact selects the artifact partition.
	KindArtifact Kind = 1
	// KindCountermeasure selects the countermeasure partition.
	KindCountermeasure Kind = 2
	// KindDataComponent selects the data-component partition.
	KindDataComponent Kind = 3
	// KindKEV selects the KEV partition.
	KindKEV Kind = 4
	// KindCWE selects the CWE weakness vocabulary.
	KindCWE Kind = 5
	// KindProduct selects the KEV product vocabulary.
	KindProduct Kind = 6
)

const (
	// GroupActor is an ATT&CK intrusion set.
	GroupActor GroupKind = 0
	// GroupSoftware is ATT&CK malware or a tool.
	GroupSoftware GroupKind = 1
	// GroupCampaign is an ATT&CK campaign.
	GroupCampaign GroupKind = 2
)

// RelAny is the union plane of every offensive relation.
const RelAny Rel = 0

// DefRelAny is the union plane of every defensive relation.
const DefRelAny DefRel = 0

// FlagSubTechnique is the technique-attribute flag bit of a sub-technique. Build
// derives it from the hierarchy, so it can never disagree with TTPParents; bits
// 1..63 are unassigned.
const FlagSubTechnique uint64 = 1 << 0

// reservedRelName is the union plane's name: relNames[0]/defRelNames[0] carry it,
// and it is a lookup key for RelAny/DefRelAny rather than a registrable predicate.
const reservedRelName = "any"

// MaxNodes is the per-partition node capacity (uint16 index space).
const MaxNodes = 65536

// NoParent marks a technique with no parent. It is index 65535, so the node at
// that index (if a builder ever fills the partition) cannot itself parent
// children: passing it as a parent reads as "no parent".
const NoParent TTP = 65535

// The Builder's error vocabulary: every Add* returns one of these, and Build
// returns ErrBuilderUsed on a second call.
var (
	// ErrTooManyNodes: more than MaxNodes nodes in one partition.
	ErrTooManyNodes = errors.New("gr4ph: node space exhausted (65536)")
	// ErrTooManyRels: more than 255 registered relations in one family.
	ErrTooManyRels = errors.New("gr4ph: relation space exhausted (255)")
	// ErrUnknownTTP: the technique id was never registered.
	ErrUnknownTTP = errors.New("gr4ph: unknown ttp id")
	// ErrUnknownArtifact: the artifact id was never registered.
	ErrUnknownArtifact = errors.New("gr4ph: unknown artifact id")
	// ErrUnknownCountermeasure: the countermeasure id was never registered.
	ErrUnknownCountermeasure = errors.New("gr4ph: unknown countermeasure id")
	// ErrUnknownRel: the offensive relation id was never registered.
	ErrUnknownRel = errors.New("gr4ph: unknown relation id")
	// ErrUnknownDefRel: the defensive relation id was never registered.
	ErrUnknownDefRel = errors.New("gr4ph: unknown defensive relation id")
	// ErrUnknownParent: the parent technique was never registered.
	ErrUnknownParent = errors.New("gr4ph: parent ttp not registered")
	// ErrNonContiguousChild: a child must be registered immediately after its
	// parent's child block.
	ErrNonContiguousChild = errors.New("gr4ph: child must be registered immediately after its parent's child block")
	// ErrDepthExceeded: the parent is itself a sub-technique.
	ErrDepthExceeded = errors.New("gr4ph: hierarchy deeper than two levels")
	// ErrEmptyKey: the node or relation key is empty.
	ErrEmptyKey = errors.New("gr4ph: empty node or relation key")
	// ErrUnknownDomain: the domain is not one of the four Domain constants.
	ErrUnknownDomain = errors.New("gr4ph: unknown domain")
	// ErrBuilderUsed: the builder has already been built.
	ErrBuilderUsed = errors.New("gr4ph: builder already built")
	// ErrReservedName: the key is the reserved union-plane name "any".
	ErrReservedName = errors.New(`gr4ph: reserved name "any"`)
	// ErrTooManyTactics: more than 64 registered tactics, which is the width of
	// the uint64 mask TTPTactics returns.
	ErrTooManyTactics = errors.New("gr4ph: tactic space exhausted (64)")
	// ErrTooManyPlatforms: more than 64 registered platforms, which is the width
	// of the uint64 mask TTPPlatforms returns.
	ErrTooManyPlatforms = errors.New("gr4ph: platform space exhausted (64)")
	// ErrUnknownTactic: the tactic id was never registered.
	ErrUnknownTactic = errors.New("gr4ph: unknown tactic id")
	// ErrUnknownPlatform: the platform id was never registered.
	ErrUnknownPlatform = errors.New("gr4ph: unknown platform id")
	// ErrUnknownDataComponent: the data component id was never registered.
	ErrUnknownDataComponent = errors.New("gr4ph: unknown data component id")
	// ErrUnknownGroup: the grouping-node id was never registered.
	ErrUnknownGroup = errors.New("gr4ph: unknown group id")
	// ErrUnknownGroupKind: the grouping kind is not one of the three GroupKind
	// constants.
	ErrUnknownGroupKind = errors.New("gr4ph: unknown group kind")
	// ErrUnknownKEV: the KEV entry id was never registered.
	ErrUnknownKEV = errors.New("gr4ph: unknown kev id")
	// ErrUnknownCWE: the CWE id was never registered.
	ErrUnknownCWE = errors.New("gr4ph: unknown cwe id")
	// ErrUnknownProduct: the product id was never registered.
	ErrUnknownProduct = errors.New("gr4ph: unknown product id")
	// ErrKEVWithoutProduct: a KEV entry names no product. Every entry names
	// exactly one, which is what KEVVendor and KEVProduct read.
	ErrKEVWithoutProduct = errors.New("gr4ph: kev entry without a product")
	// ErrKEVMultipleProducts: a KEV entry names more than one product, so
	// KEVVendor/KEVProduct (the lowest bit) and ProductsForKEV (every bit)
	// would disagree.
	ErrKEVMultipleProducts = errors.New("gr4ph: kev entry with multiple products")
)

// Builder accumulates the cold-path graph: node keys (id, label, aliases),
// domains, the technique hierarchy, and the three edge families as SoA slices.
// It is single-goroutine; the Engine it produces is immutable and safe for
// concurrent queries.
//
// A Builder is single-use: Build marks it built and every later Add* call
// returns ErrBuilderUsed, so a live Engine can never be mutated through its
// builder.
//
// The built flag lives behind a pointer that seed installs, so a copy of a
// Builder made before Build cannot register anything afterwards: every handle
// shares the flag.
//
// The zero value is usable and equivalent to NewBuilder().
type Builder struct {
	ttpIDs        []string
	ttpLabels     []string
	ttpDomains    []Domain
	ttpParents    []uint16
	ttpChildCount []uint16
	ttpRevoked    []bool // ATT&CK revoked or deprecated, index-parallel

	artNames  []string
	artLabels []string

	cmIDs    []string
	cmLabels []string

	// The tactic and platform vocabularies and their assignment edges.
	tacticIDs     []string
	tacticLabels  []string
	platformNames []string

	// The data-component partition and its detects edges.
	dcIDs    []string
	dcLabels []string

	// The grouping partition: ids, labels, kinds, the revocation flag that
	// decides who wins a shared label, and the two uses families.
	groupIDs     []string
	groupLabels  []string
	groupKinds   []GroupKind
	groupRevoked []bool

	// The KEV partition, the weakness vocabulary it names and the product
	// vocabulary it is about, plus the two edge families.
	kevIDs         []string
	kevNames       []string
	kevAdded       []string
	kevRansomware  []bool
	cweIDs         []string
	cweLabels      []string
	productVendors []string
	productNames   []string

	kevWeaknessKEV []uint16
	kevWeaknessCWE []uint16

	kevProductKEV []uint16
	kevProduct    []uint16

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

	// Edge SoA. Duplicates are harmless: Build ORs bits.
	edgeT, edgeA []uint16
	edgeR        []uint8

	defEdgeC, defEdgeA []uint16
	defEdgeR           []uint8

	defendsC, defendsT []uint16

	// Attribute assignment edges: technique -> tactic and technique -> platform.
	tacticT, tacticTA    []uint16
	platformT, platformP []uint16
	// Data-component -> technique, group -> technique, group -> software.
	detectsDC, detectsTTP    []uint16
	usesGroup, usesTTP       []uint16
	softwareFrom, softwareTo []uint16

	// built is a pointer so that a copy of the Builder shares the flag: Build
	// flips it for every handle, so no copy can reach the maps and slices the
	// live Engine holds. seed installs it.
	built *bool
}

// seed installs the reserved union-plane name, the index maps and the shared
// built flag on a builder that has none, so the zero value behaves like
// NewBuilder(): plane 0 exists and every Add* has a map to write into. It is
// called by NewBuilder, every registration method and Build; the length check
// makes it free afterwards.
func (b *Builder) seed() {
	if len(b.relNames) != 0 {
		return
	}
	b.relNames = []string{reservedRelName}
	b.defRelNames = []string{reservedRelName}
	b.ttpIndex = make(map[string]uint16)
	b.artIndex = make(map[string]uint16)
	b.cmIndex = make(map[string]uint16)
	b.dcIndex = make(map[string]uint16)
	b.groupIndex = make(map[string]uint16)
	b.tacticIndex = make(map[string]uint16)
	b.platformIndex = make(map[string]uint16)
	b.relIndex = map[string]Rel{reservedRelName: RelAny}
	b.defRelIndex = map[string]DefRel{reservedRelName: DefRelAny}
	b.kevIndex = make(map[string]uint16)
	b.cweIndex = make(map[string]uint16)
	b.productIndex = make(map[[2]string]uint16)
	b.built = new(bool)
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	b := new(Builder)
	b.seed()
	return b
}

// normalize is the single key-normalisation rule for the cold path: trim, then
// lower-case. Every lookup method applies exactly this.
func normalize(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// claim registers key in m under id unless the key is empty or already taken
// (first-wins: the earliest-registered node keeps the key, which makes
// collisions across different ids deterministic under sorted registration).
func claim(m map[string]uint16, key string, id uint16) {
	if key == "" {
		return
	}
	if _, ok := m[key]; !ok {
		m[key] = id
	}
}

// claimTTP registers key in b.ttpIndex under idx unless the key is empty. A live
// technique takes a label or alias from a revoked holder; between holders of the
// same standing the earliest registration keeps the key, so a shared key
// resolves to the live technique with the lowest index, and to the lowest-index
// one when every holder is revoked. A key that is another technique's id is
// never taken: ids are unambiguous.
func (b *Builder) claimTTP(key string, idx int) {
	if key == "" {
		return
	}
	if cur, ok := b.ttpIndex[key]; ok {
		if !b.ttpRevoked[cur] || b.ttpRevoked[idx] || normalize(b.ttpIDs[cur]) == key {
			return
		}
	}
	b.ttpIndex[key] = uint16(idx)
}

// claimGroup registers key in b.groupIndex under idx unless the key is empty. A
// live grouping node takes a label from a revoked holder, exactly as a live
// technique takes one from a revoked technique (see claimTTP): ATT&CK reuses a
// grouping node's label on its successor, so the label must resolve to the node
// that is still maintained. Between holders of the same standing the earliest
// registration keeps the key, so a shared label resolves to the live node with
// the lowest index, and to the lowest-index one when every holder is revoked. A
// key that is another node's id is never taken: ids are unambiguous.
func (b *Builder) claimGroup(key string, idx int) {
	if key == "" {
		return
	}
	if cur, ok := b.groupIndex[key]; ok {
		if !b.groupRevoked[cur] || b.groupRevoked[idx] || normalize(b.groupIDs[cur]) == key {
			return
		}
	}
	b.groupIndex[key] = uint16(idx)
}

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

// Built reports whether Build has been called. A built builder rejects every
// Add* with ErrBuilderUsed.
func (b *Builder) Built() bool { return b.built != nil && *b.built }

// TTPCount returns the number of registered techniques.
func (b *Builder) TTPCount() int { return len(b.ttpIDs) }

// ArtifactCount returns the number of registered artifacts.
func (b *Builder) ArtifactCount() int { return len(b.artNames) }

// CountermeasureCount returns the number of registered countermeasures.
func (b *Builder) CountermeasureCount() int { return len(b.cmIDs) }

// RelCount returns the number of registered offensive relations (excluding
// RelAny). It is 0 on the zero value, which has no planes yet.
func (b *Builder) RelCount() int { return max(len(b.relNames)-1, 0) }

// DefRelCount returns the number of registered defensive relations (excluding
// DefRelAny). It is 0 on the zero value, which has no planes yet.
func (b *Builder) DefRelCount() int { return max(len(b.defRelNames)-1, 0) }

// TacticCount returns the number of registered tactics.
func (b *Builder) TacticCount() int { return len(b.tacticIDs) }

// PlatformCount returns the number of registered platforms.
func (b *Builder) PlatformCount() int { return len(b.platformNames) }

// DataComponentCount returns the number of registered data components.
func (b *Builder) DataComponentCount() int { return len(b.dcIDs) }

// GroupCount returns the number of registered grouping nodes.
func (b *Builder) GroupCount() int { return len(b.groupIDs) }

// KEVCount returns the number of registered KEV entries.
func (b *Builder) KEVCount() int { return len(b.kevIDs) }

// CWECount returns the number of registered weaknesses.
func (b *Builder) CWECount() int { return len(b.cweIDs) }

// ProductCount returns the number of registered products.
func (b *Builder) ProductCount() int { return len(b.productVendors) }

// wordsFor returns the number of 64-bit words needed for n bits.
func wordsFor(n int) int { return (n + 63) / 64 }

// Build freezes the graph into an immutable Engine: it materialises every
// matrix block and its transpose, folds each union plane 0 from the predicate
// planes, and copies the per-technique attribute masks and the group-kind
// column. The builder must not be used afterwards: every Add* then returns
// ErrBuilderUsed, and a second Build returns ErrBuilderUsed too.
func (b *Builder) Build() (*Engine, error) {
	if b.Built() {
		return nil, ErrBuilderUsed
	}
	b.seed()
	*b.built = true
	e := &Engine{
		nTTP: len(b.ttpIDs),
		nArt: len(b.artNames),
		nCM:  len(b.cmIDs),
		nDC:  len(b.dcIDs),
		nGrp: len(b.groupIDs),

		nKEV:     len(b.kevIDs),
		nCWE:     len(b.cweIDs),
		nProduct: len(b.productVendors),

		nRel:      len(b.relNames),
		nDefRel:   len(b.defRelNames),
		nTactic:   len(b.tacticIDs),
		nPlatform: len(b.platformNames),

		wTTP:      wordsFor(len(b.ttpIDs)),
		wArt:      wordsFor(len(b.artNames)),
		wCM:       wordsFor(len(b.cmIDs)),
		wDC:       wordsFor(len(b.dcIDs)),
		wGrp:      wordsFor(len(b.groupIDs)),
		wTactic:   wordsFor(len(b.tacticIDs)),
		wPlatform: wordsFor(len(b.platformNames)),
		wKEV:      wordsFor(len(b.kevIDs)),
		wCWE:      wordsFor(len(b.cweIDs)),
		wProduct:  wordsFor(len(b.productVendors)),
	}

	// Six blocks, every row exactly stride words (no padding).
	e.ttpArt = make([]uint64, e.nRel*e.nTTP*e.wArt)
	e.artTTP = make([]uint64, e.nRel*e.nArt*e.wTTP)
	e.cmArt = make([]uint64, e.nDefRel*e.nCM*e.wArt)
	e.artCM = make([]uint64, e.nDefRel*e.nArt*e.wCM)
	e.cmTTP = make([]uint64, e.nCM*e.wTTP)
	e.ttpCM = make([]uint64, e.nTTP*e.wCM)

	// The attribute columns and their transposes, the two new partitions and the
	// software family. Each has a single inferred predicate, so there is no
	// planes dimension and nothing to fold.
	e.tacticTTP = make([]uint64, e.nTactic*e.wTTP)
	e.ttpTactic = make([]uint64, e.nTTP*e.wTactic)
	e.platformTTP = make([]uint64, e.nPlatform*e.wTTP)
	e.ttpPlatform = make([]uint64, e.nTTP*e.wPlatform)
	e.dcTTP = make([]uint64, e.nDC*e.wTTP)
	e.ttpDC = make([]uint64, e.nTTP*e.wDC)
	e.grpTTP = make([]uint64, e.nGrp*e.wTTP)
	e.ttpGrp = make([]uint64, e.nTTP*e.wGrp)
	e.grpSoftware = make([]uint64, e.nGrp*e.wGrp)
	e.softwareGrp = make([]uint64, e.nGrp*e.wGrp)

	// The KEV partition, the weakness vocabulary it names and the product
	// vocabulary it is about. These four arrays are allocated after every
	// existing one, so the hot blocks keep their address range.
	e.kevCWE = make([]uint64, e.nKEV*e.wCWE)
	e.cweKEV = make([]uint64, e.nCWE*e.wKEV)
	e.kevProduct = make([]uint64, e.nKEV*e.wProduct)
	e.productKEV = make([]uint64, e.nProduct*e.wKEV)

	// Predicate planes (1..n-1) from edges, in both directions.
	for i := range b.edgeT {
		t, a, r := int(b.edgeT[i]), int(b.edgeA[i]), int(b.edgeR[i])
		setBit(e.ttpArt[e.ttpArtOff(Rel(r), TTP(t)):], a)
		setBit(e.artTTP[e.artTTPOff(Rel(r), Artifact(a)):], t)
	}
	for i := range b.defEdgeC {
		cm, a, dr := int(b.defEdgeC[i]), int(b.defEdgeA[i]), int(b.defEdgeR[i])
		setBit(e.cmArt[e.cmArtOff(DefRel(dr), Countermeasure(cm)):], a)
		setBit(e.artCM[e.artCMOff(DefRel(dr), Artifact(a)):], cm)
	}
	for i := range b.defendsC {
		cm, t := int(b.defendsC[i]), int(b.defendsT[i])
		setBit(e.cmTTP[e.cmTTPOff(Countermeasure(cm)):], t)
		setBit(e.ttpCM[e.ttpCMOff(TTP(t)):], cm)
	}
	for i := range b.tacticTA {
		ta, t := int(b.tacticTA[i]), int(b.tacticT[i])
		setBit(e.tacticTTP[e.tacticTTPOff(Tactic(ta)):], t)
		setBit(e.ttpTactic[e.ttpTacticOff(TTP(t)):], ta)
	}
	for i := range b.platformP {
		p, t := int(b.platformP[i]), int(b.platformT[i])
		setBit(e.platformTTP[e.platformTTPOff(Platform(p)):], t)
		setBit(e.ttpPlatform[e.ttpPlatformOff(TTP(t)):], p)
	}
	for i := range b.detectsDC {
		dc, t := int(b.detectsDC[i]), int(b.detectsTTP[i])
		setBit(e.dcTTP[e.dcTTPOff(DataComponent(dc)):], t)
		setBit(e.ttpDC[e.ttpDCOff(TTP(t)):], dc)
	}
	for i := range b.usesGroup {
		g, t := int(b.usesGroup[i]), int(b.usesTTP[i])
		setBit(e.grpTTP[e.grpTTPOff(Group(g)):], t)
		setBit(e.ttpGrp[e.ttpGrpOff(TTP(t)):], g)
	}
	for i := range b.softwareFrom {
		from, to := int(b.softwareFrom[i]), int(b.softwareTo[i])
		setBit(e.grpSoftware[e.grpSoftwareOff(Group(from)):], to)
		setBit(e.softwareGrp[e.softwareGrpOff(Group(to)):], from)
	}
	for i := range b.kevWeaknessKEV {
		k, c := KEV(b.kevWeaknessKEV[i]), CWE(b.kevWeaknessCWE[i])
		setBit(e.kevCWE[e.kevCWEOff(k):], int(c))
		setBit(e.cweKEV[e.cweKEVOff(c):], int(k))
	}
	for i := range b.kevProductKEV {
		k, p := KEV(b.kevProductKEV[i]), Product(b.kevProduct[i])
		setBit(e.kevProduct[e.kevProductOff(k):], int(p))
		setBit(e.productKEV[e.productKEVOff(p):], int(k))
	}

	// The one-product-per-entry invariant the KEV accessors read: an entry with
	// no product (or more than one) is rejected here rather than answered
	// wrongly.
	for k := range e.nKEV {
		switch n := popcountRow(e.row(e.kevProduct, e.kevProductOff(KEV(k)), e.wProduct)); {
		case n == 0:
			return nil, ErrKEVWithoutProduct
		case n > 1:
			return nil, ErrKEVMultipleProducts
		}
	}

	// The sub-technique flag is derived from the hierarchy, the only source of
	// the bit: it can never disagree with TTPParents.
	e.ttpFlags = make([]uint64, e.nTTP)
	for i := range b.ttpParents {
		if b.ttpParents[i] != uint16(NoParent) {
			e.ttpFlags[i] = FlagSubTechnique
		}
	}

	// Fold the union planes (plane 0) from the predicate planes.
	e.foldUnion(e.ttpArt, e.nRel, e.nTTP, e.wArt)
	e.foldUnion(e.artTTP, e.nRel, e.nArt, e.wTTP)
	e.foldUnion(e.cmArt, e.nDefRel, e.nCM, e.wArt)
	e.foldUnion(e.artCM, e.nDefRel, e.nArt, e.wCM)

	e.ttpIDs = b.ttpIDs
	e.ttpLabels = b.ttpLabels
	e.ttpDomains = b.ttpDomains
	e.ttpParents = b.ttpParents
	e.ttpChildCount = b.ttpChildCount
	e.ttpRevoked = b.ttpRevoked
	e.artNames = b.artNames
	e.artLabels = b.artLabels
	e.cmIDs = b.cmIDs
	e.cmLabels = b.cmLabels
	e.relNames = b.relNames
	e.defRelNames = b.defRelNames
	e.ttpIndex = b.ttpIndex
	e.artIndex = b.artIndex
	e.cmIndex = b.cmIndex
	e.relIndex = b.relIndex
	e.defRelIndex = b.defRelIndex
	e.tacticIDs = b.tacticIDs
	e.tacticLabels = b.tacticLabels
	e.platformNames = b.platformNames
	e.dcIDs = b.dcIDs
	e.dcLabels = b.dcLabels
	e.groupIDs = b.groupIDs
	e.groupLabels = b.groupLabels
	e.groupKinds = b.groupKinds
	e.groupRevoked = b.groupRevoked
	e.tacticIndex = b.tacticIndex
	e.platformIndex = b.platformIndex
	e.dcIndex = b.dcIndex
	e.groupIndex = b.groupIndex
	e.kevIDs = b.kevIDs
	e.kevNames = b.kevNames
	e.kevAdded = b.kevAdded
	e.kevRansomware = b.kevRansomware
	e.cweIDs = b.cweIDs
	e.productVendors = b.productVendors
	e.productNames = b.productNames
	e.kevIndex = b.kevIndex
	e.cweIndex = b.cweIndex
	e.productIndex = b.productIndex

	return e, nil
}

// foldUnion ORs predicate planes 1..planes-1 into plane 0 for every row of a
// block laid out as [planes][rows][stride].
func (e *Engine) foldUnion(block []uint64, planes, rows, stride int) {
	if planes < 2 || stride == 0 {
		return
	}
	for p := 1; p < planes; p++ {
		base := p * rows * stride
		for r := range rows {
			off := base + r*stride
			orRowInto(block[r*stride:r*stride+stride], block[off:off+stride])
		}
	}
}
