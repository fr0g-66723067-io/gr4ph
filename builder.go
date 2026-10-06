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

// Kind selects a node partition for WordsPerRow.
type Kind uint8

const (
	DomainEnterprise Domain = 0
	DomainICS        Domain = 1
	DomainMobile     Domain = 2
	DomainSPARTA     Domain = 3
)

const (
	KindTTP            Kind = 0
	KindArtifact       Kind = 1
	KindCountermeasure Kind = 2
)

// RelAny is the union plane of every offensive relation.
const RelAny Rel = 0

// DefRelAny is the union plane of every defensive relation.
const DefRelAny DefRel = 0

// MaxNodes is the per-partition node capacity (uint16 index space).
const MaxNodes = 65536

// NoParent marks a technique with no parent. It is index 65535, so the node at
// that index (if a builder ever fills the partition) cannot itself parent
// children: passing it as a parent reads as "no parent".
const NoParent TTP = 65535

var (
	ErrTooManyNodes          = errors.New("gr4ph: node space exhausted (65536)")
	ErrTooManyRels           = errors.New("gr4ph: relation space exhausted (255)")
	ErrUnknownTTP            = errors.New("gr4ph: unknown ttp id")
	ErrUnknownArtifact       = errors.New("gr4ph: unknown artifact id")
	ErrUnknownCountermeasure = errors.New("gr4ph: unknown countermeasure id")
	ErrUnknownRel            = errors.New("gr4ph: unknown relation id")
	ErrUnknownDefRel         = errors.New("gr4ph: unknown defensive relation id")
	ErrUnknownParent         = errors.New("gr4ph: parent ttp not registered")
	ErrNonContiguousChild    = errors.New("gr4ph: child must be registered immediately after its parent's child block")
	ErrDepthExceeded         = errors.New("gr4ph: hierarchy deeper than two levels")
)

// Builder accumulates the cold-path graph: node keys (id, label, aliases),
// domains, the technique hierarchy, and the three edge families as SoA slices.
// It is single-goroutine; the Engine it produces is immutable and safe for
// concurrent queries.
type Builder struct {
	ttpIDs        []string
	ttpLabels     []string
	ttpDomains    []Domain
	ttpParents    []uint16
	ttpChildCount []uint16

	artNames  []string
	artLabels []string

	cmIDs    []string
	cmLabels []string

	relNames    []string // index 0 is "any"
	defRelNames []string // index 0 is "any"

	ttpIndex    map[string]uint16
	artIndex    map[string]uint16
	cmIndex     map[string]uint16
	relIndex    map[string]Rel
	defRelIndex map[string]DefRel

	// Edge SoA. Duplicates are harmless: Build ORs bits.
	edgeT, edgeA []uint16
	edgeR        []uint8

	defEdgeC, defEdgeA []uint16
	defEdgeR           []uint8

	defendsC, defendsT []uint16
}

// NewBuilder returns an empty builder.
func NewBuilder() *Builder {
	return &Builder{
		relNames:    []string{"any"},
		defRelNames: []string{"any"},
		ttpIndex:    make(map[string]uint16),
		artIndex:    make(map[string]uint16),
		cmIndex:     make(map[string]uint16),
		relIndex:    make(map[string]Rel),
		defRelIndex: make(map[string]DefRel),
	}
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

// AddRel registers an offensive relation predicate and returns its plane id
// (1..255). Idempotent on the normalised name.
func (b *Builder) AddRel(name string) (Rel, error) {
	key := normalize(name)
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
// (1..255). Idempotent on the normalised name.
func (b *Builder) AddDefRel(name string) (DefRel, error) {
	key := normalize(name)
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

// AddTTP registers a technique and returns its dense id. Idempotent on the
// normalised id (a second call returns the stored id and does not touch the
// hierarchy). parent must be NoParent or an already-registered top-level
// technique whose child block the new node extends contiguously.
func (b *Builder) AddTTP(id, label string, dom Domain, parent TTP, aliases ...string) (TTP, error) {
	key := normalize(id)
	if t, ok := b.ttpIndex[key]; ok {
		return TTP(t), nil
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
	if parent != NoParent {
		b.ttpChildCount[int(parent)]++
	}

	claim(b.ttpIndex, key, uint16(idx))
	claim(b.ttpIndex, normalize(label), uint16(idx))
	for _, a := range aliases {
		claim(b.ttpIndex, normalize(a), uint16(idx))
	}
	return TTP(idx), nil
}

// AddArtifact registers an artifact and returns its dense id. Idempotent on the
// normalised name; the label is registered as a lookup key too.
func (b *Builder) AddArtifact(name, label string) (Artifact, error) {
	key := normalize(name)
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
// Idempotent on the normalised id; label and aliases are lookup keys.
func (b *Builder) AddCountermeasure(id, label string, aliases ...string) (Countermeasure, error) {
	key := normalize(id)
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

// TTPCount returns the number of registered techniques.
func (b *Builder) TTPCount() int { return len(b.ttpIDs) }

// ArtifactCount returns the number of registered artifacts.
func (b *Builder) ArtifactCount() int { return len(b.artNames) }

// CountermeasureCount returns the number of registered countermeasures.
func (b *Builder) CountermeasureCount() int { return len(b.cmIDs) }

// RelCount returns the number of registered offensive relations (excluding
// RelAny).
func (b *Builder) RelCount() int { return len(b.relNames) - 1 }

// DefRelCount returns the number of registered defensive relations (excluding
// DefRelAny).
func (b *Builder) DefRelCount() int { return len(b.defRelNames) - 1 }

// wordsFor returns the number of 64-bit words needed for n bits.
func wordsFor(n int) int { return (n + 63) / 64 }

// Build freezes the graph into an immutable Engine: it materialises all six
// matrix blocks, folds each union plane 0 from the predicate planes, and
// transposes the countermeasure -> technique block. The builder must not be
// used afterwards.
func (b *Builder) Build() (*Engine, error) {
	e := &Engine{
		nTTP: len(b.ttpIDs),
		nArt: len(b.artNames),
		nCM:  len(b.cmIDs),

		nRel:    len(b.relNames),
		nDefRel: len(b.defRelNames),

		wTTP: wordsFor(len(b.ttpIDs)),
		wArt: wordsFor(len(b.artNames)),
		wCM:  wordsFor(len(b.cmIDs)),
	}

	// Six blocks, every row exactly stride words (no padding).
	e.ttpArt = make([]uint64, e.nRel*e.nTTP*e.wArt)
	e.artTTP = make([]uint64, e.nRel*e.nArt*e.wTTP)
	e.cmArt = make([]uint64, e.nDefRel*e.nCM*e.wArt)
	e.artCM = make([]uint64, e.nDefRel*e.nArt*e.wCM)
	e.cmTTP = make([]uint64, e.nCM*e.wTTP)
	e.ttpCM = make([]uint64, e.nTTP*e.wCM)

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
		for r := 0; r < rows; r++ {
			off := base + r*stride
			orRowInto(block[r*stride:r*stride+stride], block[off:off+stride])
		}
	}
}
