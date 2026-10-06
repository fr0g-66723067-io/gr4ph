//go:build goexperiment.simd

package gr4ph

import (
	"errors"
	"strconv"
	"testing"
)

func TestBuilderIdempotencyAndDenseOrder(t *testing.T) {
	b := NewBuilder()

	t0, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent)
	if err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	if t0 != 0 {
		t.Fatalf("first ttp id = %d, want 0", t0)
	}
	again, err := b.AddTTP("  t1003 ", "ignored", DomainICS, NoParent)
	if err != nil {
		t.Fatalf("AddTTP repeat: %v", err)
	}
	if again != t0 {
		t.Fatalf("repeat AddTTP = %d, want %d (normalised key)", again, t0)
	}
	if b.TTPCount() != 1 {
		t.Fatalf("TTPCount = %d, want 1", b.TTPCount())
	}

	a0, err := b.AddArtifact("Process", "Process")
	if err != nil {
		t.Fatalf("AddArtifact: %v", err)
	}
	a1, _ := b.AddArtifact("File", "File")
	if a0 != 0 || a1 != 1 {
		t.Fatalf("artifact ids = %d,%d want 0,1", a0, a1)
	}
	if _, err := b.AddArtifact("PROCESS", "x"); err != nil {
		t.Fatalf("AddArtifact repeat: %v", err)
	}
	if b.ArtifactCount() != 2 {
		t.Fatalf("ArtifactCount = %d, want 2", b.ArtifactCount())
	}

	c0, _ := b.AddCountermeasure("CredentialHardening", "Credential Hardening")
	if c0 != 0 {
		t.Fatalf("cm id = %d, want 0", c0)
	}
	if _, err := b.AddCountermeasure("credentialhardening", "x"); err != nil {
		t.Fatalf("AddCountermeasure repeat: %v", err)
	}
	if b.CountermeasureCount() != 1 {
		t.Fatalf("CountermeasureCount = %d, want 1", b.CountermeasureCount())
	}

	r1, err := b.AddRel("accesses")
	if err != nil {
		t.Fatalf("AddRel: %v", err)
	}
	r2, _ := b.AddRel("modifies")
	if r1 != 1 || r2 != 2 {
		t.Fatalf("rel ids = %d,%d want 1,2 (0 is RelAny)", r1, r2)
	}
	if r1b, _ := b.AddRel("ACCESSES"); r1b != r1 {
		t.Fatalf("repeat AddRel = %d, want %d", r1b, r1)
	}
	if b.RelCount() != 2 {
		t.Fatalf("RelCount = %d, want 2", b.RelCount())
	}

	dr1, err := b.AddDefRel("hardens")
	if err != nil {
		t.Fatalf("AddDefRel: %v", err)
	}
	if dr1 != 1 {
		t.Fatalf("defrel id = %d, want 1", dr1)
	}
	if dr1b, _ := b.AddDefRel("Hardens "); dr1b != dr1 {
		t.Fatalf("repeat AddDefRel = %d, want %d", dr1b, dr1)
	}
	if b.DefRelCount() != 1 {
		t.Fatalf("DefRelCount = %d, want 1", b.DefRelCount())
	}
}

// TestBuilderAliasFirstWins pins the deterministic collision rule: keys are
// claimed in order id, label, aliases, and the earliest registration keeps the
// key, so the lowest id wins.
func TestBuilderAliasFirstWins(t *testing.T) {
	b := NewBuilder()
	t0, _ := b.AddTTP("T1003", "LSASS Memory", DomainEnterprise, NoParent)
	t1, _ := b.AddTTP("T1059", "T1003", DomainEnterprise, NoParent, "Command and Scripting Interpreter")
	if t0 != 0 || t1 != 1 {
		t.Fatalf("ids = %d,%d want 0,1", t0, t1)
	}

	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Node 1's label collides with node 0's canonical id: node 0 wins.
	if got, ok := e.Incident("t1003"); !ok || got != t0 {
		t.Fatalf("Incident(t1003) = %d,%v want %d,true", got, ok, t0)
	}
	// Node 1 is still reachable by its own id and its alias.
	if got, ok := e.Incident("t1059"); !ok || got != t1 {
		t.Fatalf("Incident(t1059) = %d,%v want %d,true", got, ok, t1)
	}
	if got, ok := e.Incident("command and scripting interpreter"); !ok || got != t1 {
		t.Fatalf("alias lookup = %d,%v want %d,true", got, ok, t1)
	}
	// Node 0's own label is registered too.
	if got, ok := e.Incident(" LSASS Memory "); !ok || got != t0 {
		t.Fatalf("label lookup = %d,%v want %d,true", got, ok, t0)
	}
}

func TestBuilderEdgeValidation(t *testing.T) {
	b := NewBuilder()
	b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent)
	b.AddArtifact("Process", "Process")
	b.AddCountermeasure("CredentialHardening", "Credential Hardening")
	r, _ := b.AddRel("accesses")
	dr, _ := b.AddDefRel("hardens")

	badTTP := TTP(7)
	badArt := Artifact(7)
	badCM := Countermeasure(7)

	if err := b.AddEdge(badTTP, 0, r); !errors.Is(err, ErrUnknownTTP) {
		t.Fatalf("AddEdge bad ttp: %v", err)
	}
	if err := b.AddEdge(0, badArt, r); !errors.Is(err, ErrUnknownArtifact) {
		t.Fatalf("AddEdge bad artifact: %v", err)
	}
	if err := b.AddEdge(0, 0, RelAny); !errors.Is(err, ErrUnknownRel) {
		t.Fatalf("AddEdge RelAny: %v", err)
	}
	if err := b.AddEdge(0, 0, Rel(9)); !errors.Is(err, ErrUnknownRel) {
		t.Fatalf("AddEdge unregistered rel: %v", err)
	}
	if err := b.AddDefEdge(badCM, 0, dr); !errors.Is(err, ErrUnknownCountermeasure) {
		t.Fatalf("AddDefEdge bad cm: %v", err)
	}
	if err := b.AddDefEdge(0, badArt, dr); !errors.Is(err, ErrUnknownArtifact) {
		t.Fatalf("AddDefEdge bad artifact: %v", err)
	}
	if err := b.AddDefEdge(0, 0, DefRelAny); !errors.Is(err, ErrUnknownDefRel) {
		t.Fatalf("AddDefEdge DefRelAny: %v", err)
	}
	if err := b.AddDefEdge(0, 0, DefRel(9)); !errors.Is(err, ErrUnknownDefRel) {
		t.Fatalf("AddDefEdge unregistered dr: %v", err)
	}
	if err := b.AddDefendsEdge(badCM, 0); !errors.Is(err, ErrUnknownCountermeasure) {
		t.Fatalf("AddDefendsEdge bad cm: %v", err)
	}
	if err := b.AddDefendsEdge(0, badTTP); !errors.Is(err, ErrUnknownTTP) {
		t.Fatalf("AddDefendsEdge bad ttp: %v", err)
	}

	// Valid edges, duplicated on purpose: Build ORs bits, so duplicates are
	// harmless and the adjacency is still single-valued.
	if err := b.AddEdge(0, 0, r); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	if err := b.AddEdge(0, 0, r); err != nil {
		t.Fatalf("AddEdge dup: %v", err)
	}
	if err := b.AddDefEdge(0, 0, dr); err != nil {
		t.Fatalf("AddDefEdge: %v", err)
	}
	if err := b.AddDefendsEdge(0, 0); err != nil {
		t.Fatalf("AddDefendsEdge: %v", err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !e.AdjacentRel(0, 0, r) {
		t.Fatal("duplicate offensive edge lost")
	}
	if got := e.Degree(0, RelAny); got != 1 {
		t.Fatalf("Degree after duplicate edge = %d, want 1", got)
	}
	if got := e.CountermeasureDegree(0); got != 1 {
		t.Fatalf("CountermeasureDegree after duplicate defends = %d, want 1", got)
	}
}

func TestBuilderRelCapacity(t *testing.T) {
	b := NewBuilder()
	for i := range 255 {
		if _, err := b.AddRel("rel" + strconv.Itoa(i)); err != nil {
			t.Fatalf("AddRel #%d: %v", i, err)
		}
	}
	if _, err := b.AddRel("one-too-many"); !errors.Is(err, ErrTooManyRels) {
		t.Fatalf("AddRel past 255: %v", err)
	}
	if b.RelCount() != 255 {
		t.Fatalf("RelCount = %d, want 255", b.RelCount())
	}
}

func TestBuilderNodeCapacity(t *testing.T) {
	if testing.Short() {
		t.Skip("registers 65536 nodes")
	}
	b := NewBuilder()
	for i := range MaxNodes {
		id := "T" + strconv.Itoa(i)
		if _, err := b.AddTTP(id, "label "+id, DomainEnterprise, NoParent); err != nil {
			t.Fatalf("AddTTP #%d: %v", i, err)
		}
	}
	if b.TTPCount() != MaxNodes {
		t.Fatalf("TTPCount = %d, want %d", b.TTPCount(), MaxNodes)
	}
	if _, err := b.AddTTP("T-overflow", "x", DomainEnterprise, NoParent); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddTTP past cap: %v", err)
	}
}

// TestBuilderHierarchy covers the contiguous-child invariant that makes the
// O(1) child range valid, plus the two-level depth limit.
func TestBuilderHierarchy(t *testing.T) {
	b := NewBuilder()
	// Depth-first registration: children immediately after their parent.
	p0, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent)
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	c1, err := b.AddTTP("T1003.001", "LSASS Memory", DomainEnterprise, p0)
	if err != nil {
		t.Fatalf("child 1: %v", err)
	}
	c2, err := b.AddTTP("T1003.002", "Security Account Manager", DomainEnterprise, p0)
	if err != nil {
		t.Fatalf("child 2: %v", err)
	}
	p1, err := b.AddTTP("T1004", "Winlogon Helper DLL", DomainEnterprise, NoParent)
	if err != nil {
		t.Fatalf("parent 1: %v", err)
	}
	c3, err := b.AddTTP("T1004.001", "Winlogon Helper DLL Sub", DomainEnterprise, p1)
	if err != nil {
		t.Fatalf("child 3: %v", err)
	}
	if p0 != 0 || c1 != 1 || c2 != 2 || p1 != 3 || c3 != 4 {
		t.Fatalf("ids = %d %d %d %d %d, want 0 1 2 3 4", p0, c1, c2, p1, c3)
	}

	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if n := e.TTPChildCount(p0); n != 2 {
		t.Fatalf("TTPChildCount(T1003) = %d, want 2", n)
	}
	if n := e.TTPChildCount(p1); n != 1 {
		t.Fatalf("TTPChildCount(T1004) = %d, want 1", n)
	}
	if n := e.TTPChildCount(c1); n != 0 {
		t.Fatalf("TTPChildCount(sub) = %d, want 0", n)
	}
	buf := make([]TTP, 4)
	if n := e.TTPChildren(p0, buf); n != 2 || buf[0] != c1 || buf[1] != c2 {
		t.Fatalf("TTPChildren(T1003) = %d %v, want 2 [%d %d]", n, buf[:2], c1, c2)
	}
	if n := e.TTPChildren(c1, buf); n != 0 {
		t.Fatalf("TTPChildren(leaf) = %d, want 0", n)
	}
	if p, ok := e.TTPParent(c2); !ok || p != p0 {
		t.Fatalf("TTPParent(sub) = %d,%v want %d,true", p, ok, p0)
	}
	if p, ok := e.TTPParent(p0); ok {
		t.Fatalf("TTPParent(top-level) = %d,%v want 0,false", p, ok)
	}
	// A fresh builder must see the same parent for a node registered by id.
	if _, err := b.AddTTP("T1003.001", "ignored", DomainICS, NoParent); err != nil {
		t.Fatalf("idempotent re-add: %v", err)
	}
	if n := e.TTPChildCount(p0); n != 2 {
		t.Fatalf("re-add changed hierarchy: child count %d, want 2", n)
	}
}

func TestBuilderHierarchyErrors(t *testing.T) {
	b := NewBuilder()
	b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent)

	// Forward / out-of-range parent.
	if _, err := b.AddTTP("T1003.001", "sub", DomainEnterprise, TTP(7)); !errors.Is(err, ErrUnknownParent) {
		t.Fatalf("forward parent: %v", err)
	}
	// Real child of T1003 at index 1.
	if _, err := b.AddTTP("T1003.001", "sub", DomainEnterprise, TTP(0)); err != nil {
		t.Fatalf("child: %v", err)
	}
	// Index 1 is a sub-technique: it cannot parent a grandchild.
	if _, err := b.AddTTP("T1003.001.001", "grandchild", DomainEnterprise, TTP(1)); !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("grandchild: %v", err)
	}
	// NoParent is not a parent: the node registers top-level.
	if _, err := b.AddTTP("T1004", "top-level", DomainEnterprise, NoParent); err != nil {
		t.Fatalf("top-level: %v", err)
	}
	// Registering an unrelated node breaks the contiguous child block: index 3
	// cannot extend T1003's block (which ends at index 1).
	b.AddTTP("T1005", "unrelated", DomainEnterprise, NoParent)
	if _, err := b.AddTTP("T1003.003", "late child", DomainEnterprise, TTP(0)); !errors.Is(err, ErrNonContiguousChild) {
		t.Fatalf("non-contiguous child: %v", err)
	}
}

func TestEmptyEngine(t *testing.T) {
	e, err := NewBuilder().Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if e.TTPCount() != 0 || e.ArtifactCount() != 0 || e.CountermeasureCount() != 0 {
		t.Fatalf("counts = %d %d %d, want 0 0 0", e.TTPCount(), e.ArtifactCount(), e.CountermeasureCount())
	}
	if e.RelCount() != 0 || e.DefRelCount() != 0 {
		t.Fatalf("rel counts = %d %d, want 0 0", e.RelCount(), e.DefRelCount())
	}
	if e.WordsPerRow(KindTTP) != 0 || e.WordsPerRow(KindArtifact) != 0 || e.WordsPerRow(KindCountermeasure) != 0 {
		t.Fatal("strides must be 0 for an empty engine")
	}
	if e.Adjacent(0, 0) || e.AdjacentRel(0, 0, RelAny) {
		t.Fatal("empty engine must not report adjacency")
	}
	if n := e.Artifacts(0, nil); n != 0 {
		t.Fatalf("Artifacts = %d, want 0", n)
	}
	if n := e.TTPs(0, nil); n != 0 {
		t.Fatalf("TTPs = %d, want 0", n)
	}
	if n := e.Degree(0, RelAny); n != 0 {
		t.Fatalf("Degree = %d, want 0", n)
	}
	if n := e.ArtifactDegree(0, RelAny); n != 0 {
		t.Fatalf("ArtifactDegree = %d, want 0", n)
	}
	if n := e.CountermeasuresForTTP(0, nil); n != 0 {
		t.Fatalf("CountermeasuresForTTP = %d, want 0", n)
	}
	if n := e.CountermeasuresForArtifact(0, DefRelAny, nil); n != 0 {
		t.Fatalf("CountermeasuresForArtifact = %d, want 0", n)
	}
	if n := e.TTPsForCountermeasure(0, nil); n != 0 {
		t.Fatalf("TTPsForCountermeasure = %d, want 0", n)
	}
	if n := e.CountermeasureDegree(0); n != 0 {
		t.Fatalf("CountermeasureDegree = %d, want 0", n)
	}
	if n := e.TTPChildCount(0); n != 0 {
		t.Fatalf("TTPChildCount = %d, want 0", n)
	}
	if _, ok := e.TTPParent(0); ok {
		t.Fatal("TTPParent on empty engine must be false")
	}
	if n := e.TTPsAny(RelAny, nil, nil, nil); n != 0 {
		t.Fatalf("TTPsAny empty input = %d, want 0", n)
	}
	if n := e.ArtifactsAll(RelAny, nil, nil, nil); n != 0 {
		t.Fatalf("ArtifactsAll empty input = %d, want 0", n)
	}
	if _, ok := e.Incident("T1003"); ok {
		t.Fatal("Incident on empty engine must be false")
	}
	if _, ok := e.Rel("accesses"); ok {
		t.Fatal("Rel on empty engine must be false")
	}
}
