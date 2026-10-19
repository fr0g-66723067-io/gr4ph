//go:build goexperiment.simd

package gr4ph

import (
	"errors"
	"fmt"
	"strconv"
	"testing"
)

func TestBuilderIdempotencyAndDenseOrder(t *testing.T) {
	b := NewBuilder()

	t0, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	if t0 != 0 {
		t.Fatalf("first ttp id = %d, want 0", t0)
	}
	again, err := b.AddTTP("  t1003 ", "ignored", DomainICS, NoParent, false)
	if err != nil {
		t.Fatalf("AddTTP repeat: %v", err)
	}
	if again != t0 {
		t.Fatalf("repeat AddTTP = %d, want %d (normalized key)", again, t0)
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
	t0, _ := b.AddTTP("T1003", "LSASS Memory", DomainEnterprise, NoParent, false)
	t1, _ := b.AddTTP("T1059", "T1003", DomainEnterprise, NoParent, false, "Command and Scripting Interpreter")
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

// TestBuilderLiveLabelBeatsRevoked pins the priority rule for shared label and
// alias keys, using real ATT&CK ids: a live technique takes the key from a
// revoked holder, the earliest registration keeps it between holders of the same
// standing, and a technique's id key is never taken.
func TestBuilderLiveLabelBeatsRevoked(t *testing.T) {
	// Revoked registered first, live second.
	b := NewBuilder()
	old, err := b.AddTTP("T1015", "Accessibility Features", DomainEnterprise, NoParent, true)
	if err != nil {
		t.Fatal(err)
	}
	live, err := b.AddTTP("T1546.008", "Accessibility Features", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatal(err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := e.Incident("Accessibility Features"); !ok || got != live {
		t.Fatalf("Incident(Accessibility Features) = %d,%v want %d,true", got, ok, live)
	}
	if got, ok := e.Incident(" T1015 "); !ok || got != old {
		t.Fatalf("Incident(T1015) = %d,%v want %d,true (the id form is exact)", got, ok, old)
	}
	if !e.TTPRevoked(old) || e.TTPRevoked(live) {
		t.Fatalf("TTPRevoked = %v/%v, want true/false", e.TTPRevoked(old), e.TTPRevoked(live))
	}
	// Live registered first: the live holder keeps the key.
	b = NewBuilder()
	live, _ = b.AddTTP("T1546.008", "Accessibility Features", DomainEnterprise, NoParent, false)
	old, _ = b.AddTTP("T1015", "Accessibility Features", DomainEnterprise, NoParent, true)
	e, _ = b.Build()
	if got, _ := e.Incident("Accessibility Features"); got != live {
		t.Fatalf("Incident(Accessibility Features) = %d, want %d", got, live)
	}
	// Every holder revoked: the earliest registration keeps the key.
	b = NewBuilder()
	first, _ := b.AddTTP("T1073", "DLL Side-Loading", DomainEnterprise, NoParent, true)
	b.AddTTP("T1574.002", "DLL Side-Loading", DomainEnterprise, NoParent, true)
	e, _ = b.Build()
	if got, _ := e.Incident("DLL Side-Loading"); got != first {
		t.Fatalf("Incident(DLL Side-Loading) = %d, want %d", got, first)
	}
	// A live label never takes a revoked technique's id key.
	b = NewBuilder()
	byID, _ := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, true)
	b.AddTTP("T2", "T1003", DomainEnterprise, NoParent, false)
	e, _ = b.Build()
	if got, ok := e.Incident("T1003"); !ok || got != byID {
		t.Fatalf("Incident(T1003) = %d,%v want %d,true", got, ok, byID)
	}
}

// TestBuilderGroupLiveLabelBeatsRevoked is the grouping analog of
// TestBuilderLiveLabelBeatsRevoked, on the pair that made the difference: on the
// pinned 19.2 tables the label "TRITON" is carried by the deprecated S0609 and
// the live S1009, and resolving a shared label to the first registration handed
// the key to the retired node.
func TestBuilderGroupLiveLabelBeatsRevoked(t *testing.T) {
	// Revoked registered first, live second: the live node takes the key.
	b := NewBuilder()
	retired, err := b.AddGroup("S0609", "TRITON", GroupSoftware, true)
	if err != nil {
		t.Fatal(err)
	}
	live, err := b.AddGroup("S1009", "Triton", GroupSoftware, false)
	if err != nil {
		t.Fatal(err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := e.Group("triton"); !ok || got != live {
		t.Fatalf("Group(triton) = %d,%v want the live node %d", got, ok, live)
	}
	if got, ok := e.Group(" S0609 "); !ok || got != retired {
		t.Fatalf("Group(S0609) = %d,%v want the retired node %d (the id form is exact)", got, ok, retired)
	}
	if !e.GroupRevoked(retired) || e.GroupRevoked(live) {
		t.Fatalf("GroupRevoked = %v/%v, want true/false", e.GroupRevoked(retired), e.GroupRevoked(live))
	}
	// Live registered first: the live holder keeps the key.
	b = NewBuilder()
	live, _ = b.AddGroup("S1009", "Triton", GroupSoftware, false)
	retired, _ = b.AddGroup("S0609", "TRITON", GroupSoftware, true)
	e, _ = b.Build()
	if got, _ := e.Group("triton"); got != live {
		t.Fatalf("Group(triton) = %d, want the holder %d", got, live)
	}
	// Every holder revoked: the earliest registration keeps the key.
	b = NewBuilder()
	first, _ := b.AddGroup("S9000", "Ngrok", GroupSoftware, true)
	b.AddGroup("S9001", "ngrok", GroupSoftware, true)
	e, _ = b.Build()
	if got, _ := e.Group("ngrok"); got != first {
		t.Fatalf("Group(ngrok) = %d, want the earliest holder %d", got, first)
	}
	// A live label never takes a revoked node's id key.
	b = NewBuilder()
	byID, _ := b.AddGroup("S0609", "TRITON", GroupSoftware, true)
	b.AddGroup("S2", "S0609", GroupSoftware, false)
	e, _ = b.Build()
	if got, ok := e.Group("S0609"); !ok || got != byID {
		t.Fatalf("Group(S0609) = %d,%v want %d,true (the id key is never taken)", got, ok, byID)
	}
}

// TestBuilderValidation pins the cold-path input contract: an empty (or
// whitespace-only) key and an unknown domain are rejected without touching the
// builder's state.
func TestBuilderValidation(t *testing.T) {
	b := NewBuilder()

	if _, err := b.AddTTP("", "L", DomainEnterprise, NoParent, false); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddTTP empty id: %v", err)
	}
	if _, err := b.AddTTP("   ", "L", DomainEnterprise, NoParent, false); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddTTP blank id: %v", err)
	}
	if _, err := b.AddArtifact("", "L"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddArtifact empty name: %v", err)
	}
	if _, err := b.AddCountermeasure(" ", "L"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddCountermeasure blank id: %v", err)
	}
	if _, err := b.AddRel(""); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddRel empty name: %v", err)
	}
	if _, err := b.AddDefRel(" \t"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddDefRel blank name: %v", err)
	}
	if _, err := b.AddDataComponent("", "L"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddDataComponent empty id: %v", err)
	}
	if _, err := b.AddGroup("", "L", GroupActor, false); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddGroup empty id: %v", err)
	}
	if _, err := b.AddTactic("", "L"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddTactic empty id: %v", err)
	}
	if _, err := b.AddPlatform(""); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddPlatform empty name: %v", err)
	}
	if _, err := b.AddCWE("", "L"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddCWE empty id: %v", err)
	}
	if _, err := b.AddProduct("", "Alpha"); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddProduct empty vendor: %v", err)
	}
	if _, err := b.AddProduct("Avendor", ""); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddProduct empty product: %v", err)
	}
	if _, err := b.AddKEV("", "Name", "2099-01-01", false); !errors.Is(err, ErrEmptyKey) {
		t.Fatalf("AddKEV empty id: %v", err)
	}
	if b.TTPCount() != 0 || b.ArtifactCount() != 0 || b.CountermeasureCount() != 0 ||
		b.RelCount() != 0 || b.DefRelCount() != 0 || b.DataComponentCount() != 0 ||
		b.GroupCount() != 0 || b.TacticCount() != 0 || b.PlatformCount() != 0 ||
		b.CWECount() != 0 || b.ProductCount() != 0 || b.KEVCount() != 0 {
		t.Fatalf("rejected keys changed counts: %d %d %d %d %d %d %d %d %d %d %d %d",
			b.TTPCount(), b.ArtifactCount(), b.CountermeasureCount(), b.RelCount(), b.DefRelCount(),
			b.DataComponentCount(), b.GroupCount(), b.TacticCount(), b.PlatformCount(),
			b.CWECount(), b.ProductCount(), b.KEVCount())
	}

	if _, err := b.AddTTP("T1", "L", Domain(4), NoParent, false); !errors.Is(err, ErrUnknownDomain) {
		t.Fatalf("AddTTP domain 4: %v", err)
	}
	if _, err := b.AddTTP("T1", "L", Domain(255), NoParent, false); !errors.Is(err, ErrUnknownDomain) {
		t.Fatalf("AddTTP domain 255: %v", err)
	}
	if b.TTPCount() != 0 {
		t.Fatalf("rejected domain registered a node: TTPCount = %d", b.TTPCount())
	}

	for i, dom := range []Domain{DomainEnterprise, DomainICS, DomainMobile, DomainSPARTA} {
		id := "T" + strconv.Itoa(i)
		if _, err := b.AddTTP(id, "label "+id, dom, NoParent, false); err != nil {
			t.Fatalf("AddTTP %s domain %d: %v", id, dom, err)
		}
	}

	// An empty label is not an error, but it claims no lookup key.
	t9, err := b.AddTTP("T9", "", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("AddTTP empty label: %v", err)
	}
	if t9 != 4 {
		t.Fatalf("id with empty label = %d, want 4", t9)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := e.Incident(""); ok {
		t.Fatal("empty label must not become a lookup key")
	}
	if got := e.TTPLabel(t9); got != "" {
		t.Fatalf("TTPLabel = %q, want empty", got)
	}
}

// TestBuilderSingleUse is the regression test for the shared-backing-array
// hazard: after Build, no Add* may reach the live engine's slices.
func TestBuilderSingleUse(t *testing.T) {
	b := NewBuilder()
	t0, _ := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)
	c1, _ := b.AddTTP("T1003.001", "LSASS Memory", DomainEnterprise, t0, false)
	a0, _ := b.AddArtifact("Process", "Process")
	cm0, _ := b.AddCountermeasure("CredentialHardening", "Credential Hardening")
	r, _ := b.AddRel("accesses")
	dr, _ := b.AddDefRel("hardens")
	b.AddEdge(c1, a0, r)
	b.AddDefEdge(cm0, a0, dr)
	b.AddDefendsEdge(cm0, c1)

	if b.Built() {
		t.Fatal("Built must be false before Build")
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if !b.Built() {
		t.Fatal("Built must be true after Build")
	}

	if _, err := b.AddRel("later"); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddRel after Build: %v", err)
	}
	if _, err := b.AddDefRel("later"); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddDefRel after Build: %v", err)
	}
	if _, err := b.AddTTP("T1059", "later", DomainEnterprise, NoParent, false); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddTTP after Build: %v", err)
	}
	if _, err := b.AddArtifact("later", "later"); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddArtifact after Build: %v", err)
	}
	if _, err := b.AddCountermeasure("later", "later"); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddCountermeasure after Build: %v", err)
	}
	if err := b.AddEdge(t0, a0, r); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddEdge after Build: %v", err)
	}
	if err := b.AddDefEdge(cm0, a0, dr); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddDefEdge after Build: %v", err)
	}
	if err := b.AddDefendsEdge(cm0, t0); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("AddDefendsEdge after Build: %v", err)
	}
	if e2, err := b.Build(); !errors.Is(err, ErrBuilderUsed) || e2 != nil {
		t.Fatalf("second Build = %v, %v; want nil, ErrBuilderUsed", e2, err)
	}

	if got := e.TTPCount(); got != 2 {
		t.Fatalf("TTPCount = %d, want 2", got)
	}
	if got := e.TTPChildCount(t0); got != 1 {
		t.Fatalf("TTPChildCount = %d, want 1", got)
	}
	buf := make([]Artifact, 2)
	if n := e.Artifacts(c1, buf); n != 1 || buf[0] != a0 {
		t.Fatalf("Artifacts = %d %v, want 1 [%d]", n, buf[:n], a0)
	}
	if !e.Defends(cm0, c1) {
		t.Fatal("defends edge lost")
	}
}

// TestBuilderCopyCannotMutateEngine pins the rule that makes "a live Engine can
// never be mutated through its builder" absolute: the built flag is shared with
// a by-value copy, so a copy taken before Build is rejected too.
func TestBuilderCopyCannotMutateEngine(t *testing.T) {
	b := NewBuilder()
	t0, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	a0, err := b.AddArtifact("Process", "Process")
	if err != nil {
		t.Fatalf("AddArtifact: %v", err)
	}
	r, err := b.AddRel("accesses")
	if err != nil {
		t.Fatalf("AddRel: %v", err)
	}
	if err := b.AddEdge(t0, a0, r); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}

	c := *b // a copy taken before Build shares the maps, the slices and the flag
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if _, err := c.AddArtifact("later", "later"); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("copy AddArtifact after Build = %v, want ErrBuilderUsed", err)
	}
	if _, err := c.AddRel("later"); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("copy AddRel after Build = %v, want ErrBuilderUsed", err)
	}
	if _, err := c.AddTTP("T1059", "later", DomainEnterprise, NoParent, false); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("copy AddTTP after Build = %v, want ErrBuilderUsed", err)
	}
	if _, err := c.Build(); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("copy Build = %v, want ErrBuilderUsed", err)
	}
	if _, ok := e.Artifact("later"); ok {
		t.Fatal("a Builder copy mutated the live Engine")
	}
	if _, ok := e.Rel("later"); ok {
		t.Fatal("a Builder copy added a plane to the live Engine")
	}
	if n := e.ArtifactCount(); n != 1 {
		t.Fatalf("ArtifactCount = %d, want 1", n)
	}
}

func TestBuilderBoundsEdges(t *testing.T) {
	b := NewBuilder()
	b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)
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

// TestBuilderUnknownEndpoints covers the eight Err* values the attribute, group
// and KEV edge setters return for an unregistered endpoint, plus AddGroup's
// kind gate. The builder registers exactly one node on the side that must be in
// range — one technique, one grouping node, one KEV entry and one node of each
// KEV vocabulary — and none on the side that must be out of range, so tactic,
// platform and data-component stay empty.
func TestBuilderUnknownEndpoints(t *testing.T) {
	b := NewBuilder()
	if _, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false); err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	if _, err := b.AddGroup("G0001", "Actor One", GroupActor, false); err != nil {
		t.Fatalf("AddGroup: %v", err)
	}
	if _, err := b.AddKEV("CVE-2099-0001", "Alpha Flaw", "2099-01-01", false); err != nil {
		t.Fatalf("AddKEV: %v", err)
	}
	if _, err := b.AddCWE("CWE-20", "CWE-20"); err != nil {
		t.Fatalf("AddCWE: %v", err)
	}
	if _, err := b.AddProduct("Avendor", "Alpha"); err != nil {
		t.Fatalf("AddProduct: %v", err)
	}

	for _, tt := range []struct {
		name string
		got  error
		want error
	}{
		{"AddTacticEdge", b.AddTacticEdge(0, Tactic(0)), ErrUnknownTactic},
		{"AddPlatformEdge", b.AddPlatformEdge(0, Platform(0)), ErrUnknownPlatform},
		{"AddDetectsEdge", b.AddDetectsEdge(DataComponent(0), 0), ErrUnknownDataComponent},
		{"AddGroupUsesEdge", b.AddGroupUsesEdge(Group(1), 0), ErrUnknownGroup},
		{"AddGroupSoftwareEdge", b.AddGroupSoftwareEdge(0, Group(1)), ErrUnknownGroup},
		{"AddKEVWeaknessEdge kev", b.AddKEVWeaknessEdge(KEV(1), CWE(0)), ErrUnknownKEV},
		{"AddKEVWeaknessEdge cwe", b.AddKEVWeaknessEdge(KEV(0), CWE(1)), ErrUnknownCWE},
		{"AddKEVProductEdge kev", b.AddKEVProductEdge(KEV(1), Product(0)), ErrUnknownKEV},
		{"AddKEVProductEdge product", b.AddKEVProductEdge(KEV(0), Product(1)), ErrUnknownProduct},
		{"AddGroup kind", func() error { _, err := b.AddGroup("X9", "Unknown Kind", GroupKind(9), false); return err }(), ErrUnknownGroupKind},
	} {
		if !errors.Is(tt.got, tt.want) {
			t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.want)
		}
	}
}

func TestBuilderBoundsRels(t *testing.T) {
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

	for i := range 255 {
		if _, err := b.AddDefRel("defrel" + strconv.Itoa(i)); err != nil {
			t.Fatalf("AddDefRel #%d: %v", i, err)
		}
	}
	if _, err := b.AddDefRel("one-too-many"); !errors.Is(err, ErrTooManyRels) {
		t.Fatalf("AddDefRel past 255: %v", err)
	}
	if b.DefRelCount() != 255 {
		t.Fatalf("DefRelCount = %d, want 255", b.DefRelCount())
	}
}

// TestBuilderCountermeasureAliases: a countermeasure's label and aliases are
// lookup keys, exactly as a technique's are.
func TestBuilderCountermeasureAliases(t *testing.T) {
	b := NewBuilder()
	c0, err := b.AddCountermeasure("DE-0001", "Credential Hardening", "Credential Hardening Alias", "CH")
	if err != nil {
		t.Fatalf("AddCountermeasure: %v", err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	for _, key := range []string{"de-0001", "credential hardening", "credential hardening alias", "ch"} {
		got, ok := e.Countermeasure(key)
		if !ok || got != c0 {
			t.Fatalf("Countermeasure(%q) = %d,%v want %d,true", key, got, ok, c0)
		}
	}
}

func TestBuilderBoundsNodes(t *testing.T) {
	if testing.Short() {
		t.Skip("registers 65536 nodes")
	}
	b := NewBuilder()
	for i := range MaxNodes {
		id := "T" + strconv.Itoa(i)
		if _, err := b.AddTTP(id, "label "+id, DomainEnterprise, NoParent, false); err != nil {
			t.Fatalf("AddTTP #%d: %v", i, err)
		}
	}
	if b.TTPCount() != MaxNodes {
		t.Fatalf("TTPCount = %d, want %d", b.TTPCount(), MaxNodes)
	}
	if _, err := b.AddTTP("T-overflow", "x", DomainEnterprise, NoParent, false); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddTTP past cap: %v", err)
	}
	for i := range MaxNodes {
		id := "A" + strconv.Itoa(i)
		if _, err := b.AddArtifact(id, "label "+id); err != nil {
			t.Fatalf("AddArtifact #%d: %v", i, err)
		}
	}
	if b.ArtifactCount() != MaxNodes {
		t.Fatalf("ArtifactCount = %d, want %d", b.ArtifactCount(), MaxNodes)
	}
	if _, err := b.AddArtifact("A-overflow", "x"); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddArtifact past cap: %v", err)
	}
	for i := range MaxNodes {
		id := "C" + strconv.Itoa(i)
		if _, err := b.AddCountermeasure(id, "label "+id); err != nil {
			t.Fatalf("AddCountermeasure #%d: %v", i, err)
		}
	}
	if b.CountermeasureCount() != MaxNodes {
		t.Fatalf("CountermeasureCount = %d, want %d", b.CountermeasureCount(), MaxNodes)
	}
	if _, err := b.AddCountermeasure("C-overflow", "x"); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddCountermeasure past cap: %v", err)
	}
	for i := range MaxNodes {
		id := "DC" + strconv.Itoa(i)
		if _, err := b.AddDataComponent(id, "label "+id); err != nil {
			t.Fatalf("AddDataComponent #%d: %v", i, err)
		}
	}
	if b.DataComponentCount() != MaxNodes {
		t.Fatalf("DataComponentCount = %d, want %d", b.DataComponentCount(), MaxNodes)
	}
	if _, err := b.AddDataComponent("DC-overflow", "x"); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddDataComponent past cap: %v", err)
	}
	for i := range MaxNodes {
		id := "G" + strconv.Itoa(i)
		if _, err := b.AddGroup(id, "label "+id, GroupSoftware, false); err != nil {
			t.Fatalf("AddGroup #%d: %v", i, err)
		}
	}
	if b.GroupCount() != MaxNodes {
		t.Fatalf("GroupCount = %d, want %d", b.GroupCount(), MaxNodes)
	}
	if _, err := b.AddGroup("G-overflow", "x", GroupSoftware, false); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddGroup past cap: %v", err)
	}
	for i := range MaxNodes {
		id := "CWE-" + strconv.Itoa(i)
		if _, err := b.AddCWE(id, id); err != nil {
			t.Fatalf("AddCWE #%d: %v", i, err)
		}
	}
	if b.CWECount() != MaxNodes {
		t.Fatalf("CWECount = %d, want %d", b.CWECount(), MaxNodes)
	}
	if _, err := b.AddCWE("CWE-overflow", "CWE-overflow"); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddCWE past cap: %v", err)
	}
	for i := range MaxNodes {
		if _, err := b.AddProduct("Vendor", "Product"+strconv.Itoa(i)); err != nil {
			t.Fatalf("AddProduct #%d: %v", i, err)
		}
	}
	if b.ProductCount() != MaxNodes {
		t.Fatalf("ProductCount = %d, want %d", b.ProductCount(), MaxNodes)
	}
	if _, err := b.AddProduct("Vendor", "Product-overflow"); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddProduct past cap: %v", err)
	}
	for i := range MaxNodes {
		id := "CVE-2099-" + strconv.Itoa(i)
		if _, err := b.AddKEV(id, "name "+id, "2099-01-01", false); err != nil {
			t.Fatalf("AddKEV #%d: %v", i, err)
		}
	}
	if b.KEVCount() != MaxNodes {
		t.Fatalf("KEVCount = %d, want %d", b.KEVCount(), MaxNodes)
	}
	if _, err := b.AddKEV("CVE-2099-overflow", "x", "2099-01-01", false); !errors.Is(err, ErrTooManyNodes) {
		t.Fatalf("AddKEV past cap: %v", err)
	}
}

// TestBuilderHierarchy covers the contiguous-child invariant that makes the
// O(1) child range valid, plus the two-level depth limit.
func TestBuilderHierarchy(t *testing.T) {
	b := NewBuilder()
	// Depth-first registration: children immediately after their parent.
	p0, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("parent: %v", err)
	}
	c1, err := b.AddTTP("T1003.001", "LSASS Memory", DomainEnterprise, p0, false)
	if err != nil {
		t.Fatalf("child 1: %v", err)
	}
	c2, err := b.AddTTP("T1003.002", "Security Account Manager", DomainEnterprise, p0, false)
	if err != nil {
		t.Fatalf("child 2: %v", err)
	}
	p1, err := b.AddTTP("T1004", "Winlogon Helper DLL", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("parent 1: %v", err)
	}
	c3, err := b.AddTTP("T1004.001", "Winlogon Helper DLL Sub", DomainEnterprise, p1, false)
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
	// The builder is single-use: a re-add after Build is rejected and must not
	// touch the engine's slices.
	if _, err := b.AddTTP("T1003.001", "ignored", DomainICS, NoParent, false); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("post-Build re-add: %v", err)
	}
	if n := e.TTPChildCount(p0); n != 2 {
		t.Fatalf("re-add changed hierarchy: child count %d, want 2", n)
	}
}

func TestBuilderBoundsHierarchy(t *testing.T) {
	b := NewBuilder()
	b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)

	// Forward / out-of-range parent.
	if _, err := b.AddTTP("T1003.001", "sub", DomainEnterprise, TTP(7), false); !errors.Is(err, ErrUnknownParent) {
		t.Fatalf("forward parent: %v", err)
	}
	// Real child of T1003 at index 1.
	if _, err := b.AddTTP("T1003.001", "sub", DomainEnterprise, TTP(0), false); err != nil {
		t.Fatalf("child: %v", err)
	}
	// Index 1 is a sub-technique: it cannot parent a grandchild.
	if _, err := b.AddTTP("T1003.001.001", "grandchild", DomainEnterprise, TTP(1), false); !errors.Is(err, ErrDepthExceeded) {
		t.Fatalf("grandchild: %v", err)
	}
	// NoParent is not a parent: the node registers top-level.
	if _, err := b.AddTTP("T1004", "top-level", DomainEnterprise, NoParent, false); err != nil {
		t.Fatalf("top-level: %v", err)
	}
	// Registering an unrelated node breaks the contiguous child block: index 3
	// cannot extend T1003's block (which ends at index 1).
	b.AddTTP("T1005", "unrelated", DomainEnterprise, NoParent, false)
	if _, err := b.AddTTP("T1003.003", "late child", DomainEnterprise, TTP(0), false); !errors.Is(err, ErrNonContiguousChild) {
		t.Fatalf("non-contiguous child: %v", err)
	}
}

// TestBuilderVocabularyCap pins the attribute vocabulary bound: a technique's
// tactic and platform masks are one uint64 each, so the 65th registration must be
// refused rather than accepted into a stride TTPTactics/TTPPlatforms cannot read
// (they return word 0 of the row, so bit 64 would be silently lost).
func TestBuilderVocabularyCap(t *testing.T) {
	b := NewBuilder()
	var tactics []Tactic
	for i := range 64 {
		ta, err := b.AddTactic(fmt.Sprintf("TA%04d", i), fmt.Sprintf("Tactic %d", i))
		if err != nil {
			t.Fatalf("AddTactic #%d: %v", i, err)
		}
		tactics = append(tactics, ta)
	}
	if b.TacticCount() != 64 {
		t.Fatalf("TacticCount = %d, want 64", b.TacticCount())
	}
	if _, err := b.AddTactic("TA-overflow", "overflow"); !errors.Is(err, ErrTooManyTactics) {
		t.Fatalf("65th AddTactic = %v, want ErrTooManyTactics", err)
	}
	var platforms []Platform
	for i := range 64 {
		p, err := b.AddPlatform(fmt.Sprintf("Platform %d", i))
		if err != nil {
			t.Fatalf("AddPlatform #%d: %v", i, err)
		}
		platforms = append(platforms, p)
	}
	if b.PlatformCount() != 64 {
		t.Fatalf("PlatformCount = %d, want 64", b.PlatformCount())
	}
	if _, err := b.AddPlatform("Platform overflow"); !errors.Is(err, ErrTooManyPlatforms) {
		t.Fatalf("65th AddPlatform = %v, want ErrTooManyPlatforms", err)
	}

	// The last index of the space must still be readable as a bit: this is the
	// read the 256-entry cap silently truncated.
	ttp, err := b.AddTTP("T1003", "OS Credential Dumping", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	if err := b.AddTacticEdge(ttp, tactics[63]); err != nil {
		t.Fatalf("AddTacticEdge: %v", err)
	}
	if err := b.AddPlatformEdge(ttp, platforms[63]); err != nil {
		t.Fatalf("AddPlatformEdge: %v", err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := e.TTPTactics(ttp); got != 1<<63 {
		t.Errorf("TTPTactics = %#b, want 1<<63", got)
	}
	if got := e.TTPPlatforms(ttp); got != 1<<63 {
		t.Errorf("TTPPlatforms = %#b, want 1<<63", got)
	}
}

// The fixture's sizes are its own, not a catalog release's: they are chosen so
// the KEV strides are the 28/3/12-word rows the layout exercises. Any entry
// count in [1729, 1792] keeps the 28-word stride, so a KEV re-pin never edits
// this file.
const (
	fixTTP      = 1186
	fixArt      = 247
	fixCM       = 157
	fixRel      = 41
	fixDefRel   = 38
	fixTactic   = 41
	fixPlatform = 15
	fixDC       = 123
	fixGroup    = 1212
	fixCWE      = 189
	fixProduct  = 726
	fixKEV      = 1748
)

// TestLayoutMatchesReadme pins the memory table the README publishes: every one
// of the twenty-one frozen arrays must be exactly planes × rows × row stride
// words, with the stride ceil(other-side count / 64). The fixture's counts are
// local constants, so the test checks the builder's allocation rule rather than
// a catalog release; ontology_test.go's TestOntologyLayoutArithmetic recomputes
// the same formulas from the generated constants. Bytes are not asserted: they
// are words * 8.
func TestLayoutMatchesReadme(t *testing.T) {
	b := NewBuilder()
	for i := range fixTTP {
		// The generatedEngine parent rule: every tenth node is a parent, so the
		// contiguous-child invariant holds and the counts match the tables.
		parent := NoParent
		if k := i % 10; k != 0 {
			parent = TTP(i - k)
		}
		if _, err := b.AddTTP("T"+strconv.Itoa(i), "t"+strconv.Itoa(i), DomainEnterprise, parent, false); err != nil {
			t.Fatalf("AddTTP #%d: %v", i, err)
		}
	}
	for i := range fixArt {
		if _, err := b.AddArtifact("A"+strconv.Itoa(i), "a"+strconv.Itoa(i)); err != nil {
			t.Fatalf("AddArtifact #%d: %v", i, err)
		}
	}
	for i := range fixCM {
		if _, err := b.AddCountermeasure("CM"+strconv.Itoa(i), "cm"+strconv.Itoa(i)); err != nil {
			t.Fatalf("AddCountermeasure #%d: %v", i, err)
		}
	}
	for i := range fixRel {
		if _, err := b.AddRel("rel" + strconv.Itoa(i)); err != nil {
			t.Fatalf("AddRel #%d: %v", i, err)
		}
	}
	for i := range fixDefRel {
		if _, err := b.AddDefRel("defrel" + strconv.Itoa(i)); err != nil {
			t.Fatalf("AddDefRel #%d: %v", i, err)
		}
	}
	for i := range fixTactic {
		if _, err := b.AddTactic("TA"+strconv.Itoa(i), "tactic "+strconv.Itoa(i)); err != nil {
			t.Fatalf("AddTactic #%d: %v", i, err)
		}
	}
	for i := range fixPlatform {
		if _, err := b.AddPlatform("platform " + strconv.Itoa(i)); err != nil {
			t.Fatalf("AddPlatform #%d: %v", i, err)
		}
	}
	for i := range fixDC {
		if _, err := b.AddDataComponent("DC"+strconv.Itoa(i), "dc"+strconv.Itoa(i)); err != nil {
			t.Fatalf("AddDataComponent #%d: %v", i, err)
		}
	}
	for i := range fixGroup {
		if _, err := b.AddGroup("G"+strconv.Itoa(i), "g"+strconv.Itoa(i), GroupActor, false); err != nil {
			t.Fatalf("AddGroup #%d: %v", i, err)
		}
	}
	for i := range fixCWE {
		id := "CWE-" + strconv.Itoa(i)
		if _, err := b.AddCWE(id, id); err != nil {
			t.Fatalf("AddCWE #%d: %v", i, err)
		}
	}
	for i := range fixProduct {
		if _, err := b.AddProduct("Vendor"+strconv.Itoa(i), "Product "+strconv.Itoa(i)); err != nil {
			t.Fatalf("AddProduct #%d: %v", i, err)
		}
	}
	for i := range fixKEV {
		if _, err := b.AddKEV("CVE-2000-"+strconv.Itoa(10000+i), "Entry "+strconv.Itoa(i), "2000-01-01", false); err != nil {
			t.Fatalf("AddKEV #%d: %v", i, err)
		}
	}
	// Every entry names exactly one product: Build rejects a graph that leaves
	// one without (ErrKEVWithoutProduct). The edges only set bits, so every
	// word count pinned below is unchanged.
	for i := range fixKEV {
		if err := b.AddKEVProductEdge(KEV(i), Product(i%fixProduct)); err != nil {
			t.Fatalf("AddKEVProductEdge #%d: %v", i, err)
		}
	}
	if err := b.AddEdge(TTP(0), Artifact(0), Rel(1)); err != nil {
		t.Fatalf("AddEdge: %v", err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	offPlanes := fixRel + 1 // plane 0 of each family is the union
	defPlanes := fixDefRel + 1
	wTTP, wArt, wCM, wDC := wordsFor(fixTTP), wordsFor(fixArt), wordsFor(fixCM), wordsFor(fixDC)
	wGrp, wTactic, wPlatform := wordsFor(fixGroup), wordsFor(fixTactic), wordsFor(fixPlatform)
	wKEV, wCWE, wProduct := wordsFor(fixKEV), wordsFor(fixCWE), wordsFor(fixProduct)
	blocks := []struct {
		name  string
		words int
		want  int
	}{
		{"ttpArt", len(e.ttpArt), offPlanes * fixTTP * wArt},
		{"artTTP", len(e.artTTP), offPlanes * fixArt * wTTP},
		{"cmArt", len(e.cmArt), defPlanes * fixCM * wArt},
		{"artCM", len(e.artCM), defPlanes * fixArt * wCM},
		{"cmTTP", len(e.cmTTP), fixCM * wTTP},
		{"ttpCM", len(e.ttpCM), fixTTP * wCM},
		{"tacticTTP", len(e.tacticTTP), fixTactic * wTTP},
		{"ttpTactic", len(e.ttpTactic), fixTTP * wTactic},
		{"platformTTP", len(e.platformTTP), fixPlatform * wTTP},
		{"ttpPlatform", len(e.ttpPlatform), fixTTP * wPlatform},
		{"ttpFlags", len(e.ttpFlags), fixTTP},
		{"dcTTP", len(e.dcTTP), fixDC * wTTP},
		{"ttpDC", len(e.ttpDC), fixTTP * wDC},
		{"grpTTP", len(e.grpTTP), fixGroup * wTTP},
		{"ttpGrp", len(e.ttpGrp), fixTTP * wGrp},
		{"grpSoftware", len(e.grpSoftware), fixGroup * wGrp},
		{"softwareGrp", len(e.softwareGrp), fixGroup * wGrp},
		{"kevCWE", len(e.kevCWE), fixKEV * wCWE},
		{"cweKEV", len(e.cweKEV), fixCWE * wKEV},
		{"kevProduct", len(e.kevProduct), fixKEV * wProduct},
		{"productKEV", len(e.productKEV), fixProduct * wKEV},
	}
	subtotal, newArrays := 0, 0
	for i, bl := range blocks {
		if bl.words != bl.want {
			t.Errorf("%s = %d words, want %d (planes × rows × stride)", bl.name, bl.words, bl.want)
		}
		if i < 6 {
			subtotal += bl.words
		} else {
			newArrays += bl.words
		}
	}
	t.Logf("six blocks %d words, new arrays %d words, total %d", subtotal, newArrays, subtotal+newArrays)
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
	if e.WordsPerRow(KindKEV) != 0 || e.WordsPerRow(KindCWE) != 0 || e.WordsPerRow(KindProduct) != 0 {
		t.Fatal("KEV strides must be 0 for an empty engine")
	}
	if e.KEVCount() != 0 || e.CWECount() != 0 || e.ProductCount() != 0 {
		t.Fatal("KEV counts must be 0 for an empty engine")
	}
	if n := e.KEVCWEDegree(0); n != 0 {
		t.Fatalf("KEVCWEDegree = %d, want 0", n)
	}
	if n := e.CWEsForKEV(0, nil); n != 0 {
		t.Fatalf("CWEsForKEV = %d, want 0", n)
	}
	if n := e.KEVsForCWE(0, nil); n != 0 {
		t.Fatalf("KEVsForCWE = %d, want 0", n)
	}
	if n := e.ProductsForKEV(0, nil); n != 0 {
		t.Fatalf("ProductsForKEV = %d, want 0", n)
	}
	if n := e.KEVsForProducts(nil, nil, nil); n != 0 {
		t.Fatalf("KEVsForProducts = %d, want 0", n)
	}
	if n := e.KEVsForCWEs(nil, nil, nil); n != 0 {
		t.Fatalf("KEVsForCWEs = %d, want 0", n)
	}
	if _, ok := e.KEV("CVE-2021-44228"); ok {
		t.Fatal("KEV on an empty engine must be false")
	}
	if _, ok := e.CWE("CWE-78"); ok {
		t.Fatal("CWE on an empty engine must be false")
	}
	if _, ok := e.Product("Apache", "Log4j2"); ok {
		t.Fatal("Product on an empty engine must be false")
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
	// The union plane is seeded even when nothing is registered, so plane 0
	// always round-trips through name and id.
	if got := e.RelName(RelAny); got != "any" {
		t.Fatalf("RelName(RelAny) = %q, want any", got)
	}
	if r, ok := e.Rel("any"); !ok || r != RelAny {
		t.Fatalf("Rel(any) = %d, %v, want RelAny, true", r, ok)
	}
}

// TestZeroEngine: the zero Engine has no nodes and no planes, so its counts are
// 0 (never -1) and the id-space methods that do not take a relation stay total.
func TestZeroEngine(t *testing.T) {
	var e Engine
	if e.RelCount() != 0 || e.DefRelCount() != 0 {
		t.Fatalf("zero Engine rel counts = %d %d, want 0 0", e.RelCount(), e.DefRelCount())
	}
	if e.TTPCount() != 0 || e.ArtifactCount() != 0 || e.CountermeasureCount() != 0 {
		t.Fatalf("zero Engine counts = %d %d %d, want 0 0 0", e.TTPCount(), e.ArtifactCount(), e.CountermeasureCount())
	}
	if e.WordsPerRow(KindTTP) != 0 || e.WordsPerRow(KindArtifact) != 0 || e.WordsPerRow(KindCountermeasure) != 0 {
		t.Fatal("zero Engine strides must be 0")
	}
	if e.WordsPerRow(KindKEV) != 0 || e.WordsPerRow(KindCWE) != 0 || e.WordsPerRow(KindProduct) != 0 {
		t.Fatal("zero Engine KEV strides must be 0")
	}
	if e.KEVCount() != 0 || e.CWECount() != 0 || e.ProductCount() != 0 {
		t.Fatal("zero Engine KEV counts must be 0")
	}
	// The zero Engine has no KEV rows at all, so even the scratch-free reads
	// answer 0 rather than panicking.
	if n := e.KEVCWEDegree(0); n != 0 {
		t.Fatalf("zero Engine KEVCWEDegree = %d, want 0", n)
	}
	if n := e.KEVsForProducts(nil, nil, nil); n != 0 {
		t.Fatalf("zero Engine KEVsForProducts = %d, want 0", n)
	}
	if _, ok := e.KEV("CVE-2021-44228"); ok {
		t.Fatal("zero Engine must resolve no KEV entry")
	}
	if _, ok := e.CWE("CWE-78"); ok {
		t.Fatal("zero Engine must resolve no CWE")
	}
	if _, ok := e.Product("Apache", "Log4j2"); ok {
		t.Fatal("zero Engine must resolve no product")
	}
	if _, ok := e.TTPParent(0); ok {
		t.Fatal("zero Engine TTPParent must be false")
	}
	if n := e.TTPChildCount(0); n != 0 {
		t.Fatalf("TTPChildCount = %d, want 0", n)
	}
	if n := e.TTPChildren(0, nil); n != 0 {
		t.Fatalf("TTPChildren = %d, want 0", n)
	}
	if n := e.Response(nil, []TTP{0}); n != 1 {
		t.Fatalf("Response count = %d, want 1", n)
	}
	if _, ok := e.Incident("T1003"); ok {
		t.Fatal("zero Engine must resolve nothing")
	}
}

// TestBuilderZeroValue: the zero value behaves like NewBuilder(), so a
// `new(Builder)` is not a trap — plane 0 exists and every Add* has its maps.
func TestBuilderZeroValue(t *testing.T) {
	// A pristine zero value has no planes: both counts are 0, never -1.
	var z Builder
	if z.RelCount() != 0 || z.DefRelCount() != 0 {
		t.Fatalf("zero Builder rel counts = %d %d, want 0 0", z.RelCount(), z.DefRelCount())
	}
	e, err := new(Builder).Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if e.RelCount() != 0 || e.DefRelCount() != 0 {
		t.Fatalf("rel counts = %d %d, want 0 0", e.RelCount(), e.DefRelCount())
	}
	if e.RelName(RelAny) != "any" {
		t.Fatalf("RelName(RelAny) = %q, want any", e.RelName(RelAny))
	}
	if r, ok := e.Rel("any"); !ok || r != RelAny {
		t.Fatalf("Rel(any) = %d, %v, want RelAny, true", r, ok)
	}

	// A fresh zero-value builder is registrable, and Build stays single-use.
	b := new(Builder)
	if _, err := b.AddRel("x"); err != nil {
		t.Fatalf("AddRel: %v", err)
	}
	if _, err := b.Build(); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, err := b.Build(); !errors.Is(err, ErrBuilderUsed) {
		t.Fatalf("second Build = %v, want ErrBuilderUsed", err)
	}
}

// TestBuilderReservedRelName pins the union plane's reserved name: "any" is a
// lookup key for RelAny/DefRelAny, not a registrable predicate.
func TestBuilderReservedRelName(t *testing.T) {
	b := NewBuilder()
	for _, name := range []string{"any", " ANY ", "Any"} {
		if _, err := b.AddRel(name); !errors.Is(err, ErrReservedName) {
			t.Fatalf("AddRel(%q) = %v, want ErrReservedName", name, err)
		}
		if _, err := b.AddDefRel(name); !errors.Is(err, ErrReservedName) {
			t.Fatalf("AddDefRel(%q) = %v, want ErrReservedName", name, err)
		}
	}
	r, err := b.AddRel("accesses")
	if err != nil || r != 1 {
		t.Fatalf("AddRel(accesses) = %d, %v, want 1, nil", r, err)
	}
	if again, err := b.AddRel(" ACCESSES "); err != nil || again != r {
		t.Fatalf("AddRel repeat = %d, %v, want %d, nil", again, err, r)
	}
	if b.RelCount() != 1 {
		t.Fatalf("RelCount = %d, want 1 (a rejected name must not take a plane)", b.RelCount())
	}
}

// TestBuilderAddTTPIdempotentArguments pins the idempotency rule: a duplicate id
// is a no-op for every argument, including an invalid domain.
func TestBuilderAddTTPIdempotentArguments(t *testing.T) {
	b := NewBuilder()
	if _, err := b.AddTTP("T1", "One", Domain(9), NoParent, false); !errors.Is(err, ErrUnknownDomain) {
		t.Fatalf("fresh AddTTP with bad domain = %v, want ErrUnknownDomain", err)
	}
	t0, err := b.AddTTP("T1", "One", DomainEnterprise, NoParent, false)
	if err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	again, err := b.AddTTP("T1", "Two", Domain(9), NoParent, false, "alias")
	if err != nil {
		t.Fatalf("repeat AddTTP = %v, want nil (a duplicate ignores its arguments)", err)
	}
	if again != t0 {
		t.Fatalf("repeat AddTTP = %d, want %d", again, t0)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := e.TTPLabel(t0); got != "One" {
		t.Fatalf("TTPLabel = %q, want One (a duplicate must not relabel)", got)
	}
	if _, ok := e.Incident("alias"); ok {
		t.Fatal("a duplicate's alias must not be registered")
	}
}

// TestDomainAndGroupKindString pins the two Stringer methods the CLI and the
// examples print with: the four domain names, the three object types, and the
// fallback that keeps a value outside the constants printable instead of
// silently rendering a number.
func TestDomainAndGroupKindString(t *testing.T) {
	for _, c := range []struct {
		d    Domain
		want string
	}{
		{DomainEnterprise, "enterprise"},
		{DomainICS, "ics"},
		{DomainMobile, "mobile"},
		{DomainSPARTA, "sparta"},
		{Domain(4), "domain(4)"},
	} {
		if got := c.d.String(); got != c.want {
			t.Errorf("Domain(%d).String() = %q, want %q", int(c.d), got, c.want)
		}
	}
	for _, c := range []struct {
		k    GroupKind
		want string
	}{
		{GroupActor, "actor"},
		{GroupSoftware, "software"},
		{GroupCampaign, "campaign"},
		{GroupKind(3), "kind(3)"},
	} {
		if got := c.k.String(); got != c.want {
			t.Errorf("GroupKind(%d).String() = %q, want %q", int(c.k), got, c.want)
		}
	}
}
