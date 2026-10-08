//go:build goexperiment.simd

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/gr4ph"
	"github.com/fr0g-66723067-io/gr4ph/ontology"
)

// fixtureEngine builds the small graph every fixture expectation below is
// derived from. Registration order fixes the dense ids (techniques in
// registration order, relations in registration order, plane 0 the union), so
// the expected id lists are deterministic.
func fixtureEngine(t *testing.T) *gr4ph.Engine {
	t.Helper()
	b := gr4ph.NewBuilder()
	accesses := mustRel(t, b, "accesses")    // offensive plane 1
	blocks := mustRel(t, b, "blocks")        // offensive plane 2
	analyzes := mustDefRel(t, b, "analyzes") // defensive plane 1
	hardens := mustDefRel(t, b, "hardens")   // defensive plane 2
	defBlocks := mustDefRel(t, b, "blocks")  // defensive plane 3: the name exists in both families
	t1003 := mustTTP(t, b, "T1003", "OS Credential Dumping", gr4ph.DomainEnterprise, gr4ph.NoParent, false)
	sub := mustTTP(t, b, "T1003.001", "LSASS Memory", gr4ph.DomainEnterprise, t1003, false)
	mustTTP(t, b, "T1059", "Command and Scripting Interpreter", gr4ph.DomainEnterprise, gr4ph.NoParent, false) // no edges
	// The revoked twin and its live successor share a label; both are isolated,
	// so the dense ids of the nodes above do not move.
	mustTTP(t, b, "T1015", "Accessibility Features", gr4ph.DomainEnterprise, gr4ph.NoParent, true)
	mustTTP(t, b, "T1546.008", "Accessibility Features", gr4ph.DomainEnterprise, gr4ph.NoParent, false)
	process := mustArtifact(t, b, "Process", "Process") // label == name
	auth := mustArtifact(t, b, "AuthenticationService", "Authentication Service")
	hardening := mustCountermeasure(t, b, "CredentialHardening", "Credential Hardening")
	quarantine := mustCountermeasure(t, b, "ContentQuarantine", "Content Quarantine")
	must(t, b.AddEdge(sub, process, accesses))
	must(t, b.AddEdge(sub, auth, blocks))
	must(t, b.AddDefEdge(hardening, process, analyzes))
	must(t, b.AddDefEdge(hardening, auth, hardens))
	must(t, b.AddDefEdge(quarantine, auth, defBlocks))
	must(t, b.AddDefendsEdge(hardening, sub))
	must(t, b.AddDefendsEdge(quarantine, sub))

	// Vocabularies (registration order fixes the mask bit positions), the
	// data-component and grouping partitions, and the attribute edges.
	taInitial := mustTactic(t, b, "TA0001", "Initial Access")
	taExecution := mustTactic(t, b, "TA0002", "Execution")
	windows := mustPlatform(t, b, "Windows")
	linux := mustPlatform(t, b, "Linux")
	dcProcess := mustDC(t, b, "DC0001", "Process Creation")
	mustDC(t, b, "DC0002", "File Creation") // registered, deliberately edge-less
	actor := mustGroup(t, b, "G0001", "Actor One", gr4ph.GroupActor)
	software := mustGroup(t, b, "S0001", "Software One", gr4ph.GroupSoftware)
	mustGroup(t, b, "C0001", "Campaign One", gr4ph.GroupCampaign)
	must(t, b.AddTacticEdge(t1003, taInitial))
	must(t, b.AddTacticEdge(sub, taExecution))
	must(t, b.AddPlatformEdge(t1003, windows))
	must(t, b.AddPlatformEdge(t1003, linux))
	must(t, b.AddPlatformEdge(sub, windows))
	must(t, b.AddDetectsEdge(dcProcess, sub))
	must(t, b.AddGroupUsesEdge(actor, t1003))
	must(t, b.AddGroupSoftwareEdge(actor, software))
	e, err := b.Build()
	if err != nil {
		t.Fatalf("build fixture: %v", err)
	}
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("register: %v", err)
	}
}

func mustRel(t *testing.T, b *gr4ph.Builder, name string) gr4ph.Rel {
	t.Helper()
	r, err := b.AddRel(name)
	must(t, err)
	return r
}

func mustDefRel(t *testing.T, b *gr4ph.Builder, name string) gr4ph.DefRel {
	t.Helper()
	dr, err := b.AddDefRel(name)
	must(t, err)
	return dr
}

func mustTTP(t *testing.T, b *gr4ph.Builder, id, label string, dom gr4ph.Domain, parent gr4ph.TTP, revoked bool) gr4ph.TTP {
	t.Helper()
	tt, err := b.AddTTP(id, label, dom, parent, revoked)
	must(t, err)
	return tt
}

func mustArtifact(t *testing.T, b *gr4ph.Builder, name, label string) gr4ph.Artifact {
	t.Helper()
	a, err := b.AddArtifact(name, label)
	must(t, err)
	return a
}

func mustTactic(t *testing.T, b *gr4ph.Builder, id, label string) gr4ph.Tactic {
	t.Helper()
	v, err := b.AddTactic(id, label)
	must(t, err)
	return v
}

func mustPlatform(t *testing.T, b *gr4ph.Builder, name string) gr4ph.Platform {
	t.Helper()
	v, err := b.AddPlatform(name)
	must(t, err)
	return v
}

func mustDC(t *testing.T, b *gr4ph.Builder, id, label string) gr4ph.DataComponent {
	t.Helper()
	v, err := b.AddDataComponent(id, label)
	must(t, err)
	return v
}

func mustGroup(t *testing.T, b *gr4ph.Builder, id, label string, kind gr4ph.GroupKind) gr4ph.Group {
	t.Helper()
	v, err := b.AddGroup(id, label, kind)
	must(t, err)
	return v
}

func mustCountermeasure(t *testing.T, b *gr4ph.Builder, id, label string) gr4ph.Countermeasure {
	t.Helper()
	cm, err := b.AddCountermeasure(id, label)
	must(t, err)
	return cm
}

// runCase runs one invocation through run and returns stdout, stderr and the
// exit status.
func runCase(t *testing.T, e *gr4ph.Engine, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	status := run(e, args, &stdout, &stderr)
	return stdout.String(), stderr.String(), status
}

// The fixture blocks, quoted by more than one case.
const (
	fixtureTTPSub = `ttp T1003.001 "LSASS Memory" domain=enterprise parent=T1003 children=0 subtechnique=true tactics=TA0002 platforms=Windows
  out artifacts (2): Process, AuthenticationService "Authentication Service"
  out artifacts rollup (2): Process, AuthenticationService "Authentication Service"
  in  countermeasures (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  countermeasures rollup (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  data components (1): DC0001 "Process Creation"
  in  data components rollup (1): DC0001 "Process Creation"
  in  groups (0): -
`

	fixtureTTPParent = `ttp T1003 "OS Credential Dumping" domain=enterprise children=1 tactics=TA0001 platforms=Windows,Linux
  out artifacts (0): -
  out artifacts rollup (2): Process, AuthenticationService "Authentication Service"
  in  countermeasures (0): -
  in  countermeasures rollup (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  data components (0): -
  in  data components rollup (1): DC0001 "Process Creation"
  in  groups (1): G0001 "Actor One"
`

	fixtureTTPIsolated = `ttp T1059 "Command and Scripting Interpreter" domain=enterprise children=0
  out artifacts (0): -
  out artifacts rollup (0): -
  in  countermeasures (0): -
  in  countermeasures rollup (0): -
  in  data components (0): -
  in  data components rollup (0): -
  in  groups (0): -
`

	fixtureTTPSubBlocks = `ttp T1003.001 "LSASS Memory" domain=enterprise parent=T1003 children=0 subtechnique=true tactics=TA0002 platforms=Windows
  out artifacts (rel blocks) (1): AuthenticationService "Authentication Service"
  out artifacts rollup (rel blocks) (1): AuthenticationService "Authentication Service"
  in  countermeasures (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  countermeasures rollup (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  data components (1): DC0001 "Process Creation"
  in  data components rollup (1): DC0001 "Process Creation"
  in  groups (0): -
`

	fixtureArtifactProcess = `artifact Process
  in  techniques (1): T1003.001 "LSASS Memory"
  in  techniques rollup (1): T1003 "OS Credential Dumping"
  in  countermeasures (1): CredentialHardening "Credential Hardening"
  in  countermeasures viaTTPs (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
`

	fixtureCMHardening = `cm CredentialHardening "Credential Hardening"
  out artifacts (2): Process, AuthenticationService "Authentication Service"
  out techniques (1): T1003.001 "LSASS Memory"
  out techniques rollup (1): T1003 "OS Credential Dumping"
`

	fixtureRelAny = `rel any offensive union plane 0/2 (technique -> artifact): edges=2 sources=1
rel any defensive union plane 0/3 (countermeasure -> artifact): edges=3 sources=2
`

	fixtureRelBlocks = `rel blocks offensive plane 2/2 (technique -> artifact): edges=1 sources=1
rel blocks defensive plane 3/3 (countermeasure -> artifact): edges=1 sources=1
`

	// The revoked twin of the shared label, reached by id only.
	fixtureTTPRevoked = `ttp T1015 "Accessibility Features" domain=enterprise children=0 revoked=true
  out artifacts (0): -
  out artifacts rollup (0): -
  in  countermeasures (0): -
  in  countermeasures rollup (0): -
  in  data components (0): -
  in  data components rollup (0): -
  in  groups (0): -
`

	// The live carrier of that label, reached by the label.
	fixtureTTPLive = `ttp T1546.008 "Accessibility Features" domain=enterprise children=0
  out artifacts (0): -
  out artifacts rollup (0): -
  in  countermeasures (0): -
  in  countermeasures rollup (0): -
  in  data components (0): -
  in  data components rollup (0): -
  in  groups (0): -
`
	fixtureDCProcess = `dc DC0001 "Process Creation"
  out techniques (1): T1003.001 "LSASS Memory"
`

	// A registered data component with no detects edge: a node, an empty set.
	fixtureDCFile = `dc DC0002 "File Creation"
  out techniques (0): -
`

	fixtureGroupActor = `group G0001 "Actor One" kind=actor
  out techniques (1): T1003 "OS Credential Dumping"
  out software (1): S0001 "Software One"
  in  groups (0): -
`

	fixtureGroupSoftware = `group S0001 "Software One" kind=software
  out techniques (0): -
  out software (0): -
  in  groups (1): G0001 "Actor One"
`

	fixtureGroupCampaign = `group C0001 "Campaign One" kind=campaign
  out techniques (0): -
  out software (0): -
  in  groups (0): -
`

	fixtureTacticInitial = `tactic TA0001 "Initial Access"
  out techniques (1): T1003 "OS Credential Dumping"
`

	fixturePlatformWindows = `platform Windows
  out techniques (2): T1003 "OS Credential Dumping", T1003.001 "LSASS Memory"
`
)

// TestTextFixture pins the text encoder byte for byte, one case per behaviour,
// against the hand-built fixture graph.
func TestTextFixture(t *testing.T) {
	e := fixtureEngine(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			"sub-technique, exact and rolled up",
			[]string{"ttp", "T1003.001"},
			fixtureTTPSub,
		},
		{
			"top-level technique rolls its children up",
			[]string{"ttp", "T1003"},
			fixtureTTPParent,
		},
		{
			"technique with no edges at all",
			[]string{"ttp", "T1059"},
			fixtureTTPIsolated,
		},
		{
			"offensive relation filter names the plane",
			[]string{"ttp", "-rel", "blocks", "T1003.001"},
			fixtureTTPSubBlocks,
		},
		{
			"artifact, direct and via techniques",
			[]string{"artifact", "Process"},
			fixtureArtifactProcess,
		},
		{
			"artifact with a defensive relation filter",
			[]string{"artifact", "-defrel", "hardens", "Process"},
			`artifact Process
  in  techniques (1): T1003.001 "LSASS Memory"
  in  techniques rollup (1): T1003 "OS Credential Dumping"
  in  countermeasures (defrel hardens) (0): -
  in  countermeasures viaTTPs (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
`,
		},
		{
			"countermeasure",
			[]string{"cm", "CredentialHardening"},
			fixtureCMHardening,
		},
		{
			"countermeasure with a defensive relation filter",
			[]string{"cm", "-defrel", "blocks", "ContentQuarantine"},
			`cm ContentQuarantine "Content Quarantine"
  out artifacts (defrel blocks) (1): AuthenticationService "Authentication Service"
  out techniques (1): T1003.001 "LSASS Memory"
  out techniques rollup (1): T1003 "OS Credential Dumping"
`,
		},
		{
			"single offensive plane",
			[]string{"rel", "accesses"},
			"rel accesses offensive plane 1/2 (technique -> artifact): edges=1 sources=1\n",
		},
		{
			"union planes in both families",
			[]string{"rel", "any"},
			fixtureRelAny,
		},
		{
			"a name in both families prints one line each",
			[]string{"rel", "blocks"},
			fixtureRelBlocks,
		},
		{
			"flag after the query is still a flag",
			[]string{"rel", "analyzes", "-family", "def"},
			"rel analyzes defensive plane 1/3 (countermeasure -> artifact): edges=1 sources=1\n",
		},
		{
			"flag before the query",
			[]string{"rel", "-family", "def", "analyzes"},
			"rel analyzes defensive plane 1/3 (countermeasure -> artifact): edges=1 sources=1\n",
		},
		{
			"two queries are two blocks separated by a blank line",
			[]string{"ttp", "T1059", "T1003.001"},
			fixtureTTPIsolated + "\n" + fixtureTTPSub,
		},
		{
			"a revoked technique is marked in the header",
			[]string{"ttp", "T1015"},
			fixtureTTPRevoked,
		},
		{
			"the shared label resolves to the live twin, unmarked",
			[]string{"ttp", "Accessibility Features"},
			fixtureTTPLive,
		},
		{"data component, detecting one technique", []string{"dc", "DC0001"}, fixtureDCProcess},
		{"data component with no detects edge", []string{"dc", "DC0002"}, fixtureDCFile},
		{"group actor: techniques and software", []string{"group", "G0001"}, fixtureGroupActor},
		{"group software: who uses it", []string{"group", "S0001"}, fixtureGroupSoftware},
		{"group campaign with no edges", []string{"group", "C0001"}, fixtureGroupCampaign},
		{"tactic by TA id", []string{"tactic", "TA0001"}, fixtureTacticInitial},
		{"platform by name", []string{"platform", "Windows"}, fixturePlatformWindows},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 0 {
				t.Fatalf("status = %d, want 0 (stderr %q)", status, stderr)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
			if out != tt.want {
				t.Fatalf("stdout mismatch\n--- got ---\n%s--- want ---\n%s", out, tt.want)
			}
		})
	}
}

// TestTextPartialOutput keeps the blocks written for resolved queries when a
// later query does not resolve.
func TestTextPartialOutput(t *testing.T) {
	e := fixtureEngine(t)
	out, stderr, status := runCase(t, e, "ttp", "T1059", "nope")
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	if out != fixtureTTPIsolated {
		t.Fatalf("stdout mismatch\n--- got ---\n%s--- want ---\n%s", out, fixtureTTPIsolated)
	}
	if want := "gr4ph: no such technique: nope\n"; stderr != want {
		t.Fatalf("stderr = %q, want %q", stderr, want)
	}
}

// TestJSONFixture pins the JSON model: one object per resolved query, numeric
// ids, a label only where it differs from the name, and a children field that
// survives a zero value.
func TestJSONFixture(t *testing.T) {
	e := fixtureEngine(t)

	// A leading -json is accepted before the command, as in the usage-era form
	// `gr4ph -json ttp T1003.001`.
	out, stderr, status := runCase(t, e, "-json", "ttp", "T1003.001")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	var got result
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if got.Query != "T1003.001" || got.Kind != "ttp" || got.ID == nil || *got.ID != 1 {
		t.Fatalf("query/kind/id = %q/%q/%v, want T1003.001/ttp/1", got.Query, got.Kind, got.ID)
	}
	if got.Name != "T1003.001" || got.Label != "LSASS Memory" || got.Domain != "enterprise" || got.Parent != "T1003" {
		t.Fatalf("name/label/domain/parent = %q/%q/%q/%q", got.Name, got.Label, got.Domain, got.Parent)
	}
	if got.Children == nil || *got.Children != 0 {
		t.Fatalf("children = %v, want 0", got.Children)
	}
	if len(got.Sets) != 7 {
		t.Fatalf("sets = %d, want 7", len(got.Sets))
	}
	if strings.Join(got.Tactics, ",") != "TA0002" || strings.Join(got.Platforms, ",") != "Windows" || !got.SubTechnique {
		t.Fatalf("tactics/platforms/subtechnique = %v/%v/%v, want [TA0002]/[Windows]/true",
			got.Tactics, got.Platforms, got.SubTechnique)
	}
	if dcs := got.Sets[4]; dcs.Dir != "in" || dcs.Name != "data components" || dcs.Count != 1 {
		t.Fatalf("sets[4] = %+v, want in data components 1", dcs)
	}
	arts := got.Sets[0]
	if arts.Dir != "out" || arts.Name != "artifacts" || arts.Count != 2 {
		t.Fatalf("sets[0] = %+v, want out artifacts 2", arts)
	}
	wantNodes := []node{
		{ID: 0, Name: "Process"},
		{ID: 1, Name: "AuthenticationService", Label: "Authentication Service"},
	}
	if len(arts.Nodes) != len(wantNodes) {
		t.Fatalf("sets[0] nodes = %+v, want %+v", arts.Nodes, wantNodes)
	}
	for i, want := range wantNodes {
		if arts.Nodes[i] != want {
			t.Errorf("sets[0].nodes[%d] = %+v, want %+v", i, arts.Nodes[i], want)
		}
	}
	if cms := got.Sets[2]; cms.Dir != "in" || cms.Name != "countermeasures" || cms.Count != 2 {
		t.Fatalf("sets[2] = %+v, want in countermeasures 2", cms)
	}

	// A revoked technique carries "revoked":true; the live carrier of the same
	// label has the field absent (omitempty) and is reachable by the label.
	out, stderr, status = runCase(t, e, "-json", "ttp", "T1015")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	var revokedTT result
	if err := json.Unmarshal([]byte(out), &revokedTT); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if revokedTT.Name != "T1015" || !revokedTT.Revoked {
		t.Fatalf("revoked ttp = %q revoked=%v, want T1015 true", revokedTT.Name, revokedTT.Revoked)
	}
	out, _, status = runCase(t, e, "-json", "ttp", "Accessibility Features")
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	var liveTT result
	if err := json.Unmarshal([]byte(out), &liveTT); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if liveTT.Name != "T1546.008" || liveTT.Revoked {
		t.Fatalf("live ttp = %q revoked=%v, want T1546.008 false", liveTT.Name, liveTT.Revoked)
	}
	if strings.Contains(out, "revoked") {
		t.Fatalf("a live technique must not carry the field: %s", out)
	}

	// A live top-level technique has no subtechnique key (omitempty), and the
	// group header carries the kind as a field.
	out, _, status = runCase(t, e, "-json", "ttp", "T1003")
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	if strings.Contains(out, "subtechnique") {
		t.Fatalf("a top-level technique must not carry the field: %s", out)
	}
	var topLevel result
	if err := json.Unmarshal([]byte(out), &topLevel); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if strings.Join(topLevel.Tactics, ",") != "TA0001" || strings.Join(topLevel.Platforms, ",") != "Windows,Linux" {
		t.Fatalf("tactics/platforms = %v/%v, want [TA0001]/[Windows Linux]", topLevel.Tactics, topLevel.Platforms)
	}
	out, _, status = runCase(t, e, "-json", "group", "S0001")
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	var grp result
	if err := json.Unmarshal([]byte(out), &grp); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if grp.Kind != "group" || grp.GroupKind != "software" || grp.Name != "S0001" || grp.Label != "Software One" {
		t.Fatalf("group result = %+v, want S0001 software Software One", grp)
	}

	// rel has planes and no node id; the union plane is plane 0 of a family
	// whose plane count is the number of registered predicates.
	out, stderr, status = runCase(t, e, "rel", "-json", "any")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	var rel result
	if err := json.Unmarshal([]byte(out), &rel); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if rel.ID != nil {
		t.Errorf("id = %v, want absent", rel.ID)
	}
	if rel.Sets != nil {
		t.Errorf("sets = %+v, want absent", rel.Sets)
	}
	wantPlanes := []plane{
		{Family: "offensive", ID: 0, Count: 2, Edges: 2, Sources: 1},
		{Family: "defensive", ID: 0, Count: 3, Edges: 3, Sources: 2},
	}
	if len(rel.Planes) != len(wantPlanes) {
		t.Fatalf("planes = %+v, want %+v", rel.Planes, wantPlanes)
	}
	for i, want := range wantPlanes {
		if rel.Planes[i] != want {
			t.Errorf("planes[%d] = %+v, want %+v", i, rel.Planes[i], want)
		}
	}

	// Two resolved queries are exactly two lines.
	out, _, status = runCase(t, e, "-json", "ttp", "T1003.001", "T1059")
	if status != 0 || strings.Count(out, "\n") != 2 {
		t.Fatalf("status = %d, lines = %d in\n%s", status, strings.Count(out, "\n"), out)
	}
}

// TestOntologyValues runs the pinned numbers of the committed tables through the
// CLI. Every literal here is derived from ontology/attack_gen.go, so a change in
// the tables must fail this test rather than silently reflow the output.
func TestOntologyValues(t *testing.T) {
	e, err := buildEngine()
	if err != nil {
		t.Fatalf("buildEngine: %v", err)
	}
	if e.TTPCount() != ontology.NTTP || e.ArtifactCount() != ontology.NArtifact ||
		e.CountermeasureCount() != ontology.NCountermeasure {
		t.Fatalf("engine holds %d/%d/%d nodes, want %d/%d/%d",
			e.TTPCount(), e.ArtifactCount(), e.CountermeasureCount(),
			ontology.NTTP, ontology.NArtifact, ontology.NCountermeasure)
	}

	out, stderr, status := runCase(t, e, "ttp", "T1003.001")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	header := strings.SplitN(out, "\n", 2)[0]
	if want := `ttp T1003.001 "LSASS Memory" domain=enterprise parent=T1003 children=0 subtechnique=true tactics=TA0006 platforms=Windows`; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}
	// The parent's header has no subtechnique marker and two platform names;
	// T1059 is the widest platform row of the release.
	outTop, _, status := runCase(t, e, "ttp", "T1003")
	if status != 0 {
		t.Fatalf("ttp T1003: status = %d", status)
	}
	if got := strings.SplitN(outTop, "\n", 2)[0]; got != `ttp T1003 "OS Credential Dumping" domain=enterprise children=8 tactics=TA0006 platforms=Linux,Windows,macOS` {
		t.Errorf("T1003 header = %q", got)
	}
	outWide, _, status := runCase(t, e, "ttp", "T1059")
	if status != 0 {
		t.Fatalf("ttp T1059: status = %d", status)
	}
	if got := strings.SplitN(outWide, "\n", 2)[0]; !strings.HasSuffix(got,
		" tactics=TA0002 platforms=Containers,ESXi,IaaS,Identity Provider,Linux,Network Devices,Office Suite,SaaS,Windows,macOS") {
		t.Errorf("T1059 header = %q", got)
	}
	// A D3FEND-named node has no ATT&CK object: no attribute fields at all.
	outDE, _, status := runCase(t, e, "ttp", "DE-0006")
	if status != 0 {
		t.Fatalf("ttp DE-0006: status = %d", status)
	}
	if got := strings.SplitN(outDE, "\n", 2)[0]; strings.Contains(got, "tactics=") || strings.Contains(got, "platforms=") || strings.Contains(got, "subtechnique=") {
		t.Errorf("DE-0006 header = %q, want no attribute fields", got)
	}
	if count, nodes := setLine(t, outDE, "in data components"); count != 0 || nodes != nil {
		t.Errorf("DE-0006 data components = %d %v, want 0", count, nodes)
	}

	tests := []struct {
		name      string
		args      []string
		set       string // "<dir> <set name>"
		wantCount int
		first     string
		last      string
	}{
		{
			"artifacts of a sub-technique",
			[]string{"ttp", "T1003.001"},
			"out artifacts", 2,
			`AuthenticationService "Authentication Service"`, "Process",
		},
		{
			"countermeasures of a sub-technique",
			[]string{"ttp", "T1003.001"},
			"in countermeasures", 12,
			`Application-basedProcessIsolation "Application-based Process Isolation"`, `WebSessionAccessMediation "Web Session Access Mediation"`,
		},
		{
			"techniques touching an artifact",
			[]string{"artifact", "Process"},
			"in techniques", 5,
			`T1003.001 "LSASS Memory"`, `T1546.007 "Netsh Helper DLL"`,
		},
		{
			"those techniques collapsed to parents",
			[]string{"artifact", "Process"},
			"in techniques rollup", 3,
			`T1003 "OS Credential Dumping"`, `T1546 "Event Triggered Execution"`,
		},
		{
			"countermeasures directly linked to an artifact",
			[]string{"artifact", "Process"},
			"in countermeasures", 11,
			`Application-basedProcessIsolation "Application-based Process Isolation"`, `SystemCallFiltering "System Call Filtering"`,
		},
		{"countermeasure surface of an artifact", []string{"artifact", "Process"}, "in countermeasures viaTTPs", 36, "", ""},
		{
			"artifacts of a countermeasure",
			[]string{"cm", "CredentialHardening"},
			"out artifacts", 1,
			"Credential", "Credential",
		},
		{
			"techniques defended by a countermeasure",
			[]string{"cm", "CredentialHardening"},
			"out techniques", 25,
			`DE-0011 "Credentialed Evasion"`, `T1606.001 "Web Cookies"`,
		},
		{
			"those techniques collapsed to parents",
			[]string{"cm", "CredentialHardening"},
			"out techniques rollup", 16,
			`DE-0011 "Credentialed Evasion"`, `T1606 "Forge Web Credentials"`,
		},
		{
			"techniques a data component detects",
			[]string{"dc", "DC0084"},
			"out techniques", 9,
			"", "",
		},
		{
			"techniques of a tactic",
			[]string{"tactic", "TA0005"},
			"out techniques", 212,
			"", "",
		},
		{
			"techniques of a platform",
			[]string{"platform", "Windows"},
			"out techniques", 591,
			"", "",
		},
		{
			"techniques an actor uses",
			[]string{"group", "G0007"},
			"out techniques", 93,
			"", "",
		},
		{
			"software an actor uses",
			[]string{"group", "G0007"},
			"out software", 30,
			"", "",
		},
		{
			"techniques a software node uses",
			[]string{"group", "S0002"},
			"out techniques", 17,
			"", "",
		},
		{
			"who uses a software node",
			[]string{"group", "S0002"},
			"in groups", 60,
			"", "",
		},
		{
			"data components detecting a sub-technique",
			[]string{"ttp", "T1003.001"},
			"in data components", 5,
			"", "",
		},
		{
			"the same set rolled up to the parent",
			[]string{"ttp", "T1003"},
			"in data components rollup", 13,
			"", "",
		},
		{
			"groups using a technique",
			[]string{"ttp", "T1546.008"},
			"in groups", 7,
			"", "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 0 || stderr != "" {
				t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
			}
			count, nodes := setLine(t, out, tt.set)
			if count != tt.wantCount {
				t.Errorf("%s count = %d, want %d", tt.set, count, tt.wantCount)
			}
			if len(nodes) != tt.wantCount {
				t.Errorf("%s lists %d nodes, want %d", tt.set, len(nodes), tt.wantCount)
			}
			if tt.first != "" && nodes[0] != tt.first {
				t.Errorf("%s first = %q, want %q", tt.set, nodes[0], tt.first)
			}
			if tt.last != "" && nodes[len(nodes)-1] != tt.last {
				t.Errorf("%s last = %q, want %q", tt.set, nodes[len(nodes)-1], tt.last)
			}
		})
	}

	// The plane walk is an end-to-end check of the tables: the offensive union
	// plane equals the distinct (technique, artifact) pairs of the edge lists,
	// the defensive one the defensive edge count, both recomputed here.
	distinct := make(map[[2]uint16]struct{}, len(ontology.OffEdgeTTP))
	for i := range ontology.OffEdgeTTP {
		distinct[[2]uint16{ontology.OffEdgeTTP[i], ontology.OffEdgeArt[i]}] = struct{}{}
	}
	planes := []struct {
		name string
		args []string
		want string
	}{
		{
			"union planes",
			[]string{"rel", "any"},
			fmt.Sprintf("rel any offensive union plane 0/41 (technique -> artifact): edges=%d sources=427\n"+
				"rel any defensive union plane 0/38 (countermeasure -> artifact): edges=%d sources=157\n",
				len(distinct), len(ontology.DefEdgeCM)),
		},
		{
			"offensive plane",
			[]string{"rel", "accesses"},
			"rel accesses offensive plane 2/41 (technique -> artifact): edges=55 sources=51\n",
		},
		{
			"defensive plane",
			[]string{"rel", "analyzes"},
			"rel analyzes defensive plane 1/38 (countermeasure -> artifact): edges=49 sources=45\n",
		},
		{
			"a name in both families",
			[]string{"rel", "blocks"},
			"rel blocks offensive plane 4/41 (technique -> artifact): edges=2 sources=2\n" +
				"rel blocks defensive plane 3/38 (countermeasure -> artifact): edges=6 sources=6\n",
		},
	}
	if want := 654; len(distinct) != want {
		t.Fatalf("distinct offensive pairs = %d, want %d", len(distinct), want)
	}
	if want := 182; len(ontology.DefEdgeCM) != want {
		t.Fatalf("defensive edges = %d, want %d", len(ontology.DefEdgeCM), want)
	}
	for _, tt := range planes {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 0 || stderr != "" {
				t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
			}
			if out != tt.want {
				t.Fatalf("stdout mismatch\n--- got ---\n%s--- want ---\n%s", out, tt.want)
			}
		})
	}

	// The four new commands: the header is pinned and the set count comes from
	// setLine, because a full node list of a 93-technique row is not a useful
	// literal.
	newCommands := []struct {
		name   string
		args   []string
		header string
		set    string
		count  int
	}{
		{"tactic of a technique with two tactics", []string{"tactic", "TA0004"}, `tactic TA0004 "Privilege Escalation"`, "out techniques", 126},
		{"platform row", []string{"platform", "macOS"}, "platform macOS", "out techniques", 441},
		{"data component row", []string{"dc", "DC0084"}, `dc DC0084 "Active Directory Credential Request"`, "out techniques", 9},
		{"actor group row", []string{"group", "G0007"}, `group G0007 "APT28" kind=actor`, "out techniques", 93},
		{"actor software row", []string{"group", "G0007"}, `group G0007 "APT28" kind=actor`, "out software", 30},
		{"software group row", []string{"group", "S0002"}, `group S0002 "Mimikatz" kind=software`, "in groups", 60},
	}
	for _, tt := range newCommands {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 0 || stderr != "" {
				t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
			}
			if got := strings.SplitN(out, "\n", 2)[0]; got != tt.header {
				t.Errorf("header = %q, want %q", got, tt.header)
			}
			count, nodes := setLine(t, out, tt.set)
			if count != tt.count || len(nodes) != tt.count {
				t.Errorf("%s = %d nodes/%d count, want %d", tt.set, len(nodes), count, tt.count)
			}
		})
	}
}

// TestFlagForms pins the accepted spellings of the flags: an attached value, the
// "--" terminator, a flag between the queries, and -json before the command.
func TestFlagForms(t *testing.T) {
	e := fixtureEngine(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"value attached with =", []string{"ttp", "-rel=blocks", "T1003.001"}, fixtureTTPSubBlocks},
		{"rel before its value", []string{"ttp", "-rel", "blocks", "T1003.001"}, fixtureTTPSubBlocks},
		{"-- ends the flags", []string{"ttp", "--", "T1059"}, fixtureTTPIsolated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 0 || stderr != "" {
				t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
			}
			if out != tt.want {
				t.Fatalf("stdout mismatch\n--- got ---\n%s--- want ---\n%s", out, tt.want)
			}
		})
	}
	for _, args := range [][]string{{"--json", "ttp", "T1059"}, {"ttp", "-json=true", "T1059"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, stderr, status := runCase(t, e, args...)
			if status != 0 || stderr != "" {
				t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
			}
			var got result
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("decode %q: %v", out, err)
			}
			if got.Kind != "ttp" || got.Name != "T1059" || !strings.HasSuffix(out, "\n") {
				t.Fatalf("decoded %+v from %q", got, out)
			}
		})
	}
}

// TestDomainNames pins the domain field for each ATT&CK domain the builder
// accepts. The real tables hold all four, but only a graph built for one domain
// per technique pins each rendering independently of the tables.
func TestDomainNames(t *testing.T) {
	b := gr4ph.NewBuilder()
	want := []string{"enterprise", "ics", "mobile", "sparta"}
	domains := []gr4ph.Domain{gr4ph.DomainEnterprise, gr4ph.DomainICS, gr4ph.DomainMobile, gr4ph.DomainSPARTA}
	for i, dom := range domains {
		mustTTP(t, b, fmt.Sprintf("T%d", 9000+i), fmt.Sprintf("Technique %d", i), dom, gr4ph.NoParent, false)
	}
	graph, err := b.Build()
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	for i, want := range want {
		out, stderr, status := runCase(t, graph, "ttp", fmt.Sprintf("T%d", 9000+i))
		if status != 0 || stderr != "" {
			t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
		}
		if header := strings.SplitN(out, "\n", 2)[0]; !strings.Contains(header, "domain="+want) {
			t.Errorf("header = %q, want domain=%s", header, want)
		}
	}
}

// TestJSONWriteError pins the write-failure path: the encoder's error is
// reported verbatim on stderr and the status is 1, whatever the stream behind
// it does.
func TestJSONWriteError(t *testing.T) {
	e := fixtureEngine(t)
	var stderr bytes.Buffer
	status := run(e, []string{"-json", "ttp", "T1059"}, errWriter{}, &stderr)
	if status != 1 {
		t.Fatalf("status = %d, want 1", status)
	}
	if want := "gr4ph: " + errClosed.Error() + "\n"; stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}
}

// errWriter fails every write, standing in for a closed stdout.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errClosed }

// errClosed is the write error errWriter reports.
var errClosed = fmt.Errorf("write: closed pipe")

// TestUsageExamples runs every `gr4ph ...` line of the help text through the CLI against
// the frozen tables: an example that does not parse or resolve is a broken promise in the
// help itself, and the section is the only place the flags are shown in use.
func TestUsageExamples(t *testing.T) {
	e, err := buildEngine()
	if err != nil {
		t.Fatalf("buildEngine: %v", err)
	}
	examples := usageExamples(t)
	if len(examples) < 8 {
		t.Fatalf("help lists %d examples, want at least 8", len(examples))
	}
	flags := map[string]bool{}
	for _, args := range examples {
		for _, a := range args {
			if strings.HasPrefix(a, "-") {
				flags[a] = true
			}
		}
		out, stderr, status := runCase(t, e, args...)
		if status != 0 || stderr != "" {
			t.Errorf("gr4ph %s: status = %d, stderr = %q, want a resolved query",
				strings.Join(args, " "), status, stderr)
		}
		if out == "" {
			t.Errorf("gr4ph %s: no output", strings.Join(args, " "))
		}
	}
	for _, want := range []string{"-json", "-rel", "-defrel", "-family"} {
		if !flags[want] {
			t.Errorf("help shows no example using %s", want)
		}
	}
}

// usageExamples returns the argv of every example line of the help text, in order: the
// lines of the "examples:" section up to the blank line that ends it, each "gr4ph <args>"
// followed by at least two spaces and its description.
func usageExamples(t *testing.T) [][]string {
	t.Helper()
	var out [][]string
	inSection := false
	for _, line := range strings.Split(usage, "\n") {
		switch {
		case strings.HasPrefix(line, "examples:"):
			inSection = true
			continue
		case !inSection:
			continue
		case strings.TrimSpace(line) == "":
			if len(out) == 0 {
				t.Fatal("the examples section is empty")
			}
			return out
		}
		line = strings.TrimSpace(line)
		gap := strings.Index(line, "  ")
		if gap < 0 {
			t.Fatalf("example line %q has no gap before its description", line)
		}
		out = append(out, exampleArgs(t, strings.TrimPrefix(line[:gap], "gr4ph ")))
	}
	t.Fatal("the examples section has no blank line after it")
	return nil
}

// exampleArgs splits one example into argv, keeping a single-quoted argument (which may
// contain spaces) together and dropping the quotes.
func exampleArgs(t *testing.T, line string) []string {
	t.Helper()
	var args []string
	for i := 0; i < len(line); {
		if line[i] == ' ' {
			i++
			continue
		}
		if line[i] != '\'' {
			j := strings.IndexByte(line[i:], ' ')
			if j < 0 {
				j = len(line) - i
			}
			args = append(args, line[i:i+j])
			i += j
			continue
		}
		end := strings.IndexByte(line[i+1:], '\'')
		if end < 0 {
			t.Fatalf("example %q: unterminated quote", line)
		}
		args = append(args, line[i+1:i+1+end])
		i += end + 2
	}
	return args
}

// TestErrors pins every failure mode the fixture can reach: the exact stderr
// line, the exit status, and an empty stdout for every usage error.
func TestErrors(t *testing.T) {
	e := fixtureEngine(t)
	tests := []struct {
		name     string
		args     []string
		wantErr  string
		wantExit int
		usage    bool // whether usage follows the message on stderr
	}{
		{"no arguments at all", nil, "", 2, true},
		{"unknown command", []string{"nope"}, "gr4ph: unknown command: nope\n", 2, true},
		{"ttp without a query", []string{"ttp"}, "gr4ph: missing query\n", 2, false},
		{"artifact without a query", []string{"artifact"}, "gr4ph: missing query\n", 2, false},
		{"cm without a query", []string{"cm"}, "gr4ph: missing query\n", 2, false},
		{"rel without a name", []string{"rel"}, "gr4ph: missing relation name\n", 2, false},
		{"dc without a query", []string{"dc"}, "gr4ph: missing query\n", 2, false},
		{"group without a query", []string{"group"}, "gr4ph: missing query\n", 2, false},
		{"tactic without a query", []string{"tactic"}, "gr4ph: missing query\n", 2, false},
		{"platform without a query", []string{"platform"}, "gr4ph: missing query\n", 2, false},
		{"undefined flag", []string{"ttp", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"undefined flag in artifact", []string{"artifact", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"undefined flag in cm", []string{"cm", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"undefined flag in rel", []string{"rel", "-nope", "any"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{
			"-family outside off/def",
			[]string{"rel", "-family", "sideways", "accesses"},
			"gr4ph: -family must be off or def, got sideways\n", 2, false,
		},
		{"unresolved technique", []string{"ttp", "no-such"}, "gr4ph: no such technique: no-such\n", 1, false},
		{"unresolved artifact", []string{"artifact", "no-such"}, "gr4ph: no such artifact: no-such\n", 1, false},
		{"unresolved countermeasure", []string{"cm", "no-such"}, "gr4ph: no such countermeasure: no-such\n", 1, false},
		{"unresolved relation", []string{"rel", "no-such"}, "gr4ph: no such relation: no-such\n", 1, false},
		{"unresolved data component", []string{"dc", "no-such"}, "gr4ph: no such data component: no-such\n", 1, false},
		{"unresolved group", []string{"group", "no-such"}, "gr4ph: no such group: no-such\n", 1, false},
		{"unresolved tactic", []string{"tactic", "no-such"}, "gr4ph: no such tactic: no-such\n", 1, false},
		{"unresolved platform", []string{"platform", "no-such"}, "gr4ph: no such platform: no-such\n", 1, false},
		{
			"relation of the other family",
			[]string{"rel", "-family", "off", "analyzes"},
			"gr4ph: no such offensive relation: analyzes\n", 1, false,
		},
		{
			"relation of the other family, defensively",
			[]string{"rel", "-family", "def", "accesses"},
			"gr4ph: no such defensive relation: accesses\n", 1, false,
		},
		{
			"offensive relation filter outside its family",
			[]string{"ttp", "-rel", "analyzes", "T1003.001"},
			"gr4ph: no such offensive relation: analyzes\n", 1, false,
		},
		{
			"defensive relation filter in artifact",
			[]string{"artifact", "-defrel", "accesses", "Process"},
			"gr4ph: no such defensive relation: accesses\n", 1, false,
		},
		{
			"defensive relation filter in cm",
			[]string{"cm", "-defrel", "accesses", "Process"},
			"gr4ph: no such defensive relation: accesses\n", 1, false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != tt.wantExit {
				t.Errorf("status = %d, want %d", status, tt.wantExit)
			}
			if out != "" {
				t.Errorf("stdout = %q, want empty", out)
			}
			want := tt.wantErr
			if tt.usage {
				want += usage
			}
			if stderr != want {
				t.Errorf("stderr = %q, want %q", stderr, want)
			}
		})
	}
}

// TestHelp pins the help path: usage on stdout and status 0, whatever spelling
// asks for it.
func TestHelp(t *testing.T) {
	e := fixtureEngine(t)
	for _, args := range [][]string{{"help"}, {"ttp", "-h"}, {"-h"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, stderr, status := runCase(t, e, args...)
			if status != 0 {
				t.Fatalf("status = %d, want 0", status)
			}
			if stderr != "" {
				t.Fatalf("stderr = %q, want empty", stderr)
			}
			if out != usage {
				t.Fatalf("stdout = %q, want the usage text", out)
			}
			for _, want := range []string{"usage: gr4ph", "ttp <query>", "artifact <query>", "cm <query>",
				"dc <query>", "group <query>", "tactic <ta-id>", "platform <name>", "rel <name>", "exit status: 0"} {
				if !strings.Contains(out, want) {
					t.Errorf("usage does not mention %q", want)
				}
			}
		})
	}
}

// setLine returns the match count and the node list of the line whose set name
// is exactly want, e.g. setLine(t, out, "out artifacts rollup").
func setLine(t *testing.T, out, want string) (int, []string) {
	t.Helper()
	dir, name, ok := strings.Cut(want, " ")
	if !ok {
		t.Fatalf("setLine: %q is not a \"<dir> <set>\" pair", want)
	}
	prefix := "  " + fmt.Sprintf("%-4s", dir) + name + " ("
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		countStr, list, ok := strings.Cut(strings.TrimPrefix(line, prefix), "): ")
		if !ok {
			t.Fatalf("setLine: malformed line %q", line)
		}
		count, err := strconv.Atoi(countStr)
		if err != nil {
			t.Fatalf("setLine: count in %q: %v", line, err)
		}
		if list == "-" {
			return count, nil
		}
		return count, strings.Split(list, ", ")
	}
	t.Fatalf("setLine: no %q line in output:\n%s", want, out)
	return 0, nil
}
