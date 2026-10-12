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

	// The KEV partition, registered after every node above so no existing dense
	// id moves: two weakness classes, two products and three entries, the third
	// with no weakness and the first product shared with the first entry.
	cwe20 := mustCWE(t, b, "CWE-20")
	cwe502 := mustCWE(t, b, "CWE-502")
	alpha := mustProduct(t, b, "Avendor", "Alpha")
	beta := mustProduct(t, b, "Bvendor", "Beta")
	kevAlpha := mustKEV(t, b, "CVE-2099-0001", "Alpha Flaw", "2099-01-01", true)
	kevBeta := mustKEV(t, b, "CVE-2099-0002", "Beta Flaw", "2099-01-02", false)
	kevGamma := mustKEV(t, b, "CVE-2099-0003", "Gamma Flaw", "2099-01-03", false)
	must(t, b.AddKEVWeaknessEdge(kevAlpha, cwe20))
	must(t, b.AddKEVWeaknessEdge(kevAlpha, cwe502))
	must(t, b.AddKEVWeaknessEdge(kevBeta, cwe502))
	must(t, b.AddKEVProductEdge(kevAlpha, alpha))
	must(t, b.AddKEVProductEdge(kevBeta, beta))
	must(t, b.AddKEVProductEdge(kevGamma, alpha))

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

// mustCWE registers a weakness with its id as its label, as the ontology does:
// a weakness has no separate label, so a node prints its id alone.
func mustCWE(t *testing.T, b *gr4ph.Builder, id string) gr4ph.CWE {
	t.Helper()
	c, err := b.AddCWE(id, id)
	must(t, err)
	return c
}

func mustProduct(t *testing.T, b *gr4ph.Builder, vendor, name string) gr4ph.Product {
	t.Helper()
	p, err := b.AddProduct(vendor, name)
	must(t, err)
	return p
}

func mustKEV(t *testing.T, b *gr4ph.Builder, id, name, added string, ransomware bool) gr4ph.KEV {
	t.Helper()
	k, err := b.AddKEV(id, name, added, ransomware)
	must(t, err)
	return k
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

	// The overlay verbs on the fixture: both countermeasures defend T1003.001
	// only, so the mapped range is that one technique, the four others are
	// unmapped and anything below the mapping is undefended.
	fixtureCoverageHardening = `coverage deployed=1 mapped=1
  in  defended (1): T1003.001 "LSASS Memory"
  in  undefended (0): -
  in  unmapped (4): T1003 "OS Credential Dumping", T1059 "Command and Scripting Interpreter", T1015 "Accessibility Features", T1546.008 "Accessibility Features"
`

	fixtureCoverageEmpty = `coverage deployed=0 mapped=1
  in  defended (0): -
  in  undefended (1): T1003.001 "LSASS Memory"
  in  unmapped (4): T1003 "OS Credential Dumping", T1059 "Command and Scripting Interpreter", T1015 "Accessibility Features", T1546.008 "Accessibility Features"
`

	// Equal gains are ordered by the byte-smallest countermeasure id
	// (ContentQuarantine before CredentialHardening), not by dense id.
	fixtureGainEmpty = `gain deployed=0 candidates=2 shown=2
  1  ContentQuarantine "Content Quarantine"
  1  CredentialHardening "Credential Hardening"
`

	// The greedy walk buys the maximum gain first and stops as soon as no
	// candidate gains anything: on this fixture the second countermeasure adds
	// nothing, so the sequence is one row long.
	fixtureGainGreedy = `gain deployed=0 greedy=1
  1  ContentQuarantine "Content Quarantine"
`

	fixtureContainSub = `contain observed=1
  out countermeasures (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
`

	fixtureContainIsolated = `contain observed=1
  out countermeasures (0): -
`

	// The KEV verbs on the fixture: the catalog's own columns in the header,
	// then the weakness classes of one entry, the entries of one class and the
	// union of a product selection.
	fixtureKEVAlpha = `kev CVE-2099-0001 "Alpha Flaw" added=2099-01-01 ransomware=true vendor="Avendor" product="Alpha"
  out weaknesses (2): CWE-20, CWE-502
`

	fixtureKEVGamma = `kev CVE-2099-0003 "Gamma Flaw" added=2099-01-03 ransomware=false vendor="Avendor" product="Alpha"
  out weaknesses (0): -
`

	fixtureCWEFirst = `cwe CWE-20
  in  entries (1): CVE-2099-0001 "Alpha Flaw"
`

	fixtureCWESecond = `cwe CWE-502
  in  entries (2): CVE-2099-0001 "Alpha Flaw", CVE-2099-0002 "Beta Flaw"
`

	// One product, whose entries are the two that name it.
	fixtureProductAlpha = `product Avendor/Alpha
  out entries (2): CVE-2099-0001 "Alpha Flaw", CVE-2099-0003 "Gamma Flaw"
`

	// Two products in one selection: the union of their entries, and the header
	// names both resolved keys.
	fixtureProductBoth = `product Avendor/Alpha Bvendor/Beta
  out entries (3): CVE-2099-0001 "Alpha Flaw", CVE-2099-0002 "Beta Flaw", CVE-2099-0003 "Gamma Flaw"
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
		{"coverage of one deployed countermeasure", []string{"coverage", "CredentialHardening"}, fixtureCoverageHardening},
		{"coverage of an empty deployment", []string{"coverage"}, fixtureCoverageEmpty},
		{"gain against an empty deployment", []string{"gain"}, fixtureGainEmpty},
		{"greedy gain sequence", []string{"gain", "-greedy"}, fixtureGainGreedy},
		{"containment set of a defended technique", []string{"contain", "T1003.001"}, fixtureContainSub},
		{"containment set of an isolated technique", []string{"contain", "T1059"}, fixtureContainIsolated},
		{"kev entry with two weakness classes", []string{"kev", "CVE-2099-0001"}, fixtureKEVAlpha},
		{"kev entry with no weakness class", []string{"kev", "CVE-2099-0003"}, fixtureKEVGamma},
		{"weakness class with one entry", []string{"cwe", "CWE-20"}, fixtureCWEFirst},
		{"weakness class with two entries", []string{"cwe", "CWE-502"}, fixtureCWESecond},
		{"one product", []string{"product", "Avendor/Alpha"}, fixtureProductAlpha},
		{"two products in one selection", []string{"product", "Avendor/Alpha", "Bvendor/Beta"}, fixtureProductBoth},
		{"a repeated product query is one selection", []string{"product", "Avendor/Alpha", "Avendor/Alpha"}, fixtureProductAlpha},
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

	// The KEV verbs: a kev result carries the catalog's columns and one set of
	// weakness ids; a cwe result the entries of the class; a product selection
	// is one result whatever the number of queries.
	out, stderr, status = runCase(t, e, "-json", "kev", "CVE-2099-0001")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	var kevRes result
	if err := json.Unmarshal([]byte(out), &kevRes); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if kevRes.Kind != "kev" || kevRes.Name != "CVE-2099-0001" || kevRes.Label != "Alpha Flaw" {
		t.Fatalf("kev result = %+v, want CVE-2099-0001 Alpha Flaw", kevRes)
	}
	if kevRes.Added != "2099-01-01" || !kevRes.Ransomware || kevRes.Vendor != "Avendor" || kevRes.Product != "Alpha" {
		t.Fatalf("kev columns = %q/%v/%q/%q, want 2099-01-01/true/Avendor/Alpha",
			kevRes.Added, kevRes.Ransomware, kevRes.Vendor, kevRes.Product)
	}
	wantCWEs := []node{{ID: 0, Name: "CWE-20"}, {ID: 1, Name: "CWE-502"}}
	if len(kevRes.Sets) != 1 || kevRes.Sets[0].Dir != "out" || kevRes.Sets[0].Name != "weaknesses" {
		t.Fatalf("kev sets = %+v, want one out weaknesses set", kevRes.Sets)
	}
	if got := kevRes.Sets[0].Nodes; len(got) != len(wantCWEs) {
		t.Fatalf("kev weaknesses = %+v, want %+v", got, wantCWEs)
	} else {
		for i, want := range wantCWEs {
			if got[i] != want {
				t.Errorf("weaknesses[%d] = %+v, want %+v", i, got[i], want)
			}
		}
	}

	// A false ransomware flag is absent from the JSON: the column is only
	// meaningful when set, like revoked.
	out, _, status = runCase(t, e, "-json", "kev", "CVE-2099-0003")
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	if !strings.Contains(out, `"name":"CVE-2099-0003"`) || strings.Contains(out, "ransomware") {
		t.Errorf("kev CVE-2099-0003 = %s, want the ransomware field absent", out)
	}

	out, _, status = runCase(t, e, "-json", "cwe", "CWE-502")
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	var cweRes result
	if err := json.Unmarshal([]byte(out), &cweRes); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if cweRes.Kind != "cwe" || cweRes.Name != "CWE-502" || cweRes.Label != "" || cweRes.Added != "" {
		t.Fatalf("cwe result = %+v, want CWE-502 with no label or columns", cweRes)
	}
	if len(cweRes.Sets) != 1 || cweRes.Sets[0].Dir != "in" || cweRes.Sets[0].Name != "entries" || cweRes.Sets[0].Count != 2 {
		t.Fatalf("cwe sets = %+v, want in entries 2", cweRes.Sets)
	}

	out, _, status = runCase(t, e, "-json", "product", "Avendor/Alpha", "Bvendor/Beta")
	if status != 0 {
		t.Fatalf("status = %d, want 0", status)
	}
	if lines := strings.Count(out, "\n"); lines != 1 {
		t.Fatalf("product of two queries = %d lines, want one result", lines)
	}
	var prodRes result
	if err := json.Unmarshal([]byte(out), &prodRes); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if prodRes.Kind != "product" || prodRes.Name != "Avendor/Alpha Bvendor/Beta" {
		t.Fatalf("product result = %+v, want both resolved keys in name", prodRes)
	}
	if len(prodRes.Sets) != 1 || prodRes.Sets[0].Dir != "out" || prodRes.Sets[0].Name != "entries" || prodRes.Sets[0].Count != 3 {
		t.Fatalf("product sets = %+v, want out entries 3", prodRes.Sets)
	}

	// The overlay verbs: coverage carries the deployment and the three states,
	// gain the candidate ranking with its counts, contain the observed count.
	out, stderr, status = runCase(t, e, "-json", "coverage", "ContentQuarantine")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	if !strings.Contains(out, `"deployed":1`) || !strings.Contains(out, `"mapped":1`) {
		t.Errorf("coverage JSON must carry the deployment and the mapped count: %s", out)
	}
	for _, want := range []string{`"name":"defended"`, `"name":"undefended"`, `"name":"unmapped"`} {
		if !strings.Contains(out, want) {
			t.Errorf("coverage JSON lacks %s: %s", want, out)
		}
	}
	var cov result
	if err := json.Unmarshal([]byte(out), &cov); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if cov.Deployed == nil || *cov.Deployed != 1 || cov.Mapped == nil || *cov.Mapped != 1 {
		t.Fatalf("coverage counts = %v/%v, want 1/1", cov.Deployed, cov.Mapped)
	}
	if len(cov.Sets) != 3 || cov.Sets[0].Dir != "in" || cov.Sets[0].Count != 1 ||
		cov.Sets[1].Count != 0 || cov.Sets[2].Count != 4 {
		t.Fatalf("coverage sets = %+v, want in defended 1, undefended 0, unmapped 4", cov.Sets)
	}

	out, stderr, status = runCase(t, e, "-json", "gain", "-all")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	if !strings.Contains(out, `"candidates":2`) || !strings.Contains(out, `"gain":1`) {
		t.Errorf("gain JSON must carry the candidate count and the gains: %s", out)
	}
	var gn result
	if err := json.Unmarshal([]byte(out), &gn); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if gn.Candidates == nil || *gn.Candidates != 2 || len(gn.Gains) != 2 {
		t.Fatalf("gain counts = %v gains %+v, want 2 candidates", gn.Candidates, gn.Gains)
	}
	if gn.Gains[0].Name != "ContentQuarantine" || gn.Gains[0].Gain != 1 || gn.Gains[0].Label != "Content Quarantine" {
		t.Fatalf("gain[0] = %+v, want ContentQuarantine 1", gn.Gains[0])
	}
	if gn.Sets != nil || gn.ID != nil {
		t.Errorf("gain carries sets %+v / id %v, want neither", gn.Sets, gn.ID)
	}

	out, stderr, status = runCase(t, e, "-json", "contain", "T1003.001")
	if status != 0 || stderr != "" {
		t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	if !strings.Contains(out, `"observed":1`) {
		t.Errorf("contain JSON must carry the observed count: %s", out)
	}
	var ct result
	if err := json.Unmarshal([]byte(out), &ct); err != nil {
		t.Fatalf("decode %q: %v", out, err)
	}
	if ct.Observed == nil || *ct.Observed != 1 {
		t.Fatalf("contain observed = %v, want 1", ct.Observed)
	}
	if len(ct.Sets) != 1 || ct.Sets[0].Dir != "out" || ct.Sets[0].Name != "countermeasures" || ct.Sets[0].Count != 2 {
		t.Fatalf("contain sets = %+v, want out countermeasures 2", ct.Sets)
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

	// The KEV verbs on the committed tables: the catalog's own columns in the
	// kev header, the weakness and product directions, and an entry the catalog
	// leaves without a weakness class.
	kevCommands := []struct {
		name   string
		args   []string
		header string
		set    string
		count  int
		first  string
		last   string
	}{
		{
			"KEV entry with three weakness classes",
			[]string{"kev", "CVE-2021-44228"},
			`kev CVE-2021-44228 "Apache Log4j2 Remote Code Execution Vulnerability" added=2021-12-10 ransomware=true vendor="Apache" product="Log4j2"`,
			"out weaknesses", 3, "CWE-20", "CWE-502",
		},
		{
			"KEV entry with no weakness class",
			[]string{"kev", "CVE-2002-0367"},
			`kev CVE-2002-0367 "Microsoft Windows Privilege Escalation Vulnerability" added=2022-03-03 ransomware=false vendor="Microsoft" product="Windows"`,
			"out weaknesses", 0, "", "",
		},
		{"weakness class", []string{"cwe", "CWE-78"}, "cwe CWE-78", "in entries", 110, "", ""},
		{"one product", []string{"product", "Apache/Log4j2"}, "product Apache/Log4j2", "out entries", 2, "", ""},
		{
			"two products in one selection",
			[]string{"product", "Apache/Log4j2", "Apache/Struts"},
			"product Apache/Log4j2 Apache/Struts", "out entries", 8, "", "",
		},
	}
	for _, tt := range kevCommands {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 0 || stderr != "" {
				t.Fatalf("status = %d, stderr = %q, want 0 and empty", status, stderr)
			}
			if got := strings.SplitN(out, "\n", 2)[0]; got != tt.header {
				t.Errorf("header = %q, want %q", got, tt.header)
			}
			count, nodes := setLine(t, out, tt.set)
			if count != tt.count {
				t.Errorf("%s count = %d, want %d", tt.set, count, tt.count)
			}
			// Only the weakness set is a list of bare ids: a CVE title may
			// itself contain ", ", which setLine's comma split cannot tell from
			// a node separator, so the entry lists are pinned by the fixture
			// blocks (TestTextFixture) instead.
			if tt.first == "" && tt.last == "" {
				return
			}
			if len(nodes) != tt.count {
				t.Fatalf("%s lists %d nodes, want %d", tt.set, len(nodes), tt.count)
			}
			if nodes[0] != tt.first {
				t.Errorf("%s first = %q, want %q", tt.set, nodes[0], tt.first)
			}
			if nodes[len(nodes)-1] != tt.last {
				t.Errorf("%s last = %q, want %q", tt.set, nodes[len(nodes)-1], tt.last)
			}
		})
	}

	// The failure paths: an unknown key is a failure with the exact message, and
	// a product query that carries no "/" cannot be read as a pair at all. All
	// exit 1, and a run whose every query failed prints no block.
	kevFailures := []struct {
		name string
		args []string
		want string
	}{
		{"unknown KEV entry", []string{"kev", "CVE-2099-99999"}, "gr4ph: no such KEV entry: CVE-2099-99999\n"},
		{"unknown weakness", []string{"cwe", "CWE-9999"}, "gr4ph: no such cwe: CWE-9999\n"},
		{"unknown product", []string{"product", "Apache/Log4j"}, "gr4ph: no such product: Apache/Log4j\n"},
		{"product query without a slash", []string{"product", "Log4j2"}, "gr4ph: product query must be Vendor/Product: Log4j2\n"},
	}
	for _, tt := range kevFailures {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != 1 {
				t.Fatalf("status = %d, want 1", status)
			}
			if stderr != tt.want {
				t.Errorf("stderr = %q, want %q", stderr, tt.want)
			}
			if out != "" {
				t.Errorf("stdout = %q, want empty", out)
			}
		})
	}

	// A partial product selection keeps the block of the queries that did
	// resolve, exactly as the per-node verbs do.
	out, stderr, status = runCase(t, e, "product", "Apache/Log4j2", "Apache/Log4j")
	if status != 1 || stderr != "gr4ph: no such product: Apache/Log4j\n" {
		t.Fatalf("status = %d, stderr = %q, want 1 and the failure", status, stderr)
	}
	if count, _ := setLine(t, out, "out entries"); count != 2 {
		t.Errorf("partial product entries = %d, want 2", count)
	}

	// The overlay verbs on the committed tables: one deployment's three states
	// and the containment set of one alert.
	overlay := []struct {
		name   string
		args   []string
		header string
		set    string
		count  int
	}{
		{
			"coverage: defended",
			[]string{"coverage", "ContentQuarantine"},
			"coverage deployed=1 mapped=427", "in defended", 125,
		},
		{
			"coverage: undefended",
			[]string{"coverage", "ContentQuarantine"},
			"coverage deployed=1 mapped=427", "in undefended", 302,
		},
		{
			"coverage: unmapped",
			[]string{"coverage", "ContentQuarantine"},
			"coverage deployed=1 mapped=427", "in unmapped", 759,
		},
		{
			"contain: one alert",
			[]string{"contain", "T1003.001"},
			"contain observed=1", "out countermeasures", 12,
		},
	}
	for _, tt := range overlay {
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

	// gain -greedy walks from the empty deployment: 21 buys cover the whole
	// mapped range, led by ContentQuarantine (125) and NetworkTrafficFiltering
	// (107). The walk is replayed through coverage, so the claim "21 buys cover
	// everything mapped" is checked, not asserted.
	out, stderr, status = runCase(t, e, "gain", "-greedy")
	if status != 0 || stderr != "" {
		t.Fatalf("gain -greedy: status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	if got := strings.SplitN(out, "\n", 2)[0]; got != "gain deployed=0 greedy=21" {
		t.Errorf("gain -greedy header = %q, want gain deployed=0 greedy=21", got)
	}
	rows := gainRows(t, out)
	if len(rows) != 21 {
		t.Fatalf("gain -greedy lists %d candidates, want 21", len(rows))
	}
	if rows[0].Name != "ContentQuarantine" || rows[0].Gain != 125 {
		t.Errorf("gain -greedy[0] = %+v, want ContentQuarantine 125", rows[0])
	}
	if rows[1].Name != "NetworkTrafficFiltering" || rows[1].Gain != 107 {
		t.Errorf("gain -greedy[1] = %+v, want NetworkTrafficFiltering 107", rows[1])
	}
	coverageArgs := append([]string{"coverage"}, rowNames(rows)...)
	covOut, stderr, status := runCase(t, e, coverageArgs...)
	if status != 0 || stderr != "" {
		t.Fatalf("coverage of the greedy deployment: status = %d, stderr = %q", status, stderr)
	}
	if count, _ := setLine(t, covOut, "in undefended"); count != 0 {
		t.Errorf("the greedy deployment leaves %d techniques undefended, want 0", count)
	}
	if count, _ := setLine(t, covOut, "in defended"); count != 427 {
		t.Errorf("the greedy deployment defends %d techniques, want the whole mapped range (427)", count)
	}

	// The ranking mode against the empty deployment: the gains are each
	// countermeasure's own degree there, so NetworkTrafficFiltering reads 121
	// while the marginal 107 above is its gain over ContentQuarantine.
	out, stderr, status = runCase(t, e, "gain", "-top", "2")
	if status != 0 || stderr != "" {
		t.Fatalf("gain -top 2: status = %d, stderr = %q, want 0 and empty", status, stderr)
	}
	if got := strings.SplitN(out, "\n", 2)[0]; got != "gain deployed=0 candidates=157 shown=2" {
		t.Errorf("gain -top 2 header = %q, want gain deployed=0 candidates=157 shown=2", got)
	}
	if got := gainLine(t, out, "ContentQuarantine"); got != 125 {
		t.Errorf("gain -top 2 ContentQuarantine = %d, want 125", got)
	}
	if got := gainLine(t, out, "NetworkTrafficFiltering"); got != 121 {
		t.Errorf("gain -top 2 NetworkTrafficFiltering = %d, want 121", got)
	}
}

// rowNames returns the countermeasure ids of decoded gain rows, in order.
func rowNames(rows []gain) []string {
	names := make([]string, 0, len(rows))
	for _, g := range rows {
		names = append(names, g.Name)
	}
	return names
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

// TestTextWriteError pins the text branch of the same contract: writeText's
// first error is reported verbatim on stderr and the status is 1, instead of a
// full disk or a closed pipe exiting 0 silently.
func TestTextWriteError(t *testing.T) {
	e := fixtureEngine(t)
	var stderr bytes.Buffer
	status := run(e, []string{"ttp", "T1059"}, errWriter{}, &stderr)
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
// line, the exit status, and the stdout the invocation still writes (empty for
// every usage error and for a command that builds its block per resolved query).
func TestErrors(t *testing.T) {
	e := fixtureEngine(t)
	tests := []struct {
		name     string
		args     []string
		wantErr  string
		wantExit int
		wantOut  string // "" for the commands that write one block per resolved query
		usage    bool   // whether usage follows the message on stderr
	}{
		{"no arguments at all", nil, "", 2, "", true},
		{"unknown command", []string{"nope"}, "gr4ph: unknown command: nope\n", 2, "", true},
		{"ttp without a query", []string{"ttp"}, "gr4ph: missing query\n", 2, "", false},
		{"artifact without a query", []string{"artifact"}, "gr4ph: missing query\n", 2, "", false},
		{"cm without a query", []string{"cm"}, "gr4ph: missing query\n", 2, "", false},
		{"rel without a name", []string{"rel"}, "gr4ph: missing relation name\n", 2, "", false},
		{"dc without a query", []string{"dc"}, "gr4ph: missing query\n", 2, "", false},
		{"group without a query", []string{"group"}, "gr4ph: missing query\n", 2, "", false},
		{"tactic without a query", []string{"tactic"}, "gr4ph: missing query\n", 2, "", false},
		{"platform without a query", []string{"platform"}, "gr4ph: missing query\n", 2, "", false},
		{"contain without a query", []string{"contain"}, "gr4ph: missing query\n", 2, "", false},
		{"undefined flag", []string{"ttp", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{"undefined flag in artifact", []string{"artifact", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{"undefined flag in cm", []string{"cm", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{"undefined flag in rel", []string{"rel", "-nope", "any"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{"undefined flag in coverage", []string{"coverage", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{"undefined flag in gain", []string{"gain", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{"undefined flag in contain", []string{"contain", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, "", true},
		{
			"-family outside off/def",
			[]string{"rel", "-family", "sideways", "accesses"},
			"gr4ph: -family must be off or def, got sideways\n", 2, "", false,
		},
		{
			"-greedy with -top",
			[]string{"gain", "-greedy", "-top", "3"},
			"gr4ph: -greedy cannot be combined with -top or -all\n", 2, "", false,
		},
		{
			"-greedy with -all",
			[]string{"gain", "-greedy", "-all"},
			"gr4ph: -greedy cannot be combined with -top or -all\n", 2, "", false,
		},
		{
			"negative -top",
			[]string{"gain", "-top", "-1"},
			"gr4ph: -top must not be negative\n", 2, "", false,
		},
		{"unresolved technique", []string{"ttp", "no-such"}, "gr4ph: no such technique: no-such\n", 1, "", false},
		{"unresolved artifact", []string{"artifact", "no-such"}, "gr4ph: no such artifact: no-such\n", 1, "", false},
		{"unresolved countermeasure", []string{"cm", "no-such"}, "gr4ph: no such countermeasure: no-such\n", 1, "", false},
		{"unresolved relation", []string{"rel", "no-such"}, "gr4ph: no such relation: no-such\n", 1, "", false},
		{"unresolved data component", []string{"dc", "no-such"}, "gr4ph: no such data component: no-such\n", 1, "", false},
		{"unresolved group", []string{"group", "no-such"}, "gr4ph: no such group: no-such\n", 1, "", false},
		{"unresolved tactic", []string{"tactic", "no-such"}, "gr4ph: no such tactic: no-such\n", 1, "", false},
		{"unresolved platform", []string{"platform", "no-such"}, "gr4ph: no such platform: no-such\n", 1, "", false},
		{
			"relation of the other family",
			[]string{"rel", "-family", "off", "analyzes"},
			"gr4ph: no such offensive relation: analyzes\n", 1, "", false,
		},
		{
			"relation of the other family, defensively",
			[]string{"rel", "-family", "def", "accesses"},
			"gr4ph: no such defensive relation: accesses\n", 1, "", false,
		},
		{
			"offensive relation filter outside its family",
			[]string{"ttp", "-rel", "analyzes", "T1003.001"},
			"gr4ph: no such offensive relation: analyzes\n", 1, "", false,
		},
		{
			"defensive relation filter in artifact",
			[]string{"artifact", "-defrel", "accesses", "Process"},
			"gr4ph: no such defensive relation: accesses\n", 1, "", false,
		},
		{
			"defensive relation filter in cm",
			[]string{"cm", "-defrel", "accesses", "Process"},
			"gr4ph: no such defensive relation: accesses\n", 1, "", false,
		},
		// The overlay verbs build one block per invocation, so an unresolved
		// query still prints the block of the empty deployment: the states of
		// "nothing deployed" are an answer, not a silence.
		{
			"unresolved countermeasure in coverage",
			[]string{"coverage", "no-such"},
			"gr4ph: no such countermeasure: no-such\n", 1, fixtureCoverageEmpty, false,
		},
		{
			"unresolved countermeasure in gain",
			[]string{"gain", "no-such"},
			"gr4ph: no such countermeasure: no-such\n", 1, fixtureGainEmpty, false,
		},
		{
			"unresolved technique in contain",
			[]string{"contain", "no-such"},
			"gr4ph: no such technique: no-such\n", 1, "contain observed=0\n  out countermeasures (0): -\n", false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, stderr, status := runCase(t, e, tt.args...)
			if status != tt.wantExit {
				t.Errorf("status = %d, want %d", status, tt.wantExit)
			}
			if out != tt.wantOut {
				t.Errorf("stdout = %q, want %q", out, tt.wantOut)
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
			for _, want := range []string{
				"usage: gr4ph", "ttp <query>", "artifact <query>", "cm <query>",
				"dc <query>", "group <query>", "tactic <ta-id>", "platform <name>", "rel <name>", "exit status: 0",
				"coverage <cm>", "gain <cm>", "contain <ttp>",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("usage does not mention %q", want)
				}
			}
		})
	}
}

// gainRows decodes the candidate lines of a gain block into their names, labels
// and gains, in printed order.
func gainRows(t *testing.T, out string) []gain {
	t.Helper()
	var rows []gain
	for _, line := range strings.Split(out, "\n") {
		rest, ok := strings.CutPrefix(line, "  ")
		if !ok {
			continue
		}
		gainStr, rest, ok := strings.Cut(rest, "  ")
		if !ok {
			t.Fatalf("gainRows: malformed line %q", line)
		}
		g, err := strconv.Atoi(gainStr)
		if err != nil {
			t.Fatalf("gainRows: gain in %q: %v", line, err)
		}
		name, label, _ := strings.Cut(rest, " ")
		rows = append(rows, gain{Name: name, Label: strings.Trim(label, `"`), Gain: g})
	}
	return rows
}

// gainLine returns the gain of the candidate row naming name, e.g.
// gainLine(t, out, "ContentQuarantine").
func gainLine(t *testing.T, out, name string) int {
	t.Helper()
	for _, g := range gainRows(t, out) {
		if g.Name == name {
			return g.Gain
		}
	}
	t.Fatalf("gainLine: no %q row in output:\n%s", name, out)
	return 0
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
