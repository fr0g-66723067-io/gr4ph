//go:build goexperiment.simd

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/fr0g-66723067/gr4ph"
	"github.com/fr0g-66723067/gr4ph/ontology"
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
	t1003 := mustTTP(t, b, "T1003", "OS Credential Dumping", gr4ph.DomainEnterprise, gr4ph.NoParent)
	sub := mustTTP(t, b, "T1003.001", "LSASS Memory", gr4ph.DomainEnterprise, t1003)
	mustTTP(t, b, "T1059", "Command and Scripting Interpreter", gr4ph.DomainEnterprise, gr4ph.NoParent) // no edges
	process := mustArtifact(t, b, "Process", "Process")                                                 // label == name
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

func mustTTP(t *testing.T, b *gr4ph.Builder, id, label string, dom gr4ph.Domain, parent gr4ph.TTP) gr4ph.TTP {
	t.Helper()
	tt, err := b.AddTTP(id, label, dom, parent)
	must(t, err)
	return tt
}

func mustArtifact(t *testing.T, b *gr4ph.Builder, name, label string) gr4ph.Artifact {
	t.Helper()
	a, err := b.AddArtifact(name, label)
	must(t, err)
	return a
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
	fixtureTTPSub = `ttp T1003.001 "LSASS Memory" domain=enterprise parent=T1003 children=0
  out artifacts (2): Process, AuthenticationService "Authentication Service"
  out artifacts rollup (2): Process, AuthenticationService "Authentication Service"
  in  countermeasures (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  countermeasures rollup (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
`

	fixtureTTPParent = `ttp T1003 "OS Credential Dumping" domain=enterprise children=1
  out artifacts (0): -
  out artifacts rollup (2): Process, AuthenticationService "Authentication Service"
  in  countermeasures (0): -
  in  countermeasures rollup (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
`

	fixtureTTPIsolated = `ttp T1059 "Command and Scripting Interpreter" domain=enterprise children=0
  out artifacts (0): -
  out artifacts rollup (0): -
  in  countermeasures (0): -
  in  countermeasures rollup (0): -
`

	fixtureTTPSubBlocks = `ttp T1003.001 "LSASS Memory" domain=enterprise parent=T1003 children=0
  out artifacts (rel blocks) (1): AuthenticationService "Authentication Service"
  out artifacts rollup (rel blocks) (1): AuthenticationService "Authentication Service"
  in  countermeasures (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
  in  countermeasures rollup (2): CredentialHardening "Credential Hardening", ContentQuarantine "Content Quarantine"
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
	if len(got.Sets) != 4 {
		t.Fatalf("sets = %d, want 4", len(got.Sets))
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
	if want := `ttp T1003.001 "LSASS Memory" domain=enterprise parent=T1003 children=0`; header != want {
		t.Errorf("header = %q, want %q", header, want)
	}

	tests := []struct {
		name      string
		args      []string
		set       string // "<dir> <set name>"
		wantCount int
		first     string
		last      string
	}{
		{"artifacts of a sub-technique", []string{"ttp", "T1003.001"}, "out artifacts", 2,
			`AuthenticationService "Authentication Service"`, "Process"},
		{"countermeasures of a sub-technique", []string{"ttp", "T1003.001"}, "in countermeasures", 12,
			`Application-basedProcessIsolation "Application-based Process Isolation"`, `WebSessionAccessMediation "Web Session Access Mediation"`},
		{"techniques touching an artifact", []string{"artifact", "Process"}, "in techniques", 5,
			`T1003.001 "LSASS Memory"`, `T1546.007 "Netsh Helper DLL"`},
		{"those techniques collapsed to parents", []string{"artifact", "Process"}, "in techniques rollup", 3,
			`T1003 "OS Credential Dumping"`, `T1546 "Event Triggered Execution"`},
		{"countermeasures directly linked to an artifact", []string{"artifact", "Process"}, "in countermeasures", 11,
			`Application-basedProcessIsolation "Application-based Process Isolation"`, `SystemCallFiltering "System Call Filtering"`},
		{"countermeasure surface of an artifact", []string{"artifact", "Process"}, "in countermeasures viaTTPs", 36, "", ""},
		{"artifacts of a countermeasure", []string{"cm", "CredentialHardening"}, "out artifacts", 1,
			"Credential", "Credential"},
		{"techniques defended by a countermeasure", []string{"cm", "CredentialHardening"}, "out techniques", 25,
			`DE-0011 "Credentialed Evasion"`, `T1606.001 "Web Cookies"`},
		{"those techniques collapsed to parents", []string{"cm", "CredentialHardening"}, "out techniques rollup", 16,
			`DE-0011 "Credentialed Evasion"`, `T1606 "Forge Web Credentials"`},
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
		{"union planes", []string{"rel", "any"},
			fmt.Sprintf("rel any offensive union plane 0/41 (technique -> artifact): edges=%d sources=427\n"+
				"rel any defensive union plane 0/38 (countermeasure -> artifact): edges=%d sources=157\n",
				len(distinct), len(ontology.DefEdgeCM))},
		{"offensive plane", []string{"rel", "accesses"},
			"rel accesses offensive plane 2/41 (technique -> artifact): edges=55 sources=51\n"},
		{"defensive plane", []string{"rel", "analyzes"},
			"rel analyzes defensive plane 1/38 (countermeasure -> artifact): edges=49 sources=45\n"},
		{"a name in both families", []string{"rel", "blocks"},
			"rel blocks offensive plane 4/41 (technique -> artifact): edges=2 sources=2\n" +
				"rel blocks defensive plane 3/38 (countermeasure -> artifact): edges=6 sources=6\n"},
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
		mustTTP(t, b, fmt.Sprintf("T%d", 9000+i), fmt.Sprintf("Technique %d", i), dom, gr4ph.NoParent)
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
		{"undefined flag", []string{"ttp", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"undefined flag in artifact", []string{"artifact", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"undefined flag in cm", []string{"cm", "-nope", "X"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"undefined flag in rel", []string{"rel", "-nope", "any"}, "gr4ph: flag provided but not defined: -nope\n", 2, true},
		{"-family outside off/def", []string{"rel", "-family", "sideways", "accesses"},
			"gr4ph: -family must be off or def, got sideways\n", 2, false},
		{"unresolved technique", []string{"ttp", "no-such"}, "gr4ph: no such technique: no-such\n", 1, false},
		{"unresolved artifact", []string{"artifact", "no-such"}, "gr4ph: no such artifact: no-such\n", 1, false},
		{"unresolved countermeasure", []string{"cm", "no-such"}, "gr4ph: no such countermeasure: no-such\n", 1, false},
		{"unresolved relation", []string{"rel", "no-such"}, "gr4ph: no such relation: no-such\n", 1, false},
		{"relation of the other family", []string{"rel", "-family", "off", "analyzes"},
			"gr4ph: no such offensive relation: analyzes\n", 1, false},
		{"relation of the other family, defensively", []string{"rel", "-family", "def", "accesses"},
			"gr4ph: no such defensive relation: accesses\n", 1, false},
		{"offensive relation filter outside its family", []string{"ttp", "-rel", "analyzes", "T1003.001"},
			"gr4ph: no such offensive relation: analyzes\n", 1, false},
		{"defensive relation filter in artifact", []string{"artifact", "-defrel", "accesses", "Process"},
			"gr4ph: no such defensive relation: accesses\n", 1, false},
		{"defensive relation filter in cm", []string{"cm", "-defrel", "accesses", "Process"},
			"gr4ph: no such defensive relation: accesses\n", 1, false},
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
			for _, want := range []string{"usage: gr4ph", "ttp <query>", "artifact <query>", "cm <query>", "rel <name>", "exit status: 0"} {
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
