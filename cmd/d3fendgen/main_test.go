package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestParseAttackDedup covers the STIX rules: only attack-pattern objects with
// a mitre-attack external reference are kept, and a duplicated id prefers the
// first non-revoked, non-deprecated name, else the first in file order.
func TestParseAttackDedup(t *testing.T) {
	data := []byte(`{
	  "objects": [
	    {"type": "attack-pattern", "name": "Live First",
	     "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]},
	    {"type": "attack-pattern", "name": "Revoked Twin", "revoked": true,
	     "external_references": [{"source_name": "mitre-attack", "external_id": "T1000"}]},
	    {"type": "attack-pattern", "name": "Revoked First", "x_mitre_deprecated": true,
	     "external_references": [{"source_name": "mitre-attack", "external_id": "T2000"}]},
	    {"type": "attack-pattern", "name": "Live Second",
	     "external_references": [{"source_name": "mitre-attack", "external_id": "T2000"}]},
	    {"type": "attack-pattern", "name": "No ATT&CK id",
	     "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}]},
	    {"type": "malware", "name": "Not a technique",
	     "external_references": [{"source_name": "mitre-attack", "external_id": "S1000"}]}
	  ]
	}`)

	out := map[string]*ttpInfo{}
	if err := parseAttack(data, domEnterprise, out); err != nil {
		t.Fatalf("parseAttack: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("parsed %d ids, want 2 (T1000, T2000): %v", len(out), sortedKeys(out))
	}
	if got := out["T1000"].label; got != "Live First" {
		t.Fatalf("T1000 label = %q, want Live First (live object wins)", got)
	}
	if got := out["T2000"].label; got != "Live Second" {
		t.Fatalf("T2000 label = %q, want Live Second (deprecated name loses)", got)
	}
	if out["T1000"].bad {
		t.Fatal("T1000 must not be marked revoked")
	}
	if _, ok := out["S1000"]; ok {
		t.Fatal("non attack-pattern objects must be ignored")
	}
	if out["T1000"].domain != domEnterprise {
		t.Fatal("domain tag not applied")
	}
}

// TestParseAttackDomainPrecedence pins the defensive tiebreak: an id already
// seen in an earlier domain keeps that domain.
func TestParseAttackDomainPrecedence(t *testing.T) {
	out := map[string]*ttpInfo{}
	ent := []byte(`{"objects":[{"type":"attack-pattern","name":"Shared",
	  "external_references":[{"source_name":"mitre-attack","external_id":"T1000"}]}]}`)
	ics := []byte(`{"objects":[{"type":"attack-pattern","name":"Shared ICS",
	  "external_references":[{"source_name":"mitre-attack","external_id":"T1000"}]}]}`)
	if err := parseAttack(ent, domEnterprise, out); err != nil {
		t.Fatal(err)
	}
	if err := parseAttack(ics, domICS, out); err != nil {
		t.Fatal(err)
	}
	if out["T1000"].domain != domEnterprise || out["T1000"].label != "Shared" {
		t.Fatalf("precedence lost: %+v", out["T1000"])
	}
}

// TestParseD3FEND covers IRI local names, quoted fields with embedded commas,
// the offensive/defensive split, relation vocabularies and the defends-against
// inference.
func TestParseD3FEND(t *testing.T) {
	csv := "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
		"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
		"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n" +
		`Credential Hardening,hardens,Credential,Encrypted Credential,accesses,` +
		`"Cached Domain Credentials, v2",OS Credential Dumping,` +
		"http://x#CredentialHardening,http://x#hardens,http://x#Credential," +
		"http://x#EncryptedCredential,http://x#accesses,http://x#T1003.005,http://x#T1003\n" +
		"Process Isolation,analyzes,Process,Process,isolates,LSASS Memory,OS Credential Dumping," +
		"http://x#ProcessIsolation,http://x#analyzes,http://x#Process," +
		"http://x#Process,http://x#isolates,http://x#T1003.001,http://x#T1003\n"

	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}

	if got := d.ttpLabels("T1003.005"); len(got) != 1 || got[0] != "Cached Domain Credentials, v2" {
		t.Fatalf("ttpLabels(T1003.005) = %v, want the quoted label with its comma", got)
	}
	if got := d.cmLabel["CredentialHardening"]; got != "Credential Hardening" {
		t.Fatalf("cmLabel = %q", got)
	}
	if got := d.artLabel["EncryptedCredential"]; got != "Encrypted Credential" {
		t.Fatalf("artifact label = %q", got)
	}
	if !d.artOff["EncryptedCredential"] {
		t.Fatal("EncryptedCredential must be marked offensive")
	}
	if _, ok := d.artOff["Credential"]; ok {
		t.Fatal("Credential is defensive-only and must not be marked offensive")
	}
	if got := sortedKeys(d.offRel); len(got) != 2 || got[0] != "accesses" || got[1] != "isolates" {
		t.Fatalf("offensive rels = %v, want [accesses isolates]", got)
	}
	if got := sortedKeys(d.defRel); len(got) != 2 || got[0] != "analyzes" || got[1] != "hardens" {
		t.Fatalf("defensive rels = %v, want [analyzes hardens]", got)
	}
	if len(d.offEdge) != 2 {
		t.Fatalf("offensive triples = %d, want 2", len(d.offEdge))
	}
	if !d.offEdge[[3]string{"T1003.005", "EncryptedCredential", "accesses"}] {
		t.Fatal("missing offensive triple (T1003.005, EncryptedCredential, accesses)")
	}
	if len(d.defEdge) != 2 {
		t.Fatalf("defensive triples = %d, want 2", len(d.defEdge))
	}
	if !d.defEdge[[3]string{"ProcessIsolation", "Process", "analyzes"}] {
		t.Fatal("missing defensive triple (ProcessIsolation, Process, analyzes)")
	}
	if len(d.defends) != 2 {
		t.Fatalf("defends pairs = %d, want 2", len(d.defends))
	}
	if !d.defends[[2]string{"CredentialHardening", "T1003.005"}] {
		t.Fatal("missing defends pair (CredentialHardening, T1003.005)")
	}
	if !d.parentOf["T1003.005"]["T1003"] {
		t.Fatalf("parentOf[T1003.005] = %v, want T1003", sortedKeys(d.parentOf["T1003.005"]))
	}
	if got := d.parentLabel["T1003"]; got != "OS Credential Dumping" {
		t.Fatalf("parentLabel = %q", got)
	}
}

func TestParseD3FENDMissingColumn(t *testing.T) {
	_, err := parseD3FEND([]byte("off_tech,off_artifact\nhttp://x#T1,http://x#A\n"))
	if err == nil || !strings.Contains(err.Error(), "missing column") {
		t.Fatalf("err = %v, want a missing-column error", err)
	}
}

// TestTTPLabelVariants pins the order-independent label set: two spellings for
// one id must both survive parsing, sorted.
func TestTTPLabelVariants(t *testing.T) {
	csv := "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
		"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
		"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n" +
		"X,analyzes,Process,Process,accesses,Modify controller Tasking,Controller Tasking," +
		"http://x#X,http://x#analyzes,http://x#Process,http://x#Process,http://x#accesses,http://x#T0821,http://x#T0800\n" +
		"X,analyzes,Process,Process,accesses,Modify Controller Tasking,Controller Tasking," +
		"http://x#X,http://x#analyzes,http://x#Process,http://x#Process,http://x#accesses,http://x#T0821,http://x#T0800\n"

	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	got := d.ttpLabels("T0821")
	if len(got) != 2 || got[0] != "Modify Controller Tasking" || got[1] != "Modify controller Tasking" {
		t.Fatalf("ttpLabels(T0821) = %v, want both spellings sorted", got)
	}
}

func TestLocalNameAndCamel(t *testing.T) {
	if got := localName("http://d3fend.mitre.org/ontologies/d3fend.owl#T1003.005"); got != "T1003.005" {
		t.Fatalf("localName = %q", got)
	}
	if got := localName("T1003"); got != "T1003" {
		t.Fatalf("localName without a fragment = %q", got)
	}
	cases := map[string]string{
		"abuses":                 "Abuses",
		"may-be-associated-with": "MayBeAssociatedWith",
		"use-limits":             "UseLimits",
		"may-access":             "MayAccess",
		"-lead":                  "Lead",
		"trail-":                 "Trail",
	}
	for in, want := range cases {
		if got := camel(in); got != want {
			t.Errorf("camel(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestAssembleRejectsBadHierarchy covers the two structural invariants: depth
// is two levels and child blocks are contiguous.
func TestAssembleRejectsBadHierarchy(t *testing.T) {
	empty := &d3fendData{
		ttpLabel:    map[string]map[string]bool{},
		artLabel:    map[string]string{},
		artOff:      map[string]bool{},
		artDef:      map[string]bool{},
		cmLabel:     map[string]string{},
		offRel:      map[string]bool{},
		defRel:      map[string]bool{},
		offEdge:     map[[3]string]bool{},
		defEdge:     map[[3]string]bool{},
		defends:     map[[2]string]bool{},
		parentOf:    map[string]map[string]bool{},
		parentLabel: map[string]string{},
	}

	deep := map[string]*ttpInfo{
		"T1":     {label: "one"},
		"T1.1":   {label: "one-one", sub: true},
		"T1.1.1": {label: "three levels", sub: true},
	}
	if _, err := assemble(deep, empty); err == nil || !strings.Contains(err.Error(), "deeper than two levels") {
		t.Fatalf("err = %v, want a depth error", err)
	}

	// Depth is checked before the sub-technique flag: a three-level id is a
	// depth error even when its x_mitre_is_subtechnique flag disagrees too.
	deepNoFlag := map[string]*ttpInfo{
		"T1":     {label: "one"},
		"T1.1":   {label: "one-one", sub: true},
		"T1.1.1": {label: "three levels"},
	}
	if _, err := assemble(deepNoFlag, empty); err == nil || !strings.Contains(err.Error(), "deeper than two levels") {
		t.Fatalf("err = %v, want a depth error", err)
	}

	// "T1-9" sorts between the parent "T1" and its child "T1.2", so the child
	// block is no longer contiguous.
	gap := map[string]*ttpInfo{
		"T1":   {label: "one"},
		"T1-9": {label: "intruder"},
		"T1.2": {label: "one-two", sub: true},
	}
	if _, err := assemble(gap, empty); err == nil || !strings.Contains(err.Error(), "child block") {
		t.Fatalf("err = %v, want a contiguity error", err)
	}
}

// TestAssembleShapeDrift: a graph that is structurally fine but does not match
// the pinned release must fail the shape gate rather than emit mismatched
// indices. assemble itself no longer gates; run does.
func TestAssembleShapeDrift(t *testing.T) {
	d := &d3fendData{
		ttpLabel:    map[string]map[string]bool{"T1": {"One": true}},
		artLabel:    map[string]string{"A": "A"},
		artOff:      map[string]bool{"A": true},
		cmLabel:     map[string]string{"CM": "CM"},
		offRel:      map[string]bool{"accesses": true},
		defRel:      map[string]bool{"analyzes": true},
		offEdge:     map[[3]string]bool{{"T1", "A", "accesses"}: true},
		defEdge:     map[[3]string]bool{{"CM", "A", "analyzes"}: true},
		defends:     map[[2]string]bool{{"CM", "T1"}: true},
		parentOf:    map[string]map[string]bool{},
		parentLabel: map[string]string{},
	}
	m, err := assemble(map[string]*ttpInfo{}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if err := m.checkShape(pinnedShape); err == nil || !strings.Contains(err.Error(), "shape drift") {
		t.Fatalf("err = %v, want a shape-drift error", err)
	}
}

// TestCheckShapeHistogram covers the domain-histogram arm of the shape gate: a
// graph whose counts match but whose domain tags do not must still fail.
func TestCheckShapeHistogram(t *testing.T) {
	d := &d3fendData{
		ttpLabel:    map[string]map[string]bool{"T1": {"One": true}},
		artLabel:    map[string]string{"A": "A"},
		artOff:      map[string]bool{"A": true},
		cmLabel:     map[string]string{"CM": "CM"},
		offRel:      map[string]bool{"accesses": true},
		defRel:      map[string]bool{"analyzes": true},
		offEdge:     map[[3]string]bool{{"T1", "A", "accesses"}: true},
		defEdge:     map[[3]string]bool{{"CM", "A", "analyzes"}: true},
		defends:     map[[2]string]bool{{"CM", "T1"}: true},
		parentOf:    map[string]map[string]bool{},
		parentLabel: map[string]string{},
	}
	m, err := assemble(map[string]*ttpInfo{}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	// The single technique has no ATT&CK object, so assemble tags it SPARTA.
	small := shape{ttps: 1, artifacts: 1, cms: 1, offRels: 1, defRels: 1,
		offEdges: 1, defEdges: 1, defends: 1, offPairs: 1}
	if err := m.checkShape(small); err == nil || !strings.Contains(err.Error(), "domain histogram") {
		t.Fatalf("err = %v, want a domain-histogram error", err)
	}
}

// TestParseAttackMalformed covers the JSON error path.
func TestParseAttackMalformed(t *testing.T) {
	err := parseAttack([]byte("{"), domEnterprise, map[string]*ttpInfo{})
	if err == nil || !strings.Contains(err.Error(), "parse STIX") {
		t.Fatalf("err = %v, want a parse-STIX error", err)
	}
}

// TestSortedTriplesOrder pins the total order used for every edge table: the
// three components are compared in turn, ties keep both entries.
func TestSortedTriplesOrder(t *testing.T) {
	in := map[[3]string]bool{
		{"a", "b", "1"}: true,
		{"a", "b", "2"}: true,
		{"a", "c", "1"}: true,
	}
	got := sortedTriples(in)
	want := [][3]string{{"a", "b", "1"}, {"a", "b", "2"}, {"a", "c", "1"}}
	if len(got) != len(want) {
		t.Fatalf("sortedTriples = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedTriples = %v, want %v", got, want)
		}
	}
}

// TestLoadHTTP covers both transports: an HTTP fetch, an HTTP error status, an
// unreachable host and a missing local file.
func TestLoadHTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	got, err := load(srv.URL + "/ok")
	if err != nil {
		t.Fatalf("load(ok): %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("load(ok) = %q, want hello", got)
	}

	if _, err := load(srv.URL + "/missing"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Fatalf("load(404) err = %v, want a 404 error", err)
	}
	if _, err := load("http://127.0.0.1:1/x"); err == nil {
		t.Fatal("load(unreachable) must fail")
	}
	if _, err := load(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "read") {
		t.Fatalf("load(missing file) err = %v, want a read error", err)
	}

	// A body shorter than its Content-Length fails in io.ReadAll.
	truncated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		_, _ = w.Write([]byte("short"))
	}))
	defer truncated.Close()
	if _, err := load(truncated.URL); err == nil {
		t.Fatal("a truncated body must fail")
	}
}

// Shared fixtures for the offline pipeline tests.
//
// The CSV crosses two ATT&CK techniques (T1.1 is a sub-technique) and one
// sub-technique whose parent exists in no STIX bundle (SP-1.1 -> SP-1), with
// two artifacts, one countermeasure, two offensive edges, two defensive edges
// and two defends-against pairs.
const testCSV = "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
	"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
	"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n" +
	"CM One,analyzes,A One,A One,accesses,One One,One," +
	"http://x#CM1,http://x#analyzes,http://x#A1,http://x#A1,http://x#accesses,http://x#T1.1,http://x#T1\n" +
	"CM One,hardens,A One,A Two,accesses,Sp One One,Sp One," +
	"http://x#CM1,http://x#hardens,http://x#A1,http://x#A2,http://x#accesses,http://x#SP-1.1,http://x#SP-1\n" +
	"CM One,analyzes,A One,A One,accesses,One One Alt,One," +
	"http://x#CM1,http://x#analyzes,http://x#A1,http://x#A1,http://x#accesses,http://x#T1.1,http://x#T1\n"

const testEnterpriseJSON = `{"objects":[
  {"type":"attack-pattern","name":"One",
   "external_references":[{"source_name":"mitre-attack","external_id":"T1"}]},
  {"type":"attack-pattern","name":"One One","x_mitre_is_subtechnique":true,
   "external_references":[{"source_name":"mitre-attack","external_id":"T1.1"}]}]}`

// testShape is the shape of the graph the fixtures produce: sorted ids
// SP-1, SP-1.1, T1, T1.1, T2, T3 — two enterprise techniques, one ICS (T2),
// one mobile (T3) and two synthesised SPARTA nodes (SP-1, SP-1.1).
var testShape = shape{ttps: 6, artifacts: 2, cms: 1, offRels: 1, defRels: 2,
	offEdges: 2, defEdges: 2, defends: 2, offPairs: 2,
	enterprise: 2, mobile: 1, ics: 1, sparta: 2}

// writeFixtures lays the fixture sources out in a fresh temp dir and returns
// their paths plus the directory itself.
func writeFixtures(t *testing.T) (dir, ent, ics, mob, csvPath string) {
	t.Helper()
	dir = t.TempDir()
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	return dir, write("enterprise.json", testEnterpriseJSON),
		write("ics.json", `{"objects":[{"type":"attack-pattern","name":"Two",
		  "external_references":[{"source_name":"mitre-attack","external_id":"T2"}]}]}`),
		write("mobile.json", `{"objects":[{"type":"attack-pattern","name":"Three",
		  "external_references":[{"source_name":"mitre-attack","external_id":"T3"}]}]}`),
		write("d3fend.csv", testCSV)
}

// TestRunEndToEnd drives the whole offline pipeline on the fixture: load ->
// parseAttack -> parseD3FEND -> assemble -> shape gate -> emit -> write,
// including the synthesised-parent branch (SP-1 exists in no STIX bundle) and
// the directory creation for a nested output path.
func TestRunEndToEnd(t *testing.T) {
	dir, ent, ics, mob, csvPath := writeFixtures(t)

	out := filepath.Join(dir, "out", "attack_gen.go")
	var buf bytes.Buffer
	if err := run(ent, ics, mob, csvPath, out, &buf, testShape); err != nil {
		t.Fatalf("run: %v", err)
	}
	src, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output file: %v", err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), out, src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v", err)
	}

	// gofmt aligns the `=` inside a const block, so match the values with
	// regexps instead of pinning a space count.
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\bNTTP\s+= 6\b`),
		regexp.MustCompile(`\bNArtifact\s+= 2\b`),
		regexp.MustCompile(`\bNDefends\s+= 2\b`),
		regexp.MustCompile(`\bRelAccesses\s+gr4ph\.Rel = 1\b`),
		regexp.MustCompile(`\bDefRelAnalyzes\s+gr4ph\.DefRel = 1\b`),
		regexp.MustCompile(`\bDefRelHardens\s+gr4ph\.DefRel = 2\b`),
	} {
		if !want.Match(src) {
			t.Errorf("generated source does not match %s", want)
		}
	}
	for _, want := range []string{
		"uint16(gr4ph.NoParent)",
		"gr4ph.DomainICS",
		"gr4ph.DomainMobile",
		"gr4ph.DomainSPARTA",
		`"Sp One"`,
		`{"One One Alt"}`,
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("generated source is missing %q", want)
		}
	}

	// The shape report is the documented stdout contract (README "Regenerating
	// the tables"), so pin it byte for byte: same labels, same padding, same
	// order.
	wantSummary := "d3fendgen: wrote " + out + "\n" +
		"  ttps           6 (2 enterprise, 1 mobile, 1 ics, 2 sparta)\n" +
		"  artifacts      2\n" +
		"  countermeasures 1\n" +
		"  relations      1 offensive, 2 defensive\n" +
		"  edges          2 offensive, 2 defensive, 2 defends-against\n" +
		"  hierarchy      4 top-level, 2 sub-techniques, 2 parents, max 1 children\n"
	if got := buf.String(); got != wantSummary {
		t.Fatalf("summary mismatch\n--- got ---\n%s--- want ---\n%s", got, wantSummary)
	}
}

// TestRunErrorPaths pins error propagation: a missing source, malformed STIX, a
// bad CSV, a shape mismatch and an unwritable output must all fail, and a failed
// run must not leave a partial file behind.
func TestRunErrorPaths(t *testing.T) {
	dir, ent, ics, mob, csvPath := writeFixtures(t)
	write := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	out := filepath.Join(dir, "attack_gen.go")

	if err := run(filepath.Join(dir, "nope.json"), ics, mob, csvPath, out, io.Discard, testShape); err == nil {
		t.Fatal("missing enterprise source must fail")
	}
	bad := write("bad.json", "{")
	if err := run(bad, ics, mob, csvPath, out, io.Discard, testShape); err == nil || !strings.Contains(err.Error(), "parse STIX") {
		t.Fatalf("malformed STIX err = %v, want a parse-STIX error", err)
	}
	badCSV := write("bad.csv", "off_tech,off_artifact\nhttp://x#T1,http://x#A1\n")
	if err := run(ent, ics, mob, badCSV, out, io.Discard, testShape); err == nil || !strings.Contains(err.Error(), "missing column") {
		t.Fatalf("bad CSV err = %v, want a missing-column error", err)
	}
	if err := run(ent, ics, mob, csvPath, out, io.Discard, pinnedShape); err == nil || !strings.Contains(err.Error(), "shape drift") {
		t.Fatalf("shape mismatch err = %v, want a shape-drift error", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("a failed run must not write the output: stat err = %v", err)
	}

	// Each ATT&CK source is parsed, not just the first: malformed ICS and
	// mobile bundles must fail too.
	if err := run(ent, bad, mob, csvPath, out, io.Discard, testShape); err == nil || !strings.Contains(err.Error(), "parse STIX") {
		t.Fatalf("malformed ICS err = %v, want a parse-STIX error", err)
	}
	if err := run(ent, ics, bad, csvPath, out, io.Discard, testShape); err == nil || !strings.Contains(err.Error(), "parse STIX") {
		t.Fatalf("malformed mobile err = %v, want a parse-STIX error", err)
	}

	// A structurally invalid graph (three hierarchy levels) fails inside run,
	// before anything is emitted. The chain is otherwise valid: D-1.1 is a
	// proper two-level node, so D-1.1.1 is what makes it three.
	deep := write("deep.csv", testCSV+
		"CM One,analyzes,A One,A Three,accesses,Deep One,Deep,"+
		"http://x#CM1,http://x#analyzes,http://x#A1,http://x#A3,http://x#accesses,http://x#D-1.1,http://x#D-1\n"+
		"CM One,analyzes,A One,A Three,accesses,Deep Two,Deep One,"+
		"http://x#CM1,http://x#analyzes,http://x#A1,http://x#A3,http://x#accesses,http://x#D-1.1.1,http://x#D-1.1\n")
	if err := run(ent, ics, mob, deep, out, io.Discard, testShape); err == nil ||
		!strings.Contains(err.Error(), "deeper than two levels") {
		t.Fatalf("deep hierarchy err = %v, want a depth error", err)
	}

	// Every source load fails loudly, not just the first one.
	if err := run(ent, filepath.Join(dir, "nope.json"), mob, csvPath, out, io.Discard, testShape); err == nil {
		t.Fatal("missing ICS source must fail")
	}
	if err := run(ent, ics, filepath.Join(dir, "nope.json"), csvPath, out, io.Discard, testShape); err == nil {
		t.Fatal("missing mobile source must fail")
	}
	if err := run(ent, ics, mob, filepath.Join(dir, "nope.json"), out, io.Discard, testShape); err == nil {
		t.Fatal("missing D3FEND source must fail")
	}

	// Correct counts, wrong union-plane cardinality.
	badPairs := testShape
	badPairs.offPairs++
	if err := run(ent, ics, mob, csvPath, out, io.Discard, badPairs); err == nil ||
		!strings.Contains(err.Error(), "distinct technique/artifact pairs") {
		t.Fatalf("pair-count mismatch err = %v, want a distinct-pairs error", err)
	}

	// Unwritable output: the parent path is a file, then the path itself is a
	// directory.
	blocker := write("blocker", "not a directory")
	if err := run(ent, ics, mob, csvPath, filepath.Join(blocker, "attack_gen.go"), io.Discard, testShape); err == nil {
		t.Fatal("an output under a file must fail")
	}
	if err := run(ent, ics, mob, csvPath, dir, io.Discard, testShape); err == nil {
		t.Fatal("an output over an existing directory must fail")
	}
}

// TestParseD3FENDInputEdges covers the CSV reader's defensive paths: an empty
// input has no header, a short row reads its missing columns as empty, and a
// malformed row is reported.
func TestParseD3FENDInputEdges(t *testing.T) {
	if _, err := parseD3FEND(nil); err == nil || !strings.Contains(err.Error(), "read CSV header") {
		t.Fatalf("empty input err = %v, want a header error", err)
	}

	csv := "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
		"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
		"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n" +
		"short,row\n"
	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND(ragged row): %v", err)
	}
	if len(d.offEdge) != 0 || len(d.defEdge) != 0 {
		t.Fatalf("ragged row contributed edges: %d %d", len(d.offEdge), len(d.defEdge))
	}

	if _, err := parseD3FEND([]byte(csv + "\"unterminated\n")); err == nil ||
		!strings.Contains(err.Error(), "read CSV row") {
		t.Fatalf("malformed row err = %v, want a read-row error", err)
	}
}

// TestAssembleSynthesisedParents pins the rules for parents that exist in no
// ATT&CK domain, which is where 11 of the 1186 nodes come from.
func TestAssembleSynthesisedParents(t *testing.T) {
	header := "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
		"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
		"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n"
	row := func(offTech, offLabel, parent, parentLabel string) string {
		return "CM,analyzes,A,A,accesses," + offLabel + "," + parentLabel + "," +
			"http://x#CM,http://x#analyzes,http://x#A,http://x#A,http://x#accesses,http://x#" +
			offTech + ",http://x#" + parent + "\n"
	}
	parse := func(t *testing.T, csv string) *d3fendData {
		t.Helper()
		d, err := parseD3FEND([]byte(csv))
		if err != nil {
			t.Fatalf("parseD3FEND: %v", err)
		}
		return d
	}

	// A prefix D3FEND names itself needs no synthesis, and its sub-technique
	// may leave off_tech_parent empty.
	d := parse(t, header+row("D-1", "D One", "", "")+row("D-1.1", "D One One", "D-1", "D One"))
	m, err := assemble(map[string]*ttpInfo{}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(m.ttpIDs) != 2 || m.ttpIDs[0] != "D-1" || m.ttpIDs[1] != "D-1.1" {
		t.Fatalf("ids = %v, want [D-1 D-1.1]", m.ttpIDs)
	}
	if m.ttpParents[1] != 0 {
		t.Fatalf("parent of D-1.1 = %d, want 0", m.ttpParents[1])
	}
	for i, dom := range m.ttpDomains {
		if dom != domSPARTA {
			t.Fatalf("ttpDomains[%d] = %d, want SPARTA (no ATT&CK object)", i, dom)
		}
	}

	// A parent that exists in no table at all is synthesised from
	// off_tech_parent_label.
	m2, err := assemble(map[string]*ttpInfo{},
		parse(t, header+row("D-1.1", "D One One", "D-1", "D One")))
	if err != nil {
		t.Fatalf("assemble (synthesised parent): %v", err)
	}
	if len(m2.ttpIDs) != 2 || m2.ttpIDs[0] != "D-1" || m2.ttpLabels[0] != "D One" {
		t.Fatalf("synthesised parent = %v / %v, want [D-1] / [D One]", m2.ttpIDs, m2.ttpLabels)
	}
	if m2.ttpDomains[0] != domSPARTA {
		t.Fatalf("synthesised parent domain = %d, want SPARTA", m2.ttpDomains[0])
	}

	// A parent IRI that disagrees with the id prefix is rejected.
	if _, err := assemble(map[string]*ttpInfo{},
		parse(t, header+row("D-1.1", "D One One", "OTHER", "Other"))); err == nil ||
		!strings.Contains(err.Error(), "disagrees with its id prefix") {
		t.Fatalf("mismatching parent err = %v, want a prefix-disagreement error", err)
	}

	// A synthesised parent without a label is rejected.
	if _, err := assemble(map[string]*ttpInfo{},
		parse(t, header+row("D-1.1", "D One One", "D-1", ""))); err == nil ||
		!strings.Contains(err.Error(), "no off_tech_parent_label") {
		t.Fatalf("unlabelled parent err = %v, want a missing-label error", err)
	}

	// A three-level id is a depth error, not a missing-label one, even though
	// its intermediate node does not exist either.
	if _, err := assemble(map[string]*ttpInfo{},
		parse(t, header+row("D-1.1.1", "D One One One", "D-1.1", "D One One"))); err == nil ||
		!strings.Contains(err.Error(), "deeper than two levels") {
		t.Fatalf("three-level id err = %v, want a depth error", err)
	}

	// off_tech_parent is a set: a parent that disagrees with the id prefix is
	// reported whichever row order the CSV lists, even when another row agrees.
	agree := row("D-1.1", "D One One", "D-1", "D One")
	disagree := row("D-1.1", "D One One", "D-2", "D One")
	for _, rows := range [][]string{{agree, disagree}, {disagree, agree}} {
		if _, err := assemble(map[string]*ttpInfo{},
			parse(t, header+strings.Join(rows, ""))); err == nil ||
			!strings.Contains(err.Error(), "disagrees with its id prefix") {
			t.Fatalf("row order %v: err = %v, want a prefix-disagreement error", rows, err)
		}
	}
}

// TestAssembleArtifactLabelFallback: an artifact D3FEND never labels keeps its
// own name as its label, and a label that only the defensive side carries is
// used when the offensive side has none. Both rows are exactly 14 columns, so
// the defensive branch really parses.
func TestAssembleArtifactLabelFallback(t *testing.T) {
	header := "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
		"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
		"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n"

	// Both label cells are empty: nothing to fall back to but the name.
	csv := header + "CM,analyzes,,,accesses,One,," +
		"http://x#CM,http://x#analyzes,http://x#A,http://x#A,http://x#accesses,http://x#T1,\n"
	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	if _, ok := d.artLabel["A"]; ok {
		t.Fatalf("artLabel[A] = %q, want no label at all", d.artLabel["A"])
	}
	m, err := assemble(map[string]*ttpInfo{"T1": {label: "One"}}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(m.artNames) != 1 || m.artNames[0] != "A" {
		t.Fatalf("artNames = %v, want [A]", m.artNames)
	}
	if len(m.artLabels) != 1 || m.artLabels[0] != "A" {
		t.Fatalf("artLabels = %v, want [A] (the name is the fallback label)", m.artLabels)
	}

	// Only the defensive side labels A: the defensive spelling is the fallback,
	// which is only observable if that branch parsed the row.
	csv = header + "CM,analyzes,Defensive Name,,accesses,One,," +
		"http://x#CM,http://x#analyzes,http://x#A,http://x#A,http://x#accesses,http://x#T1,\n"
	d, err = parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	if got := d.artLabel["A"]; got != "Defensive Name" {
		t.Fatalf("artLabel[A] = %q, want the defensive label", got)
	}
	m, err = assemble(map[string]*ttpInfo{"T1": {label: "One"}}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(m.artLabels) != 1 || m.artLabels[0] != "Defensive Name" {
		t.Fatalf("artLabels = %v, want [Defensive Name]", m.artLabels)
	}
}

// TestEmitProducesValidGo exercises the emitter directly (bypassing the shape
// gate) and parses the result, so a formatting or literal bug cannot ship.
func TestEmitProducesValidGo(t *testing.T) {
	m := &model{
		ttpIDs:        []string{"T1003", "T1003.001", "T1004", "T1004.001"},
		ttpLabels:     []string{"OS Credential Dumping", "LSASS Memory", "Winlogon Helper DLL", "Winlogon Helper DLL Sub"},
		ttpAliases:    [][]string{nil, {"A", "B"}, nil, nil},
		ttpDomains:    []domain{domEnterprise, domICS, domMobile, domSPARTA},
		ttpParents:    []int{-1, -1, -1, -1},
		ttpChildCount: []int{0, 0, 0, 0},
		artNames:      []string{"Process"},
		artLabels:     []string{"Process"},
		cmIDs:         []string{"ProcessIsolation"},
		cmLabels:      []string{"Process Isolation"},
		offRelNames:   []string{"accesses"},
		defRelNames:   []string{"analyzes"},
		offT:          []int{1},
		offA:          []int{0},
		offR:          []int{1},
		defC:          []int{0},
		defA:          []int{0},
		defR:          []int{1},
		defendsC:      []int{0},
		defendsT:      []int{1},
	}

	src, err := emit(m)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), "attack_gen.go", src, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v", err)
	}
	for _, want := range []string{
		"//go:build goexperiment.simd",
		"package ontology",
		`import "github.com/fr0g-66723067/gr4ph"`,
		"RelAccesses gr4ph.Rel = 1",
		"DefRelAnalyzes gr4ph.DefRel = 1",
		"uint16(gr4ph.NoParent)",
		"gr4ph.DomainEnterprise",
		"gr4ph.DomainICS",
		"gr4ph.DomainMobile",
		"gr4ph.DomainSPARTA",
		"NTTP            = 4",
		"SourceD3FEND     = \"d3fend-full-mappings.csv@1.6.0\"",
		"{\"A\", \"B\"}",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("generated source is missing %q", want)
		}
	}
	// The child-count table duplicated TTPParents and had no reader; it must not
	// come back.
	if strings.Contains(string(src), "TTPChildCount") {
		t.Error("generated source must not carry the dead TTPChildCount table")
	}
}

// --- label resolution and node derivation ---

// csvHeader is the 14-column header of d3fend-full-mappings.csv@1.6.0, in the
// order the column constants list.
const csvHeader = "def_tech_label,def_artifact_rel_label,def_artifact_label,off_artifact_label," +
	"off_artifact_rel_label,off_tech_label,off_tech_parent_label," +
	"def_tech,def_artifact_rel,def_artifact,off_artifact,off_artifact_rel,off_tech,off_tech_parent\n"

// csvRow joins fields into one CSV record. Column order:
// def_tech_label, def_artifact_rel_label, def_artifact_label, off_artifact_label,
// off_artifact_rel_label, off_tech_label, off_tech_parent_label, def_tech,
// def_artifact_rel, def_artifact, off_artifact, off_artifact_rel, off_tech,
// off_tech_parent.
func csvRow(fields ...string) string { return strings.Join(fields, ",") + "\n" }

// TestParseD3FENDLabelOrder pins the order-independence of label resolution: an
// artifact that appears on both sides must resolve to the same label whichever
// row the CSV lists first.
func TestParseD3FENDLabelOrder(t *testing.T) {
	defensive := csvRow("CM", "analyzes", "Defensive Name", "", "", "", "",
		"http://x#CM", "http://x#analyzes", "http://x#A", "", "", "", "")
	// The offensive row carries no label of its own, so the defensive spelling
	// is the only candidate; with a label, the offensive spelling must win.
	offensiveUnlabelled := csvRow("", "", "", "", "", "One", "",
		"", "", "", "http://x#A", "http://x#accesses", "http://x#T1", "")
	offensiveLabelled := csvRow("", "", "", "Offensive Name", "", "One", "",
		"", "", "", "http://x#A", "http://x#accesses", "http://x#T1", "")

	for _, tc := range []struct {
		name string
		rows []string
		want string
	}{
		{"defensive first, no offensive label", []string{defensive, offensiveUnlabelled}, "Defensive Name"},
		{"offensive first, no offensive label", []string{offensiveUnlabelled, defensive}, "Defensive Name"},
		{"defensive first, offensive label", []string{defensive, offensiveLabelled}, "Offensive Name"},
		{"offensive first, offensive label", []string{offensiveLabelled, defensive}, "Offensive Name"},
	} {
		d, err := parseD3FEND([]byte(csvHeader + strings.Join(tc.rows, "")))
		if err != nil {
			t.Fatalf("%s: parseD3FEND: %v", tc.name, err)
		}
		if got := d.artLabel["A"]; got != tc.want {
			t.Fatalf("%s: artLabel[A] = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestParseD3FENDUnlabelledEndpoint pins the symmetric node rule: an edge
// endpoint whose own label cell is empty still becomes a node, named by its id
// (the same fallback artifacts get), instead of aborting the run.
func TestParseD3FENDUnlabelledEndpoint(t *testing.T) {
	// off_tech_label and def_tech_label are both empty.
	csv := csvHeader + csvRow("", "analyzes", "A Label", "A Label", "accesses", "", "",
		"http://x#CM", "http://x#analyzes", "http://x#A", "http://x#A", "http://x#accesses", "http://x#T1", "")

	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	if got := pickLabel(d.ttpLabel["T1"]); got != "T1" {
		t.Fatalf("ttpLabel[T1] = %q, want T1 (the id stands in for the missing label)", got)
	}
	if got := d.cmLabel["CM"]; got != "CM" {
		t.Fatalf("cmLabel[CM] = %q, want CM", got)
	}
	m, err := assemble(map[string]*ttpInfo{}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(m.ttpIDs) != 1 || m.ttpIDs[0] != "T1" {
		t.Fatalf("ttpIDs = %v, want [T1] (A is an artifact, not a technique)", m.ttpIDs)
	}
	if len(m.ttpLabels) != 1 || m.ttpLabels[0] != "T1" {
		t.Fatalf("ttpLabels = %v, want [T1]", m.ttpLabels)
	}
	if len(m.cmIDs) != 1 || m.cmIDs[0] != "CM" || m.cmLabels[0] != "CM" {
		t.Fatalf("cmIDs/labels = %v/%v, want [CM]/[CM]", m.cmIDs, m.cmLabels)
	}
}

// TestParseD3FENDDefensiveOnlyArtifact pins the symmetric artifact rule: an
// artifact that appears only on the defensive side, with no def_artifact_label
// cell of its own, still becomes a node named by its id. Without that, the
// defensive edge aborts with an unknown-artifact error.
func TestParseD3FENDDefensiveOnlyArtifact(t *testing.T) {
	csv := csvHeader + csvRow("CM", "analyzes", "", "", "", "One", "",
		"http://x#CM", "http://x#analyzes", "http://x#A", "", "", "http://x#T1", "")

	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	if !d.artDef["A"] {
		t.Fatal("A must be marked defensive")
	}
	if _, ok := d.artOff["A"]; ok {
		t.Fatal("A is defensive-only and must not be marked offensive")
	}
	if _, ok := d.artLabel["A"]; ok {
		t.Fatalf("artLabel[A] = %q, want no label (both label cells are empty)", d.artLabel["A"])
	}

	// The row's off_tech cell only infers defends-against, so T1 comes from
	// ATT&CK; A comes from the defensive side alone.
	m, err := assemble(map[string]*ttpInfo{"T1": {label: "One"}}, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(m.artNames) != 1 || m.artNames[0] != "A" {
		t.Fatalf("artNames = %v, want [A]", m.artNames)
	}
	if len(m.artLabels) != 1 || m.artLabels[0] != "A" {
		t.Fatalf("artLabels = %v, want [A] (the id fallback)", m.artLabels)
	}
	if len(m.defC) != 1 || len(m.defA) != 1 || len(m.defR) != 1 || m.defA[0] != 0 {
		t.Fatalf("defensive edges = %v/%v/%v, want one edge onto artifact 0", m.defC, m.defA, m.defR)
	}
	if len(m.defendsC) != 1 || len(m.defendsT) != 1 {
		t.Fatalf("defends-against pairs = %v/%v, want one", m.defendsC, m.defendsT)
	}
}

// TestAssembleParentPrecedence pins which hierarchy source wins. Where the id
// prefix is a node, it is the parent and D3FEND's off_tech_parent is ignored
// (real case: T1499.002 carries off_tech_parent T1498 in 1.6.0 while ATT&CK makes
// it a child of T1499). Where the prefix is no node, off_tech_parent is the only
// source and must agree with the prefix.
func TestAssembleParentPrecedence(t *testing.T) {
	// T1.1's prefix T1 is a node, and the CSV names a different parent: the tree
	// must follow the prefix.
	agreeing := csvRow("", "", "", "", "", "One One", "Two", "",
		"", "", "http://x#A1", "http://x#accesses", "http://x#T1.1", "http://x#T2")
	d, err := parseD3FEND([]byte(testCSV + agreeing))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	stix := map[string]*ttpInfo{
		"T1":   {label: "One"},
		"T1.1": {label: "One One", sub: true},
		"T2":   {label: "Two"},
	}
	m, err := assemble(stix, d)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	i := indexOf(m.ttpIDs, "T1.1")
	if i < 0 {
		t.Fatalf("T1.1 missing from %v", m.ttpIDs)
	}
	if got := m.ttpParents[i]; got != indexOf(m.ttpIDs, "T1") {
		t.Fatalf("TTPParents[T1.1] = %d, want the prefix parent T1 (%d)", got, indexOf(m.ttpIDs, "T1"))
	}

	// A synthesised parent is the only source of the hierarchy, so a
	// contradictory off_tech_parent is an error.
	bad := csvRow("", "", "", "", "", "D One One", "Other", "",
		"", "", "http://x#A1", "http://x#accesses", "http://x#D-1.1", "http://x#D-2")
	badD, err := parseD3FEND([]byte(csvHeader + bad))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	if _, err := assemble(map[string]*ttpInfo{}, badD); err == nil ||
		!strings.Contains(err.Error(), "disagrees with its id prefix") {
		t.Fatalf("synthesised-parent err = %v, want a prefix-disagreement error", err)
	}
}

// indexOf returns the position of s in ids, or -1.
func indexOf(ids []string, s string) int {
	for i, id := range ids {
		if id == s {
			return i
		}
	}
	return -1
}

// TestAssembleSubtechniqueFlagMismatch pins the hierarchy agreement checks: the
// id prefix must agree with x_mitre_is_subtechnique, and a dotted id must have a
// parent node.
func TestAssembleSubtechniqueFlagMismatch(t *testing.T) {
	csv := csvHeader + csvRow("", "", "A", "A", "accesses", "One One", "One", "",
		"", "", "http://x#A", "http://x#accesses", "http://x#T1.1", "http://x#T1")
	d, err := parseD3FEND([]byte(csv))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}

	// A dotted id whose flag is false.
	stix := map[string]*ttpInfo{"T1": {label: "One"}, "T1.1": {label: "One One"}}
	if _, err := assemble(stix, d); err == nil || !strings.Contains(err.Error(), "x_mitre_is_subtechnique") {
		t.Fatalf("dot without the flag: err = %v, want a flag-disagreement error", err)
	}

	// A dotless id whose flag is true.
	stix = map[string]*ttpInfo{"T1": {label: "One", sub: true}}
	if _, err := assemble(stix, d); err == nil || !strings.Contains(err.Error(), "x_mitre_is_subtechnique") {
		t.Fatalf("flag without a dot: err = %v, want a flag-disagreement error", err)
	}

	// A dotted id that is in no D3FEND row and whose prefix is no node at all:
	// nothing synthesises the parent, so the tree would have an orphan.
	orphanCSV := csvHeader + csvRow("", "", "A", "A", "accesses", "Two", "", "",
		"", "", "http://x#A", "http://x#accesses", "http://x#T2", "")
	orphanD, err := parseD3FEND([]byte(orphanCSV))
	if err != nil {
		t.Fatalf("parseD3FEND: %v", err)
	}
	stix = map[string]*ttpInfo{"T1.1": {label: "One One", sub: true}}
	if _, err := assemble(stix, orphanD); err == nil || !strings.Contains(err.Error(), "orphan") {
		t.Fatalf("orphan: err = %v, want an orphan error", err)
	}
}

// TestCheckShapeCaps pins the generator-side limits: a graph whose relation or
// node count cannot be represented in the emitted tables must fail before emit.
func TestCheckShapeCaps(t *testing.T) {
	m := &model{offRelNames: make([]string, maxPlanes+1)}
	if err := m.checkShape(shape{}); err == nil || !strings.Contains(err.Error(), "relation planes exceed") {
		t.Fatalf("plane cap err = %v, want a plane-space error", err)
	}

	m = &model{ttpIDs: make([]string, maxNodes+1)}
	if err := m.checkShape(shape{}); err == nil || !strings.Contains(err.Error(), "node count exceeds") {
		t.Fatalf("node cap err = %v, want a node-count error", err)
	}
}

// TestParseAttackUpgradeCarriesDomain: a live twin in another domain replaces the
// whole record, so the label and the domain always come from the same object.
func TestParseAttackUpgradeCarriesDomain(t *testing.T) {
	out := map[string]*ttpInfo{}
	revoked := []byte(`{"objects":[{"type":"attack-pattern","name":"Revoked Name","revoked":true,
	  "external_references":[{"source_name":"mitre-attack","external_id":"T9"}]}]}`)
	if err := parseAttack(revoked, domICS, out); err != nil {
		t.Fatalf("parseAttack: %v", err)
	}
	live := []byte(`{"objects":[{"type":"attack-pattern","name":"Live Name",
	  "external_references":[{"source_name":"mitre-attack","external_id":"T9"}]}]}`)
	if err := parseAttack(live, domMobile, out); err != nil {
		t.Fatalf("parseAttack: %v", err)
	}
	got := out["T9"]
	if got.label != "Live Name" {
		t.Fatalf("label = %q, want Live Name", got.label)
	}
	if got.domain != domMobile {
		t.Fatalf("domain = %v, want the live object's domain (%v)", got.domain, domMobile)
	}
}
