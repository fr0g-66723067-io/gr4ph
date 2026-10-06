package main

import (
	"go/parser"
	"go/token"
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
	if got := d.parentOf["T1003.005"]; got != "T1003" {
		t.Fatalf("parentOf = %q, want T1003", got)
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
		cmLabel:     map[string]string{},
		offRel:      map[string]bool{},
		defRel:      map[string]bool{},
		offEdge:     map[[3]string]bool{},
		defEdge:     map[[3]string]bool{},
		defends:     map[[2]string]bool{},
		parentOf:    map[string]string{},
		parentLabel: map[string]string{},
	}

	deep := map[string]*ttpInfo{
		"T1":     {label: "one"},
		"T1.1":   {label: "one-one"},
		"T1.1.1": {label: "three levels"},
	}
	if _, err := assemble(deep, empty); err == nil || !strings.Contains(err.Error(), "deeper than two levels") {
		t.Fatalf("err = %v, want a depth error", err)
	}

	// "T1-9" sorts between the parent "T1" and its child "T1.2", so the child
	// block is no longer contiguous.
	gap := map[string]*ttpInfo{
		"T1":   {label: "one"},
		"T1-9": {label: "intruder"},
		"T1.2": {label: "one-two"},
	}
	if _, err := assemble(gap, empty); err == nil || !strings.Contains(err.Error(), "child block") {
		t.Fatalf("err = %v, want a contiguity error", err)
	}
}

// TestAssembleShapeDrift: a graph that is structurally fine but does not match
// the pinned release must fail rather than emit mismatched indices.
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
		parentOf:    map[string]string{},
		parentLabel: map[string]string{},
	}
	_, err := assemble(map[string]*ttpInfo{}, d)
	if err == nil || !strings.Contains(err.Error(), "shape drift") {
		t.Fatalf("err = %v, want a shape-drift error", err)
	}
}

// TestEmitProducesValidGo exercises the emitter directly (bypassing the shape
// gate) and parses the result, so a formatting or literal bug cannot ship.
func TestEmitProducesValidGo(t *testing.T) {
	m := &model{
		ttpIDs:        []string{"T1003", "T1003.001"},
		ttpLabels:     []string{"OS Credential Dumping", "LSASS Memory"},
		ttpAliases:    [][]string{nil, {"Lsass Memory Alias"}},
		ttpDomains:    []domain{domEnterprise, domSPARTA},
		ttpParents:    []int{-1, 0},
		ttpChildCount: []int{1, 0},
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
		"gr4ph.DomainSPARTA",
		"NTTP            = 2",
		"SourceD3FEND     = \"d3fend-full-mappings.csv@1.6.0\"",
		"{\"Lsass Memory Alias\"}",
	} {
		if !strings.Contains(string(src), want) {
			t.Errorf("generated source is missing %q", want)
		}
	}
}
