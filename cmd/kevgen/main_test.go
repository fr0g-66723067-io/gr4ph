package main

import (
	"bytes"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// testKEV is the offline fixture: four entries in a deliberately unsorted order,
// one with a duplicated and unsorted CWE list, one naming a class twice under
// two spellings ("CWE-79" and "cwe-79"), one with no CWE at all, one ransomware
// entry, surrounding whitespace on a name and a vendor, and two entries whose
// product pairs differ only in case.
const testKEV = `{
  "catalogVersion": "2099.01.01",
  "vulnerabilities": [
    {"cveID": "CVE-2099-0003", "vendorProject": "Zvendor", "product": "Zed",
     "vulnerabilityName": "Zed Flaw", "dateAdded": "2099-01-03",
     "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-79", "cwe-79"]},
    {"cveID": "CVE-2099-0001", "vendorProject": "  Avendor  ", "product": "Alpha",
     "vulnerabilityName": " Alpha Flaw ", "dateAdded": "2099-01-01",
     "knownRansomwareCampaignUse": "Known", "cwes": ["CWE-502", "CWE-20", "CWE-20"]},
    {"cveID": "CVE-2099-0002", "vendorProject": "bvendor", "product": "beta",
     "vulnerabilityName": "Beta Flaw", "dateAdded": "2099-01-02",
     "knownRansomwareCampaignUse": "Unknown", "cwes": []},
    {"cveID": "CVE-2099-0004", "vendorProject": "Bvendor", "product": "Beta",
     "vulnerabilityName": "Beta Flaw Again", "dateAdded": "2099-01-04",
     "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-79"]}
  ]
}`

// testShape is the fixture's own measurement, not the pinned release's.
var testShape = shape{
	catalog: "2099.01.01",
	entries: 4, cweEdges: 4, entriesWithCWE: 3, cwes: 3, products: 3, ransomware: 1,
}

// TestParseSortsAndTrims pins the parsing rules: entries sorted by CVE id, the
// two vocabularies keyed and deduped the way the builder keys them (trimmed and
// lower-cased, one element per node), one pair per distinct weakness reference,
// one product index per entry, and the surrounding whitespace trimmed (the
// engine's key normalization trims, so a stored label must not keep it).
func TestParseSortsAndTrims(t *testing.T) {
	m, err := parse([]byte(testKEV))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if m.catalog != "2099.01.01" {
		t.Errorf("catalog = %q", m.catalog)
	}
	if got := strings.Join(m.kevIDs, ","); got != "CVE-2099-0001,CVE-2099-0002,CVE-2099-0003,CVE-2099-0004" {
		t.Errorf("kevIDs = %s, want the sorted order", got)
	}
	if got := strings.Join(m.kevNames, "|"); got != "Alpha Flaw|Beta Flaw|Zed Flaw|Beta Flaw Again" {
		t.Errorf("kevNames = %q, want trimmed names in id order", got)
	}
	if got := strings.Join(m.kevAdded, ","); got != "2099-01-01,2099-01-02,2099-01-03,2099-01-04" {
		t.Errorf("kevAdded = %s", got)
	}
	if !m.kevRansom[0] || m.kevRansom[1] || m.kevRansom[2] || m.kevRansom[3] {
		t.Errorf("kevRansom = %v, want only the Known entry", m.kevRansom)
	}
	// One element per normalized key, holding the byte-smallest spelling of it:
	// entry 2 names CWE-79 twice under two spellings, and the key it resolves to
	// is one node in the builder, so the vocabulary is three elements and not
	// four (a fourth would shift every index after it).
	if got := strings.Join(m.cweIDs, ","); got != "CWE-20,CWE-502,CWE-79" {
		t.Errorf("cweIDs = %s, want one element per normalized key", got)
	}
	// The duplicated CWE-20 of entry 0 collapses to one pair, and the pairs stay
	// sorted by (entry, cwe).
	if got := toInts(m.weakKEV); got != "0,0,2,3" {
		t.Errorf("weakKEV = %s, want 0,0,2,3", got)
	}
	if got := toInts(m.weakCWE); got != "0,1,2,2" {
		t.Errorf("weakCWE = %s, want 0,1,2,2", got)
	}
	if got := strings.Join(m.productVendors, ","); got != "Avendor,Bvendor,Zvendor" {
		t.Errorf("productVendors = %s, want (vendor, product) order", got)
	}
	if got := strings.Join(m.productNames, ","); got != "Alpha,Beta,Zed" {
		t.Errorf("productNames = %s", got)
	}
	// The fourth entry's pair ("Bvendor", "Beta") is the key of the third's
	// ("bvendor", "beta"), so both map to the same product: one node, two edges.
	if got := toInts(m.kevProduct); got != "0,1,2,1" {
		t.Errorf("kevProduct = %s, want one dense product index per entry", got)
	}
	if got := m.shape(); got != testShape {
		t.Errorf("shape = %+v, want %+v", got, testShape)
	}
}

// TestRunEndToEnd drives the offline pipeline on the fixture: load -> parse ->
// shape gate -> emit -> write, and pins the generated source and the summary the
// generator prints.
func TestRunEndToEnd(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kev.json")
	if err := os.WriteFile(src, []byte(testKEV), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(dir, "out", "kev_gen.go")
	var buf bytes.Buffer
	if err := run(src, out, &buf, testShape, false); err != nil {
		t.Fatalf("run: %v", err)
	}
	generated, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("output file: %v", err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), out, generated, parser.AllErrors); err != nil {
		t.Fatalf("generated source does not parse: %v", err)
	}
	text := string(generated)

	// gofmt aligns the `=` inside a const block, so match values with regexps.
	for _, want := range []*regexp.Regexp{
		regexp.MustCompile(`\bNKEV\s+= 4\b`),
		regexp.MustCompile(`\bNKEVCWE\s+= 4\b`),
		regexp.MustCompile(`\bNKEVWithCWE\s+= 3\b`),
		regexp.MustCompile(`\bNCWE\s+= 3\b`),
		regexp.MustCompile(`\bNProduct\s+= 3\b`),
		regexp.MustCompile(`\bNKEVRansomware\s+= 1\b`),
	} {
		if !want.Match(generated) {
			t.Errorf("generated source does not match %s", want)
		}
	}
	for _, want := range []string{
		"//go:build goexperiment.simd",
		"// Code generated by cmd/kevgen. DO NOT EDIT.",
		"// Source: CISA Known Exploited Vulnerabilities catalog 2099.01.01.",
		"package ontology",
		`const SourceKEV = "known_exploited_vulnerabilities.json@2099.01.01"`,
		`"CVE-2099-0001",`,
		`"CVE-2099-0004",`,
		`"Alpha Flaw",`,
		`"Beta Flaw Again",`,
		`"2099-01-02",`,
		"var KEVRansomware = [...]bool{",
		"var KEVProductIndex = [...]uint16{",
		"var KEVWeaknessKEV = [...]uint16{",
		"var KEVWeaknessCWE = [...]uint16{",
		`"Avendor",`,
		"var KEVProductNames = [...]string{",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated source is missing %q", want)
		}
	}
	// The two weakness arrays are parallel and neither is nested.
	weakKEV := tableBody(t, text, "KEVWeaknessKEV")
	if weakKEV != "0, 0, 2, 3," {
		t.Errorf("KEVWeaknessKEV = %q, want the parallel entry indices", weakKEV)
	}
	if got := tableBody(t, text, "KEVWeaknessCWE"); got != "0, 1, 2, 2," {
		t.Errorf("KEVWeaknessCWE = %q, want the parallel CWE indices", got)
	}
	if got := tableBody(t, text, "KEVProductIndex"); got != "0, 1, 2, 1," {
		t.Errorf("KEVProductIndex = %q, want one index per entry", got)
	}
	if strings.Contains(text, "nil") || strings.Contains(text, "import") {
		t.Errorf("the generated tables must be nil-free and import-free:\n%s", text)
	}
	// The id order in the file is the sorted order, not the feed's.
	if strings.Index(text, `"CVE-2099-0001",`) > strings.Index(text, `"CVE-2099-0002",`) {
		t.Error("KEVIDs is not in sorted order")
	}

	wantSummary := "kevgen: wrote " + out + "\n" +
		"  catalog        known_exploited_vulnerabilities.json@2099.01.01\n" +
		"  entries        4 (1 ransomware)\n" +
		"  weaknesses     4 references over 3 CWEs, 3 entries with at least one\n" +
		"  products       3 (one per entry)\n"
	if got := buf.String(); got != wantSummary {
		t.Fatalf("summary mismatch\n--- got ---\n%s--- want ---\n%s", got, wantSummary)
	}
}

// TestRunShapeDrift pins the count gate: a catalog whose counts differ from the
// pins fails with the drift message and leaves no output file behind.
func TestRunShapeDrift(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kev.json")
	if err := os.WriteFile(src, []byte(testKEV), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(dir, "kev_gen.go")

	drifted := testShape
	drifted.cwes = 4
	var buf bytes.Buffer
	err := run(src, out, &buf, drifted, false)
	if err == nil {
		t.Fatal("run accepted a drifted shape")
	}
	if want := "KEV 2099.01.01 shape drift: CWEs 4 -> 3 (the catalog was revised without a version bump; re-pin deliberately)"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("a failed run must not write %s", out)
	}
}

// TestRunStaleCatalog pins the two version-mismatch paths: a hard error when
// re-pinning is off, so nothing is ever rewritten by accident.
func TestRunStaleCatalog(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kev.json")
	if err := os.WriteFile(src, []byte(testKEV), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	stale := testShape
	stale.catalog = "2098.12.31"
	var buf bytes.Buffer
	err := run(src, filepath.Join(dir, "kev_gen.go"), &buf, stale, false)
	if err == nil {
		t.Fatal("run accepted a stale catalog with -re-pin=false")
	}
	if want := "KEV catalog 2098.12.31 expected, got 2099.01.01 (re-run without -re-pin to re-pin in place)"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
	if buf.Len() != 0 {
		t.Errorf("a hard error must print nothing, got %q", buf.String())
	}
}

// TestRunRepins drives run's re-pin branch — the one path no test could drive
// without rewriting this repository's own source. It points repinTarget at a
// copy of the generator, runs a stale catalog with re-pinning on and pins the
// branch's whole effect: the two literals rewritten to the measurement just
// taken, the re-pin line ahead of the summary, the exit status 0 (the branch
// resets the gate to the measurement, so checkShape accepts what it wrote) and
// the emitted file.
func TestRunRepins(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "kev.json")
	if err := os.WriteFile(src, []byte(testKEV), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	out := filepath.Join(dir, "kev_gen.go")

	self, err := repinTarget()
	if err != nil {
		t.Fatalf("repinTarget: %v", err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read generator: %v", err)
	}
	copyPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(copyPath, raw, 0o644); err != nil {
		t.Fatalf("write copy: %v", err)
	}
	original := repinTarget
	repinTarget = func() (string, error) { return copyPath, nil }
	t.Cleanup(func() { repinTarget = original })

	stale := testShape
	stale.catalog = "2098.12.31"
	// The stale pin also carries a count the measurement contradicts, as a real
	// re-pin does: without the branch's `want = measured` reset checkShape would
	// reject the very counts the re-pin just wrote.
	stale.cwes = 4
	var buf bytes.Buffer
	if err := run(src, out, &buf, stale, true); err != nil {
		t.Fatalf("run with a stale catalog and re-pinning on: %v", err)
	}

	rewritten, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("read rewritten copy: %v", err)
	}
	if want := `sourceKEV = "` + sourceFile() + `@` + testShape.catalog + `"`; !strings.Contains(string(rewritten), want) {
		t.Errorf("the re-pin did not rewrite sourceKEV to the measured catalog, want %q in\n%s", want, rewritten)
	}
	if want := renderShape(testShape); !strings.Contains(string(rewritten), want) {
		t.Errorf("the re-pin did not rewrite pinnedShape to the measured counts, want %q", want)
	}
	if strings.Contains(string(rewritten), stale.catalog) {
		t.Error("the stale catalog version is still in the rewritten copy")
	}

	wantRepin := "kevgen: re-pinned " + sourceFile() + "@" + stale.catalog + " -> @" + testShape.catalog +
		" (re-measure the count pins in ontology/ontology_test.go and cmd/gr4ph/main_test.go, and the README's numbers by hand)\n"
	if got := buf.String(); !strings.HasPrefix(got, wantRepin+"kevgen: wrote "+out+"\n") {
		t.Errorf("output does not start with the re-pin line then the summary\n--- got ---\n%s--- want ---\n%s", got, wantRepin)
	}
	if _, err := os.Stat(out); err != nil {
		t.Errorf("the re-pinned run still emits its output file: %v", err)
	}
}

// TestRepinPath rewrites a copy of this generator's own source and pins what
// changed: the two literals, and nothing else.
func TestRepinPath(t *testing.T) {
	self, err := generatorPath()
	if err != nil {
		t.Fatalf("generatorPath: %v", err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatalf("read generator: %v", err)
	}
	path := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write copy: %v", err)
	}

	moved := shape{
		catalog: "2099.06.30",
		entries: 2048, cweEdges: 1900, entriesWithCWE: 1800, cwes: 200, products: 800, ransomware: 400,
	}
	if err := repinPath(moved, path); err != nil {
		t.Fatalf("repinPath: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rewritten source: %v", err)
	}
	if _, err := parser.ParseFile(token.NewFileSet(), path, got, parser.AllErrors); err != nil {
		t.Fatalf("rewritten source does not parse: %v", err)
	}
	wantSource := `sourceKEV = "` + sourceFile() + `@2099.06.30`
	if !strings.Contains(string(got), wantSource) {
		t.Errorf("the sourceKEV literal was not re-pinned:\n%s", string(got))
	}
	if want := renderShape(moved); !strings.Contains(string(got), want) {
		t.Errorf("the pinnedShape literal was not re-pinned, want %q", want)
	}
	if strings.Contains(string(got), pinnedShape.catalog) {
		t.Error("the old catalog version is still in the rewritten source")
	}
	// Everything else survives: the constants, the doc comment and the code.
	for _, want := range []string{"defaultKEV", "const maxNodes = 65536", "func main()", "func emit("} {
		if !strings.Contains(string(got), want) {
			t.Errorf("the rewrite dropped %q", want)
		}
	}

	// A file without the markers is reported, not silently accepted, and a file
	// whose marker occurs twice is refused rather than rewritten at the wrong
	// occurrence.
	for _, tt := range []struct {
		name string
		src  string
		want string
	}{
		{"no sourceKEV", "package main\nvar pinnedShape = shape{\n\tcatalog: \"x\",\n}\n", "not found"},
		{"no pinnedShape", "package main\n\nconst sourceKEV = \"" + sourceFile() + "@x\"\n", "not found"},
		{
			"two sourceKEV markers",
			"package main\n\n// sourceKEV = \"a comment that carries the marker\"\nconst sourceKEV = \"" +
				sourceFile() + "@x\"\n\nvar pinnedShape = shape{\n\tcatalog: \"x\",\n}\n",
			"2 occurrences",
		},
		{
			"two pinnedShape markers",
			"package main\n\nconst sourceKEV = \"" + sourceFile() + "@x\"\n\n// var pinnedShape = shape{\nvar pinnedShape = shape{\n\tcatalog: \"x\",\n}\n",
			"2 occurrences",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "main.go")
			if err := os.WriteFile(p, []byte(tt.src), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			err := repinPath(moved, p)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("repinPath = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

// TestParseRejects pins the input invariants: an empty catalog, a missing
// version, a missing cveID, an empty vendor or product and a duplicate id.
func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"no version", `{"vulnerabilities":[{"cveID":"CVE-1","vendorProject":"V","product":"P"}]}`, "catalogVersion is empty"},
		{"no entries", `{"catalogVersion":"1","vulnerabilities":[]}`, "no vulnerabilities"},
		{"no cveID", `{"catalogVersion":"1","vulnerabilities":[{"vendorProject":"V","product":"P"}]}`, "has no cveID"},
		{"no product", `{"catalogVersion":"1","vulnerabilities":[{"cveID":"CVE-1","vendorProject":"V"}]}`, "empty vendor or product"},
		{
			"duplicate id",
			`{"catalogVersion":"1","vulnerabilities":[
			  {"cveID":"CVE-1","vendorProject":"V","product":"P"},
			  {"cveID":"CVE-1","vendorProject":"W","product":"Q"}]}`,
			"duplicate cveID CVE-1",
		},
		{
			// The builder registers one node per normalized key, so two
			// spellings of one CVE are a duplicate here, not two entries.
			"case-variant duplicate id",
			`{"catalogVersion":"1","vulnerabilities":[
			  {"cveID":"CVE-1","vendorProject":"V","product":"P"},
			  {"cveID":"cve-1","vendorProject":"W","product":"Q"}]}`,
			"duplicate cveID cve-1",
		},
		{"malformed", `{`, "parse json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parse([]byte(tt.json))
			if err == nil {
				t.Fatalf("parse accepted %s", tt.json)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error = %q, want it to contain %q", err, tt.want)
			}
		})
	}
}

// TestLoadErrors pins the file branch: a missing path is an error, not an empty
// catalog.
func TestLoadErrors(t *testing.T) {
	if _, err := load(filepath.Join(t.TempDir(), "missing.json")); err == nil || !strings.Contains(err.Error(), "read") {
		t.Errorf("load(missing) = %v, want a read error", err)
	}
}

// TestPinnedShapeIsTheCatalogShape pins the version agreement of the two
// literals and the internal consistency of the counts: a literal that cannot
// describe any catalog is caught here. The counts themselves are crossed against
// the feed by run's checkShape, and after a re-pin by the count pins in
// ontology/ontology_test.go and cmd/gr4ph/main_test.go.
func TestPinnedShapeIsTheCatalogShape(t *testing.T) {
	if sourceKEV != sourceFile()+"@"+pinnedShape.catalog {
		t.Fatalf("sourceKEV %q and pinnedShape.catalog %q disagree", sourceKEV, pinnedShape.catalog)
	}
	if pinnedShape.entriesWithCWE > pinnedShape.entries || pinnedShape.cweEdges < pinnedShape.entriesWithCWE ||
		pinnedShape.ransomware > pinnedShape.entries || pinnedShape.products > pinnedShape.entries {
		t.Fatalf("pinnedShape is internally inconsistent: %+v", pinnedShape)
	}
}

func toInts(vals []int) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(v))
	}
	return strings.Join(parts, ",")
}

// tableBody returns the comma-joined entries inside a generated table literal.
func tableBody(t *testing.T, src, name string) string {
	t.Helper()
	i := strings.Index(src, "var "+name+" = ")
	if i < 0 {
		t.Fatalf("table %s not found", name)
	}
	rest := src[i:]
	open := strings.Index(rest, "{\n")
	close := strings.Index(rest, "\n}")
	if open < 0 || close < 0 || close < open {
		t.Fatalf("table %s is malformed", name)
	}
	body := rest[open+2 : close]
	fields := strings.Fields(strings.ReplaceAll(body, "\n", " "))
	return strings.Join(fields, " ")
}
