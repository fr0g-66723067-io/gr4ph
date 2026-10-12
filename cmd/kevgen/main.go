// Command kevgen generates ontology/kev_gen.go: the frozen cold-path tables of
// the CISA Known Exploited Vulnerabilities catalog — one entry per CVE, the
// weakness vocabulary its CWE references name, and the product vocabulary its
// vendor/product pairs name.
//
// It is deliberately untagged (no goexperiment.simd) and imports nothing from
// this module, so the tables can be regenerated on a stock toolchain; the file
// it writes is tagged and lives in the ontology package.
//
// KEV is a rolling feed: CISA revises the catalog and bumps catalogVersion.
// When the fetched version differs from the pinned one this generator re-pins
// its own sourceKEV and pinnedShape literals in place, emits with the freshly
// measured counts and prints the one line that says so — the count pins in
// ontology/ontology_test.go, cmd/gr4ph/main_test.go and README.md then fail
// until they are re-measured, which is the forcing function. `-re-pin=false`
// turns that into a hard error instead, and a count change under an unchanged
// version is always an error: the version is the contract, the counts are the
// measurement that keeps the emitted tables honest.
//
// Two ingestion rules keep the emitted dense ids equal to the ones the builder
// assigns: entries are sorted by CVE id (the feed's own order is neither sorted
// nor stable) and every ingested string is trimmed of surrounding whitespace
// (the feed carries it on 27 names, 6 vendors and 13 products; the seven
// product pairs that collapse under trimming are why the pinned product count is
// 725 rather than the 732 raw pairs).
//
//	go run ./cmd/kevgen -out ontology/kev_gen.go
//	go run ./cmd/kevgen -kev /tmp/kev.json -out /tmp/kev_gen.go
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	defaultKEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// sourceKEV is the pinned release the emitted SourceKEV constant names: the
	// upstream file name and its catalogVersion, so the output is byte-identical
	// whether the input came from the URL or from a local file. A different
	// release cannot slip through unnoticed — the shape assertions below are
	// calibrated to exactly this version.
	sourceKEV = "known_exploited_vulnerabilities.json@2026.10.08"
)

// sourceFile is the upstream file name sourceKEV pins a release of.
func sourceFile() string {
	name, _, _ := strings.Cut(sourceKEV, "@")
	return name
}

// maxNodes mirrors gr4ph.MaxNodes (the uint16 id space) without importing this
// module: this package stays dependency-free, like cmd/d3fendgen.
const maxNodes = 65536

// shape is the measured shape of the pinned catalog. kevgen re-pins these
// literals in place when the feed's catalogVersion moves, and fails on a count
// change under an unchanged version.
type shape struct {
	catalog                  string
	entries                  int
	cweEdges, entriesWithCWE int
	cwes                     int
	products                 int
	ransomware               int
}

// products is 725, not the 732 *raw* (vendor, product) pairs the feed carries:
// seven pairs differ only in surrounding whitespace ("Microsoft"/"Windows " and
// "Microsoft"/"Windows", 174 entries; six more like it), and the builder indexes
// a product by its trimmed key, so the raw form would make the generator's 732
// indices disagree with the 725 nodes the builder assigns.
var pinnedShape = shape{
	catalog: "2026.10.08",
	entries: 1739, cweEdges: 1679, entriesWithCWE: 1564, cwes: 189, products: 725, ransomware: 361,
}

func main() {
	kevSrc := flag.String("kev", defaultKEV, "CISA KEV catalog JSON (URL or file path)")
	out := flag.String("out", filepath.Join("ontology", "kev_gen.go"), "output Go file")
	rePin := flag.Bool("re-pin", true, "re-pin this generator's literals in place when catalogVersion moves")
	flag.Parse()

	if err := run(*kevSrc, *out, os.Stdout, pinnedShape, *rePin); err != nil {
		fmt.Fprintln(os.Stderr, "kevgen:", err)
		os.Exit(1)
	}
}

// run loads the catalog, parses and sorts it, gates its shape against want (or
// re-pins want itself when the version moved and repin is set), writes the
// generated file and reports the measured shape to w.
func run(kevSrc, out string, w io.Writer, want shape, repin bool) error {
	data, err := load(kevSrc)
	if err != nil {
		return err
	}
	m, err := parse(data)
	if err != nil {
		return fmt.Errorf("%s: %w", kevSrc, err)
	}
	measured := m.shape()

	switch {
	case measured.catalog != want.catalog && !repin:
		return fmt.Errorf("KEV catalog %s expected, got %s (re-run without -re-pin to re-pin in place)",
			want.catalog, measured.catalog)
	case measured.catalog != want.catalog:
		if err := repinFile(measured); err != nil {
			return err
		}
		fmt.Fprintf(w, "kevgen: re-pinned %s@%s -> @%s (re-measure the count pins in ontology/ontology_test.go, cmd/gr4ph/main_test.go and README.md)\n",
			sourceFile(), want.catalog, measured.catalog)
		// The literals just became the measurement, so there is nothing left to
		// compare the counts against: the suite's own pins are the gate.
		want = measured
	}

	if err := m.checkShape(want); err != nil {
		return err
	}

	file, err := emit(m)
	if err != nil {
		return err
	}
	if dir := filepath.Dir(out); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	if err := os.WriteFile(out, file, 0o644); err != nil {
		return err
	}

	fmt.Fprintf(w, "kevgen: wrote %s\n", out)
	fmt.Fprintf(w, "  catalog        %s@%s\n", sourceFile(), m.catalog)
	fmt.Fprintf(w, "  entries        %d (%d ransomware)\n", len(m.kevIDs), m.ransomwareCount())
	fmt.Fprintf(w, "  weaknesses     %d references over %d CWEs, %d entries with at least one\n",
		len(m.weakKEV), len(m.cweIDs), m.entriesWithCWE())
	fmt.Fprintf(w, "  products       %d (one per entry)\n", len(m.productVendors))
	return nil
}

// load reads src from disk, or over HTTP when it looks like a URL.
func load(src string) ([]byte, error) {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(src)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", src, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("fetch %s: %s", src, resp.Status)
		}
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("fetch %s: %w", src, err)
		}
		return data, nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", src, err)
	}
	return data, nil
}

// catalog is the feed's JSON shape; only the fields the tables carry are decoded.
type catalog struct {
	CatalogVersion  string `json:"catalogVersion"`
	Vulnerabilities []struct {
		CVEID                      string   `json:"cveID"`
		VendorProject              string   `json:"vendorProject"`
		Product                    string   `json:"product"`
		VulnerabilityName          string   `json:"vulnerabilityName"`
		DateAdded                  string   `json:"dateAdded"`
		KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
		CWEs                       []string `json:"cwes"`
	} `json:"vulnerabilities"`
}

// entry is one vulnerability with its strings trimmed: the feed carries
// surrounding whitespace on 27 names, 6 vendors and 13 products, and the engine
// indexes a key the way it looks it up (trimmed and lower-cased), so the raw
// form would make a stored label render differently from the way it resolves —
// and, for products, would give the generator seven more indices than the
// builder has nodes (732 raw pairs, 725 distinct keys).
type entry struct {
	id, name, added string
	ransom          bool
	vendor, product string
	cwes            []string
}

// model is the parsed catalog as the dense ids the ontology registers: entries
// sorted by CVE id, the CWE and product vocabularies sorted byte-wise, and the
// weakness family as parallel index slices.
type model struct {
	catalog string

	kevIDs     []string
	kevNames   []string
	kevAdded   []string
	kevRansom  []bool
	kevProduct []int // product index, one per entry

	weakKEV []int // one pair per weakness reference, sorted by (entry, cwe)
	weakCWE []int

	cweIDs []string

	productVendors []string
	productNames   []string
}

// parse decodes and sorts the feed. The feed's own order is neither sorted nor
// stable (it starts at CVE-2015-5477 while the sorted first id is CVE-2002-0367),
// so sorting is what keeps `make gen` byte-identical across fetches, and the
// sort order is the dense id order the emitted arrays and the builder share.
func parse(data []byte) (*model, error) {
	var c catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	if c.CatalogVersion == "" {
		return nil, errors.New("catalogVersion is empty")
	}
	if len(c.Vulnerabilities) == 0 {
		return nil, errors.New("the catalog has no vulnerabilities")
	}

	entries := make([]entry, 0, len(c.Vulnerabilities))
	for i, v := range c.Vulnerabilities {
		id := strings.TrimSpace(v.CVEID)
		if id == "" {
			return nil, fmt.Errorf("entry %d has no cveID", i)
		}
		vendor, product := strings.TrimSpace(v.VendorProject), strings.TrimSpace(v.Product)
		if vendor == "" || product == "" {
			return nil, fmt.Errorf("entry %s has an empty vendor or product (%q/%q)", id, vendor, product)
		}
		entries = append(entries, entry{
			id:   id,
			name: strings.TrimSpace(v.VulnerabilityName), added: strings.TrimSpace(v.DateAdded),
			ransom: v.KnownRansomwareCampaignUse == "Known",
			vendor: vendor, product: product,
			cwes: sortedDedup(v.CWEs),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	for i := 1; i < len(entries); i++ {
		if entries[i].id == entries[i-1].id {
			return nil, fmt.Errorf("duplicate cveID %s", entries[i].id)
		}
	}

	// The weakness vocabulary, then the product vocabulary: both sorted, and
	// both the dense id space the builder will assign in registration order.
	var cwes []string
	for _, e := range entries {
		cwes = append(cwes, e.cwes...)
	}
	cweIDs := compactSorted(cwes)
	cweIndex := make(map[string]int, len(cweIDs))
	for i, w := range cweIDs {
		cweIndex[w] = i
	}

	type product struct{ vendor, name string }
	var pairs []product
	for _, e := range entries {
		pairs = append(pairs, product{e.vendor, e.product})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].vendor != pairs[j].vendor {
			return pairs[i].vendor < pairs[j].vendor
		}
		return pairs[i].name < pairs[j].name
	})
	var productVendors, productNames []string
	productIndex := map[product]int{}
	for _, p := range pairs {
		if _, ok := productIndex[p]; ok {
			continue
		}
		productIndex[p] = len(productVendors)
		productVendors = append(productVendors, p.vendor)
		productNames = append(productNames, p.name)
	}

	m := &model{
		catalog:        c.CatalogVersion,
		cweIDs:         cweIDs,
		productVendors: productVendors,
		productNames:   productNames,
	}
	for _, e := range entries {
		m.kevIDs = append(m.kevIDs, e.id)
		m.kevNames = append(m.kevNames, e.name)
		m.kevAdded = append(m.kevAdded, e.added)
		m.kevRansom = append(m.kevRansom, e.ransom)
		m.kevProduct = append(m.kevProduct, productIndex[product{e.vendor, e.product}])
		for _, w := range e.cwes {
			m.weakKEV = append(m.weakKEV, len(m.kevIDs)-1)
			m.weakCWE = append(m.weakCWE, cweIndex[w])
		}
	}
	return m, nil
}

// sortedDedup trims, drops the empty strings, sorts and dedups a vocabulary
// slice, so one entry cannot claim the same weakness twice.
func sortedDedup(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return slicesCompact(out)
}

// compactSorted dedups an already sorted slice in place.
func compactSorted(vals []string) []string {
	sort.Strings(vals)
	return slicesCompact(vals)
}

func slicesCompact(vals []string) []string {
	if len(vals) < 2 {
		return vals
	}
	out := vals[:1]
	for _, v := range vals[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func (m *model) shape() shape {
	return shape{
		catalog:        m.catalog,
		entries:        len(m.kevIDs),
		cweEdges:       len(m.weakKEV),
		entriesWithCWE: m.entriesWithCWE(),
		cwes:           len(m.cweIDs),
		products:       len(m.productVendors),
		ransomware:     m.ransomwareCount(),
	}
}

// entriesWithCWE counts the entries carrying at least one weakness; the weakness
// pairs are sorted by entry, so the distinct entries are adjacent.
func (m *model) entriesWithCWE() int {
	n := 0
	for i, k := range m.weakKEV {
		if i == 0 || k != m.weakKEV[i-1] {
			n++
		}
	}
	return n
}

func (m *model) ransomwareCount() int {
	n := 0
	for _, r := range m.kevRansom {
		if r {
			n++
		}
	}
	return n
}

// checkShape holds the emitted tables to the pinned shape. The invariants are
// checked first because a catalog that breaks one of them would emit tables the
// builder cannot register, whatever the pins say.
func (m *model) checkShape(want shape) error {
	if len(m.kevIDs) == 0 {
		return errors.New("shape drift: the catalog has no entries")
	}
	if len(m.kevIDs) > maxNodes || len(m.cweIDs) > maxNodes || len(m.productVendors) > maxNodes {
		return fmt.Errorf("shape drift: node count exceeds %d (entries %d, cwes %d, products %d)",
			maxNodes, len(m.kevIDs), len(m.cweIDs), len(m.productVendors))
	}
	if len(m.kevProduct) != len(m.kevIDs) {
		return fmt.Errorf("shape drift: %d product assignments for %d entries",
			len(m.kevProduct), len(m.kevIDs))
	}
	if len(m.productNames) != len(m.productVendors) {
		return fmt.Errorf("shape drift: %d product names for %d vendors",
			len(m.productNames), len(m.productVendors))
	}
	if len(m.kevRansom) != len(m.kevIDs) || len(m.kevNames) != len(m.kevIDs) ||
		len(m.kevAdded) != len(m.kevIDs) {
		return fmt.Errorf("shape drift: cold columns %d/%d/%d for %d entries",
			len(m.kevNames), len(m.kevAdded), len(m.kevRansom), len(m.kevIDs))
	}
	if len(m.weakCWE) != len(m.weakKEV) {
		return fmt.Errorf("shape drift: %d weakness pairs for %d entries", len(m.weakCWE), len(m.weakKEV))
	}
	if m.entriesWithCWE() > len(m.kevIDs) {
		return fmt.Errorf("shape drift: %d entries with a CWE for %d entries", m.entriesWithCWE(), len(m.kevIDs))
	}
	for i, p := range m.kevProduct {
		if p < 0 || p >= len(m.productVendors) {
			return fmt.Errorf("shape drift: entry %s has product index %d, out of range", m.kevIDs[i], p)
		}
	}

	counts := []struct {
		name string
		want int
		got  int
	}{
		{"entries", want.entries, len(m.kevIDs)},
		{"weakness references", want.cweEdges, len(m.weakKEV)},
		{"entries with a CWE", want.entriesWithCWE, m.entriesWithCWE()},
		{"CWEs", want.cwes, len(m.cweIDs)},
		{"products", want.products, len(m.productVendors)},
		{"ransomware entries", want.ransomware, m.ransomwareCount()},
	}
	for _, c := range counts {
		if c.want != c.got {
			return fmt.Errorf("KEV %s shape drift: %s %d -> %d (the catalog was revised without a version bump; re-pin deliberately)",
				want.catalog, c.name, c.want, c.got)
		}
	}
	return nil
}

// --- emission ---

func emit(m *model) ([]byte, error) {
	var b bytes.Buffer

	b.WriteString("//go:build goexperiment.simd\n\n")
	b.WriteString("// Code generated by cmd/kevgen. DO NOT EDIT.\n")
	b.WriteString("//\n")
	b.WriteString("// Source: CISA Known Exploited Vulnerabilities catalog " + m.catalog + ".\n")
	b.WriteString("// Reproduced under the catalog's own terms of use; see NOTICE.\n\n")
	b.WriteString("package ontology\n\n")

	fmt.Fprintf(&b, "// SourceKEV names the pinned catalog. Regenerate with `make gen`.\nconst SourceKEV = %q\n\n", sourceFile()+"@"+m.catalog)

	b.WriteString("// Sizes of the frozen KEV tables.\nconst (\n")
	fmt.Fprintf(&b, "\tNKEV           = %d\n", len(m.kevIDs))
	fmt.Fprintf(&b, "\tNKEVCWE        = %d\n", len(m.weakKEV))
	fmt.Fprintf(&b, "\tNKEVWithCWE    = %d\n", m.entriesWithCWE())
	fmt.Fprintf(&b, "\tNCWE           = %d\n", len(m.cweIDs))
	fmt.Fprintf(&b, "\tNProduct       = %d\n", len(m.productVendors))
	fmt.Fprintf(&b, "\tNKEVRansomware = %d\n", m.ransomwareCount())
	b.WriteString(")\n\n")

	writeStrings(&b, "KEVIDs", "KEV entry ids (CVE ids), sorted byte-wise.", m.kevIDs)
	writeStrings(&b, "KEVNames", "Vulnerability names, index-parallel to KEVIDs.", m.kevNames)
	writeStrings(&b, "KEVAdded", "Date each entry was added to the catalog, index-parallel to KEVIDs.", m.kevAdded)
	writeBools(&b, "KEVRansomware", "knownRansomwareCampaignUse == \"Known\", index-parallel to KEVIDs.", m.kevRansom)
	writeInts(&b, "KEVProductIndex", "uint16", "Product index of each entry, index-parallel to KEVIDs.", m.kevProduct, 10)
	writeInts(&b, "KEVWeaknessKEV", "uint16", "Weakness pairs: KEV entry index.", m.weakKEV, 10)
	writeInts(&b, "KEVWeaknessCWE", "uint16", "Weakness pairs: CWE index.", m.weakCWE, 10)
	writeStrings(&b, "CWEIDs", "Weakness ids (CWE ids), sorted byte-wise.", m.cweIDs)
	writeStrings(&b, "KEVProductVendors", "Vendor of each product, sorted by (vendor, product).", m.productVendors)
	writeStrings(&b, "KEVProductNames", "Product names, index-parallel to KEVProductVendors.", m.productNames)

	formatted, err := format.Source(b.Bytes())
	if err != nil {
		// Emit the unformatted source so the syntax error is visible.
		return b.Bytes(), fmt.Errorf("format generated source: %w", err)
	}
	return formatted, nil
}

func writeStrings(b *bytes.Buffer, name, doc string, vals []string) {
	fmt.Fprintf(b, "// %s holds %s\nvar %s = [...]string{\n", name, doc, name)
	for _, v := range vals {
		fmt.Fprintf(b, "\t%q,\n", v)
	}
	b.WriteString("}\n\n")
}

func writeBools(b *bytes.Buffer, name, doc string, vals []bool) {
	fmt.Fprintf(b, "// %s holds %s\nvar %s = [...]bool{\n", name, doc, name)
	for _, v := range vals {
		fmt.Fprintf(b, "\t%t,\n", v)
	}
	b.WriteString("}\n\n")
}

func writeInts(b *bytes.Buffer, name, typ, doc string, vals []int, perLine int) {
	fmt.Fprintf(b, "// %s holds %s\nvar %s = [...]%s{\n", name, doc, name, typ)
	for i, v := range vals {
		if i%perLine == 0 {
			b.WriteString("\t")
		}
		fmt.Fprintf(b, "%d,", v)
		if i%perLine == perLine-1 || i == len(vals)-1 {
			b.WriteString("\n")
		} else {
			b.WriteString(" ")
		}
	}
	b.WriteString("}\n\n")
}

// --- re-pinning ---

// repinFile rewrites this generator's own sourceKEV and pinnedShape literals in
// place, so the next run is pinned to the catalog it just read.
func repinFile(measured shape) error {
	path, err := generatorPath()
	if err != nil {
		return err
	}
	return repinPath(measured, path)
}

// repinPath rewrites the two literals in the generator source at path. Exactly
// those two are replaced and format.Source normalises the result; the rest of
// the file is untouched.
func repinPath(measured shape, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("re-pin: %w", err)
	}
	s := string(raw)

	srcMarker := `sourceKEV = "`
	i := strings.Index(s, srcMarker)
	if i < 0 {
		return fmt.Errorf("re-pin: %q not found in %s", srcMarker, path)
	}
	rest := s[i+len(srcMarker):]
	end := strings.IndexByte(rest, '"')
	if end < 0 {
		return fmt.Errorf("re-pin: unterminated sourceKEV literal in %s", path)
	}
	s = s[:i+len(srcMarker)] + sourceFile() + "@" + measured.catalog + rest[end:]

	const shapeMarker = "var pinnedShape = shape{"
	si := strings.Index(s, shapeMarker)
	if si < 0 {
		return fmt.Errorf("re-pin: %q not found in %s", shapeMarker, path)
	}
	se := strings.Index(s[si:], "\n}")
	if se < 0 {
		return fmt.Errorf("re-pin: unterminated pinnedShape literal in %s", path)
	}
	s = s[:si] + renderShape(measured) + s[si+se+2:]

	formatted, err := format.Source([]byte(s))
	if err != nil {
		return fmt.Errorf("re-pin: format %s: %w", path, err)
	}
	if err := os.WriteFile(path, formatted, 0o644); err != nil {
		return fmt.Errorf("re-pin: %w", err)
	}
	return nil
}

// renderShape renders the pinnedShape literal the re-pin writes, in the same
// layout as the literal it replaces.
func renderShape(sh shape) string {
	return fmt.Sprintf("var pinnedShape = shape{\n\tcatalog: %q,\n\tentries: %d, cweEdges: %d, entriesWithCWE: %d, cwes: %d, products: %d, ransomware: %d,\n}",
		sh.catalog, sh.entries, sh.cweEdges, sh.entriesWithCWE, sh.cwes, sh.products, sh.ransomware)
}

// generatorPath is this source file, the one repinFile rewrites.
func generatorPath() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("re-pin: cannot locate this generator's source file")
	}
	return file, nil
}
