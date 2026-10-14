// Command d3fendgen generates ontology/attack_gen.go: the frozen cold-path
// tables for MITRE ATT&CK (enterprise, ICS, mobile) crossed with D3FEND.
//
// It is deliberately untagged (no goexperiment.simd) and imports nothing from
// this module except the untagged, standard-library-only internal/atomicfile, so
// the tables can be regenerated on a stock toolchain; the file it writes is
// tagged and does import the engine package.
//
// Sources are pinned by version and fetched over HTTP unless a local path is
// given. Nothing is cached: the raw ~80 MB of STIX/CSV never enters git, only
// the generated Go tables do.
//
//	go run ./cmd/d3fendgen -out ontology/attack_gen.go
//	go run ./cmd/d3fendgen -enterprise e.json -ics i.json -mobile m.json -d3fend d.csv -out /tmp/x.go
//
// The generator asserts the shape of the assembled graph (node/edge/relation
// counts, the two-level hierarchy, contiguous child blocks) and fails loudly
// instead of emitting tables whose indices no longer match upstream.
package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fr0g-66723067-io/gr4ph/internal/atomicfile"
)

const (
	defaultEnterprise = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json"
	defaultICS        = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack-19.2.json"
	defaultMobile     = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack-19.2.json"
	defaultD3FEND     = "https://d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend-full-mappings.csv"

	// Source constants emitted into the generated file. They name the pinned
	// releases rather than echoing the input path, so the output is
	// byte-identical whether the sources came from a URL or a local file. A
	// different release cannot slip through unnoticed: the shape assertions
	// below are calibrated to exactly these versions.
	sourceEnterprise = "enterprise-attack-19.2.json"
	sourceICS        = "ics-attack-19.2.json"
	sourceMobile     = "mobile-attack-19.2.json"
	sourceD3FEND     = "d3fend-full-mappings.csv@1.6.0"
)

// Caps the emitted tables must respect, mirroring the engine's own limits
// (gr4ph.MaxNodes and the uint8 plane space) without importing the engine.
const (
	// maxPlanes is the uint8 plane space of gr4ph.Rel/DefRel (1..255).
	maxPlanes = 255
	// maxNodes is gr4ph.MaxNodes: ids must fit uint16. Index 65535 is the
	// NoParent sentinel and can never be a parent (a child would need index
	// 65536, past the cap), so the emitted parent table stays unambiguous.
	maxNodes = 65536
)

// shape is the expected graph shape of a pinned release. The generator fails
// loudly when a run drifts from it, instead of emitting tables whose indices no
// longer match upstream.
type shape struct {
	ttps, artifacts, cms            int
	offRels, defRels                int
	offEdges, defEdges, defends     int
	offPairs                        int // distinct (ttp, artifact) pairs = offensive union-plane cardinality
	enterprise, mobile, ics, sparta int
	topLevel, subs, parents         int
	maxChildren                     int

	tactics, platforms                  int
	tacticAssignments                   int
	platformAssignments                 int
	dataComponents                      int
	detectsPairs                        int
	groups, actors, software, campaigns int
	groupUses, softwareUses             int
}

// pinnedShape is ATT&CK 19.2 x D3FEND 1.6.0, measured from the pinned sources.
var pinnedShape = shape{
	ttps: 1186, artifacts: 247, cms: 157,
	offRels: 41, defRels: 38,
	offEdges: 670, defEdges: 182, defends: 4133, offPairs: 654,
	enterprise: 858, mobile: 176, ics: 106, sparta: 46,
	topLevel: 605, subs: 581, parents: 148, maxChildren: 18,

	tactics: 41, platforms: 15, tacticAssignments: 1431, platformAssignments: 2527,
	dataComponents: 123, detectsPairs: 3263,
	groups: 1212, actors: 195, software: 957, campaigns: 60,
	groupUses: 18885, softwareUses: 1339,
}

// domain mirrors gr4ph.Domain, kept local so this package imports nothing gated
// (its only module import is the untagged internal/atomicfile).
type domain uint8

const (
	domEnterprise domain = 0
	domICS        domain = 1
	domMobile     domain = 2
	domSPARTA     domain = 3
)

func (d domain) constName() string {
	switch d {
	case domEnterprise:
		return "gr4ph.DomainEnterprise"
	case domICS:
		return "gr4ph.DomainICS"
	case domMobile:
		return "gr4ph.DomainMobile"
	}
	return "gr4ph.DomainSPARTA"
}

func main() {
	entSrc := flag.String("enterprise", defaultEnterprise, "ATT&CK enterprise 19.2 STIX bundle (URL or file path)")
	icsSrc := flag.String("ics", defaultICS, "ATT&CK ICS 19.2 STIX bundle (URL or file path)")
	mobSrc := flag.String("mobile", defaultMobile, "ATT&CK mobile 19.2 STIX bundle (URL or file path)")
	d3Src := flag.String("d3fend", defaultD3FEND, "D3FEND full mappings CSV (URL or file path)")
	out := flag.String("out", filepath.Join("ontology", "attack_gen.go"), "output Go file")
	flag.Parse()

	if err := run(*entSrc, *icsSrc, *mobSrc, *d3Src, *out, os.Stdout, pinnedShape); err != nil {
		fmt.Fprintln(os.Stderr, "d3fendgen:", err)
		os.Exit(1)
	}
}

// run loads the four sources, assembles and shape-checks the graph, writes the
// generated file and reports the measured shape to w.
func run(entSrc, icsSrc, mobSrc, d3Src, out string, w io.Writer, want shape) error {
	// ATT&CK first, in precedence order: an id seen in enterprise is never
	// re-tagged by ICS or mobile (no cross-domain collisions exist in 19.2, so
	// this is only a defensive tiebreak).
	stix := make(map[string]*ttpInfo)
	g := newAttackGraph()
	for _, s := range []struct {
		src string
		dom domain
	}{{entSrc, domEnterprise}, {icsSrc, domICS}, {mobSrc, domMobile}} {
		data, err := load(s.src)
		if err != nil {
			return err
		}
		if err := parseAttack(data, s.dom, stix); err != nil {
			return fmt.Errorf("%s: %w", s.src, err)
		}
		if err := parseAttackGraph(data, g); err != nil {
			return fmt.Errorf("%s: %w", s.src, err)
		}
	}

	d3Data, err := load(d3Src)
	if err != nil {
		return err
	}
	d3, err := parseD3FEND(d3Data)
	if err != nil {
		return fmt.Errorf("%s: %w", d3Src, err)
	}

	m, err := assemble(stix, g, d3)
	if err != nil {
		return err
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
	if err := atomicfile.Write(out, file); err != nil {
		return err
	}

	fmt.Fprintf(w, "d3fendgen: wrote %s\n", out)
	fmt.Fprintf(w, "  ttps           %d (%s)\n", len(m.ttpIDs), m.domainHistogram())
	fmt.Fprintf(w, "  artifacts      %d\n", len(m.artNames))
	fmt.Fprintf(w, "  countermeasures %d\n", len(m.cmIDs))
	fmt.Fprintf(w, "  relations      %d offensive, %d defensive\n", len(m.offRelNames), len(m.defRelNames))
	fmt.Fprintf(w, "  edges          %d offensive, %d defensive, %d defends-against\n", len(m.offT), len(m.defC), len(m.defendsC))
	fmt.Fprintf(w, "  hierarchy      %d top-level, %d sub-techniques, %d parents, max %d children\n",
		m.topLevel(), len(m.ttpIDs)-m.topLevel(), m.parentCount(), m.maxChildren())
	fmt.Fprintf(w, "  revoked        %d\n", m.revokedCount())
	actor, software, campaign := m.kindHistogram()
	fmt.Fprintf(w, "  tactics        %d, platforms %d, assignments %d/%d\n",
		len(m.tacticIDs), len(m.platformNames), sumRows(m.tacticTTP), sumRows(m.platformTTP))
	fmt.Fprintf(w, "  data components %d, detects edges %d\n", len(m.dcIDs), len(m.detectsDC))
	fmt.Fprintf(w, "  groups         %d (%d actors, %d software, %d campaigns), uses edges %d technique, %d software\n",
		len(m.groupIDs), actor, software, campaign, len(m.usesGroup), len(m.softwareUseGroup))
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
