//go:build goexperiment.simd

// Command gr4ph is a read-only lookup tool over the frozen ATT&CK x D3FEND tables:
// it resolves a cold key (technique id, label or alias; artifact name or label;
// countermeasure id, label or alias; relation name) to its dense id and prints
// every relation in both directions.
//
//	GOEXPERIMENT=simd go run ./cmd/gr4ph ttp T1003.001
//	GOEXPERIMENT=simd go run ./cmd/gr4ph rel any
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fr0g-66723067-io/gr4ph"
	"github.com/fr0g-66723067-io/gr4ph/ontology"
)

const usage = `usage: gr4ph <command> [flags] <query> [<query>...]

  ttp <query>        resolve a technique id, label or alias; list its artifacts and
                     the countermeasures that defend it, exact and rolled up
  artifact <query>   resolve an artifact name or label; list the techniques that touch
                     it and the countermeasures linked to it, exact and rolled up
  cm <query>         resolve a countermeasure id, label or alias; list the artifacts and
                     techniques it covers
  rel <name>         resolve a relation name; report its plane, edge count and source
                     count in each family it belongs to
  help               print this message

flags (before or after the queries; -json may also precede the command):
  -json              emit one JSON object per resolved query instead of text
  ttp:      -rel <name>        offensive relation plane (default any)
  artifact: -rel <name>        offensive relation plane for the technique sets (default any)
            -defrel <name>     defensive relation plane for the countermeasure set (default any)
  cm:       -defrel <name>     defensive relation plane for the artifact set (default any)
  rel:      -family <off|def>  restrict the family (default: both)

examples:
  gr4ph ttp 'lsass memory'                 an alert string, not an id
  gr4ph ttp T1003.001 T1003                several queries in one run
  gr4ph ttp -rel accesses T1003.001        one offensive relation, not the union
  gr4ph artifact Process                   triage: techniques, then countermeasures
  gr4ph artifact -rel accesses Process     that technique set under one relation
  gr4ph artifact -defrel suspends Process  one defensive relation, not the union
  gr4ph cm ContentQuarantine               what a countermeasure covers
  gr4ph cm -defrel hardens CredentialHardening  one defensive relation, artifact side
  gr4ph rel blocks                         one line per family it is in
  gr4ph rel -family def blocks             one family only
  gr4ph -json ttp T0821                    one JSON object per query
  gr4ph help                               this message

exit status: 0 all queries resolved, 1 a query was not found, 2 usage error
`

// node is one resolved id with its cold keys. Label is omitted when it equals
// Name, which is exactly when the text form prints it bare.
type node struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
}

// set is one printed line: a direction, a set name, the total match count and
// the ids in ascending order.
type set struct {
	Dir   string `json:"dir"`   // "out" or "in"
	Name  string `json:"name"`  // "artifacts", "artifacts rollup", ...
	Count int    `json:"count"` // total matches; always len(Nodes) here
	Nodes []node `json:"nodes"`
}

// plane is one line of a rel result. ID is the plane index (0 is the union) and
// Count is the family's highest plane index, i.e. the number of registered
// predicates, so the union reads "0/N" and the last predicate "N/N".
type plane struct {
	Family  string `json:"family"`  // "offensive" or "defensive"
	ID      int    `json:"id"`      // 0 is the union plane
	Count   int    `json:"count"`   // registered predicates in the family
	Edges   int    `json:"edges"`   // distinct (source, target) pairs
	Sources int    `json:"sources"` // sources with at least one target
}

// result is one resolved query: the JSON object, and the source of the text block.
type result struct {
	Query    string  `json:"query"`
	Kind     string  `json:"kind"` // "ttp", "artifact", "cm", "rel"
	ID       *int    `json:"id,omitempty"`
	Name     string  `json:"name"`
	Label    string  `json:"label,omitempty"`
	Domain   string  `json:"domain,omitempty"`   // ttp only
	Parent   string  `json:"parent,omitempty"`   // ttp only, absent at top level
	Children *int    `json:"children,omitempty"` // ttp only, 0 is emitted
	Sets     []set   `json:"sets,omitempty"`     // node kinds
	Planes   []plane `json:"planes,omitempty"`   // rel
}

func main() {
	e, err := buildEngine()
	if err != nil {
		fmt.Fprintln(os.Stderr, "gr4ph:", err)
		os.Exit(1)
	}
	os.Exit(run(e, os.Args[1:], os.Stdout, os.Stderr))
}

// buildEngine registers the frozen tables into a fresh builder and freezes it.
func buildEngine() (*gr4ph.Engine, error) {
	b := gr4ph.NewBuilder()
	if err := ontology.Register(b); err != nil {
		return nil, err
	}
	return b.Build()
}

// run parses args and writes one block per query to stdout. It returns the exit
// status: 0 all queries resolved, 1 a query or relation was not found, 2 usage
// error.
func run(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	// A leading -json is accepted before the command as well as after it, so
	// `gr4ph -json ttp T1003.001` and `gr4ph ttp -json T1003.001` are the same
	// invocation; the flag is handed on to the handler that parses it.
	if len(args) > 1 && (args[0] == "-json" || args[0] == "--json") {
		args = append([]string{args[1], "-json"}, args[2:]...)
	}
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "ttp":
		return runTTP(e, rest, stdout, stderr)
	case "artifact":
		return runArtifact(e, rest, stdout, stderr)
	case "cm":
		return runCM(e, rest, stdout, stderr)
	case "rel":
		return runRel(e, rest, stdout, stderr)
	}
	fmt.Fprintf(stderr, "gr4ph: unknown command: %s\n", cmd)
	fmt.Fprint(stderr, usage)
	return 2
}

// parse parses fs against args and silences the flag package's own output, so
// only this command's text reaches the streams. It returns (status, false) when
// the caller must return status immediately: 0 after printing usage to stdout
// for -h/--help, 2 after printing the parse error and usage to stderr. When it
// returns (0, true) the caller reads the queries from splitArgs.
func parse(fs *flag.FlagSet, args []string, stdout, stderr io.Writer) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return 0, false
		}
		fmt.Fprintf(stderr, "gr4ph: %v\n", err)
		fmt.Fprint(stderr, usage)
		return 2, false
	}
	return 0, true
}

// splitArgs separates the flags of args from the positional queries, so a flag
// may follow the queries as well as precede them: `rel analyzes -family def` is
// the same invocation as `rel -family def analyzes`. Names and arity come from
// fs, which must already hold every flag of the command; a token that starts
// with "-" and names no registered flag stays a flag argument, so the flag
// package still rejects it and the caller reports a usage error.
func splitArgs(fs *flag.FlagSet, args []string) (flags, queries []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			queries = append(queries, args[i+1:]...)
			break
		}
		name, hasValue := flagName(arg)
		if name == "" {
			queries = append(queries, arg)
			continue
		}
		flags = append(flags, arg)
		// A non-boolean flag without "=" takes the next token as its value, so
		// the value is not mistaken for a query.
		if f := fs.Lookup(name); f != nil && !hasValue && !boolFlag(f) && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	return flags, queries
}

// flagName returns the name of a "-name", "--name" or "-name=value" token and
// whether the token already carries its value; a token that is not a flag
// yields "".
func flagName(arg string) (name string, hasValue bool) {
	if len(arg) < 2 || arg[0] != '-' {
		return "", false
	}
	name = strings.TrimPrefix(arg[1:], "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		return name[:i], true
	}
	return name, false
}

// boolFlag reports whether f takes no value, so the token after it is not its
// value.
func boolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}

// buffers holds the full-size destination slices and scratch rows an invocation
// needs. Sizing every dst by the engine's partition count means the library's
// truncation at len(dst) never bites, and one allocation per partition serves
// every query of the invocation.
type buffers struct {
	arts []gr4ph.Artifact
	ttps []gr4ph.TTP
	cms  []gr4ph.Countermeasure
	scrA []uint64 // artifact partition: ArtifactsRollupRel
	scrT []uint64 // technique partition: TTPsRollupRel, TTPsForCountermeasureRollup
	scrC []uint64 // countermeasure partition: CountermeasuresForTTPRollup, ...ViaTTPs
}

func newBuffers(e *gr4ph.Engine) *buffers {
	return &buffers{
		arts: make([]gr4ph.Artifact, e.ArtifactCount()),
		ttps: make([]gr4ph.TTP, e.TTPCount()),
		cms:  make([]gr4ph.Countermeasure, e.CountermeasureCount()),
		scrA: make([]uint64, e.WordsPerRow(gr4ph.KindArtifact)),
		scrT: make([]uint64, e.WordsPerRow(gr4ph.KindTTP)),
		scrC: make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure)),
	}
}

// runTTP answers `ttp <query>...`.
func runTTP(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ttp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	relName := fs.String("rel", "any", "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if len(queries) == 0 {
		fmt.Fprintln(stderr, "gr4ph: missing query")
		return 2
	}
	r, ok := e.Rel(*relName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such offensive relation: %s\n", *relName)
		return 1
	}

	buf := newBuffers(e)
	suffix := relSuffix(r, *relName)
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		t, ok := e.Incident(q)
		if !ok {
			failures = append(failures, "gr4ph: no such technique: "+q)
			continue
		}
		name, label := e.TTPName(t), e.TTPLabel(t)
		res := result{
			Query: q, Kind: "ttp",
			ID:       new(int(t)),
			Name:     name,
			Label:    collapseLabel(name, label),
			Domain:   domainName(e.TTPDomain(t)),
			Children: new(e.TTPChildCount(t)),
		}
		if p, ok := e.TTPParent(t); ok {
			res.Parent = e.TTPName(p)
		}
		n := e.ArtifactsRel(t, r, buf.arts)
		arts := set{Dir: "out", Name: "artifacts" + suffix, Count: n, Nodes: artNodes(e, buf.arts, n)}
		n = e.ArtifactsRollupRel(t, r, buf.scrA, buf.arts)
		rollupArts := set{Dir: "out", Name: "artifacts rollup" + suffix, Count: n, Nodes: artNodes(e, buf.arts, n)}
		n = e.CountermeasuresForTTP(t, buf.cms)
		cms := set{Dir: "in", Name: "countermeasures", Count: n, Nodes: cmNodes(e, buf.cms, n)}
		n = e.CountermeasuresForTTPRollup(t, buf.scrC, buf.cms)
		rollupCMs := set{Dir: "in", Name: "countermeasures rollup", Count: n, Nodes: cmNodes(e, buf.cms, n)}
		res.Sets = []set{arts, rollupArts, cms, rollupCMs}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runArtifact answers `artifact <query>...`.
func runArtifact(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("artifact", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	relName := fs.String("rel", "any", "")
	defRelName := fs.String("defrel", "any", "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if len(queries) == 0 {
		fmt.Fprintln(stderr, "gr4ph: missing query")
		return 2
	}
	r, ok := e.Rel(*relName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such offensive relation: %s\n", *relName)
		return 1
	}
	dr, ok := e.DefRel(*defRelName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such defensive relation: %s\n", *defRelName)
		return 1
	}

	buf := newBuffers(e)
	relSuffixStr := relSuffix(r, *relName)
	defSuffix := defRelSuffix(dr, *defRelName)
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		a, ok := e.Artifact(q)
		if !ok {
			failures = append(failures, "gr4ph: no such artifact: "+q)
			continue
		}
		name, label := e.ArtifactName(a), e.ArtifactLabel(a)
		res := result{
			Query: q, Kind: "artifact",
			ID:    new(int(a)),
			Name:  name,
			Label: collapseLabel(name, label),
		}
		n := e.TTPsRel(a, r, buf.ttps)
		ttps := set{Dir: "in", Name: "techniques" + relSuffixStr, Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.TTPsRollupRel(a, r, buf.scrT, buf.ttps)
		rollupTTPs := set{Dir: "in", Name: "techniques rollup" + relSuffixStr, Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.CountermeasuresForArtifact(a, dr, buf.cms)
		cms := set{Dir: "in", Name: "countermeasures" + defSuffix, Count: n, Nodes: cmNodes(e, buf.cms, n)}
		// The viaTTPs surface is the direct links unioned with the links of the
		// techniques touching a, with no relation filter, so it has no suffix.
		n = e.CountermeasuresForArtifactViaTTPs(a, buf.scrC, buf.cms)
		viaTTPs := set{Dir: "in", Name: "countermeasures viaTTPs", Count: n, Nodes: cmNodes(e, buf.cms, n)}
		res.Sets = []set{ttps, rollupTTPs, cms, viaTTPs}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runCM answers `cm <query>...`.
func runCM(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cm", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	defRelName := fs.String("defrel", "any", "")
	jsonOut := fs.Bool("json", false, "")
	flags, queries := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	if len(queries) == 0 {
		fmt.Fprintln(stderr, "gr4ph: missing query")
		return 2
	}
	dr, ok := e.DefRel(*defRelName)
	if !ok {
		fmt.Fprintf(stderr, "gr4ph: no such defensive relation: %s\n", *defRelName)
		return 1
	}

	buf := newBuffers(e)
	defSuffix := defRelSuffix(dr, *defRelName)
	results := make([]result, 0, len(queries))
	failures := make([]string, 0)
	for _, q := range queries {
		cm, ok := e.Countermeasure(q)
		if !ok {
			failures = append(failures, "gr4ph: no such countermeasure: "+q)
			continue
		}
		name, label := e.CountermeasureName(cm), e.CountermeasureLabel(cm)
		res := result{
			Query: q, Kind: "cm",
			ID:    new(int(cm)),
			Name:  name,
			Label: collapseLabel(name, label),
		}
		n := e.ArtifactsForCountermeasure(cm, dr, buf.arts)
		arts := set{Dir: "out", Name: "artifacts" + defSuffix, Count: n, Nodes: artNodes(e, buf.arts, n)}
		n = e.TTPsForCountermeasure(cm, buf.ttps)
		ttps := set{Dir: "out", Name: "techniques", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		n = e.TTPsForCountermeasureRollup(cm, buf.scrT, buf.ttps)
		rollupTTPs := set{Dir: "out", Name: "techniques rollup", Count: n, Nodes: ttpNodes(e, buf.ttps, n)}
		res.Sets = []set{arts, ttps, rollupTTPs}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// runRel answers `rel <name>...`.
func runRel(e *gr4ph.Engine, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rel", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	family := fs.String("family", "", "")
	jsonOut := fs.Bool("json", false, "")
	flags, names := splitArgs(fs, args)
	if status, ok := parse(fs, flags, stdout, stderr); !ok {
		return status
	}
	switch *family {
	case "", "off", "def":
	default:
		fmt.Fprintf(stderr, "gr4ph: -family must be off or def, got %s\n", *family)
		return 2
	}
	if len(names) == 0 {
		fmt.Fprintln(stderr, "gr4ph: missing relation name")
		return 2
	}

	buf := newBuffers(e)
	results := make([]result, 0, len(names))
	failures := make([]string, 0)
	for _, name := range names {
		r, offOK := e.Rel(name)
		dr, defOK := e.DefRel(name)
		// A relation name may exist in one family, the other, or both. Only the
		// requested families are reported, and only a requested family that does
		// not resolve is an error.
		switch {
		case *family == "off" && !offOK:
			failures = append(failures, "gr4ph: no such offensive relation: "+name)
			continue
		case *family == "def" && !defOK:
			failures = append(failures, "gr4ph: no such defensive relation: "+name)
			continue
		case *family == "" && !offOK && !defOK:
			failures = append(failures, "gr4ph: no such relation: "+name)
			continue
		}
		res := result{Query: name, Kind: "rel", Name: name}
		if *family != "def" && offOK {
			edges, sources := scanOffensive(e, r, buf.arts)
			res.Planes = append(res.Planes, plane{
				Family: "offensive", ID: int(r), Count: e.RelCount(), Edges: edges, Sources: sources,
			})
		}
		if *family != "off" && defOK {
			edges, sources := scanDefensive(e, dr, buf.arts)
			res.Planes = append(res.Planes, plane{
				Family: "defensive", ID: int(dr), Count: e.DefRelCount(), Edges: edges, Sources: sources,
			})
		}
		results = append(results, res)
	}
	return finish(stdout, stderr, results, failures, *jsonOut)
}

// scanOffensive counts the distinct (technique, artifact) pairs of plane r and
// the techniques that have at least one. It allocates nothing: buf is the
// caller's full-size artifact buffer.
func scanOffensive(e *gr4ph.Engine, r gr4ph.Rel, buf []gr4ph.Artifact) (edges, sources int) {
	for t := range e.TTPCount() {
		if n := e.ArtifactsRel(gr4ph.TTP(t), r, buf); n > 0 {
			edges += n
			sources++
		}
	}
	return edges, sources
}

// scanDefensive counts the distinct (countermeasure, artifact) pairs of plane
// dr and the countermeasures that have at least one.
func scanDefensive(e *gr4ph.Engine, dr gr4ph.DefRel, buf []gr4ph.Artifact) (edges, sources int) {
	for cm := range e.CountermeasureCount() {
		if n := e.ArtifactsForCountermeasure(gr4ph.Countermeasure(cm), dr, buf); n > 0 {
			edges += n
			sources++
		}
	}
	return edges, sources
}

// finish renders the resolved queries and reports the failures. A write error
// wins over an unresolved query: both exit 1, but the former is reported first.
func finish(stdout, stderr io.Writer, results []result, failures []string, asJSON bool) int {
	status := 0
	if asJSON {
		for _, res := range results {
			if err := writeJSON(stdout, res); err != nil {
				fmt.Fprintf(stderr, "gr4ph: %v\n", err)
				return 1
			}
		}
	} else {
		for i, res := range results {
			writeText(stdout, res)
			if i < len(results)-1 {
				fmt.Fprintln(stdout)
			}
		}
	}
	if len(failures) > 0 {
		for _, f := range failures {
			fmt.Fprintln(stderr, f)
		}
		status = 1
	}
	return status
}

// writeText writes one block: a header line, then one line per set or plane.
func writeText(w io.Writer, res result) {
	switch res.Kind {
	case "ttp":
		fmt.Fprintf(w, "ttp %s%s domain=%s%s children=%d\n",
			res.Name, quoted(res.Label), res.Domain, parentPart(res.Parent), *res.Children)
	case "rel":
		for _, p := range res.Planes {
			from, to := "technique", "artifact"
			if p.Family == "defensive" {
				from, to = "countermeasure", "artifact"
			}
			fmt.Fprintf(w, "rel %s %s %splane %d/%d (%s -> %s): edges=%d sources=%d\n",
				res.Name, p.Family, unionPart(p.ID), p.ID, p.Count, from, to, p.Edges, p.Sources)
		}
		return
	default:
		fmt.Fprintf(w, "%s %s%s\n", res.Kind, res.Name, quoted(res.Label))
	}
	for _, s := range res.Sets {
		fmt.Fprintf(w, "  %-4s%s (%d): %s\n", s.Dir, s.Name, s.Count, nodeList(s.Nodes))
	}
}

// writeJSON writes res as one JSON object on one line.
func writeJSON(w io.Writer, res result) error {
	return json.NewEncoder(w).Encode(res)
}

// artNodes materialises the first n artifact ids of ids as cold-key nodes.
func artNodes(e *gr4ph.Engine, ids []gr4ph.Artifact, n int) []node {
	nodes := make([]node, 0, n)
	for _, a := range ids[:n] {
		name := e.ArtifactName(a)
		nodes = append(nodes, node{ID: int(a), Name: name, Label: collapseLabel(name, e.ArtifactLabel(a))})
	}
	return nodes
}

// ttpNodes materialises the first n technique ids of ids as cold-key nodes.
func ttpNodes(e *gr4ph.Engine, ids []gr4ph.TTP, n int) []node {
	nodes := make([]node, 0, n)
	for _, t := range ids[:n] {
		name := e.TTPName(t)
		nodes = append(nodes, node{ID: int(t), Name: name, Label: collapseLabel(name, e.TTPLabel(t))})
	}
	return nodes
}

// cmNodes materialises the first n countermeasure ids of ids as cold-key nodes.
func cmNodes(e *gr4ph.Engine, ids []gr4ph.Countermeasure, n int) []node {
	nodes := make([]node, 0, n)
	for _, cm := range ids[:n] {
		name := e.CountermeasureName(cm)
		nodes = append(nodes, node{ID: int(cm), Name: name, Label: collapseLabel(name, e.CountermeasureLabel(cm))})
	}
	return nodes
}

// collapseLabel drops a label that repeats the node's name, so both encoders
// can read "" as "print the name bare".
func collapseLabel(name, label string) string {
	if label == name {
		return ""
	}
	return label
}

// quoted renders a label for the text form as ` "Label"`, or "" when the label
// is absent (which includes "repeats the name", collapsed at the source).
func quoted(label string) string {
	if label == "" {
		return ""
	}
	return ` "` + label + `"`
}

// parentPart renders the parent field of a ttp header, absent at top level.
func parentPart(parent string) string {
	if parent == "" {
		return ""
	}
	return " parent=" + parent
}

// unionPart labels the union plane in a rel line.
func unionPart(id int) string {
	if id == 0 {
		return "union "
	}
	return ""
}

// relSuffix names the offensive relation in a set label, and is empty for the
// union plane. flag is the raw flag value, so the label repeats what was typed.
func relSuffix(r gr4ph.Rel, flag string) string {
	if r == gr4ph.RelAny {
		return ""
	}
	return " (rel " + flag + ")"
}

// defRelSuffix is relSuffix for the defensive family.
func defRelSuffix(dr gr4ph.DefRel, flag string) string {
	if dr == gr4ph.DefRelAny {
		return ""
	}
	return " (defrel " + flag + ")"
}

// nodeList renders a set's nodes: "-" when the set is empty, else the names
// joined by ", ".
func nodeList(nodes []node) string {
	if len(nodes) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		parts = append(parts, n.Name+quoted(n.Label))
	}
	return strings.Join(parts, ", ")
}

// domainName renders the four ATT&CK domains the builder accepts.
func domainName(d gr4ph.Domain) string {
	switch d {
	case gr4ph.DomainEnterprise:
		return "enterprise"
	case gr4ph.DomainICS:
		return "ics"
	case gr4ph.DomainMobile:
		return "mobile"
	case gr4ph.DomainSPARTA:
		return "sparta"
	}
	return fmt.Sprintf("domain(%d)", int(d))
}
