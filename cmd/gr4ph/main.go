//go:build goexperiment.simd

// Command gr4ph is a read-only lookup tool over the frozen ATT&CK x D3FEND x
// KEV tables: it resolves a cold key (technique id, label or alias; artifact
// name or label; countermeasure id, label or alias; data component id or label;
// group id; tactic id; platform name; CVE id; weakness id; vendor/product pair;
// relation name) to its dense id and prints every relation in both directions.
//
//	GOEXPERIMENT=simd go run ./cmd/gr4ph ttp T1003.001
//	GOEXPERIMENT=simd go run ./cmd/gr4ph rel any
package main

import (
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

  ttp <query>        resolve a technique id, label or alias; list its artifacts, the
                     countermeasures that defend it, the data components that detect it
                     and the grouping nodes that use it, exact and rolled up
  artifact <query>   resolve an artifact name or label; list the techniques that touch
                     it and the countermeasures linked to it, exact and rolled up
  cm <query>         resolve a countermeasure id, label or alias; list the artifacts and
                     techniques it covers
  dc <query>         resolve a data component id or label; list the techniques it detects
  group <query>      resolve a grouping node (actor G, software S, campaign C); list the
                     techniques and software it uses, and who uses it
  tactic <ta-id>     resolve an ATT&CK tactic id; list its techniques
  platform <name>    resolve a platform name; list the techniques that run on it
  kev <query>        resolve a CVE id; list the weakness classes it is filed under and
                     the vendor product it is about
  cwe <query>        resolve a weakness id; list the entries in that class
  product <v>/<name> resolve a vendor/product pair; list the entries filed under it
  rel <name>         resolve a relation name; report its plane, edge count and source
                     count in each family it belongs to
  coverage [<cm>...] resolve countermeasures as the deployed set; classify every technique as
                     defended, undefended (mapped but uncovered) or unmapped
  gain [<cm>...]     resolve countermeasures as the deployed set; rank candidates by the techniques
                     they would newly cover
  contain <ttp>...   resolve techniques as the observed set; list the countermeasures that touch any
                     of them
  help               print this message

flags (before or after the queries; -json may also precede the command, and every
command accepts it):
  -json              emit one JSON object per resolved query instead of text
  ttp:      -rel <name>        offensive relation plane (default any)
  artifact: -rel <name>        offensive relation plane for the technique sets (default any)
            -defrel <name>     defensive relation plane for the countermeasure set (default any)
  cm:       -defrel <name>     defensive relation plane for the artifact set (default any)
  rel:      -family <off|def>  restrict the family (default: both)
  gain:     -top <n>           how many candidates to rank (default 10)
            -all               every candidate with a non-zero gain
            -greedy            the successive maximum-gain sequence instead of a ranking

examples:
  gr4ph ttp 'lsass memory'                 an alert string, not an id
  gr4ph ttp T1003.001 T1003                several queries in one run
  gr4ph ttp -rel accesses T1003.001        one offensive relation, not the union
  gr4ph artifact Process                   triage: techniques, then countermeasures
  gr4ph artifact -rel accesses Process     that technique set under one relation
  gr4ph artifact -defrel suspends Process  one defensive relation, not the union
  gr4ph cm ContentQuarantine               what a countermeasure covers
  gr4ph cm -defrel hardens CredentialHardening  one defensive relation, artifact side
  gr4ph dc DC0084                          what a data component detects
  gr4ph group G0007                        what an actor uses, and who uses it
  gr4ph tactic TA0005                      the techniques of one ATT&CK tactic
  gr4ph platform Windows                   the techniques of one platform
  gr4ph kev CVE-2021-44228                 an entry, its weaknesses and its product
  gr4ph cwe CWE-78                         the entries in one weakness class
  gr4ph product Apache/Log4j2              the entries for one vendor product
  gr4ph rel blocks                         one line per family it is in
  gr4ph rel -family def blocks             one family only
  gr4ph coverage ContentQuarantine         what that one countermeasure defends
  gr4ph gain -greedy ContentQuarantine     the greedy order that finishes that deployment
  gr4ph contain T1003.001                  mitigations for an alert on LSASS memory
  gr4ph -json ttp T0821                    one JSON object per query
  gr4ph help                               this message

exit status: 0 all queries resolved, 1 a query was not found or could not be read, 2 usage error
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

// gain is one row of a gain result: a candidate countermeasure and the number of
// techniques it would newly cover on top of the deployed selection.
type gain struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Label string `json:"label,omitempty"`
	Gain  int    `json:"gain"`
}

// result is one resolved query: the JSON object, and the source of the text block.
type result struct {
	Query    string `json:"query"`
	Kind     string `json:"kind"` // "ttp", "artifact", "cm", "dc", "group", "tactic", "platform", "kev", "cwe", "product", "rel", "coverage", "gain", "contain"
	ID       *int   `json:"id,omitempty"`
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Domain   string `json:"domain,omitempty"`   // ttp only
	Parent   string `json:"parent,omitempty"`   // ttp only, absent at top level
	Children *int   `json:"children,omitempty"` // ttp only, 0 is emitted
	Revoked  bool   `json:"revoked,omitempty"`  // ttp and group only, absent when live
	// Tactics and Platforms are the ttp attribute masks, rendered as ids/names in
	// index order, so bit i of TTPTactics is Tactics[i].
	Tactics      []string `json:"tactics,omitempty"`      // ttp only
	Platforms    []string `json:"platforms,omitempty"`    // ttp only
	SubTechnique bool     `json:"subtechnique,omitempty"` // ttp only, absent on a top-level technique
	GroupKind    string   `json:"group_kind,omitempty"`   // group only: actor|software|campaign
	// The KEV verbs: Added and Ransomware are the catalog's own columns, and
	// Vendor/Product are the pair the entry is filed under.
	Added      string `json:"added,omitempty"`      // kev only
	Ransomware bool   `json:"ransomware,omitempty"` // kev only
	Vendor     string `json:"vendor,omitempty"`     // kev only
	Product    string `json:"product,omitempty"`    // kev only
	// The overlay verbs: coverage and gain take countermeasures, contain takes
	// techniques, and every count is the number of distinct resolved queries.
	Deployed   *int    `json:"deployed,omitempty"`   // coverage, gain
	Mapped     *int    `json:"mapped,omitempty"`     // coverage
	Retired    *int    `json:"retired,omitempty"`    // coverage: the flagged techniques among all 1186
	Observed   *int    `json:"observed,omitempty"`   // contain
	Candidates *int    `json:"candidates,omitempty"` // gain
	Greedy     *int    `json:"greedy,omitempty"`     // gain -greedy
	Gains      []gain  `json:"gains,omitempty"`      // gain
	Sets       []set   `json:"sets,omitempty"`       // node kinds
	Planes     []plane `json:"planes,omitempty"`     // rel
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
	case "dc":
		return runDC(e, rest, stdout, stderr)
	case "group":
		return runGroup(e, rest, stdout, stderr)
	case "tactic":
		return runTactic(e, rest, stdout, stderr)
	case "platform":
		return runPlatform(e, rest, stdout, stderr)
	case "kev":
		return runKEV(e, rest, stdout, stderr)
	case "cwe":
		return runCWE(e, rest, stdout, stderr)
	case "product":
		return runProduct(e, rest, stdout, stderr)
	case "rel":
		return runRel(e, rest, stdout, stderr)
	case "coverage":
		return runCoverage(e, rest, stdout, stderr)
	case "gain":
		return runGain(e, rest, stdout, stderr)
	case "contain":
		return runContain(e, rest, stdout, stderr)
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

// requireQueries reports the shared usage error of the eleven verbs that take a
// query list, so the guard has one call site per verb instead of a copied block
// a new verb could forget. It writes the message to stderr and returns false;
// the caller returns status 2.
func requireQueries(stderr io.Writer, queries []string) bool {
	if len(queries) > 0 {
		return true
	}
	fmt.Fprintln(stderr, "gr4ph: missing query")
	return false
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
		if name == "" && !hasValue {
			// A plain word, or a lone "-" that the flag package also treats as
			// a query. "-=x" has an empty name but is still a flag: it goes to
			// the FlagSet so the flag package reports the bad syntax (status 2)
			// instead of the lookup missing (status 1).
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
// yields "". A lone "-" is not a flag, matching the flag package, which stops
// at it; "-=x" and "--=x" are, with an empty name the flag package rejects as
// bad syntax.
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
	arts  []gr4ph.Artifact
	ttps  []gr4ph.TTP
	cms   []gr4ph.Countermeasure
	dcs   []gr4ph.DataComponent
	gs    []gr4ph.Group
	kevs  []gr4ph.KEV
	cwes  []gr4ph.CWE
	gains []int    // countermeasure partition: one marginal gain per candidate
	scrA  []uint64 // artifact partition: ArtifactsRollupRel
	scrT  []uint64 // technique partition: TTPsRollupRel, TTPsForCountermeasureRollup
	scrC  []uint64 // countermeasure partition: CountermeasuresForTTPRollup, ...ViaTTPs
	scrD  []uint64 // data-component partition: DataComponentsForTTPRollup
	scrK  []uint64 // KEV partition: KEVsForProducts, KEVsForCWEs
}

func newBuffers(e *gr4ph.Engine) *buffers {
	return &buffers{
		arts:  make([]gr4ph.Artifact, e.ArtifactCount()),
		ttps:  make([]gr4ph.TTP, e.TTPCount()),
		cms:   make([]gr4ph.Countermeasure, e.CountermeasureCount()),
		dcs:   make([]gr4ph.DataComponent, e.DataComponentCount()),
		gs:    make([]gr4ph.Group, e.GroupCount()),
		kevs:  make([]gr4ph.KEV, e.KEVCount()),
		cwes:  make([]gr4ph.CWE, e.CWECount()),
		gains: make([]int, e.CountermeasureCount()),
		scrA:  make([]uint64, e.WordsPerRow(gr4ph.KindArtifact)),
		scrT:  make([]uint64, e.WordsPerRow(gr4ph.KindTTP)),
		scrC:  make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure)),
		scrD:  make([]uint64, e.WordsPerRow(gr4ph.KindDataComponent)),
		scrK:  make([]uint64, e.WordsPerRow(gr4ph.KindKEV)),
	}
}
