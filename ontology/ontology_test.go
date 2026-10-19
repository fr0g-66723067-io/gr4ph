//go:build goexperiment.simd

package ontology

import (
	"errors"
	"math/bits"
	"slices"
	"strings"
	"testing"

	"github.com/fr0g-66723067-io/gr4ph"
	"github.com/fr0g-66723067-io/gr4ph/internal/hotmethods"
)

// build registers the frozen tables into a fresh engine.
func build(tb testing.TB) *gr4ph.Engine {
	tb.Helper()
	b := gr4ph.NewBuilder()
	if err := Register(b); err != nil {
		tb.Fatalf("Register: %v", err)
	}
	e, err := b.Build()
	if err != nil {
		tb.Fatalf("Build: %v", err)
	}
	return e
}

func ttp(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.TTP {
	tb.Helper()
	id, ok := e.Incident(name)
	if !ok {
		tb.Fatalf("unknown technique %q", name)
	}
	return id
}

func art(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.Artifact {
	tb.Helper()
	id, ok := e.Artifact(name)
	if !ok {
		tb.Fatalf("unknown artifact %q", name)
	}
	return id
}

func cm(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.Countermeasure {
	tb.Helper()
	id, ok := e.Countermeasure(name)
	if !ok {
		tb.Fatalf("unknown countermeasure %q", name)
	}
	return id
}

// setSel sets bit i of sel. The root package's setBit is unexported, so the
// ontology tests build their selections with this.
func setSel(sel []uint64, i int) { sel[i>>6] |= 1 << uint(i&63) }

func rel(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.Rel {
	tb.Helper()
	r, ok := e.Rel(name)
	if !ok {
		tb.Fatalf("unknown relation %q", name)
	}
	return r
}

func ta(tb testing.TB, e *gr4ph.Engine, id string) gr4ph.Tactic {
	tb.Helper()
	v, ok := e.Tactic(id)
	if !ok {
		tb.Fatalf("unknown tactic %q", id)
	}
	return v
}

func pf(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.Platform {
	tb.Helper()
	v, ok := e.Platform(name)
	if !ok {
		tb.Fatalf("unknown platform %q", name)
	}
	return v
}

func dc(tb testing.TB, e *gr4ph.Engine, id string) gr4ph.DataComponent {
	tb.Helper()
	v, ok := e.DataComponent(id)
	if !ok {
		tb.Fatalf("unknown data component %q", id)
	}
	return v
}

func g(tb testing.TB, e *gr4ph.Engine, id string) gr4ph.Group {
	tb.Helper()
	v, ok := e.Group(id)
	if !ok {
		tb.Fatalf("unknown group %q", id)
	}
	return v
}

func defRel(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.DefRel {
	tb.Helper()
	r, ok := e.DefRel(name)
	if !ok {
		tb.Fatalf("unknown defensive relation %q", name)
	}
	return r
}

func kev(tb testing.TB, e *gr4ph.Engine, id string) gr4ph.KEV {
	tb.Helper()
	v, ok := e.KEV(id)
	if !ok {
		tb.Fatalf("unknown KEV entry %q", id)
	}
	return v
}

func cwe(tb testing.TB, e *gr4ph.Engine, id string) gr4ph.CWE {
	tb.Helper()
	v, ok := e.CWE(id)
	if !ok {
		tb.Fatalf("unknown CWE %q", id)
	}
	return v
}

func prod(tb testing.TB, e *gr4ph.Engine, vendor, name string) gr4ph.Product {
	tb.Helper()
	v, ok := e.Product(vendor, name)
	if !ok {
		tb.Fatalf("unknown product %q/%q", vendor, name)
	}
	return v
}

// eqTTPs compares ids against expected technique names, in order.
func eqTTPs(tb testing.TB, label string, e *gr4ph.Engine, got []gr4ph.TTP, want ...string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Fatalf("%s = %d ids %v, want %d %v", label, len(got), ttpNames(e, got), len(want), want)
	}
	for i, name := range want {
		if e.TTPName(got[i]) != name {
			tb.Fatalf("%s = %v, want %v", label, ttpNames(e, got), want)
		}
	}
}

func eqArtifacts(tb testing.TB, label string, e *gr4ph.Engine, got []gr4ph.Artifact, want ...string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Fatalf("%s = %d ids %v, want %d %v", label, len(got), artNames(e, got), len(want), want)
	}
	for i, name := range want {
		if e.ArtifactName(got[i]) != name {
			tb.Fatalf("%s = %v, want %v", label, artNames(e, got), want)
		}
	}
}

func eqCMs(tb testing.TB, label string, e *gr4ph.Engine, got []gr4ph.Countermeasure, want ...string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Fatalf("%s = %d ids %v, want %d %v", label, len(got), cmNames(e, got), len(want), want)
	}
	for i, name := range want {
		if e.CountermeasureName(got[i]) != name {
			tb.Fatalf("%s = %v, want %v", label, cmNames(e, got), want)
		}
	}
}

func ttpNames(e *gr4ph.Engine, ids []gr4ph.TTP) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = e.TTPName(id)
	}
	return out
}

func artNames(e *gr4ph.Engine, ids []gr4ph.Artifact) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = e.ArtifactName(id)
	}
	return out
}

func cmNames(e *gr4ph.Engine, ids []gr4ph.Countermeasure) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = e.CountermeasureName(id)
	}
	return out
}

// TestRegisterRequiresFreshBuilder pins the dense-id precondition: registering
// into a builder that already holds relations or nodes would shift every plane
// and index, so it must fail instead.
func TestRegisterRequiresFreshBuilder(t *testing.T) {
	b := gr4ph.NewBuilder()
	if err := Register(b); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := Register(b); !errors.Is(err, ErrBuilderNotEmpty) {
		t.Fatalf("second Register = %v, want ErrBuilderNotEmpty", err)
	}

	b2 := gr4ph.NewBuilder()
	if _, err := b2.AddRel("pre-registered"); err != nil {
		t.Fatalf("AddRel: %v", err)
	}
	if err := Register(b2); !errors.Is(err, ErrBuilderNotEmpty) {
		t.Fatalf("Register after AddRel = %v, want ErrBuilderNotEmpty", err)
	}

	b3 := gr4ph.NewBuilder()
	if _, err := b3.AddTTP("T1", "one", gr4ph.DomainEnterprise, gr4ph.NoParent, false); err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	if err := Register(b3); !errors.Is(err, ErrBuilderNotEmpty) {
		t.Fatalf("Register after AddTTP = %v, want ErrBuilderNotEmpty", err)
	}

	// A built-but-empty builder is not fresh either: its Add* all return
	// ErrBuilderUsed, so Register must report the documented precondition error.
	b4 := gr4ph.NewBuilder()
	if _, err := b4.Build(); err != nil {
		t.Fatalf("Build: %v", err)
	}
	if err := Register(b4); !errors.Is(err, ErrBuilderNotEmpty) {
		t.Fatalf("Register on a built builder = %v, want ErrBuilderNotEmpty", err)
	}
}

// TestRegisterAcceptsZeroValueBuilder: the Builder's zero value is documented as
// equivalent to NewBuilder(), so Register must accept it (its freshness guard
// reads RelCount, which is 0 on an unseeded builder).
func TestRegisterAcceptsZeroValueBuilder(t *testing.T) {
	var b gr4ph.Builder
	if err := Register(&b); err != nil {
		t.Fatalf("Register(zero Builder) = %v, want nil", err)
	}
	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if e.TTPCount() != NTTP || e.ArtifactCount() != NArtifact || e.CountermeasureCount() != NCountermeasure {
		t.Fatalf("counts = %d/%d/%d, want %d/%d/%d",
			e.TTPCount(), e.ArtifactCount(), e.CountermeasureCount(), NTTP, NArtifact, NCountermeasure)
	}
	if e.RelCount() != NRel || e.DefRelCount() != NDefRel {
		t.Fatalf("rel counts = %d/%d, want %d/%d", e.RelCount(), e.DefRelCount(), NRel, NDefRel)
	}
}

// TestOntologySizes pins the frozen table sizes against the pinned release.
func TestOntologySizes(t *testing.T) {
	e := build(t)

	// The engine must match the generated table sizes, and those sizes must
	// match the pinned release.
	sizes := []struct {
		name string
		got  int
		want int
	}{
		{"engine techniques / NTTP", e.TTPCount(), NTTP},
		{"engine artifacts / NArtifact", e.ArtifactCount(), NArtifact},
		{"engine countermeasures / NCountermeasure", e.CountermeasureCount(), NCountermeasure},
		{"engine relations / NRel", e.RelCount(), NRel},
		{"engine defensive relations / NDefRel", e.DefRelCount(), NDefRel},
		{"NTTP", NTTP, 1186},
		{"NArtifact", NArtifact, 247},
		{"NCountermeasure", NCountermeasure, 157},
		{"NRel", NRel, 41},
		{"NDefRel", NDefRel, 38},
		{"NOffEdges", NOffEdges, 670},
		{"NDefEdges", NDefEdges, 182},
		{"NDefends", NDefends, 4133},
		{"engine tactics / NTactic", e.TacticCount(), NTactic},
		{"engine platforms / NPlatform", e.PlatformCount(), NPlatform},
		{"engine data components / NDataComponent", e.DataComponentCount(), NDataComponent},
		{"engine groups / NGroup", e.GroupCount(), NGroup},
		{"NTactic", NTactic, 41},
		{"NPlatform", NPlatform, 15},
		{"NDataComponent", NDataComponent, 123},
		{"NGroup", NGroup, 1212},
		{"NDetects", NDetects, 3263},
		{"NUses", NUses, 18885},
		{"NSoftwareUses", NSoftwareUses, 1339},
		{"engine KEV entries / NKEV", e.KEVCount(), NKEV},
		{"engine weaknesses / NCWE", e.CWECount(), NCWE},
		{"engine products / NProduct", e.ProductCount(), NProduct},
		{"NKEV", NKEV, 1739},
		{"NKEVCWE", NKEVCWE, 1679},
		{"NKEVWithCWE", NKEVWithCWE, 1564},
		{"NCWE", NCWE, 189},
		{"NProduct", NProduct, 722},
		{"NKEVRansomware", NKEVRansomware, 361},
	}
	for _, s := range sizes {
		if s.got != s.want {
			t.Errorf("%s = %d, want %d", s.name, s.got, s.want)
		}
	}

	// WordsPerRow: 1186/64 = 19, 247/64 = 4, 157/64 = 3.
	if got := e.WordsPerRow(gr4ph.KindTTP); got != 19 {
		t.Fatalf("WordsPerRow(TTP) = %d, want 19", got)
	}
	if got := e.WordsPerRow(gr4ph.KindArtifact); got != 4 {
		t.Fatalf("WordsPerRow(Artifact) = %d, want 4", got)
	}
	if got := e.WordsPerRow(gr4ph.KindCountermeasure); got != 3 {
		t.Fatalf("WordsPerRow(Countermeasure) = %d, want 3", got)
	}
	// 123/64 = 2.
	if got := e.WordsPerRow(gr4ph.KindDataComponent); got != 2 {
		t.Fatalf("WordsPerRow(DataComponent) = %d, want 2", got)
	}
	// 1739/64 = 28, 189/64 = 3, 722/64 = 12.
	if got := e.WordsPerRow(gr4ph.KindKEV); got != 28 {
		t.Fatalf("WordsPerRow(KEV) = %d, want 28", got)
	}
	if got := e.WordsPerRow(gr4ph.KindCWE); got != 3 {
		t.Fatalf("WordsPerRow(CWE) = %d, want 3", got)
	}
	if got := e.WordsPerRow(gr4ph.KindProduct); got != 12 {
		t.Fatalf("WordsPerRow(Product) = %d, want 12", got)
	}

	// Every table name resolves to the plane the generated constant claims.
	for i, name := range RelNames {
		got, ok := e.Rel(name)
		if !ok {
			t.Fatalf("Rel(%q) not found", name)
		}
		if got != gr4ph.Rel(i+1) {
			t.Fatalf("Rel(%q) = %d, want %d", name, got, i+1)
		}
		if e.RelName(got) != name {
			t.Fatalf("RelName(%d) = %q, want %q", got, e.RelName(got), name)
		}
	}
	for i, name := range DefRelNames {
		got, ok := e.DefRel(name)
		if !ok {
			t.Fatalf("DefRel(%q) not found", name)
		}
		if got != gr4ph.DefRel(i+1) {
			t.Fatalf("DefRel(%q) = %d, want %d", name, got, i+1)
		}
		if e.DefRelName(got) != name {
			t.Fatalf("DefRelName(%d) = %q, want %q", got, e.DefRelName(got), name)
		}
	}
	if e.RelName(gr4ph.RelAny) != "any" || e.DefRelName(gr4ph.DefRelAny) != "any" {
		t.Fatal("plane 0 must be named any")
	}
	if r, ok := e.Rel("any"); !ok || r != gr4ph.RelAny {
		t.Fatalf("Rel(any) = %d,%v, want RelAny,true", r, ok)
	}
	if dr, ok := e.DefRel("any"); !ok || dr != gr4ph.DefRelAny {
		t.Fatalf("DefRel(any) = %d,%v, want DefRelAny,true", dr, ok)
	}
}

// TestOntologyLayoutArithmetic recomputes the README's block table from the
// tables themselves — the generated counts and the engine's own strides — so a
// re-pin that moves a count cannot leave the published arithmetic green.
// builder_test.go's TestLayoutMatchesReadme reads the same numbers off a
// registered builder, which is what pins the table's shape; this test pins the
// arithmetic the row widths and plane counts imply.
func TestOntologyLayoutArithmetic(t *testing.T) {
	e := build(t)

	wTTP := e.WordsPerRow(gr4ph.KindTTP)
	wArt := e.WordsPerRow(gr4ph.KindArtifact)
	wCM := e.WordsPerRow(gr4ph.KindCountermeasure)
	wDC := e.WordsPerRow(gr4ph.KindDataComponent)
	wKEV := e.WordsPerRow(gr4ph.KindKEV)
	wCWE := e.WordsPerRow(gr4ph.KindCWE)
	wProduct := e.WordsPerRow(gr4ph.KindProduct)
	// The grouping partition has no Kind, so its row width is the one stride
	// WordsPerRow does not publish.
	wGrp := (NGroup + 63) / 64
	offPlanes, defPlanes := NRel+1, NDefRel+1 // plane 0 of each family is the union
	wTactic, wPlatform := 1, 1                // one uint64 mask per technique

	blocks := []struct {
		name  string
		words int
	}{
		{"ttpArt", offPlanes * NTTP * wArt},
		{"artTTP", offPlanes * NArtifact * wTTP},
		{"cmArt", defPlanes * NCountermeasure * wArt},
		{"artCM", defPlanes * NArtifact * wCM},
		{"cmTTP", NCountermeasure * wTTP},
		{"ttpCM", NTTP * wCM},
		{"tacticTTP", NTactic * wTTP},
		{"ttpTactic", NTTP * wTactic},
		{"platformTTP", NPlatform * wTTP},
		{"ttpPlatform", NTTP * wPlatform},
		{"ttpFlags", NTTP},
		{"dcTTP", NDataComponent * wTTP},
		{"ttpDC", NTTP * wDC},
		{"grpTTP", NGroup * wTTP},
		{"ttpGrp", NTTP * wGrp},
		{"grpSoftware", NGroup * wGrp},
		{"softwareGrp", NGroup * wGrp},
		{"kevCWE", NKEV * wCWE},
		{"cweKEV", NCWE * wKEV},
		{"kevProduct", NKEV * wProduct},
		{"productKEV", NProduct * wKEV},
	}
	want := []int{
		199248, 197106, 24492, 28899, 2983, 3558,
		779, 1186, 285, 1186, 1186, 2337, 2372, 23028, 22534, 23028, 23028,
		5217, 5292, 20868, 20216,
	}
	subtotal, newArrays := 0, 0
	for i, bl := range blocks {
		if bl.words != want[i] {
			t.Errorf("%s = %d words, want %d (README block table)", bl.name, bl.words, want[i])
		}
		if i < 6 {
			subtotal += bl.words
		} else {
			newArrays += bl.words
		}
	}
	if subtotal != 456286 || newArrays != 152542 || subtotal+newArrays != 608828 {
		t.Errorf("six-block subtotal %d, new arrays %d, total %d, want 456286/152542/608828",
			subtotal, newArrays, subtotal+newArrays)
	}
}

// TestOntologyRelationConstants pins every generated constant to its plane, so
// a change in the naming rule or the sort order cannot pass unnoticed.
func TestOntologyRelationConstants(t *testing.T) {
	offensive := map[string]gr4ph.Rel{
		"abuses": RelAbuses, "accesses": RelAccesses, "adds": RelAdds, "blocks": RelBlocks,
		"connects": RelConnects, "copies": RelCopies, "creates": RelCreates, "deletes": RelDeletes,
		"disables": RelDisables, "encrypts": RelEncrypts, "enumerates": RelEnumerates,
		"executes": RelExecutes, "forges": RelForges, "impairs": RelImpairs, "injects": RelInjects,
		"installs": RelInstalls, "interprets": RelInterprets, "invokes": RelInvokes, "jams": RelJams,
		"loads": RelLoads, "may-access": RelMayAccess, "may-add": RelMayAdd,
		"may-be-associated-with": RelMayBeAssociatedWith, "may-corrupt": RelMayCorrupt,
		"may-create": RelMayCreate, "may-evaluate": RelMayEvaluate, "may-execute": RelMayExecute,
		"may-invoke": RelMayInvoke, "may-modify": RelMayModify, "may-produce": RelMayProduce,
		"may-run": RelMayRun, "may-transfer": RelMayTransfer, "modifies": RelModifies,
		"monitors": RelMonitors, "obfuscates": RelObfuscates, "produces": RelProduces,
		"queries": RelQueries, "reads": RelReads, "runs": RelRuns, "unmounts": RelUnmounts,
		"uses": RelUses,
	}
	if len(offensive) != NRel {
		t.Fatalf("offensive constant table has %d entries, want %d", len(offensive), NRel)
	}
	for name, want := range offensive {
		if got := RelNames[int(want)-1]; got != name {
			t.Errorf("RelNames[%d] = %q, want %q (constant %s)", int(want)-1, got, name, "Rel"+name)
		}
	}

	defensive := map[string]gr4ph.DefRel{
		"analyzes": DefRelAnalyzes, "authenticates": DefRelAuthenticates, "blocks": DefRelBlocks,
		"configures": DefRelConfigures, "creates": DefRelCreates, "deletes": DefRelDeletes,
		"detects": DefRelDetects, "disables": DefRelDisables, "encrypts": DefRelEncrypts,
		"erases": DefRelErases, "evaluates": DefRelEvaluates, "filters": DefRelFilters,
		"hardens": DefRelHardens, "inventories": DefRelInventories, "isolates": DefRelIsolates,
		"limits": DefRelLimits, "manages": DefRelManages, "maps": DefRelMaps,
		"may-access": DefRelMayAccess, "may-contain": DefRelMayContain, "modifies": DefRelModifies,
		"monitors": DefRelMonitors, "neutralizes": DefRelNeutralizes, "obfuscates": DefRelObfuscates,
		"quarantines": DefRelQuarantines, "reads": DefRelReads, "regenerates": DefRelRegenerates,
		"restores": DefRelRestores, "restricts": DefRelRestricts, "spoofs": DefRelSpoofs,
		"strengthens": DefRelStrengthens, "suspends": DefRelSuspends, "terminates": DefRelTerminates,
		"updates": DefRelUpdates, "use-limits": DefRelUseLimits, "uses": DefRelUses,
		"validates": DefRelValidates, "verifies": DefRelVerifies,
	}
	if len(defensive) != NDefRel {
		t.Fatalf("defensive constant table has %d entries, want %d", len(defensive), NDefRel)
	}
	for name, want := range defensive {
		if got := DefRelNames[int(want)-1]; got != name {
			t.Errorf("DefRelNames[%d] = %q, want %q (constant %s)", int(want)-1, got, name, "DefRel"+name)
		}
	}
}

func TestOntologyDomains(t *testing.T) {
	e := build(t)

	var enterprise, mobile, ics, sparta int
	for i := range e.TTPCount() {
		switch e.TTPDomain(gr4ph.TTP(i)) {
		case gr4ph.DomainEnterprise:
			enterprise++
		case gr4ph.DomainMobile:
			mobile++
		case gr4ph.DomainICS:
			ics++
		case gr4ph.DomainSPARTA:
			sparta++
		default:
			t.Fatalf("technique %d has an unknown domain", i)
		}
	}
	if enterprise != 858 || mobile != 176 || ics != 106 || sparta != 46 {
		t.Fatalf("domain histogram = %d/%d/%d/%d, want 858/176/106/46", enterprise, mobile, ics, sparta)
	}

	cases := []struct {
		name string
		dom  gr4ph.Domain
	}{
		{"T1003.001", gr4ph.DomainEnterprise},
		{"T0894", gr4ph.DomainICS},
		{"T1603", gr4ph.DomainMobile},
		{"DE-0007", gr4ph.DomainSPARTA},
		{"EX-0010", gr4ph.DomainSPARTA}, // synthesised parent
	}
	for _, c := range cases {
		if got := e.TTPDomain(ttp(t, e, c.name)); got != c.dom {
			t.Errorf("TTPDomain(%s) = %d, want %d", c.name, got, c.dom)
		}
	}
}

func TestOntologyHierarchy(t *testing.T) {
	e := build(t)

	topLevel, subs, parents, maxChildren, childSum := 0, 0, 0, 0, 0
	for i := range e.TTPCount() {
		id := gr4ph.TTP(i)
		name := e.TTPName(id)
		parent, hasParent := e.TTPParent(id)
		if hasParent {
			subs++
			// The id prefix is the authoritative hierarchy source.
			if name[:len(e.TTPName(parent))] != e.TTPName(parent) || name[len(e.TTPName(parent))] != '.' {
				t.Fatalf("%s: parent %s is not its id prefix", name, e.TTPName(parent))
			}
			if grandparent, ok := e.TTPParent(parent); ok {
				t.Fatalf("%s: parent %s is itself a sub-technique (grandparent %s)", name, e.TTPName(parent), e.TTPName(grandparent))
			}
		} else {
			topLevel++
			if len(name) > 0 && name[len(name)-1] == '.' {
				t.Fatalf("%s: top-level technique has a trailing dot", name)
			}
		}
		count := e.TTPChildCount(id)
		if count > 0 {
			parents++
			childSum += count
		}
		if count > maxChildren {
			maxChildren = count
		}
		// Children occupy exactly the contiguous range id+1 .. id+count.
		buf := make([]gr4ph.TTP, count)
		if got := e.TTPChildren(id, buf); got != count {
			t.Fatalf("%s: TTPChildren = %d, want %d", name, got, count)
		}
		for k, child := range buf {
			if want := gr4ph.TTP(int(id) + 1 + k); child != want {
				t.Fatalf("%s: child %d = %d, want %d", name, k, child, want)
			}
			if p, ok := e.TTPParent(child); !ok || p != id {
				t.Fatalf("%s: child %s does not report it as its parent", name, e.TTPName(child))
			}
		}
	}
	if topLevel != 605 || subs != 581 {
		t.Fatalf("hierarchy = %d top-level / %d sub-techniques, want 605/581", topLevel, subs)
	}
	if parents != 148 || childSum != 581 || maxChildren != 18 {
		t.Fatalf("hierarchy = %d parents, %d children total, max %d, want 148/581/18", parents, childSum, maxChildren)
	}

	// Spot checks on the extremes.
	buf := make([]gr4ph.TTP, 32)
	if got := e.TTPChildren(ttp(t, e, "T1546"), buf); got != 18 {
		t.Fatalf("TTPChildren(T1546) = %d, want 18", got)
	}
	if got := e.TTPChildren(ttp(t, e, "T1003.001"), buf); got != 0 {
		t.Fatalf("TTPChildren(T1003.001) = %d, want 0", got)
	}
	// A synthesised SPARTA parent carries its sub-technique.
	ex := ttp(t, e, "EX-0010")
	if p, ok := e.TTPParent(ttp(t, e, "EX-0010.01")); !ok || p != ex {
		t.Fatalf("TTPParent(EX-0010.01) = %d,%v want %d,true", p, ok, ex)
	}
	if got := e.TTPChildCount(ex); got == 0 {
		t.Fatal("synthesised parent EX-0010 must have children")
	}
}

// TestOntologySynthesisedParents pins the exact set of synthesised SPARTA
// parents and the README's promise about them: they exist in no ATT&CK domain,
// carry no edges and have no aliases.
func TestOntologySynthesisedParents(t *testing.T) {
	e := build(t)

	want := []string{
		"DE-0003", "EX-0001", "EX-0005", "EX-0009", "EX-0010", "EX-0012", "EX-0013",
		"EX-0016", "EXF-0006", "IA-0007", "RD-0004",
	}
	var got []string
	for i := range e.TTPCount() {
		id := gr4ph.TTP(i)
		if e.TTPDomain(id) != gr4ph.DomainSPARTA || e.TTPChildCount(id) == 0 {
			continue
		}
		got = append(got, e.TTPName(id))
		if n := e.Degree(id, gr4ph.RelAny); n != 0 {
			t.Errorf("%s: Degree = %d, want 0 (synthesised parents carry no edges)", e.TTPName(id), n)
		}
		if n := e.CountermeasuresForTTP(id, nil); n != 0 {
			t.Errorf("%s: CountermeasuresForTTP = %d, want 0", e.TTPName(id), n)
		}
		if a := TTPAliases[i]; a != nil {
			t.Errorf("%s: aliases = %v, want none", e.TTPName(id), a)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("synthesised parents = %v, want %v", got, want)
	}
}

func TestOntologyColdPath(t *testing.T) {
	e := build(t)

	// Normalization: id, label and alias are all keys, trimmed and
	// case-insensitive.
	want := ttp(t, e, "T1003.001")
	for _, alert := range []string{"t1003.001", "T1003.001", "LSASS Memory", "  lsass memory  ", " lsass MEMORY "} {
		got, ok := e.Incident(alert)
		if !ok || got != want {
			t.Errorf("Incident(%q) = %d,%v want %d,true", alert, got, ok, want)
		}
	}
	if _, ok := e.Incident("no such technique"); ok {
		t.Error("Incident must fail for an unknown alert")
	}
	if got := e.TTPName(want); got != "T1003.001" {
		t.Errorf("TTPName = %q", got)
	}
	if got := e.TTPLabel(want); got != "LSASS Memory" {
		t.Errorf("TTPLabel = %q", got)
	}

	// The D3FEND spelling of T0821 is an alias of the ATT&CK name.
	t0821 := ttp(t, e, "T0821")
	if got := e.TTPLabel(t0821); got != "Modify Controller Tasking" {
		t.Fatalf("TTPLabel(T0821) = %q, want the ATT&CK name", got)
	}
	if got, ok := e.Incident("Modify controller Tasking"); !ok || got != t0821 {
		t.Fatalf("Incident(D3FEND spelling of T0821) = %d,%v want %d,true", got, ok, t0821)
	}

	if id, ok := e.Artifact("process"); !ok || id != art(t, e, "Process") {
		t.Fatalf("Artifact(process) = %d,%v", id, ok)
	}
	if id, ok := e.Artifact("Create Process"); !ok || e.ArtifactName(id) != "CreateProcess" {
		t.Fatalf("Artifact by label = %d,%v", id, ok)
	}
	if id, ok := e.Countermeasure("credential hardening"); !ok || id != cm(t, e, "CredentialHardening") {
		t.Fatalf("Countermeasure by label = %d,%v", id, ok)
	}
	if _, ok := e.Countermeasure("D3-CH"); ok {
		t.Fatal("D3-IDs must not be indexed as countermeasure keys")
	}
	if _, ok := e.Countermeasure("D3-PH"); ok {
		t.Fatal("D3-IDs must not be indexed as countermeasure keys")
	}

	// Response formats ids back into log lines and is total over the id space.
	dst := make([]string, 4)
	ids := []gr4ph.TTP{want, gr4ph.TTP(65535)}
	if n := e.Response(dst, ids); n != 2 {
		t.Fatalf("Response count = %d, want 2", n)
	}
	if dst[0] != "T1003.001 LSASS Memory" || dst[1] != "<invalid ttp 65535>" {
		t.Fatalf("Response = %q, %q", dst[0], dst[1])
	}
	cdst := make([]string, 2)
	cms := []gr4ph.Countermeasure{cm(t, e, "CredentialHardening"), gr4ph.Countermeasure(65535)}
	if n := e.CountermeasureResponse(cdst, cms); n != 2 {
		t.Fatalf("CountermeasureResponse count = %d, want 2", n)
	}
	if cdst[0] != "CredentialHardening Credential Hardening" || cdst[1] != "<invalid cm 65535>" {
		t.Fatalf("CountermeasureResponse = %q, %q", cdst[0], cdst[1])
	}
}

// TestOntologyLabelAmbiguity pins the shared-label rule the Incident doc states:
// the pinned tables keep ATT&CK's revoked techniques, whose live successors
// reuse their labels, so a shared label resolves to its live carrier and only an
// all-revoked one falls back to the lowest index.
func TestOntologyLabelAmbiguity(t *testing.T) {
	e := build(t)

	// Ids are unambiguous: every id round-trips through the label map.
	for i := range e.TTPCount() {
		id := gr4ph.TTP(i)
		got, ok := e.Incident(e.TTPName(id))
		if !ok || got != id {
			t.Fatalf("Incident(TTPName(%d)) = %d,%v want %d,true", i, got, ok, id)
		}
	}

	// The pinned tables: 238 case-sensitive label strings carry more than one
	// technique, shadowing 269 ids. The resolver's key space is the trimmed,
	// lower-cased form, which folds two case-variant pairs into 239 groups (see
	// the sweep below).
	byLabel := map[string][]gr4ph.TTP{}
	for i := range e.TTPCount() {
		id := gr4ph.TTP(i)
		l := e.TTPLabel(id)
		byLabel[l] = append(byLabel[l], id)
	}
	shared, shadowed := 0, 0
	for _, ids := range byLabel {
		if len(ids) > 1 {
			shared++
			shadowed += len(ids) - 1
		}
	}
	if shared != 238 || shadowed != 269 {
		t.Fatalf("shared labels = %d (shadowing %d ids), want 238 (269)", shared, shadowed)
	}

	// A revoked twin and its live successor share a name. Here the live carrier
	// also has the lower index, so both rules agree; the id form is exact.
	powerShell := ttp(t, e, "T1059.001")
	revoked := ttp(t, e, "T1086")
	if e.TTPLabel(powerShell) != "PowerShell" || e.TTPLabel(revoked) != "PowerShell" {
		t.Fatalf("PowerShell labels = %q / %q", e.TTPLabel(powerShell), e.TTPLabel(revoked))
	}
	if !e.TTPRevoked(revoked) {
		t.Fatal("T1086 must be marked revoked")
	}
	if e.TTPRevoked(powerShell) {
		t.Fatal("T1059.001 must not be marked revoked")
	}
	if got, ok := e.Incident("PowerShell"); !ok || got != powerShell {
		t.Fatalf("Incident(PowerShell) = %d,%v want %d,true", got, ok, powerShell)
	}
	if got, ok := e.Incident("T1086"); !ok || got != revoked {
		t.Fatalf("Incident(T1086) = %d,%v want %d,true (the id form is exact)", got, ok, revoked)
	}
	// The revoked twin has the lower index, but the live carrier wins: the label
	// reaches T1546.008, and only the id form reaches T1015.
	revokedTwin := ttp(t, e, "T1015")
	live := ttp(t, e, "T1546.008")
	if !e.TTPRevoked(revokedTwin) || e.TTPRevoked(live) {
		t.Fatalf("TTPRevoked(T1015)=%v, TTPRevoked(T1546.008)=%v, want true, false",
			e.TTPRevoked(revokedTwin), e.TTPRevoked(live))
	}
	if got, ok := e.Incident("Accessibility Features"); !ok || got != live {
		t.Fatalf("Incident(Accessibility Features) = %d,%v want %d,true", got, ok, live)
	}
	if got, ok := e.Incident("T1015"); !ok || got != revokedTwin {
		t.Fatalf("Incident(T1015) = %d,%v want %d,true (the id form is exact)", got, ok, revokedTwin)
	}
	// A cross-domain duplicate: the ICS twin has the lowest index.
	ics := ttp(t, e, "T0893")
	if got, ok := e.Incident("Data from Local System"); !ok || got != ics {
		t.Fatalf("Incident(Data from Local System) = %d,%v want %d,true", got, ok, ics)
	}

	// A label every holder of which is revoked still resolves, to the lowest id.
	if got, ok := e.Incident("DLL Side-Loading"); !ok || got != ttp(t, e, "T1073") {
		t.Fatalf("Incident(DLL Side-Loading) = %d,%v want T1073,true", got, ok)
	}
	// The pinned 19.2 flag: 222 techniques carry it, 197 of them ATT&CK's
	// revoked: true and 25 x_mitre_deprecated without revoked.
	revokedCount := 0
	for i := range e.TTPCount() {
		if e.TTPRevoked(gr4ph.TTP(i)) {
			revokedCount++
		}
	}
	if revokedCount != 222 {
		t.Fatalf("revoked techniques = %d, want 222", revokedCount)
	}

	// The rule is falsifiable over the resolver's whole label-key space: every
	// shared key must resolve to its first live carrier, falling back to the
	// first carrier only when every carrier is revoked. The keys that fall back
	// are exactly the residual ambiguity the rule leaves.
	byKey := map[string][]gr4ph.TTP{}
	for i := range e.TTPCount() {
		id := gr4ph.TTP(i)
		key := strings.ToLower(strings.TrimSpace(e.TTPLabel(id)))
		byKey[key] = append(byKey[key], id)
	}
	var fallback []string
	for key, ids := range byKey {
		if len(ids) < 2 {
			continue
		}
		want := ids[0]
		for _, id := range ids {
			if !e.TTPRevoked(id) {
				want = id
				break
			}
		}
		if got, ok := e.Incident(key); !ok || got != want {
			t.Fatalf("Incident(%q) = %d,%v want %d,true (carriers %v)", key, got, ok, want, ids)
		}
		if e.TTPRevoked(want) {
			fallback = append(fallback, key)
		}
	}
	slices.Sort(fallback)
	const wantFallback = "dll side-loading,indicator blocking,input prompt,plist modification"
	if got := strings.Join(fallback, ","); got != wantFallback {
		t.Fatalf("all-revoked shared labels = %q, want %q", got, wantFallback)
	}

	// Artifact and countermeasure keys are unique: no key names two nodes. (A
	// node whose name and label coincide is one claim, not a collision.)
	artKey := map[string]gr4ph.Artifact{}
	for i := range e.ArtifactCount() {
		a := gr4ph.Artifact(i)
		for _, key := range []string{e.ArtifactName(a), e.ArtifactLabel(a)} {
			if prev, ok := artKey[key]; ok && prev != a {
				t.Fatalf("artifact key %q is claimed by %d and %d", key, prev, a)
			}
			artKey[key] = a
		}
	}
	cmKey := map[string]gr4ph.Countermeasure{}
	for i := range e.CountermeasureCount() {
		cm := gr4ph.Countermeasure(i)
		for _, key := range []string{e.CountermeasureName(cm), e.CountermeasureLabel(cm)} {
			if prev, ok := cmKey[key]; ok && prev != cm {
				t.Fatalf("countermeasure key %q is claimed by %d and %d", key, prev, cm)
			}
			cmKey[key] = cm
		}
	}

	// Data components: ids round-trip, no label names two nodes, and no label
	// equals another node's id (so an id key can never be shadowed by a label).
	dcKey := map[string]gr4ph.DataComponent{}
	for i := range e.DataComponentCount() {
		d := gr4ph.DataComponent(i)
		if got, ok := e.DataComponent(e.DataComponentID(d)); !ok || got != d {
			t.Fatalf("DataComponent(DataComponentID(%d)) = %d,%v want %d", i, got, ok, d)
		}
		key := e.DataComponentLabel(d)
		if prev, ok := dcKey[key]; ok && prev != d {
			t.Fatalf("data component key %q is claimed by %d and %d", key, prev, d)
		}
		dcKey[key] = d
	}
	if got, ok := e.DataComponent("Active Directory Credential Request"); !ok || got != dc(t, e, "DC0084") {
		t.Fatalf("DataComponent(label) = %d,%v want DC0084", got, ok)
	}

	// Grouping nodes: the id always resolves, and a label shared by two nodes
	// resolves to its live carrier — the lowest-index carrier only when every
	// carrier is revoked, which is the rule claimGroup mirrors from claimTTP.
	groupKey := map[string][]gr4ph.Group{}
	for i := range e.GroupCount() {
		g := gr4ph.Group(i)
		if got, ok := e.Group(e.GroupID(g)); !ok || got != g {
			t.Fatalf("Group(GroupID(%d)) = %d,%v want %d", i, got, ok, g)
		}
		key := e.GroupLabel(g)
		groupKey[key] = append(groupKey[key], g)
	}
	// liveWinner is the carrier a shared key must resolve to: the first live one
	// in index order, or the first carrier when every one is revoked.
	liveWinner := func(carriers []gr4ph.Group) gr4ph.Group {
		for _, carrier := range carriers {
			if !e.GroupRevoked(carrier) {
				return carrier
			}
		}
		return carriers[0]
	}
	revokedCarriers := 0
	sharedGroups := 0
	for key, carriers := range groupKey {
		if len(carriers) == 1 {
			continue
		}
		sharedGroups++
		// Every carrier of a shared label must belong to a different kind: a
		// label is unique within one kind.
		kinds := map[gr4ph.GroupKind]bool{}
		for _, carrier := range carriers {
			if kinds[e.GroupKind(carrier)] {
				t.Errorf("label %q is shared within one grouping kind", key)
			}
			kinds[e.GroupKind(carrier)] = true
			if e.GroupRevoked(carrier) {
				revokedCarriers++
			}
		}
		want := liveWinner(carriers)
		if got, ok := e.Group(key); !ok || got != want {
			t.Errorf("Group(%q) = %d,%v want the live carrier %s", key, got, ok, e.GroupID(want))
		}
	}
	if sharedGroups != 12 {
		t.Fatalf("group labels shared by two nodes = %d, want 12", sharedGroups)
	}
	if revokedCarriers != 6 {
		t.Fatalf("revoked carriers of a shared label = %d, want 6 (Gelsemium, Taidoor, Frankenstein, Night Dragon, Operation Wocao, CostaRicto)", revokedCarriers)
	}
	// The resolver folds the label (trim + lower-case), so three case-variant
	// pairs collapse into keys the raw sweep above cannot see. Two of them are
	// within the software kind — the one case the "unique within a kind" rule
	// does not hold for — so they are named as well as counted.
	folded := map[string][]gr4ph.Group{}
	for i := range e.GroupCount() {
		g := gr4ph.Group(i)
		key := strings.ToLower(strings.TrimSpace(e.GroupLabel(g)))
		folded[key] = append(folded[key], g)
	}
	foldedShared, foldedSameKind := 0, 0
	for key, carriers := range folded {
		if len(carriers) == 1 {
			continue
		}
		foldedShared++
		kinds := map[gr4ph.GroupKind]bool{}
		for _, carrier := range carriers {
			if kinds[e.GroupKind(carrier)] {
				foldedSameKind++
				break
			}
			kinds[e.GroupKind(carrier)] = true
		}
		want := liveWinner(carriers)
		if got, ok := e.Group(key); !ok || got != want {
			t.Errorf("folded key %q resolves to %d,%v, want the live carrier %s", key, got, ok, e.GroupID(want))
		}
	}
	if foldedShared != 15 || foldedSameKind != 2 {
		t.Fatalf("folded group keys shared by two nodes = %d (%d within one kind), want 15 (2)",
			foldedShared, foldedSameKind)
	}
	for _, key := range []string{"ngrok", "triton"} {
		carriers := folded[key]
		if len(carriers) != 2 {
			t.Fatalf("folded key %q has %d carriers, want 2", key, len(carriers))
		}
		for _, carrier := range carriers {
			if kind := e.GroupKind(carrier); kind != gr4ph.GroupSoftware {
				t.Errorf("folded key %q carries kind %d (%q), want two software nodes", key, kind, e.GroupID(carrier))
			}
		}
	}
	// The keys where live-first changes the winner — triton, taidoor and
	// gelsemium, whose retired carrier is the lower index — plus ngrok, whose
	// live carrier was the lower index already.
	for key, want := range map[string]string{
		"ngrok": "S0508", "triton": "S1009", "taidoor": "S0011", "gelsemium": "S0666",
	} {
		if got, ok := e.Group(key); !ok || e.GroupID(got) != want {
			t.Errorf("Group(%q) = %s,%v want the live carrier %s", key, e.GroupID(got), ok, want)
		}
	}
	// The pair the rule exists for: the retired S0609 keeps its own id key and
	// its exact label, and the folded key goes to the live S1009.
	retired, tritonLive := g(t, e, "S0609"), g(t, e, "S1009")
	if !e.GroupRevoked(retired) || e.GroupRevoked(tritonLive) {
		t.Errorf("GroupRevoked(S0609) = %v, GroupRevoked(S1009) = %v, want true,false",
			e.GroupRevoked(retired), e.GroupRevoked(tritonLive))
	}
	if got, ok := e.Group("triton"); !ok || got != tritonLive {
		t.Errorf("Group(triton) = %d,%v, want the live S1009", got, ok)
	}
	// Keys are folded, so the retired node's own capitalisation resolves through
	// the same key; only its id reaches it.
	if got, ok := e.Group("TRITON"); !ok || got != tritonLive {
		t.Errorf("Group(TRITON) = %d,%v, want the live S1009 (labels are keyed case-insensitively)", got, ok)
	}
	if got, ok := e.Group("S0609"); !ok || got != retired {
		t.Errorf("Group(S0609) = %d,%v, want the retired node by id", got, ok)
	}
	// The two hard cases on the pinned tables: with both carriers live the
	// earliest keeps the key, so the campaign C0001 beats the actor G0101 (which
	// is revoked in any case) and the actor G0008 beats the software S0030.
	if got, ok := e.Group("Frankenstein"); !ok || got != g(t, e, "C0001") || got == g(t, e, "G0101") {
		t.Errorf("Group(Frankenstein) = %d,%v, want the campaign C0001", got, ok)
	}
	if got, ok := e.Group("Carbanak"); !ok || got != g(t, e, "G0008") {
		t.Errorf("Group(Carbanak) = %d,%v, want the actor G0008", got, ok)
	}

	// Tactics and platforms: the TA id and the platform name are the keys, the
	// tactic label is not (11 labels name 2-3 tactics across the domains).
	for i := range e.TacticCount() {
		ta := gr4ph.Tactic(i)
		if got, ok := e.Tactic(e.TacticID(ta)); !ok || got != ta {
			t.Fatalf("Tactic(TacticID(%d)) = %d,%v want %d", i, got, ok, ta)
		}
	}
	if _, ok := e.Tactic("Stealth"); ok {
		t.Error("Tactic(label) resolved: only the TA id keys a tactic")
	}
	for i := range e.PlatformCount() {
		p := gr4ph.Platform(i)
		if got, ok := e.Platform(e.PlatformName(p)); !ok || got != p {
			t.Fatalf("Platform(PlatformName(%d)) = %d,%v want %d", i, got, ok, p)
		}
	}
	if got, ok := e.Platform("windows"); !ok || got != pf(t, e, "Windows") {
		t.Fatalf("Platform(windows) = %d,%v want the Windows id", got, ok)
	}
}

func TestOntologyOffensiveGoldens(t *testing.T) {
	e := build(t)
	bufT := make([]gr4ph.TTP, e.TTPCount())
	bufA := make([]gr4ph.Artifact, e.ArtifactCount())
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	scratchA := make([]uint64, e.WordsPerRow(gr4ph.KindArtifact))

	process := art(t, e, "Process")
	file := art(t, e, "File")

	// Techniques -> artifacts, exact and rolled up.
	n := e.Artifacts(ttp(t, e, "T1003.001"), bufA)
	eqArtifacts(t, "Artifacts(T1003.001)", e, bufA[:n], "AuthenticationService", "Process")
	if got := e.Artifacts(ttp(t, e, "T1003"), bufA); got != 0 {
		t.Fatalf("Artifacts(T1003) = %d, want 0 (a parent carries no edges of its own)", got)
	}
	n = e.ArtifactsRollup(ttp(t, e, "T1003"), scratchA, bufA)
	eqArtifacts(t, "ArtifactsRollup(T1003)", e, bufA[:n],
		"AuthenticationService", "EncryptedCredential", "EventLog", "IntranetAdministrativeNetworkTraffic",
		"Log", "OperatingSystemFile", "PasswordFile", "Process", "SystemPasswordDatabase")
	n = e.ArtifactsRollup(ttp(t, e, "T1546"), scratchA, bufA)
	if n != 16 {
		t.Fatalf("ArtifactsRollup(T1546) = %d, want 16", n)
	}
	n = e.ArtifactsRollup(ttp(t, e, "T1059"), scratchA, bufA)
	eqArtifacts(t, "ArtifactsRollup(T1059)", e, bufA[:n], "ExecutableScript")
	// A leaf's roll-up is its own row.
	n = e.ArtifactsRollup(ttp(t, e, "T1003.001"), scratchA, bufA)
	eqArtifacts(t, "ArtifactsRollup(T1003.001)", e, bufA[:n], "AuthenticationService", "Process")
	if got := e.Artifacts(ttp(t, e, "T1059.001"), bufA); got != 0 {
		t.Fatalf("Artifacts(T1059.001) = %d, want 0", got)
	}

	// Artifacts -> techniques, exact and rolled up.
	n = e.TTPs(process, bufT)
	eqTTPs(t, "TTPs(Process)", e, bufT[:n], "T1003.001", "T1003.002", "T1003.004", "T1505.003", "T1546.007")
	n = e.TTPsRollup(process, scratchT, bufT)
	eqTTPs(t, "TTPsRollup(Process)", e, bufT[:n], "T1003", "T1505", "T1546")
	if got := e.TTPsRollup(art(t, e, "CreateProcess"), scratchT, bufT); got != 23 {
		t.Fatalf("TTPsRollup(CreateProcess) = %d, want 23", got)
	}
	n = e.TTPsRollup(file, scratchT, bufT)
	eqTTPs(t, "TTPsRollup(File)", e, bufT[:n],
		"EX-0010", "RD-0004", "T1005", "T1036", "T1070", "T1072", "T1074", "T1083", "T1119",
		"T1220", "T1486", "T1552", "T1564", "T1565", "T1566")
	n = e.TTPsRollup(art(t, e, "ExecutableFile"), scratchT, bufT)
	eqTTPs(t, "TTPsRollup(ExecutableFile)", e, bufT[:n],
		"T1027", "T1036", "T1140", "T1204", "T1546", "T1548", "T1565", "T1574")
	if got := e.TTPs(file, bufT); got != 17 {
		t.Fatalf("TTPs(File) = %d, want 17 (exact, sub-techniques included)", got)
	}

	// Relation planes: plane separation and the union plane.
	n = e.TTPsRel(process, rel(t, e, "accesses"), bufT)
	eqTTPs(t, "TTPsRel(Process, accesses)", e, bufT[:n], "T1003.001")
	n = e.TTPsRel(process, rel(t, e, "may-access"), bufT)
	eqTTPs(t, "TTPsRel(Process, may-access)", e, bufT[:n], "T1003.002", "T1003.004")
	if got := e.TTPsRel(process, rel(t, e, "modifies"), bufT); got != 0 {
		t.Fatalf("TTPsRel(Process, modifies) = %d, want 0", got)
	}
	n = e.TTPsRel(file, rel(t, e, "creates"), bufT)
	eqTTPs(t, "TTPsRel(File, creates)", e, bufT[:n], "T1036.006", "T1564.006")

	if !e.AdjacentRel(ttp(t, e, "T1003.001"), process, rel(t, e, "accesses")) {
		t.Fatal("AdjacentRel(T1003.001, Process, accesses) must be true")
	}
	if e.AdjacentRel(ttp(t, e, "T1003.001"), process, rel(t, e, "modifies")) {
		t.Fatal("AdjacentRel(T1003.001, Process, modifies) must be false")
	}
	if !e.Adjacent(ttp(t, e, "T1003.001"), process) {
		t.Fatal("Adjacent must use the union plane")
	}

	// Set operations.
	if got := e.TTPsAny(gr4ph.RelAny, scratchT, bufT, []gr4ph.Artifact{process, file}); got != 22 {
		t.Fatalf("TTPsAny(Process, File) = %d, want 22", got)
	}
	if got := e.ArtifactDegree(art(t, e, "CreateProcess"), gr4ph.RelAny); got != 29 {
		t.Fatalf("ArtifactDegree(CreateProcess) = %d, want 29", got)
	}
	// The README's "≤ 29 × 3-word ORs" bound for CountermeasuresForArtifactViaTTPs
	// is the maximum over every artifact, so pin the maximum itself.
	maxDegree, argmax := 0, gr4ph.Artifact(0)
	for a := range e.ArtifactCount() {
		if d := e.ArtifactDegree(gr4ph.Artifact(a), gr4ph.RelAny); d > maxDegree {
			maxDegree, argmax = d, gr4ph.Artifact(a)
		}
	}
	if maxDegree != 29 || e.ArtifactName(argmax) != "CreateProcess" {
		t.Fatalf("max ArtifactDegree = %d at %s, want 29 at CreateProcess", maxDegree, e.ArtifactName(argmax))
	}
	if got := e.Degree(ttp(t, e, "T0894"), gr4ph.RelAny); got != 8 {
		t.Fatalf("Degree(T0894) = %d, want 8 (maximum technique degree)", got)
	}
}

// TestOntologyUnionPlaneIntegrity checks the six blocks against each other:
// every offensive pair must appear exactly once in the technique-major union
// plane and once in the artifact-major one, and the same must hold for the two
// defensive blocks and the two defends-against blocks. A transposed or
// half-folded plane cannot satisfy both directions at once.
func TestOntologyUnionPlaneIntegrity(t *testing.T) {
	e := build(t)
	bufT := make([]gr4ph.TTP, e.TTPCount())
	bufA := make([]gr4ph.Artifact, e.ArtifactCount())
	bufC := make([]gr4ph.Countermeasure, e.CountermeasureCount())

	// Offensive union plane: 654 distinct (technique, artifact) pairs.
	var sumDegree, sumArtDegree int
	for i := range e.TTPCount() {
		sumDegree += e.Degree(gr4ph.TTP(i), gr4ph.RelAny)
	}
	for i := range e.ArtifactCount() {
		sumArtDegree += e.ArtifactDegree(gr4ph.Artifact(i), gr4ph.RelAny)
	}
	if sumDegree != 654 || sumArtDegree != 654 {
		t.Fatalf("offensive union pairs = %d (ttp-major) / %d (artifact-major), want 654 / 654",
			sumDegree, sumArtDegree)
	}

	// Defensive union plane: 182 distinct (countermeasure, artifact) pairs.
	var sumCmForArt, sumArtForCm int
	for i := range e.ArtifactCount() {
		sumCmForArt += e.CountermeasuresForArtifact(gr4ph.Artifact(i), gr4ph.DefRelAny, bufC)
	}
	for i := range e.CountermeasureCount() {
		sumArtForCm += e.ArtifactsForCountermeasure(gr4ph.Countermeasure(i), gr4ph.DefRelAny, bufA)
	}
	if sumCmForArt != 182 || sumArtForCm != 182 {
		t.Fatalf("defensive union pairs = %d (artifact-major) / %d (cm-major), want 182 / 182",
			sumCmForArt, sumArtForCm)
	}

	// Defends-against: 4133 distinct (countermeasure, technique) pairs.
	var sumCmDegree, sumTTPsForCm int
	for i := range e.CountermeasureCount() {
		id := gr4ph.Countermeasure(i)
		sumCmDegree += e.CountermeasureDegree(id)
		sumTTPsForCm += e.TTPsForCountermeasure(id, bufT)
	}
	if sumCmDegree != 4133 || sumTTPsForCm != 4133 {
		t.Fatalf("defends-against pairs = %d (cm-major) / %d (ttp-major), want 4133 / 4133",
			sumCmDegree, sumTTPsForCm)
	}
}

func TestOntologyCountermeasureGoldens(t *testing.T) {
	e := build(t)
	bufC := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	bufT := make([]gr4ph.TTP, e.TTPCount())
	bufA := make([]gr4ph.Artifact, e.ArtifactCount())
	scratchC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))

	process := art(t, e, "Process")
	credentialHardening := cm(t, e, "CredentialHardening")
	contentQuarantine := cm(t, e, "ContentQuarantine")

	// Direct countermeasure -> artifact links.
	n := e.CountermeasuresForArtifact(process, gr4ph.DefRelAny, bufC)
	eqCMs(t, "CountermeasuresForArtifact(Process)", e, bufC[:n],
		"Application-basedProcessIsolation", "Hardware-basedProcessIsolation", "HostReboot", "HostShutdown",
		"Kernel-basedProcessIsolation", "ProcessLineageAnalysis", "ProcessSelf-ModificationDetection",
		"ProcessSpawnAnalysis", "ProcessSuspension", "ProcessTermination", "SystemCallFiltering")
	// Process's defensive relations are analyzes/isolates/suspends/terminates.
	if got := e.CountermeasuresForArtifact(process, defRel(t, e, "hardens"), bufC); got != 0 {
		t.Fatalf("CountermeasuresForArtifact(Process, hardens) = %d, want 0", got)
	}
	n = e.ArtifactsForCountermeasure(credentialHardening, gr4ph.DefRelAny, bufA)
	eqArtifacts(t, "ArtifactsForCountermeasure(CredentialHardening)", e, bufA[:n], "Credential")
	n = e.ArtifactsForCountermeasure(contentQuarantine, gr4ph.DefRelAny, bufA)
	eqArtifacts(t, "ArtifactsForCountermeasure(ContentQuarantine)", e, bufA[:n], "DatabaseRecord", "File")

	// The chain: direct links unioned with the countermeasures of every
	// technique touching the artifact.
	n = e.CountermeasuresForArtifactViaTTPs(process, scratchC, bufC)
	if n != 36 {
		t.Fatalf("CountermeasuresForArtifactViaTTPs(Process) = %d, want 36", n)
	}
	eqCMs(t, "ViaTTPs(Process) first five", e, bufC[:5],
		"Application-basedProcessIsolation", "ConfigurationInventory", "ContentFiltering",
		"ContentModification", "ContentQuarantine")
	// AuthenticationService has no direct countermeasure link at all: every
	// countermeasure in its surface arrives through the techniques.
	if got := e.CountermeasuresForArtifact(art(t, e, "AuthenticationService"), gr4ph.DefRelAny, bufC); got != 0 {
		t.Fatalf("direct countermeasures for AuthenticationService = %d, want 0", got)
	}
	n = e.CountermeasuresForArtifactViaTTPs(art(t, e, "AuthenticationService"), scratchC, bufC)
	if n != 25 {
		t.Fatalf("ViaTTPs(AuthenticationService) = %d, want 25 (chain only)", n)
	}
	if got := e.CountermeasuresForArtifactViaTTPs(art(t, e, "CreateProcess"), scratchC, bufC); got != 64 {
		t.Fatalf("ViaTTPs(CreateProcess) = %d, want 64", got)
	}
	if got := e.CountermeasuresForArtifactViaTTPs(art(t, e, "ProcessSegment"), scratchC, bufC); got != 66 {
		t.Fatalf("ViaTTPs(ProcessSegment) = %d, want 66 (maximum)", got)
	}

	// Countermeasures of a technique, exact and rolled up.
	n = e.CountermeasuresForTTP(ttp(t, e, "T1003.001"), bufC)
	eqCMs(t, "CountermeasuresForTTP(T1003.001)", e, bufC[:n],
		"Application-basedProcessIsolation", "Hardware-basedProcessIsolation", "HostReboot", "HostShutdown",
		"Kernel-basedProcessIsolation", "ProcessLineageAnalysis", "ProcessSelf-ModificationDetection",
		"ProcessSpawnAnalysis", "ProcessSuspension", "ProcessTermination", "SystemCallFiltering",
		"WebSessionAccessMediation")
	if got := e.CountermeasuresForTTP(ttp(t, e, "T1003"), bufC); got != 0 {
		t.Fatalf("CountermeasuresForTTP(T1003) = %d, want 0 (exact)", got)
	}
	if got := e.CountermeasuresForTTPRollup(ttp(t, e, "T1003"), scratchC, bufC); got != 48 {
		t.Fatalf("CountermeasuresForTTPRollup(T1003) = %d, want 48 (8 children)", got)
	}
	if got := e.CountermeasuresForTTPRollup(ttp(t, e, "T1546"), scratchC, bufC); got != 50 {
		t.Fatalf("CountermeasuresForTTPRollup(T1546) = %d, want 50 (18 children)", got)
	}
	if got := e.CountermeasuresForTTP(ttp(t, e, "T1059"), bufC); got != 15 {
		t.Fatalf("CountermeasuresForTTP(T1059) = %d, want 15", got)
	}
	// T1059's children add no countermeasure of their own.
	if got := e.CountermeasuresForTTPRollup(ttp(t, e, "T1059"), scratchC, bufC); got != 15 {
		t.Fatalf("CountermeasuresForTTPRollup(T1059) = %d, want 15", got)
	}
	if got := e.CountermeasuresForTTP(ttp(t, e, "T1059.001"), bufC); got != 0 {
		t.Fatalf("CountermeasuresForTTP(T1059.001) = %d, want 0", got)
	}

	// Reverse direction: techniques defended by a countermeasure.
	n = e.TTPsForCountermeasure(credentialHardening, bufT)
	if n != 25 {
		t.Fatalf("TTPsForCountermeasure(CredentialHardening) = %d, want 25", n)
	}
	eqTTPs(t, "TTPsForCountermeasure(CredentialHardening) first five", e, bufT[:5],
		"DE-0011", "PER-0005", "T0812", "T0891", "T0892")
	if got := e.TTPsForCountermeasureRollup(credentialHardening, scratchT, bufT); got != 16 {
		t.Fatalf("TTPsForCountermeasureRollup(CredentialHardening) = %d, want 16", got)
	}

	// Single-bit tests and degrees.
	if !e.Defends(contentQuarantine, ttp(t, e, "T1059")) {
		t.Fatal("Defends(ContentQuarantine, T1059) must be true")
	}
	if e.Defends(contentQuarantine, ttp(t, e, "T1003.001")) {
		t.Fatal("Defends(ContentQuarantine, T1003.001) must be false")
	}
	if got := e.CountermeasureDegree(contentQuarantine); got != 125 {
		t.Fatalf("CountermeasureDegree(ContentQuarantine) = %d, want 125 (maximum)", got)
	}
	if got := e.CountermeasureDegree(credentialHardening); got != 25 {
		t.Fatalf("CountermeasureDegree(CredentialHardening) = %d, want 25", got)
	}
	// Every countermeasure has at least one artifact and one technique link.
	for i := range e.CountermeasureCount() {
		id := gr4ph.Countermeasure(i)
		if e.CountermeasureDegree(id) == 0 {
			t.Fatalf("countermeasure %s defends no technique", e.CountermeasureName(id))
		}
		if e.ArtifactsForCountermeasure(id, gr4ph.DefRelAny, bufA) == 0 {
			t.Fatalf("countermeasure %s has no artifact link", e.CountermeasureName(id))
		}
	}
	// 759 of the 1186 techniques carry no offensive edge.
	degreeZero := 0
	// The audit's headline fact: ATT&CK moved most of its D3FEND mapping to
	// the successor id, but some flagged techniques still carry offensive
	// edges, which puts them inside the mapped range where coverage can offer
	// them as targets. The mapped set is read once, below, so the walk is one.
	revokedWithEdges := 0
	for i := range e.TTPCount() {
		tp := gr4ph.TTP(i)
		if e.Degree(tp, gr4ph.RelAny) == 0 {
			degreeZero++
		}
		if e.TTPRevoked(tp) && e.Degree(tp, gr4ph.RelAny) > 0 {
			revokedWithEdges++
		}
	}
	if degreeZero != 759 {
		t.Fatalf("degree-0 techniques = %d, want 759", degreeZero)
	}
	if revokedWithEdges != 23 {
		t.Fatalf("flagged techniques that still carry offensive edges = %d, want 23", revokedWithEdges)
	}
	mapped := make(map[gr4ph.TTP]bool, 427)
	for _, tp := range bufT[:e.TTPsMapped(scratchT, bufT)] {
		mapped[tp] = true
	}
	for i := range e.TTPCount() {
		tp := gr4ph.TTP(i)
		if e.TTPRevoked(tp) && e.Degree(tp, gr4ph.RelAny) > 0 && !mapped[tp] {
			t.Errorf("flagged %s carries offensive edges but is outside the mapped range", e.TTPName(tp))
		}
	}
	// The five ids the README names are among those 23.
	for _, id := range []string{"T1053.004", "T1070.001", "T1070.002", "T1562.001", "T1574.002"} {
		tp, ok := e.Incident(id)
		if !ok {
			t.Fatalf("Incident(%s) not found", id)
		}
		if degree, isMapped := e.Degree(tp, gr4ph.RelAny), mapped[tp]; !e.TTPRevoked(tp) || degree == 0 || !isMapped {
			t.Errorf("%s: revoked=%v degree=%d mapped=%v, want a flagged technique with edges inside the mapped range",
				id, e.TTPRevoked(tp), degree, isMapped)
		}
	}
}

// ontologySink defeats dead-code elimination without allocating.
var ontologySink int

// TestZeroAllocOntology repeats the allocation contract against the real
// engine: 1186x247x157 with 19/4/3-word rows must not allocate either. Every
// result is folded into ontologySink, so an inlined pure call cannot be
// optimized away, and the case count is pinned to the root package's.
func TestZeroAllocOntology(t *testing.T) {
	e := build(t)
	bufT := make([]gr4ph.TTP, e.TTPCount())
	bufA := make([]gr4ph.Artifact, e.ArtifactCount())
	bufC := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	scratchA := make([]uint64, e.WordsPerRow(gr4ph.KindArtifact))
	scratchC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	scratchD := make([]uint64, e.WordsPerRow(gr4ph.KindDataComponent))
	bufD := make([]gr4ph.DataComponent, e.DataComponentCount())
	bufG := make([]gr4ph.Group, e.GroupCount())
	process := art(t, e, "Process")
	t1003 := ttp(t, e, "T1003")
	t1003a := ttp(t, e, "T1003.001")
	cm0 := cm(t, e, "CredentialHardening")
	// Hoisted out of the cases: a helper call inside the closure allocates
	// (testing.T.Helper), which would break the zero-allocation assertion.
	tactic := ta(t, e, "TA0005")
	platform := pf(t, e, "Windows")
	dcProcess := dc(t, e, "DC0084")
	group := g(t, e, "G0007")
	soft := g(t, e, "S0002")
	accesses := rel(t, e, "accesses")
	arts := []gr4ph.Artifact{process, art(t, e, "File")}
	ttps := []gr4ph.TTP{t1003, t1003a}
	selC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	setSel(selC, int(cm0))
	dstGains := make([]int, e.CountermeasureCount())
	selT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	setSel(selT, int(t1003a))
	bufK := make([]gr4ph.KEV, e.KEVCount())
	bufCWE := make([]gr4ph.CWE, e.CWECount())
	bufP := make([]gr4ph.Product, e.ProductCount())
	scrK := make([]uint64, e.WordsPerRow(gr4ph.KindKEV))
	kevEntry := kev(t, e, "CVE-2021-44228")
	weak := cwe(t, e, "CWE-78")
	vendored := prod(t, e, "Apache", "Log4j2")
	selP := make([]uint64, e.WordsPerRow(gr4ph.KindProduct))
	setSel(selP, int(vendored))
	selCWE := make([]uint64, e.WordsPerRow(gr4ph.KindCWE))
	setSel(selCWE, int(weak))

	cases := []struct {
		name string
		fn   func()
	}{
		{"Adjacent", func() {
			if e.Adjacent(t1003a, process) {
				ontologySink++
			}
		}},
		{"AdjacentRel", func() {
			if e.AdjacentRel(t1003a, process, accesses) {
				ontologySink++
			}
		}},
		{"Artifacts", func() { ontologySink += e.Artifacts(t1003a, bufA) }},
		{"ArtifactsRel", func() { ontologySink += e.ArtifactsRel(t1003a, accesses, bufA) }},
		{"TTPs", func() { ontologySink += e.TTPs(process, bufT) }},
		{"TTPsRel", func() { ontologySink += e.TTPsRel(process, gr4ph.RelAny, bufT) }},
		{"Degree", func() { ontologySink += e.Degree(t1003, gr4ph.RelAny) }},
		{"ArtifactDegree", func() { ontologySink += e.ArtifactDegree(process, gr4ph.RelAny) }},
		{"ArtifactsRollup", func() { ontologySink += e.ArtifactsRollup(t1003, scratchA, bufA) }},
		{"ArtifactsRollupRel", func() {
			ontologySink += e.ArtifactsRollupRel(t1003a, accesses, scratchA, bufA)
		}},
		{"TTPsRollup", func() { ontologySink += e.TTPsRollup(process, scratchT, bufT) }},
		{"TTPsRollupRel", func() {
			ontologySink += e.TTPsRollupRel(process, accesses, scratchT, bufT)
		}},
		{"TTPsAny", func() { ontologySink += e.TTPsAny(gr4ph.RelAny, scratchT, bufT, arts) }},
		{"TTPsAll", func() { ontologySink += e.TTPsAll(gr4ph.RelAny, scratchT, bufT, arts) }},
		{"ArtifactsAny", func() { ontologySink += e.ArtifactsAny(gr4ph.RelAny, scratchA, bufA, ttps) }},
		{"ArtifactsAll", func() { ontologySink += e.ArtifactsAll(gr4ph.RelAny, scratchA, bufA, ttps) }},
		{"Defends", func() {
			if e.Defends(cm0, t1003) {
				ontologySink++
			}
		}},
		{"CountermeasuresForTTP", func() { ontologySink += e.CountermeasuresForTTP(t1003a, bufC) }},
		{"CountermeasuresForTTPRollup", func() {
			ontologySink += e.CountermeasuresForTTPRollup(t1003, scratchC, bufC)
		}},
		{"CountermeasuresForArtifact", func() {
			ontologySink += e.CountermeasuresForArtifact(process, gr4ph.DefRelAny, bufC)
		}},
		{"CountermeasuresForArtifactViaTTPs", func() {
			ontologySink += e.CountermeasuresForArtifactViaTTPs(process, scratchC, bufC)
		}},
		{"ArtifactsForCountermeasure", func() {
			ontologySink += e.ArtifactsForCountermeasure(cm0, gr4ph.DefRelAny, bufA)
		}},
		{"TTPsForCountermeasure", func() { ontologySink += e.TTPsForCountermeasure(cm0, bufT) }},
		{"TTPsForCountermeasureRollup", func() {
			ontologySink += e.TTPsForCountermeasureRollup(cm0, scratchT, bufT)
		}},
		{"CountermeasureDegree", func() { ontologySink += e.CountermeasureDegree(cm0) }},
		{"TTPsMapped", func() { ontologySink += e.TTPsMapped(scratchT, bufT) }},
		{"TTPsCovered", func() { ontologySink += e.TTPsCovered(selC, scratchT, bufT) }},
		{"TTPsBlind", func() { ontologySink += e.TTPsBlind(selT, selC, scratchT, bufT) }},
		{"CoverageGain", func() { ontologySink += e.CoverageGain(cm0, selC, scratchT) }},
		{"CoverageGains", func() { ontologySink += e.CoverageGains(selC, scratchT, dstGains) }},
		{"CountermeasuresForObserved", func() {
			ontologySink += e.CountermeasuresForObserved(selT, scratchC, bufC)
		}},
		{"KEVCWEDegree", func() { ontologySink += e.KEVCWEDegree(kevEntry) }},
		{"CWEsForKEV", func() { ontologySink += e.CWEsForKEV(kevEntry, bufCWE) }},
		{"KEVsForCWE", func() { ontologySink += e.KEVsForCWE(weak, bufK) }},
		{"ProductsForKEV", func() { ontologySink += e.ProductsForKEV(kevEntry, bufP) }},
		{"KEVsForProducts", func() { ontologySink += e.KEVsForProducts(selP, scrK, bufK) }},
		{"KEVsForCWEs", func() { ontologySink += e.KEVsForCWEs(selCWE, scrK, bufK) }},
		{"TTPTactics", func() { ontologySink += int(e.TTPTactics(t1003a)) }},
		{"TTPPlatforms", func() { ontologySink += int(e.TTPPlatforms(t1003a)) }},
		{"TTPFlags", func() { ontologySink += int(e.TTPFlags(t1003a)) }},
		{"TTPSubTechnique", func() {
			if e.TTPSubTechnique(t1003a) {
				ontologySink++
			}
		}},
		{"TTPsForTactic", func() { ontologySink += e.TTPsForTactic(tactic, bufT) }},
		{"TTPsForPlatform", func() { ontologySink += e.TTPsForPlatform(platform, bufT) }},
		{"TTPsForDataComponent", func() { ontologySink += e.TTPsForDataComponent(dcProcess, bufT) }},
		{"DataComponentsForTTP", func() { ontologySink += e.DataComponentsForTTP(t1003a, bufD) }},
		{"DataComponentsForTTPRollup", func() {
			ontologySink += e.DataComponentsForTTPRollup(t1003, scratchD, bufD)
		}},
		{"DataComponentDegree", func() { ontologySink += e.DataComponentDegree(dcProcess) }},
		{"TTPsForGroup", func() { ontologySink += e.TTPsForGroup(group, bufT) }},
		{"TTPsForGroupRollup", func() {
			ontologySink += e.TTPsForGroupRollup(group, scratchT, bufT)
		}},
		{"GroupsForTTP", func() { ontologySink += e.GroupsForTTP(t1003, bufG) }},
		{"SoftwareForGroup", func() { ontologySink += e.SoftwareForGroup(group, bufG) }},
		{"GroupsForSoftware", func() { ontologySink += e.GroupsForSoftware(soft, bufG) }},
		{"SoftwareDegree", func() { ontologySink += e.SoftwareDegree(group) }},
		{"TTPParent", func() {
			if _, ok := e.TTPParent(t1003a); ok {
				ontologySink++
			}
		}},
		{"TTPChildCount", func() { ontologySink += e.TTPChildCount(t1003) }},
		{"TTPChildren", func() { ontologySink += e.TTPChildren(t1003, bufT) }},
		{"RelName", func() {
			if e.RelName(gr4ph.RelAny) != "" {
				ontologySink++
			}
		}},
		{"DefRelName", func() {
			if e.DefRelName(gr4ph.DefRelAny) != "" {
				ontologySink++
			}
		}},
	}
	names := make([]string, len(cases))
	for i, c := range cases {
		names[i] = c.name
	}
	if !slices.Equal(names, hotmethods.Names) {
		t.Fatalf("hot-method cases = %v, want %v (internal/hotmethods)", names, hotmethods.Names)
	}
	for _, c := range cases {
		if n := testing.AllocsPerRun(50, c.fn); n != 0 {
			t.Errorf("%s: %v allocs/op, want 0", c.name, n)
		}
	}
}

func BenchmarkOntologyTTPsRel(b *testing.B) {
	e := build(b)
	a := art(b, e, "Process")
	r := rel(b, e, "accesses")
	dst := make([]gr4ph.TTP, e.TTPCount())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ontologySink += e.TTPsRel(a, r, dst)
	}
}

func BenchmarkOntologyTTPsAnyProcessFile(b *testing.B) {
	e := build(b)
	scratch := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	dst := make([]gr4ph.TTP, e.TTPCount())
	arts := []gr4ph.Artifact{art(b, e, "Process"), art(b, e, "File")}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ontologySink += e.TTPsAny(gr4ph.RelAny, scratch, dst, arts)
	}
}

func BenchmarkOntologyCountermeasuresForArtifactViaTTPs(b *testing.B) {
	e := build(b)
	scratch := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	dst := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	a := art(b, e, "Process")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ontologySink += e.CountermeasuresForArtifactViaTTPs(a, scratch, dst)
	}
}

func BenchmarkOntologyCountermeasuresForTTPRollup(b *testing.B) {
	e := build(b)
	scratch := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	dst := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	tp := ttp(b, e, "T1546")
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		ontologySink += e.CountermeasuresForTTPRollup(tp, scratch, dst)
	}
}

// TestOntologyAttributes pins the new partitions on the real tables: the
// attribute masks, the two new partitions and the grouping family, each against
// a literal re-measured from the committed generated file (not from the plan).
func TestOntologyAttributes(t *testing.T) {
	e := build(t)
	t1003 := ttp(t, e, "T1003")
	t1003a := ttp(t, e, "T1003.001")
	t1059 := ttp(t, e, "T1059")
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))

	// Attribute masks. A D3FEND-named node has no ATT&CK object, so both masks
	// are 0 while a STIX technique's are not.
	if e.TTPTactics(t1003) == 0 {
		t.Error("TTPTactics(T1003) = 0, want the Credential Access bit")
	}
	tac := ta(t, e, "TA0006")
	if got := e.TTPTactics(t1003); got != 1<<uint(tac) {
		t.Errorf("TTPTactics(T1003) = %#b, want only bit %d (TA0006)", got, tac)
	}
	de := ttp(t, e, "DE-0006")
	if got := e.TTPTactics(de); got != 0 {
		t.Errorf("TTPTactics(DE-0006) = %#b, want 0 (D3FEND-named node)", got)
	}
	if got := e.TTPPlatforms(de); got != 0 {
		t.Errorf("TTPPlatforms(DE-0006) = %#b, want 0", got)
	}
	if got := e.TTPFlags(t1003); got != 0 {
		t.Errorf("TTPFlags(T1003) = %#b, want 0 (top-level)", got)
	}
	if got := e.TTPFlags(t1003a); got != gr4ph.FlagSubTechnique {
		t.Errorf("TTPFlags(T1003.001) = %#b, want FlagSubTechnique", got)
	}
	if !e.TTPSubTechnique(t1003a) || e.TTPSubTechnique(t1003) {
		t.Error("TTPSubTechnique(T1003.001/T1003) = true/false expected")
	}

	// T1003 platforms: Linux, Windows, macOS (in vocabulary order).
	var got []string
	mask := e.TTPPlatforms(t1003)
	for i := 0; i < e.PlatformCount(); i++ {
		if mask&(1<<uint(i)) != 0 {
			got = append(got, e.PlatformName(gr4ph.Platform(i)))
		}
	}
	if s := strings.Join(got, ","); s != "Linux,Windows,macOS" {
		t.Errorf("TTPPlatforms(T1003) names = %q, want Linux,Windows,macOS", s)
	}
	// T1546.008 sits in two tactics (TA0003, TA0004), on Windows.
	t1546 := ttp(t, e, "T1546.008")
	mask = e.TTPTactics(t1546)
	if mask&(1<<uint(ta(t, e, "TA0003"))) == 0 || mask&(1<<uint(ta(t, e, "TA0004"))) == 0 {
		t.Errorf("TTPTactics(T1546.008) = %#b, want TA0003 and TA0004", mask)
	}

	// Reverse rows: the tactic vocabulary is indexed by TA id, so the row of
	// TA0005 has 212 techniques.
	dstT := make([]gr4ph.TTP, e.TTPCount())
	if n := e.TTPsForTactic(ta(t, e, "TA0005"), dstT); n != 212 {
		t.Errorf("TTPsForTactic(TA0005) = %d, want 212", n)
	}
	if n := e.TTPsForPlatform(pf(t, e, "Windows"), dstT); n != 591 {
		t.Errorf("TTPsForPlatform(Windows) = %d, want 591", n)
	}
	// T1059 is the widest platform row: 10 of the 15 names.
	if n := bits.OnesCount64(e.TTPPlatforms(t1059)); n != 10 {
		t.Errorf("popcount(TTPPlatforms(T1059)) = %d, want 10", n)
	}
	// A platform name ATT&CK defines but no technique in the table carries is
	// not in the vocabulary: the emitted names come from the techniques.
	if _, ok := e.Platform("Data Historian"); ok {
		t.Error("Platform(Data Historian) resolved: only used names are emitted")
	}

	// Data components: DC0084 detects 9 techniques (its own row), and the
	// roll-up is the one traversal that must union child rows.
	dcProcess := dc(t, e, "DC0084")
	if n := e.TTPsForDataComponent(dcProcess, dstT); n != 9 {
		t.Errorf("TTPsForDataComponent(DC0084) = %d, want 9", n)
	}
	if got := e.DataComponentDegree(dcProcess); got != 9 {
		t.Errorf("DataComponentDegree(DC0084) = %d, want 9", got)
	}
	dstD := make([]gr4ph.DataComponent, e.DataComponentCount())
	scratchD := make([]uint64, e.WordsPerRow(gr4ph.KindDataComponent))
	if n := e.DataComponentsForTTP(t1003a, dstD); n != 5 {
		t.Errorf("DataComponentsForTTP(T1003.001) = %d, want 5", n)
	}
	// The parent has its own detections (5) and 8 children: the roll-up is the
	// union, 13, strictly larger than the exact answer.
	if n := e.DataComponentsForTTP(t1003, dstD); n != 5 {
		t.Errorf("DataComponentsForTTP(T1003) = %d, want 5", n)
	}
	if n := e.DataComponentsForTTPRollup(t1003, scratchD, dstD); n != 13 {
		t.Errorf("DataComponentsForTTPRollup(T1003) = %d, want 13", n)
	}

	// Grouping partition: one partition, three kinds, both directions.
	actor := g(t, e, "G0007")
	if k := e.GroupKind(actor); k != gr4ph.GroupActor {
		t.Errorf("GroupKind(G0007) = %v, want GroupActor", k)
	}
	if n := e.TTPsForGroup(actor, dstT); n != 93 {
		t.Errorf("TTPsForGroup(G0007) = %d, want 93", n)
	}
	dstG := make([]gr4ph.Group, e.GroupCount())
	if n := e.SoftwareForGroup(actor, dstG); n != 30 {
		t.Errorf("SoftwareForGroup(G0007) = %d, want 30", n)
	}
	if n := e.TTPsForGroupRollup(actor, scratchT, dstT); n != 73 {
		t.Errorf("TTPsForGroupRollup(G0007) = %d, want 73 (sub-techniques collapse onto parents)", n)
	}
	software := g(t, e, "S0002")
	if k := e.GroupKind(software); k != gr4ph.GroupSoftware {
		t.Errorf("GroupKind(S0002) = %v, want GroupSoftware", k)
	}
	if n := e.TTPsForGroup(software, dstT); n != 17 {
		t.Errorf("TTPsForGroup(S0002) = %d, want 17", n)
	}
	if n := e.GroupsForSoftware(software, dstG); n != 60 {
		t.Errorf("GroupsForSoftware(S0002) = %d, want 60", n)
	}
	if n := e.SoftwareForGroup(software, dstG); n != 0 {
		t.Errorf("SoftwareForGroup(S0002) = %d, want 0", n)
	}

	// The whole vocabulary is represented: every row is non-empty, and the
	// assignment totals are the pinned 1431/2527.
	tsum, psum := 0, 0
	for i, row := range TacticTTP {
		tsum += len(row)
		if len(row) == 0 {
			t.Errorf("TacticTTP[%d] (%s) is empty", i, e.TacticID(gr4ph.Tactic(i)))
		}
	}
	for i, row := range PlatformTTP {
		psum += len(row)
		if len(row) == 0 {
			t.Errorf("PlatformTTP[%d] (%s) is empty", i, e.PlatformName(gr4ph.Platform(i)))
		}
	}
	if tsum != 1431 || psum != 2527 {
		t.Errorf("assignment totals = %d/%d, want 1431/2527", tsum, psum)
	}
	// The two directions are materialized from one edge list, so the tactic
	// masks and the reverse rows must agree exactly over the whole space.
	for i := 0; i < e.TacticCount(); i++ {
		tac := gr4ph.Tactic(i)
		bit := uint64(1) << uint(i)
		n := e.TTPsForTactic(tac, dstT)
		for _, tt := range dstT[:n] {
			if e.TTPTactics(tt)&bit == 0 {
				t.Fatalf("TTPsForTactic(%s) lists %s whose mask lacks the bit", e.TacticID(tac), e.TTPName(tt))
			}
		}
		sum := 0
		for j := 0; j < e.TTPCount(); j++ {
			if e.TTPTactics(gr4ph.TTP(j))&bit != 0 {
				sum++
			}
		}
		if sum != n {
			t.Fatalf("tactic %s: %d masks carry the bit, the reverse row holds %d", e.TacticID(tac), sum, n)
		}
	}

	// The same two-direction agreement for the other four pairs: each is
	// materialized from one edge list, so a transposed or mis-strided row would
	// leave a carrier count and a reverse row disagreeing.
	for i := 0; i < e.PlatformCount(); i++ {
		p := gr4ph.Platform(i)
		bit := uint64(1) << uint(i)
		n := e.TTPsForPlatform(p, dstT)
		for _, tt := range dstT[:n] {
			if e.TTPPlatforms(tt)&bit == 0 {
				t.Fatalf("TTPsForPlatform(%s) lists %s whose mask lacks the bit", e.PlatformName(p), e.TTPName(tt))
			}
		}
		sum := 0
		for j := 0; j < e.TTPCount(); j++ {
			if e.TTPPlatforms(gr4ph.TTP(j))&bit != 0 {
				sum++
			}
		}
		if sum != n {
			t.Fatalf("platform %s: %d masks carry the bit, the reverse row holds %d", e.PlatformName(p), sum, n)
		}
	}
	for i := 0; i < e.DataComponentCount(); i++ {
		d := gr4ph.DataComponent(i)
		n := e.TTPsForDataComponent(d, dstT)
		for _, tt := range dstT[:n] {
			found := false
			for _, got := range dstD[:e.DataComponentsForTTP(tt, dstD)] {
				if got == d {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("TTPsForDataComponent(%s) lists %s whose row lacks it", e.DataComponentID(d), e.TTPName(tt))
			}
		}
		sum := 0
		for j := 0; j < e.TTPCount(); j++ {
			for _, got := range dstD[:e.DataComponentsForTTP(gr4ph.TTP(j), dstD)] {
				if got == d {
					sum++
					break
				}
			}
		}
		if sum != n {
			t.Fatalf("data component %s: %d rows carry it, the reverse row holds %d", e.DataComponentID(d), sum, n)
		}
	}
	for i := 0; i < e.GroupCount(); i++ {
		grp := gr4ph.Group(i)
		// technique -> group and group -> technique must agree.
		used := e.TTPsForGroup(grp, dstT)
		for _, tt := range dstT[:used] {
			found := false
			for _, got := range dstG[:e.GroupsForTTP(tt, dstG)] {
				if got == grp {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("TTPsForGroup(%s) lists %s whose row lacks it", e.GroupID(grp), e.TTPName(tt))
			}
		}
		sum := 0
		for j := 0; j < e.TTPCount(); j++ {
			for _, got := range dstG[:e.GroupsForTTP(gr4ph.TTP(j), dstG)] {
				if got == grp {
					sum++
					break
				}
			}
		}
		if sum != used {
			t.Fatalf("group %s: %d rows carry it, the reverse row holds %d", e.GroupID(grp), sum, used)
		}
	}
	// dstSw is separate from dstG: the inner reverse lookup overwrites its
	// buffer, and the outer loop is iterating the other one.
	dstSw := make([]gr4ph.Group, e.GroupCount())
	for i := 0; i < e.GroupCount(); i++ {
		grp := gr4ph.Group(i)
		n := e.SoftwareForGroup(grp, dstG)
		for _, sw := range dstG[:n] {
			found := false
			for _, got := range dstSw[:e.GroupsForSoftware(sw, dstSw)] {
				if got == grp {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("SoftwareForGroup(%s) lists %s whose row lacks it", e.GroupID(grp), e.GroupID(sw))
			}
		}
		sum := 0
		for j := 0; j < e.GroupCount(); j++ {
			for _, got := range dstSw[:e.GroupsForSoftware(gr4ph.Group(j), dstSw)] {
				if got == grp {
					sum++
					break
				}
			}
		}
		if sum != n {
			t.Fatalf("group %s: %d software rows carry it, the reverse row holds %d", e.GroupID(grp), sum, n)
		}
	}

	// The committed GroupKinds array is index-parallel to GroupIDs: the kind of
	// every node must agree with its id prefix, and the histogram is the pinned
	// 195/957/60. (No offline check saw this before: the generator's histogram
	// gate only runs under `make gen`.)
	kindOf := map[byte]gr4ph.GroupKind{
		'C': gr4ph.GroupCampaign,
		'G': gr4ph.GroupActor,
		'S': gr4ph.GroupSoftware,
	}
	kindHist := map[gr4ph.GroupKind]int{}
	for i := range NGroup {
		id := GroupIDs[i]
		want, ok := kindOf[id[0]]
		if !ok {
			t.Fatalf("group id %s has no kind prefix", id)
		}
		got := e.GroupKind(gr4ph.Group(i))
		if got != want {
			t.Fatalf("GroupKind(%s) = %v, want %v", id, got, want)
		}
		kindHist[got]++
	}
	if a, s, c := kindHist[gr4ph.GroupActor], kindHist[gr4ph.GroupSoftware], kindHist[gr4ph.GroupCampaign]; a != 195 || s != 957 || c != 60 {
		t.Fatalf("group kind histogram = %d/%d/%d (actors/software/campaigns), want 195/957/60", a, s, c)
	}

	// The detects fold, by membership: the 9 techniques of DC0084 as a literal,
	// ascending. A count-only pin would keep a same-length mis-pairing.
	dc84 := dc(t, e, "DC0084")
	ndc := e.TTPsForDataComponent(dc84, dstT)
	names := make([]string, 0, ndc)
	for _, tt := range dstT[:ndc] {
		names = append(names, e.TTPName(tt))
	}
	wantTTPs := "T1207,T1550.002,T1550.003,T1558,T1558.001,T1558.002,T1558.003,T1558.004,T1649"
	if strings.Join(names, ",") != wantTTPs {
		t.Fatalf("TTPsForDataComponent(DC0084) = %v, want %s", names, wantTTPs)
	}
}

// TestOntologyKEV pins the weakness and product families on the real tables:
// the row and column sums of both matrices, the per-class counts of the
// best-populated weaknesses, the Log4j golden and the reverse resolvers. Every
// literal is re-measured from the committed ontology, not copied from a plan.
func TestOntologyKEV(t *testing.T) {
	e := build(t)
	if len(KEVWeaknessKEV) != NKEVCWE || len(KEVWeaknessCWE) != NKEVCWE {
		t.Fatalf("weakness edge arrays = %d/%d, want %d", len(KEVWeaknessKEV), len(KEVWeaknessCWE), NKEVCWE)
	}
	if len(KEVProductIndex) != NKEV {
		t.Fatalf("KEVProductIndex = %d, want %d", len(KEVProductIndex), NKEV)
	}

	// The weakness matrix: 1679 edges over 1564 of the 1739 entries, at most 4
	// per entry, and no entry names a weakness twice.
	dstCWE := make([]gr4ph.CWE, e.CWECount())
	degSum, withCWE, maxDeg, ransom := 0, 0, 0, 0
	for i := range e.KEVCount() {
		k := gr4ph.KEV(i)
		d := e.KEVCWEDegree(k)
		degSum += d
		if d > 0 {
			withCWE++
		}
		if d > maxDeg {
			maxDeg = d
		}
		if e.KEVRansomware(k) {
			ransom++
		}
	}
	if degSum != NKEVCWE {
		t.Errorf("weakness edges = %d, want %d", degSum, NKEVCWE)
	}
	if withCWE != NKEVWithCWE {
		t.Errorf("entries naming a weakness = %d, want %d", withCWE, NKEVWithCWE)
	}
	if maxDeg != 4 {
		t.Errorf("max weakness degree = %d, want 4", maxDeg)
	}
	if ransom != NKEVRansomware {
		t.Errorf("ransomware entries = %d, want %d", ransom, NKEVRansomware)
	}
	if n := e.CWEsForKEV(gr4ph.KEV(0), nil); n != e.KEVCWEDegree(gr4ph.KEV(0)) {
		t.Errorf("CWEsForKEV(0) = %d but KEVCWEDegree(0) = %d", n, e.KEVCWEDegree(gr4ph.KEV(0)))
	}

	// The transpose: the column sums are the row sums, every class is
	// referenced at least once, and every id is in range.
	dstK := make([]gr4ph.KEV, e.KEVCount())
	colSum := 0
	minCol := 1 << 30
	for i := range e.CWECount() {
		n := e.KEVsForCWE(gr4ph.CWE(i), dstK)
		colSum += n
		minCol = min(minCol, n)
		for _, k := range dstK[:n] {
			if int(k) >= e.KEVCount() {
				t.Fatalf("KEVsForCWE(%s) returned out-of-range entry %d", e.CWEID(gr4ph.CWE(i)), k)
			}
		}
	}
	if colSum != degSum {
		t.Errorf("weakness column sum = %d, want %d", colSum, degSum)
	}
	if minCol < 1 {
		t.Errorf("some weakness class has no entries")
	}

	// One product edge per entry, and the per-class counts of the largest
	// weaknesses.
	prodEdges := 0
	for i := range e.KEVCount() {
		prodEdges += e.ProductsForKEV(gr4ph.KEV(i), nil)
	}
	if prodEdges != NKEV {
		t.Errorf("product edges = %d, want %d", prodEdges, NKEV)
	}
	for _, c := range []struct {
		id   string
		want int
	}{
		{"CWE-20", 119},
		{"CWE-78", 110},
		{"CWE-787", 105},
		{"CWE-416", 93},
		{"CWE-119", 88},
		{"CWE-22", 81},
		{"CWE-502", 71},
		{"CWE-94", 71},
		{"CWE-79", 33},
		{"CWE-89", 32},
		{"CWE-400", 5},
	} {
		if got := e.KEVsForCWE(cwe(t, e, c.id), nil); got != c.want {
			t.Errorf("KEVsForCWE(%s) = %d, want %d", c.id, got, c.want)
		}
	}

	// The union over a weakness selection: the classes of the Log4j entry
	// overlap, so the union is smaller than the 195 ids their columns sum to;
	// the three best-populated classes happen to be disjoint, so there the
	// union equals the sum.
	sel := make([]uint64, e.WordsPerRow(gr4ph.KindCWE))
	scratch := make([]uint64, e.WordsPerRow(gr4ph.KindKEV))
	union := func(ids ...string) (int, int) {
		for i := range sel {
			sel[i] = 0
		}
		sum := 0
		for _, id := range ids {
			c := cwe(t, e, id)
			setSel(sel, int(c))
			sum += e.KEVsForCWE(c, nil)
		}
		n := e.KEVsForCWEs(sel, scratch, dstK)
		for i := 1; i < n; i++ {
			if dstK[i-1] >= dstK[i] {
				t.Fatalf("union of %v is not ascending or has duplicates: %v", ids, dstK[:n])
			}
		}
		return n, sum
	}
	if n, sum := union("CWE-79", "CWE-89", "CWE-78"); n != 175 || sum != 175 {
		t.Errorf("union of the top three classes = %d of %d ids, want 175 (disjoint)", n, sum)
	}
	if n, sum := union("CWE-20", "CWE-400", "CWE-502"); n != 191 || sum != 195 {
		t.Errorf("union of the Log4j classes = %d of %d ids, want 191 of 195", n, sum)
	}

	// The Log4j golden: its CVE record, the three weaknesses it names and the
	// product it is filed under, seen from both directions.
	log4j := kev(t, e, "CVE-2021-44228")
	if got := e.KEVName(log4j); got != "Apache Log4j2 Remote Code Execution Vulnerability" {
		t.Errorf("Log4j name = %q", got)
	}
	ndc := e.CWEsForKEV(log4j, dstCWE)
	names := make([]string, 0, ndc)
	for _, c := range dstCWE[:ndc] {
		names = append(names, e.CWEID(c))
	}
	if want := "CWE-20,CWE-400,CWE-502"; strings.Join(names, ",") != want {
		t.Errorf("Log4j weaknesses = %v, want %s", names, want)
	}
	log4jProduct := prod(t, e, "Apache", "Log4j2")
	if n := e.ProductsForKEV(log4j, make([]gr4ph.Product, 1)); n != 1 {
		t.Errorf("Log4j products = %d, want 1", n)
	}
	dstP := make([]gr4ph.Product, 4)
	np := e.ProductsForKEV(log4j, dstP)
	if np != 1 || dstP[0] != log4jProduct {
		t.Errorf("ProductsForKEV(Log4j) = %d %v, want 1 [%d]", np, dstP[:np], log4jProduct)
	}
	selP := make([]uint64, e.WordsPerRow(gr4ph.KindProduct))
	setSel(selP, int(log4jProduct))
	nk := e.KEVsForProducts(selP, scratch, dstK)
	if nk != 2 {
		t.Fatalf("KEVsForProducts(Apache/Log4j2) = %d, want 2", nk)
	}
	if !slices.Contains(dstK[:nk], log4j) {
		t.Errorf("KEVsForProducts(Apache/Log4j2) = %v, want it to contain %d", dstK[:nk], log4j)
	}

	// The reverse resolvers round-trip over the whole vocabulary.
	for i := range e.KEVCount() {
		k := gr4ph.KEV(i)
		if id := e.KEVID(k); id == "" {
			t.Fatalf("entry %d has no id", i)
		} else if got, ok := e.KEV(id); !ok || got != k {
			t.Fatalf("KEV(%q) = %d,%v, want %d,true", id, got, ok, k)
		}
		if e.CWEsForKEV(k, dstCWE) != e.KEVCWEDegree(k) {
			t.Fatalf("entry %s: degree disagrees with the row", e.KEVID(k))
		}
	}
	for i := range e.CWECount() {
		c := gr4ph.CWE(i)
		if got, ok := e.CWE(e.CWEID(c)); !ok || got != c {
			t.Fatalf("CWE(%q) = %d,%v, want %d,true", e.CWEID(c), got, ok, c)
		}
	}
	for i := range e.ProductCount() {
		p := gr4ph.Product(i)
		key := e.KEVProductVendor(p) + "/" + e.KEVProductName(p)
		if got, ok := e.Product(e.KEVProductVendor(p), e.KEVProductName(p)); !ok || got != p {
			t.Fatalf("Product(%q) = %d,%v, want %d,true", key, got, ok, p)
		}
	}
}

// TestOntologyCoverage pins the overlay queries on the real tables: the mapped
// range, the blind set of a full deployment, the marginal gain of the two
// strongest candidates and the mitigation set of one alert. Every literal is
// re-measured from the committed ontology, not copied from the plan.
func TestOntologyCoverage(t *testing.T) {
	e := build(t)
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	scratchC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	dstT := make([]gr4ph.TTP, e.TTPCount())
	dstC := make([]gr4ph.Countermeasure, e.CountermeasureCount())

	allTTP := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	for i := range e.TTPCount() {
		setSel(allTTP, i)
	}
	allCM := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	for i := range e.CountermeasureCount() {
		setSel(allCM, i)
	}
	emptyCM := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))

	if mapped := e.TTPsMapped(scratchT, dstT); mapped != 427 {
		t.Errorf("TTPsMapped = %d, want 427", mapped)
	}
	if covered := e.TTPsCovered(allCM, scratchT, dstT); covered != 427 {
		t.Errorf("TTPsCovered(all countermeasures) = %d, want 427 (the mapped range)", covered)
	}
	if blind := e.TTPsBlind(allTTP, allCM, scratchT, dstT); blind != 759 {
		t.Errorf("TTPsBlind(all active, all countermeasures) = %d, want 759 (1186-427)", blind)
	}

	quarantine, ok := e.Countermeasure("ContentQuarantine")
	if !ok {
		t.Fatal("no such countermeasure ContentQuarantine")
	}
	filtering, ok := e.Countermeasure("NetworkTrafficFiltering")
	if !ok {
		t.Fatal("no such countermeasure NetworkTrafficFiltering")
	}
	if got := e.CoverageGain(quarantine, emptyCM, scratchT); got != 119 {
		t.Errorf("CoverageGain(ContentQuarantine, nothing) = %d, want 119 (its live techniques)", got)
	}
	quarantineSel := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	setSel(quarantineSel, int(quarantine))
	if got := e.CoverageGain(filtering, quarantineSel, scratchT); got != 101 {
		t.Errorf("CoverageGain(NetworkTrafficFiltering, ContentQuarantine) = %d, want 101", got)
	}
	// The retired mask is what makes those two numbers smaller than the 125 and
	// 107 the same deployment reads without it: the difference is the flagged
	// techniques the countermeasures also defend, and CoverageGain must not
	// credit a candidate for one.
	if got := e.CountermeasureDegree(quarantine); got != 125 {
		t.Errorf("CountermeasureDegree(ContentQuarantine) = %d, want 125 (the row itself is unmasked)", got)
	}
	if got := e.CoverageGain(filtering, emptyCM, scratchT); got != 115 {
		t.Errorf("CoverageGain(NetworkTrafficFiltering, nothing) = %d, want 115", got)
	}
	// The bulk scan agrees with the single-candidate primitive on every
	// countermeasure, and reports the same best buy the documented `gain
	// -greedy ContentQuarantine` example starts with.
	gains := make([]int, e.CountermeasureCount())
	n := e.CoverageGains(quarantineSel, scratchT, gains)
	positive, best, bestGain := 0, -1, 0
	for i := range e.CountermeasureCount() {
		want := e.CoverageGain(gr4ph.Countermeasure(i), quarantineSel, scratchT)
		if gains[i] != want {
			t.Errorf("CoverageGains[%d] over ContentQuarantine = %d, CoverageGain = %d", i, gains[i], want)
		}
		if want > 0 {
			positive++
		}
		if want > bestGain {
			best, bestGain = i, want
		}
	}
	if n != positive {
		t.Errorf("CoverageGains reported %d positive gains, want %d", n, positive)
	}
	if gr4ph.Countermeasure(best) != filtering || bestGain != 101 {
		t.Errorf("the best buy after ContentQuarantine is %s at %d, want NetworkTrafficFiltering at 101",
			e.CountermeasureName(gr4ph.Countermeasure(best)), bestGain)
	}

	observed := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	setSel(observed, int(ttp(t, e, "T1003.001")))
	if got := e.CountermeasuresForObserved(observed, scratchC, dstC); got != 12 {
		t.Errorf("CountermeasuresForObserved(T1003.001) = %d, want 12", got)
	}
}
