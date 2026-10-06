//go:build goexperiment.simd

package ontology

import (
	"errors"
	"testing"

	"github.com/fr0g-66723067/gr4ph"
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

func rel(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.Rel {
	tb.Helper()
	r, ok := e.Rel(name)
	if !ok {
		tb.Fatalf("unknown relation %q", name)
	}
	return r
}

func defRel(tb testing.TB, e *gr4ph.Engine, name string) gr4ph.DefRel {
	tb.Helper()
	r, ok := e.DefRel(name)
	if !ok {
		tb.Fatalf("unknown defensive relation %q", name)
	}
	return r
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
	if _, err := b3.AddTTP("T1", "one", gr4ph.DomainEnterprise, gr4ph.NoParent); err != nil {
		t.Fatalf("AddTTP: %v", err)
	}
	if err := Register(b3); !errors.Is(err, ErrBuilderNotEmpty) {
		t.Fatalf("Register after AddTTP = %v, want ErrBuilderNotEmpty", err)
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

func TestOntologyColdPath(t *testing.T) {
	e := build(t)

	// Normalisation: id, label and alias are all keys, trimmed and
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
	for i := range e.TTPCount() {
		if e.Degree(gr4ph.TTP(i), gr4ph.RelAny) == 0 {
			degreeZero++
		}
	}
	if degreeZero != 759 {
		t.Fatalf("degree-0 techniques = %d, want 759", degreeZero)
	}
}

// ontologySink defeats dead-code elimination without allocating.
var ontologySink int

// TestZeroAllocOntology repeats the allocation contract against the real
// engine: 1186x247x157 with 19/4/3-word rows must not allocate either. Every
// result is folded into ontologySink, so an inlined pure call cannot be
// optimised away, and the case count is pinned to the root package's.
func TestZeroAllocOntology(t *testing.T) {
	e := build(t)
	bufT := make([]gr4ph.TTP, e.TTPCount())
	bufA := make([]gr4ph.Artifact, e.ArtifactCount())
	bufC := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	scratchA := make([]uint64, e.WordsPerRow(gr4ph.KindArtifact))
	scratchC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	process := art(t, e, "Process")
	t1003 := ttp(t, e, "T1003")
	t1003a := ttp(t, e, "T1003.001")
	cm0 := cm(t, e, "CredentialHardening")
	accesses := rel(t, e, "accesses")
	arts := []gr4ph.Artifact{process, art(t, e, "File")}
	ttps := []gr4ph.TTP{t1003, t1003a}

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
	}
	if len(cases) != 29 {
		t.Fatalf("hot-method coverage = %d cases, want 29 (same set as the root package)", len(cases))
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
