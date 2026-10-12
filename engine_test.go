//go:build goexperiment.simd

package gr4ph

import "testing"

// Synthetic graph used by every engine test:
//
//	TTP 0 T1003        children 1,2         TTP 3 T1059   child 4
//	TTP 1 T1003.001    TTP 2 T1003.002      TTP 4 T1059.001
//	TTP 5 T1547 (top-level)
//
//	Artifact 0 Process   1 File   2 Credential   3 NetworkTraffic
//	Rel      1 accesses  2 modifies  3 creates
//	DefRel   1 hardens   2 analyzes
//	CM       0 (analyzes Process, File; defends T1003.001, T1059.001)
//	CM       1 (hardens Credential; defends T1003, T1003.002)
//
// Offensive edges:
//
//	1 -> 0 accesses        1 -> 0 modifies       0 -> 2 accesses
//	4 -> 1 creates         3 -> 1 creates        5 -> 0 modifies
//	2 -> 3 accesses
//
// Defensive edges:
//
//	cm0 -> 0 analyzes      cm0 -> 1 analyzes     cm1 -> 2 hardens
func buildSynthetic(t *testing.T) *Engine {
	t.Helper()
	b := NewBuilder()

	ttp := func(id, label string, parent TTP) TTP {
		t.Helper()
		v, err := b.AddTTP(id, label, DomainEnterprise, parent, false)
		if err != nil {
			t.Fatalf("AddTTP(%s): %v", id, err)
		}
		return v
	}
	t1003 := ttp("T1003", "OS Credential Dumping", NoParent)
	t1003a := ttp("T1003.001", "LSASS Memory", t1003)
	t1003b := ttp("T1003.002", "Security Account Manager", t1003)
	t1059 := ttp("T1059", "Command and Scripting Interpreter", NoParent)
	t1059a := ttp("T1059.001", "PowerShell", t1059)
	t1547 := ttp("T1547", "Boot or Logon Autostart Execution", NoParent)

	art := func(name string) Artifact {
		t.Helper()
		v, err := b.AddArtifact(name, name+" Artifact")
		if err != nil {
			t.Fatalf("AddArtifact(%s): %v", name, err)
		}
		return v
	}
	process := art("Process")
	file := art("File")
	cred := art("Credential")
	traffic := art("NetworkTraffic")

	cm := func(id string) Countermeasure {
		t.Helper()
		v, err := b.AddCountermeasure(id, id+" Label")
		if err != nil {
			t.Fatalf("AddCountermeasure(%s): %v", id, err)
		}
		return v
	}
	cm0 := cm("ProcessIsolation")
	cm1 := cm("CredentialHardening")

	rel := func(name string) Rel {
		t.Helper()
		v, err := b.AddRel(name)
		if err != nil {
			t.Fatalf("AddRel(%s): %v", name, err)
		}
		return v
	}
	accesses := rel("accesses")
	modifies := rel("modifies")
	creates := rel("creates")

	defrel := func(name string) DefRel {
		t.Helper()
		v, err := b.AddDefRel(name)
		if err != nil {
			t.Fatalf("AddDefRel(%s): %v", name, err)
		}
		return v
	}
	hardens := defrel("hardens")
	analyzes := defrel("analyzes")

	edges := []struct {
		t TTP
		a Artifact
		r Rel
	}{
		{t1003a, process, accesses},
		{t1003a, process, modifies},
		{t1003, cred, accesses},
		{t1059a, file, creates},
		{t1059, file, creates},
		{t1547, process, modifies},
		{t1003b, traffic, accesses},
	}
	for _, e := range edges {
		if err := b.AddEdge(e.t, e.a, e.r); err != nil {
			t.Fatalf("AddEdge(%d,%d,%d): %v", e.t, e.a, e.r, err)
		}
	}

	defEdges := []struct {
		cm Countermeasure
		a  Artifact
		dr DefRel
	}{
		{cm0, process, analyzes},
		{cm0, file, analyzes},
		{cm1, cred, hardens},
	}
	for _, e := range defEdges {
		if err := b.AddDefEdge(e.cm, e.a, e.dr); err != nil {
			t.Fatalf("AddDefEdge: %v", err)
		}
	}

	defends := []struct {
		cm Countermeasure
		t  TTP
	}{
		{cm0, t1003a},
		{cm0, t1059a},
		{cm1, t1003},
		{cm1, t1003b},
	}
	for _, d := range defends {
		if err := b.AddDefendsEdge(d.cm, d.t); err != nil {
			t.Fatalf("AddDefendsEdge: %v", err)
		}
	}

	// Attribute vocabularies: tactic 0 Initial Access, tactic 1 Execution;
	// platform 0 Windows, platform 1 Linux.
	tactic := func(id, label string) Tactic {
		t.Helper()
		v, err := b.AddTactic(id, label)
		if err != nil {
			t.Fatalf("AddTactic(%s): %v", id, err)
		}
		return v
	}
	ta1 := tactic("TA0001", "Initial Access")
	ta2 := tactic("TA0002", "Execution")
	platform := func(name string) Platform {
		t.Helper()
		v, err := b.AddPlatform(name)
		if err != nil {
			t.Fatalf("AddPlatform(%s): %v", name, err)
		}
		return v
	}
	windows := platform("Windows")
	linux := platform("Linux")

	// Data components: DC0001 detects T1003.001 only (so the parent's own row
	// is empty and its roll-up picks the component up); DC0002 has no edge.
	dc := func(id, label string) DataComponent {
		t.Helper()
		v, err := b.AddDataComponent(id, label)
		if err != nil {
			t.Fatalf("AddDataComponent(%s): %v", id, err)
		}
		return v
	}
	dcProcess := dc("DC0001", "Process Creation")
	dc("DC0002", "File Creation") // registered, deliberately edge-less

	// Grouping nodes: one actor, one software, one campaign.
	group := func(id, label string, kind GroupKind) Group {
		t.Helper()
		v, err := b.AddGroup(id, label, kind)
		if err != nil {
			t.Fatalf("AddGroup(%s): %v", id, err)
		}
		return v
	}
	actor := group("G0001", "Actor One", GroupActor)
	software := group("S0001", "Software One", GroupSoftware)
	campaign := group("C0001", "Campaign One", GroupCampaign)

	for _, a := range []struct {
		t  TTP
		ta Tactic
	}{
		{t1003, ta1},
		{t1003a, ta2},
	} {
		if err := b.AddTacticEdge(a.t, a.ta); err != nil {
			t.Fatalf("AddTacticEdge: %v", err)
		}
	}
	for _, a := range []struct {
		t TTP
		p Platform
	}{
		{t1003, windows},
		{t1003, linux},
		{t1003a, windows},
	} {
		if err := b.AddPlatformEdge(a.t, a.p); err != nil {
			t.Fatalf("AddPlatformEdge: %v", err)
		}
	}
	if err := b.AddDetectsEdge(dcProcess, t1003a); err != nil {
		t.Fatalf("AddDetectsEdge: %v", err)
	}
	for _, u := range []struct {
		g Group
		t TTP
	}{
		{actor, t1003},
		{actor, t1003a},
		{campaign, t1059},
	} {
		if err := b.AddGroupUsesEdge(u.g, u.t); err != nil {
			t.Fatalf("AddGroupUsesEdge: %v", err)
		}
	}
	if err := b.AddGroupSoftwareEdge(actor, software); err != nil {
		t.Fatalf("AddGroupSoftwareEdge: %v", err)
	}

	// The KEV partition: two entries, two weaknesses and two products, with the
	// edges chosen so every direction of both families is non-empty (entry 0
	// names both weaknesses, entry 1 only the second; each product has exactly
	// one entry).
	cwe := func(id string) CWE {
		t.Helper()
		v, err := b.AddCWE(id, id)
		if err != nil {
			t.Fatalf("AddCWE(%s): %v", id, err)
		}
		return v
	}
	cwe20 := cwe("CWE-20")
	cwe502 := cwe("CWE-502")
	product := func(vendor, name string) Product {
		t.Helper()
		v, err := b.AddProduct(vendor, name)
		if err != nil {
			t.Fatalf("AddProduct(%s/%s): %v", vendor, name, err)
		}
		return v
	}
	alpha := product("Avendor", "Alpha")
	beta := product("Bvendor", "Beta")
	kev := func(id, name, added string, ransomware bool) KEV {
		t.Helper()
		v, err := b.AddKEV(id, name, added, ransomware)
		if err != nil {
			t.Fatalf("AddKEV(%s): %v", id, err)
		}
		return v
	}
	k0 := kev("CVE-2099-0001", "Alpha Flaw", "2099-01-01", true)
	k1 := kev("CVE-2099-0002", "Beta Flaw", "2099-01-02", false)
	for _, w := range []struct {
		k KEV
		c CWE
	}{
		{k0, cwe20},
		{k0, cwe502},
		{k1, cwe502},
	} {
		if err := b.AddKEVWeaknessEdge(w.k, w.c); err != nil {
			t.Fatalf("AddKEVWeaknessEdge: %v", err)
		}
	}
	for _, p := range []struct {
		k KEV
		p Product
	}{
		{k0, alpha},
		{k1, beta},
	} {
		if err := b.AddKEVProductEdge(p.k, p.p); err != nil {
			t.Fatalf("AddKEVProductEdge: %v", err)
		}
	}

	e, err := b.Build()
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if e.TTPCount() != 6 || e.ArtifactCount() != 4 || e.CountermeasureCount() != 2 {
		t.Fatalf("counts = %d %d %d, want 6 4 2", e.TTPCount(), e.ArtifactCount(), e.CountermeasureCount())
	}
	if e.TacticCount() != 2 || e.PlatformCount() != 2 || e.DataComponentCount() != 2 || e.GroupCount() != 3 {
		t.Fatalf("vocabulary counts = %d %d %d %d, want 2 2 2 3",
			e.TacticCount(), e.PlatformCount(), e.DataComponentCount(), e.GroupCount())
	}
	if e.KEVCount() != 2 || e.CWECount() != 2 || e.ProductCount() != 2 {
		t.Fatalf("kev counts = %d %d %d, want 2 2 2", e.KEVCount(), e.CWECount(), e.ProductCount())
	}
	return e
}

// TestSyntheticLayout pins the six blocks word by word, so a wrong offset
// formula or a transposed plane cannot pass unnoticed.
func TestSyntheticLayout(t *testing.T) {
	e := buildSynthetic(t)

	if got := e.WordsPerRow(KindTTP); got != 1 {
		t.Fatalf("WordsPerRow(TTP) = %d, want 1", got)
	}
	if got := e.WordsPerRow(KindArtifact); got != 1 {
		t.Fatalf("WordsPerRow(Artifact) = %d, want 1", got)
	}
	if got := e.WordsPerRow(KindCountermeasure); got != 1 {
		t.Fatalf("WordsPerRow(Countermeasure) = %d, want 1", got)
	}

	// The documented layout is [planes][rows][stride], with planes = RelCount()+1
	// (plane 0 is the union), rows = the partition size and stride =
	// WordsPerRow of the row partition. Asserting it through the public
	// dimensions pins the layout, not Build's own allocation expression.
	planes, defPlanes := e.RelCount()+1, e.DefRelCount()+1
	if got, want := len(e.ttpArt), planes*e.TTPCount()*e.WordsPerRow(KindArtifact); got != want {
		t.Fatalf("len(ttpArt) = %d, want %d", got, want)
	}
	if got, want := len(e.artTTP), planes*e.ArtifactCount()*e.WordsPerRow(KindTTP); got != want {
		t.Fatalf("len(artTTP) = %d, want %d", got, want)
	}
	if got, want := len(e.cmArt), defPlanes*e.CountermeasureCount()*e.WordsPerRow(KindArtifact); got != want {
		t.Fatalf("len(cmArt) = %d, want %d", got, want)
	}
	if got, want := len(e.artCM), defPlanes*e.ArtifactCount()*e.WordsPerRow(KindCountermeasure); got != want {
		t.Fatalf("len(artCM) = %d, want %d", got, want)
	}
	if got, want := len(e.cmTTP), e.CountermeasureCount()*e.WordsPerRow(KindTTP); got != want {
		t.Fatalf("len(cmTTP) = %d, want %d", got, want)
	}
	if got, want := len(e.ttpCM), e.TTPCount()*e.WordsPerRow(KindCountermeasure); got != want {
		t.Fatalf("len(ttpCM) = %d, want %d", got, want)
	}

	// (technique, artifact, relation) triples, read from the technique-major
	// block: ttpArt[rel][t] must contain exactly a.
	want := []struct {
		t TTP
		a Artifact
		r Rel
	}{
		{1, 0, 1}, {1, 0, 2}, {0, 2, 1}, {4, 1, 3}, {3, 1, 3}, {5, 0, 2}, {2, 3, 1},
	}
	for _, w := range want {
		row := e.row(e.ttpArt, e.ttpArtOff(w.r, w.t), e.wArt)
		if !testBit(row, int(w.a)) {
			t.Fatalf("ttpArt[rel %d][t %d] missing artifact %d", w.r, w.t, w.a)
		}
		if got := popcountRow(row); got != 1 {
			t.Fatalf("ttpArt[rel %d][t %d] has %d bits, want 1", w.r, w.t, got)
		}
	}

	// The transpose must mirror the technique-major rows exactly; several
	// artifacts are touched by more than one technique under the same relation.
	trows := []struct {
		r    Rel
		a    Artifact
		want []int
	}{
		{1, 0, []int{1}},
		{2, 0, []int{1, 5}},
		{1, 2, []int{0}},
		{3, 1, []int{3, 4}},
		{1, 3, []int{2}},
	}
	for _, w := range trows {
		row := e.row(e.artTTP, e.artTTPOff(w.r, w.a), e.wTTP)
		got := make([]TTP, len(w.want))
		if n := enumerate(row, got); n != len(w.want) {
			t.Fatalf("artTTP[rel %d][a %d] = %d bits, want %d", w.r, w.a, n, len(w.want))
		}
		for i, wantID := range w.want {
			if got[i] != TTP(wantID) {
				t.Fatalf("artTTP[rel %d][a %d] = %v, want %v", w.r, w.a, got, w.want)
			}
		}
	}

	// Plane separation: the same pair under two relations, and absent under a
	// third.
	if !e.AdjacentRel(1, 0, Rel(1)) || !e.AdjacentRel(1, 0, Rel(2)) {
		t.Fatal("pair (1,0) must be present under both of its relations")
	}
	if e.AdjacentRel(1, 0, Rel(3)) {
		t.Fatal("pair (1,0) must be absent under 'creates'")
	}

	// Union plane 0 is the OR of the predicate planes, row by row.
	check := func(block []uint64, planes, rows, stride int) {
		t.Helper()
		for r := range rows {
			union := make([]uint64, stride)
			for p := 1; p < planes; p++ {
				off := (p*rows + r) * stride
				for i := range stride {
					union[i] |= block[off+i]
				}
			}
			off0 := r * stride
			for i := range stride {
				if block[off0+i] != union[i] {
					t.Fatalf("union plane row %d word %d = %x, want %x", r, i, block[off0+i], union[i])
				}
			}
		}
	}
	check(e.ttpArt, e.nRel, e.nTTP, e.wArt)
	check(e.artTTP, e.nRel, e.nArt, e.wTTP)
	check(e.cmArt, e.nDefRel, e.nCM, e.wArt)
	check(e.artCM, e.nDefRel, e.nArt, e.wCM)

	// The defensive blocks and the defends blocks.
	defWant := []struct {
		cm Countermeasure
		a  Artifact
		dr DefRel
	}{{0, 0, 2}, {0, 1, 2}, {1, 2, 1}}
	for _, w := range defWant {
		if !testBit(e.row(e.cmArt, e.cmArtOff(w.dr, w.cm), e.wArt), int(w.a)) {
			t.Fatalf("cmArt[dr %d][cm %d] missing artifact %d", w.dr, w.cm, w.a)
		}
		if !testBit(e.row(e.artCM, e.artCMOff(w.dr, w.a), e.wCM), int(w.cm)) {
			t.Fatalf("artCM[dr %d][a %d] missing cm %d", w.dr, w.a, w.cm)
		}
	}
	defendsWant := []struct {
		cm Countermeasure
		t  TTP
	}{{0, 1}, {0, 4}, {1, 0}, {1, 2}}
	for _, w := range defendsWant {
		if !testBit(e.row(e.cmTTP, e.cmTTPOff(w.cm), e.wTTP), int(w.t)) {
			t.Fatalf("cmTTP[cm %d] missing ttp %d", w.cm, w.t)
		}
		if !testBit(e.row(e.ttpCM, e.ttpCMOff(w.t), e.wCM), int(w.cm)) {
			t.Fatalf("ttpCM[t %d] missing cm %d", w.t, w.cm)
		}
	}
	if got := popcountRow(e.row(e.cmTTP, e.cmTTPOff(0), e.wTTP)); got != 2 {
		t.Fatalf("cmTTP[cm 0] has %d bits, want 2", got)
	}
	if got := popcountRow(e.row(e.cmTTP, e.cmTTPOff(1), e.wTTP)); got != 2 {
		t.Fatalf("cmTTP[cm 1] has %d bits, want 2", got)
	}

	// Union-plane cardinalities: the technique-major and artifact-major blocks
	// must agree on the number of distinct pairs. The 7 offensive triples
	// collapse to 6 pairs, the defensive edges are 3 pairs and the
	// defends-against family is 4 pairs.
	var sumDegree, sumArtDegree int
	for t := range e.TTPCount() {
		sumDegree += e.Degree(TTP(t), RelAny)
	}
	for a := range e.ArtifactCount() {
		sumArtDegree += e.ArtifactDegree(Artifact(a), RelAny)
	}
	if sumDegree != 6 || sumArtDegree != 6 {
		t.Fatalf("offensive union pairs = %d (ttp-major) / %d (artifact-major), want 6 / 6",
			sumDegree, sumArtDegree)
	}
	bufC := make([]Countermeasure, 4)
	bufA := make([]Artifact, 4)
	var sumCmForArt, sumArtForCm int
	for a := range e.ArtifactCount() {
		sumCmForArt += e.CountermeasuresForArtifact(Artifact(a), DefRelAny, bufC)
	}
	for cm := range e.CountermeasureCount() {
		sumArtForCm += e.ArtifactsForCountermeasure(Countermeasure(cm), DefRelAny, bufA)
	}
	if sumCmForArt != 3 || sumArtForCm != 3 {
		t.Fatalf("defensive union pairs = %d (artifact-major) / %d (cm-major), want 3 / 3",
			sumCmForArt, sumArtForCm)
	}
	bufT := make([]TTP, 4)
	var sumCmDegree, sumTTPsForCm int
	for cm := range e.CountermeasureCount() {
		sumCmDegree += e.CountermeasureDegree(Countermeasure(cm))
		sumTTPsForCm += e.TTPsForCountermeasure(Countermeasure(cm), bufT)
	}
	if sumCmDegree != 4 || sumTTPsForCm != 4 {
		t.Fatalf("defends-against pairs = %d (cm-major) / %d (ttp-major), want 4 / 4",
			sumCmDegree, sumTTPsForCm)
	}
}

func TestSyntheticTraversal(t *testing.T) {
	e := buildSynthetic(t)
	bufT := make([]TTP, 8)
	bufA := make([]Artifact, 8)

	// Offensive traversal, both directions.
	if got := e.TTPs(0, bufT); got != 2 || bufT[0] != 1 || bufT[1] != 5 {
		t.Fatalf("TTPs(Process) = %d %v, want 2 [1 5]", got, bufT[:2])
	}
	if got := e.TTPsRel(0, Rel(1), bufT); got != 1 || bufT[0] != 1 {
		t.Fatalf("TTPsRel(Process, accesses) = %d %v, want 1 [1]", got, bufT[:1])
	}
	if got := e.TTPsRel(0, Rel(2), bufT); got != 2 || bufT[0] != 1 || bufT[1] != 5 {
		t.Fatalf("TTPsRel(Process, modifies) = %d %v, want 2 [1 5]", got, bufT[:2])
	}
	if got := e.Artifacts(1, bufA); got != 1 || bufA[0] != 0 {
		t.Fatalf("Artifacts(T1003.001) = %d %v, want 1 [0]", got, bufA[:1])
	}
	if got := e.Artifacts(0, bufA); got != 1 || bufA[0] != 2 {
		t.Fatalf("Artifacts(T1003) = %d %v, want 1 [2]", got, bufA[:1])
	}
	if got := e.TTPs(3, bufT); got != 1 || bufT[0] != 2 {
		t.Fatalf("TTPs(NetworkTraffic) = %d %v, want 1 [2]", got, bufT[:1])
	}

	// Adjacency, degree.
	if !e.Adjacent(1, 0) {
		t.Fatal("Adjacent(T1003.001, Process) must be true")
	}
	if e.Adjacent(0, 0) {
		t.Fatal("Adjacent(T1003, Process) must be false (T1003 only touches Credential)")
	}
	if got := e.Degree(1, RelAny); got != 1 {
		t.Fatalf("Degree(T1003.001, RelAny) = %d, want 1", got)
	}
	if got := e.Degree(1, Rel(3)); got != 0 {
		t.Fatalf("Degree(T1003.001, creates) = %d, want 0", got)
	}
	if got := e.ArtifactDegree(0, RelAny); got != 2 {
		t.Fatalf("ArtifactDegree(Process, RelAny) = %d, want 2", got)
	}

	// Set operations.
	if got := e.TTPsAny(RelAny, make([]uint64, 1), bufT, []Artifact{0, 1}); got != 4 {
		t.Fatalf("TTPsAny(Process,File) = %d, want 4", got)
	} else if bufT[0] != 1 || bufT[1] != 3 || bufT[2] != 4 || bufT[3] != 5 {
		t.Fatalf("TTPsAny = %v, want [1 3 4 5]", bufT[:4])
	}
	if got := e.TTPsAll(RelAny, make([]uint64, 1), bufT, []Artifact{0, 1}); got != 0 {
		t.Fatalf("TTPsAll(Process,File) = %d, want 0", got)
	}
	if got := e.TTPsAll(Rel(2), make([]uint64, 1), bufT, []Artifact{0, 0}); got != 2 {
		t.Fatalf("TTPsAll(modifies, {Process,Process}) = %d, want 2", got)
	}
	if got := e.ArtifactsAny(RelAny, make([]uint64, 1), bufA, []TTP{1, 5}); got != 1 || bufA[0] != 0 {
		t.Fatalf("ArtifactsAny({T1003.001,T1547}) = %d %v, want 1 [0]", got, bufA[:1])
	}
	if got := e.ArtifactsAll(RelAny, make([]uint64, 1), bufA, []TTP{1, 5}); got != 1 || bufA[0] != 0 {
		t.Fatalf("ArtifactsAll({T1003.001,T1547}) = %d %v, want 1 [0]", got, bufA[:1])
	}
	if got := e.ArtifactsAll(RelAny, make([]uint64, 1), bufA, []TTP{0, 1}); got != 0 {
		t.Fatalf("ArtifactsAll({T1003,T1003.001}) = %d, want 0", got)
	}
	// Out-of-range ids inside a set operation are ignored, not fatal.
	if got := e.TTPsAny(RelAny, make([]uint64, 1), bufT, []Artifact{0, 99}); got != 2 {
		t.Fatalf("TTPsAny with an invalid id = %d, want 2", got)
	}
	if got := e.ArtifactsAll(RelAny, make([]uint64, 1), bufA, []TTP{99}); got != 0 {
		t.Fatalf("ArtifactsAll with only invalid ids = %d, want 0", got)
	}

	// Roll-up.
	if got := e.ArtifactsRollup(0, make([]uint64, 1), bufA); got != 3 {
		t.Fatalf("ArtifactsRollup(T1003) = %d, want 3", got)
	} else if bufA[0] != 0 || bufA[1] != 2 || bufA[2] != 3 {
		t.Fatalf("ArtifactsRollup(T1003) = %v, want [0 2 3]", bufA[:3])
	}
	if got := e.ArtifactsRollup(1, make([]uint64, 1), bufA); got != 1 || bufA[0] != 0 {
		t.Fatalf("ArtifactsRollup(sub) = %d %v, want 1 [0] (own row only)", got, bufA[:1])
	}
	if got := e.ArtifactsRollup(3, make([]uint64, 1), bufA); got != 1 || bufA[0] != 1 {
		t.Fatalf("ArtifactsRollup(T1059) = %d %v, want 1 [1]", got, bufA[:1])
	}
	// T1059 and T1059.001 both touch File: roll-up collapses them to one id.
	if got := e.TTPsRollup(1, make([]uint64, 1), bufT); got != 1 || bufT[0] != 3 {
		t.Fatalf("TTPsRollup(File) = %d %v, want 1 [3]", got, bufT[:1])
	}
	if got := e.TTPs(1, bufT); got != 2 {
		t.Fatalf("TTPs(File) = %d, want 2 (exact, sub included)", got)
	}
	if got := e.TTPsRollup(0, make([]uint64, 1), bufT); got != 2 || bufT[0] != 0 || bufT[1] != 5 {
		t.Fatalf("TTPsRollup(Process) = %d %v, want 2 [0 5]", got, bufT[:2])
	}
	if got := e.TTPsRollupRel(0, Rel(1), make([]uint64, 1), bufT); got != 1 || bufT[0] != 0 {
		t.Fatalf("TTPsRollupRel(Process, accesses) = %d %v, want 1 [0]", got, bufT[:1])
	}

	// dst truncation still reports the true total.
	short := make([]TTP, 1)
	if got := e.TTPs(1, short); got != 2 || short[0] != 3 {
		t.Fatalf("truncated TTPs(File) = %d %v, want 2 [3]", got, short)
	}

	// Out-of-range ids are total in the hot path.
	if n := e.TTPs(Artifact(99), bufT); n != 0 {
		t.Fatalf("TTPs(invalid) = %d, want 0", n)
	}
	if e.Adjacent(TTP(99), 0) {
		t.Fatal("Adjacent(invalid) must be false")
	}
	if n := e.Artifacts(TTP(99), bufA); n != 0 {
		t.Fatalf("Artifacts(invalid) = %d, want 0", n)
	}
	if n := e.Degree(TTP(99), RelAny); n != 0 {
		t.Fatalf("Degree(invalid) = %d, want 0", n)
	}
}

func TestSyntheticCountermeasures(t *testing.T) {
	e := buildSynthetic(t)
	bufC := make([]Countermeasure, 8)
	bufT := make([]TTP, 8)
	bufA := make([]Artifact, 8)
	scratchC := make([]uint64, 1)
	scratchT := make([]uint64, 1)

	if !e.Defends(0, 1) || !e.Defends(0, 4) || !e.Defends(1, 0) || !e.Defends(1, 2) {
		t.Fatal("Defends must report the four registered pairs")
	}
	if e.Defends(0, 0) || e.Defends(1, 1) {
		t.Fatal("Defends must not report unregistered pairs")
	}

	if got := e.CountermeasuresForTTP(1, bufC); got != 1 || bufC[0] != 0 {
		t.Fatalf("CountermeasuresForTTP(T1003.001) = %d %v, want 1 [0]", got, bufC[:1])
	}
	if got := e.CountermeasuresForTTP(0, bufC); got != 1 || bufC[0] != 1 {
		t.Fatalf("CountermeasuresForTTP(T1003) = %d %v, want 1 [1] (exact)", got, bufC[:1])
	}
	if got := e.CountermeasuresForTTPRollup(0, scratchC, bufC); got != 2 || bufC[0] != 0 || bufC[1] != 1 {
		t.Fatalf("CountermeasuresForTTPRollup(T1003) = %d %v, want 2 [0 1]", got, bufC[:2])
	}
	if got := e.CountermeasuresForTTPRollup(1, scratchC, bufC); got != 1 || bufC[0] != 0 {
		t.Fatalf("CountermeasuresForTTPRollup(sub) = %d %v, want 1 [0]", got, bufC[:1])
	}

	if got := e.CountermeasuresForArtifact(0, DefRelAny, bufC); got != 1 || bufC[0] != 0 {
		t.Fatalf("CountermeasuresForArtifact(Process) = %d %v, want 1 [0]", got, bufC[:1])
	}
	if got := e.CountermeasuresForArtifact(0, DefRel(1), bufC); got != 0 {
		t.Fatalf("CountermeasuresForArtifact(Process, hardens) = %d, want 0 (plane separation)", got)
	}
	if got := e.CountermeasuresForArtifact(2, DefRelAny, bufC); got != 1 || bufC[0] != 1 {
		t.Fatalf("CountermeasuresForArtifact(Credential) = %d %v, want 1 [1]", got, bufC[:1])
	}

	// The chain contributes a countermeasure the direct link does not:
	// NetworkTraffic has no defensive edge, but T1003.002 touches it.
	if got := e.CountermeasuresForArtifact(3, DefRelAny, bufC); got != 0 {
		t.Fatalf("direct CMs for NetworkTraffic = %d, want 0", got)
	}
	if got := e.CountermeasuresForArtifactViaTTPs(3, scratchC, bufC); got != 1 || bufC[0] != 1 {
		t.Fatalf("ViaTTPs(NetworkTraffic) = %d %v, want 1 [1] (chain only)", got, bufC[:1])
	}
	// Union of direct and chain, deduplicated.
	if got := e.CountermeasuresForArtifactViaTTPs(0, scratchC, bufC); got != 1 || bufC[0] != 0 {
		t.Fatalf("ViaTTPs(Process) = %d %v, want 1 [0]", got, bufC[:1])
	}
	if got := e.CountermeasuresForArtifactViaTTPs(1, scratchC, bufC); got != 1 || bufC[0] != 0 {
		t.Fatalf("ViaTTPs(File) = %d %v, want 1 [0]", got, bufC[:1])
	}

	if got := e.ArtifactsForCountermeasure(0, DefRelAny, bufA); got != 2 || bufA[0] != 0 || bufA[1] != 1 {
		t.Fatalf("ArtifactsForCountermeasure(cm0) = %d %v, want 2 [0 1]", got, bufA[:2])
	}
	if got := e.ArtifactsForCountermeasure(0, DefRel(1), bufA); got != 0 {
		t.Fatalf("ArtifactsForCountermeasure(cm0, hardens) = %d, want 0", got)
	}
	if got := e.ArtifactsForCountermeasure(1, DefRelAny, bufA); got != 1 || bufA[0] != 2 {
		t.Fatalf("ArtifactsForCountermeasure(cm1) = %d %v, want 1 [2]", got, bufA[:1])
	}

	if got := e.TTPsForCountermeasure(0, bufT); got != 2 || bufT[0] != 1 || bufT[1] != 4 {
		t.Fatalf("TTPsForCountermeasure(cm0) = %d %v, want 2 [1 4]", got, bufT[:2])
	}
	if got := e.TTPsForCountermeasureRollup(0, scratchT, bufT); got != 2 || bufT[0] != 0 || bufT[1] != 3 {
		t.Fatalf("TTPsForCountermeasureRollup(cm0) = %d %v, want 2 [0 3]", got, bufT[:2])
	}
	// cm1 defends T1003 and T1003.002: both collapse onto T1003.
	if got := e.TTPsForCountermeasure(1, bufT); got != 2 || bufT[0] != 0 || bufT[1] != 2 {
		t.Fatalf("TTPsForCountermeasure(cm1) = %d %v, want 2 [0 2]", got, bufT[:2])
	}
	if got := e.TTPsForCountermeasureRollup(1, scratchT, bufT); got != 1 || bufT[0] != 0 {
		t.Fatalf("TTPsForCountermeasureRollup(cm1) = %d %v, want 1 [0] (dedup)", got, bufT[:1])
	}

	if got := e.CountermeasureDegree(0); got != 2 {
		t.Fatalf("CountermeasureDegree(cm0) = %d, want 2", got)
	}
	if got := e.CountermeasureDegree(1); got != 2 {
		t.Fatalf("CountermeasureDegree(cm1) = %d, want 2", got)
	}

	// Countermeasure queries are total in the hot path too.
	if n := e.CountermeasuresForTTP(TTP(99), bufC); n != 0 {
		t.Fatalf("CountermeasuresForTTP(invalid) = %d, want 0", n)
	}
	if n := e.TTPsForCountermeasure(Countermeasure(99), bufT); n != 0 {
		t.Fatalf("TTPsForCountermeasure(invalid) = %d, want 0", n)
	}
	if e.Defends(Countermeasure(99), 0) || e.Defends(0, TTP(99)) {
		t.Fatal("Defends must be false for invalid ids")
	}
}

func TestSyntheticColdPath(t *testing.T) {
	e := buildSynthetic(t)

	if got, ok := e.Incident("t1003.001"); !ok || e.TTPName(got) != "T1003.001" {
		t.Fatalf("Incident(t1003.001) = %v,%v", got, ok)
	}
	if got, ok := e.Incident("  LSASS Memory  "); !ok || e.TTPLabel(got) != "LSASS Memory" {
		t.Fatalf("label lookup = %v,%v", got, ok)
	}
	if _, ok := e.Incident("nope"); ok {
		t.Fatal("Incident(nope) must be false")
	}
	if got, ok := e.Artifact("process"); !ok || got != 0 {
		t.Fatalf("Artifact(process) = %v,%v", got, ok)
	}
	// The label is a lookup key as well as an accessor: the two must not be
	// conflated (they differ in this graph by construction).
	if got, ok := e.Artifact("process artifact"); !ok || got != 0 {
		t.Fatalf("Artifact(label key) = %v,%v", got, ok)
	}
	if got := e.ArtifactName(0); got != "Process" {
		t.Fatalf("ArtifactName(0) = %q, want Process", got)
	}
	if got := e.ArtifactLabel(0); got != "Process Artifact" {
		t.Fatalf("ArtifactLabel(0) = %q, want Process Artifact", got)
	}
	if got, ok := e.Countermeasure("credentialhardening"); !ok || got != 1 {
		t.Fatalf("Countermeasure lookup = %v,%v", got, ok)
	}
	if got, ok := e.Countermeasure("processisolation label"); !ok || got != 0 {
		t.Fatalf("Countermeasure(label key) = %v,%v", got, ok)
	}
	if got := e.CountermeasureName(0); got != "ProcessIsolation" {
		t.Fatalf("CountermeasureName(0) = %q, want ProcessIsolation", got)
	}
	if got := e.CountermeasureLabel(0); got != "ProcessIsolation Label" {
		t.Fatalf("CountermeasureLabel(0) = %q, want ProcessIsolation Label", got)
	}
	if n := e.TTPChildren(TTP(99), make([]TTP, 2)); n != 0 {
		t.Fatalf("TTPChildren(invalid) = %d, want 0", n)
	}
	if r, ok := e.Rel("ACCESSES"); !ok || e.RelName(r) != "accesses" {
		t.Fatalf("Rel(ACCESSES) = %v,%v", r, ok)
	}
	if e.RelName(RelAny) != "any" {
		t.Fatalf("RelName(RelAny) = %q, want any", e.RelName(RelAny))
	}
	// Every plane round-trips through its name and id, including the union plane.
	for r := 0; r <= e.RelCount(); r++ {
		got, ok := e.Rel(e.RelName(Rel(r)))
		if !ok || got != Rel(r) {
			t.Fatalf("Rel(%q) = %d,%v, want %d,true", e.RelName(Rel(r)), got, ok, r)
		}
	}
	for dr := 0; dr <= e.DefRelCount(); dr++ {
		got, ok := e.DefRel(e.DefRelName(DefRel(dr)))
		if !ok || got != DefRel(dr) {
			t.Fatalf("DefRel(%q) = %d,%v, want %d,true", e.DefRelName(DefRel(dr)), got, ok, dr)
		}
	}
	if dr, ok := e.DefRel("hardens"); !ok || e.DefRelName(dr) != "hardens" {
		t.Fatalf("DefRel(hardens) = %v,%v", dr, ok)
	}
	if e.TTPDomain(0) != DomainEnterprise {
		t.Fatal("TTPDomain must round-trip the registration domain")
	}

	dst := make([]string, 3)
	if n := e.Response(dst, []TTP{1, 99}); n != 2 {
		t.Fatalf("Response count = %d, want 2", n)
	}
	if dst[0] != "T1003.001 LSASS Memory" {
		t.Fatalf("Response[0] = %q", dst[0])
	}
	if dst[1] != "<invalid ttp 99>" {
		t.Fatalf("Response[1] = %q, want <invalid ttp 99>", dst[1])
	}
	cdst := make([]string, 2)
	if n := e.CountermeasureResponse(cdst, []Countermeasure{0, 99}); n != 2 {
		t.Fatalf("CountermeasureResponse count = %d, want 2", n)
	}
	if cdst[0] != "ProcessIsolation ProcessIsolation Label" || cdst[1] != "<invalid cm 99>" {
		t.Fatalf("CountermeasureResponse = %q, %q", cdst[0], cdst[1])
	}
	// Truncation is reported by the return value, not by a panic.
	one := make([]string, 1)
	if n := e.Response(one, []TTP{1, 2}); n != 2 || one[0] != "T1003.001 LSASS Memory" {
		t.Fatalf("truncated Response = %d %q", n, one)
	}
}

// TestHotPathTolerance pins the documented totality contract: every hot-path
// query answers an out-of-range id with 0/false instead of panicking, and skips
// invalid members inside set operations.
func TestHotPathTolerance(t *testing.T) {
	e := buildSynthetic(t)
	bufT := make([]TTP, 8)
	bufA := make([]Artifact, 8)
	bufC := make([]Countermeasure, 8)
	scratchT := make([]uint64, 1)
	scratchA := make([]uint64, 1)
	scratchC := make([]uint64, 1)

	badT, badA, badC := TTP(99), Artifact(99), Countermeasure(99)

	if e.Adjacent(badT, 0) {
		t.Fatal("Adjacent(invalid ttp) must be false")
	}
	if e.AdjacentRel(badT, 0, RelAny) {
		t.Fatal("AdjacentRel(invalid ttp) must be false")
	}
	if n := e.Artifacts(badT, bufA); n != 0 {
		t.Fatalf("Artifacts(invalid ttp) = %d, want 0", n)
	}
	if n := e.ArtifactsRel(badT, Rel(1), bufA); n != 0 {
		t.Fatalf("ArtifactsRel(invalid ttp) = %d, want 0", n)
	}
	if n := e.TTPs(badA, bufT); n != 0 {
		t.Fatalf("TTPs(invalid artifact) = %d, want 0", n)
	}
	if n := e.TTPsRel(badA, RelAny, bufT); n != 0 {
		t.Fatalf("TTPsRel(invalid artifact) = %d, want 0", n)
	}
	if n := e.Degree(badT, RelAny); n != 0 {
		t.Fatalf("Degree(invalid ttp) = %d, want 0", n)
	}
	if n := e.ArtifactDegree(badA, RelAny); n != 0 {
		t.Fatalf("ArtifactDegree(invalid artifact) = %d, want 0", n)
	}
	if n := e.ArtifactsRollup(badT, scratchA, bufA); n != 0 {
		t.Fatalf("ArtifactsRollup(invalid ttp) = %d, want 0", n)
	}
	if n := e.ArtifactsRollupRel(badT, Rel(1), scratchA, bufA); n != 0 {
		t.Fatalf("ArtifactsRollupRel(invalid ttp) = %d, want 0", n)
	}
	if n := e.TTPsRollup(badA, scratchT, bufT); n != 0 {
		t.Fatalf("TTPsRollup(invalid artifact) = %d, want 0", n)
	}
	if n := e.TTPsRollupRel(badA, Rel(1), scratchT, bufT); n != 0 {
		t.Fatalf("TTPsRollupRel(invalid artifact) = %d, want 0", n)
	}
	if n := e.TTPsAny(RelAny, scratchT, bufT, []Artifact{badA}); n != 0 {
		t.Fatalf("TTPsAny(invalid artifact) = %d, want 0", n)
	}
	if n := e.TTPsAll(RelAny, scratchT, bufT, []Artifact{badA}); n != 0 {
		t.Fatalf("TTPsAll(invalid artifact) = %d, want 0", n)
	}
	if n := e.ArtifactsAny(RelAny, scratchA, bufA, []TTP{badT}); n != 0 {
		t.Fatalf("ArtifactsAny(invalid ttp) = %d, want 0", n)
	}
	if n := e.ArtifactsAll(RelAny, scratchA, bufA, []TTP{badT}); n != 0 {
		t.Fatalf("ArtifactsAll(invalid ttp) = %d, want 0", n)
	}
	if e.Defends(badC, 0) {
		t.Fatal("Defends(invalid cm) must be false")
	}
	if e.Defends(0, badT) {
		t.Fatal("Defends(invalid ttp) must be false")
	}
	if n := e.CountermeasuresForTTP(badT, bufC); n != 0 {
		t.Fatalf("CountermeasuresForTTP(invalid ttp) = %d, want 0", n)
	}
	if n := e.CountermeasuresForTTPRollup(badT, scratchC, bufC); n != 0 {
		t.Fatalf("CountermeasuresForTTPRollup(invalid ttp) = %d, want 0", n)
	}
	if n := e.CountermeasuresForArtifact(badA, DefRelAny, bufC); n != 0 {
		t.Fatalf("CountermeasuresForArtifact(invalid artifact) = %d, want 0", n)
	}
	if n := e.CountermeasuresForArtifactViaTTPs(badA, scratchC, bufC); n != 0 {
		t.Fatalf("CountermeasuresForArtifactViaTTPs(invalid artifact) = %d, want 0", n)
	}
	if n := e.ArtifactsForCountermeasure(badC, DefRelAny, bufA); n != 0 {
		t.Fatalf("ArtifactsForCountermeasure(invalid cm) = %d, want 0", n)
	}
	if n := e.TTPsForCountermeasure(badC, bufT); n != 0 {
		t.Fatalf("TTPsForCountermeasure(invalid cm) = %d, want 0", n)
	}
	if n := e.TTPsForCountermeasureRollup(badC, scratchT, bufT); n != 0 {
		t.Fatalf("TTPsForCountermeasureRollup(invalid cm) = %d, want 0", n)
	}
	if n := e.CountermeasureDegree(badC); n != 0 {
		t.Fatalf("CountermeasureDegree(invalid cm) = %d, want 0", n)
	}
	if p, ok := e.TTPParent(badT); ok || p != 0 {
		t.Fatalf("TTPParent(invalid) = %d,%v want 0,false", p, ok)
	}
	if n := e.TTPChildCount(badT); n != 0 {
		t.Fatalf("TTPChildCount(invalid) = %d, want 0", n)
	}

	// Set operations skip the invalid members and fold the remaining rows.
	if n := e.TTPsAny(RelAny, scratchT, bufT, []Artifact{badA, 0}); n != 2 || bufT[0] != 1 || bufT[1] != 5 {
		t.Fatalf("TTPsAny(invalid, Process) = %d %v, want 2 [1 5]", n, bufT[:n])
	}
	if n := e.ArtifactsAll(RelAny, scratchA, bufA, []TTP{badT, 1}); n != 1 || bufA[0] != 0 {
		t.Fatalf("ArtifactsAll(invalid, T1003.001) = %d %v, want 1 [0]", n, bufA[:n])
	}
	if n := e.TTPsAll(RelAny, scratchT, bufT, []Artifact{badA, 0}); n != 2 {
		t.Fatalf("TTPsAll(invalid, Process) = %d, want 2", n)
	}
	if n := e.ArtifactsAny(RelAny, scratchA, bufA, []TTP{badT, 5}); n != 1 || bufA[0] != 0 {
		t.Fatalf("ArtifactsAny(invalid, T1547) = %d %v, want 1 [0]", n, bufA[:n])
	}
}

func TestSyntheticPanics(t *testing.T) {
	e := buildSynthetic(t)
	scratchC := make([]uint64, 1)
	scratchT := make([]uint64, 1)
	bufC := make([]Countermeasure, 4)
	bufT := make([]TTP, 4)

	mustPanic(t, "rel out of range", "gr4ph: relation out of range", func() { e.ArtifactsRel(0, Rel(9), nil) })
	mustPanic(t, "defrel out of range", "gr4ph: defensive relation out of range", func() {
		e.CountermeasuresForArtifact(0, DefRel(9), bufC)
	})
	mustPanic(t, "scratch too small (countermeasure)", "gr4ph: scratch too small", func() {
		e.CountermeasuresForTTPRollup(0, nil, bufC)
	})
	mustPanic(t, "scratch too small (ttp)", "gr4ph: scratch too small", func() {
		e.TTPsForCountermeasureRollup(0, nil, bufT)
	})
	mustPanic(t, "scratch too small (artifact)", "gr4ph: scratch too small", func() {
		e.ArtifactsRollup(0, nil, nil)
	})
	mustPanic(t, "unknown kind", "gr4ph: unknown kind", func() { e.WordsPerRow(Kind(9)) })
	mustPanic(t, "cold accessor out of range", "gr4ph: ttp out of range", func() { e.TTPName(TTP(99)) })
	mustPanic(t, "cold domain accessor out of range", "gr4ph: ttp out of range", func() { e.TTPDomain(TTP(99)) })
	mustPanic(t, "cold artifact name out of range", "gr4ph: artifact out of range", func() {
		e.ArtifactName(Artifact(99))
	})
	mustPanic(t, "cold artifact label out of range", "gr4ph: artifact out of range", func() {
		e.ArtifactLabel(Artifact(99))
	})
	mustPanic(t, "cold countermeasure name out of range", "gr4ph: countermeasure out of range", func() {
		e.CountermeasureName(Countermeasure(99))
	})
	mustPanic(t, "cold countermeasure label out of range", "gr4ph: countermeasure out of range", func() {
		e.CountermeasureLabel(Countermeasure(99))
	})
	mustPanic(t, "cold rel name out of range", "gr4ph: relation out of range", func() { e.RelName(Rel(9)) })
	mustPanic(t, "cold defrel name out of range", "gr4ph: defensive relation out of range", func() {
		e.DefRelName(DefRel(9))
	})
	mustPanic(t, "defrel out of range (artifact-major)", "gr4ph: defensive relation out of range", func() {
		e.ArtifactsForCountermeasure(0, DefRel(9), nil)
	})
	// The scratch check precedes the id bounds check, so an undersized scratch
	// panics even when the id is out of range too.
	mustPanic(t, "scratch precedes the ttp bounds check", "gr4ph: scratch too small", func() {
		e.ArtifactsRollup(TTP(99), nil, nil)
	})
	mustPanic(t, "scratch precedes the artifact bounds check", "gr4ph: scratch too small", func() {
		e.TTPsRollupRel(Artifact(99), RelAny, nil, nil)
	})

	// The documented scratch sizes work.
	e.CountermeasuresForTTPRollup(0, scratchC, bufC)
	e.TTPsForCountermeasureRollup(0, scratchT, bufT)
	e.ArtifactsRollup(0, make([]uint64, 1), nil)
}

// mustPanic asserts that f panics with the guard's own message, so a case cannot
// pass on an incidental slice-bounds panic instead of the guard it names.
func mustPanic(t *testing.T, name, want string, f func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Fatalf("%s: expected panic", name)
		}
		msg, ok := r.(string)
		if !ok || msg != want {
			t.Fatalf("%s: panic = %v (%T), want %q", name, r, r, want)
		}
	}()
	f()
}

// TestEngineAttributes pins the attribute blocks: the per-technique masks, the
// derived sub-technique flag, the reverse rows and the lookup rules.
func TestEngineAttributes(t *testing.T) {
	e := buildSynthetic(t)
	t1003, _ := e.Incident("T1003")
	t1003a, _ := e.Incident("T1003.001")
	t1059, _ := e.Incident("T1059")

	if got := e.TTPTactics(t1003); got != 1 {
		t.Errorf("TTPTactics(T1003) = %#b, want bit 0 (TA0001)", got)
	}
	if got := e.TTPTactics(t1003a); got != 2 {
		t.Errorf("TTPTactics(T1003.001) = %#b, want bit 1 (TA0002)", got)
	}
	if got := e.TTPTactics(t1059); got != 0 {
		t.Errorf("TTPTactics(T1059) = %#b, want 0", got)
	}
	if got := e.TTPPlatforms(t1003); got != 3 {
		t.Errorf("TTPPlatforms(T1003) = %#b, want Windows|Linux", got)
	}
	if got := e.TTPPlatforms(t1003a); got != 1 {
		t.Errorf("TTPPlatforms(T1003.001) = %#b, want Windows", got)
	}
	if !e.TTPSubTechnique(t1003a) || e.TTPSubTechnique(t1003) {
		t.Errorf("TTPSubTechnique = %v/%v, want true/false", e.TTPSubTechnique(t1003a), e.TTPSubTechnique(t1003))
	}
	if got := e.TTPFlags(t1003a); got != FlagSubTechnique {
		t.Errorf("TTPFlags(T1003.001) = %#b, want FlagSubTechnique", got)
	}

	dst := make([]TTP, e.TTPCount())
	if n := e.TTPsForTactic(0, dst); n != 1 || dst[0] != t1003 {
		t.Errorf("TTPsForTactic(0) = %d %v, want [T1003]", n, dst[:max(n, 0)])
	}
	if n := e.TTPsForTactic(1, dst); n != 1 || dst[0] != t1003a {
		t.Errorf("TTPsForTactic(1) = %d %v, want [T1003.001]", n, dst[:max(n, 0)])
	}
	if n := e.TTPsForPlatform(0, dst); n != 2 || dst[0] != t1003 || dst[1] != t1003a {
		t.Errorf("TTPsForPlatform(Windows) = %d %v, want [T1003 T1003.001]", n, dst[:max(n, 0)])
	}
	if n := e.TTPsForPlatform(1, dst); n != 1 || dst[0] != t1003 {
		t.Errorf("TTPsForPlatform(Linux) = %d %v, want [T1003]", n, dst[:max(n, 0)])
	}

	if ta, ok := e.Tactic("ta0001"); !ok || ta != 0 {
		t.Errorf("Tactic(ta0001) = %v %v, want 0 true (normalised)", ta, ok)
	}
	if _, ok := e.Tactic("Initial Access"); ok {
		t.Error("Tactic(label) resolved: tactic labels repeat across domains, the TA id is the key")
	}
	if _, ok := e.Platform("windows"); !ok {
		t.Error("Platform(windows) did not resolve")
	}
	if e.TacticID(0) != "TA0001" || e.TacticLabel(1) != "Execution" || e.PlatformName(1) != "Linux" {
		t.Errorf("vocabulary accessors = %q %q %q", e.TacticID(0), e.TacticLabel(1), e.PlatformName(1))
	}

	// Totality: an out-of-range id answers 0/false instead of panicking.
	if got := e.TTPTactics(TTP(99)); got != 0 {
		t.Errorf("TTPTactics(out of range) = %#b, want 0", got)
	}
	if got := e.TTPFlags(TTP(99)); got != 0 {
		t.Errorf("TTPFlags(out of range) = %#b, want 0", got)
	}
	if n := e.TTPsForTactic(Tactic(99), dst); n != 0 {
		t.Errorf("TTPsForTactic(99) = %d, want 0", n)
	}
	if n := e.TTPsForPlatform(Platform(99), dst); n != 0 {
		t.Errorf("TTPsForPlatform(99) = %d, want 0", n)
	}
}

// TestEngineDataComponents pins the detects family: the exact answer is the
// technique's own row, the roll-up adds every child's components, and a
// component with no edge stays a node of degree 0.
func TestEngineDataComponents(t *testing.T) {
	e := buildSynthetic(t)
	t1003, _ := e.Incident("T1003")
	t1003a, _ := e.Incident("T1003.001")
	dcProcess, _ := e.DataComponent("DC0001")
	dcFile, _ := e.DataComponent("DC0002")

	dstDC := make([]DataComponent, e.DataComponentCount())
	if n := e.DataComponentsForTTP(t1003a, dstDC); n != 1 || dstDC[0] != dcProcess {
		t.Errorf("DataComponentsForTTP(T1003.001) = %d %v, want [DC0001]", n, dstDC[:max(n, 0)])
	}
	if n := e.DataComponentsForTTP(t1003, dstDC); n != 0 {
		t.Errorf("DataComponentsForTTP(T1003) = %d, want 0 (the child carries the detection)", n)
	}
	scratch := make([]uint64, e.WordsPerRow(KindDataComponent))
	if n := e.DataComponentsForTTPRollup(t1003, scratch, dstDC); n != 1 || dstDC[0] != dcProcess {
		t.Errorf("DataComponentsForTTPRollup(T1003) = %d %v, want [DC0001]", n, dstDC[:max(n, 0)])
	}
	// The child's own roll-up reaches nothing new: it has no children.
	if n := e.DataComponentsForTTPRollup(t1003a, scratch, dstDC); n != 1 {
		t.Errorf("DataComponentsForTTPRollup(T1003.001) = %d, want 1", n)
	}

	dstTTP := make([]TTP, e.TTPCount())
	if n := e.TTPsForDataComponent(dcProcess, dstTTP); n != 1 || dstTTP[0] != t1003a {
		t.Errorf("TTPsForDataComponent(DC0001) = %d %v, want [T1003.001]", n, dstTTP[:max(n, 0)])
	}
	if got := e.DataComponentDegree(dcProcess); got != 1 {
		t.Errorf("DataComponentDegree(DC0001) = %d, want 1", got)
	}
	if got := e.DataComponentDegree(dcFile); got != 0 {
		t.Errorf("DataComponentDegree(DC0002) = %d, want 0", got)
	}
	if e.DataComponentID(dcProcess) != "DC0001" || e.DataComponentLabel(dcProcess) != "Process Creation" {
		t.Errorf("data component accessors = %q %q", e.DataComponentID(dcProcess), e.DataComponentLabel(dcProcess))
	}

	// Totality.
	if n := e.DataComponentsForTTPRollup(TTP(99), scratch, dstDC); n != 0 {
		t.Errorf("DataComponentsForTTPRollup(out of range) = %d, want 0", n)
	}
	if n := e.TTPsForDataComponent(DataComponent(99), dstTTP); n != 0 {
		t.Errorf("TTPsForDataComponent(out of range) = %d, want 0", n)
	}
}

// TestEngineGroups pins the grouping partition: one uses family split into
// techniques and software, both directions, the roll-up, and the kinds.
func TestEngineGroups(t *testing.T) {
	e := buildSynthetic(t)
	actor, _ := e.Group("G0001")
	software, _ := e.Group("S0001")
	campaign, _ := e.Group("C0001")
	t1003, _ := e.Incident("T1003")
	t1003a, _ := e.Incident("T1003.001")
	t1059, _ := e.Incident("T1059")

	dstTTP := make([]TTP, e.TTPCount())
	if n := e.TTPsForGroup(actor, dstTTP); n != 2 || dstTTP[0] != t1003 || dstTTP[1] != t1003a {
		t.Errorf("TTPsForGroup(G0001) = %d %v, want [T1003 T1003.001]", n, dstTTP[:max(n, 0)])
	}
	scratch := make([]uint64, e.WordsPerRow(KindTTP))
	if n := e.TTPsForGroupRollup(actor, scratch, dstTTP); n != 1 || dstTTP[0] != t1003 {
		t.Errorf("TTPsForGroupRollup(G0001) = %d %v, want [T1003]", n, dstTTP[:max(n, 0)])
	}
	if n := e.TTPsForGroup(campaign, dstTTP); n != 1 || dstTTP[0] != t1059 {
		t.Errorf("TTPsForGroup(C0001) = %d %v, want [T1059]", n, dstTTP[:max(n, 0)])
	}
	if n := e.TTPsForGroup(software, dstTTP); n != 0 {
		t.Errorf("TTPsForGroup(S0001) = %d, want 0 (software uses no techniques here)", n)
	}

	dstG := make([]Group, e.GroupCount())
	if n := e.GroupsForTTP(t1003, dstG); n != 1 || dstG[0] != actor {
		t.Errorf("GroupsForTTP(T1003) = %d %v, want [G0001]", n, dstG[:max(n, 0)])
	}
	if n := e.GroupsForTTP(t1059, dstG); n != 1 || dstG[0] != campaign {
		t.Errorf("GroupsForTTP(T1059) = %d %v, want [C0001]", n, dstG[:max(n, 0)])
	}

	if n := e.SoftwareForGroup(actor, dstG); n != 1 || dstG[0] != software {
		t.Errorf("SoftwareForGroup(G0001) = %d %v, want [S0001]", n, dstG[:max(n, 0)])
	}
	if n := e.GroupsForSoftware(software, dstG); n != 1 || dstG[0] != actor {
		t.Errorf("GroupsForSoftware(S0001) = %d %v, want [G0001]", n, dstG[:max(n, 0)])
	}
	if n := e.SoftwareForGroup(software, dstG); n != 0 {
		t.Errorf("SoftwareForGroup(S0001) = %d, want 0", n)
	}
	if got := e.SoftwareDegree(actor); got != 1 {
		t.Errorf("SoftwareDegree(G0001) = %d, want 1", got)
	}

	if k := e.GroupKind(actor); k != GroupActor {
		t.Errorf("GroupKind(G0001) = %v, want GroupActor", k)
	}
	if k := e.GroupKind(software); k != GroupSoftware {
		t.Errorf("GroupKind(S0001) = %v, want GroupSoftware", k)
	}
	if k := e.GroupKind(campaign); k != GroupCampaign {
		t.Errorf("GroupKind(C0001) = %v, want GroupCampaign", k)
	}
	if e.GroupID(software) != "S0001" || e.GroupLabel(actor) != "Actor One" {
		t.Errorf("group accessors = %q %q", e.GroupID(software), e.GroupLabel(actor))
	}
	if _, ok := e.Group("Actor One"); !ok {
		t.Error("Group(label) did not resolve")
	}

	// Totality.
	if n := e.TTPsForGroup(Group(99), dstTTP); n != 0 {
		t.Errorf("TTPsForGroup(out of range) = %d, want 0", n)
	}
	if n := e.GroupsForTTP(TTP(99), dstG); n != 0 {
		t.Errorf("GroupsForTTP(out of range) = %d, want 0", n)
	}
	if n := e.SoftwareForGroup(Group(99), dstG); n != 0 {
		t.Errorf("SoftwareForGroup(out of range) = %d, want 0", n)
	}
}
