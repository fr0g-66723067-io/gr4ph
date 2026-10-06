//go:build goexperiment.simd

// Command ontology runs both end-to-end flows against the frozen ATT&CK x
// D3FEND tables:
//
//   - defensive triage: an artifact (or an alert string) -> the techniques that
//     touch it -> the countermeasures that apply, exact and rolled up;
//
//   - authorized offensive planning: the same artifact read as the
//     countermeasure surface to attack or evade, plus which countermeasures
//     defend the most technique surface.
//
//     go run ./examples/ontology
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fr0g-66723067/gr4ph"
	"github.com/fr0g-66723067/gr4ph/ontology"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "ontology:", err)
		os.Exit(1)
	}
}

// run writes the whole walkthrough to w so the documented output can be pinned
// by a test.
func run(w io.Writer) error {
	b := gr4ph.NewBuilder()
	if err := ontology.Register(b); err != nil {
		return err
	}
	e, err := b.Build()
	if err != nil {
		return err
	}

	fmt.Fprintf(w, "ontology: %d ttps (%s), %d artifacts, %d countermeasures; rels %d/%d; edges %d/%d/%d; wordsPerRow %d/%d/%d\n",
		e.TTPCount(), histogram(e), e.ArtifactCount(), e.CountermeasureCount(),
		e.RelCount(), e.DefRelCount(),
		ontology.NOffEdges, ontology.NDefEdges, ontology.NDefends,
		e.WordsPerRow(gr4ph.KindTTP), e.WordsPerRow(gr4ph.KindArtifact), e.WordsPerRow(gr4ph.KindCountermeasure))

	// Hierarchy shape.
	topLevel, subs, parents, maxChildren := 0, 0, 0, 0
	var biggest gr4ph.TTP
	for i := range e.TTPCount() {
		id := gr4ph.TTP(i)
		if _, ok := e.TTPParent(id); ok {
			subs++
		} else {
			topLevel++
		}
		if c := e.TTPChildCount(id); c > 0 {
			parents++
			// >= keeps the highest-indexed parent among ties, which is the one
			// the README documents (T1546, 18 children).
			if c >= maxChildren {
				maxChildren, biggest = c, id
			}
		}
	}
	fmt.Fprintf(w, "hierarchy: %d top-level, %d sub-techniques, %d parents, max %d children (%s)\n",
		topLevel, subs, parents, maxChildren, e.TTPName(biggest))

	// Shared buffers: one per partition, reused by every query below.
	ttps := make([]gr4ph.TTP, e.TTPCount())
	rolledTTPs := make([]gr4ph.TTP, e.TTPCount()) // a second view, so a roll-up cannot clobber the exact set
	arts := make([]gr4ph.Artifact, e.ArtifactCount())
	cms := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	scratchA := make([]uint64, e.WordsPerRow(gr4ph.KindArtifact))
	scratchC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))

	// --- defensive triage: artifact -> techniques -> countermeasures ---

	process := lookupArtifact(e, "Process")
	file := lookupArtifact(e, "File")

	n := e.TTPs(process, ttps)
	fmt.Fprintf(w, "ttps(Process) = %d: %s\n", n, join(ttpNames(e, ttps[:n]), 5))
	n = e.TTPsRollup(process, scratchT, ttps)
	fmt.Fprintf(w, "ttpsRollup(Process) = %d: %s\n", n, join(ttpNames(e, ttps[:n]), 5))

	accesses := lookupRel(e, "accesses")
	modifies := lookupRel(e, "modifies")
	n = e.TTPsRel(process, accesses, ttps)
	fmt.Fprintf(w, "ttps(Process, accesses) = %d: %s\n", n, join(ttpNames(e, ttps[:n]), 5))
	fmt.Fprintf(w, "ttps(Process, modifies) = %d\n", e.TTPsRel(process, modifies, ttps))

	n = e.Artifacts(lookupTTP(e, "T1003.001"), arts)
	fmt.Fprintf(w, "artifacts(T1003.001) = %d: %s\n", n, join(artifactNames(e, arts[:n]), 9))

	direct := e.Artifacts(lookupTTP(e, "T1003"), arts)
	n = e.ArtifactsRollup(lookupTTP(e, "T1003"), scratchA, arts)
	fmt.Fprintf(w, "artifacts(T1003) = %d; artifactsRollup(T1003) = %d: %s\n",
		direct, n, join(artifactNames(e, arts[:n]), 9))

	createProcess := lookupArtifact(e, "CreateProcess")
	exact := e.TTPs(createProcess, ttps)
	rolled := e.TTPsRollup(createProcess, scratchT, ttps)
	fmt.Fprintf(w, "ttps(CreateProcess) = %d; ttpsRollup(CreateProcess) = %d\n", exact, rolled)

	fmt.Fprintf(w, "ttpsAny(Process, File) = %d\n",
		e.TTPsAny(gr4ph.RelAny, scratchT, ttps, []gr4ph.Artifact{process, file}))

	// Countermeasure surface of an artifact: direct links, and the chain
	// through the techniques that touch it.
	directCMs := e.CountermeasuresForArtifact(process, gr4ph.DefRelAny, cms)
	viaTTPs := e.CountermeasuresForArtifactViaTTPs(process, scratchC, cms)
	fmt.Fprintf(w, "countermeasuresForArtifact(Process) = %d; viaTTPs = %d: %s\n",
		directCMs, viaTTPs, join(cmNames(e, cms[:viaTTPs]), 5))

	// An artifact with no direct countermeasure link at all: everything arrives
	// through the chain.
	authService := lookupArtifact(e, "AuthenticationService")
	directCMs = e.CountermeasuresForArtifact(authService, gr4ph.DefRelAny, cms)
	viaTTPs = e.CountermeasuresForArtifactViaTTPs(authService, scratchC, cms)
	fmt.Fprintf(w, "countermeasuresForArtifact(AuthenticationService) = %d; viaTTPs = %d: %s\n",
		directCMs, viaTTPs, join(cmNames(e, cms[:viaTTPs]), 5))

	// A parent technique carries no edges of its own; roll-up is what reaches
	// the countermeasures of its sub-techniques.
	t1003 := lookupTTP(e, "T1003")
	exactCMs := e.CountermeasuresForTTP(t1003, cms)
	rolledCMs := e.CountermeasuresForTTPRollup(t1003, scratchC, cms)
	fmt.Fprintf(w, "countermeasuresForTTP(T1003) = %d; rollup = %d: %s\n",
		exactCMs, rolledCMs, join(cmNames(e, cms[:rolledCMs]), 5))

	// --- offensive planning: rank the countermeasure surface ---

	hardening := lookupCM(e, "CredentialHardening")
	defended := e.TTPsForCountermeasure(hardening, ttps)
	rolledDefended := e.TTPsForCountermeasureRollup(hardening, scratchT, rolledTTPs)
	fmt.Fprintf(w, "ttpsForCountermeasure(CredentialHardening) = %d (rolled %d): %s\n",
		defended, rolledDefended, join(ttpNames(e, ttps[:defended]), 5))

	hardens := lookupDefRel(e, "hardens")
	n = e.ArtifactsForCountermeasure(hardening, hardens, arts)
	fmt.Fprintf(w, "artifactsForCountermeasure(CredentialHardening, hardens) = %v\n", artifactNames(e, arts[:n]))

	quarantine := lookupCM(e, "ContentQuarantine")
	fmt.Fprintf(w, "countermeasureDegree(ContentQuarantine) = %d\n", e.CountermeasureDegree(quarantine))

	// --- the cold path: alert strings in, log lines out ---

	for _, alert := range []string{"LSASS Memory", "T0894", "T1603"} {
		id, ok := e.Incident(alert)
		if !ok {
			return fmt.Errorf("unknown alert %q", alert)
		}
		parent, hasParent := e.TTPParent(id)
		detail := ""
		if hasParent {
			detail = ", sub of " + e.TTPName(parent)
		}
		fmt.Fprintf(w, "incident %q -> %s (%s%s), %d artifacts\n",
			alert, e.TTPName(id), domainName(e.TTPDomain(id)), detail, e.Degree(id, gr4ph.RelAny))
	}
	return nil
}

func lookupTTP(e *gr4ph.Engine, name string) gr4ph.TTP {
	id, ok := e.Incident(name)
	if !ok {
		panic("unknown technique " + name)
	}
	return id
}

func lookupArtifact(e *gr4ph.Engine, name string) gr4ph.Artifact {
	id, ok := e.Artifact(name)
	if !ok {
		panic("unknown artifact " + name)
	}
	return id
}

func lookupCM(e *gr4ph.Engine, name string) gr4ph.Countermeasure {
	id, ok := e.Countermeasure(name)
	if !ok {
		panic("unknown countermeasure " + name)
	}
	return id
}

func lookupRel(e *gr4ph.Engine, name string) gr4ph.Rel {
	r, ok := e.Rel(name)
	if !ok {
		panic("unknown relation " + name)
	}
	return r
}

func lookupDefRel(e *gr4ph.Engine, name string) gr4ph.DefRel {
	r, ok := e.DefRel(name)
	if !ok {
		panic("unknown defensive relation " + name)
	}
	return r
}

func histogram(e *gr4ph.Engine) string {
	var enterprise, mobile, ics, sparta int
	for i := range e.TTPCount() {
		switch e.TTPDomain(gr4ph.TTP(i)) {
		case gr4ph.DomainEnterprise:
			enterprise++
		case gr4ph.DomainMobile:
			mobile++
		case gr4ph.DomainICS:
			ics++
		default:
			sparta++
		}
	}
	return fmt.Sprintf("%d enterprise, %d mobile, %d ics, %d sparta", enterprise, mobile, ics, sparta)
}

func domainName(d gr4ph.Domain) string {
	switch d {
	case gr4ph.DomainEnterprise:
		return "enterprise"
	case gr4ph.DomainICS:
		return "ics"
	case gr4ph.DomainMobile:
		return "mobile"
	}
	return "sparta"
}

func join(names []string, limit int) string {
	if len(names) <= limit {
		return strings.Join(names, " ")
	}
	return strings.Join(names[:limit], " ") + " ..."
}

func ttpNames(e *gr4ph.Engine, ids []gr4ph.TTP) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = e.TTPName(id)
	}
	return out
}

func artifactNames(e *gr4ph.Engine, ids []gr4ph.Artifact) []string {
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
