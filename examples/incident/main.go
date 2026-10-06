//go:build goexperiment.simd

// Command incident walks the five stages of a gr4ph query on a small
// hand-built graph:
//
//  1. boot — register nodes and relations (cold path, strings);
//
//  2. wire — hard-code the relationships;
//
//  3. incident — turn a cold alert string into a uint16 id;
//
//  4. evaluation — run the hot traversals (both directions, plus roll-up and
//     the countermeasure chain);
//
//  5. response — format the ids back into a log line (cold path again).
//
//     GOEXPERIMENT=simd go run ./examples/incident
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/fr0g-66723067/gr4ph"
)

func main() {
	if err := run(os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "incident:", err)
		os.Exit(1)
	}
}

// run writes the whole walkthrough to w so the documented output can be pinned
// by a test.
func run(w io.Writer) error {
	// Stage 1: boot. Nodes and relations are registered with their cold keys.
	b := gr4ph.NewBuilder()

	accesses, err := b.AddRel("accesses")
	if err != nil {
		return err
	}
	if _, err := b.AddRel("modifies"); err != nil { // registered, unused here
		return err
	}
	analyzes, err := b.AddDefRel("analyzes")
	if err != nil {
		return err
	}

	t1003, err := b.AddTTP("T1003", "OS Credential Dumping", gr4ph.DomainEnterprise, gr4ph.NoParent)
	if err != nil {
		return err
	}
	t1003a, err := b.AddTTP("T1003.001", "LSASS Memory", gr4ph.DomainEnterprise, t1003)
	if err != nil {
		return err
	}
	if _, err := b.AddTTP("T1059", "Command and Scripting Interpreter", gr4ph.DomainEnterprise, gr4ph.NoParent); err != nil {
		return err
	}

	// File is registered first so its index precedes Process: enumeration is
	// always ascending by index.
	file, err := b.AddArtifact("File", "File")
	if err != nil {
		return err
	}
	process, err := b.AddArtifact("Process", "Process")
	if err != nil {
		return err
	}
	hardening, err := b.AddCountermeasure("CredentialHardening", "Credential Hardening")
	if err != nil {
		return err
	}

	// Stage 2: wire. Technique -> artifact, countermeasure -> artifact, and
	// countermeasure -> technique.
	if err := b.AddEdge(t1003a, process, accesses); err != nil {
		return err
	}
	if err := b.AddEdge(t1003, file, accesses); err != nil {
		return err
	}
	if err := b.AddDefEdge(hardening, file, analyzes); err != nil {
		return err
	}
	if err := b.AddDefendsEdge(hardening, t1003a); err != nil {
		return err
	}

	e, err := b.Build()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "nodes: %d ttp, %d artifacts, %d countermeasure; rels %d/%d; wordsPerRow %d/%d/%d\n",
		e.TTPCount(), e.ArtifactCount(), e.CountermeasureCount(), e.RelCount(), e.DefRelCount(),
		e.WordsPerRow(gr4ph.KindTTP), e.WordsPerRow(gr4ph.KindArtifact), e.WordsPerRow(gr4ph.KindCountermeasure))

	// Stage 3: incident. A cold alert string becomes an id; everything after
	// this point is integer arithmetic.
	id, ok := e.Incident("lsass memory")
	if !ok {
		return fmt.Errorf("unknown alert %q", "lsass memory")
	}
	parent, _ := e.TTPParent(id)
	fmt.Fprintf(w, "incident %q -> %s (sub of %s)\n", "lsass memory", e.TTPName(id), e.TTPName(parent))

	// Stage 4: evaluation. Both directions, exact and rolled up.
	artifacts := make([]gr4ph.Artifact, e.ArtifactCount())
	n := e.Artifacts(id, artifacts)
	fmt.Fprintf(w, "artifacts(%s) = %v\n", e.TTPName(id), artifactNames(e, artifacts[:n]))

	rollup := make([]gr4ph.Artifact, e.ArtifactCount())
	scratchA := make([]uint64, e.WordsPerRow(gr4ph.KindArtifact))
	n = e.ArtifactsRollup(parent, scratchA, rollup)
	fmt.Fprintf(w, "artifactsRollup(%s) = %v\n", e.TTPName(parent), artifactNames(e, rollup[:n]))

	ttps := make([]gr4ph.TTP, e.TTPCount())
	scratchT := make([]uint64, e.WordsPerRow(gr4ph.KindTTP))
	n = e.TTPs(process, ttps)
	fmt.Fprintf(w, "ttps(%s) = %v\n", e.ArtifactName(process), ttpNames(e, ttps[:n]))
	n = e.TTPsRollup(process, scratchT, ttps)
	fmt.Fprintf(w, "ttpsRollup(%s) = %v\n", e.ArtifactName(process), ttpNames(e, ttps[:n]))

	cms := make([]gr4ph.Countermeasure, e.CountermeasureCount())
	n = e.CountermeasuresForTTP(id, cms)
	fmt.Fprintf(w, "countermeasuresForTTP(%s) = %v\n", e.TTPName(id), cmNames(e, cms[:n]))

	scratchC := make([]uint64, e.WordsPerRow(gr4ph.KindCountermeasure))
	n = e.CountermeasuresForArtifactViaTTPs(process, scratchC, cms)
	fmt.Fprintf(w, "countermeasuresForArtifactViaTTPs(%s) = %v\n", e.ArtifactName(process), cmNames(e, cms[:n]))

	// Stage 5: response. Ids become log lines again.
	lines := make([]string, e.TTPCount())
	n = e.Response(lines, []gr4ph.TTP{id})
	fmt.Fprintf(w, "response: %v\n", lines[:n])
	return nil
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
