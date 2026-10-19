//go:build goexperiment.simd

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/fr0g-66723067-io/gr4ph"
)

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
			if err := writeText(stdout, res); err != nil {
				fmt.Fprintf(stderr, "gr4ph: %v\n", err)
				return 1
			}
			if i < len(results)-1 {
				if _, err := fmt.Fprintln(stdout); err != nil {
					fmt.Fprintf(stderr, "gr4ph: %v\n", err)
					return 1
				}
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

// errRecorder passes writes through and keeps the first error, so writeText's
// block of formatted lines needs one check instead of one per line. After an
// error it reports success, so a dead stream is not written to again.
type errRecorder struct {
	w   io.Writer
	err error
}

func (r *errRecorder) Write(p []byte) (int, error) {
	if r.err != nil {
		return len(p), nil
	}
	n, err := r.w.Write(p)
	if err != nil {
		r.err = err
	}
	return n, err
}

// writeText writes one block: a header line, then one line per set or plane.
// It returns the first write error, so a full disk or a closed pipe is not
// reported as success.
func writeText(w io.Writer, res result) error {
	rec := &errRecorder{w: w}
	switch res.Kind {
	case "ttp":
		fmt.Fprintf(rec, "ttp %s%s domain=%s%s children=%d%s%s%s%s\n",
			res.Name, quoted(res.Label), res.Domain, parentPart(res.Parent), *res.Children,
			revokedPart(res.Revoked), subTechniquePart(res.SubTechnique),
			tacticsPart(res.Tactics), platformsPart(res.Platforms))
	case "group":
		fmt.Fprintf(rec, "group %s%s kind=%s%s\n", res.Name, quoted(res.Label), res.GroupKind, revokedPart(res.Revoked))
	case "kev":
		fmt.Fprintf(rec, "kev %s%s added=%s ransomware=%t vendor=%q product=%q\n",
			res.Name, quoted(res.Label), res.Added, res.Ransomware, res.Vendor, res.Product)
	case "coverage":
		fmt.Fprintf(rec, "coverage deployed=%d mapped=%d retired=%d\n", *res.Deployed, *res.Mapped, *res.Retired)
	case "gain":
		if res.Greedy != nil {
			fmt.Fprintf(rec, "gain deployed=%d greedy=%d\n", *res.Deployed, *res.Greedy)
		} else {
			fmt.Fprintf(rec, "gain deployed=%d candidates=%d shown=%d\n", *res.Deployed, *res.Candidates, len(res.Gains))
		}
		for _, g := range res.Gains {
			fmt.Fprintf(rec, "  %d  %s%s\n", g.Gain, g.Name, quoted(g.Label))
		}
		return rec.err
	case "contain":
		fmt.Fprintf(rec, "contain observed=%d\n", *res.Observed)
	case "rel":
		for _, p := range res.Planes {
			from, to := "technique", "artifact"
			if p.Family == "defensive" {
				from, to = "countermeasure", "artifact"
			}
			fmt.Fprintf(rec, "rel %s %s %splane %d/%d (%s -> %s): edges=%d sources=%d\n",
				res.Name, p.Family, unionPart(p.ID), p.ID, p.Count, from, to, p.Edges, p.Sources)
		}
		return rec.err
	default:
		fmt.Fprintf(rec, "%s %s%s\n", res.Kind, res.Name, quoted(res.Label))
	}
	for _, s := range res.Sets {
		fmt.Fprintf(rec, "  %-4s%s (%d): %s\n", s.Dir, s.Name, s.Count, nodeList(s.Nodes))
	}
	return rec.err
}

// writeJSON writes res as one JSON object on one line.
func writeJSON(w io.Writer, res result) error {
	return json.NewEncoder(w).Encode(res)
}

// artNodes materializes the first n artifact ids of ids as cold-key nodes.
func artNodes(e *gr4ph.Engine, ids []gr4ph.Artifact, n int) []node {
	nodes := make([]node, 0, n)
	for _, a := range ids[:n] {
		name := e.ArtifactName(a)
		nodes = append(nodes, node{ID: int(a), Name: name, Label: collapseLabel(name, e.ArtifactLabel(a))})
	}
	return nodes
}

// ttpNodes materializes the first n technique ids of ids as cold-key nodes.
func ttpNodes(e *gr4ph.Engine, ids []gr4ph.TTP, n int) []node {
	nodes := make([]node, 0, n)
	for _, t := range ids[:n] {
		name := e.TTPName(t)
		nodes = append(nodes, node{ID: int(t), Name: name, Label: collapseLabel(name, e.TTPLabel(t))})
	}
	return nodes
}

// cmNodes materializes the first n countermeasure ids of ids as cold-key nodes.
func cmNodes(e *gr4ph.Engine, ids []gr4ph.Countermeasure, n int) []node {
	nodes := make([]node, 0, n)
	for _, cm := range ids[:n] {
		name := e.CountermeasureName(cm)
		nodes = append(nodes, node{ID: int(cm), Name: name, Label: collapseLabel(name, e.CountermeasureLabel(cm))})
	}
	return nodes
}

// dcNodes materializes the first n data-component ids of ids as cold-key nodes.
func dcNodes(e *gr4ph.Engine, ids []gr4ph.DataComponent, n int) []node {
	nodes := make([]node, 0, n)
	for _, dc := range ids[:n] {
		name := e.DataComponentID(dc)
		nodes = append(nodes, node{ID: int(dc), Name: name, Label: collapseLabel(name, e.DataComponentLabel(dc))})
	}
	return nodes
}

// groupNodes materializes the first n grouping-node ids of ids as cold-key
// nodes: actors, software and campaigns share one partition, so the kind is
// answered per node by `group`, not by this list.
func groupNodes(e *gr4ph.Engine, ids []gr4ph.Group, n int) []node {
	nodes := make([]node, 0, n)
	for _, g := range ids[:n] {
		name := e.GroupID(g)
		nodes = append(nodes, node{ID: int(g), Name: name, Label: collapseLabel(name, e.GroupLabel(g))})
	}
	return nodes
}

// cweNodes materializes the first n weakness ids of ids as cold-key nodes. A
// weakness has no separate label, so every node prints its id alone.
func cweNodes(e *gr4ph.Engine, ids []gr4ph.CWE, n int) []node {
	nodes := make([]node, 0, n)
	for _, c := range ids[:n] {
		nodes = append(nodes, node{ID: int(c), Name: e.CWEID(c)})
	}
	return nodes
}

// kevNodes materializes the first n KEV entry ids of ids as cold-key nodes: the
// CVE id is the name and the vulnerability title the label, as in the kev
// header.
func kevNodes(e *gr4ph.Engine, ids []gr4ph.KEV, n int) []node {
	nodes := make([]node, 0, n)
	for _, k := range ids[:n] {
		name := e.KEVID(k)
		nodes = append(nodes, node{ID: int(k), Name: name, Label: collapseLabel(name, e.KEVName(k))})
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

// revokedPart renders the revoked field of a ttp header, absent when the
// technique is live.
func revokedPart(revoked bool) string {
	if !revoked {
		return ""
	}
	return " revoked=true"
}

// subTechniquePart renders the sub-technique marker, absent for a top-level
// technique. The parent= field says the same thing; the marker reports the
// generated attribute flag the API exposes.
func subTechniquePart(sub bool) string {
	if !sub {
		return ""
	}
	return " subtechnique=true"
}

// tacticsPart renders the tactic ids of a ttp header in mask order, absent when
// the technique has no ATT&CK tactic (the D3FEND-named nodes).
func tacticsPart(ids []string) string {
	if len(ids) == 0 {
		return ""
	}
	return " tactics=" + strings.Join(ids, ",")
}

// platformsPart renders the platform names of a ttp header in mask order.
func platformsPart(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return " platforms=" + strings.Join(names, ",")
}

// tacticIDs renders a tactic mask as its ids in index order, so Tactics[i] is
// the id of bit i.
func tacticIDs(e *gr4ph.Engine, mask uint64) []string {
	var out []string
	for i := 0; i < e.TacticCount(); i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, e.TacticID(gr4ph.Tactic(i)))
		}
	}
	return out
}

// platformNames renders a platform mask as its names in index order.
func platformNames(e *gr4ph.Engine, mask uint64) []string {
	var out []string
	for i := 0; i < e.PlatformCount(); i++ {
		if mask&(1<<uint(i)) != 0 {
			out = append(out, e.PlatformName(gr4ph.Platform(i)))
		}
	}
	return out
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
