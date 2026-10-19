//go:build goexperiment.simd

package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestOntologyExampleOutput runs the example against the committed tables. The
// first two lines are the contract the README's "The two flows" section
// advertises - the frozen table shape and the hierarchy - and the rest are
// per-query answers whose numbers the library and CLI tests already pin, so what
// is asserted here is that the flow still walks its stages on the real tables
// and resolves the incident it advertises.
func TestOntologyExampleOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatalf("run: %v", err)
	}
	out := buf.String()

	const wantShape = `ontology: 1186 ttps (858 enterprise, 176 mobile, 106 ics, 46 sparta), 247 artifacts, 157 countermeasures; rels 41/38; edges 670/182/4133; wordsPerRow 19/4/3/2
hierarchy: 605 top-level, 581 sub-techniques, 148 parents, max 18 children (T1546)
`
	if !strings.HasPrefix(out, wantShape) {
		t.Errorf("the example's first two lines are the table shape\n--- got ---\n%s", out)
	}
	const wantIncident = `incident "LSASS Memory" -> T1003.001 (enterprise, sub of T1003), 2 artifacts`
	if !strings.Contains(out, wantIncident) {
		t.Errorf("output must resolve the incident it advertises\n--- got ---\n%s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("output must end with a newline")
	}
	if strings.Contains(out, "\n\n") {
		t.Error("every stage prints one line: found an empty line")
	}
}
