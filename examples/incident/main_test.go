//go:build goexperiment.simd

package main

import (
	"bytes"
	"strings"
	"testing"
)

// wantStdout pins the example's stdout verbatim; the README's "The two flows"
// section describes the five stages it walks and the command to run it, but
// quotes no output, so this constant is the executable contract.
const wantStdout = `nodes: 3 ttp, 2 artifacts, 1 countermeasure; rels 2/1; wordsPerRow 1/1/1
incident "lsass memory" -> T1003.001 (sub of T1003)
artifacts(T1003.001) = [Process]
artifactsRollup(T1003) = [File Process]
ttps(Process) = [T1003.001]
ttpsRollup(Process) = [T1003]
countermeasuresForTTP(T1003.001) = [CredentialHardening]
countermeasuresForArtifactViaTTPs(Process) = [CredentialHardening]
response: [T1003.001 LSASS Memory]
`

func TestIncidentExampleOutput(t *testing.T) {
	var buf bytes.Buffer
	if err := run(&buf); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := buf.String(); got != wantStdout {
		t.Fatalf("stdout mismatch\n--- got ---\n%s--- want ---\n%s", got, wantStdout)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatal("output must end with a newline")
	}
}
