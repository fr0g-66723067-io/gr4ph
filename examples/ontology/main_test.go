//go:build goexperiment.simd

package main

import (
	"bytes"
	"strings"
	"testing"
)

// wantStdout pins the example's stdout verbatim: the numbers are the frozen
// ATT&CK 19.2 x D3FEND 1.6.0 shape (the README quotes no example output).
const wantStdout = `ontology: 1186 ttps (858 enterprise, 176 mobile, 106 ics, 46 sparta), 247 artifacts, 157 countermeasures; rels 41/38; edges 670/182/4133; wordsPerRow 19/4/3
hierarchy: 605 top-level, 581 sub-techniques, 148 parents, max 18 children (T1546)
ttps(Process) = 5: T1003.001 T1003.002 T1003.004 T1505.003 T1546.007
ttpsRollup(Process) = 3: T1003 T1505 T1546
ttps(Process, accesses) = 1: T1003.001
ttps(Process, modifies) = 0
artifacts(T1003.001) = 2: AuthenticationService Process
artifacts(T1003) = 0; artifactsRollup(T1003) = 9: AuthenticationService EncryptedCredential EventLog IntranetAdministrativeNetworkTraffic Log OperatingSystemFile PasswordFile Process SystemPasswordDatabase
ttps(CreateProcess) = 29; ttpsRollup(CreateProcess) = 23
ttpsAny(Process, File) = 22
countermeasuresForArtifact(Process) = 11; viaTTPs = 36: Application-basedProcessIsolation ConfigurationInventory ContentFiltering ContentModification ContentQuarantine ...
countermeasuresForArtifact(AuthenticationService) = 0; viaTTPs = 25: Application-basedProcessIsolation AssetVulnerabilityEnumeration DataInventory Hardware-basedProcessIsolation HostReboot ...
countermeasuresForTTP(T1003) = 0; rollup = 48: AdministrativeNetworkActivityAnalysis Application-basedProcessIsolation ApplicationExceptionMonitoring ApplicationProtocolCommandAnalysis AuthenticationCacheInvalidation ...
ttpsForCountermeasure(CredentialHardening) = 25 (rolled 16): DE-0011 PER-0005 T0812 T0891 T0892 ...
artifactsForCountermeasure(CredentialHardening, hardens) = [Credential]
countermeasureDegree(ContentQuarantine) = 125
incident "LSASS Memory" -> T1003.001 (enterprise, sub of T1003), 2 artifacts
incident "T0894" -> T0894 (ics), 8 artifacts
incident "T1603" -> T1603 (mobile), 0 artifacts
`

func TestOntologyExampleOutput(t *testing.T) {
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
