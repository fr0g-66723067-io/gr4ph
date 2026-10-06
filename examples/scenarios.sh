#!/usr/bin/env bash
#
# scenarios.sh — the ways to ask the gr4ph CLI a question, on defence and attack data.
# Every command prints the tool's complete answer; a set is one line, however long its
# node list is, so let the terminal wrap it.
#
#   make build && examples/scenarios.sh
#
# Run from the module root: the commands use ./gr4ph, the binary `make build` produces.
# Without it every line would fail with "No such file or directory", so stop here instead.
if [ ! -x ./gr4ph ]; then
	printf 'scenarios: ./gr4ph is missing or not executable — run "make build" first\n' >&2
	exit 1
fi

echo
echo '==============================================================================='
echo 'Defence 1 — an alert arrives as a label, not as an id'
echo '==============================================================================='
./gr4ph ttp 'lsass memory'            # id, label or alias; trimmed and case-insensitive

echo
echo '==============================================================================='
echo 'Defence 2 — this sub-technique, or its whole family rolled up'
echo '==============================================================================='
./gr4ph ttp T1003.001                 # exact: what this sub-technique itself touches
./gr4ph ttp T1003                     # rolled up: sub-techniques collapsed onto their parents

echo
echo '==============================================================================='
echo 'Defence 3 — start from the artifact, then narrow either direction'
echo '==============================================================================='
./gr4ph artifact Process              # techniques that touch it, then the countermeasures that apply
./gr4ph artifact -rel accesses Process    # only the techniques linked by that offensive relation
./gr4ph artifact -defrel suspends Process # only the countermeasures linked by that defensive relation

echo
echo '==============================================================================='
echo 'Defence 4 — start from a countermeasure'
echo '==============================================================================='
./gr4ph cm ContentQuarantine          # what it covers, exact and rolled up
./gr4ph cm -defrel hardens CredentialHardening

echo
echo '==============================================================================='
echo 'Defence 5 — several questions in one invocation'
echo '==============================================================================='
./gr4ph artifact Process File         # one block per query

echo
echo '==============================================================================='
echo 'Defence 6 — the relation planes themselves'
echo '==============================================================================='
./gr4ph rel any                       # the two union planes, with edges and sources
./gr4ph rel monitors                  # a name in both families: one line per family
./gr4ph rel detects
./gr4ph rel -family def blocks        # -family picks the side you asked for

echo
echo '==============================================================================='
echo 'Attack 1 — the artifacts a technique is about'
echo '==============================================================================='
./gr4ph ttp T1546.007                 # everything it touches
./gr4ph ttp T1546.007 -rel modifies   # only what it modifies
./gr4ph ttp T0821                     # an ICS technique: OT artifacts, same commands

echo
echo '==============================================================================='
echo 'Attack 2 — how much surface there is'
echo '==============================================================================='
./gr4ph artifact CreateProcess        # the widest artifact in the partition
./gr4ph rel modifies                  # the largest offensive plane
./gr4ph ttp DE-0003                   # a D3FEND-named node (domain=sparta), coverage rolled up

echo
echo '==============================================================================='
echo 'Scripting — one JSON object per resolved query'
echo '==============================================================================='
./gr4ph -json rel detects
./gr4ph -json ttp T1603

echo
echo '==============================================================================='
echo 'Failures — an unresolved key (exit 1) and a usage error (exit 2)'
echo '==============================================================================='
./gr4ph ttp 'lsass memroy'
echo $?
./gr4ph rel -family sideways accesses
echo $?

echo
echo '==============================================================================='
echo 'Help — the whole interface'
echo '==============================================================================='
./gr4ph help
