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

echo
echo "--- ./gr4ph ttp 'lsass memory'"
./gr4ph ttp 'lsass memory'            # id, label or alias; trimmed and case-insensitive

echo
echo '==============================================================================='
echo 'Defence 2 — this sub-technique, or its whole family rolled up'
echo '==============================================================================='

echo
echo '--- ./gr4ph ttp T1003.001'
./gr4ph ttp T1003.001                 # exact: what this sub-technique itself touches

echo
echo '--- ./gr4ph ttp T1003'
./gr4ph ttp T1003                     # rolled up: sub-techniques collapsed onto their parents

echo
echo '==============================================================================='
echo 'Defence 3 — start from the artifact, then narrow either direction'
echo '==============================================================================='

echo
echo '--- ./gr4ph artifact Process'
./gr4ph artifact Process              # techniques that touch it, then the countermeasures that apply

echo
echo '--- ./gr4ph artifact -rel accesses Process'
./gr4ph artifact -rel accesses Process    # only the techniques linked by that offensive relation

echo
echo '--- ./gr4ph artifact -defrel suspends Process'
./gr4ph artifact -defrel suspends Process # only the countermeasures linked by that defensive relation

echo
echo '==============================================================================='
echo 'Defence 4 — start from a countermeasure'
echo '==============================================================================='

echo
echo '--- ./gr4ph cm ContentQuarantine'
./gr4ph cm ContentQuarantine          # what it covers, exact and rolled up

echo
echo '--- ./gr4ph cm -defrel hardens CredentialHardening'
./gr4ph cm -defrel hardens CredentialHardening

echo
echo '==============================================================================='
echo 'Defence 5 — several questions in one invocation'
echo '==============================================================================='

echo
echo '--- ./gr4ph artifact Process File'
./gr4ph artifact Process File         # one block per query

echo
echo '==============================================================================='
echo 'Defence 6 — the relation planes themselves'
echo '==============================================================================='

echo
echo '--- ./gr4ph rel any'
./gr4ph rel any                       # the two union planes, with edges and sources

echo
echo '--- ./gr4ph rel monitors'
./gr4ph rel monitors                  # a name in both families: one line per family

echo
echo '--- ./gr4ph rel detects'
./gr4ph rel detects

echo
echo '--- ./gr4ph rel -family def blocks'
./gr4ph rel -family def blocks        # -family picks the side you asked for

echo
echo '==============================================================================='
echo 'Attack 1 — the artifacts a technique is about'
echo '==============================================================================='

echo
echo '--- ./gr4ph ttp T1546.007'
./gr4ph ttp T1546.007                 # everything it touches

echo
echo '--- ./gr4ph ttp T1546.007 -rel modifies'
./gr4ph ttp T1546.007 -rel modifies   # only what it modifies

echo
echo '--- ./gr4ph ttp T0821'
./gr4ph ttp T0821                     # an ICS technique: OT artifacts, same commands

echo
echo '==============================================================================='
echo 'Defence 7 — the ATT&CK attributes and the two new partitions'
echo '==============================================================================='

echo
echo '--- ./gr4ph ttp T1003.001'
./gr4ph ttp T1003.001                 # the header carries the attribute masks and the data components / groups

echo
echo '--- ./gr4ph dc DC0084'
./gr4ph dc DC0084                     # a data component: the techniques its log sources detect

echo
echo '--- ./gr4ph group G0007'
./gr4ph group G0007                   # an actor: what it uses, and who uses it

echo
echo '--- ./gr4ph group S0002'
./gr4ph group S0002                   # a software node: the other direction of the same family

echo
echo '--- ./gr4ph tactic TA0005'
./gr4ph tactic TA0005                 # an ATT&CK tactic by TA id (labels repeat across domains)

echo
echo '--- ./gr4ph platform Windows'
./gr4ph platform Windows              # one platform: which techniques run on it

echo
echo '==============================================================================='
echo 'Attack 2 — how much surface there is'
echo '==============================================================================='

echo
echo '--- ./gr4ph artifact CreateProcess'
./gr4ph artifact CreateProcess        # the widest artifact in the partition

echo
echo '--- ./gr4ph rel modifies'
./gr4ph rel modifies                  # the largest offensive plane

echo
echo '--- ./gr4ph ttp DE-0003'
./gr4ph ttp DE-0003                   # a D3FEND-named node (domain=sparta), coverage rolled up

echo
echo '==============================================================================='
echo 'Scripting — one JSON object per resolved query'
echo '==============================================================================='

echo
echo '--- ./gr4ph -json rel detects'
./gr4ph -json rel detects

echo
echo '--- ./gr4ph -json ttp T1603'
./gr4ph -json ttp T1603

echo
echo '==============================================================================='
echo 'Failures — an unresolved key (exit 1) and a usage error (exit 2)'
echo '==============================================================================='

echo
echo "--- ./gr4ph ttp 'lsass memroy'"
./gr4ph ttp 'lsass memroy'            # unresolved: a message, exit 1, no block
echo $?

echo
echo '--- ./gr4ph rel -family sideways accesses'
./gr4ph rel -family sideways accesses # usage error: exit 2
echo $?

echo
echo '==============================================================================='
echo 'Help — the whole interface'
echo '==============================================================================='

echo
echo '--- ./gr4ph help'
./gr4ph help
