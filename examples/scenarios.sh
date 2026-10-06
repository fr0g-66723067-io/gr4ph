#!/usr/bin/env bash
#
# scenarios.sh — the ways to ask the gr4ph CLI a question, on defence and attack data.
# Every command prints the tool's complete answer; a set is one line, however long its
# node list is, so let the terminal wrap it.
#
#   make build && examples/scenarios.sh
#
# Run from the module root: the commands use ./gr4ph, the binary `make build` produces.

echo 'Defence: an alert arrives as a label, not as an id'
./gr4ph ttp 'lsass memory'            # id, label or alias; trimmed and case-insensitive

echo 'Defence: this sub-technique, or its whole family rolled up'
./gr4ph ttp T1003.001                 # exact: what this sub-technique itself touches
./gr4ph ttp T1003                     # rolled up: sub-techniques collapsed onto their parents

echo 'Defence: start from the artifact, then narrow either direction'
./gr4ph artifact Process              # techniques that touch it, then the countermeasures that apply
./gr4ph artifact -rel accesses Process    # only the techniques linked by that offensive relation
./gr4ph artifact -defrel suspends Process # only the countermeasures linked by that defensive relation

echo 'Defence: start from a countermeasure'
./gr4ph cm ContentQuarantine          # what it covers, exact and rolled up
./gr4ph cm -defrel hardens CredentialHardening

echo 'Defence: several questions in one invocation'
./gr4ph artifact Process File         # one block per query

echo 'Defence: the relation planes themselves'
./gr4ph rel any                       # the two union planes, with edges and sources
./gr4ph rel monitors                  # a name in both families: one line per family
./gr4ph rel detects
./gr4ph rel -family def blocks        # -family picks the side you asked for

echo 'Attack: the artifacts a technique is about'
./gr4ph ttp T1546.007                 # everything it touches
./gr4ph ttp T1546.007 -rel modifies   # only what it modifies
./gr4ph ttp T0821                     # an ICS technique: OT artifacts, same commands

echo 'Attack: how much surface there is'
./gr4ph artifact CreateProcess        # the widest artifact in the partition
./gr4ph rel modifies                  # the largest offensive plane
./gr4ph ttp DE-0003                   # a D3FEND-named node (domain=sparta), coverage rolled up

echo 'Scripting: one JSON object per resolved query'
./gr4ph -json rel detects
./gr4ph -json ttp T1603

echo 'Failures: an unresolved key (exit 1) and a usage error (exit 2)'
./gr4ph ttp 'lsass memroy'
echo $?
./gr4ph rel -family sideways accesses
echo $?

echo 'Help'
./gr4ph help
