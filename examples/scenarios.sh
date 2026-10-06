#!/usr/bin/env bash
#
# scenarios.sh — a tour of the gr4ph command line.
#
# Each block below prints one real invocation and the answer the tool gives, so you can see
# the shapes and pick the ones that fit your question. Nothing is checked and nothing is
# expected: run it to read the tool's own output.
#
# The defence sections read an alert, an artifact or a countermeasure the way a responder
# does; the attack sections read the same graph the way an operator planning authorized
# testing does. The last section shows the machine-readable form, the failures and the help.
#
#   make build && examples/scenarios.sh
#
# GR4PH= overrides the binary (default ./gr4ph), COLS= the display width (default 100).
set -uo pipefail

GR4PH=${GR4PH:-./gr4ph}
COLS=${COLS:-100}

if [ ! -x "$GR4PH" ]; then
	printf 'scenarios: %s is not executable — run "make build" first (or set GR4PH=)\n' "$GR4PH" >&2
	exit 2
fi

# section <title> — start a group of related invocations.
section() { printf '\n=== %s\n' "$*"; }

# ask <args...> — show the invocation and what the CLI answers, cut to $COLS columns for
# width. The "(exit N)" line appears only when the command did not succeed.
ask() {
	printf '\n$ %s' "$GR4PH"
	printf ' %q' "$@"
	printf '\n'
	"$GR4PH" "$@" | cut -c1-"$COLS"
	local status=${PIPESTATUS[0]}
	[ "$status" -eq 0 ] || printf '(exit %d)\n' "$status"
}

section "Defence — an alert arrives as a label, not as an id"
ask ttp 'lsass memory'                # id, label or alias; trimmed and case-insensitive

section "Defence — this sub-technique, or its whole family"
ask ttp T1003.001                     # exact: what this sub-technique itself touches
ask ttp T1003                         # rolled up: the family, sub-techniques collapsed to parents

section "Defence — start from the artifact instead"
ask artifact Process                  # techniques that touch it, then the countermeasures that apply
ask artifact -rel accesses Process    # only the techniques linked by that offensive relation
ask artifact -defrel suspends Process # only the countermeasures linked by that defensive relation

section "Defence — start from a countermeasure"
ask cm ContentQuarantine              # the artifacts and techniques it covers, exact and rolled up
ask cm -defrel hardens CredentialHardening # restricted to one defensive relation

section "Defence — several questions in one invocation"
ask artifact Process File             # one block per query: Process, then File

section "Defence — read the relation planes themselves"
ask rel any                           # the two union planes, with edges and sources each
ask rel monitors                      # a name in both families: one line per family
ask rel detects
ask rel -family def blocks            # -family narrows to the side you asked for

section "Attack — the artifacts a technique is about"
ask ttp T1546.007                     # every artifact this technique touches
ask ttp T1546.007 -rel modifies       # ... restricted to the relation the question is about
ask ttp T0821                         # an ICS technique: OT artifacts, same commands

section "Attack — how much surface there is"
ask artifact CreateProcess            # the widest artifact in the partition
ask rel modifies                      # the largest offensive plane, counted pair by pair
ask ttp DE-0003                       # a D3FEND-named node (domain=sparta) whose coverage is rolled up

section "Scripting — one JSON object per resolved query"
COLS=140 ask -json rel detects        # a rel result: family, plane id, edges, sources
COLS=400 ask -json ttp T1603          # a node result (a mobile technique with no links): id, keys, sets

section "Failures and help"
ask ttp 'lsass memroy'                # unresolved key: a message, exit 1, no block
ask rel -family sideways accesses     # usage error: exit 2
ask help                              # flags, exit statuses and the four commands

printf '\nDone — every line above came from %s.\n' "$GR4PH"
