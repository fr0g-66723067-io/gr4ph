#!/usr/bin/env bash
#
# scenarios.sh — attack and defence scenarios executed against the gr4ph CLI.
#
# Each scenario asks the frozen ATT&CK 19.2 x D3FEND 1.6.0 tables a question the way an
# operator would — from an alert string, from an artifact, from a technique family, or
# from a relation plane — prints the answer the CLI actually gives, and checks it against
# what the tables hold. The point is to exercise the tool end to end on real data and to
# fail loudly if a later regeneration or refactor changes an answer.
#
# Where every expected number comes from:
#   * examples/ontology/main_test.go pins the table shape (1186/247/157 nodes, 670/182/4133
#     edges, the Process / CredentialHardening / ContentQuarantine / CreateProcess figures);
#   * cmd/gr4ph/main_test.go pins the rel plane walk and the union-plane cardinalities
#     (654 offensive pairs, 182 defensive edges);
#   * the recounters below (plane 33 of the offensive edge list) read ontology/attack_gen.go
#     directly, so a scenario can disagree with the tool instead of echoing it.
#
# Usage, from the module root:
#
#   make build && examples/scenarios.sh
#
# Anchored to the module root it reads ontology/attack_gen.go, so set TABLES= (or cd) if
# you run it from elsewhere. GR4PH= overrides the binary, COLS= the display width.
set -uo pipefail

GR4PH=${GR4PH:-./gr4ph}
TABLES=${TABLES:-ontology/attack_gen.go}
COLS=${COLS:-100}

scenarios=0
checks=0
failures=0

if [ ! -x "$GR4PH" ]; then
	printf 'scenarios: %s is not executable — run "make build" first (or set GR4PH=)\n' "$GR4PH" >&2
	exit 2
fi
if [ ! -f "$TABLES" ]; then
	printf 'scenarios: %s not found — run this from the module root (or set TABLES=)\n' "$TABLES" >&2
	exit 2
fi

say() { scenarios=$((scenarios + 1)); printf '\n== %s\n' "$*"; }
note() { printf -- '-- %s\n' "$*"; }

# ask <args...> — run the CLI, showing the invocation and its answer cut to $COLS columns.
# The truncation is display only: the assertions below read the untruncated counts.
ask() {
	printf '$ %s' "$GR4PH"
	printf ' %q' "$@"
	printf '\n'
	"$GR4PH" "$@" | cut -c1-"$COLS"
	[ "${PIPESTATUS[0]}" -eq 0 ] || printf '(exit %d)\n' "${PIPESTATUS[0]}"
}

# count_of <"dir set"> — the "(N)" of that set line on stdin, e.g. "in techniques rollup".
# The direction field is padded to four columns on output ("out " / "in  "), so it is
# normalised back to one space before the label is compared.
count_of() {
	awk -v set="$1" '
		{
			line = $0
			if (line ~ /^  out /) sub(/^  out /, "out ", line)
			else if (line ~ /^  in  /) sub(/^  in  /, "in ", line)
			else next
			if (substr(line, 1, length(set) + 1) != set " ") next
			rest = substr(line, length(set) + 3)   # the count, up to ")"
			print substr(rest, 1, index(rest, ")") - 1)
			exit
		}'
}

# count <"dir set"> <args...> — count_of over one CLI invocation.
count() {
	local set=$1
	shift
	"$GR4PH" "$@" | count_of "$set"
}

# line <n> <args...> — the n-th line of the output, for the whole-line pins.
line() {
	local n=$1
	shift
	"$GR4PH" "$@" | sed -n "${n}p"
}

# expect <what> <got> <want>
expect() {
	checks=$((checks + 1))
	if [ "$2" = "$3" ]; then
		printf '   ok   %-46s %s\n' "$1" "$2"
	else
		printf '   FAIL %-46s got %s, want %s\n' "$1" "$2" "$3"
		failures=$((failures + 1))
	fi
}

# Defence 1 ------------------------------------------------------------------------------
# An alert names a technique by label, the way a detection or an operator would.
say "Defence 1 — triage a credential-dumping alert"
ask ttp 'lsass memory'
expect "T1003.001 artifacts" "$(count "out artifacts" ttp 'lsass memory')" 2
expect "T1003.001 countermeasures" "$(count "in countermeasures" ttp 'lsass memory')" 12

# The parent is where the family's coverage lives: the sub-technique itself has no direct
# artifact, but its rolled-up set carries the whole family (examples/ontology/main_test.go
# pins artifactsRollup(T1003) = 9 and countermeasuresForTTPRollup(T1003) = 48).
ask ttp T1003
expect "T1003 artifacts" "$(count "out artifacts" ttp T1003)" 0
expect "T1003 artifacts rollup" "$(count "out artifacts rollup" ttp T1003)" 9
expect "T1003 countermeasures" "$(count "in countermeasures" ttp T1003)" 0
expect "T1003 countermeasures rollup" "$(count "in countermeasures rollup" ttp T1003)" 48

# Defence 2 ------------------------------------------------------------------------------
# Start from the artifact an alert names, then narrow the technique set to the relation
# plane the alert is about: 5 techniques touch Process, only one of them "accesses" it.
say "Defence 2 — artifact-first triage, then narrow to the alert-level relation"
ask artifact Process
expect "Process techniques" "$(count "in techniques" artifact Process)" 5
expect "Process techniques rollup" "$(count "in techniques rollup" artifact Process)" 3
expect "Process countermeasures" "$(count "in countermeasures" artifact Process)" 11
expect "Process countermeasures viaTTPs" "$(count "in countermeasures viaTTPs" artifact Process)" 36

ask artifact -rel accesses Process
expect "Process techniques by accesses" "$(count "in techniques (rel accesses)" artifact -rel accesses Process)" 1
expect "Process techniques rollup by accesses" "$(count "in techniques rollup (rel accesses)" artifact -rel accesses Process)" 1

# Defence 3 ------------------------------------------------------------------------------
# Some artifacts have no direct countermeasure at all: the defence arrives only through the
# techniques that touch them (the corpus-wide count is asserted in Defence 4).
say "Defence 3 — defence that only exists through the techniques"
ask artifact AuthenticationService
expect "AuthenticationService direct countermeasures" "$(count "in countermeasures" artifact AuthenticationService)" 0
expect "AuthenticationService viaTTPs" "$(count "in countermeasures viaTTPs" artifact AuthenticationService)" 25

ask artifact SystemConfigurationDatabaseRecord
expect "SystemConfigurationDatabaseRecord techniques" "$(count "in techniques" artifact SystemConfigurationDatabaseRecord)" 19
expect "SystemConfigurationDatabaseRecord direct countermeasures" "$(count "in countermeasures" artifact SystemConfigurationDatabaseRecord)" 0
expect "SystemConfigurationDatabaseRecord viaTTPs" "$(count "in countermeasures viaTTPs" artifact SystemConfigurationDatabaseRecord)" 40

# Defence 4 ------------------------------------------------------------------------------
# The same question over the whole artifact partition: 227 of the 247 artifacts carry attack
# surface, every one of them has at least one countermeasure reachable through the
# techniques that touch it, and exactly 160 have no direct countermeasure — their defence
# exists only through those techniques.
say "Defence 4 — corpus sweep: no artifact is left without a defence surface"
note "one CLI invocation per artifact, $(sed -n '/^var ArtifactNames = /,/^}/p' "$TABLES" | grep -c '"') in the partition"
swept=0
with_surface=0
via_only=0
undefended=0
while read -r name; do
	swept=$((swept + 1))
	out=$("$GR4PH" artifact "$name")
	tech=$(printf '%s\n' "$out" | count_of "in techniques")
	[ "${tech:-0}" -gt 0 ] && with_surface=$((with_surface + 1))
	direct=$(printf '%s\n' "$out" | count_of "in countermeasures")
	via=$(printf '%s\n' "$out" | count_of "in countermeasures viaTTPs")
	if [ "${direct:-0}" -eq 0 ]; then
		via_only=$((via_only + 1))
		[ "${via:-0}" -eq 0 ] && {
			undefended=$((undefended + 1))
			printf '   gap: %s (%s techniques, no countermeasure at all)\n' "$name" "$tech"
		}
	fi
done <<<"$(sed -n '/^var ArtifactNames = /,/^}/p' "$TABLES" | grep -o '"[^"]*"' | tr -d '"')"
note "$swept artifacts: $with_surface with attack surface, $via_only with no direct countermeasure"
expect "artifacts swept" "$swept" 247
expect "artifacts with attack surface" "$with_surface" 227
expect "artifacts defended only via techniques" "$via_only" 160
expect "artifacts with no defence surface" "$undefended" 0

# Defence 5 ------------------------------------------------------------------------------
# What the tables actually name: the two commonest detection words are thin, and a relation
# name can belong to both families (blocks: offensive plane 4, defensive plane 3).
say "Defence 5 — relation census: how thin the telemetry naming is"
ask rel monitors
expect "monitors offensive plane" "$(line 1 rel monitors)" "rel monitors offensive plane 34/41 (technique -> artifact): edges=5 sources=5"
expect "monitors defensive plane" "$(line 2 rel monitors)" "rel monitors defensive plane 22/38 (countermeasure -> artifact): edges=9 sources=9"

ask rel detects
expect "detects defensive plane" "$(line 1 rel detects)" "rel detects defensive plane 7/38 (countermeasure -> artifact): edges=1 sources=1"

ask rel blocks
expect "blocks offensive plane" "$(line 1 rel blocks)" "rel blocks offensive plane 4/41 (technique -> artifact): edges=2 sources=2"
expect "blocks defensive plane" "$(line 2 rel blocks)" "rel blocks defensive plane 3/38 (countermeasure -> artifact): edges=6 sources=6"

# Defence 6 ------------------------------------------------------------------------------
# Rank countermeasures by the technique surface they cover: the whole defended set, then the
# parents-only view an inventory report wants (the ContentQuarantine degree is pinned by
# examples/ontology/main_test.go).
say "Defence 6 — prioritise countermeasures by technique surface"
ask cm ContentQuarantine
expect "ContentQuarantine artifacts" "$(count "out artifacts" cm ContentQuarantine)" 2
expect "ContentQuarantine techniques" "$(count "out techniques" cm ContentQuarantine)" 125
expect "ContentQuarantine techniques rollup" "$(count "out techniques rollup" cm ContentQuarantine)" 59

ask cm CredentialHardening
expect "CredentialHardening artifacts" "$(count "out artifacts" cm CredentialHardening)" 1
expect "CredentialHardening techniques" "$(count "out techniques" cm CredentialHardening)" 25
expect "CredentialHardening techniques rollup" "$(count "out techniques rollup" cm CredentialHardening)" 16

# Attack 1 -------------------------------------------------------------------------------
# Authorized planning: the artifact with the broadest technique surface, read as the number
# of ways in and the number of countermeasures that have to be evaded (29 techniques and 23
# rolled-up parents are pinned by examples/ontology/main_test.go).
say "Attack 1 — the broadest attack surface in the artifact partition"
ask artifact CreateProcess
expect "CreateProcess techniques" "$(count "in techniques" artifact CreateProcess)" 29
expect "CreateProcess techniques rollup" "$(count "in techniques rollup" artifact CreateProcess)" 23
expect "CreateProcess countermeasures" "$(count "in countermeasures" artifact CreateProcess)" 4
expect "CreateProcess countermeasures viaTTPs" "$(count "in countermeasures viaTTPs" artifact CreateProcess)" 64

# Attack 2 -------------------------------------------------------------------------------
# The offensive plane census an operator sizes a plan with, cross-checked by recounting the
# plane from the generated edge list: plane 33 is "modifies".
say "Attack 2 — offensive plane census, cross-checked against the tables"
ask rel modifies
expect "modifies offensive plane" "$(line 1 rel modifies)" "rel modifies offensive plane 33/41 (technique -> artifact): edges=130 sources=127"
expect "modifies edges recounted from $TABLES" \
	"$(sed -n '/^var OffEdgeRel = /,/^}/p' "$TABLES" | tr ',' '\n' | tr -d ' \t' | grep -cx 33)" 130
expect "modifies union plane (RelAny)" "$(line 1 rel any)" "rel any offensive union plane 0/41 (technique -> artifact): edges=654 sources=427"

# Attack 3 -------------------------------------------------------------------------------
# The tables are not enterprise-only: an ICS technique, a mobile technique with no artifact
# surface at all, and a D3FEND-named node in no ATT&CK domain (sparta), whose coverage only
# exists through the hierarchy.
say "Attack 3 — reach outside the enterprise domain"
ask ttp T0821
expect "T0821 header" "$(line 1 ttp T0821)" 'ttp T0821 "Modify Controller Tasking" domain=ics children=0'
expect "T0821 artifacts" "$(count "out artifacts" ttp T0821)" 2
expect "T0821 countermeasures" "$(count "in countermeasures" ttp T0821)" 15

ask ttp T1603
expect "T1603 header" "$(line 1 ttp T1603)" 'ttp T1603 "Scheduled Task/Job" domain=mobile children=0'
expect "T1603 artifacts" "$(count "out artifacts" ttp T1603)" 0
expect "T1603 countermeasures" "$(count "in countermeasures" ttp T1603)" 0

ask ttp DE-0003
expect "DE-0003 header" "$(line 1 ttp DE-0003)" 'ttp DE-0003 "On-Board Values Obfuscation" domain=sparta children=1'
expect "DE-0003 artifacts" "$(count "out artifacts" ttp DE-0003)" 0
expect "DE-0003 artifacts rollup" "$(count "out artifacts rollup" ttp DE-0003)" 1

printf '\n%d scenarios, %d checks, %d failures\n' "$scenarios" "$checks" "$failures"
[ "$failures" -eq 0 ] || exit 1
