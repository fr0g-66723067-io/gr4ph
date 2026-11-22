#!/bin/sh
# Artifact-level gate: the binary a user downloads must answer from the frozen
# tables it was built with.
set -eu
bin=${1:?usage: smoke.sh BINARY}
out=$("$bin" ttp T1003.001 2>&1) || { echo "smoke: ttp failed: $out" >&2; exit 1; }
case "$out" in *"LSASS Memory"*) : ;; *) echo "smoke: T1003.001 did not resolve" >&2; exit 1 ;; esac
"$bin" kev CVE-2021-44228 >/dev/null
echo "   T1003.001 resolves; KEV CVE-2021-44228 answers"
