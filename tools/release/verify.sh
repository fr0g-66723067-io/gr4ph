#!/bin/sh
# Verifies the artifacts `make release-binaries` produced.
#
# What this proves: SHA256SUMS matches the bytes; every expected target exists;
# each binary is the architecture and container format its name claims; the
# native binary reports the tag; and tools/release/smoke.sh applies the repo's
# own artifact-level gate. A release asset that does not verify is worse than
# none: it teaches users to ignore the check.
#
# Usage: verify.sh DIST VERSION
set -eu

dist=${1:?usage: verify.sh DIST VERSION}
version=${2:?usage: verify.sh DIST VERSION}
fail() { echo "verify-release: $*" >&2; exit 1; }
root=$(cd "$(dirname "$0")/../.." && pwd)

[ -f "$dist/SHA256SUMS" ] || fail "no $dist/SHA256SUMS"
count=$(grep -c . "$dist/SHA256SUMS")
[ "$count" -eq 5 ] || fail "$dist/SHA256SUMS covers $count files, wanted 5"

echo "== checksums"
(cd "$dist" && sha256sum -c --quiet SHA256SUMS) ||
	fail "SHA256SUMS does not match the artifacts"
echo "   5 artifact(s) verified"

echo "== architectures"
native=
for f in "$dist"/*_"$version"_*; do
	[ -f "$f" ] || fail "no artifacts for $version in $dist"
	base=$(basename "$f")
	stem=${base%.exe}
	os=$(printf '%s\n' "$stem" | awk -F_ '{print $(NF-1)}')
	arch=$(printf '%s\n' "$stem" | awk -F_ '{print $NF}')
	case "$os/$arch" in
	linux/amd64)   want='x86-64' ;;
	linux/arm64)   want='aarch64' ;;
	darwin/amd64)  want='x86_64' ;;
	darwin/arm64)  want='arm64' ;;
	windows/amd64) want='x86-64' ;;
	*) fail "unexpected target $os/$arch in $base" ;;
	esac
	desc=$(file -b "$f")
	case "$desc" in *"$want"*) : ;; *) fail "$base: file reports '$desc', wanted $want" ;; esac
	case "$os" in
	windows) case "$desc" in *PE32*) : ;; *) fail "$base is not a PE binary" ;; esac ;;
	darwin)  case "$desc" in *Mach-O*) : ;; *) fail "$base is not a Mach-O binary" ;; esac ;;
	linux)   case "$desc" in *ELF*) : ;; *) fail "$base is not an ELF binary" ;; esac ;;
	esac
	if [ "$os/$arch" = linux/amd64 ]; then native=$f; fi
	echo "   $base: $want, format ok"
done

for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do
	os=${target%/*}
	arch=${target#*/}
	found=
	for f in "$dist"/*_"$version"_"$os"_"$arch" "$dist"/*_"$version"_"$os"_"$arch".exe; do
		if [ -f "$f" ]; then found=$f; fi
	done
	[ -n "$found" ] || fail "missing target $target"
done

if [ -n "$native" ] && [ "$(uname -s)/$(uname -m)" = "Linux/x86_64" ]; then
	echo "== native binary"
	got=$("$native" version 2>&1) || fail "version exited non-zero: $got"
	case "$got" in
	*"$version"*) : ;;
	*) fail "version reports '$got', wanted '$version'" ;;
	esac
	echo "   $got"
	smoke="$root/tools/release/smoke.sh"
	[ -f "$smoke" ] || fail "no $smoke"
	sh "$smoke" "$native"
fi

echo "verify-release: ok"
