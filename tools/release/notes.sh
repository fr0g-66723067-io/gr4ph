#!/bin/sh
# Renders the release body for TAG: the CHANGELOG section for that version, the
# repo's install block, the verification block, and the compare link.
#
# The release workflow runs this before it builds anything, so a tag with no
# CHANGELOG section publishes nothing. The retro-normalisation step uses it to
# rewrite existing release bodies.
set -eu

tag=${1:?usage: notes.sh TAG}
version=${tag#v}
root=$(cd "$(dirname "$0")/../.." && pwd)

slug=${GITHUB_REPOSITORY:-}
if [ -n "$slug" ]; then
	owner=${slug%/*}
	repo=${slug#*/}
else
	owner=fr0g-66723067-io
	repo=$(basename "$root")
fi

section=$(awk -v want="$version" '
	$0 ~ "^## \\[" want "\\]" { on = 1; next }
	on && /^## \[/ { exit }
	on { print }
' "$root/CHANGELOG.md")
[ -n "$section" ] || {
	echo "notes: CHANGELOG.md has no '## [$version]' section" >&2
	exit 1
}

echo "## What changed"
echo
printf '%s\n' "$section"
echo
echo "## Install"
echo
if [ "${NOTES_LEGACY:-0}" = 1 ]; then
	# A release page published before the asset pipeline has no binaries to
	# download; say so instead of linking files that do not exist.
	echo "This release predates the binary pipeline; install from source at this tag:"
	echo
	sed "s/@VERSION@/$version/g" "$root/tools/release/install-source.md"
else
	sed "s/@VERSION@/$version/g" "$root/tools/release/install.md"
	echo
	echo "## Verify"
	echo
	cat <<EOF
\`\`\`sh
sha256sum -c SHA256SUMS --ignore-missing
./${repo}_${tag}_linux_amd64 version
\`\`\`

Every asset is covered by \`SHA256SUMS\`. The tag and the release commit are
SSH-signed; the assets themselves are unsigned, and there is no attestation.
EOF
fi

prev=$(git -C "$root" describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)
if [ -n "$prev" ]; then
	printf '\n**Full Changelog**: https://github.com/%s/%s/compare/%s...%s\n' \
		"$owner" "$repo" "$prev" "$tag"
fi
