#!/bin/sh
# Publishes the release for TAG. Idempotent: a re-run edits the existing release
# and replaces its assets, because a re-pointed tag is legitimate and
# `gh release create` fails when the release already exists.
set -eu

tag=${1:?usage: publish.sh TAG}
case "$tag" in
v*) : ;;
*) echo "publish: tag must start with v: $tag" >&2; exit 1 ;;
esac
root=$(cd "$(dirname "$0")/../.." && pwd)
cd "$root"
slug=${GITHUB_REPOSITORY:-}
repo=${slug#*/}
[ -n "$slug" ] || repo=$(basename "$root")

[ -d dist ] || { echo "publish: no dist/; run make release-binaries first" >&2; exit 1; }

pre=
case "$tag" in *-*) pre=--prerelease ;; esac

if [ "${PUBLISH_DRY_RUN:-0}" = 1 ]; then
	echo "title: $repo $tag"
	echo "assets: dist/${repo}_${tag}_* dist/SHA256SUMS"
	echo "prerelease: ${pre:-no}"
	exit 0
fi

notes=$(mktemp)
trap 'rm -f "$notes"' EXIT
sh "$root/tools/release/notes.sh" "$tag" > "$notes"

if gh release view "$tag" >/dev/null 2>&1; then
	gh release edit "$tag" --title "$repo $tag" --notes-file "$notes" $pre
	gh release upload "$tag" dist/${repo}_"$tag"_* dist/SHA256SUMS --clobber
else
	gh release create "$tag" --verify-tag --title "$repo $tag" --notes-file "$notes" $pre \
		dist/${repo}_"$tag"_* dist/SHA256SUMS
fi
