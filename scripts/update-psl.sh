#!/bin/sh
# Fetches the Public Suffix List into the browser extension, where both
# the extension and secretvaultd read it (browser/extension/data, embedded
# by package browser). Run it now and then, and commit the result with
# the tests passing: go test ./svext ./browser
#
#   scripts/update-psl.sh
set -eu

url="https://publicsuffix.org/list/public_suffix_list.dat"
dir="$(cd "$(dirname "$0")/.." && pwd)"
out="$dir/browser/extension/data/public_suffix_list.dat"
tmp="$out.new"

trap 'rm -f "$tmp"' EXIT
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 -o "$tmp" "$url"

# A list cut short, or a page that is not the list, is refused.
grep -q '===BEGIN ICANN DOMAINS===' "$tmp" || { echo "update-psl.sh: $url did not send the list" >&2; exit 1; }
grep -q '===END PRIVATE DOMAINS===' "$tmp" || { echo "update-psl.sh: the list from $url is cut short" >&2; exit 1; }

mv "$tmp" "$out"
trap - EXIT
echo "Updated $out ($(wc -l < "$out") lines). Check it with: go test ./svext ./browser"
