#!/usr/bin/env bash
# Sort a patterns TSV (default: src/patterns.tsv) alphabetically by
# provider, then by name. Generic fallback rules (IDs starting with
# "generic_") are placed at the end so specific rules match first.
# Comment/blank lines are left at the top of the file.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
file=${1:-"$script_dir/src/patterns.tsv"}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
	# keep the header (and any other comments) at the top, untouched
	grep -E '^(#|$)' "$file" || true

	# specific rules first, sorted case-insensitively so "Amazon AWS"
	# comes before "AWS credentials" instead of all uppercase names first
	grep -Ev '^(#|$)' "$file" |
		awk -F $'\t' '$3 !~ /^generic_/' |
		LC_ALL=C sort -f -s -t $'\t' -k1,1 -k2,2

	# generic fallbacks last: match_line returns the first matching pattern,
	# so specific rules need to appear earlier in the generated list
	grep -Ev '^(#|$)' "$file" |
		awk -F $'\t' '$3 ~ /^generic_/' |
		LC_ALL=C sort -f -s -t $'\t' -k1,1 -k2,2
} >"$tmp"

cat "$tmp" >"$file"
