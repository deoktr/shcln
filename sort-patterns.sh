#!/usr/bin/env bash
# Sort a patterns TSV (default: src/patterns.tsv) alphabetically by
# provider, then by name. Comment/blank lines are left at the top of the file.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
file=${1:-"$script_dir/src/patterns.tsv"}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
	# keep the header (and any other comments) at the top, untouched
	grep -E '^(#|$)' "$file" || true

	# sort data rows case-insensitively, so "Amazon AWS" comes before
	# "AWS credentials" instead of all uppercase names sorting first
	grep -Ev '^(#|$)' "$file" |
		LC_ALL=C sort -f -s -t $'\t' -k1,1 -k2,2
} >"$tmp"

cat "$tmp" >"$file"
