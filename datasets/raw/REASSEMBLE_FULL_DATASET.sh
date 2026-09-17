#!/bin/sh
set -eu

folder=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
part1="$folder/MANTIS_Raw_Dataset.zip.001"
part2="$folder/MANTIS_Raw_Dataset.zip.002"
output="$folder/MANTIS_Raw_Dataset_Reassembled.zip"
expected="7900eafc6edddd2cfae0b7ac32c62213f98babcd005a23d3fb8360c262c412e2"

test -f "$part1" || { echo "Missing $part1" >&2; exit 1; }
test -f "$part2" || { echo "Missing $part2" >&2; exit 1; }
test ! -e "$output" || { echo "Output already exists: $output" >&2; exit 1; }

cat "$part1" "$part2" > "$output"
actual=$(sha256sum "$output" | awk '{print $1}')
test "$actual" = "$expected" || {
    echo "Reassembled archive hash mismatch" >&2
    exit 1
}

echo "Reassembled archive: $output"
echo "SHA256 verified: $actual"
