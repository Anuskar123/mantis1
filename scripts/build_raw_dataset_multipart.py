#!/usr/bin/env python3
"""Split the MANTIS raw dataset ZIP into upload-size parts and verify them."""

import argparse
import hashlib
import json
from pathlib import Path


DEFAULT_PART_SIZE = 900_000_000


def digest_file(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Create uploadable parts from datasets/MERGED_CSV.zip"
    )
    parser.add_argument("--source", default="datasets/MERGED_CSV.zip")
    parser.add_argument(
        "--output-dir", default="submission/Raw_Dataset_Multipart"
    )
    parser.add_argument("--part-size", type=int, default=DEFAULT_PART_SIZE)
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    source = Path(args.source).resolve()
    output_dir = Path(args.output_dir).resolve()
    if not source.is_file():
        raise FileNotFoundError(source)
    if args.part_size <= 0 or args.part_size >= 1_000_000_000:
        raise ValueError("part size must be between 1 and 999,999,999 bytes")

    output_dir.mkdir(parents=True, exist_ok=True)
    part_paths = []
    source_hash = hashlib.sha256()
    with source.open("rb") as input_stream:
        part_number = 1
        while True:
            first = input_stream.read(min(8 * 1024 * 1024, args.part_size))
            if not first:
                break
            part_path = output_dir / (
                "MANTIS_Raw_Dataset.zip.%03d" % part_number
            )
            temporary = part_path.with_suffix(part_path.suffix + ".tmp")
            written = 0
            part_hash = hashlib.sha256()
            with temporary.open("wb") as output_stream:
                block = first
                while block:
                    output_stream.write(block)
                    source_hash.update(block)
                    part_hash.update(block)
                    written += len(block)
                    remaining = args.part_size - written
                    if remaining <= 0:
                        break
                    block = input_stream.read(min(8 * 1024 * 1024, remaining))
            temporary.replace(part_path)
            part_paths.append(
                {
                    "file": part_path.name,
                    "bytes": written,
                    "sha256": part_hash.hexdigest(),
                }
            )
            part_number += 1

    if source_hash.hexdigest() != digest_file(source):
        raise RuntimeError("streamed source hash did not match source file")

    reconstructed_hash = hashlib.sha256()
    reconstructed_size = 0
    for record in part_paths:
        part_path = output_dir / record["file"]
        if digest_file(part_path) != record["sha256"]:
            raise RuntimeError("part hash mismatch: " + record["file"])
        with part_path.open("rb") as stream:
            for block in iter(lambda: stream.read(8 * 1024 * 1024), b""):
                reconstructed_hash.update(block)
                reconstructed_size += len(block)

    original_hash = source_hash.hexdigest()
    if reconstructed_size != source.stat().st_size:
        raise RuntimeError("reconstructed size does not match original")
    if reconstructed_hash.hexdigest() != original_hash:
        raise RuntimeError("reconstructed hash does not match original")

    manifest = {
        "source_file": source.name,
        "source_bytes": source.stat().st_size,
        "source_sha256": original_hash,
        "part_size_limit": args.part_size,
        "parts": part_paths,
        "verification": {
            "combined_bytes": reconstructed_size,
            "combined_sha256": reconstructed_hash.hexdigest(),
            "matches_original": True,
        },
    }
    (output_dir / "RAW_DATASET_MANIFEST.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    checksum_lines = [
        "%s  %s" % (record["sha256"], record["file"])
        for record in part_paths
    ]
    (output_dir / "SHA256SUMS.txt").write_text(
        "\n".join(checksum_lines) + "\n", encoding="utf-8"
    )

    print("SOURCE_BYTES=%d" % source.stat().st_size)
    print("SOURCE_SHA256=%s" % original_hash)
    for record in part_paths:
        print(
            "PART=%s BYTES=%d SHA256=%s"
            % (record["file"], record["bytes"], record["sha256"])
        )
    print("RECONSTRUCTION_MATCH=TRUE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
