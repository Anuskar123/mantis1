#!/usr/bin/env python3
"""Create deterministic, leakage-resistant MANTIS dataset splits.

The script never moves or edits the source datasets. It writes engine-compatible
CSV files under datasets/processed/stage_1 and records row counts, class
distributions, source hashes, and output hashes in a JSON manifest.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


DATASETS = (
    "knn_sample.csv",
    "payload_sample.csv",
    "kmeans_sample.csv",
    "zscore_sample.csv",
    "bloom_sample.csv",
)
SPLITS = ("train", "validation", "test")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_row(fieldnames, row):
    return "\x1f".join((row.get(name) or "").strip() for name in fieldnames)


def stable_rank(seed, dataset, value):
    material = "%s\x1f%s\x1f%s" % (seed, dataset, value)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def allocate_group(rows):
    """Allocate one label group while keeping every available split useful."""
    size = len(rows)
    if size == 1:
        return {"train": rows, "validation": [], "test": []}
    if size == 2:
        return {"train": rows[:1], "validation": [], "test": rows[1:]}

    train_count = max(1, int(size * 0.70))
    remaining = size - train_count
    validation_count = max(1, remaining // 2)
    test_count = remaining - validation_count
    if test_count == 0:
        train_count -= 1
        test_count = 1
    return {
        "train": rows[:train_count],
        "validation": rows[train_count:train_count + validation_count],
        "test": rows[train_count + validation_count:],
    }


def portable_path(path, project_root):
    return path.resolve().relative_to(project_root.resolve()).as_posix()


def split_dataset(source, output_root, seed, project_root):
    with source.open("r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames or "label" not in reader.fieldnames:
            raise ValueError("%s must contain a label column" % source)
        fieldnames = reader.fieldnames
        original_rows = list(reader)

    unique = {}
    for row in original_rows:
        unique.setdefault(canonical_row(fieldnames, row), row)

    groups = defaultdict(list)
    for key, row in unique.items():
        label = (row.get("label") or "Unlabelled").strip() or "Unlabelled"
        groups[label].append((key, row))

    assigned = {name: [] for name in SPLITS}
    for label in sorted(groups):
        ranked = sorted(
            groups[label],
            key=lambda item: stable_rank(seed, source.name, item[0]),
        )
        allocation = allocate_group([row for _, row in ranked])
        for split in SPLITS:
            assigned[split].extend(allocation[split])

    split_records = {}
    for split in SPLITS:
        rows = sorted(
            assigned[split],
            key=lambda row: stable_rank(
                seed, source.name + ":" + split, canonical_row(fieldnames, row)
            ),
        )
        destination = output_root / split / source.name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        split_records[split] = {
            "file": portable_path(destination, project_root),
            "rows": len(rows),
            "class_distribution": dict(Counter(row["label"] for row in rows)),
            "sha256": sha256_file(destination),
        }

    split_keys = {
        split: {canonical_row(fieldnames, row) for row in assigned[split]}
        for split in SPLITS
    }
    overlaps = {
        "train_validation": len(split_keys["train"] & split_keys["validation"]),
        "train_test": len(split_keys["train"] & split_keys["test"]),
        "validation_test": len(split_keys["validation"] & split_keys["test"]),
    }
    if any(overlaps.values()):
        raise RuntimeError("split overlap detected for %s" % source.name)

    return {
        "source_file": portable_path(source, project_root),
        "source_sha256": sha256_file(source),
        "source_rows": len(original_rows),
        "unique_rows": len(unique),
        "duplicates_removed": len(original_rows) - len(unique),
        "splits": split_records,
        "overlap_rows": overlaps,
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Create MANTIS stage_1 train, validation, and test CSVs"
    )
    parser.add_argument("--datasets-dir", default="datasets")
    parser.add_argument("--seed", default="mantis-stage-v1")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    datasets_dir = Path(args.datasets_dir).resolve()
    output_root = datasets_dir / "processed" / "stage_1"

    missing = [name for name in DATASETS if not (datasets_dir / name).is_file()]
    if missing:
        raise FileNotFoundError("missing source datasets: " + ", ".join(missing))

    records = {}
    for name in DATASETS:
        records[name] = split_dataset(
            datasets_dir / name, output_root, args.seed, datasets_dir.parent
        )

    manifest = {
        "layout_version": 1,
        "stage": "stage_1",
        "purpose": "controlled engine-compatible training and evaluation",
        "seed": args.seed,
        "split_policy": "deterministic stratified 70/15/15 with small-class safeguards",
        "datasets": records,
    }
    manifest_dir = datasets_dir / "manifests"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = manifest_dir / "stage_1_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    print("Created", output_root)
    print("Manifest", manifest_path)
    for name, record in records.items():
        counts = [record["splits"][split]["rows"] for split in SPLITS]
        print("%-20s train=%d validation=%d test=%d" % (name, *counts))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
