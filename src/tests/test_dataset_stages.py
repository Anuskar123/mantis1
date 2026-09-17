import csv
import hashlib
import json
import os
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATASETS = os.path.join(ROOT, "datasets")
MANIFEST = os.path.join(DATASETS, "manifests", "stage_1_manifest.json")


def digest(path):
    value = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def row_keys(path):
    with open(path, "r", newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        fields = reader.fieldnames or []
        return {
            "\x1f".join((row.get(field) or "").strip() for field in fields)
            for row in reader
        }


class DatasetStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(MANIFEST, "r", encoding="utf-8") as stream:
            cls.manifest = json.load(stream)

    def test_sources_and_outputs_match_manifest_hashes(self):
        for record in self.manifest["datasets"].values():
            source = os.path.join(ROOT, *record["source_file"].split("/"))
            self.assertEqual(digest(source), record["source_sha256"])
            for split in record["splits"].values():
                path = os.path.join(ROOT, *split["file"].split("/"))
                self.assertEqual(digest(path), split["sha256"])

    def test_splits_are_pairwise_disjoint(self):
        for record in self.manifest["datasets"].values():
            keys = {}
            for name, split in record["splits"].items():
                path = os.path.join(ROOT, *split["file"].split("/"))
                keys[name] = row_keys(path)
            self.assertFalse(keys["train"] & keys["validation"])
            self.assertFalse(keys["train"] & keys["test"])
            self.assertFalse(keys["validation"] & keys["test"])

    def test_split_counts_equal_unique_source_rows(self):
        for record in self.manifest["datasets"].values():
            total = sum(split["rows"] for split in record["splits"].values())
            self.assertEqual(total, record["unique_rows"])


if __name__ == "__main__":
    unittest.main()
