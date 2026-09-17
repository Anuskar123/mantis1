# Stage 1: Controlled Engine-Compatible Data

Stage 1 is generated from the five packaged sample CSVs by `scripts/prepare_dataset_stages.py`.

Each dataset is split by label into approximately 70 percent training, 15 percent validation, and 15 percent testing. Small classes are protected so validation and test examples are retained when at least three unique rows exist. Exact duplicate rows are removed before splitting.

Use `train/` to fit the engines. Use `validation/` for threshold or configuration decisions. Use `test/` once for the final controlled check. Do not recombine these directories before reporting results.

The exact source hashes, output hashes, row counts, class distributions, duplicate counts, and pairwise overlap results are recorded in `datasets/manifests/stage_1_manifest.json`.
