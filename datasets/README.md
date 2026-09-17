# MANTIS Dataset Layout

GitHub edition: the processed exports and sample datasets are included. Raw `MERGED_CSV/`, the raw ZIP, and multipart archive files are held separately and are not downloaded when cloning this repository. Checksums and reconstruction scripts are under `datasets/raw/`.

MANTIS separates original data, processed engine-compatible data, genuinely unseen evaluation data, and saved-model evidence. Existing source files remain in their original locations so current commands continue to work.

```text
datasets/
|-- raw/                         original corpus references, never edited
|-- processed/
|   |-- stage_1/                controlled engine-compatible samples
|   |   |-- train/
|   |   |-- validation/
|   |   `-- test/
|   |-- stage_2/                future larger feature-compatible aggregates
|   `-- stage_3/                future independently reviewed final corpus
|-- unseen/                     disjoint external evaluation only
|-- manifests/                  hashes, row counts, labels, and overlap checks
`-- legacy source files          retained for backward-compatible commands
```

Generate or refresh Stage 1 without changing any source CSV:

```bash
python scripts/prepare_dataset_stages.py
```

The split is deterministic and stratified by label. Exact duplicate rows are removed before allocation, and the manifest confirms zero row overlap between train, validation, and test files.

## Stage definitions

`stage_1` contains the five small packaged datasets with valid schemas for the corresponding engines. It supports reproducible code-path training and evaluation, not benchmark-scale performance claims.

`stage_2` is reserved for larger records that have been aggregated into genuine MANTIS features, including `unique_ports`, `packet_count`, `pps`, labels, source identity, and time windows. The current 300,000-row CIC flow export is not copied here because it lacks genuine `unique_ports`.

`stage_3` is reserved for a final reviewed corpus with documented provenance, disjoint splits, duplicate checks, leakage checks, and per-engine retained counts.

`unseen` must contain only sources excluded from all training and validation stages. The existing 63-file CIC-IoT2023 collection must not be described as unseen if it contributed to preparation, tuning, or model fitting.

## Packaged source datasets

These labelled samples provide a fast, reproducible demonstration of training and evaluation. They are not benchmark-scale evidence.

| File | Required fields | Intended engine |
| --- | --- | --- |
| `knn_sample.csv` | `unique_ports,packet_count,label` | KNN |
| `payload_sample.csv` | `payload,label` | Naive Bayes |
| `kmeans_sample.csv` | `pps,unique_ports,label` | K-Means |
| `zscore_sample.csv` | `pps,label` | Z-Score |
| `bloom_sample.csv` | `ip,label` | Bloom Filter |
| `threat_intel.txt` | one indicator per line | Bloom runtime feed |

## Which dataset should I use?

| Goal | Dataset | Command or location |
| --- | --- | --- |
| Demonstrate training for all five engines | Five `*_sample.csv` files | `python3 -m training.train` command below |
| Evaluate all five engine code paths | Five `*_sample.csv` files | `python3 -m evaluation.evaluate` with all five CSV arguments |
| Run a faster CIC flow-rate comparison | `cic_iot2023.csv` | `--cic-zscore-csv` with 20,000 rows |
| Run the larger CIC flow-rate comparison | `cic_iot2023_full.csv` | `--cic-zscore-csv` with 300,000 rows |
| Inspect or reproduce the original corpus | Multipart raw archive | Reassemble and extract `MERGED_CSV/` as described below |
| Train KNN or K-Means at large scale | A new aggregated dataset | Must contain genuine `unique_ports` per source and time window |

Train all five engines from the repository root using the Stage 1 training split:

```bash
cd src
python3 -m training.train \
  --knn-csv ../datasets/processed/stage_1/train/knn_sample.csv \
  --payload-csv ../datasets/processed/stage_1/train/payload_sample.csv \
  --kmeans-csv ../datasets/processed/stage_1/train/kmeans_sample.csv \
  --zscore-csv ../datasets/processed/stage_1/train/zscore_sample.csv \
  --bloom-csv ../datasets/processed/stage_1/train/bloom_sample.csv \
  --out data/mantis_brain_stage_1.json
```

Evaluate all five Stage 1 test splits against the newly written brain:

```bash
BRAIN=$(ls -1t data/mantis_brain_stage_1_*.json | head -1)
python3 -m evaluation.evaluate \
  --brain "$BRAIN" \
  --knn-csv ../datasets/processed/stage_1/test/knn_sample.csv \
  --payload-csv ../datasets/processed/stage_1/test/payload_sample.csv \
  --zscore-csv ../datasets/processed/stage_1/test/zscore_sample.csv \
  --kmeans-csv ../datasets/processed/stage_1/test/kmeans_sample.csv \
  --bloom-csv ../datasets/processed/stage_1/test/bloom_sample.csv \
  --out-json stage_1_test_results.json \
  --out-txt stage_1_test_results.txt
```

On Windows PowerShell, select the brain with:

```powershell
$BRAIN=(Get-ChildItem .\data\mantis_brain_stage_1_*.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

Then replace `"$BRAIN"` in the evaluation command with `$BRAIN` and use PowerShell line continuation or place the command on one line.

## CIC-IoT2023 flow exports

`cic_iot2023.csv` contains 20,000 rows and `cic_iot2023_full.csv` contains 300,000 rows. They contain flow-level `Rate` and `Label` fields and can be used by the Z-Score comparison evaluator. `MERGED_CSV/` contains the 63 original CIC-IoT2023 CSV exports, while `MERGED_CSV.zip` is the corresponding archive.

They do not contain genuine pre-aggregated `unique_ports`. A raw destination-port value is a port number, not a count of distinct ports per source and time window. These files must not be supplied directly as KNN or K-Means training data.

Use:

```bash
python3 -m evaluation.evaluate \
  --cic-zscore-csv ../datasets/cic_iot2023_full.csv \
  --compare
```

The flow export is strongly attack-heavy and its row order is not a true packet-rate timeline. Interpret balanced accuracy, MCC, prevalence and the no-skill baseline alongside precision and F1.

## Using the multipart raw dataset

The upload package stores the original 1.7 GB archive as two files:

```text
MANTIS_Raw_Dataset.zip.001
MANTIS_Raw_Dataset.zip.002
```

Download both parts into the same folder. Do not try to open either part separately. Run `REASSEMBLE_FULL_DATASET.ps1` on Windows or `REASSEMBLE_FULL_DATASET.sh` on Linux. The scripts create and verify `MANTIS_Raw_Dataset_Reassembled.zip`.

Extract the reconstructed ZIP. It contains the `MERGED_CSV/` directory with 63 CIC-IoT2023 CSV files. To reproduce the expected project layout, place that entire directory at:

```text
MANTIS_PROJECT/datasets/MERGED_CSV/
```

The expected files are `Merged01.csv` through `Merged63.csv`. Keep the raw files unchanged. Processing tools should write separate outputs rather than modifying these CSVs.

To reproduce a 300,000-row processed flow export from all 63 files, first back up any existing `datasets/cic_iot2023_full.csv`, then run from the project root:

```bash
python3 src/build_mega_dataset.py
```

The script uses a fixed random seed, samples across the 63 files and writes `datasets/cic_iot2023_full.csv`. This processed file is for the CIC flow-rate evaluation command. It is not automatically valid KNN, K-Means, payload or Bloom training data.

## Dataset integrity and reporting

- Use `SHA256SUMS.txt` to verify the downloaded multipart files before reconstruction.
- Use `RAW_DATASET_MANIFEST.json` to verify the original archive size and SHA-256 hash.
- Keep raw, processed, training, validation, test and unseen sources separate.
- Report input rows, retained rows and evaluation rows separately.
- Do not describe the 300,000-row file or 63-file raw corpus as training evidence for all five engines.
