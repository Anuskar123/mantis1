# Raw dataset availability

The raw archive and numbered multipart files are not included in this GitHub repository. The checksums, manifest, and reconstruction scripts below describe the separately held archive. They require both parts before reconstruction can work. The processed flow exports and small reproducible sample datasets are included in `datasets/`.

# MANTIS Raw Dataset Multipart Upload

The original `MERGED_CSV.zip` archive is larger than 1 GB. It has therefore been split into two numbered files that can be uploaded separately.

Upload both files:

1. `MANTIS_Raw_Dataset.zip.001`
2. `MANTIS_Raw_Dataset.zip.002`

Also upload these small supporting files:

- `RAW_DATASET_MANIFEST.json`
- `SHA256SUMS.txt`
- `REASSEMBLE_FULL_DATASET.ps1`
- `REASSEMBLE_FULL_DATASET.sh`

The raw dataset is evaluation evidence. It is not proof that all five MANTIS engines were trained on every contained row.

## Windows reconstruction

Place both parts and the PowerShell script in the same folder. Open PowerShell in that folder and run:

```powershell
powershell -ExecutionPolicy Bypass -File .\REASSEMBLE_FULL_DATASET.ps1
```

## Linux reconstruction

Place both parts and the shell script in the same directory and run:

```bash
sh REASSEMBLE_FULL_DATASET.sh
```

Both scripts create `MANTIS_Raw_Dataset_Reassembled.zip` and verify its SHA-256 hash against the original archive.

## Verify the downloaded parts

Windows PowerShell:

```powershell
Get-FileHash -Algorithm SHA256 .\MANTIS_Raw_Dataset.zip.001
Get-FileHash -Algorithm SHA256 .\MANTIS_Raw_Dataset.zip.002
```

Linux:

```bash
sha256sum -c SHA256SUMS.txt
```

Compare the Windows results with `SHA256SUMS.txt`. Do not continue if either hash is different.

## Extract and place the raw dataset

After reconstruction, extract `MANTIS_Raw_Dataset_Reassembled.zip`. It contains the `MERGED_CSV` directory with 63 source files named `Merged01.csv` through `Merged63.csv`.

To use the files with the complete MANTIS development project, place the directory here:

```text
MANTIS_PROJECT/datasets/MERGED_CSV/
```

The executable submission ZIP already contains `cic_iot2023.csv` with 20,000 processed rows and `cic_iot2023_full.csv` with 300,000 processed rows. A reviewer can run the documented evaluation commands without downloading the multipart raw archive.

## Reproduce the 300,000-row processed export

This step requires the complete development project because `build_mega_dataset.py` is not part of the small executable submission ZIP.

1. Place `MERGED_CSV/` under the project `datasets/` directory.
2. Back up any existing `datasets/cic_iot2023_full.csv` because the command writes that file.
3. From the project root, run:

```bash
python3 src/build_mega_dataset.py
```

The script samples across all 63 source files with a fixed random seed and produces 300,000 rows.

## Correct use of each dataset

| Dataset | Correct use |
| --- | --- |
| `knn_sample.csv` | Demonstration KNN training and evaluation |
| `payload_sample.csv` | Demonstration Naive Bayes training and evaluation |
| `kmeans_sample.csv` | Demonstration K-Means training and evaluation |
| `zscore_sample.csv` | Demonstration Z-Score baseline and evaluation |
| `bloom_sample.csv` | Demonstration Bloom Filter training and evaluation |
| `cic_iot2023.csv` | 20,000-row CIC flow-rate evaluation |
| `cic_iot2023_full.csv` | 300,000-row CIC flow-rate evaluation |
| `MERGED_CSV/` | Original external corpus, provenance and reproducibility evidence |

The merged files contain flow-level features and labels but do not contain genuine per-source `unique_ports`, payload text or IP indicator fields. They must not be passed directly to the existing KNN, K-Means, Naive Bayes or Bloom training arguments.

## Example processed-data evaluation

After extracting the executable source ZIP:

```bash
cd Anuskar_sigdel_24812606_Source_Code_Executable/src
python3 -m evaluation.evaluate \
  --cic-zscore-csv ../datasets/cic_iot2023_full.csv \
  --compare \
  --out-json cic_300000_results.json \
  --out-txt cic_300000_results.txt
```

This command evaluates the Z-Score flow-rate path. It does not retrain every MANTIS engine on 300,000 rows.
