#!/bin/bash
# MANTIS benchmark - train, test, evaluate, and print model comparison report
# No root required. Run from src/:  ./benchmark.sh
set -e

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SOURCE_DIR"

DATASETS="../datasets"
OUT_DIR="data"
BRAIN_BASE="$OUT_DIR/mantis_brain.json"
EVAL_JSON="evaluation_results.json"
EVAL_TXT="evaluation_results.txt"
REPORT_TXT="benchmark_report.txt"

KNN_SAMPLE="$DATASETS/knn_sample.csv"
PAYLOAD_SAMPLE="$DATASETS/payload_sample.csv"
ZSCORE_SAMPLE="$DATASETS/zscore_sample.csv"
CIC_CSV="$DATASETS/cic_iot2023.csv"

echo ""
echo "================================================================"
echo "  MANTIS Benchmark Pipeline"
echo "  train -> unit tests -> evaluate -> comparison report"
echo "================================================================"
echo ""

# --- fix CRLF if files were edited on Windows ---
if command -v sed >/dev/null 2>&1; then
  sed -i 's/\r$//' benchmark.sh 2>/dev/null || true
fi

# --- check datasets ---
missing=0
for f in "$KNN_SAMPLE" "$PAYLOAD_SAMPLE" "$ZSCORE_SAMPLE" "$CIC_CSV"; do
  if [ ! -f "$f" ]; then
    echo "[!] missing dataset: $f"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "[!] place sample CSVs and cic_iot2023.csv under datasets/"
  exit 1
fi

mkdir -p "$OUT_DIR"

# --- Step 1: unit tests (V-Model) ---
echo "[1/4] Running unit tests..."
TEST_LOG="$(mktemp)"
set +e
python3 -m unittest discover -s tests -v 2>&1 | tee "$TEST_LOG"
TEST_RC=${PIPESTATUS[0]}
set -e

TESTS_TOTAL=$(grep -cE '^test_' "$TEST_LOG" 2>/dev/null || echo 0)
TESTS_OK=$(grep -cE '\.\.\. ok$' "$TEST_LOG" 2>/dev/null || echo 0)
if [ "$TEST_RC" -ne 0 ]; then
  echo "[!] unit tests failed (exit $TEST_RC)"
  rm -f "$TEST_LOG"
  exit "$TEST_RC"
fi
echo "[+] tests passed: $TESTS_OK"
rm -f "$TEST_LOG"
echo ""

# --- Step 2: train 3 offline models ---
echo "[2/4] Training models (KNN + K-Means from CIC-IoT2023, Naive Bayes from payload CSV)..."
python3 -m training.train \
  --cic-iot2023 "$CIC_CSV" \
  --payload-csv "$PAYLOAD_SAMPLE" \
  --out "$BRAIN_BASE"

# pick newest brain file written by train.py
BRAIN_FILE="$(ls -t "$OUT_DIR"/mantis_brain_*.json 2>/dev/null | head -1)"
if [ -z "$BRAIN_FILE" ] || [ ! -f "$BRAIN_FILE" ]; then
  echo "[!] training did not produce mantis_brain_*.json"
  exit 1
fi
echo "[+] brain saved: $BRAIN_FILE"
echo ""

# --- Step 3: evaluate engines on labelled samples ---
echo "[3/4] Evaluating KNN, Naive Bayes, and Z-Score on sample test CSVs..."
python3 -m evaluation.evaluate \
  --brain "$BRAIN_FILE" \
  --knn-csv "$KNN_SAMPLE" \
  --payload-csv "$PAYLOAD_SAMPLE" \
  --zscore-csv "$ZSCORE_SAMPLE" \
  --out-json "$EVAL_JSON" \
  --out-txt "$EVAL_TXT"
echo ""

# --- Step 4: supervisor comparison report ---
echo "[4/4] Generating model comparison report..."
python3 -m evaluation.benchmark_report \
  --brain "$BRAIN_FILE" \
  --eval-json "$EVAL_JSON" \
  --out "$REPORT_TXT" \
  --tests-ok "$TESTS_OK" \
  --tests-total "$TESTS_TOTAL"

echo ""
echo "================================================================"
echo "  Done - files written:"
echo "    $BRAIN_FILE"
echo "    $EVAL_JSON"
echo "    $EVAL_TXT"
echo "    $REPORT_TXT   <-- show this to your supervisor"
echo "================================================================"
echo ""
echo "Quick read:"
echo "  cat $REPORT_TXT"
echo ""
