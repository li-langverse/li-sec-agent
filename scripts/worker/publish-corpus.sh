#!/usr/bin/env bash
# Publish built corpus to PVC canonical paths for eval harness consumption.
set -euo pipefail

DATA_DIR="${REFERENCE_DATA_DIR:-/data/corpus}"
SRC="${DATA_DIR}/corpus-v1.json"
DEST="${DATA_DIR}/corpus-latest.json"
MANIFEST="${DATA_DIR}/manifest.json"

if [[ ! -f "${SRC}" ]]; then
  echo "publish-corpus: missing ${SRC} — run build-reference-db first" >&2
  exit 1
fi

cp -f "${SRC}" "${DEST}"
if [[ -f "${MANIFEST}" ]]; then
  cp -f "${MANIFEST}" "${DATA_DIR}/manifest-latest.json"
fi

CASES="$(node -e "const m=require('${MANIFEST}'); console.log(m.stats.total_cases)")"
echo "publish-corpus: ${DEST} (${CASES} cases)"
