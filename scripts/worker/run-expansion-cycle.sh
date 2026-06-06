#!/usr/bin/env bash
# Idempotent reference corpus expansion cycle for homelab CronJob.
# Synthetic + OSSF eval only — rate-limited MITRE REST.
set -euo pipefail

APP_ROOT="${APP_ROOT:-/app}"
DATA_DIR="${REFERENCE_DATA_DIR:-/data/corpus}"
STATE_FILE="${DATA_DIR}/worker-state.json"
PROGRESS_LOG="${DATA_DIR}/expansion-progress.jsonl"
TARGET_CASES="${TARGET_CASES:-5000}"
OSSF_BATCH="${OSSF_BATCH:-10}"
EXPAND_BATCH="${EXPAND_BATCH:-50}"
MITRE_BATCH="${MITRE_BATCH:-5}"
MITRE_DELAY_MS="${MITRE_DELAY_MS:-400}"

mkdir -p "${DATA_DIR}" "${DATA_DIR}/logs" "${DATA_DIR}/ossf-cache"

seed_if_empty() {
  if [[ ! -f "${DATA_DIR}/manifest.json" ]]; then
    echo "==> Seeding corpus from image (${APP_ROOT}/eval/reference-database)"
    cp -a "${APP_ROOT}/eval/reference-database/." "${DATA_DIR}/"
  fi
}

read_cases() {
  if [[ -f "${DATA_DIR}/manifest.json" ]]; then
    node -e "const m=require('${DATA_DIR}/manifest.json'); console.log(m.stats?.total_cases??0)"
  else
    echo 0
  fi
}

init_state() {
  local current
  current="$(read_cases)"
  if [[ ! -f "${STATE_FILE}" ]]; then
    cat >"${STATE_FILE}" <<EOF
{
  "target_cases": ${TARGET_CASES},
  "current_cases": ${current},
  "ossf_limit": 75,
  "target_extra": 600,
  "mitre_offset": 0,
  "cycle": 0,
  "finished": false
}
EOF
  fi
}

log_progress() {
  local event="$1" cases="$2" added="$3"
  printf '{"ts":"%s","event":"%s","cases":%s,"added":%s,"target":%s}\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${event}" "${cases}" "${added}" "${TARGET_CASES}" \
    >>"${PROGRESS_LOG}"
}

seed_if_empty
init_state

BEFORE="$(read_cases)"
echo "==> Cycle start: ${BEFORE} cases (target ${TARGET_CASES})"

if node -e "const s=require('${STATE_FILE}'); process.exit(s.finished||s.current_cases>=s.target_cases?0:1)" 2>/dev/null; then
  echo "==> Target reached or worker finished — exiting 0"
  log_progress "skip_finished" "${BEFORE}" 0
  exit 0
fi

OSSF_LIMIT="$(node -e "const s=require('${STATE_FILE}'); console.log(s.ossf_limit)")"
TARGET_EXTRA="$(node -e "const s=require('${STATE_FILE}'); console.log(s.target_extra)")"
MITRE_OFFSET="$(node -e "const s=require('${STATE_FILE}'); console.log(s.mitre_offset)")"

export REFERENCE_DATA_DIR="${DATA_DIR}"
export CWE_MIRROR_URL="${CWE_MIRROR_URL:-https://cwe.klaut.pro}"
export MITRE_DELAY_MS
export MITRE_OFFSET
export MITRE_LIMIT="${MITRE_BATCH}"

cd "${APP_ROOT}"

echo "==> 1/5 CWE mirror snapshot"
WRITE_SNAPSHOT=1 REFERENCE_DATA_DIR="${DATA_DIR}" \
  npx tsx scripts/benchmarks/cwe-inventory.ts --write-snapshot \
  2>&1 | tee -a "${DATA_DIR}/logs/cycle-$(date +%Y%m%d-%H%M).log" || true

echo "==> 2/5 MITRE enrich (offset=${MITRE_OFFSET} limit=${MITRE_BATCH})"
npx tsx scripts/benchmarks/cwe-enrich-mitre.ts \
  2>&1 | tee -a "${DATA_DIR}/logs/cycle-$(date +%Y%m%d-%H%M).log"

CYCLE_NUM="$(node -e "const s=require('${STATE_FILE}'); console.log(s.cycle||0)")"
VARIANT_OFFSET="$((CYCLE_NUM * EXPAND_BATCH))"

echo "==> 3/5 OSSF fetch (limit=${OSSF_LIMIT}, append=1)"
OSSF_LIMIT="${OSSF_LIMIT}" OSSF_APPEND=1 OSSF_CACHE_DIR="${DATA_DIR}/ossf-cache" \
  npx tsx scripts/benchmarks/fetch-ossf-cve-subset.ts \
  2>&1 | tee -a "${DATA_DIR}/logs/cycle-$(date +%Y%m%d-%H%M).log"

echo "==> 4/5 Synthetic expansion (target_extra=${TARGET_EXTRA}, variant_offset=${VARIANT_OFFSET})"
TARGET_EXTRA="${TARGET_EXTRA}" EXPAND_APPEND=1 VARIANT_OFFSET="${VARIANT_OFFSET}" \
  npx tsx scripts/benchmarks/expand-reference-corpus.ts \
  2>&1 | tee -a "${DATA_DIR}/logs/cycle-$(date +%Y%m%d-%H%M).log"

echo "==> 4b/5 PrimeVul fetch (limit=50, append=1)"
PRIMEVUL_LIMIT=50 PRIMEVUL_APPEND=1 \
  npx tsx scripts/benchmarks/fetch-primevul-subset.ts \
  2>&1 | tee -a "${DATA_DIR}/logs/cycle-$(date +%Y%m%d-%H%M).log" || true

echo "==> 5/5 Build reference DB + publish"
npx tsx scripts/benchmarks/build-reference-db.ts \
  2>&1 | tee -a "${DATA_DIR}/logs/cycle-$(date +%Y%m%d-%H%M).log"

"${APP_ROOT}/scripts/worker/publish-corpus.sh"

AFTER="$(read_cases)"
ADDED=$((AFTER - BEFORE))
echo "==> Cycle complete: ${BEFORE} → ${AFTER} cases (+${ADDED})"

FINISHED=false
if [[ "${AFTER}" -ge "${TARGET_CASES}" ]]; then
  FINISHED=true
  echo "==> TARGET_CASES reached — marking worker finished"
fi

node -e "
const fs=require('fs');
const s=JSON.parse(fs.readFileSync('${STATE_FILE}','utf8'));
s.cycle=(s.cycle||0)+1;
s.current_cases=${AFTER};
s.ossf_limit=Math.min(218, (s.ossf_limit||75)+${OSSF_BATCH});
s.target_extra=(s.target_extra||600)+${EXPAND_BATCH};
s.mitre_offset=(s.mitre_offset||0)+${MITRE_BATCH};
s.finished=${FINISHED};
s.last_run=new Date().toISOString();
fs.writeFileSync('${STATE_FILE}', JSON.stringify(s,null,2)+'\n');
"

log_progress "cycle_complete" "${AFTER}" "${ADDED}"
echo "==> Done"
