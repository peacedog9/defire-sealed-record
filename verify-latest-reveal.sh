#!/usr/bin/env bash
# Verify the latest real revealed batch from public bytes, then prove one edit fails.

set -euo pipefail

BASE_URL="${DEFIRE_SEALED_BASE_URL:-https://decentralizedfire.com/wp-content/uploads/tools/sealed-record}"
MIRROR_INDEX_URL="${DEFIRE_SEALED_MIRROR_INDEX_URL:-https://raw.githubusercontent.com/peacedog9/defire-sealed-record/main/daily-index.json}"
MIRROR_ISSUANCE_INDEX_URL="${DEFIRE_SEALED_MIRROR_ISSUANCE_INDEX_URL:-https://raw.githubusercontent.com/peacedog9/defire-sealed-record/main/issuance-index.json}"
BATCH_DATE="${DEFIRE_SEALED_BATCH:-}"
LIMIT_SECONDS="${DEFIRE_SEALED_LIMIT_SECONDS:-120}"
MATCH_ATTEMPTS="${DEFIRE_SEALED_MATCH_ATTEMPTS:-12}"
MATCH_INTERVAL_SECONDS="${DEFIRE_SEALED_MATCH_INTERVAL_SECONDS:-10}"
OTS_CLIENT="${DEFIRE_SEALED_OTS_CLIENT:-npx}"
OPENSSL_CLIENT="${DEFIRE_SEALED_OPENSSL_CLIENT:-openssl}"

if [[ ! "$BASE_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "INDEPENDENT FAILURE: base URL must use HTTP or HTTPS" >&2
  exit 2
fi
if [[ ! "$MIRROR_INDEX_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "INDEPENDENT FAILURE: mirror index URL must use HTTP or HTTPS" >&2
  exit 2
fi
if [[ ! "$MIRROR_ISSUANCE_INDEX_URL" =~ ^https?://[^[:space:]]+$ ]]; then
  echo "INDEPENDENT FAILURE: mirror issuance index URL must use HTTP or HTTPS" >&2
  exit 2
fi
if [[ ! "$LIMIT_SECONDS" =~ ^[0-9]+$ ]] || [[ "$LIMIT_SECONDS" -eq 0 ]]; then
  echo "INDEPENDENT FAILURE: time limit must be a positive integer" >&2
  exit 2
fi
if [[ ! "$MATCH_ATTEMPTS" =~ ^[0-9]+$ ]] || [[ "$MATCH_ATTEMPTS" -eq 0 ]] \
  || [[ ! "$MATCH_INTERVAL_SECONDS" =~ ^[0-9]+$ ]]; then
  echo "INDEPENDENT FAILURE: match attempts must be positive and interval must be nonnegative" >&2
  exit 2
fi
for required in curl node python3 "$OPENSSL_CLIENT"; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "INDEPENDENT FAILURE: $required is required" >&2
    exit 2
  fi
done
if [[ "$OTS_CLIENT" == "npx" ]] && ! command -v npx >/dev/null 2>&1; then
  echo "INDEPENDENT FAILURE: npx is required" >&2
  exit 2
fi

WORK_DIR="$(mktemp -d)"
cleanup() {
  if [[ "$WORK_DIR" == /tmp/* || "$WORK_DIR" == /private/tmp/* || "$WORK_DIR" == /var/folders/* ]]; then
    rm -rf "$WORK_DIR"
  fi
}
trap cleanup EXIT
mkdir -p "$WORK_DIR/batch"

curl -fsSL "$MIRROR_INDEX_URL" -o "$WORK_DIR/mirror-index.json"
curl -fsSL "$MIRROR_ISSUANCE_INDEX_URL" -o "$WORK_DIR/mirror-issuance-index.json"
indexes_match=0
for ((attempt = 1; attempt <= MATCH_ATTEMPTS; attempt += 1)); do
  if curl -fsSL "$BASE_URL/index.json" -o "$WORK_DIR/live-index.json" \
    && curl -fsSL "$BASE_URL/issuance/index.json" -o "$WORK_DIR/live-issuance-index.json" \
    && cmp -s "$WORK_DIR/live-index.json" "$WORK_DIR/mirror-index.json" \
    && cmp -s "$WORK_DIR/live-issuance-index.json" "$WORK_DIR/mirror-issuance-index.json"; then
    indexes_match=1
    break
  fi
  if (( attempt < MATCH_ATTEMPTS )); then
    sleep "$MATCH_INTERVAL_SECONDS"
  fi
done
if [[ "$indexes_match" -ne 1 ]]; then
  echo "INDEPENDENT FAILURE: GitHub witness and live daily or issuance index differ after ${MATCH_ATTEMPTS} attempts" >&2
  exit 1
fi

if [[ -z "$BATCH_DATE" ]]; then
  BATCH_DATE="$(python3 - "$WORK_DIR/live-index.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    index = json.load(handle)
batches = index.get("batches")
if not isinstance(batches, list) or index.get("batch_count") != len(batches):
    raise SystemExit("INDEPENDENT FAILURE: daily index count is invalid")
eligible = [
    row for row in batches
    if isinstance(row, dict)
    and row.get("reveal_status") == "revealed"
    and isinstance(row.get("pick_count"), int)
    and row["pick_count"] > 0
]
print(max((row["batch_date"] for row in eligible), default=""))
PY
)"
fi

if [[ -z "$BATCH_DATE" ]]; then
  message="PENDING: no revealed nonempty production batch exists yet"
  echo "$message"
  if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    printf '## DeFIRE independent verification\n\n%s\n' "$message" >> "$GITHUB_STEP_SUMMARY"
  fi
  exit 0
fi
if [[ ! "$BATCH_DATE" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
  echo "INDEPENDENT FAILURE: batch must use YYYY-MM-DD" >&2
  exit 2
fi

started_at="$(date +%s)"
curl -fsSL "$BASE_URL/$BATCH_DATE/verify_sealed_record.mjs" -o "$WORK_DIR/verify.mjs"
verify_command=(
  node "$WORK_DIR/verify.mjs"
  --base-url "$BASE_URL"
  --batch "$BATCH_DATE"
  --ots-client "$OTS_CLIENT"
  --openssl-client "$OPENSSL_CLIENT"
)
set +e
if command -v timeout >/dev/null 2>&1; then
  verify_output="$(timeout "${LIMIT_SECONDS}s" "${verify_command[@]}" 2>&1)"
  verify_status="$?"
else
  verify_output="$("${verify_command[@]}" 2>&1)"
  verify_status="$?"
fi
set -e
finished_at="$(date +%s)"
elapsed_seconds="$((finished_at - started_at))"
if [[ "$verify_status" -ne 0 ]]; then
  echo "INDEPENDENT FAILURE: public verification failed with exit $verify_status" >&2
  echo "$verify_output" >&2
  exit 1
fi
if (( elapsed_seconds >= LIMIT_SECONDS )); then
  echo "INDEPENDENT FAILURE: verification took ${elapsed_seconds}s; required below ${LIMIT_SECONDS}s" >&2
  exit 1
fi
if [[ "$verify_output" != *"VERIFIED"* ]] || [[ "$verify_output" != *"Full signal set:"* ]]; then
  echo "INDEPENDENT FAILURE: verifier omitted its success or full-set receipt" >&2
  exit 1
fi

for file_name in commitment.json commitment.json.ots reveal.json verify_sealed_record.mjs; do
  curl -fsSL "$BASE_URL/$BATCH_DATE/$file_name" -o "$WORK_DIR/batch/$file_name"
done

node --input-type=module - "$WORK_DIR/batch/reveal.json" <<'NODE'
import fs from "node:fs";

const file = process.argv[2];
const reveal = JSON.parse(fs.readFileSync(file, "utf8"));
if (!Array.isArray(reveal.picks) || reveal.picks.length === 0) {
  throw new Error("tamper test requires a revealed batch with at least one pick");
}
reveal.picks[0].entry = `${reveal.picks[0].entry}1`;

function sortedValue(value) {
  if (Array.isArray(value)) return value.map(sortedValue);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortedValue(value[key])]));
  }
  return value;
}

fs.writeFileSync(file, `${JSON.stringify(sortedValue(reveal))}\n`, { mode: 0o600 });
NODE

set +e
tamper_output="$(node "$WORK_DIR/batch/verify_sealed_record.mjs" \
  --dir "$WORK_DIR/batch" \
  --ots-client "$OTS_CLIENT" \
  --openssl-client "$OPENSSL_CLIENT" 2>&1)"
tamper_status="$?"
set -e
if [[ "$tamper_status" -ne 2 ]] || [[ "$tamper_output" != *"VERIFY FAILED: TAMPER DETECTED"* ]]; then
  echo "INDEPENDENT FAILURE: altered revealed entry did not fail loudly" >&2
  echo "$tamper_output" >&2
  exit 1
fi

receipt="INDEPENDENT PASS: batch ${BATCH_DATE}; ${elapsed_seconds}s; full-set receipt present; altered entry rejected loudly"
echo "$verify_output"
echo "$receipt"
if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  printf '## DeFIRE independent verification\n\n```text\n%s\n%s\n```\n' "$verify_output" "$receipt" >> "$GITHUB_STEP_SUMMARY"
fi
