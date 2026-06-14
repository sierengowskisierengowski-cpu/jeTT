#!/usr/bin/env bash
# jeTT Round 10 — r6+r9 eval misses, live harvest, lolbin reinforce → v10.
set -euo pipefail
cd "$(dirname "$0")/.."

TOTAL="${JETT_TRAIN_TOTAL:-70000}"
LOG="${JETT_HARVEST_LOG:-/var/log/jett/jett.log}"
FAIL_R6="${JETT_FAIL_R6:-data/eval_failures_r6.jsonl}"
FAIL_R9="${JETT_FAIL_R9:-data/eval_failures_r9.jsonl}"
FAIL_MERGED="${JETT_FAIL_MERGED:-data/eval_failures_r10_merged.jsonl}"

echo "[0/6] Harvest live learn-mode FPs"
python3 scripts/harvest_learn_log.py \
  --log "$LOG" \
  --out data/eval_failures_live_r10.jsonl \
  --merge-r8 "$FAIL_R9" \
  --merged-out "$FAIL_MERGED" 2>/dev/null || {
  echo "[warn] harvest skipped — merging r6+r9 failures only"
  python3 - <<PY
import json
from pathlib import Path
paths = ["$FAIL_R6", "$FAIL_R9", "data/eval_failures_live_r10.jsonl"]
seen, out = set(), []
for p in paths:
    if not Path(p).exists():
        continue
    for line in open(p):
        line = line.strip()
        if not line:
            continue
        h = line
        if h in seen:
            continue
        seen.add(h)
        out.append(line)
open("$FAIL_MERGED", "w").write("\n".join(out) + ("\n" if out else ""))
print(f"  merged {len(out)} failure rows -> $FAIL_MERGED")
PY
}

echo "[1/6] Reinforce merged eval misses (r6 ship bar + r9 gaps)"
python3 generate_eval_reinforce.py --failures "$FAIL_MERGED" \
  --out data/bucket_j_eval_reinforce_r10.jsonl --variants 6 --round round10

echo "[2/6] Lolbin + stretch + supply-chain top-up"
python3 generate_lolbins.py --count 200 --out data/bucket_f_lolbins_r10.jsonl
python3 generate_stretch_threats.py --count 200 --out data/bucket_d3_stretch_r10.jsonl

echo "[3/6] Merge v10 (explicit buckets — no glob dedup churn)"
python3 stratified_merge.py --total "$TOTAL" --eval-frac 0.05 \
  --out data/jett_training_v10.json \
  --eval-out tests/guard_eval_v10.jsonl \
  --coverage-out data/mitre_coverage_v10.json \
  --buckets \
    data/bucket_a_threats.jsonl \
    data/bucket_a2_threats_r7.jsonl \
    data/bucket_b_scary_legit.jsonl \
    data/bucket_c_ambiguous.jsonl \
    data/bucket_d_stretch.jsonl \
    data/bucket_d2_stretch_r7.jsonl \
    data/bucket_d3_stretch_r10.jsonl \
    data/bucket_e_supply_chain.jsonl \
    data/bucket_f_lolbins.jsonl \
    data/bucket_f_lolbins_r10.jsonl \
    data/bucket_g_own_stack.jsonl \
    data/bucket_g2_own_stack_r7.jsonl \
    data/bucket_h_c2_variety.jsonl \
    data/bucket_j_eval_reinforce_r10.jsonl

echo "[4/6] Coverage gate"
python3 coverage/zero_gate.py --coverage data/mitre_coverage_v10.json

echo "[5/6] Summary"
python3 - <<'PY'
import json
train = len(json.load(open("data/jett_training_v10.json")))
eval_n = sum(1 for _ in open("tests/guard_eval_v10.jsonl") if _.strip())
merged = sum(1 for _ in open("data/eval_failures_r10_merged.jsonl") if _.strip()) if __import__("pathlib").Path("data/eval_failures_r10_merged.jsonl").exists() else 0
print(f"  merged failures: {merged}")
print(f"  training rows:   {train}")
print(f"  eval holdout:    {eval_n}")
PY

echo "[+] Round 10 ready: data/jett_training_v10.json"
