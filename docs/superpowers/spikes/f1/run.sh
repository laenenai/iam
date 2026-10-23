#!/usr/bin/env bash
# F1 filtered-ANN spike: reproduction, in the order it was actually run.
#
# Needs docker and a python3 with numpy + psycopg3 (a venv is fine).
# Everything runs against a throwaway container; no repo's dev stack is touched.
#
# Total wall clock on the box in the write-up: ~45 min of builds, ~35 min of
# measurement.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="${PY:-python3}"
PSQL="${PSQL:-psql}"
PORT="${PORT:-55432}"
DSN="postgresql://spike:spike@127.0.0.1:${PORT}/spike"
export PGPASSWORD=spike

# ---------------------------------------------------------------------------
# 1. Postgres 18 + pgvector 0.8.
#
# --shm-size is load-bearing: a PARALLEL HNSW build allocates
# maintenance_work_mem in /dev/shm and FAILS (not slows) if it does not fit.
# 03b/03c force serial builds, so 2g is enough here.
# ---------------------------------------------------------------------------
docker rm -f f1-spike-pg >/dev/null 2>&1 || true
docker run -d --name f1-spike-pg \
  -e POSTGRES_USER=spike -e POSTGRES_PASSWORD=spike -e POSTGRES_DB=spike \
  -p "${PORT}:5432" --shm-size=2g \
  pgvector/pgvector:pg18 \
  postgres \
    -c shared_buffers=8GB -c effective_cache_size=24GB \
    -c maintenance_work_mem=8GB -c work_mem=256MB \
    -c max_wal_size=16GB -c checkpoint_timeout=60min -c wal_compression=on \
    -c max_worker_processes=8 -c max_parallel_workers=5 \
    -c max_parallel_maintenance_workers=4 -c max_parallel_workers_per_gather=0 \
    -c random_page_cost=1.1 -c track_io_timing=on \
    -c max_locks_per_transaction=4096 -c jit=off \
    -c autovacuum_vacuum_cost_delay=0 >/dev/null

until docker exec f1-spike-pg pg_isready -U spike >/dev/null 2>&1; do sleep 1; done
"$PSQL" "$DSN" -qc 'create extension vector'

# ---------------------------------------------------------------------------
# 2. Schema, fixture, indexes.  (~30 min, almost all of it the two HNSW builds)
# ---------------------------------------------------------------------------
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -q -f "$HERE/01-schema.sql"
"$PY"   "$HERE/02-generate.py" --dsn "$DSN" --layout correlated     # ~2 min
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/03-index.sql"           # partitions + btrees
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/03b-hnsw.sql"           # flat HNSW, ~18 min
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/03c-part-hnsw.sql"      # 1000 HNSW, ~9 min

# ---------------------------------------------------------------------------
# 3. Calibration first: the unfiltered HNSW recall ceiling and the tie ceiling.
#    Without these the recall matrix is unattributable -- see write-up §4.
# ---------------------------------------------------------------------------
"$PY" "$HERE/10-verify.py" --dsn "$DSN" --queries 30 | tee "$HERE/calibration.txt"

# ---------------------------------------------------------------------------
# 4. The recall + latency matrix, both query distributions.  (~35 min)
# ---------------------------------------------------------------------------
"$PY" "$HERE/04-measure.py" --dsn "$DSN" --queries 30 \
    --out "$HERE/results-correlated.json" \
    --explain-out "$HERE/explain-raw.txt"
"$PY" "$HERE/07-report.py" "$HERE/results-correlated.json" | tee "$HERE/tables.md"
"$PY" "$HERE/09-trim-explain.py" "$HERE/explain-raw.txt" > "$HERE/explain-key-cases.txt"
rm -f "$HERE/explain-raw.txt"   # 30 MB of per-partition subplans and vector literals

# ---------------------------------------------------------------------------
# 5. The other three questions.
# ---------------------------------------------------------------------------
"$PSQL" "$DSN" -f "$HERE/08-predicate-cost.sql" > "$HERE/predicate-cost.txt"   # A2's 20ms
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/05-maintenance.sql" \
    | tee "$HERE/maintenance.txt"                                             # O(members)
"$PY"   "$HERE/11-plancache.py" --dsn "$DSN" --n 30 | tee "$HERE/plancache.txt"

# ---------------------------------------------------------------------------
# 6. OPTIONAL: a separately-generated uncorrelated-layout fixture. Generated
#    for the write-up but NOT indexed or measured -- the adversarial geometry
#    is covered by 04-measure.py's `global` query distribution instead. Adds
#    ~30 min of index builds if you want the separate-table confirmation.
# ---------------------------------------------------------------------------
# "$PSQL" "$DSN" -v ON_ERROR_STOP=1 -q -f "$HERE/06-independent-schema.sql"
# "$PY"   "$HERE/02-generate.py" --dsn "$DSN" --layout independent --suffix _i --skip-auth
# "$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/06b-independent-index.sql"
# "$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/06c-independent-part.sql"
# "$PY"   "$HERE/04-measure.py" --dsn "$DSN" --suffix _i --queries 30 \
#     --out "$HERE/results-independent.json"

echo "done. docker rm -f f1-spike-pg to clean up."
