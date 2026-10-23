#!/usr/bin/env bash
# F1 filtered-ANN spike: end-to-end reproduction.
#
# Requires docker and a python3 with numpy + psycopg3 (a venv is fine).
# Everything runs against a throwaway container; nothing touches any repo's
# dev stack.
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
# --shm-size matters: a PARALLEL HNSW build allocates maintenance_work_mem in
# /dev/shm and fails outright if it does not fit. 03b-hnsw.sql sidesteps this
# by building serially, so 2g is enough here; raise it and drop that SET if
# you want the parallel build.
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
# 2. Schema, fixture, indexes.
# ---------------------------------------------------------------------------
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -q -f "$HERE/01-schema.sql"
"$PY" "$HERE/02-generate.py" --dsn "$DSN" --layout correlated
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/03-index.sql"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/03b-hnsw.sql"   # ~45 min, serial

# ---------------------------------------------------------------------------
# 3. Recall + latency, correlated layout.
# ---------------------------------------------------------------------------
"$PY" "$HERE/04-measure.py" --dsn "$DSN" --queries 50 \
    --out "$HERE/results-correlated.json" \
    --explain-out "$HERE/explain-correlated.txt"

# ---------------------------------------------------------------------------
# 4. Key maintenance cost.
# ---------------------------------------------------------------------------
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/05-maintenance.sql" \
    | tee "$HERE/maintenance.txt"

# ---------------------------------------------------------------------------
# 5. Adversarial layout: cluster assignment independent of the authorization
#    zone, so a principal's accessible rows are a uniform sample of the vector
#    space. Same matrix, separate tables.
# ---------------------------------------------------------------------------
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -q -f "$HERE/06-independent-schema.sql"
"$PY" "$HERE/02-generate.py" --dsn "$DSN" --layout independent --suffix _i --skip-auth
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/06b-independent-index.sql"
"$PY" "$HERE/04-measure.py" --dsn "$DSN" --suffix _i --queries 50 \
    --out "$HERE/results-independent.json" \
    --explain-out "$HERE/explain-independent.txt"

echo "done. docker rm -f f1-spike-pg to clean up."
