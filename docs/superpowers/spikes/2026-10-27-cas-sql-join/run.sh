#!/usr/bin/env bash
# CAS SQL-join spike: reproduction.
#
# Throwaway Postgres 17 container. Nothing here touches the repo's dev stack.
# Expected wall clock on the measurement box: ~5-10 minutes for fixture and
# indexes, ~5 minutes for correctness and benchmarks.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PSQL="${PSQL:-psql}"
PORT="${PORT:-55433}"
CONTAINER="${CONTAINER:-casjoin-spike-pg}"
DSN="postgresql://spike:spike@127.0.0.1:${PORT}/spike"
export PGPASSWORD=spike

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
  -e POSTGRES_USER=spike -e POSTGRES_PASSWORD=spike -e POSTGRES_DB=spike \
  -p "${PORT}:5432" --shm-size=2g \
  postgres:17-alpine \
  postgres \
    -c shared_buffers=8GB -c effective_cache_size=24GB \
    -c maintenance_work_mem=8GB -c work_mem=256MB \
    -c max_wal_size=16GB -c checkpoint_timeout=60min -c wal_compression=on \
    -c max_worker_processes=8 -c max_parallel_workers=8 \
    -c max_parallel_maintenance_workers=4 -c max_parallel_workers_per_gather=4 \
    -c random_page_cost=1.1 -c track_io_timing=on \
    -c jit=off -c autovacuum_vacuum_cost_delay=0 >/dev/null

until docker exec "$CONTAINER" pg_isready -U spike >/dev/null 2>&1; do sleep 1; done

echo "== schema"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -q -f "$HERE/01-schema.sql"

echo "== fixture"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/02-generate.sql" 2>&1 | tee "$HERE/fixture.txt"

echo "== indexes and RLS"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/03-index.sql" 2>&1 | tee -a "$HERE/fixture.txt"

echo "== queries"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -q -f "$HERE/04-queries.sql"

echo "== correctness"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/05-correctness.sql" 2>&1 | tee "$HERE/correctness.txt"

echo "== benchmarks"
"$PSQL" "$DSN" -v ON_ERROR_STOP=1 -f "$HERE/06-bench.sql" 2>&1 | tee "$HERE/bench.txt"

echo "done. container: $CONTAINER (port $PORT); remove with: docker rm -f $CONTAINER"
