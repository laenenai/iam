#!/usr/bin/env python3
"""The plan-cache hazard that strategy (b) carries, measured on its own.

Strategy (b) passes the principal's accessible key set as a parameter:
`WHERE zone = ANY($1)`. On a table partitioned by `zone` that is fine for the
first few executions -- PostgreSQL builds a CUSTOM plan using the actual array
and prunes at plan time. From the sixth execution of a prepared statement it
may switch to a GENERIC plan, which cannot know the array and therefore cannot
prune at plan time. Runtime pruning still gives correct results, but the
planner has already produced a plan containing every partition, and paying for
that plan is not free.

Worse, the generic plan is built once and reused: a plan shaped by a
500-element array stays in force when the next caller passes a 1-element
array.

This script measures, for one 1,000-partition table and one 0.1%-selectivity
principal:

  * latency per execution, 1..N, with prepared statements allowed
  * the same with plan_cache_mode = force_custom_plan
  * the same with the key inlined as a literal (a new statement every time,
    so never prepared)

It is deliberately separate from 04-measure.py, which switches auto-prepare
off so this effect does not contaminate the recall matrix.
"""

import argparse
import math
import statistics
import time

import numpy as np
import psycopg

DIM = 768
SEED = 31337

SQL_PARAM = """
    select f.id
    from f1.facts_part f
    where f.zone = any(%(z)s)
      and not exists (
            select 1 from f1.fact_classification fc
            where fc.fact_id = f.id
              and not exists (
                    select 1 from f1.principal_clearance pc
                    where pc.principal_id = %(p)s
                      and pc.classification_id = fc.classification_id))
    order by f.embedding <=> %(q)s
    limit 20
"""


def lit(v):
    return "[" + ",".join(f"{x:.6g}" for x in v) + "]"


def queries(cur, zone, n, rng):
    cur.execute(
        "select embedding::text from f1.facts_flat where zone=%s order by id limit %s",
        (zone, n),
    )
    out = []
    for (txt,) in cur.fetchall():
        b = np.array([float(x) for x in txt.strip("[]").split(",")], dtype=np.float32)
        v = b + 0.30 * rng.standard_normal(DIM).astype(np.float32) / math.sqrt(DIM)
        v /= np.linalg.norm(v)
        out.append(lit(v))
    return out


def trial(dsn, label, *, prepare, force_custom, literal, zones, pid, n):
    rng = np.random.default_rng(SEED)
    conn = psycopg.connect(
        dsn, autocommit=True, prepare_threshold=(5 if prepare else None)
    )
    cur = conn.cursor()
    cur.execute("select '[1,2]'::vector <=> '[1,2]'::vector")
    if force_custom:
        cur.execute("set plan_cache_mode = force_custom_plan")
    cur.execute("set hnsw.iterative_scan = off")
    cur.execute("set hnsw.ef_search = 40")
    qs = queries(cur, zones[0], n, rng)
    lats = []
    for q in qs:
        if literal:
            sql = SQL_PARAM.replace(
                "f.zone = any(%(z)s)",
                "f.zone in (" + ",".join(str(z) for z in zones) + ")",
            )
            params = dict(p=pid, q=q)
        else:
            sql = SQL_PARAM
            params = dict(p=pid, q=q, z=zones)
        t = time.perf_counter()
        cur.execute(sql, params)
        cur.fetchall()
        lats.append((time.perf_counter() - t) * 1000)
    conn.close()
    first5 = statistics.fmean(lats[:5])
    rest = statistics.fmean(lats[5:]) if len(lats) > 5 else float("nan")
    print(
        f"  {label:46s} exec1-5 mean {first5:8.1f} ms | exec6+ mean {rest:8.1f} ms "
        f"| overall p50 {statistics.median(lats):8.1f} ms"
    )
    return lats


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--n", type=int, default=30)
    args = ap.parse_args()

    conn = psycopg.connect(args.dsn, autocommit=True, prepare_threshold=None)
    cur = conn.cursor()
    cur.execute("select principal_id, container_id from f1.probe where name='p01'")
    pid, zone = cur.fetchone()
    cur.execute("select count(*) from pg_inherits i join pg_class p on p.oid=i.inhparent where p.relname='facts_part'")
    nparts = cur.fetchone()[0]
    conn.close()

    print(f"facts_part partitions: {nparts}")
    print(f"probe p01: principal={pid}, accessible zones=[{zone}] (1 of {nparts})")
    print()
    print("Same query, same data, same results -- only plan caching differs:")
    trial(args.dsn, "parameterised key, prepared statements allowed",
          prepare=True, force_custom=False, literal=False, zones=[zone], pid=pid, n=args.n)
    trial(args.dsn, "parameterised key, plan_cache_mode=force_custom_plan",
          prepare=True, force_custom=True, literal=False, zones=[zone], pid=pid, n=args.n)
    trial(args.dsn, "parameterised key, auto-prepare disabled",
          prepare=False, force_custom=False, literal=False, zones=[zone], pid=pid, n=args.n)
    trial(args.dsn, "key inlined as a literal IN-list",
          prepare=False, force_custom=False, literal=True, zones=[zone], pid=pid, n=args.n)

    # And the cross-contamination case: the generic plan is shaped by whoever
    # executed first. Run 10 executions with a 500-zone array, then switch to
    # a 1-zone array on the SAME prepared statement.
    print()
    print("Cross-probe contamination: a generic plan shaped by a 500-zone array,")
    print("then reused for a 1-zone array on the same connection:")
    rng = np.random.default_rng(SEED)
    conn = psycopg.connect(args.dsn, autocommit=True, prepare_threshold=5)
    cur = conn.cursor()
    cur.execute("select '[1,2]'::vector <=> '[1,2]'::vector")
    cur.execute("set hnsw.iterative_scan = off")
    cur.execute("set hnsw.ef_search = 40")
    cur.execute("select principal_id from f1.probe where name='p50'")
    pid50 = cur.fetchone()[0]
    cur.execute(
        """select distinct zc.ancestor_id
           from f1.membership_closure mc
           join f1.grant_tuple g on g.userset_id=mc.userset_id and g.relation=1
           join f1.container_ancestry ca on ca.ancestor_id=g.container_id
           join f1.container cl on cl.id=ca.container_id and cl.depth=5
           join f1.container_ancestry zc on zc.container_id=cl.id
           join f1.container cz on cz.id=zc.ancestor_id and cz.depth=4
           where mc.principal_id=%s""",
        (pid50,),
    )
    big = [r[0] for r in cur.fetchall()]
    qs = queries(cur, zone, args.n, rng)
    for q in qs[:10]:
        cur.execute(SQL_PARAM, dict(p=pid50, q=q, z=big))
        cur.fetchall()
    lats = []
    for q in qs:
        t = time.perf_counter()
        cur.execute(SQL_PARAM, dict(p=pid, q=q, z=[zone]))
        cur.fetchall()
        lats.append((time.perf_counter() - t) * 1000)
    print(
        f"  {'1-zone query on the 500-zone generic plan':46s} "
        f"p50 {statistics.median(lats):8.1f} ms | min {min(lats):8.1f} ms"
    )
    conn.close()


if __name__ == "__main__":
    main()
