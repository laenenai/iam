#!/usr/bin/env python3
"""F1 filtered-ANN spike: recall + latency harness.

For each probe principal (whose accessible set is 50% / 10% / 1% / 0.1% /
0.05% of 2,000,000 rows) and each strategy, runs the same N query vectors and
reports recall@20 against exact search over the same filtered set, plus
p50/p95 latency and the number of rows actually returned.

"Rows returned" is reported because it is the finding, not a diagnostic: an
HNSW scan with iterative scan off does not return a short list by accident,
it returns a short list silently, which is kgs leak channel #6 arriving as a
correctness bug.

Usage:
    python3 04-measure.py --dsn ... --suffix "" --queries 50 --out results.json
"""

import argparse
import json
import math
import statistics
import time

import numpy as np
import psycopg

DIM = 768
TOPK = 20
QUERY_NOISE = 0.30
SEED = 777

RELATION_READ = 1

# ---------------------------------------------------------------------------
# The authorization predicate, as iam design §9.2 compiles it: a SQL fragment
# over the two closures plus the live tier-2 anti-join. No key.
# ---------------------------------------------------------------------------
TIER1_EXISTS = """exists (
            select 1
            from f1.container_ancestry ca
            join f1.grant_tuple g
              on g.container_id = ca.ancestor_id and g.relation = {rel}
            join f1.membership_closure mc
              on mc.userset_id = g.userset_id
            where ca.container_id = f.container_id
              and mc.principal_id = %(p)s
        )""".format(rel=RELATION_READ)

TIER2_ANTIJOIN = """not exists (
            select 1
            from f1.fact_classification fc
            where fc.fact_id = f.id
              and not exists (
                    select 1 from f1.principal_clearance pc
                    where pc.principal_id = %(p)s
                      and pc.classification_id = fc.classification_id
                  )
        )"""


def build_sql(table, *, use_key, use_tier1, limit=TOPK):
    """Compose the query for one strategy.

    use_key   -- add `zone = any(%(zones)s)`, the materialized (b) key
    use_tier1 -- keep the §9.2 tier-1 fragment as a residual predicate
    """
    preds = []
    if use_key:
        preds.append("f.zone = any(%(zones)s)")
    if use_tier1:
        preds.append(TIER1_EXISTS)
    preds.append(TIER2_ANTIJOIN)
    where = "\n          and ".join(preds)
    return f"""
        select f.id
        from f1.{table} f
        where {where}
        order by f.embedding <=> %(q)s
        limit {limit}
    """


# ---------------------------------------------------------------------------
# Strategies. (a) = predicate inside the index scan; (b) = pre-restricted.
# ---------------------------------------------------------------------------
def strategies(sfx):
    flat = f"facts_flat{sfx}"
    part = f"facts_part{sfx}"
    off = "set hnsw.iterative_scan = off"
    rel = "set hnsw.iterative_scan = relaxed_order"
    strict = "set hnsw.iterative_scan = strict_order"
    return [
        # --- ground truth -------------------------------------------------
        dict(
            name="exact",
            table=flat,
            use_key=True,
            use_tier1=True,
            setup=[
                "set enable_indexscan = off",
                "set enable_indexonlyscan = off",
                "set hnsw.iterative_scan = off",
            ],
            group="truth",
        ),
        # --- (a) predicate inside the index scan --------------------------
        dict(
            name="a-off",
            table=flat,
            use_key=False,
            use_tier1=True,
            setup=[off, "set hnsw.ef_search = 40"],
            group="a",
        ),
        dict(
            name="a-relaxed",
            table=flat,
            use_key=False,
            use_tier1=True,
            setup=[
                rel,
                "set hnsw.ef_search = 40",
                "set hnsw.max_scan_tuples = 20000",
                "set hnsw.scan_mem_multiplier = 1",
            ],
            group="a",
        ),
        dict(
            name="a-strict",
            table=flat,
            use_key=False,
            use_tier1=True,
            setup=[
                strict,
                "set hnsw.ef_search = 40",
                "set hnsw.max_scan_tuples = 20000",
                "set hnsw.scan_mem_multiplier = 1",
            ],
            group="a",
        ),
        dict(
            name="a-relaxed-tuned",
            table=flat,
            use_key=False,
            use_tier1=True,
            setup=[
                rel,
                "set hnsw.ef_search = 100",
                "set hnsw.max_scan_tuples = 2000000",
                "set hnsw.scan_mem_multiplier = 8",
            ],
            group="a",
        ),
        # --- (b) pre-restricted candidate set ------------------------------
        # key as a plain qual, no partitioning: isolates "cheap qual instead
        # of a join" from "pruning".
        dict(
            name="b-key-flat",
            table=flat,
            use_key=True,
            use_tier1=True,
            setup=[
                rel,
                "set hnsw.ef_search = 40",
                "set hnsw.max_scan_tuples = 20000",
                "set hnsw.scan_mem_multiplier = 1",
            ],
            group="b",
        ),
        # partition pruning + per-partition HNSW
        dict(
            name="b-part",
            table=part,
            use_key=True,
            use_tier1=True,
            setup=[off, "set hnsw.ef_search = 40"],
            group="b",
        ),
        dict(
            name="b-part-relaxed",
            table=part,
            use_key=True,
            use_tier1=True,
            setup=[
                rel,
                "set hnsw.ef_search = 40",
                "set hnsw.max_scan_tuples = 20000",
                "set hnsw.scan_mem_multiplier = 1",
            ],
            group="b",
        ),
        # key only -- valid ONLY when no grant is finer than the zone.
        dict(
            name="b-part-keyonly",
            table=part,
            use_key=True,
            use_tier1=False,
            setup=[off, "set hnsw.ef_search = 40"],
            group="b",
        ),
        # pruned exact: no ANN index at all, brute force the restricted set.
        dict(
            name="b-part-exact",
            table=part,
            use_key=True,
            use_tier1=True,
            setup=[
                "set enable_indexscan = off",
                "set enable_indexonlyscan = off",
                "set hnsw.iterative_scan = off",
            ],
            group="b",
        ),
    ]


RESET = [
    "set enable_indexscan = on",
    "set enable_indexonlyscan = on",
    "set enable_bitmapscan = on",
    "set hnsw.iterative_scan = off",
    "set hnsw.ef_search = 40",
    "set hnsw.max_scan_tuples = 20000",
    "set hnsw.scan_mem_multiplier = 1",
]


# ---------------------------------------------------------------------------
# (b)'s key resolution: principal -> accessible zones. This is the query the
# consumer must run (or cache) before the ANN search, and its cost counts.
# ---------------------------------------------------------------------------
ZONE_RESOLVE = """
    select distinct zc.ancestor_id
    from f1.membership_closure mc
    join f1.grant_tuple g
      on g.userset_id = mc.userset_id and g.relation = 1
    join f1.container_ancestry ca
      on ca.ancestor_id = g.container_id
    join f1.container cl
      on cl.id = ca.container_id and cl.depth = 5
    join f1.container_ancestry zc
      on zc.container_id = cl.id
    join f1.container cz
      on cz.id = zc.ancestor_id and cz.depth = 4
    where mc.principal_id = %(p)s
"""


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return float("nan")
    k = (len(xs) - 1) * q
    lo, hi = math.floor(k), math.ceil(k)
    if lo == hi:
        return xs[int(k)]
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def halfvec_literal(v):
    return "[" + ",".join(f"{x:.6g}" for x in v) + "]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--suffix", default="")
    ap.add_argument("--queries", type=int, default=50)
    ap.add_argument("--out", required=True)
    ap.add_argument("--explain-out", default=None)
    ap.add_argument("--probes", default="p50,p10,p1,p01,psub")
    args = ap.parse_args()

    rng = np.random.default_rng(SEED)
    conn = psycopg.connect(args.dsn, autocommit=True)
    cur = conn.cursor()

    # ---- environment ----------------------------------------------------
    cur.execute("select version()")
    pgver = cur.fetchone()[0]
    cur.execute("select extversion from pg_extension where extname = 'vector'")
    pgvec = cur.fetchone()[0]
    cur.execute(
        "select name, setting, unit from pg_settings where name in "
        "('shared_buffers','work_mem','maintenance_work_mem','max_parallel_workers_per_gather',"
        "'effective_cache_size','jit','random_page_cost') order by name"
    )
    settings = {r[0]: f"{r[1]}{r[2] or ''}" for r in cur.fetchall()}

    # ---- client/server round-trip overhead, so latency can be read honestly
    rtts = []
    for _ in range(300):
        t = time.perf_counter()
        cur.execute("select 1")
        cur.fetchall()
        rtts.append((time.perf_counter() - t) * 1000)
    rtt = dict(p50=pct(rtts, 0.50), p95=pct(rtts, 0.95))
    log(f"client->server RTT (select 1): p50={rtt['p50']:.2f}ms p95={rtt['p95']:.2f}ms")

    cur.execute("select name, principal_id, depth, container_id from f1.probe order by depth")
    probe_rows = {r[0]: dict(principal=r[1], depth=r[2], container=r[3]) for r in cur.fetchall()}
    wanted = [p for p in args.probes.split(",") if p in probe_rows]

    flat = f"facts_flat{args.suffix}"
    cur.execute(f"select count(*) from f1.{flat}")
    total_rows = cur.fetchone()[0]
    log(f"{flat}: {total_rows:,} rows")

    # ---- per-probe setup: zones, measured selectivity, query vectors -----
    probes = {}
    for name in wanted:
        p = probe_rows[name]["principal"]
        t = time.perf_counter()
        cur.execute(ZONE_RESOLVE, dict(p=p))
        zones = [r[0] for r in cur.fetchall()]
        zone_ms = (time.perf_counter() - t) * 1000
        # measured selectivity of the full predicate (tier 1 + tier 2)
        cnt_sql = f"""
            select count(*) from f1.{flat} f
            where f.zone = any(%(zones)s) and {TIER1_EXISTS} and {TIER2_ANTIJOIN}
        """
        cur.execute(cnt_sql, dict(p=p, zones=zones))
        n_acc = cur.fetchone()[0]
        # tier-1-only count, to show what the tier-2 anti-join removes
        cur.execute(
            f"select count(*) from f1.{flat} f where f.zone = any(%(zones)s) and {TIER1_EXISTS}",
            dict(p=p, zones=zones),
        )
        n_t1 = cur.fetchone()[0]
        # how many accessible rows are reachable via the key alone
        cur.execute(
            f"select count(*) from f1.{flat} f where f.zone = any(%(zones)s)", dict(zones=zones)
        )
        n_key = cur.fetchone()[0]
        cur.execute("select count(*) from f1.membership_closure where principal_id = %s", (p,))
        n_usersets = cur.fetchone()[0]

        # query vectors: drawn from the probe's OWN accessible rows plus
        # noise. A user searches inside their own data; drawing queries from
        # the global distribution instead would measure a different question.
        cur.execute(
            f"""select f.embedding::text from f1.{flat} f
                where f.zone = any(%(zones)s) and {TIER1_EXISTS} and {TIER2_ANTIJOIN}
                order by f.id limit 200000""",
            dict(p=p, zones=zones),
        )
        pool = cur.fetchall()
        idx = rng.choice(len(pool), size=min(args.queries, len(pool)), replace=False)
        qvecs = []
        for i in idx:
            base = np.array(
                [float(x) for x in pool[int(i)][0].strip("[]").split(",")], dtype=np.float32
            )
            noise = rng.standard_normal(DIM).astype(np.float32) / math.sqrt(DIM)
            v = base + QUERY_NOISE * noise
            v /= np.linalg.norm(v)
            qvecs.append(halfvec_literal(v))

        probes[name] = dict(
            principal=p,
            depth=probe_rows[name]["depth"],
            container=probe_rows[name]["container"],
            zones=zones,
            n_zones=len(zones),
            zone_resolve_ms=zone_ms,
            accessible=n_acc,
            accessible_tier1_only=n_t1,
            key_reachable=n_key,
            selectivity=n_acc / total_rows,
            usersets=n_usersets,
            qvecs=qvecs,
        )
        log(
            f"probe {name}: principal={p} grant@L{probe_rows[name]['depth']} "
            f"zones={len(zones)} key_rows={n_key:,} tier1={n_t1:,} final={n_acc:,} "
            f"sel={n_acc/total_rows:.4%} usersets={n_usersets} "
            f"zone_resolve={zone_ms:.1f}ms"
        )

    strat = strategies(args.suffix)
    results = []
    truth = {}

    for name in wanted:
        pr = probes[name]
        for s in strat:
            sql = build_sql(s["table"], use_key=s["use_key"], use_tier1=s["use_tier1"])
            for st in RESET + s["setup"]:
                cur.execute(st)
            params_base = dict(p=pr["principal"], zones=pr["zones"])

            # warm up (one query, not timed) so page cache state is comparable
            try:
                cur.execute(sql, dict(params_base, q=pr["qvecs"][0]))
                cur.fetchall()
            except Exception as e:  # pragma: no cover
                log(f"  {name}/{s['name']}: FAILED {e}")
                continue

            lats, recalls, returned = [], [], []
            t_start = time.perf_counter()
            for qi, q in enumerate(pr["qvecs"]):
                t = time.perf_counter()
                cur.execute(sql, dict(params_base, q=q))
                ids = [r[0] for r in cur.fetchall()]
                lats.append((time.perf_counter() - t) * 1000)
                returned.append(len(ids))
                if s["group"] == "truth":
                    truth[(name, qi)] = set(ids)
                else:
                    gt = truth.get((name, qi))
                    if gt:
                        recalls.append(len(set(ids) & gt) / len(gt))
            elapsed = time.perf_counter() - t_start

            row = dict(
                probe=name,
                strategy=s["name"],
                group=s["group"],
                table=s["table"],
                use_key=s["use_key"],
                use_tier1=s["use_tier1"],
                settings=s["setup"],
                selectivity=pr["selectivity"],
                n_queries=len(pr["qvecs"]),
                p50_ms=pct(lats, 0.50),
                p95_ms=pct(lats, 0.95),
                mean_ms=statistics.fmean(lats),
                max_ms=max(lats),
                recall_mean=statistics.fmean(recalls) if recalls else None,
                recall_min=min(recalls) if recalls else None,
                recall_p5=pct(recalls, 0.05) if recalls else None,
                returned_mean=statistics.fmean(returned),
                returned_min=min(returned),
                short_results=sum(1 for r in returned if r < TOPK),
                wall_s=elapsed,
            )
            results.append(row)
            rc = "  --  " if row["recall_mean"] is None else f"{row['recall_mean']:.4f}"
            log(
                f"  {name:5s} {s['name']:16s} recall={rc} "
                f"p50={row['p50_ms']:8.1f}ms p95={row['p95_ms']:8.1f}ms "
                f"ret={row['returned_mean']:5.1f} short={row['short_results']}/{len(returned)}"
            )

    for st in RESET:
        cur.execute(st)

    out = dict(
        generated_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
        suffix=args.suffix,
        postgres=pgver,
        pgvector=pgvec,
        settings=settings,
        client_rtt_ms=rtt,
        total_rows=total_rows,
        dim=DIM,
        topk=TOPK,
        probes={
            k: {kk: vv for kk, vv in v.items() if kk not in ("qvecs", "zones")}
            for k, v in probes.items()
        },
        results=results,
    )
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2)
    log(f"wrote {args.out}")

    # ---- EXPLAIN (ANALYZE, BUFFERS) for the key cases --------------------
    if args.explain_out:
        with open(args.explain_out, "w") as fh:
            fh.write(f"Postgres: {pgver}\npgvector: {pgvec}\n\n")
            for name in wanted:
                pr = probes[name]
                for s in strat:
                    sql = build_sql(
                        s["table"], use_key=s["use_key"], use_tier1=s["use_tier1"]
                    )
                    for st in RESET + s["setup"]:
                        cur.execute(st)
                    q = pr["qvecs"][0]
                    fh.write("=" * 78 + "\n")
                    fh.write(
                        f"probe={name} (grant at L{pr['depth']}, selectivity "
                        f"{pr['selectivity']:.4%})  strategy={s['name']}\n"
                    )
                    fh.write(f"settings: {s['setup']}\n")
                    fh.write("=" * 78 + "\n")
                    try:
                        cur.execute(
                            "explain (analyze, buffers, verbose off, settings off) " + sql,
                            dict(p=pr["principal"], zones=pr["zones"], q=q),
                        )
                        for r in cur.fetchall():
                            fh.write(r[0] + "\n")
                    except Exception as e:
                        fh.write(f"FAILED: {e}\n")
                    fh.write("\n")
        for st in RESET:
            cur.execute(st)
        log(f"wrote {args.explain_out}")

    conn.close()


if __name__ == "__main__":
    main()
