#!/usr/bin/env python3
"""Two checks the main matrix cannot make about itself.

1. TIES. halfvec is float16. If many rows sit at exactly the same cosine
   distance from the query, "the top 20" is not a well-defined set, and two
   exact plans that scan in different orders return different -- equally
   correct -- answers. Any recall number then has a ceiling below 1.0 that
   has nothing to do with the index. This check measures that ceiling by
   diffing two *exact* plans against each other.

2. UNFILTERED HNSW RECALL. Strategy (a)'s recall is a product of two things:
   how well HNSW finds the global nearest neighbours at all, and how much the
   filter costs on top. Without the first number the second is not
   attributable. This measures recall@20 with no predicate at all, by
   ef_search.
"""
import argparse, math, statistics
import numpy as np, psycopg

DIM, TOPK, SEED = 768, 20, 4242


def lit(v):
    return "[" + ",".join(f"{x:.6g}" for x in v) + "]"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--queries", type=int, default=30)
    a = ap.parse_args()
    rng = np.random.default_rng(SEED)
    cx = psycopg.connect(a.dsn, autocommit=True)
    cur = cx.cursor()
    cur.execute("select '[1,2]'::vector <=> '[1,2]'::vector")

    # ---------- 1. tie ceiling, at the 0.1% probe ----------------------
    cur.execute("select principal_id, container_id from f1.probe where name='p01'")
    pid, cont = cur.fetchone()
    cur.execute("select id from f1.container where depth=4 and id=%s", (cont,))
    zone = cur.fetchone()[0]

    cur.execute(
        "select embedding::text from f1.facts_flat where zone=%s order by id limit 2000",
        (zone,),
    )
    pool = [r[0] for r in cur.fetchall()]

    EXACT = """
      select f.id, (f.embedding <=> %(q)s)::float8 d
      from f1.{t} f
      where f.zone = any(%(z)s)
        and not exists (
            select 1 from f1.fact_classification fc
            where fc.fact_id = f.id and not exists (
                select 1 from f1.principal_clearance pc
                where pc.principal_id = %(p)s and pc.classification_id = fc.classification_id))
      order by (f.embedding <=> %(q)s) {tb}
      limit 25
    """
    for s in ["set enable_indexscan=off", "set enable_indexonlyscan=off",
              "set hnsw.iterative_scan=off"]:
        cur.execute(s)

    overlaps, tie_counts = [], []
    for i in range(a.queries):
        base = np.array([float(x) for x in pool[int(rng.integers(0, len(pool)))]
                         .strip("[]").split(",")], dtype=np.float32)
        v = base + 0.30 * rng.standard_normal(DIM).astype(np.float32) / math.sqrt(DIM)
        v /= np.linalg.norm(v)
        q = lit(v)
        par = dict(q=q, z=[zone], p=pid)
        # two exact plans over the same filtered set, differing only in
        # tie-break order (id asc vs id desc)
        cur.execute(EXACT.format(t="facts_flat", tb=", f.id asc"), par)
        A = cur.fetchall()
        cur.execute(EXACT.format(t="facts_part", tb=", f.id desc"), par)
        B = cur.fetchall()
        a20 = {r[0] for r in A[:TOPK]}
        b20 = {r[0] for r in B[:TOPK]}
        overlaps.append(len(a20 & b20) / TOPK)
        # how many rows sit at exactly the 20th distance
        d20 = A[TOPK - 1][1]
        tie_counts.append(sum(1 for r in A if r[1] == d20))

    print("--- 1. tie ceiling on exact-vs-exact, probe p01 (0.1%) ---")
    print(f"  queries: {a.queries}")
    print(f"  mean overlap@20 between two EXACT plans : {statistics.fmean(overlaps):.4f}")
    print(f"  min  overlap@20                         : {min(overlaps):.2f}")
    print(f"  mean rows sharing the 20th distance     : {statistics.fmean(tie_counts):.2f}")
    print(f"  max  rows sharing the 20th distance     : {max(tie_counts)}")

    # ---------- 2. unfiltered HNSW recall by ef_search ------------------
    print("\n--- 2. unfiltered recall@20 on facts_flat (2,000,000 rows), no predicate ---")
    cur.execute("select id from f1.facts_flat tablesample system(0.05) limit %s", (a.queries,))
    ids = [r[0] for r in cur.fetchall()][: a.queries]
    cur.execute("select id, embedding::text from f1.facts_flat where id = any(%s)", (ids,))
    qrows = cur.fetchall()
    qs = []
    for _, txt in qrows:
        base = np.array([float(x) for x in txt.strip("[]").split(",")], dtype=np.float32)
        v = base + 0.30 * rng.standard_normal(DIM).astype(np.float32) / math.sqrt(DIM)
        v /= np.linalg.norm(v)
        qs.append(lit(v))

    truth = []
    for s in ["set enable_indexscan=off", "set enable_indexonlyscan=off"]:
        cur.execute(s)
    for q in qs:
        cur.execute(
            "select id from f1.facts_flat order by (embedding <=> %s) limit 20", (q,)
        )
        truth.append({r[0] for r in cur.fetchall()})

    cur.execute("set enable_indexscan=on")
    cur.execute("set enable_indexonlyscan=on")
    for ef in [40, 100, 200, 400, 1000]:
        cur.execute("set hnsw.iterative_scan=off")
        cur.execute(f"set hnsw.ef_search={ef}")
        rec = []
        for q, gt in zip(qs, truth):
            cur.execute(
                "select id from f1.facts_flat order by embedding <=> %s limit 20", (q,)
            )
            got = {r[0] for r in cur.fetchall()}
            rec.append(len(got & gt) / 20)
        print(f"  ef_search={ef:5d}  recall@20 mean={statistics.fmean(rec):.4f} "
              f"min={min(rec):.2f}")
    cx.close()


if __name__ == "__main__":
    main()
