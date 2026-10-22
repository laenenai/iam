#!/usr/bin/env python3
"""F1 filtered-ANN spike: fixture generator.

Builds the hierarchy, identity, grants and classifications described in
01-schema.sql, then streams 2,000,000 halfvec(768) rows in as a hand-built
binary COPY stream (numpy-vectorised; the wire format was verified against
pgvector 0.8.7 by round-tripping a known vector through COPY ... TO BINARY).

Embedding layouts, selected with --layout:

  correlated   each L4 zone draws its facts from 2 of 256 topic clusters, so
               an authorization subtree is topically coherent. This is the
               realistic case: a household's facts are about the household.

  independent  cluster assignment is independent of the zone, so a principal's
               accessible rows are a uniform random sample of the vector
               space. This is the adversarial case, and it is the one kgs
               §13.3 is actually worried about.

The two layouts bracket the answer and they do not give the same answer, which
is the single most important methodological point in this spike.

Usage:
    python3 02-generate.py --dsn ... --layout correlated [--stage all]
"""

import argparse
import io
import math
import struct
import sys
import time

import numpy as np
import psycopg

DIM = 768
N_CLUSTERS = 256
CLUSTER_SIGMA = 0.5

# Hierarchy fanouts, level by level. Depth 6 => levels 0..5.
FANOUT = [1, 2, 5, 10, 10, 2]  # -> 1, 2, 10, 100, 1000, 2000 containers
FACTS_PER_LEAF = 1000  # 2000 leaves * 1000 = 2,000,000 facts
ZONE_DEPTH = 4  # L4 is the (b) key: 1000 zones of 2000 facts

N_PRINCIPALS = 2000
N_GROUPS = 200
N_GRANTS = 10000
N_CLASSIFICATION_DEFS = 500
CLASSIFIED_FRACTION = 0.20  # fraction of facts carrying >=1 classification
CLEARANCES_PER_PRINCIPAL = 480  # of 500 -> a probe loses ~0.8% of its rows

GROUP_ID_BASE = 1_000_000  # userset namespace offset for groups
RELATION_READ = 1

COPY_CHUNK = 20_000

SEED = 20261023


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---------------------------------------------------------------------------
# Hierarchy
# ---------------------------------------------------------------------------
def build_hierarchy():
    """Returns (containers, levels, ancestry, leaf_zone).

    containers: list of (id, parent_id, depth)
    levels[d]: list of container ids at depth d
    ancestry: list of (container_id, ancestor_id) including self
    leaf_zone: dict leaf_container_id -> L4 zone container id
    """
    containers = []
    levels = []
    next_id = 1
    parent_of = {}

    # level 0
    root = next_id
    next_id += 1
    containers.append((root, None, 0))
    levels.append([root])

    for depth in range(1, len(FANOUT)):
        prev = levels[depth - 1]
        cur = []
        for p in prev:
            for _ in range(FANOUT[depth]):
                cid = next_id
                next_id += 1
                containers.append((cid, p, depth))
                parent_of[cid] = p
                cur.append(cid)
        levels.append(cur)

    ancestry = []
    for cid, _, _ in containers:
        node = cid
        while node is not None:
            ancestry.append((cid, node))
            node = parent_of.get(node)

    # leaf (L5) -> zone (L4)
    leaf_zone = {}
    for leaf in levels[5]:
        node = leaf
        d = 5
        while d > ZONE_DEPTH:
            node = parent_of[node]
            d -= 1
        leaf_zone[leaf] = node

    return containers, levels, ancestry, leaf_zone, parent_of


# ---------------------------------------------------------------------------
# Binary COPY for halfvec(768)
# ---------------------------------------------------------------------------
COPY_HEADER = b"PGCOPY\n\xff\r\n\0" + struct.pack("!ii", 0, 0)
COPY_TRAILER = b"\xff\xff"


def halfvec_payload(vecs):
    """Build the per-row halfvec field bytes for an (n, DIM) float array.

    halfvec binary layout: int16 dim, int16 unused, then dim * big-endian
    float16 raw bits. Verified against pgvector 0.8.7.
    """
    n = vecs.shape[0]
    out = np.empty((n, 4 + 2 * DIM), dtype=np.uint8)
    out[:, 0:2] = np.frombuffer(struct.pack("!h", DIM), dtype=np.uint8)
    out[:, 2:4] = 0
    body = np.ascontiguousarray(vecs.astype(">f2"))
    out[:, 4:] = body.view(np.uint8).reshape(n, 2 * DIM)
    return out


def facts_copy_chunk(ids, container_ids, zones, vecs):
    """Binary COPY body for facts(id bigint, container_id int, zone int, embedding halfvec)."""
    n = len(ids)
    vec_bytes = halfvec_payload(vecs)
    veclen = 4 + 2 * DIM
    # row = int16 nfields | int32 8 | int64 id | int32 4 | int32 cid
    #       | int32 4 | int32 zone | int32 veclen | vec
    rowlen = 2 + (4 + 8) + (4 + 4) + (4 + 4) + (4 + veclen)
    buf = np.empty((n, rowlen), dtype=np.uint8)
    pos = 0

    def put(dtype, values, width):
        nonlocal pos
        buf[:, pos : pos + width] = (
            np.ascontiguousarray(values.astype(dtype)).view(np.uint8).reshape(n, width)
        )
        pos += width

    const16 = np.full(n, 4, dtype=">i2")
    buf[:, 0:2] = np.ascontiguousarray(const16).view(np.uint8).reshape(n, 2)
    pos = 2
    put(">i4", np.full(n, 8), 4)
    put(">i8", ids, 8)
    put(">i4", np.full(n, 4), 4)
    put(">i4", container_ids, 4)
    put(">i4", np.full(n, 4), 4)
    put(">i4", zones, 4)
    put(">i4", np.full(n, veclen), 4)
    buf[:, pos : pos + veclen] = vec_bytes
    pos += veclen
    assert pos == rowlen, (pos, rowlen)
    return buf.tobytes()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--layout", choices=["correlated", "independent"], default="correlated")
    ap.add_argument("--suffix", default="", help="table name suffix, e.g. _i")
    ap.add_argument("--skip-auth", action="store_true", help="auth tables already loaded")
    args = ap.parse_args()

    rng = np.random.default_rng(SEED)
    containers, levels, ancestry, leaf_zone, parent_of = build_hierarchy()
    leaves = levels[5]
    zones = levels[ZONE_DEPTH]
    log(
        f"hierarchy: {[len(l) for l in levels]} containers per level, "
        f"{len(ancestry)} ancestry rows, {len(leaves)} leaves, {len(zones)} zones"
    )

    conn = psycopg.connect(args.dsn, autocommit=True)
    cur = conn.cursor()
    cur.execute("set search_path = f1, public")

    # -- descendants of a container, for probe construction -------------------
    desc = {}
    for cid, anc in ancestry:
        desc.setdefault(anc, []).append(cid)

    if not args.skip_auth:
        log("loading containers + ancestry")
        with cur.copy("copy container (id, parent_id, depth) from stdin") as cp:
            for cid, p, d in containers:
                cp.write_row((cid, p, d))
        with cur.copy("copy container_ancestry (container_id, ancestor_id) from stdin") as cp:
            for a, b in ancestry:
                cp.write_row((a, b))

        log("loading principals + groups")
        with cur.copy("copy principal (id) from stdin") as cp:
            for i in range(1, N_PRINCIPALS + 1):
                cp.write_row((i,))

        # 200 groups; 50 of them nested one level under another group, so the
        # membership closure is genuinely transitive.
        group_parent = {}
        for g in range(1, N_GROUPS + 1):
            if g > 150:
                group_parent[g] = int(rng.integers(1, 151))
            else:
                group_parent[g] = None
        with cur.copy("copy grp (id, parent_id) from stdin") as cp:
            for g in range(1, N_GROUPS + 1):
                cp.write_row((g, group_parent[g]))

        # Direct membership: each principal in ~5 groups, overlapping.
        direct = []  # (group_id, member_id, member_kind)
        memb_of = {p: set() for p in range(1, N_PRINCIPALS + 1)}
        for p in range(1, N_PRINCIPALS + 1):
            k = int(rng.integers(3, 8))
            gs = rng.choice(N_GROUPS, size=k, replace=False) + 1
            for g in gs:
                direct.append((int(g), p, 0))
                memb_of[p].add(int(g))
        for g, parent in group_parent.items():
            if parent is not None:
                direct.append((parent, g, 1))

        # Probe principals. Each probe gets its own two-level group chain so
        # the grant is reached transitively, and is deliberately kept out of
        # the noise groups so its selectivity is exactly the subtree it was
        # granted.
        probes = {}
        probe_specs = [
            ("p50", 1),  # grant on an L1 container  -> 1,000,000 rows
            ("p10", 2),  # grant on an L2 container  ->   200,000 rows
            ("p1", 3),  # grant on an L3 container  ->    20,000 rows
            ("p01", 4),  # grant on an L4 container  ->     2,000 rows == 1 zone
            ("psub", 5),  # grant on an L5 leaf       ->     1,000 rows == half a zone
        ]
        probe_pid = N_PRINCIPALS
        probe_gid = N_GROUPS
        extra_grants = []
        for name, depth in probe_specs:
            probe_pid += 1
            pid = probe_pid
            probe_gid += 1
            gleaf = probe_gid
            probe_gid += 1
            gtop = probe_gid
            target = int(levels[depth][len(levels[depth]) // 2])
            probes[name] = dict(principal=pid, depth=depth, container=target, groups=[gleaf, gtop])
            # grant to the top group; probe reaches it via gleaf -> gtop
            extra_grants.append((GROUP_ID_BASE + gtop, target, RELATION_READ))
            # realistic membership breadth: 8 further groups, each granted
            # only on a container already inside the probe's own subtree, so
            # the closure is wide without changing selectivity.
            inside = desc.get(target, [target])
            for _ in range(8):
                probe_gid += 1
                gx = probe_gid
                probes[name]["groups"].append(gx)
                c = int(inside[int(rng.integers(0, len(inside)))])
                extra_grants.append((GROUP_ID_BASE + gx, c, RELATION_READ))

        with cur.copy("copy principal (id) from stdin") as cp:
            for name in probes:
                cp.write_row((probes[name]["principal"],))
        with cur.copy("copy grp (id, parent_id) from stdin") as cp:
            seen = set()
            for name, pr in probes.items():
                gleaf, gtop = pr["groups"][0], pr["groups"][1]
                if gleaf not in seen:
                    cp.write_row((gleaf, gtop))
                    seen.add(gleaf)
                if gtop not in seen:
                    cp.write_row((gtop, None))
                    seen.add(gtop)
                for gx in pr["groups"][2:]:
                    if gx not in seen:
                        cp.write_row((gx, None))
                        seen.add(gx)
        for name, pr in probes.items():
            direct.append((pr["groups"][0], pr["principal"], 0))
            direct.append((pr["groups"][1], pr["groups"][0], 1))
            for gx in pr["groups"][2:]:
                direct.append((gx, pr["principal"], 0))
            memb_of[pr["principal"]] = set(pr["groups"])

        with cur.copy("copy group_member (group_id, member_id, member_kind) from stdin") as cp:
            for row in set(direct):
                cp.write_row(row)

        log("computing membership closure")
        # transitive closure over nested groups
        def group_ancestors(g):
            out = []
            node = g
            while node is not None:
                out.append(node)
                node = group_parent.get(node) if node <= N_GROUPS else _probe_gparent.get(node)
            return out

        _probe_gparent = {}
        for name, pr in probes.items():
            _probe_gparent[pr["groups"][0]] = pr["groups"][1]
            _probe_gparent[pr["groups"][1]] = None
            for gx in pr["groups"][2:]:
                _probe_gparent[gx] = None

        closure_rows = []
        for p, gs in memb_of.items():
            us = {p}
            for g in gs:
                for ga in group_ancestors(g):
                    us.add(GROUP_ID_BASE + ga)
            for u in us:
                closure_rows.append((p, u))
        log(f"membership closure: {len(closure_rows)} rows")
        with cur.copy("copy membership_closure (principal_id, userset_id) from stdin") as cp:
            for row in closure_rows:
                cp.write_row(row)

        log("loading grants")
        all_cids = [c[0] for c in containers]
        gset = set()
        for _ in range(N_GRANTS):
            # usersets: 70% groups, 30% individual principals
            if rng.random() < 0.7:
                u = GROUP_ID_BASE + int(rng.integers(1, N_GROUPS + 1))
            else:
                u = int(rng.integers(1, N_PRINCIPALS + 1))
            c = int(all_cids[int(rng.integers(0, len(all_cids)))])
            gset.add((u, c, RELATION_READ))
        for row in extra_grants:
            gset.add(row)
        with cur.copy("copy grant_tuple (userset_id, container_id, relation) from stdin") as cp:
            for row in gset:
                cp.write_row(row)
        log(f"grants: {len(gset)}")

        log("loading classifications")
        with cur.copy("copy classification (id) from stdin") as cp:
            for i in range(1, N_CLASSIFICATION_DEFS + 1):
                cp.write_row((i,))
        with cur.copy("copy principal_clearance (principal_id, classification_id) from stdin") as cp:
            for p in list(range(1, N_PRINCIPALS + 1)) + [
                pr["principal"] for pr in probes.values()
            ]:
                cl = rng.choice(N_CLASSIFICATION_DEFS, size=CLEARANCES_PER_PRINCIPAL, replace=False)
                for c in cl:
                    cp.write_row((p, int(c) + 1))

        total_facts = len(leaves) * FACTS_PER_LEAF
        n_classified = int(total_facts * CLASSIFIED_FRACTION)
        log(f"loading {n_classified} fact classifications")
        with cur.copy("copy fact_classification (fact_id, classification_id) from stdin") as cp:
            step = 1_000_000
            done = 0
            while done < n_classified:
                m = min(step, n_classified - done)
                fids = rng.choice(total_facts, size=m, replace=False) + 1
                cls = rng.integers(1, N_CLASSIFICATION_DEFS + 1, size=m)
                for f, c in zip(fids.tolist(), cls.tolist()):
                    cp.write_row((f, c))
                done += m

        # record probe metadata for the measurement harness
        cur.execute(
            """
            create table if not exists probe (
                name text primary key, principal_id int, depth int, container_id int
            )"""
        )
        cur.execute("truncate probe")
        with cur.copy("copy probe (name, principal_id, depth, container_id) from stdin") as cp:
            for name, pr in probes.items():
                cp.write_row((name, pr["principal"], pr["depth"], pr["container"]))

    # -----------------------------------------------------------------------
    # Facts + embeddings
    # -----------------------------------------------------------------------
    sfx = args.suffix
    flat = f"facts_flat{sfx}"
    log(f"generating embeddings into {flat} (layout={args.layout})")

    centroids = rng.standard_normal((N_CLUSTERS, DIM)).astype(np.float32)
    centroids /= np.linalg.norm(centroids, axis=1, keepdims=True)
    # record centroids so the query harness can draw in-distribution queries
    cur.execute(
        f"create table if not exists centroid{sfx} (id int primary key, v halfvec({DIM}))"
    )
    cur.execute(f"truncate centroid{sfx}")
    with cur.copy(f"copy centroid{sfx} (id, v) from stdin (format binary)") as cp:
        cp.write(COPY_HEADER)
        n = N_CLUSTERS
        vec = halfvec_payload(centroids)
        veclen = 4 + 2 * DIM
        for i in range(n):
            cp.write(
                struct.pack("!hii", 2, 4, i)
                + struct.pack("!i", veclen)
                + vec[i].tobytes()
            )
        cp.write(COPY_TRAILER)

    # zone -> its 2 topic clusters (correlated layout only)
    zone_clusters = {
        z: rng.choice(N_CLUSTERS, size=2, replace=False) for z in zones
    }

    t0 = time.time()
    rows_done = 0
    total = len(leaves) * FACTS_PER_LEAF
    with cur.copy(
        f"copy {flat} (id, container_id, zone, embedding) from stdin (format binary)"
    ) as cp:
        cp.write(COPY_HEADER)
        fact_id = 0
        pending_ids = []
        pending_cid = []
        pending_zone = []
        pending_cluster = []

        def flush():
            nonlocal pending_ids, pending_cid, pending_zone, pending_cluster, rows_done
            if not pending_ids:
                return
            ids = np.asarray(pending_ids, dtype=np.int64)
            cids = np.asarray(pending_cid, dtype=np.int32)
            zs = np.asarray(pending_zone, dtype=np.int32)
            cl = np.asarray(pending_cluster, dtype=np.int32)
            n = len(ids)
            noise = rng.standard_normal((n, DIM)).astype(np.float32) / math.sqrt(DIM)
            v = centroids[cl] + CLUSTER_SIGMA * noise
            v /= np.linalg.norm(v, axis=1, keepdims=True)
            cp.write(facts_copy_chunk(ids, cids, zs, v))
            rows_done += n
            pending_ids, pending_cid, pending_zone, pending_cluster = [], [], [], []

        for leaf in leaves:
            z = leaf_zone[leaf]
            if args.layout == "correlated":
                cl_pool = zone_clusters[z]
                cl = cl_pool[rng.integers(0, 2, size=FACTS_PER_LEAF)]
            else:
                cl = rng.integers(0, N_CLUSTERS, size=FACTS_PER_LEAF)
            for k in range(FACTS_PER_LEAF):
                fact_id += 1
                pending_ids.append(fact_id)
                pending_cid.append(leaf)
                pending_zone.append(z)
                pending_cluster.append(int(cl[k]))
            if len(pending_ids) >= COPY_CHUNK:
                flush()
                if rows_done % 200_000 == 0:
                    el = time.time() - t0
                    log(
                        f"  {rows_done}/{total} rows ({rows_done/total:.0%}) "
                        f"{rows_done/el:,.0f} rows/s"
                    )
        flush()
        cp.write(COPY_TRAILER)
    log(f"{flat} loaded: {rows_done} rows in {time.time()-t0:.0f}s")
    conn.close()


if __name__ == "__main__":
    sys.exit(main())
