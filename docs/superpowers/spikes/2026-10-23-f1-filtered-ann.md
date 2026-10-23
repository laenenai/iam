# Spike F1 — filtered ANN versus the authorization predicate

**Status.** Measured, 2026-10-23. Subject: `iam` design §17 finding **F1**.
**Scripts and raw output:** `spikes/f1/`.

This spike measures. It does not amend `iam` or `kgs` — the owner folds in what
it finds.

---

## 0. The answer, first

**`Predicate` must return a SQL fragment *plus* a key. The fragment stays
mandatory; the key is what makes the recall target reachable at all.**

Three measured facts force that:

1. **Strategy (a) — predicate inside the index scan — never meets the recall
   target, at any selectivity, under any pgvector tuning.** Best observed
   recall@20 across every (a) variant and every selectivity is **0.787**
   against a target of 0.95 (0.90 at 0.1%). With pgvector's *defaults* it
   returns **0 of 20 rows for 30 out of 30 queries** at 0.1% selectivity, and
   says nothing about it.
2. **Strategy (b) — pre-restricted candidate set — reaches the target**, and
   the only variant that reaches it in *both* query distributions is **exact
   search over the restricted set** (recall 1.000 by construction), which fits
   the 400 ms p95 budget up to ~10% selectivity (245 ms p95) and breaks it at
   50% (1,590 ms). Per-partition HNSW reaches 0.943–0.962 at ~360 ms p95 and is
   the right answer at high selectivity.
3. **The key costs nothing to maintain.** A membership change writes **2 rows
   and zero fact rows** — identical to §9.2's closures alone. A2's O(members)
   budget is met *exactly*, so **F1's central worry is unfounded**: the key (b)
   needs is not a per-principal materialization. It is the row's own ancestry,
   denormalized onto the row.

**§9.2 is therefore not invalidated.** Its two closures are correct and cheap —
measured at ~0.006 ms per candidate row, index-served, exactly as claimed. What
§9.2 is missing is (i) the key, and (ii) the fact that the **tier-2
classification anti-join, not the closures, is what costs** — it alone turns a
0.46 ms keyset page into a 296 ms one, blowing A2's 20 ms budget by 15×.

Two things the owner must decide, because they are not Claude's to decide:

- **The key imposes a granularity invariant the module cannot enforce alone:
  no grant may be written finer than the key's depth.** Measured consequence
  when it is violated: a key-only query returned **20 rows of which 9 were
  unauthorized**. That is a disclosure, not a recall miss.
- **F1 and F3 collide.** A scalar key exists only if containment is a tree. If
  a `kgs` fact has several containment paths (F3), the key is an *array*, a
  table cannot be partitioned by it, and the pre-restriction becomes an
  `&&` overlap test whose recall this spike did not measure.

---

## 1. Environment

| | |
|---|---|
| Postgres | **18.6** (Debian 18.6-1.pgdg12+2), aarch64-unknown-linux-gnu |
| pgvector | **0.8.7** |
| Image | `pgvector/pgvector:pg18` |
| Host | Apple Silicon, 10 cores / 64 GB; Docker Desktop VM 5 vCPU / 32 GB |
| Container | `--shm-size=2g` |

Both designs state Postgres 17+ with pgvector 0.8+. What was actually tested is
**18.6 / 0.8.7**, which satisfies that. Nothing here was run on 17.

```
shared_buffers = 8GB      effective_cache_size = 24GB   work_mem = 256MB
maintenance_work_mem = 8GB                              jit = off
max_parallel_workers_per_gather = 0    random_page_cost = 1.1
plan_cache_mode = force_custom_plan    track_io_timing = on
```

`max_parallel_workers_per_gather = 0` is deliberate: parallel workers make p95
depend on how many happen to be free, which is not the property under test.
`plan_cache_mode` and the driver's auto-prepare are discussed in §8 — they are
not cosmetic.

**Latency honesty.** The harness runs on the host over published TCP, so every
latency below includes a Docker round trip, measured in the same session over
300 × `SELECT 1`: **p50 0.83 ms, p95 1.18 ms**. Subtract it if you like; it
changes nothing at the scale of the numbers that matter. Server-side
`Execution Time` is in `f1/explain-key-cases.txt` for the key cases.

**Operational note that will stop a CI fixture dead.** A *parallel* HNSW build
allocates `maintenance_work_mem` in **dynamic shared memory** — `/dev/shm`.
With `maintenance_work_mem = 8GB` and a container's default shm size the build
does not run slowly, it fails:

```
ERROR:  could not resize shared memory segment "/PostgreSQL.3478004560"
        to 8586858464 bytes: No space left on device
```

The message names shared memory but not `/dev/shm`, and nothing in it suggests
a container flag. Every build below ran serially
(`max_parallel_maintenance_workers = 0`), which takes the memory from the
backend's own address space and succeeds.

---

## 2. Fixture

**2,000,000 rows with vectors.** Not the 10,000,000 of `iam` A2 / `kgs` A2.
Build cost was the binding constraint, and it is worth recording:

| build | elapsed | size |
|---|---|---|
| fixture load, 2,000,000 rows (numpy-built binary `COPY`) | 127 s | 3,125 MB heap |
| `facts_flat_hnsw` — one graph of 2,000,000 elements | **18 min 05 s** | 3,906 MB |
| `facts_part` populate (`INSERT … SELECT`, 1,000 partitions) | 24 s | 3,125 MB |
| `facts_part_hnsw` — 1,000 graphs of 2,000 elements | **8 min 41 s** | 3,914 MB |

Two incidental findings there. The partitioned build is **2× faster** than the
single flat build for the same element count, because HNSW insertion cost grows
with graph size. And it produces an index of the same total size, so (b) costs
nothing in storage.

2,000,000 preserves what the question turns on: 0.1% selectivity is 2,000 rows,
a real working set rather than a rounding error. At 10,000,000 the flat build
alone would have been multi-hour per layout and the recall question does not
change shape between the two.

### Vector storage: `halfvec(768)`

768 `float4`s are 3,076 bytes, over Postgres's ~2,000-byte TOAST threshold, so a
`vector(768)` column is pushed out of line and every heap fetch in an ANN scan
becomes a TOAST fetch. `halfvec(768)` is 1,544 bytes and stays inline. `kgs`
§13.5 already names `halfvec` as the intended storage for the large graphs, so
this is the configuration under test, not a shortcut. Crucially, **the ANN
strategies and the exact ground truth read the same column**, so quantization
cannot inflate or deflate any recall number here.

### The authorization shape is §9.2, not a boolean column

| Table | Rows | Role |
|---|---|---|
| `container` | 3,113 | containment hierarchy, depth 6 (levels 0–5) |
| `container_ancestry` | 17,435 | §9.2 closure 2: resource → ancestors incl. self |
| `principal` | 2,005 | 2,000 noise + 5 probes |
| `grp` | 250 | 200 noise groups (50 nested one level) + 10 per probe |
| `group_member` | 10,086 | authority-side direct edges |
| `membership_closure` | 14,449 | §9.2 closure 1: principal → usersets, transitive |
| `grant_tuple` | 9,998 | `(userset, container, relation)` at every level |
| `classification` | 500 | tier-2 label **definitions** |
| `fact_classification` | 400,000 | tier-2 **assignments**, at fact cardinality |
| `principal_clearance` | 962,400 | 480 of 500 labels per principal |
| `facts_flat` | 2,000,000 | consumer table, `halfvec(768)` |
| `facts_part` | 2,000,000 | same rows, LIST-partitioned on the (b) key, 1,000 partitions |

**F2 is honoured.** 500 is the number of label *definitions*; assignments are
400,000, so the gate is not a small-table join. Every strategy below — (b)
included — evaluates the tier-2 anti-join live, per candidate row. This turns
out to matter more than anything else in §7.

### Selectivity comes from grant depth

Fanouts 1 → 2 → 10 → 100 → 1,000 → 2,000, with 1,000 facts per leaf. A grant on
a container at depth *d*, reached through a two-level group chain, yields an
exact share of the table:

| probe | grant at | zones in key | rows via key | after tier 1 | after tier 2 | **selectivity** | key resolve |
|---|---|---|---|---|---|---|---|
| `p50` | L1 | 500 | 1,000,000 | 1,000,000 | 992,052 | **49.60%** | 5.8 ms |
| `p10` | L2 | 100 | 200,000 | 200,000 | 198,389 | **9.92%** | 4.3 ms |
| `p1` | L3 | 10 | 20,000 | 20,000 | 19,837 | **0.99%** | 3.6 ms |
| `p01` | L4 | 1 | 2,000 | 2,000 | 1,983 | **0.0992%** | 2.5 ms |
| `psub` | L5 (leaf) | 1 | 2,000 | 1,000 | 992 | **0.0496%** | 2.3 ms |

Each probe reaches its grant transitively (principal → leaf group → top group →
grant) and carries **11 usersets**, so the closure join is not degenerate. The
"after tier 2" column is the tier-2 anti-join removing ~0.8% of rows — small but
nonzero, as in reality.

`psub` exists for exactly one reason: **its grant is finer than the (b) key.**
It is the probe that shows what (b) does when the key's granularity assumption
is violated.

---

## 3. The strategies

### (a) predicate inside the index scan

One global HNSW over all 2,000,000 rows (`m = 16, ef_construction = 64`). The
query is §9.2's fragment plus `ORDER BY embedding <=> $q LIMIT 20`. Postgres
drives the index and applies the predicate above it.

pgvector 0.8 defaults, confirmed on the instance under test:

| GUC | default | max |
|---|---|---|
| `hnsw.ef_search` | 40 | 1000 |
| `hnsw.iterative_scan` | `off` | — |
| `hnsw.max_scan_tuples` | 20000 | 2147483647 |
| `hnsw.scan_mem_multiplier` | 1 | 1000 |

| variant | settings |
|---|---|
| `a-off` | pgvector defaults |
| `a-relaxed` | `iterative_scan = relaxed_order` |
| `a-strict` | `iterative_scan = strict_order` |
| `a-relaxed-tuned` | `relaxed_order`, `ef_search = 100`, `max_scan_tuples = 2000000`, `scan_mem_multiplier = 8` — permission to walk the whole index |

### (b) pre-restricted candidate set

The key is `zone`: the row's **L4 ancestor**, denormalized onto the row. It is a
function of the row's own container and mentions no principal, group or grant.

| variant | what it isolates |
|---|---|
| `b-key-flat` | key as a plain qual on the **unpartitioned** table — no pruning |
| `b-part` / `b-part-relaxed` | partition pruning + per-partition HNSW |
| `b-part-literal` | key set inlined, so pruning happens at plan time |
| `b-part-keyonly` | key + tier-2 only, **§9.2 fragment dropped** |
| `b-part-exact` | pruned, then brute force — no ANN index |

### Ground truth, and the two query distributions

`exact` is the same predicate with `enable_indexscan = off`; the plans confirm a
real `Sort` over the full filtered set (`f1/explain-key-cases.txt`). recall@20 is
`|ANN ∩ exact| / 20` over **30 queries**; the per-query minimum is reported
beside the mean, because a mean of 0.95 made of 0.99s and one 0.30 is not a
system that meets a 0.95 target.

**Ties were ruled out as a confound:** two independent exact plans over the same
filtered set agree on 20/20 rows across 30 queries, and a mean of 1.00 rows
share the 20th distance. The recall ceiling is a true 1.0.

Filtered-ANN recall is **not** a function of selectivity alone — it is a
function of how much of the vector space *near the query* is accessible. Two
distributions are therefore measured against the same index and predicate:

- **`inset`** — the query is drawn from the probe's own accessible rows plus
  noise: a user searching inside their own data. The fixture's vectors are
  *correlated*, each zone drawing from 2 of 256 topic clusters (measured: mean
  intra-zone cosine distance **0.58** against **0.96** for a random sample), so
  local selectivity near the query stays high even at 0.1% global selectivity.
- **`global`** — the query is drawn from the whole table's distribution,
  ignoring the probe, so the accessible rows are *not* concentrated near it.

They bracket reality and **they do not give the same answer.** Reporting only
`inset` would have answered an easier question than the one asked.

---

## 4. Calibration: what the index can do unfiltered

This number must come first, or every (a) row below is unattributable. recall@20
on `facts_flat`, **no predicate at all**, 30 queries:

| `ef_search` | 40 (default) | 100 | 200 | 400 | 1000 (max) |
|---|---|---|---|---|---|
| unfiltered recall@20 | **0.527** | 0.690 | 0.783 | 0.858 | 0.892 |

(`f1/calibration.txt`. This script's query sample is drawn with `TABLESAMPLE`
and is *not* seeded, so repeated runs move by a point or two — an earlier run
of the same script gave 0.543 / 0.705 / 0.780 / 0.837 / 0.885. The conclusion
is insensitive to that spread.)

**This fixture is a hard ANN problem.** 256 tight clusters over 2,000,000 rows
puts ~7,800 near-equidistant neighbours around every query, so HNSW at the
default `ef_search` finds barely half the true top-20 even with nothing
filtered. Read (a)'s absolute numbers as **pessimistic by roughly this gap**: on
an easier embedding distribution where unfiltered recall at `ef_search = 40`
were 0.95+, (a)'s `inset` figures would rise substantially.

What survives the caveat — and these are the load-bearing conclusions — is
everything *structural*, because none of it depends on index quality:

- `a-off` truncating silently is a property of `iterative_scan = off`, not of
  recall;
- (a)'s monotonic collapse as selectivity falls, and its collapse when the
  accessible set is not near the query;
- the cost of tuning (a) until it returns 20 rows;
- (b)-partitioned beating the global index *because* each graph it walks holds
  2,000 elements instead of 2,000,000 — at `ef_search = 40` that is nearly
  exhaustive, which is why (b) clears a bar the flat index cannot;
- exact-over-restricted being 1.000 by definition.

---

## 5. Results

30 queries per cell. Targets: **recall@20 ≥ 0.95** at 50/10/1%, **≥ 0.90** at
0.1%; **p95 < 400 ms**. Cells meeting the recall target are **bold**.

### 5.1 `inset` — query drawn from the principal's own data

**recall@20, mean (per-query minimum)**

| strategy | p50 (49.60%) | p10 (9.92%) | p1 (0.99%) | p01 (0.0992%) | psub (0.0496%) |
|---|---|---|---|---|---|
| `exact` *(truth)* | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 |
| `a-off` | 0.485 (0.00) | 0.400 (0.00) | 0.240 (0.05) | 0.240 (0.00) | 0.132 (0.00) |
| `a-relaxed` | 0.550 (0.00) | 0.717 (0.45) | 0.727 (0.50) | 0.708 (0.25) | 0.747 (0.00) |
| `a-strict` | 0.488 (0.00) | 0.537 (0.00) | 0.530 (0.05) | 0.483 (0.00) | 0.572 (0.00) |
| `a-relaxed-tuned` | 0.642 (0.00) | 0.733 (0.50) | 0.750 (0.50) | 0.715 (0.25) | 0.787 (0.25) |
| `b-key-flat` | 0.550 (0.00) | 0.717 (0.45) | 0.727 (0.50) | **1.000 (1.00)** | **1.000 (1.00)** |
| `b-part` | **0.962 (0.85)** | **0.958 (0.85)** | **0.955 (0.85)** | **0.962 (0.80)** | 0.918 (0.75) |
| `b-part-relaxed` | **0.962 (0.85)** | **0.958 (0.85)** | **0.955 (0.85)** | **0.962 (0.80)** | **0.968 (0.90)** |
| `b-part-literal` | **0.962 (0.85)** | **0.958 (0.85)** | **0.955 (0.85)** | **0.962 (0.80)** | 0.918 (0.75) |
| `b-part-keyonly` | *0.962* | *0.958* | *0.955* | *0.962* | *0.497* — **unsafe, see §6** |
| `b-part-exact` | **1.000 (1.00)** | **1.000 (1.00)** | **1.000 (1.00)** | **1.000 (1.00)** | **1.000 (1.00)** |

**p95 latency ms (p50)**

| strategy | p50 | p10 | p1 | p01 | psub |
|---|---|---|---|---|---|
| `exact` | 1,466 (1,439) | 198 (176) | 97 (85) | 6 (5) | 5 (4) |
| `a-off` | 84 (37) | 97 (26) | 46 (12) | 6 (4) | 14 (4) |
| `a-relaxed` | 31 (8) | 76 (24) | 47 (16) | 13 (7) | 220 (10) |
| `a-strict` | 8 (4) | 22 (9) | 14 (8) | 67 (8) | 159 (10) |
| `a-relaxed-tuned` | 42 (12) | 21 (7) | 15 (9) | 13 (7) | 56 (11) |
| `b-key-flat` | 6 (5) | 8 (5) | 8 (6) | 4 (4) | 4 (3) |
| `b-part` | 806 (367) | 65 (61) | 7 (6) | 3 (2) | 3 (2) |
| `b-part-relaxed` | 379 (349) | 69 (62) | 7 (6) | 3 (2) | 3 (3) |
| `b-part-literal` | 373 (348) | 64 (61) | 7 (6) | 4 (3) | 3 (2) |
| `b-part-exact` | 1,595 (1,566) | 245 (224) | 116 (95) | 6 (5) | 4 (4) |

**rows returned of 20 requested — short results are silent**

| strategy | p50 | p10 | p1 | p01 | psub |
|---|---|---|---|---|---|
| `a-off` | 17.3 (16/30 short) | 8.5 (28/30) | 4.9 (30/30) | 5.1 (30/30) | 2.7 (30/30) |
| `a-relaxed` | 20.0 | 20.0 | 20.0 | 20.0 | 19.2 (2/30) |
| `a-strict` | 20.0 | 20.0 | 19.5 (1/30) | 19.3 (2/30) | 18.1 (3/30) |
| `a-relaxed-tuned` | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 |
| `b-part` | 20.0 | 20.0 | 20.0 | 20.0 | 18.7 (16/30) |
| everything else | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 |

### 5.2 `global` — query drawn from the whole corpus

**recall@20, mean (per-query minimum)**

| strategy | p50 (49.60%) | p10 (9.92%) | p1 (0.99%) | p01 (0.0992%) | psub (0.0496%) |
|---|---|---|---|---|---|
| `a-off` | 0.418 (0.00) | 0.117 (0.00) | 0.012 (0.00) | **0.000 (0.00)** | **0.000 (0.00)** |
| `a-relaxed` | 0.525 (0.00) | 0.445 (0.00) | 0.100 (0.00) | 0.002 (0.00) | 0.003 (0.00) |
| `a-strict` | 0.450 (0.00) | 0.295 (0.00) | 0.037 (0.00) | 0.002 (0.00) | 0.003 (0.00) |
| `a-relaxed-tuned` | 0.613 (0.00) | 0.463 (0.00) | 0.335 (0.00) | 0.375 (0.15) | 0.477 (0.20) |
| `b-key-flat` | 0.525 (0.00) | 0.445 (0.00) | 0.100 (0.00) | **1.000 (1.00)** | **1.000 (1.00)** |
| `b-part` | 0.943 (0.80) | 0.847 (0.50) | 0.717 (0.40) | 0.642 (0.20) | 0.557 (0.00) |
| `b-part-relaxed` | 0.943 (0.80) | 0.847 (0.50) | 0.717 (0.40) | 0.642 (0.20) | 0.590 (0.00) |
| `b-part-exact` | **1.000 (1.00)** | **1.000 (1.00)** | **1.000 (1.00)** | **1.000 (1.00)** | **1.000 (1.00)** |

**p95 latency ms (p50)**

| strategy | p50 | p10 | p1 | p01 | psub |
|---|---|---|---|---|---|
| `exact` | 1,465 (1,437) | 194 (176) | 105 (86) | 7 (6) | 4 (4) |
| `a-off` | 52 (15) | 24 (14) | 18 (8) | 8 (4) | 4 (4) |
| `a-relaxed` | 26 (7) | 305 (29) | 371 (300) | 260 (202) | 193 (182) |
| `a-strict` | 13 (4) | 149 (15) | 216 (169) | 182 (172) | 188 (172) |
| `a-relaxed-tuned` | 19 (8) | 149 (9) | 1,211 (272) | **18,062 (4,673)** | **15,955 (3,137)** |
| `b-key-flat` | 7 (5) | 59 (7) | 74 (63) | 5 (4) | 4 (3) |
| `b-part` | 358 (347) | 67 (61) | 14 (8) | 3 (2) | 3 (2) |
| `b-part-relaxed` | 358 (351) | 64 (62) | 9 (7) | 4 (3) | 3 (2) |
| `b-part-exact` | 1,590 (1,566) | 245 (223) | 131 (114) | 6 (5) | 5 (4) |

**rows returned of 20 requested**

| strategy | p50 | p10 | p1 | p01 | psub |
|---|---|---|---|---|---|
| `a-off` | 15.6 (18/30 short) | 3.0 (30/30) | **0.2 (30/30)** | **0.0 (30/30)** | **0.0 (30/30)** |
| `a-relaxed` | 20.0 | 20.0 | 10.0 (21/30) | 1.2 (29/30) | 0.3 (30/30) |
| `a-strict` | 20.0 | 20.0 | 9.8 (21/30) | 1.2 (29/30) | 0.3 (30/30) |
| `a-relaxed-tuned` | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 |
| `b-part` | 20.0 | 20.0 | 20.0 | 20.0 | 18.9 (10/30) |
| `b-part-exact` | 20.0 | 20.0 | 20.0 | 20.0 | 20.0 |

### 5.3 What the tables say

- **(a) fails everywhere.** No (a) variant reaches 0.95 at any selectivity in
  either distribution. The ceiling is 0.787.
- **pgvector's defaults are the F1 scenario, exactly.** `a-off` + `global` +
  0.1% selectivity returns **zero rows, thirty times out of thirty**, with no
  error. This is `kgs` leak channel #6 arriving as a correctness bug, and it is
  what "the household graph at 0.1% selectivity is exactly where a
  correct-looking system returns nothing" means in numbers.
- **Tuning (a) until it returns 20 rows converts the ANN scan into a full index
  walk** and costs **18.1 s p95** — 45× the budget — while still only reaching
  0.375 recall.
- **`iterative_scan` fixes the row count, not the recall.** `a-relaxed` returns
  20 rows at p50/p10 but its recall at 0.1%/`global` is 0.002.
- **(b) works, and partitioning is optional.** `b-key-flat` — a plain btree on
  the key, no partitioning — gets **1.000 recall at 4 ms** at 0.1%, because the
  planner abandons the ANN index once the restricted set is small. At 1% it does
  *not* (recall 0.100), while `b-part-exact` gets 1.000 at 131 ms. **The planner
  cannot be trusted to make this switch**: the consumer must choose exact
  vs. ANN explicitly from the resolved key-set size. That is an API consequence.
- **At 50% selectivity nothing is comfortable.** Exact costs 1.47–1.59 s;
  per-partition HNSW gives 0.943–0.962 at ~360 ms p95 — inside the latency
  budget, and *just* under the recall target in the `global` distribution.
- **(b)'s latency is linear in the key-set size**, at roughly **0.7 ms per
  scanned partition** (500 zones → 347 ms, 100 → 61 ms, 10 → 6 ms, 1 → 2 ms).
  That, not maintenance, is (b)'s real cost.

---

## 6. The key is not a substitute for the predicate

`b-part-keyonly` drops §9.2's fragment and keeps only the key plus the tier-2
anti-join. For `p50`/`p10`/`p1`/`p01` it is indistinguishable from `b-part` —
because for those probes every accessible zone is *wholly* accessible.

For `psub`, whose grant sits one level **below** the key's depth, it is a
disclosure. Measured directly:

| | |
|---|---|
| rows in `psub`'s zone | 2,000 |
| rows `psub` is authorized to read | 1,000 |
| rows the key alone would expose | **1,000** |
| of a 20-row key-only top-20, rows that were **unauthorized** | **9** |

The recall column records this as 0.497, which *understates* it: those rows are
not missing, they are rows the principal may not see. So:

> **The fragment is mandatory and the key is an optimization on top of it.** The
> key may only replace the fragment where the module can guarantee that no grant
> is finer than the key's granularity — and the module cannot guarantee that
> unless it owns both the key and grant admission.

---

## 7. `iam` A2's *other* claim: "adds < 20 ms, plan shows an index join"

Measured on a keyset-paginated listing (`ORDER BY id LIMIT 50`), which is a
different question from filtered ANN and has a different answer
(`f1/predicate-cost.txt`):

| query | server-side execution time |
|---|---|
| unfiltered keyset page, 50 rows | **0.46 ms** |
| + §9.2 fragment, 49.60% principal | **295.67 ms** |
| + §9.2 fragment, 0.0992% principal | **162.75 ms** |
| same 0.0992% page with the (b) key available | **3.07 ms** |

**A2's "< 20 ms at p95" is missed by 8–15×** on a 2,000,000-row table — and A2
budgets 10,000,000.

The plan says precisely which half is at fault, and it is not the half §9.2 is
about:

- **The tier-1 closure join is exactly as cheap as §9.2 claims.** A
  `Nested Loop Semi Join` over three index-only scans
  (`container_ancestry_pkey` → `grant_tuple_container` →
  `membership_closure_pkey`), **0.006 ms per candidate row**, no sequential
  scan, no materialization of the rule set. §9.2's design claim is confirmed.
- **The tier-2 classification anti-join is the cost.** The planner picks a
  `Merge Anti Join` and walks `fact_classification` from the start —
  **200,394 index-only rows and 200,394 probes into `principal_clearance`** — to
  produce 50 output rows.
- **The key fixes it.** With the candidate set pruned to 2,000 rows, the same
  anti-join becomes a per-row `Nested Loop Anti Join` at 0.001 ms × 2,000 ≈ 3 ms.

So the key earns its place twice over, for a reason that has nothing to do with
ANN: **it bounds the set the tier-2 anti-join must consider.** This is F2
arriving as a measured number, and it means A2's 20 ms bullet is unreachable
with the fragment alone at any interesting selectivity.

---

## 8. `EXPLAIN` for the key cases

Full output: `f1/explain-key-cases.txt` (23 curated cases; query vectors
replaced by a placeholder, long per-partition runs elided — the raw dump is
30 MB, almost all of it 1,000 child subplans and repeated 768-dim literals).

**(a) truncating silently** — `a-off`, 0.0992% selectivity. The HNSW scan
produces exactly `ef_search` = 40 tuples and stops; 6 survive the predicate; the
`LIMIT 20` is satisfied with 6 rows and nobody is told:

```
Limit  (actual time=4.483..4.911 rows=6.00 loops=1)
  ->  Nested Loop Anti Join  (actual time=4.482..4.910 rows=6.00 loops=1)
        ->  Nested Loop Semi Join  (actual time=4.475..4.887 rows=6.00 loops=1)
              ->  Index Scan using facts_flat_hnsw on facts_flat f
                    (actual time=4.306..4.491 rows=40.00 loops=1)
                    Order By: (embedding <=> '[<768-dim query vector>]')
                    Index Searches: 1
```

`rows=40.00` out of the index, `rows=6.00` out of the Limit. That line is the
whole of F1.

**(b) exact over a pruned partition** — 0.0992%, genuinely exact, 4.9 ms:

```
Limit  (actual time=4.873..4.877 rows=20.00 loops=1)
  ->  Sort  (actual time=4.872..4.875 rows=20.00 loops=1)
        Sort Key: ((f.embedding <=> '[<768-dim query vector>]'))
        Sort Method: top-N heapsort  Memory: 26kB
        ->  Nested Loop Anti Join  (actual time=0.087..4.712 rows=1983.00 loops=1)
              ->  Hash Semi Join  (actual time=0.084..0.919 rows=2000.00 loops=1)
                    ->  Seq Scan on facts_part_z614 f  (actual rows=2000.00 loops=1)
                          Filter: (zone = ANY ('{614}'::smallint[]))
```

Note the `Seq Scan`: A2 says "never a sequential scan", and the strategy that
actually meets the recall target uses one. It is a scan of **2,000 rows in one
pruned partition**, which is the right thing to do — so the A2 wording needs to
be about *bounded* work, not about scan node types.

**(b) at high selectivity** — 500 partitions, `Merge Append` over 500
per-partition HNSW scans:

```
Limit  (actual time=653.349..653.666 rows=20.00 loops=1)
  ->  Nested Loop Anti Join  (actual time=653.347..653.662 rows=20.00 loops=1)
        ->  Nested Loop Semi Join  (actual time=653.337..653.600 rows=20.00 loops=1)
              ->  Merge Append  (actual time=653.298..653.500 rows=20.00 loops=1)
                    Sort Key: ((f.embedding <=> '[<768-dim query vector>]'))
                    ->  Index Scan using facts_part_z620_embedding_idx ...
                    ... [2679 plan lines elided -- per-partition child subplans] ...
Planning Time: 73.790 ms
Execution Time: 655.670 ms
```

**Planning alone is 73.8 ms** at 500 partitions. This is the shape that does not
scale in the number of zones, and it is the ceiling on (b)-by-partitioning.

### A plan-stability warning I could not explain away

The first (uncontrolled) run of this matrix reported partitioned-query p50s of
**340–715 ms at every selectivity, including the single-partition case**, where
the controlled re-run reports **2–7 ms**. I tried to attribute the gap and
failed:

- **generic plans from prepared statements**: real but small — ~3 ms for
  executions 1–5 against ~9 ms for 6+ (`f1/plancache.txt`);
- **cross-probe plan contamination** (a plan shaped by a 500-zone array reused
  for a 1-zone array): did **not** reproduce — still 2.0 ms after 30 warm-up
  executions with the big array;
- **cold `shared_buffers`**: did **not** reproduce — 32 ms on the first query
  after a restart, 2 ms thereafter.

The most likely remaining cause is checkpoint I/O still draining from the
1,000-partition index build that had just finished, but that is **unverified**.
The controlled numbers are the ones in §5. What the episode establishes is that
this plan shape's latency is **not stable enough to be trusted from a single
benchmark run** — which is the argument for `iam` §13's predicate plan tests
asserting plan *shape* in CI rather than a latency budget alone. Both runs'
recall agreed; only latency moved.

---

## 9. What maintaining the key costs

A2: *"Sharing a container of 100,000 objects with a 50-member team must write
O(50) projection rows, not O(5,000,000)."* The fixture's containers are 20,000
(L3) and 200,000 (L2) objects, so A2's 100,000 sits between them and the rate is
visible rather than asserted. Measured (`f1/05-maintenance.sql`, output in
`f1/maintenance.txt`):

| key shape | +1 member to a 50-member team with access to 200,000 objects | +1 grant on that container |
|---|---|---|
| **§9.2 closures only** (no key) | **2 rows** (1 `group_member`, 1 `membership_closure`); 0 fact rows | 1 row |
| **ancestry-zone key — strategy (b)** | **2 rows**; **0 fact rows** | **1 row**; **0 fact rows** |
| per-row **access-class key** (hash of the row's effective grant set) | 2 rows; 0 fact rows | **200,000 rows** |
| **per-principal materialization** `(principal, fact)` | **200,000 rows** | — |

Supporting numbers:

- initial share of the 200,000-object container with the 50-member team under
  per-principal materialization: **10,000,000 rows, 6.6 s** — the cross product
  A2 forbids, confirmed at the budgeted scale;
- distinct access classes over 2,000,000 rows: **1,996** — i.e. the
  access-class key *looks* attractive (a plausible partition count) and is the
  wrong choice, because it is grant-dependent;
- the ancestry-zone key writes **zero** fact rows on either event, because the
  key is a function of the row's own containment path and mentions no principal,
  group or grant.

**Assessment: (b) meets A2's O(members) budget exactly, and F1's stated worry is
unfounded.** The key is not "the per-principal materialization A2 forbids"; it is
the ancestry closure §9.2 already requires, written on the row instead of in a
side table. There is no maintenance trade-off to accept here.

What the key *does* cost, honestly:

1. **Re-parenting is O(subtree).** Moving a container rewrites `zone` on every
   fact beneath it. A2 does not budget this, and it is inherent to any ancestry
   closure including §9.2's own — but on the row rather than in a 17,435-row
   side table, so the write is at fact cardinality. This needs a budget.
2. **The granularity invariant of §6** — unenforceable by the module alone.
3. **Partition count does not scale.** 1,000 partitions already costs 73.8 ms of
   planning at 500 pruned; a deployment with 100,000 entity-sets cannot
   partition by zone. Since `b-key-flat` shows partitioning is *not* required
   below ~1% selectivity, the practical shape is **an indexed key, partitioned
   only where the zone count is small and selectivity is high**.
4. **F3 breaks it.** A scalar key presumes one containment path.

---

## 10. The API answer

> **`Predicate` returns a SQL fragment plus bound parameters — and, for
> consumers with a vector index, a second thing: a resolved key set over a
> row-local containment key the consumer has materialized and indexed, together
> with that key's granularity contract and the set's cardinality.**

Concretely, the surface needs to carry four things, and the last two are new:

| | what | why, measured |
|---|---|---|
| 1 | the §9.2 SQL fragment + parameters | mandatory; dropping it exposed 9 of 20 rows (§6) |
| 2 | the deny epoch check | §9.3, unchanged by this spike |
| 3 | **the resolved key set** (`zone IN (…)`) | without it, recall tops out at 0.787 and defaults return 0 rows (§5) |
| 4 | **the key-set cardinality + the granularity contract** | the consumer must pick exact vs ANN — the planner gets it wrong at 1% (§5.3), and the contract is what makes 3 safe (§6) |

**The key's concrete shape.** On each consumer row, one scalar column holding
**the id of the row's ancestor at a declared containment depth** — the nearest
ancestor that is an authorization container at or above the finest granularity
at which grants may be written. It is derived solely from the row's containment
path. In the fixture: `zone int not null`, the L4 ancestor, with
`create index on facts (zone)`; partitioning `LIST (zone)` is optional and only
pays above ~1% selectivity.

Resolution cost, measured: **2.3–5.8 ms** to turn a principal into its key set
(§2 table, `key resolve` column) — a join over the two closures, cacheable per
principal per epoch.

**Selectivity-aware execution, which the module should own rather than leave to
the consumer:**

| resolved key set | strategy | measured recall | measured p95 |
|---|---|---|---|
| small enough to brute-force (≲ 20,000 rows, ≲ 1%) | exact over the pruned set | **1.000** | 4–131 ms |
| mid (1–10%) | exact over the pruned set | **1.000** | 131–245 ms |
| large (≳ 10%) | per-partition HNSW, `iterative_scan = relaxed_order` | 0.943–0.962 | ~360 ms |

Both rows above the last meet the recall target in **both** query
distributions. The last row meets the latency budget and is borderline on
recall — and is the one case where the owner may have to accept 0.943 or raise
`ef_search`, which this spike did not sweep per-partition.

---

## 11. What this spike does not answer

- **F3 (DAG containment).** The fixture is a tree, deliberately. A multi-path
  key is an array, not a partition key, and its filtered-ANN recall is
  unmeasured. **F1's answer depends on F3's**, and F3 should be resolved before
  the `Predicate` signature is frozen.
- **F4 (attribute-scoped classifications).** Row predicates only; untouched.
- **The 10,000,000-row scale.** Measured at 2,000,000. Recall is a function of
  selectivity and local density, both preserved; latency is not, and the 50%
  case (already 1.5 s exact) will get worse.
- **A realistic embedding distribution.** §4's calibration shows this fixture is
  harder than real embeddings. (a)'s absolute numbers are pessimistic; the
  structural conclusions are not.
- **Per-partition `ef_search` sweep**, binary quantization + rerank (which would
  make a larger candidate pool affordable for (a)), and `vector(768)` full
  precision. The first is the obvious next thing to try for the 50% case.
- **A separately-generated uncorrelated-layout table.** `f1/06*.sql` build one
  and the rows were generated (measured intra-zone cosine distance 0.9965
  versus 0.58 correlated), but the HNSW indexes were not built; the adversarial
  geometry is covered instead by the `global` query distribution, which exercises
  the same mechanism — the accessible set not being near the query — on the
  index that was built.

---

## 12. Files

All under `docs/superpowers/spikes/f1/`.

| file | what |
|---|---|
| `run.sh` | end-to-end reproduction |
| `01-schema.sql` | closures, grants, classifications, consumer tables |
| `02-generate.py` | fixture generator; numpy-built binary `COPY` (wire format verified against pgvector 0.8.7) |
| `03-index.sql`, `03b-hnsw.sql`, `03c-part-hnsw.sql` | partitions, btrees, the two HNSW builds |
| `04-measure.py` | recall + latency matrix |
| `05-maintenance.sql` | §9 write-amplification measurements |
| `06-independent-schema.sql`, `06b`, `06c` | uncorrelated-layout fixture (generated, not indexed — see §11) |
| `07-report.py` | renders the JSON into §5's tables |
| `08-predicate-cost.sql` | §7, A2's 20 ms claim |
| `09-trim-explain.py` | curates the 30 MB `EXPLAIN` dump |
| `10-verify.py` | §3's tie ceiling and §4's unfiltered calibration |
| `11-plancache.py` | §8's plan-stability investigation |
| `results-correlated.json` | every measured cell, with settings and environment |
| `tables.md` | §5's tables as generated |
| `calibration.txt` | §4's unfiltered ceiling and §3's tie ceiling |
| `explain-key-cases.txt` | `EXPLAIN (ANALYZE, BUFFERS)` for 23 cases |
| `predicate-cost.txt`, `maintenance.txt`, `plancache.txt` | raw output for §7, §9, §8 |
