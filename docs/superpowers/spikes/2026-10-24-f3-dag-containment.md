# Spike F3 — abandoned, 2026-10-24: the premise was respecified

**Status.** **Abandoned mid-flight.** Not a spike report. Subject: `iam`
design §17 finding **F3**.
**Partial probe and transcripts:** `spikes/2026-10-24-f3-dag-containment/`.

This note exists because the probe directory beside it contains real
measurements of a question that stopped being a question. Without the note, a
later reader finds six transcripts, no conclusion, and no reason.

---

## 1. What F3 asked

> **Containment is a DAG, not a tree.** §9.2's ancestry closure and §8.2's
> "only on the direct path" both assume one path, but a kgs fact has an
> episode *and* zero or more nestable, sometimes predicate-defined
> entity-sets. Many-to-many at fact cardinality, maintained on every write,
> and "the direct path" is undefined.
>
> **Blocking for §9.2.** Either kgs's entity-sets stop being an authorization
> container, or the closure and `visible_below` are redefined for multiple
> paths.

F1's resolution carried a condition that depended on it: *"(iii) A scalar key
presumes a containment tree, so this answer depends on F3's, which is open.
Settle F3 before freezing the signature."*

## 2. What the probe was going to measure

Four containment-resolution strategies side by side on one 10,000,000-fact
fixture at kgs A2's proportions, differing only in where the transitive
closure lives; five candidate replacements for F1's scalar key on one table;
three candidate meanings for "the direct path", each priced for what it
exposes. Then a `Predicate` signature, and a priced recommendation on the one
branch a measurement can only cost out rather than decide — whether
entity-sets should be authorization containers at all.

## 3. Why it stopped

**The consumer whose shape caused F3 has been respecified.** Two documents
were added to the consumer repository on 2026-10-24 and are now the
implementation target, superseding the containment model F3 was written
against:

- `docs/epistemic_quad_store_spec.md`
- `docs/epistemic_quad_store_substrates.md`

Containment there is a **strict four-tier tree** — UNIVERSE → WORLD → SCOPE →
TOPIC (§2.1) — and its schema says so three times over (§4.2, §4.3):

```sql
CREATE TABLE named_graphs (
    id              TEXT NOT NULL,
    kind            graph_kind NOT NULL,   -- ENUM ('WORLD','SCOPE','TOPIC')
    parent_graph_id TEXT,                  -- ONE parent, nullable at the root
    ...);

CREATE TABLE tenant_quads (
    graph_id   TEXT NOT NULL,              -- ONE graph per quad
    subject_id TEXT NOT NULL, ...);

CREATE TABLE tenant_entities (
    home_graph_id TEXT NOT NULL,           -- ONE graph per entity
    ...);
```

and the view that resolves a principal's ground truth walks that single
parent pointer upward:

```sql
WITH RECURSIVE tenant_hierarchy AS (
    SELECT id, parent_graph_id FROM named_graphs WHERE id = target_graph_id
  UNION ALL
    SELECT ng.id, ng.parent_graph_id
    FROM named_graphs ng JOIN tenant_hierarchy th ON ng.id = th.parent_graph_id)
```

`UNION ALL` is the detail worth pausing on: it is correct here *only* because
each graph has one parent. A DAG walked with `UNION ALL` returns an ancestor
once per path and the function would over-count; the specification's own
recursion is evidence that its author is describing a tree.

Three independent greps over both documents return **zero** occurrences of
`entity-set`, `entity_set`, `predicate-defined` or `episode`. There is no
many-to-many membership table, no nestable grouping of entities, and nothing
predicate-defined. F3's premise — *"a fact has an episode **and** zero or more
nestable, sometimes predicate-defined entity-sets"* — names nothing in the
current specification.

**One DAG does survive in the new documents and it is not this one.**
`epistemic_quad_store_substrates.md` §3 Substrate C is a "Prerequisite & Task
Dependency Engine (Directed Acyclic Graph)". Its `task_dependencies` table is
a DAG of *prerequisites between tasks*, while `task_nodes.topic_id` is a
single reference to one `named_graphs` row. So every row still lives in
exactly one container, and the acyclic graph there is a scheduling structure
rather than a containment one. It is called out because a reader who greps for
"DAG" will find it, and should not conclude this note overlooked it.

So **F3 resolves by its own first branch** — "kgs's entity-sets stop being an
authorization container" — taken in the consumer's design rather than
established by this spike's measurement. And that branch is the one the spike
had flagged as needing the owner, so the owner decision F3 was waiting for has
been answered by respecification.

## 4. What finishing it would have cost, and why that spend is no longer justified

Measured, from the run that was stopped:

| | |
|---|---|
| fixture build, 10,000,000 facts + three closures | **13 m 23 s** |
| of which `fact_ancestry` (the DAG closure) load + index | **7 m 12 s** |
| on-disk size of the fixture | **~20 GB** |
| measurement sections completed before the stop | 6 of 8 |
| measurement wall clock to that point | ~35 min |

Finishing meant the remaining two sections, a curated `EXPLAIN` pass (F1
needed a dedicated script to cut a 30 MB dump down to 23 cases), the
`Predicate` signature, and the write-up. Call it the rest of a working day.

That spend bought an answer to "how should `iam` project a many-to-many
containment relation" for **no current consumer**. CAS's containment is
`tenant > fileset > document > slot`, a tree. The respecified consumer's is a
four-tier tree. `acre` has no specification at all, so it is evidence for
nothing in either direction and must not be cited as support — a planned
consumer nobody has written down cannot be the reason to carry a projection
shape. Building the general answer now would be designing against a shape no
document describes, which is the failure mode §10 of the design document
already records once.

## 5. What was measured before the stop, labelled partial

Everything below is from the real fixture and the cross-strategy differential
check in `fixture.txt` passed at **zero divergence over 35,000 decisions**, so
these are measurements of what they say they measure. None of them is F3's
resolution, and they are preserved only because a measured number is worth
more than the effort to re-derive it if a DAG consumer ever appears.

**The fixture** (`fixture.txt`): 10,000,000 facts, 2,000,000 entities, 100,000
episodes, 22,220 entity-sets in four nested levels with 5% of level-3 sets
double-parented, 2,000 principals, 200 overlapping groups.

**The DAG closure's cardinality**, which is the number F3 was mainly about:

| closure, keyed on | rows | heap + indexes |
|---|---|---|
| the **fact** — `fact_ancestry`, every ancestor by any path | **106,495,540** (10.65/fact, max 32) | **10.9 GB** |
| the fact's **direct** containers — `fact_container` | 30,969,775 (3.097/fact) | 3.1 GB |
| the **container** — `container_ancestry` | **433,063** | **37 MB** |

A factor of 246 in rows between the first and the last. The partial finding
the run was heading towards is that a DAG closure **factors**: a fact's
containment decomposes into one immutable hop (`fact → entity`, 1.398 per
fact, fixed at ingest) and two mutable ones bounded by *entity* and
*container* cardinality rather than by fact cardinality, so the authorization
closure never has to be stored per fact. It was not finished and should not be
quoted as a conclusion.

**Maintenance** (`maintenance.txt`), per authorization event:

| event | closure on the container | `fact_container` | `fact_ancestry` |
|---|---|---|---|
| +1 grant | 0 fact rows | 0 | 0 |
| +1 group member | 0 fact rows | 0 | 0 |
| +1 entity into a level-4 set, median entity (5 facts) | **1 row** | 5 | 25 |
| +1 entity into a level-4 set, **hub** entity (1,010 facts) | **1 row** | 1,010 | **5,915** |
| re-nest an entity-set | container rows only | **0** | at fact cardinality |

**Read cost** (`read.txt`, `recommended.txt`), keyset page of 50 against A2's
"+ < 20 ms". Unfiltered: **0.85 ms**. The best unkeyed strategy: **102.79 ms**
at 0.097% selectivity and **1,110 ms** at 0.01%, so no unkeyed strategy met A2
below about 1%. Adding the key helped by one to two orders of magnitude and
**did not settle into a shape**, which is the honest form of this row and the
reason it is not a conclusion:

| at 0.097% / 0.01% selectivity | p50 ms |
|---|---|
| best unkeyed (`C1`) | 102.79 / 1,110.58 |
| key set bound, no row-local key (`C5`) | **9.19** / 48.99 |
| key + the cheap-join fragment (`K2 + C4`) | 8.51 / 96.72 |
| key + the cheap-to-maintain fragment (`K2 + C2`) | 179.07 / **4.91** |

The last two rows invert between those two selectivities by a factor of
twenty, in opposite directions. That is plan choice rather than strategy, and
F1 hit the same wall from the other side — its §8 recorded a plan-stability
episode it "could not explain away". Settling it was work the spike never got
to, and anyone quoting a single cell from this table is quoting a plan.

The one row here that *is* clean: **the point decision — §7.1's `Decide` — is
1.0–1.5 ms under every strategy at every selectivity.** So the DAG cost nothing
at point granularity and only ever showed up in the filtered-read path.

**Keys** (`keys.txt`), five candidates for F1's scalar key, and the one result
here that outlived the spike: a scalar key on the tree dimension (the fact's
episode) **over-approximates by 57–77×** once grants arrive through the
orthogonal dimension, and its key-only page returned **43–50 unauthorized rows
of 50**. A single grant on one level-3 entity-set, covering 0.097% of facts,
spread across **6,740 of 100,000 episodes**. A designated canonical container
failed the other way, silently pruning **87%** of one probe's authorized facts.
An array of the fact's direct containers with a GIN index was exact — over-factor
1.0, zero pruned away, zero unauthorized — at every probe.

**Navigational visibility** (`visible-below.txt`): the permissive reading of
`visible_below` — every container that is an ancestor of some readable object
— made **2,366 containers list-visible to a principal granted ten episodes
(1,000 facts of 10,000,000), of which 2,356 were containers it holds no grant
on and none below**, 2,354 of them entity-sets. The restrictive reading —
containers on *every* path — was measured at exactly **{tenant, graph}**, size
2, min 2, max 2, for every fact with more than one path. Those two numbers are
what would have killed both readings, and they are the part of this probe most
worth keeping.

**Predicate-defined sets** (`predicate-sets.txt`): fifty sets, each one
equality on one indexed column — the cheapest predicate there is — produced
**5,000,000 membership edges** and, under the fact-keyed closure, **84,625,000
closure rows**, with a membership refresh at **23.3 s**.

## 6. What this resolution is not

**F3 is resolved for this consumer, under this specification.** It is not a
proof that authorization containment can never be a DAG, and it must not be
read as one:

- A future consumer whose resources belong to several containers **reopens
  F3**, and reopens F1's condition (iii) with it. The register row says so.
- Nothing here establishes that the single-path assumption is *right*. It
  establishes that it is *currently true of every specified consumer*, which
  is a different and weaker claim with a different expiry.
- `acre` is a planned consumer that nobody has specified. It is not evidence
  for the tree assumption and it would not have been evidence against it.

The cheapest guard is the one the corpus already has: `scenario.Paths` returns
every containment path and `DirectPath` refuses when there is more than one,
so a consumer registering a multi-path schema fails a claim rather than
silently getting a closure that does not mean what it says.

## 7. Files

All under `docs/superpowers/spikes/2026-10-24-f3-dag-containment/`.

| file | what |
|---|---|
| `harness.go`, `queries.go` | the probe: testcontainers-go on `pgvector/pgvector:pg18`, F1's server settings, every measured query as a parameterized constant |
| `f3spike_test.go`, `reports*_test.go` | the run and its report sections; skips unless `F3_SPIKE=1` |
| `01-schema.sql` … `08-predicate-sets.sql` | the fixture and the four closure strategies, scaled by `F3_SCALE` |
| `fixture.txt` | row counts, sizes, fan-out, and the zero-divergence differential check |
| `read.txt`, `keys.txt`, `visible-below.txt`, `maintenance.txt`, `predicate-sets.txt`, `recommended.txt` | the six sections that completed |
| — | `explain.txt` and `results.json` were never written; the run stopped first |

To re-run it, if a DAG consumer ever appears:

```
F3_SPIKE=1 go test -count=1 -timeout 4h \
    ./docs/superpowers/spikes/2026-10-24-f3-dag-containment/
```

`F3_SCALE=0.05` builds a twentieth of the fixture in about half a minute,
which is what every query in it was checked against before the full run.
