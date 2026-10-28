# Spike: CAS authorization SQL joins and OpenFGA change-feed projection

**Status.** Complete, 2026-10-27. Answers the CAS row-level join question and
tests whether the IAM read models can be built from OpenFGA `ReadChanges`.
**Code and transcripts:** `spikes/2026-10-27-cas-sql-join/`.

---

## 1. The questions

1. Can a CAS-shaped consumer filter ten million documents in one SQL
   statement against IAM's read models, and which query shape should it use
   at which selectivity?
2. Can the same read models be built by listening to OpenFGA tuple changes,
   instead of applying the es-lite log directly?

The first question is the concrete form of the design's F4/join-strategy
gap. The second is a proposed simplification of the projector.

## 2. Method

Two phases, both on a throwaway Postgres 17 container and a real OpenFGA
v1.22.0 server.

**Phase 1 — SQL join.** One tenant with 10,000,000 CAS documents, 10,000
filesets, 2,000 users, 200 groups, 10,000 group memberships and about 6,000
grants. A second 100,000-document tenant exists only to prove RLS. The tree
is `root > fileset > document`. The documents carry `urn`, `fileset_urn` and
`root_urn`; that denormalization is the CAS-specific option under test.

Four paths were compared over the same fixture:

| Path | What it does |
|---|---|
| `closure` | Generic IAM read model: `cas_documents → iam_node_closure → iam_grants`, then the live-subject and live-node filters. Document-driven: walks the consumer's page index and tests each row. |
| `denorm` | CAS-optimized: `cas_documents` carries its ancestors, so it tests `iam_grants` directly and never touches the closure. Still document-driven. |
| `grant` | Grant-driven: resolve the subject's accessible ancestors, expand them through `iam_node_closure`, then sort the small candidate set. |
| `listobjects` | The v1 baseline: IAM returns the authorized URNs, the consumer puts them in a relation and joins. The URN-list materialization is measured separately. |

Every path applies the same relation ladder (`viewer < commenter < editor <
owner`), the same live-subject filter and the same live-node filter. Every
query runs under tenant RLS.

**Phase 2 — OpenFGA change feed.** A separate `proj` schema with 100
filesets, 10,000 documents, 200 users, 20 groups, 742 distinct grants and 210
memberships. 11,052 tuples were written to a real OpenFGA memory store. The
projection then read `GET /stores/{store}/changes` in pages of 100 and built
`iam_nodes_proj`, `iam_grants_proj` and `iam_group_members_proj` with no
source-table reads.

## 3. Fixture note that matters

The first fixture assigned documents to filesets contiguously:
`document i` was in `fileset (i-1)/1000 + 1`. That made a 1%-access user's
documents the *oldest* 100,000 rows, so the document-driven page query had to
walk 9.9 million rows before it found its first authorized document. It
timed out at 60 s.

The final fixture scatters the mapping (`(i * 7919) % 10000 + 1`, with 7919
coprime to 10,000), so a user's filesets contain documents across the whole
creation order. That is the realistic shape; all reported numbers use it.
It also shows that the query plan is not the only variable — the correlation
between access and page order is.

## 4. Results: SQL join

p50 milliseconds, one warm Postgres, 10M documents. `n=30`, except the
10M-access page (`n=10`), the 1% page (`n=30`), and the slow document-driven
cases noted below.

| Probe | Access | `closure` | `denorm` | `grant` | `listobjects` |
|---|---|---:|---:|---:|---:|
| `u0001` root viewer | 10,000,000 (100%) | 2.16 | **1.13** | — | infeasible |
| `u0020` 100 filesets | 100,000 (1%) | 41.59 | **27.74** | 951.18 | 8.73 + 1.52 s populate |
| `u0021` 10 filesets | 10,000 (0.1%) | 409.84 | 272.42 | **95.36** | 73.58 + 0.20 s populate |
| `u0003` group, 10 filesets | 10,000 (0.1%) | 417.40 | 268.81 | **95.81** | — |
| `u0022` one fileset | 1,000 (0.01%) | ~4,100* | ~4,100* | **7.27** | — |
| `u0004` 10 direct documents | 10 | >60,000 | >60,000 | **0.78** | — |
| point check, one document | 1 | — | — | **0.37** | — |

\* One-off measurement from the earlier run, not part of the final matrix;
the document-driven path is not the recommended shape at this selectivity.

Counts are a different path from pages. On the grant-driven path: 0.57 ms for
zero access, 0.71 ms for ten documents, 6.03 ms for 1,000, 87.85 ms for
10,000, and 865.64 ms for 100,000. The document-driven count is O(table) by
construction and is not a request path.

The `ListObjects` baseline is not competitive for large sets:

- 10,000 URNs: 200.51 ms to materialize, 73.58 ms to page, 108.71 ms to count.
- 100,000 URNs: 1,515.41 ms to materialize, 8.73 ms to page, 1,798.38 ms to
  count.
- 10,000,000 URNs: not attempted; it is the wrong shape.

### The crossover

- **Broad access** (roughly 1% or more of the table): the document-driven
  denormalized path wins. It walks the page index and tests a small `IN`
  over the row's three ancestor URNs.
- **Narrow access** (roughly below 0.1%, or direct document grants): the
  grant-driven path wins. It resolves the grants first and never walks the
  page index looking for authorized rows.
- The measured crossover is between 0.1% and 1%. At 1%, `denorm` is 27.74 ms
  against `grant` at 951.18 ms; at 0.1%, `grant` is 95.36 ms against
  `denorm` at 272.42 ms.

The consumer must know which shape to use. The grant-driven count is the
cheapest honest signal; the service can also cache the accessible-set size
from `ListObjects`. The plan should not leave this to the planner: the same
SQL can choose the wrong side of the crossover.

### Correctness

The following passed in `05-correctness.sql`:

- **Relation ladder:** editor confers viewer and editor; viewer does not
  confer editor; owner confers all three. `u0005` editor sees 1,000 docs at
  both ranks; `u0041` viewer sees 1,000 at viewer and 0 at editor.
- **Groups:** `u0003` sees 10,000 through group `g0001`; the same group grant
  is visible to the group path only.
- **Deactivation, direct grant:** `u0002` has ten direct grants and is
  deactivated; every path returns 0.
- **Deactivation, group grant:** `u0007` and `u0031` remain group members and
  are deactivated; every path returns 0.
- **Tombstone:** deleting `live` on a document removes it from both paths;
  restoring it restores access.
- **No duplicates:** a broad page has 50 distinct URNs even when several
  grants confer the same document.
- **RLS:** the `casjoin_app` role with `app.tenant = 'acme'` sees zero
  `laenen` documents and zero `laenen` grants.
- **Agents:** an agent is a subject but not a group member; the agent grant
  resolves without a group expansion.

## 5. Results: OpenFGA change-feed projection

OpenFGA v1.22.0, memory datastore, 11,052 tuples, page size 100.

| Measurement | Result |
|---|---|
| Tuple write | 11,052 tuples in 1.11 s, 100 per request |
| `ReadChanges` projection | 111 pages, 4.91 s, 2,251 changes/s |
| Projected nodes | 10,101 expected, 10,101 actual |
| Projected grants | 742 expected, 742 actual |
| Projected memberships | 210 expected, 210 actual |
| Node/grant diffs | 0 |
| Two deletes | applied in 0.04 s; 742→741 grants, 210→209 members |

The tuple-derived state reproduces exactly. Deletes work. As a catch-up or
verification mechanism, the feed is good.

### What the feed cannot carry

1. **Deactivation and suspension.** The design keeps tuples and changes only
   the live projection. `ReadChanges` therefore has no change at all. The
   spike left 14 direct grants visible for `u0009` after the fixture marked
   the user deactivated; after the simulated `PrincipalDeactivated` event
   updated `iam_live_subjects_proj`, the count went to zero. A projection
   built only from the feed serves the direct-grant leak forever.
2. **Tombstones.** Deleting a node's parent tuple is not `NodeDeleted`. The
   projected row stayed `live = true` with `parent_urn` null; only a
   simulated `NodeDeleted` event set `live = false`. A node with no tuples at
   all produces no change at all.
3. **Model version.** The change response carries no authorization-model id.
   Relation ranks had to be supplied from the model, not the feed. A model
   change cannot be detected from tuple changes.
4. **Provenance.** A change has the tuple key and timestamp, not `grant_id`
   or `granted_by`. The projected grant has neither. The log carries both by
   construction.
5. **Bootstrap.** The root node has no parent tuple. It was seeded from the
   tenant bootstrap path, not from `ReadChanges`.

So the log remains the projection source. `ReadChanges` is useful for
catching a lagging read model up after a known cursor, or for comparing the
engine and the read model, but it cannot replace the log-driven projector.

## 6. Recommendations

### For IAM

- Keep the log-driven projector. Do not make `ReadChanges` the read-model
  source. Record the feed's limits in the projector's documentation so the
  next reader does not rediscover them.
- Maintain the read models in design §9.4a: `iam_nodes`,
  `iam_node_closure`, `iam_grants`, `iam_group_members`, `iam_groups`,
  `iam_agents`, `iam_agent_supervisors`, `iam_agent_delegations`,
  `iam_live_subjects`, `iam_projection_state`, `iam_model_cursor`.
- Keep the live-subject and live-node filters mandatory in every query path.
  The direct-grant leak is a filter omission away.
- Keep RLS on every `iam_*` table and on the consumer table. The tenant
  predicate is defense in depth, not the isolation mechanism.

### For CAS

- Add `fileset_urn` and `root_urn` (or a generic ancestor array) to
  `cas_documents`. The denormalized path is ~1.5× faster than the generic
  closure at all broad selectivities, and it removes one join from the hot
  page.
- Use the document-driven denormalized query for broad access. Use the
  grant-driven query for narrow access. Choose by the accessible-set size;
  the measured crossover is between 0.1% and 1%.
- Do not use `ListObjects` to filter a large table. It is a UI/small-set API.
- For F4, make the sensitive field its own addressable resource, placed
  outside the document's subtree so it does not inherit, so the columnar
  case becomes a row case. A row join authorizes rows; it cannot hide a
  column.

### For the design

- §9.4a now records the CAS join shapes and the crossover.
- §9.2 now records why the log remains the projection source.
- §14 question 8 was closed after this spike by reification: the field is
  its own node **outside the document subtree**, or the
  permitted-attribute set is the fallback (design §9.4a, §14.8).
- The §14 questions were all resolved on 2026-10-27 (design §14); this
  report's open list is historical, not current.

## 7. What this does not settle

- **F4 field placement.** The design chooses a field node outside the
  document subtree; this spike did not measure that placement. The row
  join's authorization is measured; field lifecycle is not.
- **Production scale.** The OpenFGA projection used the memory datastore and
  local HTTP; the SQL benchmark used one Postgres and one warm cache. A
  clustered OpenFGA and a cold cache will have different absolute numbers.
- **The other owner questions** were resolved in design §14 on 2026-10-27;
  they are no longer open technical questions.
- **The threshold.** The 0.1%–1% crossover is measured on this fixture. The
  plan must choose a selection rule and test it on CAS's real distribution.

## 8. Reproduction

SQL phase:

```bash
bash docs/superpowers/spikes/2026-10-27-cas-sql-join/run.sh
```

OpenFGA phase:

```bash
docker pull openfga/openfga:v1.22.0
docker run -d --name openfga-spike -p 18080:8080 openfga/openfga:v1.22.0 run

STORE=$(go run github.com/openfga/cli/cmd/fga@latest store create \
  --name iam-proj --model docs/superpowers/spikes/2026-10-27-cas-sql-join/model.fga \
  --api-url http://127.0.0.1:18080 | jq -r .store.id)

psql "$DSN" -f docs/superpowers/spikes/2026-10-27-cas-sql-join/07-projection-schema.sql
psql "$DSN" -f docs/superpowers/spikes/2026-10-27-cas-sql-join/08-projection-fixture.sql

python3 docs/superpowers/spikes/2026-10-27-cas-sql-join/09-project.py \
  --dsn "$DSN" --api http://127.0.0.1:18080 --store "$STORE"
```

The transcripts are `fixture.txt`, `correctness.txt`, `bench.txt` and
`projection.txt` in the spike directory.
