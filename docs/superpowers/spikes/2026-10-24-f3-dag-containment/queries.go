package f3spike

// Every measured query is a constant here, parameterized, and never built by
// string concatenation — so the SQL in a transcript is the SQL that ran, and
// the key set reaches the server as a bound int4[] rather than as a literal
// a megabyte wide.
//
// Placeholder convention, uniform across the file:
//
//	$1   principal id, or the resolved container key set as int4[]
//	$2   keyset-pagination cursor, or the second half of a two-set query
//	$3   cursor, where $2 is already taken by a key set

// ---------------------------------------------------------------------------
// Resolution: principal -> containers.
// ---------------------------------------------------------------------------

// qGranted is the containers a principal holds a grant on, directly or
// through a userset. It is the anchor set question 3's grant-anchored
// visible_below is defined against.
const qGranted = `
select coalesce(array_agg(distinct g.container_id), '{}')::int[]
from grant_tuple g
join membership_closure mc on mc.userset_id = g.userset_id
where mc.principal_id = $1`

// qAccessible is qGranted plus every container reachable downward from it:
// the principal's accessible container set, and therefore the key set every
// key candidate in question 2 is resolved from. The recursion is over
// container_edge, so it is a DAG walk and UNION rather than UNION ALL is
// load-bearing.
const qAccessible = `
with recursive granted as (
    select g.container_id
    from grant_tuple g
    join membership_closure mc on mc.userset_id = g.userset_id
    where mc.principal_id = $1
), acc (id) as (
    select container_id from granted
  union
    select e.child_id from acc join container_edge e on e.parent_id = acc.id
)
select coalesce(array_agg(id), '{}')::int[] from acc`

// qAuthorizedCount counts the facts an accessible container set authorizes.
// Read downward over C1's closure because that is the cheap direction for a
// count; the figure it produces is the same set every page query below
// filters to, which is asserted rather than assumed (see TestF3/agreement).
const qAuthorizedCount = `
select count(distinct fa.fact_id) from fact_ancestry fa where fa.ancestor_id = any($1::int[])`

// ---------------------------------------------------------------------------
// The page query, once per containment strategy. A2's shape: keyset
// pagination, fifty rows, authorization in the same statement.
// ---------------------------------------------------------------------------

// qPageNone is the unfiltered baseline F1 clocked at 0.46 ms.
const qPageNone = `select f.id from fact f where f.id > $1 order by f.id limit 50`

// qPageC1 reads the materialized DAG closure: one join, fact-cardinality
// table.
const qPageC1 = `
select f.id from fact f
where f.id > $2
  and exists (
    select 1 from fact_ancestry fa
    join grant_tuple g on g.container_id = fa.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
    where fa.fact_id = f.id)
order by f.id limit 50`

// qPageC2 materializes nothing at fact cardinality beyond the immutable
// fact -> entity references: the episode arm is a column on the row, the
// entity-set arm walks entity -> set -> ancestry. Two EXISTS arms rather
// than one, which is the read cost F3 is being asked to price.
const qPageC2 = `
select f.id from fact f
where f.id > $2
  and (exists (
        select 1 from container_ancestry ca
        join grant_tuple g on g.container_id = ca.ancestor_id
        join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
        where ca.container_id = f.episode_id)
    or exists (
        select 1 from fact_entity fe
        join entity_set_member esm on esm.entity_id = fe.entity_id
        join container_ancestry ca on ca.container_id = esm.set_id
        join grant_tuple g on g.container_id = ca.ancestor_id
        join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
        where fe.fact_id = f.id))
order by f.id limit 50`

// qPageC2u is qPageC2 with the two arms folded into one semi-join over a
// UNION ALL of the fact's direct containers, which is the form the predicate
// would actually be compiled as. Measured beside qPageC2 because the planner
// does not treat them alike.
const qPageC2u = `
select f.id from fact f
where f.id > $2
  and exists (
    select 1 from (
        select f.episode_id as cid
      union all
        select esm.set_id
        from fact_entity fe
        join entity_set_member esm on esm.entity_id = fe.entity_id
        where fe.fact_id = f.id) d
    join container_ancestry ca on ca.container_id = d.cid
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1)
order by f.id limit 50`

// qPageC3 walks the containment DAG upward per candidate row, materializing
// no closure at all. Included because it is the option §9.2 rejected without
// measuring at DAG cardinality.
const qPageC3 = `
select f.id from fact f
where f.id > $2
  and exists (
    with recursive anc (id) as (
            select f.episode_id
          union
            select esm.set_id
            from fact_entity fe
            join entity_set_member esm on esm.entity_id = fe.entity_id
            where fe.fact_id = f.id
          union
            select e.parent_id from anc join container_edge e on e.child_id = anc.id)
    select 1 from anc
    join grant_tuple g on g.container_id = anc.id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1)
order by f.id limit 50`

// qPageC4 stores the fact's direct containers and joins the transitive part
// at read time.
const qPageC4 = `
select f.id from fact f
where f.id > $2
  and exists (
    select 1 from fact_container fc
    join container_ancestry ca on ca.container_id = fc.container_id
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
    where fc.fact_id = f.id)
order by f.id limit 50`

// qPageC5 takes the accessible container set as a bound array -- resolved
// once per principal per epoch rather than per query -- and tests membership.
// $1 is the key set, $2 the cursor.
const qPageC5 = `
select f.id from fact f
where f.id > $2
  and (f.episode_id = any($1::int[])
    or exists (
        select 1 from fact_entity fe
        join entity_set_member esm on esm.entity_id = fe.entity_id
        where fe.fact_id = f.id and esm.set_id = any($1::int[])))
order by f.id limit 50`

// ---------------------------------------------------------------------------
// The point decision, for the §7.1 Decide surface rather than the predicate.
// ---------------------------------------------------------------------------

const qPointC1 = `
select exists (
    select 1 from fact_ancestry fa
    join grant_tuple g on g.container_id = fa.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
    where fa.fact_id = $2)`

const qPointC2 = `
select exists (
    select 1 from (
        select f.episode_id as cid from fact f where f.id = $2
      union all
        select esm.set_id
        from fact_entity fe
        join entity_set_member esm on esm.entity_id = fe.entity_id
        where fe.fact_id = $2) d
    join container_ancestry ca on ca.container_id = d.cid
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1)`

const qPointC4 = `
select exists (
    select 1 from fact_container fc
    join container_ancestry ca on ca.container_id = fc.container_id
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
    where fc.fact_id = $2)`

// ---------------------------------------------------------------------------
// Question 2: the key candidates. $1 is always the resolved key set.
// ---------------------------------------------------------------------------

const (
	qCandK1 = `select count(*) from fact_key where ep_zone = any($1::int[])`
	qCandK2 = `select count(*) from fact_key where zones && $1::int[]`
	qCandK3 = `select count(*) from fact_key where zones3 && $1::int[]`
	qCandK4 = `select count(*) from fact_key where ep_zone = any($1::int[]) or set_zones && $1::int[]`
	qCandK5 = `select count(*) from fact_key where canon_zone = any($1::int[])`
)

// qMissed counts authorized facts a key candidate prunes AWAY. A nonzero
// value is not a recall miss that tuning can recover: the row is gone before
// the fragment ever sees it, and the consumer is told nothing.
const qMissed = `
select count(*) from (
    select distinct fa.fact_id from fact_ancestry fa where fa.ancestor_id = any($1::int[])) a
join fact_key fk on fk.id = a.fact_id
where not (%s)`

// keyTest is the %s substituted into qMissed and into the key-only page
// queries. Held as a separate constant per key so the substitution is from a
// closed set of literals in this file.
const (
	keyTestK1 = `fk.ep_zone = any($1::int[])`
	keyTestK2 = `fk.zones && $1::int[]`
	keyTestK3 = `fk.zones3 && $1::int[]`
	keyTestK4 = `fk.ep_zone = any($1::int[]) or fk.set_zones && $1::int[]`
	keyTestK5 = `fk.canon_zone = any($1::int[])`
)

// qPageKeyOnly is F1 §6's unsafe shape, kept for the same reason: it is the
// one that measures what the key alone exposes. $1 key set, $2 cursor.
const qPageKeyOnly = `
select fk.id from fact_key fk where fk.id > $2 and (%s) order by fk.id limit 50`

// qPageKeySafe is the shape F1's condition (i) mandates: the key pre-filters,
// the fragment authorizes. $1 key set, $2 cursor, $3 principal.
const qPageKeySafe = `
select fk.id from fact_key fk
where fk.id > $2 and (%s)
  and exists (
    select 1 from fact_container fc
    join container_ancestry ca on ca.container_id = fc.container_id
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $3
    where fc.fact_id = fk.id)
order by fk.id limit 50`

// qUnauthorizedInTop counts how many of a key-only page's rows the principal
// may not read -- F1 §6's "9 of 20", asked again of a DAG key.
const qUnauthorizedInTop = `
select count(*) from (
    select fk.id from fact_key fk where fk.id > 0 and (%s) order by fk.id limit 50) p
where not exists (
    select 1 from fact_container fc
    join container_ancestry ca on ca.container_id = fc.container_id
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $2
    where fc.fact_id = p.id)`

// qEpisodeKeySetFromFacts is the only sound way to build K1's key set in a
// DAG: not from the container graph, which contains no episode below an
// entity-set, but by walking the authorized FACTS. Its cost is the point.
const qEpisodeKeySetFromFacts = `
select coalesce(array_agg(distinct f.episode_id), '{}')::int[]
from (select distinct fa.fact_id from fact_ancestry fa where fa.ancestor_id = any($1::int[])) a
join fact f on f.id = a.fact_id`

// ---------------------------------------------------------------------------
// Question 3: what "only on the direct path" can mean.
// ---------------------------------------------------------------------------

// qVisUnion is the permissive reading: every container that is an ancestor of
// some fact the principal may read.
const qVisUnion = `
select coalesce(array_agg(distinct fa2.ancestor_id), '{}')::int[]
from (select distinct fa.fact_id from fact_ancestry fa where fa.ancestor_id = any($1::int[])) a
join fact_ancestry fa2 on fa2.fact_id = a.fact_id`

// qVisUnionLeak counts the containers qVisUnion exposes that are NOT in the
// principal's accessible set -- containers it holds no grant on and none
// below. $1 accessible set, $2 the union set.
const qVisUnionLeak = `
select count(*) from unnest($2::int[]) v (id) where not (v.id = any($1::int[]))`

// qVisUnionLeakByKind breaks that count down, because an entity-set leaking
// is the D8 conflict-screen case and an episode leaking is not.
const qVisUnionLeakByKind = `
select c.kind, count(*)
from unnest($2::int[]) v (id)
join container c on c.id = v.id
where not (v.id = any($1::int[]))
group by c.kind order by c.kind`

// qPathIntersection is the restrictive reading: per fact, the containers that
// lie on EVERY path from the fact upward. Reported as a distribution over the
// number of paths, because the claim under test is that the intersection is
// "cheap and frequently empty". The tenant and the graph are on every path by
// construction, so an intersection size of 2 means the reading names nothing.
const qPathIntersection = `
with sample as (
    select distinct fa.fact_id from fact_ancestry fa where fa.ancestor_id = any($1::int[]) limit 5000
), paths as (
    select s.fact_id, d.container_id as root
    from sample s join fact_container d on d.fact_id = s.fact_id
), npaths as (
    select fact_id, count(*) as np from paths group by fact_id
), seen as (
    select p.fact_id, ca.ancestor_id, count(*) as c
    from paths p join container_ancestry ca on ca.container_id = p.root
    group by p.fact_id, ca.ancestor_id
), inter as (
    select s.fact_id, count(*) as isize
    from seen s join npaths n on n.fact_id = s.fact_id
    where s.c = n.np
    group by s.fact_id
)
select n.np, count(*), avg(i.isize)::numeric(6,2), min(i.isize), max(i.isize)
from npaths n join inter i on i.fact_id = n.fact_id
group by n.np order by n.np`

// qAgreement is the spike's own differential check, and nothing else in it is
// trustworthy without it: for 5,000 facts spread across the table, do the four
// containment strategies return the same authorization answer? A nonzero
// disagreement means one of the strategies is not computing the same
// predicate and every latency beside it is a comparison of different
// questions. $1 principal, $2 accessible key set.
const qAgreement = `
select count(*),
       count(*) filter (where c1 <> c2),
       count(*) filter (where c1 <> c4),
       count(*) filter (where c1 <> c5),
       count(*) filter (where c1)
from (
  select exists (
            select 1 from fact_ancestry fa
            join grant_tuple g on g.container_id = fa.ancestor_id
            join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
            where fa.fact_id = f.id) as c1,
         exists (
            select 1 from (
                select f.episode_id as cid
              union all
                select esm.set_id from fact_entity fe
                join entity_set_member esm on esm.entity_id = fe.entity_id
                where fe.fact_id = f.id) d
            join container_ancestry ca on ca.container_id = d.cid
            join grant_tuple g on g.container_id = ca.ancestor_id
            join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1) as c2,
         exists (
            select 1 from fact_container fc
            join container_ancestry ca on ca.container_id = fc.container_id
            join grant_tuple g on g.container_id = ca.ancestor_id
            join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $1
            where fc.fact_id = f.id) as c4,
         (f.episode_id = any($2::int[])
          or exists (
            select 1 from fact_entity fe
            join entity_set_member esm on esm.entity_id = fe.entity_id
            where fe.fact_id = f.id and esm.set_id = any($2::int[]))) as c5
  from fact f
  where f.id % 2000 = 1
) z`

// ---------------------------------------------------------------------------
// Question 1: maintenance. Each of these counts the rows an authorization or
// data event forces a strategy to write, without writing them, so the fixture
// stays valid across the whole run.
// ---------------------------------------------------------------------------

// qEntityDegree is how many facts reference an entity -- the multiplier on
// every membership change under C1 and C4.
const qEntityDegree = `select count(*) from fact_entity where entity_id = $1`

// qDegreeStats is that multiplier's distribution, which is what makes the hub
// entity a measured case rather than an anecdote.
const qDegreeStats = `
select min(d), (percentile_disc(0.5) within group (order by d))::bigint,
       (percentile_disc(0.99) within group (order by d))::bigint, max(d), avg(d)
from (select entity_id, count(*) as d from fact_entity group by entity_id) z`

// qHubEntity is the highest-degree entity.
const qHubEntity = `select entity_id, count(*) as d from fact_entity group by entity_id order by d desc limit 1`

// qDeltaEsmC1 is the fact_ancestry rows that adding entity $1 to set $2
// forces. C2 writes one row for the same event; C4 writes one per fact.
const qDeltaEsmC1 = `
select count(*) from (
    select distinct fe.fact_id, ca.ancestor_id
    from fact_entity fe
    cross join container_ancestry ca
    where fe.entity_id = $1 and ca.container_id = $2) d
where not exists (
    select 1 from fact_ancestry fa where fa.fact_id = d.fact_id and fa.ancestor_id = d.ancestor_id)`

const qDeltaEsmC4 = `
select count(*) from fact_entity fe
where fe.entity_id = $1
  and not exists (select 1 from fact_container fc where fc.fact_id = fe.fact_id and fc.container_id = $2)`

// qDeltaNestAncestry is the container_ancestry rows that nesting container $1
// under container $2 forces: every descendant of $1 gains every ancestor of
// $2 it did not already have.
const qDeltaNestAncestry = `
select count(*) from (
    select distinct d.container_id, a.ancestor_id
    from container_ancestry d
    cross join container_ancestry a
    where d.ancestor_id = $1 and a.container_id = $2) z
where not exists (
    select 1 from container_ancestry ca
    where ca.container_id = z.container_id and ca.ancestor_id = z.ancestor_id)`

// qDeltaNestC1 is the same event's cost at fact cardinality: every fact under
// $1 gains every new ancestor. C4 and C2 write nothing at all for this event,
// which is the sharpest difference the spike measures.
const qDeltaNestC1 = `
select count(*) from (
    select distinct fa.fact_id, a.ancestor_id
    from fact_ancestry fa
    cross join container_ancestry a
    where fa.ancestor_id = $1 and a.container_id = $2) z
where not exists (
    select 1 from fact_ancestry f2
    where f2.fact_id = z.fact_id and f2.ancestor_id = z.ancestor_id)`

// qFactsUnder counts the facts beneath a container, so the per-fact deltas
// above can be read as a rate.
const qFactsUnder = `select count(distinct fact_id) from fact_ancestry where ancestor_id = $1`

// qFanout is C1's and C4's per-fact row counts -- the storage multiplier the
// DAG imposes, and the number a per-fact-write cost is derived from.
const qFanout = `
select (select count(*) from fact_ancestry)::numeric  / (select count(*) from fact),
       (select count(*) from fact_container)::numeric / (select count(*) from fact),
       (select count(*) from fact_entity)::numeric    / (select count(*) from fact)`

// qFanoutDist is that multiplier's distribution rather than its mean.
const qFanoutDist = `
select min(n), (percentile_disc(0.5) within group (order by n))::bigint,
       (percentile_disc(0.95) within group (order by n))::bigint,
       (percentile_disc(0.999) within group (order by n))::bigint, max(n)
from (select fact_id, count(*) as n from fact_ancestry group by fact_id) z`

// ---------------------------------------------------------------------------
// Sizes, so the storage half of question 1 is measured too.
// ---------------------------------------------------------------------------

const qSizes = `
select c.relname,
       (select reltuples::bigint from pg_class x where x.oid = c.oid),
       pg_table_size(c.oid), pg_indexes_size(c.oid)
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by pg_total_relation_size(c.oid) desc`

const qRowCounts = `
select 'container', count(*) from container
union all select 'container_edge', count(*) from container_edge
union all select 'container_ancestry', count(*) from container_ancestry
union all select 'entity', count(*) from entity
union all select 'entity_set_member', count(*) from entity_set_member
union all select 'fact', count(*) from fact
union all select 'fact_entity', count(*) from fact_entity
union all select 'fact_container', count(*) from fact_container
union all select 'fact_ancestry', count(*) from fact_ancestry
union all select 'principal', count(*) from principal
union all select 'grp', count(*) from grp
union all select 'group_member', count(*) from group_member
union all select 'membership_closure', count(*) from membership_closure
union all select 'grant_tuple', count(*) from grant_tuple`

// ---------------------------------------------------------------------------
// Question 4: the predicate-defined entity-set.
// ---------------------------------------------------------------------------

// qPredRows is how many containment edges the fifty predicate-defined sets of
// 08-predicate-sets.sql would add -- membership nobody wrote and no
// authorization event accounts for.
const qPredRows = `
select count(*) from predicate_set ps join entity e on e.country = ps.country`

// qPredC1Rows is what those edges cost C1: the fact-level closure rows that
// follow from membership nobody wrote.
const qPredC1Rows = `
select count(*) from (
    select distinct fe.fact_id, ca.ancestor_id
    from predicate_set ps
    join entity e on e.country = ps.country
    join fact_entity fe on fe.entity_id = e.id
    join container_ancestry ca on ca.container_id = ps.set_id) z`

// qPredOneEntity is the restrictive direction, priced on one row: a single
// UPDATE of entity.country removes this many fact-level closure rows, on the
// data write path, with no authorization event and nothing to bump an epoch
// from.
const qPredOneEntity = `
select count(*) from (
    select distinct fe.fact_id, ca.ancestor_id
    from fact_entity fe
    cross join container_ancestry ca
    where fe.entity_id = $1 and ca.container_id = $2) z`

// qPredEligibleEntities is how many entities one predicate-defined set
// contains -- the fan-out of a single data-driven membership rule.
const qPredEligibleEntities = `select count(*) from entity where country = $1`

// qLift3KeySet lifts a key set to entity-set level 3, which is what K3
// requires to be measured at its best: a key stored at a coarser granularity
// than the grant must have its key set lifted to the same granularity, or the
// comparison measures a resolution bug instead of the key.
const qLift3KeySet = `
select coalesce(array_agg(distinct l.lifted), '{}')::int[]
from container_lift3 l where l.container_id = any($1::int[])`

// qNewParentFor picks a container that could legitimately become a new parent
// of $1 -- same depth as its existing parent, not already one of its
// ancestors -- so the E4 maintenance event is chosen from the fixture rather
// than hard-coded and silently missing at a reduced scale.
const qNewParentFor = `
select c.id from container c
where c.kind = 3
  and c.depth = (select min(pp.depth) from container_edge e
                 join container pp on pp.id = e.parent_id where e.child_id = $1)
  and not exists (select 1 from container_ancestry ca
                  where ca.container_id = $1 and ca.ancestor_id = c.id)
order by c.id desc limit 1`

// qPageKeySafeC2 is the combination the write-up recommends and which no
// other cell measures: the K2 array key pre-restricts, and the fragment that
// authorizes is C2's -- the one that stores nothing authorization-mutable at
// fact cardinality. qPageKeySafe pairs the key with C4's fragment instead,
// which is the easier join and the more expensive table to maintain, so
// measuring only that would have recommended a shape on the strength of a
// different shape's number. $1 key set, $2 cursor, $3 principal.
const qPageKeySafeC2 = `
select fk.id from fact_key fk
where fk.id > $2 and fk.zones && $1::int[]
  and exists (
    select 1 from (
        select f.episode_id as cid from fact f where f.id = fk.id
      union all
        select esm.set_id
        from fact_entity fe
        join entity_set_member esm on esm.entity_id = fe.entity_id
        where fe.fact_id = fk.id) d
    join container_ancestry ca on ca.container_id = d.cid
    join grant_tuple g on g.container_id = ca.ancestor_id
    join membership_closure mc on mc.userset_id = g.userset_id and mc.principal_id = $3)
order by fk.id limit 50`

// qPageKeyOnlyK2 is the same query with the fragment removed, so the pair
// prices what the fragment costs on top of the key.
const qPageKeyOnlyK2 = `
select fk.id from fact_key fk
where fk.id > $2 and fk.zones && $1::int[]
order by fk.id limit 50`
