-- F1 spike, part 3: iam A2's *other* performance claim.
--
--   "The projection join added as a predicate to a consumer's existing query
--    over 10,000,000 rows: adds < 20 ms at p95, and the plan must show an
--    index join, never a sequential scan or a materialization of the rule
--    set."
--
-- That claim is about a NON-vector query -- a keyset-paginated listing. It is
-- a different question from filtered ANN and it has a different answer, so it
-- is measured separately here. Only the plan shape and the timing matter; the
-- harness in 04-measure.py handles the vector path.
--
-- Run after 03b-hnsw.sql.

set search_path = f1, public;
\timing on

-- Unfiltered keyset page: the consumer's existing query.
explain (analyze, buffers)
select f.id from facts_flat f
where f.id > 1000000
order by f.id
limit 50;

-- Same page with §9.2's predicate bolted on, for the 50%-selectivity
-- principal. This is the shape A2 describes.
explain (analyze, buffers)
select f.id from facts_flat f
where f.id > 1000000
  and exists (
        select 1
        from container_ancestry ca
        join grant_tuple g on g.container_id = ca.ancestor_id and g.relation = 1
        join membership_closure mc on mc.userset_id = g.userset_id
        where ca.container_id = f.container_id
          and mc.principal_id = 2001
      )
  and not exists (
        select 1 from fact_classification fc
        where fc.fact_id = f.id
          and not exists (
                select 1 from principal_clearance pc
                where pc.principal_id = 2001 and pc.classification_id = fc.classification_id
              )
      )
order by f.id
limit 50;

-- And for the 0.1% principal, where a keyset page must skip ~1,000 rows per
-- row it returns.
explain (analyze, buffers)
select f.id from facts_flat f
where f.id > 1000000
  and exists (
        select 1
        from container_ancestry ca
        join grant_tuple g on g.container_id = ca.ancestor_id and g.relation = 1
        join membership_closure mc on mc.userset_id = g.userset_id
        where ca.container_id = f.container_id
          and mc.principal_id = 2004
      )
  and not exists (
        select 1 from fact_classification fc
        where fc.fact_id = f.id
          and not exists (
                select 1 from principal_clearance pc
                where pc.principal_id = 2004 and pc.classification_id = fc.classification_id
              )
      )
order by f.id
limit 50;

-- The same 0.1% page with the (b) key available, so the restriction is an
-- index range rather than a scan-and-discard.
explain (analyze, buffers)
select f.id from facts_part f
where f.id > 1000000
  and f.zone = any (array[614])
  and not exists (
        select 1 from fact_classification fc
        where fc.fact_id = f.id
          and not exists (
                select 1 from principal_clearance pc
                where pc.principal_id = 2004 and pc.classification_id = fc.classification_id
              )
      )
order by f.id
limit 50;

\timing off
