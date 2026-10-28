-- CAS SQL-join spike: benchmark harness.
--
-- Runs the query text from 04-queries.sql, records every measured execution,
-- and reports p50/p95/p99. The first five executions of each case are warmup.
--
-- The matrix is deliberately split by selectivity:
--   broad   document-driven closure/denorm (walks the page index)
--   narrow  grant-driven (resolves grants first, then expands to documents)
--   point   the single-object closure check
--   list    ListObjects materialization + join
--
-- The document-driven path is not run for direct-document grants: it scans
-- the whole table looking for rows that are near the end of the page order.

\set ON_ERROR_STOP on
set search_path = casjoin, public;
set plan_cache_mode = force_custom_plan;

drop table if exists bench_results;
create table bench_results (
    path    text not null,
    subject text not null,
    rank    int not null,
    tenant  text not null,
    kind    text not null,
    run     int not null,
    ms      double precision not null,
    rows    bigint not null
);

create or replace function bench_page(
    p_path text, p_subject text, p_rank int, p_tenant text, p_runs int
) returns void
language plpgsql as $fn$
declare
    t0 timestamptz;
    i int;
    n bigint;
    q text;
    rec record;
begin
    q := sql_page(p_path);
    if q is null then
        raise exception 'unknown path %', p_path;
    end if;

    for i in 0 .. (p_runs + 4) loop
        t0 := clock_timestamp();
        n := 0;
        for rec in execute q using p_subject, p_rank, p_tenant loop
            n := n + 1;
        end loop;
        if i >= 5 then
            insert into bench_results
            values (p_path, p_subject, p_rank, p_tenant, 'page', i - 4,
                    extract(epoch from clock_timestamp() - t0) * 1000, n);
        end if;
    end loop;
end
$fn$;

create or replace function bench_count(
    p_path text, p_subject text, p_rank int, p_tenant text, p_runs int
) returns void
language plpgsql as $fn$
declare
    t0 timestamptz;
    i int;
    n bigint;
    q text;
    rec record;
begin
    q := sql_count(p_path);
    if q is null then
        raise exception 'unknown path %', p_path;
    end if;

    for i in 0 .. (p_runs + 4) loop
        t0 := clock_timestamp();
        n := 0;
        for rec in execute q using p_subject, p_rank, p_tenant loop
            n := rec.count;
        end loop;
        if i >= 5 then
            insert into bench_results
            values (p_path, p_subject, p_rank, p_tenant, 'count', i - 4,
                    extract(epoch from clock_timestamp() - t0) * 1000, n);
        end if;
    end loop;
end
$fn$;

create or replace function bench_point(
    p_label text, p_subject text, p_rank int, p_tenant text, p_object text, p_runs int
) returns void
language plpgsql as $fn$
declare
    t0 timestamptz;
    i int;
    n bigint;
    rec record;
begin
    for i in 0 .. (p_runs + 4) loop
        t0 := clock_timestamp();
        n := 0;
        for rec in execute sql_point() using p_subject, p_rank, p_tenant, p_object loop
            n := n + 1;
        end loop;
        if i >= 5 then
            insert into bench_results
            values (p_label, p_subject, p_rank, p_tenant, 'point', i - 4,
                    extract(epoch from clock_timestamp() - t0) * 1000, n);
        end if;
    end loop;
end
$fn$;

create or replace function bench_populate(
    p_subject text, p_rank int, p_tenant text, p_runs int
) returns void
language plpgsql as $fn$
declare
    t0 timestamptz;
    i int;
    n bigint;
begin
    for i in 0 .. (p_runs + 4) loop
        t0 := clock_timestamp();
        n := populate_accessible(p_subject, p_rank, p_tenant);
        if i >= 5 then
            insert into bench_results
            values ('listobjects', p_subject, p_rank, p_tenant, 'populate',
                    i - 4, extract(epoch from clock_timestamp() - t0) * 1000, n);
        end if;
    end loop;
end
$fn$;

create or replace function explain_path(
    p_path text, p_subject text, p_rank int, p_tenant text
) returns void
language plpgsql as $fn$
declare
    r record;
begin
    raise notice '--- EXPLAIN % / % / rank % / %', p_path, p_subject, p_rank, p_tenant;
    for r in execute 'explain (analyze, buffers, format text) ' || sql_page(p_path)
        using p_subject, p_rank, p_tenant
    loop
        raise notice '%', r."QUERY PLAN";
    end loop;
end
$fn$;

create or replace function explain_point(
    p_subject text, p_rank int, p_tenant text, p_object text
) returns void
language plpgsql as $fn$
declare
    r record;
begin
    raise notice '--- EXPLAIN point / % / rank % / % / %',
        p_subject, p_rank, p_tenant, p_object;
    for r in execute 'explain (analyze, buffers, format text) ' || sql_point()
        using p_subject, p_rank, p_tenant, p_object
    loop
        raise notice '%', r."QUERY PLAN";
    end loop;
end
$fn$;

-- ---------------------------------------------------------------------------
-- Broad access: document-driven page
-- ---------------------------------------------------------------------------

select 'bench: broad pages' as stage;
select bench_page('closure', 'laenen/user/u0001', 1, 'laenen', 10);
select bench_page('denorm',  'laenen/user/u0001', 1, 'laenen', 10);
select bench_page('closure', 'laenen/user/u0020', 1, 'laenen', 30);
select bench_page('denorm',  'laenen/user/u0020', 1, 'laenen', 30);
select bench_page('closure', 'laenen/user/u0021', 1, 'laenen', 30);
select bench_page('denorm',  'laenen/user/u0021', 1, 'laenen', 30);
select bench_page('closure', 'laenen/user/u0003', 1, 'laenen', 30);
select bench_page('denorm',  'laenen/user/u0003', 1, 'laenen', 30);

-- ---------------------------------------------------------------------------
-- Narrow access: grant-driven page
-- ---------------------------------------------------------------------------

select 'bench: narrow pages' as stage;
select bench_page('grant', 'laenen/user/u0020', 1, 'laenen', 10);
select bench_page('grant', 'laenen/user/u0021', 1, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0022', 1, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0003', 1, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0004', 1, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0005', 1, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0005', 3, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0041', 1, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0041', 3, 'laenen', 30);
select bench_page('grant', 'laenen/user/u0002', 1, 'laenen', 30);

-- ---------------------------------------------------------------------------
-- Counts (grant-driven; the document-driven count is O(table) by design)
-- ---------------------------------------------------------------------------

select 'bench: counts' as stage;
select bench_count('grant', 'laenen/user/u0020', 1, 'laenen', 10);
select bench_count('grant', 'laenen/user/u0021', 1, 'laenen', 30);
select bench_count('grant', 'laenen/user/u0022', 1, 'laenen', 30);
select bench_count('grant', 'laenen/user/u0003', 1, 'laenen', 30);
select bench_count('grant', 'laenen/user/u0004', 1, 'laenen', 30);
select bench_count('grant', 'laenen/user/u0002', 1, 'laenen', 30);

-- ---------------------------------------------------------------------------
-- Point checks
-- ---------------------------------------------------------------------------

select 'bench: point' as stage;
select bench_point('point-hit', 'laenen/user/u0001', 1, 'laenen', 'laenen/document/d00000001', 30);
select bench_point('point-hit', 'laenen/user/u0005', 1, 'laenen', 'laenen/document/d00005800', 30);
select bench_point('point-hit', 'laenen/user/u0005', 3, 'laenen', 'laenen/document/d00005800', 30);
select bench_point('point-miss', 'laenen/user/u0005', 1, 'laenen', 'laenen/document/d00001100', 30);

-- ---------------------------------------------------------------------------
-- ListObjects: materialize the effective set, then join
-- ---------------------------------------------------------------------------

select 'bench: listobjects' as stage;
select bench_populate('laenen/user/u0021', 1, 'laenen', 30);
select bench_page('listobjects', 'laenen/user/u0021', 1, 'laenen', 30);
select bench_count('listobjects', 'laenen/user/u0021', 1, 'laenen', 30);

select bench_populate('laenen/user/u0020', 1, 'laenen', 10);
select bench_page('listobjects', 'laenen/user/u0020', 1, 'laenen', 30);
select bench_count('listobjects', 'laenen/user/u0020', 1, 'laenen', 10);

-- ---------------------------------------------------------------------------
-- Results
-- ---------------------------------------------------------------------------

\echo '--- results'
select path,
       subject,
       rank,
       kind,
       count(*) as runs,
       round(avg(ms)::numeric, 3) as avg_ms,
       round(percentile_cont(0.50) within group (order by ms)::numeric, 3) as p50,
       round(percentile_cont(0.95) within group (order by ms)::numeric, 3) as p95,
       round(percentile_cont(0.99) within group (order by ms)::numeric, 3) as p99,
       round(min(ms)::numeric, 3) as min_ms,
       round(max(ms)::numeric, 3) as max_ms,
       max(rows) as rows
from bench_results
group by path, subject, rank, kind
order by kind, path, subject, rank;

\echo '--- relation sizes'
select relname,
       pg_size_pretty(pg_total_relation_size(c.oid)) as total,
       pg_size_pretty(pg_relation_size(c.oid)) as heap,
       pg_size_pretty(pg_indexes_size(c.oid)) as indexes
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'casjoin'
  and c.relkind = 'r'
order by pg_total_relation_size(c.oid) desc;

\echo '--- plans: key cases'
select explain_path('closure', 'laenen/user/u0020', 1, 'laenen');
select explain_path('denorm',  'laenen/user/u0020', 1, 'laenen');
select explain_path('grant',   'laenen/user/u0021', 1, 'laenen');
select explain_path('grant',   'laenen/user/u0004', 1, 'laenen');
select explain_path('listobjects', 'laenen/user/u0021', 1, 'laenen');
select explain_point('laenen/user/u0005', 1, 'laenen', 'laenen/document/d00005800');
