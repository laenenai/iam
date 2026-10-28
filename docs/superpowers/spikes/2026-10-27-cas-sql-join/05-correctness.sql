-- CAS SQL-join spike: correctness checks.
--
-- Every check raises on failure. The expected counts are the fixture's
-- contract; if a path returns a different number, the path is wrong, not the
-- test.
--
-- Counts use the grant-driven path for narrow access, because the
-- document-driven count is O(table) by construction and would only measure
-- the scan. Broad-access counts are not asserted in full; their pages are.

\set ON_ERROR_STOP on
set search_path = casjoin, public;

create or replace function expect_count(
    p_path text, p_subject text, p_rank int, p_tenant text, p_expected bigint
) returns void
language plpgsql as $fn$
declare
    n bigint;
begin
    n := query_count(p_path, p_subject, p_rank, p_tenant);
    if n <> p_expected then
        raise exception '%.% rank % on %: expected %, got %',
            p_path, p_subject, p_rank, p_tenant, p_expected, n;
    end if;
end
$fn$;

create or replace function expect_page_paths_equal(
    p_a text, p_b text, p_subject text, p_rank int, p_tenant text
) returns void
language plpgsql as $fn$
declare
    n bigint;
begin
    select count(*) into n
    from (
        (select * from query_page(p_a, p_subject, p_rank, p_tenant))
        except
        (select * from query_page(p_b, p_subject, p_rank, p_tenant))
    ) x;
    if n <> 0 then
        raise exception 'page mismatch % vs % for % rank % on %',
            p_a, p_b, p_subject, p_rank, p_tenant;
    end if;
end
$fn$;

-- ---------------------------------------------------------------------------
-- Broad access: assert the page, not the full count.
-- ---------------------------------------------------------------------------

do $fn$
declare
    n bigint;
begin
    select count(*) into n from query_page('closure', 'laenen/user/u0001', 1, 'laenen');
    if n <> 50 then raise exception 'u0001 closure page: %', n; end if;
    select count(*) into n from query_page('denorm', 'laenen/user/u0001', 1, 'laenen');
    if n <> 50 then raise exception 'u0001 denorm page: %', n; end if;
    select count(*) into n from query_page('closure', 'laenen/user/u0009', 3, 'laenen');
    if n <> 50 then raise exception 'u0009 editor page: %', n; end if;

    perform expect_count('grant', 'laenen/user/u0001', 3, 'laenen', 0);
end
$fn$;

-- ---------------------------------------------------------------------------
-- Selectivity, relation ladder, groups, agents
-- ---------------------------------------------------------------------------

do $fn$
begin
    perform expect_count('grant', 'laenen/user/u0020', 1, 'laenen', 100000);
    perform expect_count('grant', 'laenen/user/u0021', 1, 'laenen', 10000);
    perform expect_count('grant', 'laenen/user/u0022', 1, 'laenen', 1000);

    perform expect_count('grant', 'laenen/user/u0003', 1, 'laenen', 10000);
    perform expect_count('grant', 'laenen/user/u0004', 1, 'laenen', 10);

    perform expect_count('grant', 'laenen/user/u0005', 1, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0005', 3, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0041', 1, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0041', 3, 'laenen', 0);
    perform expect_count('grant', 'laenen/user/u0042', 1, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0042', 3, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0042', 4, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0008', 1, 'laenen', 1000);
    perform expect_count('grant', 'laenen/user/u0008', 3, 'laenen', 0);

    perform expect_count('grant', 'laenen/agent/a0001', 1, 'laenen', 1000);
    perform expect_count('grant', 'acme/user/u0001', 1, 'acme', 100000);
end
$fn$;

-- ---------------------------------------------------------------------------
-- Deprovisioning: direct grant, group grant, and no grant
-- ---------------------------------------------------------------------------

do $fn$
begin
    perform expect_count('grant', 'laenen/user/u0002', 1, 'laenen', 0);
    perform expect_count('grant', 'laenen/user/u0007', 1, 'laenen', 0);
    perform expect_count('grant', 'laenen/user/u0031', 1, 'laenen', 0);
    perform expect_count('grant', 'laenen/user/u0010', 1, 'laenen', 0);
end
$fn$;

-- ---------------------------------------------------------------------------
-- The paths agree on their pages
-- ---------------------------------------------------------------------------

do $fn$
begin
    perform expect_page_paths_equal('closure', 'denorm',
        'laenen/user/u0001', 1, 'laenen');
    perform expect_page_paths_equal('closure', 'denorm',
        'laenen/user/u0020', 1, 'laenen');
    perform expect_page_paths_equal('closure', 'denorm',
        'laenen/user/u0021', 1, 'laenen');
    perform expect_page_paths_equal('closure', 'grant',
        'laenen/user/u0021', 1, 'laenen');
    perform expect_page_paths_equal('closure', 'grant',
        'laenen/user/u0003', 1, 'laenen');
    perform expect_page_paths_equal('closure', 'grant',
        'laenen/user/u0005', 3, 'laenen');
    perform expect_page_paths_equal('closure', 'grant',
        'laenen/user/u0041', 1, 'laenen');
end
$fn$;

-- ---------------------------------------------------------------------------
-- The direct-grant probe has exactly ten documents, and no duplicates.
-- ---------------------------------------------------------------------------

do $fn$
declare
    n bigint;
    lo text;
    hi text;
begin
    select count(*), min(urn), max(urn) into n, lo, hi
    from query_page('grant', 'laenen/user/u0004', 1, 'laenen');
    if n <> 10 then raise exception 'u0004 page: expected 10, got %', n; end if;
    if lo <> 'laenen/document/d00000001' then raise exception 'u0004 min: %', lo; end if;
    if hi <> 'laenen/document/d00000010' then raise exception 'u0004 max: %', hi; end if;

    select count(*), count(distinct urn) into n, lo
    from query_page('closure', 'laenen/user/u0001', 1, 'laenen');
    if n <> 50 or n <> (select count(distinct urn)
                        from query_page('closure', 'laenen/user/u0001', 1, 'laenen')) then
        raise exception 'duplicate documents in broad page';
    end if;
end
$fn$;

-- ---------------------------------------------------------------------------
-- ListObjects baseline: same effective set, then the join
-- ---------------------------------------------------------------------------

do $fn$
declare
    n bigint;
begin
    n := populate_accessible('laenen/user/u0021', 1, 'laenen');
    if n <> 10000 then
        raise exception 'populate u0021: expected 10000, got %', n;
    end if;
    perform expect_count('listobjects', 'laenen/user/u0021', 1, 'laenen', 10000);
    perform expect_page_paths_equal('grant', 'listobjects',
        'laenen/user/u0021', 1, 'laenen');

    n := populate_accessible('laenen/user/u0020', 1, 'laenen');
    if n <> 100000 then
        raise exception 'populate u0020: expected 100000, got %', n;
    end if;
    perform expect_count('listobjects', 'laenen/user/u0020', 1, 'laenen', 100000);
    perform expect_page_paths_equal('grant', 'listobjects',
        'laenen/user/u0020', 1, 'laenen');
end
$fn$;

-- ---------------------------------------------------------------------------
-- Tombstone: a deleted node stops matching even though its direct grant is
-- still in the read model. The projector would delete the tuple and mark the
-- node; the query must filter the node's live flag.
-- ---------------------------------------------------------------------------

do $fn$
begin
    update iam_nodes set live = false
    where tenant_id = 'laenen' and urn = 'laenen/document/d00000001';

    perform expect_count('grant', 'laenen/user/u0004', 1, 'laenen', 9);

    update iam_nodes set live = true
    where tenant_id = 'laenen' and urn = 'laenen/document/d00000001';

    perform expect_count('grant', 'laenen/user/u0004', 1, 'laenen', 10);
end
$fn$;

-- ---------------------------------------------------------------------------
-- RLS: the app role can only see its tenant, even with a predicate naming
-- another tenant. Superusers bypass RLS, so this must run as casjoin_app.
-- ---------------------------------------------------------------------------

do $fn$
declare
    n bigint;
begin
    set local role casjoin_app;
    set local app.tenant = 'acme';

    select count(*) into n from cas_documents where tenant_id = 'laenen';
    if n <> 0 then
        raise exception 'RLS leaked % laenen documents to acme', n;
    end if;

    select count(*) into n from cas_documents;
    if n <> 100000 then
        raise exception 'RLS acme count: expected 100000, got %', n;
    end if;

    select count(*) into n from iam_grants where tenant_id = 'laenen';
    if n <> 0 then
        raise exception 'RLS leaked % laenen grants to acme', n;
    end if;
end
$fn$;

\echo 'correctness: ok'
