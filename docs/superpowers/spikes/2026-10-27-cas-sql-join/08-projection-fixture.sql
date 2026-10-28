-- OpenFGA change-feed projection spike: fixture.
--
-- 100 filesets, 10,000 documents, 200 users, 20 groups, ~950 grants, ~210
-- memberships. Small enough for OpenFGA's memory datastore and large enough
-- that the projection has to batch ReadChanges.

\set ON_ERROR_STOP on
set search_path = proj, public;
\timing on

insert into src_nodes (urn, kind, parent_urn) values
    ('proj/root/main', 'root', null);

insert into src_nodes (urn, kind, parent_urn)
select 'proj/fileset/f' || lpad(i::text, 4, '0'), 'fileset',
       'proj/root/main'
from generate_series(1, 100) i;

insert into src_nodes (urn, kind, parent_urn)
select 'proj/document/d' || lpad(i::text, 8, '0'), 'document',
       'proj/fileset/f' || lpad(((i - 1) / 100 + 1)::text, 4, '0')
from generate_series(1, 10000) i;

insert into src_docs (id, urn, fileset_urn, title)
select i,
       'proj/document/d' || lpad(i::text, 8, '0'),
       'proj/fileset/f' || lpad(((i - 1) / 100 + 1)::text, 4, '0'),
       'document ' || i
from generate_series(1, 10000) i;

insert into src_live_subjects (subject_urn, live)
select 'proj/user/u' || lpad(i::text, 4, '0'), true
from generate_series(1, 200) i
union all
select 'proj/group/g' || lpad(i::text, 2, '0'), true
from generate_series(1, 20) i;

update src_live_subjects set live = false
where subject_urn in ('proj/user/u0008', 'proj/user/u0009');

create sequence src_grant_seq;

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
values
    (nextval('src_grant_seq'), 'proj/root/main', 'proj/user/u0001',
     'user', 'viewer', 1, 'proj/user/u0001', '2026-01-01', true),
    (nextval('src_grant_seq'), 'proj/root/main', 'proj/user/u0002',
     'user', 'editor', 3, 'proj/user/u0001', '2026-01-01', true);

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
select nextval('src_grant_seq'),
       'proj/fileset/f' || lpad(i::text, 4, '0'),
       'proj/user/u0003', 'user', 'viewer', 1,
       'proj/user/u0001', '2026-01-01', true
from generate_series(1, 10) i;

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
values
    (nextval('src_grant_seq'), 'proj/fileset/f0011', 'proj/user/u0004',
     'user', 'editor', 3, 'proj/user/u0001', '2026-01-01', true),
    (nextval('src_grant_seq'), 'proj/fileset/f0012', 'proj/user/u0005',
     'user', 'commenter', 2, 'proj/user/u0001', '2026-01-01', true),
    (nextval('src_grant_seq'), 'proj/fileset/f0013', 'proj/user/u0006',
     'user', 'owner', 4, 'proj/user/u0001', '2026-01-01', true);

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
select nextval('src_grant_seq'),
       'proj/fileset/f' || lpad(i::text, 4, '0'),
       'proj/group/g01', 'group', 'viewer', 1,
       'proj/user/u0001', '2026-01-01', true
from generate_series(14, 20) i;

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
select nextval('src_grant_seq'),
       'proj/document/d' || lpad(i::text, 8, '0'),
       'proj/user/u0009', 'user', 'viewer', 1,
       'proj/user/u0001', '2026-01-01', true
from generate_series(1, 10) i;

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
select nextval('src_grant_seq'),
       'proj/document/d' || lpad(i::text, 8, '0'),
       'proj/user/u0010', 'user', 'viewer', 1,
       'proj/user/u0001', '2026-01-01', true
from generate_series(11, 20) i;

insert into src_grants
    (grant_id, object_urn, subject_urn, subject_kind, relation,
     relation_rank, granted_by, granted_at, live)
select nextval('src_grant_seq'),
       case when i % 2 = 0
            then 'proj/document/d' || lpad((((i * 37) % 10000) + 1)::text, 8, '0')
            else 'proj/fileset/f' || lpad((((i * 13) % 100) + 1)::text, 4, '0')
       end,
       case when i % 3 = 0
            then 'proj/group/g' || lpad(((i % 20) + 1)::text, 2, '0')
            else 'proj/user/u' || lpad(((i % 200) + 1)::text, 4, '0')
       end,
       case when i % 3 = 0 then 'group' else 'user' end,
       (array['viewer', 'commenter', 'editor'])[1 + (i % 3)],
       (array[1, 2, 3])[1 + (i % 3)],
       'proj/user/u0001', '2026-01-01', true
from generate_series(1, 900) i;

insert into src_group_members (group_urn, member_urn)
values
    ('proj/group/g01', 'proj/user/u0007'),
    ('proj/group/g01', 'proj/user/u0008');

insert into src_group_members (group_urn, member_urn)
select 'proj/group/g01', 'proj/user/u' || lpad(i::text, 4, '0')
from generate_series(20, 37) i;

insert into src_group_members (group_urn, member_urn)
select 'proj/group/g' || lpad(g::text, 2, '0'),
       'proj/user/u' || lpad((50 + ((g * 7 + m) % 150))::text, 4, '0')
from generate_series(2, 20) g, generate_series(1, 10) m;

analyze;
