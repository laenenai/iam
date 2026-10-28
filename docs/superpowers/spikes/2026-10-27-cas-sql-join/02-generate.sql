-- CAS SQL-join spike: fixture.
--
-- Deterministic. Probe users are in u0001..u0099 so the random grants below
-- cannot accidentally change their selectivity. The random population is
-- u1000..u1999 and g0100..g0200.
--
-- Run with psql -v ON_ERROR_STOP=1. Expect a few minutes for the 10M row
-- tenant and the 30M row closure.

\set ON_ERROR_STOP on
set search_path = casjoin, public;
\timing on

insert into tenants (tenant_id) values ('laenen'), ('acme');

-- ---------------------------------------------------------------------------
-- Subjects
-- ---------------------------------------------------------------------------

insert into iam_subjects (tenant_id, subject_urn, kind)
select 'laenen', 'laenen/user/u' || lpad(i::text, 4, '0'), 'user'
from generate_series(1, 2000) i
union all
select 'laenen', 'laenen/group/g' || lpad(i::text, 4, '0'), 'group'
from generate_series(1, 200) i
union all
select 'laenen', 'laenen/agent/a' || lpad(i::text, 4, '0'), 'agent'
from generate_series(1, 10) i;

insert into iam_subjects (tenant_id, subject_urn, kind)
select 'acme', 'acme/user/u' || lpad(i::text, 4, '0'), 'user'
from generate_series(1, 100) i
union all
select 'acme', 'acme/group/g' || lpad(i::text, 4, '0'), 'group'
from generate_series(1, 10) i;

-- ---------------------------------------------------------------------------
-- Nodes
-- ---------------------------------------------------------------------------

insert into iam_nodes (tenant_id, urn, kind, parent_urn) values
    ('laenen', 'laenen/root/main', 'root', null),
    ('acme',   'acme/root/main',   'root', null);

insert into iam_nodes (tenant_id, urn, kind, parent_urn)
select 'laenen', 'laenen/fileset/f' || lpad(i::text, 5, '0'), 'fileset',
       'laenen/root/main'
from generate_series(1, 10000) i;

insert into iam_nodes (tenant_id, urn, kind, parent_urn)
select 'acme', 'acme/fileset/f' || lpad(i::text, 5, '0'), 'fileset',
       'acme/root/main'
from generate_series(1, 1000) i;

insert into iam_nodes (tenant_id, urn, kind, parent_urn)
select 'laenen',
       'laenen/document/d' || lpad(i::text, 8, '0'),
       'document',
       'laenen/fileset/f' || lpad((((i::bigint * 7919) % 10000) + 1)::text, 5, '0')
from generate_series(1, 10000000) i;

insert into iam_nodes (tenant_id, urn, kind, parent_urn)
select 'acme',
       'acme/document/d' || lpad(i::text, 8, '0'),
       'document',
       'acme/fileset/f' || lpad((((i::bigint * 37) % 1000) + 1)::text, 5, '0')
from generate_series(1, 100000) i;

-- ---------------------------------------------------------------------------
-- Consumer table. The URNs mirror iam_nodes; the fileset and root columns
-- are the CAS-specific denormalization under test.
-- ---------------------------------------------------------------------------

insert into cas_documents
    (tenant_id, id, urn, fileset_urn, root_urn, title, body, created_at)
select 'laenen', i,
       'laenen/document/d' || lpad(i::text, 8, '0'),
       'laenen/fileset/f' || lpad((((i::bigint * 7919) % 10000) + 1)::text, 5, '0'),
       'laenen/root/main',
       'document ' || i,
       'body ' || i,
       timestamptz '2026-01-01 00:00:00+00' + (i * interval '1 second')
from generate_series(1, 10000000) i;

insert into cas_documents
    (tenant_id, id, urn, fileset_urn, root_urn, title, body, created_at)
select 'acme', i,
       'acme/document/d' || lpad(i::text, 8, '0'),
       'acme/fileset/f' || lpad((((i::bigint * 37) % 1000) + 1)::text, 5, '0'),
       'acme/root/main',
       'document ' || i,
       'body ' || i,
       timestamptz '2026-01-01 00:00:00+00' + (i * interval '1 second')
from generate_series(1, 100000) i;

-- ---------------------------------------------------------------------------
-- Tree closure. With root > fileset > document there are three rows per
-- document (self, fileset, root), two per fileset (self, root), one per root.
-- ---------------------------------------------------------------------------

insert into iam_node_closure (tenant_id, descendant_urn, ancestor_urn, depth)
select tenant_id, urn, urn, 0 from iam_nodes
union all
select tenant_id, urn, parent_urn, 1
from iam_nodes
where parent_urn is not null
union all
select tenant_id, urn,
       case when tenant_id = 'laenen' then 'laenen/root/main'
            else 'acme/root/main' end,
       2
from iam_nodes
where kind = 'document';

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------

create sequence grant_seq;

-- Root grants: u0001 viewer (all docs, but not editor), u0009 editor
-- (all docs for viewer and editor).
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
values
    ('laenen', nextval('grant_seq'), 'laenen/root/main', 'laenen/user/u0001',
     'viewer', 1, 'laenen/user/u0001', '2026-01-01', true),
    ('laenen', nextval('grant_seq'), 'laenen/root/main', 'laenen/user/u0009',
     'editor', 3, 'laenen/user/u0001', '2026-01-01', true),
    ('acme',   nextval('grant_seq'), 'acme/root/main',   'acme/user/u0001',
     'viewer', 1, 'acme/user/u0001',   '2026-01-01', true);

-- u0020: 100 filesets = 100,000 documents (1%).
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/fileset/f' || lpad(i::text, 5, '0'),
       'laenen/user/u0020', 'viewer', 1,
       'laenen/user/u0001', '2026-01-01', true
from generate_series(1, 100) i;

-- u0021: 10 filesets = 10,000 documents (0.1%).
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/fileset/f' || lpad(i::text, 5, '0'),
       'laenen/user/u0021', 'viewer', 1,
       'laenen/user/u0001', '2026-01-01', true
from generate_series(101, 110) i;

-- u0022: one fileset = 1,000 documents (0.01%).
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
values
    ('laenen', nextval('grant_seq'), 'laenen/fileset/f00111',
     'laenen/user/u0022', 'viewer', 1, 'laenen/user/u0001', '2026-01-01', true);

-- Relation-ladder probes, one fileset each.
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
values
    ('laenen', nextval('grant_seq'), 'laenen/fileset/f00201',
     'laenen/user/u0005', 'editor',    3, 'laenen/user/u0001', '2026-01-01', true),
    ('laenen', nextval('grant_seq'), 'laenen/fileset/f00202',
     'laenen/user/u0041', 'viewer',    1, 'laenen/user/u0001', '2026-01-01', true),
    ('laenen', nextval('grant_seq'), 'laenen/fileset/f00203',
     'laenen/user/u0042', 'owner',     4, 'laenen/user/u0001', '2026-01-01', true),
    ('laenen', nextval('grant_seq'), 'laenen/fileset/f00204',
     'laenen/user/u0008', 'commenter', 2, 'laenen/user/u0001', '2026-01-01', true);

-- Group g0001: 10 filesets = 10,000 documents. u0003 is live; u0007 and
-- u0031 are deactivated but remain members, so they exercise the liveness
-- filter on the group path.
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/fileset/f' || lpad(i::text, 5, '0'),
       'laenen/group/g0001', 'viewer', 1,
       'laenen/user/u0001', '2026-01-01', true
from generate_series(301, 310) i;

-- Direct document grants.
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/document/d' || lpad(i::text, 8, '0'),
       'laenen/user/u0004', 'viewer', 1,
       'laenen/user/u0001', '2026-01-01', true
from generate_series(1, 10) i;

insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/document/d' || lpad(i::text, 8, '0'),
       'laenen/user/u0002', 'viewer', 1,
       'laenen/user/u0001', '2026-01-01', true
from generate_series(11, 20) i;

-- Agent grant: an agent is a subject, not a group member.
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
values
    ('laenen', nextval('grant_seq'), 'laenen/fileset/f00401',
     'laenen/agent/a0001', 'viewer', 1, 'laenen/user/u0001', '2026-01-01', true);

-- Random population grants. These cannot touch u0001..u0099.
insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/fileset/f' || lpad((1000 + i)::text, 5, '0'),
       case when i % 3 = 0
            then 'laenen/group/g' || lpad((100 + (i % 100))::text, 4, '0')
            else 'laenen/user/u' || lpad((1000 + (i % 1000))::text, 4, '0')
       end,
       (array['viewer', 'commenter', 'editor'])[1 + (i % 3)],
       (array[1, 2, 3])[1 + (i % 3)],
       'laenen/user/u0001', '2026-01-01', true
from generate_series(1, 1000) i;

insert into iam_grants
    (tenant_id, grant_id, object_urn, subject_urn, relation, relation_rank,
     granted_by, granted_at, live)
select 'laenen', nextval('grant_seq'),
       'laenen/document/d' || lpad((100000 + i)::text, 8, '0'),
       case when i % 4 = 0
            then 'laenen/group/g' || lpad((100 + (i % 100))::text, 4, '0')
            else 'laenen/user/u' || lpad((1000 + (i % 1000))::text, 4, '0')
       end,
       (array['viewer', 'commenter', 'editor'])[1 + (i % 3)],
       (array[1, 2, 3])[1 + (i % 3)],
       'laenen/user/u0001', '2026-01-01', true
from generate_series(1, 5000) i;

-- ---------------------------------------------------------------------------
-- Group membership
-- ---------------------------------------------------------------------------

insert into iam_group_members (tenant_id, group_urn, member_urn)
values
    ('laenen', 'laenen/group/g0001', 'laenen/user/u0003'),
    ('laenen', 'laenen/group/g0001', 'laenen/user/u0007'),
    ('laenen', 'laenen/group/g0001', 'laenen/user/u0031');

insert into iam_group_members (tenant_id, group_urn, member_urn)
select 'laenen', 'laenen/group/g0001',
       'laenen/user/u' || lpad(i::text, 4, '0')
from generate_series(100, 146) i;

insert into iam_group_members (tenant_id, group_urn, member_urn)
select 'laenen', 'laenen/group/g' || lpad(g::text, 4, '0'),
       'laenen/user/u' || lpad((1000 + ((g * 37 + i) % 1000))::text, 4, '0')
from generate_series(2, 200) g, generate_series(1, 50) i;

-- ---------------------------------------------------------------------------
-- Liveness. Tuples and memberships stay in place; these three subjects must
-- still deny.
-- ---------------------------------------------------------------------------

insert into iam_live_subjects (tenant_id, subject_urn, live)
select tenant_id, subject_urn, live from iam_subjects;

update iam_live_subjects
set live = false
where tenant_id = 'laenen'
  and subject_urn in (
      'laenen/user/u0002',
      'laenen/user/u0007',
      'laenen/user/u0031'
  );

analyze;
