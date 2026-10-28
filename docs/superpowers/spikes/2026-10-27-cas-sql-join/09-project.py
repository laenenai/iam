#!/usr/bin/env python3
"""OpenFGA change-feed projection spike.

Writes the fixture's tuples to a real OpenFGA store, then builds the SQL read
models exclusively from `GET /stores/{store}/changes`. No source-table reads
are allowed during the projection step.

The script also exercises the three things the feed cannot carry:

  * deactivation, which keeps tuples and changes only liveness;
  * a node tombstone, which is not the same as deleting the node's tuples;
  * the model version, which is not on a tuple change.

Usage:
    python3 09-project.py --dsn ... --api http://127.0.0.1:18080 --store ...
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

RELATION_RANK = {
    "viewer": 1,
    "commenter": 2,
    "editor": 3,
    "owner": 4,
}

PAGE_SIZE = 100
WRITE_BATCH = 100


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def sql_lit(value):
    if value is None:
        return "null"
    return "'" + str(value).replace("'", "''") + "'"


def psql_rows(dsn, sql):
    p = subprocess.run(
        ["psql", dsn, "-v", "ON_ERROR_STOP=1", "-q", "-tA", "-F", "\t", "-c", sql],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"psql failed:\n{p.stderr}\nSQL:\n{sql}")
    rows = []
    for line in p.stdout.splitlines():
        if line == "":
            continue
        rows.append(line.split("\t"))
    return rows


def psql_exec(dsn, sql):
    p = subprocess.run(
        ["psql", dsn, "-v", "ON_ERROR_STOP=1", "-q", "-f", "-"],
        input=sql,
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        raise RuntimeError(f"psql failed:\n{p.stderr}\nSQL:\n{sql}")


def http_json(url, method="GET", body=None):
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} {url}: {e.read().decode()}") from e


def write_batch(api, store, tuples, deletes=False):
    key = "deletes" if deletes else "writes"
    http_json(
        f"{api}/stores/{store}/write",
        method="POST",
        body={key: {"tuple_keys": tuples}},
    )


def read_changes(api, store, token):
    url = f"{api}/stores/{store}/changes?page_size={PAGE_SIZE}"
    if token:
        url += "&continuation_token=" + urllib.parse.quote(token)
    return http_json(url)


def split_entity(entity):
    if ":" not in entity:
        raise ValueError(f"not an entity: {entity}")
    return entity.split(":", 1)


def apply_page(dsn, changes, token):
    stmts = ["begin;"]
    for change in changes:
        key = change["tuple_key"]
        op = change["operation"]
        delete = op == "TUPLE_OPERATION_DELETE"
        obj_type, obj_id = split_entity(key["object"])
        user_type, user_id = split_entity(key["user"])
        user_rel = None
        if "#" in user_id:
            user_id, user_rel = user_id.split("#", 1)
        rel = key["relation"]
        ts = change.get("timestamp")
        tenant = obj_id.split("/", 1)[0]

        if rel == "parent":
            if delete:
                stmts.append(
                    f"update proj.iam_nodes_proj set parent_urn = null "
                    f"where tenant_id = {sql_lit(tenant)} and urn = {sql_lit(obj_id)};"
                )
            else:
                kind = obj_id.split("/")[1] if "/" in obj_id else obj_type
                stmts.append(
                    "insert into proj.iam_nodes_proj (tenant_id, urn, kind, parent_urn, live) "
                    f"values ({sql_lit(tenant)}, {sql_lit(obj_id)}, {sql_lit(kind)}, "
                    f"{sql_lit(user_id)}, true) "
                    "on conflict (tenant_id, urn) do update set "
                    "parent_urn = excluded.parent_urn, kind = excluded.kind, live = true;"
                )
        elif rel == "member" and obj_type == "group":
            if delete:
                stmts.append(
                    f"delete from proj.iam_group_members_proj "
                    f"where tenant_id = {sql_lit(tenant)} and group_urn = {sql_lit(obj_id)} "
                    f"and member_urn = {sql_lit(user_id)};"
                )
            else:
                stmts.append(
                    "insert into proj.iam_group_members_proj (tenant_id, group_urn, member_urn) "
                    f"values ({sql_lit(tenant)}, {sql_lit(obj_id)}, {sql_lit(user_id)}) "
                    "on conflict do nothing;"
                )
        elif rel == "supervisor" and obj_type == "agent":
            if delete:
                stmts.append(
                    f"update proj.iam_agents_proj set supervisor_urn = null "
                    f"where tenant_id = {sql_lit(tenant)} and agent_urn = {sql_lit(obj_id)};"
                )
            else:
                stmts.append(
                    "insert into proj.iam_agents_proj (tenant_id, agent_urn, supervisor_urn) "
                    f"values ({sql_lit(tenant)}, {sql_lit(obj_id)}, {sql_lit(user_id)}) "
                    "on conflict (tenant_id, agent_urn) do update set "
                    "supervisor_urn = excluded.supervisor_urn;"
                )
        elif rel == "can_act_for" and obj_type == "agent":
            if delete:
                stmts.append(
                    f"update proj.iam_agents_proj set can_act_for = array_remove(can_act_for, {sql_lit(user_id)}) "
                    f"where tenant_id = {sql_lit(tenant)} and agent_urn = {sql_lit(obj_id)};"
                )
            else:
                stmts.append(
                    "insert into proj.iam_agents_proj (tenant_id, agent_urn, can_act_for) "
                    f"values ({sql_lit(tenant)}, {sql_lit(obj_id)}, array[{sql_lit(user_id)}]) "
                    "on conflict (tenant_id, agent_urn) do update set "
                    "can_act_for = array(select distinct unnest(iam_agents_proj.can_act_for || excluded.can_act_for));"
                )
        elif rel in RELATION_RANK and obj_type == "node":
            rank = RELATION_RANK[rel]
            if delete:
                stmts.append(
                    f"delete from proj.iam_grants_proj where tenant_id = {sql_lit(tenant)} "
                    f"and object_urn = {sql_lit(obj_id)} and subject_urn = {sql_lit(user_id)} "
                    f"and relation = {sql_lit(rel)};"
                )
            else:
                stmts.append(
                    "insert into proj.iam_grants_proj "
                    "(tenant_id, object_urn, subject_urn, subject_kind, relation, relation_rank, granted_at) "
                    f"values ({sql_lit(tenant)}, {sql_lit(obj_id)}, {sql_lit(user_id)}, "
                    f"{sql_lit(user_type)}, {sql_lit(rel)}, {rank}, {sql_lit(ts)}::timestamptz) "
                    "on conflict (tenant_id, object_urn, subject_urn, relation) do update set "
                    "subject_kind = excluded.subject_kind, relation_rank = excluded.relation_rank, "
                    "granted_at = excluded.granted_at;"
                )
        else:
            log(f"unhandled change: {key}")
            continue

    last_ts = changes[-1].get("timestamp") if changes else None
    stmts.append(
        "update proj.projection_cursor set "
        f"continuation_token = {sql_lit(token)}, "
        f"changes_applied = changes_applied + {len(changes)}, "
        f"last_change_at = {sql_lit(last_ts)}::timestamptz, "
        "updated_at = now() where id = 1;"
    )
    stmts.append("commit;")
    psql_exec(dsn, "\n".join(stmts))


def project(dsn, api, store, token, max_pages):
    total = 0
    pages = 0
    started = time.time()
    while pages < max_pages:
        resp = read_changes(api, store, token)
        changes = resp.get("changes") or []
        if not changes:
            break
        token = resp.get("continuation_token") or token
        apply_page(dsn, changes, token)
        total += len(changes)
        pages += 1
        log(f"projected page {pages}: {len(changes)} changes, total {total}")
    return token, total, pages, time.time() - started


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dsn", required=True)
    ap.add_argument("--api", default="http://127.0.0.1:18080")
    ap.add_argument("--store", required=True)
    ap.add_argument("--max-pages", type=int, default=500)
    args = ap.parse_args()

    log("reading source tuples")
    nodes = psql_rows(
        args.dsn,
        "select urn, parent_urn from proj.src_nodes where parent_urn is not null order by urn",
    )
    grants = psql_rows(
        args.dsn,
        "select object_urn, subject_urn, subject_kind, relation from proj.src_grants "
        "where live order by grant_id",
    )
    members = psql_rows(
        args.dsn,
        "select group_urn, member_urn from proj.src_group_members order by group_urn, member_urn",
    )

    tuples = []
    seen = set()

    def add(t):
        key = (t["user"], t["relation"], t["object"])
        if key in seen:
            return
        seen.add(key)
        tuples.append(t)

    for urn, parent in nodes:
        add({"user": f"node:{parent}", "relation": "parent", "object": f"node:{urn}"})
    for obj, subject, kind, rel in grants:
        user = (
            f"group:{subject}#member"
            if kind == "group"
            else f"{kind}:{subject}"
        )
        add({"user": user, "relation": rel, "object": f"node:{obj}"})
    for group, member in members:
        add({"user": f"user:{member}", "relation": "member", "object": f"group:{group}"})

    # The root has no parent tuple. It is created by the tenant bootstrap
    # event, not by ReadChanges; seed it the way the log-driven projector would.
    psql_exec(
        args.dsn,
        "insert into proj.iam_nodes_proj (tenant_id, urn, kind, parent_urn, live) "
        "select split_part(urn, '/', 1), urn, kind, parent_urn, live "
        "from proj.src_nodes where urn = 'proj/root/main' "
        "on conflict (tenant_id, urn) do nothing;",
    )

    log(f"writing {len(tuples)} tuples in batches of {WRITE_BATCH}")
    write_started = time.time()
    for i in range(0, len(tuples), WRITE_BATCH):
        write_batch(args.api, args.store, tuples[i : i + WRITE_BATCH])
    write_elapsed = time.time() - write_started
    log(f"wrote {len(tuples)} tuples in {write_elapsed:.2f}s")

    token, total, pages, project_elapsed = project(
        args.dsn, args.api, args.store, None, args.max_pages
    )
    log(
        f"projected {total} changes over {pages} pages in {project_elapsed:.2f}s "
        f"({total / max(project_elapsed, 0.001):.0f} changes/s)"
    )

    # -----------------------------------------------------------------------
    # Correctness against the source fixture
    # -----------------------------------------------------------------------
    checks = {
        "nodes": (
            "select count(*) from proj.src_nodes",
            "select count(*) from proj.iam_nodes_proj",
        ),
        "grants": (
            "select count(*) from (select distinct object_urn, subject_urn, subject_kind, relation, relation_rank from proj.src_grants where live) x",
            "select count(*) from proj.iam_grants_proj",
        ),
        "members": (
            "select count(*) from proj.src_group_members",
            "select count(*) from proj.iam_group_members_proj",
        ),
    }
    for name, (src_sql, proj_sql) in checks.items():
        src = int(psql_rows(args.dsn, src_sql)[0][0])
        proj = int(psql_rows(args.dsn, proj_sql)[0][0])
        status = "ok" if src == proj else "MISMATCH"
        print(f"count {name}: source={src} projection={proj} {status}")

    node_diff = psql_rows(
        args.dsn,
        "select 'src_only', urn, parent_urn, kind from ("
        "  select urn, parent_urn, kind from proj.src_nodes"
        "  except select urn, parent_urn, kind from proj.iam_nodes_proj"
        ") x union all "
        "select 'projection_only', urn, parent_urn, kind from ("
        "  select urn, parent_urn, kind from proj.iam_nodes_proj"
        "  except select urn, parent_urn, kind from proj.src_nodes"
        ") y limit 5",
    )
    print(f"node diff rows: {len(node_diff)}")
    for row in node_diff:
        print("  ", row)

    grant_diff = psql_rows(
        args.dsn,
        "select 'src_only', object_urn, subject_urn, relation from ("
        "  select object_urn, subject_urn, subject_kind, relation, relation_rank "
        "  from proj.src_grants where live"
        "  except select object_urn, subject_urn, subject_kind, relation, relation_rank "
        "  from proj.iam_grants_proj"
        ") x union all "
        "select 'projection_only', object_urn, subject_urn, relation from ("
        "  select object_urn, subject_urn, subject_kind, relation, relation_rank "
        "  from proj.iam_grants_proj"
        "  except select object_urn, subject_urn, subject_kind, relation, relation_rank "
        "  from proj.src_grants where live"
        ") y limit 5",
    )
    print(f"grant diff rows: {len(grant_diff)}")
    for row in grant_diff:
        print("  ", row)

    # -----------------------------------------------------------------------
    # Delete path
    # -----------------------------------------------------------------------
    log("delete test: one grant and one membership")
    delete_tuples = [
        {
            "user": "user:proj/user/u0010",
            "relation": "viewer",
            "object": "node:proj/document/d00000011",
        },
        {
            "user": "user:proj/user/u0007",
            "relation": "member",
            "object": "group:proj/group/g01",
        },
    ]
    before_grant = int(
        psql_rows(args.dsn, "select count(*) from proj.iam_grants_proj")[0][0]
    )
    before_member = int(
        psql_rows(args.dsn, "select count(*) from proj.iam_group_members_proj")[0][0]
    )
    write_batch(args.api, args.store, delete_tuples, deletes=True)
    token, total, pages, elapsed = project(
        args.dsn, args.api, args.store, token, args.max_pages
    )
    after_grant = int(
        psql_rows(args.dsn, "select count(*) from proj.iam_grants_proj")[0][0]
    )
    after_member = int(
        psql_rows(args.dsn, "select count(*) from proj.iam_group_members_proj")[0][0]
    )
    print(
        f"delete projection: {total} changes in {elapsed:.2f}s; "
        f"grants {before_grant}->{after_grant}, members {before_member}->{after_member}"
    )

    # -----------------------------------------------------------------------
    # Liveness gap: the feed does not change on deactivation
    # -----------------------------------------------------------------------
    direct = int(
        psql_rows(
            args.dsn,
            "select count(*) from proj.iam_grants_proj "
            "where subject_urn = 'proj/user/u0009'",
        )[0][0]
    )
    psql_exec(
        args.dsn,
        "insert into proj.iam_live_subjects_proj (tenant_id, subject_urn, live) "
        "values ('proj', 'proj/user/u0009', false) on conflict do nothing;",
    )
    after_live = int(
        psql_rows(
            args.dsn,
            "select count(*) from proj.iam_grants_proj g "
            "where g.subject_urn = 'proj/user/u0009' "
            "and not exists (select 1 from proj.iam_live_subjects_proj s "
            "  where s.subject_urn = g.subject_urn and not s.live)",
        )[0][0]
    )
    print(
        f"liveness gap: {direct} direct grants visible before the log event, "
        f"{after_live} after the simulated PrincipalDeactivated"
    )

    # -----------------------------------------------------------------------
    # Tombstone gap: deleting the parent tuple is not a tombstone
    # -----------------------------------------------------------------------
    write_batch(
        args.api,
        args.store,
        [
            {
                "user": "node:proj/fileset/f0001",
                "relation": "parent",
                "object": "node:proj/document/d00000011",
            }
        ],
        deletes=True,
    )
    token, total, pages, elapsed = project(
        args.dsn, args.api, args.store, token, args.max_pages
    )
    row = psql_rows(
        args.dsn,
        "select urn, parent_urn, live from proj.iam_nodes_proj "
        "where urn = 'proj/document/d00000011'",
    )
    print(f"tombstone gap after parent delete: {row}")
    psql_exec(
        args.dsn,
        "update proj.iam_nodes_proj set live = false "
        "where urn = 'proj/document/d00000011';",
    )
    row = psql_rows(
        args.dsn,
        "select urn, parent_urn, live from proj.iam_nodes_proj "
        "where urn = 'proj/document/d00000011'",
    )
    print(f"after simulated NodeDeleted: {row}")

    # -----------------------------------------------------------------------
    # The feed's own provenance
    # -----------------------------------------------------------------------
    sample = psql_rows(
        args.dsn,
        "select object_urn, subject_urn, relation, granted_at from proj.iam_grants_proj limit 1",
    )
    print(f"projected grant has no grant_id/granted_by: {sample}")
    print("ReadChanges carries no model id; relation ranks were supplied by the model, not the feed.")


if __name__ == "__main__":
    main()
