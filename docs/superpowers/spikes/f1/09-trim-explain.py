#!/usr/bin/env python3
"""Make the EXPLAIN dump readable.

04-measure.py's --explain-out writes EXPLAIN (ANALYZE, BUFFERS) for every
(probe, strategy) pair. Raw, that file is ~30 MB, for two reasons that are
themselves worth knowing:

 1. every plan echoes the 768-dimension query vector as a literal, repeatedly;
 2. a plan over a 1,000-partition table has ~1,000 child subplans, and that is
    a property of strategy (b), not an artefact -- a reader should see that it
    happens, but not a thousand copies of it.

This script keeps a curated set of cases, replaces query vectors with a
placeholder, and elides long runs of per-partition subplans, naming how many
lines it dropped.

    python3 09-trim-explain.py explain-correlated.txt > explain-key-cases.txt
"""

import re
import sys

KEEP = {
    ("p50", "exact"), ("p50", "a-off"), ("p50", "a-relaxed"),
    ("p50", "a-relaxed-tuned"), ("p50", "b-key-flat"), ("p50", "b-part-literal"),
    ("p10", "a-off"), ("p10", "b-part-literal"),
    ("p1", "a-off"), ("p1", "a-relaxed"), ("p1", "b-part-literal"),
    ("p01", "exact"), ("p01", "a-off"), ("p01", "a-relaxed"), ("p01", "a-strict"),
    ("p01", "a-relaxed-tuned"), ("p01", "b-key-flat"), ("p01", "b-part"),
    ("p01", "b-part-literal"), ("p01", "b-part-keyonly"), ("p01", "b-part-exact"),
    ("psub", "b-part-literal"), ("psub", "b-part-keyonly"),
}

VEC = re.compile(r"'\[[-0-9eE.,]{40,}\]'(::\w+)?")
HDR = re.compile(
    r"^probe=(\w+)\s+(?:\(grant at (L\d), selectivity ([^)]+)\)|grant at (L\d)\s+selectivity (\S+))"
    r"\s+strategy=([\w-]+)"
)
HEAD_LINES = 45
TAIL_LINES = 12


def emit(cur, buf, out):
    if cur is None:
        return
    probe, depth, sel, strategy = cur
    if (probe, strategy) not in KEEP:
        return
    body = [l for l in buf if l.strip()]
    if len(body) > HEAD_LINES + TAIL_LINES + 5:
        kept = (
            body[:HEAD_LINES]
            + [f"        ... [{len(body) - HEAD_LINES - TAIL_LINES} plan lines elided "
               f"-- mostly per-partition child subplans] ..."]
            + body[-TAIL_LINES:]
        )
    else:
        kept = body
    out.append("=" * 78)
    out.append(f"probe={probe}  grant at {depth}  selectivity {sel}  strategy={strategy}")
    out.append("=" * 78)
    out.extend(kept)
    out.append("")


def main():
    src = sys.argv[1]
    out = []
    cur, buf = None, []
    with open(src) as fh:
        for line in fh:
            m = HDR.match(line)
            if m:
                emit(cur, buf, out)
                g = m.groups()
                cur = (g[0], g[1] or g[3], g[2] or g[4], g[5])
                buf = []
                continue
            if cur is None or line.startswith("====="):
                continue
            buf.append(VEC.sub("'[<768-dim query vector>]'", line.rstrip("\n")))
    emit(cur, buf, out)
    print("Postgres: PostgreSQL 18.6 (Debian 18.6-1.pgdg12+2), aarch64-unknown-linux-gnu")
    print("pgvector: 0.8.7")
    print("Query vectors replaced by a placeholder; long per-partition runs elided.")
    print()
    print("\n".join(out))


if __name__ == "__main__":
    main()
