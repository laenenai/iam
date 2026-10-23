#!/usr/bin/env python3
"""Render the measured JSON into the markdown tables used in the write-up."""

import argparse
import json


ORDER = [
    "exact",
    "a-off",
    "a-relaxed",
    "a-strict",
    "a-relaxed-tuned",
    "b-key-flat",
    "b-part",
    "b-part-relaxed",
    "b-part-literal",
    "b-part-keyonly",
    "b-part-exact",
]

PROBE_ORDER = ["p50", "p10", "p1", "p01", "psub"]


def fmt(x, nd=1):
    return "--" if x is None else f"{x:,.{nd}f}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    args = ap.parse_args()

    for path in args.files:
        with open(path) as fh:
            d = json.load(fh)
        label = d["suffix"] or "(correlated)"
        print(f"\n### {path}  layout={label}")
        print(f"Postgres: {d['postgres']}")
        print(f"pgvector: {d['pgvector']}")
        print(f"rows: {d['total_rows']:,}  dim: {d['dim']}  top-k: {d['topk']}")
        print(
            f"client->server RTT select 1: p50 {d['client_rtt_ms']['p50']:.2f} ms, "
            f"p95 {d['client_rtt_ms']['p95']:.2f} ms  (included in every latency below)"
        )
        print("\n#### Probes\n")
        print(
            "| probe | grant depth | usersets | zones in key | rows via key | "
            "rows after tier 1 | rows after tier 2 | selectivity | key resolve ms |"
        )
        print("|---|---|---|---|---|---|---|---|---|")
        for p in PROBE_ORDER:
            if p not in d["probes"]:
                continue
            pr = d["probes"][p]
            print(
                f"| `{p}` | L{pr['depth']} | {pr['usersets']} | {pr['n_zones']} | "
                f"{pr['key_reachable']:,} | {pr['accessible_tier1_only']:,} | "
                f"{pr['accessible']:,} | {pr['selectivity']:.4%} | "
                f"{pr['zone_resolve_ms']:.1f} |"
            )

        modes = []
        for r in d["results"]:
            if r.get("query_mode", "inset") not in modes:
                modes.append(r.get("query_mode", "inset"))
        by = {
            (r.get("query_mode", "inset"), r["probe"], r["strategy"]): r
            for r in d["results"]
        }

        for mode in modes:
          print(f"\n#### query distribution: {mode}")
          print("\n##### recall@20 (mean over N queries; min in parentheses)\n")
          ps = [p for p in PROBE_ORDER if p in d["probes"]]
          hdr = "| strategy |" + "".join(
              f" {p} ({d['probes'][p]['selectivity']:.2%}) |" for p in ps
          )
          sep = "|---" * (1 + len(ps)) + "|"
          print(hdr); print(sep)
          for st in ORDER:
              cells = []
              for p in ps:
                  r = by.get((mode, p, st))
                  if r is None:
                      cells.append(" -- ")
                  elif r["recall_mean"] is None:
                      cells.append(" 1.000 (truth) ")
                  else:
                      cells.append(f" {r['recall_mean']:.3f} ({r['recall_min']:.2f}) ")
              print(f"| `{st}` |" + "|".join(cells) + "|")

          print("\n##### p95 latency, ms (p50 in parentheses)\n")
          print(hdr); print(sep)
          for st in ORDER:
              cells = []
              for p in ps:
                  r = by.get((mode, p, st))
                  cells.append(
                      " -- " if r is None else f" {r['p95_ms']:,.0f} ({r['p50_ms']:,.0f}) "
                  )
              print(f"| `{st}` |" + "|".join(cells) + "|")

          print("\n##### rows returned (of 20 requested) -- short results are silent\n")
          print(hdr); print(sep)
          for st in ORDER:
              cells = []
              for p in ps:
                  r = by.get((mode, p, st))
                  if r is None:
                      cells.append(" -- ")
                  else:
                      cells.append(
                          f" {r['returned_mean']:.1f} "
                          f"({r['short_results']}/{r['n_queries']} short) "
                      )
              print(f"| `{st}` |" + "|".join(cells) + "|")


if __name__ == "__main__":
    main()
