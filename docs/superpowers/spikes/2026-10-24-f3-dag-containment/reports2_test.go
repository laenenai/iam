package f3spike

import (
	"context"
	"fmt"
	"testing"
)

// keyCand is one of question 2's five candidate replacements for F1's scalar
// containment key.
type keyCand struct {
	name string
	cand string
	test string
	// keySet resolves the principal into the key set THIS candidate is
	// queried with. It is per-candidate and not shared, because a key stored
	// at a coarser granularity than the grant has to have its key set lifted
	// to match -- measuring every candidate against the accessible container
	// set would measure a resolution bug rather than the key.
	keySet func(context.Context, *testing.T, *pg, *probeRow) []int32
}

// accessibleSet is the key set for every candidate whose key is stored at the
// granularity grants are written at.
func accessibleSet(_ context.Context, _ *testing.T, _ *pg, pr *probeRow) []int32 {
	return pr.Accessible
}

// episodeSetFromFacts is K1's only sound key set. No episode is a descendant
// of an entity-set, so the container DAG yields nothing for an entity-set
// grant and the set has to be walked out of the authorized facts.
func episodeSetFromFacts(ctx context.Context, t *testing.T, p *pg, pr *probeRow) []int32 {
	return scalar[[]int32](ctx, t, p, qEpisodeKeySetFromFacts, pr.Accessible)
}

// lift3Set is K3's key set, lifted to the granularity K3 stores.
func lift3Set(ctx context.Context, t *testing.T, p *pg, pr *probeRow) []int32 {
	return scalar[[]int32](ctx, t, p, qLift3KeySet, pr.Accessible)
}

var keyCands = []keyCand{
	{"K1 ep_zone", qCandK1, keyTestK1, episodeSetFromFacts},
	{"K2 zones[]", qCandK2, keyTestK2, accessibleSet},
	{"K3 zones3[]", qCandK3, keyTestK3, lift3Set},
	{"K4 per-kind", qCandK4, keyTestK4, accessibleSet},
	{"K5 canonical", qCandK5, keyTestK5, accessibleSet},
}

// reportKeys writes keys.txt: question 2. For each candidate key and each
// probe -- how large is the key set, how many of the 10,000,000 rows survive
// it, how many AUTHORIZED rows it prunes away (the number that decides
// whether a candidate is admissible at all), what the key-only page exposes
// (F1 §6's "9 of 20" asked again), and what the safe shape costs.
func reportKeys(ctx context.Context, t *testing.T, p *pg, probes []probeRow, res *results) {
	x := newTranscript("keys.txt")
	x.addf("F3 question 2 -- what happens to F1's scalar containment key")
	x.addf("")
	x.addf("F1's key: \"one scalar column per row holding the id of the row's ancestor")
	x.addf("at a declared containment depth\". Five candidates, one table, 10,000,000 rows.")
	x.addf("")
	x.addf("  K1 ep_zone      scalar, declared on the tree dimension: the fact's episode")
	x.addf("  K2 zones[]      every direct container, GIN")
	x.addf("  K3 zones3[]     the same lifted to entity-set level 3")
	x.addf("  K4 per-kind     ep_zone scalar + set_zones[] GIN, one key per containment kind")
	x.addf("  K5 canonical    one designated primary container per fact, scalar")

	x.head("index size")
	x.addf("%-18s %12s", "index", "size")
	for _, k := range []string{"fact_key_ep", "fact_key_canon", "fact_key_zones", "fact_key_zones3", "fact_key_setz", "fact_key_pkey"} {
		sz, ok := scalarOK[int64](ctx, p, "select pg_relation_size($1::regclass)", k)
		if ok {
			x.addf("%-18s %9.0f MB", k, mb(sz))
			res.Counts["index_bytes."+k] = sz
		}
	}

	x.head("candidate rows surviving the key, and authorized rows the key destroys")
	x.addf("A nonzero `pruned away` is not a recall miss tuning can recover: the row is")
	x.addf("gone before the fragment is evaluated and the consumer is told nothing.")
	x.addf("")
	x.addf("%-9s %-13s %10s %14s %14s %10s %12s",
		"probe", "key", "key set", "candidates", "authorized", "over x", "pruned away")
	for i := range probes {
		pr := &probes[i]
		if skipKeys(pr) {
			x.addf("%-9s %s", pr.Name, skipNote(pr))
			continue
		}
		for _, k := range keyCands {
			ks := k.keySet(ctx, t, p, pr)
			cand := scalar[int64](ctx, t, p, k.cand, ks)
			missed := scalar[int64](ctx, t, p, withKeyTest(qMissed, k.test), ks)
			over := 0.0
			if pr.Authorized > 0 {
				over = float64(cand) / float64(pr.Authorized)
			}
			x.addf("%-9s %-13s %10s %14s %14s %10.1f %12s",
				pr.Name, k.name, comma(int64(len(ks))), comma(cand),
				comma(pr.Authorized), over, comma(missed))
			res.Counts["key.cand."+k.name+"."+pr.Name] = cand
			res.Counts["key.missed."+k.name+"."+pr.Name] = missed
		}
	}

	x.head("K1 in a DAG: the key set cannot be read off the container graph")
	x.addf("No episode is a descendant of an entity-set, so a principal whose grant is on")
	x.addf("an entity-set has an EMPTY episode key set while holding authorized facts. The")
	x.addf("only sound construction walks the authorized facts. Its cost:")
	x.addf("")
	x.addf("%-9s %14s %14s %12s", "probe", "episodes", "via facts p95", "from DAG")
	for i := range probes {
		pr := &probes[i]
		if skipKeys(pr) {
			x.addf("%-9s %s", pr.Name, skipNote(pr))
			continue
		}
		cell := measure(ctx, t, p, 5, qEpisodeKeySetFromFacts, pr.Accessible)
		eps := int64(0)
		if v, ok := scalarOK[[]int32](ctx, p, qEpisodeKeySetFromFacts, pr.Accessible); ok {
			eps = int64(len(v))
		}
		fromDAG := int64(0)
		for _, c := range pr.Accessible {
			if c >= 1_000_000 {
				fromDAG++
			}
		}
		note := fmt.Sprintf("%12s", comma(fromDAG))
		x.addf("%-9s %14s %14s %s", pr.Name, comma(eps), cell.String(), note)
		res.Counts["key.k1.episodes."+pr.Name] = eps
		res.Counts["key.k1.from_dag."+pr.Name] = fromDAG
		res.Cells["key.k1.resolve."+pr.Name] = cell
	}

	x.head("the key-only page: what the key alone exposes (F1 condition (i))")
	x.addf("%-9s %-13s %12s %14s", "probe", "key", "unauth/50", "p50/p95 ms")
	for i := range probes {
		pr := &probes[i]
		if skipKeys(pr) {
			x.addf("%-9s %s", pr.Name, skipNote(pr))
			continue
		}
		for _, k := range keyCands {
			ks := k.keySet(ctx, t, p, pr)
			unauth := scalar[int64](ctx, t, p, withKeyTest(qUnauthorizedInTop, k.test), ks, pr.Principal)
			cell := measure(ctx, t, p, pageReps, withKeyTest(qPageKeyOnly, k.test), ks, int64(0))
			x.addf("%-9s %-13s %12d %14s", pr.Name, k.name, unauth, cell.String())
			res.Counts["key.unauth."+k.name+"."+pr.Name] = unauth
			res.Cells["key.pageonly."+k.name+"."+pr.Name] = cell
		}
	}

	x.head("the safe shape: key pre-filters, fragment authorizes (p50 / p95 ms)")
	x.addf("%-9s %s", "", probeHeader(probes))
	for _, k := range keyCands {
		line := fmt.Sprintf("%-9s", k.name)
		for i := range probes {
			if skipKeys(&probes[i]) {
				line += fmt.Sprintf(" %21s", "skipped")
				continue
			}
			cell := measure(ctx, t, p, pageReps, withKeyTest(qPageKeySafe, k.test),
				k.keySet(ctx, t, p, &probes[i]), int64(0), probes[i].Principal)
			res.Cells["key.pagesafe."+k.name+"."+probes[i].Name] = cell
			line += fmt.Sprintf(" %21s", cell.String())
		}
		x.addf("%s", line)
	}

	x.write(t, p.dir)
}

// reportVisibleBelow writes visible-below.txt: question 3. Three candidate
// meanings for "only on the direct path", each measured for its size and for
// what it exposes that the principal holds no grant on or under.
func reportVisibleBelow(ctx context.Context, t *testing.T, p *pg, probes []probeRow, res *results) {
	x := newTranscript("visible-below.txt")
	x.addf("F3 question 3 -- what \"only on the direct path\" can mean when there are several")
	x.addf("")
	x.addf("Three readings, measured on the same fixture:")
	x.addf("")
	x.addf("  union      every container that is an ancestor of some fact the principal may read")
	x.addf("  anchored   that set, intersected with the principal's own accessible set")
	x.addf("  intersect  per fact, the containers on EVERY path upward from it")
	x.addf("")
	x.addf("`leak` counts containers the union reading makes list-visible that the principal")
	x.addf("holds no grant on and none below -- containers whose existence it learns from a")
	x.addf("grant somewhere else. kind 0 tenant, 1 graph, 2 episode, 3 entity-set.")

	x.head("union versus anchored")
	x.addf("%-9s %12s %12s %10s %10s %s", "probe", "union", "anchored", "leak", "leak %", "leak by kind")
	for i := range probes {
		pr := &probes[i]
		if pr.Authorized > 2_000_000 {
			x.addf("%-9s %12s  -- skipped: %s authorized facts, the union is the whole graph",
				pr.Name, "", comma(pr.Authorized))
			continue
		}
		union := scalar[[]int32](ctx, t, p, qVisUnion, pr.Accessible)
		leak := scalar[int64](ctx, t, p, qVisUnionLeak, pr.Accessible, union)
		anchored := int64(len(union)) - leak
		pctLeak := 0.0
		if len(union) > 0 {
			pctLeak = 100 * float64(leak) / float64(len(union))
		}
		kinds := ""
		krows, err := p.pool.Query(ctx, qVisUnionLeakByKind, pr.Accessible, union)
		if err != nil {
			t.Fatalf("f3: leak by kind: %v", err)
		}
		for krows.Next() {
			var kind int16
			var n int64
			if err := krows.Scan(&kind, &n); err != nil {
				krows.Close()
				t.Fatalf("f3: scan leak kind: %v", err)
			}
			kinds += fmt.Sprintf("kind %d: %s  ", kind, comma(n))
		}
		krows.Close()
		if err := krows.Err(); err != nil {
			t.Fatalf("f3: leak kind rows: %v", err)
		}
		x.addf("%-9s %12s %12s %10s %9.1f%% %s",
			pr.Name, comma(int64(len(union))), comma(anchored), comma(leak), pctLeak, kinds)
		res.Counts["vis.union."+pr.Name] = int64(len(union))
		res.Counts["vis.anchored."+pr.Name] = anchored
		res.Counts["vis.leak."+pr.Name] = leak
	}

	x.head("the intersection reading, per fact")
	x.addf("The tenant and the graph are on every path by construction, so an intersection")
	x.addf("of size 2 means the reading names nothing below the graph.")
	for i := range probes {
		pr := &probes[i]
		if pr.Authorized > 2_000_000 {
			continue
		}
		x.addf("")
		x.addf("%s (%s):", pr.Name, pr.Note)
		x.addf("  %8s %10s %12s %6s %6s", "paths", "facts", "mean inter", "min", "max")
		rows, err := p.pool.Query(ctx, qPathIntersection, pr.Accessible)
		if err != nil {
			t.Fatalf("f3: intersection %s: %v", pr.Name, err)
		}
		for rows.Next() {
			var np, facts, imin, imax int64
			var mean float64
			if err := rows.Scan(&np, &facts, &mean, &imin, &imax); err != nil {
				rows.Close()
				t.Fatalf("f3: scan intersection: %v", err)
			}
			x.addf("  %8d %10s %12.2f %6d %6d", np, comma(facts), mean, imin, imax)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatalf("f3: intersection rows: %v", err)
		}
	}

	x.write(t, p.dir)
}

// keySetCeiling is where a resolved key set stops being something a consumer
// can bind as a query parameter. It is not a tuning constant: F1 measured
// planning time alone at 73.8 ms for 500 pruned partitions, and a key set
// larger than this is a different finding rather than a slower cell.
const keySetCeiling = 20_000

// skipKeys is true for a probe whose accessible container set is past the
// ceiling. The row is reported rather than dropped, because the size IS the
// result for that probe.
func skipKeys(pr *probeRow) bool { return pr.NAccess > keySetCeiling }

func skipNote(pr *probeRow) string {
	return fmt.Sprintf("key set is %s containers -- past the %s ceiling; no key applies, see the write-up",
		comma(int64(pr.NAccess)), comma(keySetCeiling))
}
