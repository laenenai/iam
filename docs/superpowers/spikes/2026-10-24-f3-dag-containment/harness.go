// Package f3spike is the probe for design finding F3 — "containment is a DAG,
// not a tree" — and it is a measurement harness, not module code. Nothing
// here is imported by `iam` itself; it exists so the numbers in
// `docs/superpowers/spikes/2026-10-24-f3-dag-containment.md` can be
// re-derived by running one test.
//
// It follows `internal/testdb`'s pattern — testcontainers-go, one Postgres
// per binary run, the pgvector/pgvector:pg18 image CONVENTIONS pins — with
// two deliberate differences. The server GUCs are the F1 spike's, so the two
// spikes' numbers are comparable, and the fixture is built by the SQL files
// beside this one rather than by migrate.Up, because the schema under test is
// a candidate projection shape and not this module's schema.
//
// Run it:
//
//	F3_SPIKE=1 go test -count=1 -timeout 4h \
//	    ./docs/superpowers/spikes/2026-10-24-f3-dag-containment/
//
// Without F3_SPIKE the test skips, because the full fixture is 10,000,000
// facts and a ~100,000,000-row closure: it belongs in a spike run, never in
// CI. F3_SCALE=0.01 builds a hundredth of it, which is what the correctness
// of every query below was checked against before the full run.
package f3spike

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
)

// postgresImage is CONVENTIONS' pinned image, and the one the F1 spike ran
// on. Using a different server here would make the two spikes' latencies
// incomparable, which is the whole reason this is a constant and not a knob.
const postgresImage = "pgvector/pgvector:pg18"

// queryBudget bounds one measured query. A strategy that cannot answer inside
// it is recorded as a timeout rather than allowed to hang the run — and a
// timeout is a result: A2's budget for the same query is 20 ms.
const queryBudget = 120 * time.Second

// serverArgs are the F1 spike's server settings, reproduced exactly except
// for the two lines noted.
//
// max_parallel_workers_per_gather = 0 is deliberate and is F1's reasoning
// unchanged: parallel workers make p95 depend on how many happen to be free,
// which is not the property under test. The closure builds raise it locally
// and the write-up says where.
//
// max_parallel_maintenance_workers = 0 differs from F1, which used 4 plus a
// 2 GB /dev/shm. A parallel index build allocates maintenance_work_mem in
// dynamic shared memory and fails — not slows — when /dev/shm is a
// container default, which is the operational note F1 recorded. There is no
// HNSW here, so the serial build is taken instead of the shm flag and no
// container-level flag is needed at all.
var serverArgs = []string{
	"-c", "shared_buffers=8GB",
	"-c", "effective_cache_size=24GB",
	"-c", "maintenance_work_mem=8GB",
	"-c", "work_mem=256MB",
	"-c", "max_wal_size=16GB",
	"-c", "checkpoint_timeout=60min",
	"-c", "wal_compression=on",
	"-c", "max_worker_processes=8",
	"-c", "max_parallel_workers=5",
	"-c", "max_parallel_maintenance_workers=0",
	"-c", "max_parallel_workers_per_gather=0",
	"-c", "random_page_cost=1.1",
	"-c", "track_io_timing=on",
	"-c", "max_locks_per_transaction=4096",
	"-c", "jit=off",
	"-c", "plan_cache_mode=force_custom_plan",
	"-c", "autovacuum_vacuum_cost_delay=0",
}

// params are the fixture's cardinalities. The defaults are kgs A2's, which is
// the point: F2 established that the fixture shape decides whether a number
// means anything.
type params struct {
	scale float64
	vals  map[string]string
}

// newParams scales kgs A2's proportions by F3_SCALE (default 1.0).
func newParams() params {
	scale := 1.0
	if s := os.Getenv("F3_SCALE"); s != "" {
		v, err := strconv.ParseFloat(s, 64)
		if err == nil && v > 0 {
			scale = v
		}
	}
	at := func(n int) string {
		v := int(math.Round(float64(n) * scale))
		if v < 1 {
			v = 1
		}
		return strconv.Itoa(v)
	}
	nEntity := int(math.Round(2_000_000 * scale))
	if nEntity < 100 {
		nEntity = 100
	}
	return params{scale: scale, vals: map[string]string{
		"SCALE":       strconv.FormatFloat(scale, 'g', -1, 64),
		"N_FACT":      at(10_000_000),
		"N_ENTITY":    strconv.Itoa(nEntity),
		"N_TOPIC":     strconv.Itoa(max(nEntity/100, 1)),
		"N_EPISODE":   at(100_000),
		"N_ES1":       at(20),
		"N_ES2":       at(200),
		"N_ES3":       at(2_000),
		"N_ES4":       at(20_000),
		"N_HUB":       at(1_000),
		"N_PRINCIPAL": "2000",
		"N_GROUP":     "200",
		"N_GRANT":     "10000",
		"C1_BATCH":    at(500_000),
	}}
}

func (p params) n(key string) int64 {
	v, err := strconv.ParseInt(p.vals[key], 10, 64)
	if err != nil {
		return 0
	}
	return v
}

// placeholder matches the ${NAME} form the SQL files use for a cardinality.
//
// The substitution is a regexp rather than os.Expand on purpose: os.Expand
// treats PL/pgSQL's $$ dollar-quoting as a variable reference and eats it,
// which turns 04-c1-fact-ancestry.sql into a syntax error whose message names
// neither the file nor the cause.
var placeholder = regexp.MustCompile(`\$\{([A-Z0-9_]+)\}`)

// expand substitutes ${NAME} in a SQL file. A name with no value is left
// alone rather than replaced by the empty string, so a typo in a SQL file
// becomes a syntax error at the server instead of a silently different query.
func (p params) expand(sql string) string {
	return placeholder.ReplaceAllStringFunc(sql, func(m string) string {
		if v, ok := p.vals[placeholder.FindStringSubmatch(m)[1]]; ok {
			return v
		}
		return m
	})
}

// pg is the spike's database handle plus the transcript it writes to.
type pg struct {
	pool *pgxpool.Pool
	dir  string
	keep bool
}

// start connects the spike to Postgres: F3_DSN when set, otherwise a
// container started here. The pool uses the simple protocol throughout —
// the SQL files are multi-statement, and the extended protocol refuses
// those; parameterized measurement queries are unaffected because every one
// of them passes its parameters as values rather than as text.
func start(ctx context.Context, t *testing.T) *pg {
	t.Helper()

	dsn := os.Getenv("F3_DSN")
	if dsn == "" {
		if os.Getenv("F3_KEEP") != "" {
			t.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
		}
		c, err := tcpostgres.Run(ctx, postgresImage,
			tcpostgres.WithDatabase("f3"),
			tcpostgres.WithUsername("f3"),
			tcpostgres.WithPassword("f3"),
			tcpostgres.BasicWaitStrategies(),
			testcontainers.WithCmdArgs(serverArgs...),
		)
		if err != nil {
			t.Skipf("f3: no usable container runtime: %v", err)
		}
		if os.Getenv("F3_KEEP") == "" {
			t.Cleanup(func() {
				if err := testcontainers.TerminateContainer(c); err != nil {
					t.Logf("f3: terminate container: %v", err)
				}
			})
		}
		dsn, err = c.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			t.Fatalf("f3: connection string: %v", err)
		}
		t.Logf("f3: container DSN %s (F3_KEEP set: %v)", dsn, os.Getenv("F3_KEEP") != "")
	}

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("f3: parse F3_DSN")
	}
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("f3: open pool: %v", err)
	}
	t.Cleanup(pool.Close)
	for range 30 {
		if err = pool.Ping(ctx); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatalf("f3: ping: %v", err)
	}

	here, err := os.Getwd()
	if err != nil {
		t.Fatalf("f3: getwd: %v", err)
	}
	return &pg{pool: pool, dir: here, keep: os.Getenv("F3_KEEP") != ""}
}

// runFile executes one of the SQL files beside this one, with ${NAME}
// expanded, and returns how long the server took.
func (p *pg) runFile(ctx context.Context, t *testing.T, name string, prm params) time.Duration {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(p.dir, name)) // #nosec G304 -- fixed set of files beside this source
	if err != nil {
		t.Fatalf("f3: read %s: %v", name, err)
	}
	start := time.Now()
	if _, err := p.pool.Exec(ctx, prm.expand(string(raw))); err != nil {
		t.Fatalf("f3: %s: %v", name, err)
	}
	d := time.Since(start)
	t.Logf("f3: %-28s %s", name, dur(d))
	return d
}

// exec runs one statement and fails the test if it errors.
func (p *pg) exec(ctx context.Context, t *testing.T, sql string, args ...any) time.Duration {
	t.Helper()
	start := time.Now()
	if _, err := p.pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("f3: exec: %v\n%s", err, sql)
	}
	return time.Since(start)
}

// scalar runs a one-column one-row query.
func scalar[T any](ctx context.Context, t *testing.T, p *pg, sql string, args ...any) T {
	t.Helper()
	var v T
	if err := p.pool.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
		t.Fatalf("f3: scalar: %v\n%s", err, sql)
	}
	return v
}

// scalarOK is scalar for a query that may legitimately return no row.
func scalarOK[T any](ctx context.Context, p *pg, sql string, args ...any) (T, bool) {
	var v T
	if err := p.pool.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return v, false
		}
		return v, false
	}
	return v, true
}

// timing is a latency sample reduced to the two numbers F1 reported, plus
// the one F1 never needed: whether the cell finished at all.
type timing struct {
	Reps     int     `json:"reps"`
	P50      float64 `json:"p50_ms"`
	P95      float64 `json:"p95_ms"`
	Rows     int64   `json:"rows"`
	TimedOut bool    `json:"timed_out,omitempty"`
	Note     string  `json:"note,omitempty"`
}

// String renders a cell the way the transcripts' tables do.
func (x timing) String() string {
	if x.TimedOut {
		return "timeout"
	}
	return fmt.Sprintf("%9.2f %9.2f", x.P50, x.P95)
}

// measure runs sql reps times and returns p50/p95 wall-clock milliseconds and
// the row count of the last execution. Wall clock includes the Docker round
// trip, which is measured separately and reported in the write-up, exactly as
// F1 did.
//
// A cell that exceeds queryBudget is recorded as a timeout and the run
// continues: a strategy being unable to answer inside three minutes is a
// result, not an infrastructure failure, and aborting the run would lose
// every cell after it.
func measure(ctx context.Context, t *testing.T, p *pg, reps int, sql string, args ...any) timing {
	t.Helper()
	samples := make([]float64, 0, reps)
	var rows int64
	for i := 0; i < reps; i++ {
		qctx, cancel := context.WithTimeout(ctx, queryBudget)
		start := time.Now()
		r, err := p.pool.Query(qctx, sql, args...)
		if err != nil {
			cancel()
			return timing{Reps: len(samples), TimedOut: true, Note: trunc(err.Error())}
		}
		var n int64
		for r.Next() {
			n++
		}
		err = r.Err()
		r.Close()
		cancel()
		if err != nil {
			return timing{Reps: len(samples), TimedOut: true, Note: trunc(err.Error())}
		}
		elapsed := time.Since(start)
		samples = append(samples, float64(elapsed.Microseconds())/1000)
		rows = n
		// Adaptive repetition count. At A2's scale the slowest cells are
		// seconds rather than milliseconds, and twenty executions of a cell
		// that takes a minute would cost more wall clock than every other
		// cell in the spike combined -- for a p95 that is already obvious
		// from three samples. The first execution decides; the reduction is
		// recorded in the cell so a table never implies a sample size it
		// does not have.
		if i == 0 {
			switch {
			case elapsed > 20*time.Second && reps > 3:
				reps = 3
			case elapsed > 2*time.Second && reps > 5:
				reps = 5
			}
		}
	}
	sort.Float64s(samples)
	return timing{Reps: len(samples), P50: pct(samples, 0.50), P95: pct(samples, 0.95), Rows: rows}
}

// trunc keeps a driver error short enough for a table cell.
func trunc(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 90 {
		return s[:90]
	}
	return s
}

func pct(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(q*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

// explain captures EXPLAIN (ANALYZE, BUFFERS) for one query.
func explain(ctx context.Context, t *testing.T, p *pg, sql string, args ...any) string {
	t.Helper()
	rows, err := p.pool.Query(ctx, "explain (analyze, buffers, verbose off) "+sql, args...)
	if err != nil {
		return "EXPLAIN failed: " + err.Error()
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			return "EXPLAIN scan failed: " + err.Error()
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if err := rows.Err(); err != nil {
		return "EXPLAIN rows failed: " + err.Error()
	}
	return b.String()
}

// transcript accumulates one of the spike's committed .txt outputs.
type transcript struct {
	name string
	b    strings.Builder
}

func newTranscript(name string) *transcript { return &transcript{name: name} }

func (x *transcript) addf(format string, a ...any) {
	fmt.Fprintf(&x.b, format+"\n", a...)
}

func (x *transcript) head(title string) {
	x.addf("")
	x.addf("=== %s %s", title, strings.Repeat("=", max(2, 72-len(title))))
}

func (x *transcript) write(t *testing.T, dir string) {
	t.Helper()
	path := filepath.Join(dir, x.name)
	if err := os.WriteFile(path, []byte(x.b.String()), 0o600); err != nil {
		t.Fatalf("f3: write %s: %v", path, err)
	}
	t.Logf("f3: wrote %s (%d bytes)", x.name, x.b.Len())
}

// dur renders a duration the way the transcripts report one.
func dur(d time.Duration) string {
	switch {
	case d >= time.Minute:
		return fmt.Sprintf("%dm %02ds", int(d.Minutes()), int(d.Seconds())%60)
	case d >= time.Second:
		return fmt.Sprintf("%.1fs", d.Seconds())
	default:
		return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000)
	}
}

// comma renders a row count with thousands separators, because every number
// in this spike's write-up is in the millions and an unseparated one is
// unreadable.
func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	r := strings.Join(out, ",")
	if neg {
		return "-" + r
	}
	return r
}

// withKeyTest substitutes one of this file's keyTest* literals into one of
// its %s-bearing query templates. Both sides are constants in this package;
// nothing from the database or the environment reaches it.
func withKeyTest(template, test string) string {
	return fmt.Sprintf(template, test)
}
