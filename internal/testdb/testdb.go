// Package testdb is the harness every database-backed test in this module
// runs on: Start gives a test its own uniquely-named, migrated Postgres
// database, so tests run in parallel without a shared database and without
// truncation between them.
//
// It is `cas/internal/testdb` reproduced for this module, deliberately and
// temporarily. CONVENTIONS puts the shared harness in `tenancy`; `tenancy`
// does not exist yet, and this increment may not create it or reach into
// another repository. When `tenancy` ships its harness this package is
// deleted and its callers re-pointed — the same staged migration `cas`'s
// copy is on, not a second approach.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/laenenai/iam/internal/migrate"
)

// postgresImage is the image used when TEST_DATABASE_URL is not set. It is
// pgvector/pgvector:pg18 and not stock postgres:18 because CONVENTIONS
// pins it system-wide: vector columns exist in the consumers that embed
// this module's schema, and a harness on the stock image passes locally
// and fails where it matters.
const postgresImage = "pgvector/pgvector:pg18"

// adminConnectTimeout bounds every administrative connection Start makes.
const adminConnectTimeout = 10 * time.Second

// Migrator applies pending schema migrations to pool. Start calls it
// exactly once, against a freshly created empty database, before handing
// the pool back. The default is migrate.Up.
type Migrator func(ctx context.Context, pool *pgxpool.Pool) error

// Option configures Start.
type Option func(*options)

type options struct {
	migrator Migrator
}

// WithMigrator overrides the Migrator Start runs against the freshly
// created database.
func WithMigrator(m Migrator) Option {
	return func(o *options) { o.migrator = m }
}

// DB is an isolated database created for a single test by Start.
type DB struct {
	pool *pgxpool.Pool
	name string
}

// Pool returns the connection pool opened against this test's database.
func (d *DB) Pool() *pgxpool.Pool { return d.pool }

// Name returns this test's database name.
func (d *DB) Name() string { return d.name }

var (
	containerOnce sync.Once
	containerDSN  string
	containerErr  error
)

// Start creates a uniquely-named Postgres database, runs the configured
// Migrator against it, and registers a t.Cleanup that closes the pool and
// drops the database. Each call gets its own database, so tests using
// Start may run in parallel without interfering with one another.
//
// When TEST_DATABASE_URL is set, Start connects to that server and still
// creates a unique database on it rather than reusing a shared one.
// Otherwise it starts a container once per test binary run via
// testcontainers-go.
//
// It takes testing.TB rather than *testing.T so that a benchmark can have
// its own migrated database too, with the same teardown. A benchmark that
// built one by hand would be a second copy of this logic, and the half it
// would get wrong is the cleanup — which is how a long-lived
// TEST_DATABASE_URL server accumulates orphaned databases nothing ever
// drops.
//
// Start skips the test under testing.Short() — the single chokepoint for
// that convention, so every database test inherits it without its author
// remembering a gate of their own. -short wins even when
// TEST_DATABASE_URL is set: a reachable server is not a reason to run,
// since the convention is "no databases in the inner loop", period. The
// skip happens before any container or database work, so a skipped test
// pays no setup cost.
func Start(t testing.TB, opts ...Option) *DB {
	t.Helper()

	if testing.Short() {
		t.Skip("testdb: skipping database-backed test in -short mode; run `mise run test-all` for the full suite")
	}

	cfg := options{migrator: migrate.Up}
	for _, opt := range opts {
		opt(&cfg)
	}

	ctx := context.Background()
	serverDSN := adminDSN(ctx, t)
	dbName := newDatabaseName()

	adminConn, err := pgx.Connect(ctx, serverDSN)
	if err != nil {
		t.Fatalf("testdb: connect to admin database: %v", err)
	}
	defer func() { _ = adminConn.Close(ctx) }()

	if _, err := adminConn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("testdb: create database %s: %v", dbName, err)
	}

	// Register the drop now, immediately after the database exists,
	// rather than after the pool and migrator steps below: both can fail
	// via t.Fatalf, which never returns, so a Cleanup registered after
	// them would never run on that path — orphaning the database
	// permanently, which is especially damaging against a long-lived
	// TEST_DATABASE_URL server where nothing else ever drops it. pool is
	// filled in below and this closure closes over the variable, not a
	// snapshot.
	var pool *pgxpool.Pool
	t.Cleanup(func() {
		if pool != nil {
			pool.Close()
		}
		dropDatabase(serverDSN, dbName, t)
	})

	pool, err = openPool(ctx, serverDSN, dbName)
	if err != nil {
		t.Fatalf("testdb: open pool against %s: %v", dbName, err)
	}
	if err := cfg.migrator(ctx, pool); err != nil {
		t.Fatalf("testdb: migrate %s: %v", dbName, err)
	}
	return &DB{pool: pool, name: dbName}
}

// openPool opens a pool against dbName on the server named by serverDSN.
func openPool(ctx context.Context, serverDSN, dbName string) (*pgxpool.Pool, error) {
	dsn, err := withDatabase(serverDSN, dbName)
	if err != nil {
		return nil, err
	}
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		// Never include err: a DSN parse error can echo the connection
		// string, which may carry a password.
		return nil, fmt.Errorf("testdb: parse connection string for %s", dbName)
	}
	poolCfg.ConnConfig.ConnectTimeout = adminConnectTimeout
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("testdb: open pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, adminConnectTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("testdb: ping: %w", err)
	}
	return pool, nil
}

// dropDatabase removes the test's database. It reports rather than fails:
// a failure here happens during cleanup, after the test's own assertions,
// and masking the test's real result with a teardown error is worse than a
// logged leak.
func dropDatabase(serverDSN, dbName string, t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), adminConnectTimeout)
	defer cancel()

	conn, err := pgx.Connect(ctx, serverDSN)
	if err != nil {
		t.Logf("testdb: could not connect to drop %s: %v", dbName, err)
		return
	}
	defer func() { _ = conn.Close(ctx) }()

	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize()+" WITH (FORCE)"); err != nil {
		t.Logf("testdb: could not drop %s: %v", dbName, err)
	}
}

// adminDSN returns a DSN for the server these tests run against:
// TEST_DATABASE_URL when set, otherwise a container started once per test
// binary run.
func adminDSN(ctx context.Context, t testing.TB) string {
	t.Helper()
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		return dsn
	}
	containerOnce.Do(func() { containerDSN, containerErr = startContainer(ctx) })
	if containerErr != nil {
		t.Skipf("testdb: no TEST_DATABASE_URL and no usable container runtime: %v", containerErr)
	}
	return containerDSN
}

// startContainer starts one Postgres container for this test binary run.
func startContainer(ctx context.Context) (string, error) {
	container, err := tcpostgres.Run(ctx, postgresImage,
		tcpostgres.WithDatabase("iam"),
		tcpostgres.WithUsername("iam"),
		tcpostgres.WithPassword("iam"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", fmt.Errorf("start %s: %w", postgresImage, err)
	}
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return "", fmt.Errorf("connection string: %w", err)
	}
	return dsn, nil
}

// withDatabase rewrites dsn's database name to dbName, accepting either a
// URL-form or keyword/value-form connection string.
func withDatabase(dsn, dbName string) (string, error) {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("testdb: parse TEST_DATABASE_URL")
		}
		u.Path = "/" + dbName
		return u.String(), nil
	}
	// Keyword/value form: a later dbname= wins, so appending is enough.
	return dsn + " dbname=" + dbName, nil
}

// newDatabaseName returns a fresh, lowercase, identifier-safe database
// name. A ULID keeps names sortable by creation time, which makes an
// orphan on a long-lived server easy to attribute.
func newDatabaseName() string {
	return "iam_test_" + strings.ToLower(ulid.Make().String())
}
