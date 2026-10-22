// Package migrate applies `iam`'s embedded schema migrations and reports
// on their state. It is the only package that imports goose: callers see
// only Up, Status and Applied.
//
// Migrations are embedded and applied by the library, never by a separate
// tool run, because anti-goal A1 requires that adding authorization to a
// Go binary need nothing beyond a Postgres connection string and one
// constructor call.
//
// Up is safe to call concurrently, including from several separate
// processes starting against the same database at once — the shape the
// embedded deployment model requires. See lockKey for how that is
// enforced.
package migrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/laenen-ai/iam/db/migrations"
	"github.com/laenen-ai/iam/internal/domain"
)

// lockKey is the Postgres session-level advisory lock key Up and Status
// take for the duration of their run, so that N binaries starting against
// the same database serialize their migration attempts instead of racing.
// It is the CRC32 (IEEE) checksum of this package's import path — a value
// specific to this project, vanishingly unlikely to collide with an
// unrelated advisory lock taken by something else sharing the same
// Postgres cluster — computed once as:
//
//	crc32.ChecksumIEEE([]byte("github.com/laenen-ai/iam/internal/migrate"))
//
// It must never change: changing it would let an old and a new binary run
// migrations concurrently against each other during a rolling deploy,
// which is exactly the race this lock exists to prevent.
const lockKey int64 = 1000744357

// versionTableName is where goose records which migrations have been
// applied. It lives in the public schema rather than iam: the iam schema
// is created by migration 00001, but goose must be able to create its own
// bookkeeping table before that migration — or any migration — has
// necessarily run yet. public always exists, so recording state there has
// no such bootstrap-ordering problem.
const versionTableName = "public.goose_iam_db_version"

// lockPollPeriodSeconds and lockMaxRetries bound how long Up and Status
// wait to acquire the advisory lock before giving up (as
// domain.ErrUnavailable, see classify): goose's session locker polls
// pg_try_advisory_lock rather than blocking, so these are the poll
// interval in whole seconds (1 is the library's minimum) and the number of
// retries after the first attempt.
var (
	lockPollPeriodSeconds uint64 = 1
	lockMaxRetries        uint64 = 300
)

// Applied describes one migration's state as goose's bookkeeping table
// knows it.
type Applied struct {
	// Version is the migration's leading version number, e.g. 1 for
	// 00001_init.sql.
	Version int64
	// Name is the migration's filename, e.g. "00001_init.sql".
	Name string
	// Applied reports whether this migration has been applied.
	// AppliedAt is the zero time when Applied is false.
	Applied   bool
	AppliedAt time.Time
}

// Up applies every pending migration embedded in migrations.FS to pool, in
// order. Calling Up again against an already-current database applies
// nothing and returns nil.
//
// Up takes a Postgres advisory lock (see lockKey) for the duration of the
// run and releases it before returning, so concurrent callers — goroutines
// in one process or several separate processes — serialize rather than
// race.
func Up(ctx context.Context, pool *pgxpool.Pool) error {
	provider, closeDB, err := newProvider(pool)
	if err != nil {
		return err
	}
	defer closeDB()

	if _, err := provider.Up(ctx); err != nil {
		return classify("apply migrations", err)
	}
	return nil
}

// Status reports the state of every embedded migration: applied ones with
// the time they were applied, and pending ones not yet run. Like Up, it
// holds the same advisory lock for the duration of the call, so a status
// read reflects a consistent view rather than racing a concurrent Up.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]Applied, error) {
	provider, closeDB, err := newProvider(pool)
	if err != nil {
		return nil, err
	}
	defer closeDB()

	statuses, err := provider.Status(ctx)
	if err != nil {
		return nil, classify("status", err)
	}

	applied := make([]Applied, 0, len(statuses))
	for _, s := range statuses {
		applied = append(applied, Applied{
			Version:   s.Source.Version,
			Name:      path.Base(s.Source.Path),
			Applied:   s.State == goose.StateApplied,
			AppliedAt: s.AppliedAt,
		})
	}
	return applied, nil
}

// newProvider builds a goose Provider wrapping pool, configured with the
// session-level advisory lock described on lockKey, plus a cleanup
// function that closes the *sql.DB wrapper it created (not pool itself:
// pgx's stdlib.OpenDBFromPool documents that closing the returned *sql.DB
// never closes the underlying pgxpool.Pool).
//
// Handing goose the whole pool, rather than acquiring a connection to take
// the lock ourselves, is what makes the lock actually serialize the work it
// is held around: for any one call to Provider.Up or Provider.Status goose
// checks out exactly one *sql.Conn and runs the session lock, the
// bookkeeping check and every migration statement on that same connection.
// A lock taken on a different connection from the migration would protect a
// session nothing else touches.
func newProvider(pool *pgxpool.Pool) (*goose.Provider, func(), error) {
	db := stdlib.OpenDBFromPool(pool)
	closeDB := func() { _ = db.Close() }

	provider, err := buildProvider(db)
	if err != nil {
		closeDB()
		return nil, nil, err
	}
	return provider, closeDB, nil
}

func buildProvider(db *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewPostgresSessionLocker(
		lock.WithLockID(lockKey),
		lock.WithLockTimeout(lockPollPeriodSeconds, lockMaxRetries),
	)
	if err != nil {
		// Only reachable if the fixed arguments above were ever invalid;
		// there is no runtime condition that triggers it. Still a
		// deployment-shaped defect rather than a transient one, so it
		// gets the same sentinel as classify's default case.
		return nil, fmt.Errorf("%w: migrate: build session locker: %w", domain.ErrInvalidConfig, err)
	}

	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS,
		goose.WithSessionLocker(locker),
		goose.WithTableName(versionTableName),
	)
	if err != nil {
		// Reachable if the embedded migration set is malformed — a defect
		// in the binary, not the database.
		return nil, fmt.Errorf("%w: migrate: build goose provider: %w", domain.ErrInvalidConfig, err)
	}
	return provider, nil
}

// classify maps an error returned by goose's Provider into this module's
// error taxonomy, so Up and Status never return a bare error across their
// package boundary. op names which call produced err.
//
// Two failure modes are "reachable in principle, just not right now", and
// therefore domain.ErrUnavailable — worth a caller retrying: the database
// could not be reached at all (a *pgconn.ConnectError anywhere in the
// chain), and the advisory lock could not be acquired within its timeout,
// meaning another process is still migrating. goose's session locker does
// not export a sentinel for the second: its exhausted-retries error is a
// fixed, unexported string, which is what is matched below and is pinned to
// that library version's wording.
//
// Everything else — a statement Postgres rejected, an out-of-order or
// missing-migration mismatch between the binary and the database, or a
// provider that failed to construct — means the binary's embedded schema
// does not fit this database: a deployment defect, so
// domain.ErrInvalidConfig. The underlying error stays wrapped either way.
func classify(op string, err error) error {
	var connectErr *pgconn.ConnectError
	switch {
	case errors.As(err, &connectErr):
		return fmt.Errorf("%w: migrate: %s: could not reach the database: %w", domain.ErrUnavailable, op, err)
	case strings.Contains(err.Error(), "failed to acquire lock"):
		return fmt.Errorf("%w: migrate: %s: timed out waiting for another migration to finish: %w", domain.ErrUnavailable, op, err)
	default:
		return fmt.Errorf("%w: migrate: %s: %w", domain.ErrInvalidConfig, op, err)
	}
}
