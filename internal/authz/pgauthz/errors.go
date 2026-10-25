package pgauthz

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenenai/iam/internal/domain"
)

// mapErr is the single place a Postgres/pgx-layer error becomes an error
// in this module's taxonomy. Every method in this package returns through
// it, and it is a near-copy of internal/registry/pgregistry's — copied
// rather than shared because the two packages map the same codes onto the
// same sentinels for different reasons, and a shared helper would be one
// edit away from changing both.
//
//   - pgx.ErrNoRows                 -> domain.ErrNotFound. Callers that
//     mean "no such container" wrap their own message around it.
//   - unique_violation      (23505) -> domain.ErrConflict. On this schema
//     it means a grant was written twice outside the ON CONFLICT path, or
//     two writers raced for a revision despite the lock — the second being
//     a defect that announces itself rather than silently leaving a gap.
//   - foreign_key_violation (23503) -> domain.ErrConflict. This is the
//     composite tenant keys firing: a containment edge or a grant that
//     would have crossed a tenant. Go checks for it first and returns a
//     better error; this is the guarantee behind that check.
//   - check_violation       (23514) -> domain.ErrConflict, including the
//     iam.ulid domain's format check and the grants table's
//     exactly-one-subject rule.
//   - anything else — a connection failure, a pool that cannot hand out a
//     connection, a deadline, a code this schema has no business raising
//     -> domain.ErrUnavailable.
//
// It keeps only the code and the constraint name from a *pgconn.PgError,
// never Message or Detail and never err.Error()'s own text. Postgres fills
// Detail with the offending row's actual column values, so forwarding it
// would leak a principal id, a container id or a permission out through an
// error crossing this package's boundary. The constraint name says which
// rule was broken, which is what an operator needs; the values say who it
// was about, which they do not.
func mapErr(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("%w: unique violation on constraint %q", domain.ErrConflict, pgErr.ConstraintName)
		case "23503": // foreign_key_violation
			return fmt.Errorf("%w: foreign key violation on constraint %q", domain.ErrConflict, pgErr.ConstraintName)
		case "23514": // check_violation
			return fmt.Errorf("%w: check violation on constraint %q", domain.ErrConflict, pgErr.ConstraintName)
		}
	}

	return fmt.Errorf("%w: authorization store unavailable", domain.ErrUnavailable)
}
