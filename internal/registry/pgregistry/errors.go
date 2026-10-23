package pgregistry

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/laenenai/iam/internal/domain"
)

// mapErr is the single place a Postgres/pgx-layer error becomes an error
// in this module's taxonomy. Every method in this package returns through
// it:
//
//   - pgx.ErrNoRows               -> domain.ErrNotFound (callers that mean
//     "no such principal" substitute their own sentinel before calling)
//   - unique_violation     (23505) -> domain.ErrConflict
//   - foreign_key_violation (23503) -> domain.ErrConflict
//   - check_violation      (23514) -> domain.ErrConflict
//   - anything else — a connection failure, a pool that cannot hand out a
//     connection, a context deadline, a code this schema has no business
//     raising -> domain.ErrUnavailable
//
// It keeps only pgErr.Code and pgErr.ConstraintName from a
// *pgconn.PgError, never its Message or Detail and never err.Error()'s own
// text. Postgres fills Detail with the offending row's actual column
// values ("Key (tenant_id, issuer, subject)=(…, https://idp.example,
// anne@example.test) already exists."), so forwarding it verbatim would
// leak an external subject — a person's identity at their identity
// provider — out through an error crossing this package's boundary. The
// constraint name says what rule was broken, which is what an operator
// needs; the values say who it was about, which they do not.
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

	return fmt.Errorf("%w: registry store unavailable", domain.ErrUnavailable)
}
