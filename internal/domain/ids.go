package domain

import (
	"crypto/rand"
	"fmt"

	"github.com/oklog/ulid/v2"
)

// GrantID identifies one issued grant for its whole lifetime.
type GrantID string

// NewGrantID mints a ULID grant id at the clock time.
func NewGrantID(clock Clock) (GrantID, error) {
	if clock == nil {
		return "", fmt.Errorf("%w: nil clock", ErrIDGeneration)
	}
	id, err := ulid.New(ulid.Timestamp(clock.Now()), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrIDGeneration, err)
	}
	return GrantID(id.String()), nil
}
