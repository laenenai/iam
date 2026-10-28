// Package engine defines the relation-tuple engine port and a reference
// in-memory implementation.
package engine

import (
	"context"

	"github.com/laenenai/iam/internal/domain"
)

// Tuple is one relation edge. A userset tuple names a group and expands to the
// group's direct members during a check.
type Tuple struct {
	Object   domain.URN
	Relation domain.Relation
	Subject  domain.URN
	Userset  bool
}

// Engine is the derived authorization index. The projector is its only writer.
type Engine interface {
	Write(ctx context.Context, tuples ...Tuple) error
	Delete(ctx context.Context, tuples ...Tuple) error
	Check(ctx context.Context, subject domain.Subject, relation domain.Relation, object domain.URN) (bool, domain.Reason, error)
}
