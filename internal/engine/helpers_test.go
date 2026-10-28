package engine_test

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/engine"
)

func mustWrite(t *testing.T, e engine.Engine, tuples ...engine.Tuple) {
	t.Helper()
	if err := e.Write(context.Background(), tuples...); err != nil {
		t.Fatalf("write: %v", err)
	}
}
