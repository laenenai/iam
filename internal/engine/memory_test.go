package engine_test

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/engine"
	"github.com/laenenai/iam/internal/engine/enginetest"
)

func TestMemoryEngine(t *testing.T) {
	enginetest.RunSuite(t, func(_ *testing.T) engine.Engine {
		return engine.NewMemory()
	})
}

func TestOwnerImplicationsAndInheritance(t *testing.T) {
	e := engine.NewMemory()
	ctx := context.Background()
	mustWrite(t, e, engine.Tuple{Object: "t/folder/root", Relation: domain.Owner, Subject: "t/user/u1"})
	mustWrite(t, e, engine.Tuple{Object: "t/document/d1", Relation: domain.Parent, Subject: "t/folder/root"})
	for _, rel := range []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer, domain.CanShare, domain.CanDelete} {
		ok, _, err := e.Check(ctx, domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}, rel, "t/document/d1")
		if err != nil || !ok {
			t.Fatalf("%s: %v %v", rel, ok, err)
		}
	}
}
