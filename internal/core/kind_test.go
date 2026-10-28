package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

func eventlogWorkspace() eventlog.Workspace {
	return eventlog.PlatformWorkspace
}

func TestRegisterKindStagesAndPublishes(t *testing.T) {
	ctx := context.Background()
	svc := newTestIAM(t)
	admin := deploymentAdmin()
	graph := domain.KindSpec{Name: "graph", Relations: []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer}}

	if err := svc.RegisterKind(ctx, admin, RegisterKindRequest{Kind: graph}); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.store.PendingKind("graph"); !ok {
		t.Fatal("kind not pending")
	}
	if _, ok := svc.store.Kind("graph"); ok {
		t.Fatal("kind published early")
	}
	if err := svc.RegisterKind(ctx, admin, RegisterKindRequest{Kind: graph}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate pending: %v", err)
	}
	if err := svc.RegisterKind(ctx, admin, RegisterKindRequest{Kind: domain.KindSpec{Name: domain.RootKind, ContainsAny: true}}); !errors.Is(err, domain.ErrInvalidKind) {
		t.Fatalf("root: %v", err)
	}
	if err := svc.RegisterKind(ctx, ownerOfTenant("laenen"), RegisterKindRequest{Kind: graph}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-admin: %v", err)
	}

	if err := svc.PublishModel(ctx, admin, PublishModelRequest{Version: 1}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale version: %v", err)
	}
	if err := svc.PublishModel(ctx, admin, PublishModelRequest{Version: 2}); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.store.Kind("graph"); !ok {
		t.Fatal("kind not published")
	}
	if got := svc.store.ModelVersion(); got != 2 {
		t.Fatalf("model version=%d", got)
	}
	if err := svc.PublishModel(ctx, admin, PublishModelRequest{Version: 3}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("empty publish: %v", err)
	}
}
