package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

func TestRegisterNodeRules(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	root := mustRoot(t, svc, tenant)

	n, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/folder/home", Parent: root})
	if err != nil {
		t.Fatal(err)
	}
	if !allowed(t, svc, owner.Subject, domain.Owner, n.Node.URN) {
		t.Fatal("creator must be owner")
	}
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/folder/home", Parent: root}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate urn: %v", err)
	}
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/root/other", Parent: root}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("second root: %v", err)
	}

	other := mustUser(t, "other", "u1")
	mustTenant(t, svc, deploymentAdmin(), "other", other)
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/document/cross", Parent: "other/root/root"}); err == nil {
		t.Fatal("cross-tenant parent accepted")
	}

	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", root)
	if err := svc.DeleteNode(ctx, owner, DeleteNodeRequest{Tenant: tenant, URN: doc.URN, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: doc.URN, Parent: root}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("deleted urn reused: %v", err)
	}
}

func TestRegisterNodeContainment(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	root := mustRoot(t, svc, tenant)

	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", root)
	mustNode(t, svc, owner, tenant, "laenen/album/2026", folder.URN)
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/message/msg-1", Parent: folder.URN}); !errors.Is(err, domain.ErrInvalidKind) {
		t.Fatalf("folder contained a message: %v", err)
	}
	message := mustNode(t, svc, owner, tenant, "laenen/message/msg-2", root)
	if _, err := svc.RegisterNode(ctx, owner, RegisterNodeRequest{Tenant: tenant, URN: "laenen/photo/p1", Parent: message.URN}); !errors.Is(err, domain.ErrInvalidKind) {
		t.Fatalf("message contained a photo: %v", err)
	}
}

func TestDeleteNodeRules(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	root := mustRoot(t, svc, tenant)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", root)
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)

	if err := svc.DeleteNode(ctx, owner, DeleteNodeRequest{Tenant: tenant, URN: folder.URN, Reason: "test"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("deleted a parent with a live child: %v", err)
	}
	if err := svc.DeleteNode(ctx, owner, DeleteNodeRequest{Tenant: tenant, URN: root, Reason: "test"}); err == nil {
		t.Fatal("deleted the root")
	}
	if err := svc.DeleteNode(ctx, owner, DeleteNodeRequest{Tenant: tenant, URN: doc.URN, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	if node, ok := svc.store.Node(tenant, doc.URN); !ok || node.Live {
		t.Fatalf("node not tombstoned: %#v", node)
	}
}

func TestDeleteSubtree(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	root := mustRoot(t, svc, tenant)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", root)
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)

	if err := svc.DeleteSubtree(ctx, owner, DeleteSubtreeRequest{Tenant: tenant, URN: folder.URN, Reason: "test"}); err != nil {
		t.Fatal(err)
	}
	for _, urn := range []domain.URN{folder.URN, doc.URN} {
		if node, ok := svc.store.Node(tenant, urn); !ok || node.Live {
			t.Fatalf("%s not tombstoned: %#v", urn, node)
		}
		if allowed(t, svc, owner.Subject, domain.Viewer, urn) {
			t.Fatalf("%s still visible", urn)
		}
	}
	if err := svc.DeleteSubtree(ctx, owner, DeleteSubtreeRequest{Tenant: tenant, URN: root, Reason: "test"}); err == nil {
		t.Fatal("deleted the root subtree")
	}
}
