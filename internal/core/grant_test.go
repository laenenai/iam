package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

func TestGrantInheritanceAndRevocation(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	g, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.Viewer})
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer})
	if err != nil || !d.Allowed || d.Reason != domain.ReasonInherited {
		t.Fatalf("inherited: %#v %v", d, err)
	}
	if _, err := svc.Revoke(ctx, owner, RevokeRequest{Tenant: tenant, GrantID: g.GrantID}); err != nil {
		t.Fatal(err)
	}
	d, _ = svc.Check(ctx, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer})
	if d.Allowed {
		t.Fatal("revoked grant still allows")
	}
}

func TestCanDeleteRules(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", "laenen/root/root")
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	userActor := ownerOf(svc, tenant, user)

	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.CanDelete}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: folder.URN, Relation: domain.CanDelete}); !d.Allowed {
		t.Fatal("direct can_delete denied")
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.CanDelete}); d.Allowed {
		t.Fatal("can_delete inherited")
	}
	if _, err := svc.Grant(ctx, userActor, GrantRequest{Tenant: tenant, Object: doc.URN, Subject: user, Relation: domain.CanDelete}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-owner granted can_delete: %v", err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: doc.URN, Subject: user, Relation: domain.CanShare}); !errors.Is(err, domain.ErrInvalidRelation) {
		t.Fatalf("direct can_share: %v", err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: doc.URN, Subject: user, Relation: domain.CanDelete}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.CanDelete}); !d.Allowed {
		t.Fatal("direct can_delete on object denied")
	}
}

func TestGrantValidation(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	node := mustNode(t, svc, owner, tenant, "laenen/document/d1", "laenen/root/root")
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	unlinked := mustUser(t, tenant, "u3")
	agent := domain.Subject{URN: "laenen/agent/a1", Kind: domain.SubjectAgent}

	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Viewer}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Viewer}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate grant: %v", err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: unlinked, Relation: domain.Editor}); !errors.Is(err, domain.ErrUnauthorized) {
		t.Fatalf("unlinked subject: %v", err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: agent, Relation: domain.Viewer}); !errors.Is(err, domain.ErrUnsupported) {
		t.Fatalf("agent subject: %v", err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.CanView}); !errors.Is(err, domain.ErrInvalidRelation) {
		t.Fatalf("computed relation: %v", err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: "laenen/document/missing", Subject: user, Relation: domain.Viewer}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing object: %v", err)
	}
	if _, err := svc.Grant(ctx, ownerOf(svc, tenant, user), GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Editor}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-owner grant: %v", err)
	}

	g := mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Commenter})
	if _, err := svc.Revoke(ctx, ownerOf(svc, tenant, user), RevokeRequest{Tenant: tenant, GrantID: g.GrantID}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-owner revoke: %v", err)
	}
	if _, err := svc.Revoke(ctx, owner, RevokeRequest{Tenant: tenant, GrantID: g.GrantID}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Grant(ctx, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Commenter}); err != nil {
		t.Fatalf("re-grant after revoke: %v", err)
	}
}

func TestCheckAuthority(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	node := mustNode(t, svc, owner, tenant, "laenen/document/d1", "laenen/root/root")
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Viewer})

	if d := mustCheck(t, svc, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); !d.Allowed || d.Revision == 0 {
		t.Fatalf("self check: %#v", d)
	}
	if _, err := svc.Check(ctx, owner, CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("acted for another subject: %v", err)
	}

	admin := domain.Actor{ID: "tenant-admin", Tenant: tenant, Role: domain.RoleTenantAdmin, Subject: owner.Subject}
	if d := mustCheck(t, svc, admin, CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); !d.Allowed {
		t.Fatal("tenant admin check denied")
	}
	auditor := domain.Actor{ID: "auditor", Tenant: tenant, Role: domain.RoleAuditor}
	if d := mustCheck(t, svc, auditor, CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); !d.Allowed {
		t.Fatal("auditor check denied")
	}

	unlinked := mustUser(t, tenant, "u3")
	if d := mustCheck(t, svc, admin, CheckRequest{Tenant: tenant, Subject: unlinked, Object: node.URN, Relation: domain.Viewer}); d.Allowed || d.Reason != domain.ReasonNoGrant {
		t.Fatalf("unlinked subject: %#v", d)
	}
	agent := domain.Subject{URN: "laenen/agent/a1", Kind: domain.SubjectAgent}
	if _, err := svc.Check(ctx, admin, CheckRequest{Tenant: tenant, Subject: agent, Object: node.URN, Relation: domain.Viewer}); !errors.Is(err, domain.ErrUnsupported) {
		t.Fatalf("agent subject: %v", err)
	}
	if _, err := svc.Check(ctx, ownerOf(svc, "other", mustUser(t, "other", "u1")), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); err == nil {
		t.Fatal("cross-tenant actor accepted")
	}
}
