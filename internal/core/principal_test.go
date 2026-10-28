package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

func TestGlobalDeactivationFansOutAndSurvivesRelink(t *testing.T) {
	ctx := context.Background()
	svc := newTestIAM(t)
	admin := deploymentAdmin()
	ownerA, ownerB := mustUser(t, "a", "u1"), mustUser(t, "b", "u1")
	mustTenant(t, svc, admin, "a", ownerA)
	mustTenant(t, svc, admin, "b", ownerB)
	linkAsIdentity(t, svc, "a", "issuer", "external-1", ownerA)
	linkAsIdentity(t, svc, "b", "issuer", "external-1", ownerB)
	if _, err := svc.DeactivatePrincipal(ctx, identityAdapter(), DeactivatePrincipalRequest{Tenant: "a", Subject: ownerA, Source: domain.SourceGlobal, Reason: "left"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant string
		subj   domain.Subject
	}{{"a", ownerA}, {"b", ownerB}} {
		d, _ := svc.Check(ctx, ownerOfTenant(domain.TenantID(tc.tenant)), CheckRequest{Tenant: domain.TenantID(tc.tenant), Subject: tc.subj, Object: mustRoot(t, svc, domain.TenantID(tc.tenant)), Relation: domain.Owner})
		if d.Allowed {
			t.Fatalf("global deactivation missed %s", tc.tenant)
		}
	}
	late := mustUser(t, "c", "u1")
	mustTenant(t, svc, admin, "c", late)
	linkAsIdentity(t, svc, "c", "issuer", "external-1", late)
	d, _ := svc.Check(ctx, ownerOfTenant("c"), CheckRequest{Tenant: "c", Subject: late, Object: mustRoot(t, svc, "c"), Relation: domain.Owner})
	if d.Allowed {
		t.Fatal("late link started live")
	}
}

func TestPrincipalLivenessRestoresEveryArm(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	folder := mustNode(t, svc, owner, tenant, "laenen/folder/home", mustRoot(t, svc, tenant))
	doc := mustNode(t, svc, owner, tenant, "laenen/document/tax", folder.URN)

	mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: doc.URN, Subject: user, Relation: domain.Viewer})
	group, err := svc.CreateGroup(ctx, owner, CreateGroupRequest{Tenant: tenant, GroupID: "g1", Name: "Family"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddGroupMember(ctx, owner, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: doc.URN, Subject: domain.Subject{URN: group.Group.URN, Kind: domain.SubjectGroup}, Relation: domain.Commenter})
	mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: folder.URN, Subject: user, Relation: domain.Viewer})

	userActor := ownerOf(svc, tenant, user)
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer}); !d.Allowed {
		t.Fatalf("baseline denied: %#v", d)
	}

	tenantAdmin := domain.Actor{ID: "tenant-admin", Tenant: tenant, Role: domain.RoleTenantAdmin, Subject: owner.Subject}
	if _, err := svc.DeactivatePrincipal(ctx, tenantAdmin, DeactivatePrincipalRequest{Tenant: tenant, Subject: user, Source: domain.SourceTenant, Reason: "away"}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer}); d.Allowed {
		t.Fatal("tenant deactivation did not deny all arms")
	}
	if _, err := svc.ReactivatePrincipal(ctx, tenantAdmin, ReactivatePrincipalRequest{Tenant: tenant, Subject: user, Source: domain.SourceTenant, Reason: "back"}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer}); !d.Allowed {
		t.Fatal("reactivation did not restore access without re-granting")
	}

	if _, err := svc.DeactivatePrincipal(ctx, identityAdapter(), DeactivatePrincipalRequest{Tenant: tenant, Subject: user, Source: domain.SourceGlobal, Reason: "left"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ReactivatePrincipal(ctx, tenantAdmin, ReactivatePrincipalRequest{Tenant: tenant, Subject: user, Source: domain.SourceTenant, Reason: "back"}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer}); d.Allowed {
		t.Fatal("tenant reactivation overrode the global deactivation")
	}
	if _, err := svc.ReactivatePrincipal(ctx, identityAdapter(), ReactivatePrincipalRequest{Tenant: tenant, Subject: user, Source: domain.SourceGlobal, Reason: "returned"}); err != nil {
		t.Fatal(err)
	}
	if d := mustCheck(t, svc, userActor, CheckRequest{Tenant: tenant, Subject: user, Object: doc.URN, Relation: domain.Viewer}); !d.Allowed {
		t.Fatal("global reactivation did not restore access")
	}
}

func TestDeletePrincipalCleanupAndRelink(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	user := mustUser(t, tenant, "u2")
	linkAsIdentity(t, svc, tenant, "issuer", "external-2", user)
	userActor := ownerOf(svc, tenant, user)
	group, err := svc.CreateGroup(ctx, userActor, CreateGroupRequest{Tenant: tenant, GroupID: "g2", Name: "Friends"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddGroupMember(ctx, userActor, AddGroupMemberRequest{Tenant: tenant, Group: group.Group.URN, Member: user}); err != nil {
		t.Fatal(err)
	}
	node := mustNode(t, svc, owner, tenant, "laenen/document/d1", mustRoot(t, svc, tenant))
	grant := mustGrant(t, svc, owner, GrantRequest{Tenant: tenant, Object: node.URN, Subject: user, Relation: domain.Viewer})

	if _, err := svc.DeletePrincipal(ctx, ownerOfTenant(tenant), DeletePrincipalRequest{Tenant: tenant, Subject: user, Reason: "test"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("tenant admin deleted a principal: %v", err)
	}
	if _, err := svc.DeletePrincipal(ctx, identityAdapter(), DeletePrincipalRequest{Tenant: tenant, Subject: user, Reason: "offboard"}); err != nil {
		t.Fatal(err)
	}
	if g, ok := svc.store.Grant(tenant, grant.GrantID); !ok || g.Live {
		t.Fatalf("direct grant survived deletion: %#v", g)
	}
	if len(svc.store.GroupMembers(tenant, group.Group.URN)) != 0 {
		t.Fatal("membership survived deletion")
	}
	if g, ok := svc.store.Group(tenant, group.Group.URN); !ok || g.Admin.URN != "" {
		t.Fatalf("admin edge survived deletion: %#v", g)
	}
	if d := mustCheck(t, svc, ownerOf(svc, tenant, user), CheckRequest{Tenant: tenant, Subject: user, Object: node.URN, Relation: domain.Viewer}); d.Allowed {
		t.Fatal("deleted principal still allowed")
	}

	_, err = svc.LinkPrincipal(ctx, identityAdapter(), LinkPrincipalRequest{Tenant: tenant, Issuer: "issuer", ExternalID: "external-2", Subject: user})
	if !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("retired urn relinked: %v", err)
	}
	fresh := mustUser(t, tenant, "u3")
	if _, err := svc.LinkPrincipal(ctx, identityAdapter(), LinkPrincipalRequest{Tenant: tenant, Issuer: "issuer", ExternalID: "external-2", Subject: fresh}); err != nil {
		t.Fatalf("fresh urn relink: %v", err)
	}
}

func TestPrincipalAuthority(t *testing.T) {
	ctx := context.Background()
	svc, _, tenant := bootstrap(t)
	user := mustUser(t, tenant, "u2")
	linkUser(t, svc, tenant, user)
	other := mustUser(t, tenant, "u3")

	if _, err := svc.LinkPrincipal(ctx, ownerOf(svc, tenant, user), LinkPrincipalRequest{Tenant: tenant, Issuer: "issuer", ExternalID: "external-4", Subject: other}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("user linked a principal: %v", err)
	}
	if _, err := svc.DeactivatePrincipal(ctx, ownerOf(svc, tenant, user), DeactivatePrincipalRequest{Tenant: tenant, Subject: other, Source: domain.SourceGlobal, Reason: "test"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("user issued global deactivation: %v", err)
	}
	agent := domain.Subject{URN: "laenen/agent/a1", Kind: domain.SubjectAgent}
	if _, err := svc.LinkPrincipal(ctx, identityAdapter(), LinkPrincipalRequest{Tenant: tenant, Issuer: "issuer", ExternalID: "external-5", Subject: agent}); !errors.Is(err, domain.ErrUnsupported) {
		t.Fatalf("agent principal: %v", err)
	}
}
