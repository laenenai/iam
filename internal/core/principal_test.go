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

func TestResolvePrincipalReturnsLinkedPrincipal(t *testing.T) {
	ctx := context.Background()
	svc, _, tenant := bootstrap(t)

	got, err := svc.ResolvePrincipal(ctx, identityAdapter(), ResolvePrincipalRequest{
		Tenant:     tenant,
		Issuer:     "issuer",
		ExternalID: "external-u1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal.URN != mustUser(t, tenant, "u1").URN {
		t.Fatalf("principal = %s, want %s", got.Principal.URN, mustUser(t, tenant, "u1").URN)
	}
	if !got.Principal.Live {
		t.Fatal("resolved principal is not live")
	}
	if got.Revision == 0 {
		t.Fatal("resolved principal has no revision")
	}
}

func TestResolvePrincipalRequiresIdentityAdapter(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)

	_, err := svc.ResolvePrincipal(ctx, owner, ResolvePrincipalRequest{
		Tenant:     tenant,
		Issuer:     "issuer",
		ExternalID: "external-u1",
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
}

func TestResolvePrincipalUnknownExternalID(t *testing.T) {
	ctx := context.Background()
	svc, _, tenant := bootstrap(t)

	_, err := svc.ResolvePrincipal(ctx, identityAdapter(), ResolvePrincipalRequest{
		Tenant:     tenant,
		Issuer:     "issuer",
		ExternalID: "missing",
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolvePrincipalTenantIsolation(t *testing.T) {
	ctx := context.Background()
	svc := newTestIAM(t)
	admin := deploymentAdmin()
	ownerA, ownerB := mustUser(t, "a", "u1"), mustUser(t, "b", "u1")
	mustTenant(t, svc, admin, "a", ownerA)
	mustTenant(t, svc, admin, "b", ownerB)
	linkAsIdentity(t, svc, "a", "issuer", "shared-external", ownerA)
	linkAsIdentity(t, svc, "b", "issuer", "shared-external", ownerB)

	for _, tc := range []struct {
		tenant domain.TenantID
		want   domain.URN
	}{{"a", ownerA.URN}, {"b", ownerB.URN}} {
		actor := domain.Actor{ID: "identity-adapter", Tenant: tc.tenant, Role: domain.RoleIdentityAdapter}
		got, err := svc.ResolvePrincipal(ctx, actor, ResolvePrincipalRequest{
			Tenant:     tc.tenant,
			Issuer:     "issuer",
			ExternalID: "shared-external",
		})
		if err != nil {
			t.Fatal(err)
		}
		if got.Principal.URN != tc.want {
			t.Fatalf("%s principal = %s, want %s", tc.tenant, got.Principal.URN, tc.want)
		}
	}

	_, err := svc.ResolvePrincipal(ctx, domain.Actor{ID: "identity-adapter", Tenant: "b", Role: domain.RoleIdentityAdapter}, ResolvePrincipalRequest{
		Tenant:     "a",
		Issuer:     "issuer",
		ExternalID: "shared-external",
	})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("cross-tenant err = %v, want ErrForbidden", err)
	}
}

func TestResolvePrincipalReturnsDeactivatedPrincipal(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	if _, err := svc.DeactivatePrincipal(ctx, tenantAdmin(tenant, owner.Subject), DeactivatePrincipalRequest{
		Tenant:  tenant,
		Subject: owner.Subject,
		Source:  domain.SourceTenant,
		Reason:  "away",
	}); err != nil {
		t.Fatal(err)
	}

	got, err := svc.ResolvePrincipal(ctx, identityAdapter(), ResolvePrincipalRequest{
		Tenant:     tenant,
		Issuer:     "issuer",
		ExternalID: "external-u1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Principal.Live {
		t.Fatal("deactivated principal resolved live")
	}
}

func TestResolvePrincipalDeletedLinkIsNotFound(t *testing.T) {
	ctx := context.Background()
	svc, owner, tenant := bootstrap(t)
	if _, err := svc.DeletePrincipal(ctx, identityAdapter(), DeletePrincipalRequest{
		Tenant:  tenant,
		Subject: owner.Subject,
		Reason:  "offboard",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := svc.ResolvePrincipal(ctx, identityAdapter(), ResolvePrincipalRequest{
		Tenant:     tenant,
		Issuer:     "issuer",
		ExternalID: "external-u1",
	})
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestResolvePrincipalRejectsEmptyExternalIdentity(t *testing.T) {
	ctx := context.Background()
	svc, _, tenant := bootstrap(t)

	_, err := svc.ResolvePrincipal(ctx, identityAdapter(), ResolvePrincipalRequest{Tenant: tenant})
	if !errors.Is(err, domain.ErrInvalidSubject) {
		t.Fatalf("err = %v, want ErrInvalidSubject", err)
	}
}

func TestGlobalDeleteFansOutToEveryLinkedTenant(t *testing.T) {
	ctx := context.Background()
	svc := newTestIAM(t)
	admin := deploymentAdmin()
	ownerA, ownerB := mustUser(t, "a", "u1"), mustUser(t, "b", "u1")
	mustTenant(t, svc, admin, "a", ownerA)
	mustTenant(t, svc, admin, "b", ownerB)
	linkAsIdentity(t, svc, "a", "issuer", "external-delete", ownerA)
	linkAsIdentity(t, svc, "b", "issuer", "external-delete", ownerB)

	scoped := domain.Actor{ID: "scoped-identity", Tenant: "a", Role: domain.RoleIdentityAdapter}
	if _, err := svc.DeletePrincipal(ctx, scoped, DeletePrincipalRequest{Tenant: "a", Subject: ownerA}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("tenant-scoped global delete: %v", err)
	}
	if _, err := svc.DeactivatePrincipal(ctx, scoped, DeactivatePrincipalRequest{Tenant: "a", Subject: ownerA, Source: domain.SourceGlobal, Reason: "test"}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("tenant-scoped global deactivation: %v", err)
	}

	if _, err := svc.DeletePrincipal(ctx, identityAdapter(), DeletePrincipalRequest{Tenant: "a", Subject: ownerA, Reason: "offboard"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		tenant string
		subj   domain.Subject
	}{{"a", ownerA}, {"b", ownerB}} {
		d, err := svc.Check(ctx, ownerOfTenant(domain.TenantID(tc.tenant)), CheckRequest{Tenant: domain.TenantID(tc.tenant), Subject: tc.subj, Object: mustRoot(t, svc, domain.TenantID(tc.tenant)), Relation: domain.Owner})
		if err != nil || d.Allowed {
			t.Fatalf("%s after global delete: %#v %v", tc.tenant, d, err)
		}
		if p, ok := svc.store.Principal(domain.TenantID(tc.tenant), tc.subj); !ok || !p.Deleted {
			t.Fatalf("%s principal not deleted: %#v", tc.tenant, p)
		}
	}
}
