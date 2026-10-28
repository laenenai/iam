package core

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

func newTestIAM(t *testing.T) *IAM {
	t.Helper()
	svc, err := NewMemory(context.Background(), Config{Clock: domain.FixedClock{}})
	if err != nil {
		t.Fatalf("new memory iam: %v", err)
	}
	return svc
}

func deploymentAdmin() domain.Actor {
	return domain.Actor{ID: "deployment-admin", Role: domain.RoleDeploymentAdmin}
}

func identityAdapter() domain.Actor {
	return domain.Actor{ID: "identity-adapter", Role: domain.RoleIdentityAdapter}
}

func mustUser(t *testing.T, tenant domain.TenantID, id string) domain.Subject {
	t.Helper()
	user, err := domain.NewUserSubject(tenant, id)
	if err != nil {
		t.Fatalf("user %s/%s: %v", tenant, id, err)
	}
	return user
}

func mustTenant(t *testing.T, svc *IAM, admin domain.Actor, tenant domain.TenantID, owner domain.Subject) Tenant {
	t.Helper()
	created, err := svc.CreateTenant(context.Background(), admin, CreateTenantRequest{
		Tenant:     tenant,
		RootID:     "root",
		FirstOwner: owner,
	})
	if err != nil {
		t.Fatalf("create tenant %s: %v", tenant, err)
	}
	return created
}

func ownerOf(_ *IAM, tenant domain.TenantID, user domain.Subject) domain.Actor {
	return domain.Actor{ID: "actor:" + string(user.URN), Tenant: tenant, Role: domain.RoleUser, Subject: user}
}

func ownerOfTenant(tenant domain.TenantID) domain.Actor {
	return ownerOf(nil, tenant, domain.Subject{
		URN:  domain.URN(tenant.String() + "/user/u1"),
		Kind: domain.SubjectUser,
	})
}

func linkAsIdentity(t *testing.T, svc *IAM, tenant domain.TenantID, issuer, externalID string, user domain.Subject) {
	t.Helper()
	ws := eventlog.TenantWorkspace(tenant)
	if _, err := svc.appendEvents(context.Background(), ws, identityAdapter(), "LinkPrincipal", domain.PrincipalLinked{
		Issuer:     issuer,
		ExternalID: externalID,
		Subject:    user,
	}); err != nil {
		t.Fatalf("append link %s: %v", user.URN, err)
	}
	if err := svc.project(context.Background(), ws); err != nil {
		t.Fatalf("project link %s: %v", user.URN, err)
	}
}

func linkUser(t *testing.T, svc *IAM, tenant domain.TenantID, user domain.Subject) {
	t.Helper()
	linkAsIdentity(t, svc, tenant, "issuer", "external:"+string(user.URN), user)
}

func bootstrap(t *testing.T) (*IAM, domain.Actor, domain.TenantID) {
	t.Helper()
	svc := newTestIAM(t)
	owner := mustUser(t, "laenen", "u1")
	mustTenant(t, svc, deploymentAdmin(), "laenen", owner)
	linkAsIdentity(t, svc, "laenen", "issuer", "external-u1", owner)
	return svc, ownerOf(svc, "laenen", owner), "laenen"
}

func mustNode(t *testing.T, svc *IAM, actor domain.Actor, tenant domain.TenantID, urn domain.URN, parent domain.URN) domain.Node {
	t.Helper()
	result, err := svc.RegisterNode(context.Background(), actor, RegisterNodeRequest{Tenant: tenant, URN: urn, Parent: parent})
	if err != nil {
		t.Fatalf("register node %s: %v", urn, err)
	}
	return result.Node
}

func mustRoot(t *testing.T, svc *IAM, tenant domain.TenantID) domain.URN {
	t.Helper()
	for _, node := range svc.store.Nodes(tenant) {
		if node.Kind == domain.RootKind {
			return node.URN
		}
	}
	t.Fatalf("tenant %s has no root", tenant)
	return ""
}

func allowed(t *testing.T, svc *IAM, subject domain.Subject, relation domain.Relation, object domain.URN) bool {
	t.Helper()
	ok, _, err := svc.engine.Check(context.Background(), subject, relation, object)
	if err != nil {
		t.Fatalf("check %s %s: %v", relation, object, err)
	}
	return ok
}

func mustGrant(t *testing.T, svc *IAM, actor domain.Actor, req GrantRequest) GrantResult {
	t.Helper()
	result, err := svc.Grant(context.Background(), actor, req)
	if err != nil {
		t.Fatalf("grant %s on %s: %v", req.Relation, req.Object, err)
	}
	return result
}

func mustCheck(t *testing.T, svc *IAM, actor domain.Actor, req CheckRequest) Decision {
	t.Helper()
	decision, err := svc.Check(context.Background(), actor, req)
	if err != nil {
		t.Fatalf("check %s on %s: %v", req.Relation, req.Object, err)
	}
	return decision
}
