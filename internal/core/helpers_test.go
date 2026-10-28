package core

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/domain"
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
