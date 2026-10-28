package core

import (
	"context"
	"errors"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

func TestCreateTenantAndPublishKind(t *testing.T) {
	svc := newTestIAM(t)
	admin := domain.Actor{ID: "deployment-admin", Role: domain.RoleDeploymentAdmin}
	owner, _ := domain.NewUserSubject("laenen", "u1")
	tenant, err := svc.CreateTenant(context.Background(), admin, CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: owner})
	if err != nil {
		t.Fatal(err)
	}
	if tenant.Root != "laenen/root/root" || tenant.OwnerGrant == "" {
		t.Fatalf("%#v", tenant)
	}
	if _, err := svc.CreateTenant(context.Background(), admin, CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: owner}); !errors.Is(err, domain.ErrConflict) {
		t.Fatal("duplicate tenant")
	}
}

func TestNewMemorySeedsDefaultModel(t *testing.T) {
	svc := newTestIAM(t)
	if got := svc.store.ModelVersion(); got != 1 {
		t.Fatalf("model version=%d", got)
	}
	for _, kind := range domain.DefaultKinds() {
		if _, ok := svc.store.Kind(kind.Name); !ok {
			t.Fatalf("default kind %s not published", kind.Name)
		}
	}
	if got, want := svc.projector.Applied(eventlogWorkspace()), domain.Revision(len(domain.DefaultKinds())+1); got != want {
		t.Fatalf("platform applied=%d want=%d", got, want)
	}
}

func TestCreateTenantRules(t *testing.T) {
	ctx := context.Background()
	svc := newTestIAM(t)
	owner, _ := domain.NewUserSubject("laenen", "u1")

	if _, err := svc.CreateTenant(ctx, ownerOfTenant("laenen"), CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: owner}); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("non-admin: %v", err)
	}
	if _, err := svc.CreateTenant(ctx, deploymentAdmin(), CreateTenantRequest{Tenant: "Laenen", RootID: "root", FirstOwner: owner}); !errors.Is(err, domain.ErrInvalidTenant) {
		t.Fatalf("bad tenant: %v", err)
	}
	group, _ := domain.NewGroupSubject("laenen", "g1")
	if _, err := svc.CreateTenant(ctx, deploymentAdmin(), CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: group}); !errors.Is(err, domain.ErrInvalidSubject) {
		t.Fatalf("group owner: %v", err)
	}
	if _, err := svc.CreateTenant(ctx, deploymentAdmin(), CreateTenantRequest{Tenant: "laenen", RootID: "root", FirstOwner: owner}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateTenant(ctx, deploymentAdmin(), CreateTenantRequest{Tenant: "laenen", RootID: "other", FirstOwner: owner}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second root: %v", err)
	}
}
