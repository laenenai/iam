package domain

import "fmt"

// ActorRole identifies the authority a caller presents on a command.
type ActorRole string

// Actor roles.
const (
	RoleUser            ActorRole = "user"
	RoleAgent           ActorRole = "agent"
	RoleTenantAdmin     ActorRole = "tenant_admin"
	RoleDeploymentAdmin ActorRole = "deployment_admin"
	RoleIdentityAdapter ActorRole = "identity_adapter"
	RoleAuditor         ActorRole = "auditor"
)

func (r ActorRole) valid() bool {
	switch r {
	case RoleUser, RoleAgent, RoleTenantAdmin, RoleDeploymentAdmin, RoleIdentityAdapter, RoleAuditor:
		return true
	default:
		return false
	}
}

// Actor is the authenticated caller of a command or query.
type Actor struct {
	ID      string
	Subject Subject
	Tenant  TenantID
	Role    ActorRole
}

// Validate checks the actor identity, role and tenant.
func (a Actor) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidActor)
	}
	if !a.Role.valid() {
		return fmt.Errorf("%w: role %q", ErrInvalidActor, a.Role)
	}

	switch a.Role {
	case RoleUser, RoleAgent, RoleTenantAdmin:
		if _, err := ParseTenantID(string(a.Tenant)); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidActor, err)
		}
		if err := a.Subject.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidActor, err)
		}
		if a.Subject.URN.Tenant() != a.Tenant {
			return fmt.Errorf("%w: subject tenant %q does not match %q", ErrInvalidActor, a.Subject.URN.Tenant(), a.Tenant)
		}
		switch a.Role {
		case RoleUser:
			if a.Subject.Kind != SubjectUser {
				return fmt.Errorf("%w: user role requires a user subject", ErrInvalidActor)
			}
		case RoleAgent:
			if a.Subject.Kind != SubjectAgent {
				return fmt.Errorf("%w: agent role requires an agent subject", ErrInvalidActor)
			}
		case RoleTenantAdmin:
			if a.Subject.Kind != SubjectUser {
				return fmt.Errorf("%w: tenant admin requires a user subject", ErrInvalidActor)
			}
		}

	case RoleDeploymentAdmin:
		if a.Tenant != "" {
			if _, err := ParseTenantID(string(a.Tenant)); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidActor, err)
			}
		}

	case RoleIdentityAdapter:
		if a.Tenant != "" {
			if _, err := ParseTenantID(string(a.Tenant)); err != nil {
				return fmt.Errorf("%w: %w", ErrInvalidActor, err)
			}
		}

	case RoleAuditor:
		if _, err := ParseTenantID(string(a.Tenant)); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidActor, err)
		}
	}

	if a.Subject.URN != "" {
		if err := a.Subject.Validate(); err != nil {
			return fmt.Errorf("%w: %w", ErrInvalidActor, err)
		}
		if a.Tenant != "" && a.Subject.URN.Tenant() != a.Tenant {
			return fmt.Errorf("%w: subject tenant does not match actor tenant", ErrInvalidActor)
		}
	}

	return nil
}
