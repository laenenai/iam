package core

import (
	"context"
	"fmt"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

// LinkPrincipalRequest maps an external identity to a tenant principal.
type LinkPrincipalRequest struct {
	Tenant     domain.TenantID
	Issuer     string
	ExternalID string
	Subject    domain.Subject
}

// ResolvePrincipalRequest looks up a tenant principal by external identity.
type ResolvePrincipalRequest struct {
	Tenant     domain.TenantID
	Issuer     string
	ExternalID string
}

// PrincipalResult is the linked principal and its revision.
type PrincipalResult struct {
	Principal domain.Principal
	Revision  domain.Revision
}

// DeactivatePrincipalRequest changes one liveness source.
type DeactivatePrincipalRequest struct {
	Tenant  domain.TenantID
	Subject domain.Subject
	Source  domain.DeactivationSource
	Reason  string
}

// ReactivatePrincipalRequest restores one liveness source.
type ReactivatePrincipalRequest struct {
	Tenant  domain.TenantID
	Subject domain.Subject
	Source  domain.DeactivationSource
	Reason  string
}

// DeletePrincipalRequest terminally deletes a principal.
type DeletePrincipalRequest struct {
	Tenant  domain.TenantID
	Subject domain.Subject
	Reason  string
}

// LinkPrincipal links an identity adapter subject and honours a global deactivation.
func (i *IAM) LinkPrincipal(ctx context.Context, actor domain.Actor, req LinkPrincipalRequest) (PrincipalResult, error) {
	if err := authorize(actor, domain.RoleIdentityAdapter); err != nil {
		return PrincipalResult{}, err
	}
	tenant, err := i.principalRequest(req.Tenant, req.Subject)
	if err != nil {
		return PrincipalResult{}, err
	}
	if req.Issuer == "" || req.ExternalID == "" {
		return PrincipalResult{}, fmt.Errorf("%w: issuer and external id are required", domain.ErrInvalidSubject)
	}
	if actor.Tenant != "" && actor.Tenant != tenant {
		return PrincipalResult{}, fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return PrincipalResult{}, err
	}
	if _, ok := i.store.Principal(tenant, req.Subject); ok {
		return PrincipalResult{}, fmt.Errorf("%w: subject %s is already linked or retired", domain.ErrConflict, req.Subject.URN)
	}

	key := externalKey{issuer: req.Issuer, externalID: req.ExternalID}
	ident := i.external[key]
	globalLive := true
	if ident != nil {
		globalLive = ident.globalLive
		for link := range ident.links {
			if link.tenant != tenant {
				continue
			}
			previous, ok := i.store.Principal(tenant, link.subject)
			if !ok {
				continue
			}
			if !previous.Deleted {
				return PrincipalResult{}, fmt.Errorf("%w: external identity already linked in %s", domain.ErrConflict, tenant)
			}
			if link.subject.URN == req.Subject.URN {
				return PrincipalResult{}, fmt.Errorf("%w: subject %s is retired", domain.ErrConflict, req.Subject.URN)
			}
		}
	}

	events := []domain.Event{domain.PrincipalLinked{
		Issuer:     req.Issuer,
		ExternalID: req.ExternalID,
		Subject:    req.Subject,
	}}
	if !globalLive {
		events = append(events, domain.PrincipalDeactivated{
			Subject: req.Subject,
			Source:  domain.SourceGlobal,
			Reason:  "global deactivation at link",
		})
	}
	revision, err := i.appendEvents(ctx, ws, actor, "LinkPrincipal", events...)
	if err != nil {
		return PrincipalResult{}, err
	}
	if err := i.project(ctx, ws); err != nil {
		return PrincipalResult{}, err
	}

	if ident == nil {
		ident = &externalIdentity{globalLive: true, links: make(map[externalLink]struct{})}
		i.external[key] = ident
	}
	ident.links[externalLink{tenant: tenant, subject: req.Subject}] = struct{}{}
	principal, _ := i.store.Principal(tenant, req.Subject)
	return PrincipalResult{Principal: principal, Revision: revision}, nil
}

// ResolvePrincipal maps an external identity to its live tenant principal.
func (i *IAM) ResolvePrincipal(ctx context.Context, actor domain.Actor, req ResolvePrincipalRequest) (PrincipalResult, error) {
	if err := authorize(actor, domain.RoleIdentityAdapter); err != nil {
		return PrincipalResult{}, err
	}
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return PrincipalResult{}, err
	}
	if req.Issuer == "" || req.ExternalID == "" {
		return PrincipalResult{}, fmt.Errorf("%w: issuer and external id are required", domain.ErrInvalidSubject)
	}
	if actor.Tenant != "" && actor.Tenant != tenant {
		return PrincipalResult{}, fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return PrincipalResult{}, err
	}
	ident := i.external[externalKey{issuer: req.Issuer, externalID: req.ExternalID}]
	if ident == nil {
		return PrincipalResult{}, fmt.Errorf("%w: external identity", domain.ErrNotFound)
	}
	for link := range ident.links {
		if link.tenant != tenant {
			continue
		}
		principal, ok := i.store.Principal(tenant, link.subject)
		if !ok || principal.Deleted {
			continue
		}
		return PrincipalResult{Principal: principal, Revision: i.projector.Applied(ws)}, nil
	}
	return PrincipalResult{}, fmt.Errorf("%w: external identity in %s", domain.ErrNotFound, tenant)
}

// DeactivatePrincipal deactivates a principal at tenant or global scope.
func (i *IAM) DeactivatePrincipal(ctx context.Context, actor domain.Actor, req DeactivatePrincipalRequest) (domain.Revision, error) {
	return i.setPrincipalActive(ctx, actor, req.Tenant, req.Subject, req.Source, false, req.Reason)
}

// ReactivatePrincipal reactivates a principal at tenant or global scope.
func (i *IAM) ReactivatePrincipal(ctx context.Context, actor domain.Actor, req ReactivatePrincipalRequest) (domain.Revision, error) {
	return i.setPrincipalActive(ctx, actor, req.Tenant, req.Subject, req.Source, true, req.Reason)
}

// DeletePrincipal removes a principal's edges and retires its URN.
func (i *IAM) DeletePrincipal(ctx context.Context, actor domain.Actor, req DeletePrincipalRequest) (domain.Revision, error) {
	if err := i.requireGlobalIdentityAdapter(actor); err != nil {
		return 0, err
	}
	tenant, err := i.principalRequest(req.Tenant, req.Subject)
	if err != nil {
		return 0, err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	principal, ok := i.store.Principal(tenant, req.Subject)
	if !ok {
		return 0, fmt.Errorf("%w: principal %s", domain.ErrNotFound, req.Subject.URN)
	}

	key := externalKey{issuer: principal.Issuer, externalID: principal.ExternalID}
	ident := i.external[key]
	if ident == nil {
		ident = &externalIdentity{globalLive: true, links: make(map[externalLink]struct{})}
		i.external[key] = ident
	}
	ident.links[externalLink{tenant: tenant, subject: req.Subject}] = struct{}{}

	var revision domain.Revision
	for link := range ident.links {
		linked, ok := i.store.Principal(link.tenant, link.subject)
		if !ok || linked.Deleted {
			continue
		}
		rev, err := i.appendEvents(ctx, eventlog.TenantWorkspace(link.tenant), actor, "DeletePrincipal", domain.PrincipalDeleted{
			Subject: domain.Subject{URN: linked.URN, Kind: linked.Kind},
			Reason:  req.Reason,
		})
		if err != nil {
			return 0, err
		}
		if err := i.project(ctx, eventlog.TenantWorkspace(link.tenant)); err != nil {
			return 0, err
		}
		if link.tenant == tenant {
			revision = rev
		}
	}
	if revision == 0 {
		revision = i.projector.Applied(ws)
	}
	return revision, nil
}

func (i *IAM) setPrincipalActive(ctx context.Context, actor domain.Actor, tenantID domain.TenantID, subject domain.Subject, source domain.DeactivationSource, live bool, reason string) (domain.Revision, error) {
	tenant, err := i.principalRequest(tenantID, subject)
	if err != nil {
		return 0, err
	}
	if err := i.authorizePrincipalLifecycle(actor, tenant, source); err != nil {
		return 0, err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	principal, ok := i.store.Principal(tenant, subject)
	if !ok {
		return 0, fmt.Errorf("%w: principal %s", domain.ErrNotFound, subject.URN)
	}
	if principal.Deleted {
		return 0, fmt.Errorf("%w: principal %s is deleted", domain.ErrConflict, subject.URN)
	}

	if source == domain.SourceTenant {
		if principal.TenantLive == live {
			return i.projector.Applied(ws), nil
		}
		event := domain.Event(domain.PrincipalDeactivated{Subject: subject, Source: source, Reason: reason})
		if live {
			event = domain.PrincipalReactivated{Subject: subject, Source: source, Reason: reason}
		}
		revision, err := i.appendEvents(ctx, ws, actor, principalCommand(live), event)
		if err != nil {
			return 0, err
		}
		if err := i.project(ctx, ws); err != nil {
			return 0, err
		}
		return revision, nil
	}

	key := externalKey{issuer: principal.Issuer, externalID: principal.ExternalID}
	ident := i.external[key]
	if ident == nil {
		ident = &externalIdentity{globalLive: true, links: make(map[externalLink]struct{})}
		i.external[key] = ident
	}
	ident.links[externalLink{tenant: tenant, subject: subject}] = struct{}{}

	var revision domain.Revision
	for link := range ident.links {
		linked, ok := i.store.Principal(link.tenant, link.subject)
		if !ok || linked.Deleted || linked.GlobalLive == live {
			continue
		}
		linkedSubject := domain.Subject{URN: linked.URN, Kind: linked.Kind}
		event := domain.Event(domain.PrincipalDeactivated{Subject: linkedSubject, Source: source, Reason: reason})
		if live {
			event = domain.PrincipalReactivated{Subject: linkedSubject, Source: source, Reason: reason}
		}
		rev, err := i.appendEvents(ctx, eventlog.TenantWorkspace(link.tenant), actor, principalCommand(live), event)
		if err != nil {
			return 0, err
		}
		if err := i.project(ctx, eventlog.TenantWorkspace(link.tenant)); err != nil {
			return 0, err
		}
		if link.tenant == tenant {
			revision = rev
		}
	}
	ident.globalLive = live
	if revision == 0 {
		revision = i.projector.Applied(ws)
	}
	return revision, nil
}

func (i *IAM) authorizePrincipalLifecycle(actor domain.Actor, tenant domain.TenantID, source domain.DeactivationSource) error {
	switch source {
	case domain.SourceGlobal:
		return i.requireGlobalIdentityAdapter(actor)
	case domain.SourceTenant:
		switch actor.Role {
		case domain.RoleTenantAdmin:
			return i.requireLiveUser(actor, tenant)
		case domain.RoleIdentityAdapter:
			return i.requireIdentityAdapter(actor, tenant)
		default:
			return fmt.Errorf("%w: tenant deactivation needs a tenant admin or identity adapter", domain.ErrForbidden)
		}
	default:
		return fmt.Errorf("%w: deactivation source %q", domain.ErrInvalidSubject, source)
	}
}

func (i *IAM) requireIdentityAdapter(actor domain.Actor, tenant domain.TenantID) error {
	if err := authorize(actor, domain.RoleIdentityAdapter); err != nil {
		return err
	}
	if actor.Tenant != "" && actor.Tenant != tenant {
		return fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}
	return nil
}

func (i *IAM) requireGlobalIdentityAdapter(actor domain.Actor) error {
	if err := authorize(actor, domain.RoleIdentityAdapter); err != nil {
		return err
	}
	if actor.Tenant != "" {
		return fmt.Errorf("%w: a global operation needs the deployment-wide identity adapter", domain.ErrForbidden)
	}
	return nil
}

func (i *IAM) principalRequest(tenantID domain.TenantID, subject domain.Subject) (domain.TenantID, error) {
	tenant, err := domain.ParseTenantID(string(tenantID))
	if err != nil {
		return "", err
	}
	if err := subject.Validate(); err != nil {
		return "", err
	}
	switch subject.Kind {
	case domain.SubjectUser:
	case domain.SubjectAgent:
		return "", fmt.Errorf("%w: agents are not principals in this plan", domain.ErrUnsupported)
	default:
		return "", fmt.Errorf("%w: %s is not a user principal", domain.ErrInvalidSubject, subject.URN)
	}
	if subject.URN.Tenant() != tenant {
		return "", fmt.Errorf("%w: subject tenant mismatch", domain.ErrInvalidSubject)
	}
	return tenant, nil
}

func principalCommand(live bool) string {
	if live {
		return "ReactivatePrincipal"
	}
	return "DeactivatePrincipal"
}

type externalKey struct {
	issuer     string
	externalID string
}

type externalLink struct {
	tenant  domain.TenantID
	subject domain.Subject
}

type externalIdentity struct {
	globalLive bool
	links      map[externalLink]struct{}
}
