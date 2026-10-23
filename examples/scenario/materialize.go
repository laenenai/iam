package scenario

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/laenenai/iam"
)

// Env is a fixture's identity layer after it has been materialized against
// a real registry: the mapping from the fixture's local names to the
// internal ids the registry minted.
//
// It exists because the corpus must not invent identity. Everything in it
// came out of JIT provisioning, EnsureGroup, AddGroupMember and
// DelegateAgentRun — the same calls a consumer makes — so the identity
// half of every scenario in this corpus is evidence about `iam` and not
// about the corpus.
type Env struct {
	// Tenant is the minted tenant id.
	Tenant iam.TenantID
	// Registry is the registry the fixture was materialized against.
	Registry iam.Registry
	// Now is the instant the fixture was materialized at. Every read that
	// depends on liveness takes it, so a decision and the freshness check
	// that authorizes it share one instant.
	Now time.Time

	principals map[string]iam.Principal
	groups     map[string]iam.Group
}

// PrincipalID returns the internal id minted for the fixture's local name.
func (e *Env) PrincipalID(name string) (iam.PrincipalID, bool) {
	p, ok := e.principals[name]
	return p.ID, ok
}

// Principal returns the stored principal for the fixture's local name.
func (e *Env) Principal(name string) (iam.Principal, bool) {
	p, ok := e.principals[name]
	return p, ok
}

// Group returns the group the fixture's local name was materialized into.
func (e *Env) Group(name string) (iam.Group, bool) {
	g, ok := e.groups[name]
	return g, ok
}

// defaultIssuer is the issuer a fixture gets when it names none. It is a
// URL because an OIDC issuer identifier is one, and it is compared exactly
// — two issuers differing by a trailing slash are two trust roots.
const defaultIssuer = "https://idp.example"

// defaultAgentRunTTL is the TTL an agent run gets when the fixture names
// none.
const defaultAgentRunTTL = time.Hour

// Materialize applies a fixture's identity layer to reg and returns the
// mapping. It is the part of this corpus that runs today, against the real
// module, and it exercises in one pass: JIT provisioning from claims and
// its idempotence, claim-derived group upsert, locally-sourced membership,
// agent-run delegation as a first-class principal, and immediate
// deprovisioning.
//
// One thing it deliberately does not do: it never provisions an agent run
// from claims. An agent run is delegated, so that its parent is recorded
// and audit can attribute per run.
//
// It used to do a third thing — create clearance groups and admit members
// to them through a mandatory channel, carrying an auditable act — and
// there used to be a paragraph here listing what no discretionary path
// could reach. Both went with the deny mechanism. What a principal holds
// is now exactly what has been granted to it, and the fixture says so
// directly.
func Materialize(ctx context.Context, reg iam.Registry, f Fixture, clock iam.Clock) (*Env, error) {
	now := clock.Now()
	env := &Env{
		Tenant:     iam.NewTenantID(clock),
		Registry:   reg,
		Now:        now,
		principals: make(map[string]iam.Principal, len(f.Principals)),
		groups:     make(map[string]iam.Group, len(f.Groups)),
	}

	issuer := f.Issuer
	if issuer == "" {
		issuer = defaultIssuer
	}

	if err := env.provisionNonDelegated(ctx, f, issuer); err != nil {
		return nil, err
	}
	if err := env.delegateAgentRuns(ctx, f); err != nil {
		return nil, err
	}
	if err := env.materializeGroups(ctx, f); err != nil {
		return nil, err
	}
	// Deprovisioning runs last so that a principal can be a group member
	// and an agent run's parent before it is withdrawn — which is what
	// makes the cascade and the immediate-denial assertions mean
	// something.
	return env, env.deprovision(ctx, f)
}

func (e *Env) provisionNonDelegated(ctx context.Context, f Fixture, issuer string) error {
	for _, spec := range f.Principals {
		if spec.Kind == iam.PrincipalKindAgentRun {
			continue
		}
		claims, err := claimsFor(e.Tenant, spec, issuer)
		if err != nil {
			return err
		}
		p, err := e.Registry.UpsertFromClaims(ctx, claims)
		if err != nil {
			return fmt.Errorf("provision %s: %w", spec.Name, err)
		}
		e.principals[spec.Name] = p
	}
	return nil
}

func claimsFor(tenant iam.TenantID, spec PrincipalSpec, issuer string) (iam.Claims, error) {
	subject := spec.Subject
	if subject == "" {
		subject = R(spec.Name).ID
	}
	iss := spec.Issuer
	if iss == "" {
		iss = issuer
	}
	external, err := iam.ParseExternalSubject(iss, subject)
	if err != nil {
		return iam.Claims{}, fmt.Errorf("principal %s: %w", spec.Name, err)
	}
	kind := spec.Kind
	if kind == "" {
		kind = iam.PrincipalKindUser
	}
	return iam.Claims{
		TenantID:    tenant,
		Subject:     external,
		Kind:        kind,
		DisplayName: spec.Name,
		Groups:      slices.Clone(spec.ClaimGroups),
	}, nil
}

func (e *Env) delegateAgentRuns(ctx context.Context, f Fixture) error {
	for _, spec := range f.Principals {
		if spec.Kind != iam.PrincipalKindAgentRun {
			continue
		}
		parent, ok := e.principals[spec.DelegatedBy]
		if !ok {
			return fmt.Errorf("agent run %s is delegated by %q, which the fixture does not declare as a user or service",
				spec.Name, spec.DelegatedBy)
		}
		ttl := spec.TTL
		if ttl == 0 {
			ttl = defaultAgentRunTTL
		}
		run, err := e.Registry.DelegateAgentRun(ctx, parent.ID, iam.AgentRunSpec{TTL: ttl, DisplayName: spec.Name})
		if err != nil {
			return fmt.Errorf("delegate %s from %s: %w", spec.Name, spec.DelegatedBy, err)
		}
		e.principals[spec.Name] = run
	}
	return nil
}

func (e *Env) materializeGroups(ctx context.Context, f Fixture) error {
	for _, spec := range f.Groups {
		g, err := e.Registry.EnsureGroup(ctx, e.Tenant, spec.Name)
		if err != nil {
			return fmt.Errorf("ensure group %s: %w", spec.Name, err)
		}
		e.groups[spec.Name] = g
		for _, member := range spec.Members {
			p, ok := e.principals[member]
			if !ok {
				return fmt.Errorf("group %s names unknown member %q", spec.Name, member)
			}
			if err := e.Registry.AddGroupMember(ctx, g.ID, p.ID); err != nil {
				return fmt.Errorf("add %s to %s: %w", member, spec.Name, err)
			}
		}
	}
	return nil
}

func (e *Env) deprovision(ctx context.Context, f Fixture) error {
	for _, spec := range f.Principals {
		if !spec.Deprovisioned {
			continue
		}
		p, ok := e.principals[spec.Name]
		if !ok {
			return fmt.Errorf("cannot deprovision unknown principal %q", spec.Name)
		}
		if err := e.Registry.Deprovision(ctx, p.ID); err != nil {
			return fmt.Errorf("deprovision %s: %w", spec.Name, err)
		}
	}
	return nil
}
