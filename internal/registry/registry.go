// Package registry is the identity half of `iam`: who exists, which groups
// they are in, and whether they are fresh enough to be used in a decision
// at all. Registry is the port; the
// in-memory adapter in memory.go and the pgx adapter in pgregistry both
// implement it, and both must pass RunRegistrySuite in suite.go unchanged.
// That suite, not this file, is the authoritative description of the
// contract's edge-case behaviour.
//
// # Why identity lives here at all, when the token already says it
//
// Every claim this registry stores arrived in a token that the caller has
// already verified. Mirroring it into rows looks like duplication, and it
// is not: it is the single reason this module owns identity rather than
// reading it from a token on each request.
//
// Design §9 requires an authorization decision that compiles into a SQL
// predicate the consumer embeds in its own statement — joined, not
// post-filtered, over a table of ten million rows (anti-goal A2). Such a
// predicate has to resolve "is this principal in the group this grant
// names" *inside* the query plan. A group list in a JWT cannot be joined.
// The three ways a caller might try all fail at that budget:
//
//   - Inline the claim set as a literal `IN (...)`: the predicate's text
//     now varies per principal, so the plan cache misses on every request,
//     and a user in 200 overlapping groups (A2's budget) produces a
//     predicate whose length is a function of their group count.
//   - Post-filter in application code: that is KGS leak channel #6. The
//     database returns rows the principal may not see and the application
//     is trusted to drop them, so every path that forgets — a count, an
//     aggregate, an ANN search's candidate set, a log line — leaks.
//   - Pass the claims to a function the predicate calls: the planner
//     cannot use an index through it, and A2's "the plan must show an
//     index join, never a sequential scan" is lost.
//
// So membership is **rows**, and specifically rows indexed for the
// direction the predicate reads them: `(principal_id, group_id)`, so the
// predicate's `EXISTS (SELECT 1 FROM iam.group_members WHERE principal_id
// = $1 AND group_id = ...)` is an index-only probe rather than a scan.
// Design §8.1 states the conclusion in one line — "claims cannot be
// joined" — and this is what it costs to have it.
//
// The consequence, which is this package's real work, is that claims must
// be *reconciled* rather than read: a group named in a claim set is
// upserted into the registry on sight, and a claim set that shrinks
// removes the memberships it no longer names. Reconciliation is scoped to
// claim-sourced rows only (domain.GroupSource), because an issuer is not
// the authority for a membership an operator wrote by hand.
//
// # Fail-closed, twice
//
//   - **A newly provisioned principal holds nothing.** JIT grants identity
//     and never access: a principal exists, belongs to whatever groups its
//     claims name, and reaches no resource until something grants it one.
//     Default-deny is the whole of it, which is why this list is shorter
//     than it was — the third entry described a mandatory tier that no
//     longer exists.
//   - **A stale principal cannot have its memberships read.** GroupsOf
//     returns the principal's condition error rather than a membership
//     list, so "staler than the bound forces a re-sync before
//     the request proceeds" (design §8.1) is enforced by the registry
//     instead of trusted to each caller's remembering to ask first.
//   - **Deprovisioning denies immediately.** It is not a staleness
//     condition and no re-sync clears it, and the Postgres adapter's
//     joinable membership view excludes a deprovisioned principal in the
//     same statement that records the deprovisioning — so the SQL
//     predicate stops matching at once rather than at the next refresh
//     (design §8.1, §9.3).
//
// # Reads take the deciding instant; writes stamp their own
//
// Every read whose answer depends on liveness takes an explicit `asOf`.
// That is not test scaffolding: a decision and the freshness check that
// authorizes it must share one instant, or a principal can be fresh for
// the check and expired for the decision that followed it. Writes stamp
// `synced_at`, `expires_at` and `acted_at` from the registry's own clock,
// because a caller-supplied write timestamp is a caller-supplied staleness
// bound.
//
// # Out of this increment
//
// The engine adapter, relation tuples, the projection, the decision
// procedure and Predicate are all absent on purpose (design §14: the
// identity registry is the one workstream wholly independent of the F1/F3
// API questions). internal/idp defines the provisioning and key-source
// ports with a stubbed transport; no network client lives here.
//
// There is no mandatory tier and no clearance group, and that is a
// decision rather than a gap: see the design document's "no deny
// mechanism" anti-goal. An absolute is a key the deployment does not hold,
// which is `escrow`.
package registry

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/laenenai/iam/internal/domain"
)

// Claims is the subset of a verified token the registry provisions from.
//
// It is deliberately not a token, a JWT, or a map of raw claims: nothing
// in this package parses, verifies or inspects a credential (design §3 —
// this is not a token library and not an identity provider). An adapter in
// internal/idp maps one issuer's claim names onto this struct, which is
// what keeps a second IdP configuration plus tests rather than a refactor.
//
// There is no field here through which access could arrive. An issuer
// says who someone is and which groups they are in; what they may reach is
// granted here, never asserted by a token.
//
// The caller must have verified the token's signature and confirmed that
// Subject.Issuer is one its tenant accepts, *before* calling — design
// §8.1's "a token from an unregistered issuer is rejected before any
// lookup". See internal/idp.IssuerPolicy.
type Claims struct {
	// TenantID scopes everything provisioned from these claims.
	TenantID domain.TenantID
	// Subject is the verified (issuer, subject) pair.
	Subject domain.ExternalSubject
	// Kind is the principal kind the claims describe. A token from a
	// Zitadel service user becomes domain.PrincipalKindService; a human
	// login becomes domain.PrincipalKindUser. An agent run is never
	// provisioned from claims — it is delegated (DelegateAgentRun), so
	// that its parent is recorded.
	Kind domain.PrincipalKind
	// DisplayName is a human label for diagnostics and audit rendering.
	// It is not an identity: nothing resolves a principal by it, and it
	// may change on any re-sync.
	DisplayName string
	// Groups are the claim-derived group names, exactly as the issuer
	// spelled them. They are upserted into the registry on sight rather
	// than passed through, which is what keeps them joinable, and this
	// slice is *authoritative for claim-sourced membership*: a name that
	// was here last time and is absent now has its membership removed
	// (design §8.1). Duplicates are collapsed; empty names are rejected.
	Groups []string
}

// Validate reports whether c describes a provisionable principal. It is
// the shared precondition both adapters run, so an in-memory registry and
// a Postgres one refuse the same claim sets.
func (c Claims) Validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("%w: empty tenant id", domain.ErrInvalidClaims)
	}
	if c.Subject.IsZero() {
		return fmt.Errorf("%w: claims must carry an external subject", domain.ErrInvalidClaims)
	}
	if _, err := domain.ParseExternalSubject(c.Subject.Issuer, c.Subject.Subject); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrInvalidClaims, err)
	}
	switch c.Kind {
	case domain.PrincipalKindUser, domain.PrincipalKindService:
	case domain.PrincipalKindAgentRun:
		return fmt.Errorf("%w: an agent run is delegated, never provisioned from claims, so that its parent is recorded", domain.ErrInvalidClaims)
	default:
		return fmt.Errorf("%w: unknown principal kind %q", domain.ErrInvalidClaims, c.Kind)
	}
	for i, g := range c.Groups {
		if g == "" {
			return fmt.Errorf("%w: groups[%d] is empty", domain.ErrInvalidClaims, i)
		}
	}
	return nil
}

// AgentRunSpec describes one agent run to delegate.
type AgentRunSpec struct {
	// TTL is how long the run's principal remains usable. It is required
	// and must be positive: an agent-run principal with no deadline is a
	// permanent credential created by a discretionary act, which is the
	// thing the TTL exists to prevent. Config.MaxAgentRunTTL caps it.
	TTL time.Duration
	// DisplayName is a human label for the run, for audit rendering.
	DisplayName string
}

// Registry is the port every identity-registry adapter implements. See the
// package doc comment for the invariants, and suite.go for the full
// contract including the pinned behaviour of claim reconciliation,
// staleness and deprovisioning.
type Registry interface {
	// UpsertFromClaims provisions or refreshes the principal named by
	// c.Subject and reconciles its claim-sourced group membership to
	// exactly c.Groups, returning the stored principal.
	//
	// It is idempotent in the only sense that matters: a second call with
	// the same claims returns the same PrincipalID and leaves membership
	// unchanged. The id is minted on first sight and never recomputed, so
	// re-issuing or renaming the external identity — a new display name,
	// a new email, the same (issuer, subject) — keeps every grant and
	// every audit row pointing at the same principal.
	//
	// Reconciliation touches claim-sourced memberships only: a membership
	// written through AddGroupMember survives a claim set that does not
	// name it, and a claim-sourced membership whose name is gone from the
	// claim set is removed.
	//
	// It refuses a deprovisioned principal with
	// domain.ErrPrincipalDeprovisioned rather than reviving it — a fresh
	// token for a deprovisioned subject is not a reinstatement.
	UpsertFromClaims(ctx context.Context, c Claims) (domain.Principal, error)

	// ResolveExternal maps a verified (issuer, subject) pair to its
	// internal principal within tenant, or returns
	// domain.ErrPrincipalNotFound if the pair has never been seen — the
	// signal to JIT-provision.
	//
	// It resolves a deprovisioned principal successfully, returning the
	// row with DeprovisionedAt set, because audit and metering must be
	// able to attribute history to it. Whether it may be *used* is
	// Condition's answer, never this method's.
	ResolveExternal(ctx context.Context, tenant domain.TenantID, s domain.ExternalSubject) (domain.Principal, error)

	// PrincipalByID returns the principal with this internal id, or
	// domain.ErrPrincipalNotFound.
	PrincipalByID(ctx context.Context, id domain.PrincipalID) (domain.Principal, error)

	// Condition returns the typed verdict on whether the principal may be
	// used in a decision taken at asOf: usable, resync-required,
	// deprovisioned, or expired. It is a condition and not a boolean
	// because the four answers demand four different responses from the
	// caller; see domain.PrincipalState.
	//
	// asOf is the instant the decision is being taken, supplied by the
	// caller so that the decision and the freshness check that authorizes
	// it share one instant.
	Condition(ctx context.Context, id domain.PrincipalID, asOf time.Time) (domain.PrincipalCondition, error)

	// EnsureGroup returns the tenant's group of this name, creating it if
	// it does not exist. It is idempotent: a second call returns the same
	// GroupID, which is what lets a claim set name a group without
	// knowing whether it has been seen before.
	//
	// name is the group's identity within its tenant. An empty name is
	// refused; a name that collides with an existing group's is that
	// group.
	EnsureGroup(ctx context.Context, tenant domain.TenantID, name string) (domain.Group, error)

	// AddGroupMember records a locally-sourced membership
	// (domain.GroupSourceLocal), which claim reconciliation never
	// removes. Adding an existing membership is idempotent. It refuses a
	// deprovisioned principal.
	//
	// It refuses a GroupID that names no group with domain.ErrNotFound.
	// There is one namespace of groups, so a row or no row is the whole
	// answer; the two-namespace probe this used to need went with the
	// mandatory tier.
	AddGroupMember(ctx context.Context, g domain.GroupID, p domain.PrincipalID) error

	// RemoveGroupMember removes a membership regardless of its source.
	// Removing an absent membership is not an error.
	RemoveGroupMember(ctx context.Context, g domain.GroupID, p domain.PrincipalID) error

	// GroupsOf returns the ordinary groups this principal is a member of,
	// as of asOf, ordered by group name.
	//
	// It returns the principal's condition error — ErrResyncRequired,
	// ErrPrincipalDeprovisioned or ErrAgentRunExpired — instead of a
	// membership list whenever the principal is not usable at asOf. That
	// is the enforcement point for design §8.1's staleness bound: a
	// caller cannot read a stale principal's memberships and decide with
	// them, whether or not it remembered to call Condition first.
	GroupsOf(ctx context.Context, p domain.PrincipalID, asOf time.Time) ([]domain.Group, error)

	// GroupMembers returns the principals that are members of g and
	// usable at asOf, ordered by principal id.
	//
	// Unlike GroupsOf it omits rather than errors: it is a set read over
	// many principals, and one deprovisioned member must not make a group
	// unreadable. Omission is also what makes deprovisioning immediate on
	// this side — the member stops appearing the instant it is
	// deprovisioned, with no membership row deleted and no audit history
	// lost.
	GroupMembers(ctx context.Context, g domain.GroupID, asOf time.Time) ([]domain.PrincipalID, error)

	// LiveGroupsOf returns the ids of the groups whose membership an
	// authorization decision for this principal may go through at asOf.
	//
	// It exists because the authorization layer needs exactly one
	// identity fact — "which subjects may this principal act as, right
	// now" — and the two methods above both answer a slightly different
	// question. It is on this port rather than reimplemented beside the
	// grants, and that is the decision this method embodies: a second
	// copy of membership would be a copy that goes stale, and a
	// deprovisioned principal would keep reading until somebody synced
	// it. The Postgres adapter answers this from
	// iam.live_group_members, the same view the joinable residual
	// renders into a consumer's own statement, so there is one
	// definition of live membership in SQL and nothing to drift.
	//
	// It differs from GroupsOf in three ways, each of which is the
	// reason it is not GroupsOf:
	//
	//   - **It omits rather than errors.** A deprovisioned principal, an
	//     expired agent run and a principal that does not exist all
	//     return an empty slice and no error. A decision must not be an
	//     existence oracle, and a decision that returned an error where
	//     it means "no" would train callers to treat a refusal as an
	//     outage.
	//   - **It does not apply the deployment's staleness bound.** That
	//     bound is configuration rather than a row, and the residual a
	//     consumer renders into its own statement runs where no
	//     configuration exists — so if this method applied the bound,
	//     this module's two decision surfaces would disagree with each
	//     other about the same principal. Design §8.1 puts the bound on
	//     the way in, which is where GroupsOf enforces it.
	//   - **It returns ids and not groups.** A decision joins on the id;
	//     the name is for people.
	//
	// Deprovisioning and agent-run expiry *are* applied, because those
	// two must deny inside the decision itself: §8.1 requires
	// deprovisioning to deny immediately, and the Postgres view enforces
	// both in the same statement that records them.
	//
	// asOf is the instant the decision is being taken. An adapter whose
	// store evaluates liveness itself may additionally exclude a
	// principal that is unusable at that store's own instant, so a caller
	// passing an asOf in the future can get the stricter of the two
	// answers. The asymmetry is stated rather than smoothed over because
	// it can only ever deny more, and the alternative — forbidding the
	// store from applying its own clock — would mean a view that cannot
	// be joined inside a consumer's statement, which is the one thing
	// this method exists to make possible.
	LiveGroupsOf(ctx context.Context, p domain.PrincipalID, asOf time.Time) ([]domain.GroupID, error)

	// DelegateAgentRun creates an ephemeral agent-run principal with its
	// own internal id, delegated from parent, expiring spec.TTL after the
	// registry's clock reads now.
	//
	// The run is a first-class principal and not a flag on its parent, so
	// audit and metering attribute per run (design §8.1, KGS §9.5). It
	// inherits nothing: no group membership at all. A delegation grants
	// what it names and never what its parent happens to hold, so an agent
	// run that should reach a resource is granted it explicitly.
	//
	// parent must be a usable user or service principal: an agent run
	// cannot delegate a further agent run, because a chain of ephemeral
	// principals has no attributable owner and `captoken` owns delegation
	// depth (design §3).
	DelegateAgentRun(ctx context.Context, parent domain.PrincipalID, spec AgentRunSpec) (domain.Principal, error)

	// CollectExpiredAgentRuns deletes agent-run principals whose TTL
	// elapsed before asOf, together with their memberships, and returns
	// how many it removed.
	//
	// It is garbage collection and never an access control: an expired
	// agent run is unusable from its deadline (domain.PrincipalStateExpired),
	// so a collector that never runs wastes rows and grants nothing.
	CollectExpiredAgentRuns(ctx context.Context, asOf time.Time) (int, error)

	// Deprovision marks a principal unusable from now, permanently. It is
	// idempotent — deprovisioning an already-deprovisioned principal is
	// not an error — and it keeps the principal's row and memberships, so
	// audit can still attribute history to it.
	//
	// It denies immediately and unconditionally: not at the next sync, not
	// when the token expires, and not subject to asOf. See
	// domain.ErrPrincipalDeprovisioned.
	Deprovision(ctx context.Context, p domain.PrincipalID) error
}

// Config is the deployment policy both adapters share.
type Config struct {
	// Clock supplies the instant for every write. Defaults to
	// domain.SystemClock when nil.
	Clock domain.Clock
	// StalenessBound is how old a principal's synced_at may be before the
	// registry forces a re-sync (design §8.1). It must be positive: a
	// deployment declares a bound rather than inheriting a default,
	// because the default that looks harmless — zero, meaning "never
	// stale" — is the one that makes the bound a no-op. A zero or
	// negative value is refused here, and domain.EvaluateCondition reads
	// it as resync-required if it ever reaches that far.
	StalenessBound time.Duration
	// MaxAgentRunTTL caps the TTL an AgentRunSpec may ask for, so a
	// caller cannot mint an effectively permanent agent-run principal
	// through a discretionary delegation. It must be positive.
	MaxAgentRunTTL time.Duration
}

// Validate checks cfg and fills in its optional fields, returning the
// normalized value.
func (c Config) Validate() (Config, error) {
	if c.Clock == nil {
		c.Clock = domain.SystemClock{}
	}
	if c.StalenessBound <= 0 {
		return Config{}, fmt.Errorf("%w: registry: staleness_bound must be positive; a deployment declares its bound", domain.ErrInvalidConfig)
	}
	if c.MaxAgentRunTTL <= 0 {
		return Config{}, fmt.Errorf("%w: registry: max_agent_run_ttl must be positive", domain.ErrInvalidConfig)
	}
	return c, nil
}

// ValidateAgentRunSpec reports whether spec asks for a run this
// deployment's policy permits. It is exported so every adapter shares one
// ceiling rather than inventing its own.
func ValidateAgentRunSpec(spec AgentRunSpec, maxTTL time.Duration) error {
	if spec.TTL <= 0 {
		return fmt.Errorf("%w: an agent run must carry a positive TTL", domain.ErrInvalidPrincipal)
	}
	if spec.TTL > maxTTL {
		return fmt.Errorf("%w: agent run TTL %s exceeds this deployment's maximum of %s", domain.ErrInvalidPrincipal, spec.TTL, maxTTL)
	}
	return nil
}

// NormalizeClaimGroups returns groups deduplicated and sorted, which is
// the form reconciliation compares against. Deduplication matters: an
// issuer that lists a role twice must not produce two membership rows, and
// a set comparison is only a set comparison if both sides are sets.
//
// It returns an empty, non-nil slice for an empty input, because an
// adapter binding it as a SQL array parameter needs an empty array rather
// than a NULL — the difference between "remove every claim-sourced
// membership" and a predicate that matches nothing.
func NormalizeClaimGroups(groups []string) []string {
	seen := make(map[string]struct{}, len(groups))
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	slices.Sort(out)
	return out
}

// LiveForDecision reports whether a principal may be matched by an
// authorization decision at asOf: not deprovisioned, and not an agent run
// past its deadline.
//
// It is the Go statement of exactly what the Postgres views
// iam.live_principals and iam.live_group_members say in SQL, and it is
// exported so that the authorization layer's in-memory adapter and those
// views cannot drift apart without a test failing. Two conditions, and
// deliberately not a third: the deployment's staleness bound is not here,
// because a view cannot read deployment configuration and this module's
// two decision surfaces have to agree. See LiveGroupsOf.
func LiveForDecision(p domain.Principal, asOf time.Time) bool {
	if !p.DeprovisionedAt.IsZero() {
		return false
	}
	if !p.ExpiresAt.IsZero() && !p.ExpiresAt.After(asOf) {
		return false
	}
	return true
}
