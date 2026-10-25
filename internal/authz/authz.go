// Package authz is the authorization half of `iam`: containers, the
// containment closure, grants, the point decision, and the residual a
// consumer applies to its own rows. Authorizer is the port; the in-memory
// adapter in memory.go and the Postgres adapter in pgauthz both implement
// it, and both must pass iamtest.RunAuthorizerSuite unchanged. That
// suite, not this file, is the authoritative description of the
// contract's edge-case behaviour.
//
// # What this layer is, in one sentence
//
// **Membership on containers, inherited down a tree.** A subject — a
// principal or a group — holds a permission on a container, and
// everything the container contains inherits it. That is the whole rule
// language. Default-deny: every refusal is a grant nobody wrote.
//
// # Why it is so much smaller than design §8.2 describes
//
// The design document specifies a Zanzibar-shaped engine: relation
// tuples, usersets, `X from Y` inheritance, two maintained closures, a
// projection with a resumable cursor. Four decisions removed most of what
// that machinery was for, and each absence below is a decision rather
// than a gap.
//
//   - **No deny mechanism anywhere** (A3, 2026-10-23). No exclusion, no
//     negative grant, no mandatory tier, no conditions. A deny
//     administered by policy is only as absolute as whoever administers
//     the policy; an absolute that must survive a future administrator is
//     a key the deployment does not hold, which is `escrow`. So there is
//     no column here a negative rule could live in, and §7.1's decision
//     procedure is one term rather than a conjunction.
//   - **No third-party engine** (§10, 2026-10-23). The closures are *the*
//     authority rather than a projection of one, which is why they are
//     ordinary rows in this module's schema and why a consumer can join
//     them.
//   - **Containment is a tree** (F3, closed 2026-10-24). One parent per
//     container, one container per resource, and the containment key is a
//     scalar. Both specified consumers' containment is a tree, so §9.2's
//     "its containment path", singular, has a referent. A tree is not the
//     same as a fixed-depth one: domain.ContainerKind.Nestable declares
//     recursion, because design goal 4's Drive hierarchy is a folder inside
//     a folder and a declaration of fixed-depth kinds cannot say so.
//   - **The consumer settled its model** (2026-10-25). Privacy comes from
//     *placement* in a four-tier named-graph tree, and the rule it needs
//     is "which graphs may this principal read", enforced as a
//     restrictive row-level-security policy. No per-resource grants, no
//     per-attribute grants, no conditional rules.
//
// # What is deliberately not here
//
//   - **`Predicate`'s filtered-read contract.** Finding F4 is open and it
//     moves the return shape: either the authority returns a filter plus
//     a permitted-*attribute* set that the consumer applies — which
//     pushes part of the trust boundary into consumer code and makes
//     §9.4's audit responsible for consumer compliance — or `iam` becomes
//     a query rewriter across three query builders. Those are two
//     different modules. The residual below is **not** that contract: it
//     filters rows and says nothing about columns, and a consumer needing
//     column-granular restriction has to make the sensitive field its own
//     container-bearing resource, which is CAS's own cheapest answer.
//
//   - **Arbitrary relation algebra.** No usersets of usersets (a group's
//     members are principals, never other groups), no `X from Y`, no
//     computed relations, no union over relations on the same object,
//     no roles as first-class objects with relations of their own. §8.2's
//     four composition forms reduce to two plus the closure, because
//     membership and inheritance is what both consumers asked for.
//
//   - **Bottom-up navigational visibility** (§8.2's `visible_below`).
//     Nothing here answers "which containers may this principal see the
//     existence of". F3's spike measured both readings of it and killed
//     both — the permissive one made 2,356 containers list-visible to a
//     principal holding no grant on any of them, and the restrictive one
//     was exactly `{tenant, graph}` for every multi-path resource. The
//     surviving candidate, anchoring the relation on the grant rather
//     than on the object, is unbuilt.
//
//   - **Re-parenting a container, and deleting one.** A container's parent
//     is set at creation. Moving a subtree rewrites the closure rows for
//     everything below it — bounded by subtree size, which is small, so
//     this is unbuilt for want of a requirement rather than for cost:
//     neither consumer's model moves a graph between parents. The
//     database refuses a delete that would orphan children (ON DELETE
//     RESTRICT) rather than guessing what happens to the grants on the
//     subtree.
//
//   - **Persisted, versioned schemas.** RegisterSchema validates a
//     declaration and remembers it in this process. §8.4's explicit
//     schema migration and its computed access delta between two versions
//     — which §10 made ours to build, since there is no OpenFGA model to
//     diff — are unbuilt. What this costs: two binaries with different
//     registered schemas disagree about which container *kinds* may be
//     created, and agree about every decision, because the tree a
//     decision reads is enforced by the schema's single parent column in
//     the database rather than by the declaration.
//
//   - **A permission that does not inherit.** Every permission inherits
//     down the whole tree, and a consumer cannot declare one that stops.
//     §8.2's third form is per relation — `viewer from parent`, declared on
//     the relations that should inherit and omitted on those that should
//     not — so a model in which a folder's owner is deliberately *not* the
//     owner of the documents inside it is expressible there and not here.
//     This layer would allow it.
//
//     That is a reduction and not an oversight, and the use-case corpus is
//     what found it: no scenario in it distinguishes the two, which is luck
//     rather than evidence, so the corpus now fails the first row that would
//     rather than letting a declaration and an evaluator disagree quietly.
//     Neither consumer needs the distinction — "which graphs may this
//     principal read" inherits all the way down by construction, and a
//     fileset's owner owning its documents is what CAS wants — and a
//     consumer that does need it has one answer available today: put the
//     resource in a container the grant does not reach, which is the same
//     answer §7.2 gives for privacy inside a shared container.
//
//   - **Markings and the enforcement class** (§8.3). `Decide` never reads
//     one by design — the cryptographic tier is not part of the decision
//     — and this layer stores none at all, so a consumer cannot yet ask
//     this module *why* content is unreadable.
//
// # The change log, which was argued away and then argued back
//
// The reasoning that removed it was: the cursor existed so a projection
// worker could resume; the projection existed because the authority was
// OpenFGA, a separate store; with the closures *being* the authority and
// living in the same Postgres the consumer queries, a consumer joins them
// directly and there is no projection to resume. Every clause of that is
// true of a co-located Postgres consumer, and it is not true of the
// architecture: `iam` has to become separable, and a consumer on another
// store must project the authorized set locally. A projection without a
// resumable cursor cannot be restarted safely, so the log is the seam
// that makes separation possible. Design §11's *service* shape reaches
// the same conclusion from the other direction, because the closures
// would then live in the consumer's pool while the authority lives in the
// service.
//
// # Nothing here holds security-relevant material
//
// Stated rather than left implicit, because CONVENTIONS requires all four
// of fmt.Stringer, fmt.Formatter, json.Marshaler and slog.LogValuer on
// anything that does, and the absence of those methods on a type in this
// module should be a conclusion somebody reached. Every value in this
// package is either a minted opaque ULID, a permission name the consumer
// chose, or a boolean verdict. A grant is not a credential: it confers
// nothing on whoever reads it, and reproducing one in a log line
// discloses an authorization fact rather than a secret. `captoken` owns
// credentials and `keyring` owns key material; if either ever reaches
// this package, the rule applies and this paragraph is wrong.
package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/laenenai/iam/internal/domain"
)

// PrincipalGUC is the Postgres session variable a residual rendered into
// a row-level-security policy reads the deciding principal from.
//
// It is `app.principal_id`, matching `tenancy`'s `app.tenant_id`, and the
// name is load-bearing in the way tenancy records for its own: it appears
// verbatim in the policy SQL of every consumer that adopts this, so
// renaming it would silently stop matching their existing policies while
// everything still compiled. A policy that no longer matches does not
// fail — it stops filtering.
//
// It deliberately does not contain this module's import path, for the
// same reason: a module rename must not be able to move it.
//
// A session with no principal context must match no rows and raise no
// error. The rendered predicate uses `nullif(current_setting(…, true),
// ”)` with no cast, exactly as tenancy's tenant predicate does and for
// exactly its two reasons: every id here is a Crockford base32 ULID and
// never a uuid, so a cast would raise on every real row; and
// current_setting returns the empty string rather than NULL once any
// transaction on the connection has touched the setting, so a cast would
// raise for a caller with no context instead of quietly denying.
const PrincipalGUC = "app.principal_id"

// Config is the deployment policy both adapters share.
type Config struct {
	// Clock supplies the instant a write is stamped with. Defaults to
	// domain.SystemClock when nil.
	//
	// It stamps `granted_at` and a change log entry's `recorded_at`, and
	// it is never consulted for a decision: a decision's liveness is
	// evaluated at its own statement's instant, which in the Postgres
	// adapter is the database's. A configurable clock that could move a
	// decision would be a configurable authorization answer.
	Clock domain.Clock
}

// Validate checks cfg and fills in its optional fields, returning the
// normalized value.
func (c Config) Validate() (Config, error) {
	if c.Clock == nil {
		c.Clock = domain.SystemClock{}
	}
	return c, nil
}

// FilterRequest asks for the residual a consumer should apply to its own
// rows: "which of these rows may this principal <permission>".
type FilterRequest struct {
	// TenantID scopes it.
	TenantID domain.TenantID
	// Principal is whose permissions the residual is about: one named
	// principal for a residual joined into one query, or
	// domain.SessionPrincipal() for one rendered into a policy, which is
	// created once and evaluated for every principal.
	Principal domain.PrincipalRef
	// Permission is what they must hold.
	Permission domain.Permission
	// Key is the consumer's own column holding each row's container id —
	// finding F1's scalar containment key, and the one column a consumer
	// has to add to its own schema to use this module.
	Key domain.Key
	// TenantKey is the consumer's own tenant column. When it is the zero
	// Key the residual carries no tenant term, which is legitimate only
	// where something else scopes the statement — `tenancy`'s restrictive
	// tenant policy on that table, or a table with no tenant column at
	// all. Leaving it zero for an ordinary query means the authorization
	// layer itself spans tenants in that statement, so it is a zero value
	// a reviewer should notice rather than a default.
	TenantKey domain.Key
}

// Validate reports whether the request is answerable.
func (r FilterRequest) Validate() error {
	if r.TenantID == "" {
		return fmt.Errorf("%w: empty tenant id", domain.ErrInvalidRequest)
	}
	if r.Principal.IsZero() {
		return fmt.Errorf("%w: a filter must name a principal, or defer to the session with SessionPrincipal", domain.ErrInvalidRequest)
	}
	if strings.TrimSpace(string(r.Permission)) == "" {
		return fmt.Errorf("%w: a filter must name a permission", domain.ErrInvalidRequest)
	}
	if err := r.Key.Validate(); err != nil {
		return err
	}
	if r.TenantKey != (domain.Key{}) {
		if err := r.TenantKey.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Authorizer is the port every authorization adapter implements. See the
// package doc for what the layer is and is not, and iamtest's
// RunAuthorizerSuite for the contract.
//
// Every method takes a tenant explicitly rather than inferring one from
// the id it is given. That is not ceremony: inferring the tenant would
// mean reading the row first to find out whose it is, which is both an
// extra round trip and an existence oracle — "unknown container" and
// "another tenant's container" would become distinguishable answers.
// With the tenant supplied, both are the same answer.
type Authorizer interface {
	// RegisterSchema validates a consumer's declaration and remembers it
	// for this process, so that a container of an undeclared kind and a
	// grant of an undeclared permission are both refused.
	//
	// It refuses a declaration giving a container kind more than one
	// containment parent with domain.ErrMultipleContainmentParents,
	// naming the schema, the kind and the parents. That refusal is the
	// point of this method: design §8.4 accepted such a declaration, and
	// the consumer then got a closure keyed on the resource rather than
	// on the container — 106,495,540 rows and 10.9 GB against 433,063
	// rows and 37 MB at the budgeted scale — with no error at all.
	//
	// Registering a schema whose name is already registered replaces it.
	// A replacement that no longer declares a kind or a permission
	// already in use is not refused and nothing is rewritten: existing
	// containers and grants keep working, and only new writes are
	// checked against the new declaration. That is §8.4's schema
	// migration being absent, and it is the one place this method is
	// weaker than it reads.
	RegisterSchema(ctx context.Context, s domain.Schema) error

	// CreateContainer places a new container in the tenant's tree and
	// maintains the containment closure for it in the same transaction,
	// returning the stored container with its minted id.
	//
	// It refuses: a kind no registered schema declares
	// (domain.ErrSchemaNotRegistered); a root container whose kind
	// declares a parent, and a parented container whose kind declares
	// none or declares a different one (domain.ErrInvalidContainer); a
	// parent in another tenant or no tenant at all, which is reported as
	// if the parent did not exist (domain.ErrNotFound), because
	// distinguishing the two would be a cross-tenant existence oracle.
	CreateContainer(ctx context.Context, spec domain.ContainerSpec) (domain.Container, error)

	// Container returns the container with this id in this tenant, or
	// domain.ErrNotFound. Another tenant's container is not found.
	Container(ctx context.Context, tenant domain.TenantID, id domain.ContainerID) (domain.Container, error)

	// Ancestors returns the containment closure for one container:
	// itself first at depth 0, then each ancestor outwards to the root.
	// It is the closure read back, and it is on the port because a
	// consumer that cannot see the closure cannot explain a decision
	// that came through it.
	Ancestors(ctx context.Context, tenant domain.TenantID, id domain.ContainerID) ([]domain.ContainerID, error)

	// Grant records that the subject holds the permission on the
	// container, and returns the revision the write produced — the value
	// a consumer stores when it needs to know that its own projection
	// must be at least this current.
	//
	// It is idempotent: writing an existing grant again changes nothing
	// and returns the current revision without appending to the change
	// log, because a log entry for a write that changed nothing would
	// make a projection do work for no reason and would make the log's
	// length a function of retries.
	//
	// It refuses a permission no registered schema declares
	// (domain.ErrSchemaNotRegistered). A misspelled permission is a
	// grant that silently never fires, and finding it here costs one
	// error where finding it at read time costs an outage or, for a
	// revocation that never applied, a disclosure.
	Grant(ctx context.Context, spec domain.GrantSpec) (domain.Revision, error)

	// Revoke removes a grant and returns the revision the write
	// produced. Revoking a grant that does not exist is not an error and
	// appends nothing to the log.
	Revoke(ctx context.Context, spec domain.GrantSpec) (domain.Revision, error)

	// GrantsOn returns the grants written directly on this container —
	// not the inherited ones, which belong to its ancestors and are
	// returned by asking about them. Ordered by permission then subject,
	// so two adapters return the same sequence.
	GrantsOn(ctx context.Context, tenant domain.TenantID, container domain.ContainerID) ([]domain.Grant, error)

	// Decide answers design §7.1's point check as it now stands:
	//
	//	Decide(principal, permission, container) =
	//	    discretionary_allows(principal, permission, container)
	//
	// and nothing else. There is no mandatory gate to evaluate first —
	// the tier that held one was a deny administered by policy and went
	// with the deny mechanism — so the whole decision is one term, which
	// is also why the whole decision is one residual.
	//
	// It allows when some grant on the container itself or on any of its
	// ancestors names either the principal or a group the principal is a
	// live member of. It denies otherwise, and a denial is a Decision
	// rather than an error: an unknown container, an unknown principal,
	// an undeclared permission and a principal with no grants are all
	// the same answer, which is what keeps this from being an existence
	// oracle.
	//
	// Liveness is evaluated inside the decision: a deprovisioned
	// principal and an expired agent run match nothing, on both the
	// direct and the group side. The deployment's staleness bound is
	// *not* evaluated — see the package doc's note on what that costs
	// and why both decision surfaces have to agree about it.
	Decide(ctx context.Context, req domain.Request) (domain.Decision, error)

	// Filter returns the residual a consumer applies to its own rows:
	// the typed expression, plus the revision it was computed against.
	// It never returns SQL — see domain's residual doc for why text
	// crossing this port would make a second storage backend a breaking
	// change for every consumer.
	//
	// A request whose permission no registered schema declares yields
	// domain.None rather than an error, because the failure mode a
	// consumer's policy must have is zero rows and never a raised
	// exception.
	Filter(ctx context.Context, req FilterRequest) (domain.Residual, error)

	// Changes returns up to limit entries of the tenant's change log
	// after the cursor, in revision order.
	//
	// The guarantee is the one a restartable projection needs: a reader
	// that stores the highest revision it has processed and resumes with
	// that cursor sees every subsequent change exactly once. It holds
	// because revisions are gapless and assigned in commit order, so the
	// visibility of revision N implies the visibility of everything
	// below it — which is why they do not come from a sequence. See
	// db/migrations/00003_authorization.sql.
	Changes(ctx context.Context, tenant domain.TenantID, after domain.Revision, limit int) ([]domain.Change, error)

	// Revision returns the current head of this tenant's change log: the
	// authorization state of that tenant right now. Zero means no
	// authorization write has ever happened in it.
	//
	// It is per tenant and not per deployment, which was forced rather
	// than chosen: a deployment-wide counter cannot coexist with the
	// row-level-security policy on the log, because under a tenant
	// session context `max(revision)` is that tenant's maximum and two
	// tenants would be handed the same next value. Per tenant is also
	// the unit a projection resumes.
	Revision(ctx context.Context, tenant domain.TenantID) (domain.Revision, error)
}

// DefaultChangeLimit is the page size Changes uses when a caller asks for
// a non-positive limit.
const DefaultChangeLimit = 100

// MaxChangeLimit caps a page of changes, so a projection catching up from
// an old cursor pages rather than materializing an unbounded slice.
const MaxChangeLimit = 1000

// NormalizeChangeLimit applies the two bounds above. It is shared so both
// adapters page identically; a suite that asserted a page size would
// otherwise be asserting one adapter's arithmetic.
func NormalizeChangeLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultChangeLimit
	case limit > MaxChangeLimit:
		return MaxChangeLimit
	default:
		return limit
	}
}

// BuildResidual assembles the residual for a validated request. It is
// shared by both adapters, so the expression a consumer gets does not
// depend on which adapter produced it — the whole point of a typed
// residual is that it is the same value everywhere, and two adapters each
// assembling their own would have defeated it at the first divergence.
//
// permissionDeclared is the caller's answer to "does any registered schema
// declare this permission", which only the adapter holding the schemas can
// answer. When it is false the residual is domain.None: not an error,
// because the failure mode a consumer's policy must have is zero rows, and
// an error would both break the consumer's statement and distinguish an
// undeclared permission from an empty result, which is information about
// the schema.
func BuildResidual(req FilterRequest, rev domain.Revision, permissionDeclared bool) (domain.Residual, error) {
	if !permissionDeclared {
		return domain.Residual{Revision: rev, Expr: domain.None{}}, nil
	}
	terms := make([]domain.Expr, 0, 2)
	if req.TenantKey != (domain.Key{}) {
		terms = append(terms, domain.TenantIs{Key: req.TenantKey, Tenant: req.TenantID})
	}
	terms = append(terms, domain.ContainerPermits{
		Key:        req.Key,
		Principal:  req.Principal,
		Permission: req.Permission,
	})

	var expr domain.Expr
	if len(terms) == 1 {
		expr = terms[0]
	} else {
		expr = domain.And{Terms: terms}
	}
	residual := domain.Residual{Revision: rev, Expr: expr}
	if err := residual.Validate(); err != nil {
		return domain.Residual{}, err
	}
	return residual, nil
}
