package domain

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Revision is the authorization state an answer was computed against: a
// gapless, monotonically increasing counter bumped by every write that
// can move a decision. It is this design's zookie.
//
// # Why it exists now, when nothing yet reads it
//
// Today `iam`'s tables and the consumer's are in one Postgres, so a
// decision reads the authority and the revision it reports is trivially
// current. Nothing in this increment builds consistency *semantics* on
// it: there is no "decide at revision R", no bound, no staleness
// arithmetic. It exists now because it cannot be added later without
// changing the shape of every answer — a Decision that grows a field and
// a residual that grows a field are a breaking change at every call site,
// and the deployment that needs it is the one where `iam` is a separate
// store and the consumer projects locally. At that point the revision is
// the only thing distinguishing design §9.3's "lagging within a declared
// bound" from §16.5's "diverged", both of which are still open questions
// that this value is the precondition for answering.
//
// Zero is a real value and means "no authorization write has ever
// happened in this deployment". It is not a wildcard and must not be read
// as "current".
type Revision uint64

// ChangeKind names what a logged change was. The set is closed to the
// three writes that can move an answer in this layer; a fourth is a
// schema migration somebody has to review.
type ChangeKind string

const (
	// ChangeContainerCreated records a container joining the tree, which
	// moves answers for everything placed inside it afterwards.
	ChangeContainerCreated ChangeKind = "container-created"
	// ChangeGrantWritten records a grant.
	ChangeGrantWritten ChangeKind = "grant-written"
	// ChangeGrantRevoked records a revocation. It is logged as its own
	// kind rather than as an absence, because design §9.3's whole point
	// is that a revocation must propagate on a different path from a
	// grant: a projection that misses a grant is an outage and a
	// projection that misses a revocation is a disclosure.
	ChangeGrantRevoked ChangeKind = "grant-revoked"
)

// Valid reports whether k is one of the three recognized kinds.
func (k ChangeKind) Valid() bool {
	switch k {
	case ChangeContainerCreated, ChangeGrantWritten, ChangeGrantRevoked:
		return true
	default:
		return false
	}
}

// Change is one entry of the authorization change log: the unit a
// consumer on another store replays in order to maintain its own
// projection of the authorized set.
type Change struct {
	// Revision is this entry's position in the log, and the cursor a
	// reader stores. Revisions are gapless and assigned in commit order,
	// so seeing revision N implies every revision below it is already
	// visible — which is what makes "every change after the cursor,
	// exactly once" true rather than hoped for.
	Revision Revision
	// TenantID scopes the change.
	TenantID TenantID
	// Kind says what happened.
	Kind ChangeKind
	// Container is the container the change is about: the one created,
	// or the one the grant was written on.
	Container ContainerID
	// Permission is the grant's permission, empty for a container event.
	Permission Permission
	// Subject is the grant's subject, zero for a container event.
	Subject Subject
	// RecordedAt is when the entry was written, in UTC at microsecond
	// precision. It is for human diagnosis only: ordering is Revision's
	// job, because two entries can share an instant and a clock can go
	// backwards.
	RecordedAt time.Time
}

// --- The residual ------------------------------------------------------
//
// # Why this is an expression tree and not a string of SQL
//
// The obvious shape for "the filter a consumer ANDs into its own query"
// is a SQL fragment plus its bound parameters, and this module shipped
// its reasoning that way: design §15's open item asks "whether Predicate
// returns a SQL fragment, a CTE, or a joinable view". All three answers
// have the same defect, and it is not a SQL defect — it is that **SQL
// text would cross the port**. Every consumer would then hold a
// dependency on the string, and a second storage backend would be a
// breaking change to all of them rather than a new renderer here.
//
// So the port returns a *residual*: what is left of the decision once the
// authority has resolved everything it can, expressed as a typed
// expression over a consumer's own column. A backend-specific renderer
// turns it into that backend's query language. This is the shape the field
// converged on — OPA's partial evaluation returns residual policy rather
// than a WHERE clause, and Oso's data filtering returns a filter plan a
// per-adapter translator renders — and the reason both arrived there is
// the one above: one authority, one residual, a small translator per
// backend.
//
// **The Postgres renderer is the only one this increment builds**, in
// internal/authz/pgauthz. That is a deliberate single implementation of a
// deliberately general seam, and not speculation dressed as design: the
// seam costs a type switch, and the thing it buys is that adding a
// backend does not change what any existing consumer compiled against.
//
// **Cassandra is the known hard case, and it is hard in a way a renderer
// cannot fix.** CQL has no arbitrary predicate: a query may filter only
// on the partition key and, within it, a prefix of the clustering
// columns. A residual saying "this row's container key is one the
// principal may read" cannot be rendered into CQL as a filter at all —
// the containment key has to *be* part of the partition or clustering key
// of the table being read, which is a data-modelling constraint on the
// consumer rather than a translation problem here. A renderer for it must
// therefore be allowed to refuse, which is why every render path returns
// an error rather than a string.
//
// # Why there is no attribute term, and no negation
//
// Neither is a gap waiting for a node type. There is no deny mechanism
// anywhere in this design (A3), so there is nothing for a NOT to carry,
// and there is no attribute-granular restriction (findings F4 and F7, now
// one fork), so there is no column-scoped term to express. Adding either
// node here would advertise a capability the authority does not have.

// Key names the consumer's own column holding the containment key: the
// scalar column on each of its rows that says which container that row
// lives in. Finding F1 froze that key as a scalar, and it is the one
// thing a consumer has to add to its own schema in order to use this
// module.
//
// Qualifier is the table or alias the column belongs to, and it is
// usually required rather than optional: a residual rendered into a
// policy or joined into a query with more than one table has to say whose
// column it means. An empty Qualifier renders the bare column.
type Key struct {
	// Qualifier is the table name or alias, or empty for none.
	Qualifier string
	// Column is the column holding the container id.
	Column string
}

// identifierPattern is what Key accepts. It is deliberately narrower than
// what Postgres permits: an unquoted SQL identifier may contain rather
// more, and a quoted one may contain anything at all, but a key is
// something a consumer writes into its own configuration and every real
// one is a plain name.
//
// The renderer quotes identifiers as well, so this is the second of two
// defences rather than the only one. It is here and not only there
// because a Key that no renderer could ever accept should fail where it
// is constructed, not three layers later inside somebody's CREATE POLICY.
var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate reports whether the key names a column a renderer can use.
func (k Key) Validate() error {
	if !identifierPattern.MatchString(k.Column) {
		return fmt.Errorf("%w: %q is not a plain column name", ErrInvalidResidual, k.Column)
	}
	if k.Qualifier != "" && !identifierPattern.MatchString(k.Qualifier) {
		return fmt.Errorf("%w: %q is not a plain table name or alias", ErrInvalidResidual, k.Qualifier)
	}
	return nil
}

// String renders the key for diagnostics. It is not the renderer: a
// renderer quotes.
func (k Key) String() string {
	if k.Qualifier == "" {
		return k.Column
	}
	return k.Qualifier + "." + k.Column
}

// PrincipalRef names whose permissions a term is about, and it has two
// forms because the two places a residual is used need different ones.
//
// A residual joined into one query is about one principal, known when the
// residual is built. A residual rendered into a row-level-security policy
// is not: a policy is created once and evaluated for every principal that
// ever connects, so the principal has to be read from the session at
// evaluation time. The second form is what makes a restrictive policy
// possible at all, and a design that only had the first would have forced
// every consumer to create a policy per principal.
//
// Its fields are unexported so that the zero value is a third thing —
// naming nobody — which every renderer must turn into a refusal rather
// than into a wildcard.
type PrincipalRef struct {
	id      PrincipalID
	session bool
}

// NamedPrincipal returns a reference to one known principal.
func NamedPrincipal(p PrincipalID) PrincipalRef { return PrincipalRef{id: p} }

// SessionPrincipal returns a reference to whichever principal the
// evaluating session's context names — the form a policy needs. A session
// with no principal context must match no rows and raise no error; see
// PrincipalGUC in internal/authz.
func SessionPrincipal() PrincipalRef { return PrincipalRef{session: true} }

// Named returns the principal this reference names, and whether it names
// one directly.
func (r PrincipalRef) Named() (PrincipalID, bool) { return r.id, r.id != "" }

// IsSession reports whether the reference defers to the session context.
func (r PrincipalRef) IsSession() bool { return r.session }

// IsZero reports whether the reference names nobody at all.
func (r PrincipalRef) IsZero() bool { return r.id == "" && !r.session }

// String renders the reference for diagnostics.
func (r PrincipalRef) String() string {
	switch {
	case r.session:
		return "principal:<session>"
	case r.id != "":
		return "principal:" + string(r.id)
	default:
		return "principal:none"
	}
}

// Expr is one node of a residual.
//
// The interface has an unexported method, so no package outside this one
// can add a node. That is the property a renderer depends on: a type
// switch over these five types is exhaustive by construction, and a new
// node cannot appear in a residual without the compiler-visible change of
// adding it here — at which point every renderer's switch has a default
// case that must refuse it.
type Expr interface {
	// Validate reports whether the node is well formed.
	Validate() error
	// String renders the node for diagnostics, never for a database.
	String() string
	isResidualExpr()
}

// None matches no rows. It is the fail-closed residual, and it is a node
// rather than an error because the failure mode a consumer must get is
// **zero rows, never an error**: an error distinguishes "you may not see
// this" from "there is nothing here", which is an existence oracle, and
// it also breaks the consumer's statement instead of filtering it.
type None struct{}

func (None) isResidualExpr() {}

// Validate reports whether the node is well formed. None always is: it is
// the fail-closed node and has nothing to get wrong.
func (None) Validate() error { return nil }

// String renders the node for diagnostics, never for a database.
func (None) String() string { return "false" }

// All matches every row. It is never produced by this module's authority —
// default-deny means there is no request whose answer is "everything" —
// and it exists so that a renderer has a unit for an empty conjunction
// and so that a consumer composing residuals of its own has something to
// start from.
type All struct{}

func (All) isResidualExpr() {}

// Validate reports whether the node is well formed. All always is.
func (All) Validate() error { return nil }

// String renders the node for diagnostics, never for a database.
func (All) String() string { return "true" }

// And is the conjunction of its terms. It is the only combinator, because
// the authority has nothing to disjoin: a principal's permissions on a
// container are one question with one answer, and there is no second,
// alternative route to a row that a renderer would have to OR in.
type And struct{ Terms []Expr }

func (And) isResidualExpr() {}

// Validate reports whether every term is well formed. An empty And is
// valid and means All, which is what a conjunction of nothing is.
func (a And) Validate() error {
	for i, t := range a.Terms {
		if t == nil {
			return fmt.Errorf("%w: conjunction term %d is nil", ErrInvalidResidual, i)
		}
		if err := t.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// String renders the node for diagnostics.
func (a And) String() string {
	if len(a.Terms) == 0 {
		return "true"
	}
	parts := make([]string, 0, len(a.Terms))
	for _, t := range a.Terms {
		parts = append(parts, t.String())
	}
	return "(" + strings.Join(parts, " AND ") + ")"
}

// TenantIs restricts rows to one tenant by the consumer's own tenant
// column.
//
// It is in the residual even though `tenancy` already provides a
// restrictive tenant predicate on the consumer's tables, and the
// duplication is deliberate: a consumer that joins this residual into an
// ordinary query — rather than into a policy — has no policy protecting
// that statement, and a residual that silently spanned tenants there
// would be a cross-tenant read introduced by the authorization layer. A
// consumer ANDing it into a policy gets the check twice, which costs an
// equality test on a column the policy is already filtering.
type TenantIs struct {
	// Key is the consumer's tenant column.
	Key Key
	// Tenant is the tenant to restrict to.
	Tenant TenantID
}

func (TenantIs) isResidualExpr() {}

// Validate reports whether the term is well formed.
func (t TenantIs) Validate() error {
	if err := t.Key.Validate(); err != nil {
		return err
	}
	if t.Tenant == "" {
		return fmt.Errorf("%w: tenant term names no tenant", ErrInvalidResidual)
	}
	return nil
}

// String renders the node for diagnostics.
func (t TenantIs) String() string {
	return t.Key.String() + " = tenant:" + string(t.Tenant)
}

// ContainerPermits is the authorization term, and it is the whole of what
// this layer has to say: the row's container key names a container on
// which this principal holds this permission, directly or through a group
// it is a live member of, written there or on any ancestor.
//
// It is one opaque term rather than a tree of joins, and that is the
// point of returning a residual at all. What a renderer expands it into
// is backend-specific — in Postgres an EXISTS over the containment
// closure, the grants and the live membership view; in a document store a
// membership test against a projected array; in CQL, nothing, unless the
// container key is part of the table's partition or clustering key. A
// residual that spelled out the join would have fixed Postgres's answer
// into every consumer's code.
type ContainerPermits struct {
	// Key is the consumer's column holding the row's container id.
	Key Key
	// Principal is whose permissions this is about.
	Principal PrincipalRef
	// Permission is what they must hold.
	Permission Permission
}

func (ContainerPermits) isResidualExpr() {}

// Validate reports whether the term is well formed. A term naming no
// principal is refused rather than rendered, because the only two things
// a renderer could do with it are to match nothing — which None already
// says, explicitly — or to match everything, which would be the whole
// authorization layer failing open on a zero value.
func (c ContainerPermits) Validate() error {
	if err := c.Key.Validate(); err != nil {
		return err
	}
	if c.Principal.IsZero() {
		return fmt.Errorf("%w: authorization term names no principal; use SessionPrincipal for a policy, or None to match nothing", ErrInvalidResidual)
	}
	if strings.TrimSpace(string(c.Permission)) == "" {
		return fmt.Errorf("%w: authorization term names no permission", ErrInvalidResidual)
	}
	return nil
}

// String renders the node for diagnostics.
func (c ContainerPermits) String() string {
	return fmt.Sprintf("%s ∈ containers(%s, %s)", c.Key.String(), c.Principal, c.Permission)
}

// Residual is what the authority returns for a filtered read: the
// expression a consumer must apply to its own rows, and the revision of
// the authorization state it was computed against.
//
// The revision is here for the same reason it is on a Decision, and it
// matters slightly more: a residual is held and re-used across statements
// more readily than a point decision is, so the value that says what it
// was computed against is the only thing that can later say it is stale.
type Residual struct {
	// Revision is the authorization state the residual reflects.
	Revision Revision
	// Expr is the expression to apply. It is never nil for a residual
	// this module produced: a refusal is None, explicitly.
	Expr Expr
}

// Validate reports whether the residual is well formed.
func (r Residual) Validate() error {
	if r.Expr == nil {
		return fmt.Errorf("%w: residual carries no expression; a refusal is None, explicitly", ErrInvalidResidual)
	}
	return r.Expr.Validate()
}

// DeniesEverything reports whether the residual can match no row at all.
// It is a convenience for a consumer that would rather skip a query than
// run one that cannot return anything.
func (r Residual) DeniesEverything() bool {
	_, none := r.Expr.(None)
	return none
}

// String renders the residual for diagnostics and a test failure, never
// for a database.
func (r Residual) String() string {
	if r.Expr == nil {
		return fmt.Sprintf("residual@%d(nil)", r.Revision)
	}
	return fmt.Sprintf("residual@%d %s", r.Revision, r.Expr)
}
