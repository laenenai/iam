package pgauthz

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/laenenai/iam/internal/authz"
	"github.com/laenenai/iam/internal/domain"
)

// This file is the Postgres renderer: the one place in this module where a
// residual becomes SQL, and the one place where SQL is hand-composed
// rather than generated.
//
// CONVENTIONS names exactly this case as the standing exception to sqlc —
// "SQL composed at runtime ... there is no fixed query to generate" — and
// requires the text to be kept in one place rather than assembled across
// methods. The text is containerPermitsTemplate below, once, with the two
// forms of the deciding principal substituted into it.
//
// # Why there are two forms
//
// A residual joined into one query is about one principal, known when the
// residual is built, so the principal is a bound parameter. A residual
// rendered into a row-level-security policy is not: a policy is created
// once and evaluated for every principal that ever connects, so the
// principal has to be read from the session. Those are the two renderings
// below, and they differ in that one substitution and nothing else.
//
// # The failure mode is zero rows, never an error
//
// This is the property the whole file is arranged around, because it is
// the one a consumer's policy depends on. A policy that raises is worse
// than one that denies in three separate ways: it breaks the consumer's
// statement rather than filtering it, it distinguishes "you may not see
// this" from "there is nothing here" — which is an existence oracle — and
// it turns an authorization decision into an outage.
//
// Three things follow, and each one is a defence against a different way
// of raising:
//
//   - **No casts on the way in.** The policy form compares the principal
//     column to `nullif(current_setting(…, true), '')`, which is text, so
//     Postgres resolves `text = text` and coerces the iam.ulid domain
//     down to its base type. A cast the other way — to iam.ulid, or to
//     uuid — would apply the domain's format CHECK to whatever the
//     session happens to hold and *raise* for a caller with no principal
//     context instead of quietly denying. This is tenancy's own tenant
//     predicate reasoning, applied to the principal.
//   - **nullif, so "never set" and "set earlier, now ended" are one
//     thing.** current_setting(…, true) returns NULL when the setting has
//     never been touched and the empty string once any transaction on the
//     connection has set it and ended. nullif collapses both to NULL,
//     `column = NULL` is NULL, and Postgres treats NULL as false in a
//     policy — so the row is filtered and nothing is raised.
//   - **A malformed value is refused before it reaches the database.** In
//     the query form the principal is a bound parameter whose type
//     Postgres infers from the column, which is the iam.ulid domain — so
//     a malformed id would fail the domain's CHECK and raise. Render
//     therefore parses it first and returns the `false` rendering instead.
//     The policy form needs no such check because its comparison never
//     coerces upward.

// Fragment is rendered SQL together with the parameters it binds, in
// order.
//
// It is the renderer's output and not the port's: SQL text never crosses
// authz.Authorizer, for the reason domain's residual doc gives at length.
// A consumer holds this type only because it asked this backend to render
// for it.
type Fragment struct {
	// SQL is a boolean expression, parenthesized, safe to AND into a
	// larger WHERE clause.
	SQL string
	// Args are the values SQL's placeholders bind, in order, starting at
	// the firstArg given to Render.
	Args []any
}

// containerPermitsTemplate is the expansion of domain.ContainerPermits:
// "this row's container key names a container on which this principal
// holds this permission".
//
// It is one EXISTS over three artifacts, and which three is the whole
// design of this module compressed into a join:
//
//   - **iam.container_closure**, keyed on the container, which is what
//     turns "or any ancestor" into an index probe instead of a recursive
//     walk. The reflexive depth-0 row is why "the container itself" needs
//     no second clause.
//   - **iam.grants**, where a grant is written once on a container and
//     reaches everything inside it — one row per share rather than one
//     per resource.
//   - **iam.live_group_members and iam.live_principals**, the identity
//     registry's own views, joined rather than copied. That is what makes
//     deprovisioning cascade for free: the view excludes a deprovisioned
//     principal in the same statement that records the deprovisioning, so
//     a consumer's next read stops matching at once. A second copy of
//     membership would keep reading until somebody synced it.
//
// The principal's tenant is checked against the closure row's rather than
// taken on trust, because a membership can cross a tenant: iam.group_members
// has no tenant column and AddGroupMember compares none, so without this a
// principal in another tenant who had been added to a group in this one
// would be allowed by this tenant's group grant. The grants' own composite
// foreign keys cover the direct arm; this conjunct is for the group arm and
// is written once, above both.
//
// %[1]s is the consumer's container-key column, quoted. %[2]s is the
// permission. %[3]s is the deciding principal — a placeholder, or the
// session expression.
const containerPermitsTemplate = `EXISTS (
    SELECT 1
    FROM iam.container_closure cc
    JOIN iam.grants g
      ON g.container_id = cc.ancestor_id
     AND g.permission = %[2]s
    WHERE cc.container_id = %[1]s
      AND EXISTS (
          SELECT 1 FROM iam.principals pr
          WHERE pr.id = %[3]s AND pr.tenant_id = cc.tenant_id
      )
      AND (
            (
              g.principal_id = %[3]s
              AND EXISTS (SELECT 1 FROM iam.live_principals lp WHERE lp.id = %[3]s)
            )
         OR EXISTS (
              SELECT 1 FROM iam.live_group_members lgm
              WHERE lgm.group_id = g.group_id AND lgm.principal_id = %[3]s
            )
      )
)`

// sessionPrincipalExpr reads the deciding principal from the session, for
// the policy form. See this file's header for why there is no cast and why
// nullif is not decoration.
var sessionPrincipalExpr = "nullif(current_setting('" + authz.PrincipalGUC + "', true), '')"

// Render renders r for use inside an ordinary query, numbering its
// placeholders from firstArg.
//
// firstArg is explicit because a residual is ANDed into a statement the
// consumer already wrote, which already has parameters; a renderer that
// assumed $1 would collide with whatever the consumer bound first. Pass
// len(existingArgs)+1.
//
// A residual that can match nothing renders as `false` with no arguments,
// which is the whole point of domain.None reaching the renderer as a node
// rather than as an error.
func Render(r domain.Residual, firstArg int) (Fragment, error) {
	if err := r.Validate(); err != nil {
		return Fragment{}, err
	}
	if firstArg < 1 {
		return Fragment{}, fmt.Errorf("%w: first argument index %d is not a valid Postgres placeholder", domain.ErrInvalidResidual, firstArg)
	}
	b := &builder{next: firstArg}
	sql, err := b.expr(r.Expr)
	if err != nil {
		return Fragment{}, err
	}
	return Fragment{SQL: sql, Args: b.args}, nil
}

// RenderPolicy renders r as a parameterless boolean expression, for use as
// the USING clause of a row-level-security policy.
//
// The deciding principal comes from the session rather than from a
// parameter, because a policy is created once and evaluated for every
// principal. A consumer establishes it exactly as it establishes the
// tenant — `SELECT set_config('app.principal_id', $1, true)` inside its
// transaction — and a statement that establishes neither matches no rows
// and raises nothing.
//
// It refuses a residual carrying a tenant term, and the refusal is
// instructive rather than pedantic: a literal tenant inside a policy would
// pin that policy to one tenant, which is not what a policy is. Omit
// FilterRequest.TenantKey when the residual is destined for a policy and
// let `tenancy`'s own restrictive tenant policy do that half — it is
// already on the same table, it reads the tenant from the session the same
// way, and it cannot be OR-ed away by a later permissive policy.
func RenderPolicy(r domain.Residual) (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
	b := &builder{policy: true}
	return b.expr(r.Expr)
}

// builder accumulates one rendering. It carries the parameter numbering
// for the query form and nothing for the policy form.
type builder struct {
	policy bool
	next   int
	args   []any
}

// placeholder binds v and returns the SQL that reads it: a numbered
// placeholder in the query form. It is never called in the policy form —
// a policy has nothing to bind — and panicking there would be a worse
// answer than the error every path here returns, so callers branch
// explicitly on b.policy instead.
func (b *builder) placeholder(v any) string {
	b.args = append(b.args, v)
	p := "$" + strconv.Itoa(b.next)
	b.next++
	return p
}

// expr renders one node. The type switch is exhaustive by construction:
// domain.Expr's method set includes an unexported method, so no package
// outside internal/domain can add a node, and adding one there is a
// compiler-visible change that lands in this default case.
func (b *builder) expr(e domain.Expr) (string, error) {
	switch node := e.(type) {
	case domain.None:
		return "false", nil
	case domain.All:
		return "true", nil
	case domain.And:
		return b.and(node)
	case domain.TenantIs:
		return b.tenantIs(node)
	case domain.ContainerPermits:
		return b.containerPermits(node)
	default:
		return "", fmt.Errorf("%w: postgres renderer does not know residual node %T", domain.ErrUnrenderable, e)
	}
}

func (b *builder) and(node domain.And) (string, error) {
	if len(node.Terms) == 0 {
		// A conjunction of nothing is true, which is what an empty And
		// means. It is never produced by this module's authority.
		return "true", nil
	}
	parts := make([]string, 0, len(node.Terms))
	for _, t := range node.Terms {
		sql, err := b.expr(t)
		if err != nil {
			return "", err
		}
		parts = append(parts, sql)
	}
	return "(" + strings.Join(parts, "\n  AND ") + ")", nil
}

func (b *builder) tenantIs(node domain.TenantIs) (string, error) {
	if b.policy {
		return "", fmt.Errorf("%w: a tenant term cannot be rendered into a policy, because a policy is created "+
			"once and evaluated for every tenant and a literal tenant would pin it to one. Omit TenantKey from the "+
			"filter request and let tenancy's own restrictive tenant policy scope the table — it is already there, "+
			"it reads the tenant from the session, and it cannot be OR-ed away", domain.ErrUnrenderable)
	}
	// The tenant is a bound parameter compared to the consumer's own
	// column. It is parsed first for the reason Render's own principal
	// check gives: if that column is a domain with a format CHECK, a
	// malformed value would raise rather than match nothing.
	if _, err := domain.ParseTenantID(string(node.Tenant)); err != nil {
		return "false", nil
	}
	column, err := quoteKey(node.Key)
	if err != nil {
		return "", err
	}
	return "(" + column + " = " + b.placeholder(string(node.Tenant)) + ")", nil
}

func (b *builder) containerPermits(node domain.ContainerPermits) (string, error) {
	column, err := quoteKey(node.Key)
	if err != nil {
		return "", err
	}

	var permission, principal string
	if b.policy {
		if !node.Principal.IsSession() {
			return "", fmt.Errorf("%w: a policy cannot name one principal, because it is created once and "+
				"evaluated for every principal; build the residual with domain.SessionPrincipal()", domain.ErrUnrenderable)
		}
		// Both values are literals in a policy, so both are quoted. The
		// permission has already been constrained to a safe shape at
		// schema registration (domain.Schema.Validate), so this quoting
		// is the second of two defences rather than the only one.
		if err := validatePermissionLiteral(node.Permission); err != nil {
			return "", err
		}
		permission = quoteLiteral(string(node.Permission))
		principal = sessionPrincipalExpr
	} else {
		p, named := node.Principal.Named()
		if !named {
			return "", fmt.Errorf("%w: a residual built for the session's principal has no principal to bind; "+
				"render it with RenderPolicy, or rebuild it with domain.NamedPrincipal", domain.ErrUnrenderable)
		}
		if _, err := domain.ParsePrincipalID(string(p)); err != nil {
			// A malformed principal id would be coerced to the iam.ulid
			// domain by Postgres's parameter inference and raise on its
			// format CHECK. `false` is the honest rendering: this
			// principal matches nothing, and nothing is raised.
			return "false", nil
		}
		permission = b.placeholder(string(node.Permission))
		principal = b.placeholder(string(p))
	}
	return fmt.Sprintf(containerPermitsTemplate, column, permission, principal), nil
}

// quoteKey renders a consumer's column reference as a safely quoted SQL
// identifier. domain.Key has already refused anything but a plain name, so
// this is the second of two defences; it is here as well because a renderer
// that interpolated an identifier raw would be one validation change away
// from an injection.
func quoteKey(k domain.Key) (string, error) {
	if err := k.Validate(); err != nil {
		return "", err
	}
	if k.Qualifier == "" {
		return pgx.Identifier{k.Column}.Sanitize(), nil
	}
	return pgx.Identifier{k.Qualifier, k.Column}.Sanitize(), nil
}

// validatePermissionLiteral refuses a permission that cannot be safely
// written into policy text. domain.Schema.Validate already constrains a
// registered permission to this shape, so reaching this error means a
// residual was built with a permission no schema could have declared.
func validatePermissionLiteral(p domain.Permission) error {
	if !domain.ValidPermissionName(p) {
		return fmt.Errorf("%w: permission %q is not a plain name, so it cannot be written into policy text", domain.ErrUnrenderable, p)
	}
	return nil
}

// quoteLiteral renders s as a Postgres string literal. Doubling the single
// quote is the whole of it: `standard_conforming_strings` is on by default
// since 9.1, so a backslash in a plain literal is an ordinary character and
// there is no escape sequence to neutralize.
func quoteLiteral(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
