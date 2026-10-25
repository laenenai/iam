package pgauthz_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenenai/iam/internal/authz"
	"github.com/laenenai/iam/internal/authz/pgauthz"
	"github.com/laenenai/iam/internal/domain"
)

// These tests need no database, and that is deliberate: the renderer's
// output is a *text* artifact with security properties, and several of
// those properties are about what the text does **not** contain. A test
// that only ran the statement would pass for a rendering that happens to
// work today against this Postgres and raises against the next one.
//
// The companion assertions that do need a database — that the policy
// filters, that it cannot be widened, that no principal context yields zero
// rows and no error — are in pgauthz_test.go. These are the ones that can
// fail in the inner loop.

func policyResidual(key domain.Key) domain.Residual {
	return domain.Residual{Revision: 3, Expr: domain.ContainerPermits{
		Key:        key,
		Principal:  domain.SessionPrincipal(),
		Permission: "read",
	}}
}

// TestThePolicyRenderingHasNoCastOnThePrincipal is the property the whole
// renderer is arranged around, as an assertion about text.
//
// `tenancy`'s tenant predicate records the reasoning for its own half and
// it applies here verbatim. Every id in this system is a Crockford base32
// ULID and never a uuid, so a cast to uuid would raise on every real row;
// and `current_setting(…, true)` returns the empty string rather than NULL
// once any transaction on the connection has touched the setting, so a
// cast to anything at all would raise for a caller with no principal
// context — turning a quiet, correct denial into a failure that caller can
// distinguish, which is an existence oracle.
func TestThePolicyRenderingHasNoCastOnThePrincipal(t *testing.T) {
	t.Parallel()
	using, err := pgauthz.RenderPolicy(policyResidual(domain.Key{Qualifier: "quads", Column: "graph_id"}))
	if err != nil {
		t.Fatalf("RenderPolicy: %v", err)
	}

	want := "nullif(current_setting('" + authz.PrincipalGUC + "', true), '')"
	if !strings.Contains(using, want) {
		t.Fatalf("the policy does not read the principal as %s.\nrendered:\n%s\n\n"+
			"nullif is not decoration: current_setting returns NULL when the setting was never touched and the "+
			"empty string once a transaction has set it and ended, and only collapsing both to NULL makes "+
			"`column = NULL` — which Postgres reads as false in a policy — the answer in both cases", want, using)
	}
	for _, cast := range []string{"::uuid", "::iam.ulid", "::text)", "CAST("} {
		if strings.Contains(using, cast) {
			t.Errorf("the policy casts the session value (%s).\nrendered:\n%s\n\n"+
				"A cast applies the iam.ulid domain's format CHECK to whatever the session happens to hold, so a "+
				"caller with no principal context gets a raised error instead of zero rows", cast, using)
		}
	}
	// The GUC name is pinned by exact equality rather than by a sweep for
	// substrings of this module's import path, and the exact form is the
	// stronger of the two: it also catches the rename that does not happen
	// to contain one.
	//
	// Why it is pinned at all is the reason `tenancy` records for its own.
	// The name appears verbatim in the policy SQL of every consumer that
	// adopts this, so moving it silently stops matching their existing
	// policies while everything still compiles — and a policy that no
	// longer matches does not fail, it stops filtering. It therefore
	// deliberately contains no part of this module's import path, so that a
	// module rename cannot move it; on 2026-10-23 exactly that rewrote a
	// hash function's domain-separation tag in a sibling module and
	// invalidated its committed test vectors.
	if authz.PrincipalGUC != "app.principal_id" {
		t.Errorf("PrincipalGUC = %q, want \"app.principal_id\"", authz.PrincipalGUC)
	}
}

// TestTheRenderingJoinsTheRegistrysOwnViews is how "compose rather than
// duplicate" is held in place. If a later change replaced
// iam.live_group_members with a table of this layer's own, every behavioural
// test would still pass — right up to the first deprovisioning that did not
// propagate.
func TestTheRenderingJoinsTheRegistrysOwnViews(t *testing.T) {
	t.Parallel()
	using, err := pgauthz.RenderPolicy(policyResidual(domain.Key{Column: "graph_id"}))
	if err != nil {
		t.Fatalf("RenderPolicy: %v", err)
	}
	for _, artifact := range []string{
		"iam.container_closure",
		"iam.grants",
		"iam.live_group_members",
		"iam.live_principals",
		"iam.principals",
	} {
		if !strings.Contains(using, artifact) {
			t.Errorf("the rendering does not read %s.\nrendered:\n%s", artifact, using)
		}
	}
	if strings.Contains(using, "iam.group_members ") {
		t.Errorf("the rendering reads iam.group_members directly rather than through "+
			"iam.live_group_members, so it would match a deprovisioned principal's memberships.\nrendered:\n%s", using)
	}
	// The closure is probed by container and the grants by (container,
	// permission): those are the two indexes, and a rendering that joined
	// them the other way round would be correct and slow.
	if !strings.Contains(using, "cc.container_id = ") {
		t.Errorf("the rendering does not probe the closure by container_id.\nrendered:\n%s", using)
	}
	if !strings.Contains(using, "g.container_id = cc.ancestor_id") {
		t.Errorf("the rendering does not join grants to the closure's ancestors.\nrendered:\n%s", using)
	}
}

// TestIdentifiersAndLiteralsAreQuoted is the second of two defences.
// domain.Key already refuses anything but a plain name, so this is not the
// only thing standing between a consumer's configuration and injected
// policy text — it is here as well because a renderer that interpolated an
// identifier raw would be one validation change away from being the only
// thing.
func TestIdentifiersAndLiteralsAreQuoted(t *testing.T) {
	t.Parallel()

	using, err := pgauthz.RenderPolicy(policyResidual(domain.Key{Qualifier: "tenant_quads", Column: "graph_id"}))
	if err != nil {
		t.Fatalf("RenderPolicy: %v", err)
	}
	if !strings.Contains(using, `"tenant_quads"."graph_id"`) {
		t.Errorf("the consumer's column is not rendered as a quoted identifier.\nrendered:\n%s", using)
	}
	if !strings.Contains(using, `'read'`) {
		t.Errorf("the permission is not rendered as a quoted literal.\nrendered:\n%s", using)
	}

	// A key that is not a plain name is refused by the residual's own
	// validation, before any rendering happens.
	for _, key := range []domain.Key{
		{Column: "graph_id; DROP TABLE quads"},
		{Column: `graph_id" , (SELECT 1) AS "x`},
		{Qualifier: "q; --", Column: "graph_id"},
		{Column: ""},
		{Column: "1graph"},
	} {
		if _, err := pgauthz.RenderPolicy(policyResidual(key)); !errors.Is(err, domain.ErrInvalidResidual) {
			t.Errorf("RenderPolicy with key %+v returned %v, want ErrInvalidResidual", key, err)
		}
	}

	// A permission that is not a plain name cannot be registered, so it
	// cannot reach a residual through the port — but a residual built by
	// hand can carry one, and the renderer refuses rather than quoting and
	// hoping.
	hand := domain.Residual{Revision: 1, Expr: domain.ContainerPermits{
		Key:        domain.Key{Column: "graph_id"},
		Principal:  domain.SessionPrincipal(),
		Permission: "read'); DROP POLICY quad_read ON quads; --",
	}}
	if _, err := pgauthz.RenderPolicy(hand); !errors.Is(err, domain.ErrUnrenderable) {
		t.Errorf("RenderPolicy with a permission that is not a plain name returned %v, want ErrUnrenderable", err)
	}
}

// TestTheQueryFormNumbersItsPlaceholdersFromWhereItIsTold. A residual is
// ANDed into a statement the consumer already wrote, which already has
// parameters, so a renderer that assumed $1 would collide with whatever the
// consumer bound first — and the collision would not be a compile error. It
// would be a predicate about the wrong values.
func TestTheQueryFormNumbersItsPlaceholdersFromWhereItIsTold(t *testing.T) {
	t.Parallel()
	principal := domain.NewPrincipalID(domain.SystemClock{})
	tenant := domain.NewTenantID(domain.SystemClock{})
	residual := domain.Residual{Revision: 1, Expr: domain.And{Terms: []domain.Expr{
		domain.TenantIs{Key: domain.Key{Qualifier: "q", Column: "tenant_id"}, Tenant: tenant},
		domain.ContainerPermits{
			Key:        domain.Key{Qualifier: "q", Column: "graph_id"},
			Principal:  domain.NamedPrincipal(principal),
			Permission: "read",
		},
	}}}

	fragment, err := pgauthz.Render(residual, 4)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Three values: the tenant, the permission, the principal — in the
	// order the expression reads them.
	want := []any{string(tenant), "read", string(principal)}
	if len(fragment.Args) != len(want) {
		t.Fatalf("Render bound %d args, want %d: %v", len(fragment.Args), len(want), fragment.Args)
	}
	for i := range want {
		if fragment.Args[i] != want[i] {
			t.Errorf("arg %d = %v, want %v", i, fragment.Args[i], want[i])
		}
	}
	for i := range want {
		placeholder := "$" + string(rune('4'+i))
		if !strings.Contains(fragment.SQL, placeholder) {
			t.Errorf("the fragment does not use %s.\nrendered:\n%s", placeholder, fragment.SQL)
		}
	}
	if strings.Contains(fragment.SQL, "$1") || strings.Contains(fragment.SQL, "$2") || strings.Contains(fragment.SQL, "$3") {
		t.Errorf("the fragment numbered placeholders below the index it was given, which would rebind the "+
			"consumer's own parameters.\nrendered:\n%s", fragment.SQL)
	}
	if _, err := pgauthz.Render(residual, 0); !errors.Is(err, domain.ErrInvalidResidual) {
		t.Errorf("Render from index 0 returned %v, want ErrInvalidResidual: Postgres placeholders start at $1", err)
	}
}

// TestNoneAndAllRenderToConstants. None is the fail-closed residual and it
// has to render to something a policy can hold, because the alternative —
// an error — breaks the consumer's statement instead of filtering it.
func TestNoneAndAllRenderToConstants(t *testing.T) {
	t.Parallel()
	cases := []struct {
		expr domain.Expr
		want string
	}{
		{domain.None{}, "false"},
		{domain.All{}, "true"},
		{domain.And{}, "true"}, // a conjunction of nothing
	}
	for _, c := range cases {
		using, err := pgauthz.RenderPolicy(domain.Residual{Revision: 1, Expr: c.expr})
		if err != nil {
			t.Fatalf("RenderPolicy(%T): %v", c.expr, err)
		}
		if using != c.want {
			t.Errorf("RenderPolicy(%T) = %q, want %q", c.expr, using, c.want)
		}
		fragment, err := pgauthz.Render(domain.Residual{Revision: 1, Expr: c.expr}, 1)
		if err != nil {
			t.Fatalf("Render(%T): %v", c.expr, err)
		}
		if fragment.SQL != c.want || len(fragment.Args) != 0 {
			t.Errorf("Render(%T) = %q with %d args, want %q with none", c.expr, fragment.SQL, len(fragment.Args), c.want)
		}
	}

	// A residual with no expression at all is refused rather than rendered
	// as either constant: a nil expression is a bug in whoever built it,
	// and guessing which constant it meant is the authorization layer
	// guessing.
	if _, err := pgauthz.RenderPolicy(domain.Residual{Revision: 1}); !errors.Is(err, domain.ErrInvalidResidual) {
		t.Errorf("RenderPolicy with a nil expression returned %v, want ErrInvalidResidual", err)
	}
}

// TestAMalformedTenantRendersToFalse is the same defence the principal
// gets, for the other bound value. A consumer's tenant column may be a
// domain with a format CHECK, and Postgres infers a parameter's type from
// the column it is compared to.
func TestAMalformedTenantRendersToFalse(t *testing.T) {
	t.Parallel()
	residual := domain.Residual{Revision: 1, Expr: domain.TenantIs{
		Key:    domain.Key{Column: "tenant_id"},
		Tenant: "not-a-ulid",
	}}
	fragment, err := pgauthz.Render(residual, 1)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if fragment.SQL != "false" || len(fragment.Args) != 0 {
		t.Errorf("Render with a malformed tenant id produced %q with %d args, want `false` with none",
			fragment.SQL, len(fragment.Args))
	}
}
