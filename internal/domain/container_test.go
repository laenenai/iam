package domain_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/laenenai/iam/internal/domain"
)

// tree is the shape every consumer's declaration has to be: each kind
// names at most one parent.
func tree() domain.Schema {
	return domain.Schema{
		Name:    "consumer",
		Version: 1,
		Kinds: []domain.ContainerKind{
			{Name: "tenant"},
			{Name: "fileset", Parents: []string{"tenant"}},
			{Name: "document", Parents: []string{"fileset"}},
			{Name: "slot", Parents: []string{"document"}},
		},
		Permissions: []domain.Permission{"read", "write"},
	}
}

func TestSchemaValidateAcceptsATree(t *testing.T) {
	t.Parallel()
	if err := tree().Validate(); err != nil {
		t.Fatalf("CAS's own containment — tenant > fileset > document > slot — was refused: %v", err)
	}
}

// TestSchemaValidateRefusesASecondContainmentParent is the finding-F3
// refusal, and the reason this function exists at all: design §8.4
// accepted a declaration giving a resource two parents, and the consumer
// then silently got a closure keyed on the resource rather than on the
// container.
//
// The assertions are on the sentinel, on the message, and on the numbers,
// because a caller that hits this cannot act on a sentinel alone — it has
// to change a data model or reopen F3, and the thing that tells it which
// is worth doing is the 295× in the message.
func TestSchemaValidateRefusesASecondContainmentParent(t *testing.T) {
	t.Parallel()
	s := domain.Schema{
		Name:    "kgs-as-it-was",
		Version: 1,
		Kinds: []domain.ContainerKind{
			{Name: "graph"},
			{Name: "episode", Parents: []string{"graph"}},
			{Name: "entity-set", Parents: []string{"graph"}},
			{Name: "fact", Parents: []string{"episode", "entity-set"}},
		},
		Permissions: []domain.Permission{"read"},
	}

	err := s.Validate()
	if !errors.Is(err, domain.ErrMultipleContainmentParents) {
		t.Fatalf("Validate = %v, want ErrMultipleContainmentParents", err)
	}
	if errors.Is(err, domain.ErrInvalidSchema) {
		t.Error("the multi-parent refusal also matches ErrInvalidSchema, which collapses two different answers. " +
			"A malformed schema is a typo the caller fixes; a DAG is a data model the caller has to change or a " +
			"finding it has to reopen, and a caller branching on the sentinel needs them apart")
	}
	msg := err.Error()
	for _, needle := range []string{"kgs-as-it-was", "fact", "episode", "entity-set", "106,495,540", "433,063", "F3"} {
		if !strings.Contains(msg, needle) {
			t.Errorf("the refusal does not mention %q: %s", needle, msg)
		}
	}
}

func TestSchemaValidateRefusesWhatIsNotWellFormed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*domain.Schema)
		want   error
	}{
		{"no name", func(s *domain.Schema) { s.Name = "  " }, domain.ErrInvalidSchema},
		{"no kinds", func(s *domain.Schema) { s.Kinds = nil }, domain.ErrInvalidSchema},
		{"no permissions", func(s *domain.Schema) { s.Permissions = nil }, domain.ErrInvalidSchema},
		{"an empty kind name", func(s *domain.Schema) { s.Kinds[0].Name = "" }, domain.ErrInvalidSchema},
		{
			"a kind declared twice",
			func(s *domain.Schema) { s.Kinds = append(s.Kinds, domain.ContainerKind{Name: "fileset"}) },
			domain.ErrInvalidSchema,
		},
		{
			"a permission declared twice",
			func(s *domain.Schema) { s.Permissions = append(s.Permissions, "read") },
			domain.ErrInvalidSchema,
		},
		{
			"a kind inside an undeclared kind",
			func(s *domain.Schema) { s.Kinds[1].Parents = []string{"nowhere"} },
			domain.ErrInvalidSchema,
		},
		{
			"a kind inside itself",
			func(s *domain.Schema) { s.Kinds[1].Parents = []string{"fileset"} },
			domain.ErrInvalidSchema,
		},
		{
			// Every kind having a parent is not a deep tree, it is a
			// cycle: there is no root to walk to.
			"no root kind",
			func(s *domain.Schema) { s.Kinds[0].Parents = []string{"slot"} },
			domain.ErrInvalidSchema,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			s := tree()
			c.mutate(&s)
			if err := s.Validate(); !errors.Is(err, c.want) {
				t.Fatalf("Validate with %s = %v, want %v", c.name, err, c.want)
			}
		})
	}
}

// TestPermissionNamesAreRestrictedBecauseAPolicyCarriesThemAsLiterals is a
// narrowing that only makes sense once you know where a permission ends
// up: written as a literal into the text of a row-level-security policy.
// Refusing a quote here means no residual can ever carry one, which is a
// cheaper guarantee than a correct quoting function nobody forgets to call.
func TestPermissionNamesAreRestrictedBecauseAPolicyCarriesThemAsLiterals(t *testing.T) {
	t.Parallel()
	ok := []domain.Permission{"read", "write", "iam.read", "graph:read", "read-only", "R2", "_internal"}
	for _, p := range ok {
		if !domain.ValidPermissionName(p) {
			t.Errorf("ValidPermissionName(%q) = false, want true", p)
		}
	}
	bad := []domain.Permission{
		"",
		" read",
		"read ",
		"read'); DROP POLICY quad_read ON quads; --",
		"re'ad",
		`re"ad`,
		"read\n",
		".read",
		domain.Permission(strings.Repeat("a", 65)),
	}
	for _, p := range bad {
		if domain.ValidPermissionName(p) {
			t.Errorf("ValidPermissionName(%q) = true, want false", p)
		}
		s := tree()
		s.Permissions = []domain.Permission{p}
		if err := s.Validate(); !errors.Is(err, domain.ErrInvalidSchema) {
			t.Errorf("a schema declaring permission %q was accepted: %v", p, err)
		}
	}
}

// TestSubjectHasExactlyTwoStates is the whole argument for the type being
// opaque. A pair of exported id fields would have had four states, two of
// which — both set, and neither — nobody could say what they mean.
func TestSubjectHasExactlyTwoStates(t *testing.T) {
	t.Parallel()

	p := domain.PrincipalSubject("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if got, ok := p.Principal(); !ok || got != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("PrincipalSubject.Principal() = %q, %v", got, ok)
	}
	if _, ok := p.Group(); ok {
		t.Error("a principal subject also reports a group, so it is in two states at once")
	}
	if p.IsZero() {
		t.Error("a principal subject reports itself as naming nobody")
	}

	g := domain.GroupSubject("01ARZ3NDEKTSV4RRFFQ69G5FAW")
	if got, ok := g.Group(); !ok || got != "01ARZ3NDEKTSV4RRFFQ69G5FAW" {
		t.Fatalf("GroupSubject.Group() = %q, %v", got, ok)
	}
	if _, ok := g.Principal(); ok {
		t.Error("a group subject also reports a principal")
	}

	var zero domain.Subject
	if !zero.IsZero() {
		t.Error("the zero Subject does not report itself as naming nobody")
	}
	if err := zero.Validate(); !errors.Is(err, domain.ErrInvalidGrant) {
		t.Errorf("the zero Subject validates as %v, want ErrInvalidGrant: it is not a wildcard and must never match", err)
	}

	// The rendering is the design's own notation, and it is also the
	// ordering both adapters sort grants by, so it is pinned.
	if p.String() != "principal:01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("principal subject renders as %q", p.String())
	}
	if g.String() != "group:01ARZ3NDEKTSV4RRFFQ69G5FAW#member" {
		t.Errorf("group subject renders as %q", g.String())
	}
	if zero.String() != "subject:none" {
		t.Errorf("the zero subject renders as %q", zero.String())
	}
}

// TestSubjectIsUsableAsAMapKey is not a test of Go. It is a test that the
// opaque form did not cost the thing both adapters rely on: a grant's
// identity is (container, permission, subject), and the in-memory adapter
// keys a map on exactly that.
func TestSubjectIsUsableAsAMapKey(t *testing.T) {
	t.Parallel()
	m := map[domain.Subject]int{}
	m[domain.PrincipalSubject("p")] = 1
	m[domain.GroupSubject("p")] = 2
	if len(m) != 2 {
		t.Fatalf("a principal and a group with the same id collapsed to one key, so a grant to the group would " +
			"be mistaken for a grant to the principal")
	}
	m[domain.PrincipalSubject("p")] = 3
	if len(m) != 2 || m[domain.PrincipalSubject("p")] != 3 {
		t.Fatal("the same subject did not map to the same key")
	}
}

// TestDecisionConstructorsReportTheOutermostForm pins the convention the
// use-case corpus's reference oracle already uses: the reason is the
// outermost form that fired, because that is the one a consumer debugging a
// decision needs first, and the depth is a separate fact rather than a
// fifth enum value.
func TestDecisionConstructorsReportTheOutermostForm(t *testing.T) {
	t.Parallel()
	direct := domain.Grant{Container: "c", Permission: "read", Subject: domain.PrincipalSubject("p")}
	group := domain.Grant{Container: "c", Permission: "read", Subject: domain.GroupSubject("g")}

	cases := []struct {
		name  string
		got   domain.Decision
		want  domain.Reason
		depth int
	}{
		{"a grant to the principal on the container itself", domain.Allow(direct, 0, 7), domain.ReasonDirect, 0},
		{"a grant to a group on the container itself", domain.Allow(group, 0, 7), domain.ReasonUserset, 0},
		{"a grant to the principal on an ancestor", domain.Allow(direct, 2, 7), domain.ReasonInherited, 2},
		{"a grant to a group on an ancestor", domain.Allow(group, 3, 7), domain.ReasonInherited, 3},
	}
	for _, c := range cases {
		if c.got.Reason != c.want {
			t.Errorf("%s reports %q, want %q", c.name, c.got.Reason, c.want)
		}
		if c.got.Depth != c.depth {
			t.Errorf("%s reports depth %d, want %d", c.name, c.got.Depth, c.depth)
		}
		if !c.got.Allowed {
			t.Errorf("%s is not an allow", c.name)
		}
		if c.got.Revision != 7 {
			t.Errorf("%s carries revision %d, want 7", c.name, c.got.Revision)
		}
	}

	deny := domain.Deny(7)
	if deny.Allowed {
		t.Error("Deny is an allow")
	}
	if deny.Reason != domain.ReasonNoGrant {
		t.Errorf("Deny reports %q, want %q: there is one deny in this layer and it is a grant nobody wrote", deny.Reason, domain.ReasonNoGrant)
	}
	if !deny.Via.IsZero() {
		t.Errorf("Deny attributes the denial to %s", deny.Via)
	}
	if deny.Revision != 7 {
		t.Error("Deny carries no revision. \"Denied\" and \"cannot tell you what state that was computed against\" " +
			"must not be the same result")
	}

	// And the zero Decision denies, because an unevaluated decision must
	// never read as an allow.
	var zero domain.Decision
	if zero.Allowed {
		t.Fatal("the zero Decision allows")
	}
	if zero.Reason != domain.ReasonUnevaluated {
		t.Errorf("the zero Decision reports %q", zero.Reason)
	}
}

func TestSpecValidationRefusesTheUnwritable(t *testing.T) {
	t.Parallel()

	grants := []struct {
		name string
		spec domain.GrantSpec
	}{
		{"no tenant", domain.GrantSpec{Container: "c", Permission: "read", Subject: domain.PrincipalSubject("p")}},
		{"no container", domain.GrantSpec{TenantID: "t", Permission: "read", Subject: domain.PrincipalSubject("p")}},
		{"no permission", domain.GrantSpec{TenantID: "t", Container: "c", Subject: domain.PrincipalSubject("p")}},
		{"a blank permission", domain.GrantSpec{TenantID: "t", Container: "c", Permission: "   ", Subject: domain.PrincipalSubject("p")}},
		{"no subject", domain.GrantSpec{TenantID: "t", Container: "c", Permission: "read"}},
	}
	for _, c := range grants {
		if err := c.spec.Validate(); !errors.Is(err, domain.ErrInvalidGrant) {
			t.Errorf("GrantSpec with %s validated as %v, want ErrInvalidGrant", c.name, err)
		}
	}

	requests := []struct {
		name string
		req  domain.Request
	}{
		{"no tenant", domain.Request{Principal: "p", Permission: "read", Container: "c"}},
		{"no principal", domain.Request{TenantID: "t", Permission: "read", Container: "c"}},
		{"no permission", domain.Request{TenantID: "t", Principal: "p", Container: "c"}},
		{"no container", domain.Request{TenantID: "t", Principal: "p", Permission: "read"}},
	}
	for _, c := range requests {
		if err := c.req.Validate(); !errors.Is(err, domain.ErrInvalidRequest) {
			t.Errorf("Request with %s validated as %v, want ErrInvalidRequest", c.name, err)
		}
	}

	containers := []struct {
		name string
		spec domain.ContainerSpec
	}{
		{"no tenant", domain.ContainerSpec{Kind: "fileset"}},
		{"no kind", domain.ContainerSpec{TenantID: "t"}},
		{"a blank kind", domain.ContainerSpec{TenantID: "t", Kind: "  "}},
	}
	for _, c := range containers {
		if err := c.spec.Validate(); !errors.Is(err, domain.ErrInvalidContainer) {
			t.Errorf("ContainerSpec with %s validated as %v, want ErrInvalidContainer", c.name, err)
		}
	}
}
