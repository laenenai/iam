package scenario

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// ClaimKind names a structural assertion about a fixture that can be
// evaluated today, with no decision API. They are what make this corpus
// more than a wish-list: every one of them is a pure function over fixture
// data, so a scenario whose expectation table is pending still proves
// something now.
type ClaimKind string

const (
	// ClaimSchemaAccepted asserts that design §13's schema lint accepts
	// the fixture's registered kinds: every relation fits §8.5's permitted
	// subset and every tuple's subject shape is one its relation declares.
	ClaimSchemaAccepted ClaimKind = "schema-accepted"
	// ClaimSchemaRejected asserts that the lint *rejects* the fixture, and
	// that the refusal mentions Detail. This is how an unexpressible use
	// case is demonstrated rather than asserted: the corpus writes the
	// rule the requirement needs and the design refuses it.
	ClaimSchemaRejected ClaimKind = "schema-rejected"
	// ClaimTuplesPerHop asserts the arithmetic of design §8.2's "one tuple
	// per hop rather than one per object": Subject is the tuple count,
	// Detail the number of objects reached. Anti-goal A2's closure budget
	// is written to catch the violation this claim measures.
	ClaimTuplesPerHop ClaimKind = "tuples-per-hop"
	// ClaimPathCount asserts how many containment paths a resource has.
	// One is a tree and design §8.2's "only the direct path" means
	// something; more than one is finding F3.
	ClaimPathCount ClaimKind = "path-count"
	// ClaimNoDirectPath asserts that DirectPath refuses, because
	// containment above the named resource is a DAG.
	ClaimNoDirectPath ClaimKind = "no-direct-path"
	// ClaimVisibleSet asserts the exact set of objects a principal can
	// navigate to: Subject is the principal, Detail a comma-separated set
	// of refs. It is how "the path to it and only that path, not its
	// siblings" is tested rather than described.
	ClaimVisibleSet ClaimKind = "visible-set"
	// ClaimLabelSet asserts the exact classification set a resource
	// resolves to: Subject is the resource, Detail a comma-separated set
	// of labels. For a derived object this is the union of its inputs',
	// which is the propagation a pipeline must not be able to launder
	// around.
	ClaimLabelSet ClaimKind = "label-set"
	// ClaimRowEnforceable asserts that the named classification can be
	// enforced by the SQL predicate design §9 compiles. False is finding
	// F4.
	ClaimRowEnforceable ClaimKind = "row-enforceable"
	// ClaimStableUnderWrite asserts that the named resource's ancestry
	// closure and label set are unchanged by the fixture's declared later
	// writes. False means an ordinary data write moved an authorization
	// answer with no authorization operation having happened, which is
	// what a predicate-defined entity-set does.
	ClaimStableUnderWrite ClaimKind = "stable-under-write"
	// ClaimCryptoUnreadable asserts that the named resource is unreadable
	// because its classification's enforcement class is crypto, whatever
	// the decision procedure answered. It is the claim that separates the
	// decision from the enforcement tier.
	ClaimCryptoUnreadable ClaimKind = "crypto-unreadable"
	// ClaimProviderRefused asserts that a model provider allowlisted for
	// Detail's labels is refused the named resource, with a typed error.
	ClaimProviderRefused ClaimKind = "provider-refused"
	// ClaimNoClearanceFromDiscretion is the A3 mini-suite: it enumerates
	// every discretionary operation the identity registry exposes, applies
	// each on behalf of the named principal, and asserts that the
	// principal still holds no clearance afterwards. It runs live against
	// the real registry.
	ClaimNoClearanceFromDiscretion ClaimKind = "no-clearance-from-discretion"
	// ClaimLiveClearances asserts the exact clearance groups a principal
	// is in according to the real registry: Subject is the principal,
	// Detail a comma-separated set of clearance-group names, empty for
	// none. It is the live half of the mandatory scenarios.
	ClaimLiveClearances ClaimKind = "live-clearances"
	// ClaimLiveGroups asserts the exact ordinary groups a principal is in
	// according to the real registry.
	ClaimLiveGroups ClaimKind = "live-groups"
	// ClaimPrincipalUnusable asserts that the real registry refuses to
	// read the named principal's memberships, because it is deprovisioned,
	// expired, or staler than the deployment's bound.
	ClaimPrincipalUnusable ClaimKind = "principal-unusable"
	// ClaimMembershipChangeTakesEffect asserts, against the real registry,
	// that adding a principal to an ordinary group changes what the
	// authorization predicate would read — and that the grant tuple naming
	// that group is not touched. Subject is the principal, Detail the
	// group. It is how "membership change takes effect" is tested rather
	// than described: one row moves, no grant is rewritten.
	ClaimMembershipChangeTakesEffect ClaimKind = "membership-change-takes-effect"
	// ClaimEntityVisibility asserts the exact set of principals an entity
	// exists for, where existence is derived from the assertions each
	// principal may read (KGS §7.3). Subject is the entity, Detail a
	// comma-separated set of principal names. It is leak channel #1 as a
	// test: an entity must not exist for a principal merely because
	// somebody else created it.
	ClaimEntityVisibility ClaimKind = "entity-visibility"
	// ClaimProviderPermitted is ClaimProviderRefused's positive twin: a
	// provider allowlisted for Detail's labels may receive the resource.
	ClaimProviderPermitted ClaimKind = "provider-permitted"
	// ClaimAbsoluteHasNoLift asserts that no discretionary operation the
	// registry exposes gives the named principal the clearance for the
	// label in Detail. The assertion is identical to
	// ClaimNoClearanceFromDiscretion and its *meaning* is the opposite: in
	// a mandatory scenario the absence of a discretionary path is the
	// feature, and here it is the cost. A requirement that only wanted
	// "don't show her the salary" has become an absolute that the resource
	// owner cannot lift.
	ClaimAbsoluteHasNoLift ClaimKind = "absolute-has-no-lift"
	// ClaimAnyActorMayClassify asserts that the named principal, holding
	// no particular permission, can nonetheless perform a mandatory act
	// and add itself to a clearance group. It is a gap claim: it passes
	// today because design §16 question 2 — who may create and assign
	// classifications — is unanswered, so the registry demands a *witness*
	// of the mandatory channel and never checks the actor's authority.
	// When a classify permission lands, this claim fails, which is exactly
	// what should happen.
	ClaimAnyActorMayClassify ClaimKind = "any-actor-may-classify"
)

// Claim is one structural assertion, as data.
type Claim struct {
	// Kind is what is being claimed.
	Kind ClaimKind
	// Subject is what the claim is about: a resource, a principal, a
	// classification label, or a count, depending on Kind.
	Subject string
	// Detail is the claim's expected value, in the form Kind documents.
	Detail string
	// Why states, in one line, what the claim means in the modelled
	// situation. It is printed on failure, so a reader who did not write
	// the fixture can tell what broke.
	Why string
}

// C builds a claim.
func C(kind ClaimKind, subject, detail, why string) Claim {
	return Claim{Kind: kind, Subject: subject, Detail: detail, Why: why}
}

// needsRegistry reports whether evaluating this claim requires a live
// registry, as opposed to being a pure function over fixture data.
func (c Claim) needsRegistry() bool {
	switch c.Kind {
	case ClaimNoClearanceFromDiscretion, ClaimLiveClearances, ClaimLiveGroups, ClaimPrincipalUnusable,
		ClaimMembershipChangeTakesEffect, ClaimAbsoluteHasNoLift, ClaimAnyActorMayClassify:
		return true
	default:
		return false
	}
}

// evalStatic evaluates a claim that needs only fixture data.
func (c Claim) evalStatic(f Fixture) error {
	switch c.Kind {
	case ClaimSchemaAccepted:
		return claimSchemaAccepted(f)
	case ClaimSchemaRejected:
		return claimSchemaRejected(f, c.Detail)
	case ClaimTuplesPerHop:
		return claimTuplesPerHop(f, c)
	case ClaimPathCount:
		return claimPathCount(f, c)
	case ClaimNoDirectPath:
		return claimNoDirectPath(f, c)
	case ClaimVisibleSet:
		return claimVisibleSet(f, c)
	case ClaimLabelSet:
		return claimLabelSet(f, c)
	case ClaimRowEnforceable:
		return claimRowEnforceable(f, c)
	case ClaimStableUnderWrite:
		return claimStableUnderWrite(f, c)
	case ClaimCryptoUnreadable:
		return claimCryptoUnreadable(f, c)
	case ClaimProviderRefused:
		return claimProviderRefused(f, c)
	case ClaimProviderPermitted:
		return claimProviderPermitted(f, c)
	case ClaimEntityVisibility:
		return claimEntityVisibility(f, c)
	default:
		return fmt.Errorf("claim %s is not a static claim", c.Kind)
	}
}

func claimSchemaAccepted(f Fixture) error {
	if err := LintSchema(f); err != nil {
		return fmt.Errorf("the schema lint rejected a fixture that should be expressible: %w", err)
	}
	return nil
}

func claimSchemaRejected(f Fixture, mustMention string) error {
	err := LintSchema(f)
	if err == nil {
		return errors.New("the schema lint accepted a fixture this scenario claims is unexpressible: " +
			"either the lint has a hole or the design has grown a form — both are findings, neither is a pass")
	}
	if mustMention != "" && !strings.Contains(err.Error(), mustMention) {
		return fmt.Errorf("the schema lint rejected the fixture but its reason did not mention %q, so the refusal "+
			"does not point the consumer at the mechanism it should use instead; got: %v", mustMention, err)
	}
	return nil
}

func claimTuplesPerHop(f Fixture, c Claim) error {
	wantTuples, err := strconv.Atoi(c.Subject)
	if err != nil {
		return fmt.Errorf("claim %s: subject must be the expected tuple count: %w", c.Kind, err)
	}
	wantObjects, err := strconv.Atoi(c.Detail)
	if err != nil {
		return fmt.Errorf("claim %s: detail must be the expected reached-object count: %w", c.Kind, err)
	}
	got, err := CountTuples(f)
	if err != nil {
		return err
	}
	if got.Tuples != wantTuples || got.Objects != wantObjects {
		return fmt.Errorf("the share cost %d tuples reaching %d objects, want %d tuples reaching %d; "+
			"a naive per-object materialization would have written %d rows (design §9.2, anti-goal A2)",
			got.Tuples, got.Objects, wantTuples, wantObjects, got.CrossProduct)
	}
	return nil
}

func claimPathCount(f Fixture, c Claim) error {
	want, err := strconv.Atoi(c.Detail)
	if err != nil {
		return fmt.Errorf("claim %s: detail must be the expected path count: %w", c.Kind, err)
	}
	all, err := Paths(f, R(c.Subject))
	if err != nil {
		return err
	}
	if len(all) != want {
		return fmt.Errorf("%s has %d containment paths, want %d", c.Subject, len(all), want)
	}
	return nil
}

func claimNoDirectPath(f Fixture, c Claim) error {
	_, err := DirectPath(f, R(c.Subject))
	if err == nil {
		return fmt.Errorf("%s has a single direct path, but this scenario claims containment above it is a DAG", c.Subject)
	}
	if !errors.Is(err, ErrNoDirectPath) {
		return fmt.Errorf("DirectPath(%s) failed for the wrong reason: %w", c.Subject, err)
	}
	return nil
}

func claimVisibleSet(f Fixture, c Claim) error {
	got, err := Visible(f, c.Subject)
	if err != nil {
		return err
	}
	return compareRefs(got, c.Detail, fmt.Sprintf("the set %s can navigate to", c.Subject))
}

func claimLabelSet(f Fixture, c Claim) error {
	got, err := LabelsOf(f, R(c.Subject))
	if err != nil {
		return err
	}
	return compareStrings(got, c.Detail, fmt.Sprintf("the classification set of %s", c.Subject))
}

func claimRowEnforceable(f Fixture, c Claim) error {
	want := c.Detail != "false"
	ok, why := RowEnforceable(f, c.Subject)
	if ok == want {
		return nil
	}
	if want {
		return fmt.Errorf("classification %q should be enforceable by the compiled predicate but is not: %s", c.Subject, why)
	}
	return fmt.Errorf("classification %q is enforceable by a row predicate, but this scenario claims it is not — "+
		"finding F4 may have been resolved, in which case this scenario moves out of UNEXPRESSIBLE.md", c.Subject)
}

func claimStableUnderWrite(f Fixture, c Claim) error {
	if len(f.LaterWrites) == 0 {
		return fmt.Errorf("claim %s needs the fixture to declare at least one later write", c.Kind)
	}
	want := c.Detail != "false"
	resource := R(c.Subject)

	beforeAncestors, err := Ancestors(f, resource)
	if err != nil {
		return err
	}
	beforeLabels, err := LabelsOf(f, resource)
	if err != nil {
		return err
	}

	after := WithLaterWrites(f)
	afterAncestors, err := Ancestors(after, resource)
	if err != nil {
		return err
	}
	afterLabels, err := LabelsOf(after, resource)
	if err != nil {
		return err
	}

	stable := refsEqual(beforeAncestors, afterAncestors) && slices.Equal(beforeLabels, afterLabels)
	if stable == want {
		return nil
	}
	if want {
		return fmt.Errorf("%s's authorization inputs moved when an ordinary data write landed: ancestors %v -> %v, "+
			"labels %v -> %v", c.Subject, renderRefs(beforeAncestors), renderRefs(afterAncestors), beforeLabels, afterLabels)
	}
	return fmt.Errorf("%s's authorization inputs were stable under the declared write, but this scenario claims they "+
		"are not; the write declared was: %s", c.Subject, f.LaterWrites[0].What)
}

func claimCryptoUnreadable(f Fixture, c Claim) error {
	err := Readable(f, R(c.Subject))
	if err == nil {
		return fmt.Errorf("%s is readable, but this scenario claims it is crypto-enforced", c.Subject)
	}
	if !errors.Is(err, ErrCryptoEnforced) {
		return fmt.Errorf("%s is unreadable for the wrong reason: %w", c.Subject, err)
	}
	return nil
}

func claimProviderRefused(f Fixture, c Claim) error {
	var allowlisted []string
	if strings.TrimSpace(c.Detail) != "" {
		for _, l := range strings.Split(c.Detail, ",") {
			allowlisted = append(allowlisted, strings.TrimSpace(l))
		}
	}
	err := MayReceive(f, R(c.Subject), allowlisted)
	if err == nil {
		return fmt.Errorf("a provider allowlisted for %v was permitted %s, which it carries markings for", allowlisted, c.Subject)
	}
	if !errors.Is(err, ErrMarkingNotAllowlisted) {
		return fmt.Errorf("the provider was refused for the wrong reason: %w", err)
	}
	return nil
}

func claimProviderPermitted(f Fixture, c Claim) error {
	if err := MayReceive(f, R(c.Subject), parseSet(c.Detail)); err != nil {
		return fmt.Errorf("a provider allowlisted for %q was refused %s, which it should be permitted: %w",
			c.Detail, c.Subject, err)
	}
	return nil
}

func claimEntityVisibility(f Fixture, c Claim) error {
	entity := R(c.Subject)
	var exists []string
	for _, spec := range f.Principals {
		visible, err := EntityExistsFor(f, spec.Name, entity)
		if err != nil {
			return err
		}
		if visible {
			exists = append(exists, spec.Name)
		}
	}
	return compareStrings(exists, c.Detail, fmt.Sprintf("the principals %s exists for", c.Subject))
}

func compareRefs(got []Ref, want, what string) error {
	return compareStrings(renderRefs(got), want, what)
}

func renderRefs(refs []Ref) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}

func refsEqual(a, b []Ref) bool { return slices.Equal(renderRefs(a), renderRefs(b)) }

func compareStrings(got []string, want, what string) error {
	wanted := parseSet(want)
	gotSet := slices.Clone(got)
	slices.Sort(gotSet)
	gotSet = slices.Compact(gotSet)
	if slices.Equal(gotSet, wanted) {
		return nil
	}
	return fmt.Errorf("%s is %v, want %v", what, gotSet, wanted)
}

func parseSet(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
