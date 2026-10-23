package scenario

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrCryptoEnforced is the typed refusal design §7.3 requires: the API
// must refuse processing operations on crypto-enforced content with a
// typed error rather than failing obscurely later. It is returned by
// Readable, never by Decide — the whole point of tier 3 is that it is not
// part of the decision.
var ErrCryptoEnforced = errors.New("content is crypto-enforced: the deployment does not hold the key (design §7.3)")

// ErrMarkingNotAllowlisted is the typed refusal KGS §9.5 requires of a
// model-provider gate: a provider not allowlisted for a marking never
// receives content carrying it, and the pipeline fails closed rather than
// degrading.
var ErrMarkingNotAllowlisted = errors.New("provider is not allowlisted for this classification (KGS §9.5)")

// Decision is one answer from the reference decision procedure.
type Decision struct {
	// Verdict is allow or deny.
	Verdict Verdict
	// Reason names why.
	Reason ReasonKind
	// Because names the specific tuple or classification responsible, in
	// the design's notation.
	Because string
}

// Decide is the reference decision procedure: design §7.1's conjunction,
//
//	mandatory_gate(principal, resource) AND discretionary_allows(principal, action, resource)
//
// evaluated mandatory-first, because the gate is cheap and because a
// principal who fails it must not have the discretionary layer consulted
// at all — the attempt is auditable without being informative.
//
// It is an oracle for the corpus and emphatically not an engine. It
// implements exactly design §8.2's four composition forms, refuses
// anything else with ErrUnexpressible, and holds no projection, no
// closure, no staleness bound and no deny epoch. Its purpose is to make
// the corpus's expectation tables executable *before* `Decide` exists, so
// that when `Decide` does exist the two can be run against the same tables
// and diffed — which is design §9.4's differential authorization audit
// aimed one layer up.
//
// Deny-wins is structural here exactly as the design says it is: it is a
// property of the conjunction, not a rule anyone had to remember to write.
func Decide(f Fixture, principal, action string, resource Ref) (Decision, error) {
	if err := LintSchema(f); err != nil {
		return Decision{}, err
	}
	if _, ok := f.Principal(principal); !ok {
		return Decision{}, fmt.Errorf("unknown principal %q", principal)
	}

	labels, err := LabelsOf(f, resource)
	if err != nil {
		return Decision{}, err
	}
	for _, label := range labels {
		if !satisfies(f, principal, label) {
			return Decision{Verdict: Deny, Reason: ReasonClassification, Because: label}, nil
		}
	}

	kind, ok := f.Kind(resource.Kind)
	if !ok {
		return Decision{}, fmt.Errorf("unregistered resource kind %q", resource.Kind)
	}
	relation, ok := kind.Actions[action]
	if !ok {
		return Decision{}, fmt.Errorf("kind %q registers no action %q (registered: %v)", kind.Name, action, actionNames(kind))
	}

	d, err := holds(f, principal, resource.Object(), relation, 0)
	if err != nil {
		return Decision{}, err
	}
	return d, nil
}

func actionNames(k ResourceKind) []string {
	out := make([]string, 0, len(k.Actions))
	for name := range k.Actions {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// groupMemberRelation is the relation an ordinary group's membership is
// read through. It is one name, used by every fixture, so the lint and the
// oracle agree about what a group is.
const groupMemberRelation = "member"

// groupHasMember reports whether the principal is a member of the ordinary
// group named by object, through either of the two channels the registry
// has: a locally-written membership (Fixture.Groups) or a claim-derived one
// the issuer asserted (PrincipalSpec.ClaimGroups, which the registry
// upserts into the registry on sight).
//
// Both channels are consulted because both produce the same joinable row,
// and a corpus that saw only one would be unable to express the scenario
// that matters most about the second: a new joiner whose claim-derived
// membership lets him work on day one while he holds no clearance at all.
func groupHasMember(f Fixture, object Ref, principal string) bool {
	name := object.String()
	for _, g := range f.Groups {
		if g.Name == name && slices.Contains(g.Members, principal) {
			return true
		}
	}
	for _, p := range f.Principals {
		if p.Name == principal && slices.Contains(p.ClaimGroups, name) {
			return true
		}
	}
	return false
}

// satisfies reports whether the principal holds the clearance for label,
// either directly or through a clearance group. There is deliberately no
// third way: no tuple, no group membership, no ownership and no delegation
// appears in this function, which is design §8.3's "a classification
// cannot be granted away, delegated, transferred with ownership, or
// satisfied by any tier-1 relation" expressed as the absence of code.
func satisfies(f Fixture, principal, label string) bool {
	for _, dc := range f.DirectClearances {
		if dc.Principal == principal && dc.Label == label {
			return true
		}
	}
	for _, cg := range f.ClearanceGroups {
		if !slices.Contains(cg.Labels, label) {
			continue
		}
		if slices.Contains(cg.Members, principal) {
			return true
		}
	}
	return false
}

// holds evaluates the four permitted composition forms for one
// (principal, object, relation).
//
// The reason it returns names the *outermost* form that fired, and the
// `Because` the innermost tuple that actually granted it. So a grant that
// reaches a document by inheriting its folder's `editor`, which the folder
// holds by union with `owner`, reports inherited-tuple and names the owner
// tuple. That convention is worth stating because the corpus matches the
// reason exactly: the outermost form is the one a consumer debugging a
// decision needs to see first, and the innermost tuple is the row they
// then have to go and look at.
func holds(f Fixture, principal string, object Ref, relation string, depth int) (Decision, error) {
	if depth > maxDepth {
		return Decision{}, fmt.Errorf("relation resolution for %s#%s exceeds depth %d", object, relation, maxDepth)
	}
	rel, ok := f.Relation(object.Kind, relation)
	if !ok {
		return Decision{}, fmt.Errorf("kind %q registers no relation %q", object.Kind, relation)
	}

	// Form 1: direct. Ordinary-group membership is declared once, in the
	// fixture's Groups, because that is the declaration the live registry
	// is materialized from — so a fixture does not state the same
	// membership twice and cannot state it two different ways. The
	// synthesized reason is spelled exactly as the tuple would be.
	if rel.Direct && relation == groupMemberRelation && groupHasMember(f, object, principal) {
		return Decision{
			Verdict: Allow,
			Reason:  ReasonDirect,
			Because: object.String() + "#" + groupMemberRelation + "@" + principal,
		}, nil
	}

	if rel.Direct {
		for _, t := range f.Tuples {
			if t.Object.Object() == object && t.Relation == relation && t.Subject.Userset == nil && t.Subject.Principal == principal {
				return Decision{Verdict: Allow, Reason: ReasonDirect, Because: t.String()}, nil
			}
		}
	}

	// Form 2: userset. Resolved by asking whether the principal holds the
	// userset's relation on the userset's object, which is the same
	// question one level down — so a team, a role and a nested group all
	// work through one mechanism and none needs a special case.
	for _, t := range f.Tuples {
		if t.Object.Object() != object || t.Relation != relation || t.Subject.Userset == nil {
			continue
		}
		us := *t.Subject.Userset
		inner, err := holds(f, principal, us.Object, us.Relation, depth+1)
		if err != nil {
			return Decision{}, err
		}
		if inner.Verdict == Allow {
			return Decision{Verdict: Allow, Reason: ReasonUserset, Because: t.String()}, nil
		}
	}

	// Form 3: tuple-to-userset inheritance. One tuple on the container
	// reaches every descendant; nothing is written per object.
	for _, parentRelation := range rel.InheritFromParent {
		for _, e := range f.Containment {
			if e.Child.Object() != object {
				continue
			}
			up, err := holds(f, principal, e.Parent.Object(), parentRelation, depth+1)
			if err != nil {
				return Decision{}, err
			}
			if up.Verdict == Allow {
				return Decision{Verdict: Allow, Reason: ReasonInherited, Because: up.Because}, nil
			}
		}
	}

	// Form 4: union over other relations on the same object.
	for _, other := range rel.Union {
		d, err := holds(f, principal, object, other, depth+1)
		if err != nil {
			return Decision{}, err
		}
		if d.Verdict == Allow {
			return Decision{Verdict: Allow, Reason: ReasonUnion, Because: d.Because}, nil
		}
	}

	return Decision{Verdict: Deny, Reason: ReasonNoGrant}, nil
}

// TupleCount is what one share cost, broken down the way anti-goal A2's
// closure budget is written. It exists so a scenario can assert "one tuple
// per hop, not one per object" as an arithmetic fact rather than a claim in
// a comment.
type TupleCount struct {
	// Tuples is how many relation tuples the fixture actually writes.
	Tuples int
	// Objects is how many objects those tuples reach through containment.
	Objects int
	// CrossProduct is what a naive per-object materialization would have
	// written: the thing design §9.2 forbids and A2 budgets to catch.
	CrossProduct int
}

// CountTuples reports what the fixture's grants cost. Reach is every
// object that any tuple's object contains, transitively, plus the tuple
// objects themselves.
func CountTuples(f Fixture) (TupleCount, error) {
	granted := make(map[Ref]bool)
	for _, t := range f.Tuples {
		granted[t.Object.Object()] = true
	}

	reached := make(map[Ref]bool)
	objects := allObjects(f)
	for _, o := range objects {
		ancestors, err := Ancestors(f, o)
		if err != nil {
			return TupleCount{}, err
		}
		if granted[o] {
			reached[o] = true
			continue
		}
		for _, a := range ancestors {
			if granted[a] {
				reached[o] = true
				break
			}
		}
	}

	subjects := make(map[string]bool)
	for _, t := range f.Tuples {
		subjects[t.Subject.String()] = true
	}
	return TupleCount{
		Tuples:       len(f.Tuples),
		Objects:      len(reached),
		CrossProduct: len(reached) * len(subjects),
	}, nil
}

func allObjects(f Fixture) []Ref {
	seen := make(map[Ref]bool)
	add := func(r Ref) {
		o := r.Object()
		if !o.IsZero() {
			seen[o] = true
		}
	}
	for _, e := range f.Containment {
		add(e.Child)
		add(e.Parent)
	}
	for _, t := range f.Tuples {
		add(t.Object)
	}
	for _, a := range f.Assignments {
		add(a.Resource)
	}
	out := make([]Ref, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Ref) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// Visible is design §8.2's bottom-up navigational visibility: a principal
// granted a relation on a deep object gets limited list rights on that
// object's ancestors, and only on the direct path. It is what lets a
// consumer answer "find the thing you may see" without revealing its
// siblings, and it is folded back into KGS §7.3 as an explicit relation
// replacing an implicit derived existence.
//
// It returns the visible set, and it returns ErrNoDirectPath the moment
// containment is a DAG — which is finding F3, and the reason this function
// is in the corpus rather than taken on trust.
func Visible(f Fixture, principal string) ([]Ref, error) {
	if err := LintSchema(f); err != nil {
		return nil, err
	}
	visible := make(map[Ref]bool)
	for _, t := range f.Tuples {
		object := t.Object.Object()
		d, err := holds(f, principal, object, t.Relation, 0)
		if err != nil {
			return nil, err
		}
		if d.Verdict != Allow {
			continue
		}
		visible[object] = true
		path, err := DirectPath(f, object)
		if err != nil {
			return nil, err
		}
		for _, a := range path {
			visible[a] = true
		}
	}
	out := make([]Ref, 0, len(visible))
	for r := range visible {
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Ref) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

// Readable reports whether a principal that Decide permitted can actually
// read the resource, which is a different question. Design §7.3: tier 3 is
// not part of the decision. `Decide` may well return allow for a
// crypto-enforced resource and the caller still cannot read it without a
// key the deployment does not hold.
//
// This module's entire responsibility for tier 3 is the enforcement class
// field, and this function is what makes that field worth recording:
// it is how a consumer tells a user *why* something is unreadable, and how
// the API refuses a processing operation with a typed error rather than
// failing obscurely later.
func Readable(f Fixture, resource Ref) error {
	labels, err := LabelsOf(f, resource)
	if err != nil {
		return err
	}
	for _, label := range labels {
		c, ok := f.Classification(label)
		if !ok {
			return fmt.Errorf("undeclared label %q on %s", label, resource)
		}
		if c.Enforcement == EnforcementCrypto {
			return fmt.Errorf("%w: %s carries %s", ErrCryptoEnforced, resource, label)
		}
	}
	return nil
}

// EntityExistsFor reports whether an entity exists for a principal, which
// KGS §7.3 derives rather than storing: an entity exists for P iff P can
// read at least one assertion that references it. There is no entity ACL
// to get wrong, "not found" and "forbidden" are the same answer, and —
// the property the household scenario turns on — two principals can hold
// the same entity through different facts, so dedup is safe and neither
// learns of the other.
func EntityExistsFor(f Fixture, principal string, entity Ref) (bool, error) {
	for _, m := range f.Mentions {
		if m.Entity.Object() != entity.Object() {
			continue
		}
		kind, ok := f.Kind(m.Fact.Kind)
		if !ok {
			return false, fmt.Errorf("mention references unregistered kind %q", m.Fact.Kind)
		}
		action, ok := readAction(kind)
		if !ok {
			return false, fmt.Errorf("kind %q registers no read-shaped action, so entity existence cannot be derived from it", kind.Name)
		}
		d, err := Decide(f, principal, action, m.Fact)
		if err != nil {
			return false, err
		}
		if d.Verdict == Allow {
			return true, nil
		}
	}
	return false, nil
}

// readAction returns the kind's read action. The corpus spells it `read`
// on every kind whose facts can witness an entity's existence.
func readAction(k ResourceKind) (string, bool) {
	if _, ok := k.Actions["read"]; ok {
		return "read", true
	}
	return "", false
}

// MayReceive is KGS §9.5's marking-aware model gate: it reports whether a
// provider allowlisted for exactly the given labels may be sent the
// resource's content. A provider not allowlisted for a label the content
// carries never receives it, and the refusal is typed
// (ErrMarkingNotAllowlisted) so the pipeline fails closed rather than
// degrading to a lesser model or a redacted prompt.
//
// It resolves the content's labels through LabelsOf, so a *derived* object
// is gated by the union of its inputs' classifications — which is leak
// channel #15: a consolidator that saw privileged evidence must not emit
// an observation a non-allowlisted provider may then read.
func MayReceive(f Fixture, resource Ref, allowlisted []string) error {
	labels, err := LabelsOf(f, resource)
	if err != nil {
		return err
	}
	for _, label := range labels {
		if !slices.Contains(allowlisted, label) {
			return fmt.Errorf("%w: %s carries %s and the provider is allowlisted only for %v",
				ErrMarkingNotAllowlisted, resource, label, allowlisted)
		}
	}
	return nil
}
