package scenario

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnexpressible is what the corpus returns when a fixture asks for
// something design §8.5 does not permit. It is the corpus's most valuable
// error: a requirement that produces it is a requirement the design cannot
// express, located at the exact relation or rule that cannot be written.
var ErrUnexpressible = errors.New("outside the permitted subset (design §8.5)")

// ErrNoDenyMechanism is the refusal an exclusion operator earns. It names
// the anti-goal rather than an alternative mechanism, because there is no
// longer an alternative mechanism to name.
//
// There was one: ErrClearanceInTier1, which refused a tuple whose subject
// was a clearance group, on the grounds that a clearance reachable through
// a discretionary operation would breach anti-goal A3 by construction. The
// refusal was correct and the tier it protected is gone, so what is left is
// the simpler rule — nothing denies, and "may never see this" is expressed
// by not granting it.
var ErrNoDenyMechanism = errors.New("there is no deny mechanism, by design")

// LintSchema is design §13's schema lint, applied to a fixture's
// registered kinds: it rejects any relation using an exclusion operator or
// an attribute condition, and the error says what the consumer should do
// instead.
//
// # Why exclusion is refused
//
// This used to be an argument about *locality*, and the argument was
// sound but narrower than it was made to carry. In OpenFGA's `but not` and
// SpiceDB's `-`, exclusion applies only to the single relation definition
// it is written in, so a restriction meant to be absolute is absolute only
// where somebody remembered to write it. That is a real objection to
// relation-scoped exclusion specifically, and it is why the answer was
// once "write it as a classification instead".
//
// The answer now is that there is nothing to write it as. A deny
// administered by policy is only as absolute as whoever administers the
// policy, so this module has no deny mechanism at all: a restriction is
// expressed by not granting, and an absolute that must survive a future
// administrator is a key the deployment does not hold — `escrow`. The
// second reason is unchanged and still sufficient on its own: exclusion is
// the one operator that does not flatten into a precomputed closure, so
// using it forfeits the §9 projection and with it the whole A2 budget.
//
// # Why an attribute condition is refused
//
// It does not precompute into a closure either, for the same reason. The
// difference worth keeping in mind is that this refusal no longer points
// anywhere: an attribute-conditioned rule is a genuine requirement with no
// mechanism behind it in this design, which is findings F7 and F4, both
// open. See examples/UNEXPRESSIBLE.md's U1.
func LintSchema(f Fixture) error {
	var problems []error
	for _, k := range f.Kinds {
		for _, r := range k.Relations {
			if len(r.Exclude) > 0 {
				problems = append(problems, fmt.Errorf(
					"%s#%s excludes %s: %w — a restriction is expressed by not granting, and an absolute "+
						"that must survive a future administrator is a key the deployment does not hold "+
						"(`escrow`), never a policy row. Exclusion is also the one operator that cannot be "+
						"flattened into §9's closure",
					k.Name, r.Name, strings.Join(r.Exclude, ", "), ErrNoDenyMechanism))
			}
			if r.AttributeCondition != "" {
				problems = append(problems, fmt.Errorf(
					"%s#%s is conditioned on attribute %q: §8.5 permits union, usersets and tuple-to-userset "+
						"inheritance and no conditional expressions over attributes, because a conditional "+
						"expression does not precompute into a closure. There is no second tier to express it "+
						"in either — that mechanism was removed with the deny mechanism — so this requirement "+
						"has no form at all today: findings F7 and F4, both open",
					k.Name, r.Name, r.AttributeCondition))
			}
			if err := lintUsersetShapes(k, r); err != nil {
				problems = append(problems, err)
			}
		}
	}
	for _, t := range f.Tuples {
		if err := lintTuple(f, t); err != nil {
			problems = append(problems, err)
		}
	}
	if len(problems) == 0 {
		return nil
	}
	// Both sentinels are wrapped: ErrUnexpressible so a caller can ask the
	// general question, and every specific refusal so a caller can ask
	// which rule was broken. A lint that flattened its reasons into one
	// string would make the second question unanswerable in code, which is
	// how a test ends up asserting a refusal happened without asserting
	// why.
	return fmt.Errorf("%w: %w", ErrUnexpressible, errors.Join(problems...))
}

func lintUsersetShapes(k ResourceKind, r Relation) error {
	for _, shape := range r.Usersets {
		object, relation, ok := strings.Cut(shape, "#")
		if !ok || object == "" || relation == "" {
			return fmt.Errorf("%s#%s declares userset shape %q, which is not `kind#relation`", k.Name, r.Name, shape)
		}
	}
	return nil
}

func lintTuple(f Fixture, t Tuple) error {
	rel, ok := f.Relation(t.Object.Kind, t.Relation)
	if !ok {
		return fmt.Errorf("tuple %s names relation %q, which kind %q does not register", t, t.Relation, t.Object.Kind)
	}
	if t.Object.Attribute != "" {
		return fmt.Errorf("tuple %s is written on an attribute: a grant is written on an object, and whether "+
			"an attribute-scoped restriction can be enforced at all is finding F4 — see AttributeEnforceable", t)
	}
	if t.Subject.Userset == nil {
		if !rel.Direct {
			return fmt.Errorf("tuple %s has a principal subject but %s#%s does not permit form 1",
				t, t.Object.Kind, t.Relation)
		}
		if _, known := f.Principal(t.Subject.Principal); !known {
			return fmt.Errorf("tuple %s names principal %q, which the fixture does not declare", t, t.Subject.Principal)
		}
		return nil
	}
	us := *t.Subject.Userset
	shape := us.Object.Kind + "#" + us.Relation
	for _, permitted := range rel.Usersets {
		if permitted == shape {
			return nil
		}
	}
	return fmt.Errorf("tuple %s has userset subject of shape %q, which %s#%s does not permit (permitted: %v)",
		t, shape, t.Object.Kind, t.Relation, rel.Usersets)
}

// CanExpress reports whether the rule a consumer needs fits design §8.5's
// permitted subset. It is the restriction made executable, and it is the
// one function in this corpus a consumer should call before designing a
// schema.
//
// §8.5's last paragraph used to read "where a real requirement cannot be
// expressed in the subset, the answer is a classification, not a richer
// language. If a requirement arrives that is neither — that is a design
// conversation, not a configuration change." The first sentence is gone
// with the classification. What is left is the second one, and it now
// applies to everything this function refuses.
//
// It is a thin wrapper over LintSchema restricted to one relation, so the
// permitted subset is defined in exactly one place.
func CanExpress(kind ResourceKind, r Relation) (bool, string) {
	f := Fixture{Kinds: []ResourceKind{{Name: kind.Name, Shape: kind.Shape, Relations: []Relation{r}, Actions: kind.Actions}}}
	if err := LintSchema(f); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// AttributeEnforceable reports whether a restriction scoped to ref's
// attribute could be enforced by the SQL fragment design §9 compiles. It
// is finding F4 as a function.
//
// A whole-object restriction is a join against the object's rows and is
// enforceable anywhere, so a ref with no attribute is trivially true. An
// attribute-scoped restriction is enforceable only where the attribute
// *is* a row: a kgs fact carries one attribute, so hiding the attribute is
// hiding the row. Where the attribute is a column — a CAS document's
// fields — a `WHERE` clause cannot help, because a `WHERE` clause hides
// rows and not columns.
//
// There is no third option that keeps the enforcement inside this module:
// either `Predicate` also returns a permitted-attribute set that the
// *consumer* applies, which moves part of the trust boundary into consumer
// code, or this module becomes a query rewriter across three different
// query builders.
//
// This function used to take a classification label and read its scope off
// the label definition. It takes a ref now, because the removal of the
// mandatory tier removed the label and not the problem: F4 was never about
// which tier the restriction was written in.
func AttributeEnforceable(f Fixture, ref Ref) (bool, string) {
	if ref.Kind == "" {
		return false, fmt.Sprintf("%q is not in kind:id[.attribute] form", ref)
	}
	k, known := f.Kind(ref.Kind)
	if !known {
		return false, fmt.Sprintf("kind %q is not registered", ref.Kind)
	}
	if ref.Attribute == "" {
		return true, ""
	}
	if k.Shape != ShapeColumnar {
		return true, ""
	}
	return false, fmt.Sprintf(
		"%s names an attribute of a columnar kind: a row predicate hides rows, not columns, so §9's "+
			"compiled fragment cannot enforce a restriction at this granularity (finding F4)", ref)
}
