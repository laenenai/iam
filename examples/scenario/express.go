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
var ErrUnexpressible = errors.New("outside the permitted tier-1 subset (design §8.5)")

// ErrClearanceInTier1 is the refusal for a tier-1 tuple whose subject is a
// clearance group. Design §8.3 forbids it absolutely: if a clearance could
// attach to a tier-1 group, anyone able to add a member to that group could
// open a mandatory gate through a discretionary operation, and anti-goal A3
// would be breached by construction rather than by a bug.
var ErrClearanceInTier1 = errors.New("a clearance group can never be referenced in a tier-1 tuple (design §8.3)")

// clearanceKind is the object kind the corpus spells clearance groups
// with. The real separation is enforced by the type system —
// domain.ClearanceGroupID is a struct with an unexported field, so a
// GroupID cannot be converted into one — and this is the textual half, for
// a tuple whose subject arrived as a string.
const clearanceKind = "clearance"

// LintSchema is design §13's schema lint and §4/A3's third corollary,
// applied to a fixture's registered kinds: it rejects any relation using
// an exclusion operator or an attribute condition, and the error names the
// classification mechanism, because that is where an absolute belongs.
//
// The reason exclusion is refused rather than merely discouraged is
// locality (design §5a, §7.2.1). In OpenFGA's `but not` and SpiceDB's `-`,
// exclusion applies only to the single relation definition it is written
// in. To make "this principal may never see this" absolute, it must appear
// in every permission on every resource type and be remembered for every
// type added later, where one omission is a silent bypass rather than an
// error. Exclusion is also the one operator that does not flatten into a
// precomputed closure, so using it forfeits the §9 projection and with it
// the whole A2 budget.
func LintSchema(f Fixture) error {
	var problems []error
	for _, k := range f.Kinds {
		for _, r := range k.Relations {
			if len(r.Exclude) > 0 {
				problems = append(problems, fmt.Errorf(
					"%s#%s excludes %s: an absolute is a classification (design §8.3), not a relation — "+
						"exclusion in a relationship model is local to the permission it is written in, so it is "+
						"absolute only where somebody remembered it, and it cannot be flattened into §9's closure",
					k.Name, r.Name, strings.Join(r.Exclude, ", ")))
			}
			if r.AttributeCondition != "" {
				problems = append(problems, fmt.Errorf(
					"%s#%s is conditioned on attribute %q: §8.5 permits union, usersets and tuple-to-userset "+
						"inheritance and no conditional expressions over attributes — express the restriction as a "+
						"classification scoped to that attribute (design §8.3), accepting that it becomes mandatory",
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
		if object == clearanceKind {
			return fmt.Errorf("%s#%s declares userset shape %q: %w", k.Name, r.Name, shape, ErrClearanceInTier1)
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
		return fmt.Errorf("tuple %s is written on an attribute: tier 1 grants on objects, and an "+
			"attribute-level restriction is a classification (design §8.3)", t)
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
	if us.Object.Kind == clearanceKind {
		return fmt.Errorf("tuple %s: %w", t, ErrClearanceInTier1)
	}
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
// schema: a requirement that fails here is not a configuration problem, it
// is design §8.5's last paragraph — "if a requirement arrives that is
// neither [the subset nor a classification] — that is a design
// conversation, not a configuration change."
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

// RowEnforceable reports whether a classification can be enforced by the
// SQL predicate design §9 compiles, and is finding F4 as a function.
//
// A whole-resource classification is an anti-join against the resource's
// rows and is enforceable anywhere. An attribute-scoped classification is
// enforceable only where the attribute *is* a row: a kgs fact carries one
// attribute, so hiding the attribute is hiding the row. Where the
// attribute is a column — a CAS document's fields — a `WHERE` clause
// cannot help, because a `WHERE` clause hides rows and not columns. There
// is no third option that keeps the enforcement inside this module: either
// `Predicate` also returns a permitted-attribute set that the *consumer*
// applies, which moves part of the A3 trust boundary into consumer code,
// or this module becomes a query rewriter across three different query
// builders.
func RowEnforceable(f Fixture, label string) (bool, string) {
	c, ok := f.Classification(label)
	if !ok {
		return false, fmt.Sprintf("no classification %q is declared", label)
	}
	if c.Attribute == "" {
		return true, ""
	}
	var columnar []string
	for _, a := range f.Assignments {
		if a.Label != label {
			continue
		}
		k, known := f.Kind(a.Resource.Kind)
		if !known {
			return false, fmt.Sprintf("classification %q is assigned to unregistered kind %q", label, a.Resource.Kind)
		}
		if k.Shape == ShapeColumnar {
			columnar = append(columnar, a.Resource.String())
		}
	}
	if len(columnar) == 0 {
		return true, ""
	}
	return false, fmt.Sprintf(
		"classification %q is scoped to attribute %q and assigned to columnar resources (%s): a row predicate "+
			"hides rows, not columns, so §9's compiled fragment cannot enforce it (finding F4)",
		label, c.Attribute, strings.Join(columnar, ", "))
}
