package scenario

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrNoDirectPath is the refusal design §8.2's "and only on the direct
// path" earns the moment containment stops being a tree. It is finding F3
// as an error value: a kgs fact has an episode *and* zero or more
// nestable, sometimes predicate-defined entity-sets, so there are several
// paths and "the direct path" names none of them.
var ErrNoDirectPath = errors.New("containment is a DAG here, so there is no single direct path (design §8.2, finding F3)")

// maxDepth bounds the ancestry walk. Anti-goal A2 budgets a containment
// hierarchy of depth 6; the bound here is generous but finite, because a
// fixture with a cycle must fail rather than hang.
const maxDepth = 32

// Paths returns every containment path from child up to a root, each path
// listed from the nearest parent outwards. One path means a tree; more
// than one means design §9.2's ancestry closure is many-to-many and
// §8.2's bottom-up navigational visibility has no "only the direct path"
// to restrict itself to.
func Paths(f Fixture, child Ref) ([][]Ref, error) {
	return paths(f, child.Object(), 0, nil)
}

func paths(f Fixture, child Ref, depth int, seen []Ref) ([][]Ref, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("containment from %s exceeds depth %d: the fixture probably has a cycle", child, maxDepth)
	}
	if slices.Contains(seen, child) {
		return nil, fmt.Errorf("containment cycle through %s", child)
	}
	seen = append(seen, child)

	var parents []Ref
	for _, e := range f.Containment {
		if e.Child.Object() == child {
			parents = append(parents, e.Parent.Object())
		}
	}
	if len(parents) == 0 {
		return [][]Ref{{}}, nil
	}

	var out [][]Ref
	for _, parent := range parents {
		upper, err := paths(f, parent, depth+1, seen)
		if err != nil {
			return nil, err
		}
		for _, u := range upper {
			out = append(out, append([]Ref{parent}, u...))
		}
	}
	return out, nil
}

// DirectPath returns the single containment path above child, or
// ErrNoDirectPath when there is more than one. Design §8.2 grants a
// principal limited list rights on an object's ancestors "and only on the
// direct path"; this is the function that has to exist for that sentence
// to mean anything, and the error is the finding.
func DirectPath(f Fixture, child Ref) ([]Ref, error) {
	all, err := Paths(f, child)
	if err != nil {
		return nil, err
	}
	if len(all) != 1 {
		rendered := make([]string, 0, len(all))
		for _, p := range all {
			rendered = append(rendered, renderPath(p))
		}
		return nil, fmt.Errorf("%w: %s has %d paths (%s)", ErrNoDirectPath, child, len(all), strings.Join(rendered, " | "))
	}
	return all[0], nil
}

func renderPath(p []Ref) string {
	if len(p) == 0 {
		return "(root)"
	}
	parts := make([]string, 0, len(p))
	for _, r := range p {
		parts = append(parts, r.String())
	}
	return strings.Join(parts, " < ")
}

// Ancestors returns design §9.2's ancestry closure for one resource: every
// ancestor on every containment path, deduplicated and in a stable order.
// This is the set the compiled predicate joins against, and the set whose
// cardinality finding F3 says becomes many-to-many at fact scale.
func Ancestors(f Fixture, child Ref) ([]Ref, error) {
	all, err := Paths(f, child)
	if err != nil {
		return nil, err
	}
	var out []Ref
	for _, p := range all {
		for _, r := range p {
			if !slices.Contains(out, r) {
				out = append(out, r)
			}
		}
	}
	slices.SortFunc(out, func(a, b Ref) int { return strings.Compare(a.String(), b.String()) })
	return out, nil
}

// PredicateEdges returns the containment edges that are a function of
// data rather than a stored fact (KGS §9.3's predicate-defined
// entity-sets). Their presence is what makes an authorization answer
// change when an ordinary write lands, with no authorization operation
// having occurred.
func PredicateEdges(f Fixture) []Edge {
	var out []Edge
	for _, e := range f.Containment {
		if e.Kind == EdgePredicate {
			out = append(out, e)
		}
	}
	return out
}

// WithLaterWrites returns f as it is after every declared later write has
// landed. It is how a scenario shows that an authorization answer moved
// without any authorization operation having happened.
func WithLaterWrites(f Fixture) Fixture {
	out := f
	out.Containment = slices.Clone(f.Containment)
	out.Assignments = slices.Clone(f.Assignments)
	for _, w := range f.LaterWrites {
		out.Containment = append(out.Containment, w.AddEdges...)
		out.Assignments = append(out.Assignments, w.AddAssignments...)
	}
	out.LaterWrites = nil
	return out
}

// MarkingsOf resolves one resource's marking set: the markings assigned to
// the resource itself, plus those on every ancestor in its ancestry
// closure — because sealing an episode must cover the facts inside it —
// plus the union of the markings of every object it was derived from,
// transitively.
//
// Nothing here is an authorization input. A marking says what the content
// *is*, not who may have it, and the decision procedure never calls this
// function. What reads it is Readable, which answers "can anyone decrypt
// this at all", and MayReceive, which is a consumer's egress gate.
//
// The derivation half is where this design departs from Foundry (§5a), and
// it is why a pipeline cannot launder a marking by deriving: content
// derived from sealed content is sealed, and a cipher does not care which
// pipeline stage read it.
func MarkingsOf(f Fixture, resource Ref) ([]string, error) {
	markings, err := markingsOf(f, resource, 0)
	if err != nil {
		return nil, err
	}
	slices.Sort(markings)
	return slices.Compact(markings), nil
}

func markingsOf(f Fixture, resource Ref, depth int) ([]string, error) {
	if depth > maxDepth {
		return nil, fmt.Errorf("derivation chain through %s exceeds depth %d", resource, maxDepth)
	}
	object := resource.Object()

	scope, err := Ancestors(f, object)
	if err != nil {
		return nil, err
	}
	scope = append(scope, object)

	var out []string
	for _, a := range f.Assignments {
		if !slices.Contains(scope, a.Resource.Object()) {
			continue
		}
		if _, ok := f.Marking(a.Label); !ok {
			return nil, fmt.Errorf("resource %s carries undeclared marking %q", a.Resource, a.Label)
		}
		out = append(out, a.Label)
	}

	for _, d := range f.Derivations {
		if d.Output.Object() != object {
			continue
		}
		for _, in := range d.Inputs {
			inherited, err := markingsOf(f, in, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, inherited...)
		}
	}
	return out, nil
}
