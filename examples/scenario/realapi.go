package scenario

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/laenenai/iam"
)

// realSchemaName is the schema the translator registers. It is this
// corpus's own name rather than a consumer's, so materializing a fixture
// against an authorizer that already holds CAS's or cogos's schema adds
// one rather than colliding with one — the same reason iamtest registers
// under its own name.
const realSchemaName = "examples/scenario"

// ErrNotTranslatable is what Realize returns when a fixture cannot be
// materialized against the real authorization layer at all. It is the
// corpus's second-most valuable error after ErrUnexpressible, and it means
// something narrower: the *requirement* may be perfectly expressible in
// design §8.2's forms, and `iam` as built has no shape for this fixture.
//
// It is a separate sentinel precisely so the two cannot be confused. A
// scenario in examples/unexpressible is a requirement the design refuses;
// a fixture that earns this error is a requirement the design permits and
// this implementation does not reach, which is a finding about the
// implementation.
var ErrNotTranslatable = errors.New("this fixture has no form in the authorization layer as built")

// Gap is one thing a fixture declares that the real authorization layer
// has no form for. Gaps are what decide whether a scenario's expectation
// table can be replayed against `iam` at all, and they are collected
// rather than returned as an error because a fixture with one gap and
// twenty expressible grants is worth materializing: the gap is then a
// named, printed reason rather than a scenario that silently fell back to
// the oracle.
type Gap struct {
	// What names the fixture construct that has no form, in the design's
	// own notation.
	What string
	// Why says which absence it runs into, naming the thing `iam`
	// deliberately does not have.
	Why string
}

// String renders the gap for a test log.
func (g Gap) String() string { return g.What + ": " + g.Why }

// RealWorld is a fixture materialized against the real authorization
// layer: a registered schema, one container per object, and one grant per
// tuple. It answers the same question the reference oracle answers, from
// `iam.Decide` instead of from fixture data, so the two can be run against
// the same expectation table and diffed — which is design §9.4's
// differential authorization audit aimed one layer up, and the most
// valuable thing in this directory.
//
// # The translation, in three rules
//
// A **permission is a relation name, verbatim**. `folder:x#viewer@user:a`
// becomes a grant of permission `viewer` on the container for `folder:x`
// naming principal `a`. There is no mapping table and no renaming,
// because a mapping table is a place for the corpus and the module to
// mean different things by the same word.
//
// A **container is an object**. Every object that appears in the
// fixture's containment graph or as a tuple's object gets one container,
// placed under the container of its single containment parent.
//
// A **userset is a group**. `team:eng#member` resolves to the group
// `Materialize` already created in the real registry, so the membership
// side of every decision is live registry state rather than fixture data.
// A userset over something that is not a fixture group — `role:ws-reader#assignee`,
// where the set is defined by tuples on a role object — is translated
// into an ordinary group holding the principals those tuples name. That
// works exactly as far as this layer's groups do, and where it stops is
// recorded as a Gap rather than papered over: see Gaps.
//
// # Where the container *kinds* come from, and why they carry a depth
//
// They are synthesized per containment depth — `folder@0`, `folder@1` —
// rather than taken from the fixture's resource kinds, and the reason is a
// real limit worth stating. `iam.ContainerKind` declares at most one
// parent *kind*, refuses a kind that names itself as its own parent, and
// refuses at write time both a root container whose kind declares a parent
// and a parented container whose kind declares none. Those three rules
// together mean a kind nested inside itself cannot be declared at all: a
// `folder` containing a `folder`, with a `folder` at the root, has no
// declaration in this schema language. D2 and D7 are exactly that shape,
// and they are ordinary Drive-shaped hierarchies rather than exotica.
//
// Depth-indexed kinds are a corpus-side workaround for that, and they cost
// nothing a decision can see: `Decide` never reads a kind, grants name
// containers by id, and the closure is the parent chain. What they do cost
// is that `ErrMultipleContainmentParents` can no longer fire here, since
// every synthesized kind has one parent by construction — so the
// single-parent property is checked by this file instead, against the
// fixture, before any kind is synthesized.
type RealWorld struct {
	authorizer iam.Authorizer
	env        *Env
	fixture    Fixture

	// containers maps a fixture object to the container minted for it,
	// and ids maps back, so a Decision's `Via` grant can be rendered in
	// the fixture's own notation and compared to a pinned `Because`.
	containers map[Ref]iam.ContainerID
	ids        map[iam.ContainerID]Ref
	parents    map[Ref]Ref

	// principalNames and groupSubjects render a grant's subject back into
	// the notation an expectation row pins: a fixture-local principal name,
	// or a userset spelled `object#relation`.
	principalNames map[iam.PrincipalID]string
	groupSubjects  map[iam.GroupID]string

	gaps []Gap
}

// Gaps returns everything in the fixture the real layer had no form for.
// An empty result means the whole fixture reached the real module, which
// is the condition the harness uses to decide whether an expectation table
// can be replayed against it — a mechanical property of the fixture rather
// than a flag somebody maintains, because a flag is how a scenario ends up
// claiming more than it does.
func (w *RealWorld) Gaps() []Gap { return slices.Clone(w.gaps) }

// Expressible reports whether every grant in the fixture reached the real
// authorization layer.
func (w *RealWorld) Expressible() bool { return len(w.gaps) == 0 }

// Realize materializes f's grant layer against authorizer, on top of the
// identity layer env already materialized against the registry. It
// registers a schema, creates a container per object, resolves every
// userset to a real group, and writes a grant per tuple.
//
// It refuses, with ErrNotTranslatable, a fixture this layer has no shape
// for at all: containment that is not a forest (several parents for one
// child, which is finding F3 and which `iam` refuses by design), a
// containment edge that is a predicate over data rather than a stored
// parent, or a tuple written on an attribute rather than an object. Those
// refusals are the point of running the corpus against the real module and
// not a failure of it.
func Realize(ctx context.Context, authorizer iam.Authorizer, env *Env, f Fixture) (*RealWorld, error) {
	if authorizer == nil {
		return nil, fmt.Errorf("%w: no authorizer was supplied, so there is nothing to materialize against", ErrNotTranslatable)
	}
	if env == nil {
		return nil, fmt.Errorf("%w: the identity layer must be materialized first; env carries the minted ids", ErrNotTranslatable)
	}

	w := &RealWorld{
		authorizer:     authorizer,
		env:            env,
		fixture:        f,
		containers:     make(map[Ref]iam.ContainerID),
		ids:            make(map[iam.ContainerID]Ref),
		parents:        make(map[Ref]Ref),
		principalNames: make(map[iam.PrincipalID]string, len(f.Principals)),
		groupSubjects:  make(map[iam.GroupID]string),
	}

	for _, spec := range f.Principals {
		id, ok := env.PrincipalID(spec.Name)
		if !ok {
			return nil, fmt.Errorf("%w: the identity layer minted no principal for %q", ErrNotTranslatable, spec.Name)
		}
		w.principalNames[id] = spec.Name
	}

	objects, depths, err := w.placeObjects(f)
	if err != nil {
		return nil, err
	}
	if len(objects) == 0 {
		// A fixture with no containment and no tuples has no grant layer
		// to materialize, which A1 is: it is entirely about delegation and
		// the deprovision cascade. Registering a schema with no kinds is
		// refused, correctly — a declaration under which no container could
		// ever be created is a mistake every other time — so there is
		// nothing to register and the world is legitimately empty.
		return w, nil
	}
	if err := w.registerSchema(ctx, f, objects, depths); err != nil {
		return nil, err
	}
	if err := w.createContainers(ctx, objects, depths); err != nil {
		return nil, err
	}
	if err := w.resolveUsersets(ctx, f); err != nil {
		return nil, err
	}
	if err := w.writeGrants(ctx, f); err != nil {
		return nil, err
	}
	return w, nil
}

// placeObjects returns every object that needs a container, in creation
// order (parents before children), together with its containment depth. It
// is where the single-parent tree is enforced against the fixture, which
// has to happen here because the synthesized kinds below cannot express a
// second parent and so cannot be refused for one.
func (w *RealWorld) placeObjects(f Fixture) ([]Ref, map[Ref]int, error) {
	for _, e := range f.Containment {
		if e.Kind != EdgeExplicit {
			return nil, nil, fmt.Errorf("%w: the containment edge %s < %s is a predicate over data (%q) and not a "+
				"stored parent. A container's parent is set at creation here, so an edge whose membership changes "+
				"when ordinary data changes has nothing to be — see U5",
				ErrNotTranslatable, e.Child, e.Parent, e.Predicate)
		}
	}

	objects := allObjects(f)
	depths := make(map[Ref]int, len(objects))
	for _, o := range objects {
		path, err := DirectPath(f, o)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrNotTranslatable, err)
		}
		depths[o] = len(path)
		if len(path) > 0 {
			w.parents[o] = path[0]
		}
	}

	sort.Slice(objects, func(i, j int) bool {
		if depths[objects[i]] != depths[objects[j]] {
			return depths[objects[i]] < depths[objects[j]]
		}
		return objects[i].String() < objects[j].String()
	})
	return objects, depths, nil
}

// containerKind is the synthesized kind name for an object at a depth. See
// RealWorld's doc for why the depth is in the name.
func containerKind(r Ref, depth int) string { return r.Kind + "@" + strconv.Itoa(depth) }

// registerSchema declares the synthesized container kinds and every
// relation name the fixture uses as a permission.
func (w *RealWorld) registerSchema(ctx context.Context, f Fixture, objects []Ref, depths map[Ref]int) error {
	parentOf := make(map[string]string, len(objects))
	for _, o := range objects {
		kind := containerKind(o, depths[o])
		var parent string
		if p, ok := w.parents[o]; ok {
			parent = containerKind(p, depths[p])
		}
		if previous, seen := parentOf[kind]; seen && previous != parent {
			return fmt.Errorf("%w: objects of fixture kind %q at containment depth %d sit under two different "+
				"kinds (%q and %q), so no single container kind describes them. Containment here is a tree of "+
				"kinds as well as of containers",
				ErrNotTranslatable, o.Kind, depths[o], previous, parent)
		}
		parentOf[kind] = parent
	}

	kinds := make([]iam.ContainerKind, 0, len(parentOf))
	for name, parent := range parentOf {
		kind := iam.ContainerKind{Name: name}
		if parent != "" {
			kind.Parents = []string{parent}
		}
		kinds = append(kinds, kind)
	}
	sort.Slice(kinds, func(i, j int) bool { return kinds[i].Name < kinds[j].Name })

	permissions, err := permissionsOf(f)
	if err != nil {
		return err
	}
	schema := iam.Schema{Name: realSchemaName, Version: 1, Kinds: kinds, Permissions: permissions}
	if err := w.authorizer.RegisterSchema(ctx, schema); err != nil {
		return fmt.Errorf("%w: RegisterSchema: %w", ErrNotTranslatable, err)
	}
	return nil
}

// permissionsOf is the permission set a fixture needs: every relation name
// its kinds declare, plus every relation any tuple is written on. The
// second half is not redundancy — a grant of a permission no schema
// declares is refused, and finding a misspelled relation here costs one
// error where finding it at decision time costs a silent deny.
func permissionsOf(f Fixture) ([]iam.Permission, error) {
	seen := make(map[string]bool)
	add := func(name string) { seen[name] = true }
	for _, k := range f.Kinds {
		for _, r := range k.Relations {
			add(r.Name)
			for _, u := range r.Union {
				add(u)
			}
			for _, p := range r.InheritFromParent {
				add(p)
			}
		}
		for _, relation := range k.Actions {
			add(relation)
		}
	}
	for _, t := range f.Tuples {
		add(t.Relation)
	}

	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]iam.Permission, 0, len(names))
	for _, name := range names {
		p := iam.Permission(name)
		if !iam.ValidPermissionName(p) {
			return nil, fmt.Errorf("%w: relation %q is not a permission name this module accepts; a permission "+
				"is written as a literal into a row-level-security policy, which is why the set is restricted",
				ErrNotTranslatable, name)
		}
		out = append(out, p)
	}
	return out, nil
}

// createContainers mints one container per object, parents first.
func (w *RealWorld) createContainers(ctx context.Context, objects []Ref, depths map[Ref]int) error {
	for _, o := range objects {
		spec := iam.ContainerSpec{
			TenantID: w.env.Tenant,
			Kind:     containerKind(o, depths[o]),
			Label:    o.String(),
		}
		if p, ok := w.parents[o]; ok {
			parent, ok := w.containers[p]
			if !ok {
				return fmt.Errorf("%w: %s's parent %s has no container yet, so the creation order is wrong",
					ErrNotTranslatable, o, p)
			}
			spec.Parent = parent
		}
		container, err := w.authorizer.CreateContainer(ctx, spec)
		if err != nil {
			return fmt.Errorf("%w: CreateContainer(%s): %w", ErrNotTranslatable, o, err)
		}
		w.containers[o] = container.ID
		w.ids[container.ID] = o
	}
	return nil
}

// resolveUsersets maps every userset that appears as a tuple subject onto
// a real group.
//
// A userset over a group the fixture declares is the group Materialize
// already created, so a decision through it joins live registry membership
// — which is the whole reason identity lives in this module. A userset
// over anything else is a set defined by tuples, and this layer has no
// object with relations of its own to hold one: a role is not a first-class
// object here. The translation is an ordinary group holding the principals
// those tuples name directly, and a member of that set which is itself a
// set is recorded as a Gap, because this layer's groups hold principals and
// never other groups.
func (w *RealWorld) resolveUsersets(ctx context.Context, f Fixture) error {
	for _, t := range f.Tuples {
		if t.Subject.Userset == nil {
			continue
		}
		us := *t.Subject.Userset
		if _, done := w.groupIDFor(us); done {
			continue
		}
		if g, ok := w.env.Group(us.Object.String()); ok && us.Relation == groupMemberRelation {
			w.groupSubjects[g.ID] = us.String()
			continue
		}
		if err := w.synthesizeGroup(ctx, f, us); err != nil {
			return err
		}
	}
	return nil
}

// groupIDFor returns the group already resolved for a userset.
func (w *RealWorld) groupIDFor(us Userset) (iam.GroupID, bool) {
	want := us.String()
	for id, display := range w.groupSubjects {
		if display == want {
			return id, true
		}
	}
	return "", false
}

// synthesizeGroup creates the group that stands in for a userset the
// fixture defines with tuples rather than with membership.
func (w *RealWorld) synthesizeGroup(ctx context.Context, f Fixture, us Userset) error {
	group, err := w.env.Registry.EnsureGroup(ctx, w.env.Tenant, us.String())
	if err != nil {
		return fmt.Errorf("%w: EnsureGroup(%s): %w", ErrNotTranslatable, us, err)
	}
	w.groupSubjects[group.ID] = us.String()

	for _, t := range f.Tuples {
		if t.Object.Object() != us.Object || t.Relation != us.Relation {
			continue
		}
		if t.Subject.Userset != nil {
			w.gaps = append(w.gaps, Gap{
				What: t.String(),
				Why: fmt.Sprintf("the set %s has a member that is itself a set (%s). A group's members are "+
					"principals here and never other groups, and there is no relation on %s for a userset to "+
					"be resolved through either — this layer has no roles as first-class objects with "+
					"relations of their own. So this tuple reaches nobody, and every decision that depended "+
					"on it is answered by the oracle alone",
					us, t.Subject, us.Object),
			})
			continue
		}
		id, ok := w.env.PrincipalID(t.Subject.Principal)
		if !ok {
			return fmt.Errorf("%w: tuple %s names principal %q, which the identity layer did not mint",
				ErrNotTranslatable, t, t.Subject.Principal)
		}
		if err := w.env.Registry.AddGroupMember(ctx, group.ID, id); err != nil {
			return fmt.Errorf("%w: AddGroupMember(%s, %s): %w", ErrNotTranslatable, us, t.Subject.Principal, err)
		}
	}
	return nil
}

// writeGrants writes one grant per tuple.
func (w *RealWorld) writeGrants(ctx context.Context, f Fixture) error {
	for _, t := range f.Tuples {
		if t.Object.Attribute != "" {
			return fmt.Errorf("%w: tuple %s is written on an attribute. A grant is written on a container, and "+
				"whether an attribute-scoped restriction can be enforced at all is finding F4",
				ErrNotTranslatable, t)
		}
		container, ok := w.containers[t.Object.Object()]
		if !ok {
			return fmt.Errorf("%w: tuple %s is written on %s, which has no container", ErrNotTranslatable, t, t.Object)
		}
		subject, err := w.subjectFor(t)
		if err != nil {
			return err
		}
		spec := iam.GrantSpec{
			TenantID:   w.env.Tenant,
			Container:  container,
			Permission: iam.Permission(t.Relation),
			Subject:    subject,
		}
		if _, err := w.authorizer.Grant(ctx, spec); err != nil {
			return fmt.Errorf("%w: Grant(%s): %w", ErrNotTranslatable, t, err)
		}
	}
	return nil
}

// subjectFor renders a tuple's subject as a grant subject.
func (w *RealWorld) subjectFor(t Tuple) (iam.Subject, error) {
	if t.Subject.Userset == nil {
		id, ok := w.env.PrincipalID(t.Subject.Principal)
		if !ok {
			return iam.Subject{}, fmt.Errorf("%w: tuple %s names principal %q, which the identity layer did not mint",
				ErrNotTranslatable, t, t.Subject.Principal)
		}
		return iam.PrincipalSubject(id), nil
	}
	id, ok := w.groupIDFor(*t.Subject.Userset)
	if !ok {
		return iam.Subject{}, fmt.Errorf("%w: tuple %s names userset %s, which resolved to no group",
			ErrNotTranslatable, t, t.Subject)
	}
	return iam.GroupSubject(id), nil
}

// Decide answers one expectation row against the real module. Its return
// type is the corpus's own Decision, so it can be compared field by field
// with what the reference oracle answered for the same row.
//
// # Why this is a walk over Decide rather than one call to it
//
// `iam.Decide` answers one question: does some grant of this permission on
// this container or any of its ancestors reach this principal. That is
// §8.2's form 1, form 2 and form 3 in a single call, and the containment
// closure inside it is the part of this module the corpus most wants
// tested — so form 3 is resolved by `iam` and never by this file.
//
// What `iam` has no notion of is form 4, union over other relations on the
// *same* object: a permission there is a name and not a lattice. So the
// union is applied by this walk, in the order the reference oracle applies
// it — direct and userset on the object, then inheritance, then union —
// because the corpus matches the *reason* and the reason is defined as the
// outermost form that fired. Applying the union first would report `union`
// where the oracle reports `inherited`, which is not a cosmetic
// difference: it is the difference between telling a consumer to look at a
// grant on the folder and telling them to look at the schema's relation
// definition.
//
// The honest cost of doing it this way is one divergence this walk
// detects rather than hides. `iam` inherits *every* permission down the
// whole container tree; the corpus's schema declares inheritance per
// relation, so `owner` on a folder confers nothing on the documents inside
// it. Nothing in the corpus distinguishes the two today, and holds()
// refuses to paper over it if a row ever does.
func (w *RealWorld) Decide(ctx context.Context, principal, action string, resource Ref) (Decision, error) {
	if _, ok := w.fixture.Principal(principal); !ok {
		return Decision{}, fmt.Errorf("unknown principal %q", principal)
	}
	id, ok := w.env.PrincipalID(principal)
	if !ok {
		return Decision{}, fmt.Errorf("the identity layer minted no principal for %q", principal)
	}
	kind, ok := w.fixture.Kind(resource.Kind)
	if !ok {
		return Decision{}, fmt.Errorf("unregistered resource kind %q", resource.Kind)
	}
	relation, ok := kind.Actions[action]
	if !ok {
		return Decision{}, fmt.Errorf("kind %q registers no action %q (registered: %v)", kind.Name, action, actionNames(kind))
	}
	return w.holds(ctx, id, resource.Object(), relation, 0)
}

// holds evaluates one (principal, object, relation) against the real
// module, in the reference oracle's form order. See Decide for why the
// order is load-bearing.
func (w *RealWorld) holds(ctx context.Context, principal iam.PrincipalID, object Ref, relation string, depth int) (Decision, error) {
	if depth > maxDepth {
		return Decision{}, fmt.Errorf("relation resolution for %s#%s exceeds depth %d", object, relation, maxDepth)
	}
	rel, ok := w.fixture.Relation(object.Kind, relation)
	if !ok {
		return Decision{}, fmt.Errorf("kind %q registers no relation %q", object.Kind, relation)
	}

	// Forms 1, 2 and 3 in one call: iam's own containment closure.
	if container, known := w.containers[object]; known {
		d, err := w.authorizer.Decide(ctx, iam.Request{
			TenantID:   w.env.Tenant,
			Principal:  principal,
			Permission: iam.Permission(relation),
			Container:  container,
		})
		if err != nil {
			return Decision{}, fmt.Errorf("iam.Decide(%s, %s, %s): %w", principal, relation, object, err)
		}
		if d.Allowed {
			if err := w.checkInheritanceDeclared(object, relation, d.Depth); err != nil {
				return Decision{}, err
			}
			because, err := w.because(d.Via)
			if err != nil {
				return Decision{}, err
			}
			switch {
			case d.Depth > 0:
				return Decision{Verdict: Allow, Reason: ReasonInherited, Because: because}, nil
			default:
				if _, isGroup := d.Via.Subject.Group(); isGroup {
					return Decision{Verdict: Allow, Reason: ReasonUserset, Because: because}, nil
				}
				return Decision{Verdict: Allow, Reason: ReasonDirect, Because: because}, nil
			}
		}
	}

	// Form 3 again, and not redundantly. The call above already walked
	// the ancestors for *this* permission; what it cannot see is an
	// ancestor reaching this relation through a union of its own, because
	// the union set is a property of the ancestor's kind. D1's `anne may
	// write the documents in the folder she owns` is exactly that: no
	// `editor` grant exists anywhere, and the folder's `editor` unions
	// with the `owner` grant written on it.
	for _, parentRelation := range rel.InheritFromParent {
		for _, e := range w.fixture.Containment {
			if e.Child.Object() != object {
				continue
			}
			up, err := w.holds(ctx, principal, e.Parent.Object(), parentRelation, depth+1)
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
		d, err := w.holds(ctx, principal, object, other, depth+1)
		if err != nil {
			return Decision{}, err
		}
		if d.Verdict == Allow {
			return Decision{Verdict: Allow, Reason: ReasonUnion, Because: d.Because}, nil
		}
	}

	return Decision{Verdict: Deny, Reason: ReasonNoGrant}, nil
}

// checkInheritanceDeclared refuses to report an allow that `iam`'s closure
// carried further than the fixture's schema says the relation travels.
//
// It is the one place the two models are known to differ and the
// difference is not currently observable. `iam` has one containment
// closure and no per-permission inheritance: a grant on a container
// reaches every descendant, for every permission. Design §8.2's form 3 is
// declared per relation, so a schema can say `viewer from parent` and say
// nothing about `owner` — and the corpus's Drive schema does exactly that,
// which is why a folder's owner is not declared to own the documents
// inside it.
//
// No expectation row in the corpus distinguishes the two, because no row
// asks a non-inheriting permission about a nested object. Rather than
// record that as a comment and wait, this fails the row that first does:
// a silent divergence between the model a consumer reads in a schema and
// the model the module evaluates is the most expensive kind of
// authorization bug there is.
func (w *RealWorld) checkInheritanceDeclared(object Ref, relation string, depth int) error {
	current := object
	for hop := 0; hop < depth; hop++ {
		rel, ok := w.fixture.Relation(current.Kind, relation)
		if !ok {
			return fmt.Errorf("iam carried permission %q down to %s from %d hops up, but kind %q registers no "+
				"relation %q at hop %d", relation, object, depth, current.Kind, relation, hop)
		}
		if !slices.Contains(rel.InheritFromParent, relation) {
			return fmt.Errorf("iam's containment closure carried permission %q from %d hops above %s, but "+
				"%s#%s does not declare `%s from parent`. This layer inherits every permission down the whole "+
				"container tree and design §8.2's form 3 is declared per relation, so the two models differ "+
				"here: either this fixture's schema means something iam cannot express, or iam needs "+
				"per-permission inheritance. It is a finding either way, and a silent one would be worse",
				relation, depth, object, current.Kind, relation, relation)
		}
		parent, ok := w.parents[current]
		if !ok {
			return fmt.Errorf("iam reported depth %d for %s#%s, but %s has no containment parent, so the "+
				"closure is deeper than the fixture's graph", depth, object, relation, current)
		}
		current = parent
	}
	return nil
}

// because renders the grant a decision came through in the design's
// notation, `object#relation@subject`, which is what an expectation row
// pins. A grant that cannot be rendered is an error rather than a blank:
// the corpus compares this string exactly so that a scenario cannot drift
// into passing through a different grant than the one it documents, and a
// blank would make it pass through any of them.
func (w *RealWorld) because(via iam.Grant) (string, error) {
	if via.IsZero() {
		return "", errors.New("iam allowed a request without naming the grant responsible, so the reason a " +
			"scenario pins cannot be checked")
	}
	object, ok := w.ids[via.Container]
	if !ok {
		return "", fmt.Errorf("iam allowed through a grant on container %s, which this fixture did not create", via.Container)
	}
	var subject string
	switch principal, isPrincipal := via.Subject.Principal(); {
	case isPrincipal:
		name, known := w.principalNames[principal]
		if !known {
			return "", fmt.Errorf("iam allowed through a grant naming principal %s, which this fixture did not mint", principal)
		}
		subject = name
	default:
		group, isGroup := via.Subject.Group()
		if !isGroup {
			return "", fmt.Errorf("the grant on %s names neither a principal nor a group", object)
		}
		name, known := w.groupSubjects[group]
		if !known {
			return "", fmt.Errorf("iam allowed through a grant naming group %s, which this fixture did not resolve", group)
		}
		subject = name
	}
	return object.String() + "#" + string(via.Permission) + "@" + subject, nil
}

// renderGaps joins a world's gaps for a test log.
func renderGaps(gaps []Gap) string {
	out := make([]string, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, g.String())
	}
	return strings.Join(out, "\n  ")
}
