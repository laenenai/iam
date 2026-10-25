package domain

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Permission is one thing a subject may do, named by the consumer that
// registered it. Design §8.4 maps a consumer's actions onto relations;
// this layer has no relation algebra, so an action and the permission it
// needs are the same string and a consumer registers the vocabulary it
// uses.
//
// It is a named type rather than a bare string so a call site cannot pass
// a container label where a permission belongs, and it is validated on
// the way in (see Schema.Validate): a grant naming a permission no schema
// declared is refused rather than stored, because a typo in a grant is a
// grant that silently never fires.
type Permission string

// ContainerKind is one node of a consumer's declared containment tree:
// the kind's name, and the kind of container it lives in.
//
// Parents is a slice, and the slice is the point. A declaration that
// names two parents is representable here precisely so that registration
// can refuse it — see Schema.Validate and ErrMultipleContainmentParents.
// Modelling it as a single optional string would have made the refusal
// unexpressible and the invariant unenforced, which is the state finding
// F3's spike found §8.4 in.
type ContainerKind struct {
	// Name is the kind's name within its schema: "fileset", "document",
	// "topic". No consumer's kind names appear in this module's code
	// (design §8.4), so this string is the whole of what `iam` knows
	// about a consumer's model.
	Name string
	// Parents names the kinds a container of this kind may live in. An
	// empty Parents declares a root kind. Exactly one entry declares a
	// containment edge. Two or more is refused.
	Parents []string
}

// Schema is one consumer's registered model: the container kinds that
// make up its containment tree, and the permission vocabulary its grants
// may name. Design §8.4's "object types, relations, containment edges and
// the actions that map onto relations", reduced to the two of those four
// this layer has.
//
// What a Schema does not carry is the rest of §8.4, and the absences are
// decisions rather than omissions:
//
//   - **No relations.** There is no relation algebra here (no usersets of
//     usersets, no `X from Y`, no computed or union relations), so there
//     is nothing for a relation declaration to declare. A permission on a
//     container, inherited down, is the whole language.
//   - **No persistence and no versioning.** A Schema is registered into a
//     process and validated there; §8.4's explicit schema migration and
//     its computed access delta between two versions are unbuilt. A
//     deployment running two binaries with different registered schemas
//     gets two different answers to "may I create a container of this
//     kind", and the same answer to every decision — because the tree
//     that decisions read is enforced by the schema's single parent
//     column in the database, not by this struct.
type Schema struct {
	// Name identifies the consumer registering it: "cas", "cogos". It is
	// the name the refusals below quote back, so a deployment embedding
	// three consumers can tell whose declaration was refused.
	Name string
	// Version is the consumer's own schema version. It is recorded and
	// not interpreted: §8.4's migration and access-delta report are
	// unbuilt, so nothing here compares two versions.
	Version int
	// Kinds are the container kinds, in any order.
	Kinds []ContainerKind
	// Permissions is the vocabulary a grant under this schema may name.
	Permissions []Permission
}

// Container is one node of a live containment tree: a tenant's folder,
// fileset, graph or topic, by whatever name the consumer's schema gives
// its kind.
//
// There is exactly one Parent, and that single field is the enforcement
// of design §9.2's "its containment path", singular. See
// ErrMultipleContainmentParents for what it buys and what it costs.
type Container struct {
	// ID is the container's stable internal id, and the value a consumer
	// stores on its own rows as the containment key.
	ID ContainerID
	// TenantID scopes it. A container's parent is always in the same
	// tenant; a cross-tenant containment edge is refused, because
	// inheritance through one would carry a grant across the isolation
	// boundary every other part of this system enforces.
	TenantID TenantID
	// Kind is the container's kind, which must be a kind the tenant's
	// registered schema declares.
	Kind string
	// Parent is the container this one lives in, or the zero
	// ContainerID for a root.
	Parent ContainerID
	// Label is a human label for diagnostics. Nothing resolves a
	// container by it and it decides nothing.
	Label string
	// CreatedAt is when the container was recorded.
	CreatedAt time.Time
}

// IsRoot reports whether c has no parent.
func (c Container) IsRoot() bool { return c.Parent == "" }

// Subject is who a grant is written to: one principal, or one group.
//
// It is a struct with unexported fields, so the two states a Subject can
// be in are the only two states a Subject can be in. A pair of exported
// id fields would have added a third — both set — and a fourth — neither
// — and every reader of a grant would have had to decide what those mean.
// CONVENTIONS' rule for a deliberately opaque type applies: it maps to
// its primitives at the storage boundary and the adapter converts, and it
// is given no sql.Scanner or driver.Valuer, because those are exported
// and would let any package construct one.
//
// A group subject is how design §8.2's userset form survives into this
// layer, and it is the only form that does: the members of a group are
// principals, never other groups and never a relation on another object.
// That is what keeps the membership closure a single indexed probe rather
// than the unbounded set expansion §9.2 budgets for.
type Subject struct {
	principal PrincipalID
	group     GroupID
}

// PrincipalSubject returns the subject naming one principal.
func PrincipalSubject(p PrincipalID) Subject { return Subject{principal: p} }

// GroupSubject returns the subject naming one group — design §8.2's
// userset, and the form that makes a membership change take effect with
// no grant rewritten.
func GroupSubject(g GroupID) Subject { return Subject{group: g} }

// Principal returns the principal this subject names, and whether it
// names one.
func (s Subject) Principal() (PrincipalID, bool) { return s.principal, s.principal != "" }

// Group returns the group this subject names, and whether it names one.
func (s Subject) Group() (GroupID, bool) { return s.group, s.group != "" }

// IsZero reports whether s names nobody. The zero Subject is not a
// wildcard and never matches: a grant built from one is refused on the
// way in.
func (s Subject) IsZero() bool { return s.principal == "" && s.group == "" }

// String renders the subject in the design's own notation.
func (s Subject) String() string {
	switch {
	case s.principal != "":
		return "principal:" + string(s.principal)
	case s.group != "":
		return "group:" + string(s.group) + "#member"
	default:
		return "subject:none"
	}
}

// Validate reports whether s names somebody.
func (s Subject) Validate() error {
	if s.IsZero() {
		return fmt.Errorf("%w: a grant must name a principal or a group", ErrInvalidGrant)
	}
	return nil
}

// Validate checks that the schema is well formed and that its containment
// declaration is a forest of trees, returning the first problem it finds.
//
// The one refusal worth reading as a security control rather than
// validation is the multi-parent one. Design §9.2's ancestry closure is
// "bounded by hierarchy depth" only while every container has one parent.
// Finding F3's spike measured what the other shape costs at the budgeted
// scale: the same containment keyed on the resource was 106,495,540 rows
// and 10.9 GB where, keyed on the container, it was 433,063 rows and
// 37 MB. §8.4 accepted a two-parent declaration and the consumer then got
// the first of those silently, which is the gap this function closes.
func (s Schema) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("%w: a schema must name the consumer registering it", ErrInvalidSchema)
	}
	if len(s.Kinds) == 0 {
		return fmt.Errorf("%w: schema %q declares no container kinds, so no container could ever be created under it", ErrInvalidSchema, s.Name)
	}
	if len(s.Permissions) == 0 {
		return fmt.Errorf("%w: schema %q declares no permissions, so no grant could ever be written under it", ErrInvalidSchema, s.Name)
	}

	byName := make(map[string]ContainerKind, len(s.Kinds))
	for _, k := range s.Kinds {
		if strings.TrimSpace(k.Name) == "" {
			return fmt.Errorf("%w: schema %q declares a kind with an empty name", ErrInvalidSchema, s.Name)
		}
		if _, dup := byName[k.Name]; dup {
			return fmt.Errorf("%w: schema %q declares kind %q twice", ErrInvalidSchema, s.Name, k.Name)
		}
		byName[k.Name] = k
	}

	seenPermission := make(map[Permission]struct{}, len(s.Permissions))
	for _, p := range s.Permissions {
		if strings.TrimSpace(string(p)) == "" {
			return fmt.Errorf("%w: schema %q declares an empty permission", ErrInvalidSchema, s.Name)
		}
		if _, dup := seenPermission[p]; dup {
			return fmt.Errorf("%w: schema %q declares permission %q twice", ErrInvalidSchema, s.Name, p)
		}
		seenPermission[p] = struct{}{}
	}

	for _, k := range s.Kinds {
		if len(k.Parents) > 1 {
			return fmt.Errorf("%w: schema %q declares kind %q with %d containment parents (%s). "+
				"Containment is a tree here: one parent per container, one container per resource (design §9.2, finding F3). "+
				"The closure a decision reads is keyed on the container, which is what keeps it bounded by hierarchy depth — "+
				"F3's spike measured the same containment keyed on the resource at 106,495,540 rows and 10.9 GB against "+
				"433,063 rows and 37 MB keyed on the container. A second parent is refused here rather than accepted and "+
				"silently given the first of those. If a consumer genuinely has multi-path containment, F3 reopens and so "+
				"does F1's condition (iii); see docs/superpowers/spikes/2026-10-24-f3-dag-containment.md for which way to go",
				ErrMultipleContainmentParents, s.Name, k.Name, len(k.Parents), strings.Join(k.Parents, ", "))
		}
		for _, parent := range k.Parents {
			if parent == k.Name {
				return fmt.Errorf("%w: schema %q declares kind %q as its own containment parent", ErrInvalidSchema, s.Name, k.Name)
			}
			if _, ok := byName[parent]; !ok {
				return fmt.Errorf("%w: schema %q declares kind %q inside undeclared kind %q", ErrInvalidSchema, s.Name, k.Name, parent)
			}
		}
	}

	roots := 0
	for _, k := range s.Kinds {
		if len(k.Parents) == 0 {
			roots++
		}
	}
	if roots == 0 {
		return fmt.Errorf("%w: every kind in schema %q has a containment parent, so the declaration is a cycle rather than a tree", ErrInvalidSchema, s.Name)
	}
	for _, k := range s.Kinds {
		if err := s.walkToRoot(byName, k); err != nil {
			return err
		}
	}
	return nil
}

// walkToRoot follows k's single parent chain and refuses a cycle. It is
// reachable only for a declaration that passed the multi-parent refusal,
// so the walk is a line rather than a search.
func (s Schema) walkToRoot(byName map[string]ContainerKind, k ContainerKind) error {
	seen := []string{k.Name}
	current := k
	for len(current.Parents) == 1 {
		parent := current.Parents[0]
		if slices.Contains(seen, parent) {
			return fmt.Errorf("%w: schema %q declares a containment cycle through %s", ErrInvalidSchema, s.Name, strings.Join(append(seen, parent), " < "))
		}
		seen = append(seen, parent)
		current = byName[parent]
		if len(seen) > MaxContainmentDepth+1 {
			return fmt.Errorf("%w: schema %q declares a containment chain deeper than %d kinds", ErrInvalidSchema, s.Name, MaxContainmentDepth)
		}
	}
	return nil
}

// Kind returns the named kind and whether the schema declares it.
func (s Schema) Kind(name string) (ContainerKind, bool) {
	for _, k := range s.Kinds {
		if k.Name == name {
			return k, true
		}
	}
	return ContainerKind{}, false
}

// DeclaresPermission reports whether the schema declares p.
func (s Schema) DeclaresPermission(p Permission) bool {
	return slices.Contains(s.Permissions, p)
}

// ParentKind returns the kind a container of this kind must live in, and
// whether it has one. It returns one kind rather than a set because
// Validate has already refused every declaration for which the question
// has more than one answer.
func (k ContainerKind) ParentKind() (string, bool) {
	if len(k.Parents) == 1 {
		return k.Parents[0], true
	}
	return "", false
}

// MaxContainmentDepth bounds how deep a containment tree may go. Anti-goal
// A2 budgets a hierarchy of depth 6; the bound here is far looser, and it
// exists so that a cycle that slipped past the declaration check — a
// container whose parent chain was corrupted in the database, say —
// terminates the ancestry walk with an error rather than running forever
// inside an authorization decision.
const MaxContainmentDepth = 32
