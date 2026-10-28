package domain

import "fmt"

// RootKind is IAM's own kind: one root per tenant, created by CreateTenant.
const RootKind = "root"

// KindSpec is one consumer-registered kind in the published model.
type KindSpec struct {
	Name        string
	Contains    []string
	ContainsAny bool
	Relations   []Relation
}

// Validate checks the kind name, containment and declared relations.
func (k KindSpec) Validate() error {
	if !validSlug(k.Name) {
		return fmt.Errorf("%w: name %q", ErrInvalidKind, k.Name)
	}
	switch k.Name {
	case string(SubjectUser), string(SubjectAgent), string(SubjectGroup):
		return fmt.Errorf("%w: %q is a reserved subject kind", ErrInvalidKind, k.Name)
	}
	if k.Name == RootKind {
		if !k.ContainsAny {
			return fmt.Errorf("%w: root must accept any child kind", ErrInvalidKind)
		}
		if len(k.Contains) != 0 {
			return fmt.Errorf("%w: root must not enumerate contained kinds", ErrInvalidKind)
		}
		if len(k.Relations) != 0 {
			return fmt.Errorf("%w: root declares no relations", ErrInvalidKind)
		}
		return nil
	}
	if k.ContainsAny {
		return fmt.Errorf("%w: only root sets contains_any", ErrInvalidKind)
	}
	seenContains := make(map[string]struct{}, len(k.Contains))
	for _, name := range k.Contains {
		if !validSlug(name) {
			return fmt.Errorf("%w: contained kind %q", ErrInvalidKind, name)
		}
		if _, ok := seenContains[name]; ok {
			return fmt.Errorf("%w: duplicate contained kind %q", ErrInvalidKind, name)
		}
		seenContains[name] = struct{}{}
	}
	seenRelations := make(map[Relation]struct{}, len(k.Relations))
	for _, r := range k.Relations {
		if !r.IsBase() {
			return fmt.Errorf("%w: %q is not a declarable relation", ErrInvalidKind, r)
		}
		if _, ok := seenRelations[r]; ok {
			return fmt.Errorf("%w: duplicate relation %q", ErrInvalidKind, r)
		}
		seenRelations[r] = struct{}{}
	}
	return nil
}

// DefaultKinds returns the built-in node kinds.
func DefaultKinds() []KindSpec {
	return []KindSpec{
		{Name: RootKind, ContainsAny: true},
		{Name: "folder", Contains: []string{"folder", "document", "album"}, Relations: []Relation{Owner, Editor, Commenter, Viewer}},
		{Name: "document", Relations: []Relation{Owner, Editor, Commenter, Viewer}},
		{Name: "album", Contains: []string{"photo"}, Relations: []Relation{Owner, Editor, Commenter, Viewer}},
		{Name: "photo", Relations: []Relation{Owner, Editor, Commenter, Viewer}},
		{Name: "space", Contains: []string{"folder", "message"}, Relations: []Relation{Owner, Editor, Commenter, Viewer}},
		{Name: "message", Relations: []Relation{Owner, Editor, Commenter, Viewer}},
	}
}
