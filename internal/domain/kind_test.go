package domain

import (
	"errors"
	"testing"
)

func TestKindSpec(t *testing.T) {
	root := KindSpec{Name: RootKind, ContainsAny: true}
	if err := root.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := KindSpec{Name: "folder", Relations: []Relation{CanShare}}
	if err := bad.Validate(); !errors.Is(err, ErrInvalidKind) {
		t.Fatal("computed relations are not declared")
	}
}

func TestKindSpecRules(t *testing.T) {
	valid := []KindSpec{
		{Name: "folder", Contains: []string{"folder", "document"}, Relations: []Relation{Owner, Editor, Commenter, Viewer}},
		{Name: "photo"},
	}
	for _, k := range valid {
		if err := k.Validate(); err != nil {
			t.Fatalf("%#v: %v", k, err)
		}
	}

	invalid := []KindSpec{
		{Name: "Folder"},
		{Name: RootKind},
		{Name: RootKind, ContainsAny: true, Relations: []Relation{Owner}},
		{Name: "folder", ContainsAny: true},
		{Name: "folder", Contains: []string{"Photo"}},
		{Name: "folder", Relations: []Relation{Owner, Owner}},
		{Name: "folder", Relations: []Relation{CanDelete}},
		{Name: "folder", Relations: []Relation{CanView}},
	}
	for _, k := range invalid {
		if err := k.Validate(); !errors.Is(err, ErrInvalidKind) {
			t.Fatalf("%#v: %v", k, err)
		}
	}
}

func TestDefaultKinds(t *testing.T) {
	kinds := DefaultKinds()
	byName := make(map[string]KindSpec, len(kinds))
	for _, k := range kinds {
		if err := k.Validate(); err != nil {
			t.Fatalf("%s: %v", k.Name, err)
		}
		byName[k.Name] = k
	}

	root, ok := byName[RootKind]
	if !ok || !root.ContainsAny || len(root.Relations) != 0 {
		t.Fatalf("root: %#v", root)
	}
	folder := byName["folder"]
	if got := folder.Contains; len(got) != 3 || got[0] != "folder" || got[1] != "document" || got[2] != "album" {
		t.Fatalf("folder contains: %v", got)
	}
	for _, leaf := range []string{"document", "photo", "message"} {
		if len(byName[leaf].Contains) != 0 {
			t.Fatalf("%s must be a leaf", leaf)
		}
	}
}

func TestSubjectKindNamesAreReserved(t *testing.T) {
	for _, name := range []string{"user", "agent", "group"} {
		if err := (KindSpec{Name: name}).Validate(); !errors.Is(err, ErrInvalidKind) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
