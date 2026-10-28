package domain

import (
	"errors"
	"testing"
)

func TestSubjectNeedsSubjectKind(t *testing.T) {
	if _, err := ParseSubject(URN("laenen/folder/home")); !errors.Is(err, ErrInvalidSubject) {
		t.Fatal("a node kind is not a subject")
	}
	u, err := NewUserSubject("laenen", "u1")
	if err != nil {
		t.Fatal(err)
	}
	if u.Kind != SubjectUser || u.URN != "laenen/user/u1" {
		t.Fatalf("%#v", u)
	}
}

func TestParseSubjectKinds(t *testing.T) {
	for _, tc := range []struct {
		urn  URN
		kind SubjectKind
	}{
		{"laenen/user/u1", SubjectUser},
		{"laenen/agent/a1", SubjectAgent},
		{"laenen/group/g1", SubjectGroup},
	} {
		s, err := ParseSubject(tc.urn)
		if err != nil {
			t.Fatalf("%s: %v", tc.urn, err)
		}
		if s.Kind != tc.kind || s.URN != tc.urn {
			t.Fatalf("%s: %#v", tc.urn, s)
		}
		if err := s.Validate(); err != nil {
			t.Fatalf("%s: %v", tc.urn, err)
		}
	}

	if _, err := NewSubjectURN("laenen", "folder", "f1"); !errors.Is(err, ErrInvalidSubject) {
		t.Fatalf("node kind as subject: %v", err)
	}
	if _, err := NewGroupSubject("laenen", "g1"); err != nil {
		t.Fatal(err)
	}
}

func TestSubjectValidateRejectsMismatch(t *testing.T) {
	for _, s := range []Subject{
		{URN: "laenen/user/u1", Kind: SubjectGroup},
		{URN: "", Kind: SubjectUser},
		{URN: "Laenen/user/u1", Kind: SubjectUser},
	} {
		if err := s.Validate(); !errors.Is(err, ErrInvalidSubject) {
			t.Fatalf("%#v: %v", s, err)
		}
	}
}
