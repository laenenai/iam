// Package enginetest is the conformance suite for an Engine adapter.
package enginetest

import (
	"context"
	"testing"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/engine"
)

func mustWrite(t *testing.T, e engine.Engine, tuples ...engine.Tuple) {
	t.Helper()
	if err := e.Write(context.Background(), tuples...); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func mustDelete(t *testing.T, e engine.Engine, tuples ...engine.Tuple) {
	t.Helper()
	if err := e.Delete(context.Background(), tuples...); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func subject(urn domain.URN) domain.Subject {
	return domain.Subject{URN: urn, Kind: domain.SubjectUser}
}

func check(t *testing.T, e engine.Engine, s domain.Subject, rel domain.Relation, object domain.URN) (bool, domain.Reason) {
	t.Helper()
	ok, reason, err := e.Check(context.Background(), s, rel, object)
	if err != nil {
		t.Fatalf("check %s %s: %v", rel, object, err)
	}
	return ok, reason
}

// RunSuite runs the authoritative contract for an Engine adapter.
func RunSuite(t *testing.T, newEngine func(t *testing.T) engine.Engine) {
	t.Helper()

	t.Run("OwnerImpliesLadder", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		mustWrite(t, e, engine.Tuple{Object: "t/document/d1", Relation: domain.Owner, Subject: u.URN})
		for _, rel := range []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer, domain.CanShare, domain.CanDelete, domain.CanView, domain.CanEdit, domain.CanComment} {
			if ok, reason := check(t, e, u, rel, "t/document/d1"); !ok {
				t.Fatalf("%s denied", rel)
			} else if reason != domain.ReasonDirect {
				t.Fatalf("%s reason=%q", rel, reason)
			}
		}
	})

	t.Run("Inheritance", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		mustWrite(t, e,
			engine.Tuple{Object: "t/folder/root", Relation: domain.Owner, Subject: u.URN},
			engine.Tuple{Object: "t/document/d1", Relation: domain.Parent, Subject: "t/folder/root"},
		)
		for _, rel := range []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer, domain.CanShare, domain.CanDelete} {
			if ok, reason := check(t, e, u, rel, "t/document/d1"); !ok || reason != domain.ReasonInherited {
				t.Fatalf("%s: ok=%v reason=%q", rel, ok, reason)
			}
		}
	})

	t.Run("GroupUserset", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		other := subject("t/user/u2")
		mustWrite(t, e,
			engine.Tuple{Object: "t/group/g1", Relation: domain.Member, Subject: u.URN},
			engine.Tuple{Object: "t/document/d1", Relation: domain.Viewer, Subject: "t/group/g1", Userset: true},
		)
		if ok, reason := check(t, e, u, domain.Viewer, "t/document/d1"); !ok || reason != domain.ReasonUserset {
			t.Fatalf("member: ok=%v reason=%q", ok, reason)
		}
		if ok, _ := check(t, e, other, domain.Viewer, "t/document/d1"); ok {
			t.Fatal("non-member allowed")
		}
	})

	t.Run("UsersetOnAncestorIsInherited", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		mustWrite(t, e,
			engine.Tuple{Object: "t/group/g1", Relation: domain.Member, Subject: u.URN},
			engine.Tuple{Object: "t/folder/f1", Relation: domain.Viewer, Subject: "t/group/g1", Userset: true},
			engine.Tuple{Object: "t/document/d1", Relation: domain.Parent, Subject: "t/folder/f1"},
		)
		if ok, reason := check(t, e, u, domain.Viewer, "t/document/d1"); !ok || reason != domain.ReasonInherited {
			t.Fatalf("ok=%v reason=%q", ok, reason)
		}
	})

	t.Run("CanDeleteDoesNotInherit", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		mustWrite(t, e,
			engine.Tuple{Object: "t/folder/f1", Relation: domain.CanDelete, Subject: u.URN},
			engine.Tuple{Object: "t/document/d1", Relation: domain.Parent, Subject: "t/folder/f1"},
		)
		if ok, _ := check(t, e, u, domain.CanDelete, "t/document/d1"); ok {
			t.Fatal("direct can_delete inherited")
		}
		if ok, _ := check(t, e, u, domain.CanDelete, "t/folder/f1"); !ok {
			t.Fatal("direct can_delete denied")
		}
	})

	t.Run("OwnerOnAncestorAllowsDelete", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		mustWrite(t, e,
			engine.Tuple{Object: "t/folder/f1", Relation: domain.Owner, Subject: u.URN},
			engine.Tuple{Object: "t/document/d1", Relation: domain.Parent, Subject: "t/folder/f1"},
		)
		if ok, reason := check(t, e, u, domain.CanDelete, "t/document/d1"); !ok || reason != domain.ReasonInherited {
			t.Fatalf("ok=%v reason=%q", ok, reason)
		}
	})

	t.Run("DeleteRemovesTuple", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		tuple := engine.Tuple{Object: "t/document/d1", Relation: domain.Viewer, Subject: u.URN}
		mustWrite(t, e, tuple)
		if ok, _ := check(t, e, u, domain.Viewer, "t/document/d1"); !ok {
			t.Fatal("missing before delete")
		}
		mustDelete(t, e, tuple)
		if ok, reason := check(t, e, u, domain.Viewer, "t/document/d1"); ok || reason != domain.ReasonNoGrant {
			t.Fatalf("still allowed: reason=%q", reason)
		}
	})

	t.Run("WriteIsIdempotent", func(t *testing.T) {
		e := newEngine(t)
		u := subject("t/user/u1")
		tuple := engine.Tuple{Object: "t/document/d1", Relation: domain.Viewer, Subject: u.URN}
		mustWrite(t, e, tuple, tuple)
		if ok, _ := check(t, e, u, domain.Viewer, "t/document/d1"); !ok {
			t.Fatal("denied")
		}
	})

	t.Run("Deny", func(t *testing.T) {
		e := newEngine(t)
		if ok, reason := check(t, e, subject("t/user/u1"), domain.Viewer, "t/document/d1"); ok || reason != domain.ReasonNoGrant {
			t.Fatalf("ok=%v reason=%q", ok, reason)
		}
	})

	t.Run("ParentCycleTerminates", func(t *testing.T) {
		e := newEngine(t)
		mustWrite(t, e,
			engine.Tuple{Object: "t/folder/a", Relation: domain.Parent, Subject: "t/folder/b"},
			engine.Tuple{Object: "t/folder/b", Relation: domain.Parent, Subject: "t/folder/a"},
		)
		if ok, _ := check(t, e, subject("t/user/u1"), domain.Viewer, "t/folder/a"); ok {
			t.Fatal("allowed through a cycle")
		}
	})

	t.Run("RejectsUnknownRelation", func(t *testing.T) {
		e := newEngine(t)
		if _, _, err := e.Check(context.Background(), subject("t/user/u1"), domain.Relation("nope"), "t/document/d1"); err == nil {
			t.Fatal("unknown relation accepted")
		}
	})
}
