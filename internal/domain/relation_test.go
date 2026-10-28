package domain

import "testing"

func TestRelationRanks(t *testing.T) {
	if Viewer.Rank() != 1 || Commenter.Rank() != 2 || Editor.Rank() != 3 || Owner.Rank() != 4 {
		t.Fatal("rank ladder")
	}
	if CanDelete.Rank() != 0 || !CanDelete.IsGrantable() {
		t.Fatal("can_delete is global and grantable")
	}
	if CanShare.IsGrantable() {
		t.Fatal("can_share is computed")
	}
}

func TestRelationClassification(t *testing.T) {
	for _, r := range []Relation{Owner, Editor, Commenter, Viewer} {
		if !r.IsBase() || !r.IsGrantable() || r.Rank() == 0 {
			t.Fatalf("%s: base=%v grantable=%v rank=%d", r, r.IsBase(), r.IsGrantable(), r.Rank())
		}
	}
	for _, r := range []Relation{Parent, CanShare, CanView, CanEdit, CanComment, Member, Admin} {
		if r.IsBase() || r.IsGrantable() {
			t.Fatalf("%s must be neither base nor grantable", r)
		}
	}
}
