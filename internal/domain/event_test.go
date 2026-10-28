package domain

import "testing"

func TestEventStreams(t *testing.T) {
	if got := (NodeRegistered{URN: "t/folder/f1", Kind: "folder"}).Stream(); got != "node:folder_f1" {
		t.Fatal(got)
	}
	if got := (GrantIssued{Object: "t/document/d1"}).Stream(); got != "acl:document_d1" {
		t.Fatal(got)
	}
	if got := (GroupCreated{Group: "t/group/g1"}).Stream(); got != "group:g1" {
		t.Fatal(got)
	}
	if got := (PrincipalLinked{Subject: Subject{URN: "t/user/u1", Kind: SubjectUser}}).Stream(); got != "principal:user_u1" {
		t.Fatal(got)
	}
	if got := (ModelPublished{Version: 3}).Stream(); got != "model:3" {
		t.Fatal(got)
	}
}

func TestEventTypes(t *testing.T) {
	events := []struct {
		event Event
		want  string
	}{
		{NodeRegistered{}, "node.registered"},
		{NodeDeleted{}, "node.deleted"},
		{GrantIssued{}, "grant.issued"},
		{GrantRevoked{}, "grant.revoked"},
		{GroupCreated{}, "group.created"},
		{GroupAdminChanged{}, "group.admin_changed"},
		{MemberAdded{}, "member.added"},
		{MemberRemoved{}, "member.removed"},
		{GroupDeleted{}, "group.deleted"},
		{PrincipalLinked{}, "principal.linked"},
		{PrincipalDeactivated{}, "principal.deactivated"},
		{PrincipalReactivated{}, "principal.reactivated"},
		{PrincipalDeleted{}, "principal.deleted"},
		{KindRegistered{}, "kind.registered"},
		{ModelPublished{}, "model.published"},
	}
	for _, tc := range events {
		if got := tc.event.EventType(); got != tc.want {
			t.Fatalf("%T: got %q want %q", tc.event, got, tc.want)
		}
	}
}
