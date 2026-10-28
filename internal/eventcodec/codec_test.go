package eventcodec

import (
	"errors"
	"reflect"
	"testing"

	"github.com/laenenai/es-lite/es"

	"github.com/laenenai/iam/internal/domain"
)

func TestCodecRoundTripsEveryEvent(t *testing.T) {
	user := domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}
	group := domain.Subject{URN: "t/group/g1", Kind: domain.SubjectGroup}
	admin := domain.Subject{URN: "t/user/admin", Kind: domain.SubjectUser}
	events := []domain.Event{
		domain.NodeRegistered{URN: "t/document/d1", Kind: "document", Parent: "t/folder/f1", CreatedBy: "actor"},
		domain.NodeDeleted{URN: "t/document/d1", Reason: "gone"},
		domain.GrantIssued{GrantID: "01H", Object: "t/document/d1", Subject: user, Relation: domain.Viewer, GrantedBy: "owner", Reason: "share"},
		domain.GrantRevoked{GrantID: "01H", Object: "t/document/d1", RevokedBy: "owner", Reason: "unshare"},
		domain.GroupCreated{Group: "t/group/g1", Name: "Family", Admin: admin, CreatedBy: "actor"},
		domain.GroupAdminChanged{Group: "t/group/g1", Admin: admin, ChangedBy: "actor"},
		domain.MemberAdded{Group: "t/group/g1", Member: user, AddedBy: "actor"},
		domain.MemberRemoved{Group: "t/group/g1", Member: user, RemovedBy: "actor"},
		domain.GroupDeleted{Group: "t/group/g1", Reason: "gone"},
		domain.PrincipalLinked{Issuer: "issuer", ExternalID: "external-1", Subject: user},
		domain.PrincipalDeactivated{Subject: user, Source: domain.SourceGlobal, Reason: "left"},
		domain.PrincipalReactivated{Subject: group, Source: domain.SourceTenant, Reason: "back"},
		domain.PrincipalDeleted{Subject: user, Reason: "offboard"},
		domain.KindRegistered{Version: 2, Kind: domain.KindSpec{Name: "graph", Contains: []string{"node"}, Relations: []domain.Relation{domain.Owner, domain.Editor, domain.Commenter, domain.Viewer}}},
		domain.ModelPublished{Version: 2},
	}

	for _, want := range events {
		t.Run(want.EventType(), func(t *testing.T) {
			encoded, err := (Codec{}).Encode(want)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			got, err := (Codec{}).Decode(encoded)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("round trip:\n got %#v\nwant %#v", got, want)
			}
		})
	}
}

func TestCodecRejectsUnknownTypeURL(t *testing.T) {
	_, err := (Codec{}).Decode(es.EncodedEvent{TypeURL: "iam.v1.DoesNotExist"})
	if !errors.Is(err, domain.ErrUnknownEvent) {
		t.Fatalf("err = %v, want ErrUnknownEvent", err)
	}
}

func TestStreamIDMapping(t *testing.T) {
	tests := []struct {
		name  string
		event domain.Event
		want  es.StreamID
	}{
		{
			name:  "node",
			event: domain.NodeRegistered{URN: "t/document/d1"},
			want:  es.StreamID{Type: "node", ID: "document_d1"},
		},
		{
			name:  "acl",
			event: domain.GrantIssued{Object: "t/document/d1"},
			want:  es.StreamID{Type: "acl", ID: "document_d1"},
		},
		{
			name:  "group",
			event: domain.GroupCreated{Group: "t/group/g1"},
			want:  es.StreamID{Type: "group", ID: "g1"},
		},
		{
			name:  "principal",
			event: domain.PrincipalLinked{Subject: domain.Subject{URN: "t/user/u1", Kind: domain.SubjectUser}},
			want:  es.StreamID{Type: "principal", ID: "user_u1"},
		},
		{
			name:  "model",
			event: domain.KindRegistered{Version: 2},
			want:  es.StreamID{Type: "model", ID: "2"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := StreamID(tt.event)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("StreamID = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestStreamIDRejectsEmptyOrInvalidEvent(t *testing.T) {
	if _, err := StreamID(nil); err == nil {
		t.Fatal("nil event accepted")
	}
	if _, err := StreamID(domain.NodeRegistered{}); err == nil {
		t.Fatal("empty node stream accepted")
	}
}
