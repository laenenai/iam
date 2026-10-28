// Package eventcodec maps IAM domain events to their generated protobuf
// representation and back.
package eventcodec

import (
	"errors"
	"fmt"

	"github.com/laenenai/es-lite/es"

	iamv1 "github.com/laenenai/iam/gen/iam/v1"
	"github.com/laenenai/iam/internal/domain"
)

// Codec implements es.Codec for domain events.
type Codec struct{}

var _ es.Codec[domain.Event] = Codec{}

// Encode marshals a domain event as its generated protobuf message.
func (Codec) Encode(event domain.Event) (es.EncodedEvent, error) {
	msg, err := toProto(event)
	if err != nil {
		return es.EncodedEvent{}, err
	}
	return (iamv1.EventCodec{}).Encode(msg)
}

// Decode unmarshals a protobuf event into its domain representation.
func (Codec) Decode(encoded es.EncodedEvent) (domain.Event, error) {
	msg, err := (iamv1.EventCodec{}).Decode(encoded)
	if err != nil {
		if errors.Is(err, es.ErrUnknownEventType) {
			return nil, fmt.Errorf("%w: %q", domain.ErrUnknownEvent, encoded.TypeURL)
		}
		return nil, err
	}
	return fromProto(msg)
}

// StreamID returns the canonical es-lite stream for an event.
func StreamID(event domain.Event) (es.StreamID, error) {
	if event == nil {
		return es.StreamID{}, fmt.Errorf("%w: nil event", domain.ErrUnknownEvent)
	}
	stream, err := es.ParseCanonical(event.Stream())
	if err != nil {
		return es.StreamID{}, fmt.Errorf("%w: %w", domain.ErrInvalidURN, err)
	}
	return stream, nil
}

func toProto(event domain.Event) (iamv1.Event, error) {
	switch e := event.(type) {
	case domain.NodeRegistered:
		return &iamv1.NodeRegistered{
			Urn:       string(e.URN),
			Kind:      e.Kind,
			ParentUrn: string(e.Parent),
			CreatedBy: e.CreatedBy,
		}, nil

	case domain.NodeDeleted:
		return &iamv1.NodeDeleted{Urn: string(e.URN), Reason: e.Reason}, nil

	case domain.GrantIssued:
		return &iamv1.GrantIssued{
			GrantId:     string(e.GrantID),
			ObjectUrn:   string(e.Object),
			SubjectUrn:  string(e.Subject.URN),
			SubjectKind: string(e.Subject.Kind),
			Relation:    string(e.Relation),
			GrantedBy:   e.GrantedBy,
			Reason:      e.Reason,
		}, nil

	case domain.GrantRevoked:
		return &iamv1.GrantRevoked{
			GrantId:   string(e.GrantID),
			ObjectUrn: string(e.Object),
			RevokedBy: e.RevokedBy,
			Reason:    e.Reason,
		}, nil

	case domain.GroupCreated:
		return &iamv1.GroupCreated{
			GroupUrn:  string(e.Group),
			Name:      e.Name,
			AdminUrn:  string(e.Admin.URN),
			AdminKind: string(e.Admin.Kind),
			CreatedBy: e.CreatedBy,
		}, nil

	case domain.GroupAdminChanged:
		return &iamv1.GroupAdminChanged{
			GroupUrn:  string(e.Group),
			AdminUrn:  string(e.Admin.URN),
			AdminKind: string(e.Admin.Kind),
			ChangedBy: e.ChangedBy,
		}, nil

	case domain.MemberAdded:
		return &iamv1.MemberAdded{
			GroupUrn:   string(e.Group),
			MemberUrn:  string(e.Member.URN),
			MemberKind: string(e.Member.Kind),
			AddedBy:    e.AddedBy,
		}, nil

	case domain.MemberRemoved:
		return &iamv1.MemberRemoved{
			GroupUrn:   string(e.Group),
			MemberUrn:  string(e.Member.URN),
			MemberKind: string(e.Member.Kind),
			RemovedBy:  e.RemovedBy,
		}, nil

	case domain.GroupDeleted:
		return &iamv1.GroupDeleted{GroupUrn: string(e.Group), Reason: e.Reason}, nil

	case domain.PrincipalLinked:
		return &iamv1.PrincipalLinked{
			Issuer:      e.Issuer,
			ExternalId:  e.ExternalID,
			SubjectUrn:  string(e.Subject.URN),
			SubjectKind: string(e.Subject.Kind),
		}, nil

	case domain.PrincipalDeactivated:
		return &iamv1.PrincipalDeactivated{
			SubjectUrn:  string(e.Subject.URN),
			SubjectKind: string(e.Subject.Kind),
			Source:      string(e.Source),
			Reason:      e.Reason,
		}, nil

	case domain.PrincipalReactivated:
		return &iamv1.PrincipalReactivated{
			SubjectUrn:  string(e.Subject.URN),
			SubjectKind: string(e.Subject.Kind),
			Source:      string(e.Source),
			Reason:      e.Reason,
		}, nil

	case domain.PrincipalDeleted:
		return &iamv1.PrincipalDeleted{
			SubjectUrn:  string(e.Subject.URN),
			SubjectKind: string(e.Subject.Kind),
			Reason:      e.Reason,
		}, nil

	case domain.KindRegistered:
		version, err := encodeVersion(e.Version)
		if err != nil {
			return nil, err
		}
		return &iamv1.KindRegistered{Version: version, Kind: kindToProto(e.Kind)}, nil

	case domain.ModelPublished:
		version, err := encodeVersion(e.Version)
		if err != nil {
			return nil, err
		}
		return &iamv1.ModelPublished{Version: version}, nil

	default:
		return nil, fmt.Errorf("%w: %T", domain.ErrUnknownEvent, event)
	}
}

func fromProto(event iamv1.Event) (domain.Event, error) {
	switch e := event.(type) {
	case *iamv1.NodeRegistered:
		return domain.NodeRegistered{
			URN:       domain.URN(e.GetUrn()),
			Kind:      e.GetKind(),
			Parent:    domain.URN(e.GetParentUrn()),
			CreatedBy: e.GetCreatedBy(),
		}, nil

	case *iamv1.NodeDeleted:
		return domain.NodeDeleted{URN: domain.URN(e.GetUrn()), Reason: e.GetReason()}, nil

	case *iamv1.GrantIssued:
		return domain.GrantIssued{
			GrantID:   domain.GrantID(e.GetGrantId()),
			Object:    domain.URN(e.GetObjectUrn()),
			Subject:   subject(e.GetSubjectUrn(), e.GetSubjectKind()),
			Relation:  domain.Relation(e.GetRelation()),
			GrantedBy: e.GetGrantedBy(),
			Reason:    e.GetReason(),
		}, nil

	case *iamv1.GrantRevoked:
		return domain.GrantRevoked{
			GrantID:   domain.GrantID(e.GetGrantId()),
			Object:    domain.URN(e.GetObjectUrn()),
			RevokedBy: e.GetRevokedBy(),
			Reason:    e.GetReason(),
		}, nil

	case *iamv1.GroupCreated:
		return domain.GroupCreated{
			Group:     domain.URN(e.GetGroupUrn()),
			Name:      e.GetName(),
			Admin:     subject(e.GetAdminUrn(), e.GetAdminKind()),
			CreatedBy: e.GetCreatedBy(),
		}, nil

	case *iamv1.GroupAdminChanged:
		return domain.GroupAdminChanged{
			Group:     domain.URN(e.GetGroupUrn()),
			Admin:     subject(e.GetAdminUrn(), e.GetAdminKind()),
			ChangedBy: e.GetChangedBy(),
		}, nil

	case *iamv1.MemberAdded:
		return domain.MemberAdded{
			Group:   domain.URN(e.GetGroupUrn()),
			Member:  subject(e.GetMemberUrn(), e.GetMemberKind()),
			AddedBy: e.GetAddedBy(),
		}, nil

	case *iamv1.MemberRemoved:
		return domain.MemberRemoved{
			Group:     domain.URN(e.GetGroupUrn()),
			Member:    subject(e.GetMemberUrn(), e.GetMemberKind()),
			RemovedBy: e.GetRemovedBy(),
		}, nil

	case *iamv1.GroupDeleted:
		return domain.GroupDeleted{Group: domain.URN(e.GetGroupUrn()), Reason: e.GetReason()}, nil

	case *iamv1.PrincipalLinked:
		return domain.PrincipalLinked{
			Issuer:     e.GetIssuer(),
			ExternalID: e.GetExternalId(),
			Subject:    subject(e.GetSubjectUrn(), e.GetSubjectKind()),
		}, nil

	case *iamv1.PrincipalDeactivated:
		return domain.PrincipalDeactivated{
			Subject: subject(e.GetSubjectUrn(), e.GetSubjectKind()),
			Source:  domain.DeactivationSource(e.GetSource()),
			Reason:  e.GetReason(),
		}, nil

	case *iamv1.PrincipalReactivated:
		return domain.PrincipalReactivated{
			Subject: subject(e.GetSubjectUrn(), e.GetSubjectKind()),
			Source:  domain.DeactivationSource(e.GetSource()),
			Reason:  e.GetReason(),
		}, nil

	case *iamv1.PrincipalDeleted:
		return domain.PrincipalDeleted{
			Subject: subject(e.GetSubjectUrn(), e.GetSubjectKind()),
			Reason:  e.GetReason(),
		}, nil

	case *iamv1.KindRegistered:
		return domain.KindRegistered{Version: int(e.GetVersion()), Kind: kindFromProto(e.GetKind())}, nil

	case *iamv1.ModelPublished:
		return domain.ModelPublished{Version: int(e.GetVersion())}, nil

	default:
		return nil, fmt.Errorf("%w: %T", domain.ErrUnknownEvent, event)
	}
}

const maxVersion = 1<<31 - 1

func encodeVersion(version int) (int32, error) {
	if version < 0 || version > maxVersion {
		return 0, fmt.Errorf("%w: version %d", domain.ErrInvalidKind, version)
	}
	return int32(version), nil //nolint:gosec // bounded above.
}

func subject(urn, kind string) domain.Subject {
	return domain.Subject{URN: domain.URN(urn), Kind: domain.SubjectKind(kind)}
}

func kindToProto(kind domain.KindSpec) *iamv1.KindSpec {
	relations := make([]string, len(kind.Relations))
	for i, relation := range kind.Relations {
		relations[i] = string(relation)
	}
	return &iamv1.KindSpec{
		Name:        kind.Name,
		Contains:    append([]string(nil), kind.Contains...),
		Relations:   relations,
		ContainsAny: kind.ContainsAny,
	}
}

func kindFromProto(kind *iamv1.KindSpec) domain.KindSpec {
	if kind == nil {
		return domain.KindSpec{}
	}
	relations := make([]domain.Relation, len(kind.GetRelations()))
	for i, relation := range kind.GetRelations() {
		relations[i] = domain.Relation(relation)
	}
	return domain.KindSpec{
		Name:        kind.GetName(),
		Contains:    append([]string(nil), kind.GetContains()...),
		Relations:   relations,
		ContainsAny: kind.GetContainsAny(),
	}
}
