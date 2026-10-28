package domain

import "fmt"

// SubjectKind is the third URN segment for a subject.
type SubjectKind string

// Subject kinds.
const (
	SubjectUser  SubjectKind = "user"
	SubjectAgent SubjectKind = "agent"
	SubjectGroup SubjectKind = "group"
)

func (k SubjectKind) valid() bool {
	switch k {
	case SubjectUser, SubjectAgent, SubjectGroup:
		return true
	default:
		return false
	}
}

// Subject is a user, agent or group named by a tenant-scoped URN.
type Subject struct {
	URN  URN
	Kind SubjectKind
}

// NewUserSubject builds a user subject.
func NewUserSubject(tenant TenantID, id string) (Subject, error) {
	return newSubject(tenant, SubjectUser, id)
}

// NewGroupSubject builds a group subject.
func NewGroupSubject(tenant TenantID, id string) (Subject, error) {
	return newSubject(tenant, SubjectGroup, id)
}

func newSubject(tenant TenantID, kind SubjectKind, id string) (Subject, error) {
	u, err := NewSubjectURN(tenant, kind, id)
	if err != nil {
		return Subject{}, err
	}
	return Subject{URN: u, Kind: kind}, nil
}

// ParseSubject parses a user, agent or group subject URN.
func ParseSubject(u URN) (Subject, error) {
	if _, err := ParseURN(string(u)); err != nil {
		return Subject{}, fmt.Errorf("%w: %w", ErrInvalidSubject, err)
	}
	kind := SubjectKind(u.Kind())
	if !kind.valid() {
		return Subject{}, fmt.Errorf("%w: %q", ErrInvalidSubject, u)
	}
	return Subject{URN: u, Kind: kind}, nil
}

// Validate checks the subject URN and kind.
func (s Subject) Validate() error {
	if _, err := ParseURN(string(s.URN)); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidSubject, err)
	}
	if !s.Kind.valid() || s.URN.Kind() != string(s.Kind) {
		return fmt.Errorf("%w: %q is not %q", ErrInvalidSubject, s.URN, s.Kind)
	}
	return nil
}

func (s Subject) String() string {
	return string(s.URN)
}
