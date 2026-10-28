package domain

import (
	"fmt"
	"strings"
)

// URN is the stable identity of a node or subject: <tenant>/<kind>/<id>.
type URN string

// ParseURN validates a three-segment IAM URN.
func ParseURN(s string) (URN, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", fmt.Errorf("%w: %q", ErrInvalidURN, s)
	}
	if _, err := ParseTenantID(parts[0]); err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidURN, s)
	}
	if !validSlug(parts[1]) || !validSlug(parts[2]) {
		return "", fmt.Errorf("%w: %q", ErrInvalidURN, s)
	}
	return URN(s), nil
}

// NewNodeURN builds and validates a node URN.
func NewNodeURN(tenant TenantID, kind, id string) (URN, error) {
	if _, err := ParseTenantID(string(tenant)); err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidURN, err)
	}
	if !validSlug(kind) || !validSlug(id) {
		return "", fmt.Errorf("%w: %s/%s/%s", ErrInvalidURN, tenant, kind, id)
	}
	return ParseURN(string(tenant) + "/" + kind + "/" + id)
}

// NewSubjectURN builds and validates a subject URN.
func NewSubjectURN(tenant TenantID, kind SubjectKind, id string) (URN, error) {
	if !kind.valid() {
		return "", fmt.Errorf("%w: %q", ErrInvalidSubject, kind)
	}
	u, err := NewNodeURN(tenant, string(kind), id)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrInvalidSubject, err)
	}
	return u, nil
}

// Tenant returns the first URN segment.
func (u URN) Tenant() TenantID {
	parts := strings.Split(string(u), "/")
	if len(parts) != 3 {
		return ""
	}
	return TenantID(parts[0])
}

// Kind returns the second URN segment.
func (u URN) Kind() string {
	parts := strings.Split(string(u), "/")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}

// ID returns the third URN segment.
func (u URN) ID() string {
	parts := strings.Split(string(u), "/")
	if len(parts) != 3 {
		return ""
	}
	return parts[2]
}

func (u URN) String() string {
	return string(u)
}
