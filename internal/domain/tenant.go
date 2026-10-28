package domain

import (
	"fmt"
	"regexp"
)

// TenantID names an isolation boundary. It is a lower-case slug.
type TenantID string

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,127}$`)

func validSlug(s string) bool {
	return slugRE.MatchString(s)
}

// ParseTenantID validates a tenant slug.
func ParseTenantID(s string) (TenantID, error) {
	if !validSlug(s) {
		return "", fmt.Errorf("%w: %q", ErrInvalidTenant, s)
	}
	return TenantID(s), nil
}

func (t TenantID) String() string {
	return string(t)
}
