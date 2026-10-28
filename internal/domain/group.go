package domain

import (
	"fmt"
	"time"
)

// Group is a flat, human-only membership set.
type Group struct {
	URN       URN
	Tenant    TenantID
	Name      string
	Admin     Subject
	Live      bool
	CreatedAt time.Time
}

// Validate checks the group identity and admin.
func (g Group) Validate() error {
	u, err := ParseURN(string(g.URN))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURN, err)
	}
	if u.Tenant() != g.Tenant {
		return fmt.Errorf("%w: group tenant mismatch", ErrInvalidURN)
	}
	if u.Kind() != string(SubjectGroup) {
		return fmt.Errorf("%w: group urn must have kind %q", ErrInvalidURN, SubjectGroup)
	}
	if err := g.Admin.Validate(); err != nil {
		return err
	}
	if g.Admin.Kind != SubjectUser {
		return fmt.Errorf("%w: group admin must be a user", ErrInvalidSubject)
	}
	if g.Admin.URN.Tenant() != g.Tenant {
		return fmt.Errorf("%w: group admin tenant mismatch", ErrInvalidSubject)
	}
	if g.Name == "" {
		return fmt.Errorf("%w: missing group name", ErrInvalidURN)
	}
	return nil
}
