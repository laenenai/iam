package domain

import (
	"fmt"
	"time"
)

// Node is the read-model value of one registered object.
type Node struct {
	URN       URN
	Tenant    TenantID
	Kind      string
	Parent    URN
	Live      bool
	CreatedAt time.Time
	CreatedBy string
}

// Validate checks the node identity, tenant and parent.
func (n Node) Validate() error {
	u, err := ParseURN(string(n.URN))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidURN, err)
	}
	if u.Tenant() != n.Tenant {
		return fmt.Errorf("%w: tenant %q does not match %q", ErrInvalidURN, u.Tenant(), n.Tenant)
	}
	if n.Kind == "" || u.Kind() != n.Kind {
		return fmt.Errorf("%w: kind %q does not match urn %q", ErrInvalidURN, n.Kind, n.URN)
	}
	if n.Parent != "" {
		parent, err := ParseURN(string(n.Parent))
		if err != nil {
			return fmt.Errorf("%w: parent: %w", ErrInvalidURN, err)
		}
		if parent.Tenant() != n.Tenant {
			return fmt.Errorf("%w: parent tenant mismatch", ErrInvalidURN)
		}
	}
	if n.CreatedBy == "" {
		return fmt.Errorf("%w: missing created_by", ErrInvalidURN)
	}
	return nil
}
