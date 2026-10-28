package domain

import (
	"fmt"
	"time"
)

// Principal is IAM's projection of an identity-provider user or agent machine
// user. It stores liveness and the stable URN, never credentials or PII.
type Principal struct {
	URN        URN
	Tenant     TenantID
	Issuer     string
	ExternalID string
	Kind       SubjectKind
	GlobalLive bool
	TenantLive bool
	Live       bool
	Deleted    bool
	LinkedAt   time.Time
}

func (p Principal) EffectiveLive() bool {
	return p.GlobalLive && p.TenantLive && !p.Deleted
}

func (p Principal) Validate() error {
	u, err := ParseURN(string(p.URN))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidSubject, err)
	}
	if u.Tenant() != p.Tenant {
		return fmt.Errorf("%w: principal tenant mismatch", ErrInvalidSubject)
	}
	if !p.Kind.valid() || u.Kind() != string(p.Kind) {
		return fmt.Errorf("%w: principal kind does not match urn", ErrInvalidSubject)
	}
	if p.Kind == SubjectGroup {
		return fmt.Errorf("%w: groups are not principals", ErrInvalidSubject)
	}
	if p.Issuer == "" || p.ExternalID == "" {
		return fmt.Errorf("%w: missing external identity", ErrInvalidSubject)
	}
	if p.Live != p.EffectiveLive() {
		return fmt.Errorf("%w: live must equal global_live AND tenant_live AND NOT deleted", ErrInvalidSubject)
	}
	return nil
}
