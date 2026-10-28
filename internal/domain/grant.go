package domain

import (
	"fmt"
	"time"
)

// Grant is the read-model value of one issued grant.
type Grant struct {
	ID        GrantID
	Tenant    TenantID
	Object    URN
	Subject   Subject
	Relation  Relation
	GrantedBy string
	GrantedAt time.Time
	Live      bool
}

func (g Grant) Validate() error {
	if g.ID == "" {
		return fmt.Errorf("%w: missing grant id", ErrInvalidRelation)
	}
	object, err := ParseURN(string(g.Object))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURN, err)
	}
	if object.Tenant() != g.Tenant {
		return fmt.Errorf("%w: object tenant does not match grant tenant", ErrInvalidURN)
	}
	if err := g.Subject.Validate(); err != nil {
		return err
	}
	if g.Subject.URN.Tenant() != g.Tenant {
		return fmt.Errorf("%w: subject tenant does not match grant tenant", ErrInvalidSubject)
	}
	if !g.Relation.IsGrantable() {
		return fmt.Errorf("%w: %q is not grantable", ErrInvalidRelation, g.Relation)
	}
	if g.GrantedBy == "" {
		return fmt.Errorf("%w: missing granted_by", ErrInvalidRelation)
	}
	return nil
}
