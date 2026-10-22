package domain

import (
	"fmt"
	"strings"
	"time"
)

// maxReasonLen bounds a MandatoryAct's reason. The reason is recorded in
// the membership trail and read by a human reviewing why a gate was
// opened, so it is required to be short enough to read and long enough to
// name a matter or a ticket.
const maxReasonLen = 512

// MandatoryChannel names the only two ways a clearance group's membership
// may change (design §8.3). There is deliberately no third, and in
// particular there is no channel reachable from a sharing operation: if
// there were, anyone able to add a member to a group could open a
// mandatory gate through a discretionary act, and anti-goal A3 would be
// breached by construction rather than by a bug.
type MandatoryChannel string

const (
	// MandatoryChannelClassify is an act performed under the classify
	// permission: a security function deciding that this principal
	// satisfies this compartment. It is strictly more dangerous than the
	// power to grant, because a clearance cannot be granted away or
	// transferred with ownership.
	MandatoryChannelClassify MandatoryChannel = "classify-permission"
	// MandatoryChannelDirectorySync is an authoritative directory sync:
	// employment, bar admission, household membership — a fact the
	// deployment treats as authoritative rather than a discretionary
	// share. It is what makes `all-timekeepers` maintainable, and why
	// "everyone except Bob" is a clearance group that does not contain
	// Bob rather than 1,999 individual grants (design §8.3).
	MandatoryChannelDirectorySync MandatoryChannel = "directory-sync"
)

// Valid reports whether c is one of the two mandatory channels.
func (c MandatoryChannel) Valid() bool {
	switch c {
	case MandatoryChannelClassify, MandatoryChannelDirectorySync:
		return true
	default:
		return false
	}
}

// MandatoryAct witnesses that a clearance-group membership change arrived
// through a mandatory channel, and carries the trail design §8.3 requires
// such a change to leave: which channel, which actor, why, and when.
//
// Its fields are unexported and its only constructor validates, so a
// caller cannot assemble one from a struct literal or zero value. That is
// what makes the mandatory channel a type-system fact rather than a
// convention: every clearance-group write on the Registry port demands a
// MandatoryAct, and the only way to obtain one is to say, on the record,
// which authoritative channel the change came through. In particular,
// nothing on the JIT provisioning path can produce one — Claims carry no
// actor and no channel — so design §8.3's "a newly provisioned principal
// holds no clearances" is not a rule the provisioner must remember to
// obey, it is a sentence the provisioner cannot write.
type MandatoryAct struct {
	channel MandatoryChannel
	actor   PrincipalID
	reason  string
	at      time.Time
}

// NewMandatoryAct returns the witness for one mandatory change. channel
// must be a known MandatoryChannel, actor must name the principal
// performing the act (a security admin, or the service principal running
// the directory sync), reason must be non-empty, and at must be set.
//
// reason is required rather than optional because an unexplained change to
// a mandatory control is indistinguishable, after the fact, from a
// mistake; a trail of empty reasons is not an audit trail.
func NewMandatoryAct(channel MandatoryChannel, actor PrincipalID, reason string, at time.Time) (MandatoryAct, error) {
	if !channel.Valid() {
		return MandatoryAct{}, fmt.Errorf("%w: unknown channel %q", ErrMandatoryChannelRequired, channel)
	}
	if actor == "" {
		return MandatoryAct{}, fmt.Errorf("%w: the act must name its actor", ErrMandatoryChannelRequired)
	}
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" || len(trimmed) > maxReasonLen {
		return MandatoryAct{}, fmt.Errorf("%w: the act must carry a reason of 1..%d characters", ErrMandatoryChannelRequired, maxReasonLen)
	}
	if at.IsZero() {
		return MandatoryAct{}, fmt.Errorf("%w: the act must carry the instant it happened", ErrMandatoryChannelRequired)
	}
	return MandatoryAct{channel: channel, actor: actor, reason: trimmed, at: at}, nil
}

// Channel returns the mandatory channel the act came through.
func (a MandatoryAct) Channel() MandatoryChannel { return a.channel }

// Actor returns the principal that performed the act.
func (a MandatoryAct) Actor() PrincipalID { return a.actor }

// Reason returns the recorded reason for the act.
func (a MandatoryAct) Reason() string { return a.reason }

// At returns the instant the act happened.
func (a MandatoryAct) At() time.Time { return a.at }

// IsZero reports whether a is the zero MandatoryAct — the value a caller
// gets from `var act domain.MandatoryAct`, which witnesses nothing. Every
// clearance-group write rejects it with ErrMandatoryChannelRequired.
func (a MandatoryAct) IsZero() bool { return a == MandatoryAct{} }

// ClearanceGroup is a *mandatory* object: a set of principals that a
// classification's gate may be satisfied by, whose membership moves only
// through the channel it names, and which can never be referenced in a
// tier-1 tuple (design §8.3).
//
// It is not a Group with a flag set. A tier-1 group may not hold a
// clearance at all, because membership of a tier-1 group is discretionary,
// and a mandatory control that a discretionary operation can open is not a
// mandatory control. This module enforces the separation three times over,
// deliberately, because it is anti-goal A3 rather than tidiness:
//
//  1. In the type system: ClearanceGroupID is unconvertible to or from
//     GroupID (see its doc comment), so the mistake cannot be written.
//  2. In the port: every clearance write demands a MandatoryAct, which no
//     discretionary path can construct.
//  3. In the schema: clearance groups and their membership are separate
//     tables with separate foreign keys, so a group id cannot be stored
//     as a clearance group id even by a hand-written statement.
//
// What a clearance group *holds* — the classification labels it satisfies
// — is tier-2 state owned by the classification store, not by this
// registry. This increment deliberately stops at membership: the registry
// answers "which clearance groups is this principal in", and a newly
// provisioned principal is in none.
type ClearanceGroup struct {
	// ID is the clearance group's stable internal id.
	ID ClearanceGroupID
	// TenantID scopes the clearance group.
	TenantID TenantID
	// Name is the clearance group's name within its tenant, unique there
	// — `conflict-screen-acme`, `all-timekeepers`, `household-pascal`.
	Name string
	// Channel is the authoritative channel for this group's membership,
	// fixed at creation. A change arriving through the other channel is
	// refused with ErrChannelMismatch, so a directory-synced group cannot
	// be quietly diverged from the directory that owns it.
	Channel MandatoryChannel
	// CreatedAt is when the registry first recorded this clearance group.
	CreatedAt time.Time
}

// ClearanceChangeKind names what a recorded membership change did.
type ClearanceChangeKind string

const (
	// ClearanceChangeAdded records a principal joining a clearance group.
	ClearanceChangeAdded ClearanceChangeKind = "added"
	// ClearanceChangeRemoved records a principal leaving one.
	ClearanceChangeRemoved ClearanceChangeKind = "removed"
	// ClearanceChangeCreated records the clearance group's creation. It
	// is in the same trail as its memberships because "who decided this
	// compartment should exist, and why" is the same question as "who
	// decided this principal belongs in it".
	ClearanceChangeCreated ClearanceChangeKind = "created"
)

// ClearanceChange is one entry in a clearance group's append-only
// membership trail. Design §8.3 requires clearance membership to be
// audited; the `audit` module owns audit *storage*, so what lives here is
// the registry's own authoritative record of its own writes — the thing an
// audit sink mirrors, not a substitute for it.
//
// The trail is append-only: a removal appends a ClearanceChangeRemoved
// entry rather than deleting the add, because a mandatory control whose
// history can be edited is not evidence of anything.
type ClearanceChange struct {
	// ID identifies this entry; entries sort by it in recorded order.
	ID ChangeID
	// ClearanceGroupID names the clearance group the change applied to.
	ClearanceGroupID ClearanceGroupID
	// PrincipalID names the principal added or removed. It is empty for
	// ClearanceChangeCreated.
	PrincipalID PrincipalID
	// Kind is what the change did.
	Kind ClearanceChangeKind
	// Channel, Actor, Reason and ActedAt are the witnessing
	// MandatoryAct's fields, flattened for storage.
	Channel MandatoryChannel
	Actor   PrincipalID
	Reason  string
	ActedAt time.Time
	// RecordedAt is when the registry wrote the entry, which may differ
	// from ActedAt if a sync replays an earlier decision.
	RecordedAt time.Time
}
