package domain

// Reason explains how a decision was reached.
type Reason string

const (
	ReasonNoGrant   Reason = "no_grant"
	ReasonDirect    Reason = "direct"
	ReasonUserset   Reason = "userset"
	ReasonInherited Reason = "inherited"
)
