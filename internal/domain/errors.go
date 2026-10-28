package domain

import "errors"

var (
	ErrInvalidTenant     = errors.New("iam: invalid tenant")
	ErrInvalidURN        = errors.New("iam: invalid urn")
	ErrInvalidSubject    = errors.New("iam: invalid subject")
	ErrInvalidRelation   = errors.New("iam: invalid relation")
	ErrInvalidKind       = errors.New("iam: invalid kind")
	ErrInvalidActor      = errors.New("iam: invalid actor")
	ErrNotFound          = errors.New("iam: not found")
	ErrConflict          = errors.New("iam: conflict")
	ErrForbidden         = errors.New("iam: forbidden")
	ErrUnauthorized      = errors.New("iam: unauthorized")
	ErrStale             = errors.New("iam: stale")
	ErrModelNotProjected = errors.New("iam: model not projected")
	ErrUnknownEvent      = errors.New("iam: unknown event")
	ErrUnsupported       = errors.New("iam: unsupported")
	ErrIDGeneration      = errors.New("iam: id generation failed")
)
