package domain

import (
	"errors"
	"fmt"
)

// Kind classifies domain errors so adapters (HTTP, CLI) can map them.
type Kind string

const (
	KindNotFound     Kind = "not_found"
	KindConflict     Kind = "conflict"
	KindValidation   Kind = "validation"
	KindUnauthorized Kind = "unauthorized"
	KindForbidden    Kind = "forbidden"
	KindGone         Kind = "gone"
	KindUnavailable  Kind = "unavailable"
)

// Error is the single error type returned by the core.
type Error struct {
	Kind    Kind
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

// Is lets errors.Is(err, domain.ErrNotFound) match on Kind.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Message == "" && t.Kind == e.Kind
}

var (
	ErrNotFound     = &Error{Kind: KindNotFound}
	ErrConflict     = &Error{Kind: KindConflict}
	ErrValidation   = &Error{Kind: KindValidation}
	ErrUnauthorized = &Error{Kind: KindUnauthorized}
	ErrForbidden    = &Error{Kind: KindForbidden}
	ErrGone         = &Error{Kind: KindGone}
)

func NotFound(format string, a ...any) error {
	return &Error{Kind: KindNotFound, Message: fmt.Sprintf(format, a...)}
}
func Conflict(format string, a ...any) error {
	return &Error{Kind: KindConflict, Message: fmt.Sprintf(format, a...)}
}
func Invalid(format string, a ...any) error {
	return &Error{Kind: KindValidation, Message: fmt.Sprintf(format, a...)}
}
func Unauthorized(format string, a ...any) error {
	return &Error{Kind: KindUnauthorized, Message: fmt.Sprintf(format, a...)}
}
func Forbidden(format string, a ...any) error {
	return &Error{Kind: KindForbidden, Message: fmt.Sprintf(format, a...)}
}
func Gone(format string, a ...any) error {
	return &Error{Kind: KindGone, Message: fmt.Sprintf(format, a...)}
}
func Unavailable(err error, format string, a ...any) error {
	return &Error{Kind: KindUnavailable, Message: fmt.Sprintf(format, a...), Err: err}
}

// KindOf returns the Kind of err, or "" if it is not a domain error.
func KindOf(err error) Kind {
	var de *Error
	if errors.As(err, &de) {
		return de.Kind
	}
	return ""
}
