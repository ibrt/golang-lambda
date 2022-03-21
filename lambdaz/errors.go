package lambdaz

import (
	"net/http"

	"github.com/ibrt/golang-errors/errorz"
)

// Known error IDs.
const (
	ErrIDBadRequest   = errorz.ID("bad-request")
	ErrIDUnauthorized = errorz.ID("unauthorized")
	ErrIDForbidden    = errorz.ID("forbidden")
)

// NewErrBadRequest creates a new bad request error.
func NewErrBadRequest(format string, options ...errorz.Option) error {
	return errorz.Errorf(format, append(options,
		ErrIDBadRequest,
		errorz.Status(http.StatusBadRequest),
		errorz.Prefix("bad request"),
		errorz.Skip())...)
}

// WrapErrBadRequest wraps an error as bad request error.
func WrapErrBadRequest(err error, options ...errorz.Option) error {
	if errorz.GetID(err) == ErrIDBadRequest {
		return errorz.Wrap(err, options...)
	}

	if errorz.GetID(err) == "" {
		options = append(options, ErrIDBadRequest)
	}

	return errorz.Wrap(err, append(options,
		errorz.Status(http.StatusBadRequest),
		errorz.Prefix("bad request"),
		errorz.Skip())...)
}

// NewErrUnauthorized creates a new unauthorized error.
func NewErrUnauthorized(format string, options ...errorz.Option) error {
	return errorz.Errorf(format, append(options,
		ErrIDUnauthorized,
		errorz.Status(http.StatusUnauthorized),
		errorz.Prefix("unauthorized"),
		errorz.Skip())...)
}

// WrapErrUnauthorized wraps an error as unauthorized error.
func WrapErrUnauthorized(err error, options ...errorz.Option) error {
	if errorz.GetID(err) == ErrIDUnauthorized {
		return errorz.Wrap(err, options...)
	}

	if errorz.GetID(err) == "" {
		options = append(options, ErrIDUnauthorized)
	}

	return errorz.Wrap(err, append(options,
		errorz.Status(http.StatusUnauthorized),
		errorz.Prefix("unauthorized"),
		errorz.Skip())...)
}

// NewErrForbidden creates a new forbidden error.
func NewErrForbidden(format string, options ...errorz.Option) error {
	return errorz.Errorf(format, append(options,
		ErrIDForbidden,
		errorz.Status(http.StatusForbidden),
		errorz.Prefix("forbidden"),
		errorz.Skip())...)
}

// WrapErrForbidden wraps an error as forbidden error.
func WrapErrForbidden(err error, options ...errorz.Option) error {
	if errorz.GetID(err) == ErrIDForbidden {
		return errorz.Wrap(err, options...)
	}

	if errorz.GetID(err) == "" {
		options = append(options, ErrIDForbidden)
	}

	return errorz.Wrap(err, append(options,
		errorz.Status(http.StatusForbidden),
		errorz.Prefix("forbidden"),
		errorz.Skip())...)
}
