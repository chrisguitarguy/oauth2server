package oauth2server

import (
	"errors"
	"fmt"
)

const (
	ErrorTypeInvalidRequest          = "invalid_request"
	ErrorTypeUnauthorizedClient      = "unauthorized_client"
	ErrorTypeInvalidClient           = "invalid_client"
	ErrorTypeAccessDenied            = "access_denied"
	ErrorTypeUnsupportedResponseType = "unsupported_response_type"
	ErrorTypeInvalidScope            = "invalid_scope"
	ErrorTypeServerError             = "server_error"
	ErrorTypeTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorTypeInvalidGrant            = "invalid_grant"
	ErrorTypeUnsupportedGrantType    = "unsupported_grant_type"
)

// An error generated from the oauth2 server during an access token request.
// This adheres to the error format defined in the oauth2 spec
// (eg error, error_description, error_uri).
type OAuthError struct {
	// what the response status code should be.
	StatusCode int `json:"-"`

	// an oauth2 error code from the oauth2 spec: https://datatracker.ietf.org/doc/html/rfc6749
	ErrorType string `json:"error"`
	// an optional error description explain more about what was wrong
	ErrorDescription string `json:"error_description,omitempty"`
	// an optional URI to which a human can visit and get more details about the error
	ErrorURI string `json:"error_uri,omitempty"`

	// an optional upstream error
	Cause error `json:"-"`
}

func InvalidRequest(format string, a ...any) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeInvalidRequest,
		ErrorDescription: fmt.Sprintf(format, a...),
	}
}

func MissingRequestParameter(paramName string) *OAuthError {
	return InvalidRequest("request is missing the %s parameter", paramName)
}

func MissingRequestParameterWithCause(cause error, paramName string) *OAuthError {
	e := MissingRequestParameter(paramName)
	e.Cause = cause

	return e
}

func InvalidClient(format string, a ...any) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeInvalidClient,
		ErrorDescription: fmt.Sprintf(format, a...),
	}
}

func InvalidClientWithCause(cause error, format string, a ...any) *OAuthError {
	e := InvalidClient(format, a...)
	e.Cause = cause

	return e
}

func ServerError(cause error) *OAuthError {
	return &OAuthError{
		ErrorType: ErrorTypeServerError,
		Cause:     cause,
	}
}

func MaybeWrapError(cause error) *OAuthError {
	if cause == nil {
		return nil
	}

	var oauthErr *OAuthError
	if errors.As(cause, &oauthErr) {
		return oauthErr
	}

	return ServerError(cause)
}

func (e *OAuthError) Error() string {
	msg := e.ErrorType
	if e.ErrorDescription != "" {
		msg = fmt.Sprintf("%s: %s", e.ErrorType, e.ErrorDescription)
	}

	if e.Cause != nil {
		msg = fmt.Sprintf("%s caused by %s", msg, e.Cause.Error())
	}

	return msg
}

func (e *OAuthError) Unwrap() error {
	return e.Cause
}
