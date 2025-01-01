package oauth2server

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidRequestMethod           = errors.New("invalid request method")
	ErrCouldNotParseRequestBody       = errors.New("could not parse request body")
	ErrCouldNotParseQueryString       = errors.New("could not parse query string")
	ErrMissingGrantType               = fmt.Errorf("missing %s in request body", ParamGrantType)
	ErrMissingClientID                = fmt.Errorf("%s was not included in the request", ParamClientID)
	ErrClientNotFound                 = errors.New("client not found")
	ErrClientHasNoRedirectURIs        = errors.New("client does not have any redirect URIs")
	ErrClientRequiresRedirectURI      = errors.New("the client has >1 redirect uri and redirect_uri must be included in the request")
	ErrClientInvalidRedirectURI       = errors.New("redirect_uri in request was not valid for the client")
	ErrMissingClientSecret            = fmt.Errorf("%s was not included in the request", ParamClientSecret)
	ErrMissingResponseType            = fmt.Errorf("%s was not included in the requset", ParamResponseType)
	ErrUnsupportedCodeChallengeMethod = errors.New("code challenge method not supported")
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

func InvalidRequest(format string, a ...any) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeInvalidRequest,
		ErrorDescription: fmt.Sprintf(format, a...),
	}
}

func InvalidRequestWithCause(cause error, format string, a ...any) *OAuthError {
	err := InvalidRequest(format, a...)
	err.Cause = cause

	return err
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

func InvalidScope(invalidScopes []string) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeInvalidScope,
		ErrorDescription: fmt.Sprintf("invalid scopes: %s", strings.Join(invalidScopes, " ")),
	}
}

func UnsupportedResponseType(invalidTypes []string) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeUnsupportedResponseType,
		ErrorDescription: fmt.Sprintf("unsupported response types: %s", strings.Join(invalidTypes, " ")),
	}
}

func UnauthorizedClient(reason string) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeUnauthorizedClient,
		ErrorDescription: reason,
	}
}

func AsOAuthError(err error) (*OAuthError, bool) {
	var oauthErr *OAuthError
	if errors.As(err, &oauthErr) {
		return oauthErr, true
	}

	return nil, false
}

func MaybeWrapError(cause error) *OAuthError {
	if cause == nil {
		return nil
	}

	if oauthErr, ok := AsOAuthError(cause); ok {
		return oauthErr
	}

	return ServerError(cause)
}
