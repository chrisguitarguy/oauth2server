package oauth2server

import (
	"errors"
	"fmt"
	"net/http"
)

var (
	ErrAuthCodeGrantNotSet = errors.New("this server does not have the authorization code grant configured")
)

// The oauth2 server, this takes care of validating authorization requests
// as well as issuing access and refresh tokens. This is the main entrypoint
// to this library.
type AuthorizationServer interface {
	// respond to a token request and (maybe) issue an access token based on the request
	Token(req *http.Request) (*AccessTokenResponse, *OAuthError)

	// parse and validate an authorization request from the incoming request and
	// return it. Any errors returned here _cannot_ be redirected back to the user.
	// the OAuthError returned should be used display the error to the user
	ValidateAuthorizationRequest(req *http.Request) (*AuthorizationRequest, *OAuthError)

	// Deny the given authorization request. This returns a URL to which the implementation
	// _must_ redirect the user. The reason here may include more info about why it
	// was denied by the user
	DenyAuthorizationRequest(req AuthorizationRequest, reason string) (AuthorizationErrorResponse, *OAuthError)

	// Complete the authorization request and redirect the user back to the redirect URL.
	CompleteAuthorizationRequest(req AuthorizationRequest, user User) (AuthorizationCompleteResponse, *OAuthError)
}

type defaultAuthorizationServer struct {
	grants        map[string]Grant
	authCodeGrant AuthorizationCodeGrant
}

type ServerOptions struct {
	grants        map[string]Grant
	authCodeGrant AuthorizationCodeGrant
}

type ServerOption func(*ServerOptions)

func WithGrant(grant Grant) ServerOption {
	return func(opts *ServerOptions) {
		opts.grants[grant.ID()] = grant
		if authCodeGrant, ok := grant.(AuthorizationCodeGrant); ok {
			opts.authCodeGrant = authCodeGrant
		}
	}
}

func NewAuthorizationServer(config ...ServerOption) AuthorizationServer {
	options := &ServerOptions{
		grants: make(map[string]Grant),
	}
	for _, c := range config {
		c(options)
	}

	return &defaultAuthorizationServer{
		grants:        options.grants,
		authCodeGrant: options.authCodeGrant,
	}
}

func authCodeNotConfigured() *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeUnsupportedGrantType,
		ErrorDescription: ErrAuthCodeGrantNotSet.Error(),
		Cause:            ErrAuthCodeGrantNotSet,
	}
}

func (s *defaultAuthorizationServer) ValidateAuthorizationRequest(req *http.Request) (*AuthorizationRequest, *OAuthError) {
	if s.authCodeGrant == nil {
		// this is _not_ a spec compliant error, but if a user sees this, then the
		// server is very misconfigured.
		return nil, authCodeNotConfigured()
	}

	resp, err := s.authCodeGrant.ValidateAuthorizationRequest(req)

	return resp, MaybeWrapError(err)
}

func (s *defaultAuthorizationServer) DenyAuthorizationRequest(req AuthorizationRequest, reason string) (AuthorizationErrorResponse, *OAuthError) {
	if s.authCodeGrant == nil {
		return nil, authCodeNotConfigured()
	}

	return s.authCodeGrant.DenyAuthorizationRequest(req, reason), nil
}

func (s *defaultAuthorizationServer) CompleteAuthorizationRequest(req AuthorizationRequest, user User) (AuthorizationCompleteResponse, *OAuthError) {
	if s.authCodeGrant == nil {
		return nil, authCodeNotConfigured()
	}

	resp, err := s.authCodeGrant.CompleteAuthorizationRequest(req, user)

	return resp, MaybeWrapError(err)
}

func (s *defaultAuthorizationServer) Token(req *http.Request) (*AccessTokenResponse, *OAuthError) {
	tokenRequest, err := ParseAccessTokenRequest(req)
	if err != nil {
		return nil, err
	}

	grant, grantFound := s.grants[tokenRequest.GrantType]
	if !grantFound {
		return nil, &OAuthError{
			ErrorType:        ErrorTypeUnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("the %s grant type is not supported", tokenRequest.GrantType),
		}
	}

	resp, grantErr := grant.Token(tokenRequest)

	return resp, MaybeWrapError(grantErr)
}
