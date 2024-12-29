package oauth2server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

var (
	ErrAuthCodeGrantNotSet = errors.New("this server does not have the authorization code grant configured")
)

// The oauth2 server, this takes care of validating authorization requests
// as well as issuing access and refresh tokens. This is the main entrypoint
// to this library.
type AuthorizationServer interface {
	// respond to a token request and (maybe) issue an access token based on the request
	Token(ctx context.Context, req *http.Request) (*AccessTokenResponse, *OAuthError)

	// parse and validate an authorization request from the incoming request and
	// return it. Any errors returned here _cannot_ be redirected back to the user.
	// the OAuthError returned should be used display the error to the user
	ValidateAuthorizationRequest(ctx context.Context, req *http.Request) (*AuthorizationRequest, *OAuthError)

	// Deny the given authorization request. This can be for whatever reason: a user denied
	// or the authorization server itself chose not to service the request. The returned
	// oauth error can be used to generate a redirect response
	DenyAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, reason string) *OAuthError

	// complete the authorization request and returns a set of `url.Values` that can be used
	// to redirect to the user or an error that can be used to redirect with an error
	CompleteAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, user User) (url.Values, *OAuthError)
}

type defaultAuthorizationServer struct {
	grants                map[string]Grant
	authorizationHandlers map[string]AuthorizationHandler
}

type ServerOptions struct {
	grants                map[string]Grant
	authorizationHandlers map[string]AuthorizationHandler
}

type ServerOption func(*ServerOptions)

func WithGrant(grant Grant) ServerOption {
	return func(opts *ServerOptions) {
		opts.grants[grant.GrantType()] = grant
		if authHandler, ok := grant.(AuthorizationHandler); ok {
			opts.authorizationHandlers[authHandler.ResponseType()] = authHandler
		}
	}
}

func WithAuthorizationHandler(handler AuthorizationHandler) ServerOption {
	return func(opts *ServerOptions) {
		opts.authorizationHandlers[handler.ResponseType()] = handler
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
		grants:                options.grants,
		authorizationHandlers: options.authorizationHandlers,
	}
}

func authCodeNotConfigured() *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeUnsupportedGrantType,
		ErrorDescription: ErrAuthCodeGrantNotSet.Error(),
		Cause:            ErrAuthCodeGrantNotSet,
	}
}

func (s *defaultAuthorizationServer) ValidateAuthorizationRequest(ctx context.Context, req *http.Request) (*AuthorizationRequest, *OAuthError) {
	// TODO
	return nil, nil
}

func (s *defaultAuthorizationServer) DenyAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, reason string) *OAuthError {
	// TODO
	return nil
}

func (s *defaultAuthorizationServer) CompleteAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, user User) (url.Values, *OAuthError) {
	// TODO
	return nil, nil
}

func (s *defaultAuthorizationServer) Token(ctx context.Context, req *http.Request) (*AccessTokenResponse, *OAuthError) {
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

	resp, grantErr := grant.Token(ctx, tokenRequest)

	return resp, MaybeWrapError(grantErr)
}
