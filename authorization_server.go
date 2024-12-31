package oauth2server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
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
	// return it. If both an authorization requset AND error are returned here, the user
	// may be redirected with an error. If only an error is returned, the user _must not_
	// be redirected and the error should be show on the authorization server.
	ValidateAuthorizationRequest(ctx context.Context, req *http.Request) (*AuthorizationRequest, *OAuthError)

	// Deny the given authorization request. This can be for whatever reason: a user denied
	// or the authorization server itself chose not to service the request. The returned
	// oauth error can be used to generate a redirect response
	DenyAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, reason string) *OAuthError

	// complete the authorization request and returns a set of `url.Values` that can be used
	// to redirect to the user or an error that can be used to redirect with an error
	CompleteAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, user User) (url.Values, *OAuthError)
}

type ServerOptions struct {
	grants                map[string]Grant
	authorizationHandlers map[string]AuthorizationHandler
	scopeValidator        ScopeValidator
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

func WithScopeValidator(s ScopeValidator) ServerOption {
	return func(opts *ServerOptions) {
		if s != nil {
			opts.scopeValidator = s
		}
	}
}

type defaultAuthorizationServer struct {
	clients               ClientRepository
	scopeValidator        ScopeValidator
	grants                map[string]Grant
	authorizationHandlers map[string]AuthorizationHandler
}

func NewAuthorizationServer(clients ClientRepository, config ...ServerOption) AuthorizationServer {
	options := &ServerOptions{
		grants:                make(map[string]Grant),
		authorizationHandlers: make(map[string]AuthorizationHandler),
		scopeValidator:        AllowAllScopes(),
	}
	for _, c := range config {
		c(options)
	}

	return &defaultAuthorizationServer{
		clients:               clients,
		scopeValidator:        options.scopeValidator,
		grants:                options.grants,
		authorizationHandlers: options.authorizationHandlers,
	}
}

func (s *defaultAuthorizationServer) ValidateAuthorizationRequest(ctx context.Context, req *http.Request) (*AuthorizationRequest, *OAuthError) {
	authReq, err := ParseAuthorizationRequest(req)
	if err != nil {
		return nil, err
	}

	client, clientErr := GetClient(ctx, s.clients, authReq.ClientID)
	if clientErr != nil {
		return nil, clientErr
	}

	if err := ValidateRedirectURI(ctx, client, authReq.RedirectURI); err != nil {
		return nil, err
	}

	// at this point we know the redirect URI is valid and any error from here out
	// can be sent back to the redirect URI.

	if err := s.checkAuthorizationResponseType(client, authReq.ResponseType); err != nil {
		return authReq, err
	}

	if err := s.scopeValidator.ValidateScopes(ctx, authReq.Scope); err != nil {
		return authReq, MaybeWrapError(err)
	}

	// TODO
	return nil, nil
}

func (s *defaultAuthorizationServer) DenyAuthorizationRequest(ctx context.Context, req *AuthorizationRequest, reason string) *OAuthError {
	return &OAuthError{
		ErrorType:        ErrorTypeAccessDenied,
		ErrorDescription: reason,
	}
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

func (s *defaultAuthorizationServer) checkAuthorizationResponseType(client Client, wantedTypes []string) *OAuthError {
	var invalid []string
	for _, t := range wantedTypes {
		if _, ok := s.authorizationHandlers[t]; !ok {
			invalid = append(invalid, t)
		}
	}

	if len(invalid) > 0 {
		return UnsupportedResponseType(invalid)
	}

	if check, ok := client.(ClientAllowsResponseType); ok && !check.AllowsResponseType(wantedTypes) {
		return UnauthorizedClient(fmt.Sprintf(
			"client %s does not support response type: %s",
			client.ID(),
			strings.Join(wantedTypes, " "),
		))
	}

	return nil
}
