package oauth2server

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// Represents a valid authorization request
type AuthorizationRequest struct {
	// the oauth client initiation the request
	ClientID string `json:"client_id"`

	// The redirect URI included in the authorization request.
	RedirectURI string `json:"redirect_uri,omitempty"`

	// The redirect URI that's to be used for the final redirect. This might
	// be different than the redirectURI above if the above was empty or a client
	// modified it via its extension point.
	FinalRedirectURI string `json:"final_redirect_uri,omitempty"`

	// optional: oauth state, empty string == no state
	State string `json:"state,omitempty"`

	// for Proof key code exchange (PKCE): the code challenge
	CodeChallenge string `json:"code_challenge,omitempty"`

	// for PKCE code challenge method `plain` or `S256`
	CodeChallengeMethod string `json:"code_challenge_method,omitempty"`

	// the list of scopes associated with the auth code request
	Scope []string `json:"scope,omitempty"`

	// the response types that were requested
	ResponseType []string `json:"response_type,omitempty"`

	// the query string values
	QueryString url.Values `json:"-"`
}

func ParseAuthorizationRequest(req *http.Request) (*AuthorizationRequest, *OAuthError) {
	if req.Method != http.MethodGet {
		return nil, InvalidRequestWithCause(
			ErrInvalidRequestMethod,
			"authorization requests should be %s requests",
			http.MethodGet,
		)
	}

	queryString, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, &OAuthError{
			ErrorType:        ErrorTypeInvalidRequest,
			ErrorDescription: ErrCouldNotParseQueryString.Error(),
			Cause:            fmt.Errorf("%w: %w", ErrCouldNotParseQueryString, err),
		}
	}

	responseType := queryString.Get(ParamResponseType)
	if responseType == "" {
		return nil, MissingRequestParameterWithCause(ErrMissingResponseType, ParamResponseType)
	}

	clientId := queryString.Get(ParamClientID)
	if clientId == "" {
		// should this be an `invalid_client` error :thinking:
		return nil, MissingRequestParameterWithCause(ErrMissingClientID, ParamClientID)
	}

	codeChallenge := queryString.Get(ParamCodeChallenge)
	challengeMethod := queryString.Get(ParamCodeChallengeMethod)
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.3
	// defaults to plain if no present in the request
	if codeChallenge != "" && challengeMethod == "" {
		challengeMethod = CodeChallengeMethodPlain
	}

	return &AuthorizationRequest{
		ClientID:            clientId,
		ResponseType:        ParseSpaceSeparatedParameter(responseType),
		RedirectURI:         queryString.Get(ParamRedirectURI),
		Scope:               ParseSpaceSeparatedParameter(queryString.Get(ParamScope)),
		State:               queryString.Get(ParamState),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: challengeMethod,
		QueryString:         queryString,
	}, nil
}

// Able to respond to requested `GrantType` in authorization requests. Eg a
// `code` handler or an `id_token` handler. Grants may implement this or it could
// be independent of grants.
type AuthorizationHandler interface {
	// The response type that the handler responds to
	ResponseType() string

	// validate the authentication request and return an error if something is invalid
	// the error _may_ be an *OAuthError that will be passed to the user, but _can_
	// be any other error.
	ValidateAuthorizationRequest(ctx context.Context, client Client, req *AuthorizationRequest) error

	// issues the authorization response value.
	IssueAuthorizationResponse(
		ctx context.Context,
		client Client,
		req *AuthorizationRequest,
		user User,
	) (string, error)
}
