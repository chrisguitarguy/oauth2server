package oauth2server

import (
	"context"
	"net/http"
)

// Represents a valid authorization request
type AuthorizationRequest struct {
	// the oauth client initiation the request
	ClientID string `json:"client_id"`
	// The redirect URI included in the authorization request.
	RedirectURI string `json:"redirect_uri,omitempty"`
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

	// the underlying http request
	HTTPRequest *http.Request `json:"-"`
}

// Able to respond to requested `GrantType` in authorization requests. Eg a
// `code` handler or an `id_token` handler. Grants may implement this or it could
// be independent of grants.
type AuthorizationHandler interface {
	// The response type that the handler responds to
	ResponseType() string

	// issues the authorization response value.
	IssueAuthorizationResponse(ctx context.Context, req AuthorizationRequest, user User) string
}
