package oauth2server

import (
	"net/http"
)

// Represents a valid authorization request
type AuthorizationRequest struct {
}

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// The oauth2 server, this takes care of validating authorization requests
// as well as issuing access and refresh tokens. This is the main entrypoint
// to this library.
type OAuth2Server interface {
	// parse and validate an authorization request from the incoming request.
	ValidateAuthorizationRequest(req *http.Request) (*AuthorizationRequest, OAuthError)

	// respond to a token request and (maybe) issue an access token based on the request
	Token(req *http.Request) (*AccessTokenResponse, OAuthError)
}
