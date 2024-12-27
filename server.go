package oauth2server

import (
	"net/http"
)

// The oauth2 server, this takes care of validating authorization requests
// as well as issuing access and refresh tokens. This is the main entrypoint
// to this library.
type OAuth2Server interface {
	// parse and validate an authorization request from the incoming request and
	// return it. Any errors returned here _cannot_ be redirected back to the user.
	// the OAuthError returned should be used display the error to the user
	ValidateAuthorizationRequest(req *http.Request) (*AuthorizationRequest, *OAuthError)

	// Deny the given authorization request. This returns a URL to which the implementation
	// _must_ redirect the user. The reason here may include more info about why it
	// was denied by the user
	DenyAuthorizationRequest(req AuthorizationRequest, reason string) AuthorizationErrorResponse

	// Complete the authorization request and redirect the user back to the redirect URL.
	CompleteAuthorizationRequest(req AuthorizationRequest, user User) (AuthorizationCompleteResponse, *OAuthError)

	// respond to a token request and (maybe) issue an access token based on the request
	Token(req *http.Request) (*AccessTokenResponse, *OAuthError)
}
