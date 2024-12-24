package oauth2server

import (
	"net/http"
)

type defaultOAuth2Server struct {
}

func (s *defaultOAuth2Server) ValidateAuthorizationRequest(req *http.Request) (*AuthorizationRequest, OAuthError) {
	return nil, OAuthError{
		ErrorType:        ErrorTypeServerError,
		ErrorDescription: "Not Implemented",
	}
}

func (s *defaultOAuth2Server) Token(req *http.Request) (*AccessTokenResponse, OAuthError) {
	return nil, OAuthError{
		ErrorType:        ErrorTypeServerError,
		ErrorDescription: "Not Implemented",
	}
}
