package oauth2server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

const (
	ParamClientID     = "client_id"
	ParamClientSecret = "client_secret"
	ParamGrantType    = "grant_type"
)

var (
	ErrCouldNotParseRequestBody = errors.New("could not parse request body")
	ErrMissingGrantType         = fmt.Errorf("missing %s in request body", ParamGrantType)
	ErrMissingClientID          = fmt.Errorf("%s was not included in the request", ParamClientID)
	ErrMissingClientSecret      = fmt.Errorf("%s was not included in the request", ParamClientSecret)
)

type AccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

// Parse an incomding net/http request and pull out oauth client info and
// post form values.
type AccessTokenRequest struct {
	ClientID      string
	ClientSecret  string
	UsedBasicAuth bool
	GrantType     string
	HTTPRequest   *http.Request
}

// parse an incoming access token request
func ParseAccessTokenRequest(r *http.Request) (*AccessTokenRequest, *OAuthError) {
	// theoretically implementations should use their router/servermux to avoid
	// hitting this error condition, but ... just in case
	if r.Method != http.MethodPost {
		return nil, InvalidRequest("token requests must be %s requests", http.MethodPost)
	}

	err := r.ParseForm()
	if err != nil {
		oauthErr := InvalidRequest(ErrCouldNotParseRequestBody.Error())
		oauthErr.Cause = fmt.Errorf("%w: %w", ErrCouldNotParseRequestBody, err)
		return nil, oauthErr
	}

	grantType := r.PostFormValue(ParamGrantType)
	if grantType == "" {
		oauthErr := MissingRequestParameterWithCause(ErrMissingGrantType, ParamGrantType)
		return nil, oauthErr
	}

	clientId, clientSecret, basicAuth := r.BasicAuth()
	if !basicAuth {
		// fall back to request body parameters if basic auth is not present
		clientId = r.PostFormValue(ParamClientID)
		clientSecret = r.PostFormValue(ParamClientSecret)
	}

	return &AccessTokenRequest{
		ClientID:      clientId,
		ClientSecret:  clientSecret,
		UsedBasicAuth: basicAuth,
		GrantType:     grantType,
		HTTPRequest:   r,
	}, nil
}

func (r *AccessTokenRequest) ClientIDOrError() (string, *OAuthError) {
	if r.ClientID == "" {
		return "", InvalidClientWithCause(ErrMissingClientID, ErrMissingClientID.Error())
	}

	return r.ClientID, nil
}

func (r *AccessTokenRequest) ClientSecretOrError() (string, *OAuthError) {
	if r.ClientSecret == "" {
		return "", InvalidClientWithCause(ErrMissingClientSecret, ErrMissingClientSecret.Error())
	}

	return r.ClientSecret, nil
}

func (r *AccessTokenRequest) Param(paramName string) string {
	return r.HTTPRequest.PostFormValue(paramName)
}

func (r *AccessTokenRequest) ParamOrError(paramName string) (string, *OAuthError) {
	v := r.Param(paramName)
	if v == "" {
		return "", MissingRequestParameter(paramName)
	}

	return v, nil
}

type Grant interface {
	// Respond to an access token request. Any non `OAuthError` returned here will
	// be converted to an `server_error` oauth response without an error description
	Token(ctx context.Context, req *AccessTokenRequest) (*AccessTokenResponse, error)

	// the grant type the grant will handle.
	GrantType() string
}
