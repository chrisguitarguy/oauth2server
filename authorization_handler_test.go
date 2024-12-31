package oauth2server_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestParseAuthorizationRequest_ErrorsIfNotAGetRequest(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodPost, "/authorize", nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if req != nil {
		t.Errorf("expected request to be nil, got %T %v", req, req)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("unexpected error type: %q != %q", err.ErrorType, oauth2server.ErrorTypeInvalidRequest)
	}
	if !errors.Is(err, oauth2server.ErrInvalidRequestMethod) {
		t.Errorf("expected an ErrInvalidRequestMethod: %+v", err)
	}
}

func TestParseAuthorizationRequest_ErrorsIfInvalidQuery(t *testing.T) {
	// semicolon here causes it to error
	httpReq := httptest.NewRequest(http.MethodGet, "/authorize?clien;t=1", nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if req != nil {
		t.Errorf("expected request to be nil, got %T %v", req, req)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("unexpected error type: %q != %q", err.ErrorType, oauth2server.ErrorTypeInvalidRequest)
	}
	if !errors.Is(err, oauth2server.ErrCouldNotParseQueryString) {
		t.Errorf("expected an ErrCouldNotParseQueryString: %+v", err)
	}
}

func TestParseAuthorizationRequest_ErrorsIfMissingResponseType(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/authorize?client_id=1", nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if req != nil {
		t.Errorf("expected request to be nil, got %T %v", req, req)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("unexpected error type: %q != %q", err.ErrorType, oauth2server.ErrorTypeInvalidRequest)
	}
	if !errors.Is(err, oauth2server.ErrMissingResponseType) {
		t.Errorf("expected an ErrMissingResponseType: %+v", err)
	}
}

func TestParseAuthorizationRequest_ErrorsIfMissingClientID(t *testing.T) {
	httpReq := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code", nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if req != nil {
		t.Errorf("expected request to be nil, got %T %v", req, req)
	}
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("unexpected error type: %q != %q", err.ErrorType, oauth2server.ErrorTypeInvalidRequest)
	}
	if !errors.Is(err, oauth2server.ErrMissingClientID) {
		t.Errorf("expected an ErrMissingClientID: %+v", err)
	}
}

func TestParseAuthorizationRequest_ReturnsExpectedResponseIfValid(t *testing.T) {
	vals := make(url.Values)
	vals.Set(oauth2server.ParamClientID, "abc123")
	vals.Set(oauth2server.ParamResponseType, "code id_token")
	vals.Set(oauth2server.ParamState, "state")
	vals.Set(oauth2server.ParamCodeChallenge, "challenge")
	vals.Set(oauth2server.ParamCodeChallengeMethod, "plain")
	vals.Set(oauth2server.ParamRedirectURI, "http://example.com")
	vals.Set(oauth2server.ParamScope, "one  two ")

	httpReq := httptest.NewRequest(http.MethodGet, "/authorize?"+vals.Encode(), nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if err != nil {
		t.Errorf("expected nor error, got %v", err)
	}
	if req == nil {
		t.Fatal("expected not nil request")
	}
	if req.ClientID != "abc123" {
		t.Errorf(`bad client id: %q != "abc123"`, req.ClientID)
	}
	expectedResponseType := []string{"code", "id_token"}
	if !slices.Equal(req.ResponseType, expectedResponseType) {
		t.Errorf("bad response type: %+v != %+v", req.ResponseType, expectedResponseType)
	}
	if req.State != "state" {
		t.Errorf(`bad state: %q != "state"`, req.State)
	}
	if req.CodeChallenge != "challenge" {
		t.Errorf(`bad code challenge: %q != "challenge"`, req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "plain" {
		t.Errorf(`bad code challenge: %q != "plain"`, req.CodeChallengeMethod)
	}
	if req.RedirectURI != "http://example.com" {
		t.Errorf(`bad redirect URI: %q != "http://example.com"`, req.RedirectURI)
	}
	expectedScope := []string{"one", "two"}
	if !slices.Equal(req.Scope, expectedScope) {
		t.Errorf("bad scope: %+v != %+v", req.Scope, expectedScope)
	}
}

func TestParseAuthorizationRequest_MinimalRequestIsValid(t *testing.T) {
	vals := make(url.Values)
	vals.Set(oauth2server.ParamClientID, "abc123")
	vals.Set(oauth2server.ParamResponseType, "code")

	httpReq := httptest.NewRequest(http.MethodGet, "/authorize?"+vals.Encode(), nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if err != nil {
		t.Errorf("expected nor error, got %v", err)
	}
	if req == nil {
		t.Fatal("expected not nil request")
	}
	if req.ClientID != "abc123" {
		t.Errorf(`bad client id: %q != "abc123"`, req.ClientID)
	}
	expectedResponseType := []string{"code"}
	if !slices.Equal(req.ResponseType, expectedResponseType) {
		t.Errorf("bad response type: %+v != %+v", req.ResponseType, expectedResponseType)
	}
	if req.State != "" {
		t.Errorf(`bad state: %q != ""`, req.State)
	}
	if req.CodeChallenge != "" {
		t.Errorf(`bad code challenge: %q != ""`, req.CodeChallenge)
	}
	if req.CodeChallengeMethod != "" {
		t.Errorf(`bad code challenge: %q != ""`, req.CodeChallengeMethod)
	}
	if req.RedirectURI != "" {
		t.Errorf(`bad redirect URI: %q != ""`, req.RedirectURI)
	}
	if req.Scope != nil {
		t.Errorf("bad scope: %+v != nil", req.Scope)
	}
}

func TestParseAuthorizationRequest_SetsPlainCodeChallengeMethodIfMissing(t *testing.T) {
	vals := make(url.Values)
	vals.Set(oauth2server.ParamClientID, "abc123")
	vals.Set(oauth2server.ParamResponseType, "code")
	vals.Set(oauth2server.ParamCodeChallenge, "shh")

	httpReq := httptest.NewRequest(http.MethodGet, "/authorize?"+vals.Encode(), nil)
	req, err := oauth2server.ParseAuthorizationRequest(httpReq)

	if err != nil {
		t.Errorf("expected nor error, got %v", err)
	}
	if req == nil {
		t.Fatal("expected not nil request")
	}
	if req.CodeChallengeMethod != oauth2server.CodeChallengeMethodPlain {
		t.Errorf("expected to default to %q code challenge method, got %q", oauth2server.CodeChallengeMethodPlain, req.CodeChallengeMethod)
	}
}
