package oauth2server_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestParseAccessTokenRequest_ReturnsErrorIfNotAPostRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/token", nil)

	req, err := oauth2server.ParseAccessTokenRequest(r)

	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
	if req != nil {
		t.Errorf("expected nil request on error, got %#v", req)
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("Expected %q error type, got %q", oauth2server.ErrorTypeInvalidRequest, err.ErrorType)
	}
}

func TestParseAccessTokenRequest_ErrorsIfBodyCannotBeParsed(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	r.Body = nil // make sure ParseForm fails

	req, err := oauth2server.ParseAccessTokenRequest(r)

	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
	if req != nil {
		t.Errorf("expected nil request on error, got %#v", req)
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("Expected %q error type, got %q", oauth2server.ErrorTypeInvalidRequest, err.ErrorType)
	}
	if !errors.Is(err, oauth2server.ErrCouldNotParseRequestBody) {
		t.Errorf("Expected returned error to be %v, got %+v", oauth2server.ErrCouldNotParseRequestBody, err.Cause)
	}
}

func TestParseAccessTokenRequest_ErrorsIfGrantTypeIsNotFoundInRequestBody(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)

	req, err := oauth2server.ParseAccessTokenRequest(r)

	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
	if req != nil {
		t.Errorf("expected nil request on error, got %#v", req)
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("Expected %q error type, got %q", oauth2server.ErrorTypeInvalidRequest, err.ErrorType)
	}
	if !errors.Is(err, oauth2server.ErrMissingGrantType) {
		t.Errorf("Expected returned error to be %v, got %+v", oauth2server.ErrMissingGrantType, err.Cause)
	}
}

func TestParseAccessTokenRequest_UsesBasicAuthForClientIdAndSecretIfPresent(t *testing.T) {
	r := createRequestWithFormBody(http.MethodPost, "/token", map[string]string{
		"grant_type":    "test",
		"client_id":     "clientIdInBody",
		"client_secret": "clientSecretInBody",
	})
	r.SetBasicAuth("clientId", "clientSecret")

	req, err := oauth2server.ParseAccessTokenRequest(r)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if req == nil {
		t.Fatal("expected AccessTokenRequest to be non-nil")
	}
	if req.GrantType != "test" {
		t.Errorf("expected grant type to be set from request body, got %q", req.GrantType)
	}
	if req.ClientID != "clientId" {
		t.Errorf("Expected client ID to be set from basic auth, got %q", req.ClientID)
	}
	if req.ClientSecret != "clientSecret" {
		t.Errorf("Expected client secret to be set from basic auth, got %q", req.ClientSecret)
	}
}

func TestParseAccessTokenRequest_FallsBackToClientIdInBodyWhenNoBasicAuth(t *testing.T) {
	r := createRequestWithFormBody(http.MethodPost, "/token", map[string]string{
		"grant_type":    "test",
		"client_id":     "clientIdInBody",
		"client_secret": "clientSecretInBody",
	})

	req, err := oauth2server.ParseAccessTokenRequest(r)

	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if req == nil {
		t.Fatal("expected AccessTokenRequest to be non-nil")
	}
	if req.GrantType != "test" {
		t.Errorf("expected grant type to be set from request body, got %q", req.GrantType)
	}
	if req.ClientID != "clientIdInBody" {
		t.Errorf("Expected client ID to be set from request body, got %q", req.ClientID)
	}
	if req.ClientSecret != "clientSecretInBody" {
		t.Errorf("Expected client secret to be set from request body, got %q", req.ClientSecret)
	}
}

func TestAccessTokenRequest_ClientIDOrError_ReturnsErrorIfClientIDIsEmpty(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{}

	clientId, err := req.ClientIDOrError()

	if clientId != "" {
		t.Errorf("Expected client ID to be empty, got %q", clientId)
	}
	if !errors.Is(err, oauth2server.ErrMissingClientID) {
		t.Errorf("Expected error to be ErrMissingClientID, got %v", err)
	}
}

func TestAccessTokenRequest_ClientIDOrError_ReturnsClientIDIfSet(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{
		ClientID: "abc123",
	}

	clientId, err := req.ClientIDOrError()

	if clientId != "abc123" {
		t.Errorf("Expected client ID to `abc123`, got %q", clientId)
	}
	if err != nil {
		t.Errorf("Expected error to be nil, got %v", err)
	}
}

func TestAccessTokenRequest_ClientSecretOrError_ReturnsErrorIfClientSecretIsEmpty(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{}

	clientSecret, err := req.ClientSecretOrError()

	if clientSecret != "" {
		t.Errorf("Expected client secret to be empty, got %q", clientSecret)
	}
	if !errors.Is(err, oauth2server.ErrMissingClientSecret) {
		t.Errorf("Expected error to be ErrMissingClientSecret, got %v", err)
	}
}

func TestAccessTokenRequest_ClientIDOrError_ReturnsClientSecretIfSet(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{
		ClientSecret: "shh",
	}

	clientSecret, err := req.ClientSecretOrError()

	if clientSecret != "shh" {
		t.Errorf("Expected client secret to `shh`, got %q", clientSecret)
	}
	if err != nil {
		t.Errorf("Expected error to be nil, got %v", err)
	}
}

func TestAccessTokenRequest_Param_ReturnsEmptyStringIfNotSet(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{
		HTTPRequest: createRequestWithFormBody(http.MethodPost, "/token", map[string]string{}),
	}

	param := req.Param("test")

	if param != "" {
		t.Errorf("expected param to be an empty string, got %q", param)
	}
}

func TestAccessTokenRequest_Param_ReturnsValeuIfSet(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{
		HTTPRequest: createRequestWithFormBody(http.MethodPost, "/token", map[string]string{
			"test": "yes",
		}),
	}

	param := req.Param("test")

	if param != "yes" {
		t.Errorf("expected param to be `yes`, got %q", param)
	}
}

func TestAccessTokenRequest_ParamOrError_ReturnsErrorIfParameterIsNotSet(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{
		HTTPRequest: createRequestWithFormBody(http.MethodPost, "/token", map[string]string{}),
	}

	param, err := req.ParamOrError("test")

	if param != "" {
		t.Errorf("expected param to be an empty string, go %q", param)
	}
	if err == nil {
		t.Fatal("Expected an oauth error to be returned, got nil")
	}
	if err.ErrorType != oauth2server.ErrorTypeInvalidRequest {
		t.Errorf("expected %q error type, got %q", oauth2server.ErrorTypeInvalidRequest, err.ErrorType)
	}
}

func TestAccessTokenRequest_ParamOrError_ReturnsParamIfSet(t *testing.T) {
	req := &oauth2server.AccessTokenRequest{
		HTTPRequest: createRequestWithFormBody(http.MethodPost, "/token", map[string]string{
			"test": "yes",
		}),
	}

	param, err := req.ParamOrError("test")

	if param != "yes" {
		t.Errorf("expected param to be `yes`, got %q", param)
	}
	if err != nil {
		t.Errorf("Expected error to be nil, got %#v", err)
	}
}
