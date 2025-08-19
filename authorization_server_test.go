package oauth2server_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/chrisguitarguy/oauth2server"
)

const (
	testClientId     = "testclientid"
	testClientSecret = "shhhh"
	testRedirectUri  = "https://example.com/oauth2/callback"
)

func newAuthorizeRequestWithQueryString(t *testing.T, query map[string]string) *http.Request {
	t.Helper()

	uv := url.Values{}
	for k, v := range query {
		uv.Add(k, v)
	}

	return httptest.NewRequest(http.MethodGet, "/authorize?"+uv.Encode(), nil)
}

type authorizationServerTestCase struct {
	clients *oauth2server.InMemoryClientRepository
	server  oauth2server.AuthorizationServer
}

func startAuthorizationServerTest(t *testing.T, opts ...oauth2server.ServerOption) *authorizationServerTestCase {
	clients := oauth2server.NewInMemoryClientRepository()
	server := oauth2server.NewAuthorizationServer(clients, opts...)

	return &authorizationServerTestCase{
		clients: clients,
		server:  server,
	}
}

func (tc *authorizationServerTestCase) assertNilAuthRequest(t *testing.T, authReq *oauth2server.AuthorizationRequest) {
	t.Helper()
	if authReq != nil {
		t.Errorf("Expected nil authorization request, got %T", authReq)
	}
}

func (tc *authorizationServerTestCase) assertNotNilAuthRequest(t *testing.T, authReq *oauth2server.AuthorizationRequest) {
	t.Helper()
	if authReq == nil {
		t.Errorf("Expected not-nil authorization request, got %T", authReq)
	}
}

func TestDefaultAuthorizationServer_DenyAuthorizationRequest_ReturnsAccessDeniedErrorFromDenyAuthorizationRequest(t *testing.T) {
	tc := startAuthorizationServerTest(t)

	err := tc.server.DenyAuthorizationRequest(
		context.Background(),
		&oauth2server.AuthorizationRequest{},
		"nope",
	)

	if err.ErrorType != oauth2server.ErrorTypeAccessDenied {
		t.Errorf("bad error type: %q != %q", err.ErrorType, oauth2server.ErrorTypeAccessDenied)
	}
	if err.ErrorDescription != "nope" {
		t.Errorf(`expected error description from reason argument: %q != "nope"`, err.ErrorDescription)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_ErrorsIfInvalidAuthorizationRequest(t *testing.T) {
	tc := startAuthorizationServerTest(t)
	req := httptest.NewRequest(http.MethodPost, "/authorize", nil)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	tc.assertNilAuthRequest(t, authReq)
	if !errors.Is(err, oauth2server.ErrInvalidRequestMethod) {
		t.Errorf("expected ErrInvalidRequestMethod error, got %v", err)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_ErrorIfClientIsNotFound(t *testing.T) {
	tc := startAuthorizationServerTest(t)
	req := newAuthorizeRequestWithQueryString(t, map[string]string{
		oauth2server.ParamResponseType: "code",
		oauth2server.ParamClientID:     testClientId,
		oauth2server.ParamRedirectURI:  testRedirectUri,
	})
	expectedErr := errors.New("error from client")
	tc.clients.AddError(testClientId, expectedErr)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	tc.assertNilAuthRequest(t, authReq)
	if !errors.Is(err, expectedErr) {
		t.Errorf("Expected error propagated from clients, got %v", err)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_ErrorsIfRedirectURIValidationFails(t *testing.T) {
	tc := startAuthorizationServerTest(t)
	req := newAuthorizeRequestWithQueryString(t, map[string]string{
		oauth2server.ParamResponseType: "code",
		oauth2server.ParamClientID:     testClientId,
		oauth2server.ParamRedirectURI:  "https://other.example.com/invalid-redirect-uri",
	})
	client := oauth2server.NewSimpleClient(
		testClientId,
		testClientSecret,
		[]string{testRedirectUri},
	)
	tc.clients.Add(client)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	tc.assertNilAuthRequest(t, authReq)
	if !errors.Is(err, oauth2server.ErrClientInvalidRedirectURI) {
		t.Errorf("Expected ErrClientInvalidRedirectURI, got %v", err)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_ErrorsOnUnsupportedResponseType(t *testing.T) {
	tc := startAuthorizationServerTest(t)
	req := newAuthorizeRequestWithQueryString(t, map[string]string{
		oauth2server.ParamResponseType: "code",
		oauth2server.ParamClientID:     testClientId,
	})
	client := oauth2server.NewSimpleClient(
		testClientId,
		testClientSecret,
		[]string{testRedirectUri},
	)
	tc.clients.Add(client)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	tc.assertNotNilAuthRequest(t, authReq)
	if err == nil || err.ErrorType != oauth2server.ErrorTypeUnsupportedResponseType {
		t.Errorf(
			"Expected a %q error, got %v",
			oauth2server.ErrorTypeUnsupportedResponseType,
			err,
		)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_ErrorsIfClientDoesNotSupportResponseType(t *testing.T) {
	authHandler := &spyAuthorizationHandler{
		responseType: "test",
	}
	tc := startAuthorizationServerTest(t, oauth2server.WithAuthorizationHandler(authHandler))
	req := newAuthorizeRequestWithQueryString(t, map[string]string{
		oauth2server.ParamResponseType: authHandler.responseType,
		oauth2server.ParamClientID:     testClientId,
	})
	client := &SpyClient{
		id:                       testClientId,
		redirectUris:             []string{testRedirectUri},
		validRedirectURIReturn:   true,
		allowsResponseTypeReturn: false,
	}
	tc.clients.Add(client)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	tc.assertNotNilAuthRequest(t, authReq)
	if err == nil || err.ErrorType != oauth2server.ErrorTypeUnauthorizedClient {
		t.Errorf(
			"Expected a %q error, got %v",
			oauth2server.ErrorTypeUnauthorizedClient,
			err,
		)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_ErrorsIfAuthorizationHandlerErrors(t *testing.T) {
	expectedErr := errors.New("oh noz")
	authHandler := &spyAuthorizationHandler{
		responseType:                      "test",
		validateAuthorizationRequestError: expectedErr,
	}
	tc := startAuthorizationServerTest(t, oauth2server.WithAuthorizationHandler(authHandler))
	req := newAuthorizeRequestWithQueryString(t, map[string]string{
		oauth2server.ParamResponseType: authHandler.responseType,
		oauth2server.ParamClientID:     testClientId,
	})
	client := oauth2server.NewSimpleClient(
		testClientId,
		testClientSecret,
		[]string{testRedirectUri},
	)
	tc.clients.Add(client)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	tc.assertNotNilAuthRequest(t, authReq)
	if err == nil || err.ErrorType != oauth2server.ErrorTypeServerError {
		t.Errorf(
			"Expected a %q error, got %v",
			oauth2server.ErrorTypeServerError,
			err,
		)
	}
	if !errors.Is(err, expectedErr) {
		t.Errorf(
			"expected error %v propagated from authorization handler, got %v",
			expectedErr,
			err,
		)
	}
}

func TestDefaultAuthorizationServer_ValidateAuthorizationRequest_NoErrorIfEverythingValidates(t *testing.T) {
	authHandler := &spyAuthorizationHandler{
		responseType: "test",
	}
	tc := startAuthorizationServerTest(t, oauth2server.WithAuthorizationHandler(authHandler))
	req := newAuthorizeRequestWithQueryString(t, map[string]string{
		oauth2server.ParamResponseType: authHandler.responseType,
		oauth2server.ParamClientID:     testClientId,
		oauth2server.ParamState:        "abc123",
	})
	client := oauth2server.NewSimpleClient(
		testClientId,
		testClientSecret,
		[]string{testRedirectUri},
	)
	tc.clients.Add(client)

	authReq, err := tc.server.ValidateAuthorizationRequest(req.Context(), req)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	tc.assertNotNilAuthRequest(t, authReq)

	diff := cmp.Diff(&oauth2server.AuthorizationRequest{
		ClientID:         testClientId,
		FinalRedirectURI: testRedirectUri,
		State:            "abc123",
		ResponseType: []string{
			authHandler.responseType,
		},
	}, authReq, cmpopts.IgnoreFields(oauth2server.AuthorizationRequest{}, "QueryString"))
	if diff != "" {
		t.Error(diff)
	}
}
