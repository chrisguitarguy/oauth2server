package oauth2server_test

import (
	"context"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

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

func TestDefaultAuthorizationServer_ReturnsAccessDeniedErrorFromDenyAuthorizationRequest(t *testing.T) {
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
