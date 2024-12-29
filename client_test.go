package oauth2server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestNewSimpleClient_ReturnsConfidentialClient(t *testing.T) {
	c := oauth2server.NewSimpleClient("id", "secret", []string{
		"http://example.com",
	})

	if c.ID() != "id" {
		t.Errorf(`bad id: "id" != %q`, c.ID())
	}
	if c.Secret() != "secret" {
		t.Errorf(`bad secret: "secret" != %q`, c.Secret())
	}
	if !c.IsConfidential() {
		t.Errorf("expected client to be confidential: %#v", c.IsConfidential())
	}
	if len(c.RedirectURIs()) != 1 {
		t.Errorf("should have one redirect URI got %d", len(c.RedirectURIs()))
	}
	if c.RedirectURIs()[0] != "http://example.com" {
		t.Errorf(`bad redirect URI: %q != "http://example.com"`, c.RedirectURIs()[0])
	}
}

func TestNewPublicSimpleClient_ReturnsPublicClient(t *testing.T) {
	c := oauth2server.NewPublicSimpleClient("id", []string{
		"http://example.com",
	})

	if c.ID() != "id" {
		t.Errorf(`bad id: "id" != %q`, c.ID())
	}
	if c.Secret() != "" {
		t.Errorf(`bad secret, public clients should not have a secret: %q`, c.Secret())
	}
	if c.IsConfidential() {
		t.Errorf("expected client to be public: %#v", c.IsConfidential())
	}
	if len(c.RedirectURIs()) != 1 {
		t.Errorf("should have one redirect URI got %d", len(c.RedirectURIs()))
	}
	if c.RedirectURIs()[0] != "http://example.com" {
		t.Errorf(`bad redirect URI: %q != "http://example.com"`, c.RedirectURIs()[0])
	}
}

func TestInMemoryClientRepository_ClientsCanBeManagedInMemory(t *testing.T) {
	r := oauth2server.NewInMemoryClientRepository()
	clientId := "clientid"
	expectedErr := errors.New("ope")
	expectedClient := oauth2server.NewPublicSimpleClient(clientId, []string{
		"https://example.com",
	})

	client, err := r.Get(context.Background(), clientId)
	if client != nil {
		t.Errorf("expected client to be nil, got %+v", client)
	}
	if err != nil {
		t.Errorf("expected error to be nil, got %+v", err)
	}

	r.Add(expectedClient)
	r.AddError(clientId, expectedErr)

	client, err = r.Get(context.Background(), clientId)
	if client != expectedClient {
		t.Errorf("bad client: %+v != %+v", client, expectedClient)
	}
	if err != expectedErr {
		t.Errorf("bad error: %+v != %+v", err, expectedErr)
	}

	r.Remove(clientId)
	r.RemoveError(clientId)

	client, err = r.Get(context.Background(), clientId)
	if client != nil {
		t.Errorf("expected client to be nil after remove, got %+v", client)
	}
	if err != nil {
		t.Errorf("expected error to be nil after remove, got %+v", err)
	}
}