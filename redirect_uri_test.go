package oauth2server_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestValidateRedirectURI_UsesInterfaceIfDefinedAndReturnsNoErrorIfValidates(t *testing.T) {
	redirectUri := "http://example.com"
	client := &SpyClient{}
	client.validRedirectURIReturn = true

	err := oauth2server.ValidateRedirectURI(context.Background(), client, redirectUri)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if len(client.validRedirectURICalls) != 1 {
		t.Fatalf("expected one ValidRedirectURI call, got %d", len(client.validRedirectURICalls))
	}
	if client.validRedirectURICalls[0] != redirectUri {
		t.Errorf("expected ValidRedirectURI to have been called with %q, got %q", redirectUri, client.validRedirectURICalls[0])
	}
}

func TestValidateRedirectURI_UsesInterfaceIfDefinedAndReturnsErrorIfValidateReturnsFalse(t *testing.T) {
	redirectUri := "http://example.com"
	client := &SpyClient{}
	client.validRedirectURIReturn = false

	err := oauth2server.ValidateRedirectURI(context.Background(), client, redirectUri)

	if len(client.validRedirectURICalls) != 1 {
		t.Fatalf("expected one ValidRedirectURI call, got %d", len(client.validRedirectURICalls))
	}
	if client.validRedirectURICalls[0] != redirectUri {
		t.Errorf("expected ValidRedirectURI to have been called with %q, got %q", redirectUri, client.validRedirectURICalls[0])
	}
	if !errors.Is(err, oauth2server.ErrClientInvalidRedirectURI) {
		t.Errorf("expected ErrClientInvalidRedirectURI, got %v", err)
	}
}

func TestValidateRedirectURI_FallsBackToDefaultValidatorIfPresent(t *testing.T) {
	redirectUri := "http://example.com"
	client := oauth2server.NewPublicSimpleClient("clientid", []string{redirectUri})

	err := oauth2server.ValidateRedirectURI(context.Background(), client, "")

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestDefaultRedirectURIValidation_ErrorsIfClientHasNoRedirectURIs(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{})

	err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "ignored")

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if !errors.Is(err, oauth2server.ErrClientHasNoRedirectURIs) {
		t.Errorf("expected ErrClientHasNoRedirectURIs, got %v", err)
	}
}

func TestDefaultRedirectURIValidation_ErrorsIfClientMultipleRedirectURIsAndOneIsNotSupplied(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one", "two"})

	err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "")

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if !errors.Is(err, oauth2server.ErrClientRequiresRedirectURI) {
		t.Errorf("expected ErrClientRequiresRedirectURI, got %v", err)
	}
}

func TestDefaultRedirectURIValidation_ErrorsIfRedirectURIDoesNotMatch(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one", "two"})

	err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "three")

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if !errors.Is(err, oauth2server.ErrClientInvalidRedirectURI) {
		t.Errorf("expected ErrClientInvalidRedirectURI, got %v", err)
	}
}

func TestDefaultRedirectURIValidation_ValidatesIfRedirectURIMatches(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one", "two"})

	err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "one")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestDefaultRedirectURIValidation_ValidatesIfNoRedirectURISuppliedAndClientHasOnlyOneREdirectURI(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one"})

	err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}
