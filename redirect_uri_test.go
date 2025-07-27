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

	final, err := oauth2server.ValidateRedirectURI(context.Background(), client, redirectUri)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if len(client.validRedirectURICalls) != 1 {
		t.Fatalf("expected one ValidRedirectURI call, got %d", len(client.validRedirectURICalls))
	}
	if client.validRedirectURICalls[0] != redirectUri {
		t.Errorf("expected ValidRedirectURI to have been called with %q, got %q", redirectUri, client.validRedirectURICalls[0])
	}
	if final != redirectUri {
		t.Errorf("Should not have modified the redirect uri: %q != %q", final, redirectUri)
	}

}

func TestValidateRedirectURI_UsesInterfaceIfDefinedAndReturnsModifedRedirectURIIfPresent(t *testing.T) {
	redirectUri := "http://example.com"
	changedUri := "http://example.com/changed"
	client := &SpyClient{}
	client.validRedirectURIReturn = true
	client.validRedirectURIFinal = changedUri

	final, err := oauth2server.ValidateRedirectURI(context.Background(), client, redirectUri)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if len(client.validRedirectURICalls) != 1 {
		t.Fatalf("expected one ValidRedirectURI call, got %d", len(client.validRedirectURICalls))
	}
	if client.validRedirectURICalls[0] != redirectUri {
		t.Errorf("expected ValidRedirectURI to have been called with %q, got %q", redirectUri, client.validRedirectURICalls[0])
	}
	if final != changedUri {
		t.Errorf("Should have returned the modified redirect uri: %q != %q", final, changedUri)
	}

}

func TestValidateRedirectURI_UsesInterfaceIfDefinedAndReturnsErrorIfValidateReturnsFalse(t *testing.T) {
	redirectUri := "http://example.com"
	client := &SpyClient{}
	client.validRedirectURIReturn = false

	final, err := oauth2server.ValidateRedirectURI(context.Background(), client, redirectUri)

	if len(client.validRedirectURICalls) != 1 {
		t.Fatalf("expected one ValidRedirectURI call, got %d", len(client.validRedirectURICalls))
	}
	if client.validRedirectURICalls[0] != redirectUri {
		t.Errorf("expected ValidRedirectURI to have been called with %q, got %q", redirectUri, client.validRedirectURICalls[0])
	}
	if !errors.Is(err, oauth2server.ErrClientInvalidRedirectURI) {
		t.Errorf("expected ErrClientInvalidRedirectURI, got %v", err)
	}
	if final != "" {
		t.Errorf("Redirect uri should be empty, got %q", final)
	}
}

func TestValidateRedirectURI_FallsBackToDefaultValidatorIfPresent(t *testing.T) {
	redirectUri := "http://example.com"
	client := oauth2server.NewPublicSimpleClient("clientid", []string{redirectUri})

	final, err := oauth2server.ValidateRedirectURI(context.Background(), client, "")

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	if final != redirectUri {
		t.Errorf("final redirect uri, got=%q, want=%q", final, redirectUri)
	}
}

func TestDefaultRedirectURIValidation_ErrorsIfClientHasNoRedirectURIs(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{})

	final, err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "ignored")

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if !errors.Is(err, oauth2server.ErrClientHasNoRedirectURIs) {
		t.Errorf("expected ErrClientHasNoRedirectURIs, got %v", err)
	}
	if final != "" {
		t.Errorf("Expected empty redirect uri, got=%q", final)
	}
}

func TestDefaultRedirectURIValidation_ErrorsIfClientMultipleRedirectURIsAndOneIsNotSupplied(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one", "two"})

	final, err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "")

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if !errors.Is(err, oauth2server.ErrClientRequiresRedirectURI) {
		t.Errorf("expected ErrClientRequiresRedirectURI, got %v", err)
	}
	if final != "" {
		t.Errorf("Expected empty redirect uri, got=%q", final)
	}
}

func TestDefaultRedirectURIValidation_ErrorsIfRedirectURIDoesNotMatch(t *testing.T) {
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one", "two"})

	final, err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "three")

	if err == nil {
		t.Fatal("expected an error, but got nil")
	}
	if !errors.Is(err, oauth2server.ErrClientInvalidRedirectURI) {
		t.Errorf("expected ErrClientInvalidRedirectURI, got %v", err)
	}
	if final != "" {
		t.Errorf("Expected empty redirect uri, got=%q", final)
	}
}

func TestDefaultRedirectURIValidation_ValidatesIfRedirectURIMatches(t *testing.T) {
	redirectUri := "https://example.com/whatever"
	client := oauth2server.NewPublicSimpleClient("clientid", []string{"one", redirectUri})

	final, err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, redirectUri)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if final != redirectUri {
		t.Errorf("redirect uri, got=%q, want=%q", final, redirectUri)
	}
}

func TestDefaultRedirectURIValidation_ValidatesIfNoRedirectURISuppliedAndClientHasOnlyOneREdirectURI(t *testing.T) {
	redirectUri := "http://example.com"
	client := oauth2server.NewPublicSimpleClient("clientid", []string{redirectUri})

	final, err := oauth2server.DefaultRedirectURIValidation(context.Background(), client, "")

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if final != redirectUri {
		t.Errorf("expected first redirect uri from client, got=%q, want=%q", final, redirectUri)
	}
}
