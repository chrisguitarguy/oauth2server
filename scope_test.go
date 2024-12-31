package oauth2server_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestAllowAllScopes_AllowsAnyScope(t *testing.T) {
	validator := oauth2server.AllowAllScopes()

	err := validator.ValidateScopes(context.Background(), []string{"one", "two"})

	if err != nil {
		t.Errorf("All scopes should be allowed, got %v", err)
	}
}

func TestAllowScopes_DoesNotErrorIfOnlyAllowedScopesArePassed(t *testing.T) {
	validator := oauth2server.AllowScopes("one", "two")

	err := validator.ValidateScopes(context.Background(), []string{"one", "two"})

	if err != nil {
		t.Errorf("passed scopes should be allowed, got %v", err)
	}
}

func TestAllowScopes_ReturnsErrorIfInvalidScopesArePassed(t *testing.T) {
	validator := oauth2server.AllowScopes("one", "two")

	err := validator.ValidateScopes(context.Background(), []string{"invalid", "two"})

	if err == nil {
		t.Fatal("invalid scopes should have caused error, got nil")
	}
	oauthErr, ok := oauth2server.AsOAuthError(err)
	if !ok {
		t.Fatalf("Expected an oauth error, got %T", err)
	}
	if oauthErr.ErrorType != oauth2server.ErrorTypeInvalidScope {
		t.Errorf("expected %q error type, got %q", oauth2server.ErrorTypeInvalidScope, oauthErr.ErrorType)
	}
	if !strings.Contains(oauthErr.ErrorDescription, "invalid") {
		t.Errorf("error description should contain invalid scope, got %q", oauthErr.ErrorDescription)
	}
}
