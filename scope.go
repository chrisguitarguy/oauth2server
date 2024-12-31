package oauth2server

import (
	"context"
)

// rather than having scopes be an "entity" this is the extension point that
// allows validating of scope identifiers pass in from requests.
type ScopeValidator interface {
	// Check the incoming scopes and return any that are invalid, this should
	// return an invalid_scope error if any scope is inavlid. Any other, non
	// OAuthError returned will be tramsformed to a server_error
	ValidateScopes(ctx context.Context, scopes []string) error
}

type allScopesValidator struct {
}

func AllowAllScopes() ScopeValidator {
	return &allScopesValidator{}
}

func (v *allScopesValidator) ValidateScopes(ctx context.Context, scopes []string) error {
	return nil
}

type allowedScopeValidator struct {
	scopes map[string]bool
}

func AllowScopes(scopes ...string) ScopeValidator {
	s := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		s[scope] = true
	}

	return &allowedScopeValidator{
		scopes: s,
	}
}

func (v *allowedScopeValidator) ValidateScopes(ctx context.Context, scopes []string) error {
	var invalidScopes []string
	for _, s := range scopes {
		if _, ok := v.scopes[s]; !ok {
			invalidScopes = append(invalidScopes, s)
		}
	}

	if len(invalidScopes) > 0 {
		return InvalidScope(invalidScopes)
	}

	return nil
}
