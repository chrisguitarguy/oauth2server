package oauth2server

import (
	"context"
	"slices"
)

// first checks to see if the client implements its own redirect URI validation
// and if not runs it through the default validation.
func ValidateRedirectURI(ctx context.Context, client Client, redirectUri string) *OAuthError {
	// allow the implementation to hook in first before any subsequent validation
	// that means the implementation must also correctly handle empty strings
	if validates, ok := client.(ClientValidatesRedirectURI); ok {
		if validates.ValidRedirectURI(ctx, redirectUri) {
			return nil
		}

		return InvalidClientWithCause(ErrClientInvalidRedirectURI, "%s is not a valid %s", redirectUri, ParamRedirectURI)
	}

	return DefaultRedirectURIValidation(ctx, client, redirectUri)
}

// default redirect URI validation, which requires at least one redirect URI
func DefaultRedirectURIValidation(ctx context.Context, client Client, redirectUri string) *OAuthError {
	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.2
	// says that authorization servers SHOULD allow clients to register
	// redirect URIs, this turns that into a MUST
	if len(client.RedirectURIs()) < 1 {
		return InvalidClientWithCause(ErrClientHasNoRedirectURIs, "client %s does not have any registered redirect URIs", client.ID())
	}

	// https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3
	// if multiple redirect URIs are registered, then the redirect_uri MUST
	// be included in the request.
	if redirectUri == "" && len(client.RedirectURIs()) > 1 {
		return MissingRequestParameterWithCause(ErrClientRequiresRedirectURI, ParamRedirectURI)
	}

	// empty redirect URIs are allow for allowed if a client only has a single redirect URI
	if redirectUri == "" {
		return nil
	}

	// otherwise, per https://datatracker.ietf.org/doc/html/rfc6749#section-3.1.2.3
	// simple string comparison should be used to compare redirect URIs. Note that
	// this server does not support partial URIs as allowed in the spec, use custom
	// validation for that.
	if slices.Contains(client.RedirectURIs(), redirectUri) {
		return nil
	}

	return InvalidClientWithCause(ErrClientInvalidRedirectURI, "%s is not a valid %s", redirectUri, ParamRedirectURI)
}
