package oauth2server_test

import (
	"context"
)

type SpyClient struct {
	id           string
	secret       string
	redirectUris []string
	confidential bool

	validRedirectURICalls  []string
	validRedirectURIReturn bool
}

func (c *SpyClient) ID() string {
	return c.id
}

func (c *SpyClient) Secret() string {
	return c.secret
}

func (c *SpyClient) RedirectURIs() []string {
	return c.redirectUris
}

func (c *SpyClient) IsConfidential() bool {
	return c.confidential
}

func (c *SpyClient) ValidRedirectURI(ctx context.Context, redirectUri string) bool {
	c.validRedirectURICalls = append(c.validRedirectURICalls, redirectUri)
	return c.validRedirectURIReturn
}
