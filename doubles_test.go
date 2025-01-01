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

type spyPKCEVerifyCall struct {
	method    string
	challenge string
	verifier  string
}

type spyPKCE struct {
	methods      []string
	verifyReturn bool
	verifyError  error
	verifyCalls  []spyPKCEVerifyCall
}

func (p *spyPKCE) ChallengeMethods() []string {
	return p.methods
}

func (p *spyPKCE) VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error) {
	p.verifyCalls = append(p.verifyCalls, spyPKCEVerifyCall{
		method:    method,
		challenge: challenge,
		verifier:  verifier,
	})

	return p.verifyReturn, p.verifyError
}
