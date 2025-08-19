package oauth2server_test

import (
	"context"

	"github.com/chrisguitarguy/oauth2server"
)

type SpyClient struct {
	id           string
	secret       string
	redirectUris []string
	confidential bool

	validRedirectURICalls  []string
	validRedirectURIReturn bool
	validRedirectURIFinal  string

	allowsResponseTypeCalls  [][]string
	allowsResponseTypeReturn bool
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

func (c *SpyClient) ValidRedirectURI(ctx context.Context, redirectUri string) (string, bool) {
	c.validRedirectURICalls = append(c.validRedirectURICalls, redirectUri)
	return c.validRedirectURIFinal, c.validRedirectURIReturn
}

func (c *SpyClient) AllowsResponseType(responseTypes []string) bool {
	c.allowsResponseTypeCalls = append(c.allowsResponseTypeCalls, responseTypes)
	return c.allowsResponseTypeReturn
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

type validateAuthorizationRequestCall struct {
	client oauth2server.Client
	req    *oauth2server.AuthorizationRequest
}

type spyAuthorizationHandler struct {
	responseType string

	validateAuthorizationRequestCalls []validateAuthorizationRequestCall
	validateAuthorizationRequestError error
}

func (s *spyAuthorizationHandler) ResponseType() string {
	return s.responseType
}

func (s *spyAuthorizationHandler) ValidateAuthorizationRequest(
	ctx context.Context,
	client oauth2server.Client,
	req *oauth2server.AuthorizationRequest,
) error {
	s.validateAuthorizationRequestCalls = append(
		s.validateAuthorizationRequestCalls,
		validateAuthorizationRequestCall{
			client: client,
			req:    req,
		},
	)

	return s.validateAuthorizationRequestError
}

func (s *spyAuthorizationHandler) IssueAuthorizationResponse(
	ctx context.Context,
	client oauth2server.Client,
	req *oauth2server.AuthorizationRequest,
	user oauth2server.User,
) (string, error) {
	return "", nil // TODO
}
