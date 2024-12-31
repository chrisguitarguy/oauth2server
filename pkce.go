package oauth2server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

// implement "proof key code exchange" for oauth2, see
// https://datatracker.ietf.org/doc/html/rfc7636
// the TL;DR of that is that a code challenge + method coes in with an authorization
// request and is stored with the authorization code. Then when the authorization
// code is used the client sends a "code verifier" which is then used with the method
// to re-compute the challenge.
type PKCE interface {
	// Check to see if the incomign challenge method is supported
	SupportsChallengeMethod(method string) bool

	// verify the code challenge.
	VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error)
}

type defaultPKCE struct {
}

func NewDefaultPKCE() PKCE {
	return &defaultPKCE{}
}

func (p *defaultPKCE) SupportsChallengeMethod(method string) bool {
	return method == CodeChallengeMethodPlain || method == CodeChallengeMethodS256
}

func (p *defaultPKCE) VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error) {
	expectedChallenge, err := p.computeChallenge(method, verifier)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare([]byte(expectedChallenge), []byte(challenge)) == 1, nil
}

func (p *defaultPKCE) computeChallenge(method string, verifier string) (string, error) {
	if method == CodeChallengeMethodPlain {
		return verifier, nil
	}

	if method != CodeChallengeMethodS256 {
		return "", fmt.Errorf("%w: %s", ErrUnsupportedCodeChallengeMethod, method)
	}

	raw := sha256.Sum256([]byte(verifier))

	return base64.URLEncoding.EncodeToString(raw[:]), nil
}
