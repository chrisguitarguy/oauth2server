package oauth2server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"maps"
	"slices"
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
	ChallengeMethods() []string

	// verify the code challenge. how that happens depends on the method.
	VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error)
}

func constantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

type plainPKCE struct {
}

func NewPlainPKCE() PKCE {
	return &plainPKCE{}
}

func (p *plainPKCE) ChallengeMethods() []string {
	return []string{CodeChallengeMethodPlain}
}

func (p *plainPKCE) VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error) {
	if method != CodeChallengeMethodPlain {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedCodeChallengeMethod, method)
	}

	return constantTimeCompare(verifier, challenge), nil
}

type s256PKCE struct {
}

func NewS256PKCE() PKCE {
	return &s256PKCE{}
}

func (p *s256PKCE) ChallengeMethods() []string {
	return []string{CodeChallengeMethodS256}
}

func (p *s256PKCE) VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error) {
	if method != CodeChallengeMethodS256 {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedCodeChallengeMethod, method)
	}

	rawVerifierHash := sha256.Sum256([]byte(verifier))
	expectedVerifier := base64.URLEncoding.EncodeToString(rawVerifierHash[:])

	return constantTimeCompare(expectedVerifier, challenge), nil
}

type compositePKCE struct {
	methods map[string]PKCE
}

func NewDefaultPKCE(extra ...PKCE) PKCE {
	methods := map[string]PKCE{}

	plain := NewPlainPKCE()
	for _, method := range plain.ChallengeMethods() {
		methods[method] = plain
	}

	s256 := NewS256PKCE()
	for _, method := range s256.ChallengeMethods() {
		methods[method] = s256
	}

	for _, pkce := range extra {
		for _, method := range pkce.ChallengeMethods() {
			methods[method] = pkce
		}
	}

	return &compositePKCE{
		methods: methods,
	}
}

func (p *compositePKCE) ChallengeMethods() []string {
	return slices.Collect(maps.Keys(p.methods))
}

func (p *compositePKCE) VerifyCodeChallenge(ctx context.Context, method string, challenge string, verifier string) (bool, error) {
	pkce, ok := p.methods[method]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnsupportedCodeChallengeMethod, method)
	}

	return pkce.VerifyCodeChallenge(ctx, method, challenge, verifier)
}
