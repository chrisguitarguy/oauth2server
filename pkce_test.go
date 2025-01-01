package oauth2server_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestPlainPKCE_VerifyCodeChallenge_ErrorsWithOtherMethods(t *testing.T) {
	pk := oauth2server.NewPlainPKCE()

	_, err := pk.VerifyCodeChallenge(context.Background(), "badmethod", "challenge", "verifier")

	if err == nil {
		t.Fatalf("expected an error")
	}
	if !errors.Is(err, oauth2server.ErrUnsupportedCodeChallengeMethod) {
		t.Errorf("expected ErrUnsupportedCodeChallengeMethod, got %v", err)
	}
}

func TestS256PKCE_VerifyCodeChallenge_ErrorsWithOtherMethods(t *testing.T) {
	pk := oauth2server.NewS256PKCE()

	_, err := pk.VerifyCodeChallenge(context.Background(), "badmethod", "challenge", "verifier")

	if err == nil {
		t.Fatalf("expected an error")
	}
	if !errors.Is(err, oauth2server.ErrUnsupportedCodeChallengeMethod) {
		t.Errorf("expected ErrUnsupportedCodeChallengeMethod, got %v", err)
	}
}

func TestDefaultPKCE_SupportsKnownMethods(t *testing.T) {
	pk := oauth2server.NewDefaultPKCE()

	for _, method := range []string{oauth2server.CodeChallengeMethodPlain, oauth2server.CodeChallengeMethodS256} {
		t.Run(method, func(t *testing.T) {
			methods := pk.ChallengeMethods()

			if !slices.Contains(methods, method) {
				t.Errorf("expected default pkce to support %q", method)
			}
		})
	}
}

func TestDefaultPKCE_VerifyCodeChallenge_ErrorsIfInvalidChallengeMethodIsPassed(t *testing.T) {
	pk := oauth2server.NewDefaultPKCE()

	_, err := pk.VerifyCodeChallenge(context.Background(), "badmethod", "challenge", "verifier")

	if err == nil {
		t.Fatal("expected error from unknown method")
	}
	if !errors.Is(err, oauth2server.ErrUnsupportedCodeChallengeMethod) {
		t.Errorf("expected ErrUnsupportedCodeChallengeMethod, got %v", err)
	}
}

func TestDefaultPKCE_VerifyCodeChallenge_WithPlainValidatesIfVerififierMatches(t *testing.T) {
	pk := oauth2server.NewDefaultPKCE()
	challenge := "challenge"
	verifier := challenge

	ok, err := pk.VerifyCodeChallenge(
		context.Background(),
		oauth2server.CodeChallengeMethodPlain,
		challenge,
		verifier,
	)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected challenge to be verified")
	}
}

func TestDefaultPKCE_VerifyCodeChallenge_WithPlainDoesNotValidateIfVerifierDoesNotMatch(t *testing.T) {
	pk := oauth2server.NewDefaultPKCE()
	challenge := "challenge"
	verifier := "not correct"

	ok, err := pk.VerifyCodeChallenge(
		context.Background(),
		oauth2server.CodeChallengeMethodPlain,
		challenge,
		verifier,
	)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected challenge would not be verified")
	}
}

func TestDefaultPKCE_VerifyCodeChallenge_WithS256ValidatesIfVerifierMatches(t *testing.T) {
	pk := oauth2server.NewDefaultPKCE()
	challenge := "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg"
	verifier := "test"

	ok, err := pk.VerifyCodeChallenge(
		context.Background(),
		oauth2server.CodeChallengeMethodS256,
		challenge,
		verifier,
	)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !ok {
		t.Error("expected challenge to be verified")
	}
}

func TestDefaultPKCE_VerifyCodeChallenge_WithS256DoesNotValidateIfVerifierDoesNotMatch(t *testing.T) {
	pk := oauth2server.NewDefaultPKCE()
	challenge := "n4bQgYhMfWWaL-qgxVrQFaO_TxsrC4Is0V1sFbDwCgg="
	verifier := "notcorrect"

	ok, err := pk.VerifyCodeChallenge(
		context.Background(),
		oauth2server.CodeChallengeMethodS256,
		challenge,
		verifier,
	)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected challenge not to be verified")
	}
}

func TestNewDefaultPKCE_IncludesExtraMethodsIfSupplied(t *testing.T) {
	stub := &spyPKCE{
		methods: []string{"test"},
	}

	pk := oauth2server.NewDefaultPKCE(stub)

	if !slices.Contains(pk.ChallengeMethods(), "test") {
		t.Errorf("expected challenge method from extra PKCE passed in")
	}
}
