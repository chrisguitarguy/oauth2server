package oauth2server

import (
	"strings"
)

const (
	ParamClientID            = "client_id"
	ParamClientSecret        = "client_secret"
	ParamGrantType           = "grant_type"
	ParamRedirectURI         = "redirect_uri"
	ParamState               = "state"
	ParamScope               = "scope"
	ParamCodeChallenge       = "code_challenge"
	ParamCodeChallengeMethod = "code_challenge_method"
	ParamCodeVerifier        = "code_verifier"
	ParamResponseType        = "response_type"

	spaceSeparator = " "
)

func ParseSpaceSeparatedParameter(rawValue string) []string {
	trimmed := strings.TrimSpace(rawValue)
	if trimmed == "" {
		return nil
	}

	parts := strings.Split(trimmed, spaceSeparator)

	out := []string{}
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}
