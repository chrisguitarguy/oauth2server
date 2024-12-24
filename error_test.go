package oauth2server_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestOAuthError_OnlyReturnsErrorTypeIfDescriptionIsNotSet(t *testing.T) {
	err := oauth2server.OAuthError{
		ErrorType: oauth2server.ErrorTypeServerError,
	}

	if err.Error() != oauth2server.ErrorTypeServerError {
		t.Errorf(
			"expected error to return only error type: %q != %q",
			oauth2server.ErrorTypeServerError,
			err.Error(),
		)
	}
}

func TestOAuthError_IncludedErrorDescriptionIfPresent(t *testing.T) {
	err := oauth2server.OAuthError{
		ErrorType:        oauth2server.ErrorTypeServerError,
		ErrorDescription: "ope",
	}

	if !strings.Contains(err.Error(), oauth2server.ErrorTypeServerError) {
		t.Errorf(
			"expected error message to contain error type %q, got %q",
			oauth2server.ErrorTypeServerError,
			err.Error(),
		)
	}
	if !strings.Contains(err.Error(), "ope") {
		t.Errorf(
			`expected error message to contain error description "ope", got %q`,
			err.Error(),
		)
	}
}

func TestOAuthError_CanBeCausedByOtherErrors(t *testing.T) {
	cause := errors.New("oh noz")
	err := oauth2server.OAuthError{
		ErrorType: oauth2server.ErrorTypeServerError,
		Cause:     cause,
	}

	if !errors.Is(err, cause) {
		t.Error("Expected OAuthError to be `errors.Is(...)` of the cause")
	}
}
