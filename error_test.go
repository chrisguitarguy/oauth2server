package oauth2server_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestOAuthError_OnlyReturnsErrorTypeIfDescriptionIsNotSet(t *testing.T) {
	err := &oauth2server.OAuthError{
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
	err := &oauth2server.OAuthError{
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
	err := &oauth2server.OAuthError{
		ErrorType: oauth2server.ErrorTypeServerError,
		Cause:     cause,
	}

	if !errors.Is(err, cause) {
		t.Error("Expected OAuthError to be `errors.Is(...)` of the cause")
	}
}

func TestOAuthError_IncludesCauseInErrorMessageIfPresent(t *testing.T) {
	cause := errors.New("oh noz")
	err := &oauth2server.OAuthError{
		ErrorType: oauth2server.ErrorTypeServerError,
		Cause:     cause,
	}

	if !strings.Contains(err.Error(), "oh noz") {
		t.Errorf("Expected oauth error to contain error message from cause, got %q", err.Error())
	}
}

func TestMaybeWrapError_ReturnsNilIfCauseIsNil(t *testing.T) {
	err := oauth2server.MaybeWrapError(nil)

	if err != nil {
		t.Errorf("nil errors should not be wrapped")
	}
}

func TestMaybeWrapError_ReturnsProvidedErrorIfAlreadyAnOAuthError(t *testing.T) {
	cause := &oauth2server.OAuthError{}

	err := oauth2server.MaybeWrapError(cause)

	if err != cause {
		t.Errorf("Should not wrap things that are already oauth errors: %#v != %#v", cause, err)
	}
}

func TestMaybeWrapError_WrapsGenericErrorWithServerErrors(t *testing.T) {
	cause := errors.New("ope")

	err := oauth2server.MaybeWrapError(cause)

	if err == nil {
		t.Fatal("error should not be nil")
	}
	if err.ErrorType != oauth2server.ErrorTypeServerError {
		t.Errorf("expected error type to be %q, got %q", oauth2server.ErrorTypeServerError, err.ErrorType)
	}
	if !errors.Is(err, cause) {
		t.Errorf("OAuthErrors should wrap the cause: %#v", err)
	}
}
