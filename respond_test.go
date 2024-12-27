package oauth2server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/chrisguitarguy/oauth2server"
)

func TestRespondWithError_SendsJsonResponse(t *testing.T) {
	oauthErr := oauth2server.OAuthError{
		ErrorType:        oauth2server.ErrorTypeServerError,
		ErrorDescription: "oh noz",
		ErrorURI:         "https://example.com/error",
	}
	rec := httptest.NewRecorder()

	err := oauth2server.RespondWithError(rec, oauthErr)

	if err != nil {
		t.Fatalf("Unexpected error sending response: %v", err)
	}

	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Fatalf("expected a JSON response: %q", ct)
	}

	var sentErr oauth2server.OAuthError
	if err := json.Unmarshal(rec.Body.Bytes(), &sentErr); err != nil {
		t.Fatalf("unexpected error decoding response body: %v", err)
	}

	if sentErr != oauthErr {
		t.Errorf("%#v != %#v", oauthErr, sentErr)
	}
}

func TestRespondWithError_UsesBadRequestForDefaultStatusCode(t *testing.T) {
	oauthErr := oauth2server.OAuthError{
		ErrorType:        oauth2server.ErrorTypeServerError,
		ErrorDescription: "oh noz",
		ErrorURI:         "https://example.com/error",
	}
	rec := httptest.NewRecorder()

	err := oauth2server.RespondWithError(rec, oauthErr)

	if err != nil {
		t.Fatalf("Unexpected error sending response: %v", err)
	}

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected a %d response, got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestRespondWithError_UsesErrorCodeIfSupplied(t *testing.T) {
	oauthErr := oauth2server.OAuthError{
		StatusCode: http.StatusUnauthorized,
		ErrorType:  oauth2server.ErrorTypeServerError,
	}
	rec := httptest.NewRecorder()

	err := oauth2server.RespondWithError(rec, oauthErr)

	if err != nil {
		t.Fatalf("Unexpected error sending response: %v", err)
	}

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected a %d response, got %d", http.StatusUnauthorized, rec.Code)
	}
}
