package oauth2server

import (
	"encoding/json"
	"net/http"
)

func jsonResponse(w http.ResponseWriter, statusCode int, body any) error {
	w.Header().Set("Content-Type", "application/json; charset=UTF-8")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(statusCode)

	encoder := json.NewEncoder(w)
	return encoder.Encode(body)
}

// send the error response. This is would be appropriate to use for an access
// token response, but not for an auth code response.
func RespondWithError(w http.ResponseWriter, e OAuthError) error {
	statusCode := e.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusBadRequest
	}

	return jsonResponse(w, statusCode, e)
}

func ResponseWithAccessToken(w http.ResponseWriter, token *AccessTokenResponse) error {
	return jsonResponse(w, 200, token)
}
