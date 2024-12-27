package oauth2server_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
)

func createRequestWithFormBody(method string, uri string, body map[string]string) *http.Request {
	vals := url.Values{}
	for k, v := range body {
		vals.Set(k, v)
	}

	req := httptest.NewRequest(method, uri, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req
}
