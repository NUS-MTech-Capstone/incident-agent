package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPISpecServed(t *testing.T) {
	server := New(nil)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/openapi.yaml", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.Contains(contentType, "application/yaml") {
		t.Fatalf("content-type = %q", contentType)
	}
	if body := response.Body.String(); !strings.Contains(body, "openapi: 3.1.0") || !strings.Contains(body, "DenDenMushi Incident Agent API") {
		t.Fatalf("unexpected spec body: %q", body)
	}
}
