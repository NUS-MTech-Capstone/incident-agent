package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestSameOriginRejectsCrossSiteDecision(t *testing.T) {
	request := httptest.NewRequest("POST", "https://api.ddm.keiyam.me/incidents/1/approve", nil)
	request.Host = "api.ddm.keiyam.me"
	request.Header.Set("Origin", "https://evil.example")
	if sameOrigin(request) {
		t.Fatal("sameOrigin accepted a cross-site request")
	}
	request.Header.Set("Origin", "https://api.ddm.keiyam.me")
	if !sameOrigin(request) {
		t.Fatal("sameOrigin rejected the application origin")
	}
}
