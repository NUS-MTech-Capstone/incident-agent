package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsSecretsAndBoundsOutput(t *testing.T) {
	got := Text("Authorization: Bearer abc.def\npassword=hunter2\n"+strings.Repeat("x", 100), 80)
	if strings.Contains(got, "abc.def") || strings.Contains(got, "hunter2") {
		t.Fatalf("secret remained in output: %q", got)
	}
	if !strings.Contains(got, "[truncated]") {
		t.Fatalf("output was not truncated: %q", got)
	}
}
