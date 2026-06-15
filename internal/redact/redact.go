package redact

import (
	"regexp"
	"strings"
)

var patterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/-]+=*`),
	regexp.MustCompile(`(?i)(password|passwd|secret|token|private[_-]?key)\s*[:=]\s*\S+`),
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
}

func Text(value string, limit int) string {
	for _, pattern := range patterns {
		value = pattern.ReplaceAllString(value, "[REDACTED]")
	}
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r >= 0x20 {
			return r
		}
		return -1
	}, value)
	if limit > 0 && len(value) > limit {
		value = value[:limit] + "\n[truncated]\n"
	}
	return value
}
