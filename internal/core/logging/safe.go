// Package logging provides shared helpers for safe structured logging.
package logging

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"unicode"
)

const redactedValue = "[REDACTED]"

var (
	emailPattern         = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	urlPattern           = regexp.MustCompile(`(?i)https?://\S+`)
	uuidPattern          = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
	longOpaquePattern    = regexp.MustCompile(`\b[A-Za-z0-9_-]{24,}\b`)
	secretAssignmentExpr = regexp.MustCompile(`(?i)\b(password|pin|token|secret|key|auth|code|session|payload|envelope)=\S+`)
)

var sensitiveKeyWords = []string{
	"password",
	"pin",
	"token",
	"secret",
	"key",
	"auth",
	"ciphertext",
	// Intentionally broad: this app handles 2FA/recovery codes, so generic
	// code fields are redacted even though status_code/error_code would be safe.
	"code",
	"2fa",
	"session",
	"payload",
	"clipboard",
	"envelope",
}

// ShouldRedactKey reports whether key names a secret-like logging field.
//
// Sensitive words must appear as separated words, where boundaries are the
// start/end of the key or any non-letter/non-digit separator. This redacts keys
// such as "master_password" and "access-token" without over-redacting keys like
// "monkey" or "auth0_domain".
func ShouldRedactKey(key string) bool {
	lower := strings.ToLower(key)
	for _, word := range sensitiveKeyWords {
		if containsSeparatedWord(lower, word) {
			return true
		}
	}
	return false
}

// SafeValue returns a logging-safe representation of value for key.
//
// Values for secret-like keys are redacted. Error values are converted to a
// coarse error kind so raw error text is never logged by this helper.
func SafeValue(key string, value any) any {
	if ShouldRedactKey(key) {
		return redactedValue
	}
	if err, ok := value.(error); ok {
		return SafeErrorKind(err)
	}
	return value
}

// SafeErrorDetail returns sanitized diagnostic text for err.
//
// It is intended for debug logs where a coarse kind is not enough. It redacts
// common PII/secrets and bounds the output so UI code can log useful backend
// details without exposing raw credentials, 2FA codes, emails, or token-like
// fields.
func SafeErrorDetail(err error) string {
	if err == nil {
		return ""
	}
	detail := err.Error()
	detail = emailPattern.ReplaceAllString(detail, redactedValue)
	detail = urlPattern.ReplaceAllString(detail, redactedValue)
	detail = uuidPattern.ReplaceAllString(detail, redactedValue)
	detail = longOpaquePattern.ReplaceAllString(detail, redactedValue)
	detail = secretAssignmentExpr.ReplaceAllString(detail, "$1="+redactedValue)
	const maxErrorDetailRunes = 512
	if runes := []rune(detail); len(runes) > maxErrorDetailRunes {
		detail = string(runes[:maxErrorDetailRunes]) + "…"
	}
	return detail
}

// SafeErrorKind returns a logging-safe category for err without exposing the
// raw error text.
func SafeErrorKind(err error) string {
	switch {
	case err == nil:
		return "none"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "error"
	}
}

func containsSeparatedWord(key, word string) bool {
	keyRunes := []rune(key)
	wordRunes := []rune(word)
	if len(wordRunes) == 0 || len(wordRunes) > len(keyRunes) {
		return false
	}

	for i := 0; i <= len(keyRunes)-len(wordRunes); i++ {
		if !runesEqual(keyRunes[i:i+len(wordRunes)], wordRunes) {
			continue
		}
		if i > 0 && !isWordSeparator(keyRunes[i-1]) {
			continue
		}
		end := i + len(wordRunes)
		if end < len(keyRunes) && !isWordSeparator(keyRunes[end]) {
			continue
		}
		return true
	}
	return false
}

func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isWordSeparator(r rune) bool {
	return !unicode.IsLetter(r) && !unicode.IsDigit(r)
}
