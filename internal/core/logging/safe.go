// Package logging provides shared helpers for safe structured logging.
package logging

import (
	"context"
	"errors"
	"strings"
	"unicode"
)

const redactedValue = "[REDACTED]"

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
