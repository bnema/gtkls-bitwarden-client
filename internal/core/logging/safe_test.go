package logging

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestShouldRedactKeySensitiveWords(t *testing.T) {
	tests := []string{
		"master_password",
		"local_pin",
		"access_token",
		"client_secret",
		"api_key",
		"basic_auth",
		"item_ciphertext",
		"two_factor_code",
		"login_2fa",
		"session_id",
		"encrypted_payload",
		"clipboard_value",
		"pin_envelope",
	}

	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			if !ShouldRedactKey(key) {
				t.Fatalf("ShouldRedactKey(%q) = false, want true", key)
			}
		})
	}
}

func TestShouldRedactKeyAvoidsObviousFalsePositives(t *testing.T) {
	tests := []string{
		"monkey",
		"auth0_domain",
	}

	for _, key := range tests {
		t.Run(key, func(t *testing.T) {
			if ShouldRedactKey(key) {
				t.Fatalf("ShouldRedactKey(%q) = true, want false", key)
			}
		})
	}
}

func TestSafeValue(t *testing.T) {
	original := "alice"
	if got := SafeValue("username", original); got != original {
		t.Fatalf("SafeValue for non-sensitive key changed value: got %#v, want %#v", got, original)
	}

	if got := SafeValue("access_token", "token-secret"); got != redactedValue {
		t.Fatalf("SafeValue for sensitive key = %#v, want %q", got, redactedValue)
	}
}

func TestSafeValueSanitizesErrorText(t *testing.T) {
	err := errors.New("password=hunter2 token=secret-value")

	got := SafeValue("err", err)
	if got != "error" {
		t.Fatalf("SafeValue error = %#v, want %q", got, "error")
	}
	if fmt.Sprint(got) == err.Error() {
		t.Fatalf("SafeValue returned raw error text %q", err.Error())
	}
}

func TestSafeErrorDetailRedactsSensitiveText(t *testing.T) {
	err := errors.New("login failed for alice@example.com at https://vault.example.com/item/550e8400-e29b-41d4-a716-446655440000/itemid_abcdefghijklmnopqrstuvwxyz: password=hunter2 token=secret code=123456 message=two-factor authentication required")

	got := SafeErrorDetail(err)

	for _, forbidden := range []string{"alice@example.com", "https://vault.example.com", "550e8400-e29b-41d4-a716-446655440000", "itemid_abcdefghijklmnopqrstuvwxyz", "hunter2", "secret", "123456"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("SafeErrorDetail leaked %q in %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "two-factor authentication required") {
		t.Fatalf("SafeErrorDetail dropped useful diagnostic text: %q", got)
	}
}

func TestSafeErrorDetailTruncatesUTF8Safely(t *testing.T) {
	err := errors.New(strings.Repeat("é", 600))

	got := SafeErrorDetail(err)

	if !strings.HasSuffix(got, "…") {
		t.Fatalf("SafeErrorDetail should indicate truncation, got %q", got)
	}
	if strings.Contains(got, "\ufffd") {
		t.Fatalf("SafeErrorDetail produced invalid UTF-8 replacement chars: %q", got)
	}
}

func TestSafeErrorKind(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", err: nil, want: "none"},
		{name: "canceled", err: context.Canceled, want: "canceled"},
		{name: "wrapped canceled", err: fmt.Errorf("operation failed: %w", context.Canceled), want: "canceled"},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: "deadline_exceeded"},
		{name: "wrapped deadline exceeded", err: fmt.Errorf("operation failed: %w", context.DeadlineExceeded), want: "deadline_exceeded"},
		{name: "other", err: errors.New("password=hunter2"), want: "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SafeErrorKind(tt.err); got != tt.want {
				t.Fatalf("SafeErrorKind(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}
