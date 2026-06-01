package bitwarden

import (
	"errors"
	"testing"

	sdk "github.com/bnema/bitwarden-go-sdk/bitwarden"
	coreerrors "github.com/bnema/gtkls-bitwarden-client/internal/core/errors"
)

func TestClassifySDKErrorDecryptionFailed(t *testing.T) {
	err := classifySDKError("sync", sdk.ErrDecryptionFailed)

	if !errors.Is(err, &coreerrors.Error{Kind: coreerrors.KindCrypto}) {
		t.Fatalf("expected crypto kind, got %v", err)
	}
	if got := coreerrors.ShortMessage(err); got != coreerrors.ShortDecryptFailed {
		t.Fatalf("ShortMessage() = %q, want %q", got, coreerrors.ShortDecryptFailed)
	}
}

func TestClassifySDKErrorRateLimited(t *testing.T) {
	err := classifySDKError("sync", sdk.ErrRateLimited)

	if !errors.Is(err, &coreerrors.Error{Kind: coreerrors.KindTemporary}) {
		t.Fatalf("expected temporary kind, got %v", err)
	}
	if got := coreerrors.ShortMessage(err); got != coreerrors.ShortTemporaryFailed {
		t.Fatalf("ShortMessage() = %q, want %q", got, coreerrors.ShortTemporaryFailed)
	}
}

func TestClassifySDKErrorUnknownPassthrough(t *testing.T) {
	sentinel := errors.New("plain failure")
	err := classifySDKError("sync", sentinel)

	if err != sentinel {
		t.Fatalf("expected unknown errors to pass through")
	}
}
