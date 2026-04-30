package out

import (
	"context"

	session "github.com/bnema/gtk4-layershell-bitwarden/internal/core/session"
)

type CredentialStore interface {
	CheckAvailable(ctx context.Context) error
	SaveTokenBundle(ctx context.Context, ref session.AccountRef, bundle session.TokenBundle) error
	LoadTokenBundle(ctx context.Context, ref session.AccountRef) (session.TokenBundle, error)
	DeleteTokenBundle(ctx context.Context, ref session.AccountRef) error
	SaveUnlockEnvelope(ctx context.Context, ref session.AccountRef, envelope session.UnlockEnvelope) error
	LoadUnlockEnvelope(ctx context.Context, ref session.AccountRef) (session.UnlockEnvelope, error)
	DeleteUnlockEnvelope(ctx context.Context, ref session.AccountRef) error
}

type BootIDProvider interface {
	BootID(ctx context.Context) (string, error)
}

type PINEnvelopeService interface {
	Create(ctx context.Context, ref session.AccountRef, material session.UnlockMaterial, pin string, bootID string) (session.UnlockEnvelope, error)
	Open(ctx context.Context, ref session.AccountRef, envelope session.UnlockEnvelope, pin string, bootID string) (session.UnlockMaterial, session.UnlockEnvelope, error)
}
