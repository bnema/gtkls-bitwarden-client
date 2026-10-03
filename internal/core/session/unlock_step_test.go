package session

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthStatusDetailNextStep(t *testing.T) {
	tests := []struct {
		name       string
		detail     AuthStatusDetail
		wantStep   UnlockStep
		wantPINish bool
	}{
		{
			name:     "keyring unavailable",
			detail:   AuthStatusDetail{Status: KeyringUnavailable, Reason: AuthReasonKeyringUnavailable},
			wantStep: UnlockStepFixKeyring,
		},
		{
			name:       "soft unlock available",
			detail:     AuthStatusDetail{Status: LoggedInUnlockAvailable, Reason: AuthReasonSoftUnlockAvailable, HasToken: true, HasPINProfile: true, HasEnvelope: true, EnvelopeValid: true, SoftUnlockAvailable: true},
			wantStep:   UnlockStepPIN,
			wantPINish: true,
		},
		{
			name:     "unlock-available status without soft unlock flag is not PIN unlockable",
			detail:   AuthStatusDetail{Status: LoggedInUnlockAvailable, HasPINProfile: true},
			wantStep: UnlockStepRenewEnvelope,
		},
		{
			name:     "no token",
			detail:   AuthStatusDetail{Status: Unauthenticated, Reason: AuthReasonNoToken},
			wantStep: UnlockStepLogin,
		},
		{
			name:     "no PIN profile",
			detail:   AuthStatusDetail{Status: LoggedInLocked, Reason: AuthReasonNoPINProfile, HasToken: true},
			wantStep: UnlockStepSetupPIN,
		},
		{
			name:     "no envelope",
			detail:   AuthStatusDetail{Status: LoggedInLocked, Reason: AuthReasonNoEnvelope, HasToken: true, HasPINProfile: true},
			wantStep: UnlockStepRenewEnvelope,
		},
		{
			name:     "boot changed",
			detail:   AuthStatusDetail{Status: LoggedInLocked, Reason: AuthReasonBootChanged, HasToken: true, HasPINProfile: true, HasEnvelope: true},
			wantStep: UnlockStepRenewEnvelope,
		},
		{
			name:     "account mismatch",
			detail:   AuthStatusDetail{Status: LoggedInLocked, Reason: AuthReasonAccountMismatch, HasToken: true, HasPINProfile: true, HasEnvelope: true},
			wantStep: UnlockStepRenewEnvelope,
		},
		{
			name:     "envelope invalid",
			detail:   AuthStatusDetail{Status: LoggedInLocked, Reason: AuthReasonEnvelopeInvalid, HasToken: true, HasPINProfile: true, HasEnvelope: true},
			wantStep: UnlockStepRenewEnvelope,
		},
		{
			name:     "pin backoff",
			detail:   AuthStatusDetail{Status: LoggedInLocked, Reason: AuthReasonPINBackoff, HasToken: true, HasPINProfile: true, HasEnvelope: true},
			wantStep: UnlockStepWait,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.wantStep, tt.detail.NextStep())
			require.Equal(t, tt.wantPINish, tt.detail.CanPINUnlock())
		})
	}
}
