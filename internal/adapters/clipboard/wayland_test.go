package clipboard

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreferSetter_PrimarySuccessSkipsFallback(t *testing.T) {
	calls := make([]string, 0, 2)
	setter := preferSetter(
		func(text string) error {
			calls = append(calls, "primary:"+text)
			return nil
		},
		func(text string) error {
			calls = append(calls, "fallback:"+text)
			return nil
		},
	)

	require.NoError(t, setter("secret"))
	require.Equal(t, []string{"primary:secret"}, calls)
}

func TestPreferSetter_PrimaryErrorFallsBack(t *testing.T) {
	calls := make([]string, 0, 2)
	setter := preferSetter(
		func(text string) error {
			calls = append(calls, "primary:"+text)
			return errors.New("primary failed")
		},
		func(text string) error {
			calls = append(calls, "fallback:"+text)
			return nil
		},
	)

	require.NoError(t, setter("secret"))
	require.Equal(t, []string{"primary:secret", "fallback:secret"}, calls)
}

func TestPreferClearer_ReturnsPrimaryErrorWhenNoFallback(t *testing.T) {
	wantErr := errors.New("clear failed")
	clearer := preferClearer(
		func() error { return wantErr },
		nil,
	)

	err := clearer()
	require.ErrorIs(t, err, wantErr)
}
