package passwordgen

import (
	"errors"
	"io"
	"testing"
	"unicode"

	"github.com/stretchr/testify/require"
)

type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

func TestOptionsValidate(t *testing.T) {
	tests := []struct {
		name    string
		opts    Options
		wantErr error
	}{
		{
			name:    "rejects with no enabled classes",
			opts:    Options{Length: 20},
			wantErr: ErrNoCharsetEnabled,
		},
		{
			name:    "rejects length shorter than enabled classes",
			opts:    Options{Length: 2, Lowercase: true, Uppercase: true, Numbers: true},
			wantErr: ErrLengthTooShort,
		},
		{
			name: "accepts valid options",
			opts: Options{Length: 20, Lowercase: true, Uppercase: true, Numbers: true, Symbols: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.opts.Validate()
			if tt.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestGenerate_EnsuresEveryEnabledClassIsPresent(t *testing.T) {
	tests := []struct {
		name      string
		opts      Options
		hasLower  bool
		hasUpper  bool
		hasDigit  bool
		hasSymbol bool
	}{
		{
			name:      "all classes",
			opts:      Options{Length: 32, Lowercase: true, Uppercase: true, Numbers: true, Symbols: true},
			hasLower:  true,
			hasUpper:  true,
			hasDigit:  true,
			hasSymbol: true,
		},
		{
			name:      "uppercase and symbols",
			opts:      Options{Length: 16, Uppercase: true, Symbols: true},
			hasUpper:  true,
			hasSymbol: true,
		},
		{
			name:     "numbers only",
			opts:     Options{Length: 12, Numbers: true},
			hasDigit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := Generate(tt.opts)
			require.NoError(t, err)
			require.Len(t, password, tt.opts.Length)
			require.Equal(t, tt.hasLower, containsClass(password, isLower))
			require.Equal(t, tt.hasUpper, containsClass(password, isUpper))
			require.Equal(t, tt.hasDigit, containsClass(password, isDigit))
			require.Equal(t, tt.hasSymbol, containsClass(password, isSymbol))
		})
	}
}

func TestGenerate_UsesOnlyEnabledClassesAndHonorsLength(t *testing.T) {
	opts := Options{Length: 40, Lowercase: true, Numbers: true}

	password, err := Generate(opts)
	require.NoError(t, err)
	require.Len(t, password, opts.Length)

	for _, r := range password {
		require.True(t, isLower(r) || isDigit(r), "unexpected rune %q", r)
	}
}

func TestGenerateWithReader_PropagatesEntropyError(t *testing.T) {
	_, err := GenerateWithReader(failingReader{}, Options{Length: 16, Lowercase: true})
	require.True(t, errors.Is(err, io.ErrUnexpectedEOF))
}

func containsClass(password string, match func(rune) bool) bool {
	for _, r := range password {
		if match(r) {
			return true
		}
	}
	return false
}

func isLower(r rune) bool {
	return unicode.IsLower(r)
}

func isUpper(r rune) bool {
	return unicode.IsUpper(r)
}

func isDigit(r rune) bool {
	return unicode.IsDigit(r)
}

func isSymbol(r rune) bool {
	return !isLower(r) && !isUpper(r) && !isDigit(r)
}
