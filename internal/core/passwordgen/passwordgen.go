package passwordgen

import (
	cryptorand "crypto/rand"
	"errors"
	"io"
	"math/big"
	"strings"
)

const (
	lowercaseChars = "abcdefghijklmnopqrstuvwxyz"
	uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numberChars    = "0123456789"
	symbolChars    = "!@#$%^&*"
)

var (
	ErrNoCharsetEnabled = errors.New("passwordgen: at least one character set must be enabled")
	ErrLengthTooShort   = errors.New("passwordgen: length must be at least the number of enabled character sets")
)

type Options struct {
	Length    int
	Lowercase bool
	Uppercase bool
	Numbers   bool
	Symbols   bool
}

func DefaultOptions() Options {
	return Options{
		Length:    14,
		Lowercase: true,
		Uppercase: true,
		Numbers:   true,
		Symbols:   false,
	}
}

func (o Options) Validate() error {
	enabled := o.enabledCharsets()
	if len(enabled) == 0 {
		return ErrNoCharsetEnabled
	}
	if o.Length < len(enabled) {
		return ErrLengthTooShort
	}
	return nil
}

func Generate(opts Options) (string, error) {
	return GenerateWithReader(cryptorand.Reader, opts)
}

func GenerateWithReader(r io.Reader, opts Options) (string, error) {
	if err := opts.Validate(); err != nil {
		return "", err
	}

	charsets := opts.enabledCharsets()
	allChars := strings.Join(charsets, "")
	password := make([]byte, 0, opts.Length)

	for _, charset := range charsets {
		b, err := randomByte(r, charset)
		if err != nil {
			return "", err
		}
		password = append(password, b)
	}

	for len(password) < opts.Length {
		b, err := randomByte(r, allChars)
		if err != nil {
			return "", err
		}
		password = append(password, b)
	}

	if err := shuffleBytes(r, password); err != nil {
		return "", err
	}

	return string(password), nil
}

func (o Options) enabledCharsets() []string {
	charsets := make([]string, 0, 4)
	if o.Lowercase {
		charsets = append(charsets, lowercaseChars)
	}
	if o.Uppercase {
		charsets = append(charsets, uppercaseChars)
	}
	if o.Numbers {
		charsets = append(charsets, numberChars)
	}
	if o.Symbols {
		charsets = append(charsets, symbolChars)
	}
	return charsets
}

func randomByte(r io.Reader, charset string) (byte, error) {
	idx, err := randomIndex(r, len(charset))
	if err != nil {
		return 0, err
	}
	return charset[idx], nil
}

func shuffleBytes(r io.Reader, value []byte) error {
	for i := len(value) - 1; i > 0; i-- {
		j, err := randomIndex(r, i+1)
		if err != nil {
			return err
		}
		value[i], value[j] = value[j], value[i]
	}
	return nil
}

func randomIndex(r io.Reader, max int) (int, error) {
	n, err := cryptorand.Int(r, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
