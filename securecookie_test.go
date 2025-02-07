package securecookie_test

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/moroz/securecookie"
	"github.com/stretchr/testify/assert"
)

func TestNewStore(t *testing.T) {
	t.Parallel()

	examples := []struct {
		key   []byte
		valid bool
	}{
		{
			key:   []byte{1, 2, 3},
			valid: false,
		},
		{
			key:   bytes.Repeat([]byte{1}, securecookie.KeySize+1),
			valid: false,
		},
		{
			key:   bytes.Repeat([]byte{1}, securecookie.KeySize),
			valid: true,
		},
	}

	for _, example := range examples {
		_, err := securecookie.NewStore(example.key)
		if example.valid {
			assert.NoError(t, err)
		} else {
			assert.ErrorIs(t, err, securecookie.ErrKeySize)
		}
	}
}

func generateKey() []byte {
	var key = make([]byte, securecookie.KeySize)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

func TestEncryptDecrypt(t *testing.T) {
	store, err := securecookie.NewStore(generateKey())
	assert.NoError(t, err)

	plaintext := []byte("OrpheanBeholderScryDoubt")

	msg, err := store.Encrypt(plaintext)
	assert.NoError(t, err)
	assert.Len(t, msg, len(plaintext)+securecookie.NonceSize+securecookie.Overhead)

	decrypted, err := store.Decrypt(msg)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

// validateCookieOctet checks whether c is a valid cookie-octet as defined
// in RFC 6265 (https://httpwg.org/specs/rfc6265.html#sane-set-cookie):
//
// cookie-octet      = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//
//	; US-ASCII characters excluding CTLs,
//	; whitespace DQUOTE, comma, semicolon,
//	; and backslash
func validateCookieOctet(c rune) bool {
	return c == 0x21 || c >= 0x23 && c <= 0x2B || c >= 0x2D && c <= 0x3A ||
		c >= 0x3C && c <= 0x5B || c >= 0x5D && c <= 0x7E
}

// validateCookieValue checks whether each rune in the cookie is a valid cookie-octet,
// as per RFC 6265 (https://httpwg.org/specs/rfc6265.html#sane-set-cookie)
// cookie-value      = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
func validateCookieValue(cookie string) bool {
	for _, c := range cookie {
		if !validateCookieOctet(c) {
			return false
		}
	}
	return true
}

func TestEncDecCookie(t *testing.T) {
	store, err := securecookie.NewStore(generateKey())
	assert.NoError(t, err)

	plaintext := []byte("OrpheanBeholderScryDoubt")

	cookie, err := store.EncryptCookie(plaintext)
	assert.True(t, validateCookieValue(cookie))

	decrypted, err := store.DecryptCookie(cookie)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)

	// Try to tamper the cookie by NOTing a byte in the signature
	binary, _ := base64.RawURLEncoding.DecodeString(cookie)
	i := len(binary) - 5
	binary[i] = ^binary[i]

	tampered := base64.RawURLEncoding.EncodeToString(binary)

	got, err := store.DecryptCookie(tampered)
	assert.ErrorContains(t, err, "message authentication failed")
	assert.Nil(t, got)
}
