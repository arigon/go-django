package godjango

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"io"
)

// SaltedHMAC generates a salted HMAC String
// Source: https://github.com/django/django/blob/master/django/utils/crypto.py
func SaltedHMAC(in, salt, key string) string {
	// Generate SHA1 from Salt + Key
	skh := sha1.New()
	skh.Write([]byte(salt + key))

	// Generate HMAC-SHA1 from Input and Salt+Key Hash
	hash := hmac.New(sha1.New, skh.Sum(nil))
	io.WriteString(hash, in)
	return hex.EncodeToString(hash.Sum(nil))
}
