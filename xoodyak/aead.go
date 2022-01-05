package xoodyak

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"
)

const (
	keyLen   = 16
	tagLen   = 16
	nonceLen = 16
)

// CryptoEncryptAEAD encrypts a plaintext message given a 16-byte key, 16-bytes nonce, and optional
// associated metadata bytes. Along with a cipher text, a 16-byte authentication tag is also generated
// The ciphertext and tag data is compatible with the Xoodyak LWC AEAD  implementation.
func CryptoEncryptAEAD(in, key, id, ad []byte) (ct, tag []byte, err error) {
	if len(key) != keyLen {
		return []byte{}, []byte{}, fmt.Errorf("xoodyak/aead: given key length (%d bytes) incorrect (%d bytes)", len(key), keyLen)
	}
	if len(id) != nonceLen {
		return []byte{}, []byte{}, fmt.Errorf("xoodyak/aead: given nonce length (%d bytes) incorrect (%d bytes)", len(id), nonceLen)
	}
	newXd := Instantiate(key, id, nil)
	newXd.Absorb(ad)
	ct, _ = newXd.Encrypt(in)
	tag = newXd.Squeeze(tagLen)
	return ct, tag, nil
}

// CryptoDecryptAEAD decrypts and authenticates a ciphertext message given a 16-byte key, 16-byte nonce.
// optional associated metadata bytes, and a 16 byte authentication tag generated at encryption.
// A plaintext message is only returned if authentication is successful.
// This decryption process is compatible with the Xoodyak LWC AEAD implementation.
func CryptoDecryptAEAD(in, key, id, ad, tag []byte) (pt []byte, valid bool, err error) {
	if len(key) != keyLen {
		return []byte{}, false, fmt.Errorf("xoodyak/aead: given key length (%d bytes) incorrect (%d bytes)", len(key), keyLen)
	}
	if len(id) != nonceLen {
		return []byte{}, false, fmt.Errorf("xoodyak/aead: given nonce length (%d bytes) incorrect (%d bytes)", len(id), nonceLen)
	}
	newXd := Instantiate(key, id, nil)
	newXd.Absorb(ad)
	pt, _ = newXd.Decrypt(in)
	calculatedTag := newXd.Squeeze(tagLen)
	valid = true
	if subtle.ConstantTimeCompare(calculatedTag, tag) != 1 {
		valid = false
		pt = []byte{}
	}
	return pt, valid, nil
}

type xoodyakAEAD struct {
	key []byte
}

var errOpen = errors.New("xoodyak/aead: message authentication failed")

// NewXoodyakAEAD accepts a set of key bytes and returns object compatible with
// the stdlib crypto/cipher AEAD interface
func NewXoodyakAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("xoodyak/aead: given key length (%d bytes) incorrect (%d bytes)", len(key), keyLen)
	}
	newAEAD := xoodyakAEAD{key: key}
	return &newAEAD, nil
}

func (a *xoodyakAEAD) NonceSize() int {
	return nonceLen
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (a *xoodyakAEAD) Overhead() int {
	return tagLen
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (a *xoodyakAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != nonceLen {
		panic(fmt.Sprintf("xoodyak/aead: given nonce length (%d bytes) incorrect (%d bytes)", len(nonce), nonceLen))
	}

	ct, tag, _ := CryptoEncryptAEAD(plaintext, a.key, nonce, additionalData)
	output := ct
	if dst != nil {
		output = dst
		output = append(output, ct...)
	}
	output = append(output, tag...)
	return output
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (a *xoodyakAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != nonceLen {
		return []byte{}, fmt.Errorf("xoodyak/aead: given nonce length (%d bytes) incorrect (%d bytes)", len(nonce), nonceLen)
	}
	if len(ciphertext) < tagLen {
		return []byte{}, fmt.Errorf("xoodyak/aead: given ciphertext (%d bytes) less than minimum length (%d bytes)", len(ciphertext), tagLen)
	}

	tag := ciphertext[len(ciphertext)-tagLen:]
	pt, valid, _ := CryptoDecryptAEAD(ciphertext[:len(ciphertext)-tagLen], a.key, nonce, additionalData, tag)
	if !valid {
		return []byte{}, errOpen
	}
	if dst != nil {
		return append(dst, pt...), nil
	}
	return pt, nil
}
