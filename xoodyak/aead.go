package xoodyak

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/inmcm/xoodoo/xoodoo"
)

const (
	tagLen   = 16
	nonceLen = 16
)

func CryptoEncryptAEAD(in, key, id, ad []byte) (ct, tag []byte, err error) {
	newXd, err := Instantiate(key, id, nil)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	newXd.Absorb(ad)
	ct, err = newXd.Encrypt(in)
	if err != nil {
		return []byte{}, []byte{}, err
	}
	tag = newXd.Squeeze(tagLen)
	return ct, tag, nil
}

func CryptoDecryptAEAD(in, key, id, ad, tag []byte) (pt []byte, valid bool, err error) {
	newXd, err := Instantiate(key, id, nil)
	if err != nil {
		return []byte{}, false, err
	}
	newXd.Absorb(ad)
	pt, err = newXd.Decrypt(in)
	if err != nil {
		return []byte{}, false, err
	}
	calculatedTag := newXd.Squeeze(tagLen)
	valid = true
	if subtle.ConstantTimeCompare(calculatedTag, tag) != 1 {
		valid = false
		pt = []byte{}
	}
	return pt, valid, nil
}

type aead struct {
	cipher    cipher.Block
	nonceSize int
	tagSize   int
}

func NewXoodyakAEAD(cipher cipher.Block) (cipher.AEAD, error) {
	newAEAD := aead{}
	return &newAEAD, nil
}

func (a *aead) NonceSize() int {
	return 0
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (a *aead) Overhead() int {
	return 0
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (a *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return []byte{}
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
func (a *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return []byte{}, nil
}
