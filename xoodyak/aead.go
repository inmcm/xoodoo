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

type xoodyakAEAD struct {
	key []byte
}

var errOpen = errors.New("xoodyak: message authentication failed")

// NewXoodyakAEAD accepts a set of key bytes and returns object compatiable with
// the stdlib crypto/cipher AEAD interface
func NewXoodyakAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) == 0 || len(key) >= xoodoo.StateSizeBytes {
		return nil, fmt.Errorf("key size (%d) out of range", len(key))
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
		panic("xoodyak: incorrect nonce length given")
	}

	ct, tag, err := CryptoEncryptAEAD(plaintext, a.key, nonce, additionalData)
	if err != nil {
		panic(err)
	}
	output := append(dst, ct...)
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
	tag := ciphertext[len(ciphertext)-tagLen:]
	pt, valid, err := CryptoDecryptAEAD(ciphertext[:len(ciphertext)-tagLen], a.key, nonce, additionalData, tag)
	if err != nil {
		return []byte{}, err
	}
	if !valid {
		return []byte{}, errOpen
	}
	output := append(dst, pt...)
	output = append(output, tag...)
	return output, nil
}
