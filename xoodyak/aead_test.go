package xoodyak

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var cryptoAEADTestTable = []struct {
	plaintext  []byte
	key        []byte
	nonce      []byte
	ad         []byte
	ciphertext []byte
	tag        []byte
	valid      bool
	encryptErr error
	decryptErr error
}{
	{
		plaintext:  []byte{0x80, 0xf7, 0x1c, 0xb5, 0xc2, 0xe9, 0x51, 0x2e, 0x56, 0x89, 0x3c, 0xda, 0x54, 0xad, 0xb6, 0xfd, 0xfc, 0x18, 0xbd, 0x9a, 0x40, 0x1e, 0x8a, 0xba, 0x15, 0x7c, 0x04, 0xe1, 0x6f, 0x4c, 0x45, 0x56},
		key:        []byte{0xde, 0xca, 0xeb, 0xa0, 0xc1, 0xc9, 0x25, 0x4f, 0xb9, 0xfd, 0xa4, 0xe7, 0x6a, 0xf9, 0x38, 0x3b},
		nonce:      []byte{0x2e, 0x52, 0x0d, 0xd2, 0xfe, 0xfb, 0x15, 0x46, 0xc5, 0x67, 0x93, 0x9b, 0x70, 0xda, 0x92, 0xe8},
		ad:         []byte{0x0e, 0x0f, 0x62, 0x1d, 0x2a, 0x62, 0xbd, 0xb0, 0x98, 0x33, 0xa0, 0xc9, 0x20, 0x68, 0x9b, 0xe7, 0x65, 0x77, 0x36, 0xfb, 0x2d, 0x09, 0x9f, 0x5c, 0xaf, 0x90, 0x6f, 0xb9, 0x83, 0xfa, 0x4c, 0x4c},
		ciphertext: []byte{0x64, 0xF8, 0xFB, 0x79, 0x50, 0xE1, 0xE5, 0x0E, 0x4D, 0xFB, 0x3B, 0x11, 0xA9, 0xDA, 0x03, 0x75, 0x01, 0x86, 0xD9, 0xAE, 0x2A, 0x4A, 0x63, 0x60, 0x72, 0xFB, 0x78, 0x9F, 0x75, 0xE7, 0xF0, 0x64},
		tag:        []byte{0xBE, 0x6E, 0x37, 0x66, 0x53, 0x34, 0x92, 0xEE, 0x19, 0x32, 0x73, 0x84, 0xD5, 0xF3, 0x8A, 0x29},
		valid:      true,
		encryptErr: nil,
		decryptErr: nil,
	},
	{
		plaintext:  []byte{0x8b, 0x06, 0xc7, 0x9b, 0x41},
		key:        []byte{0x80, 0x4f, 0x16, 0x14, 0x7c, 0xca, 0xce, 0x97, 0xc5, 0x39, 0xe5, 0xf5, 0xa3, 0x27, 0x43, 0xd2},
		nonce:      []byte{0x9a, 0x84, 0x05, 0x13, 0x4c, 0x18, 0x46, 0x65, 0x28, 0x48, 0x36, 0x60, 0x4b, 0x98, 0xec, 0x61},
		ad:         []byte{0xc3, 0x64, 0x0d, 0x28, 0xf7, 0x52, 0xdb, 0xfb, 0x8b, 0xc3, 0xf9},
		ciphertext: []byte{0x40, 0xB0, 0xD3, 0x89, 0x14},
		tag:        []byte{0xE6, 0x11, 0xD6, 0x6D, 0xE0, 0x4F, 0x8F, 0xB0, 0xC7, 0x28, 0xFF, 0x58, 0xE5, 0x26, 0xB3, 0x3B},
		valid:      true,
		encryptErr: nil,
		decryptErr: nil,
	},
	{
		plaintext:  []byte{0x72, 0x61, 0xdc, 0x8e, 0x98, 0x0e, 0x96, 0xaf, 0x68, 0x8a, 0x0d, 0x6b, 0x6f, 0x7f, 0xa6},
		key:        []byte{0x7a, 0xca, 0xfe, 0x45, 0xfa, 0xc6, 0x8b, 0x00, 0x73, 0x3b, 0x7b, 0x50, 0x3b, 0x46, 0x62, 0xe8},
		nonce:      []byte{0x29, 0x0b, 0x45, 0x91, 0xc9, 0xb2, 0x8d, 0x9c, 0x38, 0x41, 0x10, 0xf2, 0xc5, 0xf0, 0x3e, 0xac},
		ad:         []byte{0xa9, 0xa5, 0x1a, 0x9c, 0x9b, 0xa0, 0x76, 0x1e, 0x6a, 0x29, 0xb1, 0xbd, 0x98, 0x1c, 0x70, 0x3b, 0xbe},
		ciphertext: []byte{0x2E, 0xA9, 0x89, 0x89, 0xE8, 0xE2, 0x9D, 0x7C, 0x12, 0x57, 0xBA, 0x5E, 0x6C, 0xD5, 0x80},
		tag:        []byte{0x7C, 0x45, 0x81, 0x6B, 0x94, 0x69, 0xAF, 0xC3, 0x35, 0x81, 0xBF, 0x2B, 0xCA, 0xE0, 0x17, 0x57},
		valid:      true,
		encryptErr: nil,
		decryptErr: nil,
	},
	{
		plaintext:  []byte{},
		key:        []byte{0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00},
		nonce:      []byte{0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87, 0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F},
		ad:         []byte{0x33, 0x33, 0xc2, 0xb0, 0x35, 0x39, 0xe2, 0x80, 0x99, 0x33, 0x39, 0x2e, 0x35, 0x31, 0xe2, 0x80, 0xb3, 0x4e, 0x2c, 0x20, 0x37, 0xc2, 0xb0, 0x35, 0x30, 0xe2, 0x80, 0x99, 0x33, 0x33, 0x2e, 0x36, 0x39, 0xe2, 0x80, 0xb3, 0x45},
		ciphertext: []byte{},
		tag:        []byte{0x32, 0x4b, 0x91, 0x70, 0x89, 0x7c, 0x51, 0x43, 0x91, 0xd6, 0x24, 0xe4, 0xb1, 0xb2, 0xe8, 0x4e},
		valid:      true,
		encryptErr: nil,
		decryptErr: nil,
	},
}

func TestCryptoAEAD(t *testing.T) {
	for _, tt := range cryptoAEADTestTable {
		gotCt, gotTag, gotErr := CryptoEncryptAEAD(tt.plaintext, tt.key, tt.nonce, tt.ad)
		assert.Equal(t, tt.ciphertext, gotCt)
		assert.Equal(t, tt.tag, gotTag)
		assert.Equal(t, tt.encryptErr, gotErr)

		gotPt, gotValid, gotErr := CryptoDecryptAEAD(tt.ciphertext, tt.key, tt.nonce, tt.ad, tt.tag)
		assert.Equal(t, tt.plaintext, gotPt)
		assert.Equal(t, tt.valid, gotValid)
		assert.Equal(t, tt.decryptErr, gotErr)

	}
}

func BenchmarkEncryptAEAD(b *testing.B) {
	plaintext := make([]byte, 1024)
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	ad := make([]byte, 64)
	for n := 0; n < b.N; n++ {
		CryptoEncryptAEAD(plaintext, key, nonce, ad)
	}
}

func BenchmarkDecryptAEAD(b *testing.B) {
	plaintext := make([]byte, 1024)
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	ad := make([]byte, 64)
	tag := []byte{0x7c, 0xff, 0x3f, 0x8d, 0x8d, 0x79, 0xcf, 0x00, 0xa2, 0xb3, 0xdc, 0x40, 0xfd, 0x82, 0x0f, 0xa6}
	for n := 0; n < b.N; n++ {
		CryptoDecryptAEAD(plaintext, key, nonce, ad, tag)
	}
}

var cryptoAEADTestTableTagFails = []struct {
	plaintext  []byte
	key        []byte
	nonce      []byte
	ad         []byte
	ciphertext []byte
	tag        []byte
}{
	{
		// Tag is intentionally incorrect from what is calculated
		plaintext:  []byte{0x72, 0x61, 0xdc, 0x8e, 0x98, 0x0e, 0x96, 0xaf, 0x68, 0x8a, 0x0d, 0x6b, 0x6f, 0x7f, 0xa6},
		key:        []byte{0x7a, 0xca, 0xfe, 0x45, 0xfa, 0xc6, 0x8b, 0x00, 0x73, 0x3b, 0x7b, 0x50, 0x3b, 0x46, 0x62, 0xe8},
		nonce:      []byte{0x29, 0x0b, 0x45, 0x91, 0xc9, 0xb2, 0x8d, 0x9c, 0x38, 0x41, 0x10, 0xf2, 0xc5, 0xf0, 0x3e, 0xac},
		ad:         []byte{0xa9, 0xa5, 0x1a, 0x9c, 0x9b, 0xa0, 0x76, 0x1e, 0x6a, 0x29, 0xb1, 0xbd, 0x98, 0x1c, 0x70, 0x3b, 0xbe},
		tag:        []byte{0x3C, 0x45, 0x81, 0x6B, 0x94, 0x69, 0xAF, 0xC3, 0x35, 0x81, 0xBF, 0x2B, 0xCA, 0xE0, 0x17, 0x57},
		ciphertext: []byte{0x2E, 0xA9, 0x89, 0x89, 0xE8, 0xE2, 0x9D, 0x7C, 0x12, 0x57, 0xBA, 0x5E, 0x6C, 0xD5, 0x80},
	},
	{
		// Ciphertext/Ciphertext is adulterated such that calculated tag is invalid
		plaintext:  []byte{0x32, 0x61, 0xdc, 0x8e, 0x98, 0x0e, 0x96, 0xaf, 0x68, 0x8a, 0x0d, 0x6b, 0x6f, 0x7f, 0xa6},
		key:        []byte{0x7a, 0xca, 0xfe, 0x45, 0xfa, 0xc6, 0x8b, 0x00, 0x73, 0x3b, 0x7b, 0x50, 0x3b, 0x46, 0x62, 0xe8},
		nonce:      []byte{0x29, 0x0b, 0x45, 0x91, 0xc9, 0xb2, 0x8d, 0x9c, 0x38, 0x41, 0x10, 0xf2, 0xc5, 0xf0, 0x3e, 0xac},
		ad:         []byte{0xa9, 0xa5, 0x1a, 0x9c, 0x9b, 0xa0, 0x76, 0x1e, 0x6a, 0x29, 0xb1, 0xbd, 0x98, 0x1c, 0x70, 0x3b, 0xbe},
		tag:        []byte{0x7C, 0x45, 0x81, 0x6B, 0x94, 0x69, 0xAF, 0xC3, 0x35, 0x81, 0xBF, 0x2B, 0xCA, 0xE0, 0x17, 0x57},
		ciphertext: []byte{0x6E, 0xA9, 0x89, 0x89, 0xE8, 0xE2, 0x9D, 0x7C, 0x12, 0x57, 0xBA, 0x5E, 0x6C, 0xD5, 0x80},
	},
	{
		// key is intentionally incorrect
		plaintext:  []byte{0xac, 0x71, 0x95, 0xdb, 0x26, 0xc8, 0x0, 0x6b, 0x89, 0x78, 0xde, 0xe2, 0x7d, 0x99, 0x10},
		key:        []byte{0x3a, 0xca, 0xfe, 0x45, 0xfa, 0xc6, 0x8b, 0x00, 0x73, 0x3b, 0x7b, 0x50, 0x3b, 0x46, 0x62, 0xe8},
		nonce:      []byte{0x29, 0x0b, 0x45, 0x91, 0xc9, 0xb2, 0x8d, 0x9c, 0x38, 0x41, 0x10, 0xf2, 0xc5, 0xf0, 0x3e, 0xac},
		ad:         []byte{0xa9, 0xa5, 0x1a, 0x9c, 0x9b, 0xa0, 0x76, 0x1e, 0x6a, 0x29, 0xb1, 0xbd, 0x98, 0x1c, 0x70, 0x3b, 0xbe},
		tag:        []byte{0x7C, 0x45, 0x81, 0x6B, 0x94, 0x69, 0xAF, 0xC3, 0x35, 0x81, 0xBF, 0x2B, 0xCA, 0xE0, 0x17, 0x57},
		ciphertext: []byte{0x2E, 0xA9, 0x89, 0x89, 0xE8, 0xE2, 0x9D, 0x7C, 0x12, 0x57, 0xBA, 0x5E, 0x6C, 0xD5, 0x80},
	},
}

func TestCryptoAEADTagFail(t *testing.T) {
	for _, tt := range cryptoAEADTestTableTagFails {
		gotPt, gotValid, gotErr := CryptoDecryptAEAD(tt.ciphertext, tt.key, tt.nonce, tt.ad, tt.tag)
		assert.Equal(t, []byte{}, gotPt)
		assert.Equal(t, false, gotValid)
		assert.Equal(t, nil, gotErr)
	}
}

var cryptoAEADErrorsTestTable = []struct {
	plaintext  []byte
	key        []byte
	nonce      []byte
	ad         []byte
	ciphertext []byte
	tag        []byte
	valid      bool
	err        error
}{
	{
		// Zero length key
		plaintext:  []byte{},
		key:        []byte{},
		nonce:      []byte{},
		ad:         []byte{},
		tag:        []byte{},
		ciphertext: []byte{},
		valid:      false,
		err:        errors.New("xoodyak/aead: given key length (0 bytes) incorrect (16 bytes)"),
	},
	{
		// Truncated length key
		plaintext:  []byte{},
		key:        []byte{0x00, 0x01, 0x02},
		nonce:      []byte{},
		ad:         []byte{},
		tag:        []byte{},
		ciphertext: []byte{},
		valid:      false,
		err:        errors.New("xoodyak/aead: given key length (3 bytes) incorrect (16 bytes)"),
	},
	{
		// Excessive length key
		plaintext:  []byte{},
		key:        []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
		nonce:      []byte{},
		ad:         []byte{},
		tag:        []byte{},
		ciphertext: []byte{},
		valid:      false,
		err:        errors.New("xoodyak/aead: given key length (20 bytes) incorrect (16 bytes)"),
	},
	{
		// Correct key length key, zero length nonce
		plaintext:  []byte{},
		key:        []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
		nonce:      []byte{},
		ad:         []byte{},
		tag:        []byte{},
		ciphertext: []byte{},
		valid:      false,
		err:        fmt.Errorf("xoodyak/aead: given nonce length (0 bytes) incorrect (16 bytes)"),
	},
}

func TestCryptoAEADErrors(t *testing.T) {
	for _, tt := range cryptoAEADErrorsTestTable {
		gotPt, gotTag, gotErr := CryptoEncryptAEAD(tt.ciphertext, tt.key, tt.nonce, tt.ad)
		assert.Equal(t, tt.ciphertext, gotPt)
		assert.Equal(t, tt.tag, gotTag)
		assert.Equal(t, tt.err, gotErr)

		gotCt, gotValid, gotErr := CryptoDecryptAEAD(tt.plaintext, tt.key, tt.nonce, tt.ad, tt.tag)
		assert.Equal(t, tt.plaintext, gotCt)
		assert.Equal(t, tt.valid, gotValid)
		assert.Equal(t, tt.err, gotErr)
	}
}

var cryptoAEADConstructorsErrorsTestTable = []struct {
	key []byte
	err error
}{
	{
		// Zero length key
		key: []byte{},
		err: errors.New("xoodyak/aead: given key length (0 bytes) incorrect (16 bytes)"),
	},
	{
		// Truncated length key
		key: []byte{0x00, 0x01, 0x02},
		err: errors.New("xoodyak/aead: given key length (3 bytes) incorrect (16 bytes)"),
	},
	{
		// Excessive length key
		key: []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
		err: errors.New("xoodyak/aead: given key length (20 bytes) incorrect (16 bytes)"),
	},
}

func TestCryptoAEADConstructorErrors(t *testing.T) {
	for _, tt := range cryptoAEADConstructorsErrorsTestTable {
		gotAEAD, gotErr := NewXoodyakAEAD(tt.key)
		assert.Equal(t, nil, gotAEAD)
		assert.Equal(t, tt.err, gotErr)
	}
}

func TestCryptoAEADOfficialKAT(t *testing.T) {
	kat, err := os.Open("LWC_AEAD_KAT_128_128.txt")
	assert.NoError(t, err)
	defer kat.Close()
	katBuf := bufio.NewReader(kat)

	var count int
	var key string
	var nonce string
	var pt string
	var ad string
	var ct string

	for i := 1; i <= 1089; i++ {
		nextLine, _, err := katBuf.ReadLine()
		assert.NoError(t, err)
		fmt.Sscanf(string(nextLine), "Count = %d", &count)

		nextLine, _, err = katBuf.ReadLine()
		assert.NoError(t, err)
		key = ""
		fmt.Sscanf(string(nextLine), "Key = %s", &key)
		keyBytes, err := hex.DecodeString(key)
		assert.NoError(t, err)

		nextLine, _, err = katBuf.ReadLine()
		assert.NoError(t, err)
		nonce = ""
		fmt.Sscanf(string(nextLine), "Nonce = %s", &nonce)
		nonceBytes, err := hex.DecodeString(nonce)
		assert.NoError(t, err)

		nextLine, _, err = katBuf.ReadLine()
		assert.NoError(t, err)
		pt = ""
		fmt.Sscanf(string(nextLine), "PT = %s", &pt)
		plainTextBytes, err := hex.DecodeString(pt)
		assert.NoError(t, err)

		nextLine, _, err = katBuf.ReadLine()
		assert.NoError(t, err)
		ad = ""
		fmt.Sscanf(string(nextLine), "AD = %s", &ad)
		adBytes, err := hex.DecodeString(ad)
		assert.NoError(t, err)

		nextLine, _, err = katBuf.ReadLine()
		assert.NoError(t, err)
		ct = ""
		fmt.Sscanf(string(nextLine), "CT = %s", &ct)
		combinedCtBytes, err := hex.DecodeString(ct)
		assert.NoError(t, err)
		combinedLength := len(combinedCtBytes)
		cipherTextBytes := combinedCtBytes[0 : combinedLength-16]
		tagBytes := combinedCtBytes[combinedLength-16 : combinedLength]

		// Crypto Methods
		gotCt, gotTag, gotErr := CryptoEncryptAEAD(plainTextBytes, keyBytes, nonceBytes, adBytes)
		assert.Equal(t, cipherTextBytes, gotCt)
		assert.Equal(t, tagBytes, gotTag)
		assert.NoError(t, gotErr)
		gotPt, gotValid, gotErr := CryptoDecryptAEAD(cipherTextBytes, keyBytes, nonceBytes, adBytes, tagBytes)
		assert.Equal(t, plainTextBytes, gotPt)
		assert.Equal(t, true, gotValid)
		assert.NoError(t, gotErr)

		// AEAD Seal/Open Methods
		gotAEAD, gotErr := NewXoodyakAEAD(keyBytes)
		assert.NoError(t, gotErr)

		gotCiphertext := gotAEAD.Seal(nil, nonceBytes, plainTextBytes, adBytes)
		assert.Equal(t, combinedCtBytes, gotCiphertext)

		gotPlaintext, gotErr := gotAEAD.Open(nil, nonceBytes, combinedCtBytes, adBytes)
		assert.NoError(t, gotErr)
		assert.Equal(t, plainTextBytes, gotPlaintext)

		// Empty Line
		_, _, err = katBuf.ReadLine()
		assert.NoError(t, err)
	}
}

func TestStandardAEADInterface(t *testing.T) {
	for _, tt := range cryptoAEADTestTable {
		gotAEAD, gotErr := NewXoodyakAEAD(tt.key)
		assert.NoError(t, gotErr)

		gotNoneSize := gotAEAD.NonceSize()
		assert.Equal(t, nonceLen, gotNoneSize)
		gotTagSize := gotAEAD.Overhead()
		assert.Equal(t, tagLen, gotTagSize)

		gotCiphertext := gotAEAD.Seal(nil, tt.nonce, tt.plaintext, tt.ad)
		fullCipherText := append(tt.ciphertext, tt.tag...)
		assert.Equal(t, fullCipherText, gotCiphertext)

		gotPlaintext, gotErr := gotAEAD.Open(nil, tt.nonce, fullCipherText, tt.ad)
		assert.NoError(t, gotErr)
		assert.Equal(t, tt.plaintext, gotPlaintext)

	}
}

func TestCryptoAEADInterfaceTagFail(t *testing.T) {
	for _, tt := range cryptoAEADTestTableTagFails {

		gotAEAD, gotErr := NewXoodyakAEAD(tt.key)
		assert.NoError(t, gotErr)

		fullCipherText := append(tt.ciphertext, tt.tag...)
		gotPlaintext, gotErr := gotAEAD.Open(nil, tt.nonce, fullCipherText, tt.ad)
		assert.Equal(t, errOpen, gotErr)
		assert.Equal(t, []byte{}, gotPlaintext)
	}
}

var cryptoAEADInterfaceNonceTestTable = []struct {
	nonce []byte
	err   error
}{
	{
		// Zero length nonce
		nonce: []byte{},
		err:   errors.New("xoodyak/aead: given nonce length (0 bytes) incorrect (16 bytes)"),
	},
	{
		// Truncated length nonce
		nonce: []byte{0x00, 0x01, 0x02},
		err:   errors.New("xoodyak/aead: given nonce length (3 bytes) incorrect (16 bytes)"),
	},
	{
		// Excessive length nonce
		nonce: []byte{0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x01, 0x02, 0x03},
		err:   errors.New("xoodyak/aead: given nonce length (20 bytes) incorrect (16 bytes)"),
	},
}

func TestAEADInterfaceNonceErrors(t *testing.T) {
	for _, tt := range cryptoAEADInterfaceNonceTestTable {
		key := make([]byte, 16)
		gotAEAD, gotErr := NewXoodyakAEAD(key)
		assert.Equal(t, nil, gotErr)

		panicSeal := func() {
			gotAEAD.Seal(nil, tt.nonce, []byte{0x11}, []byte{0x22})
		}

		assert.Panics(t, panicSeal)

		ciphertext := make([]byte, 50)

		gotPt, gotErr := gotAEAD.Open(nil, tt.nonce, ciphertext, []byte{0x22})
		assert.Equal(t, []byte{}, gotPt)
		assert.EqualError(t, tt.err, gotErr.Error())

	}
}

func TestAEADInterfaceDstWriting(t *testing.T) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	ad := make([]byte, 80)
	msg := []byte("hello dest")
	ctDst := []byte("append ciphertext to this")
	ctDstLen := len(ctDst)
	ptDst := []byte("append plaintext to this")
	//ptDstLen := len(ptDst)
	authCtOutput := []byte{0x51, 0xd4, 0x67, 0x7f, 0x57, 0x14, 0x6, 0x1d, 0x32, 0xc, 0xcc, 0xa9, 0x6d, 0xf2, 0xf3, 0x56, 0x1b, 0x63, 0x8d, 0x32, 0x40, 0xcf, 0x54, 0x25, 0xc1, 0x11}
	t.Run("Append to Unrelated Data", func(t *testing.T) {
		appendedCtOutput := append(ctDst, authCtOutput...)
		gotAEAD, gotErr := NewXoodyakAEAD(key)
		assert.NoError(t, gotErr)
		gotCiphertext := gotAEAD.Seal(ctDst, nonce, msg, ad)
		assert.Equal(t, appendedCtOutput, gotCiphertext)
		assert.Equal(t, []byte("hello dest"), msg)
		authCt := gotCiphertext[ctDstLen:]
		appendedPtOutput := append(ptDst, msg...)
		gotPlaintext, gotErr := gotAEAD.Open(ptDst, nonce, authCt, ad)
		assert.NoError(t, gotErr)
		assert.Equal(t, appendedPtOutput, gotPlaintext)
		assert.Equal(t, gotCiphertext[ctDstLen:], authCt)
	})

	t.Run("Overwrite plaintext inputs", func(t *testing.T) {
		key := make([]byte, 16)
		nonce := make([]byte, 16)
		ad := make([]byte, 80)
		msgBackup := make([]byte, len(msg), 15)
		copy(msgBackup, msg)
		gotAEAD, gotErr := NewXoodyakAEAD(key)
		assert.NoError(t, gotErr)
		gotCiphertext := gotAEAD.Seal(msgBackup[:0], nonce, msgBackup, ad)
		assert.Equal(t, authCtOutput[:len(msg)], msgBackup)
		assert.Equal(t, authCtOutput, gotCiphertext)
		gotPlaintext, gotErr := gotAEAD.Open(msgBackup[:0], nonce, gotCiphertext, ad)
		assert.NoError(t, gotErr)
		assert.Equal(t, msg, msgBackup)
		assert.Equal(t, msg, gotPlaintext)
	})

	t.Run("Overwrite other buffer", func(t *testing.T) {
		key := make([]byte, 16)
		nonce := make([]byte, 16)
		ad := make([]byte, 80)
		otherMsgBuffer := make([]byte, len(msg), 200)
		gotAEAD, gotErr := NewXoodyakAEAD(key)
		assert.NoError(t, gotErr)
		gotCiphertext := gotAEAD.Seal(otherMsgBuffer[:0], nonce, msg, ad)
		assert.Equal(t, authCtOutput[:len(msg)], otherMsgBuffer)
		assert.Equal(t, authCtOutput, gotCiphertext)
		otherMsgBuffer = make([]byte, len(msg))
		gotPlaintext, gotErr := gotAEAD.Open(otherMsgBuffer[:0], nonce, gotCiphertext, ad)
		assert.NoError(t, gotErr)
		assert.Equal(t, msg, otherMsgBuffer)
		assert.Equal(t, msg, gotPlaintext)
	})
}
