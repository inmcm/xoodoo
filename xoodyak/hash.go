package xoodyak

import (
	"hash"
)

const (
	cryptoHashBytes = 32
)

func cryptoHash(in []byte, hLen uint) []byte {
	newXd := Instantiate([]byte{}, []byte{}, []byte{})
	newXd.Absorb(in)
	output := newXd.Squeeze(hLen)
	return output
}

// HashXoodyak calculates a 32-byte hash on a provided slice of bytes.
// The output is compatible with the Xoodyak LWC definition
func HashXoodyak(in []byte) []byte {
	return cryptoHash(in, cryptoHashBytes)
}

// HashXoodyakLen calculates a cryptographic hash of arbitrary length on a provided slice of bytes
func HashXoodyakLen(in []byte, hLen uint) []byte {
	return cryptoHash(in, hLen)
}

/* Generic Hash Function Support */

// digest represents the partial evaluation of a Xoodyak hash
type digest struct {
	xk       *Xoodyak
	x        [16]byte
	nx       int
	absorbCd uint8
}

// NewXoodyakHash returns a initialized Xoodyak digest object compatible
// with the stdlib Hash interface
func NewXoodyakHash() hash.Hash {
	d := &digest{absorbCd: AbsorbCdInit}
	xk := Instantiate([]byte{}, []byte{}, []byte{})
	d.xk = xk
	return d
}

// Write adds more data to the running hash.
// It never returns an error.
func (d *digest) Write(p []byte) (nn int, err error) {
	nn = len(p)
	if d.nx > 0 {
		n := copy(d.x[d.nx:], p)
		d.nx += n
		if d.nx == hashSize {
			d.xk.AbsorbBlock(d.x[:], d.xk.AbsorbSize, d.absorbCd)
			d.nx = 0
		}
		p = p[n:]
	}
	if len(p) >= hashSize {
		n := len(p) &^ (hashSize - 1)
		for i := 0; i < n; i += hashSize {
			d.xk.AbsorbBlock(p[:hashSize], d.xk.AbsorbSize, d.absorbCd)
			p = p[hashSize:]
			d.absorbCd = AbsorbCdMain
		}
	}
	if len(p) > 0 {
		d.nx = copy(d.x[:], p)
	}
	return
}

// Sum appends the current hash to b and returns the resulting slice.
// Sum will finalize the absorb sequence and switch to squeezing bytes from the
// embedded Xoodoo state
func (d *digest) Sum(b []byte) []byte {

	if d.nx > 0 {
		d.xk.AbsorbBlock(d.x[:d.nx], d.xk.AbsorbSize, d.absorbCd)
		d.absorbCd = AbsorbCdMain
	}

	if d.absorbCd == AbsorbCdInit {
		d.xk.AbsorbBlock([]byte{}, d.xk.AbsorbSize, d.absorbCd)
	}

	hash := d.xk.Squeeze(cryptoHashBytes)
	return append(b, hash[:]...)
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	xk := Instantiate([]byte{}, []byte{}, []byte{})
	d.xk = xk
	d.nx = 0
	d.absorbCd = AbsorbCdInit
	d.x = [16]byte{}
}

// Size returns the number of bytes Sum will return.
func (d *digest) Size() int {
	return cryptoHashBytes
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (d *digest) BlockSize() int {
	return hashSize
}
