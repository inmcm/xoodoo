package xoodyak

import (
	"hash"
)

const (
	cryptoHashBytes = 32
)

func cryptoHash(in []byte, hLen uint) ([]byte, error) {
	newXd, err := Instantiate([]byte{}, []byte{}, []byte{})
	if err != nil {
		return []byte{}, err
	}
	err = newXd.Absorb(in)
	if err != nil {
		return []byte{}, err
	}

	output, err := newXd.Squeeze(cryptoHashBytes)
	if err != nil {
		return []byte{}, err
	}
	return output, nil
}

func HashXoodyak(in []byte) ([]byte, error) {
	return cryptoHash(in, cryptoHashBytes)
}

func HashXoodyakLen(in []byte, hLen uint) ([]byte, error) {
	return cryptoHash(in, hLen)
}

/* Generic Hash Function Support */
// digest represents the partial evaluation of a checksum.
type digest struct {
	xk       *Xoodyak
	x        [16]byte
	nx       int
	absorbCd uint8
}

func NewXoodyak() hash.Hash {
	d := &digest{absorbCd: AbsorbCdInit}
	xk, _ := Instantiate([]byte{}, []byte{}, []byte{})
	d.xk = xk
	return d
}

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

func (d *digest) Sum(in []byte) []byte {

	if d.nx > 0 {
		d.xk.AbsorbBlock(d.x[:d.nx], d.xk.AbsorbSize, d.absorbCd)
		d.absorbCd = AbsorbCdMain
	}

	if d.absorbCd == AbsorbCdInit {
		d.xk.AbsorbBlock([]byte{}, d.xk.AbsorbSize, d.absorbCd)
	}

	hash, _ := d.xk.Squeeze(cryptoHashBytes)
	return append(in, hash[:]...)
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	xk, _ := Instantiate([]byte{}, []byte{}, []byte{})
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
