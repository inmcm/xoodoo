package xoodyak

import (
	"bytes"
	"encoding/binary"

	"github.com/inmcm/xoodoo/xoodoo"
)

const (
	f_bPrime               = 48
	hashSize               = 16
	Xoodyak_Rkin           = 44
	Xoodyak_Rkout          = 24
	Xoodyak_lRatchet       = 16
	AbsorbCdInit     uint8 = 0x03
	SqueezeCuInit    uint8 = 0x40
)

type CyclistMode int

const (
	Hash CyclistMode = iota + 1
	Keyed
)

type CyclistPhase int

const (
	Down CyclistPhase = iota + 1
	Up
)

type Xoodyak struct {
	Instance    *xoodoo.XooDoo
	Mode        CyclistMode
	Phase       CyclistPhase
	AbsorbSize  uint
	SqueezeSize uint
}

// Support for hash.Hash interface
func (xk Xoodyak) Size() int      { return hashSize }
func (xk Xoodyak) BlockSize() int { return f_bPrime }
func (xk *Xoodyak) Reset()        {}

// Standard Xoodyak Interfactes
func Instantiate(key, id, counter []byte) (*Xoodyak, error) {
	newXK := Xoodyak{}
	newXK.Instance, _ = xoodoo.NewXooDoo(xoodoo.MaxRounds, [48]byte{})
	newXK.Mode = Hash
	newXK.Phase = Up
	newXK.AbsorbSize = hashSize
	newXK.SqueezeSize = hashSize
	if len(key) != 0 {
		newXK.AbsorbKey(key, id, counter)
	}

	return &newXK, nil
}

func (xk *Xoodyak) Absorb(x []byte) error {
	return xk.AbsorbAny(x, xk.AbsorbSize, AbsorbCdInit)
}
func (xk *Xoodyak) Encrypt() error {
	return nil
}
func (xk *Xoodyak) Decrypt() error {
	return nil
}
func (xk *Xoodyak) Squeeze(outLen uint) ([]byte, error) {
	return xk.SqueezeAny(outLen, SqueezeCuInit)
}
func (xk *Xoodyak) SqueezeKey() error {
	return nil
}
func (xk *Xoodyak) Ratchet() error {
	return nil
}
func (xk *Xoodyak) AbsorbAny(x []byte, r uint, cd uint8) error {
	var cdTmp uint8 = cd
	var processed uint = 0
	var remaining uint = uint(len(x))
	tmp := make([]byte, r)
	absorbLen := r
	for {
		if xk.Phase != Up {
			xk.Up(0, 0)
		}
		if remaining < absorbLen {
			absorbLen = remaining
			tmp = make([]byte, absorbLen)
		}
		copy(tmp, x[processed:])
		xk.Down(tmp, cdTmp)
		cdTmp = 0
		remaining -= absorbLen
		processed += absorbLen
		if remaining <= 0 {
			break
		}
	}
	return nil
}
func (xk *Xoodyak) AbsorbKey(key, id, counter []byte) error {
	return nil
}

func (xk *Xoodyak) SqueezeAny(YLen uint, Cu uint8) ([]byte, error) {
	squeezeLen := xk.SqueezeSize
	if YLen < squeezeLen {
		squeezeLen = YLen
	}
	output, _ := xk.Up(Cu, squeezeLen)
	var remaining uint = YLen - squeezeLen

	for remaining > 0 {
		xk.Down([]byte{}, 0)
		if remaining < squeezeLen {
			squeezeLen = remaining
		}
		tmp, _ := xk.Up(0, squeezeLen)
		output = append(output, tmp...)
		remaining -= squeezeLen
	}
	return output, nil
}

func (xk *Xoodyak) Down(Xi []byte, Cd byte) {
	cd1 := Cd
	if xk.Mode == Hash {
		cd1 &= 0x01
	}
	fill := make([]byte, f_bPrime-(len(Xi)))
	fill[0] = 0x01
	fill[len(fill)-1] = cd1
	Xi = append(Xi, fill...)

	var downState xoodoo.XooDooState
	buf := bytes.NewReader(Xi)
	binary.Read(buf, binary.LittleEndian, &downState)
	xk.Instance.State = xoodoo.XorState(xk.Instance.State, downState)
	xk.Phase = Down
}

// TODO Get rid of the error output
func (xk *Xoodyak) Up(Cu byte, Yilen uint) ([]byte, error) {
	if xk.Mode != Hash {
		// TODO Add a byte for crypt mode
		return []byte{}, nil
	}
	xk.Instance.Permutation()
	if Yilen == 0 {
		return []byte{}, nil
	}
	tmp := xk.Instance.Bytes()
	return tmp[:Yilen], nil

}
func (xk *Xoodyak) Crypt() error {
	return nil
}
