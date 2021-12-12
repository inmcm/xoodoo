package xoodoo

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

const (
	// MaxRounds is current ceiling on how many iterations of Xoodoo can be done in the permutation
	// function
	MaxRounds = 12
)

var (
	// RoundConstants is the sequence of 32-bit constants applied in each round of Xoodoo
	RoundConstants = [12]uint32{
		0x00000058,
		0x00000038,
		0x000003C0,
		0x000000D0,
		0x00000120,
		0x00000014,
		0x00000060,
		0x0000002C,
		0x00000380,
		0x000000F0,
		0x000001A0,
		0x00000012,
	}
)

type XooDooState [12]uint32

type XooDoo struct {
	State  XooDooState
	rounds int
}

func XorState(a, b XooDooState) XooDooState {
	return XooDooState{
		a[0] ^ b[0],
		a[1] ^ b[1],
		a[2] ^ b[2],
		a[3] ^ b[3],
		a[4] ^ b[4],
		a[5] ^ b[5],
		a[6] ^ b[6],
		a[7] ^ b[7],
		a[8] ^ b[8],
		a[9] ^ b[9],
		a[10] ^ b[10],
		a[11] ^ b[11],
	}
}

func (xds *XooDooState) XorStateBytes(in []byte) {
	xds[0] ^= (binary.LittleEndian.Uint32(in[0:4]))
	xds[1] ^= (binary.LittleEndian.Uint32(in[4:8]))
	xds[2] ^= (binary.LittleEndian.Uint32(in[8:12]))
	xds[3] ^= (binary.LittleEndian.Uint32(in[12:16]))
	xds[4] ^= (binary.LittleEndian.Uint32(in[16:20]))
	xds[5] ^= (binary.LittleEndian.Uint32(in[20:24]))
	xds[6] ^= (binary.LittleEndian.Uint32(in[24:28]))
	xds[7] ^= (binary.LittleEndian.Uint32(in[28:32]))
	xds[8] ^= (binary.LittleEndian.Uint32(in[32:36]))
	xds[9] ^= (binary.LittleEndian.Uint32(in[36:40]))
	xds[10] ^= (binary.LittleEndian.Uint32(in[40:44]))
	xds[11] ^= (binary.LittleEndian.Uint32(in[44:48]))
}

func (xds *XooDooState) UnmarshalBinary(data []byte) error {
	if len(data) != 48 {
		return fmt.Errorf("input data (%d bytes) != xoodoo state size (48 bytes)", len(data))
	}
	xds[0] = (binary.LittleEndian.Uint32(data[0:4]))
	xds[1] = (binary.LittleEndian.Uint32(data[4:8]))
	xds[2] = (binary.LittleEndian.Uint32(data[8:12]))
	xds[3] = (binary.LittleEndian.Uint32(data[12:16]))
	xds[4] = (binary.LittleEndian.Uint32(data[16:20]))
	xds[5] = (binary.LittleEndian.Uint32(data[20:24]))
	xds[6] = (binary.LittleEndian.Uint32(data[24:28]))
	xds[7] = (binary.LittleEndian.Uint32(data[28:32]))
	xds[8] = (binary.LittleEndian.Uint32(data[32:36]))
	xds[9] = (binary.LittleEndian.Uint32(data[36:40]))
	xds[10] = (binary.LittleEndian.Uint32(data[40:44]))
	xds[11] = (binary.LittleEndian.Uint32(data[44:48]))
	return nil
}

func (xds *XooDooState) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 48)
	binary.LittleEndian.PutUint32(data[0:4], xds[0])
	binary.LittleEndian.PutUint32(data[4:8], xds[1])
	binary.LittleEndian.PutUint32(data[8:12], xds[2])
	binary.LittleEndian.PutUint32(data[12:16], xds[3])
	binary.LittleEndian.PutUint32(data[16:20], xds[4])
	binary.LittleEndian.PutUint32(data[20:24], xds[5])
	binary.LittleEndian.PutUint32(data[24:28], xds[6])
	binary.LittleEndian.PutUint32(data[28:32], xds[7])
	binary.LittleEndian.PutUint32(data[32:36], xds[8])
	binary.LittleEndian.PutUint32(data[36:40], xds[9])
	binary.LittleEndian.PutUint32(data[40:44], xds[10])
	binary.LittleEndian.PutUint32(data[44:48], xds[11])
	return data, nil
}

func NewXooDoo(rounds int, state [48]byte) (*XooDoo, error) {
	var new XooDoo
	new.rounds = rounds
	if rounds > len(RoundConstants) {
		return nil, fmt.Errorf("invalid number of rounds: %d", rounds)
	}
	err := new.State.UnmarshalBinary(state[:])
	if err != nil {
		return nil, fmt.Errorf("invalid initial state")
	}
	return &new, nil
}

func (xd *XooDoo) Bytes() []byte {
	buf, _ := xd.State.MarshalBinary()
	return buf
}

// Permutation executes an optimized implementation of Xoodoo permutation over the provided
// xoodoo state
func (xd *XooDoo) Permutation() {
	xds := xd.State
	var tmp XooDooState
	var P, E [4]uint32
	for i := MaxRounds - xd.rounds; i < MaxRounds; i++ {
		P = [4]uint32{
			xds[0] ^ xds[4] ^ xds[8],
			xds[1] ^ xds[5] ^ xds[9],
			xds[2] ^ xds[6] ^ xds[10],
			xds[3] ^ xds[7] ^ xds[11],
		}
		E = [4]uint32{
			bits.RotateLeft32(P[3], 5) ^ bits.RotateLeft32(P[3], 14),
			bits.RotateLeft32(P[0], 5) ^ bits.RotateLeft32(P[0], 14),
			bits.RotateLeft32(P[1], 5) ^ bits.RotateLeft32(P[1], 14),
			bits.RotateLeft32(P[2], 5) ^ bits.RotateLeft32(P[2], 14),
		}

		tmp[0] = E[0] ^ xds[0] ^ RoundConstants[i]
		tmp[1] = E[1] ^ xds[1]
		tmp[2] = E[2] ^ xds[2]
		tmp[3] = E[3] ^ xds[3]

		tmp[4] = E[3] ^ xds[7]
		tmp[5] = E[0] ^ xds[4]
		tmp[6] = E[1] ^ xds[5]
		tmp[7] = E[2] ^ xds[6]

		tmp[8] = bits.RotateLeft32(E[0]^xds[8], 11)
		tmp[9] = bits.RotateLeft32(E[1]^xds[9], 11)
		tmp[10] = bits.RotateLeft32(E[2]^xds[10], 11)
		tmp[11] = bits.RotateLeft32(E[3]^xds[11], 11)

		xds[0] = (^tmp[4] & tmp[8]) ^ tmp[0]
		xds[1] = (^tmp[5] & tmp[9]) ^ tmp[1]
		xds[2] = (^tmp[6] & tmp[10]) ^ tmp[2]
		xds[3] = (^tmp[7] & tmp[11]) ^ tmp[3]

		xds[4] = bits.RotateLeft32((^tmp[8]&tmp[0])^tmp[4], 1)
		xds[5] = bits.RotateLeft32((^tmp[9]&tmp[1])^tmp[5], 1)
		xds[6] = bits.RotateLeft32((^tmp[10]&tmp[2])^tmp[6], 1)
		xds[7] = bits.RotateLeft32((^tmp[11]&tmp[3])^tmp[7], 1)

		xds[8] = bits.RotateLeft32((^tmp[2]&tmp[6])^tmp[10], 8)
		xds[9] = bits.RotateLeft32((^tmp[3]&tmp[7])^tmp[11], 8)
		xds[10] = bits.RotateLeft32((^tmp[0]&tmp[4])^tmp[8], 8)
		xds[11] = bits.RotateLeft32((^tmp[1]&tmp[5])^tmp[9], 8)

	}
	xd.State = xds
}
