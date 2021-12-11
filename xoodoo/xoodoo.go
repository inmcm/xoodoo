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
	laneFull  = 0xFFFFFFFF
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

// func (xdp XooDooPlane) Complement() XooDooPlane {
// 	return XooDooPlane{
// 		xdp[0] ^ laneFull,
// 		xdp[1] ^ laneFull,
// 		xdp[2] ^ laneFull,
// 		xdp[3] ^ laneFull,
// 	}
// }

// func XorPlane(a, b XooDooPlane) XooDooPlane {
// 	return XooDooPlane{
// 		a[0] ^ b[0],
// 		a[1] ^ b[1],
// 		a[2] ^ b[2],
// 		a[3] ^ b[3],
// 	}
// }

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
	for i := 0; i < 12; i++ {
		xds[i] ^= (binary.LittleEndian.Uint32(in[i*4 : (i*4)+4]))
	}

}

// func AndPlane(a, b XooDooPlane) XooDooPlane {
// 	return XooDooPlane{
// 		a[0] & b[0],
// 		a[1] & b[1],
// 		a[2] & b[2],
// 		a[3] & b[3],
// 	}

// }

// func (xdp XooDooPlane) Shift(x, z int) XooDooPlane {
// 	return XooDooPlane{
// 		XooDooLane(bits.RotateLeft32(uint32(xdp[((4-(x%4))%4)]), z)),
// 		XooDooLane(bits.RotateLeft32(uint32(xdp[(((4-(x%4))+1)%4)]), z)),
// 		XooDooLane(bits.RotateLeft32(uint32(xdp[(((4-(x%4))+2)%4)]), z)),
// 		XooDooLane(bits.RotateLeft32(uint32(xdp[(((4-(x%4))+3)%4)]), z)),
// 	}
// }

func (xds *XooDooState) UnmarshalBinary(data []byte) error {
	if len(data) != 48 {
		return fmt.Errorf("input data (%d bytes) != xoodoo state size (48 bytes)", len(data))
	}
	for i := 0; i < 12; i++ {
		xds[i] = binary.LittleEndian.Uint32(data[i*4 : (i*4)+4])
	}
	return nil
}

func (xds *XooDooState) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 48)
	for i := 0; i < 12; i++ {
		binary.LittleEndian.PutUint32(data[i*4:(i*4)+4], uint32(xds[i]))
	}
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

// func (xd *XooDoo) PermutationSlow() {
// 	xds := xd.State
// 	var B XooDooState
// 	var P, E XooDooPlane
// 	for i := 0; i < xd.rounds; i++ {
// 		// fmt.Printf("start round %d: %#08X\n", i-11, xds)

// 		// Theta Step
// 		P = XorPlane(XorPlane(xds[0], xds[1]), xds[2])
// 		// fmt.Printf("P: %#08X\n", P)
// 		E = XorPlane(P.Shift(1, 5), P.Shift(1, 14))
// 		// fmt.Printf("E: %#08X\n", E)
// 		xds = XooDooState{
// 			XorPlane(E, xds[0]),
// 			XorPlane(E, xds[1]),
// 			XorPlane(E, xds[2]),
// 		}
// 		// fmt.Printf("after theta: %#08X\n", xds)

// 		// Rho West Step
// 		xds[1] = xds[1].Shift(1, 0)
// 		xds[2] = xds[2].Shift(0, 11)
// 		// fmt.Printf("after rho west: %#08X\n", xds)

// 		// Iota Step
// 		xds[0] = XorPlane(xds[0], XooDooPlane{XooDooLane(RoundConstants[i]), 0, 0, 0})
// 		// fmt.Printf("after iota: %#08X\n", xds)

// 		// Chi Step
// 		B = XooDooState{
// 			AndPlane(xds[1].Complement(), xds[2]),
// 			AndPlane(xds[2].Complement(), xds[0]),
// 			AndPlane(xds[0].Complement(), xds[1]),
// 		}
// 		xds = XooDooState{
// 			XorPlane(xds[0], B[0]),
// 			XorPlane(xds[1], B[1]),
// 			XorPlane(xds[2], B[2]),
// 		}
// 		// fmt.Printf("after chi: %#08X\n", xds)

// 		// Rho East Step
// 		xds[1] = xds[1].Shift(0, 1)
// 		xds[2] = xds[2].Shift(2, 8)
// 		// fmt.Printf("after rho east: %#08X\n", xds)
// 	}
// 	xd.State = xds
// }

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
