package xoodoo

import (
	"bytes"
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
	RoundConstants = [12]XooDooLane{
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

type XooDooLane uint32
type XooDooPlane [4]XooDooLane
type XooDooState [3]XooDooPlane

type XooDoo struct {
	State  XooDooState
	rounds int
}

func (xdp XooDooPlane) Complement() XooDooPlane {
	return XooDooPlane{
		xdp[0] ^ laneFull,
		xdp[1] ^ laneFull,
		xdp[2] ^ laneFull,
		xdp[3] ^ laneFull,
	}
}

func XorPlane(a, b XooDooPlane) XooDooPlane {
	return XooDooPlane{
		a[0] ^ b[0],
		a[1] ^ b[1],
		a[2] ^ b[2],
		a[3] ^ b[3],
	}
}

func XorState(a, b XooDooState) XooDooState {
	return XooDooState{
		XooDooPlane{
			a[0][0] ^ b[0][0],
			a[0][1] ^ b[0][1],
			a[0][2] ^ b[0][2],
			a[0][3] ^ b[0][3],
		},
		XooDooPlane{
			a[1][0] ^ b[1][0],
			a[1][1] ^ b[1][1],
			a[1][2] ^ b[1][2],
			a[1][3] ^ b[1][3],
		},
		XooDooPlane{
			a[2][0] ^ b[2][0],
			a[2][1] ^ b[2][1],
			a[2][2] ^ b[2][2],
			a[2][3] ^ b[2][3],
		},
	}
}

func (xds *XooDooState) XorStateBytes(in []byte) {
	var x, j, i int
	for i = 0; i < 3; i++ {
		for j = 0; j < 4; j++ {
			x = (i << 4) + (j << 2)
			xds[i][j] ^= XooDooLane(binary.LittleEndian.Uint32(in[x : x+4]))
		}
	}
}

func AndPlane(a, b XooDooPlane) XooDooPlane {
	return XooDooPlane{
		a[0] & b[0],
		a[1] & b[1],
		a[2] & b[2],
		a[3] & b[3],
	}

}

func (xdp XooDooPlane) Shift(x, z int) XooDooPlane {
	return XooDooPlane{
		XooDooLane(bits.RotateLeft32(uint32(xdp[((4-(x%4))%4)]), z)),
		XooDooLane(bits.RotateLeft32(uint32(xdp[(((4-(x%4))+1)%4)]), z)),
		XooDooLane(bits.RotateLeft32(uint32(xdp[(((4-(x%4))+2)%4)]), z)),
		XooDooLane(bits.RotateLeft32(uint32(xdp[(((4-(x%4))+3)%4)]), z)),
	}
}

func (xds *XooDooState) UnmarshalBinary(data []byte) error {
	if len(data) != 48 {
		return fmt.Errorf("input data (%d bytes) != xoodoo state size (48 bytes)", len(data))
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			x := (i * 16) + (j * 4)
			xds[i][j] = XooDooLane(binary.LittleEndian.Uint32(data[x : x+4]))
		}
	}
	return nil
}

func (xds *XooDooState) MarshalBinary() (data []byte, err error) {
	data = make([]byte, 48)
	for i := 0; i < 3; i++ {
		for j := 0; j < 4; j++ {
			x := (i * 16) + (j * 4)
			binary.LittleEndian.PutUint32(data[x:x+4], uint32(xds[i][j]))
		}
	}
	return data, nil
}

func NewXooDoo(rounds int, state [48]byte) (*XooDoo, error) {
	var new XooDoo
	new.rounds = rounds
	if rounds > len(RoundConstants) {
		return nil, fmt.Errorf("invalid number of rounds: %d", rounds)
	}
	buf := bytes.NewReader(state[:])
	err := binary.Read(buf, binary.LittleEndian, &new.State)
	if err != nil {
		return nil, fmt.Errorf("invalid initial state")
	}
	return &new, nil
}

func (xd *XooDoo) Bytes() []byte {
	buf, _ := xd.State.MarshalBinary()
	return buf
}

func (xd *XooDoo) PermutationSlow() {
	xds := xd.State
	var B XooDooState
	var P, E XooDooPlane
	for i := 0; i < xd.rounds; i++ {
		// fmt.Printf("start round %d: %#08X\n", i-11, xds)

		// Theta Step
		P = XorPlane(XorPlane(xds[0], xds[1]), xds[2])
		// fmt.Printf("P: %#08X\n", P)
		E = XorPlane(P.Shift(1, 5), P.Shift(1, 14))
		// fmt.Printf("E: %#08X\n", E)
		xds = XooDooState{
			XorPlane(E, xds[0]),
			XorPlane(E, xds[1]),
			XorPlane(E, xds[2]),
		}
		// fmt.Printf("after theta: %#08X\n", xds)

		// Rho West Step
		xds[1] = xds[1].Shift(1, 0)
		xds[2] = xds[2].Shift(0, 11)
		// fmt.Printf("after rho west: %#08X\n", xds)

		// Iota Step
		xds[0] = XorPlane(xds[0], XooDooPlane{XooDooLane(RoundConstants[i]), 0, 0, 0})
		// fmt.Printf("after iota: %#08X\n", xds)

		// Chi Step
		B = XooDooState{
			AndPlane(xds[1].Complement(), xds[2]),
			AndPlane(xds[2].Complement(), xds[0]),
			AndPlane(xds[0].Complement(), xds[1]),
		}
		xds = XooDooState{
			XorPlane(xds[0], B[0]),
			XorPlane(xds[1], B[1]),
			XorPlane(xds[2], B[2]),
		}
		// fmt.Printf("after chi: %#08X\n", xds)

		// Rho East Step
		xds[1] = xds[1].Shift(0, 1)
		xds[2] = xds[2].Shift(2, 8)
		// fmt.Printf("after rho east: %#08X\n", xds)
	}
	xd.State = xds
}

// Permutation executes an optimized implementation of Xoodoo permutation over the provided
// xoodoo state
func (xd *XooDoo) Permutation() {
	xds := xd.State
	var tmp XooDooState
	var P, E XooDooPlane
	for i := MaxRounds - xd.rounds; i < MaxRounds; i++ {
		P = XooDooPlane{
			xds[0][0] ^ xds[1][0] ^ xds[2][0],
			xds[0][1] ^ xds[1][1] ^ xds[2][1],
			xds[0][2] ^ xds[1][2] ^ xds[2][2],
			xds[0][3] ^ xds[1][3] ^ xds[2][3],
		}
		E = XooDooPlane{
			XooDooLane(bits.RotateLeft32(uint32(P[3]), 5)) ^ XooDooLane(bits.RotateLeft32(uint32(P[3]), 14)),
			XooDooLane(bits.RotateLeft32(uint32(P[0]), 5)) ^ XooDooLane(bits.RotateLeft32(uint32(P[0]), 14)),
			XooDooLane(bits.RotateLeft32(uint32(P[1]), 5)) ^ XooDooLane(bits.RotateLeft32(uint32(P[1]), 14)),
			XooDooLane(bits.RotateLeft32(uint32(P[2]), 5)) ^ XooDooLane(bits.RotateLeft32(uint32(P[2]), 14)),
		}

		tmp[0][0] = E[0] ^ xds[0][0] ^ RoundConstants[i]
		tmp[0][1] = E[1] ^ xds[0][1]
		tmp[0][2] = E[2] ^ xds[0][2]
		tmp[0][3] = E[3] ^ xds[0][3]

		tmp[1][0] = E[3] ^ xds[1][3]
		tmp[1][1] = E[0] ^ xds[1][0]
		tmp[1][2] = E[1] ^ xds[1][1]
		tmp[1][3] = E[2] ^ xds[1][2]

		tmp[2][0] = XooDooLane(bits.RotateLeft32(uint32(E[0]^xds[2][0]), 11))
		tmp[2][1] = XooDooLane(bits.RotateLeft32(uint32(E[1]^xds[2][1]), 11))
		tmp[2][2] = XooDooLane(bits.RotateLeft32(uint32(E[2]^xds[2][2]), 11))
		tmp[2][3] = XooDooLane(bits.RotateLeft32(uint32(E[3]^xds[2][3]), 11))

		xds[0][0] = (^tmp[1][0] & tmp[2][0]) ^ tmp[0][0]
		xds[0][1] = (^tmp[1][1] & tmp[2][1]) ^ tmp[0][1]
		xds[0][2] = (^tmp[1][2] & tmp[2][2]) ^ tmp[0][2]
		xds[0][3] = (^tmp[1][3] & tmp[2][3]) ^ tmp[0][3]

		xds[1][0] = XooDooLane(bits.RotateLeft32(uint32((^tmp[2][0]&tmp[0][0])^tmp[1][0]), 1))
		xds[1][1] = XooDooLane(bits.RotateLeft32(uint32((^tmp[2][1]&tmp[0][1])^tmp[1][1]), 1))
		xds[1][2] = XooDooLane(bits.RotateLeft32(uint32((^tmp[2][2]&tmp[0][2])^tmp[1][2]), 1))
		xds[1][3] = XooDooLane(bits.RotateLeft32(uint32((^tmp[2][3]&tmp[0][3])^tmp[1][3]), 1))

		xds[2][0] = XooDooLane(bits.RotateLeft32(uint32((^tmp[0][2]&tmp[1][2])^tmp[2][2]), 8))
		xds[2][1] = XooDooLane(bits.RotateLeft32(uint32((^tmp[0][3]&tmp[1][3])^tmp[2][3]), 8))
		xds[2][2] = XooDooLane(bits.RotateLeft32(uint32((^tmp[0][0]&tmp[1][0])^tmp[2][0]), 8))
		xds[2][3] = XooDooLane(bits.RotateLeft32(uint32((^tmp[0][1]&tmp[1][1])^tmp[2][1]), 8))

	}
	xd.State = xds
}
