package xoodyak

const (
	CryptoHashBytes = 32
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

	output, err := newXd.Squeeze(CryptoHashBytes)
	if err != nil {
		return []byte{}, err
	}
	return output, nil
}

func DoHash(in []byte) ([]byte, error) {
	return cryptoHash(in, CryptoHashBytes)
}

func DoHashLen(in []byte, hLen uint) ([]byte, error) {
	return cryptoHash(in, hLen)
}

/* Generic Hash Function Support */
func NewHash() (*Xoodyak, error) {
	return Instantiate([]byte{}, []byte{}, []byte{})
}
