package multicodec

import (
	"encoding/binary"
	"fmt"
)

const (
	MaxLenUvarint63   = 9
	MaxValueUvarint63 = (1 << 63) - 1
)

const (
	P256Pub = 0x1200
)

func ParseMulticodec(multicodec []byte) (uint64, []byte, error) {
	code, n := binary.Uvarint(multicodec)
	if n <= 0 {
		return 0, nil, fmt.Errorf("invalid multicodec; varint overflow")
	}

	return code, multicodec[n:], nil
}

func EncodeMulticodec(code uint64, bytes []byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutUvarint(buf, code)
	return append(buf[:n], bytes...)
}
