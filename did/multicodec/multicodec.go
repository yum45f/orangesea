package multicodec

import (
	"fmt"
)

const (
	Secp256k1 uint64 = 0xe7
)

func ParseMulticodec(multicodec []byte) (uint64, []byte, error) {
	if len(multicodec) < 2 {
		return 0, nil, fmt.Errorf("multicodec must be at least 2 bytes")
	}

	code := uint64(multicodec[0])<<8 + uint64(multicodec[1])
	bytes := multicodec[2:]

	return code, bytes, nil
}

func EncodeMulticodec(code uint64, bytes []byte) []byte {
	return append([]byte{byte(code >> 8), byte(code)}, bytes...)
}
