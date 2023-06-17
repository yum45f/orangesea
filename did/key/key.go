package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"go.yumnet.cloud/orangesea/did/multicodec"
)

type DIDKey struct {
	PublicKey  ecdsa.PublicKey
	PrivateKey *ecdsa.PrivateKey
}

func NewDIDKeyFromDID(did string) (*DIDKey, error) {
	splited := strings.Split(did, ":")
	if len(splited) != 3 {
		return nil, fmt.Errorf("invalid did format")
	}

	if splited[0] != "did" {
		return nil, fmt.Errorf("invalid did scheme; scheme must be did")
	}
	if splited[1] != "key" {
		return nil, fmt.Errorf("invalid did method; did method must be key")
	}
	if splited[2] == "" {
		return nil, fmt.Errorf("invalid did key; must not be empty")
	}

	id := splited[2]

	// did:key must encoded by base58btc
	if !strings.HasPrefix(id, "z") {
		return nil, fmt.Errorf("invalid did key; must start with z")
	}
	decoded := base58.Decode(id[1:])

	// check if this key is supported -- currently only P256Pub is supported
	code, bytes, err := multicodec.ParseMulticodec(decoded)
	if err != nil {
		return nil, err
	}
	if code != multicodec.P256Pub {
		return nil, fmt.Errorf("multicodec not supported; code: %d", code)
	}
	if bytes == nil {
		return nil, fmt.Errorf("invalid did key; decoded bytes must not be nil")
	}
	if len(bytes) != 33 {
		return nil, fmt.Errorf("invalid did key; decoded bytes must be 33 bytes")
	}

	x, y := elliptic.UnmarshalCompressed(elliptic.P256(), bytes)
	return &DIDKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		},
		PrivateKey: nil,
	}, nil
}

func NewDIDKeyFromPrivateKey(privateKey []byte) (*DIDKey, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key; must be 32 bytes")
	}

	x, y := elliptic.P256().ScalarBaseMult(privateKey)

	pubKey := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	return &DIDKey{
		PublicKey: pubKey,
		PrivateKey: &ecdsa.PrivateKey{
			PublicKey: pubKey,
			D:         new(big.Int).SetBytes(privateKey),
		},
	}, nil
}

func (did DIDKey) DID() string {
	encoded := base58.Encode(
		multicodec.EncodeMulticodec(
			multicodec.P256Pub,
			elliptic.MarshalCompressed(elliptic.P256(), did.PublicKey.X, did.PublicKey.Y),
		),
	)

	return fmt.Sprintf("did:key:z%s", encoded)
}

func (did DIDKey) Verify(hash []byte, signature []byte) bool {
	return ecdsa.VerifyASN1(
		&did.PublicKey,
		hash,
		signature,
	)
}

func (did DIDKey) Sign(digest []byte) ([]byte, error) {
	if did.PrivateKey == nil {
		return nil, fmt.Errorf("failed to sign; private key not found")
	}
	if did.PrivateKey.Curve != elliptic.P256() {
		return nil, fmt.Errorf("failed to sign; curve must be P256")
	}
	if len(digest) != 32 {
		return nil, fmt.Errorf("failed to sign; digest must be 32 bytes")
	}

	return ecdsa.SignASN1(
		rand.Reader,
		did.PrivateKey,
		digest,
	)
}
