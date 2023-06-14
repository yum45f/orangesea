package key

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"go.yumnet.cloud/orangesea/did/multicodec"
)

type Secp256k1PubKey struct {
	X []byte
	Y []byte
}

func (p Secp256k1PubKey) Compress() []byte {
	return secp256k1.CompressPubkey(
		new(big.Int).SetBytes(p.X),
		new(big.Int).SetBytes(p.Y),
	)
}

type DIDKey struct {
	PublicKey  Secp256k1PubKey
	PrivateKey []byte
}

func NewDIDKey() (*DIDKey, error) {
	params := secp256k1.S256().Params()
	priv, x, y, err := elliptic.GenerateKey(params, rand.Reader)
	if err != nil {
		return nil, err
	}

	return &DIDKey{
		PublicKey: Secp256k1PubKey{
			X: x.Bytes(),
			Y: y.Bytes(),
		},
		PrivateKey: priv,
	}, nil
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
	if code != multicodec.Secp256k1 {
		return nil, fmt.Errorf("multicodec not supported; code: %d", code)
	}
	if bytes == nil {
		return nil, fmt.Errorf("invalid did key; decoded bytes must not be nil")
	}
	if len(bytes) != 33 {
		return nil, fmt.Errorf("invalid did key; decoded bytes must be 33 bytes")
	}

	x, y := secp256k1.DecompressPubkey(bytes)

	return &DIDKey{
		PublicKey: Secp256k1PubKey{
			X: x.Bytes(),
			Y: y.Bytes(),
		},
		PrivateKey: nil,
	}, nil
}

func NewDIDKeyFromPrivateKey(privateKey []byte) (*DIDKey, error) {
	if len(privateKey) != 32 {
		return nil, fmt.Errorf("invalid private key; must be 32 bytes")
	}

	x, y := secp256k1.S256().ScalarBaseMult(privateKey)

	return &DIDKey{
		PublicKey: Secp256k1PubKey{
			X: x.Bytes(),
			Y: y.Bytes(),
		},
		PrivateKey: privateKey,
	}, nil
}

func (k DIDKey) DID() string {
	encoded := base58.Encode(
		multicodec.EncodeMulticodec(
			multicodec.Secp256k1,
			k.PublicKey.Compress(),
		),
	)

	return fmt.Sprintf("did:key:z%s", encoded)
}

func (k DIDKey) Verify(message []byte, signature []byte) bool {
	return secp256k1.VerifySignature(
		k.PublicKey.Compress(),
		message,
		signature,
	)
}

func (k DIDKey) Sign(message []byte) ([]byte, error) {
	if k.PrivateKey == nil {
		return nil, fmt.Errorf("failed to sign; private key not found")
	}

	return secp256k1.Sign(message, k.PrivateKey)
}
