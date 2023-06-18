package key_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"os"
	"reflect"
	"testing"

	"go.yumnet.cloud/orangesea/did/key"
)

type TestCaseJSON struct {
	DID       string `json:"did"`
	PublicKey struct {
		X string `json:"x"`
		Y string `json:"y"`
	} `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

type TestCase struct {
	DID         string
	PrivateKeyB []byte
	PrivateKey  *ecdsa.PrivateKey
	PublicKey   *ecdsa.PublicKey
}

var testCases []TestCase

func init() {
	testing.Init()
	var raw []TestCaseJSON
	f, err := os.Open("./testcases.json")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var data []byte
	_, err = f.Read(data)
	if err != nil {
		panic(err)
	}

	json.Unmarshal(data, &raw)

	for _, tc := range raw {
		x, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(tc.PublicKey.X)
		if err != nil {
			panic(err)
		}
		y, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(tc.PublicKey.Y)
		if err != nil {
			panic(err)
		}

		d, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(tc.PrivateKey)
		if err != nil {
			panic(err)
		}

		pub := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}

		testCases = append(testCases, TestCase{
			DID:         tc.DID,
			PrivateKeyB: d,
			PrivateKey: &ecdsa.PrivateKey{
				PublicKey: pub, D: new(big.Int).SetBytes(d),
			},
			PublicKey: &ecdsa.PublicKey{
				Curve: elliptic.P256(),
				X:     new(big.Int).SetBytes(x),
				Y:     new(big.Int).SetBytes(y),
			},
		})
	}
}

func Test_NewDIDKeyFromDID(t *testing.T) {
	type args struct {
		did string
	}

	var tests []struct {
		name    string
		args    args
		want    *key.DIDKey
		wantErr bool
	}

	for _, tc := range testCases {
		tests = append(tests, struct {
			name    string
			args    args
			want    *key.DIDKey
			wantErr bool
		}{
			name:    tc.DID,
			args:    args{did: tc.DID},
			want:    &key.DIDKey{PublicKey: *tc.PublicKey, PrivateKey: nil},
			wantErr: false,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := key.NewDIDKeyFromDID(tt.args.did)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDIDKeyFromDID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewDIDKeyFromDID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_NewDIDKeyFromPrivateKey(t *testing.T) {
	type args struct {
		privateKey []byte
	}

	var tests []struct {
		name    string
		args    args
		want    *key.DIDKey
		wantErr bool
	}

	for _, tc := range testCases {
		tests = append(tests, struct {
			name    string
			args    args
			want    *key.DIDKey
			wantErr bool
		}{
			name:    tc.DID,
			args:    args{privateKey: tc.PrivateKeyB},
			want:    &key.DIDKey{PublicKey: *tc.PublicKey, PrivateKey: tc.PrivateKey},
			wantErr: false,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := key.NewDIDKeyFromPrivateKey(tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewDIDKeyFromPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.PublicKey, tt.want.PublicKey) {
				t.Errorf("NewDIDKeyFromPrivateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDIDKey_DID(t *testing.T) {
	type fields struct {
		PublicKey  ecdsa.PublicKey
		PrivateKey *ecdsa.PrivateKey
	}

	var tests []struct {
		name   string
		fields fields
		want   string
	}

	for _, tc := range testCases {
		tests = append(tests, struct {
			name   string
			fields fields
			want   string
		}{
			name:   tc.DID,
			fields: fields{PublicKey: *tc.PublicKey, PrivateKey: tc.PrivateKey},
			want:   tc.DID,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := key.DIDKey{
				PublicKey:  tt.fields.PublicKey,
				PrivateKey: tt.fields.PrivateKey,
			}
			if got := d.DID(); got != tt.want {
				t.Errorf("DID() = %v, want %v", got, tt.want)
			}
		})
	}
}
