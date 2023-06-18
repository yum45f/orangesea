package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"

	"go.yumnet.cloud/orangesea/did/key"
	"go.yumnet.cloud/orangesea/did/plc"
)

type TestCase struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
	DID        string `json:"did"`
}

func generateKeyPair(pubkeyPath string, prvKeyPath string) error {
	prv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	encoded, err := x509.MarshalPKCS8PrivateKey(prv)
	if err != nil {
		return err
	}

	encodedPub, err := x509.MarshalPKIXPublicKey(&prv.PublicKey)
	if err != nil {
		return err
	}

	prvfile, err := os.Create(prvKeyPath)
	if err != nil {
		return err
	}
	defer func() {
		err := prvfile.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	if err := pem.Encode(prvfile, &pem.Block{
		Type: "PRIVATE KEY", Bytes: encoded,
	}); err != nil {
		return err
	}

	pubfile, err := os.Create(pubkeyPath)
	if err != nil {
		return err
	}
	defer func() {
		err := pubfile.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	if err := pem.Encode(pubfile, &pem.Block{
		Type: "PRIVATE KEY", Bytes: encodedPub,
	}); err != nil {
		return err
	}

	return nil
}

func loadPrivateKey(prvKeyPath string) (*ecdsa.PrivateKey, error) {
	prvfile, err := os.Open(prvKeyPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := prvfile.Close()
		if err != nil {
			fmt.Println(err)
		}
	}()

	prvBytes, err := os.ReadFile(prvKeyPath)
	if err != nil {
		return nil, err
	}

	prvBlock, _ := pem.Decode(prvBytes)
	if prvBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	prv, err := x509.ParsePKCS8PrivateKey(prvBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return prv.(*ecdsa.PrivateKey), nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: cmd <command> [<args>]")
		fmt.Println("Available commands:")
		fmt.Println("genkeys <pubkey_path> <prvkey_path>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "genkeys":
		if len(os.Args) != 4 {
			fmt.Println("Usage: cmd genkeys <pubkey_path> <prvkey_path>")
			os.Exit(1)
		}
		err := generateKeyPair(os.Args[2], os.Args[3])
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
	case "did:plc":
		if len(os.Args) <= 2 {
			fmt.Println("Usage: cmd did:plc <command> [<args>]")
			fmt.Println("Available commands:")
			fmt.Println("create <prvkey_path>")
			fmt.Println("calc <prvkey_path>")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "create":
			if len(os.Args) != 4 {
				fmt.Println("Usage: cmd did:plc create <prvkey_path>")
				os.Exit(1)
			}
			prv, err := loadPrivateKey(os.Args[3])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			didKey, err := key.NewDIDKeyFromPrivateKey(prv.D.Bytes())
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			didPlc := plc.DIDPlc{
				RotationKeys: []*key.DIDKey{didKey},
				VerificationMethods: map[string]*key.DIDKey{
					"key-1": didKey,
				},
				AlsoKnownAs: []string{},
				Services:    map[string]plc.Service{},
			}

			if err := didPlc.Create(); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("DID:", didPlc.DID)

		case "calc":
			if len(os.Args) != 4 {
				fmt.Println("Usage: cmd calc <prvkey_path>")
				os.Exit(1)
			}

			prv, err := loadPrivateKey(os.Args[3])
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			didKey, err := key.NewDIDKeyFromPrivateKey(prv.D.Bytes())
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			didPlc := plc.DIDPlc{
				RotationKeys: []*key.DIDKey{didKey},
				VerificationMethods: map[string]*key.DIDKey{
					"key-1": didKey,
				},
				AlsoKnownAs: []string{},
				Services:    map[string]plc.Service{},
			}

			did, op, err := didPlc.CalcDID()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			encOp, err := json.MarshalIndent(op, "", "  ")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			fmt.Println("DID:", did)
			fmt.Printf("Operation: %s\n", encOp)
		default:
			fmt.Println("Unknown command:", os.Args[2])
			os.Exit(1)
		}

	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}
