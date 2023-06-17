package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
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

	encoded, err := x509.MarshalECPrivateKey(prv)
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
		Type: "EC PRIVATE KEY", Bytes: encoded,
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
		Type: "EC PUBLIC KEY", Bytes: encodedPub,
	}); err != nil {
		return err
	}

	return nil
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
	default:
		fmt.Println("Unknown command:", os.Args[1])
		os.Exit(1)
	}
}
