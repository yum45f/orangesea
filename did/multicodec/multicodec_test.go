package multicodec_test

import (
	"encoding/hex"
	"reflect"
	"testing"

	"go.yumnet.cloud/orangesea/did/multicodec"
)

type TestCase struct {
	code   uint64
	name   string
	input  string
	result string
}

// These testcases are taken from this repository:
// https://github.com/multiformats/go-multicodec-packed/blob/master/multicodec_test.go
// The testcases are licensed under MIT License.
// Copyright (c) 2016 Protocol Labs Inc.

var testCases = []TestCase{
	{0x70, "dag-pb", "68656c6c6f20776f726c64", "7068656c6c6f20776f726c64"},
	{0x90, "eth-block", "68656c6c6f20776f726c64", "900168656c6c6f20776f726c64"},
	{0x96, "eth-state-trie", "68656c6c6f20776f726c64", "960168656c6c6f20776f726c64"},
	{0x30, "multicodec", "68656c6c6f20776f726c64", "3068656c6c6f20776f726c64"},
	{0x31, "multihash", "68656c6c6f20776f726c64", "3168656c6c6f20776f726c64"},
	{0x94, "eth-tx-receipt-trie", "68656c6c6f20776f726c64", "940168656c6c6f20776f726c64"},
	{0x0, "<Unknown Multicodec>", "68656c6c6f20776f726c64", "0068656c6c6f20776f726c64"},
	{0x32, "multiaddr", "68656c6c6f20776f726c64", "3268656c6c6f20776f726c64"},
	{0x91, "eth-block-list", "68656c6c6f20776f726c64", "910168656c6c6f20776f726c64"},
	{0x60, "rlp", "68656c6c6f20776f726c64", "6068656c6c6f20776f726c64"},
	{0x63, "bencode", "68656c6c6f20776f726c64", "6368656c6c6f20776f726c64"},
	{0xc1, "zcash-tx", "68656c6c6f20776f726c64", "c10168656c6c6f20776f726c64"},
	{0x7c, "torrent-file", "68656c6c6f20776f726c64", "7c68656c6c6f20776f726c64"},
	{0x69, "git", "68656c6c6f20776f726c64", "6968656c6c6f20776f726c64"},
	{0x33, "multibase", "68656c6c6f20776f726c64", "3368656c6c6f20776f726c64"},
	{0x98, "eth-storage-trie", "68656c6c6f20776f726c64", "980168656c6c6f20776f726c64"},
	{0xc0, "zcash-block", "68656c6c6f20776f726c64", "c00168656c6c6f20776f726c64"},
	{0x55, "bin", "68656c6c6f20776f726c64", "5568656c6c6f20776f726c64"},
	{0x93, "eth-tx", "68656c6c6f20776f726c64", "930168656c6c6f20776f726c64"},
	{0x95, "eth-tx-receipt", "68656c6c6f20776f726c64", "950168656c6c6f20776f726c64"},
	{0xb1, "bitcoin-tx", "68656c6c6f20776f726c64", "b10168656c6c6f20776f726c64"},
	{0xd0, "stellar-block", "68656c6c6f20776f726c64", "d00168656c6c6f20776f726c64"},
	{0x71, "dag-cbor", "68656c6c6f20776f726c64", "7168656c6c6f20776f726c64"},
	{0xd1, "stellar-tx", "68656c6c6f20776f726c64", "d10168656c6c6f20776f726c64"},
	{0x92, "eth-tx-trie", "68656c6c6f20776f726c64", "920168656c6c6f20776f726c64"},
	{0x97, "eth-account-snapshot", "68656c6c6f20776f726c64", "970168656c6c6f20776f726c64"},
	{0xb0, "bitcoin-block", "68656c6c6f20776f726c64", "b00168656c6c6f20776f726c64"},
	{0x7b, "torrent-info", "68656c6c6f20776f726c64", "7b68656c6c6f20776f726c64"},
	{0xed, "ed25519-pub", "68656c6c6f20776f726c64", "ed0168656c6c6f20776f726c64"},
}

func Test_ParseMulticodec(t *testing.T) {
	type args struct {
		multicodec []byte
	}
	type want struct {
		code  uint64
		bytes []byte
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {

			input, _ := hex.DecodeString(tt.result)
			expected, _ := hex.DecodeString(tt.input)

			gotCode, gotByte, err := multicodec.ParseMulticodec(input)

			if err != nil {
				t.Errorf("ParseMulticodec() error = %v", err)
			}
			if gotCode != tt.code {
				t.Errorf("ParseMulticodec() gotCode = %v, want %v", gotCode, tt.code)
			}
			if !reflect.DeepEqual(gotByte, expected) {
				t.Errorf("ParseMulticodec() gotByte = %v, want %v", gotByte, expected)
			}
		})
	}
}

func Test_EncodeMulticodec(t *testing.T) {
	type args struct {
		code  uint64
		bytes []byte
	}
	type want struct {
		code  uint64
		bytes []byte
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {

			input, _ := hex.DecodeString(tt.input)
			expected, _ := hex.DecodeString(tt.result)

			got := multicodec.EncodeMulticodec(tt.code, input)

			if !reflect.DeepEqual(got, expected) {
				t.Errorf("EncodeMulticodec() got = %v, want %v", got, expected)
			}
		})
	}
}
