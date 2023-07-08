package rkey

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"
)

type RKeyType int

var CLOCK_ID uint16

func init() {
	rand, err := rand.Int(
		rand.Reader,
		big.NewInt(1023),
	)
	if err != nil {
		panic(err)
	}

	CLOCK_ID = uint16(rand.Uint64())
}

const (
	// rkey types
	TYPE_TID RKeyType = iota
	TYPE_LITERAL
	TYPE_ANY
)

func (t RKeyType) String() string {
	switch t {
	case TYPE_TID:
		return "tid"
	case TYPE_LITERAL:
		return "literal"
	case TYPE_ANY:
		return "any"
	default:
		return "unknown"
	}
}

const (
	S32_ALPHABET = "234567abcdefghijklmnopqrstuvwxyz"
)

type RKey interface {
	Value() string
	Type() RKeyType
}

func s32encode(n uint64) string {
	var s string
	for n > 0 {
		s = string(S32_ALPHABET[n%32]) + s
		n /= 32
	}
	return s
}

func s32decode(s string) uint64 {
	var n uint64
	for _, c := range s {
		n *= 32
		n += uint64(strings.IndexRune(S32_ALPHABET, c))
	}
	return n
}

func validateRKey(rkey string) bool {
	r := regexp.MustCompile(`^[A-Za-z0-9.\-_~]{1,512}$`)
	if ok := r.MatchString(rkey); !ok {
		return false
	}

	if rkey == "." || rkey == ".." {
		return false
	}

	return true
}

// TID is a struct that represents a TID rkey.
type TID struct {
	timestamp time.Time
	clockID   uint16
}

// NewTIDFromRKey returns a new generated TID.
func NewTID() *TID {
	return &TID{
		timestamp: time.Now(),
		clockID:   CLOCK_ID,
	}
}

// String returns the string representation of the TID
// this is the same as calling TID.Value()
func (tid *TID) String() string {
	now := s32encode(
		uint64(time.Now().UnixMicro()),
	)

	cid := s32encode(
		uint64(tid.clockID),
	)

	// pad with "2" while the clockid7s length is less than 2.
	// this is based on implementation by the reference implementation.
	// https://github.com/bluesky-social/atproto/blob/main/packages/common-web/src/tid.ts
	for len(cid) < 2 {
		cid = "2" + cid
	}

	return now + cid
}

// Value returns the string representation of the TID
// this is the same as calling TID.String()
func (tid *TID) Value() string {
	return tid.String()
}

// Type returns the type of the rkey
// this is always TYPE_TID for TID
func (tid *TID) Type() RKeyType {
	return TYPE_TID
}

type Literal struct {
	value string
}

// NewLiteralFromRKey returns a new Literal from a string
// if the string is not a valid rkey, it will return nil and error
func NewLiteral(value string) (*Literal, error) {
	if !validateRKey(value) {
		return nil, fmt.Errorf("invalid rkey: %s", value)
	}

	return &Literal{
		value: value,
	}, nil
}

// String returns the string representation of the Literal
// this is the same as calling Literal.Value()
func (literal *Literal) String() string {
	return literal.value
}

// Value returns the string representation of the Literal
// this is the same as calling Literal.String()
func (literal *Literal) Value() string {
	return literal.String()
}

// Type returns the type of the rkey
// this is always TYPE_LITERAL for literal
func (literal *Literal) Type() RKeyType {
	return TYPE_LITERAL
}

type Any struct {
	value string
}

// NewAnyFrom returns a new Any from a string
func NewAny(value string) (*Any, error) {
	if !validateRKey(value) {
		return nil, fmt.Errorf("invalid rkey: %s", value)
	}

	return &Any{
		value: value,
	}, nil
}

// String returns the string representation of the Any
// this is the same as calling Any.Value()
func (any *Any) String() string {
	return any.value
}

// Value returns the string representation of the Any
// this is the same as calling Any.String()
func (any *Any) Value() string {
	return any.String()
}

// Type returns the type of the rkey
// this is always TYPE_ANY for Any
func (any *Any) Type() RKeyType {
	return TYPE_ANY
}
