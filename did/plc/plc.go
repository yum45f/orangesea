package plc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	didkey "go.yumnet.cloud/orangesea/did/key"
)

type OperationObject struct {
	Type                string             `json:"type"`
	RotationKeys        []string           `json:"rotationKeys"`
	VerificationMethods map[string]string  `json:"verificationMethods"`
	AlsoKnownAs         []string           `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
	Prev                *string            `json:"prev"`
	Sig                 *string            `json:"sig"`
}

type Operation struct {
	CID       string          `json:"cid"`
	Operation OperationObject `json:"operation"`
	Nullified bool            `json:"nullified"`
	CreatedAt string          `json:"createdAt"`
}

type Service struct {
	Type     string `json:"type"`
	Endpoint string `json:"endpoint"`
}

type DIDPlcData struct {
	DID                 string             `json:"did"`
	VerificationMethods map[string]string  `json:"verificationMethods"`
	RotationKeys        []string           `json:"rotationKeys"`
	AlsoKnownAs         []string           `json:"alsoKnownAs"`
	Services            map[string]Service `json:"services"`
}

type DIDPlc struct {
	DID                 string
	RotationKeys        []*didkey.DIDKey
	VerificationMethods map[string]*didkey.DIDKey
	AlsoKnownAs         []string
	Services            map[string]Service
	Operations          []Operation
	OpCount             uint
}

func NewDIDPlc(did string) {
}

func (d *DIDPlc) unsignedOperation() (*OperationObject, error) {
	if len(d.RotationKeys) < 1 {
		return nil, fmt.Errorf("rotationKeys must be at least 1")
	}

	roatationKeys := make([]string, len(d.RotationKeys))
	for i, key := range d.RotationKeys {
		roatationKeys[i] = key.DID()
	}

	verificationMethods := make(map[string]string)
	for name, key := range d.VerificationMethods {
		verificationMethods[name] = key.DID()
	}

	unsigned := OperationObject{
		Type:                "plc_operation",
		RotationKeys:        roatationKeys,
		VerificationMethods: verificationMethods,
		AlsoKnownAs:         d.AlsoKnownAs,
		Services:            d.Services,
		Prev:                nil,
		Sig:                 nil,
	}

	return &unsigned, nil
}

func (d *DIDPlc) FetchData() error {
	if d.DID == "" {
		return fmt.Errorf("failed to fetch data from plc.directory; DID is empty")
	}

	resp, err := http.Get(fmt.Sprintf("https://plc.directory/%s/data", d.DID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"failed to fetch data from plc.directory; status code: %d", resp.StatusCode,
		)
	}

	var data DIDPlcData
	err = json.NewDecoder(resp.Body).Decode(&data)
	if err != nil {
		return err
	}

	for _, key := range data.RotationKeys {
		kstruct, err := didkey.NewDIDKeyFromDID(key)
		if err != nil {
			return err
		}
		d.RotationKeys = append(d.RotationKeys, kstruct)
	}

	for name, key := range data.VerificationMethods {
		kstruct, err := didkey.NewDIDKeyFromDID(key)
		if err != nil {
			return err
		}
		d.VerificationMethods[name] = kstruct
	}

	d.AlsoKnownAs = data.AlsoKnownAs
	d.Services = data.Services

	return nil
}

func (d *DIDPlc) FetchAuditLog() error {
	if d.DID == "" {
		return fmt.Errorf("failed to fetch data from plc.directory; DID is empty")
	}

	resp, err := http.Get(fmt.Sprintf("https://plc.directory/%s/log/audit", d.DID))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"failed to fetch data from plc.directory; status code: %d", resp.StatusCode,
		)
	}

	var operations []Operation

	err = json.NewDecoder(resp.Body).Decode(&operations)
	if err != nil {
		return err
	}

	d.Operations = operations
	return nil
}

func (d *DIDPlc) Create(keyID int) error {
	if err := d.FetchAuditLog(); err != nil {
		return err
	}
	if len(d.Operations) != 0 {
		return fmt.Errorf("operations must be empty")
	}

	if keyID >= len(d.RotationKeys) {
		return fmt.Errorf("invalid keyID; keyID is out of range")
	}

	key := d.RotationKeys[keyID]
	if key == nil {
		return fmt.Errorf("invalid keyID; key is nil")
	}

	unsigned, err := d.unsignedOperation()
	if err != nil {
		return err
	}

	encoded, err := ipld.Marshal(dagcbor.Encode, unsigned, nil)
	if err != nil {
		return err
	}

	sig, err := key.Sign(encoded)
	if err != nil {
		return err
	}

	s := base64.URLEncoding.EncodeToString(sig)
	unsigned.Sig = &s
	signed, err := ipld.Marshal(dagcbor.Encode, unsigned, nil)
	if err != nil {
		return err
	}

	hashed := sha256.Sum256(signed)

	// did:plc is the first 24 hex characters of the hashed value
	did := fmt.Sprintf("did:plc:%x", hashed[:12])

	body, err := json.Marshal(signed)
	if err != nil {
		return err
	}

	resp, err := http.Post(
		fmt.Sprintf("https://plc.directory/%s", did),
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to create DID; status code: %d", resp.StatusCode)
	}

	return nil
}
