package plc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/node/bindnode"
	"github.com/ipld/go-ipld-prime/schema"
	didkey "go.yumnet.cloud/orangesea/did/key"
)

const (
	PLC_DIRECTORY_BASEURL = "http://localhost:2582"
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

func (o *OperationObject) IPLDNode() *OperationIPLDNode {

	vmKeys := make([]string, 0, len(o.VerificationMethods))
	for k := range o.VerificationMethods {
		vmKeys = append(vmKeys, k)
	}

	svcKeys := make([]string, 0, len(o.Services))
	for k := range o.Services {
		svcKeys = append(svcKeys, k)
	}

	return &OperationIPLDNode{
		Type:         o.Type,
		RotationKeys: o.RotationKeys,
		VerificationMethods: struct {
			Keys   []string
			Values map[string]string
		}{
			Keys:   vmKeys,
			Values: o.VerificationMethods,
		},
		AlsoKnownAs: o.AlsoKnownAs,
		Services: struct {
			Keys   []string
			Values map[string]Service
		}{
			Keys:   svcKeys,
			Values: o.Services,
		},
		Prev: o.Prev,
		Sig:  o.Sig,
	}
}

type OperationIPLDNode struct {
	Type                string   `json:"type"`
	RotationKeys        []string `json:"rotationKeys"`
	VerificationMethods struct {
		Keys   []string
		Values map[string]string
	} `json:"verificationMethods"`
	AlsoKnownAs []string `json:"alsoKnownAs"`
	Services    struct {
		Keys   []string
		Values map[string]Service
	} `json:"services"`
	Prev *string `json:"prev"`
	Sig  *string `json:"sig"`
}

func (n *OperationIPLDNode) OperationObject() *OperationObject {
	return &OperationObject{
		Type:                n.Type,
		RotationKeys:        n.RotationKeys,
		VerificationMethods: n.VerificationMethods.Values,
		AlsoKnownAs:         n.AlsoKnownAs,
		Services:            n.Services.Values,
		Prev:                n.Prev,
		Sig:                 n.Sig,
	}
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

var (
	OperationSchema schema.Type
)

func init() {
	schema, err := ipld.LoadSchemaBytes([]byte(`
		type Operation struct {
			type String
			rotationKeys [String]
			verificationMethods { String: String }
			alsoKnownAs [String]
			services { String: Service }
			prev nullable String
			sig optional String
		} representation map

		type Service struct {
			type String
			endpoint String
		} representation map
	`))
	if err != nil {
		panic(err)
	}

	OperationSchema = schema.TypeByName("Operation")
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

	resp, err := http.Get(fmt.Sprintf("%s/%s/data", PLC_DIRECTORY_BASEURL, d.DID))
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

	resp, err := http.Get(fmt.Sprintf("%s/%s/log/audit", PLC_DIRECTORY_BASEURL, d.DID))
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

func (d *DIDPlc) calcDIDWithKeyIndex(index int) (string, *OperationObject, error) {
	if index >= len(d.RotationKeys) {
		return "", nil, fmt.Errorf("invalid keyID; keyID is out of range")
	}

	key := d.RotationKeys[index]
	if key == nil {
		return "", nil, fmt.Errorf("invalid keyID; key is nil")
	}

	op, err := d.unsignedOperation()
	if err != nil {
		return "", nil, err
	}

	buf := new(bytes.Buffer)
	node := bindnode.Wrap(op.IPLDNode(), OperationSchema).Representation()
	if err := dagcbor.Encode(
		node, buf,
	); err != nil {
		return "", nil, err
	}

	sig, err := key.Sign(sha256.Sum256(buf.Bytes()))
	if err != nil {
		return "", nil, err
	}

	b64sig := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(sig)
	op.Sig = &b64sig

	buf.Reset()

	node = bindnode.Wrap(op.IPLDNode(), OperationSchema).Representation()
	if err := dagcbor.Encode(node, buf); err != nil {
		return "", nil, err
	}

	hash := sha256.Sum256(buf.Bytes())
	b32encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	did := strings.ToLower(fmt.Sprintf("did:plc:%s", b32encoded[:24]))

	return did, op, nil
}

func (d *DIDPlc) CalcDID() (string, *OperationObject, error) {
	for i := 0; i < len(d.RotationKeys); i++ {
		did, signed, err := d.calcDIDWithKeyIndex(i)
		if err != nil {
			fmt.Printf("failed to calculate DID; %v\n", err)
			continue
		}

		return did, signed, nil
	}
	return "", nil, fmt.Errorf("failed to calculate DID with all keys")
}

func (d *DIDPlc) Create() error {
	did, signedOp, err := d.CalcDID()
	if err != nil {
		return err
	}

	// did:plc is the first 24 hex characters of the hashed value
	d.DID = did
	if err := d.FetchAuditLog(); err != nil {
		fmt.Printf("failed to fetch audit log, but this is expected; %v\n", err)
	} else {
		return fmt.Errorf("failed to create did:plc; DID already exists")
	}

	body, err := json.Marshal(signedOp)
	if err != nil {
		return err
	}

	resp, err := http.Post(
		fmt.Sprintf("%s/%s", PLC_DIRECTORY_BASEURL, d.DID),
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf(
			"failed to create DID; status code: %d",
			resp.StatusCode,
		)
	}

	if err := d.FetchAuditLog(); err != nil {
		return err
	}

	return nil
}
