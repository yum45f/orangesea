package plc

import (
	"bytes"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	cid "github.com/ipfs/go-cid"
	mc "github.com/multiformats/go-multicodec"
	mh "github.com/multiformats/go-multihash"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/codec/dagcbor"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/node/bindnode"
	"github.com/ipld/go-ipld-prime/schema"
	didkey "go.yumnet.cloud/orangesea/did/key"
)

const (
	PLC_DIRECTORY_BASEURL          = "http://localhost:2582"
	MAX_CREATE_RETRIES             = 5
	MAX_UPDATE_RETRIES_PER_KEY     = 5
	MAX_DEACTIVATE_RETRIES_PER_KEY = 5
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
	node := &OperationIPLDNode{
		Type:         o.Type,
		RotationKeys: o.RotationKeys,
		AlsoKnownAs:  o.AlsoKnownAs,
		Prev:         o.Prev,
		Sig:          o.Sig,
	}

	vmKeys := make([]string, 0, len(o.VerificationMethods))
	for k := range o.VerificationMethods {
		vmKeys = append(vmKeys, k)
	}
	sort.Strings(vmKeys)

	node.VerificationMethods = struct {
		Keys   []string
		Values map[string]string
	}{
		Keys:   vmKeys,
		Values: o.VerificationMethods,
	}

	svcKeys := make([]string, 0, len(o.Services))
	for k := range o.Services {
		svcKeys = append(svcKeys, k)
	}
	sort.Strings(svcKeys)

	node.Services = struct {
		Keys   []string
		Values map[string]Service
	}{
		Keys:   svcKeys,
		Values: o.Services,
	}

	return node
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
	CreatedAt time.Time       `json:"createdAt"`
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

// ToDo: add support for reverting with rotation operations
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
	TombstoneSchema schema.Type
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

		type Tombstone struct {
			type String
			prev String
			sig String
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
	TombstoneSchema = schema.TypeByName("Tombstone")
}

func NewDIDPlc(did string) *DIDPlc {
	return &DIDPlc{
		DID:                 did,
		RotationKeys:        make([]*didkey.DIDKey, 0),
		VerificationMethods: make(map[string]*didkey.DIDKey),
		AlsoKnownAs:         make([]string, 0),
		Services:            make(map[string]Service),
		Operations:          make([]Operation, 0),
		OpCount:             0,
	}
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

	d.sortOperationsByCreatedAt()
	oplog := d.getLatestValidOperationLog()
	if oplog != nil {
		return &OperationObject{
			Type:                "plc_operation",
			RotationKeys:        roatationKeys,
			VerificationMethods: verificationMethods,
			AlsoKnownAs:         d.AlsoKnownAs,
			Services:            d.Services,
			Prev:                &oplog.CID,
			Sig:                 nil,
		}, nil
	}

	// if no operations are found,
	// this return an unsigned operation without prev, which MUST be nil.
	return &OperationObject{
		Type:                "plc_operation",
		RotationKeys:        roatationKeys,
		VerificationMethods: verificationMethods,
		AlsoKnownAs:         d.AlsoKnownAs,
		Services:            d.Services,
		Prev:                nil,
		Sig:                 nil,
	}, nil
}

func (d *DIDPlc) unsignedTombstoneOperation() (*OperationObject, error) {
	d.sortOperationsByCreatedAt()
	oplog := d.getLatestValidOperationLog()
	if oplog == nil {
		return nil, fmt.Errorf("no operation found")
	}

	return &OperationObject{
		Type:                "plc_tombstone",
		RotationKeys:        nil,
		VerificationMethods: nil,
		AlsoKnownAs:         nil,
		Services:            nil,
		Prev:                &oplog.CID,
		Sig:                 nil,
	}, nil
}

func (d *DIDPlc) sortOperationsByCreatedAt() {
	sort.Slice(d.Operations, func(i, j int) bool {
		return d.Operations[i].CreatedAt.After(d.Operations[j].CreatedAt)
	})
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
	d.sortOperationsByCreatedAt()

	return nil
}

func (d *DIDPlc) getLatestValidOperationLog() *Operation {
	d.sortOperationsByCreatedAt()
	for _, op := range d.Operations {
		if !op.Nullified {
			return &op
		}
	}
	return nil
}

func (d *DIDPlc) calcDIDWithKeyIndex(index int, op *OperationObject) (string, *OperationObject, error) {
	if index >= len(d.RotationKeys) {
		return "", nil, fmt.Errorf("invalid keyID; keyID is out of range")
	}

	key := d.RotationKeys[index]
	if key == nil {
		return "", nil, fmt.Errorf("invalid keyID; key is nil")
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
	signedOp := &OperationObject{
		Type:                op.Type,
		RotationKeys:        op.RotationKeys,
		VerificationMethods: op.VerificationMethods,
		AlsoKnownAs:         op.AlsoKnownAs,
		Services:            op.Services,
		Prev:                op.Prev,
		Sig:                 &b64sig,
	}

	buf.Reset()

	node = bindnode.Wrap(signedOp.IPLDNode(), OperationSchema).Representation()
	if err := dagcbor.Encode(node, buf); err != nil {
		return "", nil, err
	}

	pref := cid.Prefix{
		Version:  1,
		Codec:    uint64(mc.Raw),
		MhType:   mh.SHA2_256,
		MhLength: -1,
	}

	cid, err := pref.Sum(buf.Bytes())
	if err != nil {
		return "", nil, fmt.Errorf("failed to calculate CID; %w", err)
	}

	b32encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(cid.Bytes())
	did := strings.ToLower(fmt.Sprintf("did:plc:%s", b32encoded[:24]))

	return did, signedOp, nil
}

func (d *DIDPlc) CalcDID() (string, *OperationObject, error) {
	unsigned, err := d.unsignedOperation()
	if err != nil {
		return "", nil, err
	}

	for i := 0; i < len(d.RotationKeys); i++ {
		did, signed, err := d.calcDIDWithKeyIndex(i, unsigned)
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

	buf := new(bytes.Buffer)
	node := bindnode.Wrap(signedOp.IPLDNode(), OperationSchema).Representation()

	for i := 0; i < MAX_CREATE_RETRIES; i++ {
		if err := dagjson.Encode(node, buf); err != nil {
			return err
		}

		resp, err := http.Post(
			fmt.Sprintf("%s/%s", PLC_DIRECTORY_BASEURL, d.DID),
			"application/json",
			buf,
		)
		if err != nil {
			fmt.Printf("failed to create DID; failed to send http req: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf(
				"failed to create DID; server returns invalid status code: %d\n",
				resp.StatusCode,
			)
			continue
		}

		if err := d.FetchAuditLog(); err != nil {
			return fmt.Errorf("failed to fetch audit log, but this is expected; %v", err)
		}

		return nil
	}

	return fmt.Errorf("failed to create DID; max retries exceeded")
}

func (d *DIDPlc) Update() error {
	if d.DID == "" {
		return fmt.Errorf("failed to update DID; DID is empty")
	}

	if err := d.FetchAuditLog(); err != nil {
		return fmt.Errorf("failed to update DID; %v", err)
	}

	if op := d.getLatestValidOperationLog(); op == nil {
		return fmt.Errorf("failed to update DID; there is no valid previous operation")
	}

	unsigned, err := d.unsignedOperation()
	if err != nil {
		return err
	}

	retries := MAX_UPDATE_RETRIES_PER_KEY * len(d.RotationKeys)
	for i := 0; i < retries; i++ {
		// #ToDo: We should verify the audit log before updating the DID

		_, signedOp, err := d.calcDIDWithKeyIndex(i%len(d.RotationKeys), unsigned)
		if err != nil {
			fmt.Printf("failed to calculate DID; %v\n", err)
			continue
		}
		if signedOp.Prev == nil {
			return fmt.Errorf("failed to update DID; there is no valid previous operation")
		}

		buf := new(bytes.Buffer)
		node := bindnode.Wrap(signedOp.IPLDNode(), OperationSchema).Representation()
		if err := dagjson.Encode(node, buf); err != nil {
			return err
		}

		resp, err := http.Post(
			fmt.Sprintf("%s/%s", PLC_DIRECTORY_BASEURL, d.DID),
			"application/json",
			buf,
		)
		if err != nil {
			fmt.Printf("failed to update DID; failed to send http req: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf(
				"failed to update DID; server returns invalid status code: %d\n",
				resp.StatusCode,
			)
			continue
		}

		if err := d.FetchAuditLog(); err != nil {
			return fmt.Errorf("failed to fetch audit log, but this is expected; %v", err)
		}

		return nil
	}

	return fmt.Errorf("failed to update DID; max retries exceeded")
}

func (d *DIDPlc) Deactivate() error {
	if d.DID == "" {
		return fmt.Errorf("failed to deactivate DID; DID is empty")
	}

	if err := d.FetchAuditLog(); err != nil {
		return fmt.Errorf("failed to deactivate DID; %v", err)
	}

	if op := d.getLatestValidOperationLog(); op == nil {
		return fmt.Errorf("failed to deactivate DID; there is no valid previous operation")
	}

	unsigned, err := d.unsignedTombstoneOperation()
	if err != nil {
		return err
	}

	retries := MAX_DEACTIVATE_RETRIES_PER_KEY * len(d.RotationKeys)
	for i := 0; i < retries; i++ {
		_, signedOp, err := d.calcDIDWithKeyIndex(i%len(d.RotationKeys), unsigned)
		if err != nil {
			fmt.Printf("failed to calculate DID; %v\n", err)
			continue
		}
		if signedOp.Prev == nil {
			return fmt.Errorf("failed to deactivate DID; there is no valid previous operation")
		}

		buf := new(bytes.Buffer)
		node := bindnode.Wrap(signedOp.IPLDNode(), OperationSchema).Representation()
		if err := dagjson.Encode(node, buf); err != nil {
			return err
		}

		resp, err := http.Post(
			fmt.Sprintf("%s/%s", PLC_DIRECTORY_BASEURL, d.DID),
			"application/json",
			buf,
		)
		if err != nil {
			fmt.Printf("failed to deactivate DID; failed to send http req: %v\n", err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf(
				"failed to deactivate DID; server returns invalid status code: %d\n",
				resp.StatusCode,
			)
			continue
		}

		if err := d.FetchAuditLog(); err != nil {
			return fmt.Errorf("failed to fetch audit log, but this is expected; %v", err)
		}

		return nil
	}

	return fmt.Errorf("failed to deactivate DID; max retries exceeded")
}

func (d *DIDPlc) String() string {
	return d.DID
}
