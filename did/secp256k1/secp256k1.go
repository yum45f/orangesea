// !! DEPRECATED !! THIS PACKAGE IS NOT WORKING CORRECTLY YET !!
// This package is something wrong. I may fix this later...

package secp256k1

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"math/big"
)

// secp256k1: y^2 = x^3 + 7

type CurveParams struct {
	P       *big.Int
	N       *big.Int
	B       *big.Int
	Gx, Gy  *big.Int
	BitSize int
	Name    string
}

type Point struct {
	X, Y *big.Int
}

var (
	p, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	n, _    = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	b, _    = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	gx, _   = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _   = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
	bitSize = 256
	name    = "secp256k1"
)

// affineZ returns the affine coordinate z of the given (x,y).
func (p *Point) affineZ() *big.Int {
	z := new(big.Int)
	if p.X.Sign() != 0 || p.Y.Sign() != 0 {
		z.SetInt64(1)
	}
	return z
}

// affineFromJacobian returns the affine coordinate (x,y)
// from the given Jacobian coordinate (x,y,z).
func (curve *CurveParams) affineFromJacobian(x, y, z *big.Int) *Point {
	if z.Sign() == 0 {
		return &Point{
			X: new(big.Int),
			Y: new(big.Int),
		}
	}

	zinv := new(big.Int).ModInverse(z, curve.P)
	zinvsq := new(big.Int).Mul(zinv, zinv)
	zinvcb := new(big.Int).Mul(zinvsq, zinv)

	xOut := new(big.Int).Mul(x, zinvsq)
	xOut.Mod(xOut, p)

	yOut := new(big.Int).Mul(y, zinvcb)
	yOut.Mod(yOut, p)

	return &Point{
		X: xOut,
		Y: yOut,
	}
}

func (curve *CurveParams) addJacobian(x1, y1, z1, x2, y2, z2 *big.Int) (*big.Int, *big.Int, *big.Int) {
	x3, y3, z3 := new(big.Int), new(big.Int), new(big.Int)
	if z1.Sign() == 0 {
		x3.Set(x2)
		y3.Set(y2)
		z3.Set(z2)
		return x3, y3, z3
	}
	if z2.Sign() == 0 {
		x3.Set(x1)
		y3.Set(y1)
		z3.Set(z1)
		return x3, y3, z3
	}

	z1z1 := new(big.Int).Mul(z1, z1)
	z1z1.Mod(z1z1, curve.P)
	z2z2 := new(big.Int).Mul(z2, z2)
	z2z2.Mod(z2z2, curve.P)

	u1 := new(big.Int).Mul(x1, z2z2)
	u1.Mod(u1, curve.P)
	u2 := new(big.Int).Mul(x2, z1z1)
	u2.Mod(u2, curve.P)
	h := new(big.Int).Sub(u2, u1)
	xEqual := h.Sign() == 0
	if h.Sign() == -1 {
		h.Add(h, curve.P)
	}
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	j := new(big.Int).Mul(h, i)

	s1 := new(big.Int).Mul(y1, z2)
	s1.Mul(s1, z2z2)
	s1.Mod(s1, curve.P)
	s2 := new(big.Int).Mul(y2, z1)
	s2.Mul(s2, z1z1)
	s2.Mod(s2, curve.P)
	r := new(big.Int).Sub(s2, s1)
	if r.Sign() == -1 {
		r.Add(r, curve.P)
	}
	yEqual := r.Sign() == 0
	if xEqual && yEqual {
		return curve.doubleJacobian(x1, y1, z1)
	}
	r.Lsh(r, 1)
	v := new(big.Int).Mul(u1, i)

	x3.Set(r)
	x3.Mul(x3, x3)
	x3.Sub(x3, j)
	x3.Sub(x3, v)
	x3.Sub(x3, v)
	x3.Mod(x3, curve.P)

	y3.Set(r)
	v.Sub(v, x3)
	y3.Mul(y3, v)
	s1.Mul(s1, j)
	s1.Lsh(s1, 1)
	y3.Sub(y3, s1)
	y3.Mod(y3, curve.P)

	z3.Add(z1, z2)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	z3.Mod(z3, curve.P)

	return x3, y3, z3
}

func (curve *CurveParams) doubleJacobian(x, y, z *big.Int) (*big.Int, *big.Int, *big.Int) {
	delta := new(big.Int).Exp(z, big.NewInt(2), nil)
	delta.Mod(delta, curve.P)
	gamma := new(big.Int).Exp(y, big.NewInt(2), nil)
	gamma.Mod(gamma, curve.P)

	x2 := new(big.Int).Exp(x, big.NewInt(2), nil)
	alpha := new(big.Int).Lsh(x2, 1)
	alpha.Add(alpha, x2)
	alpha.Mod(alpha, curve.P)

	beta4 := new(big.Int).Mul(x, gamma)
	beta4.Lsh(beta4, 2)
	beta4.Mod(beta4, curve.P)

	x3 := new(big.Int).Mul(alpha, alpha)
	beta8 := new(big.Int).Lsh(beta4, 1)
	x3.Sub(x3, beta8)
	x3.Mod(x3, curve.P)

	z3 := delta.Mul(y, z)
	z3.Lsh(z3, 1)
	z3.Mod(z3, curve.P)

	beta4.Sub(beta4, x3)
	y3 := alpha.Mul(alpha, beta4)
	gamma.Mul(gamma, gamma)
	gamma.Lsh(gamma, 3)
	y3.Sub(y3, gamma)
	y3.Mod(y3, curve.P)

	return x3, y3, z3
}

// Params returns the elliptic.CurveParams of secp256k1.
func (curve *CurveParams) Params() *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       p,
		N:       n,
		B:       b,
		Gx:      gx,
		Gy:      gy,
		BitSize: bitSize,
		Name:    name,
	}
}

// IsOnCurve returns whether the given (x,y) lies on the curve.
func (curve *CurveParams) IsOnCurve(x, y *big.Int) bool {
	p := Point{x, y}

	y2 := new(big.Int).Exp(p.Y, big.NewInt(2), nil)
	x3 := new(big.Int).Exp(p.X, big.NewInt(3), nil)

	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)

	y2.Mod(y2, curve.P)

	return y2.Cmp(x3) == 0
}

// Add returns the sum of p1(x,y) and p2(x,y)
func (curve *CurveParams) Add(x1, x2, y1, y2 *big.Int) (x, y *big.Int) {
	p1 := Point{x1, y1}
	p2 := Point{x2, y2}

	z1 := p1.affineZ()
	z2 := p2.affineZ()

	o := curve.affineFromJacobian(curve.addJacobian(
		p1.X, p1.Y, z1,
		p2.X, p2.Y, z2,
	))

	return o.X, o.Y
}

func (curve *CurveParams) Double(x1, y1 *big.Int) (x, y *big.Int) {

	p := Point{x1, y1}

	if p.X.Sign() == 0 && p.Y.Sign() == 0 {
		return p.X, p.Y
	}

	x3, y3, z3 := curve.doubleJacobian(p.X, p.Y, big.NewInt(1))
	o := curve.affineFromJacobian(x3, y3, z3)

	return o.X, o.Y
}

func (curve *CurveParams) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	B := Point{x1, y1}

	Bz := new(big.Int).SetInt64(1)
	x, y, z := new(big.Int), new(big.Int), new(big.Int)

	for _, byte := range k {
		for bitNum := 0; bitNum < 8; bitNum++ {
			x, y, z = curve.doubleJacobian(x, y, z)
			if byte&0x80 == 0x80 {
				x, y, z = curve.addJacobian(B.X, B.Y, Bz, x, y, z)
			}
			byte <<= 1
		}
	}

	o := curve.affineFromJacobian(x, y, z)

	return o.X, o.Y
}

func (curve *CurveParams) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func Secp256k1() elliptic.Curve {
	return &CurveParams{
		P:       p,
		N:       n,
		B:       b,
		Gx:      gx,
		Gy:      gy,
		BitSize: bitSize,
		Name:    name,
	}
}

type Secp256k1PubKey struct {
	X []byte
	Y []byte
}

func (k *Secp256k1PubKey) Bytes() []byte {
	return k.Compress()
}

func NewPublicKeyWithBytes(b []byte) *Secp256k1PubKey {
	return Decompress(b)
}

type Secp256k1PrvKey struct {
	PublicKey Secp256k1PubKey
	D         []byte
}

func (k *Secp256k1PrvKey) Bytes() []byte {
	return k.D
}

func NewPrivateKeyWithBytes(b []byte) *Secp256k1PrvKey {
	pubX, pubY := Secp256k1().ScalarBaseMult(b)
	pubKey := Secp256k1PubKey{
		X: pubX.Bytes(),
		Y: pubY.Bytes(),
	}

	return &Secp256k1PrvKey{
		PublicKey: pubKey,
		D:         b,
	}
}

func GenerateKeyPair() (*Secp256k1PrvKey, *Secp256k1PubKey, error) {
	prv, err := ecdsa.GenerateKey(Secp256k1(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pub := prv.Public().(*ecdsa.PublicKey)

	prbKey := &Secp256k1PrvKey{
		D: prv.D.Bytes(),
	}

	return prbKey, &Secp256k1PubKey{
		X: pub.X.Bytes(),
		Y: pub.X.Bytes(),
	}, nil
}

func (k *Secp256k1PubKey) Compress() []byte {
	b := elliptic.MarshalCompressed(
		Secp256k1(),
		new(big.Int).SetBytes(k.X),
		new(big.Int).SetBytes(k.Y),
	)
	return b
}

func Decompress(bytes []byte) *Secp256k1PubKey {
	x, y := elliptic.UnmarshalCompressed(Secp256k1(), bytes)
	return &Secp256k1PubKey{
		X: x.Bytes(),
		Y: y.Bytes(),
	}
}

func (k *Secp256k1PrvKey) Sign(hash []byte) ([]byte, error) {
	sig, err := ecdsa.SignASN1(rand.Reader, &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(k.D),
	}, hash)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (k *Secp256k1PubKey) Verify(hash, sig []byte) bool {
	return ecdsa.VerifyASN1(&ecdsa.PublicKey{
		X: new(big.Int).SetBytes(k.X),
		Y: new(big.Int).SetBytes(k.Y),
	}, hash, sig)
}
