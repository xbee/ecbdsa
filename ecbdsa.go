// Copyright 2017  Author: xbee All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecbdsa implements the Elliptic Curve Blind Digital Signature Algorithm, as
// defined in
//

package ecbdsa

import (
	// "crypto"
	// "crypto/aes"
	// "crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	// "crypto/sha512"
	// "encoding/asn1"
	"crypto/rand"
	"errors"
	// "fmt"
	"io"
	"math/big"
)

// A invertible implements fast inverse mod Curve.Params().N
type invertible interface {
	// Inverse returns the inverse of k in GF(P)
	Inverse(k *big.Int) *big.Int
}

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

func KeysEqual(a, b *ecdsa.PublicKey) bool {
	return a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0
}

type BlindSignature struct {
	S *big.Int // called F and s in the paper
	F *ecdsa.PublicKey
}

type Requester struct {
	// secret stuff
	a, b, c *big.Int
	bInv    *big.Int

  d *big.Int // priv key
  Q *ecdsa.PublicKey // public key

	// shareable stuff
	F  *ecdsa.PublicKey
	Mb *big.Int // called m̂ in the paper

}

// rand select a, b, c in [0, n-1]
func NewRequester() *Requester {
	crv := Secp256k1().Params()

	alice := new(Requester)

	// requester's three blinding factors (§4.2)
	var err error
	alice.a, err = RandFieldElement(rand.Reader)
	maybePanic(err)
	alice.b, err = RandFieldElement(rand.Reader)
	maybePanic(err)
	alice.c, err = RandFieldElement(rand.Reader)
	maybePanic(err)
	alice.bInv = new(big.Int).ModInverse(alice.b, crv.N)

  // generate priv and pub keys , just for ecdh 
  request, err := GenerateKey(rand.Reader)
  maybePanic(err)
  alice.d = request.D
  alice.Q = &request.PublicKey

	return alice
}

// Alice computes F = (b^-1)R + a(b^-1)Q + cG
func (alice *Requester) GenerateBlindFactor(R, Q *ecdsa.PublicKey) {

	crv := Secp256k1().Params()
	// generate F which is not equal to O (§4.2)
	// var err error
	F := new(ecdsa.PublicKey)
	for F.X == nil && F.Y == nil {
		// requester calculates point F (§4.2)
		// F = (b^-1)R + a(b^-1)Q + cG
		abInv := new(big.Int).Mul(alice.a, alice.bInv)
		abInv.Mod(abInv, crv.N)
		bInvR := ScalarMult(alice.bInv, R)
		abInvQ := ScalarMult(abInv, Q)
		cG := ScalarBaseMult(alice.c)
		F = Add(bInvR, abInvQ)
		F = Add(F, cG)
	}
	alice.F = F

	return
}

// 5. Alice blinds the hash and sends m’ = bfm + a to Bob.
func (alice *Requester) BlindMessage(m *big.Int) *big.Int {
	// Alice computes the hash h of her message.
	crv := Secp256k1().Params()

	// calculate f and m̂
	f := new(big.Int).Mod(alice.F.X, crv.N)
	mHat := new(big.Int).Mul(alice.b, f)
	mHat.Mul(mHat, m)
	mHat.Add(mHat, alice.a)
	mHat.Mod(mHat, crv.N)
	alice.Mb = mHat

	return alice.Mb
}

// 8. Alice unblinds the signature: s = (b^-1)s’ + c.
func (alice *Requester) UnblindMessage(sHat *big.Int) *BlindSignature {
	crv := Secp256k1().Params()

	// requester extracts the real signature (§4.4)
	s := new(big.Int).Mul(alice.bInv, sHat)
	s.Add(s, alice.c)
	s.Mod(s, crv.N)
	sig := &BlindSignature{S: s, F: alice.F}
	return sig
}

type Signer struct {
	// secret stuff
	d, k *big.Int

	// shareable stuff
	Q, R *ecdsa.PublicKey
}

func NewSigner() *Signer {
	bob := new(Signer)

	// generate signer's private & public key pair
	keys, err := GenerateKey(rand.Reader)
	maybePanic(err)
	bob.d = keys.D
	bob.Q = &keys.PublicKey
	// fmt.Printf("Signer:\t%x\n\t%x\n", bob.d, bob.Q.X)

	return bob
}

func (bob *Signer) GenerateSessionKeyPair() *ecdsa.PublicKey {
	// generate k and R for each user request (§4.2)
	request, err := GenerateKey(rand.Reader)
	maybePanic(err)
	bob.k = request.D
	bob.R = &request.PublicKey
	return bob.R
}

// Signs a blinded message
// Bob signs the blinded hash and returns the signature to Alice:
// s’ = dm’ + k.
func (bob *Signer) BlindSign(mHat *big.Int) *big.Int {
	crv := Secp256k1().Params()

	// verify that R matches our secret k
	R_ := ScalarBaseMult(bob.k)
	if !KeysEqual(bob.R, R_) {
		panic("unknown R")
	}

	// signer generates signature (§4.3)
	sHat := new(big.Int).Mul(bob.d, mHat)
	sHat.Add(sHat, bob.k)
	sHat.Mod(sHat, crv.N)

	return sHat
}

func BlindVerify(Q *ecdsa.PublicKey, M *big.Int, sig *BlindSignature) bool {
	e := Secp256k1()
	crv := e.Params()
	// M := hashToInt(msg, e)

	// onlooker verifies signature (§4.5)
	sG := ScalarBaseMult(sig.S)
	rm := new(big.Int).Mul(new(big.Int).Mod(sig.F.X, crv.N), M)
	rm.Mod(rm, crv.N)
	rmQ := ScalarMult(rm, Q)
	rmQplusF := Add(rmQ, sig.F)

	// fmt.Println("")
	// fmt.Printf("sG      = %x\n", sG.X)
	// fmt.Printf("rmQ + F = %x\n", rmQplusF.X)
	return KeysEqual(sG, rmQplusF)
}

var one = new(big.Int).SetInt64(1)

// RandFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func RandFieldElement(rand io.Reader) (k *big.Int, err error) {
	crv := Secp256k1().Params()
	b := make([]byte, crv.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(crv.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*ecdsa.PrivateKey, error) {
	c := Secp256k1()
	k, err := RandFieldElement(rand)
	if err != nil {
		return nil, err
	}

	priv := new(ecdsa.PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

// hashToInt converts a hash value to an integer. There is some disagreement
// about how this is done. [NSA] suggests that this is done in the obvious
// manner, but [SECG] truncates the hash to the bit-length of the curve order
// first. We follow [SECG] because that's what OpenSSL does. Additionally,
// OpenSSL right shifts excess bits from the number if the hash is too large
// and we mirror that too.
func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

// fermatInverse calculates the inverse of k in GF(P) using Fermat's method.
// This has better constant-time properties than Euclid's method (implemented
// in math/big.Int.ModInverse) although math/big itself isn't strictly
// constant-time so it's not perfect.
func fermatInverse(k, N *big.Int) *big.Int {
	two := big.NewInt(2)
	nMinus2 := new(big.Int).Sub(N, two)
	return new(big.Int).Exp(k, nMinus2, N)
}

var errZeroParam = errors.New("zero parameter")

// Multiplies the base G by a large integer.  The resulting
// point is represented as an ECDSA public key since that's
// typically how they're used.
func ScalarBaseMult(k *big.Int) *ecdsa.PublicKey {
	key := new(ecdsa.PublicKey)
	key.Curve = Secp256k1()
	key.X, key.Y = Secp256k1().ScalarBaseMult(k.Bytes())
	return key
}

// Multiply a large integer and a point.  The resulting point
// is represented as an ECDSA public key.
func ScalarMult(k *big.Int, B *ecdsa.PublicKey) *ecdsa.PublicKey {
	key := new(ecdsa.PublicKey)
	key.Curve = Secp256k1()
	key.X, key.Y = Secp256k1().ScalarMult(B.X, B.Y, k.Bytes())
	return key
}

// Adds two points to create a third.  Points are represented as
// ECDSA public keys.
func Add(a, b *ecdsa.PublicKey) *ecdsa.PublicKey {
	key := new(ecdsa.PublicKey)
	key.Curve = Secp256k1()
	key.X, key.Y = Secp256k1().Add(a.X, a.Y, b.X, b.Y)
	return key
}

func maybePanic(err error) {
	if err != nil {
		panic(err)
	}
}

