// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdsa implements the Elliptic Curve Digital Signature Algorithm, as
// defined in FIPS 186-3.
//
// This implementation  derives the nonce from an AES-CTR CSPRNG keyed by
// ChopMD(256, SHA2-512(priv.D || entropy || hash)). The CSPRNG key is IRO by
// a result of Coron; the AES-CTR stream is IRO under standard assumptions.
package ecbdsa

// References:
//   [NSA]: Suite B implementer's guide to FIPS 186-3,
//     http://www.nsa.gov/ia/_files/ecdsa.pdf
//   [SECG]: SECG, SEC1
//     http://www.secg.org/sec1-v2.pdf

import (
  "crypto"
  "crypto/aes"
  "crypto/cipher"
  "crypto/elliptic"
  "crypto/sha512"
  "encoding/asn1"
  "errors"
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

const (
  aesIV = "IV for ECBDSA CTR"
)


type ecdsaSignature struct {
  R, S *big.Int
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
  bInv *big.Int

  // shareable stuff
  F   *ecdsa.PublicKey
  Mb  *big.Int // called m̂ in the paper

}

// rand select a, b, c in [0, n-1]
func NewRequester() *Requester {
  crv := Secp256k1().Params()

  alice := new(Requester)

  // requester's three blinding factors (§4.2)
  alice.a, err = RandFieldElement(crv, rand.Reader)
  maybePanic(err)
  alice.b, err = RandFieldElement(crv, rand.Reader)
  maybePanic(err)
  alice.c, err = RandFieldElement(crv, rand.Reader)
  maybePanic(err)
  alice.bInv = new(big.Int).ModInverse(alice.b, crv.N)

  return alice
}

// Public returns the public key corresponding to priv.
func (alice *Requester) Public() *ecdsa.PublicKey {
  return alice.F
}


// Alice computes F = (b^-1)R + a(b^-1)Q + cG
func (alice *Requester) GenerateBlindKey(R, Q *ecdsa.PublicKey) {

  // generate F which is not equal to O (§4.2)
  var err error
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


// 5. Alice blinds the hash and sends h2 = a·h + b (mod n) to Bob.
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
func (alice *Requester) UnblindMessage(sHat *big.Int) (*BlindSignature) {
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
  Q, R *PublicKey
}

func NewSigner(e elliptic.Curve, p, q *big.Int) (*Signer, error) {
  bob := new(Signer)

  keys, err := GenerateKey(rand.Reader)
  maybePanic(err)
  bob.d = keys.D
  bob.Q = &keys.PublicKey
  fmt.Printf("Signer:\t%x\n\t%x\n", bob.d, bob.Q.X)
  
  return bob
}


func (bob *Signer) GetSessionKey() *PublicKey {
  // generate k and R for each user request (§4.2)
  if bob.k == nil {
    request, err := GenerateKey(rand.Reader)
    maybePanic(err)
    bob.k = request.D
    R := &request.PublicKey
    return R
  }
  
  R := ScalarBaseMult(bob.k)
  return R 
}

// Signs a blinded message
// Bob signs the blinded hash and returns the signature to Alice: 
// s1 = p·h2 + q (mod n).
func (bob *Signer) Sign(h2 *big.Int) *big.Int {
  c := bob.Curve
  n := c.Params().N

  s1 := new(big.Int).Mul(bob.p, h2)
  s1.Add(s1, bob.q)
  s1.Mod(s1, n)
  return s1

  // verify that R matches our secret k
  // R_ := ScalarBaseMult(sState.k)
  // if !KeysEqual(R, R_) {
  //   panic("unknown R")
  // }

  // // signer generates signature (§4.3)
  // sHat := new(big.Int).Mul(sState.d, mHat)
  // sHat.Add(sHat, sState.k)
  // sHat.Mod(sHat, params.N)

  // return sHat
}

func BlindVerify(Q *ecdsa.PublicKey, msg []byte, sig *BlindSignature) bool {
  e := Secp256k1()
  crv := e.Params()
  M := hashToInt(msg, e)

  // onlooker verifies signature (§4.5)
  sG := e.ScalarBaseMult(sig.S)
  rm := new(big.Int).Mul(new(big.Int).Mod(sig.F.X, crv.N), M)
  rm.Mod(rm, crv.N)
  rmQ := e.ScalarMult(rm, Q)
  rmQplusF := e.Add(rmQ, sig.F)

  fmt.Println("")
  fmt.Printf("sG      = %x\n", sG.X)
  fmt.Printf("rmQ + F = %x\n", rmQplusF.X)
  return KeysEqual(sG, rmQplusF)
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() crypto.PublicKey {
  return &priv.PublicKey
}

// Sign signs msg with priv, reading randomness from rand. This method is
// intended to support keys where the private part is kept in, for example, a
// hardware module. Common uses should use the Sign function in this package
// directly.
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
  r, s, err := Sign(rand, priv, msg)
  if err != nil {
    return nil, err
  }

  return asn1.Marshal(ecdsaSignature{r, s})
}

var one = new(big.Int).SetInt64(1)

// RandFieldElement returns a random element of the field underlying the given
// curve using the procedure given in [NSA] A.2.1.
func RandFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
  params := c.Params()
  b := make([]byte, params.BitSize/8+8)
  _, err = io.ReadFull(rand, b)
  if err != nil {
    return
  }

  k = new(big.Int).SetBytes(b)
  n := new(big.Int).Sub(params.N, one)
  k.Mod(k, n)
  k.Add(k, one)
  return
}

// GenerateKey generates a public and private key pair.
func GenerateKey(rand io.Reader) (*PrivateKey, error) {
  c := Secp256k1();
  k, err := RandFieldElement(c, rand)
  if err != nil {
    return nil, err
  }

  priv := new(PrivateKey)
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

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(rand io.Reader, priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
  // Get max(log2(q) / 2, 256) bits of entropy from rand.
  entropylen := (priv.Curve.Params().BitSize + 7) / 16
  if entropylen > 32 {
    entropylen = 32
  }
  entropy := make([]byte, entropylen)
  _, err = io.ReadFull(rand, entropy)
  if err != nil {
    return
  }

  // Initialize an SHA-512 hash context; digest ...
  md := sha512.New()
  md.Write(priv.D.Bytes()) // the private key,
  md.Write(entropy)        // the entropy,
  md.Write(hash)           // and the input hash;
  key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
  // which is an indifferentiable MAC.

  // Create an AES-CTR instance to use as a CSPRNG.
  block, err := aes.NewCipher(key)
  if err != nil {
    return nil, nil, err
  }

  // Create a CSPRNG that xors a stream of zeros with
  // the output of the AES-CTR instance.
  csprng := cipher.StreamReader{
    R: zeroReader,
    S: cipher.NewCTR(block, []byte(aesIV)),
  }

  // See [NSA] 3.4.1
  c := priv.PublicKey.Curve
  N := c.Params().N
  if N.Sign() == 0 {
    return nil, nil, errZeroParam
  }
  var k, kInv *big.Int
  for {
    for {
      k, err = RandFieldElement(c, csprng)
      if err != nil {
        r = nil
        return
      }

      if in, ok := priv.Curve.(invertible); ok {
        kInv = in.Inverse(k)
      } else {
        kInv = fermatInverse(k, N) // N != 0
      }

      r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
      r.Mod(r, N)
      if r.Sign() != 0 {
        break
      }
    }

    e := hashToInt(hash, c)
    s = new(big.Int).Mul(priv.D, r)
    s.Add(s, e)
    s.Mul(s, kInv)
    s.Mod(s, N) // N != 0
    if s.Sign() != 0 {
      break
    }
  }

  return
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
  // See [NSA] 3.4.2
  c := pub.Curve
  N := c.Params().N

  if r.Sign() <= 0 || s.Sign() <= 0 {
    return false
  }
  if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
    return false
  }
  e := hashToInt(hash, c)

  var w *big.Int
  if in, ok := c.(invertible); ok {
    w = in.Inverse(s)
  } else {
    w = new(big.Int).ModInverse(s, N)
  }

  u1 := e.Mul(e, w)
  u1.Mod(u1, N)
  u2 := w.Mul(r, w)
  u2.Mod(u2, N)

  // Check if implements S1*g + S2*p
  var x, y *big.Int
  if opt, ok := c.(combinedMult); ok {
    x, y = opt.CombinedMult(pub.X, pub.Y, u1.Bytes(), u2.Bytes())
  } else {
    x1, y1 := c.ScalarBaseMult(u1.Bytes())
    x2, y2 := c.ScalarMult(pub.X, pub.Y, u2.Bytes())
    x, y = c.Add(x1, y1, x2, y2)
  }

  if x.Sign() == 0 && y.Sign() == 0 {
    return false
  }
  x.Mod(x, N)
  return x.Cmp(r) == 0
}

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

type zr struct {
  io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
  for i := range dst {
    dst[i] = 0
  }
  return len(dst), nil
}

var zeroReader = &zr{}