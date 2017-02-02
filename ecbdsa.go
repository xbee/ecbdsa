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

// PublicKey represents an ECDSA public key.
type PublicKey struct {
  elliptic.Curve
  X, Y *big.Int
}

// PrivateKey represents a ECDSA private key.
type PrivateKey struct {
  PublicKey
  D *big.Int
}

type ecdsaSignature struct {
  R, S *big.Int
}

type BlindSignature struct {
  S *big.Int // called F and s in the paper
  F *PublicKey
}

type Requester struct {
  elliptic.Curve
  // secret stuff
  a, b, c *big.Int
  bInv *big.Int


  // shareable stuff
  F    *ecdsa.PublicKey
  X0   *big.Int //
  // Mhat *big.Int // called m̂ in the paper

}

func NewRequester(e elliptic.Curve, a, b, c, d *big.Int) *Requester {
  alice = new(Requester)
  alice.Curve = e
  n := e.params().N
  alice.a, alice.b, alice.c, alice.d = a, b, c, d

  return alice
}

// Public returns the public key corresponding to priv.
func (alice *Requester) Public() PublicKey {
  pub := new(PublicKey)
  pub.Curve = alice.Curve
  pub.X, pub.Y = alice.Tx, alice.Ty
  return pub
}


// 3. Alice computes K = (c·a) -1 ·P and 
// public key T = (a·Kx) -1 ·(b·G + Q + d·c -1 ·P).
func (alice *Requester) GenerateKeys(Px, Py, Qx, Qy *big.Int) {
  e := alice.Curve
  n := e.params().N

  // K = ((c·a)^-1)·P and 
  tmp := new(big.Int)
  Kx, Ky := e.ScalarMult(Px, Py, tmp.Mul(alice.c, alice.a).ModInverse(tmp, n).Bytes())
  alice.Kx, alice.Ky = Kx, Ky

  // public key T = ((a·Kx)^-1)·(b·G + Q + d·(c^-1)·P)
  Tx, Ty := e.ScalarBaseMult(alice.b.Bytes())
  Tx, Ty = e.Add(Tx, Ty, Qx, Qy)
  x, y = e.ScalarMult(Px, Py, new(big.Int).Mul(alice.d, new(big.Int).ModInverse(alice.c, n)).Bytes())
  Tx, Ty = e.Add(Tx, Ty, x, y)
  tmp = new(big.Int)
  Tx, Ty = e.ScalarMult(Tx, Ty, tmp.Mul(alice.a, Kx).ModInverse(tmp, n).Bytes())
  alice.Tx, alice.Ty = Tx, Ty
  return 
}


// 5. Alice blinds the hash and sends h2 = a·h + b (mod n) to Bob.
func (alice *Requester) BlindMessage(m []byte) *big.Int {
  // Alice computes the hash h of her message.
  n := alice.Curve.params().N
  h := hashToInt(hash(m), alice.Curve)
  h2 := new(big.Int).Mul(alice.a, h)
  h2.Add(h2, alice.b)
  h2.Mod(h2, n)
  return h2
}

// 8. Alice unblinds the signature: s2 = c·s1 + d (mod n).
func (alice *Requester) UnblindMessage(s1 *big.Int) (r, s *big.Int, err error) {
  n := alice.Curve.params().N

  s2 := new(big.Int).Mul(alice.c, s1)
  s2.Add(s2, alice.d)
  s2.Mod(s2, n)
  // TODO: need to check s2
  r, s = alice.Kx, s2
  err = nil
  return 
}

type Signer struct {
  elliptic.Curve
  // secret stuff
  p, q *big.Int

  // shareable stuff
  // Q = q·(p^-1)·G
  Qx, Qy *big.Int
  // P = (p^-1)·G  
  Px, Py *big.Int

}

func NewSigner(e elliptic.Curve, p, q *big.Int) (*Signer, error) {
  bob := new(Signer)
  bob.Curve = e
  n := e.params().N

  k, err := RandFieldElement(c, rand)
  if err != nil {
    return nil, err
  }
  // 2. Bob chooses random numbers p, q within [1, n – 1]
  // and sends two EC points to Alice: P = (p -1 ·G) and Q = (q·p -1 ·G).
  bob.p, bob.q = p, q
  
  return bob
}


func (bob *Signer) GenerateKeys() {
  e := alice.Curve
  n := e.params().N

  // P = ((p^-1)·G)
  bob.Px, bob.Py := e.ScalarBaseMult(new(big.Int).ModInverse(bob.p, n).Bytes())
  // Q = (q·(p^-1)·G)
  bob.Qx, bob.Qy := e.ScalarBaseMult(new(big.Int).Mul(bob.q, new(big.Int).ModInverse(bob.p, n)).Bytes()) 
  
  return 
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
func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
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