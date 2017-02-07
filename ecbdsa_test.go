package ecbdsa

import (
	"crypto/rand"
	// "crypto/elliptic"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

// var c elliptic.Curve = Secp256k1()


func Test_KeyGeneration(t *testing.T) {
	c := Secp256k1()

	Convey("When generating key", t, func() {

		priv, err := GenerateKey(rand.Reader)
		Convey("It should not return error.", func() {
			So(err, ShouldEqual, nil)
		})
		
		Convey("Point should exists on secp256k1 curve.", func() {
			So(c.IsOnCurve(priv.PublicKey.X, priv.PublicKey.Y), ShouldEqual, true)
		})

	})
}


func Test_NewSigner(t *testing.T) {
	var signer *Signer
	// Only pass t into top-level Convey calls
	Convey("Given a fresh signer", t, func() {

		signer = NewSigner()

		Convey("Now signer's priv and pub key should not be nil", func() {
			So(signer.d, ShouldNotEqual, nil)
			So(signer.k, ShouldEqual, nil)
			// So(signer.d, ShouldBeGreaterThan, )
			// So(*(signer.d), ShouldBeLessThan, crv.N)
			So(signer.Q, ShouldNotEqual, nil)
		})

		R := signer.GenerateSessionKeyPair()
		Q := signer.Q
		Convey("When signer generated session keypair", func() {
			Convey("Q, R should not nil", func() {
				So(R, ShouldNotEqual, nil)
				So(Q, ShouldNotEqual, nil)
			})
		})
	})
}


func Test_BlindSignature(t *testing.T) {
	// SetDefaultFailureMode(FailureContinues)
	// defer SetDefaultFailureMode(FailureHalts)

	var signer *Signer
	var requester *Requester

	// Only pass t into top-level Convey calls
	Convey("Given a fresh signer and a fresh requester", t, func() {

		signer = NewSigner()
		requester = NewRequester()
		crv := Secp256k1().Params()
		_ = crv.N

		Convey("Now signer's priv and pub key should not be nil", func() {
			So(signer.d, ShouldNotEqual, nil)
			So(signer.k, ShouldEqual, nil)
			// So(signer.d, ShouldBeGreaterThan, )
			// So(*(signer.d), ShouldBeLessThan, crv.N)
			So(signer.Q, ShouldNotEqual, nil)
		})

		Convey("Now requester's blindkey should be nil and a,b,c should not be nil", func() {
			So(requester.F, ShouldEqual, nil)
			So(requester.a, ShouldNotEqual, nil)
			So(requester.b, ShouldNotEqual, nil)
			So(requester.c, ShouldNotEqual, nil)
		})

		// requester: message that needs to be ecbdsa signed
		m, err := RandFieldElement(rand.Reader)
		maybePanic(err)
		// fmt.Printf("m = %x\n", m)

		// requester: ask signer to start the protocol
		R := signer.GenerateSessionKeyPair()
		Q := signer.Q
		Convey("When signer generated session keypair", func() {
			Convey("Q, R should not nil", func() {
				So(R, ShouldNotEqual, nil)
				So(Q, ShouldNotEqual, nil)
			})
		})
		
		// fmt.Println("")

		// requester: generate blindkey
		requester.GenerateBlindKey(R, Q)
		Convey("When requester generated blindkey", func() {
			Convey("Requester's blindkey should not nil", func() {
				So(requester.F, ShouldNotEqual, nil)
			})
		})

		// requester: ecbdsa message
		mHat := requester.BlindMessage(m)
		Convey("After requester blinded message", func() {
			Convey("Message should have been hiddened", func() {
				So(mHat, ShouldNotEqual, 0)
				So(mHat, ShouldNotEqual, m)
			})
		})

		// signer: create ecbdsa signature
		sHat := signer.BlindSign(mHat)

		// requester extracts real signature
		sig := requester.UnblindMessage(sHat)
		// sig.M = m
		// fmt.Printf("sig =\t%x\n\t%x\n", sig.S, sig.F.X)

		Convey("The signature verify should be ok.", func() {
			So(BlindVerify(Q, m, sig), ShouldEqual, true)
		})

	})
}

//性能测试
func Benchmark_BlindSignature(b *testing.B) {
	for i := 0; i < b.N; i++ {
		signer := NewSigner()
		requester := NewRequester()

		// requester: message that needs to be ecbdsa signed
		m, err := RandFieldElement(rand.Reader)
		maybePanic(err)
		// fmt.Printf("m = %x\n", m)

		// requester: ask signer to start the protocol

		R := signer.GenerateSessionKeyPair()
		fmt.Println("")

		Q := signer.Q
		if Q != nil && R != nil {
			// fmt.Println("Q = ", Q)
			// fmt.Println("R = ", R)

			// requester: generate blindkey
			requester.GenerateBlindKey(R, Q)
			// requester: ecbdsa message
			mHat := requester.BlindMessage(m)

			// signer: create ecbdsa signature
			sHat := signer.BlindSign(mHat)

			// requester extracts real signature
			sig := requester.UnblindMessage(sHat)
			// sig.M = m
			// fmt.Printf("sig =\t%x\n\t%x\n", sig.S, sig.F.X)

			// onlooker verifies signature
			if BlindVerify(Q, m, sig) {
				// fmt.Printf("valid signature\n")
				// b.Log("有效签名，测试通过！")
			}

			return
		}

		// b.Error("测试不通过")
	}
}
