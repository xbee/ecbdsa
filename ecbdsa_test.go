package ecbdsa

import (
	"crypto/rand"
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func Test_Blind(t *testing.T) {
	var signer *Signer
	var requester *Requester

	// Only pass t into top-level Convey calls
	Convey("Given a fresh signer and a fresh requester", t, func() {

		signer = NewSigner()
		requester = NewRequester()

		Convey("When signer's priv and pub key should not be nil", func() {
			So(signer.d, ShouldNotEqual, nil)
			So(signer.Q, ShouldNotEqual, nil)
		})

		// requester: message that needs to be ecbdsa signed
		m, err := RandFieldElement(rand.Reader)
		maybePanic(err)
		// fmt.Printf("m = %x\n", m)

		// requester: ask signer to start the protocol

		R := signer.GenerateSessionKeyPair()
		// fmt.Println("")

		Q := signer.Q
		Convey("Signer's Q and R should not be nil", func() {
			So(Q, ShouldNotEqual, nil)
			So(R, ShouldNotEqual, nil)
		})

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
