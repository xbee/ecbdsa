package main

import "crypto/rand"
import "fmt"
import "github.com/conseweb/ecbdsa"

func main() {
	signer := ecbdsa.NewSigner()
	requester := ecbdsa.NewRequester()

	// requester: message that needs to be ecbdsa signed
	m, err := ecbdsa.RandFieldElement(rand.Reader)
	maybePanic(err)
	fmt.Printf("m = %x\n", m)

	// requester: ask signer to start the protocol
	
	_ = signer.GenerateSessionKeyPair()
	fmt.Println("")

	Q, R := signer.Q, signer.R
	if Q != nil && R != nil {
		fmt.Println("Q = ", Q)
		fmt.Println("R = ", R)

		// requester: generate blindkey
		requester.GenerateBlindKey(R, Q)
		// requester: ecbdsa message
		mHat := requester.BlindMessage(m)

		// signer: create ecbdsa signature
		sHat := signer.BlindSign(mHat)

		// requester extracts real signature
		sig := requester.UnblindMessage(sHat)
		// sig.M = m
		fmt.Printf("sig =\t%x\n\t%x\n", sig.S, sig.F.X)

		// onlooker verifies signature
		if ecbdsa.BlindVerify(Q, m, sig) {
			fmt.Printf("valid signature\n")
		}
		
		return
	}

	fmt.Println("signer.GenerateSessionKeyPair failed!")
	
}

func maybePanic(err error) {
	if err != nil {
		panic(err)
	}
}
