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
	Q, R := ecbdsa.NewSession(signer)
	fmt.Println("")

	// requester: ecbdsa message
	mHat := ecbdsa.BlindMessage(requester, Q, R, m)

	// signer: create ecbdsa signature
	sHat := ecbdsa.BlindSign(signer, R, mHat)

	// requester extracts real signature
	sig := ecbdsa.UnblindMessage(requester, sHat)
	sig.M = m
	fmt.Printf("sig =\t%x\n\t%x\n", sig.S, sig.F.X)

	// onlooker verifies signature
	if ecbdsa.BlindVerify(Q, sig) {
		fmt.Printf("valid signature\n")
	}
}

func maybePanic(err error) {
	if err != nil {
		panic(err)
	}
}
