package main

import "crypto/rand"
import "fmt"
import "github.com/conseweb/ecbdsa"

func main() {
	// generate keys for Alice and Bob
	alice, _ := ecbdsa.GenerateKey(rand.Reader)
	bob, _ := ecbdsa.GenerateKey(rand.Reader)
	fmt.Printf("Alice:\t%x\n\t%x\n", alice.D, alice.PublicKey.X)
	fmt.Printf("Bob:\t%x\n\t%x\n", bob.D, bob.PublicKey.X)
	fmt.Println("")

	// Alice calculates shared secret
	aliceShared := ecbdsa.ECDH(alice, &bob.PublicKey)
	fmt.Printf("Alice: %x\n", aliceShared)

	// Bob calculates shared secret
	bobShared := ecbdsa.ECDH(bob, &alice.PublicKey)
	fmt.Printf("Bob:   %x\n", bobShared)
}
