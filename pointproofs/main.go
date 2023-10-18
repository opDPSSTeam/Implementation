package main

import (
	"crypto/rand"
	"fmt"
	"go-demo/VectorCommit"

	kbls "github.com/kilic/bls12-381"
)

func main() {
	var len = uint32(64)
	var messages []kbls.Fr
	for i := uint32(0); i < len; i++ {
		fr := kbls.Fr{}
		if _, err := fr.Rand(rand.Reader); err != nil {
			panic("")
		}
		fr.ToRed()
		messages = append(messages, fr)
	}
	vc := VectorCommit.New(len)
	commitment := vc.Commit(messages)
	witness := vc.Open(messages, 2)
	if !vc.Verify(commitment, messages[2], 2, witness) {
		panic("")
	}
	fmt.Printf("Success for len = %d\n", len)
}
