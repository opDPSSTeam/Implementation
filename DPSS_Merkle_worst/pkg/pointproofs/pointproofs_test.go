package pointproofs

import (
	"crypto/rand"
	"fmt"
	"testing"

	kbls "github.com/kilic/bls12-381"
)

func TestVC(t *testing.T) {
	var len int
	for i := 1; i < 43; i++ {
		len = 3*i + 1
		var messages []kbls.Fr
		for i := 0; i < len; i++ {
			fr := kbls.Fr{}
			if _, err := fr.Rand(rand.Reader); err != nil {
				panic("")
			}
			fr.ToRed()
			messages = append(messages, fr)
		}
		vc := New(len)
		commitment := vc.Commit(messages)
		witness := vc.Open(messages, 2)
		if !vc.Verify(commitment, messages[2], 2, witness) {
			panic("")
		}
		fmt.Printf("[len = %d] verify ok\n", len)
	}
}
