package VectorCommit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go-demo/bls"
	"math/big"
	"testing"

	kbls "github.com/kilic/bls12-381"
)

func TestVC(t *testing.T) {
	var n uint32
	for f := uint32(1); f < 42; f++ {
		n = 3*f + 1
		var messages []kbls.Fr
		var messagesG1 []bls.G1Point
		for i := uint32(0); i < n; i++ {
			fr := kbls.Fr{}
			if _, err := fr.Rand(rand.Reader); err != nil {
				panic("")
			}
			fr.ToRed()
			messages = append(messages, fr)
			var tmpG1 bls.G1Point
			var tmpFr bls.Fr
			bls.AsFr(&tmpFr, uint64(i))
			bls.MulG1(&tmpG1, &bls.GenG1, &tmpFr)
			messagesG1 = append(messagesG1, tmpG1)
		}
		vc := New(n)
		commitment := vc.Commit(messages)
		witness := vc.Open(messages, 2)
		if !vc.Verify(commitment, messages[2], 2, witness) {
			panic("")
		}
		fmt.Printf("[n = %d] verify ok\n", n)

		// we use sha256 to map bls.G1Point to kbls.Fr
		convertedMsg := make([]kbls.Fr, n)
		for i := uint32(0); i < n; i++ {
			str := sha256.Sum256([]byte(messagesG1[i].String()))
			var bv big.Int
			bv.SetString(hex.EncodeToString(str[:]), 16)
			convertedMsg[i] = *kbls.NewFr().RedFromBytes(bv.Bytes())
		}
		commitmentG1 := vc.Commit(convertedMsg)
		witnessG1 := vc.Open(convertedMsg, 2)
		if !vc.Verify(commitmentG1, convertedMsg[2], 2, witnessG1) {
			panic("")
		}
		fmt.Printf("[n = %d] verify convert ok\n", n)
	}
}
