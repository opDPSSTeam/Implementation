package vss

import (
	"fmt"
	"testing"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
	"github.com/opDPSSTeam/DPSS/pkg/pointproofs"
	"github.com/stretchr/testify/assert"
)

func TestVSS(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	vc := pointproofs.New(N)
	client := party.NewHonestParty(0, N, F, N, ipList, portList, nil, nil, nil, nil, pk, nil, sk[2*F+1], vc)

	var secret bls.Fr
	bls.AsFr(&secret, uint64(12345))

	//share
	//var shares []bls.Fr
	C, shares, witnesses, _ := VssShare(client, F, N, secret)

	//verify
	Indexes := make([]bls.Fr, F+1)
	for i := uint32(0); i < F+1; i++ {
		bls.AsFr(&Indexes[i], uint64(i+1)) // Indexes = [1,2,3,4]
		assert.True(t, client.KZG.CheckProofSingle(C, &witnesses[i], &Indexes[i], &shares[i+1]))
	}

	//reconstruct
	newPoly := polyring.LagrangeInterpolate(F, Indexes, shares[1:F+2])
	fmt.Printf("secret: %s\n", newPoly[0].String())
	fmt.Println("reconstructed polynomial:", party.PolyToString(newPoly))
	assert.True(t, bls.EqualFr(&newPoly[0], &secret), "reconstructed secret is not equal to the original secret")

	//test MakeSecret
	polyM := MakeSecret(client, F, N, Indexes[:F], shares[1:F+1])
	newShares := make([]bls.Fr, F)
	for i := uint32(0); i < F; i++ {
		bls.EvalPolyAt(&newShares[i], polyM, &Indexes[i])
		assert.True(t, bls.EqualFr(&newShares[i], &shares[i+1]))
	}
}
