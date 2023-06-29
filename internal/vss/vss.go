package vss

import (
	"log"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
)

//VssShare shares the secret s, and returns a polynomial commitment, and n share-witness tuples
func VssShare(p *party.HonestParty, f uint32, n uint32, s bls.Fr) (*bls.G1Point, []bls.Fr, []bls.G1Point, []bls.Fr) {
	polyF := make([]bls.Fr, f+1) // f-degree polynomial

	for i := 0; uint32(i) < f+1; i++ {
		polyF[i] = *bls.RandomFr()
	}
	//set the constant term to be s
	bls.CopyFr(&polyF[0], &s)

	//commit to polyF
	p.MutexKZG.Lock()
	Cvss := p.KZG.CommitToPoly(polyF)
	p.MutexKZG.Unlock()

	//shares
	shares := make([]bls.Fr, n+1)
	var position bls.Fr
	for i := 0; uint32(i) < n+1; i++ {
		bls.AsFr(&position, uint64(i))
		bls.EvalPolyAt(&shares[i], polyF, &position)
	}

	//witnesses
	w := make([]bls.G1Point, n+1)
	p.MutexKZG.Lock()
	for i := 0; uint32(i) < n+1; i++ {
		bls.AsFr(&position, uint64(i))
		w[i] = *p.KZG.ComputeProofSingle(polyF, position)
	}
	p.MutexKZG.Unlock()
	return Cvss, shares, w, polyF
}

func MakeSecret(p *party.HonestParty, f uint32, n uint32, I []bls.Fr, y []bls.Fr) []bls.Fr {
	if len(I) != len(y) || len(I) == 0 || len(I) > int(f) {
		log.Println("invalid input: too long or |I|=0")
	}

	value := make([]bls.Fr, f+1)
	index := make([]bls.Fr, f+1)
	for i := uint32(0); i < f+1; i++ {
		// bls.AsFr(&index[i], uint64(i+1))
		if i < uint32(len(I)) {
			bls.CopyFr(&index[i], &I[i])
			bls.CopyFr(&value[i], &y[i])
			// index[i] = I[i]
			// value[i] = y[i]
		} else {
			bls.AsFr(&index[i], uint64(n+i)) //make sure that the index value is not in I
			value[i] = *bls.RandomFr()
		}
	}

	newPoly := polyring.LagrangeInterpolate(f, index, value)
	// p.MutexKZG.Lock()
	// Crec := p.KZG.CommitToPoly(newPoly)
	// p.MutexKZG.Unlock()

	// w := make([]bls.G1Point, n)
	// position := make([]bls.Fr, n)
	// p.MutexKZG.Lock()
	// for i := 0; uint32(i) < n+1; i++ {
	// 	bls.AsFr(&position[i], uint64(i+1)) //position = 1, ..., N
	// 	w[i] = *p.KZG.ComputeProofSingle(newPoly, position[i])
	// }
	// p.MutexKZG.Unlock()

	return newPoly
}
