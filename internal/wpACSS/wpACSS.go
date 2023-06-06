package wpACSS

import (
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
)

type PiRec struct {
	Cdk   bls.G1Point
	wdki  bls.G1Point
	Crec  []bls.G1Point
	weval []bls.G1Point
}

func newPiRec(Cdk bls.G1Point, wdki bls.G1Point, Crec []bls.G1Point, weval []bls.G1Point) *PiRec {
	return &PiRec{Cdk, wdki, Crec, weval}
}

// // wpAcssShare shares the secret to the other parties
// // Assuming KZG setup has done, and public parameters are available
// func wpAcssShareSend(ctx context.Context, p *party.HonestParty, ID []byte, current bool, F uint32, N uint32, secret bls.Fr, validation []byte) ([]byte, []byte, bool) {

// 	Cvss, shares, witnesses, polyF := vss.VssShare(p, F, N, secret)
// 	polyZ := make([]bls.Fr, N)
// 	copy(polyZ, polyF)
// 	bls.CopyFr(&polyZ[0], &bls.ZERO) // Z(x) = F(x) - s

// 	//commit to polyZ
// 	p.MutexKZG.Lock()
// 	Cz := p.KZG.CommitToPoly(polyZ)
// 	p.MutexKZG.Unlock()

// 	//witnesses
// 	p.MutexKZG.Lock()
// 	wz0 := *p.KZG.ComputeProofSingle(polyZ, bls.ZERO)
// 	p.MutexKZG.Unlock()

// 	//commit to vg
// 	vg := make([]bls.G1Point, N)
// 	for i := uint32(0); i < N; i++ {
// 		bls.MulG1(&vg[i], &bls.GenG1, &shares[i+1])
// 	}

// 	vgBytes := make([][]byte, N)
// 	for i := uint32(0); i < N; i++ {
// 		vgBytes[i] = []byte(vg[i].String())
// 	}
// 	tre, err := vectorcommitment.NewMerkleTree(vgBytes)
// 	Cvcom := tre.GetMerkleTreeRoot()

// 	//valueMessage := core.Encapsulation("Value", ID, p.PID, &protobuf.Value{
// 	//	Value:      secret,
// 	//	Validation: validation,
// 	//})
// 	//
// 	//if current {
// 	//	err := p.Broadcast(valueMessage)
// 	//	if err != nil {
// 	//		log.Printf("Broadcast error: %v", err)
// 	//		return nil, nil, false
// 	//	}
// 	//} else {
// 	//	err := p.BroadcastToNextCommittee(valueMessage)
// 	//	if err != nil {
// 	//		log.Printf("BroadcastToNextCommittee error: %v", err)
// 	//		return nil, nil, false
// 	//	}
// 	//}

// 	sigs := [][]byte{}
// 	h := sha3.Sum512(secret)
// 	var buf bytes.Buffer
// 	buf.Write([]byte("Echo"))
// 	buf.Write(ID)
// 	buf.Write(h[:])
// 	sm := buf.Bytes()

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			return nil, nil, false
// 		case m := <-p.GetMessage("Echo", ID):
// 			payload := core.Decapsulation("Echo", m).(*protobuf.Echo)
// 			sigs = append(sigs, payload.Sigshare)
// 			if len(sigs) > int(2*p.F) {
// 				signature, _ := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite()).Recover(p.SigPK, sm, sigs, int(2*p.F+1), int(p.N))
// 				return h[:], signature, true
// 			}
// 		}
// 	}
// }

func GenRecPoly(p *party.HonestParty, f uint32, n uint32) ([]bls.Fr, [][]bls.Fr, []PiRec) {
	dsk, _, Cdk, dskShare, _, wdk := dprf.InitDPRF(p, f, n)
	y := make([]bls.Fr, n)
	I := make([]bls.Fr, n)

	ell := uint32(4)
	poly := make([][]bls.Fr, ell) //phi_k(x), k = 1, ..., ell
	Crec := make([]*bls.G1Point, ell)
	weval := make([][]bls.G1Point, ell)
	piRec := make([]PiRec, n)
	for i := uint32(0); i < n; i++ {
		piRec[i].Crec = make([]bls.G1Point, ell)
		piRec[i].weval = make([]bls.G1Point, ell)
	}

	for i := uint32(0); i < n; i++ {
		y[i] = dprf.Eval(i32tob(i+1), *dsk)
		bls.AsFr(&I[i], uint64(i+1))
		// uncomment to test GenRecPoly()
		// fmt.Printf("y[%d] = %s\n", i, y[i].String())
	}

	for i := uint32(0); i < ell; i++ {
		weval[i] = make([]bls.G1Point, n)
		if (i+1)*f < n {
			poly[i] = vss.MakeSecret(p, f, n, I[i*f:(i+1)*f], y[i*f:(i+1)*f])
		} else {
			poly[i] = vss.MakeSecret(p, f, n, I[i*f:], y[i*f:])
		}
		Crec[i] = p.KZG.CommitToPoly(poly[i])
		for j := uint32(0); j < n; j++ {
			var position bls.Fr
			bls.AsFr(&position, uint64(j))
			weval[i][j] = *p.KZG.ComputeProofSingle(poly[i], position)
		}
	}

	//the following block is used to test the correctness of GenRecPoly()
	/* 	var tmpEval bls.Fr
	   	var tmpPos bls.Fr
	   	for i := uint32(0); i < ell; i++ {
	   		for j := uint32(0); j < f; j++ {
	   			bls.AsFr(&tmpPos, uint64(i*f+j+1))
	   			bls.EvalPolyAt(&tmpEval, poly[i], &tmpPos)
	   			fmt.Printf("poly[%d](%d) = %s\n", i, i*f+j+1, tmpEval.String())
	   		}
	   	} */

	for i := uint32(0); i < n; i++ {
		bls.CopyG1(&piRec[i].Cdk, Cdk)
		bls.CopyG1(&piRec[i].wdki, &wdk[i])
		for k := uint32(0); k < ell; k++ {
			bls.CopyG1(&piRec[i].Crec[k], Crec[k])
			bls.CopyG1(&piRec[i].weval[k], &weval[k][i])
		}
	}
	return dskShare, poly, piRec
}

func i32tob(val uint32) []byte {
	r := make([]byte, 4)
	for i := uint32(0); i < 4; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}
