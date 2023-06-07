package wpACSS

import (
	"context"
	"fmt"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"github.com/opDPSSTeam/DPSS/pkg/vectorcommitment"
	"google.golang.org/protobuf/proto"
)

type PiRec struct {
	Cdk   bls.G1Point
	wdki  bls.G1Point
	Crec  []bls.G1Point
	weval []bls.G1Point
}

func printPiRec(pi *PiRec) {
	fmt.Println("Cdk: ", pi.Cdk.String())
	fmt.Println("wdki: ", pi.wdki.String())
	for i := 0; i < len(pi.Crec); i++ {
		fmt.Println("Crec: ", pi.Crec[i].String())
	}
	for i := 0; i < len(pi.weval); i++ {
		fmt.Println("weval: ", pi.weval[i].String())
	}
}

type vShare struct {
	s           bls.Fr
	dskShare    bls.Fr
	recPolyEval []bls.Fr
}

func newVShare(s bls.Fr, dskShare bls.Fr, recPolyEval []bls.Fr) *vShare {
	return &vShare{s, dskShare, recPolyEval}
}

func printVShare(v *vShare) {
	fmt.Println("s: ", v.s.String())
	fmt.Println("dskShare: ", v.dskShare.String())
	for i := 0; i < len(v.recPolyEval); i++ {
		fmt.Println("recPolyEval: ", v.recPolyEval[i].String())
	}
}

type piShare struct {
	Gs     bls.G1Point
	Cvss   bls.G1Point
	wvssi  bls.G1Point
	Cz     bls.G1Point
	wz0    bls.G1Point
	Cvcom  []byte
	piVcom vectorcommitment.PiVcomMerkle
	piRec  PiRec
}

func newPiShare(Gs bls.G1Point, Cvss bls.G1Point, wvssi bls.G1Point, Cz bls.G1Point, wz0 bls.G1Point, Cvcom []byte, piVcom vectorcommitment.PiVcomMerkle, piRec PiRec) *piShare {
	return &piShare{Gs, Cvss, wvssi, Cz, wz0, Cvcom, piVcom, piRec}
}

func printPiShare(p *piShare) {
	fmt.Println("Gs: ", p.Gs.String())
	fmt.Println("Cvss: ", p.Cvss.String())
	fmt.Println("wvssi: ", p.wvssi.String())
	fmt.Println("Cz: ", p.Cz.String())
	fmt.Println("wz0: ", p.wz0.String())
	fmt.Println("Cvcom: ", string(p.Cvcom))
	for i := 0; i < len(p.piVcom.Indicator); i++ {
		fmt.Printf("Indicator[%d]: %d", i, p.piVcom.Indicator[i])
	}
	for i := 0; i < len(p.piVcom.Path); i++ {
		fmt.Printf("Path[%d]: %s", i, string(p.piVcom.Path[i]))
	}
	printPiRec(&p.piRec)
}

// wpAcssShare shares the secret to the other parties
// Assuming KZG setup has done, and public parameters are available
func wpAcssShareSend(ctx context.Context, p *party.HonestParty, ID []byte, current bool, F uint32, N uint32, secret bls.Fr) {

	//shares[0]=s, the other n elements are secret shares
	Cvss, shares, witnesses, polyF := vss.VssShare(p, F, N, secret)

	//Gs=g^s
	var Gs bls.G1Point
	bls.MulG1(&Gs, &bls.GenG1, &shares[0])

	// Z(x) = F(x) - s
	polyZ := make([]bls.Fr, F+1)
	copy(polyZ, polyF)
	bls.CopyFr(&polyZ[0], &bls.ZERO)

	//commit to polyZ
	p.MutexKZG.Lock()
	Cz := p.KZG.CommitToPoly(polyZ)
	p.MutexKZG.Unlock()

	//witness to Z(0)
	p.MutexKZG.Lock()
	wz0 := *p.KZG.ComputeProofSingle(polyZ, bls.ZERO)
	p.MutexKZG.Unlock()

	//generate recovery polynomials, polyPhi includes ell=4 polynomials
	dskShare, polyPhi, piRec := GenRecPoly(p, F, N)

	//commit to vg
	vg := make([]bls.G1Point, N)
	for i := uint32(0); i < N; i++ {
		bls.MulG1(&vg[i], &bls.GenG1, &shares[i+1])
	}

	vgBytes := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		vgBytes[i] = []byte(vg[i].String())
	}
	tre, _ := vectorcommitment.NewMerkleTree(vgBytes)
	Cvcom := tre.GetMerkleTreeRoot()

	var tmpV *vShare
	var tmpP *piShare
	for i := 0; uint32(i) < N; i++ {
		piVcom := tre.GetMerkleTreeProofPi(i)

		var PolyEval = make([]bls.Fr, 4)
		var tmpPos bls.Fr
		bls.AsFr(&tmpPos, uint64(i))
		for j := 0; j < 4; j++ {
			bls.EvalPolyAt(&PolyEval[j], polyPhi[j], &tmpPos)
		}

		tmpV = newVShare(shares[i+1], dskShare[i], PolyEval)
		tmpP = newPiShare(Gs, *Cvss, witnesses[i+1], *Cz, wz0, Cvcom, piVcom, piRec[i])
		data := EncapsulateWpAcssSend(tmpV, tmpP)
		fmt.Printf("[wpACSS.Share] Client send wpAcssShare done for i=%d\n", i)

		var wpAcssMsg protobuf.WpAcssShare
		err := proto.Unmarshal(data, &wpAcssMsg)
		if err != nil {
			fmt.Printf("[wpACSS.Share] Client send wpAcssShare error: %v\n", err)
		}
		vDec, pDec := DecapsulateWpAcssSend(&wpAcssMsg)

		//this block is to verify the correctness of Encapsulate and Decapsulate messages
		/* 		fmt.Println("=======tmpV=======")
		   		printVShare(tmpV)
		   		fmt.Println("=======vDec=======")
		   		printVShare(vDec)

		   		fmt.Println("=======tmpP=======")
		   		printPiShare(tmpP)
		   		fmt.Println("=======pDec=======")
		   		printPiShare(pDec) */

		// err := p.Send(&protobuf.Message{
		// 	Type:   "wpAcssShare",
		// 	Id:     ID,
		// 	Sender: p.PID,
		// 	Data:   data,
		// }, uint32(i))
		// if err != nil {
		// 	fmt.Printf("[wpACSS.Share] Client send wpAcssShare error: %v\n", err)
		// }
		// tmpV.s = shares[i+1]
		// tmpV.dskShare = dskShare[i]
		// tmpV.recPolyEval = polyPhi[i]
	}

	//valueMessage := core.Encapsulation("Value", ID, p.PID, &protobuf.Value{
	//	Value:      secret,
	//	Validation: validation,
	//})
	//
	//if current {
	//	err := p.Broadcast(valueMessage)
	//	if err != nil {
	//		log.Printf("Broadcast error: %v", err)
	//		return nil, nil, false
	//	}
	//} else {
	//	err := p.BroadcastToNextCommittee(valueMessage)
	//	if err != nil {
	//		log.Printf("BroadcastToNextCommittee error: %v", err)
	//		return nil, nil, false
	//	}
	//}

	// sigs := [][]byte{}
	// h := sha3.Sum512(secret)
	// var buf bytes.Buffer
	// buf.Write([]byte("Echo"))
	// buf.Write(ID)
	// buf.Write(h[:])
	// sm := buf.Bytes()

	// for {
	// 	select {
	// 	case <-ctx.Done():
	// 		return nil, nil, false
	// 	case m := <-p.GetMessage("Echo", ID):
	// 		payload := core.Decapsulation("Echo", m).(*protobuf.Echo)
	// 		sigs = append(sigs, payload.Sigshare)
	// 		if len(sigs) > int(2*p.F) {
	// 			signature, _ := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite()).Recover(p.SigPK, sm, sigs, int(2*p.F+1), int(p.N))
	// 			return h[:], signature, true
	// 		}
	// 	}
	// }
}

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
		y[i] = dprf.Eval(utils.Uint32ToBytes(i+1), *dsk)
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

		p.MutexKZG.Lock()
		Crec[i] = p.KZG.CommitToPoly(poly[i])
		for j := uint32(0); j < n; j++ {
			var position bls.Fr
			bls.AsFr(&position, uint64(j))
			weval[i][j] = *p.KZG.ComputeProofSingle(poly[i], position)
		}
		p.MutexKZG.Unlock()
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

func EncapsulateWpAcssSend(v *vShare, pi *piShare) []byte {
	var msg = new(protobuf.WpAcssShare)
	msg.V = new(protobuf.VInShare)
	msg.P = new(protobuf.PiInShare)

	msg.V.S = []byte(v.s.String())
	msg.V.DskShare = []byte(v.dskShare.String())
	msg.V.RecPolyEval = make([][]byte, len(v.recPolyEval))
	for i := 0; i < len(v.recPolyEval); i++ {
		msg.V.RecPolyEval[i] = []byte(v.recPolyEval[i].String())
	}

	msg.P.Gs = bls.ToCompressedG1(&pi.Gs)
	msg.P.Cvss = bls.ToCompressedG1(&pi.Cvss)
	msg.P.Wvssi = bls.ToCompressedG1(&pi.wvssi)
	msg.P.Cz = bls.ToCompressedG1(&pi.Cz)
	msg.P.Wz0 = bls.ToCompressedG1(&pi.wz0)
	msg.P.Cvcom = append([]byte{}, pi.Cvcom...)

	msg.P.PiVcom = new(protobuf.PiVcomMerkle)
	for i := 0; i < len(pi.piVcom.Indicator); i++ {
		msg.P.PiVcom.Indicator = append(msg.P.PiVcom.Indicator, pi.piVcom.Indicator[i])
		msg.P.PiVcom.Path = append(msg.P.PiVcom.Path, pi.piVcom.Path[i])
	}

	msg.P.PiRec = new(protobuf.PiRec)
	msg.P.PiRec.Cdk = bls.ToCompressedG1(&pi.piRec.Cdk)
	msg.P.PiRec.Wdki = bls.ToCompressedG1(&pi.piRec.wdki)
	msg.P.PiRec.Crec = make([][]byte, len(pi.piRec.Crec))
	msg.P.PiRec.Weval = make([][]byte, len(pi.piRec.weval))
	for i := 0; i < len(pi.piRec.Crec); i++ {
		msg.P.PiRec.Crec[i] = bls.ToCompressedG1(&pi.piRec.Crec[i])
		msg.P.PiRec.Weval[i] = bls.ToCompressedG1(&pi.piRec.weval[i])
	}

	data, _ := proto.Marshal(msg)
	return data
}

func DecapsulateWpAcssSend(m *protobuf.WpAcssShare) (*vShare, *piShare) {

	//decapsulate v
	vDec := new(vShare)

	sRaw := new(bls.Fr)
	bls.SetFr(sRaw, string(m.V.S))
	bls.CopyFr(&vDec.s, sRaw)

	dskShareRaw := new(bls.Fr)
	bls.SetFr(dskShareRaw, string(m.V.DskShare))
	bls.CopyFr(&vDec.dskShare, dskShareRaw)

	vDec.recPolyEval = make([]bls.Fr, 4) //ell=4
	for i := 0; i < 4; i++ {
		recPolyEvalRaw := new(bls.Fr)
		bls.SetFr(recPolyEvalRaw, string(m.V.RecPolyEval[i]))
		bls.CopyFr(&vDec.recPolyEval[i], recPolyEvalRaw)
	}

	//decapsulate pi
	piDec := new(piShare)
	GsRaw, _ := bls.FromCompressedG1(m.P.Gs)
	bls.CopyG1(&piDec.Gs, GsRaw)

	CvssRaw, _ := bls.FromCompressedG1(m.P.Cvss)
	bls.CopyG1(&piDec.Cvss, CvssRaw)

	wvssiRaw, _ := bls.FromCompressedG1(m.P.Wvssi)
	bls.CopyG1(&piDec.wvssi, wvssiRaw)

	CzRaw, _ := bls.FromCompressedG1(m.P.Cz)
	bls.CopyG1(&piDec.Cz, CzRaw)

	wz0Raw, _ := bls.FromCompressedG1(m.P.Wz0)
	bls.CopyG1(&piDec.wz0, wz0Raw)

	piDec.Cvcom = append([]byte{}, m.P.Cvcom...)

	piDec.piVcom.Path = make([][]byte, len(m.P.PiVcom.Path))
	piDec.piVcom.Indicator = make([]int64, len(m.P.PiVcom.Indicator))
	for i := 0; i < len(m.P.PiVcom.Path); i++ {
		piDec.piVcom.Path[i] = append([]byte{}, m.P.PiVcom.Path[i]...)
		piDec.piVcom.Indicator[i] = m.P.PiVcom.Indicator[i]
	}

	CdkRaw, _ := bls.FromCompressedG1(m.P.PiRec.Cdk)
	bls.CopyG1(&piDec.piRec.Cdk, CdkRaw)

	wdkiRaw, _ := bls.FromCompressedG1(m.P.PiRec.Wdki)
	bls.CopyG1(&piDec.piRec.wdki, wdkiRaw)

	piDec.piRec.Crec = make([]bls.G1Point, len(m.P.PiRec.Crec))
	piDec.piRec.weval = make([]bls.G1Point, len(m.P.PiRec.Weval))
	for i := 0; i < len(m.P.PiRec.Crec); i++ {
		CrecRaw, _ := bls.FromCompressedG1(m.P.PiRec.Crec[i])
		bls.CopyG1(&piDec.piRec.Crec[i], CrecRaw)
		wevalRaw, _ := bls.FromCompressedG1(m.P.PiRec.Weval[i])
		bls.CopyG1(&piDec.piRec.weval[i], wevalRaw)
	}

	return vDec, piDec
}
