package wpACSS

import (
	"context"
	"errors"
	"fmt"

	kyberbls "github.com/drand/kyber-bls12381"
	"google.golang.org/protobuf/proto"

	"github.com/drand/kyber/sign/tbls"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"github.com/opDPSSTeam/DPSS/pkg/vectorcommitment"
)

// WpAcssShare shares the secret to the other parties, and returns a message md and a signature on md
// Assuming KZG setup has done, and public parameters are available
func WpAcssShareSend(ctx context.Context, p *party.HonestParty, ID []byte, current bool, F uint32, N uint32, secret bls.Fr) ([]byte, []byte) {

	//shares[0]=s, the other n elements are secret shares
	Cvss, shares, witnesses, polyF := vss.VssShare(p, F, N, secret)

	//Gs=g^s
	var Gs bls.G1Point
	bls.MulG1(&Gs, &bls.GenG1, &secret)

	// Z(x) = F(x) - s
	polyZ := make([]bls.Fr, F+1)
	copy(polyZ, polyF)
	bls.CopyFr(&polyZ[0], &bls.ZERO)

	p.MutexKZG.Lock()
	Cz := p.KZG.CommitToPoly(polyZ)                   //commit to polyZ
	wz0 := *p.KZG.ComputeProofSingle(polyZ, bls.ZERO) //witness to Z(0)
	p.MutexKZG.Unlock()

	//generate recovery polynomials, polyPhi includes ell=4 polynomials
	dskShare, polyPhi, piRec := genRecPoly(p, F, N)

	//commit to vg
	vg := make([]bls.G1Point, N)
	for i := uint32(0); i < N; i++ {
		bls.MulG1(&vg[i], &bls.GenG1, &shares[i+1])
	}

	vgBytes := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		// vgBytes[i] = []byte(vg[i].String())
		vgBytes[i] = bls.ToCompressedG1(&vg[i])
	}
	tre, _ := vectorcommitment.NewMerkleTree(vgBytes)
	Cvcom := tre.GetMerkleTreeRoot()

	var tmpV *party.VShare
	var tmpP *party.PiShare
	var data, mdPartial []byte
	var FLGmdEncoded bool = false
	for i := uint32(0); i < N; i++ {
		piVcom := tre.GetMerkleTreeProofPi(i)

		var PolyEval = make([]bls.Fr, 4)
		var tmpPos bls.Fr
		bls.AsFr(&tmpPos, uint64(i+1))
		for j := 0; j < 4; j++ {
			bls.EvalPolyAt(&PolyEval[j], polyPhi[j], &tmpPos)
		}

		tmpV = party.NewVShare(shares[i+1], dskShare[i], PolyEval)
		tmpP = party.NewPiShare(Gs, *Cvss, witnesses[i+1], *Cz, wz0, Cvcom, piVcom, piRec[i])
		if i == 0 {
			data, mdPartial = encapsulateWpAcssSend(tmpV, tmpP, FLGmdEncoded)
			FLGmdEncoded = true
		} else {
			data, _ = encapsulateWpAcssSend(tmpV, tmpP, FLGmdEncoded)
		}
		if current {
			err := p.Send(&protobuf.Message{
				Type:   "wpAcssShare",
				Id:     ID,
				Sender: p.PID,
				Data:   data,
			}, uint32(i)) //send to party i
			if err != nil {
				fmt.Printf("[wpACSS.Share] [Party %v] send wpAcssShare error: %v\n", p.PID, err)
			} else {
				fmt.Printf("[wpACSS.Share] [Party %v] send wpAcssShare to [Party %v] done\n", p.PID, i)
			}
		} else {
			err := p.SendToNextCommittee(&protobuf.Message{
				Type:   "wpAcssShare",
				Id:     ID,
				Sender: p.PID,
				Data:   data,
			}, uint32(i)) //send to party i
			if err != nil {
				fmt.Printf("[wpACSS.Share] [Old Party %v] send wpAcssShare error: %v\n", p.PID, err)
			} else {
				fmt.Printf("[wpACSS.Share] [Old Party %v] send wpAcssShare to [New Party %v] done\n", p.PID, i)
			}
		}
	}

	//this block is to verify the correctness of Encapsulate and Decapsulate messages
	/*
		var wpAcssMsg protobuf.WpAcssShare
		err := proto.Unmarshal(data, &wpAcssMsg)
		if err != nil {
			fmt.Printf("[wpACSS.Share] Client send wpAcssShare error: %v\n", err)
		}

		vDec, pDec := DecapsulateWpAcssSend(&wpAcssMsg)
		fmt.Println("=======tmpV=======")
		printVShare(tmpV)
		fmt.Println("=======vDec=======")
		printVShare(vDec)

		fmt.Println("=======tmpP=======")
		printPiShare(tmpP)
		fmt.Println("=======pDec=======")
		printPiShare(pDec) */

	sigs := [][]byte{}
	md := append([]byte{}, ID...)
	md = append(md, utils.Uint32ToBytes(p.PID)...)
	md = append(md, mdPartial...)

	for {
		select {
		case <-ctx.Done():
			return nil, nil
		case m := <-p.GetMessage("wpAcssEcho", ID):
			// case m := <-p.GetMessageFromNextCommittee("wpAcssEcho", ID):
			var payload protobuf.WpAcssEcho
			err := proto.Unmarshal(m.Data, &payload)
			if err != nil {
				fmt.Printf("[wpACSS.Share] [Party %v] unmarshal wpAcssEcho error: %v\n", p.PID, err)
			} else {
				fmt.Printf("[wpACSS.Share] [Party %v] receive wpAcssEcho from [Party %v]\n", p.PID, m.Sender)
			}

			sigs = append(sigs, payload.Sigshare)
			if uint32(len(sigs)) > 2*p.F {
				//use different SigPK for verification
				if current {
					signature, _ := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite()).Recover(p.SigPK, md, sigs, int(2*p.F+1), int(p.N))
					return md, signature
				} else {
					signature, _ := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite()).Recover(p.SigPKNew, md, sigs, int(2*p.F+1), int(p.N))
					return md, signature
				}
			}
		}
	}
}

//WpAcssShareEcho handles the wpAcssShare message from other parties, and returns a value-proof tuple (v, pi)
func WpAcssShareEcho(p *party.HonestParty, isNew bool, ID []byte) (party.VShare, party.PiShare, error) {
	m := <-p.GetMessage("wpAcssShare", ID)

	var wpAcssMsg protobuf.WpAcssShare
	err := proto.Unmarshal(m.Data, &wpAcssMsg)
	if err != nil {
		fmt.Printf("[wpACSS.Share] [Party %v] receive wpAcssShare error: %v\n", p.PID, err)
	} // else {
	// 	fmt.Printf("[wpACSS.Share] [Party %v] receive wpAcssShare from [Party %v]\n", p.PID, m.Sender)
	// }

	vDec, pDec, mdPartial, isValid := decapAndVrfyWpAcssSend(p, &wpAcssMsg)
	if !isValid {
		return party.VShare{}, party.PiShare{}, errors.New("invalid wpAcssShare")
	}

	senderID := m.Sender
	var md []byte

	// md = ID||d||g^s||Cvss||Cvcom||Cdk||Crec[k]_k=0^3
	//    = ID||d||mdPartial
	md = append([]byte(ID), utils.Uint32ToBytes(senderID)...)
	md = append(md, mdPartial...)

	sigShare, _ := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite()).Sign(p.SigSK, md)

	var echoMsg = new(protobuf.WpAcssEcho)
	echoMsg.Sigshare = sigShare
	data, _ := proto.Marshal(echoMsg)

	if isNew {
		err = p.SendToOldCommittee(&protobuf.Message{
			Type:   "wpAcssEcho",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, senderID)
		if err != nil {
			fmt.Printf("[wpACSS.Share] [New Party %d] send wpAcssEcho error: %v\n", p.PID, err)
		} else {
			fmt.Printf("[wpACSS.Share] [New Party %d] send wpAcssEcho to [Old Party %v] done\n", p.PID, senderID)
		}
	} else {
		err = p.Send(&protobuf.Message{
			Type:   "wpAcssEcho",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, senderID)
		if err != nil {
			fmt.Printf("[wpACSS.Share] [Party %d] send wpAcssEcho error: %v\n", p.PID, err)
		} else {
			fmt.Printf("[wpACSS.Share] [Party %d] send wpAcssEcho to [Party %v] done\n", p.PID, senderID)
		}
	}

	p.SetVPTuples(vDec, pDec, senderID)
	p.DSKi[senderID] = vDec.DskShare
	var tmpDVK bls.G1Point
	bls.MulG1(&tmpDVK, &bls.GenG1, &vDec.DskShare)
	bls.CopyG1(&p.DVKi[senderID], &tmpDVK)

	return *vDec, *pDec, nil
}

func verifyWpAcssSend(p *party.HonestParty, vDec *party.VShare, pDec *party.PiShare) bool {
	var tmpG1 bls.G1Point
	bls.AddG1(&tmpG1, &pDec.Gs, &pDec.Cz)
	if !bls.EqualG1(&pDec.Cvss, &tmpG1) {
		fmt.Printf("[wpACSS.Share] [Party %v] verifyWpAcssSend failed: Cvss != Gs*Cz\n", p.PID)
		return false
	}
	p.MutexKZG.Lock()
	if !p.KZG.CheckProofSingle(&pDec.Cz, &pDec.Wz0, &bls.ZERO, &bls.ZERO) {
		fmt.Printf("[wpACSS.Share] [Party %v] verifyWpAcssSend failed: wz0 proof failed\n", p.PID)
		p.MutexKZG.Unlock()
		return false
	}
	p.MutexKZG.Unlock()

	var Gsi bls.G1Point
	bls.MulG1(&Gsi, &bls.GenG1, &vDec.S)
	if !vectorcommitment.VerifyMerkleTreeProof(pDec.Cvcom, pDec.PiVcom.Path, pDec.PiVcom.Indicator, bls.ToCompressedG1(&Gsi)) {
		fmt.Printf("[wpACSS.Share] [Party %v] verifyWpAcssSend failed: piVcom proof failed\n", p.PID)
		return false
	}

	for i := 0; i < 4; i++ {
		var pos bls.Fr
		bls.AsFr(&pos, uint64(p.PID+1))
		p.MutexKZG.Lock()
		if !p.KZG.CheckProofSingle(&pDec.PiRec.Crec[i], &pDec.PiRec.Weval[i], &pos, &vDec.RecPolyEval[i]) {
			p.MutexKZG.Unlock()
			fmt.Printf("[wpACSS.Share] [Party %v] verifyWpAcssSend failed: poly commitment to Phi_%v(%v) fail\n", p.PID, i, p.PID+1)
			return false
		}
		p.MutexKZG.Unlock()
	}

	return true
}

func genRecPoly(p *party.HonestParty, f uint32, n uint32) ([]bls.Fr, [][]bls.Fr, []party.PiRec) {
	dsk, _, Cdk, dskShare, _, wdk := dprf.InitDPRF(p, f, n)
	y := make([]bls.Fr, n)
	I := make([]bls.Fr, n)

	ell := uint32(4)
	poly := make([][]bls.Fr, ell) //phi_k(x), k = 1, ..., ell
	Crec := make([]*bls.G1Point, ell)
	weval := make([][]bls.G1Point, ell)
	piRec := make([]party.PiRec, n)
	for i := uint32(0); i < n; i++ {
		piRec[i].Crec = make([]bls.G1Point, ell)
		piRec[i].Weval = make([]bls.G1Point, ell)
	}

	for i := uint32(0); i < n; i++ {
		//the input to DPRF.Eval() is 1, ..., n
		//so party i corresponds to input value i+1
		y[i] = dprf.Eval(utils.Uint32ToBytes(i+1), *dsk)
		bls.AsFr(&I[i], uint64(i+1))

		// uncomment to test genRecPoly()
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
			weval[i][j] = *p.KZG.ComputeProofSingle(poly[i], I[j])
		}
		p.MutexKZG.Unlock()
	}

	//the following block is used to test the correctness of genRecPoly()
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
		bls.CopyG1(&piRec[i].Wdki, &wdk[i])
		for k := uint32(0); k < ell; k++ {
			bls.CopyG1(&piRec[i].Crec[k], Crec[k])
			bls.CopyG1(&piRec[i].Weval[k], &weval[k][i])
		}
	}
	return dskShare, poly, piRec
}

func encapsulateWpAcssSend(v *party.VShare, pi *party.PiShare, FLGmdEncoded bool) ([]byte, []byte) {
	var msg = new(protobuf.WpAcssShare)
	msg.V = new(protobuf.VInShare)
	msg.P = new(protobuf.PiInShare)

	msg.V.S = []byte(v.S.String())
	msg.V.DskShare = []byte(v.DskShare.String())
	msg.V.RecPolyEval = make([][]byte, len(v.RecPolyEval))
	for i := 0; i < len(v.RecPolyEval); i++ {
		msg.V.RecPolyEval[i] = []byte(v.RecPolyEval[i].String())
	}

	msg.P.Gs = bls.ToCompressedG1(&pi.Gs)
	msg.P.Cvss = bls.ToCompressedG1(&pi.Cvss)
	msg.P.Wvssi = bls.ToCompressedG1(&pi.Wvssi)
	msg.P.Cz = bls.ToCompressedG1(&pi.Cz)
	msg.P.Wz0 = bls.ToCompressedG1(&pi.Wz0)
	msg.P.Cvcom = append([]byte{}, pi.Cvcom...)

	msg.P.PiVcom = new(protobuf.PiVcomMerkle)
	for i := 0; i < len(pi.PiVcom.Indicator); i++ {
		msg.P.PiVcom.Indicator = append(msg.P.PiVcom.Indicator, pi.PiVcom.Indicator[i])
		msg.P.PiVcom.Path = append(msg.P.PiVcom.Path, pi.PiVcom.Path[i])
	}

	msg.P.PiRec = new(protobuf.PiRec)
	msg.P.PiRec.Cdk = bls.ToCompressedG1(&pi.PiRec.Cdk)
	msg.P.PiRec.Wdki = bls.ToCompressedG1(&pi.PiRec.Wdki)
	msg.P.PiRec.Crec = make([][]byte, len(pi.PiRec.Crec))
	msg.P.PiRec.Weval = make([][]byte, len(pi.PiRec.Weval))
	for i := 0; i < len(pi.PiRec.Crec); i++ {
		msg.P.PiRec.Crec[i] = bls.ToCompressedG1(&pi.PiRec.Crec[i])
		msg.P.PiRec.Weval[i] = bls.ToCompressedG1(&pi.PiRec.Weval[i])
	}
	var mdPartial []byte
	if !FLGmdEncoded {
		mdPartial = append([]byte("||"), msg.P.Gs...)
		mdPartial = append(mdPartial, []byte("||")...)
		mdPartial = append(mdPartial, msg.P.Cvss...)
		mdPartial = append(mdPartial, msg.P.Cvcom...)
		mdPartial = append(mdPartial, msg.P.PiRec.Cdk...)
		mdPartial = append(mdPartial, msg.P.PiRec.Crec[0]...)
		mdPartial = append(mdPartial, msg.P.PiRec.Crec[1]...)
		mdPartial = append(mdPartial, msg.P.PiRec.Crec[2]...)
		mdPartial = append(mdPartial, msg.P.PiRec.Crec[3]...)
	} else {
		mdPartial = nil
	}

	data, _ := proto.Marshal(msg)
	return data, mdPartial
}

//decapAndVrfyWpAcssSend decapsulates the message and then verifies its correctness. It also returns a mdPartial value that is used in threshold signature.
func decapAndVrfyWpAcssSend(p *party.HonestParty, m *protobuf.WpAcssShare) (*party.VShare, *party.PiShare, []byte, bool) {
	var mdPartial []byte
	//decapsulate v
	vDec := new(party.VShare)

	sRaw := new(bls.Fr)
	bls.SetFr(sRaw, string(m.V.S))
	bls.CopyFr(&vDec.S, sRaw)

	dskShareRaw := new(bls.Fr)
	bls.SetFr(dskShareRaw, string(m.V.DskShare))
	bls.CopyFr(&vDec.DskShare, dskShareRaw)

	vDec.RecPolyEval = make([]bls.Fr, 4) //ell=4
	for i := 0; i < 4; i++ {
		recPolyEvalRaw := new(bls.Fr)
		bls.SetFr(recPolyEvalRaw, string(m.V.RecPolyEval[i]))
		bls.CopyFr(&vDec.RecPolyEval[i], recPolyEvalRaw)
	}

	//decapsulate pi
	piDec := new(party.PiShare)
	GsRaw, _ := bls.FromCompressedG1(m.P.Gs)
	bls.CopyG1(&piDec.Gs, GsRaw)

	CvssRaw, _ := bls.FromCompressedG1(m.P.Cvss)
	bls.CopyG1(&piDec.Cvss, CvssRaw)

	wvssiRaw, _ := bls.FromCompressedG1(m.P.Wvssi)
	bls.CopyG1(&piDec.Wvssi, wvssiRaw)

	CzRaw, _ := bls.FromCompressedG1(m.P.Cz)
	bls.CopyG1(&piDec.Cz, CzRaw)

	wz0Raw, _ := bls.FromCompressedG1(m.P.Wz0)
	bls.CopyG1(&piDec.Wz0, wz0Raw)

	piDec.Cvcom = append([]byte{}, m.P.Cvcom...)

	piDec.PiVcom.Path = make([][]byte, len(m.P.PiVcom.Path))
	piDec.PiVcom.Indicator = make([]int64, len(m.P.PiVcom.Indicator))
	for i := 0; i < len(m.P.PiVcom.Path); i++ {
		piDec.PiVcom.Path[i] = append([]byte{}, m.P.PiVcom.Path[i]...)
		piDec.PiVcom.Indicator[i] = m.P.PiVcom.Indicator[i]
	}

	CdkRaw, _ := bls.FromCompressedG1(m.P.PiRec.Cdk)
	bls.CopyG1(&piDec.PiRec.Cdk, CdkRaw)

	wdkiRaw, _ := bls.FromCompressedG1(m.P.PiRec.Wdki)
	bls.CopyG1(&piDec.PiRec.Wdki, wdkiRaw)

	piDec.PiRec.Crec = make([]bls.G1Point, len(m.P.PiRec.Crec))
	piDec.PiRec.Weval = make([]bls.G1Point, len(m.P.PiRec.Weval))
	for i := 0; i < len(m.P.PiRec.Crec); i++ {
		CrecRaw, _ := bls.FromCompressedG1(m.P.PiRec.Crec[i])
		bls.CopyG1(&piDec.PiRec.Crec[i], CrecRaw)
		wevalRaw, _ := bls.FromCompressedG1(m.P.PiRec.Weval[i])
		bls.CopyG1(&piDec.PiRec.Weval[i], wevalRaw)
	}

	isValid := verifyWpAcssSend(p, vDec, piDec)
	if isValid {
		// mdPartial = g^s||Cvss||Cvcom||Cdk||Crec[0...3]
		mdPartial = append([]byte("||"), m.P.Gs...)
		mdPartial = append(mdPartial, []byte("||")...)
		mdPartial = append(mdPartial, m.P.Cvss...)
		mdPartial = append(mdPartial, m.P.Cvcom...)
		mdPartial = append(mdPartial, m.P.PiRec.Cdk...)
		mdPartial = append(mdPartial, m.P.PiRec.Crec[0]...)
		mdPartial = append(mdPartial, m.P.PiRec.Crec[1]...)
		mdPartial = append(mdPartial, m.P.PiRec.Crec[2]...)
		mdPartial = append(mdPartial, m.P.PiRec.Crec[3]...)
		// fmt.Printf("[wpACSS.Share] [Party %v] decapAndVrfyWpAcssSend: valid message\n", p.PID)
	} else {
		fmt.Printf("[wpACSS.Share] [Party %v] decapAndVrfyWpAcssSend: invalid message\n", p.PID)
		mdPartial = []byte{}
	}

	return vDec, piDec, mdPartial, isValid
}
