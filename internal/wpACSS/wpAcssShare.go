package wpACSS

import (
	"bytes"
	"context"
	"errors"
	"log"

	kyberbls "github.com/drand/kyber-bls12381"
	blsSig "github.com/drand/kyber/sign/bls"

	"google.golang.org/protobuf/proto"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"github.com/opDPSSTeam/DPSS/pkg/vectorcommitment"
)

// ShareSend shares the secret to the other parties, and returns a message md and a signature on md
// Assuming KZG setup has done, and public parameters are available
func ShareSend(ctx context.Context, p *party.HonestParty, ID []byte, current bool, F uint32, N uint32, secret bls.Fr) ([]byte, []byte) {

	//shares[0]=s, the other n elements are secret shares
	PCvss, shares, witnesses, polyF := vss.VssShare(p, F, N, secret)

	//Gs=g^s
	var Gs bls.G1Point
	bls.MulG1(&Gs, &bls.GenG1, &secret)

	// Z(x) = F(x) - s
	polyZ := make([]bls.Fr, F+1)
	copy(polyZ, polyF)
	bls.CopyFr(&polyZ[0], &bls.ZERO)

	p.MutexKZG.Lock()
	PCz := p.KZG.CommitToPoly(polyZ)                  //commit to polyZ
	wz0 := *p.KZG.ComputeProofSingle(polyZ, bls.ZERO) //witness to Z(0)
	p.MutexKZG.Unlock()

	//generate recovery polynomials, polyPhi includes ell=4 polynomials
	dskShare, polyPhi, proofRec := genRecPoly(p, F, N)

	//generate vs and commit to it
	vs := make([]bls.G1Point, N)
	for i := uint32(0); i < N; i++ {
		bls.MulG1(&vs[i], &bls.GenG1, &shares[i+1])
	}

	vsBytes := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		vsBytes[i] = bls.ToCompressedG1(&vs[i])
	}
	tre, _ := vectorcommitment.NewMerkleTree(vsBytes)
	VCvs := tre.GetMerkleTreeRoot()

	var tmpV *party.VShare
	var tmpP *party.PiShare
	var data, mdPartial []byte
	var FLGmdEncoded = false
	for i := uint32(0); i < N; i++ {
		piVs := tre.GetMerkleTreeProofPi(i)

		var PolyEval = make([]bls.Fr, 4)
		var tmpPos bls.Fr
		bls.AsFr(&tmpPos, uint64(i+1))
		for j := 0; j < 4; j++ {
			bls.EvalPolyAt(&PolyEval[j], polyPhi[j], &tmpPos)
		}

		tmpV = party.NewVShare(shares[i+1], dskShare[i], PolyEval)
		tmpP = party.NewPiShare(Gs, *PCvss, witnesses[i+1], *PCz, wz0, VCvs, piVs, proofRec[i])
		if i == 0 { //only encode mdPartial once
			data, mdPartial = encapsulateWpAcssSend(tmpV, tmpP, FLGmdEncoded)
			FLGmdEncoded = true
		} else {
			data, _ = encapsulateWpAcssSend(tmpV, tmpP, FLGmdEncoded)
		}
		sendShareMsg := protobuf.Message{
			Type:   "wpAcssShare",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}
		if current {
			p.Send(&sendShareMsg, uint32(i)) //send to party i
			// 	log.Printf("[DPSS wpACSS] [Old Party %v] send wpAcssShare to [New Party %v] done\n", p.PID, i)
		} else {
			p.SendToNextCommittee(&sendShareMsg, uint32(i)) //send to party i
			// 	log.Printf("[DPSS wpACSS] [Old Party %v] send wpAcssShare to [New Party %v] done\n", p.PID, i)
		}
	}
	log.Printf("[DPSS wpACSS] [Old Party %v] send wpAcssShare done\n", p.PID)

	//this block is to verify the correctness of Encapsulate and Decapsulate messages
	/*
		var wpAcssMsg protobuf.WpAcssShare
		err := proto.Unmarshal(data, &wpAcssMsg)
		if err != nil {
			log.Printf("[wpACSS.Share] Client send wpAcssShare error: %v\n", err)
		}

		vDec, pDec := DecapsulateWpAcssSend(&wpAcssMsg)
		log.Println("=======tmpV=======")
		printVShare(tmpV)
		log.Println("=======vDec=======")
		printVShare(vDec)

		log.Println("=======tmpP=======")
		printPiShare(tmpP)
		log.Println("=======pDec=======")
		printPiShare(pDec) */

	sigs1 := [][]byte{}
	sigs2 := [][]byte{}
	md := append([]byte{}, ID...)
	md = append(md, utils.Uint32ToBytes(p.PID)...)
	md = append(md, mdPartial...)
	mReady := append([]byte("ready"), md...)
	mFinish := append([]byte("finish"), md...)
	multicastDone := false

	for {
		select {
		case <-ctx.Done():
			return nil, nil
		case m := <-p.GetMessage("wpAcssEcho", ID):
			var payload protobuf.WpAcssEcho
			err := proto.Unmarshal(m.Data, &payload)
			if err != nil {
				log.Printf("[DPSS wpACSS] [New Party %v] unmarshal wpAcssEcho error: %v\n", p.PID, err)
			} //else {
			// 	log.Printf("[DPSS wpACSS] [New Party %v] receive wpAcssEcho from [Party %v]\n", p.PID, m.Sender)
			// }

			sigs1 = append(sigs1, payload.Sigshare)
			var sigR []byte
			if uint32(len(sigs1)) > 2*p.F && !multicastDone {
				//the verification of sigshare is done at the beginning of Recover()
				//use different SigPK for verification
				if current {
					sigR, _ = p.TblsScheme.Recover(p.SigPK, mReady, sigs1, int(2*p.F+1), int(p.N))
				} else {
					sigR, _ = p.TblsScheme.Recover(p.SigPKNew, mReady, sigs1, int(2*p.F+1), int(p.N))
				}
				msgReady := new(protobuf.WpAcssReady)
				msgReady.Md = md
				msgReady.Sig = sigR
				data, _ := proto.Marshal(msgReady)
				multicastMsgReady := &protobuf.Message{
					Type:   "wpAcssReady",
					Id:     ID,
					Sender: p.PID,
					Data:   data,
				}
				if current {
					p.Broadcast(multicastMsgReady)
				} else {
					p.BroadcastToNextCommittee(multicastMsgReady)
				}
				log.Printf("[DPSS wpACSS] [New Party %v] multicast wpAcssReady done\n", p.PID)
				multicastDone = true
			}
		case m := <-p.GetMessage("wpAcssFinish", ID):
			var payload protobuf.WpAcssFinish
			err := proto.Unmarshal(m.Data, &payload)
			if err != nil {
				log.Printf("[DPSS wpACSS] [New Party %v] unmarshal WpAcssFinish error: %v\n", p.PID, err)
			} //else {
			// 	log.Printf("[DPSS wpACSS] [New Party %v] receive WpAcssFinish from [Party %v]\n", p.PID, m.Sender)
			// }

			sigs2 = append(sigs2, payload.Sigshare)
			// var sigF []byte
			if uint32(len(sigs2)) > 2*p.F {
				if current {
					sigF, _ := p.TblsScheme.Recover(p.SigPK, mFinish, sigs2, int(2*p.F+1), int(p.N))
					log.Printf("[DPSS wpACSS] [New Party %v] wpACSS.Share done\n", p.PID)
					return md, sigF
				} else {
					sigF, _ := p.TblsScheme.Recover(p.SigPKNew, mFinish, sigs2, int(2*p.F+1), int(p.N))
					log.Printf("[DPSS wpACSS] [New Party %v] wpACSS.Share done\n", p.PID)
					return md, sigF
				}
			}

		}
	}
}

//ShareReceive handles the wpAcssShare message from other parties, and returns a value-proof tuple (v, pi)
func ShareReceive(p *party.HonestParty, isNew bool, ID []byte) (party.VShare, party.PiShare, error) {
	m := <-p.GetMessage("wpAcssShare", ID)

	var wpAcssMsg protobuf.WpAcssShare
	err := proto.Unmarshal(m.Data, &wpAcssMsg)
	if err != nil {
		log.Printf("[DPSS wpACSS] [New Party %v] receive wpAcssShare error: %v\n", p.PID, err)
	} //else {
	// 	log.Printf("[DPSS wpACSS.Share] [New Party %v] receive wpAcssShare from [Old Party %v]\n", p.PID, m.Sender)
	// }

	vDec, pDec, mdPartial, isValid := decapAndVrfyWpAcssSend(p, &wpAcssMsg)
	if !isValid {
		return party.VShare{}, party.PiShare{}, errors.New("invalid wpAcssShare")
	}

	senderID := m.Sender
	var md []byte

	// md = ID||d||g^s||PCvss||VCvs||PCdsk||VCdpk||PCphi[0...3]
	//    = ID||d||mdPartial
	md = append(ID, utils.Uint32ToBytes(senderID)...)
	md = append(md, mdPartial...)
	mReady := append([]byte("ready"), md...) //mReady = ready||md
	sigShare, _ := p.TblsScheme.Sign(p.SigSK, mReady)

	var echoMsg = new(protobuf.WpAcssEcho)
	echoMsg.Sigshare = sigShare
	data, _ := proto.Marshal(echoMsg)
	sendEchoMsg := protobuf.Message{
		Type:   "wpAcssEcho",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	}

	if isNew {
		p.SendToOldCommittee(&sendEchoMsg, senderID)
	} else {
		p.Send(&sendEchoMsg, senderID)
	}

	m2 := <-p.GetMessage("wpAcssReady", ID)
	var wpAcssReadyMsg protobuf.WpAcssReady
	proto.Unmarshal(m2.Data, &wpAcssReadyMsg)

	if !bytes.Equal(md, wpAcssReadyMsg.Md) {
		log.Printf("[DPSS wpACSS] [New Party %v] receive wpAcssReady error: md not equal\n", p.PID)
		return party.VShare{}, party.PiShare{}, errors.New("md not equal")
	}

	mdR := append([]byte("ready"), wpAcssReadyMsg.Md...)
	blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
	err = blsScheme.Verify(p.SigPK.Commit(), mdR, wpAcssReadyMsg.Sig)
	if err != nil {
		log.Printf("error: %v\n", err)
		return party.VShare{}, party.PiShare{}, errors.New("verify sigR error")
	}

	mdF := append([]byte("finish"), wpAcssReadyMsg.Md...)
	finishMsg := new(protobuf.WpAcssFinish)
	finishMsg.Sigshare, _ = p.TblsScheme.Sign(p.SigSK, mdF)
	data, _ = proto.Marshal(finishMsg)
	sendFinishMsg := protobuf.Message{
		Type:   "wpAcssFinish",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	}
	if isNew {
		err = p.SendToOldCommittee(&sendFinishMsg, senderID)
		if err != nil {
			log.Printf("[DPSS wpACSS] [New Party %d] send wpAcssFinish error: %v\n", p.PID, err)
		} //else {
		// 	log.Printf("[DPSS wpACSS] [New Party %d] send wpAcssFinish to [Old Party %v] done\n", p.PID, senderID)
		// }
	} else {
		err = p.Send(&sendFinishMsg, senderID)
		if err != nil {
			log.Printf("[DPSS wpACSS] [New Party %d] send wpAcssFinish error: %v\n", p.PID, err)
		} //else {
		// 	log.Printf("[DPSS wpACSS] [New Party %d] send wpAcssFinish to [Old Party %v] done\n", p.PID, senderID)
		// }
	}

	p.SetVPTuples(vDec, pDec, senderID)
	p.DSKi[senderID] = vDec.DskShare
	var tmpDVK bls.G2Point
	bls.MulG2(&tmpDVK, &bls.GenG2, &vDec.DskShare)
	bls.CopyG2(&p.DPKi[senderID], &tmpDVK)

	return *vDec, *pDec, nil
}

func verifyWpAcssSend(p *party.HonestParty, vDec *party.VShare, pDec *party.PiShare) bool {
	var tmpG1 bls.G1Point
	bls.AddG1(&tmpG1, &pDec.Gs, &pDec.PCz)
	if !bls.EqualG1(&pDec.PCvss, &tmpG1) {
		log.Printf("[DPSS wpACSS] [New Party %v] verifyWpAcssSend failed: PCvss != Gs*PCz\n", p.PID)
		return false
	}
	p.MutexKZG.Lock()
	if !p.KZG.CheckProofSingle(&pDec.PCz, &pDec.Wz0, &bls.ZERO, &bls.ZERO) {
		log.Printf("[DPSS wpACSS] [New Party %v] verifyWpAcssSend: verify wz0 failed\n", p.PID)
		p.MutexKZG.Unlock()
		return false
	}
	p.MutexKZG.Unlock()

	var Gsi bls.G1Point
	bls.MulG1(&Gsi, &bls.GenG1, &vDec.S)
	if !vectorcommitment.VerifyMerkleTreeProof(pDec.VCvs, pDec.PiVs.Path, pDec.PiVs.Indicator, bls.ToCompressedG1(&Gsi)) {
		log.Printf("[DPSS wpACSS] [New Party %v] verifyWpAcssSend: verify piVs failed\n", p.PID)
		return false
	}

	var index bls.Fr
	bls.AsFr(&index, uint64(p.PID+1))
	p.MutexKZG.Lock()
	if !p.KZG.CheckProofSingle(&pDec.PCvss, &pDec.Wvssi, &index, &vDec.S) {
		log.Printf("[DPSS wpACSS] [New Party %v] verifyWpAcssSend: verify si failed\n", p.PID)
		p.MutexKZG.Unlock()
		return false
	}
	p.MutexKZG.Unlock()

	if !dprf.VrfyKey(p, index, vDec.DskShare, pDec.PrfRec.Dpki, pDec.PrfRec.PCdsk, pDec.PrfRec.VCdpk, pDec.PrfRec.Wdski, pDec.PrfRec.PiDpki) {
		log.Printf("[DPSS wpACSS] [New Party %v] verifyWpAcssSend: verify dskShare failed\n", p.PID)
		return false
	}

	for i := 0; i < 4; i++ {
		var pos bls.Fr
		bls.AsFr(&pos, uint64(p.PID+1))
		p.MutexKZG.Lock()
		if !p.KZG.CheckProofSingle(&pDec.PrfRec.PCphi[i], &pDec.PrfRec.Wphi[i], &pos, &vDec.RecPolyEval[i]) {
			p.MutexKZG.Unlock()
			log.Printf("[DPSS wpACSS] [New Party %v] verifyWpAcssSend failed: poly commitment to Phi_%v(%v) fail\n", p.PID, i, p.PID+1)
			return false
		}
		p.MutexKZG.Unlock()
	}

	return true
}

func genRecPoly(p *party.HonestParty, f uint32, n uint32) ([]bls.Fr, [][]bls.Fr, []party.ProofRec) {
	dsk, _, PCdsk, VCdpk, dskShare, dpkShare, wdsk, piDpk := dprf.InitDPRF(p, f, n)

	y := make([]bls.Fr, n)
	I := make([]bls.Fr, n)

	ell := uint32(4)
	poly := make([][]bls.Fr, ell) //phi_k(x), k = 1, ..., ell
	PCphi := make([]*bls.G1Point, ell)
	wPhi := make([][]bls.G1Point, ell)
	piRec := make([]party.ProofRec, n)
	for i := uint32(0); i < n; i++ {
		piRec[i].PCphi = make([]bls.G1Point, ell)
		piRec[i].Wphi = make([]bls.G1Point, ell)
	}

	for i := uint32(0); i < n; i++ {
		//the input to DPRF.Eval() is 1, ..., n
		//so party i corresponds to input value i+1
		tmp := dprf.Eval(utils.Uint32ToBytes(i+1), *dsk)
		y[i] = *utils.HashG1ToFr(&tmp)
		bls.AsFr(&I[i], uint64(i+1))

		// uncomment to test genRecPoly()
		// log.Printf("y[%d] = %s\n", i, y[i].String())
	}

	for i := uint32(0); i < ell; i++ {
		wPhi[i] = make([]bls.G1Point, n)
		if (i+1)*f < n {
			poly[i] = vss.MakeSecret(p, f, n, I[i*f:(i+1)*f], y[i*f:(i+1)*f])
		} else {
			poly[i] = vss.MakeSecret(p, f, n, I[i*f:], y[i*f:])
		}

		p.MutexKZG.Lock()
		PCphi[i] = p.KZG.CommitToPoly(poly[i])
		for j := uint32(0); j < n; j++ {
			wPhi[i][j] = *p.KZG.ComputeProofSingle(poly[i], I[j])
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
	   			log.Printf("poly[%d](%d) = %s\n", i, i*f+j+1, tmpEval.String())
	   		}
	   	} */

	for i := uint32(0); i < n; i++ {
		bls.CopyG2(&piRec[i].Dpki, &dpkShare[i])
		bls.CopyG1(&piRec[i].PCdsk, PCdsk)
		piRec[i].VCdpk = VCdpk
		bls.CopyG1(&piRec[i].Wdski, &wdsk[i])
		piRec[i].PiDpki = piDpk[i]
		for k := uint32(0); k < ell; k++ {
			bls.CopyG1(&piRec[i].PCphi[k], PCphi[k])
			bls.CopyG1(&piRec[i].Wphi[k], &wPhi[k][i])
		}
	}
	return dskShare, poly, piRec
}

func encapsulateWpAcssSend(v *party.VShare, pi *party.PiShare, FLGmdEncoded bool) ([]byte, []byte) {
	var msg = new(protobuf.WpAcssShare)
	msg.V = new(protobuf.VInShare)
	msg.P = new(protobuf.PiInShare)

	msg.V.S = v.S.String()
	msg.V.DskShare = v.DskShare.String()
	msg.V.RecPolyEval = make([]string, len(v.RecPolyEval))
	for i := 0; i < len(v.RecPolyEval); i++ {
		msg.V.RecPolyEval[i] = v.RecPolyEval[i].String()
	}

	msg.P.Gs = bls.ToCompressedG1(&pi.Gs)
	msg.P.PCvss = bls.ToCompressedG1(&pi.PCvss)
	msg.P.Wvssi = bls.ToCompressedG1(&pi.Wvssi)
	msg.P.PCz = bls.ToCompressedG1(&pi.PCz)
	msg.P.Wz0 = bls.ToCompressedG1(&pi.Wz0)
	msg.P.VCvs = append([]byte{}, pi.VCvs...)

	msg.P.PiVs = new(protobuf.PiVcomMerkle)
	for i := 0; i < len(pi.PiVs.Indicator); i++ {
		msg.P.PiVs.Indicator = append(msg.P.PiVs.Indicator, pi.PiVs.Indicator[i])
		msg.P.PiVs.Path = append(msg.P.PiVs.Path, pi.PiVs.Path[i])
	}

	msg.P.ProofRec = new(protobuf.ProofRec)
	msg.P.ProofRec.Dpki = bls.ToCompressedG2(&pi.PrfRec.Dpki)
	msg.P.ProofRec.PCdsk = bls.ToCompressedG1(&pi.PrfRec.PCdsk)
	msg.P.ProofRec.VCdpk = pi.PrfRec.VCdpk
	msg.P.ProofRec.Wdski = bls.ToCompressedG1(&pi.PrfRec.Wdski)
	msg.P.ProofRec.PiDpki = new(protobuf.PiVcomMerkle)
	for i := 0; i < len(pi.PrfRec.PiDpki.Indicator); i++ {
		msg.P.ProofRec.PiDpki.Indicator = append(msg.P.ProofRec.PiDpki.Indicator, pi.PrfRec.PiDpki.Indicator[i])
		msg.P.ProofRec.PiDpki.Path = append(msg.P.ProofRec.PiDpki.Path, pi.PrfRec.PiDpki.Path[i])
	}
	msg.P.ProofRec.PCphi = make([][]byte, len(pi.PrfRec.PCphi))
	msg.P.ProofRec.Wphi = make([][]byte, len(pi.PrfRec.Wphi))
	for i := 0; i < len(pi.PrfRec.PCphi); i++ {
		msg.P.ProofRec.PCphi[i] = bls.ToCompressedG1(&pi.PrfRec.PCphi[i])
		msg.P.ProofRec.Wphi[i] = bls.ToCompressedG1(&pi.PrfRec.Wphi[i])
	}
	var mdPartial []byte
	if !FLGmdEncoded {
		// mdPartial = g^s||PCvss||VCvs||PCdsk||VCdpk||PCphi[0...3]
		mdPartial = append([]byte("||"), msg.P.Gs...) //we will add two prefix (d and ID) before mdPartial later, so we set || before Gs
		mdPartial = append(mdPartial, []byte("||")...)
		mdPartial = append(mdPartial, msg.P.PCvss...)
		mdPartial = append(mdPartial, msg.P.VCvs...)
		mdPartial = append(mdPartial, msg.P.ProofRec.PCdsk...)
		mdPartial = append(mdPartial, msg.P.ProofRec.VCdpk...)
		mdPartial = append(mdPartial, msg.P.ProofRec.PCphi[0]...)
		mdPartial = append(mdPartial, msg.P.ProofRec.PCphi[1]...)
		mdPartial = append(mdPartial, msg.P.ProofRec.PCphi[2]...)
		mdPartial = append(mdPartial, msg.P.ProofRec.PCphi[3]...)
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
	bls.SetFr(sRaw, m.V.S)
	bls.CopyFr(&vDec.S, sRaw)

	dskShareRaw := new(bls.Fr)
	bls.SetFr(dskShareRaw, m.V.DskShare)
	bls.CopyFr(&vDec.DskShare, dskShareRaw)

	vDec.RecPolyEval = make([]bls.Fr, 4) //ell=4
	for i := 0; i < 4; i++ {
		recPolyEvalRaw := new(bls.Fr)
		bls.SetFr(recPolyEvalRaw, m.V.RecPolyEval[i])
		bls.CopyFr(&vDec.RecPolyEval[i], recPolyEvalRaw)
	}

	//decapsulate pi
	piDec := new(party.PiShare)
	GsRaw, _ := bls.FromCompressedG1(m.P.Gs)
	bls.CopyG1(&piDec.Gs, GsRaw)

	PCvssRaw, _ := bls.FromCompressedG1(m.P.PCvss)
	bls.CopyG1(&piDec.PCvss, PCvssRaw)

	wvssiRaw, _ := bls.FromCompressedG1(m.P.Wvssi)
	bls.CopyG1(&piDec.Wvssi, wvssiRaw)

	PCzRaw, _ := bls.FromCompressedG1(m.P.PCz)
	bls.CopyG1(&piDec.PCz, PCzRaw)

	wz0Raw, _ := bls.FromCompressedG1(m.P.Wz0)
	bls.CopyG1(&piDec.Wz0, wz0Raw)

	piDec.VCvs = m.P.VCvs

	piDec.PiVs.Path = make([][]byte, len(m.P.PiVs.Path))
	piDec.PiVs.Indicator = make([]int64, len(m.P.PiVs.Indicator))
	for i := 0; i < len(m.P.PiVs.Path); i++ {
		piDec.PiVs.Path[i] = m.P.PiVs.Path[i]
		piDec.PiVs.Indicator[i] = m.P.PiVs.Indicator[i]
	}

	DpkiRaw, _ := bls.FromCompressedG2(m.P.ProofRec.Dpki)
	bls.CopyG2(&piDec.PrfRec.Dpki, DpkiRaw)

	PCdskRaw, _ := bls.FromCompressedG1(m.P.ProofRec.PCdsk)
	bls.CopyG1(&piDec.PrfRec.PCdsk, PCdskRaw)

	piDec.PrfRec.VCdpk = m.P.ProofRec.VCdpk

	wdskiRaw, _ := bls.FromCompressedG1(m.P.ProofRec.Wdski)
	bls.CopyG1(&piDec.PrfRec.Wdski, wdskiRaw)

	piDec.PrfRec.PiDpki.Indicator = make([]int64, len(m.P.ProofRec.PiDpki.Indicator))
	piDec.PrfRec.PiDpki.Path = make([][]byte, len(m.P.ProofRec.PiDpki.Path))
	for i := 0; i < len(m.P.ProofRec.PiDpki.Indicator); i++ {
		piDec.PrfRec.PiDpki.Indicator[i] = m.P.ProofRec.PiDpki.Indicator[i]
		piDec.PrfRec.PiDpki.Path[i] = m.P.ProofRec.PiDpki.Path[i]
	}

	piDec.PrfRec.PCphi = make([]bls.G1Point, len(m.P.ProofRec.PCphi))
	piDec.PrfRec.Wphi = make([]bls.G1Point, len(m.P.ProofRec.Wphi))
	for i := 0; i < len(m.P.ProofRec.PCphi); i++ {
		PCphiRaw, _ := bls.FromCompressedG1(m.P.ProofRec.PCphi[i])
		bls.CopyG1(&piDec.PrfRec.PCphi[i], PCphiRaw)
		wPhiRaw, _ := bls.FromCompressedG1(m.P.ProofRec.Wphi[i])
		bls.CopyG1(&piDec.PrfRec.Wphi[i], wPhiRaw)
	}

	isValid := verifyWpAcssSend(p, vDec, piDec)
	if isValid {
		// mdPartial = g^s||PCvss||VCvs||PCdsk||VCdpk||PCphi[0...3]
		mdPartial = append([]byte("||"), m.P.Gs...)
		mdPartial = append(mdPartial, []byte("||")...)
		mdPartial = append(mdPartial, m.P.PCvss...)
		mdPartial = append(mdPartial, m.P.VCvs...)
		mdPartial = append(mdPartial, m.P.ProofRec.PCdsk...)
		mdPartial = append(mdPartial, m.P.ProofRec.VCdpk...)
		mdPartial = append(mdPartial, m.P.ProofRec.PCphi[0]...)
		mdPartial = append(mdPartial, m.P.ProofRec.PCphi[1]...)
		mdPartial = append(mdPartial, m.P.ProofRec.PCphi[2]...)
		mdPartial = append(mdPartial, m.P.ProofRec.PCphi[3]...)
		// log.Printf("[wpACSS.Share] [Party %v] decapAndVrfyWpAcssSend: valid message\n", p.PID)
	} else {
		log.Printf("[DPSS wpACSS] [New Party %v] decapAndVrfyWpAcssSend: invalid message\n", p.PID)
		mdPartial = []byte{}
	}

	return vDec, piDec, mdPartial, isValid
}
