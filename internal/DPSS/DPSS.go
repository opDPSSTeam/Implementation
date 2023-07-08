package dpss

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"time"

	kyberbls "github.com/drand/kyber-bls12381"
	blsSig "github.com/drand/kyber/sign/bls"
	kbls "github.com/kilic/bls12-381"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/mvba"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
	"github.com/opDPSSTeam/DPSS/internal/wpACSS"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"google.golang.org/protobuf/proto"
)

//DpssOld is the old party's procedures in DPSS
func DpssOld(ctx context.Context, p *party.HonestParty, ID []byte, F uint32, N uint32) {

	p.DpssOldStart = time.Now()

	vOldFr := make([]kbls.Fr, N)
	for i := uint32(0); i < N; i++ {
		vOldFr[i] = *utils.HashG1ToFr(&p.VCom[i])
	}

	VCold := p.VC.Commit(vOldFr)
	piOld := p.VC.Open(vOldFr, int(p.PID))

	data := encapsulateComMsg(VCold, &p.VCom[p.PID], piOld)
	err := p.BroadcastToNextCommittee(&protobuf.Message{
		Type:   "DpssCom",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	if err != nil {
		log.Printf("[DPSS Commit] [Old Party %v] multicast DpssCom error: %v\n", p.PID, err)
	}
	log.Printf("[DPSS Commit] [Old Party %v] multicast DpssCom done\n", p.PID)

	md, sig := wpACSS.ShareSend(ctx, p, ID, false, F, N, p.Share)

	//the following block is for testing
	/* 	blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
	   	err = blsScheme.Verify(p.SigPKNew.Commit(), md, sig)
	   	if err != nil {
	   		log.Printf("[DPSS.Commit] [Old Party %v] verify DpssProof error: %v\n", p.PID, err)
	   	} else {
	   		log.Printf("[DPSS.Commit] [Old Party %v] has generated a valid DpssProof\n", p.PID)
	   	} */

	data = encapsulateProofMsg(md, sig)
	err = p.BroadcastToNextCommittee(&protobuf.Message{
		Type:   "DpssProof",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	if err != nil {
		log.Printf("[DPSS Reshare] [Old Party %v] send DpssProof error: %v\n", p.PID, err)
	}
	log.Printf("[DPSS Reshare] [Old Party %v] multicast DpssProof done\n", p.PID)

	p.DpssOldEnd = time.Now()
}

//DpssNew is the new party's procedures in DPSS
func DpssNew(ctx context.Context, p *party.HonestParty, ID []byte, F uint32, N uint32) bls.Fr {

	p.DpssNewStart = time.Now()

	//start wpACSS instances to receive shares from old parties
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			wpACSS.ShareReceive(p, true, ID, i)
		}(i)
	}

	vOld := make([]bls.G1Point, N)
	vg := make([]bls.G1Point, F+1)
	index := make([]bls.Fr, F+1)
	ctr := uint32(0)
	getVOldChan := make(chan bool, 1)
	ifGetVOld := false
	isInterpolated := false

	//wait for commitment pieces from old parties
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("DpssCom", ID):
				if !isInterpolated {
					var DpssComMsg protobuf.DpssCom
					err := proto.Unmarshal(m.Data, &DpssComMsg)
					if err != nil {
						log.Printf("[DPSS Commit] [New Party %v] receive DpssCom error: %v\n", p.PID, err)
					} //else {
					// 	log.Printf("[DPSS Commit] [New Party %v] receive DpssCom from [Old Party %v]\n", p.PID, m.Sender)
					// }

					Gsi, _ := bls.FromCompressedG1(DpssComMsg.Gsi)
					GsiFr := utils.HashG1ToFr(Gsi)
					if !p.VC.Verify(DpssComMsg.VCold, *GsiFr, int(m.Sender), DpssComMsg.PiOld) {
						log.Printf("[DPSS Commit] [New Party %v] verify DpssCom from [Old Party %v] error: invalid commitment or value\n", p.PID, m.Sender)
						continue //wait for the next commitment
					}

					bls.CopyG1(&vg[ctr], Gsi)
					bls.AsFr(&index[ctr], uint64(m.Sender+1))
					ctr++
					if ctr > F {
						for i := uint32(0); i < N; i++ {
							vOld[i] = p.InterpolateComOrWitByKnownIndexes(F, i+1, index, vg)
						}
						p.SetVCom(vOld)
						Gs := p.InterpolateComOrWitByKnownIndexes(F, 0, index, vg)
						p.SetGs(&Gs)
						log.Printf("[DPSS Commit] [New Party %v] interpolate the commitments to all old shares done\n", p.PID)
						getVOldChan <- true
						isInterpolated = true
					}
				}
			}
		}
	}()

	MVBAsent := false
	var MvbaInMsg = new(protobuf.MvbaIn)
	MvbaInMsg.Tuple = make([]*protobuf.MvbaTuple, F+1)
	for i := uint32(0); i < F+1; i++ {
		MvbaInMsg.Tuple[i] = new(protobuf.MvbaTuple)
	}
	MVBAResChan := make(chan []byte, 1)

	//call MVBA
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("DpssProof", ID):
				//ignore DpssProof if p has called MVBA (there are sufficient proofs)
				if !MVBAsent {
					var DpssProofMsg protobuf.DpssProof
					err := proto.Unmarshal(m.Data, &DpssProofMsg)
					if err != nil {
						log.Printf("[DPSS Reshare] [New Party %v] receive DpssProof error: %v\n", p.PID, err)
					}

					mFinish := append([]byte("finish"), DpssProofMsg.M...)
					blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
					err = blsScheme.Verify(p.SigPK.Commit(), mFinish, DpssProofMsg.Sig)
					if err != nil {
						log.Printf("[DPSS Reshare] [New Party %v] verify DpssProof from [Old Party %v] error: invalid signature\n", p.PID, m.Sender)
						continue //wait for the next proof
					}

					Gsi := parseGsi(DpssProofMsg.M)
					//wait for the interpolation of all old shares' commitments
					if !ifGetVOld {
						ifGetVOld = <-getVOldChan
					}
					if !bls.EqualG1(Gsi, &p.VCom[m.Sender]) {
						log.Printf("[DPSS Verify] [New Party %v] verify DpssProof from [Old Party %v] error: Gsi != VCom[%v], Gsi = %s, VCom[%v] = %s\n", p.PID, m.Sender, m.Sender, Gsi.String(), m.Sender, p.VCom[m.Sender].String())
						continue //wait for the next proof
					}

					// log.Printf("[DPSS Verify] [New Party %v] receive valid DpssProof from [Old Party %v]\n", p.PID, m.Sender)

					proofCtr := p.SetMsgSigTuples(DpssProofMsg.M, DpssProofMsg.Sig, m.Sender)
					if uint32(proofCtr) <= F+1 {
						MvbaInMsg.Tuple[proofCtr-1].Index = m.Sender
						MvbaInMsg.Tuple[proofCtr-1].Md, MvbaInMsg.Tuple[proofCtr-1].Sig = p.GetMsgSigTuple(m.Sender)
					}

					//MVBA
					if uint32(proofCtr) >= F+1 {
						log.Printf("[DPSS MVBA] [New Party %v] call MVBA\n", p.PID)
						data, _ := proto.Marshal(MvbaInMsg)
						MVBAsent = true
						MVBAResChan <- mvba.MainProcess(p, ID, data, nil, Pmvba) //in our use case, the signatures are included in data, so we set validation as nil here
					}
				}
			}
		}
	}()

	//recover
	res := <-MVBAResChan
	var MvbaRes = new(protobuf.MvbaIn)
	err := proto.Unmarshal(res, MvbaRes)
	if err != nil {
		log.Printf("[DPSS MVBA] [New Party %v] parse MVBA output error: %v\n", p.PID, err)
	}
	I := make([]uint32, len(MvbaRes.Tuple))
	Shelp := make([]uint32, 0)
	for i := 0; i < len(MvbaRes.Tuple); i++ {
		I[i] = MvbaRes.Tuple[i].Index

		/* You may set Shelp=I to test wpACSS.Recover.
		To achieve this, you may remove the "!" before p.IfReceivedVPiTuples */
		if !p.IfReceivedVPiTuples(I[i]) {
			Shelp = append(Shelp, I[i])
		}

		/* The following lines are used to test pessimistic path in GenNewCom, in the case of N=7, F=2.
		To use these lines, you should also let GenNewCom enter pessimistic path, by adding a "!" operation before bls.EqualG1 (around line 356) */
		// if p.PID == 0 || p.PID == 1 {
		// 	Shelp = []uint32{I[0]}
		// }
		// if p.PID == 2 || p.PID == 3 {
		// 	Shelp = []uint32{I[1]}
		// }
	}
	log.Printf("[DPSS MVBA] [New Party %v] MVBA output: %v\n", p.PID, I)

	var recoverResChan = make(chan map[uint32]bls.Fr, 1)
	var SrecMap = make(map[uint32]bls.Fr) //maps dealerID to the recovered s_{d,i}

	go func() {
		if len(Shelp) > 0 {
			wpACSS.CallHelp(p, ID, Shelp)
			recoverResChan <- wpACSS.WaitHelp(p, ID, F, N, Shelp) //wait for others' help
		} else {
			log.Printf("[DPSS Recover] [New Party %v] no help needed\n", p.PID)
		}
	}()

	go wpACSS.Help(p, ID, F) //answer others' help

	if len(Shelp) > 0 {
		SrecMap = <-recoverResChan //wait for the recovery result
	}

	//refresh
	iRefresh := make([]bls.Fr, F+1)
	vRefresh := make([]bls.Fr, F+1)
	for i, j := range I {
		bls.AsFr(&iRefresh[i], uint64(j+1))
		if _, ok := SrecMap[j]; ok {
			vRefresh[i] = SrecMap[j]
		} else {
			vRefresh[i] = p.GetVShare(j).S
		}
	}
	refreshedPoly := polyring.LagrangeInterpolate(F, iRefresh, vRefresh)
	newShare := refreshedPoly[0]
	log.Printf("[DPSS Recover] [New Party %v] refresh done\n", p.PID)

	GenNewCom(p, ID, F, N, newShare, Shelp, I)
	p.DpssNewEnd = time.Now()
	return newShare
}

func Pmvba(p *party.HonestParty, ID []byte, value []byte, validation []byte) error {
	var MvbaMsg = new(protobuf.MvbaIn)
	err := proto.Unmarshal(value, MvbaMsg)
	if err != nil {
		log.Printf("[DPSS MVBA] [New Party %v] parse MvbaIn error: %v\n", p.PID, err)
		return err
	}

	blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
	for i := 0; i < len(MvbaMsg.Tuple); i++ {
		mF := append([]byte("finish"), MvbaMsg.Tuple[i].Md...)
		err := blsScheme.Verify(p.SigPK.Commit(), mF, MvbaMsg.Tuple[i].Sig)
		if err != nil {
			log.Printf("[DPSS MVBA] [New Party %v] invalid signature: %v\n", p.PID, err)
			return fmt.Errorf("[DPSS MVBA] [New Party %v] invalid signature: %v", p.PID, err)
		}
		Gsi := parseGsi(MvbaMsg.Tuple[i].Md)
		if !bls.EqualG1(Gsi, &p.VCom[MvbaMsg.Tuple[i].Index]) {
			log.Printf("[DPSS MVBA] [New Party %v] invalid Gsi\n", p.PID)
			return fmt.Errorf("[DPSS MVBA] [New Party %v] invalid Gsi", p.PID)
		}
	}
	return nil
}

func encapsulateComMsg(VCold string, Gsi *bls.G1Point, piOld string) []byte {
	var msg = new(protobuf.DpssCom)
	msg.VCold = VCold
	msg.Gsi = bls.ToCompressedG1(Gsi)
	msg.PiOld = piOld
	data, _ := proto.Marshal(msg)
	return data
}

func encapsulateProofMsg(md []byte, sig []byte) []byte {
	var msg = new(protobuf.DpssProof)
	msg.M = md
	msg.Sig = sig
	data, _ := proto.Marshal(msg)
	return data
}

func parseGsi(m []byte) *bls.G1Point {
	splited := bytes.Split(m, []byte("||"))
	Gsi, _ := bls.FromCompressedG1(splited[1])
	return Gsi
}

func GenNewCom(p *party.HonestParty, ID []byte, F uint32, N uint32, newShare bls.Fr, Shelp []uint32, MVBAOutput []uint32) {
	endSignal := make(chan bool, 1)
	var Gsi bls.G1Point
	bls.MulG1(&Gsi, &bls.GenG1, &newShare)
	var msgNewCom = new(protobuf.NewCom)
	msgNewCom.Gsi = bls.ToCompressedG1(&Gsi)
	data, err := proto.Marshal(msgNewCom)
	if err != nil {
		log.Printf("[DPSS GenNewCom] [New Party %v] marshal NewCom error: %v\n", p.PID, err)
		return
	}
	err = p.Broadcast(&protobuf.Message{
		Type:   "NewCom",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	if err != nil {
		log.Printf("[DPSS GenNewCom] [New Party %v] broadcast NewCom error: %v\n", p.PID, err)
		return
	}
	log.Printf("[DPSS GenNewCom] [New Party %v] broadcast NewCom\n", p.PID)

	//wait to help others
	go func() {
		AuxLen := len(MVBAOutput) - len(Shelp)
		var AuxMsg = new(protobuf.Aux)
		if AuxLen > 0 {
			Ii := substractSet(MVBAOutput, Shelp)
			AuxMsg.Cont = make([]*protobuf.AuxCont, AuxLen)
			var tmpGs bls.G1Point
			for index, k := range Ii {
				AuxMsg.Cont[index] = new(protobuf.AuxCont)
				AuxMsg.Cont[index].K = k
				bls.MulG1(&tmpGs, &bls.GenG1, &p.GetVShare(k).S)
				AuxMsg.Cont[index].Gs = bls.ToCompressedG1(&tmpGs)
				AuxMsg.Cont[index].VCvs = p.GetPiShare(k).VCvs
				AuxMsg.Cont[index].PiVs = p.GetPiShare(k).PiVs
			}
		}

		for {
			m := <-p.GetMessage("DpssErr", ID)
			// AuxLen == 0 means it cannot help others
			if AuxLen > 0 {
				data, err = proto.Marshal(AuxMsg)
				if err != nil {
					log.Printf("[DPSS GenNewCom] [New Party %v] marshal Aux error: %v\n", p.PID, err)
					return
				}
				err = p.Send(&protobuf.Message{
					Type:   "Aux",
					Id:     ID,
					Sender: p.PID,
					Data:   data,
				}, m.Sender)
			}
		}
	}()

	var newComCtr = uint32(0)
	newComList := make([]bls.G1Point, F+1)
	newComIndex := make([]bls.Fr, F+1)

	for newComCtr < F+1 {
		m := <-p.GetMessage("NewCom", ID)
		var msg = new(protobuf.NewCom)
		err := proto.Unmarshal(m.Data, msg)
		if err != nil {
			log.Printf("[DPSS GenNewCom] [New Party %v] parse NewCom error: %v\n", p.PID, err)
			continue
		}
		Gsi, _ := bls.FromCompressedG1(msg.Gsi)
		bls.CopyG1(&newComList[newComCtr], Gsi)
		bls.AsFr(&newComIndex[newComCtr], uint64(m.Sender+1))
		newComCtr++
	}

	newGs := p.InterpolateComOrWitByKnownIndexes(F, 0, newComIndex, newComList)
	//you may add a "!" operation before bls.EqualG1 to test the pessmistic path
	if bls.EqualG1(&newGs, &p.Gs) {
		log.Printf("[DPSS GenNewCom] [New Party %v] enter the optimistic path\n", p.PID)
		vNew := make([]bls.G1Point, N)
		for i := uint32(0); i < N; i++ {
			vNew[i] = p.InterpolateComOrWitByKnownIndexes(F, i+1, newComIndex, newComList)
		}
		log.Printf("[DPSS GenNewCom] [New Party %v] interpolate the commitments to all new shares (optimistic path)\n", p.PID)
		p.SetVCom(vNew)
		endSignal <- true
	} else {
		log.Printf("[DPSS GenNewCom] [New Party %v] enter the pessimistic path\n", p.PID)

		//multicast ERROR
		var msgError = new(protobuf.Err)
		msgError.Err = []byte("e")
		data, err = proto.Marshal(msgError)
		if err != nil {
			log.Printf("[DPSS GenNewCom] [New Party %v] marshal Err error: %v\n", p.PID, err)
			return
		}
		err = p.Broadcast(&protobuf.Message{
			Type:   "DpssErr",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		})
		if err != nil {
			log.Printf("[DPSS GenNewCom] [New Party %v] broadcast DpssErr error: %v\n", p.PID, err)
			return
		}
		log.Printf("[DPSS GenNewCom] [New Party %v] broadcast DpssErr\n", p.PID)

		//wait for Aux messages. Pj is the sender, who sends the commitments to s_k,j
		kGsMap := make(map[uint32][]bls.G1Point) //maps the sender of Aux message to the Gs elements in it
		newGsMap := make(map[uint32]bls.G1Point) //records the interpolated new Gs
		newGsCtr := uint32(0)
		vNew := make([]bls.G1Point, N)

		jListMap := make(map[uint32][]uint32)    //maps k to received j
		jGsMap := make(map[uint32][]bls.G1Point) //maps k to received Gsj
		jCtrMap := make(map[uint32]uint32)       //maps k to the number of received Gsj
		jMissingMap := make(map[uint32][]uint32) //maps j to the missing k

		for {
			m := <-p.GetMessage("Aux", ID)
			var Auxmsg = new(protobuf.Aux)
			err := proto.Unmarshal(m.Data, Auxmsg)
			if err != nil {
				log.Printf("[DPSS GenNewCom] [New Party %v] parse Aux error: %v\n", p.PID, err)
				continue
			}

			isValid, kList, kGsList := verifyAux(p, Auxmsg)
			if !isValid {
				log.Printf("[DPSS GenNewCom] [New Party %v] receive invalid Aux message from [New Party %v]\n", p.PID, m.Sender)
				continue
			}
			kGsMap[m.Sender] = kGsList

			// if there are sufficient elements in Aux message from Pj (i.e., Pj has no missing shares), interpolate the new Gs
			if uint32(len(kList)) > F {
				var kListFr = make([]bls.Fr, F+1)
				for i := uint32(0); i < F+1; i++ {
					bls.AsFr(&kListFr[i], uint64(kList[i]+1))
				}
				newGsMap[m.Sender] = p.InterpolateComOrWitByKnownIndexes(F, 0, kListFr, kGsList)
				newGsCtr++
			} else {
				// record the missing k
				jMissingMap[m.Sender] = substractSet(MVBAOutput, kList)
			}

			// record the received j and Gs_k,j for each k
			for index, k := range kList {
				if _, ok := jListMap[k]; !ok {
					jListMap[k] = make([]uint32, 0)
					jGsMap[k] = make([]bls.G1Point, 0)
					jCtrMap[k] = 0
				}
				jListMap[k] = append(jListMap[k], m.Sender)
				jGsMap[k] = append(jGsMap[k], kGsList[index])
				jCtrMap[k]++

				//check if there are enough Gs_k,* to interpolate Gs_k,j
				if jCtrMap[k] == F+1 {
					for j, missingList := range jMissingMap {
						if containsUint32(missingList, k) {
							//interpolate at j
							indexList := make([]bls.Fr, F+1)
							GsList := jGsMap[k]
							ctr := 0
							for _, sender := range jListMap[k] {
								if sender != j {
									bls.AsFr(&indexList[ctr], uint64(sender+1))
									ctr++
								}
							}
							newGsMap[j] = p.InterpolateComOrWitByKnownIndexes(F, j+1, indexList, GsList)
							newGsCtr++
						}
					}
				}
			}

			if newGsCtr > F {
				log.Printf("[DPSS GenNewCom] [New Party %v] receive enough new Gs, newGsCtr=%v\n", p.PID, newGsCtr)
				indexList := make([]bls.Fr, N)
				newGsList := make([]bls.G1Point, N)
				ctr := 0
				for i := uint32(0); i < N; i++ {
					if newGs, ok := newGsMap[i]; ok {
						bls.AsFr(&indexList[ctr], uint64(i+1))
						bls.CopyG1(&newGsList[ctr], &newGs)
						ctr++
					}
				}
				for i := uint32(0); i < N; i++ {
					vNew[i] = p.InterpolateComOrWitByKnownIndexes(F, i+1, indexList[:F+1], newGsList[:F+1])
				}
				log.Printf("[DPSS GenNewCom] [New Party %v] interpolate the commitments to all new shares (pessimistic path)\n", p.PID)
				p.SetVCom(vNew)
				endSignal <- true
				break
			}
		}
	}

	//wait for the end signal
	<-endSignal

}

func verifyAux(p *party.HonestParty, AuxMsg *protobuf.Aux) (bool, []uint32, []bls.G1Point) {
	kList := make([]uint32, 0)
	GsList := make([]bls.G1Point, 0)
	for i := 0; i < len(AuxMsg.Cont); i++ {
		Gs, _ := bls.FromCompressedG1(AuxMsg.Cont[i].Gs)
		GsFr := utils.HashG1ToFr(Gs)
		if !p.VC.Verify(AuxMsg.Cont[i].VCvs, *GsFr, i, AuxMsg.Cont[i].PiVs) {
			kList = append(kList, AuxMsg.Cont[i].K)
			tmpGs, _ := bls.FromCompressedG1(AuxMsg.Cont[i].Gs)
			GsList = append(GsList, *tmpGs)
		} else {
			return false, []uint32{0}, []bls.G1Point{}
		}
	}
	return true, kList, GsList
}

func substractSet(a, b []uint32) []uint32 {
	m := make(map[uint32]bool)
	for _, num := range b {
		m[num] = true
	}

	var result []uint32
	for _, num := range a {
		if _, ok := m[num]; !ok {
			result = append(result, num) //this is not optimal if we know the size of result, but the difference is negligible
		}
	}
	return result
}

func containsUint32(list []uint32, num uint32) bool {
	for _, v := range list {
		if v == num {
			return true
		}
	}
	return false
}
