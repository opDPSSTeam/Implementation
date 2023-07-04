package wpACSS

import (
	"log"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"google.golang.org/protobuf/proto"
)

type PiHelp struct {
	Gs     bls.G1Point
	Cdk    bls.G1Point
	Cmask  bls.G1Point
	wiMask bls.G1Point
	piDPRF dprf.ProofDPRF
}

type RecCont struct {
	dealerID     uint32
	helperID     uint32
	sMasked      bls.Fr
	DPRFContribF bls.G1Point
	piHelp       PiHelp
}

func CallHelp(p *party.HonestParty, ID []byte, F uint32, N uint32, Shelp []uint32) {
	lenS := len(Shelp)
	if lenS == 0 {
		return // no need to call help
	}

	var msg protobuf.WpAcssCallHelp
	msg.Caller = p.PID
	msg.Indices = make([]uint32, lenS)
	for i := 0; i < lenS; i++ {
		msg.Indices[i] = Shelp[i]
	}

	msgData, _ := proto.Marshal(&msg)
	err := p.BroadcastExclude(&protobuf.Message{
		Type:   "WpAcssCallHelp",
		Id:     ID,
		Sender: p.PID,
		Data:   msgData,
	}, p.PID) // sendsc CallHelp to all parties except itself
	if err != nil {
		log.Printf("[DPSS Recover] [New Party %v] Error in broadcast: %v\n", p.PID, err)
	} else {
		log.Printf("[DPSS Recover] [New Party %v] calls for help, Shelp: %v\n", p.PID, Shelp)
	}
}

func Help(p *party.HonestParty, ID []byte, F uint32, N uint32) {
	for {
		m := <-p.GetMessage("WpAcssCallHelp", ID)
		callerID := m.Sender
		var msgCallHelp protobuf.WpAcssCallHelp
		err := proto.Unmarshal(m.Data, &msgCallHelp)
		if err != nil {
			log.Printf("[DPSS Recover] [New Part %v] receive wpAcssCallHelp error: %v\n", p.PID, err)
		} else {
			log.Printf("[DPSS Recover] [New Party %v] receive WpAcssCallHelp from [New Party %v]\n", p.PID, msgCallHelp.Caller)
		}

		Shelp := msgCallHelp.Indices

		res := make([]RecCont, len(Shelp))
		var msg = new(protobuf.WpAcssHelp)
		msg.Res = make([]*protobuf.RecCont, len(Shelp))
		var isEmpty bool = true
		for index, dealerID := range Shelp {
			// only generate RecCont if received vpi tuples from dealerID
			if p.IfReceivedVPiTuples(dealerID) {
				isEmpty = false
				v := p.GetVShare(dealerID)
				pi := p.GetPiShare(dealerID)
				res[index] = recContrib(p, ID, F, dealerID, callerID, *v, *pi)

				//encapsulate RecCont
				msg.Res[index] = &protobuf.RecCont{
					DealerID:     dealerID,
					SMasked:      []byte(res[index].sMasked.String()),
					DPRFContribF: bls.ToCompressedG1(&res[index].DPRFContribF),
					PiHelp: &protobuf.PiHelp{
						Gs:     bls.ToCompressedG1(&res[index].piHelp.Gs),
						Cdk:    bls.ToCompressedG1(&res[index].piHelp.Cdk),
						Cmask:  bls.ToCompressedG1(&res[index].piHelp.Cmask),
						WiMask: bls.ToCompressedG1(&res[index].piHelp.wiMask),
						PiDPRF: dprf.EncapsulatePiDPRF(&res[index].piHelp.piDPRF),
					},
				}
			}
		}

		if !isEmpty {
			data, err := proto.Marshal(msg)
			if err != nil {
				log.Printf("[DPSS Recover] [New Party %v] Error in marshal: %v\n", err, p.PID)
			}

			p.Send(&protobuf.Message{
				Type:   "WpAcssHelp",
				Id:     ID,
				Sender: p.PID,
				Data:   data,
			}, callerID)
			log.Printf("[DPSS Recover] [New Party %v] sends WpAcssHelp to [New Party %v]\n", p.PID, callerID)
		}
	}
}

func WaitHelp(p *party.HonestParty, ID []byte, F uint32, N uint32, Shelp []uint32) map[uint32]bls.Fr {
	var CdkCounterMap = make(map[bls.G1Point]int)             //the number of times Cdk appears in the received help messages
	var CdkDealerMap = make(map[bls.G1Point]uint32)           //maps Cdk to the dealerID
	var CdkHelperMap = make(map[bls.G1Point][]uint32)         //records the helpers' indexes for the same Cdk
	var CdkSmaskMap = make(map[bls.G1Point][]bls.Fr)          //records the sMasked for the same Cdk
	var CdkDPRFMap = make(map[bls.G1Point][]bls.G1Point)      //records the DPRFContribF for the same Cdk
	var CdkPiDPRFMap = make(map[bls.G1Point][]dprf.ProofDPRF) //records the ProofDPRF for the same Cdk
	var HelperResMap = make(map[uint32][]RecCont)             //maps helperID to the received RecConts
	var SrecMap = make(map[uint32]bls.Fr)                     //maps dealerID to the recovered s_{d,i}

	var recoveredCtr int = 0

	for {
		m := <-p.GetMessage("WpAcssHelp", ID)
		res, err := decapsulateRes(m, p.PID)
		if err != nil {
			continue
		}
		HelperResMap[m.Sender] = res

		lenRes := len(res)
		var FLGContinue bool = false
		for i := 0; i < lenRes; i++ {
			if !vrfyRecCont(p, ID, F, res[i]) {
				log.Printf("[DPSS Recover] [New Party %v] verify the RecCont (dealerID: %v) from [New Party %v] fail\n", p.PID, res[i].dealerID, m.Sender)
				FLGContinue = true
				continue
			}
			// log.Printf("[DPSS Recover] [New Party %v] verify the RecCont (dealerID: %v) from [New Party %v] success\n", p.PID, res[i].dealerID, m.Sender)
		}
		//skip this message if verification fails
		if FLGContinue {
			continue
		}

		for i := 0; i < lenRes; i++ {
			tmpCdk := res[i].piHelp.Cdk
			_, ok1 := CdkCounterMap[tmpCdk]
			// ok1 denotes the map of Cdk exists
			if ok1 {
				CdkCounterMap[tmpCdk]++
				CdkHelperMap[tmpCdk] = append(CdkHelperMap[tmpCdk], m.Sender)
				CdkSmaskMap[tmpCdk] = append(CdkSmaskMap[tmpCdk], res[i].sMasked)
				CdkDPRFMap[tmpCdk] = append(CdkDPRFMap[tmpCdk], res[i].DPRFContribF)
				CdkPiDPRFMap[tmpCdk] = append(CdkPiDPRFMap[tmpCdk], res[i].piHelp.piDPRF)
			} else {
				CdkCounterMap[tmpCdk] = 1
				CdkHelperMap[tmpCdk] = []uint32{m.Sender}
				CdkSmaskMap[tmpCdk] = []bls.Fr{res[i].sMasked}
				CdkDealerMap[tmpCdk] = res[i].dealerID
				CdkDPRFMap[tmpCdk] = []bls.G1Point{res[i].DPRFContribF}
				CdkPiDPRFMap[tmpCdk] = []dprf.ProofDPRF{res[i].piHelp.piDPRF}
			}
		}

		var IdxList = make([]bls.Fr, F+1)
		var yList = make([]bls.Fr, F+1)
		var ContribList = make([]bls.G1Point, F+1)
		var piDPRFList = make([]*dprf.ProofDPRF, F+1)
		// check if there exists a Cdk that appears more than F+1 times
		for i := 0; i < lenRes; i++ {
			tmpCdk := res[i].piHelp.Cdk
			if CdkCounterMap[tmpCdk] >= int(F+1) {
				dealerID := CdkDealerMap[tmpCdk]
				for j := uint32(0); j < F+1; j++ {
					bls.AsFr(&IdxList[j], uint64(CdkHelperMap[tmpCdk][j]+1))
					bls.CopyFr(&yList[j], &CdkSmaskMap[tmpCdk][j])
					bls.CopyG1(&ContribList[j], &CdkDPRFMap[tmpCdk][j])
					piDPRFList[j] = &CdkPiDPRFMap[tmpCdk][j]
				}
				// recover sMasked at index I
				polyD := polyring.LagrangeInterpolate(F, IdxList, yList)
				var sMaskedDI bls.Fr
				var posI bls.Fr
				bls.AsFr(&posI, uint64(p.PID+1))
				bls.EvalPolyAt(&sMaskedDI, polyD, &posI)
				Fdi, _ := dprf.Combine(p, F, utils.Uint32ToBytes(p.PID+1), IdxList, ContribList, piDPRFList)
				var sdi bls.Fr
				bls.SubModFr(&sdi, &sMaskedDI, &Fdi)
				SrecMap[dealerID] = sdi
				log.Printf("[DPSS Recover] [New Party %v] recovered share from dealer %v\n", p.PID, dealerID)
				recoveredCtr++
				if recoveredCtr == len(Shelp) {
					log.Printf("[DPSS Recover] [New Party %v] recovered all missing shares\n", p.PID)
					return SrecMap
				}
			}
		}

	}
}

func decapsulateRes(m *protobuf.Message, pid uint32) ([]RecCont, error) {
	//FIXME: error handling
	var helpMsg protobuf.WpAcssHelp
	err := proto.Unmarshal(m.Data, &helpMsg)
	if err != nil {
		log.Printf("[DPSS Recover] [New Party %v] receive WpAcssHelp error: %v\n", pid, err)
		return nil, err
	} else {
		log.Printf("[DPSS Recover] [New Party %v] receive WpAcssHelp from Party %v\n", pid, m.Sender)
	}
	lenRes := len(helpMsg.Res)
	var res = make([]RecCont, lenRes)
	for i := 0; i < lenRes; i++ {

		//decapsulate
		dealerID := helpMsg.Res[i].DealerID
		res[i].dealerID = dealerID
		res[i].helperID = m.Sender

		sRaw := new(bls.Fr)
		bls.SetFr(sRaw, string(helpMsg.Res[i].SMasked))
		bls.CopyFr(&res[i].sMasked, sRaw)

		DPRFContribFRaw, _ := bls.FromCompressedG1(helpMsg.Res[i].DPRFContribF)
		bls.CopyG1(&res[i].DPRFContribF, DPRFContribFRaw)

		piHelp := new(PiHelp)
		piHelpGsRaw, _ := bls.FromCompressedG1(helpMsg.Res[i].PiHelp.Gs)
		bls.CopyG1(&piHelp.Gs, piHelpGsRaw)
		piHelpCdkRaw, _ := bls.FromCompressedG1(helpMsg.Res[i].PiHelp.Cdk)
		bls.CopyG1(&piHelp.Cdk, piHelpCdkRaw)
		piHelpCmaskRaw, _ := bls.FromCompressedG1(helpMsg.Res[i].PiHelp.Cmask)
		bls.CopyG1(&piHelp.Cmask, piHelpCmaskRaw)
		piHelpWiMaskRaw, _ := bls.FromCompressedG1(helpMsg.Res[i].PiHelp.WiMask)
		bls.CopyG1(&piHelp.wiMask, piHelpWiMaskRaw)

		piHelp.piDPRF = *dprf.DecapsulatePiDPRF(helpMsg.Res[i].PiHelp.PiDPRF)
		res[i].piHelp = *piHelp
	}
	return res, nil
}

func recContrib(p *party.HonestParty, ID []byte, F uint32, dealerID uint32, callerID uint32, v party.VShare, pi party.PiShare) RecCont {
	var sMasked bls.Fr
	var wiMask, Cmask bls.G1Point
	index := callerID / F
	// log.Printf("index: %v\n", index)
	bls.AddModFr(&sMasked, &v.S, &v.RecPolyEval[index])
	bls.AddG1(&wiMask, &pi.Wvssi, &pi.PiRec.Weval[index])
	bls.AddG1(&Cmask, &pi.Cvss, &pi.PiRec.Crec[index])
	DPRFContribF, piDPRF := dprf.Contrib(utils.Uint32ToBytes(callerID+1), p.DSKi[dealerID], p.DVKi[dealerID])
	piHelp := PiHelp{
		Gs:     pi.Gs,
		Cdk:    pi.PiRec.Cdk,
		Cmask:  Cmask,
		wiMask: wiMask,
		piDPRF: *piDPRF,
	}
	recCont := RecCont{
		dealerID:     dealerID,
		helperID:     p.PID,
		sMasked:      sMasked,
		DPRFContribF: DPRFContribF,
		piHelp:       piHelp,
	}
	return recCont
}

func vrfyRecCont(p *party.HonestParty, ID []byte, F uint32, recCont RecCont) bool {
	if bls.EqualZero(&recCont.sMasked) {
		log.Printf("[DPSS Recover] [New Party %v] verify recContrib fail: sMasked is zero\n", p.PID)
		return false
	}
	if bls.EqualG1(&recCont.DPRFContribF, &bls.GenG1) {
		log.Printf("[DPSS Recover] [New Party %v] verify recContrib fail: DPRFContribF is zero\n", p.PID)
		return false
	}

	var FrI bls.Fr
	bls.AsFr(&FrI, uint64(recCont.helperID+1))

	p.MutexKZG.Lock()
	if !p.KZG.CheckProofSingle(&recCont.piHelp.Cmask, &recCont.piHelp.wiMask, &FrI, &recCont.sMasked) {
		log.Printf("[DPSS Recover] [New Party %v] verify recContrib fail: sMasked is not valid\n", p.PID)
		p.MutexKZG.Unlock()
		return false
	}
	p.MutexKZG.Unlock()

	if !dprf.VrfyContrib(recCont.DPRFContribF, &recCont.piHelp.piDPRF) {
		log.Printf("[DPSS Recover] [New Party %v] verify recContrib fail: DPRFContribF is not valid\n", p.PID)
		return false
	}

	return true
}
