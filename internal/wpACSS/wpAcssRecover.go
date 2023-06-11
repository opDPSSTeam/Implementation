package wpACSS

import (
	"fmt"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"google.golang.org/protobuf/proto"
)

type PiHelp struct {
	Gs     bls.G1Point
	Cdk    bls.G1Point
	Cmask  bls.G1Point
	wiMask bls.G1Point
	piDPRF dprf.PiDPRF
}

type RecCont struct {
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
	err := p.Broadcast(&protobuf.Message{
		Type:   "WpAcssCallHelp",
		Id:     ID,
		Sender: p.PID,
		Data:   msgData,
	})
	if err != nil {
		fmt.Printf("Error in broadcast: %v\n", err)
	} else {
		fmt.Printf("[wpACSS.Recover] [Party %v] calls for help\n", p.PID)
	}
}

// func Help(p *party.HonestParty, ID []byte, F uint32, N uint32, Shelp []uint32) {

// }

func RecContrib(p *party.HonestParty, ID []byte, F uint32, dealerID uint32, callerID uint32, v party.VShare, pi party.PiShare) RecCont {
	var sMasked bls.Fr
	var wiMask, Cmask bls.G1Point
	index := callerID / F // ceil(callerID/F)
	fmt.Printf("index: %v\n", index)
	bls.AddModFr(&sMasked, &v.S, &v.RecPolyEval[index])
	bls.AddG1(&wiMask, &pi.Wvssi, &pi.PiRec.Weval[index])
	bls.AddG1(&Cmask, &pi.Cvss, &pi.PiRec.Crec[index])
	DPRFContribF, piDPRF := dprf.Contrib(p, utils.Uint32ToBytes(callerID), p.DSKi[dealerID], p.DVKi[dealerID])
	piHelp := PiHelp{
		Gs:     pi.Gs,
		Cdk:    pi.PiRec.Cdk,
		Cmask:  Cmask,
		wiMask: wiMask,
		piDPRF: *piDPRF,
	}
	recCont := RecCont{
		sMasked:      sMasked,
		DPRFContribF: DPRFContribF,
		piHelp:       piHelp,
	}
	return recCont
}

func VrfyContrib(p *party.HonestParty, ID []byte, F uint32, dealerID uint32, callerID uint32, helperID uint32, recCont RecCont) bool {
	if bls.EqualZero(&recCont.sMasked) {
		fmt.Printf("[wpACSS.Recover] [Party %v] verify RecContrib fail: sMasked is zero\n", p.PID)
		return false
	}
	if bls.EqualG1(&recCont.DPRFContribF, &bls.GenG1) {
		fmt.Printf("[wpACSS.Recover] [Party %v] verify RecContrib fail: DPRFContribF is zero\n", p.PID)
		return false
	}

	var FrI bls.Fr
	bls.AsFr(&FrI, uint64(helperID+1))

	p.MutexKZG.Lock()
	if !p.KZG.CheckProofSingle(&recCont.piHelp.Cmask, &recCont.piHelp.wiMask, &FrI, &recCont.sMasked) {
		fmt.Printf("[wpACSS.Recover] [Party %v] verify RecContrib fail: sMasked is not valid\n", p.PID)
		p.MutexKZG.Unlock()
		return false
	}
	p.MutexKZG.Unlock()

	if !dprf.VrfyContrib(recCont.DPRFContribF, &recCont.piHelp.piDPRF) {
		fmt.Printf("[wpACSS.Recover] [Party %v] verify RecContrib fail: DPRFContribF is not valid\n", p.PID)
		return false
	}

	return true
}
