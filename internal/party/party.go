package party

import (
	"sync"
	"time"

	"github.com/drand/kyber/share"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/polycommit"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/vectorcommitment"
)

//Party is a interface of consensus parties
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
}

type ProofRec struct {
	Dpki   bls.G2Point
	PCdsk  bls.G1Point
	VCdpk  []byte
	Wdski  bls.G1Point
	PiDpki vectorcommitment.PiVcomMerkle
	PCphi  []bls.G1Point
	Wphi   []bls.G1Point
}

// func printPiRec(pi *ProofRec) {
// 	fmt.Println("PCdsk: ", pi.PCdsk.String())
// 	fmt.Println("wdki: ", pi.wdki.String())
// 	for i := 0; i < len(pi.PCphi); i++ {
// 		fmt.Println("PCphi: ", pi.PCphi[i].String())
// 	}
// 	for i := 0; i < len(pi.weval); i++ {
// 		fmt.Println("weval: ", pi.weval[i].String())
// 	}
// }

type VShare struct {
	S           bls.Fr
	DskShare    bls.Fr
	RecPolyEval []bls.Fr
}

func NewVShare(s bls.Fr, dskShare bls.Fr, recPolyEval []bls.Fr) *VShare {
	return &VShare{s, dskShare, recPolyEval}
}

// func printVShare(v *vShare) {
// 	fmt.Println("s: ", v.s.String())
// 	fmt.Println("dskShare: ", v.dskShare.String())
// 	for i := 0; i < len(v.recPolyEval); i++ {
// 		fmt.Println("recPolyEval: ", v.recPolyEval[i].String())
// 	}
// }

type PiShare struct {
	Gs     bls.G1Point
	PCvss  bls.G1Point
	Wvssi  bls.G1Point
	PCz    bls.G1Point
	Wz0    bls.G1Point
	VCvs   []byte
	PiVs   vectorcommitment.PiVcomMerkle
	PrfRec ProofRec
}

func NewPiShare(Gs bls.G1Point, PCvss bls.G1Point, wvssi bls.G1Point, PCz bls.G1Point, wz0 bls.G1Point, VCvs []byte, piVs vectorcommitment.PiVcomMerkle, piRec ProofRec) *PiShare {
	return &PiShare{Gs, PCvss, wvssi, PCz, wz0, VCvs, piVs, piRec}
}

// func printPiShare(p *piShare) {
// 	fmt.Println("Gs: ", p.Gs.String())
// 	fmt.Println("PCvss: ", p.PCvss.String())
// 	fmt.Println("wvssi: ", p.wvssi.String())
// 	fmt.Println("PCz: ", p.PCz.String())
// 	fmt.Println("wz0: ", p.wz0.String())
// 	fmt.Println("VCvs: ", string(p.VCvs))
// 	for i := 0; i < len(p.piVcom.Indicator); i++ {
// 		fmt.Printf("Indicator[%d]: %d", i, p.piVcom.Indicator[i])
// 	}
// 	for i := 0; i < len(p.piVcom.Path); i++ {
// 		fmt.Printf("Path[%d]: %s", i, string(p.piVcom.Path[i]))
// 	}
// 	printPiRec(&p.piRec)
// }

type MsgSigTuple struct {
	md  []byte
	sig []byte
}

type VPiTuple struct {
	v  VShare
	pi PiShare
}

//HonestParty is a struct of honest consensus parties
type HonestParty struct {
	e            uint32   // epoch number
	N            uint32   // committee size
	F            uint32   // number of corrupted parties
	PID          uint32   // id of this party
	ipList       []string // ip list of the current committee
	portList     []string // port list of the current committee
	sendChannels []chan *protobuf.Message

	ipListOld          []string // ip list of the old committee
	portListOld        []string // port list of the old committee
	ipListNext         []string // ip list of the new committee
	portListNext       []string // port list of the new committee
	sendToNextChannels []chan *protobuf.Message
	sendToOldChannels  []chan *protobuf.Message
	dispatchChannels   *sync.Map

	FS       *polycommit.FFTSettings
	KZG      *polycommit.KZGSettings
	MutexKZG *sync.Mutex

	Share       bls.Fr        //share of this party
	Gs          bls.G1Point   //commitment of the original share (invariant)
	DSKi        []bls.Fr      //dprf secret key shares
	DPKi        []bls.G2Point //dprf verification key shares
	ProofTuple  []MsgSigTuple //message-signature tuples from other nodes
	ProofCtr    int           //counter of received message-signature tuples
	shareTuples []VPiTuple    //v-pi tuples from other nodes
	VCom        []bls.G1Point //commitments of all shares

	// TblsScheme sign.ThresholdScheme
	SigPK    *share.PubPoly  //tss pk of current committee
	SigSK    *share.PriShare //tss sk of current committee
	SigPKNew *share.PubPoly  //tss pk of next (new) committee

	LagrangeCoefficients [][]bls.Fr //lagrange coefficients when using f(1),f(2),...,f(2t+1) to calculate f(k) for 0 <= k <= 3*f+1.Indices start from 0

	DpssOldStart time.Time
	DpssOldEnd   time.Time
	DpssNewStart time.Time
	DpssNewEnd   time.Time
}

//NewHonestParty return a new honest party object
func NewHonestParty(e uint32, N uint32, F uint32, pid uint32, ipList []string, portList []string, ipListOld []string, portListOld []string, ipListNext []string, portListNext []string, sigPK *share.PubPoly, sigPKNew *share.PubPoly, sigSK *share.PriShare) *HonestParty {
	// var SysSuite = kyberbls.NewBLS12381Suite()
	// tblsScheme := tbls.NewThresholdSchemeOnG1(SysSuite)

	secretG1, secretG2 := polycommit.GenerateTestingSetup("46015081477078601964787943834255776126696019968430095991502055467779756761969", uint64(F+1))
	KZG := polycommit.NewKZGSettings(nil, secretG1, secretG2)

	var mutexKZG sync.Mutex

	LagrangeCoefficients := make([][]bls.Fr, N+1)
	knownIndices := make([]bls.Fr, 2*F+1)
	for i := 0; uint32(i) < 2*F+1; i++ {
		bls.AsFr(&knownIndices[i], uint64(i+1))
	}

	for i := 0; uint32(i) <= N; i++ {
		LagrangeCoefficients[i] = make([]bls.Fr, 2*F+1)
		var target bls.Fr
		bls.AsFr(&target, uint64(i))
		GetLagrangeCoefficients(2*F, knownIndices, target, LagrangeCoefficients[i])
	}

	p := HonestParty{
		e:                  e,
		N:                  N,
		F:                  F,
		PID:                pid,
		ipList:             ipList,
		portList:           portList,
		ipListOld:          ipListOld,
		portListOld:        portListOld,
		ipListNext:         ipListNext,
		portListNext:       portListNext,
		sendChannels:       make([]chan *protobuf.Message, N),
		sendToNextChannels: make([]chan *protobuf.Message, N),
		sendToOldChannels:  make([]chan *protobuf.Message, N),

		// TblsScheme: tblsScheme,
		SigPK:    sigPK,
		SigSK:    sigSK,
		SigPKNew: sigPKNew,

		KZG:      KZG,
		MutexKZG: &mutexKZG,

		Share:       bls.ZERO,
		Gs:          bls.GenG1,
		DSKi:        make([]bls.Fr, N),
		DPKi:        make([]bls.G2Point, N),
		ProofTuple:  make([]MsgSigTuple, N),
		ProofCtr:    0,
		shareTuples: make([]VPiTuple, N),
		VCom:        make([]bls.G1Point, N),

		LagrangeCoefficients: LagrangeCoefficients,
	}
	return &p
}

func (p *HonestParty) SetVPTuples(v *VShare, pi *PiShare, dealerID uint32) {
	p.shareTuples[dealerID].v = *v
	p.shareTuples[dealerID].pi = *pi
}

func (p *HonestParty) GetVShare(index uint32) *VShare {
	return &p.shareTuples[index].v
}

func (p *HonestParty) GetPiShare(index uint32) *PiShare {
	return &p.shareTuples[index].pi
}

func (p *HonestParty) IfReceivedVPiTuples(index uint32) bool {
	if bls.EqualZero(&p.shareTuples[index].v.S) || bls.EqualG1(&p.shareTuples[index].pi.Gs, &bls.GenG1) {
		return false
	}
	return true
}

func (p *HonestParty) IfReceivedMsgProofTuple(index uint32) bool {
	if p.ProofTuple[index].md == nil || p.ProofTuple[index].sig == nil {
		return false
	} else {
		return true
	}
}

func (p *HonestParty) SetMsgSigTuples(md []byte, sig []byte, dealerID uint32) int {
	p.ProofTuple[dealerID].md = append([]byte{}, md...)
	p.ProofTuple[dealerID].sig = append([]byte{}, sig...)
	p.ProofCtr = p.ProofCtr + 1
	return p.ProofCtr
}

func (p *HonestParty) GetMsgSigTuple(index uint32) ([]byte, []byte) {
	return p.ProofTuple[index].md, p.ProofTuple[index].sig
}

// SetShare is used for test initialization only
func (p *HonestParty) SetShare(share bls.Fr) {
	p.Share = share
}

// SetVCom is used for test initialization only
func (p *HonestParty) SetVCom(vcom []bls.G1Point) {
	// p.VCom = vcom
	for i := 0; i < len(vcom); i++ {
		bls.CopyG1(&p.VCom[i], &vcom[i])
	}
	//fmt.Printf("party %v has set VCOM, VCom[0] = %s\n", p.PID, p.VCom[0].String())
}

func (p *HonestParty) SetGs(gs *bls.G1Point) {
	bls.CopyG1(&p.Gs, gs)
}

func (p *HonestParty) GetVCom(index uint32) *bls.G1Point {
	return &p.VCom[index]
}
