package party

import (
	"sync"

	kyberbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign"
	"github.com/drand/kyber/sign/tbls"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/polycommit"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"

	"go.dedis.ch/kyber/v3/share"
)

//Party is a interface of consensus parties
type Party interface {
	send(m *protobuf.Message, des uint32) error
	broadcast(m *protobuf.Message) error
	getMessageWithType(messageType string) (*protobuf.Message, error)
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

	ipListNext         []string // ip list of the new committee
	portListNext       []string // port list of the new committee
	sendToNextChannels []chan *protobuf.Message
	dispatchChannels   *sync.Map

	FS       *polycommit.FFTSettings
	KZG      *polycommit.KZGSettings
	mutexKZG *sync.Mutex

	tblsScheme sign.ThresholdScheme
	SigPK      *share.PubPoly  //tss pk
	SigSK      *share.PriShare //tss sk

	LagrangeCoefficients [][]bls.Fr //lagrange coefficients when using f(1),f(2),...,f(2t+1) to calculate f(k) for 0 <= k <= 3*f+1.Indices start from 0
}

//NewHonestParty return a new honest party object
func NewHonestParty(e uint32, N uint32, F uint32, pid uint32, ipList []string, portList []string, ipListNext []string, portListNext []string, sigPK *share.PubPoly, sigSK *share.PriShare) *HonestParty {
	var SysSuite = kyberbls.NewBLS12381Suite()
	tblsScheme := tbls.NewThresholdSchemeOnG1(SysSuite)

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
		ipListNext:         ipListNext,
		portListNext:       portListNext,
		sendChannels:       make([]chan *protobuf.Message, N),
		sendToNextChannels: make([]chan *protobuf.Message, N),

		tblsScheme: tblsScheme,
		SigPK:      sigPK,
		SigSK:      sigSK,

		KZG:      KZG,
		mutexKZG: &mutexKZG,

		LagrangeCoefficients: LagrangeCoefficients,
	}
	return &p
}
