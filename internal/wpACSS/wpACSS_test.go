package wpACSS

import (
	"context"
	"log"
	"sync"
	"testing"

	kyberbls "github.com/drand/kyber-bls12381"
	blsSig "github.com/drand/kyber/sign/bls"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/dprf"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
	"github.com/opDPSSTeam/DPSS/pkg/pointproofs"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"github.com/stretchr/testify/assert"
)

func TestGenRecPoly(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here

	p := party.NewHonestParty(0, N, F, N, ipList, portList, nil, nil, nil, nil, pk, nil, sk[2*F+1])

	//uncomment the block comment in genRecPoly to test
	genRecPoly(p, F, N)

}

func TestShare(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	vc := pointproofs.New(N)

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, nil, nil, nil, nil, pk, nil, sk[i])
		p[i].SetVC(vc)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var secret bls.Fr
	bls.AsFr(&secret, uint64(12345))

	ID := []byte("testShare")
	current := true

	shares := make([]bls.Fr, N)
	pos := make([]bls.Fr, N)

	var wg sync.WaitGroup
	wg.Add(int(N) + 1)
	//let p[0] be the dealer
	go func() {
		md, sigd := WpAcssShareSend(ctx, p[0], ID, current, F, N, secret)

		blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
		err := blsScheme.Verify(p[0].SigPK.Commit(), md, sigd)
		if err != nil {
			log.Printf("error: %v\n", err)
		} else {
			log.Println("Verify full signature ok")
		}
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := WpAcssShareEcho(p[i], false, ID)
			if err != nil {
				log.Printf("error: %v\n", err)
				wg.Done()
			} else {
				shares[i] = vShare.S
				wg.Done()
			}
		}(i)
	}
	wg.Wait()

	for i := uint32(0); i < F+1; i++ {
		bls.AsFr(&pos[i], uint64(i+1))
	}
	poly := polyring.LagrangeInterpolate(F, pos[:F+2], shares[:F+2])
	log.Println("poly: ", party.PolyToString(poly))
}

func TestCallHelp(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	vc := pointproofs.New(N)

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, nil, nil, nil, nil, pk, nil, sk[i])
		p[i].SetVC(vc)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}
	ID := []byte("testCallHelp")
	var Shelp []uint32 = []uint32{0}

	CallHelp(p[1], ID, F, N, Shelp)
}

func TestRecContrib(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	vc := pointproofs.New(N)

	var p = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, nil, nil, nil, nil, pk, nil, sk[i])
		p[i].SetVC(vc)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var secret bls.Fr
	bls.AsFr(&secret, uint64(12345))

	ID := []byte("testRecContrib")
	current := true

	shares := make([]bls.Fr, N)

	var wg sync.WaitGroup
	wg.Add(int(N) + 1)
	//let p[0] be the dealer
	go func() {
		md, sigd := WpAcssShareSend(ctx, p[0], ID, current, F, N, secret)

		blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
		err := blsScheme.Verify(p[0].SigPK.Commit(), md, sigd)
		if err != nil {
			log.Printf("error: %v\n", err)
		} else {
			log.Println("Verify full signature ok")
		}
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := WpAcssShareEcho(p[i], false, ID)
			if err != nil {
				log.Printf("error: %v\n", err)
				wg.Done()
			} else {
				shares[i] = vShare.S
				wg.Done()
			}
		}(i)
	}
	wg.Wait() //wait for all shares to be received

	//verify single recContrib
	dealerID := uint32(0)
	callerID := uint32(1)

	for i := uint32(0); i < N; i++ {
		if i != dealerID && i != callerID {
			helperID := i
			cont := recContrib(p[helperID], ID, F, dealerID, callerID, *p[helperID].GetVShare(dealerID), *p[helperID].GetPiShare(dealerID))
			vrf := vrfyRecCont(p[callerID], ID, F, cont)
			assert.True(t, vrf, "Verify contribution failed")
			log.Printf("Party %v has generated a valid RecCont for caller %v\n", i, callerID)
		}
	}

	//verify the combination of recContrib
	callerID = uint32(3)
	log.Printf("original share: %v\n", p[callerID].GetVShare(dealerID).S.String())

	contList := make([]RecCont, N)
	for helperID := uint32(0); helperID < N; helperID++ {
		contList[helperID] = recContrib(p[helperID], ID, F, dealerID, callerID, *p[helperID].GetVShare(dealerID), *p[helperID].GetPiShare(dealerID))
	}

	IdxList := make([]bls.Fr, F+1)
	smList := make([]bls.Fr, F+1)
	DPRFContribList := make([]bls.G1Point, F+1)
	piDPRFList := make([]*dprf.PiDPRF, F+1)

	for i := uint32(0); i < F+1; i++ {
		bls.AsFr(&IdxList[i], uint64(i+1))
		bls.CopyFr(&smList[i], &contList[i].sMasked)
		bls.CopyG1(&DPRFContribList[i], &contList[i].DPRFContribF)
		piDPRFList[i] = &contList[i].piHelp.piDPRF
	}

	polyD := polyring.LagrangeInterpolate(F, IdxList, smList)
	var smi, sRec, posI bls.Fr
	bls.AsFr(&posI, uint64(callerID+1))
	bls.EvalPolyAt(&smi, polyD, &posI)

	Fd, _ := dprf.Combine(p[callerID], F, utils.Uint32ToBytes(callerID+1), IdxList, DPRFContribList, piDPRFList)
	bls.SubModFr(&sRec, &smi, &Fd)

	log.Printf("recovered share: %v\n", sRec.String())
	assert.True(t, bls.EqualFr(&sRec, &p[callerID].GetVShare(dealerID).S), "Recover share failed")
}

func TestRecover(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(7)
	F := uint32(2)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	vc := pointproofs.New(N)

	var p = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, nil, nil, nil, nil, pk, nil, sk[i])
		p[i].SetVC(vc)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	var secret bls.Fr
	bls.AsFr(&secret, uint64(12345))

	ID := []byte("testRecContrib")
	current := true

	shares := make([]bls.Fr, N)

	var wg sync.WaitGroup
	wg.Add(int(N) + 1)
	//let p[0] be the dealer
	go func() {
		md, sigd := WpAcssShareSend(ctx, p[0], ID, current, F, N, secret)

		blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
		err := blsScheme.Verify(p[0].SigPK.Commit(), md, sigd)
		if err != nil {
			log.Printf("error: %v\n", err)
		} else {
			log.Println("Verify full signature ok")
		}
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := WpAcssShareEcho(p[i], false, ID)
			if err != nil {
				log.Printf("error: %v\n", err)
				wg.Done()
			} else {
				shares[i] = vShare.S
				wg.Done()
			}
		}(i)
	}
	wg.Wait() //wait for all shares to be received

	dealerID := uint32(0)
	callerID := uint32(1)
	var originalShare, recoveredShare bls.Fr
	//this is the original share from dealer
	originalShare = p[callerID].GetVShare(dealerID).S
	log.Printf("original share: %v\n", originalShare.String())

	CallHelp(p[callerID], ID, F, N, []uint32{dealerID})

	for j := uint32(0); j < N; j++ {
		go Help(p[j], ID, F, N)
	}
	wg.Add(1)
	go func() {
		res := WaitHelp(p[callerID], ID, F, N, []uint32{dealerID})
		recoveredShare = res[dealerID]
		log.Printf("recovered share: %v\n", recoveredShare.String())
		wg.Done()
		log.Printf("Party %v has recovered the secret for dealerID = %v\n", callerID, dealerID)
	}()
	wg.Wait()

	assert.True(t, bls.EqualFr(&originalShare, &recoveredShare), "Recover share failed: inconsistent shares")

}
