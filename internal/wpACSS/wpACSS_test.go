package wpACSS

import (
	"context"
	"fmt"
	"sync"
	"testing"

	kyberbls "github.com/drand/kyber-bls12381"
	blsSig "github.com/drand/kyber/sign/bls"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
	"github.com/stretchr/testify/assert"
)

func TestGenRecPoly(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	p := party.NewHonestParty(0, N, F, N, ipList, portList, ipListNext, portListNext, pk, sk[2*F+1])

	//uncomment the block comment in GenRecPoly to test
	GenRecPoly(p, F, N)

}

func TestShare(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
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
		md, sigd := wpAcssShareSend(ctx, p[0], ID, current, F, N, secret)

		blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
		err := blsScheme.Verify(p[0].SigPK.Commit(), md, sigd)
		if err != nil {
			fmt.Printf("error: %v\n", err)
		} else {
			fmt.Println("Verify full signature ok")
		}
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := wpAcssShareEcho(p[i], ID)
			if err != nil {
				fmt.Printf("error: %v\n", err)
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
	fmt.Println("poly: ", party.PolyToString(poly))
}

func TestCallHelp(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
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
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here

	var p []*party.HonestParty = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, ipListNext, portListNext, pk, sk[i])
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
		md, sigd := wpAcssShareSend(ctx, p[0], ID, current, F, N, secret)

		blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
		err := blsScheme.Verify(p[0].SigPK.Commit(), md, sigd)
		if err != nil {
			fmt.Printf("error: %v\n", err)
		} else {
			fmt.Println("Verify full signature ok")
		}
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := wpAcssShareEcho(p[i], ID)
			if err != nil {
				fmt.Printf("error: %v\n", err)
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
	helperID := uint32(2)
	cont := RecContrib(p[helperID], ID, F, dealerID, callerID, *p[helperID].GetVShare(dealerID), *p[helperID].GetPiShare(dealerID))
	vrf := VrfyContrib(p[callerID], ID, F, dealerID, callerID, helperID, cont)
	assert.True(t, vrf, "Verify contribution failed")
}
