package dpss

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/internal/wpACSS"
)

func TestDpssOld(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	skNew, pkNew := party.SigKeyGen(N, 2*F+1)

	var p = make([]*party.HonestParty, N)
	var pNext = make([]*party.HonestParty, N)

	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(0, N, F, i, ipList, portList, nil, nil, ipListNext, portListNext, pk, pkNew, sk[i])
		pNext[i] = party.NewHonestParty(1, N, F, i, ipListNext, portListNext, ipList, portList, nil, nil, pkNew, nil, skNew[i])
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
		pNext[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
		p[i].InitSendToNextChannel()
		pNext[i].InitSendChannel()
		pNext[i].InitSendToOldChannel()
	}

	var secret bls.Fr
	bls.AsFr(&secret, uint64(12345))

	ID := []byte("testDpssOld")

	// current := false //send to next committee

	//let p[0] initialize the shares and commitments
	_, shares, _, _ := vss.VssShare(p[0], F, N, secret)
	var Gsi bls.G1Point
	vcom := make([]bls.G1Point, N)
	for i := uint32(0); i < N; i++ {
		bls.MulG1(&Gsi, &bls.GenG1, &shares[i+1])
		vcom[i] = Gsi
	}

	for i := uint32(0); i < N; i++ {
		p[i].SetShare(shares[i+1])
		p[i].SetVCom(vcom)
	}

	var wg sync.WaitGroup
	wg.Add(int(N) + 1)
	go func() {
		DpssOld(ctx, p[0], ID, F, N)
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := wpACSS.WpAcssShareEcho(pNext[i], true, ID)
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

}
