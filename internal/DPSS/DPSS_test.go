package dpss

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/internal/wpACSS"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"github.com/stretchr/testify/assert"
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

	subShares := make([]bls.Fr, N)
	pos := make([]bls.Fr, N)

	var wg sync.WaitGroup
	wg.Add(int(N) + 1)
	go func() {
		DpssOld(ctx, p[0], ID, F, N)
		fmt.Printf("shares[1]: %v\n", shares[1].String())
		wg.Done()
	}()

	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			vShare, _, err := wpACSS.WpAcssShareEcho(pNext[i], true, ID)
			if err != nil {
				fmt.Printf("error: %v\n", err)
				wg.Done()
			} else {
				subShares[i] = vShare.S
				wg.Done()
			}
		}(i)
	}
	wg.Wait()

	for i := uint32(0); i < F+1; i++ {
		bls.AsFr(&pos[i], uint64(i+1))
	}
	poly := polyring.LagrangeInterpolate(F, pos[:F+2], subShares[:F+2])
	fmt.Println("poly: ", party.PolyToString(poly))
	assert.True(t, bls.EqualFr(&shares[1], &poly[0]), "Reconstruction of Party 1's share from the subshares fail")
}

func TestDpssNew(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(7)
	F := uint32(2)
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
	var Gs bls.G1Point
	bls.AsFr(&secret, uint64(12345))
	bls.MulG1(&Gs, &bls.GenG1, &secret)

	ID := utils.IntToBytes(1) //ID should be generated in this way (constraints in the implementation of MVBA)

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
		p[i].SetGs(&Gs)
	}

	newShares := make([]bls.Fr, N)
	pos := make([]bls.Fr, N)

	var wg sync.WaitGroup
	wg.Add(2 * int(N))

	//old parties
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			DpssOld(ctx, p[i], ID, F, N)
			fmt.Printf("[DPSS] [Old Party %v] exit\n", i)
			// fmt.Printf("shares[1]: %v\n", shares[1].String())
			wg.Done()
		}(i)
	}

	//new parties
	for i := uint32(0); i < N; i++ {
		go func(i uint32) {
			newShares[i] = DpssNew(ctx, pNext[i], ID, F, N)
			fmt.Printf("[DPSS] [New Party %v] exit\n", i)
			wg.Done()
		}(i)
	}
	wg.Wait()

	for i := uint32(0); i < F+1; i++ {
		bls.AsFr(&pos[i], uint64(i+1))
	}
	poly := polyring.LagrangeInterpolate(F, pos[:F+2], newShares[:F+2])
	fmt.Println("poly: ", party.PolyToString(poly))
	assert.True(t, bls.EqualFr(&secret, &poly[0]), "Reconstruct secret from the newshares fail")

	//check the new commitments vNew
	var tmpGs bls.G1Point
	for i := uint32(0); i < N; i++ {
		bls.MulG1(&tmpGs, &bls.GenG1, &newShares[i])
		//here we take pNext[2]'s new commitments as an example
		assert.True(t, bls.EqualG1(&tmpGs, pNext[2].GetVCom(i)), "GenNewCom fail")
	}
}

func TestSplitMd(t *testing.T) {
	var md []byte
	g1 := bls.GenG1
	g1Compressed := bls.ToCompressedG1(&g1)
	fmt.Printf("len(g1Compressed): %v\n", len(g1Compressed))
	strG1Comp := hex.EncodeToString(g1Compressed)
	fmt.Printf("len([]byte(strG1Comp)): %v\n", len([]byte(strG1Comp)))
	md = append([]byte("||"), []byte(strG1Comp)...)
	md = append(md, []byte("||")...)
	str := string(md)
	fmt.Printf("str: %v\n", str)
	s := strings.Split(str, "||")
	fmt.Printf("s: %v\n", s[1])
	decS, _ := hex.DecodeString(s[1])
	g2, _ := bls.FromCompressedG1(decS)
	fmt.Printf("bls.EqualG1(&g1, g2): %v\n", bls.EqualG1(&g1, g2))

	md2 := append([]byte("||"), g1Compressed...)
	md2 = append(md2, []byte("||")...)
	res := bytes.Split(md2, []byte("||"))
	g3, _ := bls.FromCompressedG1(res[1])
	fmt.Printf("bls.EqualG1(&g1, g3): %v\n", bls.EqualG1(&g1, g3))
}

func TestSubstractSet(t *testing.T) {
	a := []uint32{1, 2, 3, 4, 5}
	b := []uint32{1, 2, 3}
	c := substractSet(a, b)
	fmt.Printf("c: %v\n", c)
}
