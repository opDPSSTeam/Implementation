package dprf

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/pkg/pointproofs"
)

func TestDPRF(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	vc := pointproofs.New(N)
	p := party.NewHonestParty(0, N, F, 0, ipList, portList, nil, nil, nil, nil, pk, nil, sk[2*F+1])
	p.SetVC(vc)

	//test InitDPRF() and VrfyKey()
	dsk, dpk, PCdsk, VCdpk, dski, dpki, wdski, piDpk := InitDPRF(p, F, N)

	var tmp bls.G2Point
	bls.MulG2(&tmp, &bls.GenG2, dsk)
	if !bls.EqualG2(dpk, &tmp) {
		t.Errorf("dpk is not equal to g^dsk")
	}

	for i := uint32(0); i < N; i++ {
		if !VrfyKey(p, i, dski[i], dpki[i], *PCdsk, VCdpk, wdski[i], piDpk[i]) {
			t.Errorf("Vrfy DPRF keys failed")
		}
	}

	//test Contrib() and VrfyContrib()
	x := make([]byte, 16)
	_, err := rand.Read(x)
	if err != nil {
		t.Errorf("error while generating random string: %s", err)
	}
	fmt.Printf("random message x=%s\n", hex.EncodeToString(x))

	W := make([]bls.G1Point, N)
	pi := make([]*ProofDPRF, N)
	for i := uint32(0); i < N; i++ {
		//fmt.Printf("Contrib, i=%d\n", i)
		W[i], pi[i] = Contrib(x, dski[i], dpki[i], piDpk[i])
		//fmt.Printf("VrfyContrib, i=%d\n", i)
		if !VrfyContrib(p, i, x, W[i], pi[i], VCdpk) {
			t.Errorf("Vrfy DPRF contribution failed for i=%d", i)
		}
	}

	//test Combine()
	indexFr := make([]bls.Fr, N)
	indexUint := make([]uint32, N)
	for i := uint32(0); i < N; i++ {
		indexUint[i] = i
		bls.AsFr(&indexFr[i], uint64(i+1))
	}
	v1, err := Combine(p, F, x, indexUint[:F+1], indexFr[:F+1], W[:F+1], pi[:F+1], VCdpk)
	if err != nil {
		fmt.Printf("error while combining: %s\n", err)
		t.Errorf("DPRF combine failed")
	}
	v2 := Eval(x, *dsk)
	if !bls.EqualG1(&v1, &v2) {
		fmt.Printf("v1=%s\n", v1.String())
		fmt.Printf("v2=%s\n", v2.String())
		t.Errorf("DPRF combine failed")
	}
}
