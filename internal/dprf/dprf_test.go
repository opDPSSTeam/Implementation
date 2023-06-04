package DPRF

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
)

func TestDPRF(t *testing.T) {

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	ipListNext := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portListNext := []string{"8890", "8891", "8892", "8893", "8894", "8895", "8896", "8897", "8898", "8899"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	p := party.NewHonestParty(0, N, F, N, ipList, portList, ipListNext, portListNext, pk, sk[2*F+1])

	//test InitDPRF() and VrfyKey()
	dsk, dpk, Cdk, dski, dvki, wdki := InitDPRF(p, F, N)

	var tmp bls.G1Point
	bls.MulG1(&tmp, &bls.GenG1, dsk)
	if !bls.EqualG1(dpk, &tmp) {
		t.Errorf("dpk is not equal to g^dsk")
	}

	index := make([]bls.Fr, N)
	for i := uint32(0); i < N; i++ {
		bls.AsFr(&index[i], uint64(i+1)) // Indexes = [1, ..., N]
		if !VrfyKey(p, index[i], dski[i], dvki[i], *Cdk, wdki[i]) {
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
	pi := make([]*PiDPRF, N)
	for i := uint32(0); i < N; i++ {
		//fmt.Printf("Contrib, i=%d\n", i)
		W[i], pi[i] = Contrib(p, x, dski[i], dvki[i])
		//fmt.Printf("VrfyContrib, i=%d\n", i)
		if !VrfyContrib(W[i], pi[i]) {
			t.Errorf("Vrfy DPRF contribution failed for i=%d", i)
		}
	}

	//test Combine() and VrfyCombine()
	v1, err := Combine(p, F, x, index[:F+1], W[:F+1], pi[:F+1])
	if err != nil {
		fmt.Printf("error while combining: %s\n", err)
		t.Errorf("DPRF combine failed")
	}
	v2 := Eval(x, *dsk)
	if !bls.EqualFr(&v1, &v2) {
		fmt.Printf("v1=%s\n", v1.String())
		fmt.Printf("v2=%s\n", v2.String())
		t.Errorf("DPRF combine failed")
	}
}
