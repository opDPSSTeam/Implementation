/*
forked from https://github.com/xygdys/Dory-BFT-Consensus on 29 May, 2023
*/

package pb

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"testing"

	kyberbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/tbls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/pkg/pointproofs"
	"golang.org/x/crypto/sha3"
)

func TestPb(t *testing.T) {
	ctx, _ := context.WithCancel(context.Background())

	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883"}

	N := uint32(4)
	F := uint32(1)
	sk, pk := party.SigKeyGen(N, 2*F+1)
	vc := pointproofs.New(N)

	var p = make([]*party.HonestParty, N)
	for i := uint32(0); i < N; i++ {
		p[i] = party.NewHonestParty(1, N, F, i, ipList, portList, nil, nil, nil, nil, pk, nil, sk[i])
		p[i].SetVC(vc)
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitReceiveChannel()
	}

	for i := uint32(0); i < N; i++ {
		p[i].InitSendChannel()
	}

	value := make([]byte, 10)
	validation := make([]byte, 1)
	ID := []byte{1, 2}
	tblsScheme := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite())

	go func() {
		_, sig, _ := Sender(ctx, p[0], ID, value, validation)
		h := sha3.Sum512(value)
		var buf bytes.Buffer
		buf.Write([]byte("Echo"))
		buf.Write(ID)
		buf.Write(h[:])
		sm := buf.Bytes()

		err := tblsScheme.VerifyRecovered(p[0].SigPK.Commit(), sm, sig)

		fmt.Println(err)
	}()

	var wg sync.WaitGroup
	wg.Add(int(N))
	for i := uint32(0); i < N; i++ {
		go Receiver(ctx, p[i], 0, ID, nil)
		wg.Done()
	}
	wg.Wait()
}
