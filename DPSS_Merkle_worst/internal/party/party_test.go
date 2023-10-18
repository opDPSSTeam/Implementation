package party

import (
	"fmt"
	"testing"

	"github.com/opDPSSTeam/DPSS/internal/bls"
)

func TestUtils(t *testing.T) {
	ipList := []string{"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"}
	portList := []string{"8880", "8881", "8882", "8883", "8884", "8885", "8886", "8887", "8888", "8889"}
	N := uint32(4)
	F := uint32(1)
	sk, pk := SigKeyGen(N, 2*F+1) // wrong usage, but it doesn't matter here
	p := NewHonestParty(0, N, F, N, ipList, portList, nil, nil, nil, nil, pk, nil, sk[2*F+1])

	var v VShare
	var pi PiShare
	p.SetVPTuples(&v, &pi, 1)
	fmt.Printf("p.IfReceivedVPiTuples(1): %v\n", p.IfReceivedVPiTuples(1))

	v.S = bls.ONE
	p.SetVPTuples(&v, &pi, 1)
	fmt.Printf("p.IfReceivedVPiTuples(1): %v\n", p.IfReceivedVPiTuples(1))

	fmt.Printf("p.IfReceivedMsgProofTuple(1): %v\n", p.IfReceivedMsgProofTuple(1))
	p.SetMsgSigTuples([]byte("md"), []byte("sig"), 1)
	fmt.Printf("p.IfReceivedMsgProofTuple(1): %v\n", p.IfReceivedMsgProofTuple(1))

}
