package dpss

import (
	"context"
	"fmt"

	"github.com/opDPSSTeam/DPSS/internal/wpACSS"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/vectorcommitment"
	"google.golang.org/protobuf/proto"
)

func DpssOld(ctx context.Context, p *party.HonestParty, ID []byte, F uint32, N uint32) {

	vgBytes := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		vgBytes[i] = []byte(p.VCom[i].String())
	}
	tre, _ := vectorcommitment.NewMerkleTree(vgBytes)
	Cold := tre.GetMerkleTreeRoot()

	piOld := make([]vectorcommitment.PiVcomMerkle, N)
	piOld[p.PID] = tre.GetMerkleTreeProofPi(p.PID)
	data := encapsulateComMsg(Cold, &p.VCom[p.PID], piOld[p.PID])
	err := p.BroadcastToNextCommittee(&protobuf.Message{
		Type:   "DpssCom",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	if err != nil {
		fmt.Printf("[DPSS.Commit] [Old Party %v] multicast DpssCom error: %v\n", p.PID, err)
	}
	fmt.Printf("[DPSS.Commit] [Old Party %v] multicast DpssCom done\n", p.PID)

	md, sig := wpACSS.WpAcssShareSend(ctx, p, ID, false, F, N, p.Share)
	data = encapsulateProofMsg(md, sig)
	err = p.BroadcastToNextCommittee(&protobuf.Message{
		Type:   "DpssProof",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	if err != nil {
		fmt.Printf("[DPSS.Commit] [Old Party %v] send DpssProof error: %v\n", p.PID, err)
	}
	fmt.Printf("[DPSS.Commit] [Old Party %v] multicast DpssProof done\n", p.PID)

}

func encapsulateComMsg(Cold []byte, Gsi *bls.G1Point, piOld vectorcommitment.PiVcomMerkle) []byte {
	var msg = new(protobuf.DpssCom)
	msg.Cold = Cold
	msg.Gsi = bls.ToCompressedG1(Gsi)
	msg.PiOld = new(protobuf.PiVcomMerkle)
	for i := 0; i < len(piOld.Indicator); i++ {
		msg.PiOld.Indicator = append(msg.PiOld.Indicator, piOld.Indicator[i])
		msg.PiOld.Path = append(msg.PiOld.Path, piOld.Path[i])
	}
	data, _ := proto.Marshal(msg)
	return data
}

func encapsulateProofMsg(md []byte, sig []byte) []byte {
	var msg = new(protobuf.DpssProof)
	msg.M = md
	msg.Sig = sig
	data, _ := proto.Marshal(msg)
	return data
}
