package dpss

import (
	"bytes"
	"context"
	"fmt"

	kyberbls "github.com/drand/kyber-bls12381"
	blsSig "github.com/drand/kyber/sign/bls"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/wpACSS"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/vectorcommitment"
	"google.golang.org/protobuf/proto"
)

//DpssOld is the old party's procedures in DPSS
func DpssOld(ctx context.Context, p *party.HonestParty, ID []byte, F uint32, N uint32) {

	vgBytes := make([][]byte, N)
	for i := uint32(0); i < N; i++ {
		vgBytes[i] = bls.ToCompressedG1(&p.VCom[i])
		// vgBytes[i] = []byte(p.VCom[i].String())
	}
	tre, _ := vectorcommitment.NewMerkleTree(vgBytes)
	Cold := tre.GetMerkleTreeRoot()

	piOld := tre.GetMerkleTreeProofPi(p.PID)
	data := encapsulateComMsg(Cold, &p.VCom[p.PID], piOld)
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
	//the following block is for testing
	/* 	blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
	   	err = blsScheme.Verify(p.SigPKNew.Commit(), md, sig)
	   	if err != nil {
	   		fmt.Printf("[DPSS.Commit] [Old Party %v] verify DpssProof error: %v\n", p.PID, err)
	   	} else {
	   		fmt.Printf("[DPSS.Commit] [Old Party %v] has generated a valid DpssProof\n", p.PID)
	   	} */
	data = encapsulateProofMsg(md, sig)
	err = p.BroadcastToNextCommittee(&protobuf.Message{
		Type:   "DpssProof",
		Id:     ID,
		Sender: p.PID,
		Data:   data,
	})
	if err != nil {
		fmt.Printf("[DPSS] [Old Party %v] send DpssProof error: %v\n", p.PID, err)
	}
	fmt.Printf("[DPSS] [Old Party %v] multicast DpssProof done\n", p.PID)

}

//DpssNew is the new party's procedures in DPSS
func DpssNew(ctx context.Context, p *party.HonestParty, ID []byte, F uint32, N uint32) {
	go func() {
		for {
			wpACSS.WpAcssShareEcho(p, true, ID)
		}
	}()

	vcom := make([]bls.G1Point, N)
	vg := make([]bls.G1Point, F+1)
	index := make([]bls.Fr, F+1)
	ctr := uint32(0)
	getVComChan := make(chan bool)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("DpssCom", ID):
				var DpssComMsg protobuf.DpssCom
				err := proto.Unmarshal(m.Data, &DpssComMsg)
				if err != nil {
					fmt.Printf("[DPSS] [New Party %v] receive DpssCom error: %v\n", p.PID, err)
				}
				if !verifyComMsg(&DpssComMsg) {
					fmt.Printf("[DPSS] [New Party %v] verify DpssCom from [Old Party %v] error: invalid commitment or value\n", p.PID, m.Sender)
					continue //wait for the next commitment
				}
				Gsi, _ := bls.FromCompressedG1(DpssComMsg.Gsi)
				bls.CopyG1(&vg[ctr], Gsi)
				bls.AsFr(&index[ctr], uint64(m.Sender))
				ctr++
				if ctr >= F {
					for i := uint32(0); i < N; i++ {
						vcom[i] = p.InterpolateComOrWitByKnownIndexes(F, i, index, vg)
					}
					p.SetVCom(vcom)
					fmt.Printf("[DPSS] [New Party %v] has interpolated the commitments for all old shares\n", p.PID)
					getVComChan <- true
				}
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return

		case m := <-p.GetMessage("DpssProof", ID):
			var DpssProofMsg protobuf.DpssProof
			err := proto.Unmarshal(m.Data, &DpssProofMsg)
			if err != nil {
				fmt.Printf("[DPSS] [New Party %v] receive DpssProof error: %v\n", p.PID, err)
			}

			blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
			err = blsScheme.Verify(p.SigPK.Commit(), DpssProofMsg.M, DpssProofMsg.Sig)
			if err != nil {
				fmt.Printf("[DPSS] [New Party %v] verify DpssProof from [Old Party %v] error: invalid signature\n", p.PID, m.Sender)
				continue //wait for the next proof
			}

			Gsi := parseGsi(DpssProofMsg.M)
			<-getVComChan //wait for the interpolation of all old shares' commitments
			if !bls.EqualG1(Gsi, &p.VCom[m.Sender]) {
				fmt.Printf("[DPSS] [New Party %v] verify DpssProof from [Old Party %v] error: Gsi != VCom[%v], Gsi = %s, VCom[%v] = %s\n", p.PID, m.Sender, m.Sender, Gsi.String(), m.Sender, p.VCom[m.Sender].String())
				continue //wait for the next proof
			}

			fmt.Printf("[DPSS] [New Party %v] receive valid DpssProof from [Old Party %v]\n", p.PID, m.Sender)

			p.SetMsgSigTuples(DpssProofMsg.M, DpssProofMsg.Sig, m.Sender)
			return
		}

	}
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

func verifyComMsg(msg *protobuf.DpssCom) bool {
	var piOld = new(vectorcommitment.PiVcomMerkle)
	for i := 0; i < len(msg.PiOld.Indicator); i++ {
		piOld.Indicator = append(piOld.Indicator, msg.PiOld.Indicator[i])
		piOld.Path = append(piOld.Path, msg.PiOld.Path[i])
	}
	return vectorcommitment.VerifyMerkleTreeProof(msg.Cold, piOld.Path, piOld.Indicator, msg.Gsi)
}

func parseGsi(m []byte) *bls.G1Point {
	splited := bytes.Split(m, []byte("||"))
	Gsi, _ := bls.FromCompressedG1(splited[1])
	return Gsi
}
