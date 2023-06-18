package dpss

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	kyberbls "github.com/drand/kyber-bls12381"
	blsSig "github.com/drand/kyber/sign/bls"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/mvba"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/polyring"
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
		fmt.Printf("[DPSS Commit] [Old Party %v] multicast DpssCom error: %v\n", p.PID, err)
	}
	fmt.Printf("[DPSS Commit] [Old Party %v] multicast DpssCom done\n", p.PID)

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
		fmt.Printf("[DPSS Reshare] [Old Party %v] send DpssProof error: %v\n", p.PID, err)
	}
	fmt.Printf("[DPSS Reshare] [Old Party %v] multicast DpssProof done\n", p.PID)

}

//DpssNew is the new party's procedures in DPSS
func DpssNew(ctx context.Context, p *party.HonestParty, ID []byte, F uint32, N uint32) bls.Fr {

	//start wpACSS instances to receive shares from old parties
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

	//wait for commitment pieces from old parties
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("DpssCom", ID):
				var DpssComMsg protobuf.DpssCom
				err := proto.Unmarshal(m.Data, &DpssComMsg)
				if err != nil {
					fmt.Printf("[DPSS Commit] [New Party %v] receive DpssCom error: %v\n", p.PID, err)
				}
				if !verifyComMsg(&DpssComMsg) {
					fmt.Printf("[DPSS Commit] [New Party %v] verify DpssCom from [Old Party %v] error: invalid commitment or value\n", p.PID, m.Sender)
					continue //wait for the next commitment
				}
				Gsi, _ := bls.FromCompressedG1(DpssComMsg.Gsi)
				fmt.Printf("[New Party %v] ctr: %v\n", p.PID, ctr)
				bls.CopyG1(&vg[ctr], Gsi)
				bls.AsFr(&index[ctr], uint64(m.Sender))
				ctr++
				if ctr > F {
					fmt.Printf("[New Party %v] ctr > F: %v\n", p.PID, ctr)

					for i := uint32(0); i < N; i++ {
						vcom[i] = p.InterpolateComOrWitByKnownIndexes(F, i, index, vg)
					}
					fmt.Printf("[DPSS Commit] [New Party %v] vcom[0]: %v\n", p.PID, vcom[0].String())
					p.SetVCom(vcom)
					fmt.Printf("[DPSS Commit] [New Party %v] has interpolated the commitments for all old shares\n", p.PID)
					getVComChan <- true
					return
				}
			}
		}
	}()

	MVBAsent := false
	var MvbaInMsg = new(protobuf.MvbaIn)
	MvbaInMsg.Tuple = make([]*protobuf.MvbaTuple, F+1)
	for i := uint32(0); i < F+1; i++ {
		MvbaInMsg.Tuple[i] = new(protobuf.MvbaTuple)
	}
	MVBAResChan := make(chan []byte, 1)

	//call MVBA
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case m := <-p.GetMessage("DpssProof", ID):
				var DpssProofMsg protobuf.DpssProof
				err := proto.Unmarshal(m.Data, &DpssProofMsg)
				if err != nil {
					fmt.Printf("[DPSS Reshare] [New Party %v] receive DpssProof error: %v\n", p.PID, err)
				}

				blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
				err = blsScheme.Verify(p.SigPK.Commit(), DpssProofMsg.M, DpssProofMsg.Sig)
				if err != nil {
					fmt.Printf("[DPSS Reshare] [New Party %v] verify DpssProof from [Old Party %v] error: invalid signature\n", p.PID, m.Sender)
					continue //wait for the next proof
				}

				Gsi := parseGsi(DpssProofMsg.M)
				//wait for the interpolation of all old shares' commitments
				<-getVComChan
				if !bls.EqualG1(Gsi, &p.VCom[m.Sender]) {
					fmt.Printf("[DPSS Verify] [New Party %v] verify DpssProof from [Old Party %v] error: Gsi != VCom[%v], Gsi = %s, VCom[%v] = %s\n", p.PID, m.Sender, m.Sender, Gsi.String(), m.Sender, p.VCom[m.Sender].String())
					continue //wait for the next proof
				}

				fmt.Printf("[DPSS Verify] [New Party %v] receive valid DpssProof from [Old Party %v]\n", p.PID, m.Sender)

				proofCtr := p.SetMsgSigTuples(DpssProofMsg.M, DpssProofMsg.Sig, m.Sender)
				MvbaInMsg.Tuple[proofCtr-1].Index = m.Sender
				MvbaInMsg.Tuple[proofCtr-1].Md, MvbaInMsg.Tuple[proofCtr-1].Sig = p.GetMsgSigTuple(m.Sender)

				//MVBA
				if !MVBAsent && uint32(proofCtr) >= F+1 {
					fmt.Printf("[DPSS MVBA] [New Party %v] call MVBA\n", p.PID)
					data, _ := proto.Marshal(MvbaInMsg)
					MVBAsent = true
					MVBAResChan <- mvba.MainProcess(p, ID, data, nil, Pmvba) //in our use case, the signatures are included in data, so we set validation as nil here
				}
			}

		}
	}()

	//recover
	res := <-MVBAResChan
	var MvbaRes = new(protobuf.MvbaIn)
	err := proto.Unmarshal(res, MvbaRes)
	if err != nil {
		fmt.Printf("[DPSS MVBA] [New Party %v] parse Mvba Out error: %v\n", p.PID, err)
	}
	I := make([]uint32, len(MvbaRes.Tuple))
	Shelp := make([]uint32, 0)
	for i := 0; i < len(MvbaRes.Tuple); i++ {
		I[i] = MvbaRes.Tuple[i].Index
		if p.IfReceivedVPiTuples(I[i]) {
			Shelp = append(Shelp, I[i])
		}
	}

	var recoverResChan = make(chan map[uint32]bls.Fr, 1)
	var SrecMap = make(map[uint32]bls.Fr) //maps dealerID to the recovered s_{d,i}

	go func() {
		if len(Shelp) > 0 {
			wpACSS.CallHelp(p, ID, F, N, Shelp)
			recoverResChan <- wpACSS.WaitHelp(p, ID, F, N, Shelp) //wait for others' help
		}
	}()

	go wpACSS.Help(p, ID, F, N) //answer others' help

	SrecMap = <-recoverResChan //wait for the recovery result

	//refresh
	iRefresh := make([]bls.Fr, F+1)
	vRefresh := make([]bls.Fr, F+1)
	for i, j := range I {
		bls.AsFr(&iRefresh[i], uint64(j))
		if _, ok := SrecMap[j]; ok {
			vRefresh[i] = SrecMap[j]
		} else {
			vRefresh[i] = p.GetVShare(j).S
		}
	}
	refreshedPoly := polyring.LagrangeInterpolate(F, iRefresh, vRefresh)
	newShare := refreshedPoly[0]
	return newShare

}

func Pmvba(p *party.HonestParty, ID []byte, value []byte, validation []byte) error {
	var MvbaMsg = new(protobuf.MvbaIn)
	err := proto.Unmarshal(value, MvbaMsg)
	if err != nil {
		fmt.Printf("[DPSS MVBA] [New Party %v] parse MvbaIn error: %v\n", p.PID, err)
		return err
	}

	blsScheme := blsSig.NewSchemeOnG1(kyberbls.NewBLS12381Suite())
	for i := 0; i < len(MvbaMsg.Tuple); i++ {
		err := blsScheme.Verify(p.SigPK.Commit(), MvbaMsg.Tuple[i].Md, MvbaMsg.Tuple[i].Sig)
		if err != nil {
			return fmt.Errorf("invalid signature: %v", err)
		}
		Gsi := parseGsi(MvbaMsg.Tuple[i].Md)
		if !bls.EqualG1(Gsi, &p.VCom[MvbaMsg.Tuple[i].Index]) {
			return errors.New("invalid Gsi")
		}
	}
	return nil
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
