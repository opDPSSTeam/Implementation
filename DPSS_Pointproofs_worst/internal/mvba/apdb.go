/*
forked from https://github.com/xygdys/Dory-BFT-Consensus on 29 May, 2023
*/

package mvba

//smvba with dispersal-then-recast

import (
	"bytes"

	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/pkg/core"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/reedsolomon"
	"github.com/opDPSSTeam/DPSS/pkg/utils"

	kyberbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/tbls"
	kbls "github.com/kilic/bls12-381"
	"github.com/vivint/infectious"
)

//PDSender is run by senders of provable dispersal subprotocols
func PDSender(p *party.HonestParty, ID []byte, value []byte) (string, []byte) {
	//rs encode
	rsCoder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))
	shares := rsCoder.Encode(value)

	//commit
	vec := make([]kbls.Fr, p.N)
	for i := uint32(0); i < p.N; i++ {
		vec[i] = *utils.HashByteToFr(shares[i].Data)
	}
	vc := p.VC.Commit(vec)

	//open and send
	for i := 0; uint32(i) < p.N; i++ {
		proof := p.VC.Open(vec, i)
		storeMessage := core.Encapsulation("Store", ID, p.PID, &protobuf.Store{
			Vc:    vc,
			Shard: shares[i].Data,
			Proof: proof,
		})
		p.Send(storeMessage, uint32(i))
	}

	sigs := [][]byte{}
	var buf bytes.Buffer
	buf.Write([]byte("Stored"))
	buf.Write(ID)
	buf.Write([]byte(vc))
	sm := buf.Bytes()
	tblsScheme := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite())

	for {
		m := <-p.GetMessage("Stored", ID)

		payload := core.Decapsulation("Stored", m).(*protobuf.Stored)

		sigs = append(sigs, payload.Sigshare)
		if uint32(len(sigs)) > 2*p.F {
			signature, _ := tblsScheme.Recover(p.SigPK, sm, sigs, int(2*p.F+1), int(p.N))
			return vc, signature //lock
		}
	}
}

//PDReceiver is run by receivers of provable dispersal subprotocols
func PDReceiver(p *party.HonestParty, sender uint32, ID []byte) (string, []byte, string, bool) {
	m := <-p.GetMessage("Store", ID)

	payload := (core.Decapsulation("Store", m)).(*protobuf.Store)
	ok := p.VC.Verify(payload.Vc, *utils.HashByteToFr(payload.Shard), int(p.PID), payload.Proof)
	if !ok { //sender is dishonest
		return "", nil, "", false
	}

	var buf bytes.Buffer
	buf.Write([]byte("Stored"))
	buf.Write(ID)
	buf.Write([]byte(payload.Vc))
	sm := buf.Bytes()
	sigShare, _ := tbls.NewThresholdSchemeOnG1(kyberbls.NewBLS12381Suite()).Sign(p.SigSK, sm) //sign("Stored"||ID||vc)

	storedMessage := core.Encapsulation("Stored", ID, p.PID, &protobuf.Stored{
		Sigshare: sigShare,
	})
	p.Send(storedMessage, sender)

	return payload.Vc, payload.Shard, payload.Proof, true

}

//Recast is run by all parties of recast subprotocols
func Recast(p *party.HonestParty, ID []byte, leader uint32, vc string, shard []byte, proof string) ([]byte, bool) {
	if shard != nil {
		recastMessage := core.Encapsulation("Recast", ID, p.PID, &protobuf.Recast{
			Shard: shard,
			Proof: proof,
		})
		p.Broadcast(recastMessage)
	}

	rsCoder := reedsolomon.NewRScoder(int(p.F+1), int(p.N))
	shares := []infectious.Share{}

	for {
		m := <-p.GetMessage("Recast", ID)
		payload := (core.Decapsulation("Recast", m)).(*protobuf.Recast)
		ok := p.VC.Verify(vc, *utils.HashByteToFr(payload.Shard), int(m.Sender), payload.Proof)
		if ok {
			shares = append(shares, infectious.Share{
				Data:   payload.Shard,
				Number: int(m.Sender),
			})
			if len(shares) > int(2*p.F) {
				value, err := rsCoder.Decode(shares) //decode
				if err != nil {
					panic(err)
				}

				tempShares := rsCoder.Encode(value) //re-encode

				vec := make([]kbls.Fr, p.N)
				for i := uint32(0); i < p.N; i++ {
					vec[i] = *utils.HashByteToFr(tempShares[i].Data)
				}
				tempVC := p.VC.Commit(vec) //re-commit
				if vc == tempVC {
					return value, true
				}
				return nil, false
			}
		}

	}
}
