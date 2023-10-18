/*
forked from https://github.com/xygdys/Dory-BFT-Consensus on 29 May, 2023
*/

package mvba

import (
	"bytes"
	"log"
	"sync"

	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/smvba"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"

	kyberbls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/sign/bls"
)

//MainProcess is the main process of mvba instances
func MainProcess(p *party.HonestParty, ID []byte, value []byte, validation []byte, Q func(*party.HonestParty, []byte, []byte, []byte) error) []byte {

	Sr := sync.Map{} //Lock Set
	pdResultVC := make(chan string, 1)
	pdResultSig := make(chan []byte, 1)

	//Initialize PD instances
	IDj := make([][]byte, 0, p.N)
	for j := uint32(0); j < p.N; j++ {
		var buf bytes.Buffer
		buf.Write(ID)
		buf.Write(utils.Uint32ToBytes(j))
		IDj = append(IDj, buf.Bytes())
	}

	for i := uint32(0); i < p.N; i++ {
		go func(j uint32) {
			vc, shard, proof, ok := PDReceiver(p, j, IDj[j])
			if ok { //save Store
				Sr.Store(j, &protobuf.Store{
					Vc:    vc,
					Shard: shard,
					Proof: proof,
				})
			}
		}(i)
	}

	//Run this party's PD instance
	go func() {
		var buf bytes.Buffer
		buf.Write(value)
		buf.Write(validation)
		buf.Write(utils.IntToBytes(len(validation))) //last 4 bytes is the length of validation
		valueAndValidation := buf.Bytes()

		vc, sig := PDSender(p, IDj[p.PID], valueAndValidation)
		pdResultVC <- vc
		pdResultSig <- sig

	}()

	//waiting until pd
	vc := <-pdResultVC
	sig := <-pdResultSig

	//vc -> pid||vc
	var buf bytes.Buffer
	buf.Write(utils.Uint32ToBytes(p.PID))
	buf.Write([]byte(vc))
	idAndVC := buf.Bytes()

	for r := uint32(0); ; r++ {
		var buf bytes.Buffer
		buf.Write(ID)
		buf.Write(utils.Uint32ToBytes(r))
		IDr := buf.Bytes()

		//run underlying smvba
		leaderAndVC := smvba.MainProcess(p, IDr, idAndVC, sig, validator)
		leader := utils.BytesToUint32(leaderAndVC[:4])
		leaderVC := string(leaderAndVC[4:])

		//recast
		tmp, ok1 := Sr.Load(leader)
		var valueAndValidation []byte
		var ok2 bool
		if ok1 {
			//have leader's Store
			valueAndValidation, ok2 = Recast(p, IDr, leader, leaderVC, tmp.(*protobuf.Store).Shard, tmp.(*protobuf.Store).Proof)
		} else {
			//don't have leader's Store
			log.Printf("p[%d] don't have leader's Store, recast\n", p.PID)
			valueAndValidation, ok2 = Recast(p, IDr, leader, leaderVC, nil, "")
		}
		if ok2 {
			validationLen := utils.BytesToUint32(valueAndValidation[len(valueAndValidation)-4:])
			resultValue := valueAndValidation[:len(valueAndValidation)-int(validationLen)-4]
			validation := valueAndValidation[len(resultValue) : len(resultValue)+int(validationLen)]
			if Q(p, ID, resultValue, validation) == nil {
				return resultValue
			}

		}
		//otherwise: recast failed, goto next round
	}

}

func validator(p *party.HonestParty, ID []byte, value []byte, validation []byte) error {
	var buf bytes.Buffer

	buf.Write([]byte("Stored"))
	buf.Write(ID[:4])
	buf.Write(value)
	sm := buf.Bytes()

	err := bls.NewSchemeOnG1(kyberbls.NewBLS12381Suite()).Verify(p.SigPK.Commit(), sm, validation)
	return err
}
