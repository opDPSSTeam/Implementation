package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	dpss "github.com/opDPSSTeam/DPSS/internal/DPSS"
	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/pkg/pointproofs"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
	"google.golang.org/protobuf/proto"
)

func main() {
	//metadataPath := "metadata"
	//ListPath := "list"

	N := flag.Int("n", 4, "the size of the commitee")
	F := flag.Int("f", 1, "the maximum of faults")
	id := flag.Int("id", 0, "the id of the node")
	metadataPath := flag.String("mp", "", "metadataPath")
	ListPath := flag.String("lp", "", "listPath")
	option1 := flag.String("op1", "2", "1 means generating the setup parameters, 2 means executing the protocol")
	option2 := flag.String("op2", "", "choose one from old, new")
	interval1 := flag.Int("t1", 5, "wait for t1 seconds so that new parties get ready")
	interval2 := flag.Int("t2", 10, "wait for t2 seconds so that old parties get ready")
	// interval3 := flag.Int("t3", 20, "the interval before start Signal")
	flag.Parse()

	if *option1 == "1" {
		party.GenCoefficientsFile(*N, 2**F+1)
		return
	} else if *option1 == "2" {
		sk, pk := party.SigKeyGenFix(uint32(*N), uint32(2**F+1))
		skNew, pkNew := party.SigKeyGenFix_New(uint32(*N), uint32(2**F+1))
		ID := utils.IntToBytes(1) //ID should be generated in this way (constraints in the implementation of MVBA)
		switch *option2 {
		case "old":
			OutputLog, err := os.OpenFile(*metadataPath+"/exeLogOld"+strconv.Itoa(*id)+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			ipList := ReadIpList(*ListPath, "")[0:*N]
			portList := ReadPortList(*ListPath, "")[0:*N]
			ipListNext := ReadIpList(*ListPath, "Next")[0:*N]
			portListNext := ReadPortList(*ListPath, "Next")[0:*N]
			p := party.NewHonestParty(0, uint32(*N), uint32(*F), uint32(*id), ipList, portList, nil, nil, ipListNext, portListNext, pk, pkNew, sk[*id])

			p.InitReceiveChannel()
			time.Sleep(time.Duration(*interval2) * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToNextChannel()
			log.Printf("[VSS][Old Party %v] starting...\n", p.PID)
			fmt.Printf("[VSS][Old Party %v] starting...\n", p.PID)

			// we let p[0] be the dealer to distribute the old shares
			var secret bls.Fr
			bls.AsFr(&secret, uint64(12345))

			if p.PID == 0 {
				sendInitShares(p, ID, secret)
			}
			receiveInitSharesAndSRS(p, ID)
			log.Printf("[Init][Old Party %v] Get init shares finished\n", p.PID)
			fmt.Printf("[Init][Old Party %v] Get init shares finished\n", p.PID)

			log.Printf("[DPSS][Old Party %v] DpssOld starting...\n", p.PID)
			fmt.Printf("[DPSS][Old Party %v] DpssOld starting...\n", p.PID)
			ctx, _ := context.WithCancel(context.Background())
			dpss.DpssOld(ctx, p, ID, p.F, p.N)
			log.Printf("[DPSS] [Old Party %v] DpssOld finished\n", p.PID)
			fmt.Printf("[DPSS] [Old Party %v] DpssOld finished\n", p.PID)

			f, _ := os.OpenFile(*metadataPath+"/resultOld"+strconv.Itoa(int(p.PID))+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
			defer f.Close()
			fmt.Fprintf(f, "DpssOldStart, %v\n", p.DpssOldStart.UnixNano())
			fmt.Fprintf(f, "DpssOldEnd, %v\n", p.DpssOldEnd.UnixNano())
			fmt.Fprintf(f, "DpssOldDelta, %v\n", p.DpssOldEnd.UnixNano()-p.DpssOldStart.UnixNano())

			time.Sleep(2000 * time.Second)
		case "new":
			OutputLog, err := os.OpenFile(*metadataPath+"/exeLogNew"+strconv.Itoa(*id)+".log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0777)
			if err != nil {
				log.Fatalf("error opening file: %v", err)
			}
			defer OutputLog.Close()
			log.SetOutput(OutputLog)

			ipListOld := ReadIpList(*ListPath, "")[0:*N]
			portListOld := ReadPortList(*ListPath, "")[0:*N]
			ipListNext := ReadIpList(*ListPath, "Next")[0:*N]
			portListNext := ReadPortList(*ListPath, "Next")[0:*N]
			p := party.NewHonestParty(1, uint32(*N), uint32(*F), uint32(*id), ipListNext, portListNext, ipListOld, portListOld, nil, nil, pkNew, nil, skNew[*id])

			p.InitReceiveChannel()
			time.Sleep(time.Duration(*interval1) * time.Second) //waiting for all nodes to initialize their ReceiveChannel

			p.InitSendChannel()
			p.InitSendToOldChannel()
			receiveInitSRS(p, ID)
			log.Printf("[Init][New Party %v] Get SRS finished\n", p.PID)
			fmt.Printf("[Init][New Party %v] Get SRS finished\n", p.PID)
			log.Printf("[DPSS][New Party %v] DpssNew starting...\n", p.PID)
			fmt.Printf("[DPSS][New Party %v] DpssNew starting...\n", p.PID)
			ctx, _ := context.WithCancel(context.Background())
			newShare := dpss.DpssNew(ctx, p, ID, p.F, p.N)
			log.Printf("[DPSS][New Party %v] newShare: %v\n", p.PID, newShare.String())
			log.Printf("[DPSS][New Party %v] DpssNew finished\n", p.PID)
			fmt.Printf("[DPSS][New Party %v] DpssNew finished\n", p.PID)

			f, _ := os.OpenFile(*metadataPath+"/resultNew"+strconv.Itoa(int(p.PID))+".log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
			defer f.Close()
			fmt.Fprintf(f, "DpssNewStart, %v\n", p.DpssNewStart.UnixNano())
			fmt.Fprintf(f, "DpssNewEnd, %v\n", p.DpssNewEnd.UnixNano())
			fmt.Fprintf(f, "DpssNewDelta, %v\n", p.DpssNewEnd.UnixNano()-p.DpssNewStart.UnixNano())

			time.Sleep(2000 * time.Second)
		}
	}
}

func ReadIpList(ListPath string, option string) []string {
	ipData, err := ioutil.ReadFile(ListPath + "/ipList" + option)
	if err != nil {
		log.Println(ListPath + "/ipList" + option)
		log.Fatalf("node failed to read iplist %v\n", err)
	}
	return strings.Split(string(ipData), "\n")
}

func ReadPortList(ListPath string, option string) []string {
	portData, err := ioutil.ReadFile(ListPath + "/portList" + option)
	if err != nil {
		log.Println(ListPath + "/portList" + option)
		log.Fatalf("node failed to read portlist %v\n", err)
	}
	return strings.Split(string(portData), "\n")
}

func sendInitShares(p *party.HonestParty, ID []byte, secret bls.Fr) {
	_, shares, _, _ := vss.VssShare(p, p.F, p.N, secret)
	var InitOldMsg = new(protobuf.InitOld)

	var Gs bls.G1Point
	bls.MulG1(&Gs, &bls.GenG1, &secret)
	InitOldMsg.Gs = bls.ToCompressedG1(&Gs)

	var Gsi bls.G1Point
	vcom := make([]bls.G1Point, p.N)
	for i := uint32(0); i < p.N; i++ {
		bls.MulG1(&Gsi, &bls.GenG1, &shares[i+1])
		vcom[i] = Gsi
	}
	InitOldMsg.Vcom = make([][]byte, p.N)
	vc := pointproofs.New(p.N)
	for i := uint32(0); i < p.N; i++ {
		InitOldMsg.Share = []byte(shares[i+1].String())
		for j := uint32(0); j < p.N; j++ {
			InitOldMsg.Vcom[j] = bls.ToCompressedG1(&vcom[j])
		}

		InitOldMsg.Vc = new(protobuf.VC)
		InitOldMsg.Vc.Index = vc.GetIndex()
		InitOldMsg.Vc.Srs = vc.GetSrs()
		data, _ := proto.Marshal(InitOldMsg)
		err := p.Send(&protobuf.Message{
			Type:   "InitOld",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, i)
		if err != nil {
			log.Printf("node %v failed to send Init message to old nodes: %v\n", p.PID, err)
		}

		InitNewMsg := new(protobuf.InitNew)
		InitNewMsg.Vc = new(protobuf.VC)
		InitNewMsg.Vc.Index = vc.GetIndex()
		InitNewMsg.Vc.Srs = vc.GetSrs()
		data, _ = proto.Marshal(InitNewMsg)
		err = p.SendToNextCommittee(&protobuf.Message{
			Type:   "InitNew",
			Id:     ID,
			Sender: p.PID,
			Data:   data,
		}, i)
		if err != nil {
			log.Printf("node %v failed to send Init message to new nodes: %v\n", p.PID, err)
		}
	}
}

func receiveInitSharesAndSRS(p *party.HonestParty, ID []byte) {
	m := <-p.GetMessage("InitOld", ID)
	var InitMsg protobuf.InitOld
	err := proto.Unmarshal(m.Data, &InitMsg)
	if err != nil {
		log.Printf("node %v failed to unmarshal Init message %v\n", p.PID, err)
	}

	var sRaw bls.Fr
	bls.SetFr(&sRaw, string(InitMsg.Share))
	p.SetShare(sRaw)

	Gs, _ := bls.FromCompressedG1(InitMsg.Gs)
	p.SetGs(Gs)

	vcom := make([]bls.G1Point, p.N)
	for i := uint32(0); i < p.N; i++ {
		c, _ := bls.FromCompressedG1(InitMsg.Vcom[i])
		vcom[i] = *c
	}
	p.SetVCom(vcom)

	tmpVC := new(pointproofs.VectorCommit)
	tmpVC.SetIndex(InitMsg.Vc.Index)
	tmpVC.SetSrs(InitMsg.Vc.Srs)
	p.SetVC(tmpVC)
}

func receiveInitSRS(p *party.HonestParty, ID []byte) {
	m := <-p.GetMessage("InitNew", ID)
	var InitMsg protobuf.InitNew
	err := proto.Unmarshal(m.Data, &InitMsg)
	if err != nil {
		log.Printf("node %v failed to unmarshal Init message %v\n", p.PID, err)
	}
	tmpVC := new(pointproofs.VectorCommit)
	tmpVC.SetIndex(InitMsg.Vc.Index)
	tmpVC.SetSrs(InitMsg.Vc.Srs)
	p.SetVC(tmpVC)
}
