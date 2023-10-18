package dprf

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"

	kbls "github.com/kilic/bls12-381"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/vss"
	"github.com/opDPSSTeam/DPSS/pkg/protobuf"
	"github.com/opDPSSTeam/DPSS/pkg/utils"
)

type ProofDPRF struct {
	w      bls.G1Point
	c      bls.Fr
	u      bls.Fr
	dpki   bls.G2Point
	piDpki string
}

func newProofDPRF(w bls.G1Point, c bls.Fr, u bls.Fr, dpki bls.G2Point, piDpki string) *ProofDPRF {
	return &ProofDPRF{w, c, u, dpki, piDpki}
}

func InitDPRF(p *party.HonestParty, F uint32, N uint32) (*bls.Fr, *bls.G2Point, *bls.G1Point, string, []bls.Fr, []bls.G2Point, []bls.G1Point, []string) {

	var dsk bls.Fr
	var dpk bls.G2Point
	dsk = *bls.RandomFr()
	bls.MulG2(&dpk, &bls.GenG2, &dsk)

	PCdsk, dskShare, wdsk, _ := vss.VssShare(p, F, N, dsk)
	var dpkShare = make([]bls.G2Point, N)
	for i := uint32(0); i < N; i++ {
		bls.MulG2(&dpkShare[i], &bls.GenG2, &dskShare[i+1])
	}

	dpkShareFr := make([]kbls.Fr, N)
	for i := uint32(0); i < N; i++ {
		dpkShareFr[i] = *utils.HashG2ToFr(&dpkShare[i])
	}
	VCdpk := p.VC.Commit(dpkShareFr)

	piDpk := make([]string, N)
	for i := 0; uint32(i) < N; i++ {
		piDpk[i] = p.VC.Open(dpkShareFr, i)
	}

	return &dsk, &dpk, PCdsk, VCdpk, dskShare[1:], dpkShare, wdsk[1:], piDpk
}

func EncapsulatePiDPRF(pi *ProofDPRF) *protobuf.ProofDPRF {
	var msg = new(protobuf.ProofDPRF)
	msg.W = bls.ToCompressedG1(&pi.w)
	msg.C = []byte(pi.c.String())
	msg.U = []byte(pi.u.String())
	msg.Dpk = bls.ToCompressedG2(&pi.dpki)
	msg.PiDpk = pi.piDpki
	return msg
}

func DecapsulatePiDPRF(msg *protobuf.ProofDPRF) *ProofDPRF {
	//FIXME: error handling
	var pi = new(ProofDPRF)
	wRaw, _ := bls.FromCompressedG1(msg.W)
	bls.CopyG1(&pi.w, wRaw)
	cRaw := new(bls.Fr)
	bls.SetFr(cRaw, string(msg.C))
	bls.CopyFr(&pi.c, cRaw)
	uRaw := new(bls.Fr)
	bls.SetFr(uRaw, string(msg.U))
	bls.CopyFr(&pi.u, uRaw)
	dvkRaw, _ := bls.FromCompressedG2(msg.Dpk)
	bls.CopyG2(&pi.dpki, dvkRaw)
	pi.piDpki = msg.PiDpk
	return pi
}

func VrfyKey(p *party.HonestParty, i uint32, dski bls.Fr, dpki bls.G2Point, PCdsk bls.G1Point, VCdpk string, wdski bls.G1Point, piDpki string) bool {
	var index bls.Fr
	bls.AsFr(&index, uint64(i+1))
	var tmp bls.G2Point
	bls.MulG2(&tmp, &bls.GenG2, &dski)
	if bls.EqualG2(&tmp, &dpki) {
		p.MutexKZG.Lock()
		if p.KZG.CheckProofSingle(&PCdsk, &wdski, &index, &dski) {
			p.MutexKZG.Unlock()
			return p.VC.Verify(VCdpk, *utils.HashG2ToFr(&dpki), int(i), piDpki)
		}
	}
	p.MutexKZG.Unlock()
	return false
}

func Contrib(x []byte, dski bls.Fr, dpki bls.G2Point, piDpki string) (bls.G1Point, *ProofDPRF) {
	var w bls.G1Point
	var sha256x bls.Fr
	var W bls.G1Point
	var Wr bls.G1Point
	var c bls.Fr
	var u bls.Fr

	//we use sha256 to build the hash function H1(x): {0,1}* -> G1
	//H(x)=g^sha256(x)
	//TODO: may use the HashToCurve function in https://github.com/kilic/bls12-381/blob/master/g1.go#L831 later
	hashedBytes := sha256.Sum256(x)
	stringSha256x := hex.EncodeToString(hashedBytes[:])
	bls.SetFr16(&sha256x, stringSha256x)
	//fmt.Printf("sha256x: %v\n", sha256x.String())
	bls.MulG1(&w, &bls.GenG1, &sha256x) //w=H(x)=g^sha256(x)
	bls.MulG1(&W, &w, &dski)            //W=w^dski
	r := bls.RandomFr()
	bls.MulG1(&Wr, &w, r) //Wr=w^r

	//we use sha256 to build the hash function H2(x): {0,1}* -> Zp
	msg := W.String() + w.String() + dpki.String() + bls.GenG1.String() + Wr.String()
	hashedMsg := sha256.Sum256([]byte(msg))
	bls.SetFr16(&c, hex.EncodeToString(hashedMsg[:]))

	//fmt.Println("c: ", c.String())

	var tmp bls.Fr
	bls.MulModFr(&tmp, &c, &dski)
	bls.SubModFr(&u, r, &tmp) //u=r-c*dski

	proof := newProofDPRF(w, c, u, dpki, piDpki) //proof_dprf

	return W, proof
}

func VrfyContrib(p *party.HonestParty, i uint32, x []byte, W bls.G1Point, pi *ProofDPRF, VCdpk string) bool {
	var sha256x bls.Fr
	var Hx bls.G1Point
	HxBytes := sha256.Sum256(x)
	stringSha256x := hex.EncodeToString(HxBytes[:])
	bls.SetFr16(&sha256x, stringSha256x)
	bls.MulG1(&Hx, &bls.GenG1, &sha256x) //H(x)=g^sha256(x)
	if !bls.EqualG1(&Hx, &pi.w) {
		log.Printf("verify DPRF contribution failed: H(x) != w\n")
		return false
	}

	if !p.VC.Verify(VCdpk, *utils.HashG2ToFr(&pi.dpki), int(i), pi.piDpki) {
		log.Printf("VC verification failed, i=%v\n", i)
		return false
	}

	var t bls.G1Point
	var tmp1 bls.G1Point
	var tmp2 bls.G1Point
	bls.MulG1(&tmp1, &pi.w, &pi.u)
	bls.MulG1(&tmp2, &W, &pi.c)
	bls.AddG1(&t, &tmp1, &tmp2) //t=w^u*W^c

	//fmt.Println("t: ", t.String())

	msg := W.String() + pi.w.String() + pi.dpki.String() + bls.GenG1.String() + t.String()

	var c bls.Fr
	hashedMsg := sha256.Sum256([]byte(msg))
	bls.SetFr16(&c, hex.EncodeToString(hashedMsg[:]))

	return bls.EqualFr(&c, &pi.c)
}

func Combine(p *party.HonestParty, f uint32, x []byte, Iuint32 []uint32, IFr []bls.Fr, Wi []bls.G1Point, pi []*ProofDPRF, VCdpk string) (bls.G1Point, error) {

	if uint32(len(IFr)) < f+1 {
		return bls.GenG1, errors.New("not enough DPRF contributions")
	}
	for i := uint32(0); i < f+1; i++ {
		if !VrfyContrib(p, Iuint32[i], x, Wi[i], pi[i], VCdpk) {
			return bls.GenG1, errors.New("invalid contribution")
		}
	}

	//interpolate F(x) from {Wi=F_i(x)}, i=0...f
	res := p.InterpolateComOrWitByKnownIndexes(f, 0, IFr, Wi)
	// fmt.Println("tmp: ", tmp.String())

	////return H(F(x))
	//hashedFx := sha256.Sum256([]byte(tmp.String()))
	//var res bls.Fr
	//// bls.FrFrom32(&res, hashBytes)
	//bls.SetFr16(&res, hex.EncodeToString(hashedFx[:]))
	return res, nil
}

func Eval(x []byte, dsk bls.Fr) bls.G1Point {
	var sha256x bls.Fr
	var Hx bls.G1Point
	var res bls.G1Point
	// var resFr bls.Fr

	hashedBytes := sha256.Sum256(x)
	bls.SetFr16(&sha256x, hex.EncodeToString(hashedBytes[:]))
	// bls.FrFrom32(&sha256x, hashedBytes)
	bls.MulG1(&Hx, &bls.GenG1, &sha256x) //H(x)=g^sha256(x)
	bls.MulG1(&res, &Hx, &dsk)           //res=H(x)^dsk

	// fmt.Printf("res: %v\n", res.String())
	return res
	// //hash res to Zp (Fr)
	// hashedBytes = sha256.Sum256([]byte(res.String()))
	// bls.SetFr16(&resFr, hex.EncodeToString(hashedBytes[:]))
	// // bls.FrFrom32(&resFr, hashedBytes)
	// return resFr
}

func Verify(y bls.G1Point, x []byte, dpk bls.G2Point) {
	var sha256x bls.Fr
	var Hx bls.G1Point
	hashedBytes := sha256.Sum256(x)
	bls.SetFr16(&sha256x, hex.EncodeToString(hashedBytes[:]))
	// bls.FrFrom32(&sha256x, hashedBytes)
	bls.MulG1(&Hx, &bls.GenG1, &sha256x) //H(x)=g^sha256(x)
	bls.PairingsVerify(&y, &bls.GenG2, &Hx, &dpk)
}
