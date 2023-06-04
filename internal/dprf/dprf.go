package DPRF

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/opDPSSTeam/DPSS/internal/bls"
	"github.com/opDPSSTeam/DPSS/internal/party"
	"github.com/opDPSSTeam/DPSS/internal/wpACSS"
)

type PiDPRF struct {
	w    bls.G1Point
	c    bls.Fr
	u    bls.Fr
	dvki bls.G1Point
}

func newPiDPRF(w bls.G1Point, c bls.Fr, u bls.Fr, dvki bls.G1Point) *PiDPRF {
	return &PiDPRF{w, c, u, dvki}
}

func InitDPRF(p *party.HonestParty, F uint32, N uint32) (*bls.Fr, *bls.G1Point, *bls.G1Point, []bls.Fr, []bls.G1Point, []bls.G1Point) {

	var dsk bls.Fr
	var dpk bls.G1Point
	dsk = *bls.RandomFr()
	bls.MulG1(&dpk, &bls.GenG1, &dsk)

	Cdk, dskShare, wdk := wpACSS.VssShare(p, F, N, dsk)
	var dvk = make([]bls.G1Point, N)
	for i := uint32(0); i < N; i++ {
		bls.MulG1(&dvk[i], &bls.GenG1, &dskShare[i+1])
	}
	return &dsk, &dpk, Cdk, dskShare[1:], dvk, wdk[1:]
}

func VrfyKey(p *party.HonestParty, i bls.Fr, dski bls.Fr, dvki bls.G1Point, Cdk bls.G1Point, wdki bls.G1Point) bool {
	var tmp bls.G1Point
	bls.MulG1(&tmp, &bls.GenG1, &dski)
	if bls.EqualG1(&tmp, &dvki) {
		if p.KZG.CheckProofSingle(&Cdk, &wdki, &i, &dski) {
			return true
		}
	}
	return false
}

func Contrib(p *party.HonestParty, x []byte, dski bls.Fr, dvki bls.G1Point) (bls.G1Point, *PiDPRF) {
	var w bls.G1Point
	var sha256x bls.Fr
	var W bls.G1Point
	var Wr bls.G1Point
	var c bls.Fr
	var u bls.Fr

	//we use sha256 to build the hash function H1(x): {0,1}* -> G1
	//H(x)=g^sha256(x)
	hashedBytes := sha256.Sum256(x)
	stringSha256x := hex.EncodeToString(hashedBytes[:])
	bls.SetFr16(&sha256x, stringSha256x)
	//fmt.Printf("sha256x: %v\n", sha256x.String())
	bls.MulG1(&w, &bls.GenG1, &sha256x) //w=H(x)=g^sha256(x)
	bls.MulG1(&W, &w, &dski)            //W=w^dski
	r := bls.RandomFr()
	bls.MulG1(&Wr, &w, r) //Wr=w^r

	//fmt.Println("Wr: ", Wr.String())

	//we use sha256 to build the hash function H2(x): {0,1}* -> Zp
	msg := W.String() + w.String() + dvki.String() + bls.GenG1.String() + Wr.String()
	hashedMsg := sha256.Sum256([]byte(msg))
	//fmt.Println("hashedMsg: ", hex.EncodeToString(hashedMsg[:]))
	bls.SetFr16(&c, hex.EncodeToString(hashedMsg[:]))
	//bls.FrFrom32(&c, hashedMsg)

	//fmt.Println("c: ", c.String())

	var tmp bls.Fr
	bls.MulModFr(&tmp, &c, &dski)
	bls.SubModFr(&u, r, &tmp) //u=r-c*dski

	pi := newPiDPRF(w, c, u, dvki) //pi_dprf

	return W, pi
}

func VrfyContrib(W bls.G1Point, pi *PiDPRF) bool {
	var t bls.G1Point
	var tmp1 bls.G1Point
	var tmp2 bls.G1Point
	bls.MulG1(&tmp1, &pi.w, &pi.u)
	bls.MulG1(&tmp2, &W, &pi.c)
	bls.AddG1(&t, &tmp1, &tmp2) //t=w^u*W^c

	//fmt.Println("t: ", t.String())

	msg := W.String() + pi.w.String() + pi.dvki.String() + bls.GenG1.String() + t.String()

	var c bls.Fr
	hashedMsg := sha256.Sum256([]byte(msg))
	//fmt.Printf("hashedMsg: %v\n", hashedMsg)
	//fmt.Println("hashedMsg: ", hex.EncodeToString(hashedMsg[:]))
	bls.SetFr16(&c, hex.EncodeToString(hashedMsg[:]))
	//bls.FrFrom32(&c, hashedMsg)

	return bls.EqualFr(&c, &pi.c)
}

func Combine(p *party.HonestParty, f uint32, x []byte, I []bls.Fr, Wi []bls.G1Point, pi []*PiDPRF) (bls.Fr, error) {

	if uint32(len(I)) < f+1 {
		return bls.ZERO, errors.New("not enough DPRF contributions")
	}
	for i := uint32(0); i < f+1; i++ {
		if !VrfyContrib(Wi[i], pi[i]) {
			return bls.ZERO, errors.New("invalid contribution")
		}
	}

	//interpolate F(x) from {Wi=F_i(x)}, i=0...f
	tmp := p.InterpolateComOrWitByKnownIndexes(f, 0, I, Wi)
	// fmt.Println("tmp: ", tmp.String())

	//return H(F(x))
	hashedFx := sha256.Sum256([]byte(tmp.String()))
	var res bls.Fr
	// bls.FrFrom32(&res, hashBytes)
	bls.SetFr16(&res, hex.EncodeToString(hashedFx[:]))
	return res, nil
}

func Eval(x []byte, dsk bls.Fr) bls.Fr {
	var sha256x bls.Fr
	var Hx bls.G1Point
	var res bls.G1Point
	var resFr bls.Fr

	hashedBytes := sha256.Sum256(x)
	bls.SetFr16(&sha256x, hex.EncodeToString(hashedBytes[:]))
	// bls.FrFrom32(&sha256x, hashedBytes)
	bls.MulG1(&Hx, &bls.GenG1, &sha256x) //H(x)=g^sha256(x)
	bls.MulG1(&res, &Hx, &dsk)           //res=H(x)^dsk

	// fmt.Printf("res: %v\n", res.String())

	//hash res to Zp (Fr)
	hashedBytes = sha256.Sum256([]byte(res.String()))
	bls.SetFr16(&resFr, hex.EncodeToString(hashedBytes[:]))
	// bls.FrFrom32(&resFr, hashedBytes)
	return resFr
}
