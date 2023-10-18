package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"

	kbls "github.com/kilic/bls12-381"
	"github.com/opDPSSTeam/DPSS/internal/bls"
)

//Uint32ToBytes convert uint32 to bytes
func Uint32ToBytes(n uint32) []byte {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, n)
	return bytebuf.Bytes()
}

//BytesToUint32 convert bytes to uint32
func BytesToUint32(byt []byte) uint32 {
	bytebuff := bytes.NewBuffer(byt)
	var data uint32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return data
}

//Uint64ToBytes convert int64 to bytes
func Uint64ToBytes(n uint64) []byte {
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, n)
	return bytebuf.Bytes()
}

//BytesToUint64 convert bytes to int64
func BytesToUint64(byt []byte) uint64 {
	bytebuff := bytes.NewBuffer(byt)
	var data uint64
	binary.Read(bytebuff, binary.BigEndian, &data)
	return data
}

//BytesToInt convert bytes to int
func BytesToInt(byt []byte) int {
	bytebuff := bytes.NewBuffer(byt)
	var data uint32
	binary.Read(bytebuff, binary.BigEndian, &data)
	return int(data)
}

//IntToBytes convert int to bytes
func IntToBytes(n int) []byte {
	data := uint32(n)
	bytebuf := bytes.NewBuffer([]byte{})
	binary.Write(bytebuf, binary.BigEndian, data)
	return bytebuf.Bytes()
}

func DeleteZero(src []byte) []byte {
	length := len(src)
	for i := length - 1; i >= 0; i-- {
		if src[i] == byte(0) {
			src = src[0:i] // delete the last element
		} else {
			break
		}
	}
	return src
}

func DeleteZeroWithLen(src []byte, len int) []byte {
	return src[0:len]
}

// SliceToArray will convert byte slice to a 32 byte array
func SliceToArray(bytes []byte) [32]byte {
	var byteArray [32]byte
	copy(byteArray[:], bytes)
	return byteArray
}

// HashG1ToFr map bls.G1Point to kbls.Fr using sha256
func HashG1ToFr(g *bls.G1Point) *kbls.Fr {
	str := sha256.Sum256([]byte(g.String()))
	var bv big.Int
	bv.SetString(hex.EncodeToString(str[:]), 16)
	return kbls.NewFr().RedFromBytes(bv.Bytes())
}

func HashG2ToFr(g *bls.G2Point) *kbls.Fr {
	str := sha256.Sum256([]byte(g.String()))
	var bv big.Int
	bv.SetString(hex.EncodeToString(str[:]), 16)
	return kbls.NewFr().RedFromBytes(bv.Bytes())
}

func HashByteToFr(b []byte) *kbls.Fr {
	str := sha256.Sum256(b)
	var bv big.Int
	bv.SetString(hex.EncodeToString(str[:]), 16)
	return kbls.NewFr().RedFromBytes(bv.Bytes())
}
