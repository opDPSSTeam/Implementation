package pointproofs

/*
#cgo LDFLAGS: -L../pointproofs_target/release -lvc_api
#include <stdlib.h>
#include "./pointproofs.h"
*/
import "C"

import (
	"encoding/base64"
	"unsafe"

	kbls "github.com/kilic/bls12-381"
)

const MaxLength = 127

type VectorCommit struct {
	index uint32
	srs   string
}

func New(vectorLen uint32) *VectorCommit {
	if vectorLen < 4 || vectorLen > MaxLength || vectorLen%3 != 1 {
		return nil
	}
	index := (vectorLen - 4) / 3
	indexInput := C.int(index)
	return &VectorCommit{
		index: index,
		srs:   C.GoString(C.generate_params(indexInput)),
	}
}

func (vc *VectorCommit) GetIndex() uint32 {
	return vc.index
}

func (vc *VectorCommit) GetSrs() string {
	return vc.srs
}

func (vc *VectorCommit) SetIndex(index uint32) {
	vc.index = index
}

func (vc *VectorCommit) SetSrs(srs string) {
	vc.srs = srs
}

func frToString(fr *kbls.Fr) string {
	bytes := fr.ToBytes()
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

func stringToFr(s string) kbls.Fr {
	bytes, _ := base64.StdEncoding.DecodeString(s)
	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
		bytes[i], bytes[j] = bytes[j], bytes[i]
	}
	fr := kbls.Fr{}
	fr.FromBytes(bytes)
	return fr
}

func messagesToString(messages []kbls.Fr) string {
	res := ""
	for _, i := range messages {
		res += frToString(&i)
		res += ";"
	}
	return res
}

func (v *VectorCommit) Commit(messages []kbls.Fr) string {
	indexInput := C.int(v.index)
	srsInput := C.CString(v.srs)
	defer C.free(unsafe.Pointer(srsInput))
	messagesStr := messagesToString(messages)
	messagesInput := C.CString(messagesStr)
	defer C.free(unsafe.Pointer(messagesInput))
	output := C.GoString(C.commit(indexInput, srsInput, messagesInput))
	return output
}

func (v *VectorCommit) Open(messages []kbls.Fr, pos int) string {
	indexInput := C.int(v.index)
	messagesStr := messagesToString(messages)
	srsInput := C.CString(v.srs)
	defer C.free(unsafe.Pointer(srsInput))
	messagesInput := C.CString(messagesStr)
	defer C.free(unsafe.Pointer(messagesInput))
	posInput := C.int(pos)
	output := C.GoString(C.open_(indexInput, srsInput, messagesInput, posInput))
	return output
}

func (v *VectorCommit) Verify(commitment string, message kbls.Fr, pos int, witness string) bool {
	indexInput := C.int(v.index)

	srsInput := C.CString(v.srs)
	defer C.free(unsafe.Pointer(srsInput))

	commitmentInput := C.CString(commitment)
	defer C.free(unsafe.Pointer(commitmentInput))

	messageStr := frToString(&message)
	messageInput := C.CString(messageStr)
	defer C.free(unsafe.Pointer(messageInput))

	posInput := C.int(pos)

	witnessInput := C.CString(witness)
	defer C.free(unsafe.Pointer(witnessInput))
	output := C.verify(indexInput, srsInput, commitmentInput, messageInput, posInput, witnessInput)
	return output != 0
}
