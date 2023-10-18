/*
forked from https://github.com/protolambda/go-kzg on 29 May, 2023
*/
package polycommit

import (
	"fmt"
	"strings"

	"github.com/opDPSSTeam/DPSS/internal/bls"
)

func DebugFrPtrs(msg string, values []*bls.Fr) {
	var out strings.Builder
	out.WriteString("---")
	out.WriteString(msg)
	out.WriteString("---\n")
	for i := range values {
		out.WriteString(fmt.Sprintf("#%4d: %s\n", i, bls.FrStr(values[i])))
	}
	fmt.Println(out.String())
}

func DebugFrs(msg string, values []bls.Fr) {
	fmt.Println("---------------------------")
	var out strings.Builder
	for i := range values {
		out.WriteString(fmt.Sprintf("%s %d: %s\n", msg, i, bls.FrStr(&values[i])))
	}
	fmt.Print(out.String())
}
