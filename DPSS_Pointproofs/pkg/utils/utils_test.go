package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUtils(t *testing.T) {
	i := uint64(18446744073709551615)
	b := Uint64ToBytes(i)
	j := BytesToUint64(b)
	assert.True(t, i == j, "i!=j")
}
