package vectorcommitment

import (
	"bytes"
	"crypto/sha256"

	m "github.com/cbergoon/merkletree"
)

// implement of m.Content
type implContent struct {
	x []byte
}

func buildImplContent(x []byte) *implContent {
	return &implContent{x: x}
}

func (i *implContent) CalculateHash() ([]byte, error) {
	hash := sha256.Sum256(i.x)
	return hash[:], nil
}

func (i *implContent) Equals(other m.Content) (bool, error) {
	hash1, _ := other.CalculateHash()
	hash2, _ := i.CalculateHash()
	if bytes.Equal(hash1, hash2) {
		return true, nil
	}
	return false, nil
}

//MerkleTree is a kind of vector commitment
type MerkleTree struct {
	mktree   *m.MerkleTree
	contents []m.Content
}

type PiVcomMerkle struct {
	Path      [][]byte
	Indicator []int64
}

//NewMerkleTree generates a merkletree
func NewMerkleTree(data [][]byte) (*MerkleTree, error) {
	contents := []m.Content{}
	for _, d := range data {
		c := buildImplContent(d)
		contents = append(contents, c)
	}
	mk, err := m.NewTreeWithHashStrategy(contents, sha256.New)
	if err != nil {
		return nil, err
	}
	return &MerkleTree{
		mktree:   mk,
		contents: contents,
	}, nil
}

//GetMerkleTreeRoot returns a merkletree root
func (t *MerkleTree) GetMerkleTreeRoot() []byte {
	return t.mktree.MerkleRoot()
}

//GetMerkleTreeProof returns a Path and indicator as proof
func (t *MerkleTree) GetMerkleTreeProof(id int) ([][]byte, []int64) {
	path, indicator, _ := t.mktree.GetMerklePath(t.contents[id])
	return path, indicator
}

//GetMerkleTreeProofPi returns a PiVcom as proof
func (t *MerkleTree) GetMerkleTreeProofPi(id int) PiVcomMerkle {
	path, indicator, _ := t.mktree.GetMerklePath(t.contents[id])
	return PiVcomMerkle{Path: path, Indicator: indicator}
}

func VerifyMerkleTreeProof(root []byte, proof [][]byte, indicator []int64, msg []byte) bool {
	if len(proof) != len(indicator) {
		return false
	}
	itHash, _ := (&implContent{x: msg}).CalculateHash()
	for i, p := range proof {
		s := sha256.New()
		if indicator[i] == 1 {
			s.Write(append(itHash, p...))
		} else if indicator[i] == 0 {
			s.Write(append(p, itHash...))
		} else {
			return false
		}
		itHash = s.Sum(nil)
	}
	return bytes.Equal(itHash, root)
}

func i64tob(val uint64) []byte {
	r := make([]byte, 8)
	for i := 0; i < 8; i++ {
		r[i] = byte((val >> (8 * i)) & 0xff)
	}
	return r
}
