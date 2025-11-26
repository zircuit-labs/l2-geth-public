package slsstray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

var (
	ErrNoSnapshot = errors.New("snapshot is nil")
)

// MerkleRootGenerator computes merkle roots using sha256
// merkle root over byte slices
//
//	root
//	/  \
//
// []byte []byte
type MerkleRootGenerator struct {
	merkleRoot string
}

func NewMerklerootGenerator(mr string) *MerkleRootGenerator {
	return &MerkleRootGenerator{merkleRoot: mr}
}

func (m *MerkleRootGenerator) GetMerkleRoot() string {
	return m.merkleRoot
}

// hashPair hashes two byte slices together
func (m *MerkleRootGenerator) hashPair(a, b []byte) []byte {
	h := sha256.New()
	h.Write(a)
	h.Write(b)
	return h.Sum(nil)
}

// MerkleRoot computes the Merkle root from a slice of data blocks
func (m *MerkleRootGenerator) MerkleRoot(data [][]byte) []byte {
	if len(data) == 0 {
		return sha256.New().Sum(nil)
	}

	// Hash all leaves first
	var level [][]byte
	for _, d := range data {
		hash := sha256.Sum256(d)
		level = append(level, hash[:])
	}

	// Build the tree
	for len(level) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// Odd count: duplicate last element
				nextLevel = append(nextLevel, m.hashPair(level[i], level[i]))
			} else {
				nextLevel = append(nextLevel, m.hashPair(level[i], level[i+1]))
			}
		}
		level = nextLevel
	}

	return level[0]
}

func (m *MerkleRootGenerator) SnapshotMerkleRoot(snapshot *Snapshot) (string, int64, error) {
	var root string
	if snapshot == nil {
		return root, 0, ErrNoSnapshot
	}

	// merge admin and quarantine data into slice of bytes
	data := make([][]byte, 0, len(snapshot.Admin)+len(snapshot.Quarantine))

	for _, admin := range snapshot.Admin {
		marshaled, err := json.Marshal(admin)
		if err != nil {
			return root, 0, err
		}
		data = append(data, marshaled)
	}
	for _, quarantine := range snapshot.Quarantine {
		marshaled, err := json.Marshal(quarantine)
		if err != nil {
			return root, 0, err
		}
		data = append(data, marshaled)
	}

	// generate merkle root
	start := time.Now()
	merkleRoot := hex.EncodeToString(m.MerkleRoot(data))
	elapsedMs := time.Since(start).Milliseconds()
	return merkleRoot, elapsedMs, nil
}
