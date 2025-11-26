package slsstray

import "sync"

//go:generate go tool mockgen -source merkleroot_store.go -destination mock_merkleroot_generator.go -package slsstray
type merkleRootGenerator interface {
	GetMerkleRoot() string
}

type MerkleRootStore struct {
	mu        sync.RWMutex
	generator merkleRootGenerator
}

var merkleRootStore *MerkleRootStore

func init() {
	merkleRootStore = &MerkleRootStore{}
}

// SetGenerator sets the generator instance
func (ms *MerkleRootStore) SetGenerator(gen merkleRootGenerator) {
	ms.mu.Lock()
	defer ms.mu.Unlock()
	ms.generator = gen
}

// GetMerkleRoot returns the current merkle root from the generator
func (ms *MerkleRootStore) GetMerkleRoot() string {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if ms.generator == nil {
		return ""
	}
	return ms.generator.GetMerkleRoot()
}

// Package-level convenience functions
func SetMerkleRootStore(gen merkleRootGenerator) {
	merkleRootStore.SetGenerator(gen)
}

func GetMerkleRoot() string {
	return merkleRootStore.GetMerkleRoot()
}
