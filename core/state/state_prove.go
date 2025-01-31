package state

import (
	"fmt"

	zkt "github.com/scroll-tech/zktrie/types"

	zktrie "github.com/zircuit-labs/l2-geth-public/trie"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/crypto"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
)

type TrieProve interface {
	Prove(key []byte, proofDb ethdb.KeyValueWriter) error
}

type ZktrieProofTracer struct {
	*zktrie.ProofTracer
}

// MarkDeletion overwrite the underlayer method with secure key
func (t ZktrieProofTracer) MarkDeletion(key common.Hash) {
	key_s, _ := zkt.ToSecureKeyBytes(key.Bytes())
	t.ProofTracer.MarkDeletion(key_s.Bytes())
}

// Merge overwrite underlayer method with proper argument
func (t ZktrieProofTracer) Merge(another ZktrieProofTracer) {
	t.ProofTracer.Merge(another.ProofTracer)
}

func (t ZktrieProofTracer) Available() bool {
	return t.ProofTracer != nil
}

func (t ZktrieProofTracer) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	return t.ProofTracer.Prove(key, proofDb)
}

// NewProofTracer is not in Db interface and used explictily for reading proof in storage trie (not updated by the dirty value)
func (s *StateDB) NewProofTracer(trieS Trie) ZktrieProofTracer {
	if s.IsZktrie() {
		zkTrie := trieS.(*zktrie.ZkTrie)
		if zkTrie == nil {
			panic("unexpected trie type for zktrie")
		}
		return ZktrieProofTracer{zkTrie.NewProofTracer()}
	}
	return ZktrieProofTracer{}
}

// GetStorageTrieForProof is not in Db interface and used explictily for reading proof in storage trie (not updated by the dirty value)
func (s *StateDB) GetStorageTrieForProof(addr common.Address) (Trie, error) {
	// try the trie in stateObject first, else we would create one
	stateObject := s.getStateObject(addr)
	if stateObject == nil {
		// still return a empty trie
		dummy_trie, _ := s.db.OpenStorageTrie(s.GetRootHash(), addr, common.Hash{}, s.trie)
		return dummy_trie, nil
	}

	trie := stateObject.trie
	var err error
	if trie == nil {
		// use a new, temporary trie
		trie, err = s.db.OpenStorageTrie(s.GetRootHash(), stateObject.Address(), stateObject.data.Root, s.trie)
		if err != nil {
			return nil, fmt.Errorf("can't create storage trie on root %s: %v ", stateObject.data.Root, err)
		}
	}

	return trie, nil
}

// GetSecureTrieProof handle any interface with Prove (should be a Trie in most case) and
// deliver the proof in bytes
func (s *StateDB) GetSecureTrieProof(trieProve TrieProve, key common.Hash) ([][]byte, error) {
	var proof proofList
	var err error
	if s.IsZktrie() {
		key_s, _ := zkt.ToSecureKeyBytes(key.Bytes())
		err = trieProve.Prove(key_s.Bytes(), &proof)
	} else {
		err = trieProve.Prove(crypto.Keccak256(key.Bytes()), &proof)
	}
	return proof, err
}
