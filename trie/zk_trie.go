// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"fmt"

	zktrie "github.com/scroll-tech/zktrie/trie"
	zkt "github.com/scroll-tech/zktrie/types"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/crypto/poseidon"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/trie/trienode"
)

var magicHash = []byte("THIS IS THE MAGIC INDEX FOR ZKTRIE")

// wrap zktrie for trie interface
type ZkTrie struct {
	*zktrie.ZkTrie
	db *ZktrieDatabase
}

func init() {
	zkt.InitHashScheme(poseidon.HashFixedWithDomain)
}

func sanityCheckByte32Key(b []byte) {
	if len(b) != 32 && len(b) != 20 {
		panic(fmt.Errorf("do not support length except for 120bit and 256bit now. data: %v len: %v", b, len(b)))
	}
}

func NewZkTrie(root common.Hash, db *ZktrieDatabase) (*ZkTrie, error) {
	tr, err := zktrie.NewZkTrie(*zkt.NewByte32FromBytes(root.Bytes()), db)
	if err != nil {
		return nil, err
	}
	return &ZkTrie{tr, db}, nil
}

// Get returns the value for key stored in the trie.
// The value bytes must not be modified by the caller.
func (t *ZkTrie) Get(key []byte) []byte {
	sanityCheckByte32Key(key)
	res, err := t.TryGet(key)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	return res
}

func (t *ZkTrie) GetAccount(address common.Address) (*types.StateAccount, error) {
	key := address.Bytes()
	sanityCheckByte32Key(key)
	res, err := t.TryGet(key)
	if res == nil || err != nil {
		return nil, err
	}
	return types.UnmarshalStateAccount(res)
}

func (t *ZkTrie) GetStorage(_ common.Address, key []byte) ([]byte, error) {
	sanityCheckByte32Key(key)
	return t.TryGet(key)
}

func (t *ZkTrie) UpdateAccount(address common.Address, acc *types.StateAccount) error {
	return t.TryUpdateAccount(address.Bytes(), acc)
}

// TryUpdateAccount will abstract the write of an account to the
// secure trie.
func (t *ZkTrie) TryUpdateAccount(key []byte, acc *types.StateAccount) error {
	sanityCheckByte32Key(key)
	value, flag := acc.MarshalFields()
	return t.ZkTrie.TryUpdate(key, flag, value)
}

// Update associates key with value in the trie. Subsequent calls to
// Get will return value. If value has length zero, any existing value
// is deleted from the trie and calls to Get will return nil.
//
// The value bytes must not be modified by the caller while they are
// stored in the trie.
func (t *ZkTrie) Update(key, value []byte) {
	if err := t.TryUpdate(key, value); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

// NOTE: value is restricted to length of bytes32.
// we override the underlying zktrie's TryUpdate method
func (t *ZkTrie) TryUpdate(key, value []byte) error {
	sanityCheckByte32Key(key)
	return t.ZkTrie.TryUpdate(key, 1, []zkt.Byte32{*zkt.NewByte32FromBytes(value)})
}

func (t *ZkTrie) UpdateStorage(_ common.Address, key, value []byte) error {
	return t.TryUpdate(key, value)
}

// Delete removes any existing value for key from the trie.
func (t *ZkTrie) Delete(key []byte) {
	sanityCheckByte32Key(key)
	if err := t.TryDelete(key); err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
}

func (t *ZkTrie) DeleteAccount(address common.Address) error {
	key := address.Bytes()
	sanityCheckByte32Key(key)
	return t.TryDelete(key)
}

func (t *ZkTrie) DeleteStorage(_ common.Address, key []byte) error {
	sanityCheckByte32Key(key)
	return t.TryDelete(key)
}

// GetKey returns the preimage of a hashed key that was
// previously used to store a value.
func (t *ZkTrie) GetKey(kHashBytes []byte) []byte {
	k, err := zkt.NewBigIntFromHashBytes(kHashBytes)
	if err != nil {
		log.Error(fmt.Sprintf("Unhandled trie error: %v", err))
	}
	if t.db.db.preimages != nil {
		return t.db.db.preimages.preimage(common.BytesToHash(k.Bytes()))
	}
	return nil
}

// Commit writes all dirty nodes and the secure hash pre-images to ZKTrie.
//
// Committing flushes nodes from memory. Subsequent Get calls will load nodes
// from the database.
//
// Warning: instead of other Trie implementations, ZkTrie.Commit() does not
// return the nodes due to the complicated implementation of shared interface for
// Trie and ZKTrie nodes.
func (t *ZkTrie) Commit(_ bool) (common.Hash, *trienode.NodeSet, error) {
	if err := t.ZkTrie.Commit(); err != nil {
		return common.Hash{}, nil, err
	}
	return t.Hash(), nil, nil
}

// Hash returns the root hash of SecureBinaryTrie. It does not write to the
// database and can be used even if the trie doesn't have one.
func (t *ZkTrie) Hash() common.Hash {
	var hash common.Hash
	hash.SetBytes(t.ZkTrie.Hash())
	return hash
}

// Copy returns a copy of SecureBinaryTrie.
func (t *ZkTrie) Copy() *ZkTrie {
	return &ZkTrie{t.ZkTrie.Copy(), t.db}
}

// NodeIterator returns an iterator that returns nodes of the underlying trie. Iteration
// starts at the key after the given start key.
func (t *ZkTrie) NodeIterator(start []byte) (NodeIterator, error) {
	/// FIXME
	panic("not implemented")
}

// Prove constructs a merkle proof for key. The result contains all encoded nodes
// on the path to the value at key. The value itself is also included in the last
// node and can be retrieved by verifying the proof.
//
// If the trie does not contain a value for key, the returned proof contains all
// nodes of the longest existing prefix of the key (at least the root node), ending
// with the node that proves the absence of the key.
func (t *ZkTrie) Prove(key []byte, proofDb ethdb.KeyValueWriter) error {
	fromLevel := uint(0)
	err := t.ZkTrie.Prove(key, fromLevel, func(n *zktrie.Node) error {
		nodeHash, err := n.NodeHash()
		if err != nil {
			return err
		}

		if n.Type == zktrie.NodeTypeLeaf_New {
			preImage := t.GetKey(n.NodeKey.Bytes())
			if len(preImage) > 0 {
				n.KeyPreimage = &zkt.Byte32{}
				copy(n.KeyPreimage[:], preImage)
			}
		}
		return proofDb.Put(nodeHash[:], n.Value())
	})
	if err != nil {
		return err
	}

	// we put this special kv pair in db so we can distinguish the type and
	// make suitable Proof
	return proofDb.Put(magicHash, zktrie.ProofMagicBytes())
}

// VerifyProof checks merkle proofs. The given proof must contain the value for
// key in a trie with the given root hash. VerifyProof returns an error if the
// proof contains invalid trie nodes or the wrong value.
func VerifyProofSMT(rootHash common.Hash, key []byte, proofDb ethdb.KeyValueReader) (value []byte, err error) {
	h := zkt.NewHashFromBytes(rootHash.Bytes())
	k, err := zkt.ToSecureKey(key)
	if err != nil {
		return nil, err
	}

	proof, n, err := zktrie.BuildZkTrieProof(h, k, len(key)*8, func(key *zkt.Hash) (*zktrie.Node, error) {
		buf, _ := proofDb.Get(key[:])
		if buf == nil {
			return nil, zktrie.ErrKeyNotFound
		}
		n, err := zktrie.NewNodeFromBytes(buf)
		return n, err
	})

	if err != nil {
		// does not contain the key
		return nil, err
	} else if !proof.Existence {
		return nil, nil
	}

	if zktrie.VerifyProofZkTrie(h, proof, n) {
		return n.Data(), nil
	} else {
		return nil, fmt.Errorf("bad proof node %v", proof)
	}
}
