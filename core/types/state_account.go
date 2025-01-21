// Copyright 2021 The go-ethereum Authors
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

package types

import (
	"bytes"

	"github.com/holiman/uint256"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/rlp"
)

//go:generate go run ../../rlp/rlpgen -type StateAccount -out gen_account_rlp.go

// StateAccount is the Ethereum consensus representation of accounts.
// These objects are stored in the main account trie.
type StateAccount struct {
	Nonce          uint64       `json:"nonce"       gencodec:"required"`
	Balance        *uint256.Int `json:"balance"`
	Root           common.Hash  `json:"root" gencodec:"required"` // merkle root of the storage trie
	KeccakCodeHash []byte       `json:"keccakCodeHash" gencodec:"required"`

	// Values added for zkTrie use
	PoseidonCodeHash []byte `json:"poseidonCodeHash,omitempty" rlp:"optional"`
	CodeSize         uint64 `json:"codeSize,omitempty" rlp:"optional"`
}

// NewEmptyStateAccount constructs an empty state account. ZkTrie flag affects zero values to be used.
func NewEmptyStateAccount(isZkTrie bool) *StateAccount {
	s := &StateAccount{
		Balance:        new(uint256.Int),
		Root:           EmptyLegacyTrieRootHash,
		KeccakCodeHash: EmptyKeccakCodeHash.Bytes(),
	}
	if isZkTrie {
		s.Root = EmptyZkTrieRootHash
		s.PoseidonCodeHash = EmptyPoseidonCodeHash.Bytes()
		s.CodeSize = 0
	}
	return s
}

// Copy returns a deep-copied state account object.
func (acct *StateAccount) Copy() *StateAccount {
	var balance *uint256.Int
	if acct.Balance != nil {
		balance = new(uint256.Int).Set(acct.Balance)
	}
	return &StateAccount{
		Nonce:            acct.Nonce,
		Balance:          balance,
		Root:             acct.Root,
		KeccakCodeHash:   common.CopyBytes(acct.KeccakCodeHash),
		PoseidonCodeHash: common.CopyBytes(acct.PoseidonCodeHash),
		CodeSize:         acct.CodeSize,
	}
}

// IsZkTrie reports whether it's a ZKTrie account based on Poseidon code hash
// value, which is set only on ZKTrie accounts.
func (acct *StateAccount) IsZkTrie() bool {
	return len(acct.PoseidonCodeHash) > 0 && !bytes.Equal(acct.PoseidonCodeHash, (common.Hash{}).Bytes())
}

// SlimAccount is a modified version of an Account, where the root is replaced
// with a byte slice. This format can be used to represent full-consensus format
// or slim format which replaces the empty root and code hash as nil byte slice.
type SlimAccount struct {
	Nonce            uint64
	Balance          *uint256.Int
	Root             []byte // Nil if types.IsEmptyTrieRoot(Root)
	KeccakCodeHash   []byte // Nil if keccakCodeHash equals to types.EmptyKeccakCodeHash
	PoseidonCodeHash []byte `rlp:"optional"`
	CodeSize         uint64 `rlp:"optional"`
}

// SlimAccountRLP encodes the state account in 'slim RLP' format.
func SlimAccountRLP(account StateAccount) []byte {
	slim := SlimAccount{
		Nonce:   account.Nonce,
		Balance: account.Balance,
	}
	if !IsEmptyTrieRoot(account.Root) {
		slim.Root = account.Root[:]
	}
	if !bytes.Equal(account.KeccakCodeHash, EmptyKeccakCodeHash[:]) {
		slim.KeccakCodeHash = account.KeccakCodeHash
		slim.PoseidonCodeHash = account.PoseidonCodeHash
		slim.CodeSize = account.CodeSize
	}
	data, err := rlp.EncodeToBytes(slim)
	if err != nil {
		panic(err)
	}
	return data
}

// FullAccount decodes the data on the 'slim RLP' format and returns
// the consensus format account.
func FullAccount(data []byte) (*StateAccount, error) {
	var slim SlimAccount
	if err := rlp.DecodeBytes(data, &slim); err != nil {
		return nil, err
	}
	var account StateAccount
	account.Nonce, account.Balance = slim.Nonce, slim.Balance

	// Interpret the storage root and code hash in slim format.
	isZkTrie := len(slim.PoseidonCodeHash) > 0 && !bytes.Equal(slim.PoseidonCodeHash, (common.Hash{}).Bytes())
	if len(slim.Root) == 0 {
		account.Root = EmptyLegacyTrieRootHash
		if isZkTrie {
			account.Root = EmptyZkTrieRootHash
		}
	} else {
		account.Root = common.BytesToHash(slim.Root)
	}
	if len(slim.KeccakCodeHash) == 0 {
		account.KeccakCodeHash = EmptyKeccakCodeHash[:]
		if isZkTrie {
			account.PoseidonCodeHash = EmptyPoseidonCodeHash[:]
			account.CodeSize = 0
		}
	} else {
		account.KeccakCodeHash = slim.KeccakCodeHash
		account.PoseidonCodeHash = slim.PoseidonCodeHash
		account.CodeSize = slim.CodeSize
	}

	return &account, nil
}

// FullAccountRLP converts data on the 'slim RLP' format into the full RLP-format.
func FullAccountRLP(data []byte) ([]byte, error) {
	account, err := FullAccount(data)
	if err != nil {
		return nil, err
	}
	return rlp.EncodeToBytes(account)
}
