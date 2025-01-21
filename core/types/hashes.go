// Copyright 2023 The go-ethereum Authors
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
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/crypto"
	"github.com/zircuit-labs/l2-geth-public/crypto/poseidon"
)

var (
	// EmptyZkTrieRootHash is the known root hash of an empty zktrie.
	EmptyZkTrieRootHash = common.Hash{}

	// EmptyLegacyTrieRootHash is the known root hash of an empty legacy trie.
	EmptyLegacyTrieRootHash = common.HexToHash("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")

	// EmptyUncleHash is the known hash of the empty uncle set.
	EmptyUncleHash = rlpHash([]*Header(nil)) // 1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347

	// EmptyKeccakCodeHash is the known Keccak hash of the empty EVM bytecode.
	EmptyKeccakCodeHash = crypto.Keccak256Hash(nil) // c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470

	// EmptyPoseidonCodeHash is the known Poseidon hash of the empty EVM bytecode.
	EmptyPoseidonCodeHash = poseidon.CodeHash(nil)

	// EmptyTxsHash is the known hash of the empty transaction set.
	EmptyTxsHash = EmptyLegacyTrieRootHash

	// EmptyReceiptsHash is the known hash of the empty receipt set.
	EmptyReceiptsHash = EmptyLegacyTrieRootHash

	// EmptyWithdrawalsHash is the known hash of the empty withdrawal set.
	EmptyWithdrawalsHash = EmptyLegacyTrieRootHash

	// EmptyVerkleHash is the known hash of an empty verkle trie.
	EmptyVerkleHash = common.Hash{}
)

// IsEmptyTrieRoot compares the given hash to both Trie and ZKTrie empty roots.
// It is safe to use without knowing the trie type: EmptyLegacyTrieRootHash
// cannot be calculated by Poseidon in ZKTrie, and EmptyZkTrieRootHash is
// extremely unlikely to appear.
func IsEmptyTrieRoot(hash common.Hash) bool {
	return hash == EmptyLegacyTrieRootHash || hash == EmptyZkTrieRootHash
}

func EmptyConditionalRootHash(isZkTrie bool) common.Hash {
	if isZkTrie {
		return EmptyZkTrieRootHash
	}
	return EmptyLegacyTrieRootHash
}
