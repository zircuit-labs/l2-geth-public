// Copyright 2020 The go-ethereum Authors
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

// Package miner implements Ethereum block creation and mining.
package miner

import (
	"context"
	"math/big"
	"sync"
	"testing"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/consensus"
	"github.com/zircuit-labs/l2-geth/consensus/clique"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/rawdb"
	"github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/txpool"
	"github.com/zircuit-labs/l2-geth/core/txpool/legacypool"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/ethdb"
	"github.com/zircuit-labs/l2-geth/event"
	"github.com/zircuit-labs/l2-geth/params"
	"github.com/zircuit-labs/l2-geth/trie"
	"github.com/zircuit-labs/l2-geth/triedb"
)

type mockBackend struct {
	bc     *core.BlockChain
	txPool *txpool.TxPool

	// OP-Stack additions
	supervisorInFailsafe bool
	queryFailsafeCb      func()
}

func NewMockBackend(bc *core.BlockChain, txPool *txpool.TxPool,
	supervisorInFailsafe bool, // OP-Stack addition
	queryFailsafeCb func(), // OP-Stack addition
) *mockBackend {
	return &mockBackend{
		bc:     bc,
		txPool: txPool,

		// OP-Stack addition
		supervisorInFailsafe: supervisorInFailsafe,
		queryFailsafeCb:      queryFailsafeCb,
	}
}

func (m *mockBackend) BlockChain() *core.BlockChain {
	return m.bc
}

func (m *mockBackend) TxPool() *txpool.TxPool {
	return m.txPool
}

func (m *mockBackend) ChainDb() ethdb.Database {
	return nil
}

// OP-Stack additions
func (m *mockBackend) GetSupervisorFailsafe() bool {
	return m.supervisorInFailsafe
}

func (m *mockBackend) QueryFailsafe(ctx context.Context) (bool, error) {
	if m.queryFailsafeCb != nil {
		m.queryFailsafeCb()
	}
	return m.supervisorInFailsafe, nil
}

type testBlockChain struct {
	root          common.Hash
	config        *params.ChainConfig
	statedb       *state.StateDB
	gasLimit      uint64
	chainHeadFeed *event.Feed
}

func (bc *testBlockChain) Config() *params.ChainConfig {
	return bc.config
}

func (bc *testBlockChain) CurrentBlock() *types.Header {
	return &types.Header{
		Number:     new(big.Int),
		GasLimit:   bc.gasLimit,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: common.Big0,
	}
}

func (bc *testBlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return types.NewBlock(bc.CurrentBlock(), nil, nil, nil, trie.NewStackTrie(nil))
}

func (bc *testBlockChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	return types.NewBlock(bc.CurrentBlock(), nil, nil, nil, trie.NewStackTrie(nil)).Header()
}

func (bc *testBlockChain) StateAt(common.Hash) (*state.StateDB, error) {
	return bc.statedb, nil
}

func (bc *testBlockChain) HasState(root common.Hash) bool {
	return bc.root == root
}

func (bc *testBlockChain) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return bc.chainHeadFeed.Subscribe(ch)
}

func (bc *testBlockChain) Engine() consensus.Engine {
	return nil
}

func TestBuildPendingBlocks(t *testing.T) {
	miner := createMiner(t)
	var wg sync.WaitGroup
	wg.Go(func() {
		block, _, _ := miner.Pending()
		if block == nil {
			t.Error("Pending failed")
		}
	})
	wg.Wait()
}

func minerTestGenesisBlock(period uint64, gasLimit uint64, faucet common.Address) *core.Genesis {
	config := *params.AllCliqueProtocolChanges
	config.Clique = &params.CliqueConfig{
		Period: period,
		Epoch:  config.Clique.Epoch,
	}

	// Assemble and return the genesis with the precompiles and faucet pre-funded
	return &core.Genesis{
		Config:     &config,
		ExtraData:  append(append(make([]byte, 32), faucet[:]...), make([]byte, crypto.SignatureLength)...),
		GasLimit:   gasLimit,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: big.NewInt(1),
		Alloc: map[common.Address]types.Account{
			common.BytesToAddress([]byte{1}): {Balance: big.NewInt(1)}, // ECRecover
			common.BytesToAddress([]byte{2}): {Balance: big.NewInt(1)}, // SHA256
			common.BytesToAddress([]byte{3}): {Balance: big.NewInt(1)}, // RIPEMD
			common.BytesToAddress([]byte{4}): {Balance: big.NewInt(1)}, // Identity
			common.BytesToAddress([]byte{5}): {Balance: big.NewInt(1)}, // ModExp
			common.BytesToAddress([]byte{6}): {Balance: big.NewInt(1)}, // ECAdd
			common.BytesToAddress([]byte{7}): {Balance: big.NewInt(1)}, // ECScalarMul
			common.BytesToAddress([]byte{8}): {Balance: big.NewInt(1)}, // ECPairing
			common.BytesToAddress([]byte{9}): {Balance: big.NewInt(1)}, // BLAKE2b
			faucet:                           {Balance: new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(9))},
		},
	}
}

func createMiner(t *testing.T) *Miner {
	// Create Ethash config
	config := Config{
		PendingFeeRecipient: common.HexToAddress("123456789"),
	}
	// Create chainConfig
	chainDB := rawdb.NewMemoryDatabase()
	triedb := triedb.NewDatabase(chainDB, nil)
	genesis := minerTestGenesisBlock(15, 11_500_000, testBankAddress)
	chainConfig, _, err := core.SetupGenesisBlock(chainDB, triedb, genesis)
	if err != nil {
		t.Fatalf("can't create new chain config: %v", err)
	}
	// Create consensus engine
	engine := clique.New(chainConfig.Clique, chainDB)
	// Create Ethereum backend
	bc, err := core.NewBlockChain(chainDB, genesis, engine, nil)
	if err != nil {
		t.Fatalf("can't create new chain %v", err)
	}
	statedb, _ := state.New(bc.Genesis().Root(), bc.StateCache())
	blockchain := &testBlockChain{bc.Genesis().Root(), chainConfig, statedb, 10000000, new(event.Feed)}

	pool := legacypool.New(testTxPoolConfig, blockchain, sls.DisabledConfig, sls.DisabledRefreshables)
	txpool, _ := txpool.New(testTxPoolConfig.PriceLimit, blockchain, []txpool.SubPool{pool})

	// Create Miner
	backend := NewMockBackend(bc, txpool, false, nil)
	miner := New(backend, &config, engine, sls.DisabledRefreshables)
	return miner
}
