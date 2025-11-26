// Copyright 2014 The go-ethereum Authors
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

// Package legacypool implements the normal EVM execution transaction pool.
package legacypool

// This file contains the test helpers for the legacy transaction pool.
// It was necessary to move this out of the _test file as outside packages
// need to be able to use the test helpers.

import (
	"context"
	"crypto/ecdsa"
	"math/big"
	"sync"
	"sync/atomic"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/consensus"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/rawdb"
	sls "github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/txpool"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/event"
	"github.com/zircuit-labs/l2-geth/params"
	"github.com/zircuit-labs/l2-geth/trie"
	"github.com/zircuit-labs/l2-geth/triedb"
)

// testTxPoolConfig is a transaction pool configuration without stateful disk
// sideeffects used during testing.
var testTxPoolConfig Config

func init() {
	testTxPoolConfig = DefaultConfig
	testTxPoolConfig.Journal = ""
}

type testBlockChain struct {
	config        *params.ChainConfig
	gasLimit      atomic.Uint64
	statedb       *state.StateDB
	chainHeadFeed *event.Feed
}

func (bc *testBlockChain) Config() *params.ChainConfig {
	return bc.config
}

func (bc *testBlockChain) CurrentBlock() *types.Header {
	return &types.Header{
		Number:     new(big.Int),
		Difficulty: common.Big0,
		GasLimit:   bc.gasLimit.Load(),
	}
}

func (bc *testBlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return types.NewBlock(bc.CurrentBlock(), nil, nil, nil, trie.NewStackTrie(nil))
}

func (bc *testBlockChain) StateAt(common.Hash) (*state.StateDB, error) {
	return bc.statedb, nil
}

func (bc *testBlockChain) SubscribeChainHeadEvent(ch chan<- core.ChainHeadEvent) event.Subscription {
	return bc.chainHeadFeed.Subscribe(ch)
}

func (bc *testBlockChain) Engine() consensus.Engine {
	// Not used in tests at this time
	panic("not implemented")
}

func (bc *testBlockChain) GetHeader(hash common.Hash, number uint64) *types.Header {
	// Not used in tests at this time
	panic("not implemented")
}

func newTestBlockChain(config *params.ChainConfig, gasLimit uint64, statedb *state.StateDB) *testBlockChain {
	bc := testBlockChain{config: config, statedb: statedb, chainHeadFeed: new(event.Feed)}
	bc.gasLimit.Store(gasLimit)
	return &bc
}

func SetupTestPool() (*LegacyPool, *ecdsa.PrivateKey) {
	return SetupTestPoolWithConfig(params.TestChainConfig)
}

func SetupTestPoolWithConfig(config *params.ChainConfig) (*LegacyPool, *ecdsa.PrivateKey) {
	var dbconfig *triedb.Config
	emptyRoot := types.EmptyRootHash
	db := rawdb.NewMemoryDatabase()
	statedb, _ := state.New(emptyRoot, state.NewDatabase(triedb.NewDatabase(db, dbconfig), nil))

	blockchain := newTestBlockChain(config, 10000000, statedb)

	key, _ := crypto.GenerateKey()
	pool := New(testTxPoolConfig, blockchain, sls.DisabledConfig, sls.DisabledRefreshables)
	if err := pool.Init(context.Background(), testTxPoolConfig.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		panic(err)
	}
	// wait for the pool to initialize
	<-pool.initDoneCh
	return pool, key
}

// reserver is a utility struct to sanity check that accounts are
// properly reserved by the blobpool (no duplicate reserves or unreserves).
type reserver struct {
	accounts map[common.Address]struct{}
	lock     sync.RWMutex
}

func newReserver() txpool.Reserver {
	return &reserver{accounts: make(map[common.Address]struct{})}
}

func (r *reserver) Hold(addr common.Address) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, exists := r.accounts[addr]; exists {
		panic("already reserved")
	}
	r.accounts[addr] = struct{}{}
	return nil
}

func (r *reserver) Release(addr common.Address) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, exists := r.accounts[addr]; !exists {
		panic("not reserved")
	}
	delete(r.accounts, addr)
	return nil
}

func (r *reserver) Has(address common.Address) bool {
	return false // reserver only supports a single pool
}
