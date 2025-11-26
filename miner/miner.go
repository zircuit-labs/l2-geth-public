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

// Package miner implements Ethereum block creation and mining.
package miner

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/common/hexutil"
	"github.com/zircuit-labs/l2-geth/consensus"
	"github.com/zircuit-labs/l2-geth/core"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	sls "github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/txpool"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/eth/tracers"
	"github.com/zircuit-labs/l2-geth/ethdb"
	"github.com/zircuit-labs/l2-geth/params"
)

// Backend wraps all methods required for mining. Only full node is capable
// to offer all the functions here.
type Backend interface {
	BlockChain() *core.BlockChain
	TxPool() *txpool.TxPool
	ChainDb() ethdb.Database
}

type BackendWithHistoricalState interface {
	StateAtBlock(ctx context.Context, block *types.Block, reexec uint64, base *state.StateDB, readOnly, preferDisk bool) (*state.StateDB, tracers.StateReleaseFunc, error)
}

// Config is the configuration parameters of mining.
type Config struct {
	Etherbase           common.Address `toml:",omitempty"` // Public address for block mining rewards
	PendingFeeRecipient common.Address `toml:"-"`          // Address for pending block rewards.
	ExtraData           hexutil.Bytes  `toml:",omitempty"` // Block extra data set by the miner
	GasFloor            uint64         // Target gas floor for mined blocks.
	GasCeil             uint64         // Target gas ceiling for mined blocks.
	GasPrice            *big.Int       // Minimum gas price for mining a transaction
	Recommit            time.Duration  // The time interval for miner to re-create mining work.

	EffectiveGasCeil uint64 // if non-zero, a gas ceiling to apply independent of the header's gaslimit value

	NewPayloadTimeout time.Duration // The maximum time allowance for creating a new payload

	RollupComputePendingBlock bool // Compute the pending block from tx-pool, instead of copying the latest-block

	TransactionLimit *uint64 // Maximum number of transactions to put into a block. If nil, blocks are gas-limited only. If set, blocks cannot exceed this transaction count.
}

// DefaultConfig contains default settings for miner.
var DefaultConfig = Config{
	GasCeil:  30000000,
	GasPrice: big.NewInt(params.GWei),

	// The default recommit time is chosen as two seconds since
	// consensus-layer usually will wait a half slot of time(6s)
	// for payload generation. It should be enough for Geth to
	// run 3 rounds.
	Recommit:          2 * time.Second,
	NewPayloadTimeout: 2 * time.Second,

	// Default to gas-based
	TransactionLimit: nil,
}

// Miner creates blocks and searches for proof-of-work values.
type Miner struct {
	confMu      sync.RWMutex // The lock used to protect the config fields: GasCeil, GasTip and Extradata
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	txpool      *txpool.TxPool
	prio        []common.Address // A list of senders to prioritize
	chain       *core.BlockChain
	pending     *pending
	pendingMu   sync.Mutex // Lock protects the pending block

	backend Backend

	lifeCtxCancel context.CancelFunc
	lifeCtx       context.Context

	getSLSRefreshables sls.RefreshableGetter
	slsWorker          slsCommon.Worker
}

func New(eth Backend, config *Config, engine consensus.Engine, getSLSRefreshables sls.RefreshableGetter) *Miner {
	ctx, cancel := context.WithCancel(context.Background())
	miner := &Miner{
		backend:     eth,
		config:      config,
		chainConfig: eth.BlockChain().Config(),
		engine:      engine,
		txpool:      eth.TxPool(),
		chain:       eth.BlockChain(),
		pending:     &pending{},
		// To interrupt background tasks that may be attached to external processes
		lifeCtxCancel:      cancel,
		lifeCtx:            ctx,
		getSLSRefreshables: getSLSRefreshables,
	}

	return miner
}

// Pending returns the currently pending block and associated receipts, logs
// and statedb. The returned values can be nil in case the pending block is
// not initialized.
func (miner *Miner) Pending() (*types.Block, types.Receipts, *state.StateDB) {
	if miner.chainConfig.Optimism != nil && !miner.config.RollupComputePendingBlock {
		// For compatibility when not computing a pending block, we serve the latest block as "pending"
		headHeader := miner.chain.CurrentHeader()
		headBlock := miner.chain.GetBlock(headHeader.Hash(), headHeader.Number.Uint64())
		headReceipts := miner.chain.GetReceiptsByHash(headHeader.Hash())
		stateDB, err := miner.chain.StateAt(headHeader.Root)
		if err != nil {
			return nil, nil, nil
		}

		return headBlock, headReceipts, stateDB.Copy()
	}

	pending := miner.getPending()
	if pending == nil {
		return nil, nil, nil
	}
	return pending.block, pending.receipts, pending.stateDB.Copy()
}

// SetExtra sets the content used to initialize the block extra field.
func (miner *Miner) SetExtra(extra []byte) error {
	if uint64(len(extra)) > params.MaximumExtraDataSize {
		return fmt.Errorf("extra exceeds max length. %d > %v", len(extra), params.MaximumExtraDataSize)
	}
	miner.confMu.Lock()
	miner.config.ExtraData = extra
	miner.confMu.Unlock()
	return nil
}

// SetPrioAddresses sets a list of addresses to prioritize for transaction inclusion.
func (miner *Miner) SetPrioAddresses(prio []common.Address) {
	miner.confMu.Lock()
	miner.prio = prio
	miner.confMu.Unlock()
}

// SetGasCeil sets the gaslimit to strive for when mining blocks post 1559.
// For pre-1559 blocks, it sets the ceiling.
func (miner *Miner) SetGasCeil(ceil uint64) {
	miner.confMu.Lock()
	miner.config.GasCeil = ceil
	miner.confMu.Unlock()
}

// SetGasTip sets the minimum gas tip for inclusion.
func (miner *Miner) SetGasTip(tip *big.Int) error {
	miner.confMu.Lock()
	miner.config.GasPrice = tip
	miner.confMu.Unlock()
	return nil
}

func (miner *Miner) AddSLSWorker(slsWorker slsCommon.Worker) {
	miner.slsWorker = slsWorker
}

// BuildPayload builds the payload according to the provided parameters.
func (miner *Miner) BuildPayload(args *BuildPayloadArgs) (*Payload, error) {
	return miner.buildPayload(args)
}

// getPending retrieves the pending block based on the current head block.
// The result might be nil if pending generation is failed.
func (miner *Miner) getPending() *newPayloadResult {
	header := miner.chain.CurrentHeader()
	miner.pendingMu.Lock()
	defer miner.pendingMu.Unlock()

	if cached := miner.pending.resolve(header.Hash()); cached != nil {
		return cached
	}
	var (
		timestamp  = uint64(time.Now().Unix())
		withdrawal types.Withdrawals
	)
	if miner.chainConfig.IsShanghai(new(big.Int).Add(header.Number, big.NewInt(1)), timestamp) {
		withdrawal = []*types.Withdrawal{}
	}
	ret := miner.generateWork(&generateParams{
		timestamp:         timestamp,
		forceTime:         false,
		parentHash:        header.Hash(),
		coinbase:          miner.config.PendingFeeRecipient,
		random:            common.Hash{},
		withdrawals:       withdrawal,
		beaconRoot:        nil,
		noTxs:             false,
		checkTransactions: true, // the pending block only makes sense on the sequencer, so act as one
	})
	if ret.err != nil {
		return nil
	}
	miner.pending.update(header.Hash(), ret)
	return ret
}

func (miner *Miner) Close() {
	miner.lifeCtxCancel()
}

func (miner *Miner) GetChainConfig() *params.ChainConfig {
	return miner.chainConfig
}
