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

package miner

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zircuit-labs/l2-geth-public/rollup/tracing"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/consensus"
	"github.com/zircuit-labs/l2-geth-public/consensus/misc"
	"github.com/zircuit-labs/l2-geth-public/consensus/misc/eip1559"
	"github.com/zircuit-labs/l2-geth-public/consensus/misc/eip4844"
	"github.com/zircuit-labs/l2-geth-public/core"
	"github.com/zircuit-labs/l2-geth-public/core/rawdb"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/txpool"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/core/vm"
	"github.com/zircuit-labs/l2-geth-public/eth/tracers"
	"github.com/zircuit-labs/l2-geth-public/event"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/metrics"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/rollup/circuitcapacitychecker"
	"github.com/zircuit-labs/l2-geth-public/trie"
)

const (
	// resultQueueSize is the size of channel listening to sealing result.
	resultQueueSize = 10

	// txChanSize is the size of channel listening to NewTxsEvent.
	// The number is referenced from the size of tx pool.
	txChanSize = 4096

	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10

	// resubmitAdjustChanSize is the size of resubmitting interval adjustment channel.
	resubmitAdjustChanSize = 10

	// minRecommitInterval is the minimal time interval to recreate the sealing block with
	// any newly arrived transactions.
	minRecommitInterval = 100 * time.Millisecond

	// maxRecommitInterval is the maximum time interval to recreate the sealing block with
	// any newly arrived transactions.
	maxRecommitInterval = 15 * time.Second

	// intervalAdjustRatio is the impact a single interval adjustment has on sealing work
	// resubmitting interval.
	intervalAdjustRatio = 0.1

	// intervalAdjustBias is applied during the new resubmit interval calculation in favor of
	// increasing upper limit or decreasing lower limit so that the limit can be reachable.
	intervalAdjustBias = 200 * 1000.0 * 1000.0

	// staleThreshold is the maximum depth of the acceptable stale block.
	staleThreshold = 7
)

var (
	errBlockInterruptedByNewHead  = errors.New("new head arrived while building block")
	errBlockInterruptedByRecommit = errors.New("recommit interrupt while building block")
	errBlockInterruptedByTimeout  = errors.New("timeout while building block")
	errBlockInterruptedByResolve  = errors.New("payload resolution while building block")

	// Metrics for the skipped txs
	l1TxGasLimitExceededCounter       = metrics.NewRegisteredCounter("miner/skipped_txs/l1/gas_limit_exceeded", nil)
	l1TxRowConsumptionOverflowCounter = metrics.NewRegisteredCounter("miner/skipped_txs/l1/row_consumption_overflow", nil)
	l2TxRowConsumptionOverflowCounter = metrics.NewRegisteredCounter("miner/skipped_txs/l2/row_consumption_overflow", nil)
	l1TxCccUnknownErrCounter          = metrics.NewRegisteredCounter("miner/skipped_txs/l1/ccc_unknown_err", nil)
	l2TxCccUnknownErrCounter          = metrics.NewRegisteredCounter("miner/skipped_txs/l2/ccc_unknown_err", nil)
	l1TxStrangeErrCounter             = metrics.NewRegisteredCounter("miner/skipped_txs/l1/strange_err", nil)
	l2CommitTxsTimer                  = metrics.NewRegisteredTimer("miner/commit/txs_all", nil)
	l2CommitTxTimer                   = metrics.NewRegisteredTimer("miner/commit/tx_all", nil)
	l2CommitTxTraceTimer              = metrics.NewRegisteredTimer("miner/commit/tx_trace", nil)
	l2CommitTxCCCTimer                = metrics.NewRegisteredTimer("miner/commit/tx_ccc", nil)
	l2CommitTxApplyTimer              = metrics.NewRegisteredTimer("miner/commit/tx_apply", nil)
	l2CommitTimer                     = metrics.NewRegisteredTimer("miner/commit/all", nil)
	l2CommitTraceTimer                = metrics.NewRegisteredTimer("miner/commit/trace", nil)
	l2CommitCCCTimer                  = metrics.NewRegisteredTimer("miner/commit/ccc", nil)
	l2PrepareWorkTimer                = metrics.NewRegisteredTimer("miner/prepare/work_all", nil)
	l2ResultTimer                     = metrics.NewRegisteredTimer("miner/result/all", nil)
)

// environment is the worker's current environment and holds all
// information of the sealing block generation.
type environment struct {
	signer       types.Signer
	state        *state.StateDB // apply state changes here
	tcount       int            // tx count in cycle
	forcedtcount int
	blockSize    uint64        // approximate size of tx payload in bytes
	gasPool      *core.GasPool // available gas used to pack transactions
	coinbase     common.Address

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
	sidecars []*types.BlobTxSidecar
	blobs    int

	// circuit capacity check related fields
	traceEnv *tracing.TraceEnv     // env for tracing
	accRows  *types.RowConsumption // accumulated row consumption for a block
}

// copy creates a deep copy of environment.
func (env *environment) copy() *environment {
	cpy := &environment{
		signer:    env.signer,
		state:     env.state.Copy(),
		tcount:    env.tcount,
		blockSize: env.blockSize,
		coinbase:  env.coinbase,
		header:    types.CopyHeader(env.header),
		receipts:  copyReceipts(env.receipts),
		traceEnv:  env.traceEnv, // don't deep copy
		accRows:   env.accRows,  // don't deep copy
	}
	if env.gasPool != nil {
		gasPool := *env.gasPool
		cpy.gasPool = &gasPool
	}
	cpy.txs = make([]*types.Transaction, len(env.txs))
	copy(cpy.txs, env.txs)

	cpy.sidecars = make([]*types.BlobTxSidecar, len(env.sidecars))
	copy(cpy.sidecars, env.sidecars)

	return cpy
}

// discard terminates the background prefetcher go-routine. It should
// always be called for all created environment instances otherwise
// the go-routine leak can happen.
func (env *environment) discard() {
	if env.state == nil {
		return
	}
	env.state.StopPrefetcher()
}

// task contains all information for consensus engine sealing and result submitting.
type task struct {
	receipts  []*types.Receipt
	state     *state.StateDB
	block     *types.Block
	createdAt time.Time
	accRows   *types.RowConsumption // accumulated row consumption in the circuit side
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
	commitInterruptTimeout
	commitInterruptResolve
)

// newWorkReq represents a request for new sealing work submitting with relative interrupt notifier.
type newWorkReq struct {
	interrupt *atomic.Int32
	timestamp int64
}

// newPayloadResult is the result of payload generation.
type newPayloadResult struct {
	err               error
	block             *types.Block
	fees              *big.Int               // total block fees
	sidecars          []*types.BlobTxSidecar // collected blobs of blob transactions
	depositExclusions []common.Hash
}

// getWorkReq represents a request for getting a new sealing work with provided parameters.
type getWorkReq struct {
	params *generateParams
	result chan *newPayloadResult // non-blocking channel
}

// intervalAdjust represents a resubmitting interval adjustment.
type intervalAdjust struct {
	ratio float64
	inc   bool
}

// worker is the main object which takes care of submitting new work to consensus engine
// and gathering the sealing result.
type worker struct {
	config      *Config
	chainConfig *params.ChainConfig
	engine      consensus.Engine
	eth         Backend
	chain       *core.BlockChain

	// Feeds
	pendingLogsFeed event.Feed

	// Subscriptions
	mux          *event.TypeMux
	txsCh        chan core.NewTxsEvent
	txsSub       event.Subscription
	chainHeadCh  chan core.ChainHeadEvent
	chainHeadSub event.Subscription

	// Channels
	newWorkCh          chan *newWorkReq
	getWorkCh          chan *getWorkReq
	taskCh             chan *task
	resultCh           chan *types.Block
	startCh            chan struct{}
	exitCh             chan struct{}
	resubmitIntervalCh chan time.Duration
	resubmitAdjustCh   chan *intervalAdjust

	wg sync.WaitGroup

	current *environment // An environment for current running cycle.

	mu       sync.RWMutex // The lock used to protect the coinbase and extra fields
	coinbase common.Address
	extra    []byte

	pendingMu    sync.RWMutex
	pendingTasks map[common.Hash]*task

	snapshotMu       sync.RWMutex // The lock used to protect the snapshots below
	snapshotBlock    *types.Block
	snapshotReceipts types.Receipts
	snapshotState    *state.StateDB

	// atomic status counters
	running atomic.Bool  // The indicator whether the consensus engine is running or not.
	newTxs  atomic.Int32 // New arrival transaction count since last sealing work submitting.
	syncing atomic.Bool  // The indicator whether the node is still syncing.

	// newpayloadTimeout is the maximum timeout allowance for creating payload.
	// The default value is 2 seconds but node operator can set it to arbitrary
	// large value. A large timeout allowance may cause Geth to fail creating
	// a non-empty payload within the specified time and eventually miss the slot
	// in case there are some computation expensive transactions in txpool.
	newpayloadTimeout time.Duration

	// recommit is the time interval to re-create sealing work or to re-build
	// payload in proof-of-stake stage.
	recommit time.Duration

	// External functions
	isLocalBlock func(header *types.Header) bool // Function used to determine whether the specified block is mined by local miner.

	circuitCapacityChecker *circuitcapacitychecker.CircuitCapacityChecker

	// Test hooks
	newTaskHook  func(*task)                        // Method to call upon receiving a new sealing task.
	skipSealHook func(*task) bool                   // Method to decide whether skipping the sealing.
	fullTaskHook func()                             // Method to call before pushing the full sealing task.
	resubmitHook func(time.Duration, time.Duration) // Method to call upon updating resubmitting interval.
}

func newWorker(config *Config, chainConfig *params.ChainConfig, engine consensus.Engine, eth Backend, mux *event.TypeMux, isLocalBlock func(header *types.Header) bool, init bool, cccConfig circuitcapacitychecker.Config) *worker {
	worker := &worker{
		config:                 config,
		chainConfig:            chainConfig,
		engine:                 engine,
		eth:                    eth,
		chain:                  eth.BlockChain(),
		mux:                    mux,
		isLocalBlock:           isLocalBlock,
		coinbase:               config.Etherbase,
		extra:                  config.ExtraData,
		pendingTasks:           make(map[common.Hash]*task),
		txsCh:                  make(chan core.NewTxsEvent, txChanSize),
		chainHeadCh:            make(chan core.ChainHeadEvent, chainHeadChanSize),
		newWorkCh:              make(chan *newWorkReq),
		getWorkCh:              make(chan *getWorkReq),
		taskCh:                 make(chan *task),
		resultCh:               make(chan *types.Block, resultQueueSize),
		startCh:                make(chan struct{}, 1),
		exitCh:                 make(chan struct{}),
		resubmitIntervalCh:     make(chan time.Duration),
		resubmitAdjustCh:       make(chan *intervalAdjust, resubmitAdjustChanSize),
		circuitCapacityChecker: circuitcapacitychecker.NewCircuitCapacityChecker(true, eth.BlockChain(), cccConfig),
	}
	log.Info("created new worker", "CircuitCapacityChecker ID", worker.circuitCapacityChecker.ID)

	// Subscribe for transaction insertion events (whether from network or resurrects)
	worker.txsSub = eth.TxPool().SubscribeTransactions(worker.txsCh, true)
	// Subscribe events for blockchain
	worker.chainHeadSub = eth.BlockChain().SubscribeChainHeadEvent(worker.chainHeadCh)

	// Sanitize recommit interval if the user-specified one is too short.
	recommit := worker.config.Recommit
	if recommit < minRecommitInterval {
		log.Warn("Sanitizing miner recommit interval", "provided", recommit, "updated", minRecommitInterval)
		recommit = minRecommitInterval
	}
	worker.recommit = recommit

	// Sanitize the timeout config for creating payload.
	newpayloadTimeout := worker.config.NewPayloadTimeout
	if newpayloadTimeout == 0 {
		log.Warn("Sanitizing new payload timeout to default", "provided", newpayloadTimeout, "updated", DefaultConfig.NewPayloadTimeout)
		newpayloadTimeout = DefaultConfig.NewPayloadTimeout
	}
	if newpayloadTimeout < time.Millisecond*100 {
		log.Warn("Low payload timeout may cause high amount of non-full blocks", "provided", newpayloadTimeout, "default", DefaultConfig.NewPayloadTimeout)
	}
	worker.newpayloadTimeout = newpayloadTimeout

	worker.wg.Add(4)
	go worker.mainLoop()
	go worker.newWorkLoop(recommit)
	go worker.resultLoop()
	go worker.taskLoop()

	// Submit first work to initialize pending state.
	if init {
		worker.startCh <- struct{}{}
	}
	return worker
}

// GetCCC returns a pointer to this worker's CCC instance.
// Only used in tests.
func (w *worker) GetCCC() *circuitcapacitychecker.CircuitCapacityChecker {
	return w.circuitCapacityChecker
}

// setEtherbase sets the etherbase used to initialize the block coinbase field.
func (w *worker) setEtherbase(addr common.Address) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.coinbase = addr
}

// etherbase retrieves the configured etherbase address.
func (w *worker) etherbase() common.Address {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.coinbase
}

func (w *worker) setGasCeil(ceil uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.config.GasCeil = ceil
}

// setExtra sets the content used to initialize the block extra field.
func (w *worker) setExtra(extra []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.extra = extra
}

// setRecommitInterval updates the interval for miner sealing work recommitting.
func (w *worker) setRecommitInterval(interval time.Duration) {
	select {
	case w.resubmitIntervalCh <- interval:
	case <-w.exitCh:
	}
}

// pending returns the pending state and corresponding block. The returned
// values can be nil in case the pending block is not initialized.
func (w *worker) pending() (*types.Block, *state.StateDB) {
	if w.chainConfig.Optimism != nil && !w.config.RollupComputePendingBlock {
		return nil, nil // when not computing the pending block, there is never a pending state
	}
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	if w.snapshotState == nil {
		return nil, nil
	}
	return w.snapshotBlock, w.snapshotState.Copy()
}

// pendingBlock returns pending block. The returned block can be nil in case the
// pending block is not initialized.
func (w *worker) pendingBlock() *types.Block {
	if w.chainConfig.Optimism != nil && !w.config.RollupComputePendingBlock {
		// For compatibility when not computing a pending block, we serve the latest block as "pending"
		headHeader := w.eth.BlockChain().CurrentHeader()
		headBlock := w.eth.BlockChain().GetBlock(headHeader.Hash(), headHeader.Number.Uint64())
		return headBlock
	}
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock
}

// pendingBlockAndReceipts returns pending block and corresponding receipts.
// The returned values can be nil in case the pending block is not initialized.
func (w *worker) pendingBlockAndReceipts() (*types.Block, types.Receipts) {
	if w.chainConfig.Optimism != nil && !w.config.RollupComputePendingBlock {
		return nil, nil // when not computing the pending block, there are no pending receipts, and thus no pending logs
	}
	w.snapshotMu.RLock()
	defer w.snapshotMu.RUnlock()
	return w.snapshotBlock, w.snapshotReceipts
}

// start sets the running status as 1 and triggers new work submitting.
func (w *worker) start() {
	w.running.Store(true)
	w.startCh <- struct{}{}
}

// stop sets the running status as 0.
func (w *worker) stop() {
	w.running.Store(false)
}

// isRunning returns an indicator whether worker is running or not.
func (w *worker) isRunning() bool {
	return w.running.Load()
}

// close terminates all background threads maintained by the worker.
// Note the worker does not support being closed multiple times.
func (w *worker) close() {
	w.running.Store(false)
	close(w.exitCh)
	w.wg.Wait()
}

// recalcRecommit recalculates the resubmitting interval upon feedback.
func recalcRecommit(minRecommit, prev time.Duration, target float64, inc bool) time.Duration {
	var (
		prevF = float64(prev.Nanoseconds())
		next  float64
	)
	if inc {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target+intervalAdjustBias)
		max := float64(maxRecommitInterval.Nanoseconds())
		if next > max {
			next = max
		}
	} else {
		next = prevF*(1-intervalAdjustRatio) + intervalAdjustRatio*(target-intervalAdjustBias)
		min := float64(minRecommit.Nanoseconds())
		if next < min {
			next = min
		}
	}
	return time.Duration(int64(next))
}

// newWorkLoop is a standalone goroutine to submit new sealing work upon received events.
func (w *worker) newWorkLoop(recommit time.Duration) {
	defer w.wg.Done()
	if w.chainConfig.Optimism != nil && !w.config.RollupComputePendingBlock {
		for { // do not update the pending-block, instead drain work without doing it, to keep producers from blocking.
			select {
			case <-w.startCh:
			case <-w.chainHeadCh:
			case <-w.resubmitIntervalCh:
			case <-w.resubmitAdjustCh:
			case <-w.exitCh:
				return
			}
		}
	}

	var (
		interrupt   *atomic.Int32
		minRecommit = recommit // minimal resubmit interval specified by user.
		timestamp   int64      // timestamp for each round of sealing.
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	<-timer.C // discard the initial tick

	// commit aborts in-flight transaction execution with given signal and resubmits a new one.
	commit := func(s int32) {
		if interrupt != nil {
			interrupt.Store(s)
		}
		interrupt = new(atomic.Int32)
		select {
		case w.newWorkCh <- &newWorkReq{interrupt: interrupt, timestamp: timestamp}:
		case <-w.exitCh:
			return
		}
		timer.Reset(recommit)
		w.newTxs.Store(0)
	}
	// clearPending cleans the stale pending tasks.
	clearPending := func(number uint64) {
		w.pendingMu.Lock()
		for h, t := range w.pendingTasks {
			if t.block.NumberU64()+staleThreshold <= number {
				delete(w.pendingTasks, h)
			}
		}
		w.pendingMu.Unlock()
	}

	for {
		select {
		case <-w.startCh:
			clearPending(w.chain.CurrentBlock().Number.Uint64())
			timestamp = time.Now().Unix()
			commit(commitInterruptNewHead)

		case head := <-w.chainHeadCh:
			clearPending(head.Block.NumberU64())
			timestamp = time.Now().Unix()
			commit(commitInterruptNewHead)

		case <-timer.C:
			// If sealing is running resubmit a new work cycle periodically to pull in
			// higher priced transactions. Disable this overhead for pending blocks.
			if w.isRunning() && (w.chainConfig.Clique == nil || w.chainConfig.Clique.Period > 0) {
				// Short circuit if no new transaction arrives.
				if w.newTxs.Load() == 0 {
					timer.Reset(recommit)
					continue
				}
				commit(commitInterruptResubmit)
			}

		case interval := <-w.resubmitIntervalCh:
			// Adjust resubmit interval explicitly by user.
			if interval < minRecommitInterval {
				log.Warn("Sanitizing miner recommit interval", "provided", interval, "updated", minRecommitInterval)
				interval = minRecommitInterval
			}
			log.Info("Miner recommit interval update", "from", minRecommit, "to", interval)
			minRecommit, recommit = interval, interval

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case adjust := <-w.resubmitAdjustCh:
			// Adjust resubmit interval by feedback.
			if adjust.inc {
				before := recommit
				target := float64(recommit.Nanoseconds()) / adjust.ratio
				recommit = recalcRecommit(minRecommit, recommit, target, true)
				log.Trace("Increase miner recommit interval", "from", before, "to", recommit)
			} else {
				before := recommit
				recommit = recalcRecommit(minRecommit, recommit, float64(minRecommit.Nanoseconds()), false)
				log.Trace("Decrease miner recommit interval", "from", before, "to", recommit)
			}

			if w.resubmitHook != nil {
				w.resubmitHook(minRecommit, recommit)
			}

		case <-w.exitCh:
			return
		}
	}
}

// mainLoop is responsible for generating and submitting sealing work based on
// the received event. It can support two modes: automatically generate task and
// submit it or return task according to given parameters for various proposes.
func (w *worker) mainLoop() {
	defer w.wg.Done()
	defer w.txsSub.Unsubscribe()
	defer w.chainHeadSub.Unsubscribe()
	defer func() {
		if w.current != nil {
			w.current.discard()
		}
	}()

	for {
		select {
		case req := <-w.newWorkCh:
			w.commitWork(req.interrupt, req.timestamp)

		case req := <-w.getWorkCh:
			req.result <- w.generateWork(req.params)

		case ev := <-w.txsCh:
			if w.chainConfig.Optimism != nil && !w.config.RollupComputePendingBlock {
				continue // don't update the pending-block snapshot if we are not computing the pending block
			}
			// Apply transactions to the pending state if we're not sealing
			//
			// Note all transactions received may not be continuous with transactions
			// already included in the current sealing block. These transactions will
			// be automatically eliminated.
			if !w.isRunning() && w.current != nil {
				// If block is already full, abort
				if gp := w.current.gasPool; gp != nil && gp.Gas() < params.TxGas {
					continue
				}
				txs := make(map[common.Address][]*txpool.LazyTransaction, len(ev.Txs))
				for _, tx := range ev.Txs {
					acc, _ := types.Sender(w.current.signer, tx)
					txs[acc] = append(txs[acc], &txpool.LazyTransaction{
						Pool:      w.eth.TxPool(), // We don't know where this came from, yolo resolve from everywhere
						Hash:      tx.Hash(),
						Tx:        nil, // Do *not* set this! We need to resolve it later to pull blobs in
						Time:      tx.Time(),
						GasFeeCap: tx.GasFeeCap(),
						GasTipCap: tx.GasTipCap(),
						Gas:       tx.Gas(),
						BlobGas:   tx.BlobGas(),
					})
				}
				txset := newTransactionsByPriceAndNonce(w.current.signer, txs, w.current.header.BaseFee)
				tcount := w.current.tcount
				w.commitTransactions(w.current, txset, nil)

				// Only update the snapshot if any new transactions were added
				// to the pending block
				if tcount != w.current.tcount {
					w.updateSnapshot(w.current)
				}
			} else {
				// Special case, if the consensus engine is 0 period clique(dev mode),
				// submit sealing work here since all empty submission will be rejected
				// by clique. Of course the advance sealing(empty submission) is disabled.
				if w.chainConfig.Clique != nil && w.chainConfig.Clique.Period == 0 {
					w.commitWork(nil, time.Now().Unix())
				}
			}
			w.newTxs.Add(int32(len(ev.Txs)))

		// System stopped
		case <-w.exitCh:
			return
		case <-w.txsSub.Err():
			return
		case <-w.chainHeadSub.Err():
			return
		}
	}
}

// taskLoop is a standalone goroutine to fetch sealing task from the generator and
// push them to consensus engine.
func (w *worker) taskLoop() {
	defer w.wg.Done()
	var (
		stopCh chan struct{}
		prev   common.Hash
	)

	// interrupt aborts the in-flight sealing task.
	interrupt := func() {
		if stopCh != nil {
			close(stopCh)
			stopCh = nil
		}
	}
	for {
		select {
		case task := <-w.taskCh:
			if w.newTaskHook != nil {
				w.newTaskHook(task)
			}
			// Reject duplicate sealing work due to resubmitting.
			sealHash := w.engine.SealHash(task.block.Header())
			if sealHash == prev {
				continue
			}
			// Interrupt previous sealing operation
			interrupt()
			stopCh, prev = make(chan struct{}), sealHash

			if w.skipSealHook != nil && w.skipSealHook(task) {
				continue
			}
			w.pendingMu.Lock()
			w.pendingTasks[sealHash] = task
			w.pendingMu.Unlock()

			if err := w.engine.Seal(w.chain, task.block, w.resultCh, stopCh); err != nil {
				log.Warn("Block sealing failed", "err", err)
				w.pendingMu.Lock()
				delete(w.pendingTasks, sealHash)
				w.pendingMu.Unlock()
			}
		case <-w.exitCh:
			interrupt()
			return
		}
	}
}

// resultLoop is a standalone goroutine to handle sealing result submitting
// and flush relative data to the database.
func (w *worker) resultLoop() {
	defer w.wg.Done()
	for {
		select {
		case block := <-w.resultCh:
			// Short circuit when receiving empty result.
			if block == nil {
				continue
			}
			// Short circuit when receiving duplicate result caused by resubmitting.
			if w.chain.HasBlock(block.Hash(), block.NumberU64()) {
				continue
			}
			var (
				sealhash = w.engine.SealHash(block.Header())
				hash     = block.Hash()
			)
			w.pendingMu.RLock()
			task, exist := w.pendingTasks[sealhash]
			w.pendingMu.RUnlock()
			if !exist {
				log.Error("Block found but no relative pending task", "number", block.Number(), "sealhash", sealhash, "hash", hash)
				continue
			}

			startTime := time.Now()

			// Different block could share same sealhash, deep copy here to prevent write-write conflict.
			var (
				receipts = make([]*types.Receipt, len(task.receipts))
				logs     []*types.Log
			)
			for i, taskReceipt := range task.receipts {
				receipt := new(types.Receipt)
				receipts[i] = receipt
				*receipt = *taskReceipt

				// add block location fields
				receipt.BlockHash = hash
				receipt.BlockNumber = block.Number()
				receipt.TransactionIndex = uint(i)

				// Update the block hash in all logs since it is now available and not when the
				// receipt/log of individual transactions were created.
				receipt.Logs = make([]*types.Log, len(taskReceipt.Logs))
				for i, taskLog := range taskReceipt.Logs {
					log := new(types.Log)
					receipt.Logs[i] = log
					*log = *taskLog
					log.BlockHash = hash
				}
				logs = append(logs, receipt.Logs...)
			}
			// Store circuit row consumption.
			log.Trace(
				"Worker write block row consumption",
				"id", w.circuitCapacityChecker.ID,
				"number", block.Number(),
				"hash", hash.String(),
				"accRows", task.accRows,
			)
			rawdb.WriteBlockRowConsumption(w.eth.ChainDb(), hash, task.accRows)
			// Commit block and state to database.
			_, err := w.chain.WriteBlockAndSetHead(block, receipts, logs, task.state, true)
			if err != nil {
				l2ResultTimer.Update(time.Since(startTime))
				log.Error("Failed writing block to chain", "err", err)
				continue
			}
			log.Info("Successfully sealed new block", "number", block.Number(), "sealhash", sealhash, "hash", hash,
				"elapsed", common.PrettyDuration(time.Since(task.createdAt)))

			// Broadcast the block and announce chain insertion event
			w.mux.Post(core.NewMinedBlockEvent{Block: block})

			l2ResultTimer.Update(time.Since(startTime))

		case <-w.exitCh:
			return
		}
	}
}

// makeEnv creates a new environment for the sealing block.
func (w *worker) makeEnv(parent *types.Header, header *types.Header, coinbase common.Address) (*environment, error) {
	parentBlock := w.eth.BlockChain().GetBlockByHash(parent.Hash())

	parentHeader := w.chain.HeaderOrWaitZKTrie(parent)
	// Retrieve the parent state to execute on top and start a prefetcher for
	// the miner to speed block sealing up a bit.
	state, err := w.chain.StateAtHeader(parentHeader)
	if err != nil && w.chainConfig.Optimism != nil { // Allow the miner to reorg its own chain arbitrarily deep
		if historicalBackend, ok := w.eth.(BackendWithHistoricalState); ok {
			var release tracers.StateReleaseFunc
			state, release, err = historicalBackend.StateAtBlock(context.Background(), parentBlock, ^uint64(0), nil, false, false)
			state = state.Copy()
			release()
		}
	}
	if err != nil {
		return nil, err
	}

	// don't commit the state during tracing for circuit capacity checker, otherwise we cannot revert.
	// and even if we don't commit the state, the `refund` value will still be correct, as explained in `CommitTransaction`
	commitStateAfterApply := false
	traceEnv, err := tracing.CreateTraceEnv(w.chainConfig, w.chain, w.engine, w.eth.ChainDb(), state,
		// new block with a placeholder tx, for traceEnv's ExecutionResults length & TxStorageTraces length
		types.NewBlockWithHeader(header).WithBody([]*types.Transaction{types.NewTx(&types.LegacyTx{})}, nil),
		commitStateAfterApply)
	if err != nil {
		return nil, err
	}
	state.StartPrefetcher("miner")

	// Note the passed coinbase may be different with header.Coinbase.
	env := &environment{
		signer:   types.MakeSigner(w.chainConfig, header.Number, header.Time),
		state:    state,
		coinbase: coinbase,
		header:   header,
		traceEnv: traceEnv,
		accRows:  nil,
	}
	// Keep track of transactions which return errors so they can be removed
	env.tcount = 0
	env.blockSize = 0
	return env, nil
}

// updateSnapshot updates pending snapshot block, receipts and state.
func (w *worker) updateSnapshot(env *environment) {
	w.snapshotMu.Lock()
	defer w.snapshotMu.Unlock()

	w.snapshotBlock = types.NewBlock(
		env.header,
		env.txs,
		nil,
		env.receipts,
		trie.NewStackTrie(nil),
	)
	w.snapshotReceipts = copyReceipts(env.receipts)
	w.snapshotState = env.state.Copy()
}

func (w *worker) commitTransaction(env *environment, txM *transactionAndMeta) ([]*types.Log, *types.BlockTrace, error) {
	tx := txM.tx
	if tx.Type() == types.BlobTxType {
		return w.commitBlobTransaction(env, txM)
	}
	receipt, traces, err := w.applyTransaction(env, txM)
	if err != nil {
		return nil, nil, err
	}
	env.txs = append(env.txs, tx)
	env.receipts = append(env.receipts, receipt)
	return receipt.Logs, traces, nil
}

func (w *worker) commitBlobTransaction(env *environment, txM *transactionAndMeta) ([]*types.Log, *types.BlockTrace, error) {
	tx := txM.tx
	sc := tx.BlobTxSidecar()
	if sc == nil {
		panic("blob transaction without blobs in miner")
	}
	// Checking against blob gas limit: It's kind of ugly to perform this check here, but there
	// isn't really a better place right now. The blob gas limit is checked at block validation time
	// and not during execution. This means core.ApplyTransaction will not return an error if the
	// tx has too many blobs. So we have to explicitly check it here.
	if (env.blobs+len(sc.Blobs))*params.BlobTxBlobGasPerBlob > params.MaxBlobGasPerBlock {
		return nil, nil, errors.New("max data blobs reached")
	}
	receipt, traces, err := w.applyTransaction(env, txM)
	if err != nil {
		return nil, nil, err
	}
	env.txs = append(env.txs, tx.WithoutBlobTxSidecar())
	env.receipts = append(env.receipts, receipt)
	env.sidecars = append(env.sidecars, sc)
	env.blobs += len(sc.Blobs)
	*env.header.BlobGasUsed += receipt.BlobGasUsed
	return receipt.Logs, traces, nil
}

// CCCError is a wrapper for the ccc error
type CCCError struct {
	err error
}

func (e *CCCError) Error() string {
	return e.err.Error()
}

func (e *CCCError) Is(target error) bool {
	return e.err == target
}

type transactionAndMeta struct {
	tx          *types.Transaction
	mustInclude bool // tx created by protocol that cannot be removed
}

func mustIncludeTx(env *environment, tx *types.Transaction, index int) bool {
	sender, _ := types.Sender(env.signer, tx)
	return types.ProtocolTx(index, tx, sender)
}

// applyTransaction runs the transaction. If execution fails, state and gas pool are reverted.
func (w *worker) applyTransaction(env *environment, txM *transactionAndMeta) (*types.Receipt, *types.BlockTrace, error) {
	var (
		snap    = env.state.Snapshot()
		gp      = env.gasPool.Gas()
		accRows *types.RowConsumption
		traces  *types.BlockTrace
		err     error
		tx      = txM.tx
	)

	// do not do CCC checks on follower nodes
	// system txs are exempt from ccc checks
	// and only check deposits if either CheckDeposits or EnforceMaxRowsRejection is enabled
	if w.circuitCapacityChecker.Config.Enabled &&
		(!tx.IsDepositTx() || w.circuitCapacityChecker.Config.CheckDeposits || circuitcapacitychecker.IsEnforcingMaxRowsRejection()) {
		defer func(t0 time.Time) {
			l2CommitTxTimer.Update(time.Since(t0))
		}(time.Now())
		// do gas limit check up-front and do not run CCC if it fails
		if env.gasPool.Gas() < tx.Gas() {
			return nil, nil, core.ErrGasLimitReached
		}

		log.Trace(
			"Worker apply ccc for tx",
			"id", w.circuitCapacityChecker.ID,
			"txHash", tx.Hash().Hex(),
		)

		block := types.NewBlockWithHeader(env.header).WithBody([]*types.Transaction{tx}, nil)

		// 1. we have to check circuit capacity before `core.ApplyTransaction`,
		// because if the tx can be successfully executed but circuit capacity overflows, it will be inconvenient to revert.
		// 2. even if we don't commit to the state during the tracing (which means `clearJournalAndRefund` is not called during the tracing),
		// the `refund` value will still be correct, because:
		// 2.1 when starting handling the first tx, `state.refund` is 0 by default,
		// 2.2 after tracing, the state is either committed in `core.ApplyTransaction`, or reverted, so the `state.refund` can be cleared,
		// 2.3 when starting handling the following txs, `state.refund` comes as 0
		withTimer(l2CommitTxTraceTimer, func() {
			traces, err = env.traceEnv.GetBlockTrace(block)
		})

		// `env.traceEnv.State` & `env.state` share a same pointer to the state, so only need to revert `env.state`
		// revert to snapshot for calling `core.ApplyMessage` again, (both `traceEnv.GetBlockTrace` & `core.ApplyTransaction` will call `core.ApplyMessage`)
		env.state.RevertToSnapshot(snap)
		if err != nil {
			return nil, nil, err
		}
		withTimer(l2CommitTxCCCTimer, func() {
			accRows, err = w.circuitCapacityChecker.ApplyTransaction(traces, block)
		})
		if err != nil {
			if !txM.mustInclude {
				return nil, traces, &CCCError{err}
			}
			log.Error("failed to apply system transaction in CCC", "err", err)
		}

		log.Trace(
			"Worker apply ccc for tx result",
			"id", w.circuitCapacityChecker.ID,
			"txHash", tx.Hash().Hex(),
			"accRows", accRows,
		)
	}

	// create new snapshot
	snap = env.state.Snapshot()

	var receipt *types.Receipt
	withTimer(l2CommitTxApplyTimer, func() {
		receipt, err = core.ApplyTransaction(w.chainConfig, w.chain, &env.coinbase, env.gasPool, env.state, env.header, tx, &env.header.GasUsed, *w.chain.GetVMConfig())
	})

	if err != nil {
		env.state.RevertToSnapshot(snap)
		env.gasPool.SetGas(gp)

		if accRows != nil {
			// At this point, we have called CCC but the transaction failed in `ApplyTransaction`.
			// If we skip this tx and continue to pack more, the next tx will likely fail with
			// `circuitcapacitychecker.ErrUnknown`. However, at this point we cannot decide whether
			// we should seal the block or skip the tx and continue, so we simply return the error.
			log.Error(
				"GetBlockTrace passed but ApplyTransaction failed, ccc is left in inconsistent state",
				"blockNumber", env.header.Number,
				"txHash", tx.Hash().Hex(),
				"err", err,
			)
		}

		return nil, traces, err
	}
	return receipt, traces, err
}

func (w *worker) commitTransactions(env *environment, txs *transactionsByPriceAndNonce, interrupt *atomic.Int32) (error, bool) {
	defer func(t0 time.Time) {
		l2CommitTxsTimer.Update(time.Since(t0))
	}(time.Now())

	var circuitCapacityReached bool

	// Short circuit if current is nil
	if env == nil {
		return nil, circuitCapacityReached
	}

	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	var coalescedLogs []*types.Log

loop:
	for {
		// Check interruption signal and abort building if it's fired.
		if interrupt != nil {
			if signal := interrupt.Load(); signal != commitInterruptNone {
				return signalToErr(signal), circuitCapacityReached
			}
		}
		// If we don't have enough gas for any further transactions then we're done.
		if env.gasPool.Gas() < params.TxGas {
			log.Trace("Not enough gas for further transactions", "have", env.gasPool, "want", params.TxGas)
			break
		}
		// Retrieve the next transaction and abort if all done.
		ltx := txs.Peek()
		if ltx == nil {
			break
		}

		// If we don't have enough space for the next transaction, skip the account.
		if env.gasPool.Gas() < ltx.Gas {
			log.Trace("Not enough gas left for transaction", "hash", ltx.Hash, "left", env.gasPool.Gas(), "needed", ltx.Gas)
			txs.Pop()
			continue
		}
		if left := uint64(params.MaxBlobGasPerBlock - env.blobs*params.BlobTxBlobGasPerBlob); left < ltx.BlobGas {
			log.Trace("Not enough blob gas left for transaction", "hash", ltx.Hash, "left", left, "needed", ltx.BlobGas)
			txs.Pop()
			continue
		}
		// Transaction seems to fit, pull it up from the pool
		tx := ltx.Resolve()
		if tx == nil {
			log.Trace("Ignoring evicted transaction", "hash", ltx.Hash)
			txs.Pop()
			continue
		}

		// If we have collected enough transactions then we're done
		// Originally we only limit l2txs count, but now strictly limit total txs number.
		if !w.chainConfig.Scroll.IsValidTxCount(env.tcount + 1) {
			log.Trace("Transaction count limit reached", "have", env.tcount, "want", w.chainConfig.Scroll.MaxTxPerBlock)
			break
		}

		// If including this tx would violate the max size of the block (payload bytes), skip it and any other tx from this account
		if !tx.IsDepositTx() && !w.chainConfig.Scroll.IsValidBlockSize(env.blockSize+tx.Size()) {
			log.Trace("Block size limit reached", "have", env.blockSize, "want", w.chainConfig.Scroll.MaxTxPayloadBytesPerBlock, "tx", tx.Size())
			txs.Pop() // skip transactions from this account
			continue
		}

		// Error may be ignored here. The error has already been checked
		// during transaction acceptance in the transaction pool.
		from, _ := types.Sender(env.signer, tx)

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !w.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring replay protected transaction", "hash", ltx.Hash, "eip155", w.chainConfig.EIP155Block)
			txs.Pop()
			continue
		}
		// Start executing the transaction
		env.state.SetTxContext(tx.Hash(), env.tcount)

		logs, _, err := w.commitTransaction(env, &transactionAndMeta{tx: tx})
		switch {
		case errors.Is(err, core.ErrGasLimitReached):
			// Pop the current out-of-gas transaction without shifting in the next from the account
			log.Trace("Gas limit exceeded for current block", "sender", from)
			txs.Pop()

		case errors.Is(err, core.ErrNonceTooLow):
			// New head notification data race between the transaction pool and miner, shift
			log.Trace("Skipping transaction with low nonce", "hash", ltx.Hash, "sender", from, "nonce", tx.Nonce())
			txs.Shift()

		case errors.Is(err, nil):
			// Everything ok, collect the logs and shift in the next transaction from the same account
			coalescedLogs = append(coalescedLogs, logs...)
			env.tcount++
			txs.Shift()

			if !tx.IsDepositTx() {
				// only consider block size limit for L2 transactions
				env.blockSize += tx.Size()
			}

		// Circuit capacity check
		case errors.Is(err, circuitcapacitychecker.ErrBlockRowConsumptionOverflow):
			if env.tcount-env.forcedtcount >= 1 {
				// 1. Circuit capacity limit reached in a block, and it's not the first tx:
				// don't pop or shift, just quit the loop immediately;
				// though it might still be possible to add some "smaller" txs,
				// but it's a trade-off between tracing overhead & block usage rate
				log.Trace("Circuit capacity limit reached in a block", "acc_rows", env.accRows, "tx", tx.Hash().String())
				log.Info("Skipping message", "tx", tx.Hash().String(), "block", env.header.Number, "reason", "accumulated row consumption overflow")
				circuitCapacityReached = true
				break loop
			} else {
				// 2. Circuit capacity limit reached in a block, and it's the first tx: skip the tx
				log.Trace("Circuit capacity limit reached for a single tx", "tx", tx.Hash().String())

				if tx.IsDepositTx() {
					// Skip L1 message transaction,
					// shift to the next from the account because we shouldn't skip the entire txs from the same account
					txs.Shift()
					l1TxRowConsumptionOverflowCounter.Inc(1)
				} else {
					// Skip L2 transaction and all other transactions from the same sender account
					log.Info("Skipping L2 message", "tx", tx.Hash().String(), "block", env.header.Number, "reason", "first tx row consumption overflow")
					txs.Pop()
					w.eth.TxPool().RemoveTx(tx.Hash(), true, true)
					l2TxRowConsumptionOverflowCounter.Inc(1)
				}
				// Reset ccc so that we can process other transactions for this block
				w.circuitCapacityChecker.Reset()
				log.Trace("Worker reset ccc", "id", w.circuitCapacityChecker.ID)
				circuitCapacityReached = false
			}

		case (errors.Is(err, circuitcapacitychecker.ErrUnknown) && tx.IsDepositTx()):
			log.Trace("Unknown circuit capacity checker error for L1MessageTx", "tx", tx.Hash().String())
			log.Info("Skipping L1 message", "tx", tx.Hash().String(), "block", env.header.Number, "reason", "unknown row consumption error")
			l1TxCccUnknownErrCounter.Inc(1)
			// Normally we would do `txs.Shift()` here.
			// However, after `ErrUnknown`, ccc might remain in an
			// inconsistent state, so we cannot pack more transactions.
			circuitCapacityReached = true
			w.checkCurrentTxNumWithCCC(env.tcount)
			break loop

		case (errors.Is(err, circuitcapacitychecker.ErrUnknown) && !tx.IsDepositTx()):
			// Circuit capacity check: unknown circuit capacity checker error for L2MessageTx, skip the account
			log.Trace("Unknown circuit capacity checker error for L2MessageTx", "tx", tx.Hash().String())
			log.Info("Skipping L2 message", "tx", tx.Hash().String(), "block", env.header.Number, "reason", "unknown row consumption error", "error", err)

			// Normally we would do `txs.Pop()` here.
			// However, after `ErrUnknown`, ccc might remain in an
			// inconsistent state, so we cannot pack more transactions.
			w.eth.TxPool().RemoveTx(tx.Hash(), true, true)
			circuitCapacityReached = true
			w.checkCurrentTxNumWithCCC(env.tcount)
			break loop

		case (errors.Is(err, core.ErrInsufficientFunds) || errors.Is(errors.Unwrap(err), core.ErrInsufficientFunds)):
			log.Trace("Skipping tx with insufficient funds", "sender", from, "tx", tx.Hash().String())
			txs.Pop()
			w.eth.TxPool().RemoveTx(tx.Hash(), true, true)

		default:
			// Transaction is regarded as invalid, drop all consecutive transactions from
			// the same sender because of `nonce-too-high` clause.
			log.Debug("Transaction failed, account skipped", "hash", ltx.Hash.String(), "err", err)
			txs.Shift()
		}
	}
	if !w.isRunning() && len(coalescedLogs) > 0 {
		// We don't push the pendingLogsEvent while we are sealing. The reason is that
		// when we are sealing, the worker will regenerate a sealing block every 3 seconds.
		// In order to avoid pushing the repeated pendingLog, we disable the pending log pushing.

		// make a copy, the state caches the logs and these logs get "upgraded" from pending to mined
		// logs by filling in the block hash when the block was mined by the local miner. This can
		// cause a race condition if a log was "upgraded" before the PendingLogsEvent is processed.
		cpy := make([]*types.Log, len(coalescedLogs))
		for i, l := range coalescedLogs {
			cpy[i] = new(types.Log)
			*cpy[i] = *l
		}
		w.pendingLogsFeed.Send(cpy)
	}
	return nil, circuitCapacityReached
}

func (w *worker) checkCurrentTxNumWithCCC(expected int) {
	match, got, err := w.circuitCapacityChecker.CheckTxNum(expected)
	if err != nil {
		log.Error("failed to CheckTxNum in ccc", "err", err)
		return
	}
	if !match {
		log.Error("tx count in miner is different with CCC", "expected", expected, "got", got)
	}
}

// generateParams wraps various of settings for generating sealing task.
type generateParams struct {
	timestamp   uint64            // The timstamp for sealing task
	forceTime   bool              // Flag whether the given timestamp is immutable or not
	parentHash  common.Hash       // Parent block hash, empty means the latest chain head
	coinbase    common.Address    // The fee recipient address for including transaction
	random      common.Hash       // The randomness generated by beacon chain, empty before the merge
	withdrawals types.Withdrawals // List of withdrawals to include in block.
	beaconRoot  *common.Hash      // The beacon root (cancun field).
	noTxs       bool              // Flag whether an empty block without any transaction is expected

	txs       types.Transactions // Deposit transactions to include at the start of the block
	gasLimit  *uint64            // Optional gas limit override
	interrupt *atomic.Int32      // Optional interruption signal to pass down to worker.generateWork
	isUpdate  bool               // Optional flag indicating that this is building a discardable update

	l1Info *types.L1Info // L1Info to store in DB on block sealing
}

// validateParams validates the given parameters.
// It currently checks that the parent block is known and that the timestamp is valid,
// i.e., after the parent block's timestamp.
// It returns an upper bound of the payload building duration as computed
// by the difference in block timestamps between the parent and genParams.
func (w *worker) validateParams(genParams *generateParams) (time.Duration, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()

	// Find the parent block for sealing task
	parent := w.chain.CurrentBlock()
	if genParams.parentHash != (common.Hash{}) {
		block := w.chain.GetBlockByHash(genParams.parentHash)
		if block == nil {
			return 0, fmt.Errorf("missing parent %v", genParams.parentHash)
		}
		parent = block.Header()
	}

	// Sanity check the timestamp correctness
	blockTime := int64(genParams.timestamp) - int64(parent.Time)
	if blockTime <= 0 && genParams.forceTime {
		return 0, fmt.Errorf("invalid timestamp, parent %d given %d", parent.Time, genParams.timestamp)
	}

	// minimum payload build time of 2s
	if blockTime < 2 {
		blockTime = 2
	}
	return time.Duration(blockTime) * time.Second, nil
}

// prepareWork constructs the sealing task according to the given parameters,
// either based on the last chain head or specified parent. In this function
// the pending transactions are not filled yet, only the empty task returned.
func (w *worker) prepareWork(genParams *generateParams) (*environment, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	defer func(t0 time.Time) {
		l2PrepareWorkTimer.Update(time.Since(t0))
	}(time.Now())

	// Find the parent block for sealing task
	parent := w.chain.CurrentBlock()
	w.circuitCapacityChecker.Reset()
	log.Trace("Worker reset ccc", "id", w.circuitCapacityChecker.ID)

	if genParams.parentHash != (common.Hash{}) {
		block := w.chain.GetBlockByHash(genParams.parentHash)
		if block == nil {
			return nil, fmt.Errorf("missing parent")
		}
		parent = block.Header()
	}
	// Sanity check the timestamp correctness, recap the timestamp
	// to parent+1 if the mutation is allowed.
	timestamp := genParams.timestamp
	if parent.Time >= timestamp {
		if genParams.forceTime {
			return nil, fmt.Errorf("invalid timestamp, parent %d given %d", parent.Time, timestamp)
		}
		timestamp = parent.Time + 1
	}
	// Construct the sealing block header.
	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     new(big.Int).Add(parent.Number, common.Big1),
		GasLimit:   core.CalcGasLimit(parent.GasLimit, w.config.GasCeil),
		Time:       timestamp,
		Coinbase:   genParams.coinbase,
	}
	// Set the extra field.
	if len(w.extra) != 0 && w.chainConfig.Optimism == nil { // Optimism chains must not set any extra data.
		header.Extra = w.extra
	}
	// Set the randomness field from the beacon chain if it's available.
	if genParams.random != (common.Hash{}) {
		header.MixDigest = genParams.random
	}
	// Set baseFee and GasLimit if we are on an EIP-1559 chain
	if w.chainConfig.IsLondon(header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(w.chainConfig, parent, header.Time)
		if !w.chainConfig.IsLondon(parent.Number) {
			parentGasLimit := parent.GasLimit * w.chainConfig.ElasticityMultiplier()
			header.GasLimit = core.CalcGasLimit(parentGasLimit, w.config.GasCeil)
		}
	}
	if genParams.gasLimit != nil { // override gas limit if specified
		header.GasLimit = *genParams.gasLimit
	} else if w.chain.Config().Optimism != nil && w.config.GasCeil != 0 {
		// configure the gas limit of pending blocks with the miner gas limit config when using optimism
		header.GasLimit = w.config.GasCeil
	}
	// Apply EIP-4844, EIP-4788.
	if w.chainConfig.IsCancun(header.Number, header.Time) {
		var excessBlobGas uint64
		if w.chainConfig.IsCancun(parent.Number, parent.Time) {
			excessBlobGas = eip4844.CalcExcessBlobGas(*parent.ExcessBlobGas, *parent.BlobGasUsed)
		} else {
			// For the first post-fork block, both parent.data_gas_used and parent.excess_data_gas are evaluated as 0
			excessBlobGas = eip4844.CalcExcessBlobGas(0, 0)
		}
		header.BlobGasUsed = new(uint64)
		header.ExcessBlobGas = &excessBlobGas
		header.ParentBeaconRoot = genParams.beaconRoot
	}
	// Run the consensus preparation with the default or customized consensus engine.
	if err := w.engine.Prepare(w.chain, header); err != nil {
		log.Error("Failed to prepare header for sealing", "err", err)
		return nil, err
	}
	// Could potentially happen if starting to mine in an odd state.
	// Note genParams.coinbase can be different with header.Coinbase
	// since clique algorithm can modify the coinbase field in header.
	env, err := w.makeEnv(parent, header, genParams.coinbase)
	if err != nil {
		log.Error("Failed to create sealing context", "err", err)
		return nil, err
	}
	if header.ParentBeaconRoot != nil {
		context := core.NewEVMBlockContext(header, w.chain, nil, w.chainConfig, env.state)
		vmenv := vm.NewEVM(context, vm.TxContext{}, env.state, w.chainConfig, vm.Config{})
		core.ProcessBeaconBlockRoot(*header.ParentBeaconRoot, vmenv, env.state)
	}
	return env, nil
}

// fillTransactions retrieves the pending transactions from the txpool and fills them
// into the given sealing block. The transaction selection and ordering strategy can
// be customized with the plugin in the future.
func (w *worker) fillTransactions(interrupt *atomic.Int32, env *environment) error {
	pending := w.eth.TxPool().Pending(true)

	// Split the pending transactions into locals and remotes.
	localTxs, remoteTxs := make(map[common.Address][]*txpool.LazyTransaction), pending
	for _, account := range w.eth.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			localTxs[account] = txs
		}
	}

	// Fill the block with all available pending transactions.
	var err error
	var circuitCapacityReached bool
	if len(localTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, localTxs, env.header.BaseFee)
		err, circuitCapacityReached = w.commitTransactions(env, txs, interrupt)
		if err != nil {
			return err
		}
	}
	if len(remoteTxs) > 0 && !circuitCapacityReached {
		txs := newTransactionsByPriceAndNonce(env.signer, remoteTxs, env.header.BaseFee)
		// don't need to get `circuitCapacityReached` here because we don't have further `commitTransactions`
		if err, _ := w.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	return nil
}

// generateWork generates a sealing block based on the given parameters.
func (w *worker) generateWork(genParams *generateParams) *newPayloadResult {
	work, err := w.prepareWork(genParams)
	if err != nil {
		return &newPayloadResult{err: err}
	}
	defer work.discard()
	if work.gasPool == nil {
		work.gasPool = new(core.GasPool).AddGas(work.header.GasLimit)
	}

	misc.EnsureCreate2Deployer(w.chainConfig, work.header.Time, work.state)
	var (
		depositExclusionList []common.Hash
		cccErr               *CCCError
	)
	for i, tx := range genParams.txs {
		from, _ := types.Sender(work.signer, tx)
		work.state.SetTxContext(tx.Hash(), work.tcount)
		txM := &transactionAndMeta{tx: tx, mustInclude: mustIncludeTx(work, tx, i)}
		_, _, err := w.commitTransaction(work, txM)
		if errors.As(err, &cccErr) {
			log.Info("Detected CCC error. Setting up deposit rejections")
			//subsequent txs are automatically rejected
			for j := i; j < len(genParams.txs); j++ {
				log.Info("Txs excluded by ccc: ", "tx", genParams.txs[j].Hash())
				depositExclusionList = append(depositExclusionList, genParams.txs[j].Hash())
			}
			return &newPayloadResult{depositExclusions: depositExclusionList, err: err}
		}

		if err != nil {
			return &newPayloadResult{err: fmt.Errorf("failed to force-include tx: %s type: %d sender: %s nonce: %d, err: %w", tx.Hash(), tx.Type(), from, tx.Nonce(), err)}
		}
		work.tcount++
		work.forcedtcount++
	}

	// forced transactions done, fill rest of block with transactions
	if !genParams.noTxs {
		// use shared interrupt if present
		interrupt := genParams.interrupt
		if interrupt == nil {
			interrupt = new(atomic.Int32)
		}
		timer := time.AfterFunc(w.newpayloadTimeout, func() {
			interrupt.Store(commitInterruptTimeout)
		})

		err := w.fillTransactions(interrupt, work)
		timer.Stop() // don't need timeout interruption anymore
		if errors.Is(err, errBlockInterruptedByTimeout) {
			log.Warn("Block building is interrupted", "allowance", common.PrettyDuration(w.newpayloadTimeout))
		} else if errors.Is(err, errBlockInterruptedByResolve) {
			log.Info("Block building got interrupted by payload resolution")
		}
	}
	if intr := genParams.interrupt; intr != nil && genParams.isUpdate && intr.Load() != commitInterruptNone {
		return &newPayloadResult{err: errInterruptedUpdate}
	}

	block, err := w.engine.FinalizeAndAssemble(w.chain, work.header, work.state, work.txs, nil, work.receipts, genParams.withdrawals)
	if err != nil {
		return &newPayloadResult{err: err}
	}

	// Write the L1Info to the database
	if block != nil {
		rawdb.WriteL1Info(w.eth.ChainDb(), block.Hash(), genParams.l1Info)
	}

	return &newPayloadResult{
		block:    block,
		fees:     totalFees(block, work.receipts),
		sidecars: work.sidecars,
	}
}

// commitWork generates several new sealing tasks based on the parent block
// and submit them to the sealer.
func (w *worker) commitWork(interrupt *atomic.Int32, timestamp int64) {
	// Abort committing if node is still syncing
	if w.syncing.Load() {
		return
	}
	start := time.Now()

	// Set the coinbase if the worker is running or it's required
	var coinbase common.Address
	if w.isRunning() {
		coinbase = w.etherbase()
		if coinbase == (common.Address{}) {
			log.Error("Refusing to mine without etherbase")
			return
		}
	}
	work, err := w.prepareWork(&generateParams{
		timestamp: uint64(timestamp),
		coinbase:  coinbase,
	})
	if err != nil {
		log.Warn("Failed to prepare work", "err", err)
		return
	}
	// Fill pending transactions from the txpool into the block.
	err = w.fillTransactions(interrupt, work)
	switch {
	case err == nil:
		// The entire block is filled, decrease resubmit interval in case
		// of current interval is larger than the user-specified one.
		w.adjustResubmitInterval(&intervalAdjust{inc: false})

	case errors.Is(err, errBlockInterruptedByRecommit):
		// Notify resubmit loop to increase resubmitting interval if the
		// interruption is due to frequent commits.
		gaslimit := work.header.GasLimit
		ratio := float64(gaslimit-work.gasPool.Gas()) / float64(gaslimit)
		if ratio < 0.1 {
			ratio = 0.1
		}
		w.adjustResubmitInterval(&intervalAdjust{
			ratio: ratio,
			inc:   true,
		})

	case errors.Is(err, errBlockInterruptedByNewHead):
		// If the block building is interrupted by newhead event, discard it
		// totally. Committing the interrupted block introduces unnecessary
		// delay, and possibly causes miner to mine on the previous head,
		// which could result in higher uncle rate.
		work.discard()
		return

	default:
		log.Warn("Failed to fill transactions", "err", err)
	}
	// Submit the generated block for consensus sealing.
	if err = w.commit(work.copy(), w.fullTaskHook, true, start); err != nil {
		log.Warn("Failed to commit work", "err", err)
	}

	// Swap out the old work with the new one, terminating any leftover
	// prefetcher processes in the mean time and starting a new one.
	if w.current != nil {
		w.current.discard()
	}
	w.current = work
}

// commit runs any post-transaction state modifications, assembles the final block
// and commits new work if consensus engine is running.
// Note the assumption is held that the mutation is allowed to the passed env, do
// the deep copy first.
func (w *worker) commit(env *environment, interval func(), update bool, start time.Time) error {
	// set wenv.accRows for empty-but-not-genesis block
	if (env.header.Number.Uint64() != 0) &&
		(env.accRows == nil || len(*env.accRows) == 0) && w.isRunning() &&
		w.circuitCapacityChecker.Config.Enabled {
		// With Optimism, we should never encounter an empty block.
		// Log this warning and continue as Scroll would do in this case.
		log.Warn(
			"empty block encountered",
			"number", env.header.Number,
			"hash", env.header.Hash().String(),
		)

		log.Trace(
			"Worker apply ccc for empty block",
			"id", w.circuitCapacityChecker.ID,
			"number", env.header.Number,
			"hash", env.header.Hash().String(),
		)
		var traces *types.BlockTrace
		var err error
		block := types.NewBlockWithHeader(env.header)
		withTimer(l2CommitTraceTimer, func() {
			traces, err = env.traceEnv.GetBlockTrace(block)
		})
		if err != nil {
			return err
		}

		// truncate ExecutionResults&TxStorageTraces, because we declare their lengths with a dummy tx before;
		// however, we need to clean it up for an empty block
		traces.ExecutionResults = traces.ExecutionResults[:0]
		traces.TxStorageTraces = traces.TxStorageTraces[:0]
		var accRows *types.RowConsumption
		withTimer(l2CommitCCCTimer, func() {
			accRows, err = w.circuitCapacityChecker.ApplyBlock(traces, block)
		})
		if err != nil {
			return err
		}

		log.Trace(
			"Worker apply ccc for empty block result",
			"id", w.circuitCapacityChecker.ID,
			"number", env.header.Number,
			"hash", env.header.Hash().String(),
			"accRows", accRows,
		)

		env.accRows = accRows
	}

	if w.isRunning() {
		if interval != nil {
			interval()
		}
		// Create a local environment copy, avoid the data race with snapshot state.
		// https://github.com/zircuit-labs/l2-geth-public/issues/24299
		env := env.copy()
		// Withdrawals are set to nil here, because this is only called in PoW.
		block, err := w.engine.FinalizeAndAssemble(w.chain, env.header, env.state, env.txs, nil, env.receipts, nil)
		if err != nil {
			return err
		}
		// If we're post merge, just ignore
		if !w.isTTDReached(block.Header()) {
			select {
			case w.taskCh <- &task{receipts: env.receipts, state: env.state, block: block, accRows: env.accRows, createdAt: time.Now()}:
				fees := totalFees(block, env.receipts)
				feesInEther := new(big.Float).Quo(new(big.Float).SetInt(fees), big.NewFloat(params.Ether))
				log.Info("Commit new sealing work", "number", block.Number(), "sealhash", w.engine.SealHash(block.Header()),
					"txs", env.tcount, "gas", block.GasUsed(), "fees", feesInEther,
					"elapsed", common.PrettyDuration(time.Since(start)))

			case <-w.exitCh:
				log.Info("Worker has exited")
			}
		}
	}
	if update {
		w.updateSnapshot(env)
	}
	return nil
}

// getSealingBlock generates the sealing block based on the given parameters.
// The generation result will be passed back via the given channel no matter
// the generation itself succeeds or not.
func (w *worker) getSealingBlock(params *generateParams) *newPayloadResult {
	req := &getWorkReq{
		params: params,
		result: make(chan *newPayloadResult, 1),
	}
	select {
	case w.getWorkCh <- req:
		return <-req.result
	case <-w.exitCh:
		return &newPayloadResult{err: errors.New("miner closed")}
	}
}

// isTTDReached returns the indicator if the given block has reached the total
// terminal difficulty for The Merge transition.
func (w *worker) isTTDReached(header *types.Header) bool {
	td, ttd := w.chain.GetTd(header.ParentHash, header.Number.Uint64()-1), w.chain.Config().TerminalTotalDifficulty
	return td != nil && ttd != nil && td.Cmp(ttd) >= 0
}

// adjustResubmitInterval adjusts the resubmit interval.
func (w *worker) adjustResubmitInterval(message *intervalAdjust) {
	select {
	case w.resubmitAdjustCh <- message:
	default:
		log.Warn("the resubmitAdjustCh is full, discard the message")
	}
}

// copyReceipts makes a deep copy of the given receipts.
func copyReceipts(receipts []*types.Receipt) []*types.Receipt {
	result := make([]*types.Receipt, len(receipts))
	for i, l := range receipts {
		cpy := *l
		result[i] = &cpy
	}
	return result
}

// totalFees computes total consumed miner fees in Wei. Block transactions and receipts have to have the same order.
func totalFees(block *types.Block, receipts []*types.Receipt) *big.Int {
	feesWei := new(big.Int)
	for i, tx := range block.Transactions() {
		minerFee, _ := tx.EffectiveGasTip(block.BaseFee())
		feesWei.Add(feesWei, new(big.Int).Mul(new(big.Int).SetUint64(receipts[i].GasUsed), minerFee))
	}
	return feesWei
}

// signalToErr converts the interruption signal to a concrete error type for return.
// The given signal must be a valid interruption signal.
func signalToErr(signal int32) error {
	switch signal {
	case commitInterruptNewHead:
		return errBlockInterruptedByNewHead
	case commitInterruptResubmit:
		return errBlockInterruptedByRecommit
	case commitInterruptTimeout:
		return errBlockInterruptedByTimeout
	case commitInterruptResolve:
		return errBlockInterruptedByResolve
	default:
		panic(fmt.Errorf("undefined signal %d", signal))
	}
}

func withTimer(timer metrics.Timer, f func()) {
	if metrics.Enabled {
		timer.Time(f)
	} else {
		f()
	}
}
