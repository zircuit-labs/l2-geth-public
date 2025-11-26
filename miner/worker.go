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
	"sync/atomic"
	"time"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/consensus/misc"
	"github.com/zircuit-labs/l2-geth/consensus/misc/eip1559"
	"github.com/zircuit-labs/l2-geth/consensus/misc/eip4844"
	"github.com/zircuit-labs/l2-geth/core"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	sls "github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/sls-public/evmlimiter"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/stateless"
	"github.com/zircuit-labs/l2-geth/core/txpool"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/core/vm"
	"github.com/zircuit-labs/l2-geth/eth/tracers"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/l2-geth/metrics"
	"github.com/zircuit-labs/l2-geth/params"
	legacyTracing "github.com/zircuit-labs/l2-geth/rollup/tracing"
	"github.com/zircuit-labs/l2-geth/trie"
)

const (
	// minRecommitInterruptInterval is the minimum time interval used to interrupt filling a
	// sealing block with pending transactions from the mempool
	minRecommitInterruptInterval = 2 * time.Second
)

var (
	errBlockInterruptedByNewHead  = errors.New("new head arrived while building block")
	errBlockInterruptedByRecommit = errors.New("recommit interrupt while building block")
	errBlockInterruptedByTimeout  = errors.New("timeout while building block")
	errBlockInterruptedByResolve  = errors.New("payload resolution while building block")

	// Metrics for the skipped txs
	l1TxGasLimitExceededCounter = metrics.NewRegisteredCounter("miner/skipped_txs/l1/gas_limit_exceeded", nil)
	l1TxStrangeErrCounter       = metrics.NewRegisteredCounter("miner/skipped_txs/l1/strange_err", nil)
	l2CommitTxsTimer            = metrics.NewRegisteredTimer("miner/commit/txs_all", nil)
	l2CommitTxTimer             = metrics.NewRegisteredTimer("miner/commit/tx_all", nil)
	l2CommitTxTraceTimer        = metrics.NewRegisteredTimer("miner/commit/tx_trace", nil)
	l2CommitTxApplyTimer        = metrics.NewRegisteredTimer("miner/commit/tx_apply", nil)
	l2CommitTimer               = metrics.NewRegisteredTimer("miner/commit/all", nil)
	l2CommitTraceTimer          = metrics.NewRegisteredTimer("miner/commit/trace", nil)
	l2PrepareWorkTimer          = metrics.NewRegisteredTimer("miner/prepare/work_all", nil)
	l2ResultTimer               = metrics.NewRegisteredTimer("miner/result/all", nil)
)

// environment is the worker's current environment and holds all
// information of the sealing block generation.
type environment struct {
	signer   types.Signer
	state    *state.StateDB // apply state changes here
	tcount   int            // tx count in cycle
	size     uint64         // size of the block we are building
	gasPool  *core.GasPool  // available gas used to pack transactions
	coinbase common.Address
	evm      *vm.EVM

	header   *types.Header
	txs      []*types.Transaction
	receipts []*types.Receipt
	sidecars []*types.BlobTxSidecar
	blobs    int

	noTxs  bool            // true if we are reproducing a block, and do not have to check interop txs
	rpcCtx context.Context // context to control block-building RPC work. No RPC allowed if nil.
}

// txFits reports whether the transaction fits into the block size limit.
func (env *environment) txFitsSize(tx *types.Transaction) bool {
	return env.size+tx.Size() < params.MaxBlockSize-maxBlockSizeBufferZone
}

const (
	commitInterruptNone int32 = iota
	commitInterruptNewHead
	commitInterruptResubmit
	commitInterruptTimeout
	commitInterruptResolve
)

// Block size is capped by the protocol at params.MaxBlockSize. When producing blocks, we
// try to say below the size including a buffer zone, this is to avoid going over the
// maximum size with auxiliary data added into the block.
const maxBlockSizeBufferZone = 1_000_000

// newPayloadResult is the result of payload generation.
type newPayloadResult struct {
	err               error
	block             *types.Block
	fees              *big.Int               // total block fees
	sidecars          []*types.BlobTxSidecar // collected blobs of blob transactions
	stateDB           *state.StateDB         // StateDB after executing the transactions
	receipts          []*types.Receipt       // Receipts collected during construction
	requests          [][]byte               // Consensus layer requests collected during block construction
	depositExclusions []common.Hash
}

// generateParams wraps various settings for generating sealing task.
type generateParams struct {
	timestamp   uint64            // The timestamp for sealing task
	forceTime   bool              // Flag whether the given timestamp is immutable or not
	parentHash  common.Hash       // Parent block hash, empty means the latest chain head
	coinbase    common.Address    // The fee recipient address for including transaction
	random      common.Hash       // The randomness generated by beacon chain, empty before the merge
	withdrawals types.Withdrawals // List of withdrawals to include in block (shanghai field)
	beaconRoot  *common.Hash      // The beacon root (cancun field).
	noTxs       bool              // Flag whether an empty block without any transaction is expected

	txs           types.Transactions // Deposit transactions to include at the start of the block
	gasLimit      *uint64            // Optional gas limit override
	eip1559Params []byte             // Optional EIP-1559 parameters
	interrupt     *atomic.Int32      // Optional interruption signal to pass down to worker.generateWork
	isUpdate      bool               // Optional flag indicating that this is building a discardable update
	minBaseFee    *uint64            // Optional minimum base fee

	rpcCtx context.Context // context to control block-building RPC work. No RPC allowed if nil.

	checkTransactions bool // Zircuit addition: whether limits should be checked on transactions
}

// generateWork generates a sealing block based on the given parameters.
func (miner *Miner) generateWork(genParam *generateParams) *newPayloadResult {
	work, err := miner.prepareWork(genParam)
	if err != nil {
		return &newPayloadResult{err: err}
	}

	// Check withdrawals fit max block size.
	// Due to the cap on withdrawal count, this can actually never happen, but we still need to
	// check to ensure the CL notices there's a problem if the withdrawal cap is ever lifted.
	maxBlockSize := params.MaxBlockSize - maxBlockSizeBufferZone
	if genParam.withdrawals.Size() > maxBlockSize {
		return &newPayloadResult{err: errors.New("withdrawals exceed max block size")}
	}
	// Also add size of withdrawals to work block size.
	work.size += uint64(genParam.withdrawals.Size())

	if work.gasPool == nil {
		gasLimit := work.header.GasLimit

		// If we're building blocks with mempool transactions, we need to ensure that the
		// gas limit is not higher than the effective gas limit. We must still accept any
		// explicitly selected transactions with gas usage up to the block header's limit.
		if !genParam.noTxs {
			effectiveGasLimit := miner.config.EffectiveGasCeil
			if effectiveGasLimit != 0 && effectiveGasLimit < gasLimit {
				gasLimit = effectiveGasLimit
			}
		}
		work.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	misc.EnsureCreate2Deployer(miner.chainConfig, work.header.Time, work.state)

	var (
		depositExclusionList []common.Hash
	)

	for i, tx := range genParam.txs {
		// save snapshot for accumulated block limit
		limiter := work.evm.ExecutionLimiter()
		if limiter != nil {
			limiter.TakeBlockLimitSnapshot()
		}

		from, _ := types.Sender(work.signer, tx)
		work.state.SetTxContext(tx.Hash(), work.tcount)
		txM := &transactionAndMeta{tx: tx, mustInclude: mustIncludeTx(work, tx, i)}
		_, err := miner.commitTransaction(work, txM)

		// check if there is an evm limiter error
		if vm.IsEVMLimitError(err) {
			// Restore accumulated block limit for deposits
			if limiter != nil {
				limiter.RestoreBlockLimitToSnapshot()
			}
			log.Warn("Deposit tx rejected by limiter", "tx", tx.Hash(), "error", err.Error())
			depositExclusionList = append(depositExclusionList, tx.Hash())
			// we will try next deposit
			continue
		}
		if err != nil {
			return &newPayloadResult{err: fmt.Errorf("failed to force-include tx: %s type: %d sender: %s nonce: %d, err: %w", tx.Hash(), tx.Type(), from, tx.Nonce(), err)}
		}
	}

	// treat it as sls worker error so we can build it in PayloadEnvelope and add to bitmap
	if len(depositExclusionList) > 0 {
		return &newPayloadResult{
			depositExclusions: depositExclusionList,
			err:               slsCommon.WorkerError{DepositTransactionsFlagged: true},
		}
	}

	// forced transactions done, fill rest of block with transactions
	if !genParam.noTxs {
		// use shared interrupt if present
		interrupt := genParam.interrupt
		if interrupt == nil {
			interrupt = new(atomic.Int32)
		}
		timer := time.AfterFunc(max(minRecommitInterruptInterval, miner.config.Recommit), func() {
			interrupt.Store(commitInterruptTimeout)
		})

		err := miner.fillTransactions(interrupt, work)
		timer.Stop() // don't need timeout interruption anymore
		if errors.Is(err, errBlockInterruptedByTimeout) {
			log.Warn("Block building is interrupted", "allowance", common.PrettyDuration(miner.config.Recommit))
		} else if errors.Is(err, errBlockInterruptedByResolve) {
			log.Info("Block building got interrupted by payload resolution")
		}
	}
	if intr := genParam.interrupt; intr != nil && genParam.isUpdate && intr.Load() != commitInterruptNone {
		return &newPayloadResult{err: errInterruptedUpdate}
	}

	body := types.Body{Transactions: work.txs, Withdrawals: genParam.withdrawals}

	// Collect consensus-layer requests if Prague is enabled.
	var requests [][]byte

	isTenrec := miner.chainConfig.IsTenrec(work.header.Time)
	// Zircuit: this is what Optimism is using. Since we never had it active, we don't need to enable it
	// if miner.chainConfig.IsPrague(work.header.Number, work.header.Time) && !isIsthmus {
	// 	requests = [][]byte{}
	// 	// EIP-6110 deposits
	// 	if err := core.ParseDepositLogs(&requests, allLogs, miner.chainConfig); err != nil {
	// 		return &newPayloadResult{err: err}
	// 	}
	// 	// EIP-7002
	// 	if err := core.ProcessWithdrawalQueue(&requests, work.evm); err != nil {
	// 		return &newPayloadResult{err: err}
	// 	}
	// 	// EIP-7251 consolidations
	// 	if err := core.ProcessConsolidationQueue(&requests, work.evm); err != nil {
	// 		return &newPayloadResult{err: err}
	// 	}
	// }

	if isTenrec {
		requests = [][]byte{}
	}

	if requests != nil {
		reqHash := types.CalcRequestsHash(requests)
		work.header.RequestsHash = &reqHash
	}

	block, err := miner.engine.FinalizeAndAssemble(miner.chain, work.header, work.state, &body, work.receipts)
	if err != nil {
		return &newPayloadResult{err: err}
	}

	if sls.BlockLevelScanningEnabled(miner.getSLSRefreshables) {
		trace, err := miner.getBlockTrace(block)
		if err != nil {
			return &newPayloadResult{err: err}
		}

		for i, tx := range block.Transactions() {
			from, err := types.Sender(work.signer, tx)
			if err != nil {
				log.Warn("Failed to get sender of tx", "tx", tx.Hash().String(), "err", err)
				continue
			}

			var traceLength int
			if i < len(trace.ExecutionResults) && trace.ExecutionResults[i] != nil && trace.ExecutionResults[i].CallTrace != nil {
				traceLength = len(trace.ExecutionResults[i].CallTrace)
			}

			log.Info(
				"Found transaction in block",
				"sls", "bastet",
				"txNumber", i,
				"txHash", tx.Hash().String(),
				"from", from,
				"to", tx.To(),
				"nonce", tx.Nonce(),
				"blockNumber", block.Number(),
				"blockHash", block.Hash().String(),
				"timestamp", tx.Time(),
				"traceLength", traceLength,
			)
		}

		if miner.slsWorker == nil {
			err = errors.New("SLS block scanning enabled but no worker added")
			return &newPayloadResult{err: err}
		}

		flaggedDepositTxs, err := miner.slsWorker.ValidateBlock(context.Background(), genParam.txs, block, trace)
		if err != nil {
			return &newPayloadResult{depositExclusions: flaggedDepositTxs, err: err}
		}
	}

	return &newPayloadResult{
		block:    block,
		fees:     totalFees(block, work.receipts),
		sidecars: work.sidecars,
		stateDB:  work.state,
		receipts: work.receipts,
		requests: requests,
	}
}

// prepareWork constructs the sealing task according to the given parameters,
// either based on the last chain head or specified parent. In this function
// the pending transactions are not filled yet, only the empty task returned.
func (miner *Miner) prepareWork(genParams *generateParams) (*environment, error) {
	miner.confMu.RLock()
	defer miner.confMu.RUnlock()

	// Find the parent block for sealing task
	parent := miner.chain.CurrentBlock()
	if genParams.parentHash != (common.Hash{}) {
		block := miner.chain.GetBlockByHash(genParams.parentHash)
		if block == nil {
			return nil, errors.New("missing parent")
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
		GasLimit:   core.CalcGasLimit(parent.GasLimit, miner.config.GasCeil),
		Time:       timestamp,
		Coinbase:   genParams.coinbase,
	}
	// Set the extra field.
	if len(miner.config.ExtraData) != 0 && miner.chainConfig.Optimism == nil { // Optimism chains must not set any extra data.
		header.Extra = miner.config.ExtraData
	}
	// Set the randomness field from the beacon chain if it's available.
	if genParams.random != (common.Hash{}) {
		header.MixDigest = genParams.random
	}
	// Set baseFee and GasLimit if we are on an EIP-1559 chain
	if miner.chainConfig.IsLondon(header.Number) {
		header.BaseFee = eip1559.CalcBaseFee(miner.chainConfig, parent, header.Time)
		if !miner.chainConfig.IsLondon(parent.Number) {
			parentGasLimit := parent.GasLimit * miner.chainConfig.ElasticityMultiplier()
			header.GasLimit = core.CalcGasLimit(parentGasLimit, miner.config.GasCeil)
		}
	}
	if genParams.gasLimit != nil { // override gas limit if specified
		header.GasLimit = *genParams.gasLimit
	} else if miner.chain.Config().Optimism != nil && miner.config.GasCeil != 0 {
		// configure the gas limit of pending blocks with the miner gas limit config when using optimism
		header.GasLimit = miner.config.GasCeil
	}
	if miner.chainConfig.IsHolocene(header.Time) {
		if err := eip1559.ValidateHolocene1559Params(genParams.eip1559Params); err != nil {
			return nil, err
		}
		// If this is a holocene block and the params are 0, we must convert them to their previous
		// constants in the header.
		d, e := eip1559.DecodeHolocene1559Params(genParams.eip1559Params)
		if d == 0 {
			d = miner.chainConfig.BaseFeeChangeDenominator(header.Time)
			e = miner.chainConfig.ElasticityMultiplier()
		}
		header.Extra = eip1559.EncodeHoloceneExtraData(d, e)
	} else if genParams.eip1559Params != nil {
		return nil, errors.New("got eip1559 params, expected none")
	}

	if miner.chainConfig.IsMonoFee(header.Number, header.Time) {
		header.GasLimit = 10_000_000
	}

	// Run the consensus preparation with the default or customized consensus engine.
	if err := miner.engine.Prepare(miner.chain, header); err != nil {
		log.Error("Failed to prepare header for sealing", "err", err)
		return nil, err
	}

	// Apply EIP-4844, EIP-4788.
	if miner.chainConfig.IsCancun(header.Number, header.Time) {
		var excessBlobGas uint64
		if miner.chainConfig.IsCancun(parent.Number, parent.Time) {
			excessBlobGas = eip4844.CalcExcessBlobGas(miner.chainConfig, parent, timestamp)
		}
		header.BlobGasUsed = new(uint64)
		header.ExcessBlobGas = &excessBlobGas
		header.ParentBeaconRoot = genParams.beaconRoot
	}
	// Could potentially happen if starting to mine in an odd state.
	// Note genParams.coinbase can be different with header.Coinbase
	// since clique algorithm can modify the coinbase field in header.
	env, err := miner.makeEnv(parent, header, genParams.coinbase, false, genParams.rpcCtx, genParams.checkTransactions)
	if err != nil {
		log.Error("Failed to create sealing context", "err", err)
		return nil, err
	}
	if header.ParentBeaconRoot != nil {
		core.ProcessBeaconBlockRoot(*header.ParentBeaconRoot, env.evm)
	}
	if miner.chainConfig.IsTenrec(header.Time) {
		core.ProcessParentBlockHash(header.ParentHash, env.evm)
	}
	return env, nil
}

// makeEnv creates a new environment for the sealing block.
func (miner *Miner) makeEnv(parent *types.Header, header *types.Header, coinbase common.Address, witness bool, rpcCtx context.Context, checkTransactions bool) (*environment, error) {

	// Retrieve the parent state to execute on top and start a prefetcher for
	// the miner to speed block sealing up a bit.
	state, err := miner.chain.StateAt(parent.Root)

	if err != nil && miner.chainConfig.Optimism != nil { // Allow the miner to reorg its own chain arbitrarily deep
		if historicalBackend, ok := miner.backend.(BackendWithHistoricalState); ok {
			var release tracers.StateReleaseFunc
			parentBlock := miner.backend.BlockChain().GetBlockByHash(parent.Hash())
			state, release, err = historicalBackend.StateAtBlock(context.Background(), parentBlock, ^uint64(0), nil, false, false)
			if err != nil {
				return nil, err
			}
			state = state.Copy()
			release()
		}
	}

	if witness {
		bundle, err := stateless.NewWitness(header, miner.chain)
		if err != nil {
			return nil, err
		}
		state.StartPrefetcher("miner", bundle, nil)
	}

	evm := vm.NewEVM(core.NewEVMBlockContext(header, miner.chain, &coinbase, miner.chainConfig, state), state, miner.chainConfig, vm.Config{})

	if checkTransactions {
		// Only create limiter if enabled (default: enabled)
		if evmlimiter.WhalekillerLimitsEnabled() {
			limiterCfg := evmlimiter.BuildLimitConfig()
			limiter := evmlimiter.NewEVMLimiter(limiterCfg)
			evm.SetExecutionLimiter(limiter)
		}
	}

	// Note the passed coinbase may be different with header.Coinbase.
	env := &environment{
		signer:   types.MakeSigner(miner.chainConfig, header.Number, header.Time),
		state:    state,
		tcount:   0,
		size:     uint64(header.Size()),
		coinbase: coinbase,
		header:   header,
		evm:      evm,
		rpcCtx:   rpcCtx,
	}
	// Keep track of transactions which return errors so they can be removed
	return env, nil
}

func (miner *Miner) commitTransaction(env *environment, txM *transactionAndMeta) ([]*types.Log, error) {
	tx := txM.tx
	if tx.Type() == types.BlobTxType {
		return miner.commitBlobTransaction(env, txM)
	}
	receipt, err := miner.applyTransaction(env, txM)
	if err != nil {
		return nil, err
	}
	env.txs = append(env.txs, tx)
	env.size += tx.Size()
	env.receipts = append(env.receipts, receipt)
	env.tcount++
	return receipt.Logs, nil
}

func (miner *Miner) commitBlobTransaction(env *environment, txM *transactionAndMeta) ([]*types.Log, error) {
	tx := txM.tx
	sc := tx.BlobTxSidecar()
	if sc == nil {
		panic("blob transaction without blobs in miner")
	}
	// Checking against blob gas limit: It's kind of ugly to perform this check here, but there
	// isn't really a better place right now. The blob gas limit is checked at block validation time
	// and not during execution. This means core.ApplyTransaction will not return an error if the
	// tx has too many blobs. So we have to explicitly check it here.
	maxBlobs := eip4844.MaxBlobsPerBlock(miner.chainConfig, env.header.Time)
	if env.blobs+len(sc.Blobs) > maxBlobs {
		return nil, errors.New("max data blobs reached")
	}
	receipt, err := miner.applyTransaction(env, txM)
	if err != nil {
		return nil, err
	}
	txNoBlob := tx.WithoutBlobTxSidecar()
	env.txs = append(env.txs, tx.WithoutBlobTxSidecar())
	env.receipts = append(env.receipts, receipt)
	env.sidecars = append(env.sidecars, sc)
	env.blobs += len(sc.Blobs)
	env.size += txNoBlob.Size()
	*env.header.BlobGasUsed += receipt.BlobGasUsed
	env.tcount++
	return receipt.Logs, nil
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
func (miner *Miner) applyTransaction(env *environment, txM *transactionAndMeta) (*types.Receipt, error) {
	var (
		snap = env.state.Snapshot()
		gp   = env.gasPool.Gas()
		err  error
		tx   = txM.tx
	)

	snap = env.state.Snapshot()

	var receipt *types.Receipt
	receipt, err = core.ApplyTransaction(env.evm, env.gasPool, env.state, env.header, tx, &env.header.GasUsed)

	if err != nil {
		env.state.RevertToSnapshot(snap)
		env.gasPool.SetGas(gp)

		return nil, err
	}
	return receipt, err
}

func (miner *Miner) commitTransactions(env *environment, txs *transactionsByPriceAndNonce, interrupt *atomic.Int32) error {
	defer func(t0 time.Time) {
		l2CommitTxsTimer.Update(time.Since(t0))
	}(time.Now())

	// Short circuit if current is nil
	if env == nil {
		return nil
	}

	gasLimit := env.header.GasLimit
	if env.gasPool == nil {
		env.gasPool = new(core.GasPool).AddGas(gasLimit)
	}

	var coalescedLogs []*types.Log

	for {
		// Check interruption signal and abort building if it's fired.
		if interrupt != nil {
			if signal := interrupt.Load(); signal != commitInterruptNone {
				return signalToErr(signal)
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
		if left := uint64(eip4844.MaxBlobsPerBlock(miner.chainConfig, env.header.Time)); left < ltx.BlobGas {
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

		// if inclusion of the transaction would put the block size over the
		// maximum we allow, don't add any more txs to the payload.
		if !env.txFitsSize(tx) {
			break
		}

		// Only enforce tx limit if explicitly set (non-nil AND greater than 0)
		// If we have collected enough transactions then we're done
		if miner.config.TransactionLimit != nil && *miner.config.TransactionLimit > 0 && uint64(env.tcount) >= *miner.config.TransactionLimit {
			log.Trace("Transaction count limit reached", "have", env.tcount, "want", *miner.config.TransactionLimit)
			break
		}

		// Error may be ignored here. The error has already been checked
		// during transaction acceptance in the transaction pool.
		from, _ := types.Sender(env.signer, tx)

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !miner.chainConfig.IsEIP155(env.header.Number) {
			log.Trace("Ignoring replay protected transaction", "hash", ltx.Hash, "eip155", miner.chainConfig.EIP155Block)
			txs.Pop()
			continue
		}
		// Start executing the transaction
		env.state.SetTxContext(tx.Hash(), env.tcount)

		logs, err := miner.commitTransaction(env, &transactionAndMeta{tx: tx})
		switch {
		case vm.IsEVMTxLimitError(err):
			// Tx-level limit: tx is fundamentally too heavy and drop it from pool.
			log.Warn("Dropping tx due to tx-level limit", "hash", ltx.Hash, "sender", from, "err", err)
			txs.Pop()
			miner.backend.TxPool().RemoveTx(tx.Hash(), true, true)

		case vm.IsEVMBlockLimitError(err):
			// Block-level limit: tx is OK in principle, but not in this block.
			log.Trace("Deferring transaction due to block-level limit", "hash", ltx.Hash, "sender", from, "err", err)
			txs.Pop()

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
			txs.Shift()

		case (errors.Is(err, core.ErrInsufficientFunds) || errors.Is(errors.Unwrap(err), core.ErrInsufficientFunds)):
			log.Trace("Skipping tx with insufficient funds", "sender", from, "tx", tx.Hash().String())
			txs.Pop()
			miner.backend.TxPool().RemoveTx(tx.Hash(), true, true)

		default:
			// Transaction is regarded as invalid, drop all consecutive transactions from
			// the same sender because of `nonce-too-high` clause.
			log.Debug("Transaction failed, account skipped", "hash", ltx.Hash.String(), "err", err)
			txs.Shift()
		}
	}
	return nil
}

// fillTransactions retrieves the pending transactions from the txpool and fills them
// into the given sealing block. The transaction selection and ordering strategy can
// be customized with the plugin in the future.
func (miner *Miner) fillTransactions(interrupt *atomic.Int32, env *environment) error {
	pending := miner.backend.TxPool().Pending(true)

	// Split the pending transactions into locals and remotes.
	localTxs, remoteTxs := make(map[common.Address][]*txpool.LazyTransaction), pending
	for _, account := range miner.backend.TxPool().Locals() {
		if txs := remoteTxs[account]; len(txs) > 0 {
			delete(remoteTxs, account)
			filtered := txs[:0]
			for _, tx := range txs {
				if miner.chainConfig.IsOsaka(env.header.Number, env.header.Time) && tx.Gas > params.MaxTxGas {
					continue
				}
				filtered = append(filtered, tx)
			}
			localTxs[account] = filtered
		}
	}

	// Fill the block with all available pending transactions.
	if len(localTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, localTxs, env.header.BaseFee)
		if err := miner.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	if len(remoteTxs) > 0 {
		txs := newTransactionsByPriceAndNonce(env.signer, remoteTxs, env.header.BaseFee)
		if err := miner.commitTransactions(env, txs, interrupt); err != nil {
			return err
		}
	}
	return nil
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

// validateParams validates the given parameters.
// It currently checks that the parent block is known and that the timestamp is valid,
// i.e., after the parent block's timestamp.
// It returns an upper bound of the payload building duration as computed
// by the difference in block timestamps between the parent and genParams.
func (miner *Miner) validateParams(genParams *generateParams) (time.Duration, error) {
	miner.confMu.RLock()
	defer miner.confMu.RUnlock()

	// Find the parent block for sealing task
	parent := miner.chain.CurrentBlock()
	if genParams.parentHash != (common.Hash{}) {
		block := miner.chain.GetBlockByHash(genParams.parentHash)
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

// getBlockTrace generates a full trace of the given block by utilizing the state database and tracing environment.
// It returns the block trace or an error if tracing fails.
func (miner *Miner) getBlockTrace(block *types.Block) (*types.BlockTrace, error) {
	stateDB, trie, err := miner.getStateDB(block)
	if err != nil {
		return nil, fmt.Errorf("getBlockTrace: failed to get stateDB: %w", err)
	}
	traceEnv, err := legacyTracing.CreateTraceEnv(miner.chainConfig, miner.chain, miner.engine, miner.backend.ChainDb(), stateDB, trie, block, block.Header(), true)
	if err != nil {
		return nil, fmt.Errorf("getBlockTrace: failed to create trace env: %w", err)
	}

	result, err := traceEnv.GetBlockTrace(block)
	if err != nil {
		return nil, fmt.Errorf("getBlockTrace: failed to get block trace: %w", err)
	}

	return result, nil
}

// getStateDB retrieves the state database for a given block by its parent hash.
// It handles state determination based on if MonoFee was reached.
// Returns an error if the parent block is not found.
func (miner *Miner) getStateDB(block *types.Block) (*state.StateDB, *trie.StateTrie, error) {
	parent := miner.chain.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, nil, fmt.Errorf("getStateDB: parent block not found")
	}

	stateDB, err := miner.chain.StateAt(parent.Root())
	if err != nil {
		return nil, nil, fmt.Errorf("getStateDB: failed to get state: %w", err)
	}
	trie, err := trie.NewStateTrie(trie.StateTrieID(parent.Root()), stateDB.Database().TrieDB())
	if err != nil {
		return nil, nil, fmt.Errorf("getStateDB: failed to create new state trie: %w", err)
	}
	return stateDB, trie, nil
}
