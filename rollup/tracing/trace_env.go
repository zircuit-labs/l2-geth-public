package tracing

import (
	"bytes"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
	"github.com/zircuit-labs/l2-geth-public/consensus"
	"github.com/zircuit-labs/l2-geth-public/core"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/core/vm"
	"github.com/zircuit-labs/l2-geth-public/eth/tracers"
	"github.com/zircuit-labs/l2-geth-public/eth/tracers/logger"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/rollup/rcfg"
	"github.com/zircuit-labs/l2-geth-public/trie/zkproof"
)

type TraceEnv struct {
	logConfig        *logger.Config
	commitAfterApply bool
	chainConfig      *params.ChainConfig

	coinbase common.Address

	signer   types.Signer
	state    *state.StateDB
	blockCtx vm.BlockContext

	// The following Mutex is used to protect against parallel read/write,
	// since txs are executed in parallel.
	cMu sync.Mutex // for `TraceEnv.Codes`

	// pMu lock is used to protect Proofs' read and write mutual exclusion,
	// since txs are executed in parallel, so this lock is required.
	pMu sync.Mutex
	// sMu is required because of txs are executed in parallel,
	// this lock is used to protect StorageTrace's read and write mutual exclusion.
	sMu sync.Mutex
	*types.StorageTrace

	Codes           map[common.Hash]logger.CodeInfo
	TxStorageTraces []*types.StorageTrace
	// zktrie tracer is used for zktrie storage to build additional deletion proof
	ZkTrieTracer     map[string]state.ZktrieProofTracer
	ExecutionResults []*types.ExecutionResult
}

// Context is the same as Context in eth/tracers/tracers.go
type Context struct {
	BlockHash common.Hash
	TxIndex   int
	TxHash    common.Hash
}

// txTraceTask is the same as txTraceTask in eth/tracers/api.go
type txTraceTask struct {
	statedb *state.StateDB
	index   int
}

func CreateTraceEnvHelper(chainConfig *params.ChainConfig, logConfig *logger.Config, blockCtx vm.BlockContext, coinbase common.Address, statedb *state.StateDB, rootBefore common.Hash, block *types.Block, commitAfterApply bool) *TraceEnv {
	return &TraceEnv{
		logConfig:        logConfig,
		commitAfterApply: commitAfterApply,
		chainConfig:      chainConfig,
		coinbase:         coinbase,
		signer:           types.MakeSigner(chainConfig, block.Number(), block.Time()),
		state:            statedb,
		blockCtx:         blockCtx,
		StorageTrace: &types.StorageTrace{
			RootBefore:    rootBefore,
			RootAfter:     block.Root(),
			Proofs:        make(map[string][]hexutil.Bytes),
			StorageProofs: make(map[string]map[string][]hexutil.Bytes),
		},
		Codes:            make(map[common.Hash]logger.CodeInfo),
		ZkTrieTracer:     make(map[string]state.ZktrieProofTracer),
		ExecutionResults: make([]*types.ExecutionResult, block.Transactions().Len()),
		TxStorageTraces:  make([]*types.StorageTrace, block.Transactions().Len()),
	}
}

func validateCreateTraceEnvParams(chainConfig *params.ChainConfig, chainContext core.ChainContext, engine consensus.Engine, chaindb ethdb.Database, statedb *state.StateDB, block *types.Block) error {
	var invalidParams []string

	if chainConfig == nil {
		invalidParams = append(invalidParams, "chainConfig")
	}
	if chainContext == nil {
		invalidParams = append(invalidParams, "chainContext")
	}
	if engine == nil {
		invalidParams = append(invalidParams, "engine")
	}
	if chaindb == nil {
		invalidParams = append(invalidParams, "chaindb")
	}
	if statedb == nil {
		invalidParams = append(invalidParams, "statedb")
	}
	if block == nil {
		invalidParams = append(invalidParams, "block")
	}

	if len(invalidParams) > 0 {
		return fmt.Errorf("CreateTraceEnv parameter validation failed: %s are nil", strings.Join(invalidParams, ", "))
	}
	return nil
}

func CreateTraceEnv(
	chainConfig *params.ChainConfig,
	chainContext core.ChainContext,
	engine consensus.Engine,
	chaindb ethdb.Database,
	statedb *state.StateDB,
	block *types.Block,
	commitAfterApply bool,
) (*TraceEnv, error) {

	if err := validateCreateTraceEnvParams(chainConfig, chainContext, engine, chaindb, statedb, block); err != nil {
		return nil, err
	}

	var coinbase common.Address
	var err error
	coinbase, err = engine.Author(block.Header())
	if err != nil {
		log.Warn("recover coinbase in CreateTraceEnv fail. using zero-address", "err", err, "blockNumber", block.Header().Number, "headerHash", block.Header().Hash())
	}

	env := CreateTraceEnvHelper(
		chainConfig,
		&logger.Config{
			EnableMemory:     false,
			EnableReturnData: true,
		},
		core.NewEVMBlockContext(block.Header(), chainContext, nil, chainConfig, statedb),
		coinbase,
		statedb,
		statedb.GetRootHash(),
		block,
		commitAfterApply,
	)

	key := coinbase.String()
	if _, exist := env.Proofs[key]; !exist {
		proof, err := env.state.GetProof(coinbase)
		if err != nil {
			log.Error("Proof for coinbase not available", "coinbase", coinbase, "error", err)
			// but we still mark the proofs map with nil array
		}
		wrappedProof := make([]hexutil.Bytes, len(proof))
		for i, bt := range proof {
			wrappedProof[i] = bt
		}
		env.Proofs[key] = wrappedProof
	}

	return env, nil
}

func (env *TraceEnv) GetBlockTrace(block *types.Block) (*types.BlockTrace, error) {
	// Execute all the transaction contained within the block concurrently
	var (
		txs   = block.Transactions()
		pend  = new(sync.WaitGroup)
		jobs  = make(chan *txTraceTask, len(txs))
		errCh = make(chan error, 1)
	)
	threads := runtime.NumCPU()
	if threads > len(txs) {
		threads = len(txs)
	}
	for th := 0; th < threads; th++ {
		pend.Add(1)
		go func() {
			defer pend.Done()
			// Fetch and execute the next transaction trace tasks
			for task := range jobs {
				if err := env.getTxResult(task.statedb, task.index, block); err != nil {
					select {
					case errCh <- err:
					default:
					}
					// the error indicates that the tx cannot be applied on the state
					// if it is from mempool, the tx will eventually be skipped and other txs will be tried
					log.Warn(
						"failed to trace tx",
						"txHash", txs[task.index].Hash().String(),
						"blockHash", block.Hash().String(),
						"blockNumber", block.NumberU64(),
						"err", err,
					)
				}
			}
		}()
	}

	// Feed the transactions into the tracers and return
	var failed error
	for i, tx := range txs {
		// Send the trace task over for execution
		jobs <- &txTraceTask{statedb: env.state.Copy(), index: i}

		// Generate the next state snapshot fast without tracing
		msg, _ := core.TransactionToMessage(tx, env.signer, block.BaseFee())
		env.state.SetTxContext(tx.Hash(), i)
		vmenv := vm.NewEVM(env.blockCtx, core.NewEVMTxContext(msg), env.state, env.chainConfig, vm.Config{})
		if _, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.Gas())); err != nil {
			failed = err
			break
		}
		if env.commitAfterApply {
			env.state.Finalise(vmenv.ChainConfig().IsEIP158(block.Number()))
		}
	}
	close(jobs)
	pend.Wait()

	// after all tx has been traced, collect "deletion proof" for zktrie
	for _, tracer := range env.ZkTrieTracer {
		delProofs, err := tracer.GetDeletionProofs()
		if err != nil {
			log.Error("deletion proof failure", "error", err)
		} else {
			for _, proof := range delProofs {
				env.DeletionProofs = append(env.DeletionProofs, proof)
			}
		}
	}

	// build dummy per-tx deletion proof
	for _, txStorageTrace := range env.TxStorageTraces {
		if txStorageTrace != nil {
			txStorageTrace.DeletionProofs = env.DeletionProofs
		}
	}

	// If execution failed in between, abort
	select {
	case err := <-errCh:
		return nil, err
	default:
		if failed != nil {
			return nil, failed
		}
	}

	return env.fillBlockTrace(block)
}

func (env *TraceEnv) getTxResult(state *state.StateDB, index int, block *types.Block) error {
	tx := block.Transactions()[index]
	msg, _ := core.TransactionToMessage(tx, env.signer, block.BaseFee())
	from, _ := types.Sender(env.signer, tx)
	to := tx.To()

	txctx := &Context{
		BlockHash: block.TxHash(),
		TxIndex:   index,
		TxHash:    tx.Hash(),
	}

	sender := &types.AccountWrapper{
		Address:          from,
		Nonce:            state.GetNonce(from),
		Balance:          (*hexutil.Big)(state.GetBalance(from).ToBig()),
		KeccakCodeHash:   state.GetKeccakCodeHash(from),
		PoseidonCodeHash: state.GetPoseidonCodeHash(from),
		CodeSize:         state.GetCodeSize(from),
	}
	var receiver *types.AccountWrapper
	if to != nil {
		receiver = &types.AccountWrapper{
			Address:          *to,
			Nonce:            state.GetNonce(*to),
			Balance:          (*hexutil.Big)(state.GetBalance(*to).ToBig()),
			KeccakCodeHash:   state.GetKeccakCodeHash(*to),
			PoseidonCodeHash: state.GetPoseidonCodeHash(*to),
			CodeSize:         state.GetCodeSize(*to),
		}
	}

	tracerContext := tracers.Context{
		BlockHash: block.Hash(),
		TxIndex:   index,
		TxHash:    tx.Hash(),
	}

	callTracer, err := tracers.DefaultDirectory.New("callTracer", &tracerContext, nil)
	if err != nil {
		return fmt.Errorf("failed to create callTracer: %w", err)
	}

	structLogger := logger.NewStructLogger(env.logConfig)
	tracer := NewMuxTracer(structLogger, callTracer)
	// Run the transaction with tracing enabled.
	vmenv := vm.NewEVM(env.blockCtx, core.NewEVMTxContext(msg), state, env.chainConfig, vm.Config{Tracer: tracer, NoBaseFee: true}) // Debug: true

	// Call Prepare to clear out the statedb access list
	state.SetTxContext(txctx.TxHash, txctx.TxIndex)

	result, err := core.ApplyMessage(vmenv, msg, new(core.GasPool).AddGas(tx.Gas()))
	if err != nil {
		return fmt.Errorf("tracing failed: %w", err)
	}
	// If the result contains a revert reason, return it.
	returnVal := result.Return()
	if len(result.Revert()) > 0 {
		returnVal = result.Revert()
	}

	createdAcc := structLogger.CreatedAccount()
	var after []*types.AccountWrapper
	if to == nil {
		if createdAcc == nil {
			return errors.New("unexpected tx: address for created contract unavailable")
		}
		to = &createdAcc.Address
	}
	// collect affected account after tx being applied
	for _, acc := range []common.Address{from, *to, env.coinbase} {
		after = append(after, &types.AccountWrapper{
			Address:          acc,
			Nonce:            state.GetNonce(acc),
			Balance:          (*hexutil.Big)(state.GetBalance(acc).ToBig()),
			KeccakCodeHash:   state.GetKeccakCodeHash(acc),
			PoseidonCodeHash: state.GetPoseidonCodeHash(acc),
			CodeSize:         state.GetCodeSize(acc),
		})
	}

	txStorageTrace := &types.StorageTrace{
		Proofs:        make(map[string][]hexutil.Bytes),
		StorageProofs: make(map[string]map[string][]hexutil.Bytes),
	}
	// still we have no state root for per tx, only set the head and tail
	if index == 0 {
		txStorageTrace.RootBefore = state.GetRootHash()
	} else if index == len(block.Transactions())-1 {
		txStorageTrace.RootAfter = block.Root()
	}

	// merge bytecodes
	env.cMu.Lock()
	for codeHash, codeInfo := range structLogger.TracedBytecodes() {
		if codeHash != (common.Hash{}) {
			env.Codes[codeHash] = codeInfo
		}
	}
	env.cMu.Unlock()

	// merge required proof data
	proofAccounts := structLogger.UpdatedAccounts()
	proofAccounts[vmenv.FeeRecipient()] = struct{}{}
	for addr := range proofAccounts {
		addrStr := addr.String()

		env.pMu.Lock()
		checkedProof, existed := env.Proofs[addrStr]
		if existed {
			txStorageTrace.Proofs[addrStr] = checkedProof
		}
		env.pMu.Unlock()
		if existed {
			continue
		}
		proof, err := state.GetProof(addr)
		if err != nil {
			log.Error("Proof not available", "address", addrStr, "error", err)
			// but we still mark the proofs map with nil array
		}
		wrappedProof := types.WrapProof(proof)
		env.pMu.Lock()
		env.Proofs[addrStr] = wrappedProof
		txStorageTrace.Proofs[addrStr] = wrappedProof
		env.pMu.Unlock()
	}

	proofStorages := structLogger.UpdatedStorages()
	for addr, keys := range proofStorages {
		if _, existed := txStorageTrace.StorageProofs[addr.String()]; !existed {
			txStorageTrace.StorageProofs[addr.String()] = make(map[string][]hexutil.Bytes)
		}

		env.sMu.Lock()
		trie, err := state.GetStorageTrieForProof(addr)
		if err != nil {
			// but we still continue to next address
			log.Error("Storage trie not available", "error", err, "address", addr)
			env.sMu.Unlock()
			continue
		}
		zktrieTracer := state.NewProofTracer(trie)
		env.sMu.Unlock()

		for key, values := range keys {
			addrStr := addr.String()
			keyStr := key.String()
			isDelete := bytes.Equal(values.Bytes(), common.Hash{}.Bytes())

			txm := txStorageTrace.StorageProofs[addrStr]
			env.sMu.Lock()
			m, existed := env.StorageProofs[addrStr]
			if !existed {
				m = make(map[string][]hexutil.Bytes)
				env.StorageProofs[addrStr] = m
			}
			if zktrieTracer.Available() && !env.ZkTrieTracer[addrStr].Available() {
				env.ZkTrieTracer[addrStr] = state.NewProofTracer(trie)
			}

			if proof, existed := m[keyStr]; existed {
				txm[keyStr] = proof
				// still need to touch tracer for deletion
				if isDelete && zktrieTracer.Available() {
					env.ZkTrieTracer[addrStr].MarkDeletion(key)
				}
				env.sMu.Unlock()
				continue
			}
			env.sMu.Unlock()

			var proof [][]byte
			var err error
			if zktrieTracer.Available() {
				proof, err = state.GetSecureTrieProof(zktrieTracer, key)
			} else {
				proof, err = state.GetSecureTrieProof(trie, key)
			}
			if err != nil {
				log.Error("Storage proof not available", "error", err, "address", addrStr, "key", keyStr)
				// but we still mark the proofs map with nil array
			}
			wrappedProof := types.WrapProof(proof)
			env.sMu.Lock()
			txm[keyStr] = wrappedProof
			m[keyStr] = wrappedProof
			if zktrieTracer.Available() {
				if isDelete {
					zktrieTracer.MarkDeletion(key)
				}
				env.ZkTrieTracer[addrStr].Merge(zktrieTracer)
			}
			env.sMu.Unlock()
		}
	}

	callTrace, err := callTracer.GetResult()
	if err != nil {
		return fmt.Errorf("failed to get callTracer result: %w", err)
	}

	env.ExecutionResults[index] = &types.ExecutionResult{
		From:           sender,
		To:             receiver,
		AccountCreated: createdAcc,
		AccountsAfter:  after,
		Gas:            result.UsedGas,
		Failed:         result.Failed(),
		ReturnValue:    fmt.Sprintf("%x", returnVal),
		StructLogs:     logger.FormatLogs(structLogger.StructLogs()),
		CallTrace:      callTrace,
	}
	env.TxStorageTraces[index] = txStorageTrace

	return nil
}

// fillBlockTrace content after all the txs are finished running.
func (env *TraceEnv) fillBlockTrace(block *types.Block) (*types.BlockTrace, error) {
	statedb := env.state

	txs := make([]*types.TransactionData, block.Transactions().Len())
	for i, tx := range block.Transactions() {
		txs[i] = types.NewTransactionData(tx, block.NumberU64(), block.Time(), env.chainConfig)
	}

	intrinsicStorageProofs := map[common.Address][]common.Hash{
		rcfg.L2MessageQueueAddress: {rcfg.WithdrawTrieRootSlot},
		rcfg.L1GasPriceOracleAddress: {
			rcfg.L1BaseFeeSlot,
			rcfg.OverheadSlot,
			rcfg.ScalarSlot,
			rcfg.L1BlobBaseFeeSlot,
			rcfg.CommitScalarSlot,
			rcfg.BlobScalarSlot,
			rcfg.IsCurieSlot,
		},
	}

	for addr, storages := range intrinsicStorageProofs {
		if _, existed := env.Proofs[addr.String()]; !existed {
			if proof, err := statedb.GetProof(addr); err != nil {
				log.Error("Proof for intrinstic address not available", "error", err, "address", addr)
			} else {
				env.Proofs[addr.String()] = types.WrapProof(proof)
			}
		}

		if _, existed := env.StorageProofs[addr.String()]; !existed {
			env.StorageProofs[addr.String()] = make(map[string][]hexutil.Bytes)
		}

		for _, slot := range storages {
			if _, existed := env.StorageProofs[addr.String()][slot.String()]; !existed {
				if trie, err := statedb.GetStorageTrieForProof(addr); err != nil {
					log.Error("Storage proof for intrinstic address not available", "error", err, "address", addr)
				} else if proof, err := statedb.GetSecureTrieProof(trie, slot); err != nil {
					log.Error("Get storage proof for intrinstic address failed", "error", err, "address", addr, "slot", slot)
				} else {
					env.StorageProofs[addr.String()][slot.String()] = types.WrapProof(proof)
				}
			}
		}
	}

	var chainID uint64
	if env.chainConfig.ChainID != nil {
		chainID = env.chainConfig.ChainID.Uint64()
	}
	blockTrace := &types.BlockTrace{
		ChainID: chainID,
		Version: params.ArchiveVersion(params.CommitHash),
		Coinbase: &types.AccountWrapper{
			Address:          env.coinbase,
			Nonce:            statedb.GetNonce(env.coinbase),
			Balance:          (*hexutil.Big)(statedb.GetBalance(env.coinbase).ToBig()),
			KeccakCodeHash:   statedb.GetKeccakCodeHash(env.coinbase),
			PoseidonCodeHash: statedb.GetPoseidonCodeHash(env.coinbase),
			CodeSize:         statedb.GetCodeSize(env.coinbase),
		},
		Header:           block.Header(),
		Bytecodes:        make([]*types.BytecodeTrace, 0, len(env.Codes)),
		StorageTrace:     env.StorageTrace,
		ExecutionResults: env.ExecutionResults,
		TxStorageTraces:  env.TxStorageTraces,
		Transactions:     txs,
	}

	for i, tx := range block.Transactions() {
		evmTrace := env.ExecutionResults[i]
		// Contract is created.
		if tx.To() == nil {
			evmTrace.ByteCode = hexutil.Encode(tx.Data())
		} else { // contract call be included at this case, specially fallback call's data is empty.
			evmTrace.ByteCode = hexutil.Encode(statedb.GetCode(*tx.To()))
			// Get tx.to address's code hash.
			codeHash := statedb.GetPoseidonCodeHash(*tx.To())
			evmTrace.PoseidonCodeHash = &codeHash
		}
	}

	// only zktrie model has the ability to get `mptwitness`.
	if statedb.IsZktrie() {
		// we use MPTWitnessNothing by default and do not allow switch among MPTWitnessType atm.
		// MPTWitness will be removed from traces in the future.
		if err := zkproof.FillBlockTraceForMPTWitness(zkproof.MPTWitnessNothing, blockTrace); err != nil {
			log.Error("fill mpt witness fail", "error", err)
		}
	}

	blockTrace.Bytecodes = append(blockTrace.Bytecodes, &types.BytecodeTrace{
		CodeSize:         0,
		KeccakCodeHash:   types.EmptyKeccakCodeHash,
		PoseidonCodeHash: types.EmptyPoseidonCodeHash,
		Code:             hexutil.Bytes{},
	})
	for _, codeInfo := range env.Codes {
		blockTrace.Bytecodes = append(blockTrace.Bytecodes, &types.BytecodeTrace{
			CodeSize:         codeInfo.CodeSize,
			KeccakCodeHash:   codeInfo.KeccakCodeHash,
			PoseidonCodeHash: codeInfo.PoseidonCodeHash,
			Code:             codeInfo.Code,
		})
	}

	return blockTrace, nil
}
