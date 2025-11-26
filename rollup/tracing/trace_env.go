package tracing

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"strings"
	"sync"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/common/hexutil"
	"github.com/zircuit-labs/l2-geth/consensus"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/core/vm"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/eth/tracers"
	"github.com/zircuit-labs/l2-geth/eth/tracers/logger"
	"github.com/zircuit-labs/l2-geth/eth/tracers/native"
	"github.com/zircuit-labs/l2-geth/ethdb"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/l2-geth/params"
	"github.com/zircuit-labs/l2-geth/rollup/rcfg"
	"github.com/zircuit-labs/l2-geth/trie"
)

type TraceEnv struct {
	logConfig        *logger.Config
	commitAfterApply bool
	chainConfig      *params.ChainConfig

	coinbase common.Address

	signer   types.Signer
	state    *state.StateDB
	trie     *trie.StateTrie
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

	Codes            map[common.Hash]logger.CodeInfo
	TxStorageTraces  []*types.StorageTrace
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

// proofList implements ethdb.KeyValueWriter and collects the proofs as
// hex-strings for delivery to rpc-caller.
type proofList []string

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, hexutil.Encode(value))
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

func CreateTraceEnvHelper(chainConfig *params.ChainConfig, logConfig *logger.Config, blockCtx vm.BlockContext, coinbase common.Address, statedb *state.StateDB, trie *trie.StateTrie, rootBefore common.Hash, block *types.Block, commitAfterApply bool) *TraceEnv {
	return &TraceEnv{
		logConfig:        logConfig,
		commitAfterApply: commitAfterApply,
		chainConfig:      chainConfig,
		coinbase:         coinbase,
		signer:           types.MakeSigner(chainConfig, block.Number(), block.Time()),
		state:            statedb,
		trie:             trie,
		blockCtx:         blockCtx,
		StorageTrace: &types.StorageTrace{
			RootBefore:    rootBefore,
			RootAfter:     block.Root(),
			Proofs:        make(map[string][]hexutil.Bytes),
			StorageProofs: make(map[string]map[string][]hexutil.Bytes),
		},
		Codes:            make(map[common.Hash]logger.CodeInfo),
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
	trie *trie.StateTrie,
	block *types.Block,
	originalHeader *types.Header,
	commitAfterApply bool,
) (*TraceEnv, error) {
	if err := validateCreateTraceEnvParams(chainConfig, chainContext, engine, chaindb, statedb, block); err != nil {
		return nil, err
	}

	// we are using the original header here since the clique consensus uses the hash of the header
	// as part of their signature verification, which means any modifications will lead to recovering
	// the wrong signer and therefore the wrong coinbase. If there was no modification, block.Header() == originalHeader
	// the header modification takes place as part of DebugBlockTrace
	coinbase, err := engine.Author(originalHeader)
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
		trie,
		// it is assumed that statedb was opened on parent root instead of block root
		trie.Hash(),
		block,
		commitAfterApply,
	)

	key := coinbase.String()
	if _, exist := env.Proofs[key]; !exist {

		var proof proofList
		err := env.trie.Prove(crypto.Keccak256(coinbase.Bytes()), &proof)
		if err != nil {
			log.Error("Proof for coinbase not available", "coinbase", coinbase, "error", err)
			// but we still mark the proofs map with nil array
		}
		wrappedProof := make([]hexutil.Bytes, len(proof))
		for i, bt := range proof {
			wrappedProof[i] = []byte(bt)
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
	threads := min(runtime.NumCPU(), len(txs))
	for range threads {
		pend.Go(func() {
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
		})
	}

	// Feed the transactions into the tracers and return
	var failed error
	for i, tx := range txs {
		// Send the trace task over for execution
		jobs <- &txTraceTask{statedb: env.state.Copy(), index: i}

		// Generate the next state snapshot fast without tracing
		msg, _ := core.TransactionToMessage(tx, env.signer, block.BaseFee())
		env.state.SetTxContext(tx.Hash(), i)
		vmenv := vm.NewEVM(env.blockCtx, env.state, env.chainConfig, vm.Config{})
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
		Address:  from,
		Nonce:    state.GetNonce(from),
		Balance:  (*hexutil.Big)(state.GetBalance(from).ToBig()),
		CodeHash: state.GetCodeHash(from),
		CodeSize: uint64(state.GetCodeSize(from)),
	}
	var receiver *types.AccountWrapper
	if to != nil {
		receiver = &types.AccountWrapper{
			Address:  *to,
			Nonce:    state.GetNonce(*to),
			Balance:  (*hexutil.Big)(state.GetBalance(*to).ToBig()),
			CodeHash: state.GetCodeHash(*to),
			CodeSize: uint64(state.GetCodeSize(*to)),
		}
	}

	tracerContext := tracers.Context{
		BlockHash: block.Hash(),
		TxIndex:   index,
		TxHash:    tx.Hash(),
	}

	callTracer, err := tracers.DefaultDirectory.New("callTracer", &tracerContext, nil, env.chainConfig)
	if err != nil {
		return fmt.Errorf("failed to create callTracer: %w", err)
	}

	structLogger := logger.NewStructLogger(env.logConfig)
	tracer := NewMuxTracer(structLogger.Hooks(), callTracer.Hooks)

	state.SetTxContext(tx.Hash(), index)
	// Run the transaction with tracing enabled.
	vmenv := vm.NewEVM(env.blockCtx, state, env.chainConfig, vm.Config{Tracer: tracer.Hooks(), NoBaseFee: true}) // Debug: true

	// Call Prepare to clear out the statedb access list
	state.SetTxContext(txctx.TxHash, txctx.TxIndex)
	tracer.Hooks().OnTxStart(vmenv.GetVMContext(), tx, from)
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
		after = append(after, wrapAccount(acc, state))
	}

	txStorageTrace := &types.StorageTrace{
		Proofs:        make(map[string][]hexutil.Bytes),
		StorageProofs: make(map[string]map[string][]hexutil.Bytes),
	}
	// still we have no state root for per tx, only set the head and tail
	if index == 0 {
		txStorageTrace.RootBefore = env.trie.Hash()
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
	proofAccounts[vmenv.GetVMContext().Coinbase] = struct{}{}
	for addr := range proofAccounts {
		env.setAddrStorageProof(addr, txStorageTrace, state)
	}

	callTraceRaw, err := callTracer.GetResult()
	if err != nil {
		return fmt.Errorf("failed to get callTracer result: %w", err)
	}

	// For post pectra fork, collect proofs and trace data for each EOA call.
	// It is done by collecting the call trace and then iterating over the recipients,
	// checking whether the recipient is a deligation contract by.
	if env.chainConfig.IsPrague(block.Number(), block.Time()) {
		var callTrace native.CallFrame
		if err := callTrace.UnmarshalJSON(callTraceRaw); err != nil {
			return fmt.Errorf("unmarshalling call trace: %w", err)
		}

		for _, recipient := range collectRecipients(callTrace) {
			code := state.GetCode(recipient)
			if target, ok := types.ParseDelegation(code); len(code) != 0 && ok {
				targetCodeHash := state.GetCodeHash(target)
				env.cMu.Lock()
				env.Codes[targetCodeHash] = logger.CodeInfo{
					CodeHash: targetCodeHash,
					Code:     state.GetCode(target),
				}
				env.cMu.Unlock()

				env.setAddrStorageProof(target, txStorageTrace, state)
				after = append(after, wrapAccount(target, state))
			}
		}
	}

	var authListAccs []*types.AccountWrapper
	if setCodeAuths := tx.SetCodeAuthorizations(); setCodeAuths != nil {
		for _, auth := range setCodeAuths {
			address := auth.Address
			env.setAddrStorageProof(address, txStorageTrace, state)
			wrappedAccount := wrapAccount(address, state)
			after = append(after, wrappedAccount)
			authListAccs = append(authListAccs, wrappedAccount)
		}
	}

	proofStorages := structLogger.UpdatedStorages()
	for addr, keys := range proofStorages {
		if _, existed := txStorageTrace.StorageProofs[addr.String()]; !existed {
			txStorageTrace.StorageProofs[addr.String()] = make(map[string][]hexutil.Bytes)
		}

		env.sMu.Lock()
		trie, err := state.OpenStorageTrie(addr)
		if err != nil {
			// but we still continue to next address
			log.Error("Storage trie not available", "error", err, "address", addr)
			env.sMu.Unlock()
			continue
		}
		env.sMu.Unlock()

		for key := range keys {
			addrStr := addr.String()
			keyStr := key.String()

			txm := txStorageTrace.StorageProofs[addrStr]
			env.sMu.Lock()
			m, existed := env.StorageProofs[addrStr]
			if !existed {
				m = make(map[string][]hexutil.Bytes)
				env.StorageProofs[addrStr] = m
			}

			if proof, existed := m[keyStr]; existed {
				txm[keyStr] = proof
				env.sMu.Unlock()
				continue
			}
			env.sMu.Unlock()

			var proof proofList
			var err error
			err = trie.Prove(crypto.Keccak256(key.Bytes()), &proof)
			if err != nil {
				log.Error("Storage proof not available", "error", err, "address", addrStr, "key", keyStr)
				// but we still mark the proofs map with nil array
			}
			wrappedProof := make([]hexutil.Bytes, len(proof))
			for i, bt := range proof {
				wrappedProof[i] = []byte(bt)
			}
			env.sMu.Lock()
			txm[keyStr] = wrappedProof
			m[keyStr] = wrappedProof
			env.sMu.Unlock()
		}
	}

	env.ExecutionResults[index] = &types.ExecutionResult{
		From:              sender,
		To:                receiver,
		AccountCreated:    createdAcc,
		AccountsAfter:     after,
		Gas:               result.UsedGas,
		Failed:            result.Failed(),
		ReturnValue:       fmt.Sprintf("%x", returnVal),
		StructLogs:        logger.FormatLogs(structLogger.StructLogs()),
		CallTrace:         callTraceRaw,
		AuthorizationList: authListAccs,
	}
	env.TxStorageTraces[index] = txStorageTrace

	return nil
}

func collectRecipients(traceCall native.CallFrame) []common.Address {
	var recipients []common.Address

	if traceCall.To != nil {
		recipients = append(recipients, *traceCall.To)
	}

	for _, nestedTraceCall := range traceCall.Calls {
		recipients = append(recipients, collectRecipients(nestedTraceCall)...)
	}

	return recipients
}

func wrapAccount(acc common.Address, state *state.StateDB) *types.AccountWrapper {
	return &types.AccountWrapper{
		Address:  acc,
		Nonce:    state.GetNonce(acc),
		Balance:  (*hexutil.Big)(state.GetBalance(acc).ToBig()),
		CodeHash: state.GetCodeHash(acc),
		CodeSize: uint64(state.GetCodeSize(acc)),
	}
}

func (env *TraceEnv) setAddrStorageProof(addr common.Address, txStorageTrace *types.StorageTrace, state *state.StateDB) {
	addrStr := addr.String()
	env.pMu.Lock()
	checkedProof, existed := env.Proofs[addrStr]
	if existed {
		txStorageTrace.Proofs[addrStr] = checkedProof
	}
	env.pMu.Unlock()
	if existed {
		return
	}

	var proof proofList
	err := env.trie.Prove(crypto.Keccak256(addr.Bytes()), &proof)
	if err != nil {
		log.Error("Proof not available", "address", addrStr, "error", err)
		// but we still mark the proofs map with nil array
	}
	wrappedProof := make([]hexutil.Bytes, len(proof))
	for i, bt := range proof {
		wrappedProof[i] = []byte(bt)
	}

	env.pMu.Lock()
	env.Proofs[addrStr] = wrappedProof
	txStorageTrace.Proofs[addrStr] = wrappedProof
	env.pMu.Unlock()
}

// fillBlockTrace content after all the txs are finished running.
func (env *TraceEnv) fillBlockTrace(block *types.Block) (*types.BlockTrace, error) {
	statedb := env.state

	txs := make([]*types.TransactionData, block.Transactions().Len())
	for i, tx := range block.Transactions() {
		txToAdd := types.NewTransactionData(tx, block.NumberU64(), block.Time(), env.chainConfig, env.blockCtx.BaseFee)

		if tx.IsDepositTx() {
			// Rewrite tx hash to provide compliance with Scroll prover.
			txToAdd.TxHash = types.GetProvableHash(tx, txToAdd.From).Hex()
		}

		txs[i] = txToAdd
	}

	intrinsicStorageProofs := map[common.Address][]common.Hash{
		rcfg.L1GasPriceOracleAddress: {
			rcfg.L1BaseFeeSlot,
			rcfg.OverheadSlot,
			rcfg.ScalarSlot,
			rcfg.L1BlobBaseFeeSlot,
			rcfg.ScalarsSlots,
			rcfg.OperatorCostSlot,
		},
	}

	for addr, storages := range intrinsicStorageProofs {
		if _, existed := env.Proofs[addr.String()]; !existed {
			var proof proofList
			if err := env.trie.Prove(crypto.Keccak256(addr.Bytes()), &proof); err != nil {
				log.Error("Proof for intrinstic address not available", "error", err, "address", addr)
			} else {
				wrappedProof := make([]hexutil.Bytes, len(proof))
				for i, bt := range proof {
					wrappedProof[i] = []byte(bt)
				}
				env.Proofs[addr.String()] = wrappedProof
			}
		}

		if _, existed := env.StorageProofs[addr.String()]; !existed {
			env.StorageProofs[addr.String()] = make(map[string][]hexutil.Bytes)
		}

		for _, slot := range storages {
			if _, existed := env.StorageProofs[addr.String()][slot.String()]; !existed {
				var proof proofList
				if trie, err := statedb.OpenStorageTrie(addr); err != nil {
					log.Error("Storage proof for intrinstic address not available", "error", err, "address", addr)
				} else if err := trie.Prove(crypto.Keccak256(slot.Bytes()), &proof); err != nil {
					log.Error("Get storage proof for intrinstic address failed", "error", err, "address", addr, "slot", slot)
				} else {
					wrappedProof := make([]hexutil.Bytes, len(proof))
					for i, bt := range proof {
						wrappedProof[i] = []byte(bt)
					}
					env.StorageProofs[addr.String()][slot.String()] = wrappedProof
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
		Version: fmt.Sprintf("zircuit-l2geth %s", params.VersionWithMeta),
		Coinbase: &types.AccountWrapper{
			Address:  env.coinbase,
			Nonce:    statedb.GetNonce(env.coinbase),
			Balance:  (*hexutil.Big)(statedb.GetBalance(env.coinbase).ToBig()),
			CodeHash: statedb.GetCodeHash(env.coinbase),
			CodeSize: uint64(statedb.GetCodeSize(env.coinbase)),
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
		}
	}

	blockTrace.Bytecodes = append(blockTrace.Bytecodes, &types.BytecodeTrace{
		CodeHash: types.EmptyCodeHash,
		Code:     hexutil.Bytes{},
	})
	for _, codeInfo := range env.Codes {
		blockTrace.Bytecodes = append(blockTrace.Bytecodes, &types.BytecodeTrace{
			CodeHash: codeInfo.CodeHash,
			Code:     codeInfo.Code,
		})
	}

	return blockTrace, nil
}

func (env *TraceEnv) ResetState(state *state.StateDB) {
	env.state = state
}

func (env *TraceEnv) FinaliseState(blockNumber *big.Int) {
	env.state.Finalise(env.chainConfig.IsEIP158(blockNumber))
}
