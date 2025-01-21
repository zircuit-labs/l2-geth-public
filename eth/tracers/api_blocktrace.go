package tracers

import (
	"context"
	"encoding/hex"
	"errors"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
	"github.com/zircuit-labs/l2-geth-public/consensus"
	"github.com/zircuit-labs/l2-geth-public/core"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/eth/tracers/logger"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/rollup/circuitcapacitychecker"
	"github.com/zircuit-labs/l2-geth-public/rpc"
)

var (
	ErrNoScrollTracerWrapper              = errors.New("no ScrollTracerWrapper")
	ErrGenesisIsNotTraceable              = errors.New("genesis is not traceable")
	ErrNeitherBlockNumberNorHashSpecified = errors.New("invalid arguments; neither block number nor hash specified")
)

type TraceBlock interface {
	DebugBlockTrace(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash, config *TraceConfig) (trace *types.DebugBlockTraceResult, err error)
}

type scrollTracerWrapper interface {
	CreateTraceEnvAndGetBlockTrace(*params.ChainConfig, core.ChainContext, consensus.Engine, ethdb.Database, *state.StateDB, *types.Block, bool) (*types.BlockTrace, error)
	GetCodesAndProofs(block *types.Block, trace *types.BlockTrace, isLatest bool) (map[*common.Address]string, []*circuitcapacitychecker.MiniAccountResult, error)
}

type proofList []string

func (n *proofList) Put(key []byte, value []byte) error {
	*n = append(*n, hexutil.Encode(value))
	return nil
}

func (n *proofList) Delete(key []byte) error {
	panic("not supported")
}

// DebugBlockTrace replays the block and returns the structured BlockTrace, code map and proofs by hash or number.
func (api *API) DebugBlockTrace(ctx context.Context, blockNrOrHash rpc.BlockNumberOrHash, config *TraceConfig) (*types.DebugBlockTraceResult, error) {
	if api.scrollTracerWrapper == nil {
		return nil, ErrNoScrollTracerWrapper
	}

	var (
		block *types.Block
		err   error
	)
	if number, ok := blockNrOrHash.Number(); ok {
		block, err = api.blockByNumber(ctx, number)
	} else if hash, ok := blockNrOrHash.Hash(); ok {
		block, err = api.blockByHash(ctx, hash)
	} else {
		return nil, ErrNeitherBlockNumberNorHashSpecified
	}
	if err != nil {
		return nil, err
	}
	if block.NumberU64() == 0 {
		return nil, ErrGenesisIsNotTraceable
	}

	return api.createTraceEnvAndGetBlockTrace(ctx, config, block)
}

// Make trace environment for current block, and then get the trace for the block.
func (api *API) createTraceEnvAndGetBlockTrace(ctx context.Context, config *TraceConfig, block *types.Block) (*types.DebugBlockTraceResult, error) {
	if config == nil {
		config = &TraceConfig{
			Config: &logger.Config{
				DisableStorage:   true,
				DisableStack:     true,
				EnableMemory:     false,
				EnableReturnData: true,
			},
		}
	} else if config.Tracer != nil {
		config.Tracer = nil
		log.Warn("Tracer params is unsupported")
	}

	parent, err := api.blockByNumberAndHash(ctx, rpc.BlockNumber(block.NumberU64()-1), block.ParentHash())
	if err != nil {
		return nil, err
	}
	reexec := defaultTraceReexec
	if config != nil && config.Reexec != nil {
		reexec = *config.Reexec
	}
	statedb, _, err := api.backend.StateAtBlock(ctx, parent, reexec, nil, true, true)
	if err != nil {
		return nil, err
	}

	blockTrace, err := api.scrollTracerWrapper.CreateTraceEnvAndGetBlockTrace(
		api.backend.ChainConfig(),
		api.chainContext(ctx),
		api.backend.Engine(),
		api.backend.ChainDb(),
		statedb,
		block,
		true,
	)
	if err != nil {
		return nil, err
	}

	// pass false to get codes and proofs not for latest block, but for the previous one
	codeMap, proofs, err := api.scrollTracerWrapper.GetCodesAndProofs(block, blockTrace, false)
	if err != nil {
		return nil, err
	}

	proofsToReturn := make([]*types.AccountResult, 0)
	for _, proof := range proofs {
		if proof == nil {
			continue
		}
		storageProofsToReturn := make([]types.StorageResult, 0)
		for _, storageProof := range proof.StorageProof {
			storageProofToReturn := types.StorageResult{
				Key:   storageProof.Key,
				Value: storageProof.Value,
				Proof: storageProof.Proof,
			}
			storageProofsToReturn = append(storageProofsToReturn, storageProofToReturn)
		}

		proofToReturn := &types.AccountResult{
			Address:          proof.Address,
			AccountProof:     proof.AccountProof,
			Balance:          proof.Balance,
			KeccakCodeHash:   proof.KeccakCodeHash,
			PoseidonCodeHash: proof.PoseidonCodeHash,
			CodeSize:         proof.CodeSize,
			Nonce:            proof.Nonce,
			StorageHash:      proof.StorageHash,
			StorageProof:     storageProofsToReturn,
		}
		proofsToReturn = append(proofsToReturn, proofToReturn)
	}

	codeMapToReturn := make(map[common.Address]hexutil.Bytes)
	for addr, code := range codeMap {
		if addr == nil {
			continue
		}
		res, err := hex.DecodeString(code)
		if err != nil {
			return nil, err
		}
		codeMapToReturn[*addr] = res
	}

	return &types.DebugBlockTraceResult{
		BlockTrace: blockTrace,
		CodeMap:    codeMapToReturn,
		Proofs:     proofsToReturn,
	}, nil
}
