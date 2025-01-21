package tracing

import (
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/consensus"
	"github.com/zircuit-labs/l2-geth-public/core"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	_ "github.com/zircuit-labs/l2-geth-public/eth/tracers/native"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/rollup/circuitcapacitychecker"
)

// TracerWrapper implements ScrollTracerWrapper interface
type TracerWrapper struct {
	cccHelper *circuitcapacitychecker.CCCHelper
}

// NewTracerWrapper TracerWrapper creates a new TracerWrapper
func NewTracerWrapper(b circuitcapacitychecker.MiniBlockChain) *TracerWrapper {
	return &TracerWrapper{
		cccHelper: circuitcapacitychecker.NewCCCHelper(
			circuitcapacitychecker.NewMiniBlockChainAPI(b),
			circuitcapacitychecker.NewStateAccessesFinder(),
		),
	}
}

// CreateTraceEnvAndGetBlockTrace wraps the whole block tracing logic for a block
func (tw *TracerWrapper) CreateTraceEnvAndGetBlockTrace(
	chainConfig *params.ChainConfig, chainContext core.ChainContext,
	engine consensus.Engine, chaindb ethdb.Database, statedb *state.StateDB,
	block *types.Block, commitAfterApply bool,
) (*types.BlockTrace, error) {
	traceEnv, err := CreateTraceEnv(chainConfig, chainContext, engine, chaindb, statedb, block, commitAfterApply)
	if err != nil {
		return nil, err
	}

	return traceEnv.GetBlockTrace(block)
}

func (tw *TracerWrapper) GetCodesAndProofs(
	block *types.Block, trace *types.BlockTrace, isLatest bool,
) (map[*common.Address]string, []*circuitcapacitychecker.MiniAccountResult, error) {
	return tw.cccHelper.GetCodesAndProofs(block, trace, isLatest)
}
