package vm

import "github.com/zircuit-labs/l2-geth/common"

// ExecutionLimiter represents a strategy for enforcing execution limits within
// the EVM. Different implementations (count-based, cycle-based, etc.) can be
// swapped in depending on chain configuration.
type ExecutionLimiter interface {
	ResetTx()
	TrackOpcode(op OpCode, gasUsed uint64) error
	TrackPrecompile(addr common.Address, gasUsed uint64) error
	TakeBlockLimitSnapshot()
	RestoreBlockLimitToSnapshot()
}

func opcodeLimitError(op OpCode, scope LimiterScope, limit uint64) error {
	return &ErrOpcodeLimit{Opcode: op, Scope: scope, Limit: limit}
}

func precompileLimitError(addr common.Address, scope LimiterScope, limit uint64) error {
	return &ErrPrecompileLimit{Address: addr, Scope: scope, Limit: limit}
}
