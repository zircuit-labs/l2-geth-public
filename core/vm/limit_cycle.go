package vm

import (
	"math/bits"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/log"
)

// cycleLimiter tracks weighted execution costs to prevent resource exhaustion.
// It calculates cycles as: (callOverhead + gasUsed) × multiplier per operation.
type cycleLimiter struct {
	callOverhead          uint64                    // base cost per call
	thresholdPerTx        uint64                    // max cycles allowed per tx
	thresholdPerBlock     uint64                    // max cycles allowed per block
	opcodeCyclePerGas     [256]uint64               // weight per opcode
	precompileCyclePerGas map[common.Address]uint64 // weight per precompile

	cyclesPerTx    uint64 // accumulator for current tx and running state (reset per transaction)
	cyclesPerBlock uint64 // accumulator for current block

	blockLimitSnapshot uint64 // a snapshot for current accumulated block cycles
}

func newCycleLimiter(cfg *CycleLimitConfig) ExecutionLimiter {
	if cfg == nil || cfg.ThresholdPerTx == 0 || cfg.ThresholdPerBlock == 0 {
		return nil
	}
	lim := &cycleLimiter{
		callOverhead:          cfg.CallOverhead,
		thresholdPerTx:        cfg.ThresholdPerTx,
		thresholdPerBlock:     cfg.ThresholdPerBlock,
		precompileCyclePerGas: make(map[common.Address]uint64),
	}
	for op, multiplier := range cfg.OpcodeCyclePerGas {
		lim.opcodeCyclePerGas[int(op)] = multiplier
	}
	for addr, multiplier := range cfg.PrecompileCyclePerGas {
		lim.precompileCyclePerGas[addr] = multiplier
	}
	return lim
}

func (l *cycleLimiter) ResetTx() {
	// Only reset per-tx accumulator, per-block accumulator lives for whole block
	l.cyclesPerTx = 0
}

func (l *cycleLimiter) TakeBlockLimitSnapshot() {
	l.blockLimitSnapshot = l.cyclesPerBlock
}

func (l *cycleLimiter) RestoreBlockLimitToSnapshot() {
	l.cyclesPerBlock = l.blockLimitSnapshot
	l.blockLimitSnapshot = 0
}

// TrackOpcode records cycles for an opcode execution and returns an error if the tx limit is exceeded.
func (l *cycleLimiter) TrackOpcode(op OpCode, gasUsed uint64) error {
	if l == nil {
		return nil
	}
	multiplier := l.opcodeCyclePerGas[int(op)]
	if multiplier == 0 {
		return nil
	}

	cycles, overflow := l.cyclesForOpcode(gasUsed, multiplier)
	if overflow {
		return opcodeLimitError(op, LimiterTxScope, l.thresholdPerTx)
	}

	// Check tx level
	if err := l.addTxCycles(cycles, func() error {
		return opcodeLimitError(op, LimiterTxScope, l.thresholdPerTx)
	}); err != nil {
		return err
	}

	// Check block level
	return l.addBlockCycles(cycles, func() error {
		return opcodeLimitError(op, LimiterBlockScope, l.thresholdPerBlock)
	})
}

// TrackPrecompile records cycles for a precompile call and returns an error if the tx limit is exceeded.
func (l *cycleLimiter) TrackPrecompile(addr common.Address, gasUsed uint64) error {
	if l == nil {
		return nil
	}
	multiplier := l.precompileCyclePerGas[addr]
	if multiplier == 0 {
		return nil
	}
	cycles, overflow := l.cyclesForPrecompile(gasUsed, multiplier)
	if overflow {
		return precompileLimitError(addr, LimiterTxScope, l.thresholdPerTx)
	}

	// Check tx level
	if err := l.addTxCycles(cycles, func() error {
		return precompileLimitError(addr, LimiterTxScope, l.thresholdPerTx)
	}); err != nil {
		return err
	}

	// Check block level
	return l.addBlockCycles(cycles, func() error {
		return precompileLimitError(addr, LimiterBlockScope, l.thresholdPerBlock)
	})
}

// cyclesForOpcode computes weighted cycles for opcode: gasUsed * multiplier.
// For opcodes, there is NO fixed call overhead.
func (l *cycleLimiter) cyclesForOpcode(gasUsed, multiplier uint64) (uint64, bool) {
	hi, lo := bits.Mul64(gasUsed, multiplier)
	if hi != 0 {
		// Return 0 on overflow
		return 0, true
	}
	return lo, false
}

// cyclesForPrecompile computes weighted cycles for precompile: (callOverhead + gasUsed) × multiplier.
func (l *cycleLimiter) cyclesForPrecompile(gasUsed, multiplier uint64) (uint64, bool) {
	totalGas := l.callOverhead + gasUsed
	if totalGas < gasUsed {
		return 0, true
	}
	hi, lo := bits.Mul64(totalGas, multiplier)
	if hi != 0 {
		return 0, true
	}
	return lo, false
}

// addCycles adds delta to the running total and checks if threshold is exceeded.
func (l *cycleLimiter) addTxCycles(delta uint64, buildError func() error) error {
	if delta == 0 {
		return nil
	}

	actual := l.cyclesPerTx + delta

	// Check for overflow OR threshold exceeded
	if actual < l.cyclesPerTx || actual > l.thresholdPerTx {
		return buildError()
	}

	l.cyclesPerTx = actual
	return nil
}

// addBlockCycles adds delta to the block total and checks block threshold.
func (l *cycleLimiter) addBlockCycles(delta uint64, buildError func() error) error {
	if delta == 0 {
		return nil
	}

	// add to running total
	actual := l.cyclesPerBlock + delta

	log.Trace("whalekiller block cycles",
		"delta", delta,
		"before", l.cyclesPerBlock,
		"after", actual,
		"txLimit", l.thresholdPerTx,
		"blkLimit", l.thresholdPerBlock,
	)

	// overflow or over block threshold
	if actual < l.cyclesPerBlock || actual > l.thresholdPerBlock {
		return buildError()
	}

	l.cyclesPerBlock = actual
	return nil
}
