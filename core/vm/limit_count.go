package vm

import (
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/log"
)

type opcodeLimitStore struct {
	limitPerTx    [256]uint64
	limitPerBlock [256]uint64
	countPerTx    [256]uint64
	countPerBlock [256]uint64
}

type precompileLimitStore struct {
	limitPerTx    map[common.Address]uint64
	limitPerBlock map[common.Address]uint64
	countPerTx    map[common.Address]uint64
	countPerBlock map[common.Address]uint64
}

type countLimiter struct {
	opcode     opcodeLimitStore
	precompile precompileLimitStore

	opcodeBlockSnapshot     [256]uint64
	precompileBlockSnapshot map[common.Address]uint64
}

func newCountLimiter(cfg *CountLimitConfig) ExecutionLimiter {
	if cfg == nil {
		return nil
	}
	lim := &countLimiter{
		precompile: precompileLimitStore{
			limitPerTx:    make(map[common.Address]uint64),
			limitPerBlock: make(map[common.Address]uint64),
			countPerTx:    make(map[common.Address]uint64),
			countPerBlock: make(map[common.Address]uint64),
		},
	}
	for op, limit := range cfg.OpcodePerTx {
		lim.opcode.limitPerTx[int(op)] = limit
	}
	for op, limit := range cfg.OpcodePerBlock {
		lim.opcode.limitPerBlock[int(op)] = limit
	}
	for addr, limit := range cfg.PrecompilePerTx {
		lim.precompile.limitPerTx[addr] = limit
		log.Trace("vm: configured precompile per-tx limit", "addr", addr, "limit", limit)
	}
	for addr, limit := range cfg.PrecompilePerBlock {
		lim.precompile.limitPerBlock[addr] = limit
		log.Trace("vm: configured precompile per-block limit", "addr", addr, "limit", limit)
	}
	return lim
}

func (l *countLimiter) ResetTx() {
	for i := range l.opcode.countPerTx {
		l.opcode.countPerTx[i] = 0
	}
	l.precompile.countPerTx = make(map[common.Address]uint64)
}

func (l *countLimiter) TakeBlockLimitSnapshot() {
	l.opcodeBlockSnapshot = l.opcode.countPerBlock

	// deep copy the map
	l.precompileBlockSnapshot = make(map[common.Address]uint64, len(l.precompile.countPerBlock))
	for addr, count := range l.precompile.countPerBlock {
		l.precompileBlockSnapshot[addr] = count
	}
}

func (l *countLimiter) RestoreBlockLimitToSnapshot() {
	l.opcode.countPerBlock = l.opcodeBlockSnapshot
	l.precompile.countPerBlock = l.precompileBlockSnapshot

	// reset to snapshot to empty
	l.opcodeBlockSnapshot = [256]uint64{}
	l.precompileBlockSnapshot = map[common.Address]uint64{}
}

func (l *countLimiter) TrackOpcode(op OpCode, _ uint64) error {
	if l == nil {
		return nil
	}
	idx := int(op)
	if limit := l.opcode.limitPerTx[idx]; limit > 0 {
		if l.opcode.countPerTx[idx] >= limit {
			return opcodeLimitError(op, LimiterTxScope, limit)
		}
		l.opcode.countPerTx[idx]++
	}
	if limit := l.opcode.limitPerBlock[idx]; limit > 0 {
		if l.opcode.countPerBlock[idx] >= limit {
			return opcodeLimitError(op, LimiterBlockScope, limit)
		}
		l.opcode.countPerBlock[idx]++
	}
	return nil
}

func (l *countLimiter) TrackPrecompile(addr common.Address, _ uint64) error {
	if l == nil {
		return nil
	}
	if limit, ok := l.precompile.limitPerTx[addr]; ok && limit > 0 {
		if count := l.precompile.countPerTx[addr]; count >= limit {
			return precompileLimitError(addr, LimiterTxScope, limit)
		}
		l.precompile.countPerTx[addr]++
	}
	if limit, ok := l.precompile.limitPerBlock[addr]; ok && limit > 0 {
		if count := l.precompile.countPerBlock[addr]; count >= limit {
			return precompileLimitError(addr, LimiterBlockScope, limit)
		}
		l.precompile.countPerBlock[addr]++
	}
	return nil
}
