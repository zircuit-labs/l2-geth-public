package vm

import (
	"errors"
	"testing"

	"github.com/zircuit-labs/l2-geth/common"
)

func TestVMCountLimitsOpcodePerTx(t *testing.T) {
	limitCfg := LimitConfig{
		Count: &CountLimitConfig{
			OpcodePerTx: map[OpCode]uint64{MULMOD: 2},
		},
	}
	limits := NewEVMLimiter(limitCfg)

	if err := limits.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := limits.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := limits.TrackOpcode(MULMOD, 1); err == nil {
		t.Fatalf("expected error when exceeding per-tx limit")
	} else {
		var limitErr *ErrOpcodeLimit
		if !errors.As(err, &limitErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if limitErr.Scope != LimiterTxScope {
			t.Fatalf("expected tx scope, got %v", limitErr.Scope)
		}
	}

	limits.ResetTx()
	if err := limits.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}
}

func TestVMCountLimitsOpcodePerBlock(t *testing.T) {
	limitCfg := LimitConfig{
		Count: &CountLimitConfig{
			OpcodePerBlock: map[OpCode]uint64{MULMOD: 2},
		},
	}
	limits := NewEVMLimiter(limitCfg)

	for i := 0; i < 2; i++ {
		if err := limits.TrackOpcode(MULMOD, 1); err != nil {
			t.Fatalf("unexpected error at iteration %d: %v", i, err)
		}
		limits.ResetTx()
	}
	if err := limits.TrackOpcode(MULMOD, 1); err == nil {
		t.Fatalf("expected block limit error")
	} else {
		var limitErr *ErrOpcodeLimit
		if !errors.As(err, &limitErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if limitErr.Scope != LimiterBlockScope {
			t.Fatalf("expected block scope, got %v", limitErr.Scope)
		}
	}
}

func TestVMCountLimitsPrecompilePerTx(t *testing.T) {
	addr := common.BytesToAddress([]byte{0x01})
	limitCfg := LimitConfig{
		Count: &CountLimitConfig{
			PrecompilePerTx: map[common.Address]uint64{addr: 1},
		},
	}
	limits := NewEVMLimiter(limitCfg)

	if err := limits.TrackPrecompile(addr, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := limits.TrackPrecompile(addr, 1); err == nil {
		t.Fatalf("expected per-tx precompile limit error")
	} else {
		var limitErr *ErrPrecompileLimit
		if !errors.As(err, &limitErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if limitErr.Scope != LimiterTxScope {
			t.Fatalf("expected tx scope, got %v", limitErr.Scope)
		}
	}

	limits.ResetTx()
	if err := limits.TrackPrecompile(addr, 1); err != nil {
		t.Fatalf("unexpected error after reset: %v", err)
	}
}

func TestVMCountLimitsPrecompilePerBlock(t *testing.T) {
	addr := common.BytesToAddress([]byte{0x02})
	limitCfg := LimitConfig{
		Count: &CountLimitConfig{
			PrecompilePerBlock: map[common.Address]uint64{addr: 2},
		},
	}
	limits := NewEVMLimiter(limitCfg)

	for i := 0; i < 2; i++ {
		if err := limits.TrackPrecompile(addr, 1); err != nil {
			t.Fatalf("unexpected error at iteration %d: %v", i, err)
		}
		limits.ResetTx()
	}
	if err := limits.TrackPrecompile(addr, 1); err == nil {
		t.Fatalf("expected per-block precompile limit error")
	} else {
		var limitErr *ErrPrecompileLimit
		if !errors.As(err, &limitErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if limitErr.Scope != LimiterBlockScope {
			t.Fatalf("expected block scope, got %v", limitErr.Scope)
		}
	}
}

func TestVMLimitsCycleOpcode(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      100, // callOverhead should not be used for opcode cycle
			ThresholdPerTx:    75,
			ThresholdPerBlock: 100,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 50,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)
	if limit == nil {
		t.Fatalf("expected limiter to be created")
	}

	if err := limit.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Second invocation should exceed the tx cycle threshold: 2 * 50 = 100 > 75
	// (CallOverhead is intentionally ignored for opcode cycles).
	if err := limit.TrackOpcode(MULMOD, 1); err == nil {
		t.Fatalf("expected cycle limit breach")
	} else {
		var cycleErr *ErrOpcodeLimit
		if !errors.As(err, &cycleErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if cycleErr.Scope != LimiterTxScope {
			t.Fatalf("expected tx scope, got %v", cycleErr.Scope)
		}
	}
}

func TestVMLimitsCycleOpcodeBlockScope(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      100, // callOverhead should not be used for opcode cycle
			ThresholdPerTx:    100,
			ThresholdPerBlock: 100,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 40,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)
	if limit == nil {
		t.Fatalf("expected limiter to be created")
	}

	// tx1: 40 cycles, cycles for block is now 40
	if err := limit.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error on tx1: %v", err)
	}

	// Simulate end of tx1 and start of tx2
	limit.ResetTx()

	// tx2: another 40 cycles, cycles for block is now 80
	if err := limit.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error on tx2: %v", err)
	}

	// Simulate end of tx2 and start of tx3
	limit.ResetTx()

	// tx3: another 40 cycles
	// tx total: 40 <= 100
	// block total: 40 + 40 + 40 = 120 > 100, so this should trip BLOCK scope
	err := limit.TrackOpcode(MULMOD, 1)
	if err == nil {
		t.Fatalf("expected block-scope cycle limit breach on tx3")
	}

	var cycleErr *ErrOpcodeLimit
	if !errors.As(err, &cycleErr) {
		t.Fatalf("unexpected error type: %v", err)
	}
	if cycleErr.Scope != LimiterBlockScope {
		t.Fatalf("expected block scope, got %v", cycleErr.Scope)
	}
}

func TestVMLimitsCyclePrecompile(t *testing.T) {
	addr := common.BytesToAddress([]byte{0x05})
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      100,
			ThresholdPerTx:    300,
			ThresholdPerBlock: 300,
			PrecompileCyclePerGas: map[common.Address]uint64{
				addr: 2,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)
	if limit == nil {
		t.Fatalf("expected limiter to be created")
	}

	if err := limit.TrackPrecompile(addr, 10); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Next call should overflow the threshold.
	if err := limit.TrackPrecompile(addr, 10); err == nil {
		t.Fatalf("expected cycle limit breach for precompile")
	} else {
		var cycleErr *ErrPrecompileLimit
		if !errors.As(err, &cycleErr) {
			t.Fatalf("unexpected error type: %v", err)
		}
		if cycleErr.Scope != LimiterTxScope {
			t.Fatalf("expected tx scope, got %v", cycleErr.Scope)
		}
	}
}

func TestVMLimitsCyclePrecompileBlockScope(t *testing.T) {
	addr := common.BytesToAddress([]byte{0x05})
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      100,
			ThresholdPerTx:    300, // tx-level never trips in this test
			ThresholdPerBlock: 300, // block-level will trip after 3 txs
			PrecompileCyclePerGas: map[common.Address]uint64{
				addr: 1, // cycles per call = (100 + gasUsed) * 1 = 101
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)
	if limit == nil {
		t.Fatalf("expected limiter to be created")
	}

	// Tx 1: first tx with precompile (101 cycles), under both tx and block thresholds.
	if err := limit.TrackPrecompile(addr, 1); err != nil {
		t.Fatalf("unexpected error in tx1: %v", err)
	}

	// Tx 2: another tx (101 cycles), block total 202, still under block threshold.
	limit.ResetTx()
	if err := limit.TrackPrecompile(addr, 1); err != nil {
		t.Fatalf("unexpected error in tx2: %v", err)
	}

	// Tx 3: another tx (101 cycles), block total 303 > 300, lead to block-scope breach.
	limit.ResetTx()
	err := limit.TrackPrecompile(addr, 1)
	if err == nil {
		t.Fatalf("expected block-scope cycle limit breach for precompile")
	}
	var cycleErr *ErrPrecompileLimit
	if !errors.As(err, &cycleErr) {
		t.Fatalf("unexpected error type: %v", err)
	}
	if cycleErr.Scope != LimiterBlockScope {
		t.Fatalf("expected block scope, got %v", cycleErr.Scope)
	}
}

func TestVMLimitsWhalekillerDefaults(t *testing.T) {
	limitCfg := BuildLimitConfig()
	limit := NewEVMLimiter(limitCfg)

	if limit == nil {
		t.Fatalf("expected limits to be enabled for whalekiller")
	}

	if limitCfg.Count == nil || limitCfg.Count.OpcodePerTx[JUMPDEST] == 0 {
		t.Fatalf("expected default JUMPDEST per-tx limit to be set")
	}
	addr := common.HexToAddress("0x08")
	if limitCfg.Count.PrecompilePerTx[addr] == 0 {
		t.Fatalf("expected default precompile limit for address 0x08")
	}
}

func TestVMLimitsCycleBlockSnapshotRestore(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      0,
			ThresholdPerTx:    1000,
			ThresholdPerBlock: 1000,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 100,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)
	if limit == nil {
		t.Fatalf("expected limiter to be created")
	}

	// Execute first opcode: 100 cycles
	if err := limit.TrackOpcode(MULMOD, 1); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Take snapshot (should save 100)
	limit.TakeBlockLimitSnapshot()

	// Execute more opcodes: 100 + 200 = 300 cycles
	if err := limit.TrackOpcode(MULMOD, 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Restore to snapshot (should go back to 100)
	limit.RestoreBlockLimitToSnapshot()

	// Execute opcode that would fail if counter was at 300
	// 100 + 400 = 500 < 1000
	if err := limit.TrackOpcode(MULMOD, 4); err != nil {
		t.Fatalf("unexpected error after restore: %v", err)
	}

	// Verify we're now at 500 (not 700)
	// This should succeed: 500 + 300 = 800 < 1000
	if err := limit.TrackOpcode(MULMOD, 3); err != nil {
		t.Fatalf("unexpected error, counter not restored properly: %v", err)
	}
}

func TestVMLimitsCycleBlockSnapshotClearedAfterRestore(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      0,
			ThresholdPerTx:    1000,
			ThresholdPerBlock: 1000,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 100,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)

	// Build up to 200 cycles
	if err := limit.TrackOpcode(MULMOD, 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Take snapshot (saves 200)
	limit.TakeBlockLimitSnapshot()

	// Add more: 200 + 300 = 500
	if err := limit.TrackOpcode(MULMOD, 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Restore (back to 200, snapshot cleared)
	limit.RestoreBlockLimitToSnapshot()

	// Reset tx counter (required for next transaction)
	limit.ResetTx()

	// Try to restore again - should restore to 0 (snapshot was cleared)
	limit.RestoreBlockLimitToSnapshot()

	// If snapshot was properly cleared, block counter should be 0 now
	// TX counter is also 0 (from ResetTx)
	// So this should succeed: 0 + 1000 = 1000 (at limit but ok)
	if err := limit.TrackOpcode(MULMOD, 10); err != nil {
		t.Fatalf("snapshot not properly cleared: %v", err)
	}
}

func TestVMLimitsCycleBlockSnapshotMultipleTransactions(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      0,
			ThresholdPerTx:    500,
			ThresholdPerBlock: 1000,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 100,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)

	// TX1: Execute 200 cycles
	if err := limit.TrackOpcode(MULMOD, 2); err != nil {
		t.Fatalf("unexpected error in tx1: %v", err)
	}
	limit.ResetTx()

	// Block counter should be 200
	// TX2: Take snapshot, try operation that fails
	limit.TakeBlockLimitSnapshot() // saves 200

	// Try operation: 200 + 900 = 1100 > 1000 (block limit)
	err := limit.TrackOpcode(MULMOD, 9)
	if err == nil {
		t.Fatalf("expected block limit error")
	}

	// Restore to snapshot (back to 200)
	limit.RestoreBlockLimitToSnapshot()
	limit.ResetTx()

	// TX3: Should succeed now with small operation
	// 200 + 300 = 500 < 1000
	if err := limit.TrackOpcode(MULMOD, 3); err != nil {
		t.Fatalf("unexpected error after restore in tx3: %v", err)
	}
}

func TestVMLimitsCycleBlockSnapshotPrecompile(t *testing.T) {
	addr := common.BytesToAddress([]byte{0x08})
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      100,
			ThresholdPerTx:    1000,
			ThresholdPerBlock: 1000,
			PrecompileCyclePerGas: map[common.Address]uint64{
				addr: 2,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)

	// First call: (100 + 50) * 2 = 300 cycles
	if err := limit.TrackPrecompile(addr, 50); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Take snapshot (saves block=300)
	limit.TakeBlockLimitSnapshot()

	// Second call: block=300+400=700, tx=300+400=700
	if err := limit.TrackPrecompile(addr, 100); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Restore to snapshot (block back to 300, tx still 700)
	limit.RestoreBlockLimitToSnapshot()

	// Simulate new transaction
	limit.ResetTx()

	// Third call (new tx): block=300+600=900, tx=600
	// Both: 600 < 1000 (tx), 900 < 1000 (block)
	if err := limit.TrackPrecompile(addr, 200); err != nil {
		t.Fatalf("unexpected error after restore: %v", err)
	}

	// Verify we're at block=900 (not 1300)
	// This should fail: 900 + 320 = 1220 > 1000 (block limit)
	err := limit.TrackPrecompile(addr, 60)
	if err == nil {
		t.Fatalf("expected block limit error, counter not restored properly")
	}

	var limitErr *ErrPrecompileLimit
	if !errors.As(err, &limitErr) || limitErr.Scope != LimiterBlockScope {
		t.Fatalf("expected block scope error, got %v", err)
	}
}

func TestVMLimitsCycleBlockSnapshotWithoutRestore(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      0,
			ThresholdPerTx:    1000,
			ThresholdPerBlock: 1000,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 100,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)

	// TX1: Execute 200 cycles
	if err := limit.TrackOpcode(MULMOD, 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Take snapshot but DON'T restore
	limit.TakeBlockLimitSnapshot()
	limit.ResetTx() // Start new transaction

	// TX2: Execute 300 cycles (block now at 200+300=500)
	if err := limit.TrackOpcode(MULMOD, 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Take another snapshot (overwrites previous, saves 500)
	limit.TakeBlockLimitSnapshot()
	limit.ResetTx() // Start new transaction

	// TX3: Execute 400 cycles (block now at 500+400=900)
	if err := limit.TrackOpcode(MULMOD, 4); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Restore to most recent snapshot (back to 500, not 200)
	limit.RestoreBlockLimitToSnapshot()
	limit.ResetTx() // Start new transaction

	// TX4: Should be at block=500, tx=0
	// block: 500 + 500 = 1000 (at limit but ok)
	// tx: 0 + 500 = 500 < 1000 ✓
	if err := limit.TrackOpcode(MULMOD, 5); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// TX5: This should fail at BLOCK level
	// block: 1000 + 100 = 1100 > 1000
	// tx: 0 + 100 = 100 < 1000 (would pass tx check)
	limit.ResetTx()
	err := limit.TrackOpcode(MULMOD, 1)
	if err == nil {
		t.Fatalf("expected block limit error")
	}

	var limitErr *ErrOpcodeLimit
	if !errors.As(err, &limitErr) || limitErr.Scope != LimiterBlockScope {
		t.Fatalf("expected block scope error, got %v", err)
	}
}

func TestVMLimitsCycleBlockSnapshotResetTxBehavior(t *testing.T) {
	limitCfg := LimitConfig{
		Cycle: &CycleLimitConfig{
			CallOverhead:      0,
			ThresholdPerTx:    500,
			ThresholdPerBlock: 1000,
			OpcodeCyclePerGas: map[OpCode]uint64{
				MULMOD: 100,
			},
		},
	}
	limit := NewEVMLimiter(limitCfg)

	// TX1: 200 cycles
	if err := limit.TrackOpcode(MULMOD, 2); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Take snapshot (saves block counter = 200)
	limit.TakeBlockLimitSnapshot()

	// ResetTx should only reset tx counter, not affect block counter or snapshot
	limit.ResetTx()

	// TX2: 300 cycles (block now at 200 + 300 = 500)
	if err := limit.TrackOpcode(MULMOD, 3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Restore should go back to block=200 (snapshot was taken before ResetTx)
	limit.RestoreBlockLimitToSnapshot()

	// Start TX3 (reset tx counter)
	limit.ResetTx()

	// Should be at block=200, tx=0
	// block: 200 + 400 = 600 < 1000 ✓
	// tx: 0 + 400 = 400 < 500 ✓
	if err := limit.TrackOpcode(MULMOD, 4); err != nil {
		t.Fatalf("unexpected error after restore: %v", err)
	}

	// Start TX4 to verify block counter is at 600 (not 900 if restore failed)
	limit.ResetTx()

	// Verify block counter is at 600
	// block: 600 + 300 = 900 < 1000 ✓
	// tx: 0 + 300 = 300 < 500 ✓
	if err := limit.TrackOpcode(MULMOD, 3); err != nil {
		t.Fatalf("block counter not restored properly: %v", err)
	}

	// Final verification: one more operation should bring us to block limit
	limit.ResetTx()
	// block: 900 + 200 = 1100 > 1000 ✗
	err := limit.TrackOpcode(MULMOD, 2)
	if err == nil {
		t.Fatalf("expected block limit error")
	}
	var limitErr *ErrOpcodeLimit
	if !errors.As(err, &limitErr) || limitErr.Scope != LimiterBlockScope {
		t.Fatalf("expected block scope error, got %v", err)
	}
}
