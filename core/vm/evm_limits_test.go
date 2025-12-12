package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/params"
)

func TestWhalekillerDefaultLimitsApplied(t *testing.T) {
	limitCfg := BuildLimitConfig()
	t.Logf("limitCfg: %+v", limitCfg)
	if limitCfg.Count == nil {
		t.Fatalf("expected whalekiller defaults to enable count limits")
	}
	if limitCfg.Cycle == nil {
		t.Fatalf("expected whalekiller defaults to include cycle limits")
	}
	for opcode, lim := range params.WhalekillerDefaultLimits.Opcodes {
		op := OpCode(opcode)
		if got := limitCfg.Count.OpcodePerTx[op]; got != lim.PerTx {
			t.Fatalf("unexpected per-tx limit for opcode 0x%x: have %d want %d", opcode, got, lim.PerTx)
		}
		if got := limitCfg.Count.OpcodePerBlock[op]; got != lim.PerBlock {
			t.Fatalf("unexpected per-block limit for opcode 0x%x: have %d want %d", opcode, got, lim.PerBlock)
		}
	}
	for addrHex, lim := range params.WhalekillerDefaultLimits.Precompiles {
		addr := common.HexToAddress(addrHex)
		if got := limitCfg.Count.PrecompilePerTx[addr]; got != lim.PerTx {
			t.Fatalf("unexpected per-tx precompile limit for %s: have %d want %d", addrHex, got, lim.PerTx)
		}
		if got := limitCfg.Count.PrecompilePerBlock[addr]; got != lim.PerBlock {
			t.Fatalf("unexpected per-block precompile limit for %s: have %d want %d", addrHex, got, lim.PerBlock)
		}
	}
	// ensure execution limiter constructed is non-nil
	limits := NewEVMLimiter(limitCfg)
	if limits == nil {
		t.Fatalf("expected whalekiller limits to instantiate")
	}
}

func TestWhalekillerLimitOverride(t *testing.T) {
	dir := t.TempDir()
	override := &params.WhalekillerLimitsConfig{
		CycleTracking:    &params.WhalekillerCycleTracking{CallOverhead: 5, ThresholdPerTx: 12345, ThresholdPerBlock: 12345},
		OpcodeCycles:     map[uint8]uint64{0x5b: 99},
		PrecompileCycles: map[string]uint64{common.BytesToAddress([]byte{0x01}).Hex(): 111},
	}
	t.Logf("override threshold=%d", override.CycleTracking.ThresholdPerTx)
	data, err := json.Marshal(override)
	if err != nil {
		t.Fatalf("failed to marshal override: %v", err)
	}
	file := filepath.Join(dir, "whalekiller_override.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}
	t.Setenv(WhalekillerLimitsEnv, file)

	loaded := whalekillerLimitsOverride()
	if loaded == nil || loaded.CycleTracking == nil {
		t.Fatalf("override not loaded")
	}
	t.Logf("loaded threshold=%d", loaded.CycleTracking.ThresholdPerTx)
	if loaded.CycleTracking.ThresholdPerTx != 12345 {
		t.Fatalf("override data not parsed correctly")
	}
	if loaded.CycleTracking.ThresholdPerBlock != 12345 {
		t.Fatalf("override data not parsed correctly")
	}
	defer func() {
		t.Setenv(WhalekillerLimitsEnv, "")
	}()
}

func TestBuildLimitConfigWhalekillerDefaultThenOverride(t *testing.T) {
	// defaults (no env override), ensure no env and no cached override.
	t.Setenv(WhalekillerLimitsEnv, "")

	defaultCfg := BuildLimitConfig()

	if defaultCfg.Cycle == nil {
		t.Fatalf("expected whalekiller default cycle limits to be enabled")
	}
	if defaultCfg.Count == nil {
		t.Fatalf("expected whalekiller default count limits to be enabled")
	}

	// check a couple of representative default values to prove it's using WhalekillerDefaultLimits.
	defaultTxThresh := params.WhalekillerDefaultLimits.CycleTracking.ThresholdPerTx
	if got := defaultCfg.Cycle.ThresholdPerTx; got != defaultTxThresh {
		t.Fatalf("default ThresholdPerTx mismatch: have %d want %d", got, defaultTxThresh)
	}

	defaultBlockThresh := params.WhalekillerDefaultLimits.CycleTracking.ThresholdPerBlock
	if got := defaultCfg.Cycle.ThresholdPerBlock; got != defaultBlockThresh {
		t.Fatalf("default ThresholdPerBlock mismatch: have %d want %d", got, defaultBlockThresh)
	}

	// check opcode count default (e.g. JUMPDEST per-tx).
	jumpdest := OpCode(0x5b)
	expectedJDPerTx := params.WhalekillerDefaultLimits.Opcodes[0x5b].PerTx
	if got := defaultCfg.Count.OpcodePerTx[jumpdest]; got != expectedJDPerTx {
		t.Fatalf("default JUMPDEST per-tx limit mismatch: have %d want %d", got, expectedJDPerTx)
	}

	// env override and provide JSON file
	dir := t.TempDir()
	override := &params.WhalekillerLimitsConfig{
		CycleTracking: &params.WhalekillerCycleTracking{
			CallOverhead:      7,
			ThresholdPerTx:    12345,
			ThresholdPerBlock: 54321,
		},
		OpcodeCycles: map[uint8]uint64{
			0x5b: 99, // override JUMPDEST cycle multiplier
		},
	}

	data, err := json.Marshal(override)
	if err != nil {
		t.Fatalf("failed to marshal override: %v", err)
	}
	file := filepath.Join(dir, "whalekiller_override.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatalf("failed to write override file: %v", err)
	}

	t.Setenv(WhalekillerLimitsEnv, file)
	overriddenCfg := BuildLimitConfig()

	if overriddenCfg.Cycle == nil {
		t.Fatalf("expected cycle limits after override")
	}

	// Thresholds should be from override, not defaults.
	if got := overriddenCfg.Cycle.ThresholdPerTx; got != 12345 {
		t.Fatalf("override ThresholdPerTx mismatch: have %d want %d", got, 12345)
	}
	if got := overriddenCfg.Cycle.ThresholdPerBlock; got != 54321 {
		t.Fatalf("override ThresholdPerBlock mismatch: have %d want %d", got, 54321)
	}

	// JUMPDEST cycle multiplier should be the overridden one (99), not the default.
	if got := overriddenCfg.Cycle.OpcodeCyclePerGas[jumpdest]; got != 99 {
		t.Fatalf("override JUMPDEST cycle multiplier mismatch: have %d want %d", got, 99)
	}
}

func ptrUint64(v uint64) *uint64 { return &v }
