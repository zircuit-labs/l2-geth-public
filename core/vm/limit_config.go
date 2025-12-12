package vm

import (
	"encoding/json"
	"os"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/l2-geth/params"
)

// CountLimitConfig configures per-opcode and per-precompile invocation count limits.
type CountLimitConfig struct {
	OpcodePerTx        map[OpCode]uint64
	OpcodePerBlock     map[OpCode]uint64
	PrecompilePerTx    map[common.Address]uint64
	PrecompilePerBlock map[common.Address]uint64
}

// CycleLimitConfig configures cycle-based execution limits.
// Cycles are computed as: (callOverhead + gasUsed) * multiplier
type CycleLimitConfig struct {
	CallOverhead          uint64
	ThresholdPerTx        uint64
	ThresholdPerBlock     uint64
	OpcodeCyclePerGas     map[OpCode]uint64
	PrecompileCyclePerGas map[common.Address]uint64
}

// LimitConfig holds either count-based or cycle-based limit configuration.
// If both are provided, cycle limits take precedence.
type LimitConfig struct {
	Count *CountLimitConfig
	Cycle *CycleLimitConfig
}

// Empty returns true if no limits are configured.
func (cfg LimitConfig) Empty() bool {
	return cfg.Count == nil && cfg.Cycle == nil
}

func BuildLimitConfig() LimitConfig {
	var result LimitConfig
	limitsCfg := params.WhalekillerDefaultLimits

	// Apply JSON override from WHALEKILLER_LIMITS_CONFIG if present
	if override := whalekillerLimitsOverride(); override != nil {
		limitsCfg = override
	}

	// Count-based limits
	countCfg := result.Count
	if countCfg == nil {
		countCfg = &CountLimitConfig{
			OpcodePerTx:        make(map[OpCode]uint64),
			OpcodePerBlock:     make(map[OpCode]uint64),
			PrecompilePerTx:    make(map[common.Address]uint64),
			PrecompilePerBlock: make(map[common.Address]uint64),
		}
	}
	for code, limit := range limitsCfg.Opcodes {
		op := OpCode(code)
		if limit.PerTx > 0 && countCfg.OpcodePerTx[op] == 0 {
			countCfg.OpcodePerTx[op] = limit.PerTx
		}
		if limit.PerBlock > 0 && countCfg.OpcodePerBlock[op] == 0 {
			countCfg.OpcodePerBlock[op] = limit.PerBlock
		}
	}
	for key, limit := range limitsCfg.Precompiles {
		addr := common.HexToAddress(key)
		if limit.PerTx > 0 && countCfg.PrecompilePerTx[addr] == 0 {
			countCfg.PrecompilePerTx[addr] = limit.PerTx
		}
		if limit.PerBlock > 0 && countCfg.PrecompilePerBlock[addr] == 0 {
			countCfg.PrecompilePerBlock[addr] = limit.PerBlock
		}
	}
	if len(countCfg.OpcodePerTx) > 0 || len(countCfg.OpcodePerBlock) > 0 || len(countCfg.PrecompilePerTx) > 0 || len(countCfg.PrecompilePerBlock) > 0 {
		result.Count = countCfg
	}

	// Cycle-based limits
	if tracking := limitsCfg.CycleTracking; tracking != nil && tracking.ThresholdPerTx > 0 {
		cycleCfg := &CycleLimitConfig{
			CallOverhead:          tracking.CallOverhead,
			ThresholdPerTx:        tracking.ThresholdPerTx,
			ThresholdPerBlock:     tracking.ThresholdPerBlock,
			OpcodeCyclePerGas:     make(map[OpCode]uint64),
			PrecompileCyclePerGas: make(map[common.Address]uint64),
		}
		for code, multiplier := range limitsCfg.OpcodeCycles {
			cycleCfg.OpcodeCyclePerGas[OpCode(code)] = multiplier
		}
		for key, multiplier := range limitsCfg.PrecompileCycles {
			addr := common.HexToAddress(key)
			cycleCfg.PrecompileCyclePerGas[addr] = multiplier
		}
		result.Cycle = cycleCfg
	}

	if result.Count != nil {
		if len(result.Count.OpcodePerTx) == 0 && len(result.Count.OpcodePerBlock) == 0 && len(result.Count.PrecompilePerTx) == 0 && len(result.Count.PrecompilePerBlock) == 0 {
			result.Count = nil
		}
	}
	if result.Cycle != nil {
		if result.Cycle.ThresholdPerTx == 0 || result.Cycle.ThresholdPerBlock == 0 {
			result.Cycle = nil
		}
	}
	return result
}

const (
	WhalekillerLimitsEnv         = "WHALEKILLER_LIMITS_CONFIG"
	WhalekillerLimitsDisabledEnv = "WHALEKILLER_LIMITS_DISABLED"
)

func whalekillerLimitsOverride() *params.WhalekillerLimitsConfig {
	path := os.Getenv(WhalekillerLimitsEnv)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		log.Warn("Failed to read Whalekiller limits override", "path", path, "err", err)
		return nil
	}
	var cfg params.WhalekillerLimitsConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Warn("Failed to parse Whalekiller limits override", "path", path, "err", err)
		return nil
	}
	return &cfg
}
