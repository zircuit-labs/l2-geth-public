//go:build !circuit_capacity_checker

package circuitcapacitychecker

import (
	"math/rand"

	"github.com/zircuit-labs/l2-geth-public/core/types"
)

type CircuitCapacityChecker struct {
	Config         Config
	ID             uint64
	countdown      int
	blockCountdown int
	nextError      *error
	nextBlockError *error
}

// NewCircuitCapacityChecker creates a new CircuitCapacityChecker
func NewCircuitCapacityChecker(lightMode bool, blockchain MiniBlockChain, config Config) *CircuitCapacityChecker {
	ccc := &CircuitCapacityChecker{Config: config, ID: rand.Uint64()}
	ccc.SetLightMode(lightMode)
	return ccc
}

// Reset resets a ccc, but need to do nothing in mock_ccc.
func (ccc *CircuitCapacityChecker) Reset() {
}

// ApplyTransaction appends a tx's wrapped BlockTrace into the ccc, and return the accumulated RowConsumption.
// Will only return a dummy value in mock_ccc.
func (ccc *CircuitCapacityChecker) ApplyTransaction(traces *types.BlockTrace, block *types.Block) (*types.RowConsumption, error) {
	if ccc.nextError != nil {
		ccc.countdown--
		if ccc.countdown == 0 {
			err := *ccc.nextError
			ccc.nextError = nil
			return nil, err
		}
	}
	return &types.RowConsumption{types.SubCircuitRowUsage{
		Name:      "mock",
		RowNumber: 1,
	}}, nil
}

// ApplyBlock gets a block's RowConsumption.
// Will only return a dummy value in mock_ccc.
func (ccc *CircuitCapacityChecker) ApplyBlock(traces *types.BlockTrace, block *types.Block) (*types.RowConsumption, error) {
	if ccc.nextBlockError != nil {
		ccc.blockCountdown--
		if ccc.blockCountdown == 0 {
			err := *ccc.nextBlockError
			ccc.nextBlockError = nil
			return nil, err
		}
	}
	return &types.RowConsumption{types.SubCircuitRowUsage{
		Name:      "mock",
		RowNumber: 2,
	}}, nil
}

// CheckTxNum compares whether the tx_count in ccc match the expected.
// Will alway return true in mock_ccc.
func (ccc *CircuitCapacityChecker) CheckTxNum(expected int) (bool, uint64, error) {
	return true, uint64(expected), nil
}

// SetLightMode sets to ccc light mode
func (ccc *CircuitCapacityChecker) SetLightMode(lightMode bool) error {
	return nil
}

// ScheduleError schedules an error for a tx (see `ApplyTransaction`), only used in tests.
func (ccc *CircuitCapacityChecker) ScheduleError(cnt int, err error) {
	ccc.countdown = cnt
	ccc.nextError = &err
}

// ScheduleBlockError schedules an error for a block (see `ApplyBlock`), only used in tests.
func (ccc *CircuitCapacityChecker) ScheduleBlockError(cnt int, err error) {
	ccc.blockCountdown = cnt
	ccc.nextBlockError = &err
}
