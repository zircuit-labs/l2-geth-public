//go:build circuit_capacity_checker

package circuitcapacitychecker

/*
#cgo LDFLAGS: -lm -ldl -lzkp -lzktrie
#include <stdlib.h>
#include "./libzkp/libzkp.h"
#cgo linux LDFLAGS: -Wl,--allow-multiple-definition
*/
import "C" //nolint:typecheck

import (
	"encoding/json"
	"fmt"
	"sync"
	"unsafe"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/log"
)

// mutex for concurrent CircuitCapacityChecker creations
var creationMu sync.Mutex

func init() {
	C.init()
}

type CircuitCapacityChecker struct {
	// mutex for each CircuitCapacityChecker itself
	sync.Mutex
	Config    Config
	ID        uint64
	cccHelper cccHelper
}

type (
	cccHelper interface {
		GetCodesAndProofs(block *types.Block, trace *types.BlockTrace, isLatest bool) (map[*common.Address]string, []*MiniAccountResult, error)
	}
)

// NewCircuitCapacityChecker creates a new CircuitCapacityChecker
func NewCircuitCapacityChecker(lightMode bool, blockchain MiniBlockChain, config Config) *CircuitCapacityChecker {
	creationMu.Lock()
	defer creationMu.Unlock()

	helper := NewCCCHelper(NewMiniBlockChainAPI(blockchain), NewStateAccessesFinder())
	id := C.new_circuit_capacity_checker()

	ccc := &CircuitCapacityChecker{
		Config:    config,
		ID:        uint64(id),
		cccHelper: helper,
	}
	ccc.SetLightMode(lightMode)
	return ccc
}

// Reset resets a CircuitCapacityChecker
func (ccc *CircuitCapacityChecker) Reset() {
	ccc.Lock()
	defer ccc.Unlock()

	C.reset_circuit_capacity_checker(C.uint64_t(ccc.ID))
}

// ApplyTransaction appends a tx's wrapped BlockTrace into the ccc, and return the accumulated RowConsumption
func (ccc *CircuitCapacityChecker) ApplyTransaction(traces *types.BlockTrace, block *types.Block) (*types.RowConsumption, error) {
	ccc.Lock()
	defer ccc.Unlock()

	if len(traces.Transactions) != 1 || len(traces.ExecutionResults) != 1 || len(traces.TxStorageTraces) != 1 {
		log.Error("malformatted BlockTrace in ApplyTransaction", "id", ccc.ID,
			"len(traces.Transactions)", len(traces.Transactions),
			"len(traces.ExecutionResults)", len(traces.ExecutionResults),
			"len(traces.TxStorageTraces)", len(traces.TxStorageTraces),
			"err", "length of Transactions, or ExecutionResults, or TxStorageTraces, is not equal to 1")
		return nil, ErrUnknown
	}

	codes, proofs, err := ccc.cccHelper.GetCodesAndProofs(block, traces, false)
	if err != nil {
		return nil, err
	}

	tracesByt, err := json.Marshal(traces)
	if err != nil {
		log.Error("fail to json marshal traces in ApplyTransaction", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", err)
		return nil, ErrUnknown
	}

	proofsByt, err := json.Marshal(proofs)
	if err != nil {
		log.Error("fail to json marshal proofs in ApplyTransaction", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", err)
		return nil, ErrUnknown
	}

	codesByt, err := json.Marshal(codes)
	if err != nil {
		log.Error("fail to json marshal codes in ApplyTransaction", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", err)
		return nil, ErrUnknown
	}

	tracesStr := C.CString(string(tracesByt))
	defer func() {
		C.free(unsafe.Pointer(tracesStr))
	}()

	proofTracesStr := C.CString(string(proofsByt))
	defer func() {
		C.free(unsafe.Pointer(proofTracesStr))
	}()

	codeTracesStr := C.CString(string(codesByt))
	defer func() {
		C.free(unsafe.Pointer(codeTracesStr))
	}()

	log.Debug("start to check circuit capacity for tx", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash)
	rawResult := C.apply_tx(C.uint64_t(ccc.ID), tracesStr, proofTracesStr, codeTracesStr)
	defer func() {
		C.free_c_chars(rawResult)
	}()
	log.Debug("check circuit capacity for tx done", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash)

	result := &WrappedRowUsage{}
	if err = json.Unmarshal([]byte(C.GoString(rawResult)), result); err != nil {
		log.Error("fail to json unmarshal apply_tx result", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", err)
		return nil, ErrUnknown
	}

	if result.Error != "" {
		log.Error("fail to apply_tx in CircuitCapacityChecker", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", result.Error)
		return nil, ErrUnknown
	}
	if result.AccRowUsage == nil {
		log.Error("fail to apply_tx in CircuitCapacityChecker",
			"id", ccc.ID, "TxHash", traces.Transactions[0].TxHash,
			"result.AccRowUsage == nil", result.AccRowUsage == nil,
			"err", "AccRowUsage is empty unexpectedly")
		return nil, ErrUnknown
	}
	if !result.AccRowUsage.IsOk {
		return nil, ErrBlockRowConsumptionOverflow
	}
	return (*types.RowConsumption)(&result.AccRowUsage.RowUsageDetails), nil
}

// ApplyBlock gets a block's RowConsumption
func (ccc *CircuitCapacityChecker) ApplyBlock(traces *types.BlockTrace, block *types.Block) (*types.RowConsumption, error) {
	ccc.Lock()
	defer ccc.Unlock()

	codes, proofs, err := ccc.cccHelper.GetCodesAndProofs(block, traces, false)
	if err != nil {
		return nil, err
	}

	tracesByt, err := json.Marshal(traces)
	if err != nil {
		log.Error("fail to json marshal traces in ApplyBlock", "id", ccc.ID, "blockNumber", traces.Header.Number, "blockHash", traces.Header.Hash(), "err", err)
		return nil, ErrUnknown
	}

	proofsByt, err := json.Marshal(proofs)
	if err != nil {
		log.Error("fail to json marshal proofs in ApplyTransaction", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", err)
		return nil, ErrUnknown
	}

	codesByt, err := json.Marshal(codes)
	if err != nil {
		log.Error("fail to json marshal codes in ApplyTransaction", "id", ccc.ID, "TxHash", traces.Transactions[0].TxHash, "err", err)
		return nil, ErrUnknown
	}

	tracesStr := C.CString(string(tracesByt))
	defer func() {
		C.free(unsafe.Pointer(tracesStr))
	}()

	proofTracesStr := C.CString(string(proofsByt))
	defer func() {
		C.free(unsafe.Pointer(proofTracesStr))
	}()

	codeTracesStr := C.CString(string(codesByt))
	defer func() {
		C.free(unsafe.Pointer(codeTracesStr))
	}()

	log.Debug("start to check circuit capacity for block", "id", ccc.ID, "blockNumber", traces.Header.Number, "blockHash", traces.Header.Hash())
	rawResult := C.apply_block(C.uint64_t(ccc.ID), tracesStr, proofTracesStr, codeTracesStr)
	defer func() {
		C.free_c_chars(rawResult)
	}()
	log.Debug("check circuit capacity for block done", "id", ccc.ID, "blockNumber", traces.Header.Number, "blockHash", traces.Header.Hash())

	result := &WrappedRowUsage{}
	if err = json.Unmarshal([]byte(C.GoString(rawResult)), result); err != nil {
		log.Error("fail to json unmarshal apply_block result", "id", ccc.ID, "blockNumber", traces.Header.Number, "blockHash", traces.Header.Hash(), "err", err)
		return nil, ErrUnknown
	}

	if result.Error != "" {
		log.Error("fail to apply_block in CircuitCapacityChecker", "id", ccc.ID, "blockNumber", traces.Header.Number, "blockHash", traces.Header.Hash(), "err", result.Error)
		return nil, ErrUnknown
	}
	if result.AccRowUsage == nil {
		log.Error("fail to apply_block in CircuitCapacityChecker", "id", ccc.ID, "blockNumber", traces.Header.Number, "blockHash", traces.Header.Hash(), "err", "AccRowUsage is empty unexpectedly")
		return nil, ErrUnknown
	}
	if !result.AccRowUsage.IsOk {
		return nil, ErrBlockRowConsumptionOverflow
	}
	return (*types.RowConsumption)(&result.AccRowUsage.RowUsageDetails), nil
}

// CheckTxNum compares whether the tx_count in ccc match the expected
func (ccc *CircuitCapacityChecker) CheckTxNum(expected int) (bool, uint64, error) {
	ccc.Lock()
	defer ccc.Unlock()

	log.Debug("ccc get_tx_num start", "id", ccc.ID)
	rawResult := C.get_tx_num(C.uint64_t(ccc.ID))
	defer func() {
		C.free_c_chars(rawResult)
	}()
	log.Debug("ccc get_tx_num end", "id", ccc.ID)

	result := &WrappedTxNum{}
	if err := json.Unmarshal([]byte(C.GoString(rawResult)), result); err != nil {
		return false, 0, fmt.Errorf("fail to json unmarshal get_tx_num result, id: %d, err: %w", ccc.ID, err)
	}
	if result.Error != "" {
		return false, 0, fmt.Errorf("fail to get_tx_num in CircuitCapacityChecker, id: %d, err: %w", ccc.ID, result.Error)
	}

	return result.TxNum == uint64(expected), result.TxNum, nil
}

// SetLightMode sets to ccc light mode
func (ccc *CircuitCapacityChecker) SetLightMode(lightMode bool) error {
	ccc.Lock()
	defer ccc.Unlock()

	log.Debug("ccc set_light_mode start", "id", ccc.ID)
	rawResult := C.set_light_mode(C.uint64_t(ccc.ID), C.bool(lightMode))
	defer func() {
		C.free_c_chars(rawResult)
	}()
	log.Debug("ccc set_light_mode end", "id", ccc.ID)

	result := &WrappedCommonResult{}
	if err := json.Unmarshal([]byte(C.GoString(rawResult)), result); err != nil {
		return fmt.Errorf("fail to json unmarshal set_light_mode result, id: %d, err: %w", ccc.ID, err)
	}
	if result.Error != "" {
		return fmt.Errorf("fail to set_light_mode in CircuitCapacityChecker, id: %d, err: %w", ccc.ID, result.Error)
	}

	return nil
}
