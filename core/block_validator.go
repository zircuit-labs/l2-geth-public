// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"fmt"
	"sync"

	"github.com/zircuit-labs/l2-geth-public/consensus"
	"github.com/zircuit-labs/l2-geth-public/core/rawdb"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/rollup/circuitcapacitychecker"
	"github.com/zircuit-labs/l2-geth-public/trie"
)

// BlockValidator is responsible for validating block headers, uncles and
// processed state.
//
// BlockValidator implements Validator.
type BlockValidator struct {
	config *params.ChainConfig // Chain configuration options
	bc     *BlockChain         // Canonical block chain
	engine consensus.Engine    // Consensus engine used for validating

	// circuit capacity checker related fields
	db                     ethdb.Database                                 // db to store row consumption
	cMu                    sync.Mutex                                     // mutex for circuit capacity checker
	tracer                 tracerWrapper                                  // scroll tracer wrapper
	circuitCapacityChecker *circuitcapacitychecker.CircuitCapacityChecker // circuit capacity checker instance
}

// NewBlockValidator returns a new block validator which is safe for re-use
func NewBlockValidator(
	config *params.ChainConfig, blockchain *BlockChain, engine consensus.Engine, db ethdb.Database,
) *BlockValidator {
	validator := &BlockValidator{
		config: config,
		engine: engine,
		bc:     blockchain,
		db:     db,
	}

	log.Info("created new BlockValidator")
	return validator
}

func (v *BlockValidator) SetupTracerAndCircuitCapacityChecker(tracer tracerWrapper, cccConfig circuitcapacitychecker.Config) {
	v.tracer = tracer
	v.circuitCapacityChecker = circuitcapacitychecker.NewCircuitCapacityChecker(true, v.bc, cccConfig)
	log.Info("new CircuitCapacityChecker in BlockValidator", "ID", v.circuitCapacityChecker.ID)
}

type tracerWrapper interface {
	CreateTraceEnvAndGetBlockTrace(*params.ChainConfig, ChainContext, consensus.Engine, ethdb.Database, *state.StateDB, *types.Block, bool) (*types.BlockTrace, error)
}

// ValidateBody validates the given block's uncles and verifies the block
// header's transaction and uncle roots. The headers are assumed to be already
// validated at this point.
func (v *BlockValidator) ValidateBody(block *types.Block) error {
	// Check whether the block is already imported.
	if v.bc.HasBlockAndState(block.Hash(), block.NumberU64()) {
		return ErrKnownBlock
	}
	if !v.config.Scroll.IsValidTxCount(len(block.Transactions())) {
		return consensus.ErrInvalidTxCount
	}
	// Check if block payload size is smaller than the max size
	if !v.config.Scroll.IsValidBlockSize(block.PayloadSize()) {
		return ErrInvalidBlockPayloadSize
	}

	// Header validity is known at this point. Here we verify that uncles, transactions
	// and withdrawals given in the block body match the header.
	header := block.Header()
	if err := v.engine.VerifyUncles(v.bc, block); err != nil {
		return err
	}
	if hash := types.CalcUncleHash(block.Uncles()); hash != header.UncleHash {
		return fmt.Errorf("uncle root hash mismatch (header value %x, calculated %x)", header.UncleHash, hash)
	}
	if hash := types.DeriveSha(block.Transactions(), trie.NewStackTrie(nil)); hash != header.TxHash {
		return fmt.Errorf("transaction root hash mismatch (header value %x, calculated %x)", header.TxHash, hash)
	}

	// Withdrawals are present after the Shanghai fork.
	if header.WithdrawalsHash != nil {
		// Withdrawals list must be present in body after Shanghai.
		if block.Withdrawals() == nil {
			return errors.New("missing withdrawals in block body")
		}
		if hash := types.DeriveSha(block.Withdrawals(), trie.NewStackTrie(nil)); hash != *header.WithdrawalsHash {
			return fmt.Errorf("withdrawals root hash mismatch (header value %x, calculated %x)", *header.WithdrawalsHash, hash)
		}
	} else if block.Withdrawals() != nil {
		// Withdrawals are not allowed prior to Shanghai fork
		return errors.New("withdrawals present in block body")
	}

	// Blob transactions may be present after the Cancun fork.
	var blobs int
	for i, tx := range block.Transactions() {
		// Count the number of blobs to validate against the header's blobGasUsed
		blobs += len(tx.BlobHashes())

		// If the tx is a blob tx, it must NOT have a sidecar attached to be valid in a block.
		if tx.BlobTxSidecar() != nil {
			return fmt.Errorf("unexpected blob sidecar in transaction at index %d", i)
		}

		// The individual checks for blob validity (version-check + not empty)
		// happens in StateTransition.
	}

	// Check blob gas usage.
	if header.BlobGasUsed != nil {
		if want := *header.BlobGasUsed / params.BlobTxBlobGasPerBlob; uint64(blobs) != want { // div because the header is surely good vs the body might be bloated
			return fmt.Errorf("blob gas used mismatch (header %v, calculated %v)", *header.BlobGasUsed, blobs*params.BlobTxBlobGasPerBlob)
		}
	} else {
		if blobs > 0 {
			return errors.New("data blobs present in block body")
		}
	}

	// Ancestor block must be known.
	if !v.bc.HasBlockAndState(block.ParentHash(), block.NumberU64()-1) {
		if !v.bc.HasBlock(block.ParentHash(), block.NumberU64()-1) {
			return consensus.ErrUnknownAncestor
		}
		return consensus.ErrPrunedAncestor
	}
	if v.circuitCapacityChecker != nil && v.circuitCapacityChecker.Config.Enabled {
		// if a block's RowConsumption has been stored, which means it has been processed before,
		// (e.g., in miner/worker.go or in insertChain),
		// we simply skip its calculation and validation
		if rawdb.ReadBlockRowConsumption(v.db, block.Hash()) != nil {
			return nil
		}
		// TODO: update block validation according to the deposit flag
		rowConsumption, err := v.validateCircuitRowConsumption(block)
		if err != nil {
			return err
		}
		log.Trace(
			"Validator write block row consumption",
			"id", v.circuitCapacityChecker.ID,
			"number", block.NumberU64(),
			"hash", block.Hash().String(),
			"rowConsumption", rowConsumption,
		)
		rawdb.WriteBlockRowConsumption(v.db, block.Hash(), rowConsumption)
	}
	return nil
}

// ValidateState validates the various changes that happen after a state transition,
// such as amount of used gas, the receipt roots and the state root itself.
func (v *BlockValidator) ValidateState(block *types.Block, statedb *state.StateDB, receipts types.Receipts, usedGas uint64) error {
	header := block.Header()
	if block.GasUsed() != usedGas {
		return fmt.Errorf("invalid gas used (remote: %d local: %d)", block.GasUsed(), usedGas)
	}
	// Validate the received block's bloom with the one derived from the generated receipts.
	// For valid blocks this should always validate to true.
	rbloom := types.CreateBloom(receipts)
	if rbloom != header.Bloom {
		return fmt.Errorf("invalid bloom (remote: %x  local: %x)", header.Bloom, rbloom)
	}
	// Tre receipt Trie's root (R = (Tr [[H1, R1], ... [Hn, Rn]]))
	receiptSha := types.DeriveSha(receipts, trie.NewStackTrie(nil))
	if receiptSha != header.ReceiptHash {
		return fmt.Errorf("invalid receipt root hash (remote: %x local: %x)", header.ReceiptHash, receiptSha)
	}
	// Validate the state root against the received state root and throw
	// an error if they don't match.
	if root := statedb.IntermediateRoot(v.config.IsEIP158(header.Number)); header.Root != root {
		return fmt.Errorf("invalid merkle root (remote: %x local: %x) dberr: %w", header.Root, root, statedb.Error())
	}
	return nil
}

// CalcGasLimit computes the gas limit of the next block after parent. It aims
// to keep the baseline gas close to the provided target, and increase it towards
// the target if the baseline gas is lower.
func CalcGasLimit(parentGasLimit, desiredLimit uint64) uint64 {
	delta := parentGasLimit/params.GasLimitBoundDivisor - 1
	limit := parentGasLimit
	if desiredLimit < params.MinGasLimit {
		desiredLimit = params.MinGasLimit
	}
	// If we're outside our allowed gas range, we try to hone towards them
	if limit < desiredLimit {
		limit = parentGasLimit + delta
		if limit > desiredLimit {
			limit = desiredLimit
		}
		return limit
	}
	if limit > desiredLimit {
		limit = parentGasLimit - delta
		if limit < desiredLimit {
			limit = desiredLimit
		}
	}
	return limit
}

func (v *BlockValidator) createTraceEnvAndGetBlockTrace(block *types.Block) (*types.BlockTrace, error) {
	parent := v.bc.GetBlock(block.ParentHash(), block.NumberU64()-1)
	if parent == nil {
		return nil, errors.New("validateCircuitRowConsumption: no parent block found")
	}

	statedb, err := v.bc.StateAtHeader(v.bc.HeaderOrWaitZKTrie(parent.Header()))
	if err != nil {
		return nil, err
	}

	return v.tracer.CreateTraceEnvAndGetBlockTrace(v.config, v.bc, v.engine, v.db, statedb, block, true)
}

func (v *BlockValidator) validateCircuitRowConsumption(block *types.Block) (*types.RowConsumption, error) {
	log.Trace(
		"Validator apply ccc for block",
		"id", v.circuitCapacityChecker.ID,
		"number", block.NumberU64(),
		"hash", block.Hash().String(),
		"len(txs)", block.Transactions().Len(),
	)

	traces, err := v.createTraceEnvAndGetBlockTrace(block)
	if err != nil {
		return nil, err
	}

	v.cMu.Lock()
	defer v.cMu.Unlock()

	v.circuitCapacityChecker.Reset()
	log.Trace("Validator reset ccc", "id", v.circuitCapacityChecker.ID)
	rc, err := v.circuitCapacityChecker.ApplyBlock(traces, block)

	log.Trace(
		"Validator apply ccc for block result",
		"id", v.circuitCapacityChecker.ID,
		"number", block.NumberU64(),
		"hash", block.Hash().String(),
		"len(txs)", block.Transactions().Len(),
		"rc", rc,
		"err", err,
	)

	return rc, err
}
