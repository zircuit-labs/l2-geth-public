// Copyright 2022 The go-ethereum Authors
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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package miner

import (
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth-public/beacon/engine"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/consensus/ethash"
	"github.com/zircuit-labs/l2-geth-public/core/rawdb"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/rollup/circuitcapacitychecker"
)

func TestBuildPayload(t *testing.T) {
	t.Run("no-tx-pool", func(t *testing.T) { testBuildPayload(t, true, false) })
	// no-tx-pool case with interrupt not interesting because no-tx-pool doesn't run
	// the builder routine
	t.Run("with-tx-pool", func(t *testing.T) { testBuildPayload(t, false, false) })
	t.Run("with-tx-pool-interrupt", func(t *testing.T) { testBuildPayload(t, false, true) })
}

func testBuildPayload(t *testing.T, noTxPool, interrupt bool) {
	t.Parallel()
	var (
		db        = rawdb.NewMemoryDatabase()
		recipient = common.HexToAddress("0xdeadbeef")
	)
	w, b := newTestWorker(t, params.TestChainConfig, ethash.NewFaker(), db, 0)
	defer w.close()

	const numInterruptTxs = 256
	if interrupt {
		// when doing interrupt testing, create a large pool so interruption will
		// definitely be visible.
		txs := genTxs(1, numInterruptTxs)
		b.txPool.Add(txs, true, false)
	}

	timestamp := uint64(time.Now().Unix())
	args := &BuildPayloadArgs{
		Parent:       b.chain.CurrentBlock().Hash(),
		Timestamp:    timestamp,
		Random:       common.Hash{},
		FeeRecipient: recipient,
		NoTxPool:     noTxPool,
	}
	// payload resolution now interrupts block building, so we have to
	// wait for the payloading building process to build its first block
	payload, err := w.buildPayload(args)
	if err != nil {
		t.Fatalf("Failed to build payload %v", err)
	}
	verify := func(outer *engine.ExecutionPayloadEnvelope, txs int) {
		t.Helper()
		if outer == nil {
			t.Fatal("ExecutionPayloadEnvelope is nil")
		}
		payload := outer.ExecutionPayload
		if payload.ParentHash != b.chain.CurrentBlock().Hash() {
			t.Fatal("Unexpected parent hash")
		}
		if payload.Random != (common.Hash{}) {
			t.Fatal("Unexpected random value")
		}
		if payload.Timestamp != timestamp {
			t.Fatal("Unexpected timestamp")
		}
		if payload.FeeRecipient != recipient {
			t.Fatal("Unexpected fee recipient")
		}
		if !interrupt && len(payload.Transactions) != txs {
			t.Fatalf("Unexpect transaction set: got %d, expected %d", len(payload.Transactions), txs)
		} else if interrupt && len(payload.Transactions) >= txs {
			t.Fatalf("Unexpect transaction set: got %d, expected less than %d", len(payload.Transactions), txs)
		}
	}

	if noTxPool {
		// we only build the empty block when ignoring the tx pool
		empty := payload.ResolveEmpty()
		verify(empty, 0)
		full := payload.ResolveFull()
		verify(full, 0)
	} else if interrupt {
		full := payload.ResolveFull()
		verify(full, len(pendingTxs)+numInterruptTxs)
	} else { // tx-pool and no interrupt
		payload.WaitFull()
		full := payload.ResolveFull()
		verify(full, len(pendingTxs))
	}

	// Ensure resolve can be called multiple times and the
	// result should be unchanged
	dataOne := payload.Resolve()
	dataTwo := payload.Resolve()
	if !reflect.DeepEqual(dataOne, dataTwo) {
		t.Fatal("Unexpected payload data")
	}
}

func genTxs(startNonce, count uint64) types.Transactions {
	txs := make(types.Transactions, 0, count)
	signer := types.LatestSigner(params.TestChainConfig)
	for nonce := startNonce; nonce < startNonce+count; nonce++ {
		txs = append(txs, types.MustSignNewTx(testBankKey, signer, &types.AccessListTx{
			ChainID:  params.TestChainConfig.ChainID,
			Nonce:    nonce,
			To:       &testUserAddress,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas,
			GasPrice: big.NewInt(params.InitialBaseFee),
		}))
	}
	return txs
}

func TestPayloadId(t *testing.T) {
	t.Parallel()
	ids := make(map[string]int)
	for i, tt := range []*BuildPayloadArgs{
		{
			Parent:       common.Hash{1},
			Timestamp:    1,
			Random:       common.Hash{0x1},
			FeeRecipient: common.Address{0x1},
		},
		// Different parent
		{
			Parent:       common.Hash{2},
			Timestamp:    1,
			Random:       common.Hash{0x1},
			FeeRecipient: common.Address{0x1},
		},
		// Different timestamp
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x1},
			FeeRecipient: common.Address{0x1},
		},
		// Different Random
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x1},
		},
		// Different fee-recipient
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
		},
		// Different withdrawals (non-empty)
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
			Withdrawals: []*types.Withdrawal{
				{
					Index:     0,
					Validator: 0,
					Address:   common.Address{},
					Amount:    0,
				},
			},
		},
		// Different withdrawals (non-empty)
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
			Withdrawals: []*types.Withdrawal{
				{
					Index:     2,
					Validator: 0,
					Address:   common.Address{},
					Amount:    0,
				},
			},
		},
	} {
		id := tt.Id().String()
		if prev, exists := ids[id]; exists {
			t.Errorf("ID collision, case %d and case %d: id %v", prev, i, id)
		}
		ids[id] = i
	}
}

func TestBuildPayloadWithCCCOverflow(t *testing.T) {
	// if first tx overflows a block, the tx is being removed from the pool
	t.Run("first-tx-overflow", func(t *testing.T) { testBuildPayloadWithCCCOverflow(t, true) })
	t.Run("second-tx-overflow", func(t *testing.T) { testBuildPayloadWithCCCOverflow(t, false) })
}

func testBuildPayloadWithCCCOverflow(t *testing.T, firstTxOverflow bool) {
	t.Parallel()
	var (
		db        = rawdb.NewMemoryDatabase()
		recipient = common.HexToAddress("0xdeadbeef")
	)
	w, b := newTestWorker(t, params.TestChainConfig, ethash.NewFaker(), db, 0)
	defer w.close()

	timestamp := uint64(time.Now().Unix())
	args := &BuildPayloadArgs{
		Parent:       b.chain.CurrentBlock().Hash(),
		Timestamp:    timestamp,
		Random:       common.Hash{},
		FeeRecipient: recipient,
		Transactions: types.Transactions{b.newRandomForcedTx(false)},
	}

	// there is single pending tx in default local environment and zero in Earthly environment
	if pending, _ := b.TxPool().Stats(); pending < 1 {
		b.txPool.Add([]*types.Transaction{b.newRandomTx(true)}, true, true)
	}

	var additionalPendingTxs int
	if !firstTxOverflow {
		b.txPool.Add([]*types.Transaction{b.newRandomTx(true)}, true, true)
		additionalPendingTxs++
	}

	pending, _ := b.TxPool().Stats()
	assert.Equal(t, len(pendingTxs)+additionalPendingTxs, pending) // consider additional pending transaction

	// error is scheduled for the last non-forced transaction
	w.circuitCapacityChecker.ScheduleError(len(args.Transactions)+pending, circuitcapacitychecker.ErrBlockRowConsumptionOverflow)

	// payload resolution now interrupts block building, so we have to
	// wait for the payloading building process to build its first block
	payload, err := w.buildPayload(args)
	if err != nil {
		t.Fatalf("Failed to build payload %v", err)
	}
	verify := func(outer *engine.ExecutionPayloadEnvelope, txs int) {
		t.Helper()
		if outer == nil {
			t.Fatal("ExecutionPayloadEnvelope is nil")
		}
		payload := outer.ExecutionPayload
		if payload.ParentHash != b.chain.CurrentBlock().Hash() {
			t.Fatal("Unexpected parent hash")
		}
		if payload.Random != (common.Hash{}) {
			t.Fatal("Unexpected random value")
		}
		if payload.Timestamp != timestamp {
			t.Fatal("Unexpected timestamp")
		}
		if payload.FeeRecipient != recipient {
			t.Fatal("Unexpected fee recipient")
		}
		if len(payload.Transactions) != txs {
			t.Fatalf("Unexpect transaction set: got %d, expected %d", len(payload.Transactions), txs)
		}
	}

	payload.WaitFull()
	full := payload.ResolveFull()
	if firstTxOverflow {
		verify(full, len(args.Transactions)+additionalPendingTxs)
	} else {
		verify(full, len(args.Transactions)+additionalPendingTxs)
	}

	previousPending := pending
	pending, _ = b.TxPool().Stats()
	if firstTxOverflow {
		// after the scheduled CCC failure on the first non-forced tx
		// pool should contain zero pending transactions
		assert.Equal(t, 0, pending)
	} else {
		// after the scheduled CCC failure on the second non-forced tx
		// pool should the same amount of transactions as before
		assert.Equal(t, previousPending, pending)
	}

	// Ensure resolve can be called multiple times and the
	// result should be unchanged
	dataOne := payload.Resolve()
	dataTwo := payload.Resolve()
	if !reflect.DeepEqual(dataOne, dataTwo) {
		t.Fatal("Unexpected payload data")
	}
}
