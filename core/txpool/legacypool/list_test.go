// Copyright 2016 The go-ethereum Authors
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

package legacypool

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/crypto"
)

// Tests that transactions can be added to strict lists and list contents and
// nonce boundaries are correctly maintained.
func TestStrictListAdd(t *testing.T) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 1024)
	for i := range txs {
		txs[i] = transaction(uint64(i), 0, key)
	}
	// Insert the transactions in a random order
	list := newList(true)
	for _, v := range rand.Perm(len(txs)) {
		list.Add(txs[v], DefaultConfig.PriceBump)
	}
	// Verify internal state
	if list.txs.Len() != len(txs) {
		t.Errorf("transaction count mismatch: have %d, want %d", list.txs.Len(), len(txs))
	}
	for i, tx := range txs {
		if list.txs.Get(tx.Nonce()) != tx {
			t.Errorf("item %d: transaction mismatch: have %v, want %v", i, list.txs.Get(tx.Nonce()), tx)
		}
	}
}

// TestList_SubTotalCost checks panic on computing on nil values
func TestList_SubTotalCost(t *testing.T) {
	key, _ := crypto.GenerateKey()
	txs := []*types.Transaction{transaction(uint64(0), 0, key), transaction(uint64(1), 0, key)}

	list := newList(true)

	// panic should happen
	assert.PanicsWithValue(t, "cannot compute on nil value", func() {
		list.subTotalCost(txs)
	}, "should panic with 'cannot compute on nil value'")

	list.Add(txs[0], DefaultConfig.PriceBump)
	list.Add(txs[1], DefaultConfig.PriceBump)
	assert.NotEmpty(t, list.txCosts, "map should not be empty")

	// no panic
	list.subTotalCost(txs)
	assert.Empty(t, list.txCosts, "map should be empty")
}

// TestListAddVeryExpensive tests adding txs which exceed 256 bits in cost. It is
// expected that the list does not panic.
func TestListAddVeryExpensive(t *testing.T) {
	key, _ := crypto.GenerateKey()
	list := newList(true)
	for i := range 3 {
		value := big.NewInt(100)
		gasprice, _ := new(big.Int).SetString("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 0)
		gaslimit := uint64(i)
		tx, _ := types.SignTx(types.NewTransaction(uint64(i), common.Address{}, value, gaslimit, gasprice, nil), types.HomesteadSigner{}, key)
		t.Logf("cost: %x bitlen: %d\n", tx.Cost(), tx.Cost().BitLen())
		list.Add(tx, DefaultConfig.PriceBump)
	}
}

func BenchmarkListAdd(b *testing.B) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 100000)
	for i := range txs {
		txs[i] = transaction(uint64(i), 0, key)
	}
	// Insert the transactions in a random order
	priceLimit := uint256.NewInt(DefaultConfig.PriceLimit)
	for b.Loop() {
		list := newList(true)
		for _, v := range rand.Perm(len(txs)) {
			list.Add(txs[v], DefaultConfig.PriceBump)
			list.Filter(priceLimit, DefaultConfig.PriceBump)
		}
	}
}

func TestListShouldReplace(t *testing.T) {
	key, err := crypto.GenerateKey()
	assert.NoError(t, err)

	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Helper function to create transactions
	createTx := func(nonce uint64, gasFeeCap, gasTipCap int64) *types.Transaction {
		return types.NewTx(&types.DynamicFeeTx{
			Nonce:     nonce,
			GasTipCap: big.NewInt(gasTipCap),
			GasFeeCap: big.NewInt(gasFeeCap),
			Gas:       21000,
			To:        &addr,
			Value:     big.NewInt(0),
		})
	}

	tests := []struct {
		name          string
		setupTx       *types.Transaction
		newTx         *types.Transaction
		priceBump     uint64
		expectReplace bool
		expectHash    bool // whether an old transaction hash is expected
	}{
		{
			name:          "no existing transaction, should replace",
			setupTx:       nil, // No transaction exists
			newTx:         createTx(1, 100, 10),
			priceBump:     10,
			expectReplace: true,
			expectHash:    false,
		},
		{
			name:          "lower gas fee cap, should not replace",
			setupTx:       createTx(1, 200, 15),
			newTx:         createTx(1, 100, 10),
			priceBump:     10,
			expectReplace: false,
			expectHash:    true,
		},
		{
			name:          "higher gas fee cap and tip but below price bump threshold, should not replace",
			setupTx:       createTx(1, 200, 15),
			newTx:         createTx(1, 210, 16),
			priceBump:     20,
			expectReplace: false,
			expectHash:    true,
		},
		{
			name:          "higher gas fee cap and tip meeting price bump threshold, should replace",
			setupTx:       createTx(1, 200, 15),
			newTx:         createTx(1, 240, 18),
			priceBump:     20,
			expectReplace: true,
			expectHash:    true,
		},
		{
			name:          "equal gas fee cap and tip, should not replace",
			setupTx:       createTx(1, 200, 15),
			newTx:         createTx(1, 200, 15),
			priceBump:     10,
			expectReplace: false,
			expectHash:    true,
		},
		{
			name:          "nonce mismatch, should replace (treated as new)",
			setupTx:       createTx(1, 200, 15),
			newTx:         createTx(2, 210, 16),
			priceBump:     10,
			expectReplace: true,
			expectHash:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list := newList(true)
			if tt.setupTx != nil {
				list.Add(tt.setupTx, DefaultConfig.PriceBump)
			}
			shouldReplace, oldHash := list.ShouldReplace(tt.newTx, tt.priceBump)

			// Validate results
			if shouldReplace != tt.expectReplace {
				t.Errorf("expected replace: %v, got: %v", tt.expectReplace, shouldReplace)
			}
			if (oldHash != nil) != tt.expectHash {
				t.Errorf("expected hash presence: %v, got: %v", tt.expectHash, oldHash != nil)
			}
		})
	}
}

func BenchmarkListCapOneTx(b *testing.B) {
	// Generate a list of transactions to insert
	key, _ := crypto.GenerateKey()

	txs := make(types.Transactions, 32)
	for i := range txs {
		txs[i] = transaction(uint64(i), 0, key)
	}

	for b.Loop() {
		list := newList(true)
		// Insert the transactions in a random order
		for _, v := range rand.Perm(len(txs)) {
			list.Add(txs[v], DefaultConfig.PriceBump)
		}
		b.StartTimer()
		list.Cap(list.Len() - 1)
		b.StopTimer()
	}
}
