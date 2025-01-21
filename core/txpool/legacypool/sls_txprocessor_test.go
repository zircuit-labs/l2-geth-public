package legacypool

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls"
	"github.com/zircuit-labs/l2-geth-public/core/sls/duration"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/crypto"
)

func TestSLSTxProcessor(t *testing.T) {
	tests := []struct {
		name                                string
		setupTransactions                   func(*ecdsa.PrivateKey, types.Signer) (common.Address, types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool)
		setupMocks                          func(*sls.MockDetectorManager, *sls.MockSlsQuarantiner, *types.Transactions, *types.Transactions, time.Duration)
		timeout                             duration.Duration
		expectedTxIDs                       map[common.Hash]bool
		expectedCollected                   int
		expectedPromotables                 int
		expectedSendBackToPoolBeforeTimeout int
		expectedSendBackToPoolAfterTimeout  int
		expectTimeout                       bool
		slowTxProcessTime                   time.Duration
	}{
		{
			name: "Collect processed promotable txs within timeout",
			setupTransactions: func(key *ecdsa.PrivateKey, signer types.Signer) (common.Address, types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool) {
				tx1 := transaction(0, 100, key)
				tx2 := transaction(10, 100, key)
				tx3 := transaction(10, 100, key)
				addr, _ := types.Sender(signer, tx1)

				expectedTxIDs := map[common.Hash]bool{
					tx1.Hash(): true,
					tx2.Hash(): true,
					tx3.Hash(): true,
				}

				return addr, types.Transactions{tx1, tx2, tx3}, expectedTxIDs, nil, nil, nil, nil
			},
			setupMocks: func(mockManager *sls.MockDetectorManager, mockQuarantiner *sls.MockSlsQuarantiner, slowTxs *types.Transactions, failedTx *types.Transactions, processTime time.Duration) {
				mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), gomock.Any()).AnyTimes()
				mockManager.EXPECT().Stop().AnyTimes()
			},
			timeout:                             duration.Duration(1 * time.Second),
			expectedCollected:                   3,
			expectedSendBackToPoolBeforeTimeout: 0,
			expectedSendBackToPoolAfterTimeout:  0,
			expectTimeout:                       false,
			slowTxProcessTime:                   0,
		},
		{
			name: "Slow tx should continue to process and be added to promotables after timeout",
			setupTransactions: func(key *ecdsa.PrivateKey, signer types.Signer) (common.Address, types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool) {
				tx1 := transaction(0, 100, key)
				tx2 := transaction(10, 100, key)
				slowTx3 := transaction(10, 100, key)
				slowTx4 := transaction(20, 100, key)
				addr, _ := types.Sender(signer, tx1)

				expectedTxIDs := map[common.Hash]bool{tx1.Hash(): true, tx2.Hash(): true}
				expectedSlowTxIDs := map[common.Hash]bool{slowTx3.Hash(): true, slowTx4.Hash(): true}
				return addr, types.Transactions{tx1, tx2, slowTx3, slowTx4}, expectedTxIDs, &types.Transactions{slowTx3, slowTx4}, expectedSlowTxIDs, nil, nil
			},
			setupMocks: func(mockManager *sls.MockDetectorManager, mockQuarantiner *sls.MockSlsQuarantiner, slowTxs *types.Transactions, failedTx *types.Transactions, processTime time.Duration) {
				// tx3, tx4 will finish after timeout
				for _, tx := range *slowTxs {
					mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), tx).DoAndReturn(
						func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
							time.Sleep(processTime)
							return sls.ManagerResult{
								ShouldBeQuarantined: false,
							}, nil
						})
				}
				mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), gomock.Any()).AnyTimes()
				mockManager.EXPECT().Stop().AnyTimes()
			},
			timeout:                             duration.Duration(1 * time.Second),
			expectedCollected:                   2,
			expectedPromotables:                 2,
			expectedSendBackToPoolBeforeTimeout: 0,
			expectedSendBackToPoolAfterTimeout:  0,
			expectTimeout:                       true,
			slowTxProcessTime:                   2 * time.Second,
		},
		{
			name: "Failed txs should be added to sendBackToPool",
			setupTransactions: func(key *ecdsa.PrivateKey, signer types.Signer) (common.Address, types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool) {
				// Processed within timeout
				tx1 := transaction(0, 100, key)
				tx2 := transaction(10, 100, key)

				// Added to sendBackToPool due to qurantinee error
				failedTx1 := transaction(10, 100, key)
				failedTx2 := transaction(20, 100, key)
				addr, _ := types.Sender(signer, tx1)

				expectedTxIDs := map[common.Hash]bool{tx1.Hash(): true, tx2.Hash(): true}
				expectedFailedTxIDs := map[common.Hash]bool{failedTx1.Hash(): true, failedTx2.Hash(): true}

				allTx := types.Transactions{tx1, tx2, failedTx1, failedTx2}
				failedTxs := &types.Transactions{failedTx1, failedTx2}
				return addr, allTx, expectedTxIDs, nil, nil, failedTxs, expectedFailedTxIDs
			},
			setupMocks: func(mockManager *sls.MockDetectorManager, mockQuarantiner *sls.MockSlsQuarantiner, slowTxs *types.Transactions, failedTxs *types.Transactions, processTime time.Duration) {
				for _, tx := range *failedTxs {
					mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), tx).DoAndReturn(
						func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
							return sls.ManagerResult{
								ShouldBeQuarantined: true,
							}, nil
						})
				}
				mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), gomock.Any()).AnyTimes()
				mockManager.EXPECT().Stop().AnyTimes()
				for _, tx := range *failedTxs {
					err := errors.New("Error when trying to quarantine transaction")
					mockQuarantiner.EXPECT().SendToQuarantine(gomock.Any(), tx, gomock.Any(), gomock.Any(), gomock.Any()).Return(err)
				}
			},
			timeout:                             duration.Duration(1 * time.Second),
			expectedCollected:                   2,
			expectedPromotables:                 0,
			expectedSendBackToPoolBeforeTimeout: 2,
			expectedSendBackToPoolAfterTimeout:  0,
			expectTimeout:                       false,
			slowTxProcessTime:                   0,
		},
		{
			name: "Collect promotable txs and failed txs within timeout, add slows txs to promotables and slow failed txs to sendBackToPool after timeout",
			setupTransactions: func(key *ecdsa.PrivateKey, signer types.Signer) (common.Address, types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool, *types.Transactions, map[common.Hash]bool) {
				// Processed within timeout
				tx1 := transaction(0, 100, key)
				tx2 := transaction(10, 100, key)

				// Added to promotables after timeout
				slowTx3 := transaction(10, 100, key)
				slowTx4 := transaction(20, 100, key)

				// Added to sendBackToPool due to qurantinee error
				failedTx1 := transaction(10, 100, key)
				failedSlowTx2 := transaction(20, 100, key)
				addr, _ := types.Sender(signer, tx1)

				expectedTxIDs := map[common.Hash]bool{tx1.Hash(): true, tx2.Hash(): true}
				expectedSlowTxIDs := map[common.Hash]bool{slowTx3.Hash(): true, slowTx4.Hash(): true}
				expectedFailedTxIDs := map[common.Hash]bool{failedTx1.Hash(): true, failedSlowTx2.Hash(): true}

				allTx := types.Transactions{tx1, tx2, slowTx3, slowTx4, failedTx1, failedSlowTx2}
				slowTxs := &types.Transactions{slowTx3, slowTx4}
				failedTxs := &types.Transactions{failedTx1, failedSlowTx2}
				return addr, allTx, expectedTxIDs, slowTxs, expectedSlowTxIDs, failedTxs, expectedFailedTxIDs
			},
			setupMocks: func(mockManager *sls.MockDetectorManager, mockQuarantiner *sls.MockSlsQuarantiner, slowTxs *types.Transactions, failedTxs *types.Transactions, processTime time.Duration) {
				// tx3, tx4 will finish after timeout
				for _, tx := range *slowTxs {
					mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), tx).DoAndReturn(
						func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
							time.Sleep(processTime)
							return sls.ManagerResult{
								ShouldBeQuarantined: false,
							}, nil
						})
				}

				mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), (*failedTxs)[0]).DoAndReturn(
					func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
						return sls.ManagerResult{
							ShouldBeQuarantined: true,
						}, nil
					})
				mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), (*failedTxs)[1]).DoAndReturn(
					func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
						time.Sleep(processTime)
						return sls.ManagerResult{
							ShouldBeQuarantined: true,
						}, nil
					})

				for _, tx := range *failedTxs {
					err := errors.New("Error when trying to quarantine transaction")
					mockQuarantiner.EXPECT().SendToQuarantine(gomock.Any(), tx, gomock.Any(), gomock.Any(), gomock.Any()).Return(err)
				}
				mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), gomock.Any()).AnyTimes()
				mockManager.EXPECT().Stop().AnyTimes()
			},
			timeout:                             duration.Duration(1 * time.Second),
			expectedCollected:                   2,
			expectedPromotables:                 2,
			expectedSendBackToPoolBeforeTimeout: 1,
			expectedSendBackToPoolAfterTimeout:  1,
			expectTimeout:                       true,
			slowTxProcessTime:                   2 * time.Second,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			pool, key := setupPool()
			defer pool.Close()

			// Setup related mocks
			ctrl := gomock.NewController(t)
			mockManager := sls.NewMockDetectorManager(ctrl)
			mockQuarantiner := sls.NewMockSlsQuarantiner(ctrl)

			// Create transactions and expected IDs map
			addr, transactions, expectedTxIDs, slowTxs, expectedSlowTxIDs, failedTxs, expectedFailedTxIDs := tt.setupTransactions(key, pool.signer)
			tt.setupMocks(mockManager, mockQuarantiner, slowTxs, failedTxs, tt.slowTxProcessTime)

			pool.slsConfig.Enabled = true
			pool.slsConfig.MaxWorkersPerCycle = 5
			pool.slsConfig.MaxConcurrencyPool = 10
			pool.detectorManager = mockManager
			pool.quarantiner = mockQuarantiner
			pool.executor = NewExecutor(pool.quarantiner, pool.signer, pool, time.Duration(1))

			pool.slsConfig.PromotablesCollectionTimeout = tt.timeout

			// Start testing txProcessor
			txProcessor := NewSLSTxProcessor(pool)

			startTime := time.Now()
			collectedPromotables := txProcessor.ProcessTransactionsWithTimeout(ctx, addr, transactions)
			elapsedTime := time.Since(startTime)

			if tt.expectTimeout {
				assert.GreaterOrEqual(t, elapsedTime, 1*time.Duration(tt.timeout), "should have waited before collecting promotables")
			} else {
				assert.Less(t, elapsedTime, 1*time.Duration(tt.timeout), "should have returned before timeout")
			}

			// Verify the correct transactions were collected within timeout
			for _, tx := range collectedPromotables {
				if _, found := expectedTxIDs[tx.Hash()]; !found {
					t.Fatalf("Unexpected transaction ID: %s", tx.Hash())
				}
			}
			assert.Equal(t, tt.expectedCollected, len(collectedPromotables))
			// Promotables should be cleared after collecting txs
			assert.Equal(t, 0, len(txProcessor.promotables[addr]))

			// Verify the failed transaction being added to sendBackToPool
			if tt.expectedSendBackToPoolBeforeTimeout > 0 {
				assert.Equal(t, tt.expectedSendBackToPoolBeforeTimeout, len(txProcessor.sendBackToPool))
				for _, tx := range txProcessor.sendBackToPool {
					if _, found := expectedFailedTxIDs[tx.Hash()]; !found {
						t.Fatalf("Unexpected transaction ID in sendBackToPool: %s", tx.Hash())
					}
				}
			}

			// Stimulate the behaviour of pool.promoteExctuables
			sendBackToPool := txProcessor.CollectSendBackToPool()
			assert.Equal(t, sendBackToPool.Len(), tt.expectedSendBackToPoolBeforeTimeout)
			// SendBackToPool should be cleared after collecting txs
			assert.Equal(t, 0, len(txProcessor.sendBackToPool))

			// After timeout
			if tt.expectTimeout {
				<-time.After(tt.slowTxProcessTime)

				// slow tx completed after timeout should be added to promotables
				assert.Equal(t, tt.expectedPromotables, len(txProcessor.promotables[addr]))

				for _, tx := range txProcessor.promotables[addr] {
					if _, found := expectedSlowTxIDs[tx.Hash()]; !found {
						t.Fatalf("Unexpected transaction ID in promotables: %s, %s", addr, tx.Hash())
					}
				}

				// slow tx that failed after timeout should be added to sendBackToPool
				if tt.expectedSendBackToPoolAfterTimeout > 0 {
					assert.Equal(t, tt.expectedSendBackToPoolAfterTimeout, len(txProcessor.sendBackToPool))
					for _, tx := range txProcessor.sendBackToPool {
						if _, found := expectedFailedTxIDs[tx.Hash()]; !found {
							t.Fatalf("Unexpected transaction ID in sendBackToPool: %s", tx.Hash())
						}
					}
				}
			}
		})
	}
}

func TestSLSTxProcessorCollectAllPromotables(t *testing.T) {
	t.Parallel()

	pool, key := setupPool()
	defer pool.Close()

	txProcessor := NewSLSTxProcessor(pool)

	signer := pool.signer
	tx1 := transaction(0, 100, key)
	tx2 := transaction(10, 100, key)
	tx3 := transaction(20, 100, key)
	addr1, _ := types.Sender(signer, tx1)

	key2, _ := crypto.GenerateKey()
	tx4 := transaction(0, 100, key2)
	tx5 := transaction(10, 100, key2)
	addr2, _ := types.Sender(signer, tx4)

	txProcessor.promotables[addr1] = types.Transactions{tx1, tx2, tx3}
	txProcessor.promotables[addr2] = types.Transactions{tx4, tx5}

	allPromotables := txProcessor.CollectAllPromotables()

	expectedTxCount := 5
	if len(allPromotables) != expectedTxCount {
		t.Fatalf("Expected %d promotable transactions, but got %d", expectedTxCount, len(allPromotables))
	}

	expectedTxHashes := map[common.Hash]bool{
		tx1.Hash(): true,
		tx2.Hash(): true,
		tx3.Hash(): true,
		tx4.Hash(): true,
		tx5.Hash(): true,
	}

	for _, tx := range allPromotables {
		if _, exists := expectedTxHashes[tx.Hash()]; !exists {
			t.Fatalf("Unexpected transaction hash found: %s", tx.Hash().Hex())
		}
	}

	// Ensure that promotables map is cleared after collection
	assert.Equal(t, 0, len(txProcessor.promotables), "Expected promotables map to be empty after collection, but it is not.")
}

func TestSLSTxProcessorCollectPromotablesByAddrss(t *testing.T) {
	t.Parallel()

	pool, key := setupPool()
	defer pool.Close()

	txProcessor := NewSLSTxProcessor(pool)

	signer := pool.signer
	tx1 := transaction(0, 100, key)
	tx2 := transaction(10, 100, key)
	tx3 := transaction(20, 100, key)
	addr1, _ := types.Sender(signer, tx1)

	txProcessor.promotables[addr1] = types.Transactions{tx1, tx2, tx3}

	collectedPromotables := txProcessor.CollectPromotablesByAddrss(addr1)

	expectedTxCount := 3
	if len(collectedPromotables) != expectedTxCount {
		t.Fatalf("Expected %d promotable transactions for address %s, but got %d", expectedTxCount, addr1.Hex(), len(collectedPromotables))
	}

	expectedTxHashes := map[common.Hash]bool{
		tx1.Hash(): true,
		tx2.Hash(): true,
		tx3.Hash(): true,
	}

	for _, tx := range collectedPromotables {
		if _, exists := expectedTxHashes[tx.Hash()]; !exists {
			t.Fatalf("Unexpected transaction hash found: %s", tx.Hash().Hex())
		}
	}

	// Ensure that promotables map entry for addr1 is cleared after collection
	if len(txProcessor.promotables[addr1]) != 0 {
		t.Fatalf("Expected promotables map entry for address %s to be empty after collection, but got %d entries", addr1.Hex(), len(txProcessor.promotables[addr1]))
	}

	// Ensure that promotables map does not contain addr1 anymore
	if _, exists := txProcessor.promotables[addr1]; exists {
		t.Fatalf("Expected promotables map to not contain address %s after collection", addr1.Hex())
	}
}

func TestSLSTxProcessorCollectSendBackToPool(t *testing.T) {
	t.Parallel()

	pool, key := setupPool()
	defer pool.Close()

	txProcessor := NewSLSTxProcessor(pool)

	tx1 := transaction(0, 100, key)
	tx2 := transaction(10, 100, key)
	tx3 := transaction(20, 100, key)

	txProcessor.sendBackToPool = types.Transactions{tx1, tx2, tx3}

	collectedSendBackToPool := txProcessor.CollectSendBackToPool()

	expectedTxCount := 3
	if len(collectedSendBackToPool) != expectedTxCount {
		t.Fatalf("Expected %d transactions in sendBackToPool, but got %d", expectedTxCount, len(collectedSendBackToPool))
	}

	expectedTxHashes := map[common.Hash]bool{
		tx1.Hash(): true,
		tx2.Hash(): true,
		tx3.Hash(): true,
	}

	for _, tx := range collectedSendBackToPool {
		if _, exists := expectedTxHashes[tx.Hash()]; !exists {
			t.Fatalf("Unexpected transaction hash found: %s", tx.Hash().Hex())
		}
	}

	// Ensure that sendBackToPool is cleared after collection
	if len(txProcessor.sendBackToPool) != 0 {
		t.Fatalf("Expected sendBackToPool to be empty after collection, but got %d entries", len(txProcessor.sendBackToPool))
	}
}

func TestSLSTxProcessorWorkerLimit(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	pool, key := setupPool()
	defer pool.Close()

	signer := pool.signer
	slowTx1 := transaction(0, 100, key)
	slowTx2 := transaction(10, 100, key)
	slowTx3 := transaction(11, 100, key)
	slowTx4 := transaction(12, 100, key)
	addr1, _ := types.Sender(signer, slowTx1)
	addr1Txs := types.Transactions{slowTx1, slowTx2, slowTx3, slowTx4}

	key2, _ := crypto.GenerateKey()
	slowTx5 := transaction(0, 100, key2)
	slowTx6 := transaction(10, 100, key2)
	addr2, _ := types.Sender(signer, slowTx5)
	addr2Txs := types.Transactions{slowTx5, slowTx6}

	// Setup related mocks
	ctrl := gomock.NewController(t)
	mockManager := sls.NewMockDetectorManager(ctrl)
	mockQuarantiner := sls.NewMockSlsQuarantiner(ctrl)

	processTime := 2 * time.Second
	promotablesCollectionTimeout := 1 * time.Second

	slowTxs := types.Transactions{slowTx1, slowTx2, slowTx3, slowTx4}

	// Mock slow transactions that take longer to process
	for _, tx := range slowTxs {
		mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), tx).DoAndReturn(
			func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
				time.Sleep(processTime)
				return sls.ManagerResult{
					ShouldBeQuarantined: false,
				}, nil
			})
	}

	// Mock slow transactions for addr2 but should complete within timeout
	mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), slowTx5).DoAndReturn(
		func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
			time.Sleep(900 * time.Millisecond)
			return sls.ManagerResult{
				ShouldBeQuarantined: false,
			}, nil
		})
	mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), slowTx6).DoAndReturn(
		func(ctx context.Context, tx *types.Transaction) (sls.ManagerResult, error) {
			time.Sleep(900 * time.Millisecond)
			return sls.ManagerResult{
				ShouldBeQuarantined: false,
			}, nil
		})
	mockManager.EXPECT().ShouldBeQuarantined(gomock.Any(), gomock.Any()).AnyTimes()
	mockManager.EXPECT().Stop().AnyTimes()

	// Setup sls config
	pool.slsConfig.Enabled = true
	pool.slsConfig.MaxWorkersPerCycle = 2
	pool.slsConfig.MaxConcurrencyPool = 3
	pool.detectorManager = mockManager
	pool.quarantiner = mockQuarantiner
	pool.executor = NewExecutor(pool.quarantiner, pool.signer, pool, time.Duration(1))
	pool.slsConfig.PromotablesCollectionTimeout = duration.Duration(promotablesCollectionTimeout)

	txProcessor := NewSLSTxProcessor(pool)

	// Start the promotion process for addr1
	collectedPromotables := txProcessor.ProcessTransactionsWithTimeout(ctx, addr1, addr1Txs)
	assert.Equal(t, 0, len(collectedPromotables), "Expected 0 transactions processed within timeout for addr1")

	// Wait for the processing time to complete for addr1Txs
	time.Sleep(processTime)

	// Only 2 workers allowed to process addr1Txs due to MaxWorkersPerCycle limit
	assert.Equal(t, 2, txProcessor.promotables[addr1].Len(), "Expected 2 transactions processed for addr1 due to MaxWorkersPerCycle limit")

	// Start the promotion process for addr2Txs
	collectedPromotables = txProcessor.ProcessTransactionsWithTimeout(ctx, addr2, addr2Txs)

	// 2 workers are occupied from previous slow transactions to process the rest of addr1Txs
	// Only 1 worker available for this cycle (MaxConcurrencyPool - MaxWorkersPerCycle).
	assert.Equal(t, 1, len(collectedPromotables), "Expected 1 transaction processed for addr2 due to MaxConcurrencyPool limit")

	// Wait for the remaining transactions to complete
	time.Sleep(processTime)
	assert.Equal(t, 4, txProcessor.promotables[addr1].Len(), "Expected all transactions for addr1 to be completed")
	assert.Equal(t, 1, txProcessor.promotables[addr2].Len(), "Expected the rest of transactions for addr2 to be completed")
}
