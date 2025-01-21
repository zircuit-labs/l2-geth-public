package legacypool

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls"
	"github.com/zircuit-labs/l2-geth-public/core/sls/slslog"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/log"
	"golang.org/x/sync/semaphore"
)

var (
	defaultWorkerPool        = 1
	defaultWorkersPerCycle   = 1
	defaultSLSProcessTimeOut = 1 * time.Second
)

var (
	errorDetectorManager = &sls.ManagerResult{
		ShouldBeQuarantined: true,
		Detectors:           "Error",
		Reasons:             "Transaction couldn't be verified",
		Loss:                0,
	}

	acceptDetectorManager = &sls.ManagerResult{
		ShouldBeQuarantined: false,
	}
)

type SLSTxProcessor struct {
	pool                     *LegacyPool                           // Reference to a pool of transactions (legacy).
	processTimeout           time.Duration                         // The maximum duration allowed for processing transactions.
	promotables              map[common.Address]types.Transactions // Transctions that have been verified and ready to promote.
	sendBackToPool           types.Transactions                    // Transactions that have a failure and need to send back to pool.
	maxWorkersPerCycle       int                                   // Max number of sls workers for each promotion cycle.
	maxConcurrencyPool       int                                   // Max number of sls workers across all promotion cycle.
	workerConcurrencyLimiter *semaphore.Weighted                   // Semaphore to control max concurrent workers across all promotion cycles.
	logger                   log.Logger
	mu                       sync.Mutex
}

// NewSLSTxProcessor creates and returns a new SLSTxProcessor instance, initializing it with the provided parameters.
func NewSLSTxProcessor(pool *LegacyPool) *SLSTxProcessor {
	processTimeout := defaultSLSProcessTimeOut
	if pool.slsConfig.PromotablesCollectionTimeout > 0 {
		processTimeout = time.Duration(pool.slsConfig.PromotablesCollectionTimeout)
	}

	maxWorkersPerCycle := defaultWorkersPerCycle
	if pool.slsConfig.MaxWorkersPerCycle > 1 {
		maxWorkersPerCycle = pool.slsConfig.MaxWorkersPerCycle
	}

	maxConcurrencyPool := defaultWorkerPool
	if pool.slsConfig.MaxConcurrencyPool > 1 {
		maxConcurrencyPool = pool.slsConfig.MaxConcurrencyPool
	}

	return &SLSTxProcessor{
		pool:                     pool,
		processTimeout:           processTimeout,
		promotables:              make(map[common.Address]types.Transactions),
		sendBackToPool:           types.Transactions{},
		maxWorkersPerCycle:       maxWorkersPerCycle,
		maxConcurrencyPool:       maxConcurrencyPool,
		workerConcurrencyLimiter: semaphore.NewWeighted(int64(maxConcurrencyPool)),
		logger:                   slslog.NewWith("sls_txprocessor", true),
	}
}

// ProcessTransactionsWithTimeout coordinates the concurrent processing of transactions by spawning goroutines.
// It utilizes a semaphore (workerConcurrencyLimiter) to limit the maximum number of concurrent workers globally.
// While the function itself does not directly modify shared state, it ensures thread-safe updates within each worker.
// It blocks until all transactions are processed or the timeout is reached, then returns the transactions completed within that time limit.
func (s *SLSTxProcessor) ProcessTransactionsWithTimeout(ctx context.Context, addr common.Address, transactions types.Transactions) types.Transactions {
	// Generate a unique promotion ID for slsworker logger
	promotionID := time.Now().UnixMilli()

	toBeVerified := make(chan *types.Transaction, len(transactions))
	done := make(chan struct{})

	for _, tx := range transactions {
		toBeVerified <- tx
	}
	s.logger.Debug("Sent all transactions to be verified", "promotionID", promotionID)
	close(toBeVerified)

	var wg sync.WaitGroup
	for i := 0; i < s.maxWorkersPerCycle; i++ {
		wg.Add(1)
		workerID := fmt.Sprintf("%d-%d", promotionID, i)
		go s.slsWorker(ctx, workerID, addr, toBeVerified, &wg)
	}

	// Close the done channel once all workers are finished
	// This allow us to early return if all txs in current promotion cycle are processed before timeout
	go func() {
		wg.Wait()
		close(done)
	}()

	// This will block until the timeout or until all transactions are processed
	return s.waitAndCollectPromotables(addr, done)
}

// waitAndCollectPromotables waits for either the specified timeout or until all goroutines complete their processing.
// If the timeout is reached first, it logs and returns the transactions processed so far. If all transactions are processed
// before the timeout, it logs and returns immediately. The function does not directly modify shared state and
// instead relies on CollectPromotablesByAddrss for thread-safe access to the shared promotables map.
func (s *SLSTxProcessor) waitAndCollectPromotables(addr common.Address, done <-chan struct{}) types.Transactions {
	select {
	case <-time.After(s.processTimeout):
		s.logger.Debug("Processing timeout reached. Returning transactions processed so far.", s.processTimeout)
	case <-done:
		s.logger.Debug("All transactions are processed before the timeout.")
	}

	return s.CollectPromotablesByAddrss(addr)
}

// CollectSendBackToPool returns all transactions that were identified for sending back to the pool due to errors.
// The function is protected by a mutex to ensure thread-safe access when collecting transactions from the sendBackToPool slice.
// After collecting, it clears the sendBackToPool slice to prepare for future use.
func (s *SLSTxProcessor) CollectSendBackToPool() types.Transactions {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := s.sendBackToPool
	s.sendBackToPool = types.Transactions{}
	return results
}

// CollectPromotablesByAddress returns all promotable transactions for the given address and removes them from the promotables map.
// The function is protected by a mutex to ensure thread-safe access when collecting and removing transactions.
// After collecting, it deletes the promotables transactions for the address to avoid reprocessing in future cycles.
func (s *SLSTxProcessor) CollectPromotablesByAddrss(addr common.Address) types.Transactions {
	s.mu.Lock()
	defer s.mu.Unlock()

	results := s.promotables[addr]
	delete(s.promotables, addr)

	return results
}

// CollectAllPromotables returns all promotable transactions from the promotables map across all addresses.
// The function is protected by a mutex to ensure thread-safe access when collecting and removing transactions.
// After collecting, it clears the promotables map to avoid reprocessing these transactions in future promotion cycles.
func (s *SLSTxProcessor) CollectAllPromotables() types.Transactions {
	s.mu.Lock()
	defer s.mu.Unlock()

	var allPromotables types.Transactions

	for _, txs := range s.promotables {
		allPromotables = append(allPromotables, txs...)
	}

	// Clear promotables
	s.promotables = make(map[common.Address]types.Transactions)

	return allPromotables
}

// slsWorker processes transactions concurrently by reading from the toBeVerified channel and handling each transaction.
// The function itself does not directly modify shared state. Instead, it uses thread-safe helper methods (addToPromotables and addToSendBackToPool)
// to safely update promotables map. These helper methods manage mutex locking internally, ensuring that all modifications to promotables
// and sendBackToPool are handled in a thread-safe manner.
func (s *SLSTxProcessor) slsWorker(ctx context.Context, id string, addr common.Address, toBeVerified chan *types.Transaction, wg *sync.WaitGroup) {
	defer wg.Done()

	logger := s.logger.With("id", id)

	// The worker uses a semaphore (workerConcurrencyLimiter) to control the start of its processing. When the worker is spawned,
	// it will wait (block) until a slot becomes available in the semaphore, respecting the global concurrency limit across all
	// promotion cycles. Once a slot is available, the worker acquires it and starts processing transactions. After processing,
	// the worker releases the slot, allowing other workers to start their processing.
	// This helps prevent overwhelming providers when too many workers send requests concurrently.
	logger.Debug("SLS worker started, waiting to acquire a semaphore slot")
	if err := s.workerConcurrencyLimiter.Acquire(ctx, 1); err != nil {
		logger.Error("Failed to acquire semaphore for sls worker", "error", err)
		return
	}
	logger.Debug("SLS worker acquired semaphore slot, starting to work")

	// Release the semaphore slot after work is done
	defer func() {
		logger.Debug("SLS worker releasing semaphore slot")
		s.workerConcurrencyLimiter.Release(1)
	}()

	for {
		select {
		case tx, ok := <-toBeVerified:
			if !ok {
				logger.Debug("SLS worker shutting down due to channel closure")
				return
			}

			signer := types.LatestSignerForChainID(tx.ChainId())
			sender, _ := signer.Sender(tx) // we don't want to block if this fails as it's just for logging purposes, so not checking error

			txLogger := logger.With(
				"hash", tx.Hash().String(),
				"from", sender,
				"to", tx.To(),
				"value", tx.Value(),
				"gasLimit", tx.Gas(),
				"maxFeePerGas", tx.GasFeeCap(),
				"maxPriorityFeePerGas", tx.GasTipCap(),
				"gasPrice", tx.GasPrice(),
			)
			detectorResult := s.handleTransaction(ctx, txLogger, tx)

			if !detectorResult.ShouldBeQuarantined {
				txLogger.Debug("Transaction does not require quarantine. Sending to promotion.")

				s.addToPromotables(addr, tx)
				continue
			}

			// If the transaction should be quarantined based on the detector's analysis,
			// attempt to send it to quarantine using the pool's quarantiner component.
			txLogger.Info("Attempting to quarantine transaction")

			err := s.pool.quarantiner.SendToQuarantine(ctx, tx, detectorResult.Detectors, detectorResult.Reasons, detectorResult.Loss)
			if err != nil {
				txLogger.Warn("Error when trying to quarantine transaction - sending transaction back to queue", "err", err)

				s.addToSendBackToPool(tx)
				continue
			}

			txLogger.Info("Transaction successfully quarantined", "detectors", detectorResult.Detectors)
		case <-ctx.Done():
			logger.Debug("SLS worker shutting down due to context cancellation")
			return
		}
	}
}

// handleTransaction determines if a transaction should be quarantined based on checks.
// This function does not modify any shared state directly.
func (s *SLSTxProcessor) handleTransaction(ctx context.Context, logger log.Logger, tx *types.Transaction) *sls.ManagerResult {
	// Check if SLS is enabled.
	if !s.pool.slsConfig.Enabled {
		logger.Debug("SLS is disabled. Skipping SLS checks.")
		return acceptDetectorManager
	}

	logger.Debug("SLS is enabled. Proceeding with transaction scan.")

	// Use the pool's detectorManager to check if the current transaction should be quarantined.
	// This check returns a boolean value, the name of the detector that identified the transaction,
	// a reason for quarantine, and an error if the check could not be completed.
	detectorResult, err := s.pool.detectorManager.ShouldBeQuarantined(ctx, tx)
	if err != nil {
		if s.pool.slsConfig.AssumeInnocenceOnError {
			logger.Error("Error when trying to scan transaction - assuming innocence - sending transaction to promotion", "err", err)
			return acceptDetectorManager
		} else {
			logger.Error("Error when trying to scan transaction - assuming guilty - sending transaction to quarantine", "err", err)
			return errorDetectorManager
		}
	}

	logger.With("shouldBeQuarantined", detectorResult.ShouldBeQuarantined,
		"detectorName", detectorResult.Detectors,
		"reason", detectorResult.Reasons,
		"loss", detectorResult.Loss).Debug("Transaction scan completed")

	return &detectorResult
}

// addToPromotables safely adds a transaction to the promotables map for a given address.
// The function acquires a mutex lock to ensure thread-safe access to the promotables map
// before appending the transaction.
func (s *SLSTxProcessor) addToPromotables(addr common.Address, tx *types.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.promotables[addr] = append(s.promotables[addr], tx)
}

// addToSendBackToPool safely adds a transaction to the sendBackToPool slice.
// The function acquires a mutex lock to ensure thread-safe access to the sendBackToPool slice
// before appending the transaction.
func (s *SLSTxProcessor) addToSendBackToPool(tx *types.Transaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendBackToPool = append(s.sendBackToPool, tx)
}
