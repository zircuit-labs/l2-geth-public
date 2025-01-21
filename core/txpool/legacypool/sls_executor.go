package legacypool

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/log"
)

type (
	Executor struct {
		quarantiner quarantiner    // Interface to interact with quarantined transactions.
		signer      types.Signer   // Ethereum transaction signer for signature verification.
		pool        *LegacyPool    // Reference to a pool of transactions (legacy).
		stopChan    chan struct{}  // Channel used to signal stopping the executor loop.
		once        sync.Once      // Ensures stop signal is only sent once.
		wg          sync.WaitGroup // Wait group for managing goroutine lifecycle.
		interval    time.Duration  // Interval between each execution attempt.
	}
)

const (
	defaultInterval = time.Second
)

// NewExecutor creates and returns a new Executor instance, initializing it with the provided parameters.
func NewExecutor(quarantiner quarantiner, signer types.Signer, pool *LegacyPool, interval time.Duration) *Executor {
	execInterval := defaultInterval
	if interval > 0 {
		execInterval = interval
	}

	return &Executor{
		quarantiner: quarantiner,
		signer:      signer,
		pool:        pool,
		stopChan:    make(chan struct{}),
		interval:    execInterval,
	}
}

var ErrNotPromoted = errors.New("can't promote transaction")

// Loop starts the main loop of the Executor in a separate goroutine, where it periodically
// checks for quarantined transactions that can be released and executed.
func (e *Executor) Loop(ctx context.Context) {
	e.wg.Add(1)
	defer e.wg.Done()
	defer e.pool.wg.Done()

	execute := time.NewTicker(e.interval) // Timer for scheduling executions.
	defer execute.Stop()

	log.Info("Executor loop started", "interval", e.interval)

	for {
		select {
		case <-execute.C: // On each tick, check and process quarantined transactions.
			log.Debug("Checking for pending releases")
			quarantines, err := e.quarantiner.PendingRelease(ctx, model.PoolQuarantineType)
			if err != nil {
				log.Warn("Failed to fetch pending releases", "error", err)
				continue
			}

			for _, quarantine := range quarantines {
				if !quarantine.ShouldBeReleased() { // Sanity check
					log.Info("Transaction shouldn't be released yet", "txHash", quarantine.TxHash)
					continue
				}

				tx, err := quarantine.Tx()
				if err != nil {
					log.Warn("Failed to deserialize transaction", "txHash", quarantine.TxHash, "error", err)
					continue
				}

				if err := e.Execute(tx); err != nil {
					log.Warn("Execution failed", "txHash", quarantine.TxHash, "error", err)
					continue
				}

				if err := e.quarantiner.Release(ctx, tx); err != nil {
					log.Warn("Failed to mark transaction as released", "txHash", tx.Hash().String(), "error", err)
					continue
				}

				log.Info("Transaction processed and released", "txHash", tx.Hash().String())
			}

		case <-e.stopChan: // Stop the loop when stop signal is received.
			log.Info("Executor loop stopped")
			return
		}
	}
}

// Stop signals the executor loop to stop and waits for it to terminate.
func (e *Executor) Stop() {
	e.once.Do(func() {
		close(e.stopChan) // Close the stop channel to signal the loop to stop.
	})
	e.wg.Wait() // Wait for the loop goroutine to finish.
}

// Execute attempts to promote and execute a given transaction from the pool.
func (e *Executor) Execute(tx *types.Transaction) error {
	e.pool.mu.Lock()
	defer e.pool.mu.Unlock()

	addr, err := types.Sender(e.signer, tx)
	if err != nil {
		return err
	}

	hash := tx.Hash()

	// Attempt to promote the transaction within the pool.
	promoted := e.pool.promoteTx(addr, hash, tx)

	if !promoted {
		return ErrNotPromoted
	}

	events := map[common.Address]*sortedMap{
		addr: newSortedMap(),
	}

	events[addr].Put(tx)

	var txs []*types.Transaction
	for _, set := range events {
		txs = append(txs, set.Flatten()...)
	}

	e.pool.txFeed.Send(core.NewTxsEvent{Txs: txs})

	return nil
}
