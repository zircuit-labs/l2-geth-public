package sls

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/sls/slslog"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/log"
)

//go:generate mockgen -source manager.go -destination mock_manager.go -package sls

type (
	// Manager struct manages multiple detectors, checking transactions against each
	// to determine if they should be quarantined.
	Manager struct {
		detectorsByPriority [][]Detector    // A map of detectors grouped by their priority.
		trustVerifiers      []TrustVerifier // an ordered list of all the trust verifiers.
		db                  Database        // Database to store transaction results.
		logger              log.Logger
	}

	DetectorManager interface {
		ShouldBeQuarantined(ctx context.Context, tx *types.Transaction) (ManagerResult, error)
		Stop()
	}

	Detector interface {
		ShouldBeQuarantined(ctx context.Context, transaction *types.Transaction) (bool, string, uint64, error)
		Name() string
		Stop()
	}

	TrustVerifier interface {
		Name() string
		IsTrustable(ctx context.Context, transaction *types.Transaction) (bool, error)
	}

	Database interface {
		AddTransactionResult(ctx context.Context, result *model.TransactionResult) error
	}

	// detectorResult is used to communicate the outcome of the quarantine check.
	detectorResult struct {
		shouldBeQuarantined bool
		detectorName        string
		reason              string
		loss                uint64
		err                 error
	}

	ManagerResult struct {
		ShouldBeQuarantined bool
		Detectors           string
		Reasons             string
		Loss                uint64
	}
)

// NewManager creates a new instance of Manager with the detectors already grouped by priority.
func NewManager(detectorsByPriority [][]Detector, trustVerifiers []TrustVerifier, db Database) *Manager {
	return &Manager{
		detectorsByPriority: detectorsByPriority,
		trustVerifiers:      trustVerifiers,
		logger:              slslog.New(),
		db:                  db,
	}
}

// ShouldBeQuarantined iterates through all detectors to check if a transaction should be quarantined.
// It returns a boolean indicating the quarantine status, the name of the detector that triggered it,
// the reason for quarantine, and any error encountered.
func (m Manager) ShouldBeQuarantined(ctx context.Context, tx *types.Transaction) (ManagerResult, error) {
	logger := m.logger.With("txHash", tx.Hash().String())
	logger.Debug("Starting quarantine check")

	for _, verifier := range m.trustVerifiers {
		isTrustable, err := verifier.IsTrustable(ctx, tx)
		if err != nil {
			logger.With("err", err.Error()).Warn("TrustVerifier failed to verify transaction")
			continue
		}

		if isTrustable {
			logger.Debug("transaction was validated by a TrustVerifier - skipping detectors", "trust_verifier", verifier.Name())
			result := ManagerResult{ShouldBeQuarantined: false}
			m.recordResult(ctx, result, tx.Hash().String())
			return result, nil
		}
	}

	var errs []error

	for _, detectors := range m.detectorsByPriority {
		var wg sync.WaitGroup
		resultsChan := make(chan detectorResult, len(detectors))

		for _, d := range detectors {
			wg.Add(1)
			go func(d Detector) {
				defer wg.Done()

				loggerDetector := logger.New("detector", d.Name())
				loggerDetector.Debug("Starting detector")

				shouldBeQuarantined, reason, loss, err := d.ShouldBeQuarantined(ctx, tx)
				if err != nil {
					loggerDetector.With("error", err).Warn("Error in quarantine check")
				}

				loggerDetector.Debug("Detector finished")

				resultsChan <- detectorResult{
					shouldBeQuarantined: shouldBeQuarantined,
					detectorName:        d.Name(),
					reason:              reason,
					loss:                loss,
					err:                 err,
				}
			}(d)
		}

		// Using wg.Wait() in a goroutine allows immediate processing of results as they arrive.
		// This improves efficiency by not delaying result processing.
		go func() {
			wg.Wait() // Wait for all detectors at this priority level to finish
			close(resultsChan)
			logger.Debug("All detectors have completed processing for this priority level")
		}()

		// Process results
		var quarantineNames []string
		var quarantineReasons []string
		var losses uint64
		shouldBeQuarantined := false

		for res := range resultsChan {
			loggerResult := logger.New("detector", res.detectorName)
			loggerResult.Debug("Processing results")

			if res.err != nil {
				errs = append(errs, NewError(res.detectorName, res.err, tx.Hash().String()))
				continue
			}

			if res.shouldBeQuarantined {
				shouldBeQuarantined = true
				quarantineNames = append(quarantineNames, res.detectorName)
				quarantineReasons = append(quarantineReasons, res.reason)
				losses += res.loss
				loggerResult.With("reason", res.reason).Debug("Quarantine condition met")
			}
		}

		logger.Debug("Finished processing results")

		if shouldBeQuarantined {
			result := ManagerResult{
				ShouldBeQuarantined: true,
				Detectors:           strings.Join(quarantineNames, ", "),
				Reasons:             strings.Join(quarantineReasons, "; "),
				Loss:                losses,
			}
			m.recordResult(ctx, result, tx.Hash().String())
			logger.With("detectors", strings.Join(quarantineNames, ", "), "reasons", strings.Join(quarantineReasons, "; "), "totalLoss", losses).Debug("Transaction will be quarantined")
			return result, nil
		}
	}

	if errs != nil {
		logger.With("errors", errs).Error("Errors encountered during quarantine checks")
		result := ManagerResult{ShouldBeQuarantined: false}
		m.recordResult(ctx, result, tx.Hash().String())
		return result, errors.Join(errs...) // no quarantine, but some Detectors have failed.
	}

	logger.Info("No quarantine conditions met for transaction")
	result := ManagerResult{ShouldBeQuarantined: false}
	m.recordResult(ctx, result, tx.Hash().String())
	return result, nil // If no quarantine condition was detected
}

// recordResult stores the transaction result in the database.
func (m Manager) recordResult(ctx context.Context, managerResult ManagerResult, txHash string) {
	result := &model.TransactionResult{
		TxHash:      txHash,
		Quarantined: managerResult.ShouldBeQuarantined,
	}
	err := m.db.AddTransactionResult(ctx, result)
	if err != nil {
		m.logger.With("txHash", txHash, "error", err).Error("Failed to record transaction result")
	}
}

func (m Manager) Stop() {
	for _, d := range m.detectorsByPriority {
		for _, detector := range d {
			detector.Stop()
		}
	}
}
