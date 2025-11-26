package sls

import (
	"context"
	"errors"
	"fmt"

	"github.com/zircuit-labs/l2-geth/core/types"
)

//go:generate go tool mockgen -source manager.go -destination mock_manager.go -package sls

// QuarantineSource identifies the detector and reason a transaction was quarantined.
type QuarantineSource struct {
	Detector string
	Reason   string
}

// QuarantinedTransactionFromBlock identifies a quarantined transaction
// along with sources (detector and reason); a transaction may be
// flagged by multiple detectors.
type QuarantinedTransactionFromBlock struct {
	Tx      *types.Transaction
	Sources []QuarantineSource
}

type DetectorManager interface {
	ShouldBeQuarantined(ctx context.Context, tx *types.Transaction, detectorType DetectorType) (ManagerResult, error)
	DetectQuarantinableTransactionsInBlock(ctx context.Context, block *types.Block, blockTrace *types.BlockTrace) ([]QuarantinedTransactionFromBlock, error)
	IsTrusted(ctx context.Context, tx *types.Transaction) bool
	RecordBlockTransactionResults(ctx context.Context, block *types.Block, flaggedTxs []QuarantinedTransactionFromBlock) error
	Stop()
}

type TransactionDetector interface {
	ShouldBeQuarantined(ctx context.Context, transaction *types.Transaction) (bool, string, uint64, error)
	Name() string
	Stop()
}

type BlockDetector interface {
	DetectQuarantinableTransactions(ctx context.Context, block *types.Block, blockTrace *types.BlockTrace) (types.Transactions, string, error)
	Name() string
	Stop()
}

type TrustVerifier interface {
	Name() string
	IsTrustable(ctx context.Context, transaction *types.Transaction) (bool, error)
}

type ManagerResult struct {
	ShouldBeQuarantined bool
	Detectors           string
	Reasons             string
	Loss                uint64
}

// ErrDetectorsTimedOut is returned when detectors fail to return within in the configured timeout.
var ErrDetectorsTimedOut = errors.New("timeout while waiting for detectors to run")

// ErrDetectorsFailed is returned whenever one or more detectors returns failure.
// It contains an accumulation of all such errors.
type ErrDetectorsFailed struct {
	Errors error
}

func (e *ErrDetectorsFailed) Error() string {
	return fmt.Sprintf("one or more detectors returned error: %v", e.Errors)
}

func (e *ErrDetectorsFailed) Unwrap() error {
	return e.Errors
}

// ErrParentCancellation is returned when the passed-in context signals that it is done.
type ErrParentCancellation struct {
	Cause error
}

func (e *ErrParentCancellation) Error() string {
	return fmt.Sprintf("got cancellation notice from parent context: %v", e.Cause)
}

func (e *ErrParentCancellation) Unwrap() error {
	return e.Cause
}
