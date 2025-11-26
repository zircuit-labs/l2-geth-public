package sls

import (
	"context"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

// to determine if they should be quarantined.
type Manager struct{}

// NewManager creates a new instance of Manager with the detectors already grouped by priority.
func NewManager(getSLSRefreshables RefreshableGetter, detectorRegistry any, trustVerifiers []slsCommon.TrustVerifier, db any, metricsCollector any) *Manager {
	return &Manager{}
}

func (m Manager) AddTransactionDetectors(detectorsByPriority map[int][]slsCommon.TransactionDetector) error {
	return nil
}

func (m Manager) ShouldBeQuarantined(context.Context, *types.Transaction, slsCommon.DetectorType) (slsCommon.ManagerResult, error) {
	return slsCommon.ManagerResult{}, nil
}

func (m Manager) Stop() {
	// no-op
}

func (m Manager) AddBlockDetectors(detectors []slsCommon.BlockDetector) {
	// no-op
}

func (m Manager) AddTransactionDetector(priority int, detector slsCommon.TransactionDetector) error {
	return nil
}

func (m Manager) DetectQuarantinableTransactionsInBlock(ctx context.Context, block *types.Block, blockTrace *types.BlockTrace) ([]slsCommon.QuarantinedTransactionFromBlock, error) {
	return nil, nil
}

func (m Manager) IsTrusted(ctx context.Context, tx *types.Transaction) bool {
	return false
}

func (m Manager) RecordBlockTransactionResults(ctx context.Context, block *types.Block, flaggedTxs []slsCommon.QuarantinedTransactionFromBlock) error {
	return nil
}

var _ slsCommon.DetectorManager = (*Manager)(nil)
