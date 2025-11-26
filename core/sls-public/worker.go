package sls

import (
	"context"

	"github.com/zircuit-labs/l2-geth/common"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type Worker struct{}

func NewWorker(slsStorage slsCommon.Storage, slsConfig Config, getSLSRefreshables RefreshableGetter, detectorManager slsCommon.DetectorManager, transactionClassifier, transactionRemover any, signer any, metricsCollector any) (*Worker, error) {
	return &Worker{}, nil
}

func (w *Worker) ValidateBlock(ctx context.Context, depositTxs types.Transactions, block *types.Block, blockTrace *types.BlockTrace) ([]common.Hash, error) {
	return []common.Hash{}, nil
}

var _ slsCommon.Worker = (*Worker)(nil)
