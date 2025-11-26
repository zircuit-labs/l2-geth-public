package sls

import (
	"context"

	common "github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

//go:generate go tool mockgen -source worker.go -destination mock_worker.go -package sls

type Worker interface {
	ValidateBlock(ctx context.Context, depositTxs types.Transactions, block *types.Block, blockTrace *types.BlockTrace) ([]common.Hash, error)
}

type TransactionClassifier interface {
	Classify(depositTxs, flaggedTxs types.Transactions) (flaggedDepositTxs, flaggedPoolTxs []common.Hash)
}
