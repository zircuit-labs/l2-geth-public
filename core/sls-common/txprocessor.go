package sls

//go:generate go tool mockgen -source txprocessor.go -destination mock_txprocessor.go -package sls

import (
	"context"

	common "github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type TXProcessor interface {
	ProcessTransactions(ctx context.Context, addr common.Address, transactions types.Transactions) types.Transactions
	CollectSendBackToPool() types.Transactions
	CollectAllPromotables() types.Transactions
	IsAddressWaiting(addr common.Address) bool
	CollectQuarantinedAddresses() []common.Address
	Awaited(addr common.Address) types.Transactions
	Stop()
}

type EventSender interface {
	Send(value any) (nsent int)
}

type LegacyPool[CFG any, R any] interface {
	SLSConfig() CFG
	DetectorManager() DetectorManager
	Quarantiner() Quarantiner
	PromoteTx(addr common.Address, hash common.Hash, tx *types.Transaction) bool
	TxFeed() EventSender
	GetSLSRefreshables() R
}
