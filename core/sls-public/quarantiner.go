package sls

import (
	"context"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/types"
)

// Quarantiner struct holds the logic for managing quarantined transactions.
// It includes a storage backend and a default duration for quarantine.
type Quarantiner struct{}

var _ slsCommon.Quarantiner = (*Quarantiner)(nil)

func NewQuarantiner(ctx context.Context, storage slsCommon.Storage, config Config, getSLSRefreshables RefreshableGetter, signer types.Signer) *Quarantiner {
	return &Quarantiner{}
}

func (q *Quarantiner) SendToQuarantine(ctx context.Context, transaction *types.Transaction, quarantineType model.QuarantineType, detector, reason string, loss uint64) error {
	return nil
}

func (q *Quarantiner) SendManyToQuarantine(ctx context.Context, transactions []slsCommon.QuarantinedTransaction) error {
	return nil
}

func (q *Quarantiner) PendingRelease(ctx context.Context, quarantineTypes []model.QuarantineType) ([]*model.Quarantine, error) {
	return nil, nil
}

func (q *Quarantiner) Release(ctx context.Context, transaction *types.Transaction) error {
	return nil
}

func (q *Quarantiner) Add(txHash string) {}

func (q *Quarantiner) WasRecentlyQuarantined(txHash string) bool {
	return false
}
