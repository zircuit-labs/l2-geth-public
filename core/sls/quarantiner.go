package sls

import (
	"context"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/types"
)

//go:generate mockgen -source quarantiner.go -destination mock_quarantiner.go -package sls

// Quarantiner struct holds the logic for managing quarantined transactions.
// It includes a storage backend and a default duration for quarantine.
type (
	Quarantiner struct {
		storage  Storage
		duration time.Duration
		signer   types.Signer
	}

	Storage interface {
		Add(ctx context.Context, quarantine *model.Quarantine) error
		Quarantined(ctx context.Context, from *common.Address) ([]*model.Quarantine, int, error)
		PendingRelease(ctx context.Context, quarantineType model.QuarantineType) ([]*model.Quarantine, error)
		Release(ctx context.Context, txHash common.Hash, reason string) (bool, error)
	}

	SlsQuarantiner interface {
		SendToQuarantine(ctx context.Context, transaction *types.Transaction, detector, reason string, loss uint64) error
		PendingRelease(ctx context.Context, quarantineType model.QuarantineType) ([]*model.Quarantine, error)
		Release(ctx context.Context, transaction *types.Transaction) error
	}
)

const (
	releaseReason = "quarantine time expired"
)

// NewQuarantiner is a constructor function that initializes a new Quarantiner instance
// with a specified storage and quarantine duration.
func NewQuarantiner(storage Storage, duration time.Duration, signer types.Signer) *Quarantiner {
	return &Quarantiner{
		storage:  storage,
		duration: duration,
		signer:   signer,
	}
}

// SendToQuarantine adds a transaction to the quarantine storage with a reason and the detector's identifier.
func (q *Quarantiner) SendToQuarantine(ctx context.Context, transaction *types.Transaction, detector, reason string, loss uint64) error {
	from, err := types.Sender(q.signer, transaction)
	if err != nil {
		return err
	}

	quarantine, err := model.NewQuarantine(transaction, detector, reason, from.String(), q.duration, loss)
	if err != nil {
		return err
	}

	return q.storage.Add(ctx, quarantine)
}

// PendingRelease retrieves all transactions currently in quarantine that are pending release.
func (q *Quarantiner) PendingRelease(ctx context.Context, quarantineType model.QuarantineType) ([]*model.Quarantine, error) {
	return q.storage.PendingRelease(ctx, quarantineType)
}

// Release removes a transaction from quarantine, marking it as released by a specified wallet.
func (q *Quarantiner) Release(ctx context.Context, transaction *types.Transaction) error {
	_, err := q.storage.Release(ctx, transaction.Hash(), releaseReason)
	return err
}
