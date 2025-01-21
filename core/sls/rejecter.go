package sls

import (
	"context"

	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/sls/storage"
	"github.com/zircuit-labs/l2-geth-public/core/types"
)

// Rejecter struct holds the logic for managing quarantined transactions.
// It includes a storage backend and a default duration for quarantine.
type (
	Rejecter struct {
		storage storage.Storage
		signer  types.Signer
	}
)

// NewRejecter is a constructor function that initializes a new Rejecter instance
// with a specified storage and quarantine duration.
func NewRejecter(storage storage.Storage, signer types.Signer) *Rejecter {
	return &Rejecter{
		storage: storage,
		signer:  signer,
	}
}

func (q *Rejecter) RecordRejectedTx(ctx context.Context, transaction *types.Transaction, detector, reason string, loss uint64) error {
	from, err := types.Sender(q.signer, transaction)
	if err != nil {
		return err
	}

	quarantine, err := model.NewQuarantineRejected(transaction, detector, reason, from.String(), loss)
	if err != nil {
		return err
	}

	return q.storage.Add(ctx, quarantine)
}
