package sls

import (
	"context"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
)

type Rejecter struct{}

func NewRejecter(storage any, signer any) *Rejecter {
	return &Rejecter{}
}

func (r *Rejecter) RecordRejectedTx(ctx context.Context, transaction *types.Transaction, detector, reason string, loss uint64) error {
	return nil
}

func (r *Rejecter) Quarantined(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error) {
	return pg.Cursor{}, nil, nil
}

func (r *Rejecter) AdminAddresses(ctx context.Context, opts pg.QueryOpts) ([]*model.Admin, error) {
	return nil, nil
}
