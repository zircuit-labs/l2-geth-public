package sls

import (
	"context"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
)

//go:generate go tool mockgen -source quarantiner.go -destination mock_quarantiner.go -package sls

type (
	// QuarantinedTransaction represents a single quarantined transaction plus metadata for a DB insert.
	QuarantinedTransaction struct {
		Tx             *types.Transaction
		QuarantineType model.QuarantineType
		Detector       string
		Reason         string
		Loss           uint64
	}

	Storage interface {
		Add(ctx context.Context, quarantine *model.Quarantine) error
		AddMany(ctx context.Context, quarantines []*model.Quarantine) error
		PendingRelease(ctx context.Context, quarantineTypes []model.QuarantineType) ([]*model.Quarantine, error)
		Release(ctx context.Context, txHash common.Hash, reason string) (bool, error)
		Quarantined(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error)
		AdminAddresses(ctx context.Context, opts pg.QueryOpts) ([]*model.Admin, error)
	}

	Quarantiner interface {
		SendToQuarantine(ctx context.Context, transaction *types.Transaction, quarantineType model.QuarantineType, detector, reason string, loss uint64) error
		SendManyToQuarantine(ctx context.Context, transactions []QuarantinedTransaction) error
		PendingRelease(ctx context.Context, quarantineTypes []model.QuarantineType) ([]*model.Quarantine, error)
		Release(ctx context.Context, transaction *types.Transaction) error
		WasRecentlyQuarantined(txHash string) bool
	}
)
