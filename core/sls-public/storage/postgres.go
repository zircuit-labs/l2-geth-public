package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	commonStorage "github.com/zircuit-labs/l2-geth/core/sls-common/storage"
)

// Postgres struct provides a Bun database storage mechanism for quarantined transactions.
type Postgres struct {
	commonStorage.Postgres
}

// Ensure Postgres implements the DatabaseStore interface.
var _ commonStorage.DatabaseStore = (*Postgres)(nil)

// NewPostgres initializes and returns a new instance of Postgres storage with an established database connection.
func NewPostgres(db *sql.DB) *Postgres {
	p := commonStorage.NewPostgres(db)
	return &Postgres{
		Postgres: *p,
	}
}

// Add public-facing version does not have write access. This is a placeholder.
func (p *Postgres) Add(ctx context.Context, quarantine *model.Quarantine) error {
	panic("This functionality has been intentionally excluded for this release.")
}

// AddMany public-facing version does not have write access. This is a placeholder.
func (p *Postgres) AddMany(ctx context.Context, quarantines []*model.Quarantine) error {
	panic("This functionality has been intentionally excluded for this release.")
}

// Release public-facing version does not have write access. This is a placeholder.
func (p *Postgres) Release(ctx context.Context, txHash common.Hash, reason string) (bool, error) {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) IsAdmin(ctx context.Context, address common.Address) (bool, error) {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error) {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) LogQuarantineDetectorLog(ctx context.Context, call *model.QuarantineDetectorCalls) error {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) LogBlockQuarantineDetectorLog(ctx context.Context, call *model.BlockQuarantineDetectorCalls) error {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) AddTransactionResult(ctx context.Context, result *model.TransactionResult) error {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) AddTransactionResults(ctx context.Context, results []*model.TransactionResult) error {
	panic("This functionality has been intentionally excluded for this release.")
}

func (p *Postgres) GetReleasedQuarantinesByHashes(ctx context.Context, txHash []common.Hash) (map[common.Hash]*model.Quarantine, error) {
	panic("This functionality has been intentionally excluded for this release.")
}
