package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	_ "github.com/uptrace/bun/driver/pgdriver"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
)

// QuarantineQueryOpts extends pg.QueryOpts with quarantine-specific filtering capabilities
type QuarantineQueryOpts interface {
	pg.QueryOpts
	GetCircuitCapacityFilter() string
}

// DatabaseStore references all the methods that the database storage must implement.
// Avoid using this interface as generally, not all methods are required in most use cases.
// This interfaces should only be used to ensure that both public and private SLS implementations
// are compatible with the same storage interface.
type DatabaseStore interface {
	Ping(ctx context.Context) error
	All(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error)
	Quarantined(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error)
	IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error)
	PendingRelease(ctx context.Context, quarantineTypes []model.QuarantineType) ([]*model.Quarantine, error)
	FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error)
	GetAdminAddresses(ctx context.Context) ([]common.Address, error)
	AdminAddresses(ctx context.Context, opts pg.QueryOpts) ([]*model.Admin, error)
	Add(ctx context.Context, quarantine *model.Quarantine) error
	AddMany(ctx context.Context, quarantines []*model.Quarantine) error
	Release(ctx context.Context, txHash common.Hash, reason string) (bool, error)
	SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error)

	IsQuarantinedAndScanned(ctx context.Context, txHash common.Hash) (*model.TransactionResult, error)
	IsQuarantinedSoftMatch(ctx context.Context, to string, data []byte) (bool, error)
	IsAdmin(ctx context.Context, address common.Address) (bool, error)
	LogQuarantineDetectorLog(ctx context.Context, call *model.QuarantineDetectorCalls) error
	LogBlockQuarantineDetectorLog(ctx context.Context, call *model.BlockQuarantineDetectorCalls) error
	AddTransactionResult(ctx context.Context, result *model.TransactionResult) error
	AddTransactionResults(ctx context.Context, results []*model.TransactionResult) error
	GetReleasedQuarantinesByHashes(ctx context.Context, txHash []common.Hash) (map[common.Hash]*model.Quarantine, error)
}

// Postgres struct provides a Bun database storage mechanism for quarantined transactions.
type Postgres struct {
	DB *bun.DB
}

// NewPostgres initializes and returns a new instance of Postgres storage with an established database connection.
func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{DB: bun.NewDB(db, pgdialect.New())}
}

var ErrTransactionNotFound = errors.New("transaction not found")

// Ping checks the connection to the database.
func (p *Postgres) Ping(ctx context.Context) error {
	return p.DB.PingContext(ctx)
}

// All retrieves a paginated list of all quarantined transactions stored in the database.
func (p *Postgres) All(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error) {
	var quarantines []*model.Quarantine
	query := p.DB.NewSelect().Model(&quarantines)
	if from != nil {
		query = query.Where("from_addr = ?", from.String())
	}

	// Apply circuit capacity filter if the opts supports it
	if qopts, ok := opts.(QuarantineQueryOpts); ok {
		switch qopts.GetCircuitCapacityFilter() {
		case "exclude":
			query = query.Where("quarantined_by != ?", "Circuit Capacity Checker")
		case "only":
			query = query.Where("quarantined_by = ?", "Circuit Capacity Checker")
		}
	}

	data, cursor, err := pg.Paginate[model.Quarantine, model.TimeOrderedQuarantine](ctx, query, opts)
	if err != nil {
		return cursor, nil, stacktrace.Wrap(err)
	}
	return cursor, data, err
}

// Quarantined retrieves all transactions that are currently quarantined and not released from the database.
func (p *Postgres) Quarantined(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error) {
	var quarantines []*model.Quarantine
	query := p.DB.NewSelect().Model(&quarantines)
	query = query.Where("is_released = false")
	if from != nil {
		query = query.Where("from_addr = ?", from.String())
	}

	data, cursor, err := pg.Paginate[model.Quarantine, model.TimeOrderedQuarantine](ctx, query, opts)
	if err != nil {
		return cursor, nil, stacktrace.Wrap(err)
	}
	return cursor, data, err
}

// IsQuarantined checks if a given transaction hash corresponds to a transaction that is currently quarantined in the database.
func (p *Postgres) IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error) {
	query := p.DB.NewSelect().Model((*model.Quarantine)(nil)).
		Column("is_released").
		Where("tx_hash = ?", txHash.String())
	var isReleased bool
	err := query.Scan(ctx, &isReleased)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil // transaction was never in quarantine
	}
	if err != nil {
		return false, err
	}

	return !isReleased, nil
}

func (p *Postgres) IsQuarantinedAndScanned(ctx context.Context, txHash common.Hash) (*model.TransactionResult, error) {
	var result model.TransactionResult

	err := p.DB.NewSelect().
		Model(&result).
		Relation("Quarantine").
		Where("tr.tx_hash = ?", txHash.String()).
		Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTransactionNotFound
	}
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func (p *Postgres) IsQuarantinedSoftMatch(ctx context.Context, to string, data []byte) (bool, error) {
	var foundSoftMatch bool

	foundSoftMatch, err := p.DB.NewSelect().
		Model((*model.Quarantine)(nil)).
		Where("to_addr = ?", to).
		Where("data = ?", data).
		Where("is_released = ?", false).
		Exists(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return foundSoftMatch, nil
}

// PendingRelease retrieves all transactions currently in quarantine that are pending release.
func (p *Postgres) PendingRelease(ctx context.Context, quarantineTypes []model.QuarantineType) ([]*model.Quarantine, error) {
	var quarantines []*model.Quarantine
	// Select quarantines where is_released is false and expires_on is before the current time
	err := p.DB.NewSelect().
		Model(&quarantines).
		Where("is_released = false").
		Where("quarantine_type IN (?)", bun.In(quarantineTypes)).
		Where("expires_on <= ?", time.Now()).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return quarantines, nil
}

func (p *Postgres) FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error) {
	var quarantine model.Quarantine
	query := p.DB.NewSelect().Model(&quarantine)
	query = query.Where("tx_hash = ?", txHash.String())
	err := query.Scan(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrTransactionNotFound
	}
	if err != nil {
		return nil, err
	}

	return &quarantine, nil
}

func (p *Postgres) GetAdminAddresses(ctx context.Context) ([]common.Address, error) {
	var admins []*model.Admin

	err := p.DB.NewSelect().Model(&admins).Scan(ctx)
	if err != nil {
		return nil, err
	}

	addresses := make([]common.Address, 0, len(admins))
	for _, entry := range admins {
		addresses = append(addresses, common.HexToAddress(entry.Address))
	}

	return addresses, nil
}

func (p *Postgres) AdminAddresses(ctx context.Context, opts pg.QueryOpts) ([]*model.Admin, error) {
	var admins []*model.Admin

	query := p.DB.NewSelect().Model(&admins)
	data, _, err := pg.Paginate[model.Admin, model.TimeOrderedAdmin](ctx, query, opts)
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}

	return data, nil
}
