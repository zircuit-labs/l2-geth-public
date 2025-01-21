package storage

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	_ "github.com/uptrace/bun/driver/pgdriver"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
)

type (
	// Postgres struct provides a Bun database storage mechanism for quarantined transactions.
	Postgres struct {
		db *bun.DB
	}
)

var (
	ErrTransactionNotFound = errors.New("transaction not found")
)

// NewPostgres initializes and returns a new instance of Postgres storage with an established database connection.
func NewPostgres(db *sql.DB) *Postgres {
	return &Postgres{db: bun.NewDB(db, pgdialect.New())}
}

// Add inserts a new quarantined transaction into the database.
func (p *Postgres) Add(ctx context.Context, quarantine *model.Quarantine) error {
	_, err := p.db.NewInsert().Model(quarantine).On("CONFLICT (tx_hash) DO UPDATE").Set("tx_data = EXCLUDED.tx_data").Exec(ctx)
	return err
}

// All retrieves a paginated list of all quarantined transactions stored in the database.
func (p *Postgres) All(ctx context.Context, offset, limit int, from *common.Address) ([]*model.Quarantine, int, error) {
	var quarantines []*model.Quarantine
	query := p.db.NewSelect().Model(&quarantines)

	if from != nil {
		query = query.Where("from_addr = ?", from.String())
	}

	query = query.Order("quarantined_at DESC")
	query = query.Offset(offset)
	query = query.Limit(limit)

	count, err := query.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, err
	}

	return quarantines, count, nil
}

// Quarantined retrieves all transactions that are currently quarantined and not released from the database.
func (p *Postgres) Quarantined(ctx context.Context, from *common.Address) ([]*model.Quarantine, int, error) {
	var quarantines []*model.Quarantine
	query := p.db.NewSelect().Model(&quarantines)
	query = query.Where("is_released = false").Order("quarantined_at DESC")

	if from != nil {
		query = query.Where("from_addr = ?", from.String())
	}

	count, err := query.ScanAndCount(ctx)
	if err != nil {
		return nil, 0, err
	}

	return quarantines, count, nil
}

// Release marks a quarantined transaction as released in the database.
func (p *Postgres) Release(ctx context.Context, txHash common.Hash, reason string) (bool, error) {
	query := p.db.NewUpdate().Model((*model.Quarantine)(nil)).
		Set("is_released = true").
		Set("released_reason = ?", reason).
		Set("released_at = NOW()").
		Where("tx_hash = ? AND is_released = false", txHash.String())
	result, err := query.Exec(ctx)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}

// SetExpiresOn updates the expiration time of a quarantined transaction in the database.
func (p *Postgres) SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error) {
	query := p.db.NewUpdate().Model((*model.Quarantine)(nil)).
		Set("expires_on = ?", expiresOn).
		Set("released_by = ?", releaser.String()).
		Where("tx_hash = ?", txHash.String())
	result, err := query.Exec(ctx)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return rowsAffected > 0, nil
}

// IsQuarantined checks if a given transaction hash corresponds to a transaction that is currently quarantined in the database.
func (p *Postgres) IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error) {
	query := p.db.NewSelect().Model((*model.Quarantine)(nil)).
		Column("is_released").
		Where("tx_hash = ?", txHash.String())
	var isReleased bool
	err := query.Scan(ctx, &isReleased)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil //transaction was never in quarantine
	}
	if err != nil {
		return false, err
	}

	return !isReleased, nil
}

// LogQuarantineDetectorLog adds a new quarantine log to the database.
func (p *Postgres) LogQuarantineDetectorLog(ctx context.Context, call *model.QuarantineDetectorCalls) error {
	_, err := p.db.NewInsert().Model(call).Exec(ctx)
	return err
}

// PendingRelease retrieves all transactions currently in quarantine that are pending release.
func (p *Postgres) PendingRelease(ctx context.Context, quarantineType model.QuarantineType) ([]*model.Quarantine, error) {
	var quarantines []*model.Quarantine
	// Select quarantines where is_released is false and expires_on is before the current time
	err := p.db.NewSelect().
		Model(&quarantines).
		Where("is_released = false").
		Where("quarantine_type = ?", quarantineType).
		Where("expires_on <= ?", time.Now()).
		Scan(ctx)
	if err != nil {
		return nil, err
	}

	return quarantines, nil
}

func (p *Postgres) FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error) {
	var quarantine model.Quarantine
	query := p.db.NewSelect().Model(&quarantine)
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

// Ping checks the connection to the database.
func (p *Postgres) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *Postgres) AddIntegrityListAddresses(ctx context.Context, addresses []common.Address) error {
	if len(addresses) == 0 {
		return nil
	}
	entries := entriesFromAddresses(addresses)
	_, err := p.db.NewInsert().Model(&entries).Exec(ctx)
	return err
}

func (p *Postgres) RemoveIntegrityListAddresses(ctx context.Context, addresses []common.Address) error {
	if len(addresses) == 0 {
		return nil
	}
	entries := entriesFromAddresses(addresses)
	_, err := p.db.NewDelete().Model(&entries).WherePK().Exec(ctx)
	return err
}

func (p *Postgres) GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error) {
	var entries []*model.IntegrityListEntry

	err := p.db.NewSelect().Model(&entries).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return addressesFromEntries(entries), nil
}

func (p *Postgres) AddressesInIntegrityList(ctx context.Context, addresses []common.Address) ([]common.Address, error) {
	if len(addresses) == 0 {
		return nil, nil
	}

	var foundEntries []*model.IntegrityListEntry
	entries := entriesFromAddresses(addresses)
	err := p.db.NewSelect().
		Model(&entries).
		Column("address").
		WherePK().
		Scan(ctx, &foundEntries)

	if err != nil {
		return nil, err
	}

	return addressesFromEntries(foundEntries), nil
}

func (p *Postgres) GetAdminAddresses(ctx context.Context) ([]common.Address, error) {
	var admins []*model.Admin

	err := p.db.NewSelect().Model(&admins).Scan(ctx)
	if err != nil {
		return nil, err
	}

	addresses := make([]common.Address, 0, len(admins))
	for _, entry := range admins {
		addresses = append(addresses, common.HexToAddress(entry.Address))
	}

	return addresses, nil
}

// AddTransactionResult adds a new transaction result to the database.
func (p *Postgres) AddTransactionResult(ctx context.Context, result *model.TransactionResult) error {
	_, err := p.db.NewInsert().
		Model(result).
		On("CONFLICT (tx_hash) DO UPDATE").
		Set("quarantined = EXCLUDED.quarantined").
		Exec(ctx)
	return err
}

func (p *Postgres) IsQuarantinedAndScanned(ctx context.Context, txHash common.Hash) (*model.TransactionResult, error) {
	var result model.TransactionResult

	err := p.db.NewSelect().
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

func (p *Postgres) IsAdmin(ctx context.Context, address common.Address) (bool, error) {
	admin := new(model.Admin)
	err := p.db.NewSelect().Model(admin).Where("address = ?", address.String()).Scan(ctx)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return false, nil
	case err != nil:
		return false, err
	}

	return true, nil
}

// AddressInTrustList checks if a given address is trusted in the database.
func (p *Postgres) AddressInTrustList(ctx context.Context, address common.Address) (bool, error) {
	addresses, err := p.AddressesInTrustList(ctx, []common.Address{address})
	if err != nil {
		return false, err
	}
	return len(addresses) > 0, nil
}

// AddressesInTrustList checks if addresses are trusted in the database.
func (p *Postgres) AddressesInTrustList(ctx context.Context, addresses []common.Address) ([]common.Address, error) {
	if len(addresses) == 0 {
		return nil, nil
	}

	var foundEntries []*model.TrustListEntry
	entries := trustListEntriesFromAddresses(addresses)
	err := p.db.NewSelect().
		Model(&entries).
		Column("address").
		WherePK().
		Scan(ctx, &foundEntries)

	if err != nil {
		return nil, err
	}

	return addressesFromTrustListEntries(foundEntries), nil
}

// AddTrustListAddresses adds a new trusted address to the database.
func (p *Postgres) AddTrustListAddresses(ctx context.Context, addresses []common.Address) error {
	if len(addresses) == 0 {
		return nil
	}
	entries := trustListEntriesFromAddresses(addresses)
	_, err := p.db.NewInsert().Model(&entries).Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// RemoveTrustListAddresses removes a trusted address from the database.
func (p *Postgres) RemoveTrustListAddresses(ctx context.Context, addresses []common.Address) error {
	if len(addresses) == 0 {
		return nil
	}
	entries := trustListEntriesFromAddresses(addresses)
	_, err := p.db.NewDelete().Model(&entries).WherePK().Exec(ctx)
	if err != nil {
		return err
	}
	return nil
}

// GetTrustListAddresses retrieves all trusted addresses from the database.
func (p *Postgres) GetTrustListAddresses(ctx context.Context) ([]common.Address, error) {
	var entries []*model.TrustListEntry
	err := p.db.NewSelect().Model(&entries).Scan(ctx)
	if err != nil {
		return nil, err
	}
	return addressesFromTrustListEntries(entries), nil
}
