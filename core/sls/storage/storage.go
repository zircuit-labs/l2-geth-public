package storage

import (
	"context"
	"database/sql"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"

	_ "github.com/lib/pq"
)

// Storage interface defines the required operations for a storage backend managing quarantined transactions.
type Storage interface {
	All(ctx context.Context, offset, limit int, from *common.Address) ([]*model.Quarantine, int, error)
	Add(ctx context.Context, quarantine *model.Quarantine) error
	Quarantined(ctx context.Context, from *common.Address) ([]*model.Quarantine, int, error)
	PendingRelease(ctx context.Context, quarantineType model.QuarantineType) ([]*model.Quarantine, error)
	Release(ctx context.Context, txHash common.Hash, reason string) (bool, error)
	SetExpiresOn(ctx context.Context, txHash common.Hash, expiresOn time.Time, releaser common.Address) (bool, error)
	IsQuarantined(ctx context.Context, txHash common.Hash) (bool, error)
	FindByHash(ctx context.Context, txHash common.Hash) (*model.Quarantine, error)
	Ping(ctx context.Context) error

	LogQuarantineDetectorLog(ctx context.Context, call *model.QuarantineDetectorCalls) error
	IsQuarantinedAndScanned(ctx context.Context, txHash common.Hash) (*model.TransactionResult, error)
	AddTransactionResult(ctx context.Context, result *model.TransactionResult) error

	// IntegrityDetectorList related api calls
	AddIntegrityListAddresses(ctx context.Context, addresses []common.Address) error
	RemoveIntegrityListAddresses(ctx context.Context, addresses []common.Address) error
	GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error)
	GetAdminAddresses(ctx context.Context) ([]common.Address, error)
	IsAdmin(ctx context.Context, address common.Address) (bool, error)
	AddressesInIntegrityList(ctx context.Context, addresses []common.Address) ([]common.Address, error)

	// TrustList related api calls
	AddressInTrustList(ctx context.Context, address common.Address) (bool, error)
	AddTrustListAddresses(ctx context.Context, addresses []common.Address) error
	RemoveTrustListAddresses(ctx context.Context, addresses []common.Address) error
	GetTrustListAddresses(ctx context.Context) ([]common.Address, error)
	AddressesInTrustList(ctx context.Context, addresses []common.Address) ([]common.Address, error)
}

// NewStorage initializes a storage backend based on the provided Config.
// If DSN is empty, it uses an in-memory storage; otherwise, it attempts to connect to a Postgres database.
func NewStorage(ctx context.Context, config Config) (Storage, error) {
	if config.DSN == "" {
		return NewMemory(), nil // Use in-memory storage if no DSN is provided.
	}

	db, err := sql.Open("postgres", config.DSN)
	if err != nil {
		return nil, err
	}

	store := NewPostgres(db)      // Initialize Postgres storage with the open database connection.
	return store, store.Ping(ctx) // Return the store and ping the database to check for connectivity.
}
