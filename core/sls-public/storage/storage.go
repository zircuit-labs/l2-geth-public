package storage

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq"

	commonStorage "github.com/zircuit-labs/l2-geth/core/sls-common/storage"
)

// NewStorage initializes a new Postgres storage instance using the provided configuration.
// It establishes a database connection and verifies connectivity by pinging the database.
func NewStorage(ctx context.Context, config commonStorage.Config) (commonStorage.DatabaseStore, error) {
	if config.GetDSN() == "" {
		return nil, commonStorage.ErrNoDSN
	}

	db, err := sql.Open("postgres", config.GetDSN())
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(config.GetDBMaxOpenConns())
	db.SetMaxIdleConns(config.GetDBMaxIdleConns())

	store := NewPostgres(db)
	return store, store.Ping(ctx) // Return the store and ping the database to check for connectivity.
}
