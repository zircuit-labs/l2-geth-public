// Package storage provides the storage layer for the SLS service.
package storage

type Config interface {
	// GetDSN returns the Data Source Name (DSN) for the database connection.
	GetDSN() string
	GetDBMaxOpenConns() int
	GetDBMaxIdleConns() int
}
