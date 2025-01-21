// Package storage provides the storage layer for the SLS service.
package storage

// Config struct defines configuration parameters for the SLS storage.
type Config struct {
	DSN string // Data Source Name for database connections, specifying the address and credentials for DB.
}
