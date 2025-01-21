package sls

import (
	"github.com/zircuit-labs/l2-geth-public/core/sls/duration"
	"github.com/zircuit-labs/zkr-go-common/stores/s3"
)

// Config struct defines configuration parameters for the SLS.
// It includes settings for integrity list, the releaser identity,
// intervals for execution and quarantine durations, and the data source name (DSN) for database connection.
type (
	Config struct {
		Enabled                      bool               // Feature flag to enable/disable SLS - disabled by default.
		EnableZircAPI                bool               // Enable Zirc API - disabled by default.
		EnableZircAdminAPI           bool               // Enable Zirc Admin API - disabled by default.
		ZircAdminAPISignatureExpiry  duration.Duration  // Expiry duration for Zirc Admin API authentication for signature verification.
		AlwaysAllowEmptyTransaction  bool               // If true, empty transaction will always be accepted.
		ExecutorInterval             duration.Duration  // Frequency at which the executor should run.
		QuarantineDuration           duration.Duration  // Duration for which transactions remain in quarantine before being re-evaluated or released.
		IntegrityDBSyncInterval      duration.Duration  // Sync interval for the integrity detector.
		DSN                          string             // Data Source Name for database connections, specifying the address and credentials for DB.
		MaxConcurrencyPool           int                // Maximum number of concurrent sls workers allowed globally across all promotion cycles.
		MaxWorkersPerCycle           int                // Maximum number of sls workers that can be spawned per promotion cycle.
		AssumeInnocenceOnError       bool               // If SLS encounters an error it'll allow the transaction to proceed.
		PromotablesCollectionTimeout duration.Duration  // Duration to wait for SLS to process before collecting and promoting transactions.
		AWS                          s3.BlobStoreConfig // AWS configurations.
	}
)

var (
	// DisabledConfig is the disabled configuration for the SLS.
	DisabledConfig = Config{Enabled: false, EnableZircAPI: false, EnableZircAdminAPI: false}
)
