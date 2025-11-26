package sls

import (
	"time"

	"github.com/zircuit-labs/l2-geth/core/sls-common/duration"
	"github.com/zircuit-labs/zkr-go-common/stores/s3"
)

const (
	DefaultDetectorStatusRefreshInterval = time.Second
)

// Config struct defines configuration parameters for the SLS.
type Config struct {
	Refreshable                   RefreshableConfigs `toml:"Refreshable"`
	RefreshableInterval           duration.Duration
	EnableZircAPI                 bool               // Enable Zirc API - disabled by default.
	DSN                           string             // Data Source Name for database connections, specifying the address and credentials for DB.
	SLSDataSyncS3                 s3.BlobStoreConfig // AWS configurations for SLS Stray.
	EnableSLSDataSync             bool               // Enable SLS data synchronization.
	PondPoolMaxConcurrency        int                // Max concurrency for pond pool
	DetectorStatusRefreshInterval duration.Duration  // Interval to refresh detector status
}

// DisabledConfig is the disabled configuration for the SLS.
var DisabledConfig = Config{Refreshable: RefreshableConfigs{}}

func (c Config) DepositTxTimeout() time.Duration {
	return time.Second
}

// Public SLS is always disabled.
func (c Config) IsEnabled() bool {
	return false
}

func (c Config) GetDSN() string {
	return c.DSN
}

func (c Config) GetDBMaxOpenConns() int {
	return 100
}

func (c Config) GetDBMaxIdleConns() int {
	return 10
}

func (c Config) MaxConcurrency() int {
	return 1
}
