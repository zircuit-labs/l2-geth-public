package sls

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/knadh/koanf"
)

// RefreshableConfigs struct defines refreshable configuration parameters for the SLS.
type RefreshableConfigs struct {
	Enabled bool
}

// RefreshableGetter is a function that returns the latest refreshable sls configs from live‐reloading reader
type RefreshableGetter func() RefreshableConfigs

var DisabledRefreshables RefreshableGetter = func() RefreshableConfigs {
	return DisabledConfig.Refreshable
}

var (
	initOnce sync.Once
	reader   *FileReader
	initErr  error
)

type (
	FileReader struct {
		k            *koanf.Koanf
		cfg          atomic.Value
		pollInterval time.Duration
	}
)

// InitReader will initialize FileReader that keeps polling SLS refreshable configs
func InitReader(filePath string, pollInterval time.Duration) (*FileReader, error) {
	initOnce.Do(func() {
		reader = newSLSConfigReader(pollInterval)
	})
	return reader, nil
}

// Public SLS doesn't support dynamic config updates.
func GetterOrStatic(static RefreshableConfigs) RefreshableGetter {
	return func() RefreshableConfigs {
		return static
	}
}

// Reader returns the singleton.
func Reader() *FileReader {
	return reader
}

// Config returns a copy of the latest Config (lock-free).
func (r *FileReader) Config() Config {
	return *r.cfg.Load().(*Config)
}

// Refreshables returns a copy of the latest refreshable configs (lock-free).
func (r *FileReader) Refreshables() RefreshableConfigs {
	return r.Config().Refreshable
}

// NewReader constructs the FileReader and seeds it with an empty Config.
func newSLSConfigReader(pollInterval time.Duration) *FileReader {
	r := &FileReader{
		k:            koanf.New("."),
		pollInterval: pollInterval,
	}
	r.cfg.Store(&Config{})
	return r
}

func BlockLevelScanningEnabled(getter RefreshableGetter) bool {
	return false
}

func GetReAddBatchSize(getter RefreshableGetter) int {
	return 1
}

func GetEnableStray(getter RefreshableGetter) bool {
	return false
}
