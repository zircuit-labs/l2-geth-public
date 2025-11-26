package slsstray

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	common "github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/sls-common/slsapi"
	pg "github.com/zircuit-labs/zkr-go-common/stores/pg"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

const (
	defaultSnapshotPath = "/tmp/sls/snapshot"

	SnapshotFilename LocalStorageFileName = "snapshot"
)

var (
	ErrNoSnapshotFound         = errors.New("no snapshot found")
	ErrCannotStoreNilSnapshot  = errors.New("cannot store nil snapshot")
	ErrMissingSnapshotInFolder = errors.New("snapshot folder does not contain snapshot")
	ErrNoStorage               = errors.New("cannot initialize snapshot generator with nil storage")
)

//go:generate go tool mockgen -source snapshot_generator.go -destination mock_sls_store.go -package slsstray
type slsStore interface {
	AdminAddresses(ctx context.Context, opts pg.QueryOpts) ([]*model.Admin, error)
	Quarantined(ctx context.Context, opts pg.QueryOpts, from *common.Address) (pg.Cursor, []*model.Quarantine, error)
}

type Snapshot struct {
	Timestamp  time.Time           `json:"timestamp"`
	Admin      []*model.Admin      `json:"admin"`
	Quarantine []*model.Quarantine `json:"quarantine"`
}

type SnapshotConfig struct {
	storagePath string
}

type SnapshotGenerator struct {
	mu      *sync.RWMutex
	store   slsStore
	config  *SnapshotConfig
	gzipper *GZipper
}

func NewSnapshotGenerator(store slsStore) (*SnapshotGenerator, error) {
	if store == nil {
		return nil, stacktrace.Wrap(ErrNoStorage)
	}
	config := &SnapshotConfig{storagePath: defaultSnapshotPath}
	return &SnapshotGenerator{config: config, store: store, mu: new(sync.RWMutex), gzipper: NewGZipper()}, nil
}

func (sg *SnapshotGenerator) SetConfig(config *SnapshotConfig) {
	sg.mu.Lock()
	defer sg.mu.Unlock()
	if config == nil {
		config = &SnapshotConfig{storagePath: defaultSnapshotPath}
	}
	sg.config = config	
}

// TakeNewSnapshot gets and stores new snapshot
func (sg *SnapshotGenerator) TakeNewSnapshot(ctx context.Context) error {
	s, err := sg.GetSnapshot(ctx)
	if err != nil {
		return stacktrace.Wrap(err)
	}
	_, err = sg.StoreSnapshot(s)
	if err != nil {
		return stacktrace.Wrap(err)
	}
	return nil
}

// GetSnapshot fetches the admin and quarantine state from the sls database
func (sg *SnapshotGenerator) GetSnapshot(ctx context.Context) (*Snapshot, error) {
	sg.mu.RLock()
	defer sg.mu.RUnlock()

	snapshot := &Snapshot{Timestamp: time.Now().UTC()}

	// get all sls admins
	admins, err := sg.store.AdminAddresses(ctx, slsapi.DefaultQueryOpts)
	if err != nil {
		return snapshot, stacktrace.Wrap(err)
	}
	snapshot.Admin = admins

	// get all sls quarantine txs
	_, quarantined, err := sg.store.Quarantined(ctx, slsapi.DefaultQueryOpts, nil)
	if err != nil {
		return snapshot, stacktrace.Wrap(err)
	}
	snapshot.Quarantine = quarantined

	return snapshot, nil
}

// StoreSnapshot stores a sls snapshot as a gzipped json file
func (sg *SnapshotGenerator) StoreSnapshot(snapshot *Snapshot) (string, error) {
	if snapshot == nil {
		return "", stacktrace.Wrap(ErrCannotStoreNilSnapshot)
	}
	return sg.gzipper.StoreGzipJson(snapshot, sg.config.storagePath, SnapshotFilename, snapshot.Timestamp)
}

// getLatestSnapshot returns the latest snapshot available and throws an error if no snapshot was found
func getLatestSnapshot(gzipper *GZipper, folderPath string) (*Snapshot, *SnapshotInfo, error) {
	entries, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, nil, ErrNoSnapshotFound
	}
	if len(entries) == 0 {
		return nil, nil, ErrNoSnapshotFound
	}

	// latest folder
	latestFolderPath := filepath.Join(folderPath, entries[len(entries)-1].Name())
	file, err := os.ReadDir(latestFolderPath)
	if err != nil {
		return nil, nil, stacktrace.Wrap(err)
	}
	if len(file) == 0 {
		return nil, nil, stacktrace.Wrap(ErrMissingSnapshotInFolder)
	}

	var snapshot Snapshot
	var snapshotMeta SnapshotInfo
	if len(file) > 0 {

		path := filepath.Join(latestFolderPath, file[0].Name())
		snapshotUncompressed, err := gzipper.OpenGzipJson(path)
		if err != nil {
			return nil, nil, stacktrace.Wrap(err)
		}
		if err := json.Unmarshal(snapshotUncompressed, &snapshot); err != nil {
			return nil, nil, stacktrace.Wrap(err)
		}

		snapshotMeta = SnapshotInfo{
			Path:      path,
			Timestamp: snapshot.Timestamp.Unix(),
		}
	}
	return &snapshot, &snapshotMeta, nil
}
