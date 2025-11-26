package slsstray

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/sqliteshim"
	model "github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

const (
	// Metadata file key in S3
	MetadataKey    = "metadata.json.gz"
	MetadataBucket = "metadata"
	DiffBucket     = "diffs"
	SnapshotBucket = "snapshots"

	// SQLite database path
	DefaultDBPath = "database/sls_data.db"
)

// MetadataFile represents the structure of the metadata JSON
type MetadataFile struct {
	LatestSnapshot SnapshotInfo `json:"latestSnapshot"`
	Diffs          []DiffInfo   `json:"diffs"`
}

type DiffInfo struct {
	Path       string `json:"path"`
	Timestamp  int64  `json:"timestamp"`
	MerkleRoot string `json:"merkleRoot"`
}

// SnapshotInfo contains information about a snapshot
type SnapshotInfo struct {
	Path       string `json:"path"`
	Timestamp  int64  `json:"timestamp"`
	MerkleRoot string `json:"merkleRoot"`
}

type SLSDataSyncer struct {
	s3Client s3Store
	db       *bun.DB
	dbPath   string
	mu       *sync.RWMutex
}

// SnapshotSync tracks sync history
type SnapshotSync struct {
	bun.BaseModel `bun:"table:snapshot_sync,alias:ss"`

	ID                int64     `bun:"id,pk,autoincrement"`
	SnapshotTimestamp time.Time `bun:"snapshot_timestamp,notnull"`
	SyncedAt          time.Time `bun:"synced_at,nullzero,notnull,default:current_timestamp"`
	AdminCount        int       `bun:"admin_count"`
	QuarantineCount   int       `bun:"quarantine_count"`
	MerkleRoot        string    `bun:"merkle_root"`
}

// s3Store defines the interface for S3 operations
// method signatures from BlobStore struct zkr-go-common/blob/main/stores/s3/blobstore.go

//go:generate go tool mockgen -source slsdata_syncer.go -destination s3_store_mock.go -package slsstray
type s3Store interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Upload(ctx context.Context, key string, data []byte) error
	Exists(ctx context.Context, key string) error
	GetAllList(ctx context.Context) ([]string, error)
	Delete(ctx context.Context, key string) error
	SetBucket(bucket string)
	GetBucket() string
}

// NewSLSDataSyncer constructs a new syncer with the given S3 client and DB path.
func NewSLSDataSyncer(s3Client s3Store, dbPath string) *SLSDataSyncer {
	if dbPath == "" {
		dbPath = DefaultDBPath
	}
	return &SLSDataSyncer{s3Client: s3Client, dbPath: dbPath, mu: new(sync.RWMutex)}
}

// SyncSLSData initializes the SQLite database and restores the latest snapshot from S3.
func (s *SLSDataSyncer) SyncSLSData(ctx context.Context) error {
	if s.s3Client == nil {
		return fmt.Errorf("s3 client is nil")
	}

	// Initialize SQLite database
	if err := s.initSQLite(ctx); err != nil {
		return fmt.Errorf("failed to initialize SQLite: %w", err)
	}

	// Download and restore the latest snapshot to local sqlite database
	if err := s.restoreLatestSnapshot(ctx); err != nil {
		return fmt.Errorf("failed to download and restore snapshot: %w", err)
	}

	return nil
}

// GetLatestMetadata downloads and decompresses the metadata file from S3.
func (s *SLSDataSyncer) GetLatestMetadata(ctx context.Context) (*MetadataFile, error) {
	meta, err := fetchGzipJSON[MetadataFile](ctx, s.s3Client, MetadataKey, "metadata")
	if err != nil {
		return nil, err
	}
	if meta.LatestSnapshot.Path == "" {
		return nil, fmt.Errorf("metadata missing latestSnapshot.path")
	}
	return meta, nil
}

// restoreLatestSnapshot fetches metadata, downloads the referenced snapshot, and stores it in SQLite.
func (s *SLSDataSyncer) restoreLatestSnapshot(ctx context.Context) error {
	metadata, err := s.GetLatestMetadata(ctx)
	if err != nil {
		return err
	}

	snapShot, err := fetchGzipJSON[Snapshot](ctx, s.s3Client, metadata.LatestSnapshot.Path, "snapshot")
	if err != nil {
		return fmt.Errorf("failed to fetch snapshot data from s3: %w", err)
	}

	// Store the data in SQLite
	if err := s.storeSnapshotData(ctx, snapShot, metadata.LatestSnapshot.MerkleRoot); err != nil {
		return fmt.Errorf("failed to store snapshot data: %w", err)
	}
	log.Info("Successfully synced snapshot", "path", metadata.LatestSnapshot.Path, "timestamp", snapShot.Timestamp, "admins", len(snapShot.Admin), "quarantines", len(snapShot.Quarantine))

	return nil
}

// initSQLite opens/creates the SQLite database and ensures the required schema exists.
func (s *SLSDataSyncer) initSQLite(ctx context.Context) error {
	// Make sure the directory exists before opening SQLite
	if err := os.MkdirAll(filepath.Dir(s.dbPath), 0o755); err != nil {
		return fmt.Errorf("failed to create SLS DB directory: %v", err)
	}

	sqldb, err := sql.Open(sqliteshim.ShimName, s.dbPath)
	if err != nil {
		return fmt.Errorf("failed to open SQLite database: %w", err)
	}
	s.db = bun.NewDB(sqldb, sqlitedialect.New())

	if err := s.createTables(ctx); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	return nil
}

// createTables creates the admin, quarantine, and snapshot_sync tables (and their indexes) if they don't exist.
func (s *SLSDataSyncer) createTables(ctx context.Context) error {
	adminModel := (*model.Admin)(nil)
	quarantineModel := (*model.Quarantine)(nil)

	// Create admin table without schema
	if _, err := s.db.NewCreateTable().
		Model(adminModel).
		ModelTableExpr("admin"). // Override table name for SQLite
		IfNotExists().
		Exec(ctx); err != nil {
		return fmt.Errorf("failed to create admin table: %w", err)
	}

	// Create quarantine table without schema
	if _, err := s.db.NewCreateTable().
		Model(quarantineModel).
		ModelTableExpr("quarantine"). // Override table name for SQLite
		IfNotExists().
		Exec(ctx); err != nil {
		return fmt.Errorf("failed to create quarantine table: %w", err)
	}

	if _, err := s.db.NewCreateTable().
		Model((*SnapshotSync)(nil)).
		IfNotExists().
		Exec(ctx); err != nil {
		return fmt.Errorf("failed to create quarantine table: %w", err)
	}

	indexes := []struct {
		table  string
		column string
	}{
		{"quarantine", "tx_hash"},
		{"admin", "address"},
	}

	for _, idx := range indexes {
		if _, err := s.db.NewCreateIndex().
			Table(idx.table).
			IfNotExists().
			Index(fmt.Sprintf("idx_%s_%s", idx.table, idx.column)).
			Column(idx.column).
			Exec(ctx); err != nil {
			return fmt.Errorf("failed to create index on %s.%s: %w", idx.table, idx.column, err)
		}
	}

	return nil
}

// storeSnapshotData inserts the snapshot’s quarantine/admin rows and records a SnapshotSync entry.
func (s *SLSDataSyncer) storeSnapshotData(ctx context.Context, snapshot *Snapshot, merkleRoot string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if len(snapshot.Quarantine) > 0 {
		// Override table name for SQLite
		if _, err := tx.NewInsert().Model(&snapshot.Quarantine).ModelTableExpr("quarantine").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert: %w", err)
		}
	}

	if len(snapshot.Admin) > 0 {
		// Override table name for SQLite
		if _, err := tx.NewInsert().Model(&snapshot.Admin).ModelTableExpr("admin").Exec(ctx); err != nil {
			return fmt.Errorf("failed to insert: %w", err)
		}
	}

	// Record the sync
	syncRecord := &SnapshotSync{
		SnapshotTimestamp: snapshot.Timestamp,
		AdminCount:        len(snapshot.Admin),
		QuarantineCount:   len(snapshot.Quarantine),
		MerkleRoot:        merkleRoot,
	}

	if _, err := tx.NewInsert().Model(syncRecord).Exec(ctx); err != nil {
		return fmt.Errorf("failed to record sync: %w", err)
	}

	// Commit the transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}

func (s *SLSDataSyncer) closeDB() {
	if s.db != nil {
		s.db.Close()
	}
}

// fetchGzipJSON downloads a gzipped JSON object from S3, decompresses it, and unmarshals into T.
func fetchGzipJSON[T any](ctx context.Context, s3 s3Store, key, itemName string) (*T, error) {
	b, err := s3.Get(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("failed to download %s from S3: %w", itemName, err)
	}

	gr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gr.Close()
	raw, err := io.ReadAll(gr)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s gzip stream: %w", itemName, err)
	}

	var out T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("failed to decode %s JSON: %w", itemName, err)
	}
	return &out, nil
}

// uploadGzipJSON uploads a compressed go struct to S3.
func uploadGzipJSON[T any](ctx context.Context, logger log.Logger, s3 s3Store, gostruct *T, key string) error {
	compressed, err := structToGzipJSON(gostruct)
	if err != nil {
		logger.Error("Cannot compress go struct", "key", key, "err", err)
		return stacktrace.Wrap(err)
	}
	err = s3.Upload(ctx, key, compressed)
	if err != nil {
		logger.Error("Cannot upload stray object to S3", "key", key, "err", err)
	}
	return stacktrace.Wrap(err)
}

// structToGzipJSON marshals the struct T into JSON and compresses the JSON as gzip.
func structToGzipJSON[T any](gostruct *T) ([]byte, error) {
	// marshal struct into JSON
	jsonBytes, err := json.MarshalIndent(gostruct, "", "  ")
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}

	// buffer to hold compressed data
	var buf bytes.Buffer

	// gzip writer around that buffer
	gz := gzip.NewWriter(&buf)

	// write JSON into the gzip writer
	if _, err := gz.Write(jsonBytes); err != nil {
		gz.Close()
		return nil, stacktrace.Wrap(err)
	}

	// close gzip writer to flush remaining data
	if err := gz.Close(); err != nil {
		return nil, stacktrace.Wrap(err)
	}

	// return compressed bytes
	return buf.Bytes(), nil
}
