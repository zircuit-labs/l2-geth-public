package slsstray

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/log"
	gomock "go.uber.org/mock/gomock"
)

// Test helpers
type testHelper struct {
	metadata           *MetadataFile
	compressedMetadata []byte
	snapshot           *Snapshot
	compressedSnapshot []byte
}

// setupTestData creates all test data at once
func setupTestData(t *testing.T) *testHelper {
	th := &testHelper{}

	// Create metadata
	th.metadata = &MetadataFile{
		LatestSnapshot: SnapshotInfo{
			Path:       "snapshots/test-snapshot.json.gz",
			Timestamp:  1719470440,
			MerkleRoot: "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5",
		},
	}

	jsonData, err := json.Marshal(th.metadata)
	require.NoError(t, err)

	th.compressedMetadata, err = gzipCompress(jsonData)
	require.NoError(t, err)

	// Create snapshot
	expiresOn := time.Unix(0, 0)
	th.snapshot = &Snapshot{
		Timestamp: time.Now(),
		Admin: []*model.Admin{
			{Address: "0xbdA0CF32C6d22d3bC0F1E42abeC21e40519CfE32"},
			{Address: "0xe9F2476d1DD71FF0F6E308c076aF99bd20cb8670"},
		},
		Quarantine: []*model.Quarantine{
			{
				TxHash:            "0x1c948c35e781f552f2f48008912555d8451e257b454bd81a7a7d1b224b5285dc",
				QuarantinedAt:     time.Unix(1719470440, 0),
				ReleasedAt:        time.Unix(1719470555, 0),
				ExpiresOn:         &expiresOn,
				ReleasedReason:    "Admin release",
				QuarantinedBy:     "detector",
				QuarantinedReason: "reason",
				ReleasedBy:        "0x4838B106FCe9647Bdf1E7877BF73cE8B0BAD5f97",
			},
			{
				TxHash:            "0x74897e278b84cf5f19f3e09f6dd882f5158f98f988a72a2add4054c05bdd9887",
				QuarantinedAt:     time.Unix(1719470111, 0),
				ReleasedAt:        time.Time{},
				ExpiresOn:         &expiresOn,
				ReleasedReason:    "",
				QuarantinedBy:     "detector",
				QuarantinedReason: "reason",
				ReleasedBy:        "",
			},
		},
	}

	snapshotJSON, err := json.Marshal(th.snapshot)
	require.NoError(t, err)

	th.compressedSnapshot, err = gzipCompress(snapshotJSON)
	require.NoError(t, err)

	return th
}

// gzipCompress compresses data with gzip
func gzipCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// setupMockS3 configures mock S3 expectations for successful flow
func setupMockS3Success(mockS3 *Mocks3Store, th *testHelper) {
	ctx := context.Background()
	mockS3.EXPECT().Get(ctx, MetadataKey).Return(th.compressedMetadata, nil)
	mockS3.EXPECT().Get(ctx, "snapshots/test-snapshot.json.gz").Return(th.compressedSnapshot, nil)
}

// createTestSyncer creates a syncer with temp database
func createTestSyncer(t *testing.T, mockS3 s3Store) (*SLSDataSyncer, string) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	return NewSLSDataSyncer(mockS3, dbPath), dbPath
}

func TestNewSLSDataSyncer(t *testing.T) {
	tests := []struct {
		name           string
		s3Client       s3Store
		dbPath         string
		expectedDBPath string
	}{
		{
			name:           "with custom db path",
			s3Client:       new(Mocks3Store),
			dbPath:         "custom.db",
			expectedDBPath: "custom.db",
		},
		{
			name:           "with empty db path uses default",
			s3Client:       new(Mocks3Store),
			dbPath:         "",
			expectedDBPath: DefaultDBPath,
		},
		{
			name:           "with nil client",
			s3Client:       nil,
			dbPath:         "test.db",
			expectedDBPath: "test.db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			syncer := NewSLSDataSyncer(tt.s3Client, tt.dbPath)
			assert.NotNil(t, syncer)
			assert.Equal(t, tt.s3Client, syncer.s3Client)
			assert.Equal(t, tt.expectedDBPath, syncer.dbPath)
		})
	}
}

func TestSyncSLSDataErrors(t *testing.T) {
	tests := []struct {
		name          string
		setupMock     func(*Mocks3Store, *testHelper)
		useNilClient  bool
		expectedError string
	}{
		{
			name:          "nil s3 client",
			useNilClient:  true,
			expectedError: "s3 client is nil",
		},
		{
			name: "metadata download error",
			setupMock: func(m *Mocks3Store, th *testHelper) {
				ctx := context.Background()
				m.EXPECT().Get(ctx, MetadataKey).Return(nil, fmt.Errorf("s3 error"))
			},
			expectedError: "failed to download metadata from S3",
		},
		{
			name: "snapshot download error",
			setupMock: func(m *Mocks3Store, th *testHelper) {
				ctx := context.Background()
				m.EXPECT().Get(ctx, MetadataKey).Return(th.compressedMetadata, nil)
				m.EXPECT().Get(ctx, "snapshots/test-snapshot.json.gz").Return(nil, fmt.Errorf("snapshot not found"))
			},
			expectedError: "failed to fetch snapshot data from s3",
		},
		{
			name: "missing snapshot path in metadata",
			setupMock: func(m *Mocks3Store, th *testHelper) {
				// Create metadata without path
				emptyMetadata := &MetadataFile{
					LatestSnapshot: SnapshotInfo{
						Timestamp:  1719470440,
						MerkleRoot: "0x123",
						Path:       "", // Empty path
					},
				}
				jsonData, _ := json.Marshal(emptyMetadata)
				compressed, _ := gzipCompress(jsonData)

				ctx := context.Background()
				m.EXPECT().Get(ctx, MetadataKey).Return(compressed, nil)
			},
			expectedError: "metadata missing latestSnapshot.path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			th := setupTestData(t)
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			var syncer *SLSDataSyncer
			if tt.useNilClient {
				syncer = NewSLSDataSyncer(nil, "test.db")
			} else {
				mockS3 := NewMocks3Store(ctrl)
				tt.setupMock(mockS3, th)
				syncer, _ = createTestSyncer(t, mockS3)
			}

			err := syncer.SyncSLSData(context.Background())
			assert.Error(t, err)
			assert.Contains(t, err.Error(), tt.expectedError)
		})
	}
}

func TestGetLatestMetadata(t *testing.T) {
	ctx := context.Background()
	th := setupTestData(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("successful metadata fetch", func(t *testing.T) {
		mockS3 := NewMocks3Store(ctrl)
		mockS3.EXPECT().Get(ctx, MetadataKey).Return(th.compressedMetadata, nil)

		syncer, _ := createTestSyncer(t, mockS3)

		metadata, err := syncer.GetLatestMetadata(ctx)
		assert.NoError(t, err)
		assert.NotNil(t, metadata)
		assert.Equal(t, "snapshots/test-snapshot.json.gz", metadata.LatestSnapshot.Path)
		assert.Equal(t, th.metadata.LatestSnapshot.MerkleRoot, metadata.LatestSnapshot.MerkleRoot)
	})
}

func TestInitSQLite(t *testing.T) {
	ctx := context.Background()
	syncer, _ := createTestSyncer(t, nil)

	err := syncer.initSQLite(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, syncer.db)
	defer syncer.closeDB()

	// Verify tables were created
	tables := []string{"admin", "quarantine", "snapshot_sync"}
	for _, table := range tables {
		var name string
		err := syncer.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&name)
		assert.NoError(t, err, "table %s should exist", table)
	}

	// Verify indexes were created
	indexes := []string{"idx_quarantine_tx_hash", "idx_admin_address"}
	for _, idx := range indexes {
		var name string
		err := syncer.db.QueryRow("SELECT name FROM sqlite_master WHERE type='index' AND name=?", idx).Scan(&name)
		assert.NoError(t, err, "index %s should exist", idx)
	}
}

func TestStoreSnapshotData(t *testing.T) {
	ctx := context.Background()
	th := setupTestData(t)

	syncer, _ := createTestSyncer(t, nil)
	err := syncer.initSQLite(ctx)
	require.NoError(t, err)
	defer syncer.closeDB()

	merkleRoot := "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5"
	err = syncer.storeSnapshotData(ctx, th.snapshot, merkleRoot)
	assert.NoError(t, err)

	// Verify data was stored correctly
	verifyStoredData(t, syncer, merkleRoot)
}

func TestSyncSLSDataFullWorkflow(t *testing.T) {
	th := setupTestData(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockS3 := NewMocks3Store(ctrl)
	setupMockS3Success(mockS3, th)

	syncer, _ := createTestSyncer(t, mockS3)

	err := syncer.SyncSLSData(context.Background())
	assert.NoError(t, err)
	assert.NotNil(t, syncer.db)
	defer syncer.closeDB()

	// Verify all data was properly stored
	verifyStoredData(t, syncer, th.metadata.LatestSnapshot.MerkleRoot)
}

func TestFetchGzipJSON(t *testing.T) {
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	t.Run("successful fetch", func(t *testing.T) {
		mockS3 := NewMocks3Store(ctrl)

		data := map[string]string{"test": "data"}
		jsonData, _ := json.Marshal(data)
		compressed, _ := gzipCompress(jsonData)

		mockS3.EXPECT().Get(ctx, "test-key").Return(compressed, nil)

		result, err := fetchGzipJSON[map[string]string](ctx, mockS3, "test-key", "test")
		assert.NoError(t, err)
		assert.Equal(t, "data", (*result)["test"])
	})

	t.Run("s3 error", func(t *testing.T) {
		mockS3 := NewMocks3Store(ctrl)
		mockS3.EXPECT().Get(ctx, "test-key").Return(nil, fmt.Errorf("s3 error"))

		result, err := fetchGzipJSON[map[string]string](ctx, mockS3, "test-key", "test")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to download test from S3")
	})

	t.Run("invalid gzip metadata", func(t *testing.T) {
		mockS3 := NewMocks3Store(ctrl)
		mockS3.EXPECT().Get(ctx, "test-key").Return([]byte("not gzipped"), nil)

		result, err := fetchGzipJSON[map[string]string](ctx, mockS3, "test-key", "test")
		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Contains(t, err.Error(), "failed to create gzip reader")
	})
}

// Helper function to verify stored data
func verifyStoredData(t *testing.T, syncer *SLSDataSyncer, expectedMerkleRoot string) {
	// Verify admin count
	var adminCount int
	err := syncer.db.QueryRow("SELECT COUNT(*) FROM admin").Scan(&adminCount)
	assert.NoError(t, err)
	assert.Equal(t, 2, adminCount)

	// Verify quarantine count
	var quarantineCount int
	err = syncer.db.QueryRow("SELECT COUNT(*) FROM quarantine").Scan(&quarantineCount)
	assert.NoError(t, err)
	assert.Equal(t, 2, quarantineCount)

	// Verify snapshot sync record
	var syncCount int
	var merkleRoot string
	err = syncer.db.QueryRow("SELECT COUNT(*), MAX(merkle_root) FROM snapshot_sync").Scan(&syncCount, &merkleRoot)
	assert.NoError(t, err)
	assert.Equal(t, 1, syncCount)
	assert.Equal(t, expectedMerkleRoot, merkleRoot)

	// Verify a specific quarantine record
	var txHash string
	err = syncer.db.QueryRow("SELECT tx_hash FROM quarantine WHERE tx_hash = ?", "0x1c948c35e781f552f2f48008912555d8451e257b454bd81a7a7d1b224b5285dc").Scan(&txHash)
	assert.NoError(t, err)
	assert.Equal(t, "0x1c948c35e781f552f2f48008912555d8451e257b454bd81a7a7d1b224b5285dc", txHash)
}

type MockSlogHandler struct {
	records []slog.Record
}

func (h *MockSlogHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

func (h *MockSlogHandler) Handle(_ context.Context, r slog.Record) error {
	// Store a copy of the record (must clone attributes, since slog reuses them)
	rCopy := slog.Record{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
	}
	r.Attrs(func(a slog.Attr) bool {
		rCopy.AddAttrs(a)
		return true
	})
	h.records = append(h.records, rCopy)
	return nil
}

func (h *MockSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Optional: carry attrs over to new handler
	newH := &MockSlogHandler{}
	newH.records = h.records
	return newH
}

func (h *MockSlogHandler) WithGroup(name string) slog.Handler {
	// Ignore groups for simplicity
	return h
}

func TestUploadGzipJSON(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	fixedTime := time.Date(2025, 10, 20, 12, 0, 0, 0, time.UTC)

	t.Run("upload snapshot to s3", func(t *testing.T) {
		key := "snapshot/snapshot.json.gz"
		snapshot := Snapshot{
			Timestamp: fixedTime,
			Admin: []*model.Admin{{CreatedAt: &fixedTime, Reference: "admin", Address: "0x0"}},
			Quarantine: []*model.Quarantine{{},
				{
					ExpiresOn:         &fixedTime,
					TxData:            []byte("txdata"),
					TxHash:            "hash",
					Data:              []byte("data"),
					QuarantinedAt:     fixedTime,
					QuarantinedReason: "reason",
					QuarantinedBy:     "detector",
					ReleasedAt:        fixedTime,
					ReleasedReason:    "reason",
					ReleasedBy:        "0x4441A244464a444e4444DA504447715c7eA30444",
					IsReleased:        false,
					From:              "0x4441A244464a444e4444DA504447715c7eA30444",
					To:                "0x4441A244464a444e4444DA504447715c7eA30444",
					Nonce:             1,
					Loss:              uint256.NewInt(1),
					Value:             uint256.NewInt(1),
					QuarantineType:    model.PoolQuarantineType,
				},
			},
		}
		logger := log.NewLogger(&MockSlogHandler{})
		mockS3Client := NewMocks3Store(ctrl)

		compressed, err := structToGzipJSON(&snapshot)
		assert.Nil(t, err)

		mockS3Client.EXPECT().Upload(t.Context(), key, compressed).Return(nil)
		uploadGzipJSON(t.Context(), logger, mockS3Client, &snapshot, key)
	})

	t.Run("upload metadata to s3", func(t *testing.T) {
		key := "metadata/metadata.json.gz"
		metadata := MetadataFile{
			LatestSnapshot: SnapshotInfo{
				Path:       "snapshots/test-snapshot.json.gz",
				Timestamp:  1719470440,
				MerkleRoot: "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5",
			},
		}
		logger := log.NewLogger(&MockSlogHandler{})
		mockS3Client := NewMocks3Store(ctrl)

		compressed, err := structToGzipJSON(&metadata)
		assert.Nil(t, err)

		mockS3Client.EXPECT().Upload(t.Context(), key, compressed).Return(nil)
		uploadGzipJSON(t.Context(), logger, mockS3Client, &metadata, key)
	})

	t.Run("compression error", func(t *testing.T) {
		key := "metadata/metadata.json.gz"
		type Bad struct {
			Ch chan int
			Fn func() string
		}
		
		slogHandler := &MockSlogHandler{}
		logger := log.NewLogger(slogHandler)
		mockS3Client := NewMocks3Store(ctrl)
		
		err := uploadGzipJSON(t.Context(), logger, mockS3Client, &Bad{}, key)
		assert.NotNil(t, err)

		logMsg := "Cannot compress go struct"
		assert.Equal(t, slogHandler.records[0].Message, logMsg)
	})

	t.Run("upload error", func(t *testing.T) {
		key := "metadata/metadata.json.gz"
		metadata := &MetadataFile{
			LatestSnapshot: SnapshotInfo{
				Timestamp:  1719470440,
				MerkleRoot: "0x123",
				Path:       "",
			},
		}
		slogHandler := &MockSlogHandler{}
		logger := log.NewLogger(slogHandler)
		mockS3Client := NewMocks3Store(ctrl)

		compressed, err := structToGzipJSON(&metadata)
		assert.Nil(t, err)

		mockS3Client.EXPECT().Upload(t.Context(), key, compressed).Return(errors.New("upload failed"))
		uploadGzipJSON(t.Context(), logger, mockS3Client, &metadata, key)

		logMsg := "Cannot upload stray object to S3"
		assert.Equal(t, slogHandler.records[0].Message, logMsg)
	})
}

func TestStructToGzipJSON(t *testing.T) {
	t.Run("gzip compression success", func(t *testing.T) {
		expectedBytes := []byte{0x1f, 0x8b, 0x8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0x2c, 0xcc, 0x41, 0xa, 0xc2, 0x30, 0x10, 0x85, 0xe1, 0x7d, 0x4e, 0xf1, 0x78, 0x6b, 0x17, 0x89, 0x6, 0x8a, 0x39, 0x86, 0x9e, 0x20, 0xe0, 0x94, 0x16, 0x27, 0x6d, 0x70, 0x46, 0x10, 0xa4, 0x77, 0x97, 0xaa, 0xcb, 0xf7, 0x3e, 0xf8, 0xdf, 0x1, 0xa0, 0x56, 0x17, 0xf3, 0xeb, 0x52, 0xbb, 0x4d, 0xab, 0xb3, 0x60, 0x7f, 0x1, 0xf6, 0xea, 0x13, 0xb, 0xc8, 0xc3, 0x6f, 0xfb, 0xdc, 0xc4, 0xbc, 0xb6, 0xce, 0x82, 0x34, 0xa4, 0x73, 0x1e, 0x62, 0xce, 0xf1, 0x8f, 0x4d, 0x1e, 0x77, 0x95, 0xcb, 0xfa, 0xd, 0x30, 0xbe, 0xd2, 0xf1, 0xc4, 0x0, 0x6c, 0x3b, 0xf3, 0x36, 0x8f, 0xa3, 0xb1, 0x60, 0x79, 0xaa, 0x86, 0xed, 0x13, 0x0, 0x0, 0xff, 0xff, 0xfe, 0xeb, 0x22, 0x90, 0x75, 0x0, 0x0, 0x0}
		metadata := &MetadataFile{
			LatestSnapshot: SnapshotInfo{
				Timestamp:  1719470440,
				MerkleRoot: "0x123",
				Path:       "",
			},
		}
		compressed, err := structToGzipJSON(metadata)
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, compressed)
	})

	t.Run("gzip compression error", func(t *testing.T) {
		type Bad struct {
			Ch chan int
			Fn func() string
		}
		_, err := structToGzipJSON(&Bad{})
		assert.NotNil(t, err)
		var ute *json.UnsupportedTypeError
		assert.ErrorAs(t, err, &ute)
	})
}
