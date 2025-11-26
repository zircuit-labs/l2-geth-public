package slsstray

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/log"
	"go.uber.org/mock/gomock"
	"golang.org/x/sync/errgroup"
)

func dummyData(t *testing.T, key1, key2, key3 string) []byte {

	metadata := &MetadataFile{
		LatestSnapshot: SnapshotInfo{
			Path:       "https://sls.s3.eu-west-1.amazonaws.com/snapshots/" + key1,
			Timestamp:  1719470440,
			MerkleRoot: "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5",
		},
		Diffs: []DiffInfo{
			{
				Path:       "https://sls.s3.eu-west-1.amazonaws.com/diffs/" + key2,
				Timestamp:  1719470440,
				MerkleRoot: "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5",
			},
			{
				Path:       "https://sls.s3.eu-west-1.amazonaws.com/diffs/" + key3,
				Timestamp:  1719470440,
				MerkleRoot: "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5",
			},
		},
	}

	jsonData, err := json.Marshal(metadata)
	assert.NoError(t, err)

	compressedMetadata, err := gzipCompress(jsonData)
	assert.NoError(t, err)

	return compressedMetadata
}

func TestEnforceRetentionPolicy(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	snapshotKey1 := "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	snapshotKey2 := "0xaaac394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	diffKey1 := "0xbbbc394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	diffKey2 := "0xfffc394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	diffKey3 := "0xdddc394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	compressedMetadata := dummyData(t, snapshotKey1, diffKey1, diffKey2)
	beforeBucket := "test-bucket"

	tests := []struct {
		name              string
		setupMocks        func(context.Context) s3Store
		expectedErrString string
	}{
		{
			name: "error nil dependency",
			setupMocks: func(ctx context.Context) s3Store {
				return nil
			},
			expectedErrString: "missing dependency definition, slsDataSyncer or s3Client is nil",
		},
		{
			name: "error get all snapshots",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{}, errors.New("error"))
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "error",
		},
		{
			name: "error get all diffs",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey1, snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{}, errors.New("error"))
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "error",
		},
		{
			name: "error get metadata",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey1, snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{diffKey1, diffKey2, diffKey3}, nil)
				mockS3.EXPECT().SetBucket(MetadataBucket).Times(1)
				mockS3.EXPECT().Get(ctx, MetadataKey).Times(1).Return([]byte{}, errors.New("error"))
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "error",
		},
		{
			name: "error snapshot file missing in s3",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{diffKey1, diffKey2, diffKey3}, nil)
				mockS3.EXPECT().SetBucket(MetadataBucket).Times(1)
				mockS3.EXPECT().Get(ctx, MetadataKey).Times(1).Return(compressedMetadata, nil)
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "latest snapshot file missing in s3",
		},
		{
			name: "error diff file missing in s3",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey1, snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{diffKey1}, nil)
				mockS3.EXPECT().SetBucket(MetadataBucket).Times(1)
				mockS3.EXPECT().Get(ctx, MetadataKey).Times(1).Return(compressedMetadata, nil)
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "diff file missing in s3",
		},
		{
			name: "error delete snapshot",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey1, snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{diffKey1, diffKey2, diffKey3}, nil)
				mockS3.EXPECT().SetBucket(MetadataBucket).Times(1)
				mockS3.EXPECT().Get(ctx, MetadataKey).Times(1).Return(compressedMetadata, nil)
				mockS3.EXPECT().SetBucket(SnapshotBucket)
				mockS3.EXPECT().Delete(ctx, snapshotKey2).Times(1).Return(errors.New("error"))
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "error",
		},
		{
			name: "error delete diff",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey1, snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{diffKey1, diffKey2, diffKey3}, nil)
				mockS3.EXPECT().SetBucket(MetadataBucket).Times(1)
				mockS3.EXPECT().Get(ctx, MetadataKey).Times(1).Return(compressedMetadata, nil)
				mockS3.EXPECT().SetBucket(SnapshotBucket)
				mockS3.EXPECT().Delete(ctx, snapshotKey2).Times(1).Return(nil)
				mockS3.EXPECT().SetBucket(DiffBucket)
				mockS3.EXPECT().Delete(ctx, diffKey3).Times(1).Return(errors.New("error"))
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "error",
		},
		{
			name: "success",
			setupMocks: func(ctx context.Context) s3Store {
				mockS3 := NewMocks3Store(ctrl)
				mockS3.EXPECT().GetBucket().Times(1).Return(beforeBucket)
				mockS3.EXPECT().SetBucket(SnapshotBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{snapshotKey1, snapshotKey2}, nil)
				mockS3.EXPECT().SetBucket(DiffBucket).Times(1)
				mockS3.EXPECT().GetAllList(ctx).Times(1).Return([]string{diffKey1, diffKey2, diffKey3}, nil)
				mockS3.EXPECT().SetBucket(MetadataBucket).Times(1)
				mockS3.EXPECT().Get(ctx, MetadataKey).Times(1).Return(compressedMetadata, nil)
				mockS3.EXPECT().SetBucket(SnapshotBucket)
				mockS3.EXPECT().Delete(ctx, snapshotKey2).Times(1).Return(nil)
				mockS3.EXPECT().SetBucket(DiffBucket)
				mockS3.EXPECT().Delete(ctx, diffKey3).Times(1).Return(nil)
				mockS3.EXPECT().SetBucket(beforeBucket).Times(1)
				return mockS3
			},
			expectedErrString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mockS3 := tt.setupMocks(ctx)
			syncer := NewSLSDataSyncer(mockS3, "test path")
			assert.NotNil(t, syncer)

			glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, false))
			err := EnforceRetentionPolicy(ctx, syncer, log.NewLogger(glogger))
			if tt.expectedErrString != "" {
				assert.ErrorContains(t, err, tt.expectedErrString)
			}
		})
	}
}

func TestEnforceRetentionPolicyConcurrency(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	snapshotKey1 := "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	snapshotKey2 := "0xaaac394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	diffKey1 := "0xbbbc394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	diffKey2 := "0xfffc394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	compressedMetadata := dummyData(t, snapshotKey1, diffKey1, diffKey2)

	ctx := context.Background()

	mockS3 := NewMocks3Store(ctrl)
	mockS3.EXPECT().GetBucket().AnyTimes()
	mockS3.EXPECT().SetBucket(gomock.Any()).AnyTimes()
	mockS3.EXPECT().GetAllList(ctx).AnyTimes().Return([]string{snapshotKey1, snapshotKey2, diffKey1, diffKey2}, nil)
	mockS3.EXPECT().Get(ctx, gomock.Any()).AnyTimes().Return(compressedMetadata, nil)
	mockS3.EXPECT().Delete(ctx, gomock.Any()).AnyTimes().Return(nil)

	syncer := NewSLSDataSyncer(mockS3, "test path")
	assert.NotNil(t, syncer)

	glogger := log.NewGlogHandler(log.NewTerminalHandler(os.Stderr, false))

	const goroutines = 50
	g := new(errgroup.Group)
	for range goroutines {
		g.Go(func() error {
			return EnforceRetentionPolicy(ctx, syncer, log.NewLogger(glogger))
		})
	}

	// Wait for all goroutines to complete
	if err := g.Wait(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifyFnInMap(t *testing.T) {
	t.Parallel()

	// success case
	fn := "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	latestSnapshotPath := "https://sls.s3.eu-west-1.amazonaws.com/snapshots/0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"

	snapshotMap := map[string]bool{}
	snapshotMap[fn] = true

	snapshotFileName, err := verifyFnInMap(snapshotMap, latestSnapshotPath, SnapshotBucket, ErrNoSnapshotFileName, ErrSnapshotNotInS3)

	assert.NoError(t, err)
	assert.Equal(t, "0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz", snapshotFileName)

	// error case: wrong snapshotPath
	falseLatestSnapshotPath := "https://sls.s3.eu-west-1.amazonaws.com/snap0x3f5c394d3f3e89ea1a6f51e65f8b5d7cf055c7e8b19e1bc19b1db3b1a424e5e5.json.gz"
	_, err = verifyFnInMap(snapshotMap, falseLatestSnapshotPath, SnapshotBucket, ErrNoSnapshotFileName, ErrSnapshotNotInS3)
	assert.ErrorIs(t, err, ErrNoSnapshotFileName)

	// error case: snapshot not in s3
	_, err = verifyFnInMap(map[string]bool{}, latestSnapshotPath, SnapshotBucket, ErrNoSnapshotFileName, ErrSnapshotNotInS3)
	assert.ErrorIs(t, err, ErrSnapshotNotInS3)
}
