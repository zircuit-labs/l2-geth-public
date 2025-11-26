package slsstray

import (
	"context"
	"errors"
	"strings"

	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

// get blobStore --> s3Client - s3.blobStore from slsdata_syncer (will be part of stray object)
// todo add this function to the stray object in stray.go

var (
	ErrNoSnapshotFileName = errors.New("cannot find snapshot filename in metadata")
	ErrNoDiffFileName     = errors.New("cannot find diff filename in metadata")
	ErrSnapshotNotInS3    = errors.New("latest snapshot file missing in s3")
	ErrDiffNotInS3        = errors.New("diff file missing in s3")
	ErrNilDependency      = errors.New("missing dependency definition, slsDataSyncer or s3Client is nil")
)

// EnforceRetentionPolicy cleans S3 from unused snapshot and diff files
// no need to clean up metadata file --> metadata file is overwritten on every update
func EnforceRetentionPolicy(ctx context.Context, slsDataSyncer *SLSDataSyncer, logger log.Logger) error {
	if slsDataSyncer == nil || slsDataSyncer.s3Client == nil {
		return stacktrace.Wrap(ErrNilDependency)
	}

	// since the function will be called on every stray update
	// use locks such that blobStore fetches target correct s3 buckets
	slsDataSyncer.mu.Lock()
	defer slsDataSyncer.mu.Unlock()

	bucketBefore := slsDataSyncer.s3Client.GetBucket()
	defer slsDataSyncer.s3Client.SetBucket(bucketBefore)

	// hashMaps for O(1) access
	snapshotMap := map[string]bool{}
	diffMap := map[string]bool{}

	slsDataSyncer.s3Client.SetBucket(SnapshotBucket)
	snapshots, err := slsDataSyncer.s3Client.GetAllList(ctx)
	if err != nil {
		return stacktrace.Wrap(err)
	}
	for _, name := range snapshots {
		snapshotMap[name] = true
	}

	slsDataSyncer.s3Client.SetBucket(DiffBucket)
	diffs, err := slsDataSyncer.s3Client.GetAllList(ctx)
	if err != nil {
		return stacktrace.Wrap(err)
	}
	for _, name := range diffs {
		diffMap[name] = true
	}

	slsDataSyncer.s3Client.SetBucket(MetadataBucket)
	metadata, err := slsDataSyncer.GetLatestMetadata(ctx)
	if err != nil {
		return stacktrace.Wrap(err)
	}

	// if any metadata path does not exists in diffs or snapshots, throw error

	snapshotFileName, err := verifyFnInMap(snapshotMap, metadata.LatestSnapshot.Path, SnapshotBucket, ErrNoSnapshotFileName, ErrSnapshotNotInS3)
	if err != nil {
		return stacktrace.Wrap(err)
	}
	// mark the snapshot, all others will be deleted
	snapshotMap[snapshotFileName] = false

	for _, diffinfo := range metadata.Diffs {
		diffFilename, err := verifyFnInMap(diffMap, diffinfo.Path, DiffBucket, ErrNoDiffFileName, ErrDiffNotInS3)
		if err != nil {
			return stacktrace.Wrap(err)
		}
		diffMap[diffFilename] = false
	}

	// enforce policy by cleaning unused snapshots
	slsDataSyncer.s3Client.SetBucket(SnapshotBucket)
	for key, remove := range snapshotMap {
		if remove {
			logger.Info("Deleting unused snapshot", "bucket", SnapshotBucket, "key", key)
			err = slsDataSyncer.s3Client.Delete(ctx, key)
			if err != nil {
				logger.Error("Failed to delete snapshot", "bucket", SnapshotBucket, "key", key, "error", err)
				return stacktrace.Wrap(err)
			}
		}
	}

	// enforce policy by cleaning unused diffs
	slsDataSyncer.s3Client.SetBucket(DiffBucket)
	for key, remove := range diffMap {
		if remove {
			logger.Info("Deleting unused diff", "bucket", DiffBucket, "key", key)
			err = slsDataSyncer.s3Client.Delete(ctx, key)
			if err != nil {
				logger.Error("Failed to delete diff", "bucket", DiffBucket, "key", key, "error", err)
				return stacktrace.Wrap(err)
			}
		}
	}

	return nil
}

func verifyFnInMap(m map[string]bool, path, bucket string, err1, err2 error) (string, error) {
	split := strings.Split(path, bucket+"/")
	if len(split) < 2 {
		return "", err1
	}
	snapshotFileName := split[1]
	if _, ok := m[snapshotFileName]; !ok {
		return "", err2
	}
	return snapshotFileName, nil
}
