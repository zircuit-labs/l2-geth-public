package slsstray

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

const (
	defaultMetadataPath = "/tmp/sls/metadata"

	defaultRetainsDiffs = 100
	defaultFilename     = "metadata"

	MetadataFilename LocalStorageFileName = "metadata"
)

type MetadataConfig struct {
	storagePath  string
	diffPath     string
	snapshotPath string
	fileName     string
	retainDiffs  int
}

type MetadataGenerator struct {
	config *MetadataConfig
	mu     *sync.RWMutex
	mrg    *MerkleRootGenerator
	slsDataSyncer *SLSDataSyncer
	gzipper *GZipper
}

func NewMetadataGenerator(c *MetadataConfig) *MetadataGenerator {
	c = checkConfig(c)
	return &MetadataGenerator{config: c, mu: new(sync.RWMutex), mrg: NewMerklerootGenerator(""), gzipper: NewGZipper()}
}

func checkConfig(c *MetadataConfig) *MetadataConfig {
	if c == nil {
		c = &MetadataConfig{
			storagePath:  defaultMetadataPath,
			diffPath:     defaultDiffPath,
			snapshotPath: defaultSnapshotPath,
			retainDiffs:  defaultRetainsDiffs,
			fileName:     defaultFilename,
		}
	}
	if c.storagePath == "" {
		c.storagePath = defaultMetadataPath
	}
	if c.diffPath == "" {
		c.diffPath = defaultDiffPath
	}
	if c.snapshotPath == "" {
		c.snapshotPath = defaultSnapshotPath
	}
	if c.retainDiffs <= 0 {
		c.retainDiffs = defaultRetainsDiffs
	}
	if c.fileName == "" {
		c.fileName = defaultFilename
	}
	return c
}

func (mg *MetadataGenerator) SetConfig(c *MetadataConfig) {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	c = checkConfig(c)
	mg.config = c
}

// NewMetadata generates a new metadata file and stores it
func (mg *MetadataGenerator) NewMetadata() error {
	// collect latest snapshot
	snapshot, snapshotMeta, err := getLatestSnapshot(mg.gzipper, mg.config.snapshotPath)
	if err != nil {
		return err
	}
	// collect latest diffs
	diffs, diffsMeta, err := getLatestDiffs(mg.gzipper, mg.config.diffPath, mg.config.retainDiffs, snapshot.Timestamp)
	if err != nil && !errors.Is(err, ErrNoDiffFound) {
		return err
	}

	// compute merkleroots
	data := make([][]byte, 0, 1+len(diffs)) // 1 for snapshot hash, then hash every diff

	// snapshot
	byteSlice, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	data = append(data, byteSlice)
	snapshotMeta.MerkleRoot = hex.EncodeToString(mg.mrg.MerkleRoot(data))

	// select retainDiffs number of diffs that are older than snapshot
	for idx, diff := range diffs {
		byteSlice, err := json.Marshal(diff)
		if err != nil {
			return err
		}
		data = append(data, byteSlice)
		diffsMeta[idx].MerkleRoot = hex.EncodeToString(mg.mrg.MerkleRoot(data))
	}

	// create metadata
	metadata := MetadataFile{LatestSnapshot: *snapshotMeta, Diffs: diffsMeta}

	// store file
	return mg.StoreInFS(&metadata, MetadataFilename)
}

// MetadataGenerator stores metadata in the file system
func (mg *MetadataGenerator) StoreInFS(metadata *MetadataFile, fname LocalStorageFileName) error {
	mg.mu.RLock()
	defer mg.mu.RUnlock()
	path := mg.config.storagePath
	_, err := mg.gzipper.StoreGzipJson(metadata, path, fname, time.Now())
	return err
}
