package slsstray

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common"
)

func TestSetConfig(t *testing.T) {
	// check NewMetadataGenerator without config
	mdg := NewMetadataGenerator(nil)
	assert.Equal(t, defaultMetadataPath, mdg.config.storagePath)
	assert.Equal(t, defaultFilename, mdg.config.fileName)

	// check NewMetadataGenerator with config
	newPath := "sample/path"
	mdg = NewMetadataGenerator(&MetadataConfig{storagePath: newPath})
	assert.Equal(t, newPath, mdg.config.storagePath)

	// check SetConfig new value
	newNumber := defaultRetainsDiffs - 1
	mdg.SetConfig(&MetadataConfig{retainDiffs: newNumber})
	assert.Equal(t, newNumber, mdg.config.retainDiffs)

	// check SetConfig defaults used
	mdg.SetConfig(&MetadataConfig{retainDiffs: 0})
	assert.Equal(t, defaultRetainsDiffs, mdg.config.retainDiffs)
}

func setupDataInFS(t *testing.T, diffPath, snapshotPath string, numberDiffs int) {

	// setup first snapshot
	store := setupStore(t)
	snapGen, err := NewSnapshotGenerator(store)
	snapGen.SetConfig(&SnapshotConfig{storagePath: snapshotPath})
	assert.NoError(t, err)
	qs, ads := setupQuarantineAdmin()
	snapshot := &Snapshot{Timestamp: time.Now(), Quarantine: qs, Admin: ads}
	snapGen.StoreSnapshot(snapshot)

	// diff setup
	addr1 := "0x0000000000000000000000000000000000000000"
	addr2 := "0xaaaa000000000000000000000000000000000000"
	diffGenerator := NewDiffGenerator(&DiffConfig{StoragePath: diffPath})

	// store first diff file
	diffGenerator.AddDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}, {Address: common.HexToAddress(addr2)}})
	time.Sleep(1 * time.Second)

	// add another snapshot
	snapshot = &Snapshot{Timestamp: time.Now(), Quarantine: qs}
	snapGen.StoreSnapshot(snapshot)

	// store other diff files
	for range numberDiffs {
		diffGenerator.AddDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}})
	}
}

func TestNewMetadata(t *testing.T) {
	diffPath := filepath.Join(os.TempDir(), "tmp/sls/diff")
	snapshotPath := filepath.Join(os.TempDir(), "tmp/sls/snapshot")
	metadataPath := filepath.Join(os.TempDir(), "tmp/sls/metadata")
	os.RemoveAll(diffPath)
	os.RemoveAll(snapshotPath)
	os.RemoveAll(metadataPath)

	// define suitable folder structure such that getLatestSnapshot and getLatestDiffs can pick data
	setupDataInFS(t, diffPath, snapshotPath, 5)

	// first lets consider all diffs
	mdg := NewMetadataGenerator(&MetadataConfig{snapshotPath: snapshotPath, diffPath: diffPath, storagePath: metadataPath})
	mdg.NewMetadata()

	entries, err := os.ReadDir(metadataPath)
	assert.NoError(t, err)
	fPath := filepath.Join(filepath.Join(metadataPath, entries[0].Name()), mdg.config.fileName)

	_, err = mdg.gzipper.OpenGzipJson(fPath + ".json.gz")
	assert.NoError(t, err)
	// fmt.Println("metadata:", string(jsonData))

	// clean up folders
	os.RemoveAll(diffPath)
	os.RemoveAll(snapshotPath)
	os.RemoveAll(metadataPath)
}