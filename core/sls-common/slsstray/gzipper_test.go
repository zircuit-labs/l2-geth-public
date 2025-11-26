package slsstray

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
)

func TestStoreGzipJson(t *testing.T) {
	gzipper := NewGZipper()

	basePath := filepath.Join(os.TempDir(), "tmp/sls/snapshot")
	os.RemoveAll(basePath)
	deterministicTime := time.Unix(int64(1722252100), 0).UTC()

	snapshot := &Snapshot{
		Quarantine: []*model.Quarantine{{}},
		Admin:      []*model.Admin{{Address: "0x123", CreatedAt: &deterministicTime}, {Address: "0x000"}},
		Timestamp:  deterministicTime,
	}

	now := time.Now().UTC()
	path, err := gzipper.StoreGzipJson(snapshot, basePath, "snapshot", now)
	assert.Equal(t, nil, err)

	// Check if the file exists
	_, err = os.Stat(path)
	assert.Equal(t, nil, err)

	// Check file content
	jsonData, err := gzipper.OpenGzipJson(path)
	assert.Equal(t, nil, err)

	if !strings.Contains(string(jsonData), `"admin": [`) {
		t.Fatalf("Expected admin key")
	}
	if !strings.Contains(string(jsonData), `"quarantine": [`) {
		t.Fatalf("Expected quarantine key")
	}
}

func TestIncrementFilename(t *testing.T) {
	tmpDir := t.TempDir()
	gzipper := NewGZipper()

	// Case 1: no conflict → filename returned as-is
	f1 := filepath.Join(tmpDir, "file.json.gz")
	got, err := gzipper.incrementFilename(f1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != f1 {
		t.Errorf("expected %s, got %s", f1, got)
	}

	// Create the file to simulate it exists
	if _, err := os.Create(f1); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// Case 2: one conflict → should get file(1).json.gz
	expected := filepath.Join(tmpDir, "file(1).json.gz")
	got, err = gzipper.incrementFilename(f1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}

	// Create file(1).json.gz to simulate another conflict
	if _, err := os.Create(expected); err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}

	// Case 3: two conflicts → should get file(2).json.gz
	expected = filepath.Join(tmpDir, "file(2).json.gz")
	got, err = gzipper.incrementFilename(f1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}

func TestManyStoreGzipJson(t *testing.T) {
	basePath := filepath.Join(os.TempDir(), "tmp/sls/snapshot")
	os.RemoveAll(basePath)

	gzipper := NewGZipper()

	now := time.Now().UTC()
	timeString := fmt.Sprintf("%d", now.Unix())

	_, err := gzipper.StoreGzipJson(&Diff{}, basePath, "diff", now)
	assert.Equal(t, nil, err)
	_, err = gzipper.StoreGzipJson(&Diff{}, basePath, "diff", now)
	assert.Equal(t, nil, err)
	_, err = gzipper.StoreGzipJson(&Diff{}, basePath, "diff", now)
	assert.Equal(t, nil, err)

	fileNames := []string{"diff.json.gz", "diff(1).json.gz", "diff(2).json.gz"}
	entries, err := os.ReadDir(basePath + "/" + timeString)
	assert.NoError(t, err)
	for _, entry := range entries {
		assert.Contains(t, fileNames, entry.Name(), fmt.Sprintf("slice should contain '%s'", entry.Name()))
	}
}
