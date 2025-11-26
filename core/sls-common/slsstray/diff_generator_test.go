package slsstray

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common"
)

// setupDiffs generates numberDiffs+1 diffs in two folders
func setupDiffs(basePath string, numberDiffs int) {
	addr1 := "0x0000000000000000000000000000000000000000"
	addr2 := "0xaaaa000000000000000000000000000000000000"

	diffGenerator := NewDiffGenerator(&DiffConfig{StoragePath: basePath})

	for range numberDiffs {
		diffGenerator.AddDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}})
	}
	time.Sleep(1 * time.Second)
	diffGenerator.AddDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}, {Address: common.HexToAddress(addr2)}})
}

func TestGetDiffGenerator(t *testing.T) {
	dg := NewDiffGenerator(nil)
	assert.Equal(t, "/tmp/sls/diff", dg.Config.StoragePath)
	dg = NewDiffGenerator(&DiffConfig{StoragePath: "123"})
	assert.Equal(t, "123", dg.Config.StoragePath)
}

func TestAddRemoveDiffAdmins(t *testing.T) {
	basePath := filepath.Join(os.TempDir(), "tmp/sls/diff")
	os.RemoveAll(basePath)
	addr1 := "0x0000000000000000000000000000000000000000"
	addr2 := "0xaaaa000000000000000000000000000000000000"

	diffGenerator := NewDiffGenerator(&DiffConfig{StoragePath: basePath})
	diffGenerator.AddDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}, {Address: common.HexToAddress(addr2)}})
	diffGenerator.AddDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}})
	diffGenerator.RemoveDiffAdmins([]sls.ListItem{{Address: common.HexToAddress(addr1)}})

	entries, err := os.ReadDir(basePath)
	assert.Equal(t, nil, err)
	dir1 := filepath.Join(basePath, entries[0].Name())

	entries, err = os.ReadDir(dir1)
	assert.Equal(t, nil, err)
	assert.Equal(t, "admin(1).json.gz", entries[0].Name())
	assert.Equal(t, "admin.json.gz", entries[2].Name())
	assert.Equal(t, "admin(2).json.gz", entries[1].Name())

	jsonData, err := diffGenerator.gzipper.OpenGzipJson(filepath.Join(dir1, entries[2].Name()))
	assert.Equal(t, nil, err)
	if !strings.Contains(string(jsonData), `"admin": [
    {
      "action": "add",
      "address": "0x0000000000000000000000000000000000000000"
    },
    {
      "action": "add",
      "address": "0xaAaa000000000000000000000000000000000000"
    }
  ],`) {
		t.Fatalf("Expected 'admin' key")
	}

	jsonData, err = diffGenerator.gzipper.OpenGzipJson(filepath.Join(dir1, entries[1].Name()))
	assert.Equal(t, nil, err)
	if !strings.Contains(string(jsonData), `"admin": [
    {
      "action": "remove",
      "address": "0x0000000000000000000000000000000000000000"
    }
  ],`) {
		t.Fatalf("Expected 'admin' key")
	}
}

func TestGetLatestDiffs(t *testing.T) {
	t.Parallel()
	basePath := filepath.Join(os.TempDir(), "tmp/sls/diff")
	os.RemoveAll(basePath)
	tn := time.Now()
	setupDiffs(basePath, 3)
	defer os.RemoveAll(basePath)

	tests := []struct {
		name       string
		limit      int
		expectErr  error
		epectedLen int
	}{
		{
			name:       "limit < number of diffs",
			limit:      2,
			expectErr:  nil,
			epectedLen: 2,
		},
		{
			name:       "limit > number of diffs",
			limit:      7,
			expectErr:  nil,
			epectedLen: 4,
		},
		{
			name:       "limit = number of diffs",
			limit:      4,
			expectErr:  nil,
			epectedLen: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			diffGenerator := NewDiffGenerator(&DiffConfig{StoragePath: basePath})
			diffs, _, err := getLatestDiffs(diffGenerator.gzipper, basePath, tt.limit, tn)
			assert.ErrorIs(t, tt.expectErr, err)
			if len(diffs) != tt.epectedLen {
				t.Errorf("expected len(diffs)=%d, got: len(diffs)=%d", tt.epectedLen, len(diffs))
			}
		})
	}
}

func TestGetLatestDiffsErrors(t *testing.T) {
	basePath := filepath.Join(os.TempDir(), "tmp/sls/diff")
	os.RemoveAll(basePath)
	os.Mkdir(basePath, 0755)

	diffGenerator := NewDiffGenerator(&DiffConfig{StoragePath: basePath})
	_, _, err := getLatestDiffs(diffGenerator.gzipper, basePath, 100, time.Now())
	assert.True(t, errors.Is(err, ErrNoDiffFound))
	os.RemoveAll(basePath)
}
