package slsstray

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

type DiffQuarantineAction string
type LocalStorageFileName string

const (
	defaultDiffPath = "/tmp/sls/diff"

	AddAction DiffQuarantineAction = "add"
	RemoveAction DiffQuarantineAction = "remove"

	QuarantineFilename LocalStorageFileName = "quarantine"
	AdminFilename LocalStorageFileName = "admin"
)

var (
	ErrNoDiffFound = errors.New("no diff found")
)


type DiffConfig struct {
	StoragePath string
}

type Diff struct {
	Timestamp  time.Time         `json:"timestamp"`
	Admin      []*DiffAdmin      `json:"admin"`
	Quarantine []*DiffQuarantine `json:"quarantine"`
}

type DiffQuarantine struct {
	Action            DiffQuarantineAction     `json:"action"`
	TxHash            string     `json:"transactionHash"`
	QuarantinedAt     time.Time  `json:"quarantinedAt"`
	ReleasedAt        time.Time  `json:"releasedAt"`
	ExpiresOn         *time.Time `json:"expiresOn"`
	ReleasedReason    string     `json:"releasedReason,omitempty"`
	QuarantinedBy     string     `json:"quarantinedBy,omitempty"`
	QuarantinedReason string     `json:"quarantinedReason,omitempty"`
	ReleasedBy        string     `json:"releasedBy,omitempty"`
}

func newDiffQuarantine(action DiffQuarantineAction, q *model.Quarantine) *DiffQuarantine {
	return &DiffQuarantine{
		Action:            action,
		TxHash:            q.TxHash,
		QuarantinedAt:     q.QuarantinedAt,
		ReleasedAt:        q.ReleasedAt,
		ExpiresOn:         q.ExpiresOn,
		ReleasedReason:    q.ReleasedReason,
		QuarantinedBy:     q.QuarantinedBy,
		QuarantinedReason: q.QuarantinedReason,
		ReleasedBy:        q.ReleasedBy,
	}
}

type DiffAdmin struct {
	Action  DiffQuarantineAction `json:"action"`
	Address string `json:"address"`
}

func newDiffAdmin(action DiffQuarantineAction, admin *model.Admin) *DiffAdmin {
	return &DiffAdmin{Action: action, Address: admin.Address}
}

type DiffGenerator struct {
	mu      sync.RWMutex
	Config  *DiffConfig
	gzipper *GZipper
}

func NewDiffGenerator(config *DiffConfig) *DiffGenerator {

	if config == nil {
		config = &DiffConfig{}
	}
	if config.StoragePath == "" {
		config.StoragePath = defaultDiffPath
	}

	return &DiffGenerator{Config: config, gzipper: NewGZipper()}
}

// AddDiffQuarantines computes a diff which adds quarantines
func (dg *DiffGenerator) AddDiffQuarantines(quarantines []*model.Quarantine) error {
	diffQuarantine := []*DiffQuarantine{}
	for _, q := range quarantines {
		diffQuarantine = append(diffQuarantine, newDiffQuarantine(AddAction, q))
	}
	diff := &Diff{Timestamp: time.Now().UTC(), Admin: []*DiffAdmin{}, Quarantine: diffQuarantine}

	return dg.StoreDiff(diff, QuarantineFilename)
}

// RemoveDiffQuarantines computes a diff which removes quarantines
func (dg *DiffGenerator) RemoveDiffQuarantines(txHashes []string) error {
	diffQuarantine := []*DiffQuarantine{}
	for _, h := range txHashes {
		diffQuarantine = append(diffQuarantine, newDiffQuarantine(RemoveAction, &model.Quarantine{TxHash: h}))
	}
	diff := &Diff{Timestamp: time.Now().UTC(), Admin: []*DiffAdmin{}, Quarantine: diffQuarantine}

	return dg.StoreDiff(diff, QuarantineFilename)
}

// AddDiffAdmins computes a diff which adds admins
func (dg *DiffGenerator) AddDiffAdmins(admins []slsCommon.ListItem) error {
	diffAdmins := []*DiffAdmin{}
	for _, it := range admins {
		diffAdmins = append(diffAdmins, newDiffAdmin(AddAction, &model.Admin{Address: it.Address.Hex()}))
	}
	diff := &Diff{Timestamp: time.Now().UTC(), Admin: diffAdmins, Quarantine: []*DiffQuarantine{}}

	return dg.StoreDiff(diff, AdminFilename)
}

// RemoveDiffAdmins computes a diff which removes admins
func (dg *DiffGenerator) RemoveDiffAdmins(admins []slsCommon.ListItem) error {
	diffAdmins := []*DiffAdmin{}
	for _, it := range admins {
		diffAdmins = append(diffAdmins, newDiffAdmin(RemoveAction, &model.Admin{Address: it.Address.Hex()}))
	}
	diff := &Diff{Timestamp: time.Now().UTC(), Admin: diffAdmins, Quarantine: []*DiffQuarantine{}}

	return dg.StoreDiff(diff, AdminFilename)
}

// StoreDiff stores a diff in the file system
func (dg *DiffGenerator) StoreDiff(diff *Diff, fname LocalStorageFileName) error {
	dg.mu.RLock()
	defer dg.mu.RUnlock()

	path := dg.Config.StoragePath
	_, err := dg.gzipper.StoreGzipJson(diff, path, fname, diff.Timestamp)
	if err != nil {
		return stacktrace.Wrap(err)
	}
	return err
}

// getLatestDiffs returns the limit number of diffs inside the folder with path folderPath
func getLatestDiffs(gzipper *GZipper, folderPath string, limit int, snapshotTime time.Time) ([]Diff, []DiffInfo, error) {
	var diffs []Diff
	var diffsMeta []DiffInfo

	// get timestamp directories
	entries, err := os.ReadDir(folderPath)
	if err != nil {
		return nil, nil, stacktrace.Wrap(err)
	}

	if len(entries) == 0 {
		return nil, nil, stacktrace.Wrap(ErrNoDiffFound)
	}

	// sort entries by timestamp
	sort.Slice(entries, func(i, j int) bool {
		ti, _ := strconv.ParseInt(entries[i].Name(), 10, 64)
		tj, _ := strconv.ParseInt(entries[j].Name(), 10, 64)
		return ti < tj
	})

	// Iterate backwards with limit
	count := 0
	for i := len(entries) - 1; i >= 0; i-- {
		subPath := filepath.Join(folderPath, entries[i].Name())

		// capture all diff files inside folder
		files, err := os.ReadDir(subPath)
		if err != nil {
			return nil, nil, stacktrace.Wrap(err)
		}

		// collect all diffs inside folder
		for _, entry := range files {

			path := filepath.Join(subPath, entry.Name())
			diffUncompressed, err := gzipper.OpenGzipJson(path)
			if err != nil {
				return nil, nil, stacktrace.Wrap(err)
			}
			var diff Diff
			if err := json.Unmarshal(diffUncompressed, &diff); err != nil {
				return nil, nil, stacktrace.Wrap(err)
			}

			// filter diffs after latest snapshot
			if diff.Timestamp.After(snapshotTime) {

				// prepend element to keep order
				diffs = append([]Diff{diff}, diffs...)

				diffMeta := DiffInfo{Timestamp: diff.Timestamp.Unix(), Path: path}
				diffsMeta = append([]DiffInfo{diffMeta}, diffsMeta...)

				// increment diff count
				count++
				if count >= limit {
					return diffs, diffsMeta, nil
				}
			}

		}
	}
	return diffs, diffsMeta, nil
}
