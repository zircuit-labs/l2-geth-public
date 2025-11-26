package slsstray

import (
	"context"
	"errors"
	"sync"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"golang.org/x/sync/errgroup"
)

type StrayConfig struct {
	// every time updateCount hits snapshotIntervalLimit, a quarantine/admin snapshot is taken
	snapshotIntervalLimit int
}

const (
	defaultSnapshotIntervalLimit = 3
)

var (
	ErrStrayModeConflict     = errors.New("cannot run stray in both sequencer mode and replica mode")
	ErrNoSnapshotGenerator   = errors.New("no snapshot generator provided during stray object initialization")
)

//go:generate go tool mockgen -source stray.go -destination mock_stray.go -package slsstray
type metadataGenerator interface {
	NewMetadata() error
	StoreInFS(metadata *MetadataFile, fname LocalStorageFileName) error
}

//go:generate go tool mockgen -source stray.go -destination mock_stray.go -package slsstray
type diffGenerator interface {
	AddDiffQuarantines(quarantines []*model.Quarantine) error
	RemoveDiffQuarantines(txHashes []string) error
	AddDiffAdmins(admins []slsCommon.ListItem) error
	RemoveDiffAdmins(admins []slsCommon.ListItem) error
}

//go:generate go tool mockgen -source stray.go -destination mock_stray.go -package slsstray
type snapshotGenerator interface {
	TakeNewSnapshot(ctx context.Context) error
}

type Stray struct {
	mode   StrayMode
	mu     *sync.RWMutex
	config *StrayConfig

	// internal counter incrementing every time admin or quarantine data changes. resets when it hits snapshotIntervalLimit
	counter int

	// generators
	snapshotGenerator snapshotGenerator
	diffGenerator     diffGenerator
	metadataGenerator metadataGenerator
}

var stray *Stray

// NewStray has no inputs because we init the singleton in init()
// modify stray object state via methods
func NewStray() *Stray {
	return &Stray{
		mode:              ModeDisabled,
		mu:                new(sync.RWMutex),
		config:            &StrayConfig{snapshotIntervalLimit: defaultSnapshotIntervalLimit},
		counter:           0,
		diffGenerator:     NewDiffGenerator(nil),
		metadataGenerator: NewMetadataGenerator(nil),
		// snapshotGenerator is nil until first invocation of GetStray
	}
}

// Initialize the stray object as global singleton (exists only once)
// reason: can take a reference of stray object in different pacakages without the need to pass it around
func init() {
	stray = NewStray()
}

// GetStray returns the global instance of the Stray object and fails if storage is not set
// GetStray takes early snapshot if stray is enabled to ensure data availability for metadata files
func GetStray(ctx context.Context, config *StrayConfig, mode StrayMode, snapshotGenerator snapshotGenerator, metadataGenerator metadataGenerator, diffGenerator diffGenerator) (*Stray, error) {
	if mode == ModeUnknown {
		return nil, ErrStrayModeConflict
	}
	stray.mu.Lock()
	defer stray.mu.Unlock()
	stray.mode = mode

	// set config
	if config == nil {
		config = &StrayConfig{}
	}
	if config.snapshotIntervalLimit <= 0 {
		config.snapshotIntervalLimit = defaultSnapshotIntervalLimit
	}
	stray.config = config

	// set generators
	if stray.snapshotGenerator == nil && snapshotGenerator == nil {
		return nil, ErrNoSnapshotGenerator
	}
	if snapshotGenerator != nil {
		stray.snapshotGenerator = snapshotGenerator
	}
	if metadataGenerator != nil {
		stray.metadataGenerator = metadataGenerator
	}
	if diffGenerator != nil {
		stray.diffGenerator = diffGenerator
	}

	return stray, nil
}

// RegisterAdminAddition triggers a diff and metadata update on admin changes
func (s *Stray) RegisterAdminAddition(ctx context.Context, admins []slsCommon.ListItem) error {
	return s.updateState(ctx, admins, true)
}

// RegisterAdminRemoval triggers a diff and metadata update on admin changes
func (s *Stray) RegisterAdminRemoval(ctx context.Context, admins []slsCommon.ListItem) error {
	return s.updateState(ctx, admins, false)
}

// RegisterQuarantineAddition triggers a diff and metadata update on quarantine changes
func (s *Stray) RegisterQuarantineAddition(ctx context.Context, quarantines []*model.Quarantine) error {
	return s.updateState(ctx, quarantines, false)
}

// RegisterQuarantineRemoval triggers a diff and metadata update on quarantine changes
func (s *Stray) RegisterQuarantineRemoval(ctx context.Context, txHashes []string) error {
	return s.updateState(ctx, txHashes, false)
}

// updateState wraps async goroutine calls with am error group
func (s *Stray) updateState(ctx context.Context, d any, add bool) error {
	// prevent update in replica mode
	if s.mode.IsReplica() {
		return nil
	}

	// newSnapshot bool indicates if snapshot interval has been hit
	newSnapshot := s.CheckCounter(ctx)

	g, gCtx := errgroup.WithContext(ctx)
	s.NewDiffAndMetadata(g, gCtx, d, add, newSnapshot)
	return waitOnGroupErrors(g)
}

// CheckCounter increments counter and may capture a new snapshot
func (s *Stray) CheckCounter(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.counter += 1

	// check if count hits snapshotIntervalLimit
	if s.counter >= s.config.snapshotIntervalLimit {
		// reset interval
		s.counter = 0

		return true
	}
	return false
}

// NewMetadata get latest snapshot and diffs to create a new metadata file
func (s *Stray) NewDiffAndMetadata(g *errgroup.Group, gCtx context.Context, data any, add, newSnapshot bool) {
	g.Go(func() error {
		select {
		case <-gCtx.Done(): // handle gCtx call
			return gCtx.Err()
		default:
			// create new diff
			var err error
			switch v := data.(type) {
			case []string:
				// v = txHashes
				err = s.diffGenerator.RemoveDiffQuarantines(v)
			case []*model.Quarantine:
				// v = quarantines
				err = s.diffGenerator.AddDiffQuarantines(v)
			case []slsCommon.ListItem:
				// v = admins
				if add {
					err = s.diffGenerator.AddDiffAdmins(v)
				} else {
					err = s.diffGenerator.RemoveDiffAdmins(v)
				}
			}
			if err != nil {
				// return because if no new diff is created, old metadata file contains latest state
				return err
			}

			if newSnapshot {
				// create new snapshot
				err := s.snapshotGenerator.TakeNewSnapshot(gCtx)
				if err != nil {
					return err
				}
			}

			// update metadata file
			return s.metadataGenerator.NewMetadata()
		}
	})
}

// WaitOnGroupErrors collects errors and returns
func waitOnGroupErrors(g *errgroup.Group) error {
	if err := g.Wait(); err != nil {
		return err
	}
	return nil
}
