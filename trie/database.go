// Copyright 2022 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package trie

import (
	"errors"
	"sync"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/trie/triedb/hashdb"
	"github.com/zircuit-labs/l2-geth-public/trie/triedb/pathdb"
	"github.com/zircuit-labs/l2-geth-public/trie/trienode"
	"github.com/zircuit-labs/l2-geth-public/trie/triestate"
)

// Config defines all necessary options for database.
type Config struct {
	Preimages bool           // Flag whether the preimage of node key is recorded
	HashDB    *hashdb.Config // Configs for hash-based scheme
	PathDB    *pathdb.Config // Configs for experimental path-based scheme
	IsVerkle  bool
	IsZktrie  bool
}

func (c *Config) copy() *Config {
	cp := &Config{
		Preimages: c.Preimages,
		IsVerkle:  c.IsVerkle,
		IsZktrie:  c.IsZktrie,
	}
	if c.HashDB != nil {
		cp.HashDB = &hashdb.Config{
			CleanCacheSize: c.HashDB.CleanCacheSize,
			IsZkTrie:       c.HashDB.IsZkTrie,
		}
	}
	if c.PathDB != nil {
		cp.PathDB = &pathdb.Config{
			StateHistory:   c.PathDB.StateHistory,
			CleanCacheSize: c.PathDB.CleanCacheSize,
			DirtyCacheSize: c.PathDB.DirtyCacheSize,
			ReadOnly:       c.PathDB.ReadOnly,
		}
	}
	return cp
}

// HashDefaults represents a config for using hash-based scheme with
// default settings.
func HashDefaults() *Config {
	return &Config{
		Preimages: false,
		HashDB:    hashdb.Defaults,
	}
}

// backend defines the methods needed to access/update trie nodes in different
// state scheme.
type backend interface {
	// Scheme returns the identifier of used storage scheme.
	Scheme() string

	// Initialized returns an indicator if the state data is already initialized
	// according to the state scheme.
	Initialized(genesisRoot common.Hash) bool

	// Size returns the current storage size of the diff layers on top of the
	// disk layer and the storage size of the nodes cached in the disk layer.
	//
	// For hash scheme, there is no differentiation between diff layer nodes
	// and dirty disk layer nodes, so both are merged into the second return.
	Size() (common.StorageSize, common.StorageSize)

	// Update performs a state transition by committing dirty nodes contained
	// in the given set in order to update state from the specified parent to
	// the specified root.
	//
	// The passed in maps(nodes, states) will be retained to avoid copying
	// everything. Therefore, these maps must not be changed afterwards.
	Update(root common.Hash, parent common.Hash, block uint64, nodes *trienode.MergedNodeSet, states *triestate.Set) error

	// Commit writes all relevant trie nodes belonging to the specified state
	// to disk. Report specifies whether logs will be displayed in info level.
	Commit(root common.Hash, report bool) error

	// Close closes the trie database backend and releases all held resources.
	Close() error

	// database supplementary methods, to get the underlying fields
	GetLock() *sync.RWMutex
}

// Database is the wrapper of the underlying backend which is shared by different
// types of node backend as an entrypoint. It's responsible for all interactions
// relevant with trie nodes and node preimages.
type Database struct {
	config    *Config        // Configuration for trie database
	diskdb    ethdb.Database // Persistent database to store the snapshot
	preimages *preimageStore // The store for caching preimages
	backend   backend        // The backend for managing trie nodes

	// zktrie related stuff
	// TODO: It's a quick&dirty implementation. FIXME later.
	rawDirties KvMap
}

// NewDatabase initializes the trie database with default settings, note
// the legacy hash-based scheme is used by default.
func NewDatabase(diskdb ethdb.Database, config *Config) *Database {
	// Sanitize the config and use the default one if it's not specified.
	if config == nil {
		config = HashDefaults()
	}
	config = config.copy()
	var preimages *preimageStore
	if config.Preimages {
		preimages = newPreimageStore(diskdb)
	}
	db := &Database{
		config:    config,
		diskdb:    diskdb,
		preimages: preimages,
		// scroll-related
		rawDirties: make(KvMap),
	}
	if config.HashDB != nil && config.PathDB != nil {
		panic("both 'hash' and 'path' mode are configured")
	}
	if config.PathDB != nil {
		db.backend = pathdb.New(diskdb, config.PathDB)
		return db
	}
	if config.HashDB == nil {
		config.HashDB = hashdb.Defaults
		config.HashDB.IsZkTrie = config.IsZktrie
	}
	db.backend = hashdb.New(diskdb, &hashdb.Config{
		CleanCacheSize: config.HashDB.CleanCacheSize,
		IsZkTrie:       config.HashDB.IsZkTrie,
	}, mptResolver{})
	return db
}

func (db *Database) IsZktrie() bool {
	// compatible logic for light mode
	if db == nil || db.config == nil {
		return false
	}
	return db.config.IsZktrie
}

func (db *Database) SetIsZktrie(isZktrie bool) {
	db.config.IsZktrie = isZktrie
}

func (db *Database) IsVerkle() bool {
	return db != nil && db.config != nil && db.config.IsVerkle
}

// Reader returns a reader for accessing all trie nodes with provided state root.
// An error will be returned if the requested state is not available.
func (db *Database) Reader(blockRoot common.Hash) (Reader, error) {
	switch b := db.backend.(type) {
	case *hashdb.Database:
		return b.Reader(blockRoot)
	case *pathdb.Database:
		return b.Reader(blockRoot)
	}
	return nil, errors.New("unknown backend")
}

// Update performs a state transition by committing dirty nodes contained in the
// given set in order to update state from the specified parent to the specified
// root. The held pre-images accumulated up to this point will be flushed in case
// the size exceeds the threshold.
//
// The passed in maps(nodes, states) will be retained to avoid copying everything.
// Therefore, these maps must not be changed afterwards.
func (db *Database) Update(root common.Hash, parent common.Hash, block uint64, nodes *trienode.MergedNodeSet, states *triestate.Set) error {
	if db.preimages != nil {
		db.preimages.commit(false)
	}
	return db.backend.Update(root, parent, block, nodes, states)
}

// Commit iterates over all the children of a particular node, writes them out
// to disk. As a side effect, all pre-images accumulated up to this point are
// also written.
func (db *Database) Commit(root common.Hash, report bool) error {
	batch := db.diskdb.NewBatch()

	db.GetLock().Lock()
	for _, v := range db.rawDirties {
		if err := batch.Put(v.K, v.V); err != nil {
			return err
		}
	}
	for k := range db.rawDirties {
		delete(db.rawDirties, k)
	}
	db.GetLock().Unlock()
	if err := batch.Write(); err != nil {
		return err
	}
	batch.Reset()

	if (root == common.Hash{}) {
		return nil
	}

	if db.preimages != nil {
		if err := db.preimages.commit(true); err != nil {
			return err
		}
	}
	return db.backend.Commit(root, report)
}

// Size returns the storage size of diff layer nodes above the persistent disk
// layer, the dirty nodes buffered within the disk layer, and the size of cached
// preimages.
func (db *Database) Size() (common.StorageSize, common.StorageSize, common.StorageSize) {
	var (
		diffs, nodes common.StorageSize
		preimages    common.StorageSize
	)
	diffs, nodes = db.backend.Size()
	if db.preimages != nil {
		preimages = db.preimages.size()
	}
	return diffs, nodes, preimages
}

// Initialized returns an indicator if the state data is already initialized
// according to the state scheme.
func (db *Database) Initialized(genesisRoot common.Hash) bool {
	return db.backend.Initialized(genesisRoot)
}

// Scheme returns the node scheme used in the database.
func (db *Database) Scheme() string {
	return db.backend.Scheme()
}

// Close flushes the dangling preimages to disk and closes the trie database.
// It is meant to be called when closing the blockchain object, so that all
// resources held can be released correctly.
func (db *Database) Close() error {
	db.WritePreimages()
	return db.backend.Close()
}

// WritePreimages flushes all accumulated preimages to disk forcibly.
func (db *Database) WritePreimages() {
	if db.preimages != nil {
		db.preimages.commit(true)
	}
}

// Preimage retrieves a cached trie node pre-image from memory. If it cannot be
// found cached, the method queries the persistent database for the content.
func (db *Database) Preimage(hash common.Hash) []byte {
	if db.preimages == nil {
		return nil
	}
	return db.preimages.preimage(hash)
}

// Cap iteratively flushes old but still referenced trie nodes until the total
// memory usage goes below the given threshold. The held pre-images accumulated
// up to this point will be flushed in case the size exceeds the threshold.
//
// It's only supported by hash-based database and will return an error for others.
func (db *Database) Cap(limit common.StorageSize) error {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	if db.preimages != nil {
		db.preimages.commit(false)
	}
	return hdb.Cap(limit)
}

// Reference adds a new reference from a parent node to a child node. This function
// is used to add reference between internal trie node and external node(e.g. storage
// trie root), all internal trie nodes are referenced together by database itself.
//
// It's only supported by hash-based database and will return an error for others.
func (db *Database) Reference(root common.Hash, parent common.Hash) error {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	hdb.Reference(root, parent)
	return nil
}

// Dereference removes an existing reference from a root node. It's only
// supported by hash-based database and will return an error for others.
func (db *Database) Dereference(root common.Hash) error {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	hdb.Dereference(root)
	return nil
}

// Node retrieves the rlp-encoded node blob with provided node hash. It's
// only supported by hash-based database and will return an error for others.
// Note, this function should be deprecated once ETH66 is deprecated.
func (db *Database) Node(hash common.Hash) ([]byte, error) {
	hdb, ok := db.backend.(*hashdb.Database)
	if !ok {
		return nil, errors.New("not supported")
	}
	return hdb.Node(hash)
}

// Recover rollbacks the database to a specified historical point. The state is
// supported as the rollback destination only if it's canonical state and the
// corresponding trie histories are existent. It's only supported by path-based
// database and will return an error for others.
func (db *Database) Recover(target common.Hash) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Recover(target, &trieLoader{db: db})
}

// Recoverable returns the indicator if the specified state is enabled to be
// recovered. It's only supported by path-based database and will return an
// error for others.
func (db *Database) Recoverable(root common.Hash) (bool, error) {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return false, errors.New("not supported")
	}
	return pdb.Recoverable(root), nil
}

// Disable deactivates the database and invalidates all available state layers
// as stale to prevent access to the persistent state, which is in the syncing
// stage.
//
// It's only supported by path-based database and will return an error for others.
func (db *Database) Disable() error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Disable()
}

// Enable activates database and resets the state tree with the provided persistent
// state root once the state sync is finished.
func (db *Database) Enable(root common.Hash) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Enable(root)
}

// Journal commits an entire diff hierarchy to disk into a single journal entry.
// This is meant to be used during shutdown to persist the snapshot without
// flattening everything down (bad for reorgs). It's only supported by path-based
// database and will return an error for others.
func (db *Database) Journal(root common.Hash) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.Journal(root)
}

// SetBufferSize sets the node buffer size to the provided value(in bytes).
// It's only supported by path-based database and will return an error for
// others.
func (db *Database) SetBufferSize(size int) error {
	pdb, ok := db.backend.(*pathdb.Database)
	if !ok {
		return errors.New("not supported")
	}
	return pdb.SetBufferSize(size)
}

func (db *Database) Copy() *Database {
	return &Database{
		config:     db.config.copy(),
		diskdb:     db.diskdb,
		preimages:  db.preimages,
		backend:    db.backend,
		rawDirties: db.rawDirties,
	}
}
