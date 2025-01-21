package core

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/holiman/uint256"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
	"github.com/zircuit-labs/l2-geth-public/core/rawdb"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/trie"
)

type ZKStateMigrator struct {
	bc         *BlockChain
	db         ethdb.Database
	indexDb    ethdb.Database
	genesis    *Genesis
	head       uint64      // the next block to be processed
	parentRoot common.Hash // ZKTrie root on the last block processed
	untilBlock uint64      // the number of the switch block
	log        log.Logger

	retries int
	period  time.Duration
	done    chan struct{}
}

var (
	zkTrieHeadKey     = []byte("head")
	zkTriePrevRootKey = []byte("prevRoot")
)

func NewZKStateMigrator(db ethdb.Database, bc *BlockChain, genesis *Genesis, untilBlock uint64) *ZKStateMigrator {
	var (
		indexDb = rawdb.NewTable(db, string(rawdb.ZKTrieIndexPrefix))
		logger  = log.New("who", "zk_state_migrator")
		// skipping "not found" errors, which can't be expected due to being spread across different implementations
		head, _     = indexDb.Get(zkTrieHeadKey)
		prevRoot, _ = indexDb.Get(zkTriePrevRootKey)
	)

	if len(head) != 8 {
		if len(head) != 0 {
			logger.Warn("Invalid data stored in zkTrieHeadKey", "head", hexutil.Encode(head))
		}
		head = make([]byte, 8)
		binary.BigEndian.PutUint64(head, 0)
	}

	return &ZKStateMigrator{
		bc:         bc,
		db:         db,
		indexDb:    indexDb,
		genesis:    genesis,
		head:       binary.BigEndian.Uint64(head),
		parentRoot: common.BytesToHash(prevRoot),
		untilBlock: untilBlock,
		log:        logger,
		retries:    0,
		done:       make(chan struct{}),
	}
}

func (z *ZKStateMigrator) WithRetry(retries int, period time.Duration) *ZKStateMigrator {
	z.retries = retries
	z.period = period
	return z
}

func (z *ZKStateMigrator) Start(ctx context.Context) (err error) {
	if params.ZKTrieEnabled.Load() {
		z.log.Warn("ZKTrie is already globally enabled, migrator will not start")
		close(z.done)
		return nil
	}

	defer func() {
		if err == nil {
			params.ZKTrieEnabled.Store(true)
			z.bc.zkTrieCache = z.bc.triedb.Copy()
			z.bc.zkTrieCache.SetIsZktrie(true)
		}
		close(z.done)
	}()

	defer func() {
		if rvr := recover(); rvr != nil {
			err = fmt.Errorf("ZKStateMigrator panicked: %v", rvr)
		}
	}()

	if err = z.run(ctx); err == nil {
		return nil
	}

	t := time.NewTicker(z.period)
	defer t.Stop()

	for i := 1; i <= z.retries; i++ {
		select {
		case <-ctx.Done():
			z.log.Warn("Context cancelled, stopping ZKTrie migration")
			return nil
		case <-t.C:
			z.log.Warn("Retrying ZKTrie migration", "attempt", i, "error", err)
			if err = z.run(ctx); err == nil {
				return nil
			}
		}
	}

	return fmt.Errorf("migrate to zkTrie after %d retries: %w", z.retries, err)
}

func (z *ZKStateMigrator) run(ctx context.Context) error {
	if z.head == 0 {
		z.log.Info("Starting migration from genesis block")
		if err := z.ensureGenesis(); err != nil {
			return fmt.Errorf("ensure genesis: %w", err)
		}

		z.log.Debug("Genesis block ensured", "trie_state_root", z.genesis.StateHash)
		if err := z.processGenesis(); err != nil {
			return fmt.Errorf("process genesis with ZKTrie: %w", err)
		}

		z.head++
		if err := z.storeMigrationState(); err != nil {
			return fmt.Errorf("store genesis migration state: %w", err)
		}
		z.log.Info("Genesis block processed", "root", z.parentRoot.Hex())
	}

	z.log.Trace("Running migration event loop", "head", z.head, "untilBlock", z.untilBlock)
	return z.eventLoop(ctx)
}

func (z *ZKStateMigrator) eventLoop(ctx context.Context) error {
	for {
		if z.head >= z.untilBlock { // exclusive - must be on ZKTrie right at the switch block
			z.log.Info("Migration finished", "head", z.head, "untilBlock", z.untilBlock, "root", z.parentRoot.Hex())
			return nil
		}

		select {
		case <-ctx.Done():
			z.log.Warn("Context cancelled, stopping ZKTrie migration")
			return nil
		default:
			z.log.Trace("Processing block sequentially", "block", z.head)
			block := z.bc.GetBlockByNumber(z.head)
			if block == nil {
				num := z.bc.CurrentHeader().Number.Uint64()
				if z.head <= num {
					return fmt.Errorf("block before head not found [block=%d head=%d]", z.head, num)
				}
				z.log.Info("Migrated sequentially to current head, switching to subscription", "zk_trie_head", z.head, "chain_head", num)
				return z.subscribe(ctx)
			}

			if err := z.process(block); err != nil {
				return fmt.Errorf("process block [num=%d]: %w", z.head, err)
			}
		}
	}
}

func (z *ZKStateMigrator) subscribe(ctx context.Context) error {
	ch := make(chan ChainHeadEvent)
	sub := z.bc.SubscribeChainHeadEvent(ch)
	defer sub.Unsubscribe()

	for {
		if z.head >= z.untilBlock {
			z.log.Info("Migration finished", "head", z.head, "untilBlock", z.untilBlock)
			return nil
		}

		select {
		case <-ctx.Done():
			z.log.Warn("Context cancelled, stopping ZKTrie migration")
			return nil
		case head := <-ch:
			num := head.Block.NumberU64()
			z.log.Trace("Received block from subscription", "block", num)
			if z.head != num {
				return fmt.Errorf("subscription block number mismatch [expected=%d, got=%d]", z.head, num)
			}
			if err := z.process(head.Block); err != nil {
				return fmt.Errorf("process header [num=%d]: %w", num, err)
			}
		}
	}
}

func (z *ZKStateMigrator) process(block *types.Block) error {
	cachingDb := state.NewDatabaseWithNodeDB(z.db, trie.NewDatabase(z.db, &trie.Config{IsZktrie: true}))

	stateDb, err := state.New(z.parentRoot, cachingDb, nil)
	if err != nil {
		return fmt.Errorf("open state zktrie with root=%x: %w", z.parentRoot, err)
	}

	_, _, _, err = z.bc.processor.Process(block, stateDb, z.bc.vmConfig)
	if err != nil {
		return fmt.Errorf("process state with zktrie: %w", err)
	}

	root, err := stateDb.Commit(block.Number().Uint64(), true)
	if err != nil {
		return fmt.Errorf("commit StateDB zktrie: %w", err)
	}

	if err = cachingDb.TrieDB().Commit(root, false); err != nil {
		return fmt.Errorf("commit Database zktrie: %w", err)
	}
	// assign here, because only at TrieDB().Commit the root is persisted, which
	// allows us to open StateDB at correct root in case of failure
	z.parentRoot = root

	z.head++
	if err = z.storeMigrationState(); err != nil {
		return fmt.Errorf("store migration state: %w", err)
	}

	z.log.Debug("Processed block with ZKTrie", "block", block.NumberU64(), "zk_trie_head", z.head, "new_root", root.Hex())
	return nil
}

func (z *ZKStateMigrator) storeMigrationState() error {
	head := make([]byte, 8)
	binary.BigEndian.PutUint64(head, z.head)
	z.log.Trace("Storing migration state", "head", fmt.Sprintf("0x%x", head), "root", z.parentRoot.Hex())

	if err := z.indexDb.Put(zkTrieHeadKey, head); err != nil {
		return fmt.Errorf("write latest head to index db: %w", err)
	}

	if err := z.indexDb.Put(zkTriePrevRootKey, z.parentRoot.Bytes()); err != nil {
		return fmt.Errorf("write latest root to index db: %w", err)
	}

	return nil
}

func (z *ZKStateMigrator) ensureGenesis() error {
	if z.genesis != nil {
		return nil
	}
	genesis, err := ReadGenesis(z.db)
	if err != nil {
		return fmt.Errorf("read genesis: %w", err)
	}
	z.genesis = genesis
	return nil
}

// processGenesis logic is copied from Genesis.flush() and related functions
func (z *ZKStateMigrator) processGenesis() error {
	triedb := trie.NewDatabase(z.db, &trie.Config{IsZktrie: true})
	statedb, err := state.New(types.EmptyZkTrieRootHash, state.NewDatabaseWithNodeDB(z.db, triedb), nil)
	if err != nil {
		return fmt.Errorf("open statedb with empty root: %w", err)
	}

	for addr, account := range z.genesis.Alloc {
		if account.Balance != nil {
			statedb.AddBalance(addr, uint256.MustFromBig(account.Balance))
		}
		statedb.SetCode(addr, account.Code)
		statedb.SetNonce(addr, account.Nonce)
		for key, value := range account.Storage {
			statedb.SetState(addr, key, value)
		}
	}

	z.log.Trace("Wrote genesis allocations to ZKTrie", "count", len(z.genesis.Alloc))
	root, err := statedb.Commit(0, false)
	if err != nil {
		return fmt.Errorf("commit statedb: %w", err)
	}

	if root != types.EmptyZkTrieRootHash {
		if err = triedb.Commit(root, true); err != nil {
			return fmt.Errorf("commit new root to zktrie: %w", err)
		}
		z.parentRoot = root
	}

	return nil
}
