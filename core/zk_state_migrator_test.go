package core

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/consensus/ethash"
	"github.com/zircuit-labs/l2-geth-public/core/rawdb"
	"github.com/zircuit-labs/l2-geth-public/core/state"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/params"
	"github.com/zircuit-labs/l2-geth-public/trie"
	"github.com/zircuit-labs/l2-geth-public/trie/triedb/hashdb"
)

const (
	defaultBlocksCount uint64 = 10
	halfBlocksCount    uint64 = 5
)

var trieChainRoots = []string{
	"0x2a818fd589c562e83d4a38bb9a779166ded29dcc85c32782025b8745f8c04f65",
	"0x36adac229116786f2608acdf788efbeb91cfd60a3bd093848d6913d8bfb81a32",
	"0x9f7c2925a31b3e18f495f2cd289c0c71a39899db8db33b7f660559a24b4f28f5",
	"0x4251587cf20d5ca54c8f2a13c31af244b7dc958f09a8d6ba41c01c9f26a212ad",
	"0x233a187ebb0f06a80a4540c4ff8c804deab08887c75d9128263215ced7747792",
	"0x1d7f07c7dfb9c45df4ef37eaa2d0d9005313da3fc1aeaf6b1e47778e294aae23",
	"0x4493a7f0715428c2db5110a147299f2659ec4e82f2d4b059d85a267af9721f60",
	"0x6db7d338a92efa527b2cd5952ca7a5317e550deb1733f84f5e3b73a76a243f15",
	"0x1bf238bd56e83d4cee1f70912dbba0bd30da09ddfdb38d15068fbb599c94e24c",
	"0xfcb8264be224e408e562b2e96b58d084f37e58ea5b0ba0667d7837764e57d29a",
}

var zkTrieChainRoots = []string{
	"0x1884281fd48f7f9c9e4776f39e84fefaaa909208f8d1ec036e0181db5df3722c",
	"0x1a3031b4e8c07d25f8ce8831b384a834d9e90c23ac11e57b840feda6654756f3",
	"0x2eb85904f86d37d91f78d96059fe35e10cb65734696b217bbf4baabe3c3883b1",
	"0x07d7f4e8240938a4c7e7380f2f16c8de2de3d80e3ddae3be78083430fa3ba67b",
	"0x09848d43afd61060819096ad703325d7185942396306fb0b2999c750d385edf3",
	"0x0a61d0b4411f90bd3132c73129d56d47201cad430f0d2dd66b0e5329d3499340",
	"0x2c9d2749b6968b045dee5e9c6e716c0ba2c9a6c1fef3fd9da723229f55367b08",
	"0x1ef9070b5c392dde954c724fd7d8d9980af2966396540ac6a974c3f6ea3bd972",
	"0x27c510a7d13bacda93015077b08ac0313b86d6ab543f3279d12f7d0519395257",
	"0x0880e38135adfad6119e1cb7b96017cdf3317ccf47732bbb33bf3ec8385af416",
}

func TestMigrationToZKTrie(t *testing.T) {
	bc, genesis, db := newTrieChain(t, defaultBlocksCount, rawdb.PathScheme)

	runMigration(t, db, bc, genesis, defaultBlocksCount+1)
	checkZKTriePersisted(t, common.HexToHash(zkTrieChainRoots[defaultBlocksCount-1]), db)
	compareStateRoots(t, bc, false, 1, defaultBlocksCount) // old blocks remain unchanged
}

func newTrieChain(t *testing.T, blocksCount uint64, scheme string) (*BlockChain, *Genesis, ethdb.Database) {
	t.Helper()

	db, genesis, bc, err := newCanonical(ethash.NewFaker(), int(blocksCount), true, scheme)
	require.NoError(t, err)

	t.Cleanup(func() {
		bc.Stop()
		params.ZKTrieEnabled.Store(false)
	})

	return bc, genesis, db
}

func runMigration(t *testing.T, db ethdb.Database, bc *BlockChain, genesis *Genesis, endBlock uint64) {
	migrator := NewZKStateMigrator(db, bc, genesis, endBlock)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	require.NoError(t, migrator.Start(ctx))
}

func TestMigrationInterruption(t *testing.T) {
	bc, genesis, db := newTrieChain(t, defaultBlocksCount, rawdb.PathScheme)

	runMigration(t, db, bc, genesis, halfBlocksCount+1)
	checkZKTriePersisted(t, common.HexToHash(zkTrieChainRoots[halfBlocksCount-1]), db)
	compareStateRoots(t, bc, false, 1, halfBlocksCount)

	// Restart migration from where it was interrupted
	params.ZKTrieEnabled.Store(false)
	runMigration(t, db, bc, genesis, defaultBlocksCount+1)
	checkZKTriePersisted(t, common.HexToHash(zkTrieChainRoots[defaultBlocksCount-1]), db)
	// it's still an old Trie state from newCanonical
	compareStateRoots(t, bc, false, halfBlocksCount+1, defaultBlocksCount)
}

func TestMigrationStartOnSpecificBlock(t *testing.T) {
	bc, genesis, db := newTrieChain(t, halfBlocksCount, rawdb.PathScheme)
	params.ZKTrieEnabled.Store(false)
	migrator := NewZKStateMigrator(bc.db, bc, genesis, defaultBlocksCount+1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var finished bool
	var wg sync.WaitGroup
	go func() {
		wg.Add(1)
		require.NoError(t, migrator.Start(ctx))
		finished = true
		wg.Done()
	}()

	assert.Equal(t, common.Hash{}, migrator.parentRoot, "migrator shouldn't have been running yet")
	assert.False(t, finished)

	// insert the second part of the chain
	newChain := makeBlockChain(bc.chainConfig, bc.GetBlockByHash(bc.CurrentBlock().Hash()), int(halfBlocksCount), ethash.NewFaker(), db, forkSeed)
	_, err := bc.InsertChain(newChain)
	require.NoError(t, err)
	params.ZKTrieEnabled.Store(true)

	wg.Wait()
	assert.True(t, finished)
}

func compareStateRoots(t *testing.T, bc *BlockChain, isZKTrie bool, from, to uint64) {
	t.Helper()

	roots := trieChainRoots
	if isZKTrie {
		roots = zkTrieChainRoots
	}

	for i := from; i < to; i++ {
		header := bc.GetHeaderByNumber(i)
		require.NotNil(t, header)
		assert.Equal(t, roots[i-1], header.Root.String())
	}
}

func checkZKTriePersisted(t *testing.T, root common.Hash, db ethdb.Database) {
	t.Helper()

	sdb := state.NewDatabaseWithNodeDB(db, trie.NewDatabase(db, &trie.Config{
		HashDB:   hashdb.Defaults,
		IsZktrie: true,
	}))

	assert.True(t, sdb.TrieDB().IsZktrie())
	sdb2, err := state.New(root, sdb, nil)
	require.NoError(t, err)
	assert.True(t, sdb2.IsZktrie())
	assert.Equal(t, root, sdb2.GetRootHash())
}
