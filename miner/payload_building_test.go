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
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>

package miner

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"math/big"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zircuit-labs/l2-geth/beacon/engine"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/consensus"
	"github.com/zircuit-labs/l2-geth/consensus/beacon"
	"github.com/zircuit-labs/l2-geth/consensus/clique"
	"github.com/zircuit-labs/l2-geth/consensus/ethash"
	"github.com/zircuit-labs/l2-geth/consensus/misc/eip1559"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/rawdb"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/txpool"
	"github.com/zircuit-labs/l2-geth/core/txpool/legacypool"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/ethdb"
	"github.com/zircuit-labs/l2-geth/params"
)

var (
	// Test chain configurations
	testTxPoolConfig  legacypool.Config
	ethashChainConfig *params.ChainConfig
	cliqueChainConfig *params.ChainConfig

	// Test accounts
	testBankKey, _  = crypto.GenerateKey()
	testBankAddress = crypto.PubkeyToAddress(testBankKey.PublicKey)
	testBankFunds   = big.NewInt(1000000000000000000)

	testUserKey, _  = crypto.GenerateKey()
	testUserAddress = crypto.PubkeyToAddress(testUserKey.PublicKey)

	testRecipient = common.HexToAddress("0xdeadbeef")
	testTimestamp = uint64(time.Now().Unix())

	// Test transactions
	pendingTxs []*types.Transaction
	newTxs     []*types.Transaction

	testConfig = Config{
		PendingFeeRecipient: testBankAddress,
		Recommit:            time.Second,
		GasCeil:             50_000_000,
	}
)

const (
	numDAFilterTxs = 256
)

var (
	zero               = uint64(0)
	validEIP1559Params = eip1559.EncodeHolocene1559Params(250, 6)
)

func init() {
	testTxPoolConfig = legacypool.DefaultConfig
	testTxPoolConfig.Journal = ""
	ethashChainConfig = new(params.ChainConfig)
	*ethashChainConfig = *params.TestChainConfig
	cliqueChainConfig = new(params.ChainConfig)
	*cliqueChainConfig = *params.TestChainConfig
	cliqueChainConfig.Clique = &params.CliqueConfig{
		Period: 10,
		Epoch:  30000,
	}

	signer := types.LatestSigner(params.TestChainConfig)
	tx1 := types.MustSignNewTx(testBankKey, signer, &types.AccessListTx{
		ChainID:  params.TestChainConfig.ChainID,
		Nonce:    0,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	pendingTxs = append(pendingTxs, tx1)

	tx2 := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    1,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(params.InitialBaseFee),
	})
	newTxs = append(newTxs, tx2)
}

// testWorkerBackend implements worker.Backend interfaces and wraps all information needed during the testing.
type testWorkerBackend struct {
	db      ethdb.Database
	txPool  *txpool.TxPool
	chain   *core.BlockChain
	genesis *core.Genesis
}

func newTestWorkerBackend(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, n int) *testWorkerBackend {
	gspec := &core.Genesis{
		Config: chainConfig,
		Alloc:  types.GenesisAlloc{testBankAddress: {Balance: testBankFunds}},
	}
	switch e := engine.(type) {
	case *clique.Clique:
		gspec.ExtraData = make([]byte, 32+common.AddressLength+crypto.SignatureLength)
		copy(gspec.ExtraData[32:32+common.AddressLength], testBankAddress.Bytes())
		e.Authorize(testBankAddress)
	case *ethash.Ethash, *beacon.Beacon:
	default:
		t.Fatalf("unexpected consensus engine type: %T", engine)
	}
	if chainConfig.HoloceneTime != nil {
		gspec.ExtraData = eip1559.EncodeHoloceneExtraData(250, 6)
	}
	chain, err := core.NewBlockChain(db, gspec, engine, &core.BlockChainConfig{ArchiveMode: true})
	if err != nil {
		t.Fatalf("core.NewBlockChain failed: %v", err)
	}
	pool := legacypool.New(testTxPoolConfig, chain, sls.DisabledConfig, sls.DisabledRefreshables)
	txpool, _ := txpool.New(testTxPoolConfig.PriceLimit, chain, []txpool.SubPool{pool})

	return &testWorkerBackend{
		db:      db,
		chain:   chain,
		txPool:  txpool,
		genesis: gspec,
	}
}

func (b *testWorkerBackend) BlockChain() *core.BlockChain { return b.chain }
func (b *testWorkerBackend) TxPool() *txpool.TxPool       { return b.txPool }
func (b *testWorkerBackend) ChainDb() ethdb.Database      { return nil }

func newTestWorker(t *testing.T, chainConfig *params.ChainConfig, engine consensus.Engine, db ethdb.Database, blocks int) (*Miner, *testWorkerBackend) {
	backend := newTestWorkerBackend(t, chainConfig, engine, db, blocks)
	backend.txPool.Add(pendingTxs, true, false)
	w := New(backend, &testConfig, engine, sls.DisabledRefreshables)
	return w, backend
}

func TestBuildPayload(t *testing.T) {
	t.Run("no-tx-pool", func(t *testing.T) { testBuildPayload(t, true, false, nil, params.TestChainConfig) })
	// no-tx-pool case with interrupt not interesting because no-tx-pool doesn't run
	// the builder routine
	t.Run("with-tx-pool", func(t *testing.T) { testBuildPayload(t, false, false, nil, params.TestChainConfig) })
	t.Run("with-tx-pool-interrupt", func(t *testing.T) { testBuildPayload(t, false, true, nil, params.TestChainConfig) })

	t.Run("with-params-holocene", func(t *testing.T) { testBuildPayload(t, false, false, validEIP1559Params, holoceneConfig()) })
	t.Run("with-params-no-tx-pool-holocene", func(t *testing.T) { testBuildPayload(t, true, false, validEIP1559Params, holoceneConfig()) })
	t.Run("with-params-interrupt-holocene", func(t *testing.T) { testBuildPayload(t, false, true, validEIP1559Params, holoceneConfig()) })
	zeroParams := make([]byte, 8)
	t.Run("with-zero-params-holocene", func(t *testing.T) { testBuildPayload(t, true, false, zeroParams, holoceneConfig()) })
}

func TestCreateRejectedPayloadEnvelopeSLSError(t *testing.T) {
	t.Parallel()
	depositTx := types.NewTx(&types.DepositTx{Value: big.NewInt(0)})
	tests := []struct {
		name             string
		excludedDeposits []common.Hash
		slsErr           *slsCommon.WorkerError
		expectFlag       bool
		expectErr        bool
	}{
		{
			name:             "No transactions flagged",
			excludedDeposits: []common.Hash{},
			slsErr:           &slsCommon.WorkerError{PoolTransactionsFlagged: false},
			expectFlag:       false,
		},
		{
			name:             "Some transactions flagged",
			slsErr:           &slsCommon.WorkerError{PoolTransactionsFlagged: true, DepositTransactionsFlagged: true},
			excludedDeposits: []common.Hash{depositTx.Hash()},
			expectFlag:       true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			envelope := createRejectedPayloadEnvelopeSLSError(tt.excludedDeposits, tt.slsErr)

			if envelope.RejectedPayloadM.BlockFailedSLS != tt.expectFlag {
				t.Errorf("BlockFailedSLS mismatch, got %v, want %v", envelope.RejectedPayloadM.BlockFailedSLS, tt.expectFlag)
			}

			assert.Equal(t, tt.excludedDeposits, envelope.RejectedPayloadM.TxsRejectedBySLS)
		})
	}
}

func TestResolveWithSLSError(t *testing.T) {
	t.Parallel()

	slsErr := &slsCommon.WorkerError{PoolTransactionsFlagged: true}
	payload := &Payload{
		id:        engine.PayloadID{0x1},
		stop:      make(chan struct{}),
		cond:      sync.NewCond(&sync.Mutex{}),
		interrupt: new(atomic.Int32),
		DepositExclusionsM: &depositExclusionsMeta{
			RejectedTxs:             make(map[common.Hash]struct{}),
			PoolTransactionsFlagged: false,
		},
		err: slsErr,
	}

	envelope := payload.Resolve()

	if envelope == nil || envelope.ExecutionErr == nil {
		t.Fatal("Expected a non-nil ExecutionPayloadEnvelope with error")
	}

	if envelope.ExecutionErr.Err != slsErr.Error() {
		t.Fatalf("Expected error %v, got %v", slsErr.Error(), envelope.ExecutionErr.Err)
	}

	if envelope.RejectedPayloadM == nil || !envelope.RejectedPayloadM.BlockFailedSLS {
		t.Fatal("Expected BlockFailedSLS to be true in RejectedPayloadMeta")
	}
}

func TestPayloadUpdateWithSLSError(t *testing.T) {
	t.Parallel()

	payload := &Payload{
		id:        engine.PayloadID{0x1},
		stop:      make(chan struct{}),
		interrupt: new(atomic.Int32),
		DepositExclusionsM: &depositExclusionsMeta{
			RejectedTxs:             make(map[common.Hash]struct{}),
			PoolTransactionsFlagged: false,
		},
	}
	payload.cond = sync.NewCond(&payload.lock)

	slsErr := &slsCommon.WorkerError{PoolTransactionsFlagged: true, DepositTransactionsFlagged: true}

	result := &newPayloadResult{
		err:               slsErr,
		depositExclusions: nil,
		block:             types.NewBlockWithHeader(&types.Header{Number: big.NewInt(123)}),
		fees:              big.NewInt(0),
	}

	payload.update(result, time.Millisecond)

	if !errors.Is(slsErr, payload.err) {
		t.Fatalf("Expected payload.err to be %v, got %v", slsErr, payload.err)
	}

	if !payload.DepositExclusionsM.PoolTransactionsFlagged {
		t.Fatal("Expected PoolTransactionsFlagged to be true")
	}

	if payload.full != nil {
		t.Fatal("Expected no full block to be set due to SLS error")
	}
}

func TestBuildPayloadError(t *testing.T) {
	t.Run("pre-holocene-with-params", func(t *testing.T) {
		cfg := holoceneConfig()
		cfg.HoloceneTime = nil
		testBuildPayloadError(t, cfg,
			"got eip1559 params, expected none",
			func(args *BuildPayloadArgs) { args.EIP1559Params = validEIP1559Params })
	})
	t.Run("holocene-no-params", func(t *testing.T) {
		testBuildPayloadError(t, holoceneConfig(),
			"holocene eip-1559 params should be 8 bytes, got 0",
			func(args *BuildPayloadArgs) { args.EIP1559Params = nil })
	})
	t.Run("holocene-bad-params", func(t *testing.T) {
		testBuildPayloadError(t, holoceneConfig(),
			"holocene params cannot have a 0 denominator unless elasticity is also 0",
			func(args *BuildPayloadArgs) { args.EIP1559Params = eip1559.EncodeHolocene1559Params(0, 6) })
	})
}

func holoceneConfig() *params.ChainConfig {
	config := *params.OptimismTestConfig
	config.HoloceneTime = &zero
	config.IsthmusTime = nil
	config.PragueTime = nil
	config.OsakaTime = nil
	return &config
}

func isthmusConfig() *params.ChainConfig {
	config := holoceneConfig()
	config.IsthmusTime = &zero
	config.PragueTime = &zero
	return config
}

// newPayloadArgs returns valid BuildPaylooadArgs for the given chain config with the given parentHash,
// testTimestamp for Timestamp, and testRecipient for recipient.
// OP-Stack chains will have one dummy deposit transaction in Transactions.
// NoTxPool is set to true.
// A test can modify individual fields afterwards to enable the transaction
// pool, create invalid eip-1559 params, minBaseFee, etc.
func newPayloadArgs(parentHash common.Hash, cfg *params.ChainConfig) *BuildPayloadArgs {
	args := &BuildPayloadArgs{
		Parent:       parentHash,
		Timestamp:    testTimestamp,
		FeeRecipient: testRecipient,
		Withdrawals:  types.Withdrawals{},
		NoTxPool:     true,
	}

	if !cfg.IsOptimism() {
		return args
	}

	if cfg.IsHolocene(args.Timestamp) {
		args.EIP1559Params = validEIP1559Params
	}
	dtx := new(types.DepositTx)
	args.Transactions = []*types.Transaction{types.NewTx(dtx)}

	return args
}

func testBuildPayload(t *testing.T, noTxPool, interrupt bool, params1559 []byte, config *params.ChainConfig) {
	t.Parallel()
	db := rawdb.NewMemoryDatabase()

	w, b := newTestWorker(t, config, ethash.NewFaker(), db, 0)

	const numInterruptTxs = 256

	if interrupt {
		// when doing interrupt testing, create a large pool so interruption will
		// definitely be visible.
		txs := genTxs(1, numInterruptTxs)
		b.txPool.Add(txs, false, false)
	}

	args := newPayloadArgs(b.chain.CurrentBlock().Hash(), config)
	args.NoTxPool = noTxPool
	args.EIP1559Params = params1559

	// payload resolution now interrupts block building, so we have to
	// wait for the payloading building process to build its first block
	payload, err := w.buildPayload(args)
	if err != nil {
		t.Fatalf("Failed to build payload %v", err)
	}
	if !interrupt {
		time.Sleep(2 * time.Second)
	}
	verify := func(outer *engine.ExecutionPayloadEnvelope, txs int) {
		t.Helper()
		if config.IsOptimism() {
			txs++ // account for dummy deposit tx
		}
		if outer == nil {
			t.Fatal("ExecutionPayloadEnvelope is nil")
		}
		payload := outer.ExecutionPayload
		if payload.ParentHash != b.chain.CurrentBlock().Hash() {
			t.Fatal("Unexpected parent hash")
		}
		if payload.Random != (common.Hash{}) {
			t.Fatal("Unexpected random value")
		}
		if payload.Timestamp != testTimestamp {
			t.Fatal("Unexpected timestamp")
		}
		if payload.FeeRecipient != testRecipient {
			t.Fatal("Unexpected fee recipient")
		}

		if !interrupt && len(payload.Transactions) != txs {
			t.Fatalf("Unexpect transaction set: got %d, expected %d", len(payload.Transactions), txs)
		} else if interrupt && len(payload.Transactions) >= txs {
			t.Fatalf("Unexpect transaction set: got %d, expected less than %d", len(payload.Transactions), txs)
		}
	}
	// OP-Stack: we only build the empty payload if noTxPool is set.
	if args.NoTxPool {
		empty := payload.ResolveEmpty()
		verify(empty, 0)
	}

	// make sure the 1559 params we've specied (if any) ends up in both the full and empty block headers
	var expected []byte
	if len(params1559) != 0 {
		versionByte := eip1559.HoloceneExtraDataVersionByte
		expected = []byte{versionByte}

		d, _ := eip1559.DecodeHolocene1559Params(params1559)
		if d == 0 {
			expected = append(expected, eip1559.EncodeHolocene1559Params(10, 50)...)
		} else {
			expected = append(expected, params1559...)
		}
	}
	if payload.full != nil && !bytes.Equal(payload.full.Header().Extra, expected) {
		t.Fatalf("ExtraData doesn't match. want: %x, got %x", expected, payload.full.Header().Extra)
	}
	if payload.empty != nil && !bytes.Equal(payload.empty.Header().Extra, expected) {
		t.Fatalf("ExtraData doesn't match on empty block. want: %x, got %x", expected, payload.empty.Header().Extra)
	}

	// Test extraData
	if payload.full != nil && len(params1559) != 0 {
		d, e := eip1559.DecodeHoloceneExtraData(payload.full.Header().Extra)

		expectedDenominator := binary.BigEndian.Uint32(params1559[:4])
		expectedElasticity := binary.BigEndian.Uint32(params1559[4:])
		if expectedDenominator == 0 {
			expectedDenominator = 10
			expectedElasticity = 50
		}
		if d != uint64(expectedDenominator) {
			t.Fatalf("denominator doesn't match. want: %d, got %d", expectedDenominator, d)
		}
		if e != uint64(expectedElasticity) {
			t.Fatalf("elasticity doesn't match. want: %d, got %d", expectedElasticity, e)
		}
	}

	if noTxPool {
		// we only build the empty block when ignoring the tx pool
		empty := payload.ResolveEmpty()
		verify(empty, 0)
		full := payload.ResolveFull()
		verify(full, 0)
	} else if interrupt {
		full := payload.ResolveFull()
		verify(full, len(pendingTxs)+numInterruptTxs)
	} else { // tx-pool and no interrupt
		payload.WaitFull()
		full := payload.ResolveFull()
		verify(full, len(pendingTxs))
	}

	// Ensure resolve can be called multiple times and the
	// result should be unchanged
	dataOne := payload.Resolve()
	dataTwo := payload.Resolve()
	if !reflect.DeepEqual(dataOne, dataTwo) {
		t.Fatal("Unexpected payload data")
	}
}

func testBuildPayloadError(t *testing.T, config *params.ChainConfig, expErrStr string, mod func(*BuildPayloadArgs)) {
	t.Parallel()
	db := rawdb.NewMemoryDatabase()
	w, b := newTestWorker(t, config, ethash.NewFaker(), db, 0)

	args := newPayloadArgs(b.chain.CurrentBlock().Hash(), config)
	mod(args)
	payload, err := w.buildPayload(args)
	require.Nil(t, payload)
	if err != nil {
		require.ErrorContains(t, err, expErrStr)
	} else if payload.err != nil {
		require.ErrorContains(t, payload.err, expErrStr)
	} else {
		t.Fatalf("expected error, got none")
	}
}

func genTxs(startNonce, count uint64) types.Transactions {
	txs := make(types.Transactions, 0, count)
	signer := types.LatestSigner(params.TestChainConfig)
	for nonce := startNonce; nonce < startNonce+count; nonce++ {
		// generate incompressible data to put in the tx for DA filter testing. each of these
		// txs will be bigger than the 100 minimum.
		randomBytes := make([]byte, 100)
		_, err := rand.Read(randomBytes)
		if err != nil {
			panic(err)
		}
		tx := types.MustSignNewTx(testBankKey, signer, &types.AccessListTx{
			ChainID:  params.TestChainConfig.ChainID,
			Nonce:    nonce,
			To:       &testUserAddress,
			Value:    big.NewInt(1000),
			Gas:      params.TxGas + uint64(len(randomBytes))*40,
			GasPrice: big.NewInt(params.InitialBaseFee),
			Data:     randomBytes,
		})
		txs = append(txs, tx)
	}
	return txs
}

func TestPayloadId(t *testing.T) {
	t.Parallel()
	ids := make(map[string]int)
	for i, tt := range []*BuildPayloadArgs{
		{
			Parent:       common.Hash{1},
			Timestamp:    1,
			Random:       common.Hash{0x1},
			FeeRecipient: common.Address{0x1},
		},
		// Different parent
		{
			Parent:       common.Hash{2},
			Timestamp:    1,
			Random:       common.Hash{0x1},
			FeeRecipient: common.Address{0x1},
		},
		// Different timestamp
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x1},
			FeeRecipient: common.Address{0x1},
		},
		// Different Random
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x1},
		},
		// Different fee-recipient
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
		},
		// Different withdrawals (non-empty)
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
			Withdrawals: []*types.Withdrawal{
				{
					Index:     0,
					Validator: 0,
					Address:   common.Address{},
					Amount:    0,
				},
			},
		},
		// Different withdrawals (non-empty)
		{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
			Withdrawals: []*types.Withdrawal{
				{
					Index:     2,
					Validator: 0,
					Address:   common.Address{},
					Amount:    0,
				},
			},
		},
	} {
		id := tt.Id().String()
		if prev, exists := ids[id]; exists {
			t.Errorf("ID collision, case %d and case %d: id %v", prev, i, id)
		}
		ids[id] = i
	}
}

// OPStack addition
func TestDeterministicPayloadId(t *testing.T) {
	makeArgs := func() *BuildPayloadArgs {
		return &BuildPayloadArgs{
			Parent:       common.Hash{2},
			Timestamp:    2,
			Random:       common.Hash{0x2},
			FeeRecipient: common.Address{0x2},
		}
	}

	id1 := makeArgs().Id().String()
	id2 := makeArgs().Id().String()
	require.Equal(t, id1, id2)
}
