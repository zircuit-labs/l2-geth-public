package miner

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/consensus/beacon"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/rawdb"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	sls "github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/txpool"
	"github.com/zircuit-labs/l2-geth/core/txpool/legacypool"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/core/vm"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/params"
)

const (
	// whalekillerBeaconRootsBytecode is the EIP-4788 contract used post-merge.
	whalekillerBeaconRootsBytecode = "3373fffffffffffffffffffffffffffffffffffffffe14604d57602036146024575f5ffd5b5f35801560495762001fff810690815414603c575f5ffd5b62001fff01545f5260205ff35b5f5ffd5b62001fff42064281555f359062001fff015500"
)

// TestWorkerWhalekillerTransactions exercises a minimal happy-path in Whalekiller
// mode: three ordinary L2 txs should all land successfully in a single block.
func TestWorkerWhalekillerTransactions(t *testing.T) {
	key, addr := newTestKeyAndAddress()

	w, backend, cfg := newWhalekillerMiner(t, key)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	baseNonce := backend.txPool.Nonce(addr)
	for i := 0; i < 3; i++ {
		tx := types.MustSignNewTx(key, signer, &types.LegacyTx{
			Nonce:    baseNonce + uint64(i),
			To:       &addr,
			Value:    big.NewInt(100),
			Gas:      params.TxGas,
			GasPrice: gasPrice,
		})
		errs := backend.txPool.Add([]*types.Transaction{tx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])
	}

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)

	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 3)

	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 3)
	for i, receipt := range receipts {
		require.Equalf(t, types.ReceiptStatusSuccessful, receipt.Status, "receipt %d", i)
	}
}

// TestWorkerWhalekillerOpcodeLimitJumpdest verifies that a transaction whose execution would exceed the
// Whalekiller tx-level JUMPDEST limit is never included in a block and is dropped from the pool since we can't process it.
func TestWorkerWhalekillerOpcodeLimitJumpdest(t *testing.T) {
	// make block limit higher
	limits := tinyCycleWhalekillerLimits(100_000, 10_000_000)

	// Set config override
	setWhalekillerOverrideForTest(t, limits)
	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	limitPair, ok := params.WhalekillerDefaultLimits.Opcodes[0x5b]
	require.True(t, ok, "missing whalekiller default for opcode 0x5b")

	// runtime code will execute JUMPDEST way more than the allowed limit when we later call it.
	iterations := int(limitPair.PerTx)*2 + 1

	gasPrice := big.NewInt(params.InitialBaseFee)

	// Deploy a loop-heavy contract that executes JUMPDEST more times than the
	// allowed per-tx threshold.
	creation := makeContractCreation(makeJumpdestHammerRuntime(iterations))
	nonce := backend.txPool.Nonce(testForcedAddress)
	createTx := types.MustSignNewTx(testForcedKey, types.LatestSigner(cfg), &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     creation,
	})
	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	// Mine the deployment before issuing the stress-call.
	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 1)
	require.Equal(t, createTx.Hash(), block.Transactions()[0].Hash())

	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	createReceipt := receipts[0]
	require.Equal(t, types.ReceiptStatusSuccessful, createReceipt.Status, "contract deployment should succeed")
	contractAddr := createReceipt.ContractAddress
	require.NotEqual(t, (common.Address{}), contractAddr)

	nonce = backend.txPool.Nonce(testForcedAddress)
	callTx := types.MustSignNewTx(testForcedKey, types.LatestSigner(cfg), &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      4_000_000,
		GasPrice: gasPrice,
	})
	errs = backend.txPool.Add([]*types.Transaction{callTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 0, "over-limit tx must not be included in block")
	receipts = backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 0, "no receipts for dropped over-limit tx")

	// Nonce must NOT advance, because the tx never made it into the block
	stateAfter := stateAtHeaderRoot(t, backend.chain, block.Header())
	require.Equal(t, nonce, stateAfter.GetNonce(testForcedAddress), "nonce must not advance when tx is dropped by miner")

	// And it should be gone from the pool
	pending := backend.txPool.Pending(false)
	for _, txs := range pending {
		for _, lazy := range txs {
			require.NotEqual(t, callTx.Hash(), lazy.Tx.Hash(), "over-limit tx should be removed from pool")
		}
	}
}

// TestWorkerGetSealingBlockWhalekillerDepositLimit verify when L1 deposit tx overflows, it should fills depositExclusions
func TestWorkerGetSealingBlockWhalekillerDepositLimit(t *testing.T) {
	limits := tinyCycleWhalekillerLimits(100_000, 100_000)
	// Set config override
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	// Deploy the jumpdest hammer contract
	limitPair, ok := params.WhalekillerDefaultLimits.Opcodes[0x5b]
	require.True(t, ok, "missing whalekiller default for opcode 0x5b")
	iterations := int(limitPair.PerTx)*2 + 1

	gasPrice := big.NewInt(params.InitialBaseFee)

	creation := makeContractCreation(makeJumpdestHammerRuntime(iterations))
	nonce := backend.txPool.Nonce(testForcedAddress)
	createTx := types.MustSignNewTx(testForcedKey, types.LatestSigner(cfg), &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     creation,
	})
	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	// Mine the deployment.
	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 1)
	require.Equal(t, createTx.Hash(), block.Transactions()[0].Hash())

	contractAddr := crypto.CreateAddress(testForcedAddress, nonce)
	require.NotEqual(t, (common.Address{}), contractAddr)

	// Build an L1 deposit tx that will hit the Whalekiller limit when executed.
	depositInner := &types.DepositTx{
		SourceHash:          common.Hash{},
		From:                testForcedAddress,
		To:                  &contractAddr,
		Mint:                big.NewInt(0),
		Value:               big.NewInt(0),
		Gas:                 4_000_000,
		IsSystemTransaction: false,
		Data:                nil,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx(), "expected a deposit tx")

	// Call generateWork with depositTx in generateParams.txs.
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx},
		checkTransactions: true,
	})

	// generateWork (via generateWork) took the Whalekiller path.
	require.Error(t, result.err, "expected generateWork to fail due to Whalekiller on deposit tx")

	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr), "err is not a WorkerError")
	require.True(t, workerErr.DepositTransactionsFlagged, "DepositTransactionsFlagged should be true")

	require.Len(t, result.depositExclusions, 1)
	require.Equal(t, depositTx.Hash(), result.depositExclusions[0])
}

// TestWorkerWhalekillerDepositOkL2TxLimit verifies that a normal L2 tx hit the tx cycle limit and should not affect deposit tx.
func TestWorkerWhalekillerDepositOkL2TxLimit(t *testing.T) {
	// make the block level threshold higher, so that the L2 tx will hit the tx-level error
	limits := tinyCycleWhalekillerLimits(100_000, 10_000_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy a "safe" contract (low iterations) for deposit tx
	safeCreation := makeContractCreation(makeJumpdestHammerRuntime(100)) // well below cycle cap
	nonce := backend.txPool.Nonce(testForcedAddress)
	safeCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     safeCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{safeCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)

	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	safeAddr := receipts[0].ContractAddress

	// Deploy a "hammer" contract (high iterations) that WILL hit Whalekiller
	hammerRuntime := makeJumpdestHammerRuntime(10_000) // big enough to exceed tinyCycle limits
	hammerCreation := makeContractCreation(hammerRuntime)

	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	hammerCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     hammerCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{hammerCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	hammerReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	hammerAddr := hammerReceipts[0].ContractAddress

	// Build a deposit to the SAFE contract (should NOT overflow Whalekiller)
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	depositInner := &types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr, // safe target
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        2_000_000,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx())

	// Build a normal L2 tx calling the HAMMER contract (will hit Whalekiller)
	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	hammerCall := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &hammerAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})
	errs = backend.txPool.Add([]*types.Transaction{hammerCall}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	// Build sealing block with forced deposit + pool tx
	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx}, // forced deposit
		checkTransactions: true,
	})

	block = result.block

	// Deposit should be fine -> no WorkerError, no exclusions
	require.NoError(t, result.err)
	require.Empty(t, result.depositExclusions)
	require.NotNil(t, block)

	// Import the block so receipts get written
	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)

	recs := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, recs, 1)

	// Only the deposit is included in this block
	require.Len(t, recs, 1)
	require.Equal(t, depositTx.Hash(), recs[0].TxHash)
	require.Equal(t, types.ReceiptStatusSuccessful, recs[0].Status)

	// The hammer tx should not be included in the block and drop from the pool since it is over tx limit
	for _, r := range recs {
		require.NotEqual(t, hammerCall.Hash(), r.TxHash, "hammer tx should not be included in the block")
	}

	require.False(t, txInPool(backend.txPool, hammerCall.Hash()), "hammer tx should be dropped after exceeding tx-level limit")
}

// TestWorkerWhalekillerDepositOkL2TxOk verifies that a deposit and a normal L2
// transaction both succeed under the tx cycle limit without any exclusions.
func TestWorkerWhalekillerDepositOkL2TxOk(t *testing.T) {
	limits := tinyCycleWhalekillerLimits(100_000, 100_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy a "safe" contract to receive the deposit (very low iterations).
	safeRuntime := makeJumpdestHammerRuntime(10) // way below cycle cap
	safeCreation := makeContractCreation(safeRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	safeCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     safeCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{safeCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	safeAddr := receipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), safeAddr)

	// Deploy a "safe" hammer contract for the L2 tx (still below cycle cap).
	hammerRuntime := makeJumpdestHammerRuntime(50) // < 200 JUMPDESTs, below tinyCycle cap
	hammerCreation := makeContractCreation(hammerRuntime)

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	hammerCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     hammerCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{hammerCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	hammerReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, hammerReceipts, 1)
	hammerAddr := hammerReceipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), hammerAddr)

	// Build a deposit to the SAFE contract (should NOT hit Whalekiller).
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	depositInner := &types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx(), "expected a deposit tx")

	// Build a normal L2 tx calling the hammer contract (also below Whalekiller cap).
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	hammerCall := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &hammerAddr,
		Gas:      1_000_000,
		GasPrice: gasPrice,
	})
	errs = backend.txPool.Add([]*types.Transaction{hammerCall}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	// Build sealing block with forced deposit + pool tx.
	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx}, // forced deposit
		checkTransactions: true,
	})

	// No Whalekiller error on deposit, no WorkerError and no exclusions.
	require.NoError(t, result.err)
	require.Empty(t, result.depositExclusions)

	block = result.block
	require.NotNil(t, block)

	// Import the block so receipts are persisted.
	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)

	recs := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, recs, 2)

	// Look up receipts by tx hash to avoid relying on ordering.
	byHash := make(map[common.Hash]*types.Receipt)
	for _, r := range recs {
		rr := r
		byHash[rr.TxHash] = rr
	}

	depositRec, ok := byHash[depositTx.Hash()]
	require.True(t, ok, "missing deposit receipt")
	hammerRec, ok := byHash[hammerCall.Hash()]
	require.True(t, ok, "missing hammer-call receipt")

	// Both should succeed.
	require.Equal(t, types.ReceiptStatusSuccessful, depositRec.Status)
	require.Equal(t, types.ReceiptStatusSuccessful, hammerRec.Status)
}

// TestWorkerWhalekillerDepositLimitL2Ok verifies that when a tx cycle limit is hit by a deposit transaction, only that deposit is excluded and
// normal L2 pool transactions remain unaffected.
func TestWorkerWhalekillerDepositLimitL2Ok(t *testing.T) {
	limits := tinyCycleWhalekillerLimits(100_000, 100_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy a "hammer" contract (high iterations) that WILL hit Whalekiller
	hammerRuntime := makeJumpdestHammerRuntime(10_000) // large loop ⇒ lots of JUMPDEST
	hammerCreation := makeContractCreation(hammerRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	hammerCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_500_000,
		GasPrice: gasPrice,
		Data:     hammerCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{hammerCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 1)
	require.Equal(t, hammerCreateTx.Hash(), block.Transactions()[0].Hash())

	hammerAddr := crypto.CreateAddress(testForcedAddress, nonce)
	require.NotEqual(t, (common.Address{}), hammerAddr)

	// Build a deposit to the HAMMER contract (this one should overflow Whalekiller).
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	depositInner := &types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &hammerAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        4_000_000, // enough gas; cycles are what will kill it
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx(), "expected a deposit tx")

	// Build a normal L2 tx that is completely safe (no Whalekiller overflow).
	// Simple self-transfer from the funded testForcedAddress.
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	l2SafeTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &testForcedAddress, // simple EOA call, no heavy opcodes
		Gas:      500_000,
		GasPrice: gasPrice,
	})
	errs = backend.txPool.Add([]*types.Transaction{l2SafeTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	// Ask the worker to build a block with the forced deposit.
	// The deposit will hit the Whalekiller cycle limiter and should add deposit exclusion for this tx.
	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx},
		checkTransactions: true,
	})

	require.Error(t, result.err, "expected generateWork to fail due to Whalekiller on deposit tx")

	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr), "err is not a WorkerError")
	require.True(t, workerErr.DepositTransactionsFlagged, "DepositTransactionsFlagged should be true")

	// Only the offending deposit should be excluded.
	require.Len(t, result.depositExclusions, 1)
	require.Equal(t, depositTx.Hash(), result.depositExclusions[0])

	// The normal L2 tx should still be pending in the pool; only the failing deposit is excluded.
	require.True(t, txInPool(backend.txPool, l2SafeTx.Hash()), "tx should be send back to pool after exceeding block-level limit")
}

// TestWorkerWhalekillerMultipleDepositsLimit verifies that when one forced deposit hits the tx cycle limit,
// ONLY that tx should be flagged in depositExclusions for the sequencer to exclude, we should try all the rest of txs.
func TestWorkerWhalekillerMultipleDepositsLimit(t *testing.T) {
	limits := tinyCycleWhalekillerLimits(100_000, 200_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy a "safe" contract (low iterations)
	safeRuntime := makeJumpdestHammerRuntime(100) // well below cycle cap
	safeCreation := makeContractCreation(safeRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	safeCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     safeCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{safeCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)

	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	safeAddr := receipts[0].ContractAddress

	// Deploy a "hammer" contract that WILL overflow Whalekiller with tiny limits.
	hammerRuntime := makeJumpdestHammerRuntime(10_000)
	hammerCreation := makeContractCreation(hammerRuntime)

	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	hammerCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     hammerCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{hammerCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	hammerReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, hammerReceipts, 1)
	hammerAddr := hammerReceipts[0].ContractAddress

	// Build three deposits:
	//    dep0: to safeAddr 65K (block = 65K)
	//    dep1: to hammerAddr (hits Whalekiller)
	//    dep2: to safeAddr again, 65K + 65K = 130K < 200K
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	dep0 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	dep1 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &hammerAddr, // this one will hit cycle tx limit
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	dep2 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr, // would be OK, but comes after failing dep1
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})

	require.True(t, dep0.IsDepositTx())
	require.True(t, dep1.IsDepositTx())
	require.True(t, dep2.IsDepositTx())

	// Call generateWork with all three deposits forced in order.
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{dep0, dep1, dep2},
		checkTransactions: true,
	})

	// Assert: Whalekiller on dep1 triggers WorkerError and excludes only dep1.
	require.Error(t, result.err, "expected Whalekiller to flag deposits")
	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr), "err is not a WorkerError")
	require.True(t, workerErr.DepositTransactionsFlagged, "DepositTransactionsFlagged should be true")

	require.Len(t, result.depositExclusions, 1, "should exclude failing deposit and subsequent deposits")
	require.Equal(t, dep1.Hash(), result.depositExclusions[0])
}

// TestWorkerWhalekillerMultipleDepositsBlockLimit verifies that when the block cycle threshold is exceeded
// by deposits (while each deposit is under the per-tx threshold), the worker returns a WorkerError and excludes the failed deposits in that payload.
func TestWorkerWhalekillerMultipleDepositsBlockLimit(t *testing.T) {
	// Per-tx and per-block caps are the same. With JUMPDEST multiplier=500 and
	// iterations=3, each deposit contributes 3*500 = 1500 cycles:
	//   per-tx    = 2000 (OK for a single deposit)
	//   per-block = 2000 (dep0=1500 OK, dep0+dep1=3000 > 2000, lead to block overflow)
	limits := params.WhalekillerLimitsConfig{
		Opcodes:          map[uint8]params.LimitPair{},
		Precompiles:      map[string]params.LimitPair{},
		OpcodeCycles:     map[uint8]uint64{0x5b: 500}, // JUMPDEST cost in cycles
		PrecompileCycles: map[string]uint64{},
		CycleTracking: &params.WhalekillerCycleTracking{
			CallOverhead:      0,
			ThresholdPerTx:    2_000,
			ThresholdPerBlock: 2_000,
		},
	}
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy a "mid" contract that does a small JUMPDEST hammer (3 iterations),
	// so a single call is under per-tx cycles, but two calls overflow per-block.
	midRuntime := makeJumpdestHammerRuntime(3) // 3 * 500 = 1500 cycles per call
	midCreation := makeContractCreation(midRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     midCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	// Mine the deployment.
	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts[0].Status)
	target := receipts[0].ContractAddress

	// Build three deposits, each individually under per-tx but together dep0 + dep1 overflow
	// the per-block cap; dep2 should be excluded as well.
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	dep0 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &target,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	dep1 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &target,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	dep2 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &target,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})

	require.True(t, dep0.IsDepositTx())
	require.True(t, dep1.IsDepositTx())
	require.True(t, dep2.IsDepositTx())

	// Build sealing block with all three forced deposits.
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{dep0, dep1, dep2},
		checkTransactions: true,
	})

	// Whalekiller should trip on dep1 for block scope, returning a WorkerError and excluding dep1 + dep2.
	require.Error(t, result.err, "expected block-scope Whalekiller to flag deposits")

	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr), "err is not a WorkerError")
	require.True(t, workerErr.DepositTransactionsFlagged, "DepositTransactionsFlagged should be true")

	require.Len(t, result.depositExclusions, 2, "deposits that overflow block limit must be excluded")
	require.Equal(t, dep1.Hash(), result.depositExclusions[0])
	require.Equal(t, dep2.Hash(), result.depositExclusions[1])
}

// TestWorkerWhalekillerDepositsAndL2AllOk verifies that two forced deposits and two
// normal L2 transactions all execute under the Whalekiller tx/block cycle limits,
// resulting in no WorkerError, no deposit exclusions, and all successful receipts.
func TestWorkerWhalekillerDepositsAndL2AllOk(t *testing.T) {
	// cap = 100_000 cycles, JUMPDEST = 500 cycles per gas unit.
	//
	// We will choose iteration counts such that:
	//   - each tx < 100_000 cycles (tx limit),
	//   - total block cycles (2 deposits + 2 L2 txs) < 100_000.
	//
	// Each txs:
	//   deposit target:  10 iterations  ->  10 * 500 = 5_000 cycles per deposit tx
	//   L2-1 target:     50 iterations  ->  50 * 500 = 25_000 cycles
	//   L2-2 target:     50 iterations  ->  50 * 500 = 25_000 cycles
	//
	// Block total:
	//   2 deposits: 2 *  5_000 = 10_000
	//   2 L2 calls: 2 * 25_000 = 50_000
	//   TOTAL: 60_000 < 100_000  -> no Whalekiller trip, under both tx and block level limit.
	limits := tinyCycleWhalekillerLimits(100_000, 100_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy deposit target contract (10 iterations) -> depositAddr.
	depositRuntime := makeJumpdestHammerRuntime(10) // 10 * 500 = 5_000 cycles
	depositCreation := makeContractCreation(depositRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	depositCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     depositCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{depositCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)

	depositAddr := receipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), depositAddr)

	// First L2 contract (50 * 500 = 25_000 cycles)
	firstRuntime := makeJumpdestHammerRuntime(50)
	firstCreation := makeContractCreation(firstRuntime)

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	firstCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     firstCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{firstCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	firstReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, firstReceipts, 1)

	l2FirstAddr := firstReceipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), l2FirstAddr)

	// Second L2 contract (also 50 * 500 = 25_000 cycles)
	secondRuntime := makeJumpdestHammerRuntime(50)
	secondCreation := makeContractCreation(secondRuntime)

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	secondCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     secondCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{secondCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	secondReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, secondReceipts, 1)

	l2SecondAddr := secondReceipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), l2SecondAddr)

	// Two deposits to depositAddr (each 10 iterations -> 5_000 cycles).
	depFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	dep0 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depFrom,
		To:         &depositAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	dep1 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depFrom,
		To:         &depositAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	require.True(t, dep0.IsDepositTx())
	require.True(t, dep1.IsDepositTx())

	// Two normal L2 calls from pool
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	l2First := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &l2FirstAddr,
		Gas:      1_000_000,
		GasPrice: gasPrice,
	})
	nonce++
	l2Second := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &l2SecondAddr,
		Gas:      1_000_000,
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{l2First, l2Second}, true, false)
	require.Len(t, errs, 2)
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	// Build sealing block with forced deposits + pool L2 txs.
	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{dep0, dep1}, // forced deposits
		checkTransactions: true,
	})

	// No Whalekiller error on deposits: no WorkerError and no exclusions.
	require.NoError(t, result.err)
	require.Empty(t, result.depositExclusions)

	block = result.block
	require.NotNil(t, block)

	// Persist receipts.
	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)

	recs := backend.chain.GetReceiptsByHash(block.Hash())
	// We expect exactly: 2 forced deposits + 2 L2 txs from the pool.
	require.Len(t, recs, 4)

	byHash := make(map[common.Hash]*types.Receipt)
	for _, r := range recs {
		rr := r
		byHash[rr.TxHash] = rr
	}

	dep0Rec, ok := byHash[dep0.Hash()]
	require.True(t, ok, "missing dep0 receipt")
	dep1Rec, ok := byHash[dep1.Hash()]
	require.True(t, ok, "missing dep1 receipt")
	l2FirstRec, ok := byHash[l2First.Hash()]
	require.True(t, ok, "missing l2First receipt")
	l2SecondRec, ok := byHash[l2Second.Hash()]
	require.True(t, ok, "missing l2Second receipt")

	// All four transactions should succeed: no Whalekiller trips.
	require.Equal(t, types.ReceiptStatusSuccessful, dep0Rec.Status)
	require.Equal(t, types.ReceiptStatusSuccessful, dep1Rec.Status)
	require.Equal(t, types.ReceiptStatusSuccessful, l2FirstRec.Status)
	require.Equal(t, types.ReceiptStatusSuccessful, l2SecondRec.Status)
}

// TestWorkerWhalekillerOpCodeBlockLimitOnL2Txs verifies that when normal L2 transactions
// overflow the block-level cycle limit, deposits still succeed, are not added
// to depositExclusions, and the offending L2 transaction does not included in the block and send back to pool.
func TestWorkerWhalekillerOpCodeBlockLimitOnL2Txs(t *testing.T) {
	limits := tinyCycleWhalekillerLimits(100_000, 100_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// ---------------------------------------------------------------------
	// 1) Deploy "tiny" contract for deposits: 10 iterations (very cheap)
	// ---------------------------------------------------------------------
	// 10 * 500 = 5000 cycles
	tinyRuntime := makeJumpdestHammerRuntime(10)
	tinyCreation := makeContractCreation(tinyRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	tinyCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     tinyCreation,
	})
	errs := backend.txPool.Add([]*types.Transaction{tinyCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)

	tinyAddr := receipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), tinyAddr)

	// ---------------------------------------------------------------------
	// 2) Deploy two L2 contracts: firstAddr (50 iters), secondAddr (160 iters)
	// ---------------------------------------------------------------------

	// First contract will cost 50 * 500 = 2500 cycles
	firstRuntime := makeJumpdestHammerRuntime(50)
	firstCreation := makeContractCreation(firstRuntime)

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	firstCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     firstCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{firstCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	firstReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, firstReceipts, 1)
	firstAddr := firstReceipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), firstAddr)

	// 150 * 500 = 75000 cycles
	secondRuntime := makeJumpdestHammerRuntime(150)
	secondCreation := makeContractCreation(secondRuntime)

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	secondCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     secondCreation,
	})
	errs = backend.txPool.Add([]*types.Transaction{secondCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	secondReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, secondReceipts, 1)
	secondAddr := secondReceipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), secondAddr)

	// ---------------------------------------------------------------------
	// 3) Two deposits to tinyAddr (both cheap)
	// ---------------------------------------------------------------------
	depFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	dep0 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depFrom,
		To:         &tinyAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	dep1 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depFrom,
		To:         &tinyAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})
	require.True(t, dep0.IsDepositTx())
	require.True(t, dep1.IsDepositTx())

	// ---------------------------------------------------------------------
	// 4) Two L2 calls from pool: l2First (OK), l2Second (block-limit fail)
	// ---------------------------------------------------------------------
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	l2First := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &firstAddr,
		Gas:      1_000_000,
		GasPrice: gasPrice,
	})
	nonce++
	l2Second := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &secondAddr,
		Gas:      1_000_000,
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{l2First, l2Second}, true, false)
	require.Len(t, errs, 2)
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	// ---------------------------------------------------------------------
	// 5) Build sealing block with forced deposits + pool L2 txs
	// ---------------------------------------------------------------------
	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{dep0, dep1}, // forced deposits
		checkTransactions: true,
	})

	// Deposits did not trigger Whalekiller -> no WorkerError, no exclusions.
	require.NoError(t, result.err)
	require.Empty(t, result.depositExclusions)

	block = result.block
	require.NotNil(t, block)

	// Persist receipts.
	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)

	recs := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, recs, 3) // 2 deposits + 1 L2 txs

	byHash := make(map[common.Hash]*types.Receipt)
	for _, r := range recs {
		rr := r
		byHash[rr.TxHash] = rr
	}

	dep0Rec, ok := byHash[dep0.Hash()]
	require.True(t, ok, "missing dep0 receipt")
	dep1Rec, ok := byHash[dep1.Hash()]
	require.True(t, ok, "missing dep1 receipt")
	l2FirstRec, ok := byHash[l2First.Hash()]
	require.True(t, ok, "missing l2First receipt")

	// Deposits OK
	require.Equal(t, types.ReceiptStatusSuccessful, dep0Rec.Status)
	require.Equal(t, types.ReceiptStatusSuccessful, dep1Rec.Status)

	// First L2 OK, second L2 failed due to Whalekiller (block-level)
	require.Equal(t, types.ReceiptStatusSuccessful, l2FirstRec.Status)

	require.True(t, txInPool(backend.txPool, l2Second.Hash()), "tx-level limit tx should be send back to pool")
}

func TestWorkerWhalekillerPrecompileTxCycleLimit(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	key, addr := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, key)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy bnPair-caller contract (runtime calls bnPair once).
	creation := makeBnPairCallerCreation(1)

	nonce := backend.txPool.Nonce(addr)
	createTx := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     creation,
	})

	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 1)
	require.Equal(t, createTx.Hash(), block.Transactions()[0].Hash())

	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts[0].Status, "deployment must succeed")

	contractAddr := receipts[0].ContractAddress
	require.NotEqual(t, (common.Address{}), contractAddr)

	// Call bnPair-caller contract once: this should exceed precompile tx cycle limit.
	nonce = backend.txPool.Nonce(addr)
	callTx := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})
	errs = backend.txPool.Add([]*types.Transaction{callTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	require.Len(t, block.Transactions(), 0)

	// The tx should not be included due to Whalekiller precompile cycle limit.
	require.False(t, txInPool(backend.txPool, callTx.Hash()), "over tx level limit, should not send back to pool")
}

// TestWorkerWhalekillerPrecompileBlockCycleLimit verifies that when the block-level
// precompile cycle limit is exceeded across multiple transactions, subsequent transactions
// are deferred back to the pool (not dropped).
func TestWorkerWhalekillerPrecompileBlockCycleLimit(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	limits.CycleTracking.ThresholdPerTx = 100_000    // tx1: 79,100 < 100,000
	limits.CycleTracking.ThresholdPerBlock = 150_000 // tx1+tx2: 158,200 > 150,000

	setWhalekillerOverrideForTest(t, limits)

	key, addr := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, key)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy bnPair-caller contract
	creation := makeBnPairCallerCreation(1)

	nonce := backend.txPool.Nonce(addr)
	createTx := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     creation,
	})

	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	contractAddr := receipts[0].ContractAddress

	// Create two transactions that call the precompile
	nonce = backend.txPool.Nonce(addr)
	tx1 := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})
	nonce++
	tx2 := types.MustSignNewTx(key, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{tx1, tx2}, true, false)
	require.Len(t, errs, 2)
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts = backend.chain.GetReceiptsByHash(block.Hash())

	// Only first tx should be included (second hits block limit)
	require.Len(t, receipts, 1)
	require.Equal(t, tx1.Hash(), receipts[0].TxHash)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts[0].Status)

	// Second tx should still be in pool (deferred, not dropped)
	require.True(t, txInPool(backend.txPool, tx2.Hash()), "block-level limit tx should remain in pool")
}

// TestWorkerWhalekillerDepositPrecompileLimit verifies that a deposit transaction
// hitting the precompile cycle limit is excluded and flagged in depositExclusions.
func TestWorkerWhalekillerDepositPrecompileLimit(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy bnPair-caller contract
	creation := makeBnPairCallerCreation(1)

	nonce := backend.txPool.Nonce(testForcedAddress)
	createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     creation,
	})

	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	contractAddr := receipts[0].ContractAddress

	// Build deposit that will hit precompile limit
	depositInner := &types.DepositTx{
		SourceHash:          common.Hash{},
		From:                testForcedAddress,
		To:                  &contractAddr,
		Mint:                big.NewInt(0),
		Value:               big.NewInt(0),
		Gas:                 4_000_000,
		IsSystemTransaction: false,
		Data:                nil,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx())

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx},
		checkTransactions: true,
	})

	// Expect WorkerError with deposit flagged
	require.Error(t, result.err)
	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr))
	require.True(t, workerErr.DepositTransactionsFlagged)

	require.Len(t, result.depositExclusions, 1)
	require.Equal(t, depositTx.Hash(), result.depositExclusions[0])
}

// TestWorkerWhalekillerDepositOkL2PrecompileLimit verifies that when an L2 tx hits
// the precompile tx-level limit, the deposit still succeeds and the L2 tx is dropped.
func TestWorkerWhalekillerDepositOkL2PrecompileLimit(t *testing.T) {
	// Make block limit much higher so only tx limit matters
	limits := params.WhalekillerLimitsConfig{
		Opcodes:      map[uint8]params.LimitPair{},
		Precompiles:  map[string]params.LimitPair{},
		OpcodeCycles: map[uint8]uint64{},
		CycleTracking: &params.WhalekillerCycleTracking{
			CallOverhead:      100,
			ThresholdPerTx:    10_000,     // low tx limit
			ThresholdPerBlock: 10_000_000, // high block limit
		},
		PrecompileCycles: map[string]uint64{
			common.BytesToAddress([]byte{0x08}).Hex(): 1,
		},
	}
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy safe contract (no precompile calls)
	safeCreation := makeContractCreation([]byte{0x00}) // just STOP

	nonce := backend.txPool.Nonce(testForcedAddress)
	safeCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     safeCreation,
	})

	errs := backend.txPool.Add([]*types.Transaction{safeCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	safeAddr := receipts[0].ContractAddress

	// Deploy precompile-heavy contract
	heavyCreation := makeBnPairCallerCreation(1)

	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	heavyCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     heavyCreation,
	})

	errs = backend.txPool.Add([]*types.Transaction{heavyCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	heavyReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	heavyAddr := heavyReceipts[0].ContractAddress

	// Deposit to safe contract (OK)
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	depositInner := &types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx())

	// L2 call to heavy contract (will hit tx limit)
	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	heavyCall := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &heavyAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{heavyCall}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx},
		checkTransactions: true,
	})

	// Deposit should succeed, no WorkerError
	require.NoError(t, result.err)
	require.Empty(t, result.depositExclusions)

	block = result.block
	require.NotNil(t, block)

	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)

	recs := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, recs, 1) // only deposit

	require.Equal(t, depositTx.Hash(), recs[0].TxHash)
	require.Equal(t, types.ReceiptStatusSuccessful, recs[0].Status)

	// Heavy call should be dropped from pool
	require.False(t, txInPool(backend.txPool, heavyCall.Hash()), "tx-level precompile limit tx should be dropped")
}

// TestWorkerWhalekillerDepositPrecompileLimitL2Ok verifies that when a deposit hits
// the precompile tx-level limit, it's excluded while normal L2 transactions succeed.
func TestWorkerWhalekillerDepositPrecompileLimitL2Ok(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy safe contract
	safeCreation := makeContractCreation([]byte{0x00})

	nonce := backend.txPool.Nonce(testForcedAddress)
	safeCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     safeCreation,
	})

	errs := backend.txPool.Add([]*types.Transaction{safeCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	safeAddr := receipts[0].ContractAddress

	// Deploy heavy precompile contract
	heavyCreation := makeBnPairCallerCreation(1)

	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	heavyCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     heavyCreation,
	})

	errs = backend.txPool.Add([]*types.Transaction{heavyCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	heavyReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	heavyAddr := heavyReceipts[0].ContractAddress

	// Deposit to heavy contract (will hit limit)
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	depositInner := &types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &heavyAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        4_000_000,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx())

	// L2 call to safe contract (OK)
	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	safeCall := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &safeAddr,
		Gas:      500_000,
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{safeCall}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx},
		checkTransactions: true,
	})

	// Deposit hits limit -> WorkerError
	require.Error(t, result.err)
	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr))
	require.True(t, workerErr.DepositTransactionsFlagged)

	require.Len(t, result.depositExclusions, 1)
	require.Equal(t, depositTx.Hash(), result.depositExclusions[0])

	// L2 tx should still be in pool
	require.True(t, txInPool(backend.txPool, safeCall.Hash()))
}

// TestWorkerWhalekillerMultipleDepositsPrecompileLimit verifies that when one deposit
// hits the precompile tx-level limit, that deposit will be excluded and we should continue to try the rest
// and NOT exclude all of them.
func TestWorkerWhalekillerMultipleDepositsPrecompileLimit(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy safe contract
	safeCreation := makeContractCreation([]byte{0x00})

	nonce := backend.txPool.Nonce(testForcedAddress)
	safeCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     safeCreation,
	})

	errs := backend.txPool.Add([]*types.Transaction{safeCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	safeAddr := receipts[0].ContractAddress

	// Deploy heavy contract
	heavyCreation := makeBnPairCallerCreation(1)

	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	nonce = backend.txPool.Nonce(testForcedAddress)
	heavyCreateTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      1_000_000,
		GasPrice: gasPrice,
		Data:     heavyCreation,
	})

	errs = backend.txPool.Add([]*types.Transaction{heavyCreateTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	heavyReceipts := backend.chain.GetReceiptsByHash(block.Hash())
	heavyAddr := heavyReceipts[0].ContractAddress

	// Three deposits: safe, heavy (hits limit), safe again
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")

	dep0 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr,
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})

	dep1 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &heavyAddr, // hits precompile limit
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})

	dep2 := types.NewTx(&types.DepositTx{
		SourceHash: common.Hash{},
		From:       depositFrom,
		To:         &safeAddr, // should be ok, since we do not accumulate the cycle on failed tx
		Mint:       big.NewInt(0),
		Value:      big.NewInt(0),
		Gas:        1_000_000,
	})

	require.True(t, dep0.IsDepositTx())
	require.True(t, dep1.IsDepositTx())
	require.True(t, dep2.IsDepositTx())

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{dep0, dep1, dep2},
		checkTransactions: true,
	})

	// dep1 hits limit -> exclude dep1 but continue on dep2
	require.Error(t, result.err)
	var workerErr *slsCommon.WorkerError
	require.True(t, errors.As(result.err, &workerErr))
	require.True(t, workerErr.DepositTransactionsFlagged)

	require.Len(t, result.depositExclusions, 1)
	require.Equal(t, dep1.Hash(), result.depositExclusions[0])
}

// TestWorkerWhalekillerLimitsDisabledEnv verifies that setting WHALEKILLER_LIMITS_DISABLED
// environment variable disables the execution limiter.
func TestWorkerWhalekillerLimitsDisabledEnv(t *testing.T) {
	testForcedKey, testForcedAddress := newTestKeyAndAddress()

	// Test with limits ENABLED (default)
	t.Run("limiter should be enabled by default", func(t *testing.T) {
		t.Setenv(vm.WhalekillerLimitsDisabledEnv, "") // Empty/unset value ⇒ limits stay enabled

		limits := tinyCycleWhalekillerLimits(100_000, 10_000_000)
		setWhalekillerOverrideForTest(t, limits)

		w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
		defer w.Close()

		gasPrice := big.NewInt(params.InitialBaseFee)
		signer := types.LatestSigner(cfg)

		// Deploy JUMPDEST hammer contract that exceeds tx limit
		creation := makeContractCreation(makeJumpdestHammerRuntime(10_000))

		nonce := backend.txPool.Nonce(testForcedAddress)
		createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			Gas:      2_000_000,
			GasPrice: gasPrice,
			Data:     creation,
		})

		errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent := backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		receipts := backend.chain.GetReceiptsByHash(block.Hash())
		require.Len(t, receipts, 1)
		contractAddr := receipts[0].ContractAddress

		// Call contract - should be DROPPED due to limits
		nonce = backend.txPool.Nonce(testForcedAddress)
		callTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			To:       &contractAddr,
			Gas:      4_000_000,
			GasPrice: gasPrice,
		})

		errs = backend.txPool.Add([]*types.Transaction{callTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent = backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		require.Len(t, block.Transactions(), 0, "tx should not be included when limits enabled")

		// Verify tx was dropped from pool
		require.False(t, txInPool(backend.txPool, callTx.Hash()), "tx should be dropped due to tx-level limit")
	})

	// Test with limits DISABLED via env var = "true"
	t.Run("limiter to be disabled when env var is set to true", func(t *testing.T) {
		t.Setenv(vm.WhalekillerLimitsDisabledEnv, "true") // Explicitly disabled

		limits := tinyCycleWhalekillerLimits(100_000, 10_000_000)
		setWhalekillerOverrideForTest(t, limits)

		w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
		defer w.Close()

		gasPrice := big.NewInt(params.InitialBaseFee)
		signer := types.LatestSigner(cfg)

		// Same contract that exceeded limits above
		creation := makeContractCreation(makeJumpdestHammerRuntime(10_000))

		nonce := backend.txPool.Nonce(testForcedAddress)
		createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			Gas:      2_000_000,
			GasPrice: gasPrice,
			Data:     creation,
		})

		errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent := backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		receipts := backend.chain.GetReceiptsByHash(block.Hash())
		require.Len(t, receipts, 1)
		contractAddr := receipts[0].ContractAddress

		// Call contract - should SUCCEED because limits disabled
		nonce = backend.txPool.Nonce(testForcedAddress)
		callTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			To:       &contractAddr,
			Gas:      4_000_000,
			GasPrice: gasPrice,
		})

		errs = backend.txPool.Add([]*types.Transaction{callTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent = backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		require.Len(t, block.Transactions(), 1, "tx should be included when limits disabled")

		receipts = backend.chain.GetReceiptsByHash(block.Hash())
		require.Len(t, receipts, 1)
		require.Equal(t, types.ReceiptStatusSuccessful, receipts[0].Status, "tx should succeed when limits disabled")
	})

	// Test with limits DISABLED via env var = "1"
	t.Run("limiter to be be disabled via env var to 1", func(t *testing.T) {
		t.Setenv(vm.WhalekillerLimitsDisabledEnv, "1") // Explicitly disabled

		limits := tinyCycleWhalekillerLimits(100_000, 10_000_000)
		setWhalekillerOverrideForTest(t, limits)

		w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
		defer w.Close()

		gasPrice := big.NewInt(params.InitialBaseFee)
		signer := types.LatestSigner(cfg)

		creation := makeContractCreation(makeJumpdestHammerRuntime(10_000))

		nonce := backend.txPool.Nonce(testForcedAddress)
		createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			Gas:      2_000_000,
			GasPrice: gasPrice,
			Data:     creation,
		})

		errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent := backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		receipts := backend.chain.GetReceiptsByHash(block.Hash())
		require.Len(t, receipts, 1)
		contractAddr := receipts[0].ContractAddress

		nonce = backend.txPool.Nonce(testForcedAddress)
		callTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			To:       &contractAddr,
			Gas:      4_000_000,
			GasPrice: gasPrice,
		})

		errs = backend.txPool.Add([]*types.Transaction{callTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent = backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		require.Len(t, block.Transactions(), 1, "tx should be included when limits disabled via '1'")

		receipts = backend.chain.GetReceiptsByHash(block.Hash())
		require.Len(t, receipts, 1)
		require.Equal(t, types.ReceiptStatusSuccessful, receipts[0].Status)
	})

	// Test with env var set to "false" - should still be ENABLED
	t.Run("limiter to be enabled when env var set to false", func(t *testing.T) {
		t.Setenv(vm.WhalekillerLimitsDisabledEnv, "false")

		limits := tinyCycleWhalekillerLimits(100_000, 10_000_000)
		setWhalekillerOverrideForTest(t, limits)

		w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
		defer w.Close()

		gasPrice := big.NewInt(params.InitialBaseFee)
		signer := types.LatestSigner(cfg)

		creation := makeContractCreation(makeJumpdestHammerRuntime(10_000))

		nonce := backend.txPool.Nonce(testForcedAddress)
		createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			Gas:      2_000_000,
			GasPrice: gasPrice,
			Data:     creation,
		})

		errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent := backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		receipts := backend.chain.GetReceiptsByHash(block.Hash())
		require.Len(t, receipts, 1)
		contractAddr := receipts[0].ContractAddress

		nonce = backend.txPool.Nonce(testForcedAddress)
		callTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			To:       &contractAddr,
			Gas:      4_000_000,
			GasPrice: gasPrice,
		})

		errs = backend.txPool.Add([]*types.Transaction{callTx}, true, false)
		require.Len(t, errs, 1)
		require.NoError(t, errs[0])

		parent = backend.chain.CurrentBlock()
		require.NotNil(t, parent)
		beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

		block = mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
		require.Len(t, block.Transactions(), 0, "tx should not be included when env='false' (limits enabled)")

		require.False(t, txInPool(backend.txPool, callTx.Hash()), "tx should be dropped when limits enabled")
	})
}

// TestWorkerWhalekillerLimitsDisabledDeposit verifies that when limits are disabled,
// deposits that would normally exceed limits are processed successfully.
func TestWorkerWhalekillerLimitsDisabledDeposit(t *testing.T) {
	t.Setenv(vm.WhalekillerLimitsDisabledEnv, "true")

	limits := tinyCycleWhalekillerLimits(100_000, 100_000)
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy contract that would exceed limits if they were enabled
	creation := makeContractCreation(makeJumpdestHammerRuntime(10_000))

	nonce := backend.txPool.Nonce(testForcedAddress)
	createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     creation,
	})

	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	contractAddr := receipts[0].ContractAddress

	// Build deposit that would hit limits if enabled
	depositFrom := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	depositInner := &types.DepositTx{
		SourceHash:          common.Hash{},
		From:                depositFrom,
		To:                  &contractAddr,
		Mint:                big.NewInt(0),
		Value:               big.NewInt(0),
		Gas:                 1_500_000,
		IsSystemTransaction: false,
		Data:                nil,
	}
	depositTx := types.NewTx(depositInner)
	require.True(t, depositTx.IsDepositTx())

	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))
	random := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	result := w.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         parent.Time + 1,
		forceTime:         true,
		beaconRoot:        &beaconRoot,
		random:            random,
		txs:               types.Transactions{depositTx},
		checkTransactions: true,
	})

	// With limits disabled, deposit should succeed (no error, no exclusions)
	require.NoError(t, result.err, "deposit should succeed when limits disabled")
	require.Empty(t, result.depositExclusions, "no deposits should be excluded when limits disabled")

	block = result.block
	require.NotNil(t, block)

	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)

	recs := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, recs, 1)
	require.Equal(t, depositTx.Hash(), recs[0].TxHash)
	require.Equal(t, types.ReceiptStatusSuccessful, recs[0].Status, "deposit should succeed when limits disabled")
}

// TestWorkerWhalekillerBlockLimitResetsAcrossBlocks verifies that the block-level
// cycle counter resets when moving to a new block, allowing transactions that would
// exceed the limit together to be included in separate blocks.
func TestWorkerWhalekillerBlockLimitResetsAcrossBlocks(t *testing.T) {
	// Set limits so 2 txs fit in one block, but not 4
	limits := tinyCycleWhalekillerLimits(100_000, 150_000)
	// tx limit: 100_000, block limit: 150_000
	// Each tx: ~60K cycles
	// 2 txs: 120K < 150K
	// 4 txs: 240K > 150K
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy contract that uses moderate cycles (~60K per call)
	moderateRuntime := makeJumpdestHammerRuntime(120)
	moderateCreation := makeContractCreation(moderateRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	createTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      2_000_000,
		GasPrice: gasPrice,
		Data:     moderateCreation,
	})

	errs := backend.txPool.Add([]*types.Transaction{createTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	contractAddr := receipts[0].ContractAddress

	// Create 4 transactions
	nonce = backend.txPool.Nonce(testForcedAddress)

	tx1 := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})
	nonce++

	tx2 := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})
	nonce++

	tx3 := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})
	nonce++

	tx4 := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &contractAddr,
		Gas:      2_000_000,
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{tx1, tx2, tx3, tx4}, true, false)
	require.Len(t, errs, 4)
	for _, err := range errs {
		require.NoError(t, err)
	}

	// BLOCK 1: Should include tx1 and tx2
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block1 := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts1 := backend.chain.GetReceiptsByHash(block1.Hash())

	// Should have 2 txs (tx1, tx2)
	// tx3 would exceed block limit (120K + 60K = 180K > 150K)
	require.Len(t, receipts1, 2, "block 1 should have 2 transactions")
	require.Equal(t, tx1.Hash(), receipts1[0].TxHash)
	require.Equal(t, tx2.Hash(), receipts1[1].TxHash)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts1[0].Status)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts1[1].Status)

	// Verify tx3 and tx4 are still in pool (deferred, not dropped)
	require.True(t, txInPool(backend.txPool, tx3.Hash()), "tx3 should remain in pool")
	require.True(t, txInPool(backend.txPool, tx4.Hash()), "tx4 should remain in pool")

	// BLOCK 2: Should include tx3 and tx4 (block level cycle counter reset)
	parent = backend.chain.CurrentBlock()
	require.NotNil(t, parent)
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block2 := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts2 := backend.chain.GetReceiptsByHash(block2.Hash())

	// Should have 2 txs (tx3, tx4)
	require.Len(t, receipts2, 2, "block 2 should have 2 transactions (counter reset)")
	require.Equal(t, tx3.Hash(), receipts2[0].TxHash)
	require.Equal(t, tx4.Hash(), receipts2[1].TxHash)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts2[0].Status)
	require.Equal(t, types.ReceiptStatusSuccessful, receipts2[1].Status)

	// Verify both blocks are different
	require.NotEqual(t, block1.Hash(), block2.Hash())
	require.Equal(t, block1.Hash(), block2.ParentHash())
}

// TestWorkerWhalekillerFailedPrecompileCallsTracked verifies that precompile calls
// with invalid input that return errors are still tracked by the cycle limiter.
func TestWorkerWhalekillerFailedPrecompileCallsTracked(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy contract that calls BN_PAIR with INVALID input (will fail but consume cycles)
	// Use fewer calls to stay within gas limits
	invalidBnPairCallerRuntime := makeInvalidBnPairCallerRuntime(2) // Just 2 failed calls
	creationCode := makeContractCreation(invalidBnPairCallerRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	deployTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      3_000_000, // Within block limit
		GasPrice: gasPrice,
		Data:     creationCode,
	})

	errs := backend.txPool.Add([]*types.Transaction{deployTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	failingContractAddr := receipts[0].ContractAddress

	// Call the contract multiple times - each call makes 2 invalid BN_PAIR calls
	// The failed calls should accumulate and hit Whalekiller limit
	parent = backend.chain.CurrentBlock()
	nonce = backend.txPool.Nonce(testForcedAddress)

	// Create multiple transactions calling the failing contract
	var txs []*types.Transaction
	for i := 0; i < 3; i++ {
		tx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			To:       &failingContractAddr,
			Gas:      3_000_000, // Within block limit
			GasPrice: gasPrice,
		})
		txs = append(txs, tx)
		nonce++
	}

	errs = backend.txPool.Add(txs, true, false)
	require.Len(t, errs, 3)
	for _, err := range errs {
		require.NoError(t, err)
	}

	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	// Build block - should hit Whalekiller limit before including all 3 txs
	// because failed BN_PAIR calls are tracked
	block = buildWhalekillerBlock(t, w, parent, parent.Time+1, beaconRoot, nil)
	receipts = backend.chain.GetReceiptsByHash(block.Hash())

	// Should not include all 3 transactions due to Whalekiller cycle limit
	// Each tx has 2 failed BN_PAIR calls, so 6 total failed calls would exceed limit
	includedCount := 0
	for _, receipt := range receipts {
		for _, tx := range txs {
			if receipt.TxHash == tx.Hash() {
				includedCount++
			}
		}
	}

	require.Less(t, includedCount, 3,
		"should not include all transactions due to Whalekiller limit (failed calls tracked)")
	t.Logf("Included %d of 3 transactions (failed calls tracked, limit hit)", includedCount)
}

// TestWorkerWhalekillerFailedPrecompileDOS demonstrates that without tracking
// failed precompile calls, an attacker can DOS the prover.
func TestWorkerWhalekillerFailedPrecompileDOS(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy contract that makes multiple invalid BN_PAIR calls
	invalidBnPairCallerRuntime := makeInvalidBnPairCallerRuntime(10) // 10 failed calls
	creationCode := makeContractCreation(invalidBnPairCallerRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	deployTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      4_500_000, // Within block limit
		GasPrice: gasPrice,
		Data:     creationCode,
	})

	errs := backend.txPool.Add([]*types.Transaction{deployTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent := backend.chain.CurrentBlock()
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 1)
	dosContractAddr := receipts[0].ContractAddress

	// Call the DOS contract
	nonce = backend.txPool.Nonce(testForcedAddress)
	dosTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		To:       &dosContractAddr,
		Gas:      4_500_000, // Within block limit
		GasPrice: gasPrice,
	})

	errs = backend.txPool.Add([]*types.Transaction{dosTx}, true, false)
	require.Len(t, errs, 1)
	require.NoError(t, errs[0])

	parent = backend.chain.CurrentBlock()
	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	// Try to build block
	block = buildWhalekillerBlock(t, w, parent, parent.Time+1, beaconRoot, nil)
	receipts = backend.chain.GetReceiptsByHash(block.Hash())

	dosIncluded := false
	for _, receipt := range receipts {
		if receipt.TxHash == dosTx.Hash() {
			dosIncluded = true
			t.Logf("DOS tx was included with status: %d", receipt.Status)
		}
	}

	if dosIncluded {
		t.Errorf("VULNERABILITY: DOS transaction with 10 failed BN_PAIR calls was included! Failed calls not being tracked.")
	} else {
		t.Logf("SUCCESS: DOS transaction excluded by Whalekiller (failed calls are tracked)")
	}
}

// TestWorkerWhalekillerMixedSuccessfulAndFailedPrecompileCalls verifies that
// both successful and failed precompile calls contribute to cycle tracking.
func TestWorkerWhalekillerMixedSuccessfulAndFailedPrecompileCalls(t *testing.T) {
	limits := precompileCycleWhalekillerLimits()
	setWhalekillerOverrideForTest(t, limits)

	testForcedKey, testForcedAddress := newTestKeyAndAddress()
	w, backend, cfg := newWhalekillerMiner(t, testForcedKey)
	defer w.Close()

	gasPrice := big.NewInt(params.InitialBaseFee)
	signer := types.LatestSigner(cfg)

	// Deploy valid BN_PAIR caller (1 call)
	validRuntime := makeBnPairCallerRuntime(1)
	validCreation := makeContractCreation(validRuntime)

	nonce := backend.txPool.Nonce(testForcedAddress)
	validDeployTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      3_000_000,
		GasPrice: gasPrice,
		Data:     validCreation,
	})
	nonce++

	// Deploy invalid BN_PAIR caller (1 failed call)
	invalidRuntime := makeInvalidBnPairCallerRuntime(1)
	invalidCreation := makeContractCreation(invalidRuntime)

	invalidDeployTx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
		Nonce:    nonce,
		Gas:      3_000_000,
		GasPrice: gasPrice,
		Data:     invalidCreation,
	})

	errs := backend.txPool.Add([]*types.Transaction{validDeployTx, invalidDeployTx}, true, false)
	require.Len(t, errs, 2)
	for _, err := range errs {
		require.NoError(t, err)
	}

	parent := backend.chain.CurrentBlock()
	beaconRoot := common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	block := mineWhalekillerBlock(t, w, backend, parent, parent.Time+1, beaconRoot, nil)
	receipts := backend.chain.GetReceiptsByHash(block.Hash())
	require.Len(t, receipts, 2)
	validContractAddr := receipts[0].ContractAddress
	invalidContractAddr := receipts[1].ContractAddress

	// Create transactions alternating between valid and invalid calls
	parent = backend.chain.CurrentBlock()
	nonce = backend.txPool.Nonce(testForcedAddress)

	var txs []*types.Transaction
	for i := 0; i < 4; i++ {
		var target *common.Address
		if i%2 == 0 {
			target = &validContractAddr // Valid BN_PAIR call
		} else {
			target = &invalidContractAddr // Invalid BN_PAIR call
		}

		tx := types.MustSignNewTx(testForcedKey, signer, &types.LegacyTx{
			Nonce:    nonce,
			To:       target,
			Gas:      3_000_000,
			GasPrice: gasPrice,
		})
		txs = append(txs, tx)
		nonce++
	}

	errs = backend.txPool.Add(txs, true, false)
	require.Len(t, errs, 4)
	for _, err := range errs {
		require.NoError(t, err)
	}

	beaconRoot = common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1))

	// Try to build block - should hit limit before including all 4 txs
	block = buildWhalekillerBlock(t, w, parent, parent.Time+1, beaconRoot, nil)
	receipts = backend.chain.GetReceiptsByHash(block.Hash())

	// Should not include all 4 transactions due to cycle limit
	require.Less(t, len(receipts), 4, "should hit cycle limit from mixed successful/failed calls")
	t.Logf("Included %d of 4 transactions (limit hit as expected)", len(receipts))
}

// makeInvalidBnPairCallerRuntime creates runtime code that calls BN_PAIR with
// invalid input (wrong size) causing the precompile to fail, but still consuming cycles.
func makeInvalidBnPairCallerRuntime(callCount int) []byte {
	if callCount <= 0 {
		return []byte{0x00}
	}

	var runtime []byte
	for i := 0; i < callCount; i++ {
		runtime = append(runtime,
			0x60, 0x00, // PUSH1 0 (ret size)
			0x60, 0x00, // PUSH1 0 (ret offset)
			0x60, 0x20, // PUSH1 0x20 (INVALID args size - should be 0xc0 for BN_PAIR)
			0x60, 0x00, // PUSH1 0 (args offset)
			0x60, 0x08, // PUSH1 0x08 (BN_PAIR precompile)
			0x5a, // GAS
			0xfa, // STATICCALL (will fail due to invalid input size)
			0x50, // POP (discard result, continue anyway)
		)
	}
	runtime = append(runtime, 0x00) // STOP

	return runtime
}

func precompileCycleWhalekillerLimits() params.WhalekillerLimitsConfig {
	bnPair := common.BytesToAddress([]byte{0x08}).Hex() // BN_PAIR precompile

	return params.WhalekillerLimitsConfig{
		Opcodes:     map[uint8]params.LimitPair{},
		Precompiles: map[string]params.LimitPair{},

		CycleTracking: &params.WhalekillerCycleTracking{
			CallOverhead:      100,
			ThresholdPerTx:    10_000, // very low so a single bnPair call blows past it
			ThresholdPerBlock: 10_000,
		},
		OpcodeCycles: map[uint8]uint64{},
		PrecompileCycles: map[string]uint64{
			bnPair: 1, // cycles = (callOverhead + gasUsed) * 1; bnPair gas is huge
		},
	}
}

func tinyCycleWhalekillerLimits(thresholdPerTx uint64, thresholdPerBlock uint64) params.WhalekillerLimitsConfig {
	return params.WhalekillerLimitsConfig{
		Opcodes:          map[uint8]params.LimitPair{},
		Precompiles:      map[string]params.LimitPair{},
		OpcodeCycles:     map[uint8]uint64{0x5b: 500}, // JUMPDEST cost in cycles
		PrecompileCycles: map[string]uint64{},

		CycleTracking: &params.WhalekillerCycleTracking{
			CallOverhead:      100,
			ThresholdPerTx:    thresholdPerTx,
			ThresholdPerBlock: thresholdPerBlock,
		},
	}
}

func newWhalekillerMiner(t *testing.T, key *ecdsa.PrivateKey) (*Miner, *testWorkerBackend, *params.ChainConfig) {
	t.Helper()

	addr := crypto.PubkeyToAddress(key.PublicKey)

	// Chain config: Whalekiller from time 0, like before
	cfg := *params.MergedTestChainConfig
	zero := func() *uint64 { v := uint64(0); return &v }
	cfg.TerminalTotalDifficultyPassed = true
	cfg.TerminalTotalDifficulty = common.Big0
	cfg.ShanghaiTime = zero()
	cfg.CancunTime = zero()
	cfg.TenrecTime = zero()

	db := rawdb.NewMemoryDatabase()

	funds := new(big.Int).Mul(big.NewInt(1337), big.NewInt(params.Ether))
	alloc := types.GenesisAlloc{
		addr: {Balance: funds},
		params.BeaconRootsAddress: {
			Balance: common.Big0,
			Code:    common.Hex2Bytes(whalekillerBeaconRootsBytecode),
		},
	}

	gspec := &core.Genesis{
		Config:     &cfg,
		Alloc:      alloc,
		BaseFee:    big.NewInt(params.InitialBaseFee),
		Difficulty: common.Big1,
		GasLimit:   5_000_000,
		Timestamp:  1,
	}

	// Use your current NewBlockChain signature (as in your repo):
	engine := beacon.NewFaker()
	chain, err := core.NewBlockChain(db, gspec, engine, nil)
	require.NoError(t, err)

	// txpool
	lpCfg := legacypool.DefaultConfig
	lpCfg.Journal = ""
	lp := legacypool.New(lpCfg, chain, sls.DisabledConfig, sls.DisabledRefreshables)
	txp, _ := txpool.New(lpCfg.PriceLimit, chain, []txpool.SubPool{lp})

	backend := &testWorkerBackend{
		db:      db,
		chain:   chain,
		txPool:  txp,
		genesis: gspec,
	}

	minerCfg := &Config{
		Recommit:          time.Second,
		GasCeil:           params.GenesisGasLimit,
		TransactionLimit:  nil,
		NewPayloadTimeout: 2 * time.Second,
	}
	m := New(backend, minerCfg, engine, sls.DisabledRefreshables)
	m.SetPrioAddresses(nil)

	return m, backend, &cfg
}

func buildWhalekillerBlock(t *testing.T, m *Miner, parent *types.Header, ts uint64, beaconRoot common.Hash, forced types.Transactions) *types.Block {
	t.Helper()
	var withdrawals types.Withdrawals
	if m.chainConfig.IsShanghai(new(big.Int).Add(parent.Number, common.Big1), ts) {
		withdrawals = []*types.Withdrawal{}
	}

	r := m.generateWork(&generateParams{
		parentHash:        parent.Hash(),
		timestamp:         ts,
		forceTime:         true,
		coinbase:          m.config.Etherbase,
		beaconRoot:        &beaconRoot,
		random:            common.BigToHash(new(big.Int).SetUint64(parent.Number.Uint64() + 1)),
		noTxs:             false,
		txs:               forced,
		withdrawals:       withdrawals,
		checkTransactions: true,
	})
	if r.err != nil {
		t.Fatalf("generateWork failed: %v", r.err)
	}
	return r.block
}

func mineWhalekillerBlock(t *testing.T, m *Miner, backend *testWorkerBackend, parent *types.Header, ts uint64, beaconRoot common.Hash, forced types.Transactions) *types.Block {
	t.Helper()
	// Give the transaction pool time to propagate pending transactions to the miner
	// This is mainly for Docker/CI environments
	time.Sleep(10 * time.Millisecond)

	block := buildWhalekillerBlock(t, m, parent, ts, beaconRoot, forced)
	_, err := backend.chain.InsertChain([]*types.Block{block})
	require.NoError(t, err)
	return block
}

func makeBnPairCallerCreation(callCount int) []byte {
	return makeContractCreation(makeBnPairCallerRuntime(callCount))
}

// makeContractCreation wraps runtime bytecode in a bare-bones CREATE payload.
func makeContractCreation(runtime []byte) []byte {
	if len(runtime) > 0xff {
		panic("runtime too large for simple creation helper")
	}
	header := []byte{
		0x60, byte(len(runtime)),
		0x60, 0x00, // placeholder for offset
		0x60, 0x00,
		0x39,
		0x60, byte(len(runtime)),
		0x60, 0x00,
		0xf3,
	}
	offset := len(header)
	if offset > 0xff {
		panic("creation header too large")
	}
	header[3] = byte(offset)
	return append(header, runtime...)
}

// makeJumpdestHammerRuntime builds code that keeps looping and touching a JUMPDEST
// instruction the requested number of times. It stops once the loop counter reaches
// the target so we can deliberately exercise the limiter.
func makeJumpdestHammerRuntime(iterations int) []byte {
	if iterations <= 0 {
		return []byte{0x00}
	}
	runtime := make([]byte, 0, 64)
	runtime = append(runtime, pushValue(iterations)...)
	runtime = append(runtime, 0x60, 0x00) // PUSH1 0 (counter)
	loopPos := len(runtime)
	runtime = append(runtime, 0x5b)       // JUMPDEST
	runtime = append(runtime, 0x60, 0x01) // PUSH1 1
	runtime = append(runtime, 0x01)       // ADD
	runtime = append(runtime, 0x80)       // DUP1 (counter)
	runtime = append(runtime, 0x82)       // DUP3 (limit)
	runtime = append(runtime, 0x90)       // SWAP1 -> counter, limit, counter
	runtime = append(runtime, 0x10)       // LT (counter < limit)
	pushIdx := len(runtime)
	runtime = append(runtime, 0x61, 0x00, 0x00) // PUSH2 loop (placeholder)
	runtime = append(runtime, 0x57)             // JUMPI
	runtime = append(runtime, 0x00)             // STOP
	if loopPos > 0xffff {
		panic("loop offset too large")
	}
	runtime[pushIdx+1] = byte(loopPos >> 8)
	runtime[pushIdx+2] = byte(loopPos)
	return runtime
}

// pushValue emits the shortest PUSH instruction required to place value on stack.
func pushValue(value int) []byte {
	if value < 0 {
		panic("negative push value")
	}
	b := new(big.Int).SetUint64(uint64(value)).Bytes()
	if len(b) == 0 {
		b = []byte{0x00}
	}
	if len(b) > 32 {
		panic("push value too large")
	}
	op := byte(0x60 + len(b) - 1)
	return append([]byte{op}, b...)
}

// makeBnPairCallerRuntime emits runtime code that calls the bnPair precompile callCount times,
// reverting immediately when any invocation fails (to surface Whalekiller limits).
func makeBnPairCallerRuntime(callCount int) []byte {
	if callCount <= 0 {
		return []byte{0x00}
	}
	var runtime []byte
	var placeholders []int
	for i := 0; i < callCount; i++ {
		runtime = append(runtime,
			0x60, 0x00, // PUSH1 0 (ret size)
			0x60, 0x00, // PUSH1 0 (ret offset)
			0x60, 0xc0, // PUSH1 0xc0 (args size)
			0x60, 0x00, // PUSH1 0 (args offset)
			0x60, 0x08, // PUSH1 0x08 (bnPair precompile)
			0x5a,       // GAS
			0xfa,       // STATICCALL
			0x15,       // ISZERO -> 1 if call failed
			0x60, 0x00, // PUSH1 <revert_label> (placeholder)
			0x57, // JUMPI (jump to revert if failed)
		)
		placeholders = append(placeholders, len(runtime)-2)
	}
	runtime = append(runtime, 0x00) // STOP

	revertLabel := len(runtime)
	runtime = append(runtime,
		0x5b,       // JUMPDEST
		0x60, 0x00, // PUSH1 0 (ret size)
		0x60, 0x00, // PUSH1 0 (ret offset)
		0xfd, // REVERT
	)

	if revertLabel > 0xff {
		panic("revert label out of range for PUSH1")
	}
	for _, idx := range placeholders {
		runtime[idx] = byte(revertLabel)
	}

	return runtime
}

func stateAtHeaderRoot(t *testing.T, chain *core.BlockChain, header *types.Header) *state.StateDB {
	t.Helper()

	stateDB, err := chain.StateAt(header.Root)
	require.NoError(t, err)
	return stateDB
}

func newTestKeyAndAddress() (*ecdsa.PrivateKey, common.Address) {
	testForcedKey, _ := crypto.GenerateKey()
	testForcedAddress := crypto.PubkeyToAddress(testForcedKey.PublicKey)
	return testForcedKey, testForcedAddress
}

func setWhalekillerOverrideForTest(t *testing.T, limits params.WhalekillerLimitsConfig) {
	dir := t.TempDir()
	data, err := json.Marshal(&limits)
	require.NoError(t, err)

	overridePath := filepath.Join(dir, "whalekiller_override.json")
	require.NoError(t, os.WriteFile(overridePath, data, 0o600))
	// This sets the env var and automatically restores it after the test.
	t.Setenv(vm.WhalekillerLimitsEnv, overridePath)
}

// txInPool reports whether a transaction with the given hash is still pending in the txpool.
func txInPool(tp *txpool.TxPool, hash common.Hash) bool {
	pending := tp.Pending(false)
	for _, txs := range pending {
		for _, lazy := range txs {
			if lazy.Tx.Hash() == hash {
				return true
			}
		}
	}
	return false
}
