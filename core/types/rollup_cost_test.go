package types

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/bits-and-blooms/bitset"
	"github.com/stretchr/testify/require"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/params"
)

var (
	baseFee  = big.NewInt(1000 * 1e6)
	overhead = big.NewInt(50)
	scalar   = big.NewInt(7 * 1e6)

	blobBaseFee         = big.NewInt(10 * 1e6)
	baseFeeScalar       = big.NewInt(2)
	blobBaseFeeScalar   = big.NewInt(3)
	operatorFeeScalar   = big.NewInt(1439103868)
	operatorFeeConstant = big.NewInt(1256417826609331460)

	// below are the expected cost func outcomes for the above parameter settings on the emptyTx
	// which is defined in transaction_test.go
	bedrockFee        = big.NewInt(11326000000000)
	regolithFee       = big.NewInt(3710000000000)
	ecotoneFee        = big.NewInt(960900)              // (480/16)*(2*16*1000 + 3*10) == 960900
	fjordFee          = big.NewInt(3203000)             // 100_000_000 * (2 * 1000 * 1e6 * 16 + 3 * 10 * 1e6) / 1e12
	ithmusOperatorFee = big.NewInt(1256417826611659930) // 1618 * 1439103868 / 1e6 + 1256417826609331460

	bedrockGas      = big.NewInt(1618)
	regolithGas     = big.NewInt(530) // 530  = 1618 - (16*68)
	ecotoneGas      = big.NewInt(480)
	minimumFjordGas = big.NewInt(1600) // fastlz size of minimum txn, 100_000_000 * 16 / 1e6
)

func TestBedrockL1CostFunc(t *testing.T) {
	costFunc0 := newL1CostFuncBedrockHelper(baseFee, overhead, scalar, false /*isRegolith*/)
	costFunc1 := newL1CostFuncBedrockHelper(baseFee, overhead, scalar, true)

	c0, g0 := costFunc0(emptyTx.RollupCostData()) // pre-Regolith
	c1, g1 := costFunc1(emptyTx.RollupCostData())

	require.Equal(t, bedrockFee, c0)
	require.Equal(t, bedrockGas, g0) // gas-used

	require.Equal(t, regolithFee, c1)
	require.Equal(t, regolithGas, g1)
}

func TestEcotoneL1CostFunc(t *testing.T) {
	costFunc := newL1CostFuncEcotone(baseFee, blobBaseFee, baseFeeScalar, blobBaseFeeScalar)
	c, g := costFunc(emptyTx.RollupCostData())
	require.Equal(t, ecotoneGas, g)
	require.Equal(t, ecotoneFee, c)
}

func TestFjordL1CostFuncMinimumBounds(t *testing.T) {
	costFunc := NewL1CostFuncFjord(
		baseFee,
		blobBaseFee,
		baseFeeScalar,
		blobBaseFeeScalar,
	)

	// Minimum size transactions:
	// -42.5856 + 0.8365*110 = 49.4294
	// -42.5856 + 0.8365*150 = 82.8894
	// -42.5856 + 0.8365*170 = 99.6194
	for _, fastLzsize := range []uint64{100, 150, 170} {
		c, g := costFunc(RollupCostData{
			FastLzSize: fastLzsize,
		})

		require.Equal(t, minimumFjordGas, g)
		require.Equal(t, fjordFee, c)
	}

	// Larger size transactions:
	// -42.5856 + 0.8365*171 = 100.4559
	// -42.5856 + 0.8365*175 = 108.8019
	// -42.5856 + 0.8365*200 = 124.7144
	for _, fastLzsize := range []uint64{171, 175, 200} {
		c, g := costFunc(RollupCostData{
			FastLzSize: fastLzsize,
		})

		require.Greater(t, g.Uint64(), minimumFjordGas.Uint64())
		require.Greater(t, c.Uint64(), fjordFee.Uint64())
	}
}

// TestFjordL1CostSolidityParity tests that the cost function for the fjord upgrade matches a Solidity
// test to ensure the outputs are the same.
func TestFjordL1CostSolidityParity(t *testing.T) {
	costFunc := NewL1CostFuncFjord(
		big.NewInt(2*1e6),
		big.NewInt(3*1e6),
		big.NewInt(20),
		big.NewInt(15),
	)

	c0, g0 := costFunc(RollupCostData{
		FastLzSize: 235,
	})

	require.Equal(t, big.NewInt(2463), g0)
	require.Equal(t, big.NewInt(105484), c0)
}

func TestExtractBedrockGasParams(t *testing.T) {
	regolithTime := uint64(1)
	config := &params.ChainConfig{
		Optimism:     params.OptimismTestConfig.Optimism,
		RegolithTime: &regolithTime,
	}

	data := getBedrockL1Attributes(baseFee, overhead, scalar)

	gasParamsPreRegolith, err := extractL1GasParams(config, regolithTime-1, data)
	require.NoError(t, err)

	// Function should continue to succeed even with extra data (that just gets ignored) since we
	// have been testing the data size is at least the expected number of bytes instead of exactly
	// the expected number of bytes. It's unclear if this flexibility was intentional, but since
	// it's been in production we shouldn't change this behavior.
	data = append(data, []byte{0xBE, 0xEE, 0xEE, 0xFF}...) // tack on garbage data
	gasParamsRegolith, err := extractL1GasParams(config, regolithTime, data)
	require.NoError(t, err)

	c, _ := gasParamsPreRegolith.costFunc(emptyTx.RollupCostData())
	require.Equal(t, bedrockFee, c)

	c, _ = gasParamsRegolith.costFunc(emptyTx.RollupCostData())
	require.Equal(t, regolithFee, c)

	// try to extract from data which has not enough params, should get error.
	data = data[:len(data)-4-32]
	_, err = extractL1GasParams(config, regolithTime, data)
	require.Error(t, err)
}

func TestExtractEcotoneGasParams(t *testing.T) {
	testExtractEcotoneGasParams(t, nil)
	bm := NewBitmap(&bitset.BitSet{})
	bm.Set(2)
	testExtractEcotoneGasParams(t, bm)
}

func testExtractEcotoneGasParams(t *testing.T, depositExclusionBitmap *Bitmap) {
	zeroTime := uint64(0)
	// create a config where ecotone upgrade is active
	config := &params.ChainConfig{
		Optimism:     params.OptimismTestConfig.Optimism,
		RegolithTime: &zeroTime,
		EcotoneTime:  &zeroTime,
	}
	require.True(t, config.IsOptimismEcotone(0))

	data := getEcotoneL1Attributes(baseFee, blobBaseFee, baseFeeScalar, blobBaseFeeScalar, depositExclusionBitmap)

	gasParams, err := extractL1GasParams(config, 0, data)
	require.NoError(t, err)

	c, g := gasParams.costFunc(emptyTx.RollupCostData())

	require.Equal(t, ecotoneGas, g)
	require.Equal(t, ecotoneFee, c)

	// make sure wrong amount of data results in error
	if depositExclusionBitmap == nil {
		data = append(data, 0x00) // tack on garbage byte
		_, err = extractL1GasParamsPostEcotone(data)
		require.Error(t, err)
	}
}

func TestExtractFjordGasParams(t *testing.T) {
	testExtractFjordGasParams(t, nil)
	bm := NewBitmap(&bitset.BitSet{})
	bm.Set(2)
	testExtractFjordGasParams(t, bm)
}

func testExtractFjordGasParams(t *testing.T, depositExclusionBitmap *Bitmap) {
	zeroTime := uint64(0)
	// create a config where fjord is active
	config := &params.ChainConfig{
		Optimism:     params.OptimismTestConfig.Optimism,
		RegolithTime: &zeroTime,
		EcotoneTime:  &zeroTime,
		FjordTime:    &zeroTime,
		IsthmusTime:  &zeroTime,
	}
	require.True(t, config.IsFjord(zeroTime))

	data := getIsthmusL1Attributes(
		baseFee,
		blobBaseFee,
		baseFeeScalar,
		blobBaseFeeScalar,
		operatorFeeScalar,
		operatorFeeConstant,
		depositExclusionBitmap,
	)

	gasparams, err := extractL1GasParams(config, zeroTime, data)
	require.NoError(t, err)
	costFunc := gasparams.costFunc

	c, g := costFunc(emptyTx.RollupCostData())

	require.Equal(t, minimumFjordGas, g)
	require.Equal(t, fjordFee, c)
}

// make sure the first block of the ecotone upgrade is properly detected, and invokes the bedrock
// cost function appropriately
func TestFirstBlockEcotoneGasParams(t *testing.T) {
	zeroTime := uint64(0)
	// create a config where ecotone upgrade is active
	config := &params.ChainConfig{
		Optimism:     params.OptimismTestConfig.Optimism,
		RegolithTime: &zeroTime,
		EcotoneTime:  &zeroTime,
	}
	require.True(t, config.IsOptimismEcotone(0))

	data := getBedrockL1Attributes(baseFee, overhead, scalar)

	oldGasParams, err := extractL1GasParams(config, 0, data)
	require.NoError(t, err)
	c, _ := oldGasParams.costFunc(emptyTx.RollupCostData())
	require.Equal(t, regolithFee, c)
}

func getBedrockL1Attributes(baseFee, overhead, scalar *big.Int) []byte {
	uint256 := make([]byte, 32)
	ignored := big.NewInt(1234)
	data := []byte{}
	data = append(data, BedrockL1AttributesSelector...)
	data = append(data, ignored.FillBytes(uint256)...)  // arg 0
	data = append(data, ignored.FillBytes(uint256)...)  // arg 1
	data = append(data, baseFee.FillBytes(uint256)...)  // arg 2
	data = append(data, ignored.FillBytes(uint256)...)  // arg 3
	data = append(data, ignored.FillBytes(uint256)...)  // arg 4
	data = append(data, ignored.FillBytes(uint256)...)  // arg 5
	data = append(data, overhead.FillBytes(uint256)...) // arg 6
	data = append(data, scalar.FillBytes(uint256)...)   // arg 7
	return data
}

func getEcotoneL1Attributes(baseFee, blobBaseFee, baseFeeScalar, blobBaseFeeScalar *big.Int, depositExclusionBitmap *Bitmap) []byte {
	ignored := big.NewInt(1234)
	data := []byte{}
	uint256 := make([]byte, 32)
	uint64 := make([]byte, 8)
	uint32 := make([]byte, 4)
	if depositExclusionBitmap == nil {
		data = append(data, EcotoneL1AttributesSelector...)
	} else {
		data = append(data, EcotoneL1ExclusionsAttributesSelector...)
	}
	data = append(data, baseFeeScalar.FillBytes(uint32)...)
	data = append(data, blobBaseFeeScalar.FillBytes(uint32)...)
	data = append(data, ignored.FillBytes(uint64)...)
	data = append(data, ignored.FillBytes(uint64)...)
	data = append(data, ignored.FillBytes(uint64)...)
	data = append(data, baseFee.FillBytes(uint256)...)
	data = append(data, blobBaseFee.FillBytes(uint256)...)
	data = append(data, ignored.FillBytes(uint256)...)
	data = append(data, ignored.FillBytes(uint256)...)
	if depositExclusionBitmap != nil {
		data = append(data, depositExclusionBitmap.MustBytes()...)
	}
	return data
}

func getIsthmusL1Attributes(baseFee, blobBaseFee, baseFeeScalar, blobBaseFeeScalar, operatorFeeScalar, operatorFeeConstant *big.Int, depositExclusionBitmap *Bitmap) []byte {
	ignored := big.NewInt(1234)
	data := []byte{}
	uint256Slice := make([]byte, 32)
	uint64Slice := make([]byte, 8)
	uint32Slice := make([]byte, 4)
	if depositExclusionBitmap == nil {
		data = append(data, IsthmusL1AttributesSelector...)
	} else {
		data = append(data, IsthmusL1ExclusionsAttributesSelector...)
	}
	data = append(data, baseFeeScalar.FillBytes(uint32Slice)...)
	data = append(data, blobBaseFeeScalar.FillBytes(uint32Slice)...)
	data = append(data, ignored.FillBytes(uint64Slice)...)
	data = append(data, ignored.FillBytes(uint64Slice)...)
	data = append(data, ignored.FillBytes(uint64Slice)...)
	data = append(data, baseFee.FillBytes(uint256Slice)...)
	data = append(data, blobBaseFee.FillBytes(uint256Slice)...)
	data = append(data, ignored.FillBytes(uint256Slice)...)
	data = append(data, ignored.FillBytes(uint256Slice)...)
	data = append(data, operatorFeeScalar.FillBytes(uint32Slice)...)
	data = append(data, operatorFeeConstant.FillBytes(uint64Slice)...)
	if depositExclusionBitmap != nil {
		data = append(data, depositExclusionBitmap.MustBytes()...)
	}
	return data
}

type testStateGetter struct {
	baseFee, blobBaseFee, overhead, scalar *big.Int
	baseFeeScalar, blobBaseFeeScalar       uint32
}

func (sg *testStateGetter) GetState(addr common.Address, slot common.Hash) common.Hash {
	buf := common.Hash{}
	switch slot {
	case L1BaseFeeSlot:
		sg.baseFee.FillBytes(buf[:])
	case OverheadSlot:
		sg.overhead.FillBytes(buf[:])
	case ScalarSlot:
		sg.scalar.FillBytes(buf[:])
	case L1BlobBaseFeeSlot:
		sg.blobBaseFee.FillBytes(buf[:])
	case L1FeeScalarsSlot:
		offset := scalarSectionStart
		binary.BigEndian.PutUint32(buf[offset:offset+4], sg.baseFeeScalar)
		binary.BigEndian.PutUint32(buf[offset+4:offset+8], sg.blobBaseFeeScalar)
	default:
		panic("unknown slot")
	}
	return buf
}

// TestNewL1CostFunc tests that the appropriate cost function is selected based on the
// configuration and statedb values.
func TestNewL1CostFunc(t *testing.T) {
	time := uint64(1)
	config := &params.ChainConfig{
		Optimism: params.OptimismTestConfig.Optimism,
	}
	statedb := &testStateGetter{
		baseFee:           baseFee,
		overhead:          overhead,
		scalar:            scalar,
		blobBaseFee:       blobBaseFee,
		baseFeeScalar:     uint32(baseFeeScalar.Uint64()),
		blobBaseFeeScalar: uint32(blobBaseFeeScalar.Uint64()),
	}

	costFunc := NewL1CostFunc(config, statedb)
	require.NotNil(t, costFunc)

	// empty cost data should result in nil fee
	fee := costFunc(RollupCostData{}, time)
	require.Nil(t, fee)

	// emptyTx fee w/ bedrock config should be the bedrock fee
	fee = costFunc(emptyTx.RollupCostData(), time)
	require.NotNil(t, fee)
	require.Equal(t, bedrockFee, fee)

	// emptyTx fee w/ regolith config should be the regolith fee
	config.RegolithTime = &time
	costFunc = NewL1CostFunc(config, statedb)
	require.NotNil(t, costFunc)
	fee = costFunc(emptyTx.RollupCostData(), time)
	require.NotNil(t, fee)
	require.Equal(t, regolithFee, fee)

	// emptyTx fee w/ ecotone config should be the ecotone fee
	config.EcotoneTime = &time
	costFunc = NewL1CostFunc(config, statedb)
	fee = costFunc(emptyTx.RollupCostData(), time)
	require.NotNil(t, fee)
	require.Equal(t, ecotoneFee, fee)

	// emptyTx fee w/ fjord config should be the fjord fee
	config.FjordTime = &time
	costFunc = NewL1CostFunc(config, statedb)
	fee = costFunc(emptyTx.RollupCostData(), time)
	require.NotNil(t, fee)
	require.Equal(t, fjordFee, fee)

	// emptyTx fee w/ ecotone config, but simulate first ecotone block by blowing away the ecotone
	// params. Should result in regolith fee.
	statedb.baseFeeScalar = 0
	statedb.blobBaseFeeScalar = 0
	statedb.blobBaseFee = new(big.Int)
	costFunc = NewL1CostFunc(config, statedb)
	fee = costFunc(emptyTx.RollupCostData(), time)
	require.NotNil(t, fee)
	require.Equal(t, regolithFee, fee)
}
