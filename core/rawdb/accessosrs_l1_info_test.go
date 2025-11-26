package rawdb

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/bits-and-blooms/bitset"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/ethdb"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/l2-geth/rlp"
)

// WriteBlockL1Info writes a L1InfoLegacy of the block to the database
func WriteL1InfoLegacy(db ethdb.KeyValueWriter, l2BlockHash common.Hash, l1Info *types.L1InfoLegacy) {
	if l1Info == nil {
		return
	}

	encoded, err := rlp.EncodeToBytes(l1Info)
	if err != nil {
		log.Crit("Failed to RLP encode L1Info", "err", err)
	}
	if err := db.Put(l1InfoKey(l2BlockHash), encoded); err != nil {
		log.Crit("Failed to store L1Info", "err", err)
	}
}

func TestReadL1InfoBitmap(t *testing.T) {
	l2BlockHash := common.BigToHash(big.NewInt(10))

	// Test case for a non-empty bitmap.
	t.Run("Non-empty bitmap", func(t *testing.T) {
		bitmap := types.Bitmap{
			Bs: bitset.New(10),
		}
		bitmap.Set(3)

		l1info := types.L1Info{
			Number:              1,
			Time:                10,
			BaseFee:             common.Big1,
			BlockHash:           common.BigToHash(big.NewInt(10)),
			SequenceNumber:      1,
			BatcherAddr:         common.BigToAddress(big.NewInt(10)),
			L1FeeOverhead:       common.BigToHash(big.NewInt(0)),
			L1FeeScalar:         common.BigToHash(big.NewInt(0)),
			BlobBaseFee:         common.Big1,
			BaseFeeScalar:       1,
			BlobBaseFeeScalar:   2,
			OperatorFeeScalar:   3,
			OperatorFeeConstant: 4,
			DepositExclusions:   &bitmap,
		}

		db := NewMemoryDatabase()
		WriteL1Info(db, l2BlockHash, &l1info)

		got := ReadL1Info(db, l2BlockHash)
		if got == nil || !reflect.DeepEqual(l1info, *got) {
			t.Fatalf("Non-empty bitmap mismatch:\nexpected: %+v\ngot:      %+v", l1info, got)
		}
	})

	// Test case for an empty bitmap.
	t.Run("Empty bitmap", func(t *testing.T) {
		// having a nil DepositExclusions.
		l1info := types.L1Info{
			Number:              2,
			Time:                20,
			BaseFee:             common.Big1,
			BlockHash:           common.BigToHash(big.NewInt(20)),
			SequenceNumber:      2,
			BatcherAddr:         common.BigToAddress(big.NewInt(20)),
			L1FeeOverhead:       common.BigToHash(big.NewInt(0)),
			L1FeeScalar:         common.BigToHash(big.NewInt(0)),
			BlobBaseFee:         common.Big1,
			BaseFeeScalar:       1,
			BlobBaseFeeScalar:   2,
			OperatorFeeScalar:   3,
			OperatorFeeConstant: 4,
			DepositExclusions:   nil,
		}

		db := NewMemoryDatabase()
		WriteL1Info(db, l2BlockHash, &l1info)

		got := ReadL1Info(db, l2BlockHash)
		if got == nil {
			t.Fatal("Expected L1Info but got nil")
		}
		// The DepositExclusions field should remain nil.
		if got.DepositExclusions != nil {
			t.Fatalf("Empty bitmap mismatch: expected nil DepositExclusions, got: %+v", got.DepositExclusions)
		}
	})

	// Test case for a legacy l1info that was written prior to the introduction of operator fee fields
	t.Run("Empty bitmap, legacy info", func(t *testing.T) {
		bitmap := types.Bitmap{
			Bs: bitset.New(10),
		}
		bitmap.Set(3)

		l1info := types.L1InfoLegacy{
			Number:            1,
			Time:              10,
			BaseFee:           common.Big1,
			BlockHash:         common.BigToHash(big.NewInt(10)),
			SequenceNumber:    1,
			BatcherAddr:       common.BigToAddress(big.NewInt(10)),
			L1FeeOverhead:     common.BigToHash(big.NewInt(0)),
			L1FeeScalar:       common.BigToHash(big.NewInt(0)),
			BlobBaseFee:       common.Big1,
			BaseFeeScalar:     1,
			BlobBaseFeeScalar: 2,
			DepositExclusions: nil,
		}

		db := NewMemoryDatabase()
		WriteL1InfoLegacy(db, l2BlockHash, &l1info)

		got := ReadL1Info(db, l2BlockHash)
		if got == nil || !reflect.DeepEqual(*types.L1InfoFromLegacy(&l1info), *got) {
			t.Fatalf("Non-empty bitmap, legacy info mismatch:\nexpected: %+v\ngot:      %+v", l1info, got)
		}
	})

	// Test case for a legacy l1info that was written prior to the introduction of operator fee fields
	t.Run("Non-empty bitmap, legacy info", func(t *testing.T) {
		bitmap := types.Bitmap{
			Bs: bitset.New(10),
		}
		bitmap.Set(3)

		l1info := types.L1InfoLegacy{
			Number:            1,
			Time:              10,
			BaseFee:           common.Big1,
			BlockHash:         common.BigToHash(big.NewInt(10)),
			SequenceNumber:    1,
			BatcherAddr:       common.BigToAddress(big.NewInt(10)),
			L1FeeOverhead:     common.BigToHash(big.NewInt(0)),
			L1FeeScalar:       common.BigToHash(big.NewInt(0)),
			BlobBaseFee:       common.Big1,
			BaseFeeScalar:     1,
			BlobBaseFeeScalar: 2,
			DepositExclusions: &bitmap,
		}

		db := NewMemoryDatabase()
		WriteL1InfoLegacy(db, l2BlockHash, &l1info)

		got := ReadL1Info(db, l2BlockHash)
		if got == nil || !reflect.DeepEqual(*types.L1InfoFromLegacy(&l1info), *got) {
			t.Fatalf("Non-empty bitmap, legacy info mismatch:\nexpected: %+v\ngot:      %+v", l1info, got)
		}
	})
}
