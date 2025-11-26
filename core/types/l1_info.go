package types

import (
	"math/big"

	"github.com/zircuit-labs/l2-geth/common"
)

// L1BlockInfo presents the information stored in a L1Block.setL1BlockValues call
type L1Info struct {
	Number    uint64      `json:"number"`
	Time      uint64      `json:"time"`
	BaseFee   *big.Int    `json:"baseFee"`
	BlockHash common.Hash `json:"blockHash"`
	// Not strictly a piece of L1 information. Represents the number of L2 blocks since the start of the epoch,
	// i.e. when the actual L1 info was first introduced.
	SequenceNumber uint64 `json:"sequenceNumber"`
	// BatcherAddr version 0 is just the address with 0 padding to the left.
	BatcherAddr common.Address `json:"batcherAddr"`

	L1FeeOverhead [32]byte `json:"l1FeeOverhead"` // ignored after Ecotone upgrade
	L1FeeScalar   [32]byte `json:"l1FeeScalar"`   // ignored after Ecotone upgrade

	BlobBaseFee         *big.Int `json:"blobBaseFee"`                        // added by Ecotone upgrade
	BaseFeeScalar       uint32   `json:"baseFeeScalar"`                      // added by Ecotone upgrade
	BlobBaseFeeScalar   uint32   `json:"blobBaseFeeScalar"`                  // added by Ecotone upgrade
	OperatorFeeScalar   uint32   `json:"operatorFeeScalar" rlp:"optional"`   // added by Isthmus upgrade
	OperatorFeeConstant uint64   `json:"operatorFeeConstant" rlp:"optional"` // added by Isthmus upgrade

	DepositExclusions *Bitmap `json:"depositExclusions" rlp:"optional"`
}

// L1BlockInfoLegacy is for being able to unmarshal `L1Info`s that have been written prior to the introduction
// of the operator fee fields
type L1InfoLegacy struct {
	Number    uint64      `json:"number"`
	Time      uint64      `json:"time"`
	BaseFee   *big.Int    `json:"baseFee"`
	BlockHash common.Hash `json:"blockHash"`
	// Not strictly a piece of L1 information. Represents the number of L2 blocks since the start of the epoch,
	// i.e. when the actual L1 info was first introduced.
	SequenceNumber uint64 `json:"sequenceNumber"`
	// BatcherAddr version 0 is just the address with 0 padding to the left.
	BatcherAddr common.Address `json:"batcherAddr"`

	L1FeeOverhead [32]byte `json:"l1FeeOverhead"` // ignored after Ecotone upgrade
	L1FeeScalar   [32]byte `json:"l1FeeScalar"`   // ignored after Ecotone upgrade

	BlobBaseFee       *big.Int `json:"blobBaseFee"`       // added by Ecotone upgrade
	BaseFeeScalar     uint32   `json:"baseFeeScalar"`     // added by Ecotone upgrade
	BlobBaseFeeScalar uint32   `json:"blobBaseFeeScalar"` // added by Ecotone upgrade

	DepositExclusions *Bitmap `json:"depositExclusions" rlp:"optional"`
}

func L1InfoFromLegacy(l1InfoLegacy *L1InfoLegacy) *L1Info {
	l1Info := new(L1Info)

	l1Info.Number = l1InfoLegacy.Number
	l1Info.Time = l1InfoLegacy.Time
	l1Info.BaseFee = l1InfoLegacy.BaseFee
	l1Info.BlockHash = l1InfoLegacy.BlockHash
	l1Info.SequenceNumber = l1InfoLegacy.SequenceNumber
	l1Info.BatcherAddr = l1InfoLegacy.BatcherAddr
	l1Info.L1FeeOverhead = l1InfoLegacy.L1FeeOverhead
	l1Info.L1FeeScalar = l1InfoLegacy.L1FeeScalar
	l1Info.BlobBaseFee = l1InfoLegacy.BlobBaseFee
	l1Info.BaseFeeScalar = l1InfoLegacy.BaseFeeScalar
	l1Info.BlobBaseFeeScalar = l1InfoLegacy.BlobBaseFeeScalar
	l1Info.DepositExclusions = l1InfoLegacy.DepositExclusions

	return l1Info
}
