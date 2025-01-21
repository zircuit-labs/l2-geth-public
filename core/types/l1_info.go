package types

import (
	"math/big"

	"github.com/zircuit-labs/l2-geth-public/common"
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

	BlobBaseFee       *big.Int `json:"blobBaseFee"`       // added by Ecotone upgrade
	BaseFeeScalar     uint32   `json:"baseFeeScalar"`     // added by Ecotone upgrade
	BlobBaseFeeScalar uint32   `json:"blobBaseFeeScalar"` // added by Ecotone upgrade

	DepositExclusions *Bitmap `json:"depositExclusions" rlp:"optional"`
}
