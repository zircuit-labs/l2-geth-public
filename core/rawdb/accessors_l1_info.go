package rawdb

import (
	"bytes"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/types"
	"github.com/zircuit-labs/l2-geth-public/ethdb"
	"github.com/zircuit-labs/l2-geth-public/log"
	"github.com/zircuit-labs/l2-geth-public/rlp"
)

// WriteBlockL1Info writes a L1Info of the block to the database.
func WriteL1Info(db ethdb.KeyValueWriter, l2BlockHash common.Hash, l1Info *types.L1Info) {
	if l1Info == nil {
		return
	}

	bytes, err := rlp.EncodeToBytes(&l1Info)
	if err != nil {
		log.Crit("Failed to RLP encode L1Info ", "err", err)
	}
	if err := db.Put(l1InfoKey(l2BlockHash), bytes); err != nil {
		log.Crit("Failed to store L1Info ", "err", err)
	}
}

// ReadBlockL1Info retrieves the L1Info corresponding to the block hash.
func ReadL1Info(db ethdb.Reader, l2BlockHash common.Hash) *types.L1Info {
	data := ReadL1InfoRLP(db, l2BlockHash)
	if len(data) == 0 {
		return nil
	}
	l1Info := new(types.L1Info)
	if err := rlp.Decode(bytes.NewReader(data), l1Info); err != nil {
		log.Crit("Invalid L1Info message RLP", "l2BlockHash", l2BlockHash.String(), "data", data, "err", err)
	}
	return l1Info
}

// ReadBlockL1Info retrieves the L1Info in its raw RLP database encoding.
func ReadL1InfoRLP(db ethdb.Reader, l2BlockHash common.Hash) rlp.RawValue {
	data, err := db.Get(l1InfoKey(l2BlockHash))
	if err != nil && isNotFoundErr(err) {
		return nil
	}
	if err != nil {
		log.Crit("Failed to load L1Info", "l2BlockHash", l2BlockHash.String(), "err", err)
	}
	return data
}
