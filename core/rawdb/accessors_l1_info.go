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
package rawdb

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/cockroachdb/pebble"
	leveldb "github.com/syndtr/goleveldb/leveldb/errors"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/ethdb"
	"github.com/zircuit-labs/l2-geth/log"
	"github.com/zircuit-labs/l2-geth/rlp"
	"github.com/zircuit-labs/l2-geth/ethdb/memorydb"
)

// WriteBlockL1Info writes a L1Info of the block to the database.
func WriteL1Info(db ethdb.KeyValueWriter, l2BlockHash common.Hash, l1Info *types.L1Info) {
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

// ReadBlockL1Info retrieves the L1Info corresponding to the block hash.
func ReadL1Info(db ethdb.Reader, l2BlockHash common.Hash) *types.L1Info {
	data := ReadL1InfoRLP(db, l2BlockHash)
	if len(data) == 0 {
		return nil
	}
	l1Info := new(types.L1Info)

	// First attempt RLP decoding.
	if err := rlp.Decode(bytes.NewReader(data), l1Info); err != nil {
		initialErr := err
		l1InfoLegacy := new(types.L1InfoLegacy)
		if err := rlp.Decode(bytes.NewReader(data), l1InfoLegacy); err != nil {
			log.Error("RLP decoding failed for ReadL1Info; trying JSON unmarshal", "l2BlockHash", l2BlockHash.String(), "data", data, "rlpErr", initialErr, "rlpErrLegacy", err)
			// Fallback to JSON decoding just incase L1Info was in json.
			if err2 := json.Unmarshal(data, l1Info); err2 != nil {
				log.Crit("Invalid L1Info message: both RLP and JSON decoding failed", "l2BlockHash", l2BlockHash.String(), "data", data, "rlpErr", err, "jsonErr", err2)
			}
		} else {
			// copy over legacy data
			l1Info = types.L1InfoFromLegacy(l1InfoLegacy)
		}
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

func isNotFoundErr(err error) bool {
	return errors.Is(err, leveldb.ErrNotFound) ||
		errors.Is(err, memorydb.ErrMemorydbNotFound) ||
		errors.Is(err, pebble.ErrNotFound)
}
