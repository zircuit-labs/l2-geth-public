// Copyright 2015 The go-ethereum Authors
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

package filters

import (
	"context"
	"math/big"
	"testing"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/consensus/ethash"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/filtermaps"
	"github.com/zircuit-labs/l2-geth/core/rawdb"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/crypto"
	"github.com/zircuit-labs/l2-geth/params"
	"github.com/zircuit-labs/l2-geth/rpc"
	"github.com/zircuit-labs/l2-geth/triedb"
)

func makeReceipt(addr common.Address) *types.Receipt {
	receipt := types.NewReceipt(nil, false, 0)
	receipt.Logs = []*types.Log{
		{Address: addr},
	}
	receipt.Bloom = types.CreateBloom(receipt)
	return receipt
}

func BenchmarkFiltersIndexed(b *testing.B) {
	benchmarkFilters(b, 0, false)
}

func BenchmarkFiltersHalfIndexed(b *testing.B) {
	benchmarkFilters(b, 50000, false)
}

func BenchmarkFiltersUnindexed(b *testing.B) {
	benchmarkFilters(b, 0, true)
}

func benchmarkFilters(b *testing.B, history uint64, noHistory bool) {
	var (
		db           = rawdb.NewMemoryDatabase()
		backend, sys = newTestFilterSystem(db, Config{})
		key1, _      = crypto.HexToECDSA("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
		addr1        = crypto.PubkeyToAddress(key1.PublicKey)
		addr2        = common.BytesToAddress([]byte("jeff"))
		addr3        = common.BytesToAddress([]byte("ethereum"))
		addr4        = common.BytesToAddress([]byte("random addresses please"))

		gspec = &core.Genesis{
			Alloc:   types.GenesisAlloc{addr1: {Balance: big.NewInt(1000000)}},
			BaseFee: big.NewInt(params.InitialBaseFee),
			Config:  params.TestChainConfig,
		}
	)
	defer db.Close()
	_, chain, receipts := core.GenerateChainWithGenesis(gspec, ethash.NewFaker(), 100010, func(i int, gen *core.BlockGen) {
		switch i {
		case 2403:
			receipt := makeReceipt(addr1)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		case 1034:
			receipt := makeReceipt(addr2)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		case 34:
			receipt := makeReceipt(addr3)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		case 99999:
			receipt := makeReceipt(addr4)
			gen.AddUncheckedReceipt(receipt)
			gen.AddUncheckedTx(types.NewTransaction(999, common.HexToAddress("0x999"), big.NewInt(999), 999, gen.BaseFee(), nil))
		}
	})
	// The test txs are not properly signed, can't simply create a chain
	// and then import blocks. TODO(rjl493456442) try to get rid of the
	// manual database writes.
	gspec.MustCommit(db, triedb.NewDatabase(db, triedb.HashDefaults))

	for i, block := range chain {
		rawdb.WriteBlock(db, block)
		rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
		rawdb.WriteHeadBlockHash(db, block.Hash())
		rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts[i])
	}
	backend.startFilterMaps(history, noHistory, filtermaps.DefaultParams)
	defer backend.stopFilterMaps()

	filter := sys.NewRangeFilter(0, int64(rpc.LatestBlockNumber), []common.Address{addr1, addr2, addr3, addr4}, nil)

	for b.Loop() {
		filter.begin = 0
		logs, _ := filter.Logs(context.Background())
		if len(logs) != 4 {
			b.Fatal("expected 4 logs, got", len(logs))
		}
	}
}
