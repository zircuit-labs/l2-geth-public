// Copyright 2021 The go-ethereum Authors
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

package ethstats

import (
	"math/big"
	"os"
	"strconv"
	"testing"

	"github.com/zircuit-labs/l2-geth/params"
)

func TestParseEthstatsURL(t *testing.T) {
	cases := []struct {
		url              string
		node, pass, host string
	}{
		{
			url:  `"debug meowsbits":mypass@ws://mordor.dash.fault.dev:3000`,
			node: "debug meowsbits", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `"debug @meowsbits":mypass@ws://mordor.dash.fault.dev:3000`,
			node: "debug @meowsbits", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `"debug: @meowsbits":mypass@ws://mordor.dash.fault.dev:3000`,
			node: "debug: @meowsbits", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `name:@ws://mordor.dash.fault.dev:3000`,
			node: "name", pass: "", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `name@ws://mordor.dash.fault.dev:3000`,
			node: "name", pass: "", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `:mypass@ws://mordor.dash.fault.dev:3000`,
			node: "", pass: "mypass", host: "ws://mordor.dash.fault.dev:3000",
		},
		{
			url:  `:@ws://mordor.dash.fault.dev:3000`,
			node: "", pass: "", host: "ws://mordor.dash.fault.dev:3000",
		},
	}

	for i, c := range cases {
		parts, err := parseEthstatsURL(c.url)
		if err != nil {
			t.Fatal(err)
		}
		node, pass, host := parts[0], parts[1], parts[2]

		// unquote because the value provided will be used as a CLI flag value, so unescaped quotes will be removed
		nodeUnquote, err := strconv.Unquote(node)
		if err == nil {
			node = nodeUnquote
		}

		if node != c.node {
			t.Errorf("case=%d mismatch node value, got: %v ,want: %v", i, node, c.node)
		}
		if pass != c.pass {
			t.Errorf("case=%d mismatch pass value, got: %v ,want: %v", i, pass, c.pass)
		}
		if host != c.host {
			t.Errorf("case=%d mismatch host value, got: %v ,want: %v", i, host, c.host)
		}
	}
}

func newUint64(val uint64) *uint64 { return &val }
func newInt(val int) *int          { return &val }

func TestFilterForks(t *testing.T) {

	// Ensure consistent timezone for string formatting
	oldTZ := os.Getenv("TZ")
	os.Setenv("TZ", "America/New_York")
	defer func() {
		if oldTZ == "" {
			os.Unsetenv("TZ")
		} else {
			os.Setenv("TZ", oldTZ)
		}
	}()

	// fixing configs because real ones might change in future
	// find config structs in l2-geth/params/config.go
	zircuitTestnetChainConfig := &params.ChainConfig{
		ChainID:                       big.NewInt(48898),
		HomesteadBlock:                big.NewInt(0),
		EIP150Block:                   big.NewInt(0),
		EIP155Block:                   big.NewInt(0),
		EIP158Block:                   big.NewInt(0),
		ByzantiumBlock:                big.NewInt(0),
		ConstantinopleBlock:           big.NewInt(0),
		PetersburgBlock:               big.NewInt(0),
		IstanbulBlock:                 big.NewInt(0),
		MuirGlacierBlock:              big.NewInt(0),
		BerlinBlock:                   big.NewInt(0),
		LondonBlock:                   big.NewInt(0),
		ArrowGlacierBlock:             big.NewInt(0),
		GrayGlacierBlock:              big.NewInt(0),
		MergeNetsplitBlock:            big.NewInt(0),
		ShanghaiTime:                  newUint64(0),
		BedrockBlock:                  big.NewInt(0),
		RegolithTime:                  newUint64(0),
		CanyonTime:                    newUint64(0),
		EcotoneTime:                   newUint64(0),
		CancunTime:                    newUint64(0),
		MonoFeeBlock:                  big.NewInt(4),
		AlfieTime:                     newUint64(1744725600),
		IsthmusTime:                   newUint64(1746460800),
		PragueTime:                    newUint64(1746460800),
		JavelinaTime:                  newUint64(1746460800),
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
		Optimism: &params.OptimismConfig{
			EIP1559Elasticity:        10,
			EIP1559Denominator:       50,
			EIP1559DenominatorCanyon: 250,
		},
		Scroll: params.ScrollConfig{
			MaxTxPerBlock:             newInt(16),
			MaxTxPayloadBytesPerBlock: newInt(122880),
		},
	}

	mergedTestChainConfig := &params.ChainConfig{
		ChainID:                       big.NewInt(1),
		HomesteadBlock:                big.NewInt(0),
		DAOForkBlock:                  nil,
		DAOForkSupport:                false,
		EIP150Block:                   big.NewInt(0),
		EIP155Block:                   big.NewInt(0),
		EIP158Block:                   big.NewInt(0),
		ByzantiumBlock:                big.NewInt(0),
		ConstantinopleBlock:           big.NewInt(0),
		PetersburgBlock:               big.NewInt(0),
		IstanbulBlock:                 big.NewInt(0),
		MuirGlacierBlock:              big.NewInt(0),
		BerlinBlock:                   big.NewInt(0),
		LondonBlock:                   big.NewInt(0),
		ArrowGlacierBlock:             big.NewInt(0),
		GrayGlacierBlock:              big.NewInt(0),
		MergeNetsplitBlock:            big.NewInt(0),
		ShanghaiTime:                  newUint64(0),
		CancunTime:                    newUint64(0),
		PragueTime:                    newUint64(0),
		VerkleTime:                    nil,
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
		Ethash:                        new(params.EthashConfig),
		Clique:                        nil,
	}

	nonActivatedConfig := &params.ChainConfig{
		ChainID:                       big.NewInt(1),
		HomesteadBlock:                nil,
		DAOForkBlock:                  nil,
		DAOForkSupport:                false,
		EIP150Block:                   nil,
		EIP155Block:                   nil,
		EIP158Block:                   nil,
		ByzantiumBlock:                nil,
		ConstantinopleBlock:           nil,
		PetersburgBlock:               nil,
		IstanbulBlock:                 nil,
		MuirGlacierBlock:              nil,
		BerlinBlock:                   nil,
		LondonBlock:                   nil,
		ArrowGlacierBlock:             nil,
		GrayGlacierBlock:              nil,
		MergeNetsplitBlock:            nil,
		ShanghaiTime:                  nil,
		CancunTime:                    nil,
		PragueTime:                    nil,
		VerkleTime:                    nil,
		TerminalTotalDifficulty:       nil,
		TerminalTotalDifficultyPassed: false,
		Ethash:                        new(params.EthashConfig),
		Clique:                        nil,
	}

	allDevChainProtocolChanges := &params.ChainConfig{
		ChainID:                       big.NewInt(1337),
		HomesteadBlock:                big.NewInt(0),
		EIP150Block:                   big.NewInt(0),
		EIP155Block:                   big.NewInt(0),
		EIP158Block:                   big.NewInt(0),
		ByzantiumBlock:                big.NewInt(0),
		ConstantinopleBlock:           big.NewInt(0),
		PetersburgBlock:               big.NewInt(0),
		IstanbulBlock:                 big.NewInt(0),
		MuirGlacierBlock:              big.NewInt(0),
		BerlinBlock:                   big.NewInt(0),
		LondonBlock:                   big.NewInt(0),
		ArrowGlacierBlock:             big.NewInt(0),
		GrayGlacierBlock:              big.NewInt(0),
		ShanghaiTime:                  newUint64(0),
		PragueTime:                    newUint64(0),
		TerminalTotalDifficulty:       big.NewInt(0),
		TerminalTotalDifficultyPassed: true,
	}

	cases := []struct {
		chainConfig *params.ChainConfig
		wanted      []fork
	}{
		{
			// active forks "Shanghai,Cancun,Prague,Regolith,Canyon,Ecotone,Alfie,Isthmus,Javelina,..."
			chainConfig: zircuitTestnetChainConfig,
			// but want just last 3
			wanted: []fork{{Name: "Alfie", Time: *zircuitTestnetChainConfig.AlfieTime}, {Name: "Isthmus", Time: *zircuitTestnetChainConfig.IsthmusTime}, {Name: "Javelina", Time: *zircuitTestnetChainConfig.JavelinaTime}},
		},
		{
			chainConfig: mergedTestChainConfig,
			wanted:      []fork{{Name: "Shanghai", Time: *mergedTestChainConfig.ShanghaiTime}, {Name: "Cancun", Time: *mergedTestChainConfig.CancunTime}, {Name: "Prague", Time: *mergedTestChainConfig.PragueTime}},
		},
		{
			chainConfig: nonActivatedConfig,
			wanted:      []fork{},
		},
		{
			chainConfig: allDevChainProtocolChanges,
			wanted:      []fork{{Name: "Shanghai", Time: *allDevChainProtocolChanges.ShanghaiTime}, {Name: "Prague", Time: *allDevChainProtocolChanges.PragueTime}},
		},
	}
	for _, c := range cases {
		activeForks := filterForks(c.chainConfig)
		if len(activeForks) != len(c.wanted) {
			t.Errorf("fork count mismatch. want: %d, got: %d. wanted: %v, got: %v", len(c.wanted), len(activeForks), c.wanted, activeForks)
		}
		for i, entry := range c.wanted {
			if entry.Name != activeForks[i].Name || entry.Time != activeForks[i].Time {
				t.Errorf("fork[%d] mismatch. want: %v, got: %v", i, entry, activeForks[i])
			}
		}
	}
}
