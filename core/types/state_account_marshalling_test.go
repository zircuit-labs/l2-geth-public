package types

import (
	"math"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/stretchr/testify/assert"

	"github.com/zircuit-labs/l2-geth-public/common"
)

func assertAccountsEqual(t *testing.T, expected *StateAccount, actual *StateAccount) {
	assert.Equal(t, expected.Nonce, actual.Nonce)
	assert.Zero(t, expected.Balance.Cmp(actual.Balance))
	assert.Equal(t, expected.Root, actual.Root)
	assert.Equal(t, expected.KeccakCodeHash, actual.KeccakCodeHash)
	assert.Equal(t, expected.PoseidonCodeHash, actual.PoseidonCodeHash)
	assert.Equal(t, expected.CodeSize, actual.CodeSize)
}

func TestMarshalUnmarshalEmptyAccount(t *testing.T) {
	acc := StateAccount{
		Nonce:            0,
		Balance:          uint256.NewInt(0),
		Root:             common.Hash{},
		KeccakCodeHash:   EmptyKeccakCodeHash.Bytes(),
		PoseidonCodeHash: EmptyPoseidonCodeHash.Bytes(),
		CodeSize:         0,
	}

	// marshal account

	bytes, flag := acc.MarshalFields()

	assert.Equal(t, 5, len(bytes))
	assert.Equal(t, uint32(8), flag)

	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[0].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[1].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[2].Bytes())
	assert.Equal(t, common.Hex2Bytes("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"), bytes[3].Bytes())
	assert.Equal(t, common.Hex2Bytes("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"), bytes[4].Bytes())

	// unmarshal account

	flatBytes := []byte("")

	for _, item := range bytes {
		flatBytes = append(flatBytes, item.Bytes()...)
	}

	acc2, err := UnmarshalStateAccount(flatBytes)

	assert.Nil(t, err)
	assertAccountsEqual(t, &acc, acc2)
}

func TestMarshalUnmarshalZeroAccount(t *testing.T) {
	acc := StateAccount{
		Nonce:            0,
		Balance:          uint256.NewInt(0),
		Root:             common.Hash{},
		KeccakCodeHash:   make([]byte, 0),
		PoseidonCodeHash: make([]byte, 0),
		CodeSize:         0,
	}

	// marshal account

	bytes, flag := acc.MarshalFields()

	assert.Equal(t, 5, len(bytes))
	assert.Equal(t, uint32(8), flag)

	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[0].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[1].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[2].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[3].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"), bytes[4].Bytes())
}

func TestMarshalUnmarshalNonEmptyAccount(t *testing.T) {
	acc := StateAccount{
		Nonce:            0x11111111,
		Balance:          uint256.NewInt(0x33333333),
		Root:             common.HexToHash("123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234"),
		KeccakCodeHash:   common.Hex2Bytes("1111111111111111111111111111111111111111111111111111111111111111"),
		PoseidonCodeHash: common.Hex2Bytes("2222222222222222222222222222222222222222222222222222222222222222"),
		CodeSize:         0x22222222,
	}

	// marshal account

	bytes, flag := acc.MarshalFields()

	assert.Equal(t, 5, len(bytes))
	assert.Equal(t, uint32(8), flag)

	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000222222220000000011111111"), bytes[0].Bytes())
	assert.Equal(t, common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000033333333"), bytes[1].Bytes())
	assert.Equal(t, common.Hex2Bytes("123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234"), bytes[2].Bytes())
	assert.Equal(t, common.Hex2Bytes("1111111111111111111111111111111111111111111111111111111111111111"), bytes[3].Bytes())
	assert.Equal(t, common.Hex2Bytes("2222222222222222222222222222222222222222222222222222222222222222"), bytes[4].Bytes())

	// unmarshal account

	flatBytes := []byte("")

	for _, item := range bytes {
		flatBytes = append(flatBytes, item.Bytes()...)
	}

	acc2, err := UnmarshalStateAccount(flatBytes)

	assert.Nil(t, err)
	assertAccountsEqual(t, &acc, acc2)
}

func TestMarshalUnmarshalAccountWithMaxFields(t *testing.T) {
	maxFieldElement := new(uint256.Int).Sub(uint256.MustFromBig(constants.Q), uint256.NewInt(1))

	acc := StateAccount{
		Nonce:            math.MaxUint64,
		Balance:          maxFieldElement,
		Root:             common.BigToHash(maxFieldElement.ToBig()),
		KeccakCodeHash:   common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		PoseidonCodeHash: maxFieldElement.Bytes(),
		CodeSize:         math.MaxUint64,
	}

	// marshal account

	bytes, flag := acc.MarshalFields()

	assert.Equal(t, 5, len(bytes))
	assert.Equal(t, uint32(8), flag)

	assert.Equal(t, common.Hex2Bytes("00000000000000000000000000000000ffffffffffffffffffffffffffffffff"), bytes[0].Bytes())
	assert.Equal(t, common.Hex2Bytes("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"), bytes[1].Bytes())
	assert.Equal(t, common.Hex2Bytes("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"), bytes[2].Bytes())
	assert.Equal(t, common.Hex2Bytes("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), bytes[3].Bytes())
	assert.Equal(t, common.Hex2Bytes("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000"), bytes[4].Bytes())

	// unmarshal account

	flatBytes := []byte("")

	for _, item := range bytes {
		flatBytes = append(flatBytes, item.Bytes()...)
	}

	acc2, err := UnmarshalStateAccount(flatBytes)

	assert.Nil(t, err)
	assertAccountsEqual(t, &acc, acc2)
}

func TestMarshalPanic(t *testing.T) {
	assert.PanicsWithValue(t, "StateAccount balance nil", func() {
		acc := StateAccount{}
		acc.MarshalFields()
	})

	assert.PanicsWithValue(t, "StateAccount balance overflow", func() {
		acc := StateAccount{Balance: uint256.MustFromBig(constants.Q)}
		acc.MarshalFields()
	})

	assert.PanicsWithValue(t, "StateAccount balance overflow", func() {
		balance := new(big.Int)
		balance, ok := balance.SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
		assert.True(t, ok)
		acc := StateAccount{Balance: uint256.MustFromBig(balance)}
		acc.MarshalFields()
	})

	assert.PanicsWithValue(t, "StateAccount root overflow: 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001", func() {
		acc := StateAccount{Balance: uint256.NewInt(0), Root: common.BigToHash(constants.Q)}
		acc.MarshalFields()
	})

	assert.PanicsWithValue(t, "StateAccount root overflow: 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", func() {
		acc := StateAccount{Balance: uint256.NewInt(0), Root: EmptyLegacyTrieRootHash}
		acc.MarshalFields()
	})

	assert.PanicsWithValue(t, "StateAccount poseidonCodeHash overflow", func() {
		acc := StateAccount{Balance: uint256.NewInt(0), PoseidonCodeHash: constants.Q.Bytes()}
		acc.MarshalFields()
	})
}
