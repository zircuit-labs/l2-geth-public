package circuitcapacitychecker

import (
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
)

type MiniStorageResult struct {
	Key   string       `json:"key"`
	Value *hexutil.Big `json:"value"`
	Proof []string     `json:"proof"`
}

type MiniAccountResult struct {
	Address          common.Address      `json:"address"`
	AccountProof     []string            `json:"accountProof"`
	Balance          *hexutil.Big        `json:"balance"`
	PoseidonCodeHash common.Hash         `json:"poseidonCodeHash"`
	KeccakCodeHash   common.Hash         `json:"keccakCodeHash"`
	CodeSize         hexutil.Uint64      `json:"codeSize"`
	Nonce            hexutil.Uint64      `json:"nonce"`
	StorageHash      common.Hash         `json:"storageHash"`
	StorageProof     []MiniStorageResult `json:"storageProof"`
}

type MiniProofList []string

func (n *MiniProofList) Put(key []byte, value []byte) error {
	*n = append(*n, hexutil.Encode(value))
	return nil
}

func (n *MiniProofList) Delete(key []byte) error {
	panic("not supported")
}
