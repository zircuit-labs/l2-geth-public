package types

import (
	"io"

	"github.com/zircuit-labs/l2-geth-public/rlp"
)

func (obj *StateAccount) EncodeRLP(_w io.Writer) error {
	w := rlp.NewEncoderBuffer(_w)
	_tmp0 := w.List()
	w.WriteUint64(obj.Nonce)
	if obj.Balance == nil {
		w.Write(rlp.EmptyString)
	} else {
		w.WriteUint256(obj.Balance)
	}
	w.WriteBytes(obj.Root[:])
	w.WriteBytes(obj.KeccakCodeHash)
	// Only write if using zktrie (otherwise will change root hash value)
	if obj.IsZkTrie() {
		w.WriteBytes(obj.PoseidonCodeHash)
		w.WriteUint64(obj.CodeSize)
	}
	w.ListEnd(_tmp0)
	return w.Flush()
}
