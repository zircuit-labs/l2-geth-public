package types

import (
	"bytes"

	"github.com/bits-and-blooms/bitset"
	"github.com/zircuit-labs/l2-geth-public/common/hexutil"
)

type Bitmap struct {
	Bs *bitset.BitSet `json:"bs"`
}

func NewBitmap(bs *bitset.BitSet) *Bitmap {
	return &Bitmap{Bs: bs}
}

// MustBytes returns portable bytes from a Bitmap.
func (bm Bitmap) MustBytes() hexutil.Bytes {
	if bm.Len() == 0 {
		return nil
	}

	var buf bytes.Buffer
	_, err := bm.Bs.WriteTo(&buf)
	if err != nil {
		panic("failed to write to buffer")
	}
	return hexutil.Bytes(buf.Bytes())
}

// Indices returns the indices of the set bits in the Bitmap.
// NOTE: this func is quite inefficient and should only be used for testing.
func (bm Bitmap) Indices() []int {
	indices := make([]uint, bm.Bs.Count())
	bm.Bs.NextSetMany(0, indices)
	idxs := make([]int, len(indices))
	for i, v := range indices {
		idxs[i] = int(v)
	}
	return idxs
}

// Set sets the given index in the Bitmap.
func (bm Bitmap) Set(i int) {
	bm.Bs.Set(uint(i))
}

// Clear unsets the given index in the Bitmap.
func (bm Bitmap) Clear(i int) {
	// set first to force growth (underlying bitset is too clever)
	bm.Bs.Set(uint(i))
	bm.Bs.Clear(uint(i))
}

// Test returns true if the given index in the Bitmap is set.
func (bm Bitmap) Test(i int) bool {
	return bm.Bs.Test(uint(i))
}

// Equal returns true iff the other Bitmap is identical.
func (bm Bitmap) Equal(other Bitmap) bool {
	return bm.Bs.Equal(other.Bs)
}

// Len returns the total number of bits in the BitSet.
func (bm Bitmap) Len() int {
	return int(bm.Bs.Len())
}

// Count returns the number of bits that are set in the BitSet.
func (bm Bitmap) Count() int {
	return int(bm.Bs.Count())
}

// String returns a human-readable binary string representation of the Bitmask.
// The string will start with index 0 on left
func (bm Bitmap) String() string {
	if bm.Len() == 0 {
		return "<empty>"
	}

	buf := bytes.NewBufferString("0b")
	// DumpAsBits ends with a '.' and has index 0 on the right
	// It also includes bits that are used internally for tracking the length
	// which we don't want to include in our representation
	s := bm.Bs.DumpAsBits()
	for i := 0; i < bm.Len(); i++ {
		buf.WriteByte(s[len(s)-2-i])
	}
	return buf.String()
}

func MustBitmap(b hexutil.Bytes) *Bitmap {
	if len(b) == 0 {
		return nil
	}

	bs := bitset.New(uint(len(b)))
	buf := bytes.NewBuffer(b)
	_, err := bs.ReadFrom(buf)
	if err != nil {
		panic("failed to read from buffer")
	}

	return NewBitmap(bs)
}
