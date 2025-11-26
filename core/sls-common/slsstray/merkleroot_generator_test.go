package slsstray

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/types"
)

func TestMerkleRoot(t *testing.T) {

	smr := NewMerklerootGenerator("")

	tests := []struct {
		name string
		data [][]byte
		want string
	}{
		{
			name: "empty tree",
			data: make([][]byte, 0),
			want: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name: "single element",
			data: [][]byte{[]byte("single")},
			want: "947f187506f7629c81c81879a2cb2256455038e4ac770091d897fa0a8b945e3b",
		},
		{
			name: "two elements",
			data: [][]byte{[]byte("first"), []byte("second")},
			want: "2f3416032c534e1b3cd58f0e0528c5a8f57dea586b788b040c4fab0d37055d28",
		},
		{
			name: "different data to ensure determinism",
			data: [][]byte{[]byte("a"), []byte("b"), []byte("c")},
			want: "d31a37ef6ac14a2db1470c4316beb5592e6afd4465022339adafda76a18ffabe",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mr := hex.EncodeToString(smr.MerkleRoot(tt.data))
			assert.Equal(t, tt.want, mr)
		})
	}
}

func TestSnapshotMerkleRoot(t *testing.T) {
	// structs and slices are marshalled deterministically with encoding/json package
	// maps are **not** mashalled deterministically with encoding/json package
	// in slsstray, we only use structs and slices of structs

	t.Parallel()
	ts, err := time.Parse(time.RFC3339, "2023-10-26T10:30:00Z")
	assert.Equal(t, nil, err)

	tx := types.NewTx(&types.LegacyTx{})
	detector := "test detector"
	reason := "test reason"
	sender := common.Address{}

	tests := []struct {
		name       string
		snapshot   *Snapshot
		expectErr  bool
		merkleRoot string
	}{
		{
			name:       "empty expect empty hash root",
			snapshot:   &Snapshot{Admin: []*model.Admin{}, Quarantine: []*model.Quarantine{}},
			expectErr:  false,
			merkleRoot: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:       "non-empty admin: all zero addr",
			snapshot:   &Snapshot{Admin: []*model.Admin{{Address: sender.Hex()}}, Quarantine: []*model.Quarantine{}},
			expectErr:  false,
			merkleRoot: "fb35427cc7fc026be258e32964fdad1d9b726d346965a22055b1d3d8ddb25f51",
		},
		{
			name:       "non-empty quarantine",
			snapshot:   &Snapshot{Admin: []*model.Admin{}, Quarantine: []*model.Quarantine{{}}},
			expectErr:  false,
			merkleRoot: "b32a9700dc5da58a407e8633a686e55a70fbf27d4dd6060b6d950a81c4be26a8",
		},
		{
			name: "non-empty admin, non-empty quarantine",
			snapshot: &Snapshot{
				Admin: []*model.Admin{{Address: "0x4441A244464a444e4444DA504447715c7eA30444"}},
				Quarantine: []*model.Quarantine{{},
					{
						ExpiresOn:         &ts,
						TxData:            tx.Data(),
						TxHash:            tx.Hash().String(),
						Data:              tx.Data(),
						QuarantinedAt:     ts,
						QuarantinedReason: reason,
						QuarantinedBy:     detector,
						ReleasedAt:        ts,
						ReleasedReason:    reason,
						ReleasedBy:        "0x4441A244464a444e4444DA504447715c7eA30444",
						IsReleased:        false,
						From:              "0x4441A244464a444e4444DA504447715c7eA30444",
						To:                "0x4441A244464a444e4444DA504447715c7eA30444",
						Nonce:             1,
						Loss:              uint256.NewInt(1),
						Value:             uint256.NewInt(1),
						QuarantineType:    model.PoolQuarantineType,
					},
				},
			},
			expectErr:  false,
			merkleRoot: "b7372ca08dbbc4efb0b0750a1d99a2cefdca5650ebddda8846a78817168643a9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			smr := NewMerklerootGenerator("")
			mr, _, err := smr.SnapshotMerkleRoot(tt.snapshot)
			if tt.expectErr == false {
				assert.Equal(t, nil, err)
				assert.Equal(t, tt.merkleRoot, mr)
			}
		})
	}

}
