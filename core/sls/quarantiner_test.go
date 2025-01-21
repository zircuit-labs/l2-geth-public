package sls

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/types"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

// MockSigner is a mock implementation of types.Signer
type MockSigner struct {
	sender common.Address
	err    error
}

func (m MockSigner) Sender(tx *types.Transaction) (common.Address, error) {
	return m.sender, m.err
}

func (m MockSigner) SignatureValues(tx *types.Transaction, sig []byte) (r, s, v *big.Int, err error) {
	return nil, nil, nil, nil
}

func (m MockSigner) ChainID() *big.Int {
	return nil
}

func (m MockSigner) Hash(tx *types.Transaction) common.Hash {
	return common.Hash{}
}

func (m MockSigner) Equal(types.Signer) bool {
	return false
}

func TestQuarantinerSendToQuarantine(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	tx := types.NewTx(&types.LegacyTx{})
	detector := "test detector"
	reason := "test reason"
	loss := uint64(100)
	sender := common.Address{}

	tests := []struct {
		name    string
		setup   func(*MockStorage) *MockSigner
		wantErr bool
	}{
		{
			name: "Error getting sender",
			setup: func(mockStorage *MockStorage) *MockSigner {
				return &MockSigner{
					err: errors.New("can't get signer"),
				}
			},
			wantErr: true,
		},
		{
			name: "Error adding to storage",
			setup: func(mockStorage *MockStorage) *MockSigner {
				mockStorage.EXPECT().Add(ctx, gomock.Any()).Return(errors.New("storage error"))
				return &MockSigner{sender: sender}
			},
			wantErr: true,
		},
		{
			name: "Successful quarantine",
			setup: func(mockStorage *MockStorage) *MockSigner {
				mockStorage.EXPECT().Add(ctx, gomock.Any()).Return(nil)
				return &MockSigner{sender: sender}
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockStorage(ctrl)
			mockSigner := tt.setup(mockStorage)

			q := NewQuarantiner(mockStorage, time.Hour, mockSigner)
			err := q.SendToQuarantine(ctx, tx, detector, reason, loss)
			if (err != nil) != tt.wantErr {
				t.Errorf("SendToQuarantine() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQuarantinerPendingRelease(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()

	quarantines := []*model.Quarantine{{}}

	tests := []struct {
		name    string
		setup   func(mockStorage *MockStorage)
		want    []*model.Quarantine
		wantErr bool
	}{
		{
			name: "Error retrieving pending release from storage",
			setup: func(mockStorage *MockStorage) {
				mockStorage.EXPECT().PendingRelease(ctx, model.PoolQuarantineType).Return(nil, errors.New("storage error"))
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Successful pending release",
			setup: func(mockStorage *MockStorage) {
				mockStorage.EXPECT().PendingRelease(ctx, model.PoolQuarantineType).Return(quarantines, nil)
			},
			want:    quarantines,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			mockStorage := NewMockStorage(ctrl)

			tt.setup(mockStorage)

			q := NewQuarantiner(mockStorage, time.Hour, types.HomesteadSigner{})

			got, err := q.PendingRelease(ctx, model.PoolQuarantineType)
			if (err != nil) != tt.wantErr {
				t.Errorf("PendingRelease() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			require.Equal(t, tt.want, got)
		})
	}
}

func TestQuarantinerRelease(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ctx := context.Background()
	tx := types.NewTx(&types.LegacyTx{})

	tests := []struct {
		name    string
		setup   func(mockStorage *MockStorage)
		wantErr bool
	}{
		{
			name: "Error releasing from storage",
			setup: func(mockStorage *MockStorage) {
				mockStorage.EXPECT().Release(ctx, tx.Hash(), releaseReason).Return(false, errors.New("storage error"))
			},
			wantErr: true,
		},
		{
			name: "Successful release",
			setup: func(mockStorage *MockStorage) {
				mockStorage.EXPECT().Release(ctx, tx.Hash(), releaseReason).Return(true, nil)
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockStorage(ctrl)
			tt.setup(mockStorage)

			q := NewQuarantiner(mockStorage, time.Hour, types.HomesteadSigner{})

			err := q.Release(ctx, tx)
			if (err != nil) != tt.wantErr {
				t.Errorf("Release() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
