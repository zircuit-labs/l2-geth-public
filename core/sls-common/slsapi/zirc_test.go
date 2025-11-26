package slsapi

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
	"go.uber.org/mock/gomock"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	storage2 "github.com/zircuit-labs/l2-geth/core/sls-common/storage"
	"github.com/zircuit-labs/l2-geth/core/types"
)

func TestZircAPIIsQuarantined(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	ctx := context.Background()
	hash := common.Hash{}
	tx := types.NewTx(&types.LegacyTx{})
	txBin, err := tx.MarshalBinary()
	assert.NoError(t, err)

	quarantined := &model.Quarantine{
		IsReleased: false,
		TxData:     txBin,
	}
	released := &model.Quarantine{
		IsReleased: true,
		TxData:     txBin,
	}
	q, err := NewQuarantine(quarantined)
	assert.NoError(t, err)
	r, err := NewQuarantine(released)
	assert.NoError(t, err)

	tests := []struct {
		name    string
		txHash  common.Hash
		setup   func(mockstorage *MockQuarantineStorage)
		want    *IsQuarantinedResponse
		wantErr error
	}{
		{
			name:   "Storage returns an error",
			txHash: hash,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().FindByHash(ctx, hash).Return(nil, errors.New("can't connect to database"))
			},
			want:    nil,
			wantErr: ErrStorage,
		},
		{
			name:   "Transaction was never scanned",
			txHash: hash,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().FindByHash(ctx, hash).Return(nil, storage2.ErrTransactionNotFound)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: false,
				Quarantine:    nil,
				TxData:        nil,
			},
			wantErr: nil,
		},
		{
			name:   "Transaction is on quarantine",
			txHash: hash,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().FindByHash(ctx, hash).Return(quarantined, nil)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: true,
				Quarantine:    q,
				TxData:        txBin,
			},
			wantErr: nil,
		},
		{
			name:   "Transaction is not quarantined",
			txHash: hash,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().FindByHash(ctx, hash).Return(nil, storage2.ErrTransactionNotFound)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: false,
				Quarantine:    nil,
				TxData:        nil,
			},
			wantErr: nil,
		},
		{
			name:   "It was released from quarantine",
			txHash: hash,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().FindByHash(ctx, hash).Return(released, nil)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: false,
				Quarantine:    r,
				TxData:        txBin,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockQuarantineStorage(ctrl)
			tt.setup(mockStorage)
			z := NewZircAPI(mockStorage)

			got, err := z.IsQuarantined(ctx, tt.txHash)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("IsQuarantined(%v, %v)", ctx, tt.txHash)
			}

			assert.Equalf(t, tt.want, got, "IsQuarantined(%v, %v)", ctx, tt.txHash)
		})
	}
	ctrl.Finish()
}

func TestZircAPIGetQuarantined(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	ctx := context.Background()
	address := common.Address{}

	tests := []struct {
		name    string
		from    common.Address
		setup   func(mockstorage *MockQuarantineStorage)
		want    []*Quarantine
		wantErr error
	}{
		{
			name: "Storage returns an error",
			from: address,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().Quarantined(ctx, defaultQueryOpts{}, &address).Return(pg.Cursor{}, nil, errors.New("can't connect to database"))
			},
			want:    nil,
			wantErr: ErrStorage,
		},
		{
			name: "No items",
			from: address,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().Quarantined(ctx, defaultQueryOpts{}, &address).Return(pg.Cursor{}, nil, nil)
			},
			want:    []*Quarantine{},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockQuarantineStorage(ctrl)
			tt.setup(mockStorage)
			z := NewZircAPI(mockStorage)

			got, err := z.GetQuarantined(ctx, &tt.from)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetQuarantined(%v, %v)", ctx, tt.from)
			}

			assert.Equalf(t, tt.want, got, "GetQuarantined(%v, %v)", ctx, tt.from)
		})
	}
	ctrl.Finish()
}

func TestZircAPIGetQuarantineHistory(t *testing.T) {
	t.Parallel()
	ctrl := gomock.NewController(t)
	ctx := context.Background()
	address := common.Address{}
	offset := 1
	limit := 10

	tests := []struct {
		name    string
		offset  int
		limit   int
		from    common.Address
		setup   func(mockstorage *MockQuarantineStorage)
		want    []*Quarantine
		wantErr error
	}{
		{
			name:   "Storage returns an error",
			offset: offset,
			limit:  limit,
			from:   address,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().All(ctx, defaultQueryOpts{}, &address).Return(pg.Cursor{}, nil, errors.New("can't connect to database"))
			},
			want:    nil,
			wantErr: ErrStorage,
		},
		{
			name:   "No items",
			from:   address,
			offset: offset,
			limit:  limit,
			setup: func(mockStorage *MockQuarantineStorage) {
				mockStorage.EXPECT().All(ctx, defaultQueryOpts{}, &address).Return(pg.Cursor{}, nil, nil)
			},
			want:    []*Quarantine{},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockQuarantineStorage(ctrl)
			tt.setup(mockStorage)
			z := NewZircAPI(mockStorage)

			got, err := z.GetQuarantineHistory(ctx, tt.offset, tt.limit, &tt.from)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("GetQuarantined(%v, %v)", ctx, tt.from)
			}

			assert.Equalf(t, tt.want, got, "GetQuarantined(%v, %v)", ctx, tt.from)
		})
	}
	ctrl.Finish()
}
