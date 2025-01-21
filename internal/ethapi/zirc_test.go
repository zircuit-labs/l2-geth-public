package ethapi

import (
	"context"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	storage2 "github.com/zircuit-labs/l2-geth-public/core/sls/storage"
	"github.com/zircuit-labs/l2-geth-public/core/types"
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
		setup   func(mockstorage *Mockstorage)
		want    *IsQuarantinedResponse
		wantErr error
	}{
		{
			name:   "Storage returns an error",
			txHash: hash,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(nil, errors.New("can't connect to database"))
			},
			want:    nil,
			wantErr: ErrStorage,
		},
		{
			name:   "Transaction was never scanned",
			txHash: hash,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(nil, storage2.ErrTransactionNotFound)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: false,
				Quarantine:    nil,
				WasScanned:    false,
			},
			wantErr: nil,
		},
		{
			name:   "Transaction was scanned and is on quarantine",
			txHash: hash,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: true,
					Quarantine:  quarantined,
				}, nil)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: true,
				WasScanned:    true,
				Quarantine:    q,
			},
			wantErr: nil,
		},
		{
			name:   "Transaction was scanned and was on quarantine",
			txHash: hash,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: true,
					Quarantine:  released,
				}, nil)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: false,
				Quarantine:    r,
				WasScanned:    true,
			},
			wantErr: nil,
		},
		{
			name:   "Transaction was scanned and not quarantined",
			txHash: hash,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: false,
					Quarantine:  nil,
				}, nil)
			},
			want: &IsQuarantinedResponse{
				IsQuarantined: false,
				Quarantine:    nil,
				WasScanned:    true,
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockstorage(ctrl)
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
		setup   func(mockstorage *Mockstorage)
		want    []*Quarantine
		wantErr error
	}{
		{
			name: "Storage returns an error",
			from: address,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().Quarantined(ctx, &address).Return(nil, 0, errors.New("can't connect to database"))
			},
			want:    nil,
			wantErr: ErrStorage,
		},
		{
			name: "No items",
			from: address,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().Quarantined(ctx, &address).Return(nil, 0, nil)
			},
			want:    []*Quarantine{},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockstorage(ctrl)
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
		setup   func(mockstorage *Mockstorage)
		want    []*Quarantine
		wantErr error
	}{
		{
			name:   "Storage returns an error",
			offset: offset,
			limit:  limit,
			from:   address,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().All(ctx, offset, limit, &address).Return(nil, 0, errors.New("can't connect to database"))
			},
			want:    nil,
			wantErr: ErrStorage,
		},
		{
			name:   "No items",
			from:   address,
			offset: offset,
			limit:  limit,
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().All(ctx, offset, limit, &address).Return(nil, 0, nil)
			},
			want:    []*Quarantine{},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockstorage(ctrl)
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
