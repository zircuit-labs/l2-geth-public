package ethapi

import (
	"context"
	"errors"
	"testing"

	"github.com/zircuit-labs/l2-geth-public/rpc"

	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/types"
)

// TestZircConfig tests the Zirc API and ZircAdmin API based on the SLS configuration.
func TestZircConfig(t *testing.T) {
	t.Parallel()

	signer := common.Address{}
	ctx := context.Background()
	ctx = rpc.ContextWithSigner(ctx, signer)

	ctrl := gomock.NewController(t)
	tx := types.NewTx(&types.LegacyTx{})
	txBin, err := tx.MarshalBinary()
	assert.NoError(t, err)
	hash := common.Hash{}
	quarantined := &model.Quarantine{
		IsReleased: false,
		TxData:     txBin,
	}
	q, err := NewQuarantine(quarantined)
	assert.NoError(t, err)

	tests := []struct {
		name             string
		config           sls.Config
		setup            func(mockstorage *Mockstorage)
		wantZirc         *IsQuarantinedResponse
		wantZircAdmin    bool
		wantZircErr      error
		wantZircAdminErr error
	}{
		{
			name: "Disabled Zirc API",
			config: sls.Config{
				Enabled:            true,
				EnableZircAPI:      false,
				EnableZircAdminAPI: false,
			},
			setup: func(mockStorage *Mockstorage) {
			},
			wantZirc:         nil,
			wantZircErr:      ErrSLSDisabled,
			wantZircAdminErr: ErrSLSDisabled,
		},
		{
			name: "Enabled Zirc API",
			config: sls.Config{
				Enabled:            true,
				EnableZircAPI:      true,
				EnableZircAdminAPI: false,
			},
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: true,
					Quarantine:  quarantined,
				}, nil)
			},
			wantZirc: &IsQuarantinedResponse{
				IsQuarantined: true,
				Quarantine:    q,
				WasScanned:    true,
			},
			wantZircErr:      nil,
			wantZircAdminErr: ErrSLSDisabled,
		},
		{
			name: "Disabled ZircAdmin API",
			config: sls.Config{
				Enabled:            true,
				EnableZircAPI:      true,
				EnableZircAdminAPI: false,
			},
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: true,
					Quarantine:  quarantined,
				}, nil)
			},
			wantZirc: &IsQuarantinedResponse{
				IsQuarantined: true,
				Quarantine:    q,
				WasScanned:    true,
			},
			wantZircErr:      nil,
			wantZircAdminErr: ErrSLSDisabled,
		},
		{
			name: "Enabled ZircAdmin API",
			config: sls.Config{
				Enabled:            true,
				EnableZircAPI:      false,
				EnableZircAdminAPI: true,
			},
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().SetExpiresOn(ctx, hash, gomock.Any(), gomock.Any()).Return(true, nil)
			},
			wantZirc:         nil,
			wantZircAdmin:    true,
			wantZircErr:      ErrSLSDisabled,
			wantZircAdminErr: nil,
		},
		{
			name: "Only Disable SLS",
			config: sls.Config{
				Enabled:            false,
				EnableZircAPI:      true,
				EnableZircAdminAPI: true,
			},
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: true,
					Quarantine:  quarantined,
				}, nil)
			},
			wantZirc: &IsQuarantinedResponse{
				IsQuarantined: true,
				Quarantine:    q,
				WasScanned:    true,
			},
			wantZircAdmin:    false,
			wantZircErr:      nil,
			wantZircAdminErr: ErrSLSDisabled,
		},
		{
			name: "All Enabled",
			config: sls.Config{
				Enabled:            true,
				EnableZircAPI:      true,
				EnableZircAdminAPI: true,
			},
			setup: func(mockStorage *Mockstorage) {
				mockStorage.EXPECT().IsQuarantinedAndScanned(ctx, hash).Return(&model.TransactionResult{
					TxHash:      hash.String(),
					Quarantined: true,
					Quarantine:  quarantined,
				}, nil)
				mockStorage.EXPECT().SetExpiresOn(ctx, hash, gomock.Any(), gomock.Any()).Return(true, nil)
			},
			wantZirc: &IsQuarantinedResponse{
				IsQuarantined: true,
				Quarantine:    q,
				WasScanned:    true,
			},
			wantZircAdmin:    true,
			wantZircErr:      nil,
			wantZircAdminErr: nil,
		},
		{
			name: "All Disabled",
			config: sls.Config{
				Enabled:            false,
				EnableZircAPI:      false,
				EnableZircAdminAPI: false,
			},
			setup: func(mockStorage *Mockstorage) {
			},
			wantZirc:         nil,
			wantZircAdmin:    false,
			wantZircErr:      ErrSLSDisabled,
			wantZircAdminErr: ErrSLSDisabled,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockstorage(ctrl)
			mockMessageHasher := NewMockpayloadFormatter(ctrl)
			tt.setup(mockStorage)

			slsAPI := slsAPIFactory(mockStorage, mockMessageHasher, tt.config)

			// Test zircAPI
			gotZirc, err := slsAPI.zircAPI.IsQuarantined(ctx, common.Hash{})
			if !errors.Is(err, tt.wantZircErr) {
				t.Errorf("IsQuarantined(%v)", err)
			}
			assert.Equalf(t, tt.wantZirc, gotZirc, "IsQuarantined()")

			// Test zircAdminAPI
			gotZircAdmin, err := slsAPI.zircAdminAPI.ReleaseTransactionQuarantine(ctx, hash)
			if !errors.Is(err, tt.wantZircAdminErr) {
				t.Errorf("ReleaseTransactionQuarantine(%v)", err)
			}
			assert.Equalf(t, tt.wantZircAdmin, gotZircAdmin, "ReleaseTransactionQuarantine()")
		})
	}
	ctrl.Finish()
}
