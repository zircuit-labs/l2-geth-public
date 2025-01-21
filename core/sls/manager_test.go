package sls

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/zircuit-labs/l2-geth-public/core/sls/model"
	"github.com/zircuit-labs/l2-geth-public/core/types"
)

func TestManagerShouldBeQuarantined(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	ctx := context.Background()

	tx := types.NewTx(&types.LegacyTx{})
	reason := "transaction sus"
	loss := uint64(0)
	name := "test detector"

	tests := []struct {
		name    string
		tx      *types.Transaction
		setup   func(*MockDetector, *MockTrustVerifier, *MockDatabase)
		want    ManagerResult
		wantErr bool
	}{
		{
			name: "Trustable transaction",
			tx:   tx,
			setup: func(mockDetector *MockDetector, mockTrustVerifier *MockTrustVerifier, mockDatabase *MockDatabase) {
				mockTrustVerifier.EXPECT().Name().Return("mock_trust_verifier").AnyTimes()
				mockTrustVerifier.EXPECT().IsTrustable(ctx, tx).Return(true, nil)
				mockDatabase.EXPECT().AddTransactionResult(ctx, &model.TransactionResult{
					TxHash:      tx.Hash().String(),
					Quarantined: false,
				})
			},
			want:    ManagerResult{ShouldBeQuarantined: false},
			wantErr: false,
		},
		{
			name: "Transaction should go to quarantine",
			tx:   tx,
			setup: func(mockDetector *MockDetector, mockTrustVerifier *MockTrustVerifier, mockDatabase *MockDatabase) {
				mockTrustVerifier.EXPECT().IsTrustable(ctx, tx).Return(false, nil)
				mockDetector.EXPECT().ShouldBeQuarantined(ctx, tx).Return(true, reason, loss, nil)
				mockDetector.EXPECT().Name().Return(name).AnyTimes()
				mockDatabase.EXPECT().AddTransactionResult(ctx, &model.TransactionResult{
					TxHash:      tx.Hash().String(),
					Quarantined: true,
				})
			},
			want: ManagerResult{
				ShouldBeQuarantined: true,
				Detectors:           name,
				Reasons:             reason,
				Loss:                loss,
			},
			wantErr: false,
		},
		{
			name: "Transaction shouldn't go to quarantine",
			tx:   tx,
			setup: func(mockDetector *MockDetector, mockTrustVerifier *MockTrustVerifier, mockDatabase *MockDatabase) {
				mockTrustVerifier.EXPECT().IsTrustable(ctx, tx).Return(false, nil)
				mockDetector.EXPECT().ShouldBeQuarantined(ctx, tx).Return(false, "", uint64(0), nil)
				mockDetector.EXPECT().Name().Return(name).AnyTimes()
				mockDatabase.EXPECT().AddTransactionResult(ctx, &model.TransactionResult{
					TxHash:      tx.Hash().String(),
					Quarantined: false,
				})
			},
			want: ManagerResult{
				ShouldBeQuarantined: false,
			},
			wantErr: false,
		},
		{
			name: "Error with trust Verifier, but Transaction should go to quarantine",
			tx:   tx,
			setup: func(mockDetector *MockDetector, mockTrustVerifier *MockTrustVerifier, mockDatabase *MockDatabase) {
				mockTrustVerifier.EXPECT().IsTrustable(ctx, tx).Return(false, errors.New("trust verifier error"))
				mockDetector.EXPECT().ShouldBeQuarantined(ctx, tx).Return(true, reason, loss, nil)
				mockDetector.EXPECT().Name().Return(name).AnyTimes()
				mockDatabase.EXPECT().AddTransactionResult(ctx, &model.TransactionResult{
					TxHash:      tx.Hash().String(),
					Quarantined: true,
				})
			},
			want: ManagerResult{
				ShouldBeQuarantined: true,
				Detectors:           name,
				Reasons:             reason,
				Loss:                loss,
			},
			wantErr: false,
		},
		{
			name: "Error with trust Verifier, but Transaction shouldn't go to quarantine",
			tx:   tx,
			setup: func(mockDetector *MockDetector, mockTrustVerifier *MockTrustVerifier, mockDatabase *MockDatabase) {
				mockTrustVerifier.EXPECT().IsTrustable(ctx, tx).Return(false, errors.New("trust verifier error"))
				mockDetector.EXPECT().ShouldBeQuarantined(ctx, tx).Return(false, "", uint64(0), nil)
				mockDetector.EXPECT().Name().Return(name).AnyTimes()
				mockDatabase.EXPECT().AddTransactionResult(ctx, &model.TransactionResult{
					TxHash:      tx.Hash().String(),
					Quarantined: false,
				})
			},
			want: ManagerResult{
				ShouldBeQuarantined: false,
			},
			wantErr: false,
		},
		{
			name: "Error on detector",
			tx:   tx,
			setup: func(mockDetector *MockDetector, mockTrustVerifier *MockTrustVerifier, mockDatabase *MockDatabase) {
				mockTrustVerifier.EXPECT().IsTrustable(ctx, tx).Return(false, nil)
				mockDetector.EXPECT().ShouldBeQuarantined(ctx, tx).Return(false, "", uint64(0), errors.New("detector error"))
				mockDetector.EXPECT().Name().Return(name).AnyTimes()
				mockDatabase.EXPECT().AddTransactionResult(ctx, &model.TransactionResult{
					TxHash:      tx.Hash().String(),
					Quarantined: false,
				})
			},
			want: ManagerResult{
				ShouldBeQuarantined: false,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mockDetector := NewMockDetector(ctrl)
			mockTrustVerifier := NewMockTrustVerifier(ctrl)
			mockDB := NewMockDatabase(ctrl)

			tt.setup(mockDetector, mockTrustVerifier, mockDB)

			detectors := [][]Detector{{mockDetector}}
			trustVerifiers := []TrustVerifier{mockTrustVerifier}

			m := NewManager(detectors, trustVerifiers, mockDB)

			got, err := m.ShouldBeQuarantined(ctx, tt.tx)
			if (err != nil) != tt.wantErr {
				t.Errorf("ShouldBeQuarantined() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ShouldBeQuarantined() got = %v, want %v", got, tt.want)
			}
		})
	}
	ctrl.Finish()
}
