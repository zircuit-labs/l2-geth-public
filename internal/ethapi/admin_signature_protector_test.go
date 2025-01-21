package ethapi

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/zircuit-labs/l2-geth-public/accounts"
	"github.com/zircuit-labs/l2-geth-public/common"

	"github.com/zircuit-labs/l2-geth-public/crypto"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestAdminSignatureProtectorVerifySignature(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctrl := gomock.NewController(t)

	privateKey, err := crypto.GenerateKey()
	assert.NoError(t, err)
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	adminAddAddress := "admin_addAddress"
	currTime := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	addr1 := common.HexToAddress("0x1111111111111111111111111111111111111111")
	payload1 := "1609459200,admin_addaddress,0x1111111111111111111111111111111111111111"

	type args struct {
		signTime  time.Time
		method    string
		args      []any
		signature string
	}
	tests := []struct {
		name            string
		signatureExpiry time.Duration
		args            args
		setup           func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter)
		want            common.Address
		want1           bool
	}{
		{
			name: "Invalid signature",
			args: args{
				signature: "NOT_A_VALID_SIGNATURE",
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {},
			want:  common.Address{},
			want1: false,
		},
		{
			name: "Signature with V set to 1",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: "0x" + hex.EncodeToString(append(make([]byte, 64), 1)),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {},
			want:  common.Address{},
			want1: false,
		},
		{
			name: "Signature with V set to 26",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: "0x" + hex.EncodeToString(append(make([]byte, 64), 26)),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {},
			want:  common.Address{},
			want1: false,
		},
		{
			name: "Signature with V set to 29",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: "0x" + hex.EncodeToString(append(make([]byte, 64), 29)),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {},
			want:  common.Address{},
			want1: false,
		},
		{
			name: "Signature with invalid public key",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: "0x" + hex.EncodeToString(make([]byte, 65)),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {
				mockFormatter.EXPECT().Format(currTime, adminAddAddress, []any{addr1}).Return(payload1)
				mockStorage.EXPECT().IsAdmin(ctx, address).Return(false, nil)
			},
			want:  common.Address{},
			want1: false,
		},
		{
			name: "Database error",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: signMessage(t, payload1, privateKey),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {
				mockFormatter.EXPECT().Format(currTime, adminAddAddress, []any{addr1}).Return(payload1)
				mockStorage.EXPECT().IsAdmin(ctx, address).Return(false, errors.New("can't connect to database"))
			},
			want:  common.Address{},
			want1: false,
		},
		{
			name: "Signer is not an admin",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: signMessage(t, payload1, privateKey),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {
				mockFormatter.EXPECT().Format(currTime, adminAddAddress, []any{addr1}).Return(payload1)
				mockStorage.EXPECT().IsAdmin(ctx, address).Return(false, nil)
			},
			want:  address,
			want1: false,
		},
		{
			name: "Signed by admin",
			args: args{
				signTime:  currTime,
				method:    adminAddAddress,
				args:      []any{addr1},
				signature: signMessage(t, payload1, privateKey),
			},
			setup: func(mockStorage *Mockstorage, mockFormatter *MockpayloadFormatter) {
				mockFormatter.EXPECT().Format(currTime, adminAddAddress, []any{addr1}).Return(payload1)
				mockStorage.EXPECT().IsAdmin(ctx, address).Return(true, nil)
			},
			want:  address,
			want1: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockStorage := NewMockstorage(ctrl)
			mockPayloadFormatter := NewMockpayloadFormatter(ctrl)

			tt.setup(mockStorage, mockPayloadFormatter)

			s := newAdminSignatureProtector(mockStorage, mockPayloadFormatter, tt.signatureExpiry)

			got, got1 := s.verifySignature(ctx, tt.args.signTime, tt.args.method, tt.args.args, tt.args.signature)
			assert.Equalf(t, tt.want, got, "verifySignature(%v, %v, %v, %v)", tt.args.signTime, tt.args.method, tt.args.args, tt.args.signature)
			assert.Equalf(t, tt.want1, got1, "verifySignature(%v, %v, %v, %v)", tt.args.signTime, tt.args.method, tt.args.args, tt.args.signature)
		})
	}

	ctrl.Finish()
}

func signMessage(t *testing.T, message string, privateKey *ecdsa.PrivateKey) string {
	hash := accounts.TextHash([]byte(message))

	signature, err := crypto.Sign(hash, privateKey)
	assert.NoError(t, err)

	if signature[64] < 27 {
		signature[64] += 27
	}

	return hex.EncodeToString(signature)
}
