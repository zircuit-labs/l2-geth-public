package ethapi

import (
	"context"

	"github.com/zircuit-labs/l2-geth-public/common"
)

type (
	ZircAdminDisabledAPI struct{}
)

func NewZircAdminDisabledAPI() *ZircAdminDisabledAPI {
	return &ZircAdminDisabledAPI{}
}

func (z ZircAdminDisabledAPI) ReleaseTransactionQuarantine(ctx context.Context, hash common.Hash) (bool, error) {
	return false, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) ExtendTransactionQuarantine(ctx context.Context, hash common.Hash, minutes int) (bool, error) {
	return false, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error) {
	return nil, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) AddAddressesToIntegrityList(ctx context.Context, address []common.Address) (bool, error) {
	return false, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) RemoveAddressesFromIntegrityList(ctx context.Context, address []common.Address) (bool, error) {
	return false, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) GetTrustListAddresses(ctx context.Context) ([]common.Address, error) {
	return nil, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) AddAddressesToTrustList(ctx context.Context, address []common.Address) (bool, error) {
	return false, ErrSLSDisabled
}

func (z ZircAdminDisabledAPI) RemoveAddressesFromTrustList(ctx context.Context, address []common.Address) (bool, error) {
	return false, ErrSLSDisabled
}
