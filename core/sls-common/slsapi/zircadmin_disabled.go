package slsapi

import (
	"context"

	"github.com/zircuit-labs/l2-geth/common"
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
