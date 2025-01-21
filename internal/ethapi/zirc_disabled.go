package ethapi

import (
	"context"

	"github.com/zircuit-labs/l2-geth-public/common"
)

type (
	ZircDisabledAPI struct{}
)

func NewZircDisabledAPI() *ZircDisabledAPI {
	return &ZircDisabledAPI{}
}

func (z ZircDisabledAPI) GetQuarantined(ctx context.Context, from *common.Address) ([]*Quarantine, error) {
	return nil, ErrSLSDisabled
}

func (z ZircDisabledAPI) IsQuarantined(ctx context.Context, txHash common.Hash) (*IsQuarantinedResponse, error) {
	return nil, ErrSLSDisabled
}

func (z ZircDisabledAPI) GetQuarantineHistory(ctx context.Context, offset, limit int, from *common.Address) ([]*Quarantine, error) {
	return nil, ErrSLSDisabled
}

func (z ZircDisabledAPI) GetAdminAddresses(ctx context.Context) ([]common.Address, error) {
	return nil, ErrSLSDisabled
}
