package slsapi

import (
	context "context"

	common "github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/rpc"
)

type ZircAPI interface {
	GetQuarantined(ctx context.Context, from *common.Address) ([]*Quarantine, error)
	IsQuarantined(ctx context.Context, txHash common.Hash) (*IsQuarantinedResponse, error)
	GetQuarantineHistory(ctx context.Context, offset, limit int, from *common.Address) ([]*Quarantine, error)
	GetAdminAddresses(ctx context.Context) ([]common.Address, error)
}

func DisabledAPIs() ([]rpc.API, ZircAPI, error) {
	disabledZircAPI := NewZircDisabledAPI()
	return []rpc.API{
		{Namespace: "zirc", Service: disabledZircAPI},
		{Namespace: "admin", Service: NewZircAdminDisabledAPI()},
		{Namespace: "admin", Service: NewZircAdminAPIPublicDisabled()},
	}, disabledZircAPI, nil
}
