package slsapi

import (
	"context"

	slsapiCommon "github.com/zircuit-labs/l2-geth/core/sls-common/slsapi"
	sls "github.com/zircuit-labs/l2-geth/core/sls-public"
	slsStorage "github.com/zircuit-labs/l2-geth/core/sls-public/storage"
	"github.com/zircuit-labs/l2-geth/rpc"
)

func Factory(ctx context.Context, config sls.Config, payloadFormatter slsapiCommon.PayloadFormatter) ([]rpc.API, slsapiCommon.ZircAPI, error) {
	if !config.EnableZircAPI {
		return slsapiCommon.DisabledAPIs()
	}

	db, err := slsStorage.NewStorage(ctx, config)
	if err != nil {
		return nil, nil, err
	}

	zircAPI := slsapiCommon.NewZircAPI(db)
	var apis []rpc.API
	apis = append(apis, rpc.API{Namespace: "zirc", Service: zircAPI})

	return apis, zircAPI, nil
}
