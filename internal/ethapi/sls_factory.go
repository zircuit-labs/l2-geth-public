package ethapi

import (
	"context"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/sls"
)

type (
	zircAPI interface {
		GetQuarantined(ctx context.Context, from *common.Address) ([]*Quarantine, error)
		IsQuarantined(ctx context.Context, txHash common.Hash) (*IsQuarantinedResponse, error)
		GetQuarantineHistory(ctx context.Context, offset, limit int, from *common.Address) ([]*Quarantine, error)
		GetAdminAddresses(ctx context.Context) ([]common.Address, error)
	}

	zircAdminAPI interface {
		ReleaseTransactionQuarantine(ctx context.Context, hash common.Hash) (bool, error)
		ExtendTransactionQuarantine(ctx context.Context, hash common.Hash, minutes int) (bool, error)
		GetIntegrityListAddresses(ctx context.Context) ([]common.Address, error)
		AddAddressesToIntegrityList(ctx context.Context, address []common.Address) (bool, error)
		RemoveAddressesFromIntegrityList(ctx context.Context, address []common.Address) (bool, error)
	}

	zircAdminAPIPublic interface {
		GetFormattedPayload(method string, args []any) string
	}

	slsAPI struct {
		zircAPI            zircAPI
		zircAdminAPI       zircAdminAPI
		zircAdminAPIPublic zircAdminAPIPublic
	}
)

// slsAPIFactory returns instances to SLS services based on the SLS configuration.
func slsAPIFactory(db storage, payloadFormatter payloadFormatter, slsConfig sls.Config) slsAPI {
	// Default to disabled versions
	api := slsAPI{
		zircAPI:            NewZircDisabledAPI(),
		zircAdminAPI:       NewZircAdminDisabledAPI(),
		zircAdminAPIPublic: NewZircAdminAPIPublicDisabled(),
	}

	if slsConfig.Enabled {
		if slsConfig.EnableZircAdminAPI {
			api.zircAdminAPI = NewZircAdminAPI(db)
			api.zircAdminAPIPublic = NewZircAdminAPIPublic(db, payloadFormatter)
		}
	}

	// Enable Zirc API if the flag is set. This is independent of the SLS feature flag.
	if slsConfig.EnableZircAPI {
		api.zircAPI = NewZircAPI(db)
	}

	return api
}
