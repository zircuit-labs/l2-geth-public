package detector

import (
	"context"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/state"
	"github.com/zircuit-labs/l2-geth/core/types"
	"github.com/zircuit-labs/l2-geth/params"
)

// Dependencies is a struct containing essential components and configurations required for application functionality.
type Dependencies[CFG any, Getter any] struct {
	Signer                types.Signer
	SLSDatabase           slsDatabase
	Blockchain            blockFinder
	LegacyPool            LegacyPool
	SLSConfig             *CFG
	GetRefreshableConfigs Getter
}

type blockFinder interface {
	CurrentBlock() *types.Header
}

type slsDatabase interface {
	LogQuarantineDetectorLog(ctx context.Context, call *model.QuarantineDetectorCalls) error
	LogBlockQuarantineDetectorLog(ctx context.Context, call *model.BlockQuarantineDetectorCalls) error
}

type LegacyPool interface {
	Signer() types.Signer
	CurrentHead() *types.Header
	CurrentState() (*state.StateDB, error)
	ChainConfig() *params.ChainConfig
	Chain() core.ChainContext
	NoncedPending(addr common.Address) types.Transactions
}
