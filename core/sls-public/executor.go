package sls

import (
	"context"
	"sync"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type ExecutorStub struct{}

var _ slsCommon.Executor = (*ExecutorStub)(nil)

// NewExecutor creates and returns a new Executor instance, initializing it with the provided parameters.
func NewExecutor(quarantiner slsCommon.Quarantiner, signer types.Signer, pool slsCommon.LegacyPool[Config, RefreshableConfigs]) *ExecutorStub {
	return &ExecutorStub{}
}

func (e *ExecutorStub) Loop(ctx context.Context, callerWG *sync.WaitGroup, _ *sync.RWMutex) {
	defer callerWG.Done()
}

func (e *ExecutorStub) Stop() {}
