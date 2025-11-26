package processor

import (
	"context"

	"github.com/alitto/pond/v2"

	"github.com/zircuit-labs/l2-geth/common"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/sls-common/model"
	"github.com/zircuit-labs/l2-geth/core/sls-public"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type SLSTxProcessorStub struct{}

var _ slsCommon.TXProcessor = (*SLSTxProcessorStub)(nil)

type TxProcessorOption func()

type (
	manager interface {
		ShouldBeQuarantined(ctx context.Context, tx *types.Transaction, detectorType slsCommon.DetectorType) (slsCommon.ManagerResult, error)
	}

	quarantiner interface {
		SendToQuarantine(ctx context.Context, transaction *types.Transaction, quarantineType model.QuarantineType, detector, reason string, loss uint64) error
	}
)

func New(m manager, q quarantiner, pondPool pond.Pool, refreshableGetter sls.RefreshableGetter) *SLSTxProcessorStub {
	return &SLSTxProcessorStub{}
}

func (s SLSTxProcessorStub) ProcessTransactions(ctx context.Context, addr common.Address, transactions types.Transactions) types.Transactions {
	panic("This functionality has been intentionally excluded for this release.")
}

func (s SLSTxProcessorStub) CollectSendBackToPool() types.Transactions {
	panic("This functionality has been intentionally excluded for this release.")
}

func (s SLSTxProcessorStub) CollectAllPromotables() types.Transactions {
	panic("This functionality has been intentionally excluded for this release.")
}

func (s SLSTxProcessorStub) IsAddressWaiting(addr common.Address) bool {
	panic("This functionality has been intentionally excluded for this release.")
}

func (s SLSTxProcessorStub) CollectQuarantinedAddresses() []common.Address {
	panic("This functionality has been intentionally excluded for this release.")
}

func (s SLSTxProcessorStub) Awaited(addr common.Address) types.Transactions {
	// panic("This functionality has been intentionally excluded for this release.")
	return nil
}

func (s SLSTxProcessorStub) Stop() {
	panic("This functionality has been intentionally excluded for this release.")
}
