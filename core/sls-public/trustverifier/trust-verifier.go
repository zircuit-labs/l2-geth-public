package trustverifier

import (
	"context"

	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type TrustVerifierStub struct{}

func (t TrustVerifierStub) Name() string {
	return "stub"
}

func (t TrustVerifierStub) IsTrustable(ctx context.Context, transaction *types.Transaction) (bool, error) {
	return true, nil
}

var _ slsCommon.TrustVerifier = (*TrustVerifierStub)(nil)

func NewSystemTransactions(signer types.Signer) *TrustVerifierStub {
	return &TrustVerifierStub{}
}

func NewTrustList(signer types.Signer, db any) *TrustVerifierStub {
	return &TrustVerifierStub{}
}
