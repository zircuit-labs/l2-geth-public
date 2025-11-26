package sls

import (
	"github.com/zircuit-labs/l2-geth/common"
	slsCommon "github.com/zircuit-labs/l2-geth/core/sls-common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type (
	TransactionClassifier struct{}
)

func NewTransactionClassifier() *TransactionClassifier {
	return &TransactionClassifier{}
}

var _ slsCommon.TransactionClassifier = (*TransactionClassifier)(nil)

func (t TransactionClassifier) Classify(depositTxs, flaggedTxs types.Transactions) (flaggedDepositTxs, flaggedPoolTxs []common.Hash) {
	return nil, nil
}
