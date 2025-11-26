package sls

type (
	WorkerError struct {
		DepositTransactionsFlagged bool
		PoolTransactionsFlagged    bool
	}
)

func (s WorkerError) Error() string {
	return "sls worker: block has transactions flagged"
}
