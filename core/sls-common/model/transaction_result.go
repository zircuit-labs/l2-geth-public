package model

import (
	"time"

	"github.com/uptrace/bun"
)

type (
	// TransactionResult represents a model for transaction results in the table
	TransactionResult struct {
		bun.BaseModel `bun:"table:sls.transaction_results,alias:tr"`
		TxHash        string      `bun:"tx_hash,pk,type:text"`
		Quarantined   bool        `bun:"quarantined,type:boolean"`
		CreatedOn     time.Time   `bun:"created_on,nullzero,notnull,default:current_timestamp"`
		Quarantine    *Quarantine `bun:"rel:has-one,join:tx_hash=tx_hash"`
	}
)
