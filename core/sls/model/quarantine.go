package model

import (
	"time"

	"github.com/zircuit-labs/l2-geth-public/common"
	"github.com/zircuit-labs/l2-geth-public/core/types"

	"github.com/uptrace/bun"
)

type (
	// Quarantine struct represents a transaction that has been quarantined,
	// containing details such as the transaction itself, reason for quarantine,
	// who quarantined it, and release information.
	Quarantine struct {
		bun.BaseModel `bun:"table:sls.quarantine,alias:q"`

		ExpiresOn         *time.Time     `bun:"expires_on,type:timestamptz"`     // The time when the quarantine period expires.
		TxData            []byte         `bun:"tx_data,type:bytea"`              // The transaction that is quarantined.
		TxHash            string         `bun:"tx_hash,type:text"`               // Transaction hash as a string
		QuarantinedAt     time.Time      `bun:"quarantined_at,type:timestamptz"` // The time when the transaction was quarantined.
		QuarantinedReason string         `bun:"quarantined_reason,type:text"`    // Reason for quarantining the transaction.
		QuarantinedBy     string         `bun:"quarantined_by,type:text"`        // Identifier of the detector that quarantined the transaction.
		ReleasedAt        time.Time      `bun:"released_at,type:timestamptz"`    // The time when the transaction was released.
		ReleasedReason    string         `bun:"released_reason,type:text"`       // Reason for releasing the transaction.
		ReleasedBy        string         `bun:"released_by,type:text"`           // Ethereum address of the entity that released the transaction.
		IsReleased        bool           `bun:"is_released,type:boolean"`        // Flag indicating whether the transaction has been released.
		From              string         `bun:"from_addr,type:text"`             // Ethereum address of the sender.
		Nonce             uint64         `bun:"nonce,type:bigint"`               // The nonce of the transaction.
		Loss              uint64         `bun:"loss,type:bigint"`                // The amount of loss in wei.
		Value             uint64         `bun:"value,type:bigint"`               // The value of the transaction in wei.
		QuarantineType    QuarantineType `bun:"quarantine_type,type:int"`        // The type of the quarantine.
	}

	QuarantineType int
)

const (
	PoolQuarantineType QuarantineType = iota
	APIRejectedQuarantineType
)

// NewQuarantine creates a new Quarantine instance for a transaction,
// setting the quarantine start time and duration until expiration.
func NewQuarantine(tx *types.Transaction, detector, reason, from string, duration time.Duration, loss uint64) (*Quarantine, error) {
	txData, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var expires *time.Time
	if duration > 0 {
		finalTime := time.Now().Add(duration)
		expires = &finalTime
	}

	return &Quarantine{
		ExpiresOn:         expires,
		TxData:            txData,
		TxHash:            tx.Hash().String(),
		QuarantinedAt:     time.Now(),
		QuarantinedReason: reason,
		QuarantinedBy:     detector,
		IsReleased:        false,
		Nonce:             tx.Nonce(),
		Value:             tx.Value().Uint64(),
		From:              from,
		Loss:              loss,
		QuarantineType:    PoolQuarantineType,
	}, nil
}

func NewQuarantineRejected(tx *types.Transaction, detector, reason, from string, loss uint64) (*Quarantine, error) {
	txData, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &Quarantine{
		TxData:            txData,
		TxHash:            tx.Hash().String(),
		QuarantinedAt:     time.Now(),
		QuarantinedReason: reason,
		QuarantinedBy:     detector,
		IsReleased:        false,
		Nonce:             tx.Nonce(),
		Value:             tx.Value().Uint64(),
		From:              from,
		Loss:              loss,
		QuarantineType:    APIRejectedQuarantineType,
	}, nil
}

// ShouldBeReleased determines if the quarantine period has expired and the transaction
// has not yet been released, indicating it should now be released.
func (q *Quarantine) ShouldBeReleased() bool {
	return !q.IsReleased && q.ExpiresOn.Before(time.Now())
}

// Tx returns the quarantined transaction.
func (q *Quarantine) Tx() (*types.Transaction, error) {
	var tx types.Transaction
	if err := tx.UnmarshalBinary(q.TxData); err != nil {
		return nil, err
	}
	return &tx, nil
}

// SetExpiresOn updates the expiration time of the quarantine period.
func (q *Quarantine) SetExpiresOn(expiresOn time.Time) {
	q.ExpiresOn = &expiresOn
}

// SetReleaser sets the releaser on the quarantine entry.
func (q *Quarantine) SetReleaser(releasedBy common.Address) {
	q.ReleasedBy = releasedBy.String()
}

// Release marks the transaction as released and records the releasing entity.
func (q *Quarantine) Release(reason string) {
	q.ReleasedAt = time.Now()
	q.ReleasedReason = reason
	q.IsReleased = true
}
