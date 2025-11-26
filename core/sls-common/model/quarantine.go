package model

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/holiman/uint256"

	"github.com/uptrace/bun"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"

	"github.com/zircuit-labs/l2-geth/common"
	"github.com/zircuit-labs/l2-geth/core/types"
)

type (
	// Quarantine struct represents a transaction that has been quarantined,
	// containing details such as the transaction itself, reason for quarantine,
	// who quarantined it, and release information.
	Quarantine struct {
		bun.BaseModel `bun:"table:sls.quarantine,alias:q"`

		ExpiresOn         *time.Time     `bun:"expires_on,type:timestamptz" json:"expiresOn"`          // The time when the quarantine period expires.
		TxData            []byte         `bun:"tx_data,type:bytea" json:"-"`                           // The transaction that is quarantined.
		TxHash            string         `bun:"tx_hash,type:text" json:"transactionHash"`              // Transaction hash as a string
		Data              []byte         `bun:"data,type:bytea"`                                       // Transaction input data
		QuarantinedAt     time.Time      `bun:"quarantined_at,type:timestamptz" json:"quarantinedAt"`  // The time when the transaction was quarantined.
		QuarantinedReason string         `bun:"quarantined_reason,type:text" json:"quarantinedReason"` // Reason for quarantining the transaction.
		QuarantinedBy     string         `bun:"quarantined_by,type:text" json:"quarantinedBy"`         // Identifier of the detector that quarantined the transaction.
		ReleasedAt        time.Time      `bun:"released_at,type:timestamptz" json:"releasedAt"`        // The time when the transaction was released.
		ReleasedReason    string         `bun:"released_reason,type:text" json:"releasedReason"`       // Reason for releasing the transaction.
		ReleasedBy        string         `bun:"released_by,type:text" json:"releasedBy"`               // Ethereum address of the entity that released the transaction.
		IsReleased        bool           `bun:"is_released,type:boolean" json:"-"`                     // Flag indicating whether the transaction has been released.
		From              string         `bun:"from_addr,type:text" json:"-"`                          // Ethereum address of the sender.
		To                string         `bun:"to_addr,type:text"`                                     // Ethereum address of the target.
		Nonce             uint64         `bun:"nonce,type:bigint" json:"-"`                            // The nonce of the transaction.
		Loss              *uint256.Int   `bun:"loss,type:numeric" json:"-"`                            // The amount of loss in wei.
		Value             *uint256.Int   `bun:"value,type:numeric" json:"-"`                           // The value of the transaction in wei.
		QuarantineType    QuarantineType `bun:"quarantine_type,type:int" json:"-"`                     // The type of the quarantine.
	}

	QuarantineType int
)

type TimeOrderedQuarantine Quarantine

func (t TimeOrderedQuarantine) UnWrap() Quarantine {
	return Quarantine(t)
}

func (TimeOrderedQuarantine) KeySort() []pg.KeySort {
	return []pg.KeySort{
		{Key: "quarantined_at", Sort: pg.SortOrderDescending},
	}
}

func (t TimeOrderedQuarantine) CursorValues() []string {
	return []string{fmt.Sprintf("%d", t.QuarantinedAt.UTC().Unix())}
}

func (t TimeOrderedQuarantine) DeserizalizeCursorValues(values []string) ([]any, error) {
	if len(values) != 1 {
		return nil, stacktrace.Wrap(pg.ErrCursorValues)
	}

	i, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}
	return []any{time.Unix(i, 0)}, nil
}

const (
	PoolQuarantineType QuarantineType = iota
	APIRejectedQuarantineType
	BlockPoolQuarantineType
	BlockDepositQuarantineType
)

// NewQuarantine creates a new Quarantine instance for a transaction,
// setting the quarantine start time and duration until expiration.
func NewQuarantine(tx *types.Transaction, detector, reason, from string, duration time.Duration, loss uint64, quarantineType QuarantineType) (*Quarantine, error) {
	if tx == nil {
		return nil, errors.New("transaction cannot be nil")
	}
	if tx.Value() == nil {
		return nil, errors.New("transaction value cannot be nil")
	}
	txData, err := tx.MarshalBinary()
	if err != nil {
		return nil, err
	}

	var expires *time.Time
	if duration > 0 {
		finalTime := time.Now().Add(duration)
		expires = &finalTime
	}
	var toAddr string
	if tx.To() != nil {
		toAddr = tx.To().String()
	}
	return &Quarantine{
		ExpiresOn:         expires,
		TxData:            txData,
		TxHash:            tx.Hash().String(),
		Data:              tx.Data(),
		QuarantinedAt:     time.Now(),
		QuarantinedReason: reason,
		QuarantinedBy:     detector,
		IsReleased:        false,
		Nonce:             tx.Nonce(),
		Value:             uint256.MustFromBig(tx.Value()),
		From:              from,
		To:                toAddr,
		Loss:              uint256.NewInt(loss),
		QuarantineType:    quarantineType,
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
		Value:             uint256.MustFromBig(tx.Value()),
		From:              from,
		Loss:              uint256.NewInt(loss),
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
