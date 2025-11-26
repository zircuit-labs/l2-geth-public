package model

import (
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type (
	// BlockQuarantineDetectorCalls struct represents a model which stores the
	// BlockQuarantine calls that are sent to the provider.
	BlockQuarantineDetectorCalls struct {
		bun.BaseModel    `bun:"table:sls.block_quarantine_detector_calls,alias:q"`
		ID               uuid.UUID               `bun:"type:uuid,default:uuid_generate_v4()"` // Unique identifier of the BlockQuarantine call
		Path             string                  `bun:"path,type:text"`                       // The path of the BlockQuarantine API call
		Provider         BlockQuarantineProvider `bun:"provider,type:text"`                   // Identifier of the provider that provided the BlockQuarantine call
		ResponseCode     int                     `bun:"response_code,type:int"`               // The response code of the BlockQuarantine API call
		SentAt           time.Time               `bun:"sent_at,type:timestamptz"`             // The time when the call was sent to Provider
		ResponseDuration time.Duration           `bun:"response_duration,type:bigint"`        // The duration of the response
		Attempt          int                     `bun:"attempt,type:int"`                     // The nth attempt to send the BlockQuarantine call
		BlockNumber      int                     `bun:"block_number,type:int"`                // The block number that was simulated
		BlockTime        int                     `bun:"block_time,type:int"`                  // The block time that was simulated
		CreatedAt        time.Time               `bun:"created_at,type:timestamptz"`          // The time when the BlockQuarantine call was created
		UpdatedAt        time.Time               `bun:"updated_at,type:timestamptz"`          // The time when the BlockQuarantine call was updated
	}
)

type BlockQuarantineProvider string

// BlockQuarantineCallsCreateOpts represents the create options of the BlockQuarantine calls.
type BlockQuarantineCallsCreateOpts func(*BlockQuarantineDetectorCalls)

func WithBlockQuarantineCallsPath(path string) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.Path = path
	}
}

func WithBlockQuarantineCallsProvider(provider BlockQuarantineProvider) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.Provider = provider
	}
}

func WithBlockQuarantineCallsResponseCode(code int) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.ResponseCode = code
	}
}

func WithBlockQuarantineCallsSentAt(sentAt time.Time) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.SentAt = sentAt
	}
}

func WithBlockQuarantineCallsResponseDuration(duration time.Duration) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.ResponseDuration = duration
	}
}

func WithBlockQuarantineCallsAttempt(attempt int) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.Attempt = attempt
	}
}

func WithBlockQuarantineCallsBlockNumber(blockNumber int) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.BlockNumber = blockNumber
	}
}

func WithBlockQuarantineCallsBlockTime(blockTime int) BlockQuarantineCallsCreateOpts {
	return func(qc *BlockQuarantineDetectorCalls) {
		qc.BlockTime = blockTime
	}
}

// NewBlockQuarantineDetectorCalls creates a new BlockQuarantineCalls instance for a transaction,
func NewBlockQuarantineDetectorCalls(opts ...BlockQuarantineCallsCreateOpts) *BlockQuarantineDetectorCalls {
	qc := &BlockQuarantineDetectorCalls{}
	for _, opt := range opts {
		opt(qc)
	}
	qc.CreatedAt = time.Now()
	qc.UpdatedAt = time.Now()
	return qc
}
