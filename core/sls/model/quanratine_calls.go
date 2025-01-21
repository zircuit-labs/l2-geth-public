package model

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

type (
	// QuarantineDetectorCalls struct represents a model which stores the
	// quarantine calls that are sent to the provider.
	QuarantineDetectorCalls struct {
		bun.BaseModel    `bun:"table:sls.quarantine_detector_calls,alias:q"`
		ID               uuid.UUID          `bun:"type:uuid,default:uuid_generate_v4()"` // Unique identifier of the quarantine call
		Path             string             `bun:"path,type:text"`                       // The path of the quarantine API call
		RequestBody      json.RawMessage    `bun:"request_body,type:jsonb"`              // The request body of the quarantine API call
		ResponseBody     json.RawMessage    `bun:"response_body,type:jsonb"`             // The response body of the quarantine API call
		Provider         QuarantineProvider `bun:"provider,type:text"`                   // Identifier of the provider that provided the quarantine call
		ResponseCode     int                `bun:"response_code,type:int"`               // The response code of the quarantine API call
		SentAt           time.Time          `bun:"sent_at,type:timestamptz"`             // The time when the call was sent to Provider
		ResponseDuration time.Duration      `bun:"response_duration,type:bigint"`        // The duration of the response
		Attempt          int                `bun:"attempt,type:int"`                     // The nth attempt to send the quarantine call
		From             string             `bun:"from_addr,type:text"`                  // Ethereum address of the sender.
		TxHash           string             `bun:"tx_hash,type:text"`                    // Transaction hash as a string
		CreatedAt        time.Time          `bun:"created_at,type:timestamptz"`          // The time when the quarantine call was created
		UpdatedAt        time.Time          `bun:"updated_at,type:timestamptz"`          // The time when the quarantine call was updated
	}
)

type QuarantineProvider string

// QuarantineCallsCreateOpts represents the creat options of the quarantine calls.
type QuarantineCallsCreateOpts func(*QuarantineDetectorCalls)

func WithQuarantineCallsPath(path string) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.Path = path
	}
}

func WithQuarantineCallsRequestBody(body []byte) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.RequestBody = body
	}
}

func WithQuarantineCallsProvider(provider QuarantineProvider) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.Provider = provider
	}
}

func WithQuarantineCallsResponseCode(code int) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.ResponseCode = code
	}
}

func WithQuarantineCallsSentAt(sentAt time.Time) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.SentAt = sentAt
	}
}

func WithQuarantineCallsResponseDuration(duration time.Duration) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.ResponseDuration = duration
	}
}

func WithQuarantineCallsAttempt(attempt int) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.Attempt = attempt
	}
}

func WithQuarantineCallsFrom(from string) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.From = from
	}
}

func WithQuarantineCallsTxHash(txHash string) QuarantineCallsCreateOpts {
	return func(qc *QuarantineDetectorCalls) {
		qc.TxHash = txHash
	}
}

// NewQuarantineDetectorCalls creates a new QuarantineCalls instance for a transaction,
func NewQuarantineDetectorCalls(opts ...QuarantineCallsCreateOpts) *QuarantineDetectorCalls {
	qc := &QuarantineDetectorCalls{}
	for _, opt := range opts {
		opt(qc)
	}
	qc.CreatedAt = time.Now()
	qc.UpdatedAt = time.Now()
	return qc
}
