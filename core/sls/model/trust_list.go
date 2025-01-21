package model

import (
	"time"

	"github.com/uptrace/bun"
)

// TrustListEntry represents a model for a trusted address in the table.
type TrustListEntry struct {
	bun.BaseModel `bun:"table:sls.trust_list,alias:t"`
	Address       string    `bun:"address,pk,type:text"`
	CreatedAt     time.Time `bun:"created_at,type:timestamptz,nullzero"`
}
