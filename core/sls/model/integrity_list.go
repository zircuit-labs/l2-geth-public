package model

import (
	"github.com/uptrace/bun"
)

// IntegrityListEntry represents a model for integrity list entry in the table
type IntegrityListEntry struct {
	bun.BaseModel `bun:"table:sls.integrity_address,alias:i"`
	Address       string `bun:"address,pk,type:text"`
}
