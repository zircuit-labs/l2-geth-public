package sls

import (
	"time"

	common "github.com/zircuit-labs/l2-geth/common"
)

type (
	ListItem struct {
		Address   common.Address `json:"address"`
		Reference string         `json:"reference,omitempty"`
		CreatedAt time.Time      `json:"created_at,omitzero"`
	}
)
