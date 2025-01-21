package model

import (
	"github.com/uptrace/bun"
)

type Admin struct {
	bun.BaseModel `bun:"table:sls.admin,alias:a"`
	Address       string `bun:"address,type:text"`
}
