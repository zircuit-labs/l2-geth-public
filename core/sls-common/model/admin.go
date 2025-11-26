package model

import (
	"fmt"
	"strconv"
	"time"

	"github.com/uptrace/bun"
	"github.com/zircuit-labs/zkr-go-common/stores/pg"
	"github.com/zircuit-labs/zkr-go-common/xerrors/stacktrace"
)

type Admin struct {
	bun.BaseModel `bun:"table:sls.admin,alias:a"`
	Address       string     `bun:"address,pk,type:text" json:"address"`
	Reference     string     `bun:"reference,type:text,nullzero" json:"-"`
	CreatedAt     *time.Time `bun:"created_on,type:timestamptz" json:"-"`
}

type TimeOrderedAdmin Admin

func (t TimeOrderedAdmin) UnWrap() Admin {
	return Admin(t)
}

func (TimeOrderedAdmin) KeySort() []pg.KeySort {
	return []pg.KeySort{
		{Key: "created_on", Sort: pg.SortOrderDescending},
	}
}

func (t TimeOrderedAdmin) CursorValues() []string {
	return []string{fmt.Sprintf("%d", t.CreatedAt.UTC().Unix())}
}

func (t TimeOrderedAdmin) DeserizalizeCursorValues(values []string) ([]any, error) {
	if len(values) != 1 {
		return nil, stacktrace.Wrap(pg.ErrCursorValues)
	}

	i, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return nil, stacktrace.Wrap(err)
	}
	return []any{time.Unix(i, 0)}, nil
}
