package ethapi

import (
	"time"
)

//go:generate mockgen -source zircadmin_public.go -destination mock_zircadmin_public.go -package ethapi

type (
	ZircAdminAPIPublic struct {
		storage          storage
		payloadFormatter payloadFormatter
	}

	payloadFormatter interface {
		Format(currTime time.Time, method string, args []any) string
	}
)

func NewZircAdminAPIPublic(storage storage, payloadFormatter payloadFormatter) *ZircAdminAPIPublic {
	return &ZircAdminAPIPublic{storage: storage, payloadFormatter: payloadFormatter}
}

func (z *ZircAdminAPIPublic) GetFormattedPayload(method string, args []any) string {
	return z.payloadFormatter.Format(time.Now().UTC(), method, args)
}
